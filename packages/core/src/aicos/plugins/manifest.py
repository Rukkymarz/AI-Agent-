"""Plugin manifest (plugin.yaml) schema and capability grammar.

Capability grammar:  <domain>:<verb>[:<scope>]
  events:subscribe:<EventType|*>      receive events (wildcard is SENSITIVE)
  events:publish:<Namespace>.<Event>  publish ONLY into the plugin's own namespace
  llm:invoke:<task|*>                 call the LLM router
  memory:read:<company|project|agent> memory:write:<...>  (company write is SENSITIVE)
  knowledge:read | knowledge:ingest
  net:egress:<exact-host>             outbound HTTPS to one host (SENSITIVE)
  secrets:read:<path-prefix>          read secrets under prefix (SENSITIVE)
  actions:register:<action.type>      contribute an action handler
  agents:register                     contribute agent specs
  models:register                     contribute an LLM provider / models
  loaders:register                    contribute knowledge loaders
"""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from aicos.agents.base import AgentSpec
from aicos.domain.common import canonical_json, sha256_hex
from aicos.domain.identity import CRITICAL_PERMISSIONS, Permission


class PluginKind(StrEnum):
    AGENT = "agent"
    ACTION = "action"
    LLM_PROVIDER = "llm_provider"
    KNOWLEDGE_LOADER = "knowledge_loader"
    EVENT_SUBSCRIBER = "event_subscriber"
    POLICY_GUARD = "policy_guard"  # may only ADD restrictions; CORE tier only


class TrustTier(StrEnum):
    CORE = "core"  # signed by the project release key
    VERIFIED = "verified"  # signed by an allow-listed publisher key
    COMMUNITY = "community"  # unsigned / unknown signer -> container isolation mandatory


class IsolationMode(StrEnum):
    IN_PROCESS = "in_process"
    CONTAINER = "container"


_CAP = re.compile(
    r"^(events:subscribe:(\*|[A-Z][A-Za-z0-9]{2,63}(\.[A-Za-z0-9]{2,63})?)"
    r"|events:publish:[A-Z][A-Za-z0-9]{1,63}\.[A-Z][A-Za-z0-9]{2,63}"
    r"|llm:invoke:(\*|coding|reasoning|business|fast|general)"
    r"|memory:(read|write):(company|project|agent)"
    r"|knowledge:(read|ingest)"
    r"|net:egress:[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+"
    r"|secrets:read:[a-z0-9][a-z0-9_\-/]{1,120}"
    r"|actions:register:[a-z][a-z0-9_]*(\.[a-z0-9_]+)+"
    r"|agents:register|models:register|loaders:register)$"
)
_SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?$")


def is_sensitive(cap: str, actions: list[ActionDecl] | None = None) -> bool:
    if cap.startswith(("secrets:", "net:egress:")) or cap in {"events:subscribe:*", "memory:write:company", "models:register"}:
        return True
    if cap.startswith("actions:register:"):
        name = cap.split(":", 2)[2]
        return any(a.action == name and a.permission in CRITICAL_PERMISSIONS for a in actions or [])
    return False


class ResourceLimits(BaseModel):
    cpus: float = Field(default=0.5, gt=0, le=8)
    memory_mb: int = Field(default=512, ge=64, le=16_384)
    pids: int = Field(default=128, ge=16, le=4096)
    timeout_s: float = Field(default=30.0, gt=0, le=600)


class ActionDecl(BaseModel):
    action: str = Field(pattern=r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$")
    permission: Permission
    description: str = ""


def _parse_version(v: str) -> tuple[int, int, int]:
    core = v.split("-", 1)[0]
    a, b, c = (int(x) for x in core.split("."))
    return a, b, c


def version_satisfies(version: str, spec: str) -> bool:
    """Minimal PEP440-ish range check supporting >=, >, <=, <, == joined by commas."""
    current = _parse_version(version)
    for clause in (c.strip() for c in spec.split(",") if c.strip()):
        m = re.match(r"^(>=|<=|==|>|<)\s*(\d+\.\d+\.\d+)$", clause)
        if not m:
            raise ValueError(f"bad version clause: {clause}")
        op, target = m.group(1), _parse_version(m.group(2))
        ok = {">=": current >= target, "<=": current <= target, "==": current == target, ">": current > target, "<": current < target}[op]
        if not ok:
            return False
    return True


class PluginManifest(BaseModel):
    api_version: Literal["aicos.io/v1"] = "aicos.io/v1"
    name: str = Field(pattern=r"^[a-z][a-z0-9-]{2,49}$")
    namespace: str = Field(pattern=r"^[A-Z][A-Za-z0-9]{1,63}$", description="event namespace, e.g. HubSpot")
    version: str
    publisher: str = Field(min_length=2, max_length=100)
    description: str = Field(default="", max_length=2000)
    license: str = "MIT"
    homepage: str | None = None
    kinds: list[PluginKind] = Field(min_length=1)
    entrypoint: str = Field(pattern=r"^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)*:[A-Za-z_][A-Za-z0-9_]*$")
    aicos_version: str = ">=0.1.0"
    isolation: IsolationMode = IsolationMode.IN_PROCESS
    capabilities: list[str] = Field(default_factory=list)
    actions: list[ActionDecl] = Field(default_factory=list)
    agents: list[AgentSpec] = Field(default_factory=list)
    resources: ResourceLimits = Field(default_factory=ResourceLimits)
    dependencies: list[str] = Field(default_factory=list)
    integrity: dict[str, str] = Field(default_factory=dict, description="relative path -> sha256")

    @property
    def module_root(self) -> str:
        return self.entrypoint.split(":", 1)[0].split(".", 1)[0]

    @property
    def action_prefix(self) -> str:
        return self.name.replace("-", "_") + "."

    @field_validator("version")
    @classmethod
    def _semver(cls, v: str) -> str:
        if not _SEMVER.match(v):
            raise ValueError("version must be semver")
        return v

    @field_validator("capabilities")
    @classmethod
    def _caps(cls, caps: list[str]) -> list[str]:
        bad = [c for c in caps if not _CAP.match(c)]
        if bad:
            raise ValueError(f"invalid capabilities: {bad}")
        if len(set(caps)) != len(caps):
            raise ValueError("duplicate capabilities")
        return caps

    @model_validator(mode="after")
    def _consistency(self) -> PluginManifest:
        if self.module_root != self.name.replace("-", "_"):
            raise ValueError("entrypoint top-level module must equal plugin name with '-' -> '_'")
        for cap in self.capabilities:
            if cap.startswith("events:publish:") and not cap.split(":", 2)[2].startswith(self.namespace + "."):
                raise ValueError("plugins may only publish events in their own namespace")
        for a in self.actions:
            if not a.action.startswith(self.action_prefix):
                raise ValueError(f"action '{a.action}' must be prefixed with '{self.action_prefix}'")
            if f"actions:register:{a.action}" not in self.capabilities:
                raise ValueError(f"action '{a.action}' declared without capability")
        for s in self.agents:
            if not s.id.startswith(self.name + "-"):
                raise ValueError(f"agent id '{s.id}' must be prefixed with '{self.name}-'")
        if self.agents and "agents:register" not in self.capabilities:
            raise ValueError("agents declared without agents:register capability")
        try:
            version_satisfies("0.0.0", self.aicos_version)  # syntax check only
        except ValueError as exc:
            raise ValueError(f"invalid aicos_version: {exc}") from None
        return self

    def sensitive_capabilities(self) -> list[str]:
        return [c for c in self.capabilities if is_sensitive(c, self.actions)]

    def digest(self) -> str:
        return sha256_hex(canonical_json(self.model_dump(mode="json")))

    @classmethod
    def load(cls, path: str | Path) -> PluginManifest:
        return cls.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")))
