"""Policy engine. Deny-by-default; DENY overrides REQUIRE_APPROVAL overrides ALLOW.

Evaluation order:
  1. Tenant isolation
  2. RBAC (with delegation intersection for agents)
  3. Agent hard-deny list
  4. Declarative rules (YAML) and programmatic rules
  5. Critical-permission gate -> REQUIRE_APPROVAL unless a valid execution grant is presented
  6. MFA for humans executing critical actions
"""

from __future__ import annotations

import fnmatch
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Protocol

import yaml
from pydantic import BaseModel, ConfigDict, Field

from aicos.domain.common import canonical_json, new_id, sha256_hex
from aicos.domain.identity import (
    AGENT_FORBIDDEN_PERMISSIONS,
    CRITICAL_PERMISSIONS,
    Permission,
    Principal,
    PrincipalType,
)
from aicos.security.rbac import delegated_permissions


class Effect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class ActionRequest(BaseModel):
    """A concrete side-effecting action an actor wants to perform."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(default_factory=lambda: new_id("act"))
    tenant_id: str = "default"
    actor: Principal
    on_behalf_of: Principal | None = None
    action: str = Field(pattern=r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$", max_length=120)
    permission: Permission
    resource: str = Field(default="*", max_length=500)
    payload: dict[str, Any] = Field(default_factory=dict)
    rationale: str = Field(default="", max_length=4000)

    def payload_hash(self) -> str:
        """Binds an approval to the exact action content (prevents bait-and-switch)."""
        return sha256_hex(
            canonical_json(
                {
                    "tenant": self.tenant_id,
                    "action": self.action,
                    "permission": str(self.permission),
                    "resource": self.resource,
                    "payload": self.payload,
                }
            )
        )


class PolicyDecision(BaseModel):
    effect: Effect
    reasons: list[str] = Field(default_factory=list)
    matched_rules: list[str] = Field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.effect is Effect.ALLOW


class PolicyRule(Protocol):
    id: str

    def evaluate(self, request: ActionRequest) -> Effect | None: ...


Op = Literal["eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in", "contains"]


class Condition(BaseModel):
    field: str  # dotted path into payload, e.g. "payload.amount"
    op: Op
    value: Any

    def matches(self, request: ActionRequest) -> bool:
        current: Any = {"payload": request.payload, "resource": request.resource, "action": request.action}
        for part in self.field.split("."):
            if not isinstance(current, dict) or part not in current:
                return False
            current = current[part]
        try:
            match self.op:
                case "eq":
                    return bool(current == self.value)
                case "ne":
                    return bool(current != self.value)
                case "gt":
                    return bool(current > self.value)
                case "gte":
                    return bool(current >= self.value)
                case "lt":
                    return bool(current < self.value)
                case "lte":
                    return bool(current <= self.value)
                case "in":
                    return current in self.value
                case "not_in":
                    return current not in self.value
                case "contains":
                    return self.value in current
        except TypeError:
            return False
        return False  # pragma: no cover


class DeclarativeRule(BaseModel):
    id: str
    description: str = ""
    effect: Effect
    actions: list[str] = Field(default_factory=lambda: ["*"])
    principal_types: list[PrincipalType] = Field(default_factory=lambda: list(PrincipalType))
    when: list[Condition] = Field(default_factory=list)

    def evaluate(self, request: ActionRequest) -> Effect | None:
        if request.actor.type not in self.principal_types:
            return None
        if not any(fnmatch.fnmatchcase(request.action, pat) for pat in self.actions):
            return None
        if all(c.matches(request) for c in self.when):
            return self.effect
        return None


class PolicyEngine:
    def __init__(self, rules: list[PolicyRule] | None = None) -> None:
        self._rules: list[PolicyRule] = list(rules or [])

    @property
    def rules(self) -> list[PolicyRule]:
        return list(self._rules)

    def add_rule(self, rule: PolicyRule) -> None:
        self._rules.append(rule)

    def remove_rule(self, rule_id: str) -> None:
        self._rules = [r for r in self._rules if r.id != rule_id]

    @classmethod
    def from_yaml(cls, path: str | Path) -> PolicyEngine:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        rules: list[PolicyRule] = [DeclarativeRule.model_validate(r) for r in raw.get("rules", [])]
        return cls(rules)

    def evaluate(self, request: ActionRequest, *, grant_valid: bool = False) -> PolicyDecision:
        actor, delegator = request.actor, request.on_behalf_of

        if actor.tenant_id != request.tenant_id or (delegator and delegator.tenant_id != request.tenant_id):
            return PolicyDecision(effect=Effect.DENY, reasons=["tenant_mismatch"])

        perms = delegated_permissions(actor, delegator)
        if actor.type is PrincipalType.AGENT and not perms:
            return PolicyDecision(effect=Effect.DENY, reasons=["agent_requires_human_delegator"])
        if request.permission not in perms:
            return PolicyDecision(effect=Effect.DENY, reasons=[f"missing_permission:{request.permission}"])
        if actor.type is PrincipalType.AGENT and request.permission in AGENT_FORBIDDEN_PERMISSIONS:
            return PolicyDecision(effect=Effect.DENY, reasons=["agent_forbidden_permission"])

        if request.permission in CRITICAL_PERMISSIONS and actor.is_human and not actor.mfa_verified:
            return PolicyDecision(effect=Effect.DENY, reasons=["mfa_required"])

        matched: list[str] = []
        needs_approval = request.permission in CRITICAL_PERMISSIONS
        for rule in self._rules:
            effect = rule.evaluate(request)
            if effect is None:
                continue
            matched.append(rule.id)
            if effect is Effect.DENY:
                return PolicyDecision(effect=Effect.DENY, reasons=[f"rule:{rule.id}"], matched_rules=matched)
            if effect is Effect.REQUIRE_APPROVAL:
                needs_approval = True

        if needs_approval and not grant_valid:
            return PolicyDecision(effect=Effect.REQUIRE_APPROVAL, reasons=["critical_action"], matched_rules=matched)

        return PolicyDecision(effect=Effect.ALLOW, reasons=["ok"], matched_rules=matched)
