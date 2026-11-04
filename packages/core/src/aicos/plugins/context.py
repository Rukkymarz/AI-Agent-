"""Capability-guarded host API handed to plugins (object-capability pattern).

A plugin never receives raw service handles. Every call checks the granted capability
set, is audited on denial, and counts toward the plugin's health budget.

NOTE: for IN_PROCESS plugins this is a *policy* boundary, not a hard *security*
boundary (Python cannot sandbox in-process code). That is why COMMUNITY-tier plugins
are forced into CONTAINER isolation where the same API is served over RPC.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from aicos.domain.errors import PluginError
from aicos.events.bus import DomainEvent, EventBus
from aicos.llm.providers import LLMResponse, Message
from aicos.llm.router import LLMRouter, TaskType
from aicos.memory.service import MemoryService
from aicos.memory.store import MemoryScope, ScopeKey
from aicos.security.audit import AuditLog, Outcome
from aicos.security.secrets import SecretProvider


class CapabilityDenied(PluginError):
    code = "capability_denied"


class PluginContext:
    def __init__(
        self,
        *,
        plugin: str,
        namespace: str,
        tenant_id: str,
        granted: frozenset[str],
        bus: EventBus,
        router: LLMRouter,
        memory: MemoryService,
        secrets: SecretProvider,
        audit: AuditLog,
        on_violation: Callable[[str, str], None],
    ) -> None:
        self.plugin, self.namespace, self.tenant_id = plugin, namespace, tenant_id
        self._granted = granted
        self._bus, self._router, self._memory, self._secrets, self._audit = bus, router, memory, secrets, audit
        self._on_violation = on_violation
        self.log = logging.getLogger(f"aicos.plugin.{plugin}")

    # ------------------------------------------------------------------ guard
    @property
    def capabilities(self) -> frozenset[str]:
        return self._granted

    def has(self, cap: str) -> bool:
        if cap in self._granted:
            return True
        domain_verb = cap.rsplit(":", 1)[0]
        return f"{domain_verb}:*" in self._granted and not cap.startswith(("secrets:", "net:"))

    def require(self, cap: str) -> None:
        if not self.has(cap):
            self._audit.record(
                tenant_id=self.tenant_id,
                actor_id=f"plugin:{self.plugin}",
                actor_type="service",
                action="plugin.capability",
                resource=cap,
                outcome=Outcome.DENIED,
            )
            self._on_violation(self.plugin, cap)
            raise CapabilityDenied(f"plugin '{self.plugin}' lacks capability '{cap}'")

    # ------------------------------------------------------------------ events
    async def publish(self, event: str, payload: dict[str, Any], correlation_id: str | None = None) -> None:
        if not event.startswith(self.namespace + "."):
            self._on_violation(self.plugin, f"events:publish:{event}")
            raise CapabilityDenied("plugins may only publish namespaced events")
        self.require(f"events:publish:{event}")
        await self._bus.publish(
            DomainEvent(
                type=event, tenant_id=self.tenant_id, source=f"plugin:{self.plugin}", correlation_id=correlation_id, payload=payload
            )
        )

    # ------------------------------------------------------------------ llm
    async def complete(self, task: TaskType, messages: list[Message]) -> LLMResponse:
        self.require(f"llm:invoke:{task.value}")
        return await self._router.complete(task, messages)

    # ------------------------------------------------------------------ memory
    _SCOPES = {"company": MemoryScope.COMPANY, "project": MemoryScope.PROJECT, "agent": MemoryScope.AGENT}

    async def recall(self, scope: str, owner_id: str, query: str, k: int = 5) -> list[str]:
        self.require(f"memory:read:{scope}")
        hits = await self._memory.recall(
            tenant_id=self.tenant_id, query=query, keys=[ScopeKey(scope=self._SCOPES[scope], owner_id=owner_id)], k=k
        )
        return [h.record.content for h in hits]

    async def remember(self, scope: str, owner_id: str, content: str) -> str:
        self.require(f"memory:write:{scope}")
        rec = await self._memory.remember(
            tenant_id=self.tenant_id, scope=self._SCOPES[scope], owner_id=owner_id, content=content, metadata={"plugin": self.plugin}
        )
        return rec.id

    # ------------------------------------------------------------------ secrets
    def secret(self, name: str) -> str:
        allowed = [c.split(":", 2)[2] for c in self._granted if c.startswith("secrets:read:")]
        if ".." in name or not any(name == p or name.startswith(p.rstrip("/") + "/") for p in allowed):
            self.require(f"secrets:read:{name}")  # raises + audits
        value = self._secrets.get(name)
        self._audit.record(
            tenant_id=self.tenant_id,
            actor_id=f"plugin:{self.plugin}",
            actor_type="service",
            action="plugin.secret_read",
            resource=name,
            outcome=Outcome.SUCCESS if value else Outcome.FAILURE,
        )
        if not value:
            raise PluginError(f"secret '{name}' not configured")
        return value

    # ------------------------------------------------------------------ network
    def check_egress(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            self._on_violation(self.plugin, f"net:egress:{url}")
            raise CapabilityDenied("only https egress is permitted")
        self.require(f"net:egress:{parsed.hostname.lower()}")

    def http(self, timeout: float = 15.0) -> Any:  # pragma: no cover - network
        """httpx.AsyncClient whose every request is checked against net:egress grants."""
        import httpx

        ctx = self

        async def _guard(request: httpx.Request) -> None:
            ctx.check_egress(str(request.url))

        return httpx.AsyncClient(timeout=timeout, follow_redirects=False, event_hooks={"request": [_guard]})
