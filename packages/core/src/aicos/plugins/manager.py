"""Plugin lifecycle manager.

State machine:
  DISCOVERED -> VERIFIED -> PENDING_APPROVAL -> APPROVED -> ACTIVE <-> SUSPENDED
        any -> FAILED | UNINSTALLED ;  PENDING_APPROVAL -> REJECTED

Gates:
  verify   : manifest schema, integrity map covers every file, Ed25519 signature -> trust tier,
             tier/isolation rules, core-version compatibility, dependency presence
  install  : plugin.install is a CRITICAL action -> Human Approval Gateway (payload = manifest digest
             + full capability list, sensitive caps highlighted to reviewers)
  activate : re-verify integrity and digest == approved digest (TOCTOU), deps ACTIVE, then
             entrypoint.activate(ctx, registrar) with capability-checked registrar
  runtime  : handler timeouts, tenant isolation, error budget -> automatic SUSPENSION (fail closed)
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import logging
import sys
import threading
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, Field

from aicos import __version__
from aicos.agents.base import Agent, AgentSpec
from aicos.agents.registry import AgentRegistry
from aicos.approvals.gateway import ApprovalGateway, Proposal, ProposalStatus
from aicos.domain.common import utcnow
from aicos.domain.errors import AuthorizationError, IntegrityError, PluginError, ValidationFailed
from aicos.domain.identity import AGENT_FORBIDDEN_PERMISSIONS, Permission, Principal
from aicos.events.bus import DomainEvent, EventBus, EventType
from aicos.knowledge.loaders import Loader, LoaderRegistry
from aicos.llm.providers import LLMProvider
from aicos.llm.router import LLMRouter, ModelSpec
from aicos.memory.service import MemoryService
from aicos.orchestrator.actions import ActionExecutor
from aicos.plugins.context import CapabilityDenied, PluginContext
from aicos.plugins.manifest import (
    IsolationMode,
    PluginKind,
    PluginManifest,
    TrustTier,
    version_satisfies,
)
from aicos.plugins.signing import MANIFEST_FILE, SIG_FILE, TrustStore, verify_integrity
from aicos.security.audit import AuditLog, Outcome
from aicos.security.policy import ActionRequest, Effect, PolicyEngine, PolicyRule
from aicos.security.rbac import effective_permissions
from aicos.security.secrets import SecretProvider

log = logging.getLogger(__name__)
_BACKGROUND: set[asyncio.Future[Any]] = set()


def _spawn(aw: Any) -> None:
    """Schedule and keep a strong reference until done (prevents GC of in-flight tasks)."""
    fut = asyncio.ensure_future(aw)
    _BACKGROUND.add(fut)
    fut.add_done_callback(_BACKGROUND.discard)


class PluginState(StrEnum):
    DISCOVERED = "discovered"
    VERIFIED = "verified"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REJECTED = "rejected"
    FAILED = "failed"
    UNINSTALLED = "uninstalled"


S = PluginState
_TRANSITIONS: dict[PluginState, set[PluginState]] = {
    S.DISCOVERED: {S.VERIFIED, S.FAILED, S.UNINSTALLED},
    S.VERIFIED: {S.PENDING_APPROVAL, S.FAILED, S.UNINSTALLED},
    S.PENDING_APPROVAL: {S.APPROVED, S.REJECTED, S.FAILED, S.UNINSTALLED},
    S.APPROVED: {S.ACTIVE, S.FAILED, S.UNINSTALLED},
    S.ACTIVE: {S.SUSPENDED, S.FAILED, S.UNINSTALLED},
    S.SUSPENDED: {S.ACTIVE, S.FAILED, S.UNINSTALLED},
    S.REJECTED: {S.VERIFIED, S.UNINSTALLED},
    S.FAILED: {S.VERIFIED, S.UNINSTALLED},
    S.UNINSTALLED: set(),
}


class PluginRecord(BaseModel):
    manifest: PluginManifest
    path: str
    signature: str | None = None
    tier: TrustTier = TrustTier.COMMUNITY
    state: PluginState = PluginState.DISCOVERED
    proposal_id: str | None = None
    approved_digest: str | None = None
    granted: list[str] = Field(default_factory=list)
    errors: int = 0
    violations: int = 0
    last_error: str | None = None
    history: list[dict[str, str]] = Field(default_factory=list)

    @property
    def name(self) -> str:
        return self.manifest.name


@dataclass
class HostServices:
    agents: AgentRegistry
    executor: ActionExecutor
    router: LLMRouter
    bus: EventBus
    memory: MemoryService
    secrets: SecretProvider
    audit: AuditLog
    approvals: ApprovalGateway
    policy: PolicyEngine
    loaders: LoaderRegistry


class ContainerPluginRuntime(Protocol):
    async def start(self, record: PluginRecord) -> None: ...
    async def stop(self, name: str) -> None: ...


class _RestrictOnlyRule:
    """Wraps a plugin policy rule so it can only tighten policy. Errors fail closed."""

    def __init__(self, plugin: str, rule: PolicyRule) -> None:
        self.id = f"plugin:{plugin}:{rule.id}"
        self._rule = rule

    def evaluate(self, request: ActionRequest) -> Effect | None:
        try:
            effect = self._rule.evaluate(request)
        except Exception:  # noqa: BLE001
            return Effect.REQUIRE_APPROVAL
        return effect if effect in (Effect.DENY, Effect.REQUIRE_APPROVAL) else None


class PluginRegistrar:
    """Capability-checked registration surface. Every registration is reversible."""

    def __init__(self, record: PluginRecord, host: HostServices, ctx: PluginContext, manager: PluginManager) -> None:
        self._r, self._host, self._ctx, self._mgr = record, host, ctx, manager
        self._undo: list[Callable[[], None]] = []
        self.registered: list[str] = []

    def _need(self, kind: PluginKind, cap: str | None = None) -> None:
        if kind not in self._r.manifest.kinds:
            raise CapabilityDenied(f"plugin kind '{kind}' not declared")
        if cap is not None:
            self._ctx.require(cap)

    # ---------------------------------------------------------------- agents
    def register_agent(self, spec: AgentSpec, factory: Callable[[AgentSpec], Agent] | None = None) -> None:
        self._need(PluginKind.AGENT, "agents:register")
        declared = {s.id: s for s in self._r.manifest.agents}
        decl = declared.get(spec.id)
        if decl is None:
            raise CapabilityDenied(f"agent '{spec.id}' not declared in manifest")
        if not spec.permissions <= decl.permissions or spec.permissions & AGENT_FORBIDDEN_PERMISSIONS:
            raise CapabilityDenied("agent permissions exceed manifest declaration")
        if not set(spec.tools) <= set(decl.tools):
            raise CapabilityDenied("agent tools exceed manifest declaration")
        spec = spec.model_copy(update={"source": f"plugin:{self._r.name}"})
        self._host.agents.register(spec, factory)
        self._undo.append(lambda: self._host.agents.unregister(spec.id))
        self.registered.append(f"agent:{spec.id}")

    # ---------------------------------------------------------------- actions
    def register_action(
        self,
        action: str,
        permission: Permission,
        handler: Callable[[ActionRequest], Awaitable[dict[str, Any]]],
    ) -> None:
        self._need(PluginKind.ACTION, f"actions:register:{action}")
        decl = {a.action: a for a in self._r.manifest.actions}.get(action)
        if decl is None or decl.permission != permission:
            raise CapabilityDenied(f"action '{action}' not declared with permission {permission}")
        timeout, name, tenant = self._r.manifest.resources.timeout_s, self._r.name, self._ctx.tenant_id

        async def guarded(req: ActionRequest) -> dict[str, Any]:
            if req.tenant_id != tenant:
                raise PluginError("cross-tenant invocation refused")
            try:
                return await asyncio.wait_for(handler(req), timeout=timeout)
            except Exception as exc:
                self._mgr.report_error(name, exc)
                raise

        self._host.executor.register_action(action, permission, guarded)
        self._undo.append(lambda: self._host.executor.unregister_action(action))
        self.registered.append(f"action:{action}")

    # ---------------------------------------------------------------- events
    def subscribe(self, event_type: str, handler: Callable[[DomainEvent], Awaitable[None]]) -> None:
        self._need(PluginKind.EVENT_SUBSCRIBER)
        if not (self._ctx.has(f"events:subscribe:{event_type}") or self._ctx.has("events:subscribe:*")):
            self._ctx.require(f"events:subscribe:{event_type}")
        timeout, name, tenant = self._r.manifest.resources.timeout_s, self._r.name, self._ctx.tenant_id

        async def guarded(event: DomainEvent) -> None:
            if event.tenant_id != tenant:
                return
            try:
                await asyncio.wait_for(handler(event), timeout=timeout)
            except Exception as exc:  # noqa: BLE001 - do not trigger bus retries for plugin bugs
                self._mgr.report_error(name, exc)

        sub = self._host.bus.subscribe(event_type, guarded, name=f"plugin:{name}:{event_type}")
        self._undo.append(lambda: self._host.bus.unsubscribe(sub.id))
        self.registered.append(f"subscription:{event_type}")

    # ---------------------------------------------------------------- models
    def register_llm_provider(self, provider_name: str, provider: LLMProvider, models: list[ModelSpec]) -> None:
        self._need(PluginKind.LLM_PROVIDER, "models:register")
        if provider_name in self._host.router.providers:
            raise CapabilityDenied(f"provider '{provider_name}' already registered")
        if any(not m.local for m in models) and not any(c.startswith("net:egress:") for c in self._r.granted):
            raise CapabilityDenied("remote models require a declared net:egress capability")
        router = self._host.router
        router.providers[provider_name] = provider
        for m in models:
            if m.name in router.models:
                raise CapabilityDenied(f"model '{m.name}' already registered")
            router.register_model(m.model_copy(update={"provider": provider_name}))

        def undo() -> None:
            router.providers.pop(provider_name, None)
            for m in models:
                router.models.pop(m.name, None)
                for chain in router.routes.values():
                    if m.name in chain:
                        chain.remove(m.name)

        self._undo.append(undo)
        self.registered.append(f"provider:{provider_name}")

    # ---------------------------------------------------------------- loaders
    def register_loader(self, loader: Loader) -> None:
        self._need(PluginKind.KNOWLEDGE_LOADER, "loaders:register")
        clash = set(loader.extensions) & self._host.loaders.extensions
        if clash:
            raise CapabilityDenied(f"loader would override existing extensions: {sorted(clash)}")
        self._host.loaders.register(loader)
        self._undo.append(lambda: self._host.loaders.unregister(loader))
        self.registered.append(f"loader:{','.join(loader.extensions)}")

    # ---------------------------------------------------------------- policy guards
    def add_policy_guard(self, rule: PolicyRule) -> None:
        self._need(PluginKind.POLICY_GUARD)
        if self._r.tier is not TrustTier.CORE:
            raise CapabilityDenied("policy guards require CORE trust tier")
        wrapped = _RestrictOnlyRule(self._r.name, rule)
        self._host.policy.add_rule(wrapped)
        self._undo.append(lambda: self._host.policy.remove_rule(wrapped.id))
        self.registered.append(f"policy_guard:{wrapped.id}")

    def rollback(self) -> None:
        while self._undo:
            try:
                self._undo.pop()()
            except Exception:
                log.exception("plugin rollback step failed")
        self.registered.clear()


class PluginManager:
    def __init__(
        self,
        host: HostServices,
        trust: TrustStore,
        *,
        tenant_id: str = "default",
        error_threshold: int = 5,
        violation_threshold: int = 3,
        container_runtime: ContainerPluginRuntime | None = None,
        core_version: str = __version__,
    ) -> None:
        self.host, self.trust, self.tenant_id = host, trust, tenant_id
        self.error_threshold, self.violation_threshold = error_threshold, violation_threshold
        self.container_runtime, self.core_version = container_runtime, core_version
        self.records: dict[str, PluginRecord] = {}
        self._instances: dict[str, Any] = {}
        self._registrars: dict[str, PluginRegistrar] = {}
        self._lock = threading.RLock()

    # ---------------------------------------------------------------- helpers
    def get(self, name: str) -> PluginRecord:
        try:
            return self.records[name]
        except KeyError:
            raise PluginError(f"plugin '{name}' not found") from None

    def _transition(self, rec: PluginRecord, to: PluginState, reason: str = "") -> None:
        if to not in _TRANSITIONS[rec.state]:
            raise PluginError(f"illegal transition {rec.state} -> {to}")
        frm, rec.state = rec.state, to
        rec.history.append({"ts": utcnow().isoformat(), "from": frm, "to": to, "reason": reason})
        self.host.audit.record(
            tenant_id=self.tenant_id,
            actor_id=f"plugin:{rec.name}",
            actor_type="service",
            action="plugin.state",
            resource=rec.name,
            outcome=Outcome.FAILURE if to is PluginState.FAILED else Outcome.SUCCESS,
            details={"from": frm, "to": to, "reason": reason, "version": rec.manifest.version},
        )
        self._emit(
            DomainEvent(
                type=EventType.PLUGIN_STATE_CHANGED,
                tenant_id=self.tenant_id,
                source="plugin-manager",
                payload={"plugin": rec.name, "from": frm, "to": to, "reason": reason},
            )
        )

    def _emit(self, event: DomainEvent) -> None:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            asyncio.run(self.host.bus.publish(event))
            return
        _spawn(self.host.bus.publish(event))

    def _fail(self, rec: PluginRecord, reason: str) -> None:
        rec.last_error = reason
        self._transition(rec, PluginState.FAILED, reason)

    # ---------------------------------------------------------------- discovery
    def add_from_path(self, path: str | Path) -> PluginRecord:
        root = Path(path).resolve()
        manifest = PluginManifest.load(root / MANIFEST_FILE)
        existing = self.records.get(manifest.name)
        if existing and existing.state is not PluginState.UNINSTALLED:
            raise PluginError(f"plugin '{manifest.name}' already registered")
        sig_path = root / SIG_FILE
        rec = PluginRecord(manifest=manifest, path=str(root), signature=sig_path.read_text(encoding="utf-8") if sig_path.exists() else None)
        self.records[manifest.name] = rec
        self.host.audit.record(
            tenant_id=self.tenant_id,
            actor_id="plugin-manager",
            actor_type="service",
            action="plugin.discover",
            resource=manifest.name,
            outcome=Outcome.SUCCESS,
            details={"version": manifest.version, "path": str(root)},
        )
        return rec

    def discover(self, directory: str | Path) -> list[str]:
        found: list[str] = []
        for d in sorted(Path(directory).iterdir()):
            if (d / MANIFEST_FILE).is_file():
                try:
                    found.append(self.add_from_path(d).name)
                except (PluginError, ValueError) as exc:
                    self.host.audit.record(
                        tenant_id=self.tenant_id,
                        actor_id="plugin-manager",
                        actor_type="service",
                        action="plugin.discover",
                        resource=str(d),
                        outcome=Outcome.FAILURE,
                        details={"error": str(exc)[:500]},
                    )
        return found

    # ---------------------------------------------------------------- verify
    def verify(self, name: str) -> PluginRecord:
        rec = self.get(name)
        m = rec.manifest
        try:
            verify_integrity(rec.path, m)
            rec.tier = self.trust.resolve_tier(m, rec.signature)
            if rec.tier is TrustTier.COMMUNITY and m.isolation is IsolationMode.IN_PROCESS:
                raise PluginError("community-tier plugins must declare isolation: container")
            if PluginKind.POLICY_GUARD in m.kinds and rec.tier is not TrustTier.CORE:
                raise PluginError("policy_guard plugins require CORE trust tier")
            if not version_satisfies(self.core_version, m.aicos_version):
                raise PluginError(f"requires aicos {m.aicos_version}, host is {self.core_version}")
            missing = [d for d in m.dependencies if d not in self.records]
            if missing:
                raise PluginError(f"missing dependencies: {missing}")
        except (IntegrityError, PluginError, ValueError) as exc:
            self._fail(rec, str(exc))
            raise PluginError(str(exc)) from exc
        self._transition(rec, PluginState.VERIFIED, f"tier={rec.tier}")
        return rec

    # ---------------------------------------------------------------- install (approval-gated)
    def _install_request(self, rec: PluginRecord, requester: Principal) -> ActionRequest:
        m = rec.manifest
        return ActionRequest(
            tenant_id=self.tenant_id,
            actor=requester,
            action="plugin.install",
            permission=Permission.PLUGIN_INSTALL,
            resource=m.name,
            rationale=f"Install {m.name}@{m.version} from {m.publisher}",
            payload={
                "name": m.name,
                "version": m.version,
                "digest": m.digest(),
                "tier": rec.tier,
                "isolation": m.isolation,
                "publisher": m.publisher,
                "capabilities": sorted(m.capabilities),
                "sensitive_capabilities": sorted(m.sensitive_capabilities()),
                "actions": [f"{a.action}->{a.permission}" for a in m.actions],
                "agents": [f"{s.id}:{sorted(s.permissions)}" for s in m.agents],
            },
        )

    async def request_install(self, name: str, requester: Principal) -> Proposal:
        rec = self.get(name)
        if rec.state is not PluginState.VERIFIED:
            raise PluginError(f"plugin must be verified first (state={rec.state})")
        areq = self._install_request(rec, requester)
        decision = self.host.policy.evaluate(areq)
        if decision.effect is Effect.DENY:
            raise AuthorizationError(f"install denied: {decision.reasons}")
        proposal = await self.host.approvals.submit(areq)
        rec.proposal_id = proposal.id
        self._transition(rec, PluginState.PENDING_APPROVAL, f"proposal={proposal.id}")
        return proposal

    def sync_approval(self, name: str) -> PluginRecord:
        rec = self.get(name)
        if rec.state is PluginState.PENDING_APPROVAL and rec.proposal_id:
            p = self.host.approvals.get(rec.proposal_id, self.tenant_id)
            if p.status in (ProposalStatus.REJECTED, ProposalStatus.EXPIRED, ProposalStatus.CANCELLED):
                self._transition(rec, PluginState.REJECTED, f"proposal {p.status}")
        return rec

    async def install(self, name: str, grant_token: str, executor: Principal) -> PluginRecord:
        rec = self.sync_approval(name)
        if rec.state is not PluginState.PENDING_APPROVAL or not rec.proposal_id:
            raise PluginError(f"plugin not awaiting install (state={rec.state})")
        if not executor.is_human or not executor.mfa_verified:
            raise AuthorizationError("install requires an MFA-verified human")
        proposal = self.host.approvals.get(rec.proposal_id, self.tenant_id)
        areq = proposal.action
        if areq.payload.get("digest") != rec.manifest.digest():
            self._fail(rec, "manifest changed after approval was requested")
            raise IntegrityError("manifest changed after approval was requested")
        if self.host.policy.evaluate(areq, grant_valid=True).effect is not Effect.ALLOW:
            raise AuthorizationError("install no longer permitted by policy")
        self.host.approvals.consume_grant(grant_token, areq)
        rec.granted = list(rec.manifest.capabilities)
        rec.approved_digest = rec.manifest.digest()
        self._transition(rec, PluginState.APPROVED, f"approved via {proposal.id}")
        return rec

    # ---------------------------------------------------------------- activate
    def _load_entrypoint(self, rec: PluginRecord) -> Any:
        mod_name, attr = rec.manifest.entrypoint.split(":")
        root = Path(rec.path)
        top = rec.manifest.module_root
        loaded = sys.modules.get(top)
        if loaded is not None and root not in Path(getattr(loaded, "__file__", "/") or "/").resolve().parents:
            raise PluginError(f"module name '{top}' collides with an already-loaded module")
        sys.path.insert(0, str(root))
        try:
            module = importlib.import_module(mod_name)
        finally:
            sys.path.remove(str(root))
        if root not in Path(module.__file__ or "/").resolve().parents:
            raise PluginError("entrypoint resolved outside the plugin directory")
        factory = getattr(module, attr, None)
        if factory is None:
            raise PluginError(f"entrypoint attribute '{attr}' not found")
        instance = factory()
        if not callable(getattr(instance, "activate", None)):
            raise PluginError("plugin object must define activate(ctx, registrar)")
        return instance

    def _context(self, rec: PluginRecord) -> PluginContext:
        return PluginContext(
            plugin=rec.name,
            namespace=rec.manifest.namespace,
            tenant_id=self.tenant_id,
            granted=frozenset(rec.granted),
            bus=self.host.bus,
            router=self.host.router,
            memory=self.host.memory,
            secrets=self.host.secrets,
            audit=self.host.audit,
            on_violation=self.report_violation,
        )

    async def activate(self, name: str) -> PluginRecord:
        rec = self.get(name)
        if rec.state not in (PluginState.APPROVED, PluginState.SUSPENDED):
            raise PluginError(f"cannot activate from state {rec.state}")
        try:
            verify_integrity(rec.path, PluginManifest.load(Path(rec.path) / MANIFEST_FILE))
            if PluginManifest.load(Path(rec.path) / MANIFEST_FILE).digest() != rec.approved_digest:
                raise IntegrityError("plugin changed since approval")
            inactive = [d for d in rec.manifest.dependencies if self.get(d).state is not PluginState.ACTIVE]
            if inactive:
                raise PluginError(f"dependencies not active: {inactive}")
        except (IntegrityError, PluginError) as exc:
            self._fail(rec, str(exc))
            raise PluginError(str(exc)) from exc

        if rec.manifest.isolation is IsolationMode.CONTAINER:
            if self.container_runtime is None:
                self._fail(rec, "container isolation requested but no container runtime configured")
                raise PluginError(rec.last_error or "")
            await self.container_runtime.start(rec)
            rec.errors = rec.violations = 0
            self._transition(rec, PluginState.ACTIVE, "container")
            return rec

        ctx = self._context(rec)
        registrar = PluginRegistrar(rec, self.host, ctx, self)
        try:
            instance = self._instances.get(name) or self._load_entrypoint(rec)
            result = instance.activate(ctx, registrar)
            if inspect.isawaitable(result):
                await result
        except Exception as exc:
            registrar.rollback()
            self._fail(rec, f"activation failed: {type(exc).__name__}: {exc}")
            raise PluginError(rec.last_error or "") from exc
        self._instances[name], self._registrars[name] = instance, registrar
        rec.errors = rec.violations = 0
        self._transition(rec, PluginState.ACTIVE, f"registered={registrar.registered}")
        return rec

    # ---------------------------------------------------------------- suspend / uninstall
    def _teardown(self, name: str) -> None:
        registrar = self._registrars.pop(name, None)
        if registrar:
            registrar.rollback()
        instance = self._instances.get(name)
        if instance is not None and callable(getattr(instance, "deactivate", None)):
            try:
                res = instance.deactivate()
                if inspect.isawaitable(res):
                    _spawn(res)
            except Exception:
                log.exception("plugin %s deactivate() failed", name)

    def suspend(self, name: str, reason: str) -> PluginRecord:
        with self._lock:
            rec = self.get(name)
            if rec.state is not PluginState.ACTIVE:
                return rec
            self._teardown(name)
            if rec.manifest.isolation is IsolationMode.CONTAINER and self.container_runtime:
                _spawn(self.container_runtime.stop(name))
            self._transition(rec, PluginState.SUSPENDED, reason)
            return rec

    def uninstall(self, name: str, actor: Principal) -> PluginRecord:
        if Permission.PLUGIN_MANAGE not in effective_permissions(actor):
            raise AuthorizationError("missing plugin:manage")
        rec = self.get(name)
        if rec.state is PluginState.ACTIVE:
            self.suspend(name, "uninstall")
        self._teardown(name)
        self._instances.pop(name, None)
        self._transition(rec, PluginState.UNINSTALLED, f"by {actor.id}")
        return rec

    # ---------------------------------------------------------------- health
    def report_error(self, name: str, exc: BaseException) -> None:
        rec = self.records.get(name)
        if rec is None:
            return
        rec.errors += 1
        rec.last_error = f"{type(exc).__name__}: {exc}"[:500]
        if rec.errors >= self.error_threshold and rec.state is PluginState.ACTIVE:
            self.suspend(name, f"error budget exhausted ({rec.errors} errors)")

    def report_violation(self, name: str, capability: str) -> None:
        rec = self.records.get(name)
        if rec is None:
            return
        rec.violations += 1
        self._emit(
            DomainEvent(
                type=EventType.SECURITY_ALERT,
                tenant_id=self.tenant_id,
                source="plugin-manager",
                payload={"kind": "plugin_capability_violation", "plugin": name, "capability": capability},
            )
        )
        if rec.violations >= self.violation_threshold and rec.state is PluginState.ACTIVE:
            self.suspend(name, f"capability violations ({rec.violations})")


def validate_manifest_file(path: str | Path) -> PluginManifest:
    """CLI helper used by `scripts/plugin.py validate`."""
    try:
        return PluginManifest.load(path)
    except ValueError as exc:
        raise ValidationFailed(str(exc)) from exc
