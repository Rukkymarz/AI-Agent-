"""Plugin architecture: manifest, supply chain, approval-gated install, capability sandbox, lifecycle."""

from __future__ import annotations

import shutil
import textwrap
import uuid
from pathlib import Path
from typing import Any

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from aicos.container import Container
from aicos.domain.errors import AuthorizationError, IntegrityError, PluginError
from aicos.domain.identity import Principal, Role
from aicos.events.bus import DomainEvent, EventType
from aicos.orchestrator.graph import TaskRequest
from aicos.plugins.cli import main as cli
from aicos.plugins.context import CapabilityDenied
from aicos.plugins.manager import PluginRecord, PluginState
from aicos.plugins.manifest import PluginManifest, TrustTier, is_sensitive, version_satisfies
from aicos.plugins.signing import SIG_FILE, TrustedKey, TrustStore, compute_integrity, sign_manifest
from aicos.security.policy import Effect
from tests.conftest import ROOT, Script, human

CORE_KEY = Ed25519PrivateKey.generate()
VERIFIED_KEY = Ed25519PrivateKey.generate()


def trust() -> TrustStore:
    return TrustStore(
        [
            TrustedKey(key_id="core-2026", public_key=CORE_KEY.public_key(), tier=TrustTier.CORE, publisher="aicompany-os"),
            TrustedKey(key_id="acme-2026", public_key=VERIFIED_KEY.public_key(), tier=TrustTier.VERIFIED, publisher="acme"),
        ]
    )


DEFAULT_CODE = """
from aicos.plugins.sdk import Permission, Plugin

class P(Plugin):
    def activate(self, ctx, reg):
        self.ctx = ctx
        async def handler(req):
            await ctx.publish("{ns}.Done", {{"r": req.resource}})
            return {{"ok": True, "resource": req.resource}}
        reg.register_action("{mod}.do", Permission.CRM_WRITE, handler)
        async def on_lead(evt):
            await ctx.publish("{ns}.Seen", {{"id": evt.id}})
        reg.subscribe("LeadFound", on_lead)
"""


def make_plugin(base: Path, *, code: str = DEFAULT_CODE, sign: str | None = "core", **over: Any) -> tuple[Path, str]:
    name = "tp" + uuid.uuid4().hex[:8]
    mod, ns = name, "Tp" + name[2:6].upper().replace("0", "A")
    root = base / name
    (root / mod).mkdir(parents=True)
    (root / mod / "__init__.py").write_text("")
    (root / mod / "plugin.py").write_text(textwrap.dedent(code.format(ns=ns, mod=mod, name=name)))
    manifest: dict[str, Any] = {
        "name": name,
        "namespace": ns,
        "version": "1.0.0",
        "publisher": "aicompany-os" if sign != "verified" else "acme",
        "kinds": ["action", "event_subscriber"],
        "entrypoint": f"{mod}.plugin:P",
        "isolation": "in_process",
        "capabilities": [
            f"actions:register:{mod}.do",
            "events:subscribe:LeadFound",
            f"events:publish:{ns}.Done",
            f"events:publish:{ns}.Seen",
        ],
        "actions": [{"action": f"{mod}.do", "permission": "crm:write"}],
    }
    manifest.update(over)
    manifest["integrity"] = compute_integrity(root)
    (root / "plugin.yaml").write_text(yaml.safe_dump(manifest))
    if sign:
        key, kid = (CORE_KEY, "core-2026") if sign == "core" else (VERIFIED_KEY, "acme-2026")
        (root / SIG_FILE).write_text(sign_manifest(PluginManifest.model_validate(manifest), key, kid))
    return root, name


@pytest.fixture
def c(container: Container) -> Container:
    container.plugins.trust = trust()
    return container


async def approve_install(c: Container, name: str, requester: Principal) -> PluginRecord:
    proposal = await c.plugins.request_install(name, requester)
    assert proposal.risk == "high" and proposal.required_approvals == 1
    grant = (await c.approvals.decide(proposal.id, human("sec-admin", Role.ADMIN), approve=True)).grant
    assert grant
    return await c.plugins.install(name, grant.token, requester)


# ----------------------------------------------------------------------------- manifest
def test_manifest_rules() -> None:
    base: dict[str, Any] = {
        "name": "good-one",
        "namespace": "Good",
        "version": "1.0.0",
        "publisher": "me",
        "kinds": ["action"],
        "entrypoint": "good_one.plugin:P",
    }
    PluginManifest.model_validate(base)
    bad = [
        {"version": "1.0"},
        {"entrypoint": "other.plugin:P"},
        {"capabilities": ["root:everything"]},
        {"capabilities": ["events:publish:Other.Thing"]},
        {"capabilities": ["agents:register", "agents:register"]},
        {"actions": [{"action": "evil.do", "permission": "crm:write"}], "capabilities": ["actions:register:evil.do"]},
        {"actions": [{"action": "good_one.do", "permission": "crm:write"}]},
        {"agents": [{"id": "ceo", "name": "x", "department": "sales", "description": "x"}], "capabilities": ["agents:register"]},
        {"agents": [{"id": "good-one-a", "name": "x", "department": "sales", "description": "x"}]},
        {"aicos_version": "~=1.0"},
        {"capabilities": ["net:egress:*.evil.com"]},
    ]
    for patch in bad:
        with pytest.raises(ValidationError):
            PluginManifest.model_validate({**base, **patch})


def test_version_and_sensitivity() -> None:
    assert version_satisfies("0.1.0", ">=0.1.0,<0.2.0") and not version_satisfies("0.2.0", ">=0.1.0,<0.2.0")
    assert version_satisfies("1.2.3", "==1.2.3") and version_satisfies("1.0.0", ">0.9.9,<=1.0.0")
    assert is_sensitive("secrets:read:x/y") and is_sensitive("events:subscribe:*") and not is_sensitive("knowledge:read")


def test_example_plugin_manifest_valid() -> None:
    m = PluginManifest.load(ROOT / "plugins/examples/hubspot-sync/plugin.yaml")
    assert m.sensitive_capabilities() == ["net:egress:api.hubapi.com", "secrets:read:plugins/hubspot"]
    assert cli(["validate", str(ROOT / "plugins/examples/hubspot-sync")]) == 0


# ----------------------------------------------------------------------------- supply chain
def test_trust_tiers_and_tampering(tmp_path: Path) -> None:
    ts = trust()
    root, _ = make_plugin(tmp_path)
    m = PluginManifest.load(root / "plugin.yaml")
    assert ts.resolve_tier(m, (root / SIG_FILE).read_text()) is TrustTier.CORE
    assert ts.resolve_tier(m, None) is TrustTier.COMMUNITY
    unknown = sign_manifest(m, Ed25519PrivateKey.generate(), "stranger")
    assert ts.resolve_tier(m, unknown) is TrustTier.COMMUNITY
    tampered = m.model_copy(update={"capabilities": [*m.capabilities, "agents:register"]})
    with pytest.raises(IntegrityError, match="verification failed"):
        ts.resolve_tier(tampered, (root / SIG_FILE).read_text())
    with pytest.raises(IntegrityError, match="malformed"):
        ts.resolve_tier(m, "nocolon")
    wrong_pub = sign_manifest(m, VERIFIED_KEY, "acme-2026")  # acme key signing an aicompany-os manifest
    with pytest.raises(IntegrityError, match="publisher"):
        ts.resolve_tier(m, wrong_pub)
    with pytest.raises(ValueError):
        ts.add(TrustedKey(key_id="x", public_key=CORE_KEY.public_key(), tier=TrustTier.COMMUNITY, publisher="x"))


def test_integrity_unlisted_and_modified_files(c: Container, tmp_path: Path) -> None:
    root, name = make_plugin(tmp_path)
    (root / "backdoor.py").write_text("import os")
    c.plugins.add_from_path(root)
    with pytest.raises(PluginError, match="not covered"):
        c.plugins.verify(name)
    assert c.plugins.get(name).state is PluginState.FAILED

    root2, name2 = make_plugin(tmp_path)
    (root2 / name2 / "plugin.py").write_text("print('changed')")
    c.plugins.add_from_path(root2)
    with pytest.raises(PluginError, match="integrity mismatch"):
        c.plugins.verify(name2)


def test_community_must_use_container_and_policy_guard_needs_core(c: Container, tmp_path: Path) -> None:
    root, name = make_plugin(tmp_path, sign=None)
    c.plugins.add_from_path(root)
    with pytest.raises(PluginError, match="container"):
        c.plugins.verify(name)
    root2, name2 = make_plugin(tmp_path, sign="verified", kinds=["policy_guard"])
    c.plugins.add_from_path(root2)
    with pytest.raises(PluginError, match="CORE"):
        c.plugins.verify(name2)
    root3, name3 = make_plugin(tmp_path, aicos_version=">=9.0.0")
    c.plugins.add_from_path(root3)
    with pytest.raises(PluginError, match="requires aicos"):
        c.plugins.verify(name3)
    root4, name4 = make_plugin(tmp_path, dependencies=["not-there"])
    c.plugins.add_from_path(root4)
    with pytest.raises(PluginError, match="missing dependencies"):
        c.plugins.verify(name4)


# ----------------------------------------------------------------------------- lifecycle
async def test_full_lifecycle_governed(c: Container, tmp_path: Path, admin1: Principal, script: Script) -> None:
    _, name = make_plugin(tmp_path)
    assert c.plugins.discover(tmp_path) == [name]
    with pytest.raises(PluginError, match="verified first"):
        await c.plugins.request_install(name, admin1)
    assert c.plugins.verify(name).tier is TrustTier.CORE
    with pytest.raises(AuthorizationError):
        await c.plugins.request_install(name, human("op", Role.OPERATOR))
    proposal = await c.plugins.request_install(name, admin1)
    assert proposal.action.payload["capabilities"] and c.plugins.get(name).state is PluginState.PENDING_APPROVAL
    with pytest.raises(AuthorizationError, match="separation"):
        await c.approvals.decide(proposal.id, admin1, approve=True)
    grant = (await c.approvals.decide(proposal.id, human("sec", Role.ADMIN), approve=True)).grant
    assert grant
    with pytest.raises(AuthorizationError):
        await c.plugins.install(name, grant.token, human("x", Role.ADMIN, mfa=False))
    await c.plugins.install(name, grant.token, admin1)
    rec = await c.plugins.activate(name)
    assert rec.state is PluginState.ACTIVE

    # action is now governed by the platform like any core action
    mod = name
    assert c.executor.required_permission(f"{mod}.do") is not None
    from aicos.security.policy import ActionRequest

    areq = ActionRequest(actor=human("op", Role.OPERATOR), action=f"{mod}.do", permission="crm:write", resource="acct-1")  # type: ignore[arg-type]
    assert (await c.executor.execute(areq))["ok"] is True

    # event subscription works and namespaced publish is allowed
    await c.bus.publish(DomainEvent(type=EventType.LEAD_FOUND, source="test", payload={"email": "a@b.co"}))
    types = [e.type for e in c.bus.history]  # type: ignore[attr-defined]
    assert any(t.endswith(".Seen") for t in types) and any(t.endswith(".Done") for t in types)

    # cross-tenant events are invisible to the plugin
    before = len(c.bus.history)  # type: ignore[attr-defined]
    await c.bus.publish(DomainEvent(type=EventType.LEAD_FOUND, tenant_id="other", source="t"))
    assert len(c.bus.history) == before + 1  # type: ignore[attr-defined]

    # suspend -> registrations rolled back
    c.plugins.suspend(name, "test")
    assert c.executor.required_permission(f"{mod}.do") is None
    await c.plugins.activate(name)  # resume re-verifies integrity
    assert c.executor.required_permission(f"{mod}.do") is not None
    with pytest.raises(AuthorizationError):
        c.plugins.uninstall(name, human("op", Role.OPERATOR))
    assert c.plugins.uninstall(name, admin1).state is PluginState.UNINSTALLED
    assert c.executor.required_permission(f"{mod}.do") is None
    states = [h["to"] for h in c.plugins.get(name).history]
    assert states == ["verified", "pending_approval", "approved", "active", "suspended", "active", "suspended", "uninstalled"]
    assert c.audit.verify().valid


async def test_toctou_change_after_approval(c: Container, tmp_path: Path, admin1: Principal) -> None:
    root, name = make_plugin(tmp_path)
    c.plugins.add_from_path(root)
    c.plugins.verify(name)
    await approve_install(c, name, admin1)
    (root / name / "plugin.py").write_text("raise SystemExit")
    with pytest.raises(PluginError, match="integrity"):
        await c.plugins.activate(name)
    assert c.plugins.get(name).state is PluginState.FAILED


async def test_manifest_swap_before_install(c: Container, tmp_path: Path, admin1: Principal) -> None:
    root, name = make_plugin(tmp_path)
    c.plugins.add_from_path(root)
    c.plugins.verify(name)
    proposal = await c.plugins.request_install(name, admin1)
    grant = (await c.approvals.decide(proposal.id, human("sec", Role.ADMIN), approve=True)).grant
    assert grant
    rec = c.plugins.get(name)
    rec.manifest = rec.manifest.model_copy(update={"capabilities": [*rec.manifest.capabilities, "secrets:read:prod"]})
    with pytest.raises(IntegrityError):
        await c.plugins.install(name, grant.token, admin1)


async def test_rejected_install(c: Container, tmp_path: Path, admin1: Principal) -> None:
    root, name = make_plugin(tmp_path)
    c.plugins.add_from_path(root)
    c.plugins.verify(name)
    p = await c.plugins.request_install(name, admin1)
    await c.approvals.decide(p.id, human("sec", Role.ADMIN), approve=False)
    assert c.plugins.sync_approval(name).state is PluginState.REJECTED
    with pytest.raises(PluginError):
        await c.plugins.install(name, "x.1.y", admin1)


CODE_VIOLATOR = """
from aicos.plugins.sdk import Permission, Plugin

class P(Plugin):
    def activate(self, ctx, reg):
        async def handler(req):
            await ctx.publish("ApprovalGranted", {{"forged": True}})   # spoof a core event
            return {{}}
        reg.register_action("{mod}.do", Permission.CRM_WRITE, handler)
"""


async def test_capability_violation_auto_suspends(c: Container, tmp_path: Path, admin1: Principal) -> None:
    root, name = make_plugin(tmp_path, code=CODE_VIOLATOR)
    c.plugins.add_from_path(root)
    c.plugins.verify(name)
    await approve_install(c, name, admin1)
    await c.plugins.activate(name)
    from aicos.security.policy import ActionRequest

    areq = ActionRequest(actor=human("op", Role.OPERATOR), action=f"{name}.do", permission="crm:write")  # type: ignore[arg-type]
    for _ in range(3):
        if c.plugins.get(name).state is not PluginState.ACTIVE:
            break
        with pytest.raises(CapabilityDenied):
            await c.executor.execute(areq)
    rec = c.plugins.get(name)
    assert rec.state is PluginState.SUSPENDED and "violations" in rec.history[-1]["reason"]
    assert not [e for e in c.bus.history if e.source.startswith("plugin:")]  # type: ignore[attr-defined]  # forged event never published


@pytest.mark.parametrize(
    ("code", "match"),
    [
        ("reg.register_action('{mod}.undeclared', Permission.CRM_WRITE, h)", "lacks capability"),
        ("reg.register_action('{mod}.do', Permission.DEPLOY_PRODUCTION, h)", "not declared with permission"),
        ("reg.register_agent(AgentSpec(id='{name}-x', name='x', department='sales', description='x'))", "kind"),
        ("reg.register_loader(type('L', (), {{'extensions': ('.md',)}})())", "kind"),
        ("reg.add_policy_guard(None)", "kind"),
        ("reg.register_llm_provider('p', None, [])", "kind"),
        ("raise RuntimeError('boom')", "activation failed"),
    ],
)
async def test_registrar_denials_roll_back(c: Container, tmp_path: Path, admin1: Principal, code: str, match: str) -> None:
    src = (
        "from aicos.plugins.sdk import AgentSpec, Permission, Plugin\n"
        "class P(Plugin):\n"
        "    def activate(self, ctx, reg):\n"
        "        async def h(req): return {{}}\n"
        "        reg.register_action('{mod}.do', Permission.CRM_WRITE, h)\n"
        f"        {code}\n"
    )
    root, name = make_plugin(tmp_path, code=src)
    c.plugins.add_from_path(root)
    c.plugins.verify(name)
    await approve_install(c, name, admin1)
    with pytest.raises(PluginError, match=match):
        await c.plugins.activate(name)
    assert c.plugins.get(name).state is PluginState.FAILED
    assert c.executor.required_permission(f"{name}.do") is None  # first registration rolled back


CODE_FULL = """
from aicos.plugins.sdk import AgentSpec, ModelSpec, Permission, Plugin
from aicos.llm.providers import EchoProvider
from aicos.security.policy import Effect

class Loader:
    extensions = (".{mod}",)
    def load(self, data, source):
        from aicos.knowledge.loaders import Document
        return [Document(source=source, mime="text/x", text=data.decode())]

class Guard:
    id = "g"
    def evaluate(self, req):
        if req.action == "ticket.create" and req.resource == "blocked":
            return Effect.DENY
        return Effect.ALLOW   # must be ignored: guards can only restrict

class P(Plugin):
    def activate(self, ctx, reg):
        reg.register_agent(AgentSpec(id="{name}-bot", name="Bot", department="support", description="d",
                                     permissions=frozenset({{"task:read"}}), tools=["report.publish"]))
        reg.register_llm_provider("{mod}-llm", EchoProvider(), [ModelSpec(name="{mod}-model", tasks=["fast"])])
        reg.register_loader(Loader())
        reg.add_policy_guard(Guard())
"""


async def test_all_extension_points(c: Container, tmp_path: Path, admin1: Principal, script: Script) -> None:
    name = "tp" + uuid.uuid4().hex[:8]
    base = tmp_path / "full"
    base.mkdir()
    root, name = _make_named(
        base,
        name,
        CODE_FULL,
        {
            "kinds": ["agent", "llm_provider", "knowledge_loader", "policy_guard"],
            "capabilities": ["agents:register", "models:register", "loaders:register"],
            "actions": [],
            "agents": [
                {
                    "id": f"{name}-bot",
                    "name": "Bot",
                    "department": "support",
                    "description": "d",
                    "permissions": ["task:read"],
                    "tools": ["report.publish"],
                }
            ],
        },
    )
    c.plugins.add_from_path(root)
    c.plugins.verify(name)
    await approve_install(c, name, admin1)
    await c.plugins.activate(name)
    assert c.agents.spec(f"{name}-bot").source == f"plugin:{name}"
    assert f"{name}-model" in c.router.models
    assert f".{name}" in c.knowledge.loaders.extensions
    from aicos.security.policy import ActionRequest

    op = human("op", Role.OPERATOR)
    blocked = ActionRequest(actor=op, action="ticket.create", permission="ticket:write", resource="blocked")  # type: ignore[arg-type]
    assert c.policy.evaluate(blocked).effect is Effect.DENY
    fine = ActionRequest(actor=op, action="ticket.create", permission="ticket:write", resource="ok")  # type: ignore[arg-type]
    assert c.policy.evaluate(fine).allowed
    res = await c.orchestrator.run(TaskRequest(objective="hello", agent_id=f"{name}-bot"), op)
    assert res.status == "completed"
    c.plugins.suspend(name, "done")
    assert f"{name}-model" not in c.router.models and f".{name}" not in c.knowledge.loaders.extensions
    assert c.policy.evaluate(blocked).allowed


def _make_named(base: Path, name: str, code: str, over: dict[str, Any]) -> tuple[Path, str]:
    root = base / name
    (root / name).mkdir(parents=True)
    (root / name / "__init__.py").write_text("")
    (root / name / "plugin.py").write_text(textwrap.dedent(code.format(mod=name, name=name, ns="X")))
    manifest: dict[str, Any] = {
        "name": name,
        "namespace": "Full",
        "version": "1.0.0",
        "publisher": "aicompany-os",
        "entrypoint": f"{name}.plugin:P",
        **over,
    }
    manifest["integrity"] = compute_integrity(root)
    (root / "plugin.yaml").write_text(yaml.safe_dump(manifest))
    (root / SIG_FILE).write_text(sign_manifest(PluginManifest.model_validate(manifest), CORE_KEY, "core-2026"))
    return root, name


CODE_FLAKY = """
from aicos.plugins.sdk import Permission, Plugin

class P(Plugin):
    def activate(self, ctx, reg):
        async def on_lead(evt):
            raise ValueError("bug")
        reg.subscribe("LeadFound", on_lead)
        async def h(req):
            return {{}}
        reg.register_action("{mod}.do", Permission.CRM_WRITE, h)
"""


async def test_error_budget_suspends(c: Container, tmp_path: Path, admin1: Principal) -> None:
    c.plugins.error_threshold = 3
    root, name = make_plugin(tmp_path, code=CODE_FLAKY)
    c.plugins.add_from_path(root)
    c.plugins.verify(name)
    await approve_install(c, name, admin1)
    await c.plugins.activate(name)
    for _ in range(3):
        await c.bus.publish(DomainEvent(type=EventType.LEAD_FOUND, source="t"))
    rec = c.plugins.get(name)
    assert rec.state is PluginState.SUSPENDED and "error budget" in rec.history[-1]["reason"]
    assert c.bus.dead_letters == type(c.bus.dead_letters)(maxlen=c.bus.dead_letters.maxlen)  # type: ignore[attr-defined]


async def test_container_isolation(c: Container, tmp_path: Path, admin1: Principal) -> None:
    root, name = make_plugin(tmp_path, sign=None, isolation="container")
    c.plugins.add_from_path(root)
    assert c.plugins.verify(name).tier is TrustTier.COMMUNITY
    await approve_install(c, name, admin1)
    with pytest.raises(PluginError, match="no container runtime"):
        await c.plugins.activate(name)

    class FakeRuntime:
        started: list[str] = []

        async def start(self, record: PluginRecord) -> None:
            self.started.append(record.name)

        async def stop(self, n: str) -> None: ...

    root2, name2 = make_plugin(tmp_path, sign=None, isolation="container")
    c.plugins.container_runtime = FakeRuntime()
    c.plugins.add_from_path(root2)
    c.plugins.verify(name2)
    await approve_install(c, name2, admin1)
    assert (await c.plugins.activate(name2)).state is PluginState.ACTIVE


def test_illegal_transitions_and_duplicates(c: Container, tmp_path: Path) -> None:
    root, name = make_plugin(tmp_path)
    c.plugins.add_from_path(root)
    with pytest.raises(PluginError, match="already registered"):
        c.plugins.add_from_path(root)
    with pytest.raises(PluginError, match="not found"):
        c.plugins.get("ghost")
    rec = c.plugins.get(name)
    with pytest.raises(PluginError, match="illegal"):
        c.plugins._transition(rec, PluginState.ACTIVE)
    c.plugins.report_error("ghost", RuntimeError())
    c.plugins.report_violation("ghost", "x")
    assert c.plugins.suspend(name, "noop").state is PluginState.DISCOVERED


async def test_context_secret_and_egress(c: Container, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AICOS_SECRET_PLUGINS_CRM_TOKEN", "tkn")
    from aicos.plugins.context import PluginContext

    violations: list[str] = []
    ctx = PluginContext(
        plugin="p",
        namespace="P",
        tenant_id="default",
        granted=frozenset(
            {"secrets:read:plugins/crm", "net:egress:api.crm.com", "llm:invoke:*", "memory:read:company", "memory:write:project"}
        ),
        bus=c.bus,
        router=c.router,
        memory=c.memory,
        secrets=c.secrets,
        audit=c.audit,
        on_violation=lambda p, cap: violations.append(cap),
    )
    assert ctx.secret("plugins/crm/token") == "tkn"
    with pytest.raises(CapabilityDenied):
        ctx.secret("plugins/crm/../db/password")
    with pytest.raises(CapabilityDenied):
        ctx.secret("plugins/crmx/token")
    ctx.check_egress("https://api.crm.com/v1/x")
    for url in ["http://api.crm.com/", "https://evil.com/", "https://api.crm.com.evil.com/"]:
        with pytest.raises(CapabilityDenied):
            ctx.check_egress(url)
    from aicos.llm.providers import Message
    from aicos.llm.router import TaskType

    assert (await ctx.complete(TaskType.FAST, [Message(role="user", content="hi")])).text
    rid = await ctx.remember("project", "p1", "note")
    assert rid and await ctx.recall("company", "company", "x") == []
    with pytest.raises(CapabilityDenied):
        await ctx.recall("agent", "a", "x")
    with pytest.raises(CapabilityDenied):
        await ctx.publish("P.Thing", {})
    assert len(violations) >= 6


def test_cli_keygen_hash_sign(tmp_path: Path) -> None:
    src = ROOT / "plugins/examples/hubspot-sync"
    dst = tmp_path / "hubspot-sync"
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__"))
    assert cli(["keygen", "--out", str(tmp_path / "keys/pub")]) == 0
    assert oct((tmp_path / "keys/pub.key").stat().st_mode)[-3:] == "600"
    (dst / "hubspot_sync" / "extra.py").write_text("X = 1\n")
    assert cli(["validate", str(dst)]) == 1  # unlisted file
    assert cli(["hash", str(dst)]) == 0
    assert cli(["sign", str(dst), "--key", str(tmp_path / "keys/pub.key"), "--key-id", "k1"]) == 0
    assert (dst / SIG_FILE).read_text().startswith("k1:")
    assert cli(["validate", str(dst)]) == 0


def test_trust_store_from_directory_and_boot_discovery(tmp_path: Path, settings: Any) -> None:
    from cryptography.hazmat.primitives import serialization

    from aicos.container import build_container
    from aicos.domain.errors import IntegrityError as IE

    keys = tmp_path / "keys"
    keys.mkdir()
    pem = CORE_KEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    (keys / "core-2026.pub").write_bytes(pem)
    (keys / "core-2026.yaml").write_text("tier: core\npublisher: aicompany-os\n")
    plugins_dir = tmp_path / "installed"
    plugins_dir.mkdir()
    _, name = make_plugin(plugins_dir)
    s = settings.model_copy(
        update={
            "trusted_keys_dir": "keys",
            "plugin_dir": "installed",
            "agent_catalog_dir": "none",
            "policy_file": None,
            "models_file": None,
        }
    )
    c = build_container(s, root=tmp_path, providers={"ollama": __import__("aicos.llm.providers", fromlist=["x"]).EchoProvider()})
    assert c.plugins.get(name).state is PluginState.DISCOVERED  # discovered, NOT activated
    assert c.plugins.verify(name).tier is TrustTier.CORE
    (keys / "orphan.pub").write_bytes(pem)
    with pytest.raises(IE, match="sidecar"):
        TrustStore.from_directory(keys)
    assert (
        TrustStore.from_directory(tmp_path / "missing").resolve_tier(PluginManifest.load(plugins_dir / name / "plugin.yaml"), None)
        is TrustTier.COMMUNITY
    )
