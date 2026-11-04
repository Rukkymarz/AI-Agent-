from __future__ import annotations

import pytest
from pydantic import ValidationError

from aicos.agents.base import AgentInput, AgentSpec, AutonomyLevel, Department
from aicos.agents.llm_agent import LLMAgent
from aicos.agents.registry import AgentRegistry, load_catalog
from aicos.domain.errors import NotFound, ValidationFailed
from aicos.domain.identity import Permission
from aicos.llm.providers import EchoProvider, Message
from aicos.llm.router import CircuitBreaker, LLMRouter, ModelSpec, NoModelAvailable, RouteConstraints, TaskType, classify_task
from tests.conftest import ROOT


@pytest.mark.parametrize(
    ("text", "task"),
    [
        ("fix the bug in this python function", TaskType.CODING),
        ("analyze the root cause and trade-offs of our architecture", TaskType.REASONING),
        ("draft a sales proposal for this lead", TaskType.BUSINESS),
        ("hi", TaskType.FAST),
        ("Tell me something interesting about the history of the printing press in Europe please", TaskType.GENERAL),
    ],
)
def test_classifier(text: str, task: TaskType) -> None:
    assert classify_task(text) is task


def test_routing_table_matches_spec() -> None:
    r = LLMRouter({"ollama": EchoProvider()})
    assert r.candidates(TaskType.CODING)[0].name.startswith("deepseek-coder")
    assert r.candidates(TaskType.REASONING)[0].name.startswith("deepseek-r1")
    assert r.candidates(TaskType.BUSINESS)[0].name.startswith("qwen3")
    assert r.candidates(TaskType.FAST)[0].name.startswith("mistral")
    assert r.candidates(TaskType.EMBEDDING)[0].name == "bge-m3"


async def test_fallback_and_circuit_breaker() -> None:
    t = [0.0]
    provider = EchoProvider(fail_models={"deepseek-r1:14b"})
    usage: list[tuple[str, bool]] = []
    r = LLMRouter(
        {"ollama": provider},
        breaker=CircuitBreaker(threshold=2, cooldown_s=10, clock=lambda: t[0]),
        usage_hook=lambda task, resp, model, err: usage.append((model, err is None)),
    )
    for _ in range(2):
        resp = await r.complete(TaskType.REASONING, [Message(role="user", content="why")])
        assert resp.model == "qwen3:14b"
    assert ("deepseek-r1:14b", False) in usage
    assert "deepseek-r1:14b" not in [m.name for m in r.candidates(TaskType.REASONING)]  # open
    t[0] = 11
    assert r.candidates(TaskType.REASONING)[0].name == "deepseek-r1:14b"  # half-open retry


async def test_no_model_available() -> None:
    r = LLMRouter({"ollama": EchoProvider(fail_models={m for m in ["mistral:7b", "gemma3:4b", "qwen3:14b", "llama3.1:8b"]})})
    with pytest.raises(NoModelAvailable):
        await r.complete(TaskType.FAST, [Message(role="user", content="x")])
    with pytest.raises(NoModelAvailable):
        await r.complete(TaskType.FAST, [], constraints=RouteConstraints(min_context=10_000_000))
    with pytest.raises(ValueError):
        await r.complete(TaskType.EMBEDDING, [])


def test_constraints_and_pluggable_models() -> None:
    r = LLMRouter({"ollama": EchoProvider(), "cloud": EchoProvider()})
    r.register_model(
        ModelSpec(
            name="big-cloud",
            provider="cloud",
            tasks=[TaskType.REASONING],
            local=False,
            cost_per_1k_input=0.01,
            cost_per_1k_output=0.03,
            quality=10,
        ),
        prepend=True,
    )
    assert r.candidates(TaskType.REASONING)[0].name == "deepseek-r1:14b"  # require_local default
    open_ = RouteConstraints(require_local=False)
    assert r.candidates(TaskType.REASONING, open_)[0].name == "big-cloud"
    cheap = RouteConstraints(require_local=False, max_cost_per_1k=0.001)
    assert "big-cloud" not in [m.name for m in r.candidates(TaskType.REASONING, cheap)]
    assert all(m.quality >= 8 for m in r.candidates(TaskType.GENERAL, RouteConstraints(min_quality=8)))


def test_router_from_yaml() -> None:
    r = LLMRouter.from_yaml(ROOT / "models/registry.yaml", {"ollama": EchoProvider()})
    assert len(r.models) == 10 and TaskType.CODING in r.routes


def test_catalog_complete_and_valid() -> None:
    specs = load_catalog(ROOT / "agents/catalog")
    assert len(specs) == 56
    ids = {s.id for s in specs}
    assert {"ceo", "coo", "cto", "ciso", "cfo", "cmo", "deployment-agent", "seo-agent", "support-agent"} <= ids
    assert {s.department for s in specs} == set(Department)
    from aicos.orchestrator.actions import ACTION_PERMISSIONS

    for s in specs:  # every tool is a known action and the agent holds its permission
        for tool in s.tools:
            assert tool in ACTION_PERMISSIONS, (s.id, tool)
            assert ACTION_PERMISSIONS[tool] in s.permissions, (s.id, tool)


def test_spec_rejects_forbidden_permissions() -> None:
    with pytest.raises(ValidationError):
        AgentSpec(id="evil", name="Evil", department=Department.IT, description="x", permissions=frozenset({Permission.APPROVAL_DECIDE}))


def test_registry_routing_and_errors() -> None:
    reg = AgentRegistry(LLMRouter({"ollama": EchoProvider()}))
    reg.load_catalog(ROOT / "agents/catalog")
    assert reg.route("We need SEO keyword research for the blog") == "seo-agent"
    assert reg.route("deploy the release to production with a rollback plan") == "deployment-agent"
    assert reg.route("zzz qqq") == "coo"
    assert len(reg.list(Department.EXECUTIVE)) == 6
    with pytest.raises(NotFound):
        reg.spec("nope")
    with pytest.raises(ValidationFailed):
        reg.register(reg.spec("ceo"))
    reg.unregister("coo")
    assert reg.route("zzz") != "coo"


def test_llm_agent_parse() -> None:
    body, recs, actions, invalid = LLMAgent.parse(
        'Plan.\n```json\n{"recommendations": ["r1"], "actions": [{"action": "ticket.create", "permission": "ticket:write"},'
        ' {"action": "BAD ACTION", "permission": "ticket:write"}]}\n```'
    )
    assert body == "Plan." and recs == ["r1"] and len(actions) == 1 and invalid == 1
    assert LLMAgent.parse("```json\n{broken\n```")[3] == 1
    assert LLMAgent.parse("plain") == ("plain", [], [], 0)


async def test_llm_agent_run_and_advise_mode() -> None:
    reply = 'ok\n```json\n{"actions": [{"action": "ticket.create", "permission": "ticket:write"}]}\n```'
    provider = EchoProvider(responder=lambda m, msgs: reply)
    router = LLMRouter({"ollama": provider})
    spec = AgentSpec(
        id="t-agent",
        name="T",
        department=Department.SUPPORT,
        description="d",
        tools=["ticket.create"],
        permissions=frozenset({Permission.TICKET_WRITE}),
        max_actions=1,
    )
    out = await LLMAgent(spec, router).run(
        AgentInput(
            task_id="t1",
            objective="help",
            context=["CTX"],
            policies=["P1"],
            granted_permissions=[Permission.TICKET_WRITE],
            allowed_tools=["ticket.create"],
        )
    )
    assert len(out.proposed_actions) == 1 and out.metrics["model"]
    system, user = provider.calls[-1][1]
    assert "cannot execute anything" in system.content and "P1" in system.content and "CTX" in user.content
    advise = spec.model_copy(update={"autonomy": AutonomyLevel.ADVISE})
    out2 = await LLMAgent(advise, router).run(AgentInput(task_id="t2", objective="x"))
    assert out2.proposed_actions == []
