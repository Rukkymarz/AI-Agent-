"""LangGraph orchestrator — the only component that can turn agent intent into effects.

  START
    │
screen_input ──blocked──────────────┐
    │                               │
authorize ─────denied───────────────┤
    │                               │
retrieve (memory + knowledge, wrapped as untrusted)
    │                               │
execute_agent ─error/timeout────────┤
    │                               │
screen_output (secret redaction)    │
    │                               │
govern (per action: catalog -> policy -> ALLOW: execute | APPROVAL: propose | DENY)
    │                               │
finalize ◄──────────────────────────┘ (audit, memory, events, metrics)
    │
   END
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Literal, TypedDict

from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel, Field

from aicos.agents.base import AgentInput, AgentOutput, AgentSpec
from aicos.agents.registry import AgentRegistry
from aicos.approvals.gateway import ApprovalGateway
from aicos.domain.common import canonical_json, new_id
from aicos.domain.errors import AicosError, AuthorizationError, NotFound
from aicos.domain.identity import Permission, Principal
from aicos.events.bus import DomainEvent, EventBus, EventType
from aicos.knowledge.pipeline import KnowledgeService
from aicos.memory.service import MemoryService, visible_scopes
from aicos.memory.store import MemoryScope
from aicos.observability.metrics import Metrics, NoopMetrics
from aicos.orchestrator.actions import ActionExecutor
from aicos.security.audit import AuditLog, Outcome
from aicos.security.firewall import PromptFirewall, ScanResult
from aicos.security.policy import ActionRequest, Effect, PolicyEngine
from aicos.security.rbac import delegated_permissions, effective_permissions

ActionStatus = Literal["executed", "pending_approval", "denied", "failed"]
TaskStatus = Literal["completed", "rejected", "failed"]


class TaskRequest(BaseModel):
    id: str = Field(default_factory=lambda: new_id("task"))
    tenant_id: str = "default"
    objective: str = Field(min_length=1, max_length=20_000)
    agent_id: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9-]{1,62}$")
    project_id: str | None = Field(default=None, max_length=100)
    conversation_id: str | None = Field(default=None, max_length=100)


class ActionOutcome(BaseModel):
    action: str
    status: ActionStatus
    reasons: list[str] = Field(default_factory=list)
    proposal_id: str | None = None
    result: dict[str, Any] | None = None


class TaskResult(BaseModel):
    task_id: str
    status: TaskStatus
    agent_id: str | None = None
    output: str = ""
    recommendations: list[str] = Field(default_factory=list)
    actions: list[ActionOutcome] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    security_findings: list[str] = Field(default_factory=list)


class OrchestratorState(TypedDict, total=False):
    request: TaskRequest
    principal: Principal
    started: float
    status: str
    error: str
    agent_id: str
    granted: list[Permission]
    scan: ScanResult
    context: list[str]
    output: AgentOutput
    outcomes: list[ActionOutcome]
    findings: list[str]
    result: TaskResult


class Orchestrator:
    def __init__(
        self,
        *,
        agents: AgentRegistry,
        policy: PolicyEngine,
        approvals: ApprovalGateway,
        audit: AuditLog,
        bus: EventBus,
        firewall: PromptFirewall,
        memory: MemoryService,
        knowledge: KnowledgeService,
        executor: ActionExecutor,
        metrics: Metrics | None = None,
        policy_notes: list[str] | None = None,
        agent_timeout_s: float = 180.0,
        max_context_chars: int = 12_000,
    ) -> None:
        self.agents, self.policy, self.approvals, self.audit = agents, policy, approvals, audit
        self.bus, self.firewall, self.memory, self.knowledge = bus, firewall, memory, knowledge
        self.executor, self.metrics = executor, metrics or NoopMetrics()
        self.policy_notes = policy_notes or [
            "Critical actions (deploys, payments, permission changes, merges, mass email) require human approval.",
            "Customer PII must not leave the platform.",
        ]
        self.agent_timeout_s, self.max_context_chars = agent_timeout_s, max_context_chars
        self.graph = self._build()

    # ------------------------------------------------------------------ graph
    def _build(self) -> Any:
        g: StateGraph[OrchestratorState] = StateGraph(OrchestratorState)
        for name in ("screen_input", "authorize", "retrieve", "execute_agent", "screen_output", "govern", "finalize"):
            g.add_node(name, getattr(self, f"_n_{name}"))
        g.add_edge(START, "screen_input")
        g.add_conditional_edges("screen_input", self._next, {"go": "authorize", "stop": "finalize"})
        g.add_conditional_edges("authorize", self._next, {"go": "retrieve", "stop": "finalize"})
        g.add_edge("retrieve", "execute_agent")
        g.add_conditional_edges("execute_agent", self._next, {"go": "screen_output", "stop": "finalize"})
        g.add_edge("screen_output", "govern")
        g.add_edge("govern", "finalize")
        g.add_edge("finalize", END)
        return g.compile()

    @staticmethod
    def _next(state: OrchestratorState) -> str:
        return "go" if state.get("status") == "running" else "stop"

    async def run(self, request: TaskRequest, principal: Principal) -> TaskResult:
        state: OrchestratorState = {
            "request": request,
            "principal": principal,
            "started": time.perf_counter(),
            "status": "running",
            "outcomes": [],
            "findings": [],
        }
        final = await self.graph.ainvoke(state)
        result: TaskResult = final["result"]
        return result

    # ------------------------------------------------------------------ nodes
    async def _n_screen_input(self, s: OrchestratorState) -> dict[str, Any]:
        req, who = s["request"], s["principal"]
        scan = self.firewall.scan(req.objective)
        if scan.allowed:
            return {"scan": scan}
        threats = sorted(scan.threats)
        for t in threats:
            self.metrics.firewall_block(t)
        self.audit.record(
            tenant_id=req.tenant_id,
            actor_id=who.id,
            actor_type=who.type,
            action="task.submit",
            resource=req.id,
            outcome=Outcome.BLOCKED,
            details={"threats": threats, "score": scan.score},
        )
        await self.bus.publish(
            DomainEvent(
                type=EventType.SECURITY_ALERT,
                tenant_id=req.tenant_id,
                source="prompt-firewall",
                correlation_id=req.id,
                payload={"kind": "prompt_injection", "threats": threats, "principal": who.id, "score": scan.score},
            )
        )
        return {"scan": scan, "status": "rejected", "error": "request blocked by prompt firewall", "findings": threats}

    async def _n_authorize(self, s: OrchestratorState) -> dict[str, Any]:
        req, who = s["request"], s["principal"]
        try:
            if who.tenant_id != req.tenant_id:
                raise AuthorizationError("tenant mismatch")
            if not who.is_human:
                raise AuthorizationError("tasks must be submitted by (or on behalf of) a human")
            perms = effective_permissions(who)
            if not {Permission.TASK_SUBMIT, Permission.AGENT_INVOKE} <= perms:
                raise AuthorizationError("missing task:submit / agent:invoke")
            agent_id = req.agent_id or self.agents.route(req.objective)
            spec = self.agents.spec(agent_id)
        except (AuthorizationError, NotFound) as exc:
            self.audit.record(
                tenant_id=req.tenant_id,
                actor_id=who.id,
                actor_type=who.type,
                action="task.submit",
                resource=req.id,
                outcome=Outcome.DENIED,
                details={"reason": str(exc)},
            )
            return {"status": "rejected", "error": str(exc)}
        granted = sorted(delegated_permissions(spec.principal(req.tenant_id), who))
        self.audit.record(
            tenant_id=req.tenant_id,
            actor_id=who.id,
            actor_type=who.type,
            action="task.submit",
            resource=req.id,
            outcome=Outcome.SUCCESS,
            details={"agent": agent_id},
        )
        await self.bus.publish(
            DomainEvent(
                type=EventType.TASK_SUBMITTED,
                tenant_id=req.tenant_id,
                source="orchestrator",
                correlation_id=req.id,
                payload={"agent": agent_id, "principal": who.id},
            )
        )
        return {"agent_id": agent_id, "granted": granted}

    async def _n_retrieve(self, s: OrchestratorState) -> dict[str, Any]:
        req, who = s["request"], s["principal"]
        keys = visible_scopes(agent_id=s["agent_id"], conversation_id=req.conversation_id, project_id=req.project_id, human_id=who.id)
        context: list[str] = []
        if Permission.KNOWLEDGE_READ in s["granted"]:
            for chunk in await self.knowledge.search(tenant_id=req.tenant_id, query=req.objective, keys=keys, k=6):
                context.append(chunk.text)
        budget, trimmed = self.max_context_chars, []
        for c in context:
            if budget - len(c) < 0:
                break
            trimmed.append(c)
            budget -= len(c)
        return {"context": trimmed}

    async def _n_execute_agent(self, s: OrchestratorState) -> dict[str, Any]:
        req, spec = s["request"], self.agents.spec(s["agent_id"])
        agent = self.agents.get(spec.id)
        task = AgentInput(
            task_id=req.id,
            objective=req.objective,
            context=s.get("context", []),
            policies=self.policy_notes,
            granted_permissions=s["granted"],
            allowed_tools=spec.tools,
            metadata={"project_id": req.project_id},
        )
        try:
            output = await asyncio.wait_for(agent.run(task), timeout=self.agent_timeout_s)
        except TimeoutError:
            return {"status": "failed", "error": f"agent timed out after {self.agent_timeout_s}s"}
        except (AicosError, RuntimeError, ValueError) as exc:
            return {"status": "failed", "error": f"agent error: {type(exc).__name__}: {exc}"}
        return {"output": output}

    async def _n_screen_output(self, s: OrchestratorState) -> dict[str, Any]:
        out = s["output"]
        result, n = self.firewall.redact_secrets(out.result)
        recs: list[str] = []
        for r in out.recommendations:
            red, k = self.firewall.redact_secrets(r)
            recs.append(red)
            n += k
        findings = list(s.get("findings", []))
        if n:
            findings.append(f"redacted_secrets:{n}")
        return {"output": out.model_copy(update={"result": result, "recommendations": recs}), "findings": findings}

    async def _n_govern(self, s: OrchestratorState) -> dict[str, Any]:
        req, who = s["request"], s["principal"]
        spec = self.agents.spec(s["agent_id"])
        outcomes: list[ActionOutcome] = []
        for pa in s["output"].proposed_actions:
            outcome = await self._govern_one(req, who, spec, pa.action, pa.permission, pa.resource, pa.payload, pa.rationale)
            self.metrics.action(pa.action, outcome.status)
            outcomes.append(outcome)
        return {"outcomes": outcomes}

    async def _govern_one(
        self,
        req: TaskRequest,
        who: Principal,
        spec: AgentSpec,
        action: str,
        declared: Permission,
        resource: str,
        payload: dict[str, Any],
        rationale: str,
    ) -> ActionOutcome:
        agent_p = spec.principal(req.tenant_id)
        required = self.executor.required_permission(action)
        reasons: list[str] = []
        if action not in spec.tools:
            reasons.append("tool_not_allowed_for_agent")
        if required is None:
            reasons.append("unknown_action")
        elif declared != required:
            reasons.append(f"permission_mismatch:declared={declared},required={required}")
        if self.firewall.scan_secrets(canonical_json(payload)):
            reasons.append("secret_in_payload")
        if reasons or required is None:
            return await self._deny(req, agent_p, action, resource, reasons)

        areq = ActionRequest(
            tenant_id=req.tenant_id,
            actor=agent_p,
            on_behalf_of=who,
            action=action,
            permission=required,
            resource=resource,
            payload=payload,
            rationale=rationale,
        )
        decision = self.policy.evaluate(areq)
        if decision.effect is Effect.DENY:
            return await self._deny(req, agent_p, action, resource, decision.reasons)
        if decision.effect is Effect.REQUIRE_APPROVAL:
            proposal = await self.approvals.submit(areq)
            return ActionOutcome(action=action, status="pending_approval", reasons=decision.reasons, proposal_id=proposal.id)
        try:
            result = await self.executor.execute(areq)
        except Exception as exc:  # noqa: BLE001 - handler failures are reported, not raised
            self.audit.record(
                tenant_id=req.tenant_id,
                actor_id=agent_p.id,
                actor_type=agent_p.type,
                action=action,
                resource=resource,
                outcome=Outcome.FAILURE,
                correlation_id=req.id,
                details={"error": str(exc)},
            )
            return ActionOutcome(action=action, status="failed", reasons=[str(exc)])
        self.audit.record(
            tenant_id=req.tenant_id,
            actor_id=agent_p.id,
            actor_type=agent_p.type,
            action=action,
            resource=resource,
            outcome=Outcome.SUCCESS,
            correlation_id=req.id,
            details={"on_behalf_of": who.id, "payload_hash": areq.payload_hash()},
        )
        return ActionOutcome(action=action, status="executed", reasons=decision.reasons, result=result)

    async def _deny(self, req: TaskRequest, actor: Principal, action: str, resource: str, reasons: list[str]) -> ActionOutcome:
        self.audit.record(
            tenant_id=req.tenant_id,
            actor_id=actor.id,
            actor_type=actor.type,
            action=action,
            resource=resource,
            outcome=Outcome.DENIED,
            correlation_id=req.id,
            details={"reasons": reasons},
        )
        await self.bus.publish(
            DomainEvent(
                type=EventType.ACTION_DENIED,
                tenant_id=req.tenant_id,
                source="orchestrator",
                correlation_id=req.id,
                payload={"action": action, "agent": actor.id, "reasons": reasons},
            )
        )
        return ActionOutcome(action=action, status="denied", reasons=reasons)

    async def _n_finalize(self, s: OrchestratorState) -> dict[str, Any]:
        req, who = s["request"], s["principal"]
        status: TaskStatus = "completed" if s.get("status") == "running" else s.get("status", "failed")  # type: ignore[assignment]
        out = s.get("output")
        agent_id = s.get("agent_id")
        elapsed = time.perf_counter() - s["started"]
        result = TaskResult(
            task_id=req.id,
            status=status,
            agent_id=agent_id,
            output=out.result if out else "",
            recommendations=out.recommendations if out else [],
            actions=s.get("outcomes", []),
            metrics={**(out.metrics if out else {}), "elapsed_s": round(elapsed, 4)},
            error=s.get("error"),
            security_findings=s.get("findings", []),
        )
        if status == "completed" and out and agent_id:
            await self.memory.remember(
                tenant_id=req.tenant_id,
                scope=MemoryScope.SHORT_TERM,
                owner_id=req.id,
                content=out.result[:4000],
                metadata={"agent": agent_id},
            )
            if req.conversation_id:
                await self.memory.remember(
                    tenant_id=req.tenant_id,
                    scope=MemoryScope.CONVERSATION,
                    owner_id=req.conversation_id,
                    content=f"Q: {req.objective[:1000]}\nA: {out.result[:3000]}",
                    metadata={"agent": agent_id, "task_id": req.id},
                )
        self.audit.record(
            tenant_id=req.tenant_id,
            actor_id=who.id,
            actor_type=who.type,
            action="task.complete",
            resource=req.id,
            outcome=Outcome.SUCCESS if status == "completed" else Outcome.FAILURE,
            details={"status": status, "agent": agent_id, "actions": [a.status for a in result.actions]},
        )
        await self.bus.publish(
            DomainEvent(
                type=EventType.TASK_COMPLETED if status == "completed" else EventType.TASK_FAILED,
                tenant_id=req.tenant_id,
                source="orchestrator",
                correlation_id=req.id,
                payload={"agent": agent_id, "status": status, "error": result.error},
            )
        )
        self.metrics.task(agent_id or "none", status, elapsed)
        return {"result": result}

    # ------------------------------------------------------------------ post-approval execution
    async def execute_approved(self, proposal_id: str, grant_token: str, executor: Principal) -> ActionOutcome:
        if not executor.is_human or not executor.mfa_verified:
            raise AuthorizationError("execution requires an MFA-verified human")
        p = self.approvals.get(proposal_id, executor.tenant_id)
        if executor.id not in (p.proposer_id, p.delegator_id) and Permission.APPROVAL_DECIDE not in effective_permissions(executor):
            raise AuthorizationError("not allowed to trigger execution of this proposal")
        areq = p.action
        decision = self.policy.evaluate(areq, grant_valid=True)  # re-check: rules may have changed since approval
        if decision.effect is not Effect.ALLOW:
            self.audit.record(
                tenant_id=p.tenant_id,
                actor_id=executor.id,
                actor_type=executor.type,
                action=areq.action,
                resource=areq.resource,
                outcome=Outcome.DENIED,
                correlation_id=p.id,
                details={"reasons": decision.reasons},
            )
            return ActionOutcome(action=areq.action, status="denied", reasons=decision.reasons, proposal_id=p.id)
        self.approvals.consume_grant(grant_token, areq)
        try:
            result = await self.executor.execute(areq)
        except Exception as exc:  # noqa: BLE001
            self.approvals.record_result(p.id, ok=False, result={"error": str(exc)})
            self.audit.record(
                tenant_id=p.tenant_id,
                actor_id=executor.id,
                actor_type=executor.type,
                action=areq.action,
                resource=areq.resource,
                outcome=Outcome.FAILURE,
                correlation_id=p.id,
                details={"error": str(exc)},
            )
            return ActionOutcome(action=areq.action, status="failed", reasons=[str(exc)], proposal_id=p.id)
        self.approvals.record_result(p.id, ok=True, result=result)
        self.audit.record(
            tenant_id=p.tenant_id,
            actor_id=executor.id,
            actor_type=executor.type,
            action=areq.action,
            resource=areq.resource,
            outcome=Outcome.SUCCESS,
            correlation_id=p.id,
            details={"proposal_id": p.id, "approvers": [v.reviewer_id for v in p.votes if v.approve]},
        )
        self.metrics.action(areq.action, "executed")
        return ActionOutcome(action=areq.action, status="executed", proposal_id=p.id, result=result)
