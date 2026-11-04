"""HTTP routes (v1). Every route declares its permission; the domain layer re-checks."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Form, Query, Request, UploadFile
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, Field

from aicos.agents.base import AgentSpec, Department
from aicos.approvals.gateway import ExecutionGrant, Proposal, ProposalStatus
from aicos.compliance.controls import ComplianceReport, ComplianceState, Framework, generate_report
from aicos.domain.errors import AuthorizationError
from aicos.domain.identity import Permission, Principal
from aicos.events.bus import DomainEvent
from aicos.knowledge.pipeline import IngestReport, RetrievedChunk
from aicos.memory.service import visible_scopes
from aicos.orchestrator.graph import ActionOutcome, TaskRequest, TaskResult
from aicos.plugins.manager import PluginRecord
from aicos.security.audit import AuditRecord, ChainVerification
from aicos_api.deps import ContainerDep, require

P = Permission
router = APIRouter(prefix="/v1")
health = APIRouter()


# ----------------------------------------------------------------------------- health
@health.get("/healthz", include_in_schema=False)
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@health.get("/readyz", include_in_schema=False)
async def readyz(c: ContainerDep) -> dict[str, Any]:
    v = c.audit.verify()
    return {"status": "ready" if v.valid else "degraded", "audit_chain_valid": v.valid, "agents": len(c.agents.list())}


@health.get("/metrics", include_in_schema=False)
async def metrics(c: ContainerDep) -> Response:
    try:
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
    except ImportError:  # pragma: no cover
        return PlainTextResponse("", status_code=204)
    registry = getattr(c.metrics, "registry", None)
    return Response(generate_latest(registry) if registry else b"", media_type=CONTENT_TYPE_LATEST)


# ----------------------------------------------------------------------------- tasks
class TaskIn(BaseModel):
    objective: str = Field(min_length=1, max_length=20_000)
    agent_id: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9-]{1,62}$")
    project_id: str | None = Field(default=None, max_length=100)
    conversation_id: str | None = Field(default=None, max_length=100)


@router.post("/tasks", response_model=TaskResult, tags=["tasks"])
async def submit_task(
    body: TaskIn, c: ContainerDep, who: Annotated[Principal, Depends(require(P.TASK_SUBMIT, P.AGENT_INVOKE))]
) -> TaskResult:
    req = TaskRequest(tenant_id=who.tenant_id, **body.model_dump())
    return await c.orchestrator.run(req, who)


# ----------------------------------------------------------------------------- agents
@router.get("/agents", response_model=list[AgentSpec], tags=["agents"])
async def list_agents(
    c: ContainerDep, _: Annotated[Principal, Depends(require(P.AGENT_READ))], department: Department | None = None
) -> list[AgentSpec]:
    return c.agents.list(department)


@router.get("/agents/{agent_id}", response_model=AgentSpec, tags=["agents"])
async def get_agent(agent_id: str, c: ContainerDep, _: Annotated[Principal, Depends(require(P.AGENT_READ))]) -> AgentSpec:
    return c.agents.spec(agent_id)


# ----------------------------------------------------------------------------- approvals
class DecisionIn(BaseModel):
    approve: bool
    comment: str = Field(default="", max_length=2000)


class DecisionOut(BaseModel):
    proposal: Proposal
    grant: ExecutionGrant | None = None


class ExecuteIn(BaseModel):
    grant_token: str = Field(min_length=10, max_length=500)


@router.get("/approvals", response_model=list[Proposal], tags=["approvals"])
async def list_approvals(
    c: ContainerDep, who: Annotated[Principal, Depends(require(P.APPROVAL_READ))], status: ProposalStatus | None = None
) -> list[Proposal]:
    return c.approvals.list(who.tenant_id, status)


@router.get("/approvals/{proposal_id}", response_model=Proposal, tags=["approvals"])
async def get_approval(proposal_id: str, c: ContainerDep, who: Annotated[Principal, Depends(require(P.APPROVAL_READ))]) -> Proposal:
    return c.approvals.get(proposal_id, who.tenant_id)


@router.post("/approvals/{proposal_id}/decision", response_model=DecisionOut, tags=["approvals"])
async def decide(
    proposal_id: str, body: DecisionIn, c: ContainerDep, who: Annotated[Principal, Depends(require(P.APPROVAL_DECIDE))]
) -> DecisionOut:
    d = await c.approvals.decide(proposal_id, who, approve=body.approve, comment=body.comment)
    return DecisionOut(proposal=d.proposal, grant=d.grant)


@router.post("/approvals/{proposal_id}/execute", response_model=ActionOutcome, tags=["approvals"])
async def execute(
    proposal_id: str, body: ExecuteIn, c: ContainerDep, who: Annotated[Principal, Depends(require(P.APPROVAL_READ))]
) -> ActionOutcome:
    proposal = c.approvals.get(proposal_id, who.tenant_id)
    if proposal.action.action == "plugin.install":
        raise AuthorizationError("use POST /v1/plugins/{name}/install for plugin installs")
    return await c.orchestrator.execute_approved(proposal_id, body.grant_token, who)


@router.post("/approvals/{proposal_id}/cancel", response_model=Proposal, tags=["approvals"])
async def cancel(proposal_id: str, c: ContainerDep, who: Annotated[Principal, Depends(require(P.APPROVAL_READ))]) -> Proposal:
    return await c.approvals.cancel(proposal_id, who)


# ----------------------------------------------------------------------------- audit
@router.get("/audit", response_model=list[AuditRecord], tags=["audit"])
async def audit_log(
    c: ContainerDep, who: Annotated[Principal, Depends(require(P.AUDIT_READ))], limit: Annotated[int, Query(ge=1, le=1000)] = 100
) -> list[AuditRecord]:
    return list(c.audit.query(tenant_id=who.tenant_id, limit=limit))


@router.get("/audit/verify", response_model=ChainVerification, tags=["audit"])
async def audit_verify(c: ContainerDep, _: Annotated[Principal, Depends(require(P.AUDIT_READ))]) -> ChainVerification:
    return c.audit.verify()


# ----------------------------------------------------------------------------- knowledge
class SearchIn(BaseModel):
    query: str = Field(min_length=1, max_length=4000)
    k: int = Field(default=6, ge=1, le=50)
    project_id: str | None = None


@router.post("/knowledge/documents", response_model=IngestReport, tags=["knowledge"])
async def ingest(
    c: ContainerDep,
    who: Annotated[Principal, Depends(require(P.KNOWLEDGE_WRITE))],
    file: Annotated[UploadFile, File()],
    source: Annotated[str | None, Form(max_length=500)] = None,
) -> IngestReport:
    data = await file.read(c.settings.max_body_bytes + 1)
    name = source or file.filename or "upload.txt"
    return await c.knowledge.ingest_bytes(tenant_id=who.tenant_id, actor_id=who.id, source=name, data=data)


@router.post("/knowledge/search", response_model=list[RetrievedChunk], tags=["knowledge"])
async def search(body: SearchIn, c: ContainerDep, who: Annotated[Principal, Depends(require(P.KNOWLEDGE_READ))]) -> list[RetrievedChunk]:
    keys = visible_scopes(project_id=body.project_id, human_id=who.id)
    return await c.knowledge.search(tenant_id=who.tenant_id, query=body.query, keys=keys, k=body.k)


# ----------------------------------------------------------------------------- plugins
class PluginOut(BaseModel):
    name: str
    version: str
    state: str
    tier: str
    isolation: str
    capabilities: list[str]
    sensitive_capabilities: list[str]
    proposal_id: str | None
    errors: int
    last_error: str | None

    @classmethod
    def of(cls, r: PluginRecord) -> PluginOut:
        m = r.manifest
        return cls(
            name=m.name,
            version=m.version,
            state=r.state,
            tier=r.tier,
            isolation=m.isolation,
            capabilities=m.capabilities,
            sensitive_capabilities=m.sensitive_capabilities(),
            proposal_id=r.proposal_id,
            errors=r.errors,
            last_error=r.last_error,
        )


@router.get("/plugins", response_model=list[PluginOut], tags=["plugins"])
async def list_plugins(c: ContainerDep, _: Annotated[Principal, Depends(require(P.PLUGIN_READ))]) -> list[PluginOut]:
    return [PluginOut.of(r) for r in c.plugins.records.values()]


@router.post("/plugins/{name}/verify", response_model=PluginOut, tags=["plugins"])
async def verify_plugin(name: str, c: ContainerDep, _: Annotated[Principal, Depends(require(P.PLUGIN_MANAGE))]) -> PluginOut:
    return PluginOut.of(c.plugins.verify(name))


@router.post("/plugins/{name}/request-install", response_model=Proposal, tags=["plugins"])
async def request_install(name: str, c: ContainerDep, who: Annotated[Principal, Depends(require(P.PLUGIN_INSTALL))]) -> Proposal:
    return await c.plugins.request_install(name, who)


@router.post("/plugins/{name}/install", response_model=PluginOut, tags=["plugins"])
async def install_plugin(
    name: str, body: ExecuteIn, c: ContainerDep, who: Annotated[Principal, Depends(require(P.PLUGIN_INSTALL))]
) -> PluginOut:
    await c.plugins.install(name, body.grant_token, who)
    return PluginOut.of(await c.plugins.activate(name))


@router.post("/plugins/{name}/suspend", response_model=PluginOut, tags=["plugins"])
async def suspend_plugin(name: str, c: ContainerDep, who: Annotated[Principal, Depends(require(P.PLUGIN_MANAGE))]) -> PluginOut:
    return PluginOut.of(c.plugins.suspend(name, f"manual by {who.id}"))


# ----------------------------------------------------------------------------- compliance
@router.get("/compliance/report", response_model=ComplianceReport, tags=["compliance"])
async def compliance(
    c: ContainerDep,
    who: Annotated[Principal, Depends(require(P.COMPLIANCE_REPORT))],
    framework: Framework | None = None,
    format: str = "json",
) -> Any:
    s = c.settings
    report = generate_report(
        ComplianceState(
            audit=c.audit,
            approvals=c.approvals,
            policy=c.policy,
            tenant_id=who.tenant_id,
            settings={
                "require_mfa": s.require_mfa,
                "tls_enabled": s.tls_enabled,
                "encryption_at_rest": s.encryption_at_rest,
                "data_retention_days": s.data_retention_days,
            },
        ),
        framework,
    )
    if format == "markdown":
        return PlainTextResponse(report.to_markdown(), media_type="text/markdown")
    return report


# ----------------------------------------------------------------------------- events
class EventIn(BaseModel):
    type: str = Field(pattern=r"^[A-Z][A-Za-z0-9]{2,63}$")
    payload: dict[str, Any] = Field(default_factory=dict)
    correlation_id: str | None = None


_HUMAN_PUBLISHABLE = {"LeadFound", "CustomerCreated", "IssueDetected", "TicketCreated", "DeploymentRequested"}


@router.post("/events", status_code=202, tags=["events"])
async def publish_event(
    body: EventIn, request: Request, c: ContainerDep, who: Annotated[Principal, Depends(require(P.EVENT_PUBLISH))]
) -> dict[str, str]:
    if body.type not in _HUMAN_PUBLISHABLE:
        raise AuthorizationError("event type is system-reserved")
    evt = DomainEvent(
        type=body.type,
        tenant_id=who.tenant_id,
        source=f"api:{who.id}",
        payload=body.payload,
        correlation_id=body.correlation_id or request.scope["state"].get("request_id"),
    )
    await c.bus.publish(evt)
    return {"id": evt.id}


# ----------------------------------------------------------------------------- service integrations (HMAC-signed)
@router.post("/integrations/events", status_code=202, tags=["integrations"])
async def integration_event(body: EventIn, request: Request, c: ContainerDep) -> dict[str, str]:
    """n8n / external systems push events here; HardeningMiddleware verified the HMAC signature."""
    if body.type not in _HUMAN_PUBLISHABLE:
        raise AuthorizationError("event type is system-reserved")
    key_id = request.scope["state"]["service_key_id"]
    evt = DomainEvent(
        type=body.type,
        tenant_id=c.settings.tenant_id,
        source=f"integration:{key_id}",
        payload=body.payload,
        correlation_id=body.correlation_id,
    )
    await c.bus.publish(evt)
    return {"id": evt.id}
