"""RevenueOS HTTP API (mounted by aicos_api.main at /v1/revenue, plus public unsubscribe + signed webhooks)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field, HttpUrl

from aicos.approvals.gateway import Proposal
from aicos.domain.identity import Permission, Principal
from aicos_api.deps import require
from revenueos.analyzer import BusinessAnalysis
from revenueos.email import Brand, EmailStep
from revenueos.metrics import Dashboard
from revenueos.models import Grade, Lead, LeadScore, LeadStatus, Reputation, SocialSignals, WebsiteSignals
from revenueos.pipeline import Deal, Stage
from revenueos.sequences import EngagementEvent
from revenueos.service import Campaign, RevenueOS, TickReport
from revenueos.strategy import to_html, to_markdown, to_slides

P = Permission
router = APIRouter(prefix="/v1/revenue", tags=["revenueos"])
public = APIRouter(tags=["revenueos-public"])
signed = APIRouter(prefix="/v1/integrations/revenue", tags=["integrations"])


def svc(request: Request) -> RevenueOS:
    return request.app.state.revenue  # type: ignore[no-any-return]


Svc = Annotated[RevenueOS, Depends(svc)]


class LeadIn(BaseModel):
    business_name: str = Field(min_length=1, max_length=300)
    owner_name: str | None = None
    industry: str | None = None
    sub_industry: str | None = None
    website: HttpUrl | None = None
    google_business_url: HttpUrl | None = None
    linkedin_url: HttpUrl | None = None
    facebook_url: HttpUrl | None = None
    instagram_url: HttpUrl | None = None
    phone: str | None = None
    email: str | None = None
    city: str | None = None
    state: str | None = None
    zip_code: str | None = None
    timezone: str = "America/New_York"
    employee_count: int | None = None
    estimated_revenue: float | None = None
    years_in_business: int | None = None
    lead_source: str = "manual"


class AnalyzeIn(BaseModel):
    website: WebsiteSignals
    reputation: Reputation | None = None
    social: SocialSignals = Field(default_factory=SocialSignals)


class AnalyzeOut(BaseModel):
    analysis: BusinessAnalysis
    score: LeadScore


class CampaignIn(BaseModel):
    name: str
    brand: Brand
    consultant: str
    consultant_title: str | None = None
    lead_ids: list[uuid.UUID] = Field(min_length=1, max_length=5000)


class GrantIn(BaseModel):
    grant_token: str = Field(min_length=10, max_length=500)


class EmailEventIn(BaseModel):
    event: EngagementEvent
    message_id: str | None = None
    enrollment_id: uuid.UUID | None = None
    email: str | None = None
    at: datetime | None = None


class DealIn(BaseModel):
    lead_id: uuid.UUID
    monthly_value: float = 0
    package: str | None = None


class MoveIn(BaseModel):
    stage: Stage
    reason: str = ""


class ContractIn(BaseModel):
    monthly_value: float = Field(gt=0)
    setup_fee: float = Field(default=0, ge=0)
    contract_months: int = Field(default=12, ge=1, le=60)
    package: str


class CloseIn(BaseModel):
    contract_proposal_id: str


class PreviewIn(BaseModel):
    brand: Brand
    consultant: str
    lead_id: uuid.UUID
    step: EmailStep = EmailStep.INITIAL


# ----------------------------------------------------------------------------- leads
@router.post("/leads", response_model=Lead)
async def create_lead(body: LeadIn, s: Svc, who: Annotated[Principal, Depends(require(P.CRM_WRITE))]) -> Lead:
    return await s.add_lead(Lead(**body.model_dump()), actor=who.id)


@router.get("/leads", response_model=list[Lead])
async def list_leads(
    s: Svc,
    _: Annotated[Principal, Depends(require(P.TASK_READ))],
    grade: Grade | None = None,
    status: LeadStatus | None = None,
    min_score: int = 0,
) -> list[Lead]:
    rows = [
        x
        for x in s.leads.values()
        if (grade is None or x.grade == grade) and (status is None or x.status == status) and x.score >= min_score
    ]
    return sorted(rows, key=lambda x: x.score, reverse=True)


@router.post("/leads/{lead_id}/analyze", response_model=AnalyzeOut)
async def analyze_lead(lead_id: uuid.UUID, body: AnalyzeIn, s: Svc, who: Annotated[Principal, Depends(require(P.CRM_WRITE))]) -> AnalyzeOut:
    a, sc = await s.analyze_lead(lead_id, website=body.website, reputation=body.reputation, social=body.social, actor=who.id)
    return AnalyzeOut(analysis=a, score=sc)


@router.get("/leads/{lead_id}/proposal")
async def proposal(
    lead_id: uuid.UUID,
    s: Svc,
    who: Annotated[Principal, Depends(require(P.CONTENT_DRAFT))],
    format: Literal["json", "markdown", "html", "slides"] = "markdown",
) -> Any:
    p = await s.generate_proposal(lead_id, prepared_by=who.display_name or who.id)
    if format == "json":
        return p
    if format == "html":
        return HTMLResponse(to_html(p), headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})
    return PlainTextResponse(to_slides(p) if format == "slides" else to_markdown(p), media_type="text/markdown")


# ----------------------------------------------------------------------------- campaigns
@router.post("/campaigns", response_model=Campaign)
async def create_campaign(body: CampaignIn, s: Svc, who: Annotated[Principal, Depends(require(P.CRM_WRITE))]) -> Campaign:
    return s.create_campaign(
        name=body.name,
        brand=body.brand,
        consultant=body.consultant,
        consultant_title=body.consultant_title,
        lead_ids=body.lead_ids,
        created_by=who.id,
    )


@router.get("/campaigns", response_model=list[Campaign])
async def list_campaigns(s: Svc, _: Annotated[Principal, Depends(require(P.TASK_READ))]) -> list[Campaign]:
    return list(s.campaigns.values())


@router.post("/campaigns/preview", response_class=HTMLResponse)
async def preview(body: PreviewIn, s: Svc, _: Annotated[Principal, Depends(require(P.CONTENT_DRAFT))]) -> HTMLResponse:
    lead = s.lead(body.lead_id)
    from revenueos.service import Campaign as C

    c = C(name="preview", brand=body.brand, consultant=body.consultant, lead_ids=[lead.id], created_by="preview")
    r = s.renderer.render(body.step, brand=body.brand, context=s._context(c, lead), unsubscribe_url=body.brand.unsubscribe_base_url)
    return HTMLResponse(
        r.html,
        headers={"X-Email-Subject": r.subject, "Content-Security-Policy": "default-src 'none'; img-src https:; style-src 'unsafe-inline'"},
    )


@router.post("/campaigns/{campaign_id}/request-launch", response_model=Proposal)
async def request_launch(campaign_id: uuid.UUID, s: Svc, who: Annotated[Principal, Depends(require(P.EMAIL_MASS_SEND))]) -> Proposal:
    return await s.request_launch(campaign_id, who)


@router.post("/campaigns/{campaign_id}/launch", response_model=Campaign)
async def launch(campaign_id: uuid.UUID, body: GrantIn, s: Svc, who: Annotated[Principal, Depends(require(P.EMAIL_MASS_SEND))]) -> Campaign:
    return await s.launch(campaign_id, body.grant_token, who)


@router.post("/campaigns/{campaign_id}/pause", response_model=Campaign)
async def pause(campaign_id: uuid.UUID, s: Svc, who: Annotated[Principal, Depends(require(P.CRM_WRITE))]) -> Campaign:
    return s.pause(campaign_id, actor=who.id, reason="manual")


@router.get("/outreach")
async def outreach(s: Svc, _: Annotated[Principal, Depends(require(P.TASK_READ))]) -> list[dict[str, Any]]:
    return [s.outreach_row(e) for e in s.enrollments.values()]


# ----------------------------------------------------------------------------- pipeline
@router.post("/deals", response_model=Deal)
async def open_deal(body: DealIn, s: Svc, who: Annotated[Principal, Depends(require(P.CRM_WRITE))]) -> Deal:
    return s.open_deal(body.lead_id, actor=who.id, monthly_value=body.monthly_value, package=body.package)


@router.get("/deals", response_model=list[Deal])
async def list_deals(s: Svc, _: Annotated[Principal, Depends(require(P.TASK_READ))], stage: Stage | None = None) -> list[Deal]:
    return [d for d in s.deals.values() if stage is None or d.stage == stage]


@router.post("/deals/{deal_id}/stage", response_model=Deal)
async def move(deal_id: uuid.UUID, body: MoveIn, s: Svc, who: Annotated[Principal, Depends(require(P.CRM_WRITE))]) -> Deal:
    return s.move_deal(deal_id, body.stage, actor=who.id, reason=body.reason)


@router.post("/deals/{deal_id}/contract", response_model=Proposal)
async def contract(deal_id: uuid.UUID, body: ContractIn, s: Svc, who: Annotated[Principal, Depends(require(P.CONTRACT_SIGN))]) -> Proposal:
    return await s.request_contract(deal_id, who, **body.model_dump())


@router.post("/deals/{deal_id}/won", response_model=Deal)
async def won(deal_id: uuid.UUID, body: CloseIn, s: Svc, who: Annotated[Principal, Depends(require(P.CRM_WRITE))]) -> Deal:
    return await s.close_won(deal_id, contract_proposal_id=body.contract_proposal_id, actor=who)


@router.get("/dashboard", response_model=Dashboard)
async def get_dashboard(s: Svc, _: Annotated[Principal, Depends(require(P.TASK_READ))]) -> Dashboard:
    return s.dashboard()


# ----------------------------------------------------------------------------- public: unsubscribe (no auth by design)
_UNSUB_PAGE = (
    "<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'>"
    "<title>Unsubscribed</title></head><body style='font-family:sans-serif;max-width:480px;margin:80px auto'>"
    "<h2>{title}</h2><p>{msg}</p></body></html>"
)


@public.get("/u/{token}", response_class=HTMLResponse, include_in_schema=False)
@public.post("/u/{token}", response_class=HTMLResponse, include_in_schema=False)  # RFC 8058 one-click
async def unsubscribe(token: str, s: Svc) -> HTMLResponse:
    ok = await s.unsubscribe(token[:600])
    if ok:
        return HTMLResponse(_UNSUB_PAGE.format(title="You're unsubscribed", msg="You won't receive further emails from us."))
    return HTMLResponse(
        _UNSUB_PAGE.format(title="Link not recognised", msg="Reply to any email with 'unsubscribe' and we'll remove you."), status_code=400
    )


# ----------------------------------------------------------------------------- signed service integrations
@signed.post("/email-events", status_code=202)
async def email_event(body: EmailEventIn, s: Svc) -> dict[str, int]:
    """Postal / Mailcow / reply-detector / calendar webhooks via n8n (HMAC-signed by HardeningMiddleware)."""
    hits = await s.record_event(body.event, at=body.at, message_id=body.message_id, enrollment_id=body.enrollment_id, email=body.email)
    return {"matched": len(hits)}


@signed.post("/tick", response_model=TickReport)
async def tick(s: Svc) -> TickReport:
    """Advance follow-ups. Scheduled by n8n every 5 minutes."""
    return await s.tick()


def mount(app: Any, service: RevenueOS) -> None:
    app.state.revenue = service
    app.include_router(router)
    app.include_router(public)
    app.include_router(signed)


__all__ = ["Response", "mount"]
