"""RevenueOS application service: leads -> analysis -> scoring -> governed campaigns -> follow-ups -> pipeline -> MRR.

Human approval (via the AICOS Approval Gateway) is required for:
  * launching a campaign (mass email)          action campaign.send   permission email:mass_send
  * sending a contract / closing a deal as won action contract.send   permission contract:sign
  * social posting                              action social.post     permission social:publish
  * financial actions                           action finance.payment permission finance:execute
Campaign approvals are bound to the lead list hash AND the template bundle hash: changing either after
approval invalidates the grant; changing templates while a campaign runs auto-pauses it.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from aicos.approvals.gateway import ApprovalGateway, Proposal, ProposalStatus
from aicos.domain.common import sha256_hex, utcnow
from aicos.domain.errors import AuthorizationError, NotFound, PolicyViolation, ValidationFailed
from aicos.domain.identity import Permission, Principal
from aicos.events.bus import DomainEvent, EventBus, EventType
from aicos.security.audit import AuditLog, Outcome
from aicos.security.policy import ActionRequest, Effect, PolicyEngine
from aicos.security.rbac import effective_permissions
from revenueos.analyzer import BusinessAnalysis, analyze
from revenueos.email import (
    Brand,
    EmailRenderer,
    EmailStep,
    Mailer,
    OutboundEmail,
    SendPolicy,
    SuppressionList,
    SuppressionReason,
    UnsubscribeTokens,
)
from revenueos.metrics import Dashboard, dashboard
from revenueos.models import Grade, Lead, LeadScore, LeadStatus, Reputation, SEOAnalysis, SocialSignals, WebsiteSignals
from revenueos.pipeline import Deal, Stage
from revenueos.scoring import ICP, score_lead
from revenueos.sequences import TERMINAL, DecisionKind, EngagementEvent, Enrollment, EnrollmentStatus, PipelineMove, SentStep, decide
from revenueos.strategy import Proposal as SalesProposal
from revenueos.strategy import build_proposal

AREA_LABELS = {
    "seo": "Search visibility",
    "local_seo": "Local search (Google Maps)",
    "speed": "Website performance",
    "mobile": "Mobile experience",
    "conversion": "Lead generation",
    "design": "Website design",
    "reputation": "Customer reviews",
    "content": "Content",
    "social": "Social media presence",
    "advertising": "Advertising & retargeting",
    "website": "Website",
}


class CampaignStatus(StrEnum):
    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"


class Campaign(BaseModel):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    tenant_id: str = "default"
    name: str = Field(min_length=1, max_length=200)
    sequence: str = "sequence_1"
    brand: Brand
    consultant: str
    consultant_title: str | None = None
    lead_ids: list[uuid.UUID]
    status: CampaignStatus = CampaignStatus.DRAFT
    proposal_id: str | None = None
    approved_template_hash: str | None = None
    approved_lead_hash: str | None = None
    created_by: str
    mailbox_first_send: date | None = None
    sends_by_day: dict[str, int] = Field(default_factory=dict)
    paused_reason: str | None = None

    def lead_hash(self) -> str:
        return sha256_hex(",".join(sorted(str(i) for i in self.lead_ids)))


class TickReport(BaseModel):
    sent: list[dict[str, str]] = Field(default_factory=list)
    stopped: list[dict[str, str]] = Field(default_factory=list)
    skipped: list[dict[str, str]] = Field(default_factory=list)
    paused_campaigns: list[str] = Field(default_factory=list)


class RevenueOS:
    def __init__(
        self,
        *,
        approvals: ApprovalGateway,
        policy: PolicyEngine,
        audit: AuditLog,
        bus: EventBus,
        mailer: Mailer,
        unsubscribe_key: bytes,
        renderer: EmailRenderer | None = None,
        send_policy: SendPolicy | None = None,
        icp: ICP | None = None,
        tenant_id: str = "default",
    ) -> None:
        self.approvals, self.policy, self.audit, self.bus, self.mailer = approvals, policy, audit, bus, mailer
        self.renderer = renderer or EmailRenderer()
        self.send_policy, self.icp, self.tenant_id = send_policy or SendPolicy(), icp or ICP(), tenant_id
        self.tokens = UnsubscribeTokens(unsubscribe_key)
        self.suppression = SuppressionList()
        self.leads: dict[uuid.UUID, Lead] = {}
        self.seo: dict[uuid.UUID, SEOAnalysis] = {}
        self.reputation: dict[uuid.UUID, Reputation] = {}
        self.analyses: dict[uuid.UUID, BusinessAnalysis] = {}
        self.scores: dict[uuid.UUID, LeadScore] = {}
        self.campaigns: dict[uuid.UUID, Campaign] = {}
        self.enrollments: dict[uuid.UUID, Enrollment] = {}
        self.deals: dict[uuid.UUID, Deal] = {}
        self._by_message: dict[str, uuid.UUID] = {}

    # ------------------------------------------------------------------ helpers
    def _audit(self, actor: str, action: str, resource: str, outcome: Outcome = Outcome.SUCCESS, **details: Any) -> None:
        self.audit.record(
            tenant_id=self.tenant_id,
            actor_id=actor,
            actor_type="human" if not actor.startswith(("system", "agent:")) else "service",
            action=action,
            resource=resource,
            outcome=outcome,
            details=details,
        )

    async def _emit(self, type_: str, payload: dict[str, Any], correlation: str | None = None) -> None:
        await self.bus.publish(
            DomainEvent(type=type_, tenant_id=self.tenant_id, source="revenueos", payload=payload, correlation_id=correlation)
        )

    def lead(self, lead_id: uuid.UUID) -> Lead:
        try:
            return self.leads[lead_id]
        except KeyError:
            raise NotFound("lead not found") from None

    def campaign(self, campaign_id: uuid.UUID) -> Campaign:
        try:
            return self.campaigns[campaign_id]
        except KeyError:
            raise NotFound("campaign not found") from None

    def deal(self, deal_id: uuid.UUID) -> Deal:
        try:
            return self.deals[deal_id]
        except KeyError:
            raise NotFound("deal not found") from None

    # ------------------------------------------------------------------ leads
    @staticmethod
    def _dedupe_key(lead: Lead) -> str:
        if lead.website:
            return "web:" + (lead.website.host or "").removeprefix("www.")
        return f"name:{lead.business_name.lower().strip()}|{(lead.city or '').lower()}"

    async def add_lead(self, lead: Lead, *, actor: str) -> Lead:
        key = self._dedupe_key(lead)
        for existing in self.leads.values():
            if self._dedupe_key(existing) == key:
                return existing
        lead = lead.model_copy(update={"tenant_id": self.tenant_id})
        self.leads[lead.id] = lead
        self._audit(actor, "lead.create", str(lead.id), source=lead.lead_source)
        await self._emit(EventType.LEAD_FOUND, {"lead_id": str(lead.id), "business_name": lead.business_name, "source": lead.lead_source})
        return lead

    async def analyze_lead(
        self, lead_id: uuid.UUID, *, website: WebsiteSignals, reputation: Reputation | None, social: SocialSignals, actor: str
    ) -> tuple[BusinessAnalysis, LeadScore]:
        lead = self.lead(lead_id)
        if reputation is not None:
            reputation = reputation.model_copy(update={"lead_id": lead.id})
        analysis = analyze(lead, website, reputation, social)
        if reputation is not None:
            reputation.reputation_score = analysis.reputation_score
            self.reputation[lead.id] = reputation
        score = score_lead(lead, website, reputation, social, self.icp)
        self.seo[lead.id] = SEOAnalysis(
            lead_id=lead.id,
            page_speed_score=website.page_speed_score,
            mobile_score=website.mobile_score,
            local_seo_score=website.local_seo_score,
            seo_score=analysis.seo_score,
        )
        self.analyses[lead.id], self.scores[lead.id] = analysis, score
        status = LeadStatus.QUALIFIED if score.total >= 60 else LeadStatus.ANALYZED
        if lead.status in (LeadStatus.NEW, LeadStatus.ANALYZED, LeadStatus.QUALIFIED):
            lead.status = status
        lead.score, lead.grade, lead.updated_at = score.total, score.grade, utcnow()
        self._audit(actor, "lead.analyze", str(lead.id), score=score.total, grade=score.grade)
        return analysis, score

    # ------------------------------------------------------------------ campaigns (governed)
    def create_campaign(
        self, *, name: str, brand: Brand, consultant: str, lead_ids: list[uuid.UUID], created_by: str, consultant_title: str | None = None
    ) -> Campaign:
        eligible = []
        for lid in dict.fromkeys(lead_ids):
            lead = self.lead(lid)
            if not lead.email or self.suppression.is_suppressed(lead.email) or lead.grade is Grade.IGNORE:
                continue
            eligible.append(lid)
        if not eligible:
            raise ValidationFailed("no eligible leads (need email, not suppressed, grade above IGNORE)")
        c = Campaign(
            name=name,
            brand=brand,
            consultant=consultant,
            consultant_title=consultant_title,
            lead_ids=eligible,
            created_by=created_by,
            tenant_id=self.tenant_id,
        )
        self.campaigns[c.id] = c
        self._audit(created_by, "campaign.create", str(c.id), recipients=len(eligible), excluded=len(lead_ids) - len(eligible))
        return c

    def _launch_request(self, c: Campaign, actor: Principal) -> ActionRequest:
        return ActionRequest(
            tenant_id=self.tenant_id,
            actor=actor,
            action="campaign.send",
            permission=Permission.EMAIL_MASS_SEND,
            resource=str(c.id),
            rationale=f"Launch '{c.name}' to {len(c.lead_ids)} recipients",
            payload={
                "campaign_id": str(c.id),
                "name": c.name,
                "sequence": c.sequence,
                "recipients": len(c.lead_ids),
                "lead_ids_sha256": c.lead_hash(),
                "template_hash": self.renderer.bundle_hash(),
                "from_email": c.brand.from_email,
                "physical_address": c.brand.physical_address,
            },
        )

    async def request_launch(self, campaign_id: uuid.UUID, requester: Principal) -> Proposal:
        c = self.campaign(campaign_id)
        if c.status not in (CampaignStatus.DRAFT, CampaignStatus.PAUSED):
            raise ValidationFailed(f"campaign is {c.status}")
        req = self._launch_request(c, requester)
        decision = self.policy.evaluate(req)
        if decision.effect is Effect.DENY:
            raise PolicyViolation(f"launch denied: {decision.reasons}")
        proposal = await self.approvals.submit(req)
        c.proposal_id, c.status = proposal.id, CampaignStatus.PENDING_APPROVAL
        return proposal

    async def launch(self, campaign_id: uuid.UUID, grant_token: str, executor: Principal, *, now: datetime | None = None) -> Campaign:
        c = self.campaign(campaign_id)
        if c.status is not CampaignStatus.PENDING_APPROVAL or not c.proposal_id:
            raise ValidationFailed(f"campaign is {c.status}")
        if not executor.is_human or not executor.mfa_verified:
            raise AuthorizationError("launch requires an MFA-verified human")
        proposal = self.approvals.get(c.proposal_id, self.tenant_id)
        current = self._launch_request(c, proposal.action.actor)  # recomputed from live state
        self.approvals.consume_grant(grant_token, current)  # fails if leads/templates changed since approval
        now = now or utcnow()
        c.status, c.paused_reason = CampaignStatus.ACTIVE, None
        c.approved_template_hash, c.approved_lead_hash = current.payload["template_hash"], c.lead_hash()
        c.mailbox_first_send = c.mailbox_first_send or now.date()
        enrolled = {e.lead_id for e in self.enrollments.values() if e.campaign_id == c.id}
        for lid in c.lead_ids:
            lead = self.leads[lid]
            if lid in enrolled or not lead.email:
                continue
            e = Enrollment(campaign_id=c.id, lead_id=lid, email=lead.email, timezone=lead.timezone, started_at=now)
            self.enrollments[e.id] = e
        self._audit(
            executor.id,
            "campaign.launch",
            str(c.id),
            proposal_id=c.proposal_id,
            recipients=len(c.lead_ids),
            approvers=[v.reviewer_id for v in proposal.votes if v.approve],
        )
        return c

    def pause(self, campaign_id: uuid.UUID, *, actor: str, reason: str) -> Campaign:
        c = self.campaign(campaign_id)
        c.status, c.paused_reason = CampaignStatus.PAUSED, reason
        self._audit(actor, "campaign.pause", str(c.id), reason=reason)
        return c

    # ------------------------------------------------------------------ follow-up engine
    def _context(self, c: Campaign, lead: Lead) -> dict[str, Any]:
        a = self.analyses.get(lead.id)
        findings = [f.model_dump() for f in a.top_opportunities(10)] if a else []
        areas = list(dict.fromkeys(AREA_LABELS.get(f["area"], f["area"].title()) for f in findings))[:4]
        ctx: dict[str, Any] = {
            "business_name": lead.business_name,
            "owner_name": lead.owner_name,
            "city": lead.city,
            "consultant": c.consultant,
            "consultant_title": c.consultant_title,
            "findings": findings,
            "health_score": a.business_health_score if a else "—",
        }
        if areas:
            ctx["opportunity_areas"] = areas
        if findings:
            ctx["top_finding"] = findings[0]
        return ctx

    def _cap_ok(self, c: Campaign, now: datetime) -> bool:
        age = (now.date() - (c.mailbox_first_send or now.date())).days
        return c.sends_by_day.get(now.date().isoformat(), 0) < self.send_policy.daily_cap(age)

    async def tick(self, now: datetime | None = None) -> TickReport:
        """Advance every active enrollment. Run by aicos-worker (e.g. every 5 minutes)."""
        now = now or utcnow()
        report = TickReport()
        bundle = self.renderer.bundle_hash()
        for c in self.campaigns.values():
            if c.status is not CampaignStatus.ACTIVE:
                continue
            if bundle != c.approved_template_hash:
                self.pause(c.id, actor="system", reason="templates changed after approval — re-approval required")
                self._audit("system", "campaign.integrity", str(c.id), Outcome.BLOCKED)
                await self._emit(EventType.SECURITY_ALERT, {"kind": "campaign_templates_changed", "campaign_id": str(c.id)})
                report.paused_campaigns.append(str(c.id))
                continue
            members = [x for x in self.enrollments.values() if x.campaign_id == c.id]
            for e in members:
                if e.status in TERMINAL:
                    continue
                d = decide(e, now, policy=self.send_policy)
                if d.kind is DecisionKind.STOP:
                    await self._apply_stop(e, d.pipeline, d.reason)
                    report.stopped.append({"enrollment": str(e.id), "reason": d.reason})
                    continue
                if d.kind is DecisionKind.WAIT or d.step is None:
                    continue
                if self.suppression.is_suppressed(e.email):
                    e.status = EnrollmentStatus.UNSUBSCRIBED
                    report.skipped.append({"enrollment": str(e.id), "reason": "suppressed"})
                    continue
                if not self._cap_ok(c, now):
                    report.skipped.append({"enrollment": str(e.id), "reason": "daily_cap"})
                    continue
                await self._send(c, e, d.step, now)
                report.sent.append({"enrollment": str(e.id), "step": d.step.value, "reason": d.reason})
            if all(x.status in TERMINAL for x in members):
                c.status = CampaignStatus.COMPLETED
        return report

    async def _send(self, c: Campaign, e: Enrollment, step: EmailStep, now: datetime) -> None:
        lead = self.leads[e.lead_id]
        unsub = f"{c.brand.unsubscribe_base_url.rstrip('/')}/{self.tokens.make(e.email)}"
        rendered = self.renderer.render(step, brand=c.brand, context=self._context(c, lead), unsubscribe_url=unsub)
        msg = OutboundEmail(
            to_email=e.email,
            to_name=lead.owner_name,
            rendered=rendered,
            brand=c.brand,
            unsubscribe_url=unsub,
            in_reply_to=e.thread_id,
            headers={"X-AICOS-Campaign": str(c.id), "X-AICOS-Enrollment": str(e.id), "X-AICOS-Step": step.value},
        )
        message_id = await self.mailer.send(msg)
        e.sent.append(SentStep(step=step, sent_at=now, message_id=message_id))
        e.last_contact = now
        self._by_message[message_id] = e.id
        day = now.date().isoformat()
        c.sends_by_day[day] = c.sends_by_day.get(day, 0) + 1
        if lead.status in (LeadStatus.NEW, LeadStatus.ANALYZED, LeadStatus.QUALIFIED):
            lead.status = LeadStatus.IN_SEQUENCE
        self._audit(
            "system",
            "email.send",
            str(e.id),
            campaign=str(c.id),
            step=step.value,
            template_hash=rendered.template_hash,
            proposal_id=c.proposal_id,
        )

    async def _apply_stop(self, e: Enrollment, move: PipelineMove | None, reason: str) -> None:
        lead = self.leads[e.lead_id]
        if move is PipelineMove.NURTURE:
            e.status = EnrollmentStatus.COMPLETED
            if lead.status is LeadStatus.IN_SEQUENCE:
                lead.status = LeadStatus.NURTURE
        elif move is PipelineMove.SUPPRESS:
            self.suppression.add(
                e.email, SuppressionReason.BOUNCED if e.status is EnrollmentStatus.BOUNCED else SuppressionReason.UNSUBSCRIBED
            )
            lead.status = LeadStatus.SUPPRESSED
        elif move in (PipelineMove.OPPORTUNITY, PipelineMove.MEETING):
            deal = next((d for d in self.deals.values() if d.lead_id == lead.id and d.stage not in (Stage.LOST, Stage.CHURNED)), None)
            if deal is None:
                deal = Deal(lead_id=lead.id, campaign_id=e.campaign_id, tenant_id=self.tenant_id)
                self.deals[deal.id] = deal
                await self._emit(
                    EventType.OPPORTUNITY_CREATED,
                    {"lead_id": str(lead.id), "deal_id": str(deal.id), "stage": "opportunity", "reason": reason},
                )
            if move is PipelineMove.MEETING and deal.stage is Stage.OPPORTUNITY:
                deal.move(Stage.MEETING, actor="system", reason=reason)
            lead.status = LeadStatus.OPPORTUNITY

    async def record_event(
        self,
        event: EngagementEvent,
        *,
        at: datetime | None = None,
        message_id: str | None = None,
        enrollment_id: uuid.UUID | None = None,
        email: str | None = None,
    ) -> list[Enrollment]:
        """Ingest ESP webhooks (Postal/Mailcow), reply detection or calendar bookings."""
        at = at or utcnow()
        targets: list[Enrollment] = []
        if message_id and message_id in self._by_message:
            targets = [self.enrollments[self._by_message[message_id]]]
        elif enrollment_id and enrollment_id in self.enrollments:
            targets = [self.enrollments[enrollment_id]]
        elif email:
            targets = [e for e in self.enrollments.values() if e.email.lower() == email.strip().lower()]
        if email and event in (EngagementEvent.UNSUBSCRIBED, EngagementEvent.COMPLAINED, EngagementEvent.BOUNCED):
            reason = {EngagementEvent.BOUNCED: SuppressionReason.BOUNCED, EngagementEvent.COMPLAINED: SuppressionReason.COMPLAINED}
            self.suppression.add(email, reason.get(event, SuppressionReason.UNSUBSCRIBED))
        for e in targets:
            late_ok = {EngagementEvent.REPLIED, EngagementEvent.MEETING_BOOKED, EngagementEvent.UNSUBSCRIBED, EngagementEvent.COMPLAINED}
            if e.status in TERMINAL and e.status is not EnrollmentStatus.COMPLETED and event not in late_ok:
                continue  # e.g. an open arriving after a reply changes nothing
            e.apply(event, at)
            if event in (EngagementEvent.UNSUBSCRIBED, EngagementEvent.COMPLAINED, EngagementEvent.BOUNCED):
                self.suppression.add(
                    e.email, SuppressionReason.BOUNCED if event is EngagementEvent.BOUNCED else SuppressionReason.UNSUBSCRIBED
                )
            d = decide(e, at, policy=self.send_policy)
            if d.kind is DecisionKind.STOP:
                await self._apply_stop(e, d.pipeline, d.reason)
            self._audit("system", f"email.event.{event.value}", str(e.id))
        return targets

    async def unsubscribe(self, token: str) -> bool:
        email = self.tokens.parse(token)
        if email is None:
            return False
        self.suppression.add(email, SuppressionReason.UNSUBSCRIBED)
        await self.record_event(EngagementEvent.UNSUBSCRIBED, email=email)
        return True

    # ------------------------------------------------------------------ proposals & deals
    async def generate_proposal(self, lead_id: uuid.UUID, *, prepared_by: str) -> SalesProposal:
        lead = self.lead(lead_id)
        analysis = self.analyses.get(lead.id)
        if analysis is None:
            raise ValidationFailed("analyze the lead before generating a proposal")
        p = build_proposal(lead, analysis, self.scores.get(lead.id), prepared_by=prepared_by)
        await self._emit(EventType.PROPOSAL_GENERATED, {"lead_id": str(lead.id), "recommended": p.recommended})
        self._audit(prepared_by, "proposal.generate", str(lead.id), recommended=p.recommended)
        return p

    def open_deal(self, lead_id: uuid.UUID, *, actor: str, monthly_value: float = 0, package: str | None = None) -> Deal:
        lead = self.lead(lead_id)
        deal = Deal(lead_id=lead.id, tenant_id=self.tenant_id, monthly_value=monthly_value, package=package)
        self.deals[deal.id] = deal
        lead.status = LeadStatus.OPPORTUNITY
        self._audit(actor, "deal.create", str(deal.id), lead=str(lead.id))
        return deal

    def move_deal(self, deal_id: uuid.UUID, to: Stage, *, actor: str, reason: str = "") -> Deal:
        if to is Stage.WON:
            raise PolicyViolation("use close_won(): winning a deal requires an approved, executed contract.send")
        deal = self.deal(deal_id)
        deal.move(to, actor=actor, reason=reason)
        self._audit(actor, "deal.move", str(deal.id), to=to.value)
        return deal

    async def request_contract(
        self, deal_id: uuid.UUID, requester: Principal, *, monthly_value: float, setup_fee: float, contract_months: int, package: str
    ) -> Proposal:
        deal = self.deal(deal_id)
        deal.monthly_value, deal.setup_fee, deal.contract_months, deal.package = monthly_value, setup_fee, contract_months, package
        req = ActionRequest(
            tenant_id=self.tenant_id,
            actor=requester,
            action="contract.send",
            permission=Permission.CONTRACT_SIGN,
            resource=str(deal.id),
            rationale=f"{package} at ${monthly_value:,.0f}/mo for {contract_months} months",
            payload={
                "deal_id": str(deal.id),
                "lead_id": str(deal.lead_id),
                "package": package,
                "monthly_value": monthly_value,
                "setup_fee": setup_fee,
                "contract_months": contract_months,
            },
        )
        decision = self.policy.evaluate(req)
        if decision.effect is Effect.DENY:
            raise PolicyViolation(f"contract denied: {decision.reasons}")
        return await self.approvals.submit(req)

    async def close_won(self, deal_id: uuid.UUID, *, contract_proposal_id: str, actor: Principal) -> Deal:
        deal = self.deal(deal_id)
        p = self.approvals.get(contract_proposal_id, self.tenant_id)
        a = p.action
        if a.action != "contract.send" or a.resource != str(deal.id):
            raise PolicyViolation("proposal is not a contract for this deal")
        if p.status is not ProposalStatus.EXECUTED:
            raise PolicyViolation(f"contract proposal is {p.status}; it must be approved and executed")
        if a.payload.get("monthly_value") != deal.monthly_value or a.payload.get("contract_months") != deal.contract_months:
            raise PolicyViolation("deal terms differ from the approved contract")
        if Permission.CRM_WRITE not in effective_permissions(actor):
            raise AuthorizationError("missing crm:write")
        if deal.stage in (Stage.OPPORTUNITY, Stage.MEETING):
            deal.move(Stage.PROPOSAL, actor=actor.id, reason="contract sent")
        deal.move(Stage.WON, actor=actor.id, reason=f"contract {p.id}")
        lead = self.leads.get(deal.lead_id)
        if lead:
            lead.status = LeadStatus.CLIENT
        self._audit(actor.id, "deal.won", str(deal.id), mrr=deal.monthly_value, contract=p.id)
        await self._emit(
            EventType.CUSTOMER_CREATED,
            {"deal_id": str(deal.id), "lead_id": str(deal.lead_id), "mrr": deal.monthly_value, "package": deal.package},
        )
        return deal

    # ------------------------------------------------------------------ BI
    def dashboard(self) -> Dashboard:
        return dashboard(self.leads.values(), self.deals.values(), self.enrollments.values())

    def outreach_row(self, e: Enrollment) -> dict[str, Any]:
        """Projection matching the `outreach` table in the spec."""
        deal = next((d for d in self.deals.values() if d.lead_id == e.lead_id), None)
        return {
            "lead_id": str(e.lead_id),
            "sequence_name": self.campaigns[e.campaign_id].sequence,
            "email_sent": bool(e.sent),
            "opened": bool(e.opened_at),
            "clicked": bool(e.clicked_at),
            "replied": bool(e.replied_at),
            "meeting_booked": bool(e.meeting_booked_at),
            "proposal_sent": bool(deal and deal.proposal_sent_at),
            "client_signed": bool(deal and deal.stage is Stage.WON),
            "last_contact": e.last_contact.isoformat() if e.last_contact else None,
        }
