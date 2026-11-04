"""Executive / BI dashboard metrics."""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import BaseModel

from revenueos.models import Grade, Lead
from revenueos.pipeline import Deal, Stage
from revenueos.sequences import Enrollment


class CampaignStats(BaseModel):
    campaign_id: str
    enrolled: int
    emails_sent: int
    open_rate: float
    click_rate: float
    reply_rate: float
    meeting_rate: float


class Dashboard(BaseModel):
    leads_generated: int
    qualified_leads: int
    leads_by_grade: dict[str, int]
    meetings_booked: int
    proposals_sent: int
    deals_won: int
    deals_lost: int
    close_rate: float
    mrr: float
    arr: float
    pipeline_value: float
    weighted_pipeline_value: float
    retention_rate: float
    campaigns: list[CampaignStats]


def _rate(n: int, d: int) -> float:
    return round(n / d, 4) if d else 0.0


def campaign_stats(campaign_id: str, enrollments: list[Enrollment]) -> CampaignStats:
    n = len(enrollments)
    return CampaignStats(
        campaign_id=campaign_id,
        enrolled=n,
        emails_sent=sum(len(e.sent) for e in enrollments),
        open_rate=_rate(sum(1 for e in enrollments if e.opened_at), n),
        click_rate=_rate(sum(1 for e in enrollments if e.clicked_at), n),
        reply_rate=_rate(sum(1 for e in enrollments if e.replied_at), n),
        meeting_rate=_rate(sum(1 for e in enrollments if e.meeting_booked_at), n),
    )


def dashboard(leads: Iterable[Lead], deals: Iterable[Deal], enrollments: Iterable[Enrollment]) -> Dashboard:
    leads, deals, enrollments = list(leads), list(deals), list(enrollments)
    by_grade = {g.value: 0 for g in Grade}
    for lead in leads:
        by_grade[lead.grade.value] += 1
    won = [d for d in deals if d.stage is Stage.WON]
    churned = [d for d in deals if d.stage is Stage.CHURNED]
    lost = [d for d in deals if d.stage is Stage.LOST]
    open_ = [d for d in deals if d.stage in (Stage.OPPORTUNITY, Stage.MEETING, Stage.PROPOSAL, Stage.NEGOTIATION)]
    mrr = sum(d.monthly_value for d in won)
    by_campaign: dict[str, list[Enrollment]] = {}
    for e in enrollments:
        by_campaign.setdefault(str(e.campaign_id), []).append(e)
    ever_clients = len(won) + len(churned)
    return Dashboard(
        leads_generated=len(leads),
        qualified_leads=sum(1 for lead in leads if lead.score >= 60),
        leads_by_grade=by_grade,
        meetings_booked=sum(1 for e in enrollments if e.meeting_booked_at)
        + sum(1 for d in deals if d.stage is Stage.MEETING and d.campaign_id is None),
        proposals_sent=sum(1 for d in deals if d.proposal_sent_at),
        deals_won=len(won),
        deals_lost=len(lost),
        close_rate=_rate(len(won) + len(churned), len(won) + len(churned) + len(lost)),
        mrr=mrr,
        arr=mrr * 12,
        pipeline_value=sum(d.monthly_value * d.contract_months for d in open_),
        weighted_pipeline_value=round(sum(d.weighted_monthly_value * d.contract_months for d in open_), 2),
        retention_rate=_rate(len(won), ever_clients),
        campaigns=[campaign_stats(cid, es) for cid, es in sorted(by_campaign.items())],
    )
