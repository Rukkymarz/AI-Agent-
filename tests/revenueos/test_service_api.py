from __future__ import annotations

import json
import uuid
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aicos.container import Container
from aicos.domain.errors import ApprovalError, AuthorizationError, NotFound, PolicyViolation, ValidationFailed
from aicos.domain.identity import Role
from aicos.events.bus import EventType
from aicos.security.signing import RequestSigner
from aicos_api.main import create_app
from revenueos.email import Brand, EmailRenderer, EmailStep, OutboxMailer
from revenueos.models import Grade, Lead, LeadStatus, Reputation, SocialSignals, WebsiteSignals
from revenueos.pipeline import Stage
from revenueos.sequences import EngagementEvent, EnrollmentStatus
from revenueos.service import CampaignStatus, RevenueOS
from revenueos.strategy import to_html, to_markdown, to_slides
from tests.conftest import KEY, human
from tests.revenueos.conftest import MONDAY

WEAK = WebsiteSignals(
    seo_score=20,
    page_speed_score=35,
    has_cta=False,
    mobile_friendly=False,
    outdated_design=True,
    has_chat=False,
    word_count=150,
    has_blog=False,
    has_meta_pixel=False,
    has_google_ads_tag=False,
    local_seo_score=0,
)


async def qualified(rev: RevenueOS, name: str = "Acme Plumbing", email: str | None = "sam@acme.example") -> Lead:
    lead = await rev.add_lead(
        Lead(
            business_name=name,
            owner_name="Sam",
            email=email,
            city="Austin",
            employee_count=12,
            website=f"https://{name.lower().replace(' ', '')}.example",
        ),
        actor="alice",
    )  # type: ignore[arg-type]
    await rev.analyze_lead(
        lead.id, website=WEAK, reputation=Reputation(total_reviews=9, google_rating=4.0), social=SocialSignals(), actor="alice"
    )
    return lead


async def approved_campaign(rev: RevenueOS, brand: Brand, leads: list[Lead]):  # type: ignore[no-untyped-def]
    c = rev.create_campaign(
        name="Austin plumbers Q4", brand=brand, consultant="Dana Reyes", lead_ids=[x.id for x in leads], created_by="mgr"
    )
    mgr = human("mgr", Role.MANAGER)
    p = await rev.request_launch(c.id, mgr)
    assert p.action.payload["recipients"] == len(leads) and p.risk == "medium"
    grant = (await rev.approvals.decide(p.id, human("boss", Role.ADMIN), approve=True)).grant
    assert grant
    return c, mgr, grant


async def test_lead_dedupe_analysis_and_grade(rev: RevenueOS) -> None:
    lead = await qualified(rev)
    again = await rev.add_lead(Lead(business_name="ACME dup", website="https://www.acmeplumbing.example"), actor="x")  # type: ignore[arg-type]
    assert again.id == lead.id and len(rev.leads) == 1
    assert lead.score == 100 and lead.grade is Grade.PLATINUM and lead.status is LeadStatus.QUALIFIED
    assert rev.reputation[lead.id].reputation_score > 0 and rev.seo[lead.id].seo_score == 20
    with pytest.raises(NotFound):
        rev.lead(uuid.uuid4())


async def test_full_revenue_loop(rev: RevenueOS, brand: Brand, mailer: OutboxMailer) -> None:
    a, b = await qualified(rev, "Acme Plumbing", "sam@acme.example"), await qualified(rev, "Bolt Electric", "jo@bolt.example")
    c, mgr, grant = await approved_campaign(rev, brand, [a, b])
    await rev.launch(c.id, grant.token, mgr, now=MONDAY)
    assert c.status is CampaignStatus.ACTIVE and len(rev.enrollments) == 2

    r1 = await rev.tick(MONDAY)  # DAY 1
    assert [s["step"] for s in r1.sent] == ["initial", "initial"] and len(mailer.sent) == 2
    first = mailer.sent[0]
    assert first["Subject"] == "Quick observation about Acme Plumbing" and first["List-Unsubscribe-Post"]
    assert "Weak on-page SEO".lower() not in first["Subject"].lower()
    assert (await rev.tick(MONDAY + timedelta(hours=1))).sent == []  # nothing due

    ea = next(e for e in rev.enrollments.values() if e.lead_id == a.id)
    eb = next(e for e in rev.enrollments.values() if e.lead_id == b.id)
    await rev.record_event(EngagementEvent.CLICKED, message_id=ea.sent[0].message_id, at=MONDAY + timedelta(hours=2))
    r3 = await rev.tick(MONDAY + timedelta(days=2))  # DAY 3 branches
    steps = {x["enrollment"]: x["step"] for x in r3.sent}
    assert steps[str(ea.id)] == "audit_sample" and steps[str(eb.id)] == "followup_1"
    assert mailer.sent[-1]["In-Reply-To"] == eb.sent[0].message_id  # threaded

    r7 = await rev.tick(MONDAY + timedelta(days=7))  # DAY 7
    steps = {x["enrollment"]: x["step"] for x in r7.sent}
    assert steps[str(ea.id)] == "meeting_invite" and steps[str(eb.id)] == "followup_2"

    await rev.record_event(EngagementEvent.REPLIED, email="SAM@acme.example", at=MONDAY + timedelta(days=8))
    assert ea.status is EnrollmentStatus.REPLIED and a.status is LeadStatus.OPPORTUNITY
    deal = next(d for d in rev.deals.values() if d.lead_id == a.id)
    assert deal.stage is Stage.OPPORTUNITY
    await rev.record_event(EngagementEvent.MEETING_BOOKED, enrollment_id=ea.id)
    assert deal.stage is Stage.MEETING

    r14 = await rev.tick(MONDAY + timedelta(days=14))  # DAY 14 only for b
    assert [x["step"] for x in r14.sent] == ["followup_3"]
    await rev.tick(MONDAY + timedelta(days=21))
    assert eb.status is EnrollmentStatus.COMPLETED and b.status is LeadStatus.NURTURE
    assert c.status is CampaignStatus.COMPLETED

    # proposal -> contract (approval) -> won -> MRR
    prop = await rev.generate_proposal(a.id, prepared_by="Dana")
    assert prop.recommended == "Scale" and "## 4. Investment" in to_markdown(prop)
    rev.move_deal(deal.id, Stage.PROPOSAL, actor="dana")
    with pytest.raises(PolicyViolation):
        rev.move_deal(deal.id, Stage.WON, actor="dana")
    contract = await rev.request_contract(deal.id, mgr, monthly_value=3000, setup_fee=1500, contract_months=12, package="Growth")
    with pytest.raises(PolicyViolation, match="pending"):
        await rev.close_won(deal.id, contract_proposal_id=contract.id, actor=mgr)
    cgrant = (await rev.approvals.decide(contract.id, human("boss", Role.ADMIN), approve=True)).grant
    assert cgrant
    rev.approvals.consume_grant(cgrant.token, contract.action)  # == POST /v1/approvals/{id}/execute
    deal.monthly_value = 9999  # tamper with terms after approval
    with pytest.raises(PolicyViolation, match="differ"):
        await rev.close_won(deal.id, contract_proposal_id=contract.id, actor=mgr)
    deal.monthly_value = 3000
    await rev.close_won(deal.id, contract_proposal_id=contract.id, actor=mgr)
    assert deal.stage is Stage.WON and a.status is LeadStatus.CLIENT

    dash = rev.dashboard()
    assert dash.mrr == 3000 and dash.arr == 36000 and dash.deals_won == 1 and dash.close_rate == 1.0
    assert dash.qualified_leads == 2 and dash.leads_by_grade["platinum"] == 2 and dash.proposals_sent == 1
    [cs] = dash.campaigns
    assert cs.enrolled == 2 and cs.emails_sent == 7 and cs.reply_rate == 0.5 and cs.meeting_rate == 0.5 and cs.click_rate == 0.5
    row = rev.outreach_row(ea)
    assert row["replied"] and row["meeting_booked"] and row["client_signed"] and row["proposal_sent"]
    types = [e.type for e in rev.bus.history]  # type: ignore[attr-defined]
    for t in (
        EventType.LEAD_FOUND,
        EventType.APPROVAL_REQUESTED,
        EventType.OPPORTUNITY_CREATED,
        EventType.PROPOSAL_GENERATED,
        EventType.CUSTOMER_CREATED,
    ):
        assert t in types
    assert rev.audit.verify().valid


async def test_campaign_approval_gates(rev: RevenueOS, brand: Brand) -> None:
    lead = await qualified(rev)
    c = rev.create_campaign(name="x", brand=brand, consultant="D", lead_ids=[lead.id], created_by="op")
    with pytest.raises(PolicyViolation):  # operators lack email:mass_send
        await rev.request_launch(c.id, human("op", Role.OPERATOR))
    mgr = human("mgr", Role.MANAGER)
    p = await rev.request_launch(c.id, mgr)
    with pytest.raises(AuthorizationError, match="separation"):
        await rev.approvals.decide(p.id, mgr, approve=True)
    grant = (await rev.approvals.decide(p.id, human("boss", Role.ADMIN), approve=True)).grant
    assert grant
    with pytest.raises(AuthorizationError):
        await rev.launch(c.id, grant.token, human("mgr", Role.MANAGER, mfa=False))
    c.lead_ids.append(uuid.uuid4())  # swap the audience after approval
    with pytest.raises(ApprovalError, match="differs"):
        await rev.launch(c.id, grant.token, mgr)
    with pytest.raises(ValidationFailed):
        rev.create_campaign(
            name="none", brand=brand, consultant="D", lead_ids=[(await qualified(rev, "No Mail", None)).id], created_by="op"
        )
    with pytest.raises(NotFound):
        rev.campaign(uuid.uuid4())


async def test_template_change_pauses_running_campaign(rev: RevenueOS, brand: Brand, tmp_path: Path) -> None:
    import shutil

    from revenueos.email import TEMPLATE_DIR

    shutil.copytree(TEMPLATE_DIR, tmp_path / "t")
    rev.renderer = EmailRenderer(tmp_path / "t")
    lead = await qualified(rev)
    c, mgr, grant = await approved_campaign(rev, brand, [lead])
    await rev.launch(c.id, grant.token, mgr, now=MONDAY)
    (tmp_path / "t" / "followup_1.txt.j2").write_text("Send me your password")
    report = await rev.tick(MONDAY)
    assert report.paused_campaigns == [str(c.id)] and report.sent == [] and c.status is CampaignStatus.PAUSED
    assert "templates changed" in (c.paused_reason or "")


async def test_unsubscribe_suppresses_everywhere(rev: RevenueOS, brand: Brand, mailer: OutboxMailer) -> None:
    lead = await qualified(rev)
    c, mgr, grant = await approved_campaign(rev, brand, [lead])
    await rev.launch(c.id, grant.token, mgr, now=MONDAY)
    await rev.tick(MONDAY)
    token = mailer.sent[0]["List-Unsubscribe"].strip("<>").rsplit("/", 1)[1]
    assert await rev.unsubscribe(token) and not await rev.unsubscribe("bad.token")
    assert lead.status is LeadStatus.SUPPRESSED
    assert (await rev.tick(MONDAY + timedelta(days=3))).sent == []
    with pytest.raises(ValidationFailed):  # suppressed leads never re-enter a campaign
        rev.create_campaign(name="again", brand=brand, consultant="D", lead_ids=[lead.id], created_by="op")


async def test_bounce_and_daily_cap(rev: RevenueOS, brand: Brand) -> None:
    leads = [await qualified(rev, f"Biz {i}", f"o{i}@biz{i}.example") for i in range(25)]
    c, mgr, grant = await approved_campaign(rev, brand, leads)
    await rev.launch(c.id, grant.token, mgr, now=MONDAY)
    r = await rev.tick(MONDAY)
    assert len(r.sent) == 20 and sum(1 for s in r.skipped if s["reason"] == "daily_cap") == 5  # warm-up cap
    e = next(iter(rev.enrollments.values()))
    await rev.record_event(EngagementEvent.BOUNCED, message_id=e.sent[0].message_id)
    assert e.status is EnrollmentStatus.BOUNCED and rev.suppression.is_suppressed(e.email)
    await rev.record_event(EngagementEvent.OPENED, message_id=e.sent[0].message_id)  # late open ignored
    assert e.opened_at is None


async def test_proposal_formats(rev: RevenueOS) -> None:
    lead = await qualified(rev)
    with pytest.raises(ValidationFailed):
        await rev.generate_proposal((await rev.add_lead(Lead(business_name="New"), actor="x")).id, prepared_by="D")
    p = await rev.generate_proposal(lead.id, prepared_by="Dana")
    html = to_html(p)
    assert "<table>" in html and "Growth Proposal" in html and "<script" not in html
    slides = to_slides(p)
    assert slides.startswith("---\nmarp: true") and slides.count("\n---\n") >= 6
    assert {i.component for i in p.plan.items} >= {"SEO", "Reviews", "Retargeting", "Google Business Profile", "Email", "Social media"}


def test_deal_transitions() -> None:
    from revenueos.pipeline import Deal

    d = Deal(lead_id=uuid.uuid4())
    with pytest.raises(ValueError):
        d.move(Stage.WON)
    d.move(Stage.PROPOSAL)
    with pytest.raises(ValueError, match="monthly_value"):
        d.move(Stage.WON)
    d.monthly_value = 1500
    d.move(Stage.WON)
    d.move(Stage.CHURNED)
    d.move(Stage.CHURNED)  # no-op
    assert d.churned_at and len(d.history) == 3 and d.weighted_monthly_value == 0


# ----------------------------------------------------------------------------- HTTP
MGR = {"Authorization": "Bearer dev:mgr:Manager:1"}
OP = {"Authorization": "Bearer dev:op:Operator:1"}
BOSS = {"Authorization": "Bearer dev:boss:Admin:1"}
VIEW = {"Authorization": "Bearer dev:v:Viewer:0"}


def test_http_flow(container: Container, brand: Brand) -> None:
    client = TestClient(create_app(container))
    r = client.post(
        "/v1/revenue/leads",
        headers=OP,
        json={
            "business_name": "Acme Plumbing",
            "email": "sam@acme.example",
            "website": "https://acme.example",
            "employee_count": 10,
            "owner_name": "Sam",
        },
    )
    assert r.status_code == 200
    lid = r.json()["id"]
    assert client.post("/v1/revenue/leads", headers=VIEW, json={"business_name": "x"}).status_code == 403
    a = client.post(f"/v1/revenue/leads/{lid}/analyze", headers=OP, json={"website": WEAK.model_dump(), "reputation": {"total_reviews": 5}})
    assert a.status_code == 200 and a.json()["score"]["grade"] == "platinum"
    assert client.get("/v1/revenue/leads?grade=platinum", headers=VIEW).json()[0]["id"] == lid
    md = client.get(f"/v1/revenue/leads/{lid}/proposal", headers=OP)
    assert md.headers["content-type"].startswith("text/markdown") and "Growth Proposal" in md.text
    assert client.get(f"/v1/revenue/leads/{lid}/proposal?format=html", headers=OP).text.startswith("<!DOCTYPE html>")
    assert client.get(f"/v1/revenue/leads/{lid}/proposal?format=json", headers=OP).json()["recommended"]
    assert "marp: true" in client.get(f"/v1/revenue/leads/{lid}/proposal?format=slides", headers=OP).text
    b = json.loads(brand.model_dump_json())
    pv = client.post(
        "/v1/revenue/campaigns/preview", headers=OP, json={"brand": b, "consultant": "Dana", "lead_id": lid, "step": "audit_sample"}
    )
    assert pv.status_code == 200 and "Acme Plumbing" in pv.text and pv.headers["x-email-subject"]

    camp = client.post("/v1/revenue/campaigns", headers=OP, json={"name": "Q4", "brand": b, "consultant": "Dana", "lead_ids": [lid]}).json()
    assert client.post(f"/v1/revenue/campaigns/{camp['id']}/request-launch", headers=OP).status_code == 403
    prop = client.post(f"/v1/revenue/campaigns/{camp['id']}/request-launch", headers=MGR).json()
    token = client.post(f"/v1/approvals/{prop['id']}/decision", headers=BOSS, json={"approve": True}).json()["grant"]["token"]
    assert client.post(f"/v1/revenue/campaigns/{camp['id']}/launch", headers=MGR, json={"grant_token": token}).json()["status"] == "active"
    assert len(client.get("/v1/revenue/campaigns", headers=VIEW).json()) == 1

    path = "/v1/integrations/revenue/tick"
    tick = client.post(path, content=b"", headers=RequestSigner("n8n", KEY.encode()).sign("POST", path, b""))
    assert tick.status_code == 200
    assert client.post(path).status_code == 401  # unsigned
    rev: RevenueOS = client.app.state.revenue  # type: ignore[attr-defined]
    sent = tick.json()["sent"]
    if sent:  # depends on wall-clock send window; engine logic is covered above with a fixed clock
        msg_id = next(iter(rev.enrollments.values())).sent[0].message_id
        body = json.dumps({"event": "replied", "message_id": msg_id}).encode()
        ep = "/v1/integrations/revenue/email-events"
        ev = client.post(
            ep, content=body, headers={**RequestSigner("n8n", KEY.encode()).sign("POST", ep, body), "Content-Type": "application/json"}
        )
        assert ev.json() == {"matched": 1}

    tok = rev.tokens.make("sam@acme.example")
    assert client.get(f"/u/{tok}").status_code == 200 and rev.suppression.is_suppressed("sam@acme.example")
    assert client.post("/u/forged.token").status_code == 400
    assert client.get("/v1/revenue/outreach", headers=VIEW).json()[0]["sequence_name"] == "sequence_1"

    deal = client.post("/v1/revenue/deals", headers=OP, json={"lead_id": lid}).json()
    assert client.post(f"/v1/revenue/deals/{deal['id']}/stage", headers=OP, json={"stage": "proposal"}).json()["stage"] == "proposal"
    assert client.post(f"/v1/revenue/deals/{deal['id']}/stage", headers=OP, json={"stage": "won"}).status_code == 403
    assert (
        client.post(f"/v1/revenue/deals/{deal['id']}/contract", headers=OP, json={"monthly_value": 2000, "package": "Growth"}).status_code
        == 403
    )
    cp = client.post(f"/v1/revenue/deals/{deal['id']}/contract", headers=MGR, json={"monthly_value": 2000, "package": "Growth"}).json()
    ct = client.post(f"/v1/approvals/{cp['id']}/decision", headers=BOSS, json={"approve": True}).json()["grant"]["token"]
    assert client.post(f"/v1/approvals/{cp['id']}/execute", headers=MGR, json={"grant_token": ct}).json()["status"] == "executed"
    won = client.post(f"/v1/revenue/deals/{deal['id']}/won", headers=MGR, json={"contract_proposal_id": cp["id"]})
    assert won.status_code == 200 and won.json()["stage"] == "won"
    assert client.get("/v1/revenue/deals?stage=won", headers=VIEW).json()[0]["monthly_value"] == 2000
    d = client.get("/v1/revenue/dashboard", headers=VIEW).json()
    assert d["mrr"] == 2000 and d["arr"] == 24000
    assert client.post(f"/v1/revenue/campaigns/{camp['id']}/pause", headers=OP).json()["status"] == "paused"


def test_preview_steps_cover_all(brand: Brand) -> None:
    assert {s.value for s in EmailStep} == {
        p.name.split(".")[0] for p in __import__("revenueos.email", fromlist=["x"]).TEMPLATE_DIR.glob("*.html.j2")
    } - {"_base"}
