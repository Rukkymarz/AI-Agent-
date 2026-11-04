from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from revenueos.email import (
    SUBJECTS,
    Brand,
    EmailRenderer,
    EmailStep,
    OutboundEmail,
    SendPolicy,
    SuppressionList,
    SuppressionReason,
    UnsubscribeTokens,
)
from revenueos.sequences import DecisionKind, EngagementEvent, Enrollment, EnrollmentStatus, PipelineMove, SentStep, decide
from tests.revenueos.conftest import MONDAY

R = EmailRenderer()


def ctx(**kw: object) -> dict[str, object]:
    return {"business_name": "Acme Plumbing", "owner_name": "Sam", "consultant": "Dana Reyes", "city": "Austin", **kw}


@pytest.mark.parametrize("step", list(EmailStep))
def test_every_step_renders_html_and_text(step: EmailStep, brand: Brand) -> None:
    findings = [{"area": "seo", "severity": "high", "finding": "Weak on-page SEO", "recommendation": "Fix titles", "evidence": "x"}]
    r = R.render(
        step,
        brand=brand,
        context=ctx(findings=findings, health_score=42, top_finding=findings[0]),
        unsubscribe_url="https://api.northwind.example/u/tok",
    )
    for part in (r.html, r.text):
        assert "100 Main St, Suite 4, Austin, TX 78701" in part  # CAN-SPAM postal address
        assert "https://api.northwind.example/u/tok" in part  # unsubscribe
        assert "Dana Reyes" in part and "Acme Plumbing" in part
    assert r.html.startswith("<!DOCTYPE html>") and 'name="viewport"' in r.html and "@media only screen" in r.html
    assert r.subject == SUBJECTS[step].format(business_name="Acme Plumbing")


def test_day1_matches_spec_copy(brand: Brand) -> None:
    r = R.render(EmailStep.INITIAL, brand=brand, context=ctx(), unsubscribe_url="https://x.example/u")
    assert r.subject == "Quick observation about Acme Plumbing"
    assert "Hi Sam," in r.text and "I reviewed Acme Plumbing and identified several opportunities related to:" in r.text
    for item in ("Search visibility", "Website performance", "Customer reviews", "Lead generation"):
        assert f"• {item}" in r.text
    assert "Would you like a complimentary summary report?" in r.text and "Best regards," in r.text
    assert "Get my free summary report" in r.html and brand.report_url in r.html


def test_subjects_follow_spec() -> None:
    assert SUBJECTS[EmailStep.FOLLOWUP_1] == "Following up on the opportunities we identified"
    assert SUBJECTS[EmailStep.FOLLOWUP_2] == "Worth a quick conversation?"
    assert SUBJECTS[EmailStep.FOLLOWUP_3] == "Final follow-up"


def test_html_escaping_and_header_injection(brand: Brand) -> None:
    evil = "<script>alert(1)</script>Acme\r\nBcc: victim@x.com"
    r = R.render(
        EmailStep.INITIAL,
        brand=brand,
        context=ctx(business_name=evil, owner_name="<img src=x onerror=1>"),
        unsubscribe_url="https://x.example/u",
    )
    assert "<script>alert(1)</script>" not in r.html and "&lt;script&gt;" in r.html
    assert "<img src=x" not in r.html
    assert "\r" not in r.subject and "\n" not in r.subject
    mime = OutboundEmail(to_email="sam@acme.example", rendered=r, brand=brand, unsubscribe_url="https://x.example/u").to_mime()
    assert "Bcc" not in mime


def test_missing_owner_name_and_strict_undefined(brand: Brand) -> None:
    r = R.render(
        EmailStep.FOLLOWUP_3, brand=brand, context={"business_name": "Acme", "consultant": "Dana"}, unsubscribe_url="https://x.example/u"
    )
    assert "Hi there," in r.text and "Get" not in r.html.split("Closing the loop")[-1].split("Best regards")[0]


def test_mime_headers(brand: Brand) -> None:
    r = R.render(EmailStep.FOLLOWUP_2, brand=brand, context=ctx(), unsubscribe_url="https://x.example/u/abc")
    m = OutboundEmail(
        to_email="sam@acme.example",
        to_name="Sam",
        rendered=r,
        brand=brand,
        unsubscribe_url="https://x.example/u/abc",
        in_reply_to="<first@northwind.example>",
        headers={"X-AICOS-Step": "followup_2", "Evil-Header": "x"},
    ).to_mime()
    assert m["List-Unsubscribe"] == "<https://x.example/u/abc>" and m["List-Unsubscribe-Post"] == "List-Unsubscribe=One-Click"
    assert m["In-Reply-To"] == "<first@northwind.example>" and m["X-AICOS-Step"] == "followup_2" and m["Evil-Header"] is None
    assert m.is_multipart() and {p.get_content_type() for p in m.iter_parts()} == {"text/plain", "text/html"}


def test_template_bundle_hash_stable() -> None:
    assert R.bundle_hash() == EmailRenderer().bundle_hash() and len(R.bundle_hash()) == 64


def test_unsubscribe_tokens_and_suppression() -> None:
    t = UnsubscribeTokens(b"k" * 32)
    tok = t.make("Sam@Acme.example ")
    assert t.parse(tok) == "sam@acme.example"
    assert t.parse(tok[:-1] + ("0" if tok[-1] != "0" else "1")) is None and t.parse("garbage") is None and t.parse("zz.yy") is None
    with pytest.raises(ValueError):
        UnsubscribeTokens(b"short")
    s = SuppressionList()
    s.add("SAM@acme.example", SuppressionReason.UNSUBSCRIBED)
    assert s.is_suppressed("sam@acme.example ") and len(s) == 1


def test_send_window_and_warmup() -> None:
    p = SendPolicy()
    sat = datetime(2026, 11, 7, 15, 0, tzinfo=UTC)
    nxt = p.next_window(sat, "America/New_York")
    assert nxt.weekday() == 0 and nxt.hour == 9  # Monday 9:00 local
    early = datetime(2026, 11, 2, 10, 0, tzinfo=UTC)  # 05:00 NY
    assert p.next_window(early, "America/New_York").hour == 9
    late = datetime(2026, 11, 2, 23, 0, tzinfo=UTC)  # 18:00 NY
    assert p.next_window(late, "America/New_York").day == 3
    inside = MONDAY + timedelta(hours=2)
    assert p.next_window(inside, "America/New_York") == inside
    assert p.daily_cap(0) == 20 and p.daily_cap(5) == 70 and p.daily_cap(100) == 150


# ----------------------------------------------------------------------------- follow-up decision engine
def enr(**kw: object) -> Enrollment:
    return Enrollment(campaign_id=uuid.uuid4(), lead_id=uuid.uuid4(), email="sam@acme.example", started_at=MONDAY, **kw)  # type: ignore[arg-type]


def sent(e: Enrollment, step: EmailStep, at: datetime) -> None:
    e.sent.append(SentStep(step=step, sent_at=at, message_id=f"<{step}@x>"))


def test_day1_sends_initial_immediately() -> None:
    d = decide(enr(), MONDAY)
    assert d.kind is DecisionKind.SEND and d.step is EmailStep.INITIAL


@pytest.mark.parametrize(
    ("opened", "clicked", "step"),
    [
        (False, False, EmailStep.FOLLOWUP_1),
        (True, False, EmailStep.CASE_STUDY),
        (True, True, EmailStep.AUDIT_SAMPLE),
        (False, True, EmailStep.AUDIT_SAMPLE),
    ],
)
def test_day3_branches(opened: bool, clicked: bool, step: EmailStep) -> None:
    e = enr()
    sent(e, EmailStep.INITIAL, MONDAY)
    if opened:
        e.apply(EngagementEvent.OPENED, MONDAY + timedelta(hours=1))
    if clicked:
        e.apply(EngagementEvent.CLICKED, MONDAY + timedelta(hours=2))
    wait = decide(e, MONDAY + timedelta(days=1))
    assert wait.kind is DecisionKind.WAIT and wait.send_at == MONDAY + timedelta(days=2) and wait.step is step
    go = decide(e, MONDAY + timedelta(days=2))
    assert go.kind is DecisionKind.SEND and go.step is step


@pytest.mark.parametrize(("clicked", "step"), [(False, EmailStep.FOLLOWUP_2), (True, EmailStep.MEETING_INVITE)])
def test_day7_branches(clicked: bool, step: EmailStep) -> None:
    e = enr()
    sent(e, EmailStep.INITIAL, MONDAY)
    sent(e, EmailStep.FOLLOWUP_1, MONDAY + timedelta(days=2))
    if clicked:
        e.apply(EngagementEvent.CLICKED, MONDAY + timedelta(days=3))
    sunday = decide(e, MONDAY + timedelta(days=6))  # day 7 is a Sunday -> waits for Monday 09:00 local
    assert sunday.kind is DecisionKind.WAIT and sunday.send_at == MONDAY + timedelta(days=7)
    d = decide(e, MONDAY + timedelta(days=7))
    assert d.kind is DecisionKind.SEND and d.step is step


def test_day14_breakup_then_nurture() -> None:
    e = enr()
    for i, s in enumerate([EmailStep.INITIAL, EmailStep.FOLLOWUP_1, EmailStep.FOLLOWUP_2]):
        sent(e, s, MONDAY + timedelta(days=[0, 2, 6][i]))
    d = decide(e, MONDAY + timedelta(days=13))  # day 14 = Sunday
    assert d.step is EmailStep.FOLLOWUP_3 and d.kind is DecisionKind.WAIT and d.send_at == MONDAY + timedelta(days=14)
    assert decide(e, MONDAY + timedelta(days=14)).kind is DecisionKind.SEND
    sent(e, EmailStep.FOLLOWUP_3, MONDAY + timedelta(days=14))
    end = decide(e, MONDAY + timedelta(days=20))
    assert end.kind is DecisionKind.STOP and end.pipeline is PipelineMove.NURTURE


@pytest.mark.parametrize(
    ("event", "move"),
    [
        (EngagementEvent.REPLIED, PipelineMove.OPPORTUNITY),
        (EngagementEvent.MEETING_BOOKED, PipelineMove.MEETING),
        (EngagementEvent.UNSUBSCRIBED, PipelineMove.SUPPRESS),
        (EngagementEvent.COMPLAINED, PipelineMove.SUPPRESS),
        (EngagementEvent.BOUNCED, PipelineMove.SUPPRESS),
    ],
)
def test_terminal_events_stop_sequence(event: EngagementEvent, move: PipelineMove) -> None:
    e = enr()
    sent(e, EmailStep.INITIAL, MONDAY)
    e.apply(event, MONDAY + timedelta(hours=3))
    d = decide(e, MONDAY + timedelta(days=2))
    assert d.kind is DecisionKind.STOP and d.pipeline is move


def test_no_two_touches_within_24h_and_paused() -> None:
    e = enr()
    sent(e, EmailStep.INITIAL, MONDAY + timedelta(days=1, hours=20))  # initial went out late
    d = decide(e, MONDAY + timedelta(days=2))
    assert d.kind is DecisionKind.WAIT and d.send_at and d.send_at >= MONDAY + timedelta(days=2, hours=20)
    p = enr(status=EnrollmentStatus.PAUSED)
    assert decide(p, MONDAY).kind is DecisionKind.WAIT
    c = enr(status=EnrollmentStatus.COMPLETED)
    assert decide(c, MONDAY).pipeline is PipelineMove.NURTURE


def test_apply_is_idempotent_and_click_implies_open() -> None:
    e = enr()
    e.apply(EngagementEvent.CLICKED, MONDAY)
    e.apply(EngagementEvent.CLICKED, MONDAY + timedelta(days=1))
    e.apply(EngagementEvent.DELIVERED, MONDAY)
    assert e.clicked_at == MONDAY and e.opened_at == MONDAY and e.thread_id is None


def test_font_stack_valid_css_and_injection_rejected(brand: Brand) -> None:
    from pydantic import ValidationError

    r = R.render(EmailStep.INITIAL, brand=brand, context=ctx(), unsubscribe_url="https://x.example/u")
    style = r.html.split("<style>")[1].split("</style>")[0]
    assert "'Segoe UI'" in style and "&#39;" not in style
    with pytest.raises(ValidationError):
        brand.model_validate({**brand.model_dump(), "font_stack": "Arial}</style><script>alert(1)</script>"})
