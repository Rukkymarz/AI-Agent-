from __future__ import annotations

from datetime import UTC, datetime

import pytest

from revenueos.analyzer import analyze, extract_signals, reputation_score
from revenueos.models import Grade, Lead, Reputation, Segment, SocialSignals, WebsiteSignals
from revenueos.scoring import ICP, classify_segment, grade_for, score_lead

LEAD = Lead(business_name="Acme Plumbing", employee_count=12, industry="plumbing")


def rules(score) -> dict[str, int]:  # type: ignore[no-untyped-def]
    return {i.rule: i.points for i in score.breakdown}


def test_worst_presence_caps_at_100() -> None:
    s = score_lead(LEAD, WebsiteSignals(has_website=False), Reputation(total_reviews=3), SocialSignals())
    r = rules(s)
    assert r["no_seo"] == 25 and r["missing_site"] == 20 and r["under_20_reviews"] == 15
    assert r["no_facebook"] == 5 and r["no_instagram"] == 5 and r["ideal"] == 20
    assert s.raw_total == 90 and s.total == 90 and s.grade is Grade.PLATINUM


def test_website_rules_and_cap() -> None:
    web = WebsiteSignals(
        seo_score=20,
        page_speed_score=30,
        has_cta=False,
        mobile_friendly=False,
        outdated_design=True,
        has_meta_pixel=False,
        has_google_ads_tag=False,
    )
    s = score_lead(LEAD, web, Reputation(total_reviews=10), SocialSignals())
    r = rules(s)
    assert {
        "weak_seo": 15,
        "page_speed_below_50": 15,
        "no_cta": 10,
        "bad_mobile_experience": 10,
        "outdated_design": 10,
        "no_google_ads": 5,
        "no_social_ads": 5,
    }.items() <= r.items()
    assert s.raw_total > 100 and s.total == 100


@pytest.mark.parametrize(
    ("reviews", "rule", "pts"),
    [
        (0, "under_20_reviews", 15),
        (19, "under_20_reviews", 15),
        (20, "20_to_50_reviews", 10),
        (50, "20_to_50_reviews", 10),
        (51, "50_to_100_reviews", 5),
        (100, "50_to_100_reviews", 5),
    ],
)
def test_reputation_bands(reviews: int, rule: str, pts: int) -> None:
    s = score_lead(
        LEAD,
        WebsiteSignals(seo_score=90),
        Reputation(total_reviews=reviews),
        SocialSignals(has_facebook=True, has_instagram=True, last_post_days_ago=1),
    )
    assert rules(s)[rule] == pts


def test_strong_business_scores_low_and_unknowns_score_zero() -> None:
    strong = WebsiteSignals(seo_score=85, page_speed_score=90, has_cta=True, mobile_friendly=True, outdated_design=False)
    social = SocialSignals(has_facebook=True, has_instagram=True, last_post_days_ago=2, runs_google_ads=True, runs_social_ads=True)
    s = score_lead(Lead(business_name="Big Co", employee_count=2000), strong, Reputation(total_reviews=400), social)
    assert rules(s) == {"enterprise": 5} and s.grade is Grade.IGNORE
    unknown = score_lead(
        Lead(business_name="X"), WebsiteSignals(), None, SocialSignals(has_facebook=True, has_instagram=True, last_post_days_ago=1)
    )
    assert unknown.total == 0


def test_seo_tiers_and_inactive_social() -> None:
    assert "average_seo" in rules(score_lead(LEAD, WebsiteSignals(seo_score=55), None, SocialSignals()))
    assert "no_seo" in rules(score_lead(LEAD, WebsiteSignals(seo_score=0), None, SocialSignals()))
    s = score_lead(LEAD, WebsiteSignals(seo_score=80), None, SocialSignals(has_facebook=True, has_instagram=True, last_post_days_ago=90))
    assert rules(s).get("inactive_social") == 5


@pytest.mark.parametrize(
    ("score", "grade"),
    [
        (100, Grade.PLATINUM),
        (90, Grade.PLATINUM),
        (89, Grade.GOLD),
        (75, Grade.GOLD),
        (74, Grade.SILVER),
        (60, Grade.SILVER),
        (59, Grade.BRONZE),
        (40, Grade.BRONZE),
        (39, Grade.IGNORE),
    ],
)
def test_grade_boundaries(score: int, grade: Grade) -> None:
    assert grade_for(score) is grade


def test_segments() -> None:
    icp = ICP()
    assert classify_segment(Lead(business_name="a", employee_count=10), icp) is Segment.IDEAL
    assert classify_segment(Lead(business_name="a", employee_count=200), icp) is Segment.MID_MARKET
    assert classify_segment(Lead(business_name="a", employee_count=900), icp) is Segment.ENTERPRISE
    assert classify_segment(Lead(business_name="a", employee_count=1), icp) is Segment.UNKNOWN
    assert classify_segment(Lead(business_name="a", estimated_revenue=1_000_000), icp) is Segment.IDEAL
    assert classify_segment(Lead(business_name="a", estimated_revenue=20_000_000), icp) is Segment.MID_MARKET
    assert classify_segment(Lead(business_name="a", estimated_revenue=90_000_000), icp) is Segment.ENTERPRISE
    assert classify_segment(Lead(business_name="a"), icp) is Segment.UNKNOWN
    assert (
        classify_segment(Lead(business_name="a", employee_count=10, industry="law"), ICP(target_industries=["dental"])) is Segment.UNKNOWN
    )


OLD_SITE = """<html><head><title>Bob's Plumbing</title></head><body bgcolor="#fff"><center><font>Welcome</font></center>
<p>We fix pipes.</p><p>&copy; 2019 Bob's Plumbing</p></body></html>"""

MODERN = (
    """<html><head><title>Acme Dental | Family Dentist in Austin TX</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="Gentle family dentistry in Austin. Same-week appointments, most insurance accepted, free whitening consult.">
<script type="application/ld+json">{"@type":"Dentist","name":"Acme"}</script>
<script src="https://widget.intercom.io/widget/abc"></script>
<script>fbq('init','123');</script><script async src="https://www.googleadservices.com/pagead/conversion.js"></script>
</head><body><h1>Acme Dental</h1><a href="/blog/">Blog</a><p>Book an appointment today. Call (512) 555-0101. Austin TX 78701</p>
"""
    + "<p>"
    + "word " * 700
    + "</p><footer>© 2025 Acme</footer></body></html>"
)


def test_extract_signals_old_vs_modern() -> None:
    now = datetime(2026, 6, 1, tzinfo=UTC)
    old = extract_signals(OLD_SITE, url="http://bobsplumbing.example", now=now)
    assert old.outdated_design and old.mobile_friendly is False and old.has_cta is False and old.has_chat is False
    assert old.copyright_year == 2019 and old.https is False and (old.seo_score or 0) < 40
    new = extract_signals(MODERN, url="https://acmedental.example", now=now)
    assert new.mobile_friendly and new.has_cta and new.has_chat and new.has_meta_pixel and new.has_google_ads_tag
    assert new.has_blog and not new.outdated_design and (new.seo_score or 0) >= 80 and new.local_seo_score == 100


def test_analysis_findings_and_flags() -> None:
    web = extract_signals(OLD_SITE, url="http://bobsplumbing.example", now=datetime(2026, 6, 1, tzinfo=UTC))
    a = analyze(LEAD, web, Reputation(total_reviews=8, google_rating=4.1, response_rate=0.2), SocialSignals())
    assert {"poor_seo", "outdated_design", "missing_chat", "low_reviews", "weak_content", "weak_social_presence", "no_retargeting"} <= set(
        a.opportunity.flags()
    )
    assert a.top_opportunities(2)[0].severity == "high"
    assert all(f.evidence for f in a.findings)
    assert 0 <= a.business_health_score < 50 and a.sales_score <= 40
    nosite = analyze(LEAD, WebsiteSignals(has_website=False), None, SocialSignals())
    assert nosite.seo_score == 0 and nosite.opportunity.poor_seo and nosite.findings[0].finding == "No website found"


def test_reputation_score() -> None:
    assert reputation_score(None) == 0
    assert reputation_score(Reputation(google_rating=5, total_reviews=200, response_rate=1)) == 100
