"""Lead Scoring Engine — exact implementation of the RevenueOS rubric (score out of 100, capped).

SEO opportunity      none +25 · weak +15 · average +5 · strong 0
Website quality      missing site +20 · speed<50 +15 · no CTA +10 · bad mobile +10 · outdated design +10
Reputation           <20 reviews +15 · 20-50 +10 · 50-100 +5 · 100+ 0
Social presence      no Facebook +5 · no Instagram +5 · inactive +5
Advertising          no Google Ads +5 · no social ads +5
Revenue potential    ideal +20 · mid-market +15 · enterprise +5

High score == high *opportunity for us* (weak presence + right-sized business), not business quality.
Unknown signals score 0 — we never award points for data we did not observe.
"""

from __future__ import annotations

from pydantic import BaseModel

from revenueos.models import Grade, Lead, LeadScore, Reputation, ScoreItem, Segment, SocialSignals, WebsiteSignals


class ICP(BaseModel):
    """Ideal-customer profile used for the revenue-potential component. Tune per agency."""

    ideal_employees: tuple[int, int] = (3, 50)
    ideal_revenue: tuple[float, float] = (300_000, 5_000_000)
    mid_market_employees: tuple[int, int] = (51, 500)
    enterprise_min_employees: int = 501
    target_industries: list[str] = []  # empty = any


def classify_segment(lead: Lead, icp: ICP) -> Segment:
    emp, rev = lead.employee_count, lead.estimated_revenue
    if icp.target_industries and (lead.industry or "").lower() not in {i.lower() for i in icp.target_industries}:
        return Segment.UNKNOWN
    if emp is not None:
        if emp >= icp.enterprise_min_employees:
            return Segment.ENTERPRISE
        if icp.mid_market_employees[0] <= emp <= icp.mid_market_employees[1]:
            return Segment.MID_MARKET
        if icp.ideal_employees[0] <= emp <= icp.ideal_employees[1]:
            return Segment.IDEAL
        return Segment.UNKNOWN
    if rev is not None:
        if icp.ideal_revenue[0] <= rev <= icp.ideal_revenue[1]:
            return Segment.IDEAL
        if rev > icp.ideal_revenue[1] * 10:
            return Segment.ENTERPRISE
        if rev > icp.ideal_revenue[1]:
            return Segment.MID_MARKET
    return Segment.UNKNOWN


def grade_for(score: int) -> Grade:
    if score >= 90:
        return Grade.PLATINUM
    if score >= 75:
        return Grade.GOLD
    if score >= 60:
        return Grade.SILVER
    if score >= 40:
        return Grade.BRONZE
    return Grade.IGNORE


def score_lead(
    lead: Lead,
    website: WebsiteSignals,
    reputation: Reputation | None,
    social: SocialSignals,
    icp: ICP | None = None,
) -> LeadScore:
    icp = icp or ICP()
    items: list[ScoreItem] = []

    def add(category: str, rule: str, points: int) -> None:
        if points:
            items.append(ScoreItem(category=category, rule=rule, points=points))

    # SEO opportunity
    seo = website.seo_score
    if not website.has_website or seo == 0:
        add("seo", "no_seo", 25)
    elif seo is not None:
        if seo < 40:
            add("seo", "weak_seo", 15)
        elif seo < 70:
            add("seo", "average_seo", 5)

    # Website quality
    if not website.has_website:
        add("website", "missing_site", 20)
    else:
        if website.page_speed_score is not None and website.page_speed_score < 50:
            add("website", "page_speed_below_50", 15)
        if website.has_cta is False:
            add("website", "no_cta", 10)
        bad_mobile = website.mobile_friendly is False or (website.mobile_score is not None and website.mobile_score < 50)
        if bad_mobile:
            add("website", "bad_mobile_experience", 10)
        if website.outdated_design:
            add("website", "outdated_design", 10)

    # Reputation
    reviews = reputation.total_reviews if reputation else None
    if reviews is not None:
        if reviews < 20:
            add("reputation", "under_20_reviews", 15)
        elif reviews <= 50:
            add("reputation", "20_to_50_reviews", 10)
        elif reviews <= 100:
            add("reputation", "50_to_100_reviews", 5)

    # Social presence
    if not social.has_facebook:
        add("social", "no_facebook", 5)
    if not social.has_instagram:
        add("social", "no_instagram", 5)
    if (social.has_facebook or social.has_instagram) and social.inactive:
        add("social", "inactive_social", 5)

    # Advertising
    if social.runs_google_ads is False or (social.runs_google_ads is None and website.has_google_ads_tag is False):
        add("advertising", "no_google_ads", 5)
    if social.runs_social_ads is False or (social.runs_social_ads is None and website.has_meta_pixel is False):
        add("advertising", "no_social_ads", 5)

    # Revenue potential
    segment = classify_segment(lead, icp)
    add("revenue", segment.value, {Segment.IDEAL: 20, Segment.MID_MARKET: 15, Segment.ENTERPRISE: 5}.get(segment, 0))

    raw = sum(i.points for i in items)
    total = min(100, raw)
    return LeadScore(lead_id=lead.id, total=total, raw_total=raw, grade=grade_for(total), segment=segment, breakdown=items)
