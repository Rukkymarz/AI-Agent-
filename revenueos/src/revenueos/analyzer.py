"""Business Analyzer: website HTML heuristics -> signals -> health/SEO/marketing/sales scores + opportunities.

Deterministic and explainable (every finding cites the signal that produced it). LLM agents narrate the
report; they never invent the numbers. Page-speed comes from Google PageSpeed Insights / Lighthouse when
configured (`PageSpeedProvider`); otherwise it is left unknown and scores 0 points.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Protocol

from pydantic import BaseModel, Field

from revenueos.models import Lead, Opportunity, Reputation, SocialSignals, WebsiteSignals

_CTA = re.compile(
    r"\b(book (a |an |your )?(call|appointment|consultation|demo|now)|get (a |your )?(free )?(quote|estimate|started)|"
    r"schedule (a |your )?(call|appointment|consultation)|contact us|call (us )?(now|today)|request (a )?(quote|callback)|buy now|sign up)\b",
    re.I,
)
_CHAT = re.compile(
    r"(intercom|drift\.com|tawk\.to|crisp\.chat|livechatinc|zopim|zendesk.*widget|hubspot.*conversations|tidio|olark|freshchat)", re.I
)
_META_PIXEL = re.compile(r"(connect\.facebook\.net/[^\"']+/fbevents\.js|fbq\(\s*['\"]init)", re.I)
_GADS = re.compile(r"(googleadservices\.com|gtag\(\s*['\"]config['\"]\s*,\s*['\"]AW-|google_conversion_id)", re.I)
_VIEWPORT = re.compile(r"<meta[^>]+name=[\"']viewport[\"']", re.I)
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_META_DESC = re.compile(r"<meta[^>]+name=[\"']description[\"'][^>]+content=[\"']([^\"']*)", re.I)
_H1 = re.compile(r"<h1[\s>]", re.I)
_SCHEMA = re.compile(r"application/ld\+json", re.I)
_LOCALBIZ = re.compile(r"\"@type\"\s*:\s*\"(LocalBusiness|[A-Za-z]+Business|Restaurant|Dentist|Attorney|Plumber|HVACBusiness)\"", re.I)
_COPYRIGHT = re.compile(r"(?:©|&copy;|copyright)\s*(?:\d{4}\s*[-\u2013]\s*)?(\d{4})", re.I)
_OUTDATED = re.compile(r"(<table[^>]+width=|<font[\s>]|<marquee|<center>|jquery-1\.|\.swf\b|bgcolor=)", re.I)
_TAGS = re.compile(r"<script.*?</script>|<style.*?</style>|<[^>]+>", re.I | re.S)
_BLOG = re.compile(r"href=[\"'][^\"']*/(blog|news|articles|insights)[/\"']", re.I)


def extract_signals(html: str, *, url: str, now: datetime | None = None) -> WebsiteSignals:
    now = now or datetime.now(UTC)
    text = re.sub(r"\s+", " ", _TAGS.sub(" ", html))
    years = [int(y) for y in _COPYRIGHT.findall(html) if 1990 <= int(y) <= now.year + 1]
    copyright_year = max(years) if years else None
    outdated = bool(_OUTDATED.search(html)) or (copyright_year is not None and now.year - copyright_year >= 3)

    seo = 0
    seo += 15 if (m := _TITLE.search(html)) and 10 <= len(m.group(1).strip()) <= 70 else 0
    seo += 15 if (d := _META_DESC.search(html)) and 50 <= len(d.group(1)) <= 170 else 0
    seo += 10 if _H1.search(html) else 0
    seo += 15 if _SCHEMA.search(html) else 0
    seo += 15 if url.startswith("https://") else 0
    seo += 10 if _VIEWPORT.search(html) else 0
    words = len(text.split())
    seo += 20 if words >= 600 else 10 if words >= 300 else 0
    local = 50 if _LOCALBIZ.search(html) else 0
    local += 25 if re.search(r"(?<!\d)\(?\d{3}\)?[\s.-]?\d{3}[\s.-]\d{4}(?!\d)", text) else 0  # NAP: phone
    local += 25 if re.search(r"\b\d{5}(-\d{4})?\b", text) else 0

    return WebsiteSignals(
        has_website=True,
        mobile_friendly=bool(_VIEWPORT.search(html)),
        has_cta=bool(_CTA.search(text)),
        has_chat=bool(_CHAT.search(html)),
        outdated_design=outdated,
        https=url.startswith("https://"),
        word_count=words,
        has_blog=bool(_BLOG.search(html)),
        has_meta_pixel=bool(_META_PIXEL.search(html)),
        has_google_ads_tag=bool(_GADS.search(html)),
        copyright_year=copyright_year,
        seo_score=min(100, seo),
        local_seo_score=min(100, local),
    )


class PageSpeedProvider(Protocol):
    async def scores(self, url: str) -> tuple[int | None, int | None]: ...  # (performance, mobile)


class PageSpeedInsights:  # pragma: no cover - network
    """Google PageSpeed Insights v5 (free API key). Strategy=mobile."""

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    async def scores(self, url: str) -> tuple[int | None, int | None]:
        import httpx

        async with httpx.AsyncClient(timeout=60) as c:
            r = await c.get(
                "https://www.googleapis.com/pagespeedonline/v5/runPagespeed", params={"url": url, "strategy": "mobile", "key": self.api_key}
            )
            r.raise_for_status()
            perf = r.json()["lighthouseResult"]["categories"]["performance"]["score"]
            score = round(perf * 100) if perf is not None else None
            return score, score


async def fetch_signals(url: str, pagespeed: PageSpeedProvider | None = None) -> WebsiteSignals:  # pragma: no cover - network
    import httpx

    from aicos.knowledge.loaders import assert_public_url

    assert_public_url(url, allow_http=True)
    async with httpx.AsyncClient(
        timeout=20, follow_redirects=True, max_redirects=3, headers={"User-Agent": "Mozilla/5.0 (compatible; RevenueOS-Audit/0.1)"}
    ) as c:
        r = await c.get(url)
        assert_public_url(str(r.url), allow_http=True)  # re-check after redirects
        html = r.text[:2_000_000]
    signals = extract_signals(html, url=str(r.url))
    if pagespeed:
        perf, mobile = await pagespeed.scores(str(r.url))
        signals.page_speed_score, signals.mobile_score = perf, mobile
    return signals


class Finding(BaseModel):
    area: str
    severity: str  # high | medium | low
    finding: str
    recommendation: str
    evidence: str


class BusinessAnalysis(BaseModel):
    lead_id: str
    business_health_score: int = Field(ge=0, le=100)
    seo_score: int = Field(ge=0, le=100)
    marketing_score: int = Field(ge=0, le=100)
    sales_score: int = Field(ge=0, le=100)
    reputation_score: int = Field(ge=0, le=100)
    opportunity: Opportunity
    findings: list[Finding]

    def top_opportunities(self, n: int = 4) -> list[Finding]:
        order = {"high": 0, "medium": 1, "low": 2}
        return sorted(self.findings, key=lambda f: order[f.severity])[:n]


def reputation_score(rep: Reputation | None) -> int:
    if rep is None:
        return 0
    rating = rep.google_rating or rep.facebook_rating or 0
    volume = min(rep.total_reviews, 200) / 200
    s = (rating / 5) * 60 + volume * 30 + (rep.response_rate or 0) * 10
    return round(min(100, s))


def analyze(lead: Lead, web: WebsiteSignals, rep: Reputation | None, social: SocialSignals) -> BusinessAnalysis:
    f: list[Finding] = []

    def add(area: str, sev: str, finding: str, rec: str, ev: str) -> None:
        f.append(Finding(area=area, severity=sev, finding=finding, recommendation=rec, evidence=ev))

    seo = 0 if not web.has_website else (web.seo_score or 0)
    if not web.has_website:
        add("website", "high", "No website found", "Launch a conversion-focused site with local landing pages", "no website URL")
    else:
        if seo < 40:
            add("seo", "high", "Weak on-page SEO", "Fix titles/meta, add schema markup and service-area pages", f"seo_score={seo}")
        elif seo < 70:
            add("seo", "medium", "Average on-page SEO", "Expand content depth and internal linking", f"seo_score={seo}")
        if (web.local_seo_score or 0) < 50:
            add(
                "local_seo",
                "high",
                "Weak local SEO signals",
                "Add LocalBusiness schema, NAP consistency, GBP optimisation",
                f"local_seo_score={web.local_seo_score}",
            )
        if web.page_speed_score is not None and web.page_speed_score < 50:
            add(
                "speed",
                "high",
                "Slow website",
                "Compress images, lazy-load, CDN, remove render-blocking scripts",
                f"page_speed={web.page_speed_score}",
            )
        if web.has_cta is False:
            add(
                "conversion",
                "high",
                "No clear call-to-action",
                "Add above-the-fold booking/quote CTA and click-to-call",
                "no CTA phrase detected",
            )
        if web.mobile_friendly is False or (web.mobile_score is not None and web.mobile_score < 50):
            add(
                "mobile",
                "high",
                "Poor mobile experience",
                "Responsive redesign; most local searches are mobile",
                "no viewport meta / low mobile score",
            )
        if web.outdated_design:
            add(
                "design", "medium", "Outdated design", "Modern, trust-building redesign", f"legacy markup or copyright {web.copyright_year}"
            )
        if web.has_chat is False:
            add(
                "conversion",
                "medium",
                "No live chat / chatbot",
                "Add an AI chat assistant to capture after-hours leads",
                "no chat widget detected",
            )
        if (web.word_count or 0) < 300 or web.has_blog is False:
            add(
                "content",
                "medium",
                "Thin content",
                "Publish service pages and a monthly blog/FAQ cadence",
                f"words={web.word_count}, blog={web.has_blog}",
            )
    rep_score = reputation_score(rep)
    if rep is None or rep.total_reviews < 50:
        add(
            "reputation",
            "high" if (rep is None or rep.total_reviews < 20) else "medium",
            "Low review volume",
            "Automated post-service review requests (SMS + email)",
            f"reviews={rep.total_reviews if rep else 0}",
        )
    if rep and rep.response_rate is not None and rep.response_rate < 0.5:
        add("reputation", "low", "Reviews often unanswered", "Respond to every review within 48h", f"response_rate={rep.response_rate}")
    weak_social = not (social.has_facebook and social.has_instagram) or social.inactive
    if weak_social:
        add(
            "social",
            "medium",
            "Weak social presence",
            "3x/week posting calendar with local proof content",
            f"fb={social.has_facebook}, ig={social.has_instagram}, last_post={social.last_post_days_ago}",
        )
    no_retargeting = web.has_meta_pixel is not True and web.has_google_ads_tag is not True
    if web.has_website and no_retargeting:
        add(
            "advertising",
            "medium",
            "No retargeting pixels",
            "Install Meta Pixel + Google tag, run retargeting to site visitors",
            "no pixel detected",
        )

    opp = Opportunity(
        lead_id=lead.id,
        poor_seo=not web.has_website or seo < 40,
        slow_website=web.page_speed_score is not None and web.page_speed_score < 50,
        outdated_design=bool(web.outdated_design),
        missing_chat=web.has_website and web.has_chat is False,
        low_reviews=rep is None or rep.total_reviews < 50,
        weak_content=web.has_website and ((web.word_count or 0) < 300 or web.has_blog is False),
        weak_social_presence=weak_social,
        no_retargeting=web.has_website and no_retargeting,
        notes=[x.finding for x in f],
    )
    opp.opportunity_score = min(100, len(opp.flags()) * 12 + (10 if not web.has_website else 0))

    marketing = 100
    marketing -= 25 if weak_social else 0
    marketing -= 20 if no_retargeting else 0
    marketing -= 20 if opp.weak_content else 0
    marketing -= 15 if social.runs_google_ads is not True and web.has_google_ads_tag is not True else 0
    marketing = max(0, marketing)
    sales = 100
    sales -= 35 if web.has_cta is False or not web.has_website else 0
    sales -= 20 if web.has_chat is False else 0
    sales -= 25 if web.mobile_friendly is False else 0
    sales = max(0, sales)
    health = round(0.3 * seo + 0.25 * marketing + 0.25 * sales + 0.2 * rep_score)
    return BusinessAnalysis(
        lead_id=str(lead.id),
        business_health_score=health,
        seo_score=seo,
        marketing_score=marketing,
        sales_score=sales,
        reputation_score=rep_score,
        opportunity=opp,
        findings=f,
    )
