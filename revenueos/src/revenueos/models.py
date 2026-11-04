"""RevenueOS domain models. Mirrors infra/postgres/init/002_revenueos.sql."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, HttpUrl

from aicos.domain.common import utcnow


class LeadStatus(StrEnum):
    NEW = "new"
    ANALYZED = "analyzed"
    QUALIFIED = "qualified"
    IN_SEQUENCE = "in_sequence"
    ENGAGED = "engaged"
    OPPORTUNITY = "opportunity"
    CLIENT = "client"
    NURTURE = "nurture"
    DISQUALIFIED = "disqualified"
    SUPPRESSED = "suppressed"


class Grade(StrEnum):
    PLATINUM = "platinum"
    GOLD = "gold"
    SILVER = "silver"
    BRONZE = "bronze"
    IGNORE = "ignore"


class Segment(StrEnum):
    IDEAL = "ideal"
    MID_MARKET = "mid_market"
    ENTERPRISE = "enterprise"
    UNKNOWN = "unknown"


class Lead(BaseModel):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    tenant_id: str = "default"
    business_name: str = Field(min_length=1, max_length=300)
    owner_name: str | None = Field(default=None, max_length=200)
    industry: str | None = Field(default=None, max_length=120)
    sub_industry: str | None = Field(default=None, max_length=120)
    website: HttpUrl | None = None
    google_business_url: HttpUrl | None = None
    linkedin_url: HttpUrl | None = None
    facebook_url: HttpUrl | None = None
    instagram_url: HttpUrl | None = None
    phone: str | None = Field(default=None, max_length=40)
    email: str | None = Field(default=None, max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
    city: str | None = Field(default=None, max_length=120)
    state: str | None = Field(default=None, max_length=60)
    zip_code: str | None = Field(default=None, max_length=20)
    timezone: str = "America/New_York"
    employee_count: int | None = Field(default=None, ge=0)
    estimated_revenue: float | None = Field(default=None, ge=0)
    years_in_business: int | None = Field(default=None, ge=0)
    lead_source: str = Field(default="manual", max_length=60)
    score: int = Field(default=0, ge=0, le=100)
    grade: Grade = Grade.IGNORE
    status: LeadStatus = LeadStatus.NEW
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class SEOAnalysis(BaseModel):
    lead_id: uuid.UUID
    domain_authority: int | None = Field(default=None, ge=0, le=100)
    page_speed_score: int | None = Field(default=None, ge=0, le=100)
    mobile_score: int | None = Field(default=None, ge=0, le=100)
    indexed_pages: int | None = Field(default=None, ge=0)
    backlinks: int | None = Field(default=None, ge=0)
    keyword_count: int | None = Field(default=None, ge=0)
    organic_visibility: float | None = Field(default=None, ge=0, le=100)
    local_seo_score: int | None = Field(default=None, ge=0, le=100)
    seo_score: int = Field(default=0, ge=0, le=100)


class Reputation(BaseModel):
    lead_id: uuid.UUID | None = None
    google_rating: float | None = Field(default=None, ge=0, le=5)
    google_reviews: int = Field(default=0, ge=0)
    facebook_rating: float | None = Field(default=None, ge=0, le=5)
    total_reviews: int = Field(default=0, ge=0)
    sentiment_score: float | None = Field(default=None, ge=-1, le=1)
    response_rate: float | None = Field(default=None, ge=0, le=1)
    reputation_score: int = Field(default=0, ge=0, le=100)


class Opportunity(BaseModel):
    lead_id: uuid.UUID
    poor_seo: bool = False
    slow_website: bool = False
    outdated_design: bool = False
    missing_chat: bool = False
    low_reviews: bool = False
    weak_content: bool = False
    weak_social_presence: bool = False
    no_retargeting: bool = False
    opportunity_score: int = Field(default=0, ge=0, le=100)
    notes: list[str] = Field(default_factory=list)

    def flags(self) -> list[str]:
        names = [
            "poor_seo",
            "slow_website",
            "outdated_design",
            "missing_chat",
            "low_reviews",
            "weak_content",
            "weak_social_presence",
            "no_retargeting",
        ]
        return [n for n in names if getattr(self, n)]


class WebsiteSignals(BaseModel):
    """Raw observations about a business's web presence (from the website analyzer or manual entry)."""

    has_website: bool = True
    page_speed_score: int | None = Field(default=None, ge=0, le=100)
    mobile_friendly: bool | None = None
    mobile_score: int | None = Field(default=None, ge=0, le=100)
    has_cta: bool | None = None
    has_chat: bool | None = None
    outdated_design: bool | None = None
    https: bool | None = None
    word_count: int | None = Field(default=None, ge=0)
    has_blog: bool | None = None
    has_meta_pixel: bool | None = None
    has_google_ads_tag: bool | None = None
    copyright_year: int | None = None
    seo_score: int | None = Field(default=None, ge=0, le=100)
    local_seo_score: int | None = Field(default=None, ge=0, le=100)


class SocialSignals(BaseModel):
    has_facebook: bool = False
    has_instagram: bool = False
    has_linkedin: bool = False
    last_post_days_ago: int | None = Field(default=None, ge=0)
    runs_google_ads: bool | None = None
    runs_social_ads: bool | None = None

    @property
    def inactive(self) -> bool:
        return self.last_post_days_ago is None or self.last_post_days_ago > 30


class ScoreItem(BaseModel):
    category: str
    rule: str
    points: int


class LeadScore(BaseModel):
    lead_id: uuid.UUID
    total: int = Field(ge=0, le=100)
    raw_total: int
    grade: Grade
    segment: Segment
    breakdown: list[ScoreItem]
