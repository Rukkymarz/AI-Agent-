"""Email Campaign Engine: branded responsive templates, compliance guardrails, delivery.

Compliance built in (CAN-SPAM; also the baseline for CASL/GDPR B2B outreach — get legal review per market):
  * accurate From / no deceptive subjects (subjects are fixed per step, only merge fields vary)
  * physical postal address in every message (rendering refuses without one)
  * working one-click unsubscribe (RFC 8058 List-Unsubscribe + List-Unsubscribe-Post) honoured immediately
  * suppression list checked before every send (unsubscribes, bounces, complaints)
Deliverability: per-mailbox daily caps with warm-up ramp, weekday business-hours send window in the lead's
timezone, multipart text+HTML, no attachments in cold touches.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import smtplib
import ssl
from datetime import datetime, time, timedelta
from email.message import EmailMessage
from email.utils import formataddr, make_msgid
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol
from zoneinfo import ZoneInfo

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape
from pydantic import BaseModel, Field

from aicos.domain.common import sha256_hex

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates" / "email"


class EmailStep(StrEnum):
    INITIAL = "initial"  # day 1
    FOLLOWUP_1 = "followup_1"  # day 3 — not opened: re-engagement
    CASE_STUDY = "case_study"  # day 3 — opened, no click
    AUDIT_SAMPLE = "audit_sample"  # day 3 — clicked, no reply
    FOLLOWUP_2 = "followup_2"  # day 7 — meeting request
    MEETING_INVITE = "meeting_invite"  # day 7 — engaged: direct calendar invite
    FOLLOWUP_3 = "followup_3"  # day 14 — close the loop


SUBJECTS: dict[EmailStep, str] = {
    EmailStep.INITIAL: "Quick observation about {business_name}",
    EmailStep.FOLLOWUP_1: "Following up on the opportunities we identified",
    EmailStep.CASE_STUDY: "Following up on the opportunities we identified",
    EmailStep.AUDIT_SAMPLE: "Following up on the opportunities we identified",
    EmailStep.FOLLOWUP_2: "Worth a quick conversation?",
    EmailStep.MEETING_INVITE: "Worth a quick conversation?",
    EmailStep.FOLLOWUP_3: "Final follow-up",
}

CTA: dict[EmailStep, str | None] = {
    EmailStep.INITIAL: "Get my free summary report",
    EmailStep.FOLLOWUP_1: None,
    EmailStep.CASE_STUDY: "See the plan for my business",
    EmailStep.AUDIT_SAMPLE: "Get the full audit",
    EmailStep.FOLLOWUP_2: "Book 15 minutes",
    EmailStep.MEETING_INVITE: "Pick a time",
    EmailStep.FOLLOWUP_3: None,
}


class Brand(BaseModel):
    company_name: str = Field(min_length=1, max_length=120)
    physical_address: str = Field(min_length=10, max_length=300, description="CAN-SPAM: valid postal address")
    from_name: str
    from_email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
    reply_to: str | None = None
    phone: str | None = None
    logo_url: str | None = Field(default=None, pattern=r"^https://")
    primary_color: str = Field(default="#2563eb", pattern=r"^#[0-9a-fA-F]{6}$")
    background_color: str = Field(default="#f3f4f6", pattern=r"^#[0-9a-fA-F]{6}$")
    # strict allow-list: emitted unescaped inside <style> (HTML entities are not decoded in raw-text elements)
    font_stack: str = Field(
        default="-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif", pattern=r"^[A-Za-z0-9 ,'\-]{1,200}$"
    )
    booking_url: str = Field(pattern=r"^https://")
    report_url: str = Field(pattern=r"^https://")
    unsubscribe_base_url: str = Field(pattern=r"^https://")


class CaseStudy(BaseModel):
    industry: str
    location: str
    timeframe: str
    results: list[dict[str, str]]  # [{"value": "+212%", "label": "organic traffic"}]


DEFAULT_CASE_STUDY = CaseStudy(
    industry="home services",
    location="the Midwest",
    timeframe="90 days",
    results=[
        {"value": "+38%", "label": "inbound calls"},
        {"value": "4.2 → 4.8", "label": "Google rating"},
        {"value": "3x", "label": "monthly review volume"},
    ],
)


class RenderedEmail(BaseModel):
    step: EmailStep
    subject: str
    html: str
    text: str
    template_hash: str


def _clean_header(value: str) -> str:
    return re.sub(r"[\r\n\t]+", " ", value).strip()[:250]


def template_bundle_hash(directory: Path = TEMPLATE_DIR) -> str:
    """Hash of every template file + subjects: bound into campaign approvals (no swapping copy after sign-off)."""
    h = hashlib.sha256()
    for p in sorted(directory.glob("*.j2")):
        h.update(p.name.encode())
        h.update(p.read_bytes())
    h.update(repr(sorted(SUBJECTS.items())).encode())
    return h.hexdigest()


class EmailRenderer:
    def __init__(self, directory: Path = TEMPLATE_DIR) -> None:
        self.directory = directory
        common: dict[str, Any] = {
            "loader": FileSystemLoader(str(directory)),
            "undefined": StrictUndefined,
            "trim_blocks": True,
            "lstrip_blocks": True,
        }
        self._html = Environment(autoescape=select_autoescape(enabled_extensions=("html.j2",), default_for_string=True), **common)
        self._text = Environment(autoescape=False, **common)  # noqa: S701 - plain text part, never rendered as HTML

    def bundle_hash(self) -> str:
        return template_bundle_hash(self.directory)

    def render(
        self, step: EmailStep, *, brand: Brand, context: dict[str, Any], unsubscribe_url: str, tracking: dict[str, str] | None = None
    ) -> RenderedEmail:
        if not brand.physical_address.strip():
            raise ValueError("CAN-SPAM: brand.physical_address is required")
        tracking = tracking or {}
        cta_label = CTA[step]
        cta_url = None
        if cta_label:
            cta_url = brand.booking_url if step in (EmailStep.FOLLOWUP_2, EmailStep.MEETING_INVITE) else brand.report_url
            cta_url = tracking.get("click_url", cta_url)
        ctx: dict[str, Any] = {
            "owner_name": None,
            "city": None,
            "consultant_title": None,
            "case_study": DEFAULT_CASE_STUDY.model_dump(),
            "opportunity_areas": ["Search visibility", "Website performance", "Customer reviews", "Lead generation"],
            "top_finding": {"finding": "Low review volume", "recommendation": "Automated review requests after every job"},
            "findings": [],
            "health_score": "—",
            **context,
            "brand": brand.model_dump(),
            "cta_label": cta_label,
            "cta_url": cta_url,
            "unsubscribe_url": unsubscribe_url,
            "tracking_pixel_url": tracking.get("open_pixel_url"),
        }
        subject = _clean_header(SUBJECTS[step].format(business_name=context["business_name"]))
        ctx["subject"] = subject
        html = self._html.get_template(f"{step.value}.html.j2").render(ctx)
        text = self._text.get_template(f"{step.value}.txt.j2").render(ctx)
        return RenderedEmail(step=step, subject=subject, html=html, text=text, template_hash=self.bundle_hash())


# ----------------------------------------------------------------------------- unsubscribe + suppression
class UnsubscribeTokens:
    def __init__(self, key: bytes) -> None:
        if len(key) < 32:
            raise ValueError("unsubscribe key must be >= 32 bytes")
        self._key = key

    def make(self, email: str) -> str:
        e = email.strip().lower()
        mac = hmac.new(self._key, e.encode(), hashlib.sha256).hexdigest()[:32]
        return f"{e.encode().hex()}.{mac}"

    def parse(self, token: str) -> str | None:
        try:
            enc, mac = token.split(".", 1)
            email = bytes.fromhex(enc).decode()
        except (ValueError, UnicodeDecodeError):
            return None
        expected = hmac.new(self._key, email.encode(), hashlib.sha256).hexdigest()[:32]
        return email if hmac.compare_digest(mac, expected) else None


class SuppressionReason(StrEnum):
    UNSUBSCRIBED = "unsubscribed"
    BOUNCED = "bounced"
    COMPLAINED = "complained"
    MANUAL = "manual"


class SuppressionList:
    """Stores sha256(email) only — suppression must outlive data deletion (GDPR erasure keeps the hash)."""

    def __init__(self) -> None:
        self._items: dict[str, SuppressionReason] = {}

    @staticmethod
    def _k(email: str) -> str:
        return sha256_hex(email.strip().lower())

    def add(self, email: str, reason: SuppressionReason) -> None:
        self._items[self._k(email)] = reason

    def is_suppressed(self, email: str) -> bool:
        return self._k(email) in self._items

    def __len__(self) -> int:
        return len(self._items)


# ----------------------------------------------------------------------------- send policy
class SendPolicy(BaseModel):
    window_start: time = time(9, 0)
    window_end: time = time(16, 30)
    weekdays_only: bool = True
    warmup_start_per_day: int = Field(default=20, ge=1)
    warmup_increment_per_day: int = Field(default=10, ge=0)
    max_per_day: int = Field(default=150, ge=1)

    def daily_cap(self, mailbox_age_days: int) -> int:
        return min(self.max_per_day, self.warmup_start_per_day + self.warmup_increment_per_day * max(0, mailbox_age_days))

    def next_window(self, at: datetime, tz: str) -> datetime:
        """First instant >= `at` inside the sending window, expressed in the lead's local time."""
        zone = ZoneInfo(tz)
        local = at.astimezone(zone)
        for _ in range(14):
            if self.weekdays_only and local.weekday() >= 5:
                local = (local + timedelta(days=1)).replace(
                    hour=self.window_start.hour, minute=self.window_start.minute, second=0, microsecond=0
                )
                continue
            start = local.replace(hour=self.window_start.hour, minute=self.window_start.minute, second=0, microsecond=0)
            end = local.replace(hour=self.window_end.hour, minute=self.window_end.minute, second=0, microsecond=0)
            if local < start:
                return start
            if local <= end:
                return local
            local = start + timedelta(days=1)
        return local  # pragma: no cover


# ----------------------------------------------------------------------------- delivery
class OutboundEmail(BaseModel):
    to_email: str
    to_name: str | None = None
    rendered: RenderedEmail
    brand: Brand
    unsubscribe_url: str
    in_reply_to: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)

    def to_mime(self) -> EmailMessage:
        msg = EmailMessage()
        domain = self.brand.from_email.split("@", 1)[1]
        msg["Message-ID"] = make_msgid(domain=domain)
        msg["From"] = formataddr((_clean_header(self.brand.from_name), self.brand.from_email))
        msg["To"] = formataddr((_clean_header(self.to_name or ""), self.to_email))
        msg["Subject"] = self.rendered.subject
        if self.brand.reply_to:
            msg["Reply-To"] = self.brand.reply_to
        if self.in_reply_to:  # thread follow-ups under the first email
            msg["In-Reply-To"] = self.in_reply_to
            msg["References"] = self.in_reply_to
        msg["List-Unsubscribe"] = f"<{self.unsubscribe_url}>"
        msg["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"
        for k, v in self.headers.items():
            if re.match(r"^X-[A-Za-z0-9-]{1,60}$", k):
                msg[k] = _clean_header(v)
        msg.set_content(self.rendered.text)
        msg.add_alternative(self.rendered.html, subtype="html")
        return msg


class Mailer(Protocol):
    async def send(self, email: OutboundEmail) -> str: ...


class OutboxMailer:
    """Captures mail instead of sending (tests, dry-runs, previews)."""

    def __init__(self) -> None:
        self.sent: list[EmailMessage] = []

    async def send(self, email: OutboundEmail) -> str:
        mime = email.to_mime()
        self.sent.append(mime)
        return str(mime["Message-ID"])


class SMTPMailer:  # pragma: no cover - network (Mailcow / Postal / any SMTP relay)
    def __init__(self, host: str, port: int, username: str, password: str, *, starttls: bool = True) -> None:
        self.host, self.port, self.username, self._password, self.starttls = host, port, username, password, starttls

    def _send_sync(self, mime: EmailMessage) -> None:
        ctx = ssl.create_default_context()
        if self.port == 465:
            with smtplib.SMTP_SSL(self.host, self.port, context=ctx, timeout=30) as s:
                s.login(self.username, self._password)
                s.send_message(mime)
            return
        with smtplib.SMTP(self.host, self.port, timeout=30) as s:
            if self.starttls:
                s.starttls(context=ctx)
            s.login(self.username, self._password)
            s.send_message(mime)

    async def send(self, email: OutboundEmail) -> str:
        import asyncio

        mime = email.to_mime()
        await asyncio.to_thread(self._send_sync, mime)
        return str(mime["Message-ID"])
