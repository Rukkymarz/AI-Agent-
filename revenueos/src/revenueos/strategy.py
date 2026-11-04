"""Marketing Strategist (30/60/90-day plans) + Proposal Generator (audit, plan, pricing, roadmap).

Plans are assembled deterministically from the analyzer's opportunity flags, so every line item maps to an
observed gap. An LLM agent may *rewrite the narrative*; it may not change scope or price (those come from here).
"""

from __future__ import annotations

import html as _html
import io
from datetime import date

from pydantic import BaseModel, Field

from revenueos.analyzer import BusinessAnalysis
from revenueos.models import Lead, LeadScore

# flag -> (component, 30-day, 60-day, 90-day, KPI)
PLAYBOOK: dict[str, tuple[str, str, str, str, str]] = {
    "poor_seo": (
        "SEO",
        "Technical fixes: titles, meta, schema, indexation",
        "Service + location landing pages (6-10)",
        "Authority: local citations + 10 quality backlinks",
        "Top-3 map pack for 5 money keywords",
    ),
    "slow_website": (
        "Website performance",
        "Image compression, caching, CDN",
        "Core Web Vitals pass on mobile",
        "Ongoing performance budget + monitoring",
        "PageSpeed mobile >= 80",
    ),
    "outdated_design": (
        "Conversion design",
        "Wireframe + trust elements (reviews, guarantees)",
        "Launch redesigned key pages",
        "A/B test hero + CTA",
        "+30% lead conversion rate",
    ),
    "missing_chat": (
        "AI chat assistant",
        "Deploy chat with FAQ + booking",
        "Train on services/pricing; after-hours capture",
        "Route qualified chats to CRM",
        "Leads captured outside business hours",
    ),
    "low_reviews": (
        "Reviews",
        "Automated review request after every job (SMS + email)",
        "Respond to 100% of reviews in 48h",
        "Showcase reviews on site + ads",
        "+15 reviews/month, rating >= 4.7",
    ),
    "weak_content": (
        "Content",
        "Content strategy + editorial calendar",
        "2 posts/month + 1 case study",
        "Lead magnet (checklist/guide) + email capture",
        "Organic sessions +40%",
    ),
    "weak_social_presence": (
        "Social media",
        "Profile clean-up + weekly calendar",
        "3 posts/week (proof, tips, team)",
        "Monthly campaign tied to an offer",
        "Engagement rate >= 3%",
    ),
    "no_retargeting": (
        "Retargeting",
        "Install Meta Pixel + Google tag, audiences",
        "Launch retargeting to site visitors",
        "Lookalike prospecting from customer list",
        "Cost per lead -25%",
    ),
}
ALWAYS = [
    (
        "Google Business Profile",
        "Complete profile, categories, photos, Q&A",
        "Weekly GBP posts + offers",
        "Review GBP insights, refine categories",
        "Calls from GBP +25%",
    ),
    (
        "Email",
        "Customer list clean-up + welcome flow",
        "Monthly newsletter + reactivation flow",
        "Referral campaign",
        "Repeat business +10%",
    ),
]


class PlanItem(BaseModel):
    component: str
    day_30: str
    day_60: str
    day_90: str
    kpi: str


class MarketingPlan(BaseModel):
    lead_id: str
    business_name: str
    items: list[PlanItem]


def marketing_plan(lead: Lead, analysis: BusinessAnalysis) -> MarketingPlan:
    rows = [PLAYBOOK[f] for f in analysis.opportunity.flags() if f in PLAYBOOK] + ALWAYS
    return MarketingPlan(
        lead_id=str(lead.id),
        business_name=lead.business_name,
        items=[PlanItem(component=c, day_30=a, day_60=b, day_90=d, kpi=k) for c, a, b, d, k in rows],
    )


class Package(BaseModel):
    name: str
    monthly: float
    setup: float
    includes: list[str]
    min_flags: int


DEFAULT_PACKAGES = [
    Package(
        name="Foundation",
        monthly=1500,
        setup=750,
        min_flags=0,
        includes=["Google Business Profile", "Reviews", "Technical SEO", "Monthly report"],
    ),
    Package(
        name="Growth",
        monthly=3000,
        setup=1500,
        min_flags=3,
        includes=["Everything in Foundation", "Content (2/mo)", "Social (3/wk)", "Retargeting", "AI chat assistant"],
    ),
    Package(
        name="Scale",
        monthly=5500,
        setup=2500,
        min_flags=6,
        includes=["Everything in Growth", "Paid ads management", "Conversion redesign", "Quarterly strategy review"],
    ),
]


class Proposal(BaseModel):
    lead_id: str
    business_name: str
    prepared_by: str
    date: date
    analysis: BusinessAnalysis
    score: LeadScore | None
    plan: MarketingPlan
    packages: list[Package]
    recommended: str
    roadmap: list[str] = Field(default_factory=list)


def build_proposal(
    lead: Lead,
    analysis: BusinessAnalysis,
    score: LeadScore | None,
    *,
    prepared_by: str,
    packages: list[Package] | None = None,
    today: date | None = None,
) -> Proposal:
    packages = packages or DEFAULT_PACKAGES
    n = len(analysis.opportunity.flags())
    recommended = max((p for p in packages if n >= p.min_flags), key=lambda p: p.min_flags).name
    plan = marketing_plan(lead, analysis)
    roadmap = [
        f"Days 1-30: {', '.join(i.component for i in plan.items[:3])} foundations",
        "Days 31-60: content, campaigns and conversion improvements live",
        "Days 61-90: scale what works; quarterly review with ROI report",
    ]
    return Proposal(
        lead_id=str(lead.id),
        business_name=lead.business_name,
        prepared_by=prepared_by,
        date=today or date.today(),
        analysis=analysis,
        score=score,
        plan=plan,
        packages=packages,
        recommended=recommended,
        roadmap=roadmap,
    )


def _md_escape(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def to_markdown(p: Proposal) -> str:
    a = p.analysis
    out = [
        f"# Growth Proposal — {p.business_name}",
        f"_Prepared by {p.prepared_by} · {p.date.isoformat()}_",
        "",
        "## 1. Business audit",
        "",
        "| Score | Value |",
        "|---|---|",
        f"| Business health | **{a.business_health_score}/100** |",
        f"| SEO | {a.seo_score}/100 |",
        f"| Marketing | {a.marketing_score}/100 |",
        f"| Sales / conversion | {a.sales_score}/100 |",
        f"| Reputation | {a.reputation_score}/100 |",
        "",
        "### Findings",
        "",
        "| Severity | Area | Finding | Recommendation |",
        "|---|---|---|---|",
    ]
    out += [f"| {f.severity.upper()} | {f.area} | {_md_escape(f.finding)} | {_md_escape(f.recommendation)} |" for f in a.findings]
    out += ["", "## 2. 30 / 60 / 90-day growth plan", "", "| Component | Day 30 | Day 60 | Day 90 | KPI |", "|---|---|---|---|---|"]
    out += [f"| {i.component} | {i.day_30} | {i.day_60} | {i.day_90} | {i.kpi} |" for i in p.plan.items]
    out += ["", "## 3. Roadmap", ""] + [f"- {r}" for r in p.roadmap]
    out += ["", "## 4. Investment", "", "| Package | Monthly | Setup | Includes |", "|---|---|---|---|"]
    for pk in p.packages:
        star = " ⭐ recommended" if pk.name == p.recommended else ""
        out.append(f"| **{pk.name}**{star} | ${pk.monthly:,.0f}/mo | ${pk.setup:,.0f} | {', '.join(pk.includes)} |")
    out += [
        "",
        "Month-to-month after an initial 3-month term. Cancel with 30 days' notice.",
        "",
        "## 5. Next steps",
        "",
        "1. 30-minute kickoff call",
        "2. Access to website, GBP and ad accounts",
        "3. Day-30 results review",
    ]
    return "\n".join(out)


def to_html(p: Proposal) -> str:
    """Minimal, escaped HTML (print-friendly; feed to WeasyPrint for PDF)."""
    md = to_markdown(p)
    body: list[str] = []
    table: list[list[str]] = []

    def flush() -> None:
        if table:
            head, *rows = table
            body.append(
                "<table><thead><tr>"
                + "".join(f"<th>{c}</th>" for c in head)
                + "</tr></thead><tbody>"
                + "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
                + "</tbody></table>"
            )
            table.clear()

    for line in md.splitlines():
        if line.startswith("|"):
            cells = [_html.escape(c.strip().replace("\\|", "|")).replace("**", "") for c in line.strip("|").split(" | ")]
            if not set("".join(cells)) <= set("-"):
                table.append(cells)
            continue
        flush()
        esc = _html.escape(line)
        if line.startswith("# "):
            body.append(f"<h1>{esc[2:]}</h1>")
        elif line.startswith("## "):
            body.append(f"<h2>{esc[3:]}</h2>")
        elif line.startswith("### "):
            body.append(f"<h3>{esc[4:]}</h3>")
        elif line.startswith("- "):
            body.append(f"<ul><li>{esc[2:]}</li></ul>")
        elif line.strip():
            body.append(f"<p>{esc.strip('_')}</p>")
    flush()
    css = (
        "body{font-family:Helvetica,Arial,sans-serif;max-width:860px;margin:40px auto;color:#111827;line-height:1.5}"
        "table{border-collapse:collapse;width:100%;margin:12px 0}th,td{border:1px solid #e5e7eb;padding:8px;font-size:14px;"
        "vertical-align:top}th{background:#f3f4f6;text-align:left}h1{color:#1d4ed8}"
    )
    return (
        f"<!DOCTYPE html><html><head><meta charset='utf-8'><title>{_html.escape(p.business_name)} proposal</title>"
        f"<style>{css}</style></head><body>{''.join(body)}</body></html>"
    )


def to_slides(p: Proposal) -> str:
    """Marp-compatible Markdown deck (`npx @marp-team/marp-cli deck.md --pptx`)."""
    a = p.analysis
    slides = [
        "---\nmarp: true\ntheme: default\npaginate: true\n---",
        f"# {p.business_name}\n## Growth opportunity review\n{p.prepared_by} · {p.date.isoformat()}",
        f"# Where you stand\n- Business health **{a.business_health_score}/100**\n- SEO {a.seo_score} · Marketing "
        f"{a.marketing_score} · Sales {a.sales_score} · Reputation {a.reputation_score}",
        "# Top opportunities\n" + "\n".join(f"- **{f.finding}** — {f.recommendation}" for f in a.top_opportunities(4)),
        "# 90-day plan\n" + "\n".join(f"- {r}" for r in p.roadmap),
        "# Investment\n" + "\n".join(f"- **{k.name}** ${k.monthly:,.0f}/mo{' ⭐' if k.name == p.recommended else ''}" for k in p.packages),
        "# Next step\nKickoff call → access → day-30 review",
    ]
    return "\n\n---\n\n".join(slides)


def to_docx(p: Proposal) -> bytes:  # pragma: no cover - optional dependency
    import docx

    d = docx.Document()
    for line in to_markdown(p).splitlines():
        if line.startswith("# "):
            d.add_heading(line[2:], 0)
        elif line.startswith("## "):
            d.add_heading(line[3:], 1)
        elif line.startswith("|") and not set(line) <= set("|-"):
            d.add_paragraph(" · ".join(c.strip() for c in line.strip("|").split(" | ")))
        elif line.strip():
            d.add_paragraph(line.lstrip("- "))
    buf = io.BytesIO()
    d.save(buf)
    return buf.getvalue()


def to_pdf(p: Proposal) -> bytes:  # pragma: no cover - optional dependency
    from weasyprint import HTML

    return bytes(HTML(string=to_html(p)).write_pdf())
