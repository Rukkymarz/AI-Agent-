# STATE.md — AICOMPANY-OS

_Last updated: 2026-11-04 · Session 1 (RevenueOS added on branch `feat/revenueos`)_

## Current target
**RevenueOS first** (user directive): find → score → outreach → follow-ups → pipeline → recurring MRR, on top of the governed AICOS core.
Repo: https://github.com/Rukkymarz/AI-Agent- (main = core; `feat/revenueos` = RevenueOS).

## Verdict (binding until falsified)
- **Build: GO on the governance core. NO-GO on positioning as a horizontal "AI company OS."**
  The horizontal agent-platform category is crowded (CrewAI, Dify, LangGraph Platform, Microsoft Agent Framework, n8n AI,
  OpenHands). _Tier 4 (training knowledge, no live research this session): low confidence on competitive specifics._
- The defensible asset is the **control plane**: approval gateway + policy + tamper-evident audit + compliance evidence +
  signed capability-based plugins. Enterprises buy that; they don't buy "40 agents."
- Pivot candidate to validate first: **AgentGate** (governance sidecar for *any* agent framework / MCP gateway).

## Stack (as built)
Python 3.12+, FastAPI, LangGraph 1.2, Pydantic 2, Postgres 16 + pgvector (HNSW, RLS, append-only audit), Redis Streams,
Ollama (Qwen3 / DeepSeek-R1 / DeepSeek-Coder-V2 / Llama 3.1 / Mistral / Gemma 3 / BGE-M3), Keycloak 26 (OIDC + TOTP),
Vault (AppRole, KV v2, transit), Traefik v3, n8n, Open WebUI (SSO + governed pipe), Langfuse v2, OTel, Prometheus, Grafana.

## Verified this session
| Gate | Result |
|---|---|
| Tests | 258 passed (incl. 64 RevenueOS) — was 194 (unit, security, API, plugins, orchestrator e2e) · 3 integration tests skip without Postgres/Redis |
| Coverage | 96.27 % (gate 80 %; `aicos/infrastructure` excluded → covered by CI integration job) |
| mypy --strict | 0 issues / 73 files |
| ruff lint + format | clean |
| Live API (uvicorn) | 40 agents, routing, injection block, 401/403, security headers, metrics |
| `docker compose config` | valid |
| Docker image build | **NOT verified** (no daemon in sandbox) |

## Capital deployed
$0. Monthly run-rate estimate for a team deployment: one 24 GB-GPU box (~$150–400/mo cloud, or owned hardware).

## Known gaps (honest)
1. **Tasks and plugin records are in-memory.** Postgres adapters exist for audit, memory, proposals only. Restart loses plugin state.
2. **Redis bus in API process:** plugin event subscriptions registered in the API never consume (only the worker calls `bus.run()`).
   Fix: run plugin subscribers in the worker, or start a consumer task on API startup.
3. Nonce cache + rate limiter are per-process → use Redis for multi-replica.
4. Container plugin runtime is an interface only (`ContainerPluginRuntime`); COMMUNITY plugins can't activate yet.
5. Keycloak realm uses `${DOMAIN}`-style placeholders — confirm env substitution on import in your Keycloak version.
6. Image tags in `.env.example` are best-effort defaults; run `scripts/pin-images.sh` before production.
7. Action handlers default to an outbox; no real GitHub/CRM/email executors yet (HubSpot reference plugin only).

## RevenueOS gaps
- In-memory state (schema `002_revenueos.sql` ready, repository adapter not written) — **blocks real use**.
- Discovery connectors + PageSpeed are stubs; leads must be imported/analyzed via API for now.
- Cold-email legality differs by market (CAN-SPAM ok; CASL/GDPR restrictive) — legal review before EU/UK/CA sends.

## Next 3 actions (superseded order)
1. Postgres repository for RevenueOS (leads/campaigns/outreach/deals) so a restart loses nothing.
2. Overpass + CSV lead import endpoint; PageSpeed key; send 50 real emails to one niche from a warmed secondary domain.
3. Measure reply rate; kill threshold < 2% replies after 200 sends → change niche/offer, not tooling.

## Previous next actions
1. `git init`, push to GitHub, let CI run end-to-end (Docker build, Trivy, CodeQL, integration job). Fix whatever breaks.
2. Close gaps 1–2 (persist tasks/plugins; event consumers out of the API process). Then deploy on one GPU box with real models.
3. Run the AgentGate validation (below) **before** building more agents.

## Validation experiments (each < $50)
| Mutation | Test | Kill threshold |
|---|---|---|
| AgentGate: governance sidecar / MCP gateway | Landing page (Carrd ~$19) + Show HN + 50 LinkedIn DMs to platform-security leads | < 30 work-email waitlist signups in 14 days |
| Approval-decision risk model (data loop) | 10 interviews with ops/sec leads: "% of agent actions you'd auto-approve with a risk score" | < 4/10 say they would pay to reduce review load |
| $15–35k "Agent Governance Readiness" engagement | 20 targeted CISO/compliance DMs at Series B–D SaaS, ask for a paid pilot deposit | 0 deposits after 2 discovery calls |

## Open risks
- Market: horizontal platforms commoditise fast; open source → monetise via support, hosted control plane, or compliance services.
- Security: heuristic firewall is evadable — fine by design (evasion yields proposals, not effects). Add a classifier later.
- Ops: self-hosting 14 services is heavy for SMBs → the hosted control-plane SKU matters.
