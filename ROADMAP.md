# Roadmap

Status legend: ✅ shipped & tested · 🟡 scaffolded (config/adapters present, needs live-infra hardening) · ⬜ planned

## Phase 1 — Foundation
✅ Docker Compose stack · ✅ Postgres + pgvector schema (RLS, append-only audit) · ✅ Redis · ✅ Ollama · ✅ Open WebUI (SSO, governed pipe)

## Phase 2 — Brain
✅ LangGraph orchestrator · ✅ 6-scope memory · ✅ knowledge ingestion & retrieval · ✅ event bus (in-memory) · 🟡 Redis Streams bus (integration test in CI) · ⬜ LlamaIndex/Haystack retriever adapters (`knowledge` extra)

## Phase 3 — Security
✅ RBAC · ✅ policy engine · ✅ prompt firewall · ✅ request signing · ✅ rate limiting · ✅ audit chain · 🟡 Keycloak realm (import tested manually) · 🟡 Vault AppRole adapter · ⬜ model-based injection classifier (pluggable `extra_detectors`)

## Phase 4 — Engineering / DevOps / IT agents
✅ specs + governance · ⬜ sandboxed code execution runtime (OpenHands/Aider in `build` profile) · ⬜ GitHub/Gitea/GitLab PR action handlers (plugins)

## Phase 5 — Sales / Marketing / Research
✅ specs + governance · ✅ reference HubSpot plugin · ⬜ SearXNG `web.search` handler · ⬜ Mailcow/Postal email handlers · ⬜ Playwright/Browser-Use research tool in `research` sandbox

## Phase 6 — Approval gateway & observability
✅ approval gateway · ✅ Prometheus metrics + alerts · ✅ Grafana dashboard · 🟡 OTel → Langfuse pipeline · ⬜ approvals UI (console app) — today: API + n8n notifications

## Phase 7 — Continuous improvement
⬜ failure-analysis agent reading audit/metrics · ⬜ eval harness (golden tasks per agent, model benchmarking via router) · ⬜ agent-authored PRs (`code.pull_request`, never auto-merge — `code:merge` is critical)

## Phase 8 — Multi-tenant enterprise
✅ tenant isolation in domain + RLS · 🟡 Kubernetes base (PSA restricted, NetworkPolicies, HPA, PDB) · ⬜ per-tenant plugin enablement · ⬜ Helm chart · ⬜ SCIM provisioning · ⬜ signed plugin registry (TUF)

## Next 3 milestones
1. **v0.2** — persistence of tasks/plugins in Postgres, container plugin runtime, approvals console (React)
2. **v0.3** — GitHub + SearXNG + email action plugins, eval harness, Langfuse traces end-to-end
3. **v0.4** — Helm chart, SCIM, WASM plugin tier
