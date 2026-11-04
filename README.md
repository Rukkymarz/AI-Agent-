# AICOMPANY-OS

**A self-hosted, governed AI workforce.** 40 department agents (executive → engineering → sales → support)
that can *propose* anything and *do* nothing without passing RBAC, policy, human approval and an immutable audit trail.

[![ci](https://github.com/aicompany-os/aicompany-os/actions/workflows/ci.yml/badge.svg)](.github/workflows/ci.yml)
![license](https://img.shields.io/badge/license-MIT-blue) ![python](https://img.shields.io/badge/python-3.12%2B-blue) ![coverage](https://img.shields.io/badge/coverage-95%25-brightgreen)

```text
 human ──OIDC+MFA──► API ──► Prompt Firewall ──► RBAC ──► LangGraph Orchestrator ──► Agent (pure: proposes only)
                                                                │
                              ┌──── ALLOW ─────► Executor ──► n8n / GitHub / CRM
              Policy Engine ──┼──── APPROVAL ──► Approval Queue ──► 2 humans (MFA, SoD) ──► single-use grant
                              └──── DENY ──────► Audit + SecurityAlert
                         every step ──► HMAC hash-chained, append-only audit log
```

## Why this exists

Agent platforms fail in production for one reason: **excessive agency** (OWASP LLM06). AICOMPANY-OS inverts the
default — agents have no handles to the network, database, secrets or executors. They return
`{result, recommendations, proposed_actions}`. The orchestrator is the only thing that can act, and it acts
only through policy.

## What's in the box

| Capability | Status | Where |
|---|---|---|
| LangGraph orchestrator (firewall → authz → retrieve → agent → redact → govern → audit) | ✅ tested | `packages/core/src/aicos/orchestrator` |
| 40 agents across 11 departments, declarative YAML, least-privilege | ✅ tested | `agents/catalog` |
| RBAC (6 roles, 37 permissions) + delegation intersection | ✅ tested | `aicos/security/rbac.py` |
| Policy engine (deny-overrides, YAML rules) | ✅ tested | `aicos/security/policy.py`, `security/policies` |
| Human approval gateway (quorum, SoD, MFA, payload-bound single-use grants) | ✅ tested | `aicos/approvals` |
| Prompt-injection firewall (5 threat classes, encoding-smuggling, indirect injection quarantine) | ✅ tested | `aicos/security/firewall.py` |
| Tamper-evident audit (HMAC chain + Postgres append-only trigger) | ✅ tested | `aicos/security/audit.py` |
| Memory (6 scopes, pgvector) + knowledge ingestion (PDF/DOCX/TXT/CSV/JSON/MD/HTML/web/git) | ✅ tested | `aicos/memory`, `aicos/knowledge` |
| LLM router (task routing, local-only default, fallback, circuit breaker) | ✅ tested | `aicos/llm` |
| Event bus (in-memory + Redis Streams) | ✅ / integration-tested in CI | `aicos/events`, `aicos/infrastructure` |
| **Plugin system** (signed, capability-based, approval-gated, auto-suspend) | ✅ tested | `aicos/plugins`, [docs](docs/plugins/README.md) |
| Agent sandbox profiles (non-root, ro, cap-drop, no-net / egress proxy, gVisor) | ✅ tested | `aicos/sandbox` |
| Compliance evidence (SOC2, NIST CSF 2.0, OWASP LLM, GDPR, CCPA) | ✅ tested | `aicos/compliance` |
| FastAPI service (OIDC/Keycloak, HMAC service auth, rate limit, body limit, security headers) | ✅ tested | `services/api` |
| Full stack compose (Traefik, Postgres, Redis, Ollama, Open WebUI, Keycloak, Vault, n8n, Langfuse, OTel, Prometheus, Grafana) | ✅ `docker compose config` valid | `docker-compose.yml` |
| CI: ruff, mypy --strict, pytest ≥80 %, CodeQL, Semgrep, Trivy, pip-audit, Safety, OWASP DC | ✅ | `.github/workflows` |

## Quick start

```bash
./scripts/bootstrap.sh && $EDITOR .env && ./scripts/start.sh      # full stack
./scripts/dev.sh                                                   # API only, in-memory, no GPU
curl -s -H 'Authorization: Bearer dev:alice:Operator:1' localhost:8000/v1/agents | jq length   # 40
```

Full guide: [docs/installation/INSTALL.md](docs/installation/INSTALL.md) (Ubuntu, Windows, WSL, Docker, Ollama,
Postgres, Keycloak, Vault, Open WebUI, n8n, Langfuse, Grafana, Prometheus).

## Documentation

* [ARCHITECTURE.md](ARCHITECTURE.md) — diagrams, layers, orchestrator, approvals, security model, data model
* [docs/plugins](docs/plugins/README.md) — plugin architecture, capability grammar, trust tiers, SDK
* [docs/api.md](docs/api.md) — HTTP API
* [docs/developer](docs/developer/README.md) — adding agents, actions, models, loaders
* [SECURITY.md](SECURITY.md) · [docs/security/threat-model.md](docs/security/threat-model.md)
* [ROADMAP.md](ROADMAP.md) — 8 phases, honest status

## Development

```bash
python -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"
make check     # ruff + format + mypy --strict + pytest (coverage gate 80%)
```

MIT © 2026 Rukkymarz
