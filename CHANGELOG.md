# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [SemVer](https://semver.org/).

## [0.1.0] — 2026-11-04
### Added
- Governed LangGraph orchestrator with firewall, RBAC, retrieval, agent execution, output redaction, action governance.
- 40-agent department catalog (executive, operations, engineering, devops, IT, security, product, sales, marketing, support, data).
- RBAC (6 roles), policy engine with YAML rules, human approval gateway (quorum, SoD, MFA, payload-bound grants).
- Prompt-injection firewall, secret redaction, HMAC request signing, token-bucket rate limiting.
- Hash-chained audit log with Postgres append-only enforcement.
- Six-scope memory on pgvector; knowledge ingestion with dedupe, quarantine and PII tagging.
- LLM router for Qwen3 / DeepSeek / Llama / Mistral / Gemma with fallbacks and circuit breaking.
- Plugin system: signed manifests, capability grants, approval-gated install, restrict-only policy guards, auto-suspension; reference HubSpot plugin and `aicos-plugin` CLI.
- Compliance evidence reports (SOC2, NIST CSF 2.0, OWASP LLM Top 10, GDPR, CCPA).
- FastAPI service, worker, Open WebUI pipe, Docker Compose stack, Kubernetes base, CI/CD with security scanners.
