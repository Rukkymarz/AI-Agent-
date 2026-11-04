# Threat Model (STRIDE)

Assets: customer data & PII, credentials, production infrastructure, money movement, audit integrity, model weights.
Trust boundaries: internet ↔ Traefik · API ↔ orchestrator ↔ agents (LLM output is untrusted) · platform ↔ plugins · platform ↔ external SaaS.

| STRIDE | Threat | Mitigation | Test |
|---|---|---|---|
| S | Forged user identity | OIDC JWT (JWKS, iss/aud/exp), dev auth refused outside dev | `test_api.py::test_authentication_required`, `test_dev_auth_forbidden_in_prod` |
| S | Forged service calls (n8n) | HMAC signatures, nonce, skew | `test_audit_signing.py::test_signing_*`, `test_signed_integration_endpoint` |
| T | Audit tampering | HMAC chain, append-only trigger, INSERT-only role, external anchoring | `test_audit_*`, `tests/integration::test_audit_append_only_in_postgres` |
| T | Bait-and-switch after approval | payload hash bound into grant | `test_bait_and_switch_rejected` |
| T | Plugin code swapped post-approval | integrity + approved digest re-verified | `test_toctou_change_after_approval` |
| R | "The agent did it" | every decision audited with actor, delegator, approvers, payload hash | `test_full_flow_two_person_rule` |
| I | Prompt-based secret extraction | firewall, secrets never in agent context, output redaction | `test_firewall.py`, `test_secret_redaction_*` |
| I | Indirect injection via documents | ingestion scan → quarantine; untrusted wrapping | `test_ingest_search_dedupe_quarantine` |
| I | Cross-tenant reads | tenant checks in every service + RLS | `test_memory_scoping_tenant_and_ttl`, `test_tenant_mismatch_rejected` |
| I | SSRF via web ingestion | https-only, private/link-local/metadata blocked, no redirects | `test_ssrf_guard_blocks` |
| D | Request floods / huge bodies | token bucket, body limit, Traefik rate limit | `test_body_limit_and_rate_limit` |
| D | Runaway agents/plugins | timeouts, max actions, error budget suspension | `test_agent_timeout_and_error`, `test_error_budget_suspends` |
| E | Agent self-escalation | forbidden permission set, delegation intersection, catalog validation | `test_agent_ignores_roles_and_forbidden`, `test_delegation_limits_agent` |
| E | Self-approval | SoD, humans only, MFA, reviewer authority | `test_reviewer_rules` |
| E | Plugin escalation | capability facade, manifest-bounded registrar, restrict-only guards | `test_registrar_denials_roll_back`, `test_capability_violation_auto_suspends` |

**Residual risks (accepted, tracked):**
1. Heuristic firewall can be evaded by novel phrasing → defence-in-depth means evasion yields *proposals*, not effects. Add a model-based classifier via `extra_detectors`.
2. In-process plugins are trusted code → only CORE/VERIFIED tiers may run in-process.
3. A full-chain audit rewrite by an attacker holding the HMAC key → mitigated by external head-hash anchoring to WORM storage.
4. Approver collusion (two malicious admins) → out of scope for software; use org controls + alerting on approval patterns.
