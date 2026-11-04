# HTTP API (v1)

Base: `https://api.<DOMAIN>` · Auth: `Authorization: Bearer <Keycloak access token>` · OpenAPI: `/openapi.json` (non-production).
Errors: `{"error": "<code>", "detail": "..."}` — `401 unauthenticated` · `403 forbidden/policy_violation` · `404` · `409 approval_error/plugin_error/integrity_error` · `413` · `422 validation_failed` (input never echoed) · `429`.

| Method | Path | Permission | Purpose |
|---|---|---|---|
| GET | `/healthz` · `/readyz` · `/metrics` | — | liveness · readiness (audit chain) · Prometheus |
| POST | `/v1/tasks` | `task:submit` + `agent:invoke` | run an objective (auto-routed or `agent_id`) |
| GET | `/v1/agents[?department=]` · `/v1/agents/{id}` | `agent:read` | catalog |
| GET | `/v1/approvals[?status=]` · `/v1/approvals/{id}` | `approval:read` | approval queue |
| POST | `/v1/approvals/{id}/decision` `{approve, comment}` | `approval:decide` + MFA | vote; returns grant at quorum |
| POST | `/v1/approvals/{id}/execute` `{grant_token}` | requester/delegator or approver, MFA | execute approved action |
| POST | `/v1/approvals/{id}/cancel` | requester | cancel pending |
| GET | `/v1/audit?limit=` · `/v1/audit/verify` | `audit:read` | audit trail · chain verification |
| POST | `/v1/knowledge/documents` (multipart `file`, `source`) | `knowledge:write` | ingest |
| POST | `/v1/knowledge/search` `{query, k, project_id}` | `knowledge:read` | retrieve (wrapped as untrusted) |
| GET | `/v1/plugins` | `plugin:read` | plugin states |
| POST | `/v1/plugins/{name}/verify` · `/suspend` | `plugin:manage` | lifecycle |
| POST | `/v1/plugins/{name}/request-install` · `/install` | `plugin:install` + MFA | approval-gated install |
| GET | `/v1/compliance/report?framework=&format=markdown` | `compliance:report` | evidence |
| POST | `/v1/events` `{type, payload}` | `event:publish` | publish whitelisted business events |
| POST | `/v1/integrations/events` | HMAC signature (`X-AICOS-*`) | n8n / external systems |

### Example: task with an approval-gated action

```bash
curl -s -X POST $API/v1/tasks -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"objective":"Release 2.4.0 to production with a rollback plan","agent_id":"deployment-agent"}'
# → {"status":"completed","actions":[{"action":"deploy.production","status":"pending_approval","proposal_id":"prop_…"}],…}
```

### Service signature

```
string_to_sign = METHOD \n PATH \n UNIX_TS \n NONCE \n sha256_hex(body)
X-AICOS-Signature = hex(HMAC_SHA256(key, string_to_sign))     # ±300 s skew, nonce single-use
```
