# Security Policy

## Reporting a vulnerability

Email **security@aicompany-os.dev** (PGP key in `security/trusted-keys/security-team.asc`) or open a
GitHub *private security advisory*. Do **not** open public issues for vulnerabilities.

| Severity | Acknowledge | Fix target |
|---|---|---|
| Critical (approval bypass, auth bypass, RCE, cross-tenant read) | 24 h | 7 days |
| High | 72 h | 30 days |
| Medium / Low | 7 days | next minor |

We credit reporters in release notes unless asked otherwise. Good-faith research is welcome; do not access
other users' data, degrade service, or exfiltrate beyond proof-of-concept.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

## Security invariants (regressions are Critical)

1. No agent can hold `approval:decide`, `policy:write`, `permission:change`, `user:delete`, `user:manage`,
   `plugin:install`, `plugin:manage`, `tenant:manage`, `agent:manage`.
2. Every permission in `CRITICAL_PERMISSIONS` requires an approved, payload-bound, unexpired, single-use grant.
3. Approvers are MFA-verified humans, distinct from the requester and delegator, holding the target permission for HIGH/CRITICAL risk.
4. The audit chain verifies; the DB role used by the app cannot UPDATE/DELETE audit rows.
5. Plugins cannot publish core event types, override core actions/agents, or exceed declared capabilities.
6. Production boot refuses: dev auth, echo/hashing models, missing keys, TLS disabled.

Each invariant has unit tests under `tests/`; CODEOWNERS requires security review for the enforcing code.

## Hardening guide

See [docs/security/threat-model.md](docs/security/threat-model.md) and the post-install checklist in
[docs/installation/INSTALL.md](docs/installation/INSTALL.md).
