# Frontend Design

**v0.1: Open WebUI is the primary interface.** It gives chat, file upload, model selection and SSO for free;
the `apps/openwebui-pipe` function exposes every AICOS agent as a model and forwards the user's token, so all
governance applies. n8n delivers approval notifications to Slack/email with deep links.

**v0.2: `apps/console` (React + TypeScript + Vite)** — the operational surface Open WebUI lacks:

| View | Data | Roles |
|---|---|---|
| Approval inbox | `GET /v1/approvals?status=pending`, diff of payload, risk, sensitive caps; approve/reject with MFA step-up | Reviewer+ |
| Task timeline | task → agent → actions → proposals → audit records (correlation id) | Operator+ |
| Agent directory | catalog by department, permissions, tools, usage & success metrics | Viewer+ |
| Plugin manager | lifecycle state machine, capabilities (sensitive highlighted), history | Admin |
| Audit explorer | filter/search + live chain verification badge | Reviewer+ |
| Compliance | per-framework control status, export Markdown/PDF | Reviewer+ |

Principles: no approval from notifications (always the console, MFA step-up); show *what exactly* will execute
(the hashed payload); destructive actions require typing the resource name; WCAG 2.2 AA; CSP `default-src 'self'`.
