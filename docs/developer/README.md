# Developer Guide

## Layout

```
packages/core/src/aicos/   domain · security · approvals · events · memory · knowledge · llm · agents · orchestrator · plugins · sandbox · compliance · observability · infrastructure · container.py
services/api/src/aicos_api FastAPI (auth, deps, middleware, routers)
services/worker/           background jobs
agents/catalog/            department agent specs (YAML)
plugins/examples/          reference plugins
security/policies/         declarative policy rules
models/registry.yaml       model registry + routing
infra/                     compose configs, postgres, keycloak, vault, traefik, prometheus, grafana, otel, n8n, k8s
tests/                     unit · security · api · integration · load
```

## Recipes

**Add an agent** — append to `agents/catalog/<department>.yaml`:
```yaml
  - id: pricing-analyst
    name: Pricing Analyst Agent
    description: Price testing and packaging recommendations.
    model_task: reasoning
    permissions: [task:read, knowledge:read]
    tools: [report.publish]
    keywords: [pricing, packaging, willingness to pay]
```
The catalog test fails if a tool's required permission is missing or a forbidden permission is requested.

**Add an action** — core: add to `ACTION_PERMISSIONS` and register a handler via `ActionExecutor.register_handler`.
Third-party: ship it as a plugin (`actions:register:<plugin>.<verb>`). Mark the permission critical in
`CRITICAL_PERMISSIONS` if a human must approve it.

**Add a model** — `models/registry.yaml` (`name`, `provider`, `tasks`, `context_window`, `quality`) + route list.
Remote/paid providers: implement `LLMProvider`, ship as an `llm_provider` plugin with `net:egress:<host>`; they are
excluded unless a caller sets `RouteConstraints(require_local=False)`.

**Add a loader** — implement `Loader` (`extensions`, `load(bytes, source) -> list[Document]`), register in
`LoaderRegistry` or via a `knowledge_loader` plugin.

**Add a policy rule** — `security/policies/default.yaml`:
```yaml
  - id: no-weekend-campaigns
    effect: deny
    actions: ["campaign.send"]
    when: [{field: payload.weekday, op: in, value: ["sat", "sun"]}]
```

## Testing

`make check`. Fixtures in `tests/conftest.py`: a container with in-memory adapters, an `EchoProvider` driven by
`Script` (set `script.actions = [...]` to make an agent propose actions), and principal helpers.
Integration tests (`-m integration`) need `AICOS_IT_DATABASE_URL` / `AICOS_IT_REDIS_URL`.
