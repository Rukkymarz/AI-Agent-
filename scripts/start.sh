#!/usr/bin/env bash
# Start the stack, wait for health, pull models. Usage: ./scripts/start.sh [--profile tools] [--profile search]
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f .env ]] || ./scripts/bootstrap.sh
set -a; . ./.env; set +a
[[ "${DOMAIN}" == "aicos.example.com" ]] && echo "WARNING: DOMAIN is still the example value"
docker compose "$@" up -d --build
echo "==> waiting for postgres/redis/api"
for svc in postgres redis; do
  until [[ "$(docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q "$svc")" 2>/dev/null)" == "healthy" ]]; do sleep 3; done
  echo "  $svc healthy"
done
./scripts/pull-models.sh
docker compose ps
cat <<MSG

AICOMPANY-OS is starting:
  Chat (Open WebUI) https://chat.${DOMAIN}
  API               https://api.${DOMAIN}/healthz
  Identity          https://auth.${DOMAIN}       (create users, enforce TOTP)
  Workflows (n8n)   https://flows.${DOMAIN}      (internal networks only)
  Traces (Langfuse) https://trace.${DOMAIN}      (internal networks only)
  Metrics (Grafana) https://metrics.${DOMAIN}    (internal networks only)
Next: initialise Vault -> docs/installation/INSTALL.md (section 8)
MSG
