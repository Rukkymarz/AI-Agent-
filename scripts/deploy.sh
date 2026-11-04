#!/usr/bin/env bash
# Production deploy. Refuses to run without an approved AICOS proposal grant (the platform's own approval gate).
#   ./scripts/deploy.sh <version> <proposal_id> <grant_token>
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${1:?version}"; PROPOSAL="${2:?proposal id}"; GRANT="${3:?grant token}"
: "${AICOS_API:=https://api.$(grep ^DOMAIN= .env | cut -d= -f2)}"
: "${AICOS_TOKEN:?export AICOS_TOKEN (your OIDC access token, MFA session)}"

echo "==> verifying approval ${PROPOSAL}"
status=$(curl -fsS -H "Authorization: Bearer ${AICOS_TOKEN}" "${AICOS_API}/v1/approvals/${PROPOSAL}" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["status"], d["action"]["action"], d["action"]["payload"].get("version",""))')
read -r st action ver <<<"$status"
[[ "$st" == "approved" && "$action" == "deploy.production" && "$ver" == "$VERSION" ]] || { echo "approval mismatch: $status"; exit 1; }

echo "==> pre-deploy backup"
./scripts/backup.sh

echo "==> pulling + scanning image"
docker compose pull aicos-api || true
command -v trivy >/dev/null && trivy image --exit-code 1 --severity CRITICAL "aicompany-os/api:${VERSION}"

echo "==> consuming grant (marks proposal executed, audited)"
curl -fsS -X POST -H "Authorization: Bearer ${AICOS_TOKEN}" -H "Content-Type: application/json" \
  -d "{\"grant_token\": \"${GRANT}\"}" "${AICOS_API}/v1/approvals/${PROPOSAL}/execute" >/dev/null

echo "==> rolling restart"
AICOS_VERSION="${VERSION}" docker compose up -d --no-deps aicos-api aicos-worker
for i in $(seq 1 30); do
  curl -fsS "${AICOS_API}/healthz" >/dev/null && { echo "healthy on ${VERSION}"; exit 0; }; sleep 2
done
echo "health check failed — rolling back"; docker compose up -d --no-deps aicos-api aicos-worker; exit 1
