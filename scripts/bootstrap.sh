#!/usr/bin/env bash
# First-run bootstrap: generates strong random secrets into ./secrets (0600) and .env. Idempotent: never overwrites.
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
mkdir -p secrets backups
rand() { openssl rand -base64 48 | tr -d '\n/+=' | cut -c1-"${1:-48}"; }
put() { [[ -s "secrets/$1" ]] || { printf '%s' "$2" > "secrets/$1"; echo "  generated secrets/$1"; }; }

command -v openssl >/dev/null || { echo "openssl required"; exit 1; }
echo "==> secrets"
for s in pg_superuser_password pg_aicos_password pg_migrator_password pg_keycloak_password pg_n8n_password \
         pg_langfuse_password aicos_audit_hmac_key aicos_approval_signing_key n8n_signing_key \
         keycloak_admin_password grafana_admin_password; do
  put "$s" "$(rand 48)"
done
put aicos_database_url "postgresql://aicos_app:$(cat secrets/pg_aicos_password)@postgres:5432/aicos?sslmode=prefer"
put aicos_service_signing_keys "{\"n8n\": \"$(cat secrets/n8n_signing_key)\"}"
[[ -e secrets/vault_secret_id ]] || : > secrets/vault_secret_id

echo "==> .env"
if [[ ! -f .env ]]; then
  cp .env.example .env
  sed -i.bak \
    -e "s|^REDIS_PASSWORD=.*|REDIS_PASSWORD=$(rand 40)|" \
    -e "s|^PG_KEYCLOAK_PASSWORD=.*|PG_KEYCLOAK_PASSWORD=$(cat secrets/pg_keycloak_password)|" \
    -e "s|^PG_N8N_PASSWORD=.*|PG_N8N_PASSWORD=$(cat secrets/pg_n8n_password)|" \
    -e "s|^PG_LANGFUSE_PASSWORD=.*|PG_LANGFUSE_PASSWORD=$(cat secrets/pg_langfuse_password)|" \
    -e "s|^KEYCLOAK_ADMIN_PASSWORD=.*|KEYCLOAK_ADMIN_PASSWORD=$(cat secrets/keycloak_admin_password)|" \
    -e "s|^OPENWEBUI_OIDC_SECRET=.*|OPENWEBUI_OIDC_SECRET=$(rand 40)|" \
    -e "s|^N8N_OIDC_SECRET=.*|N8N_OIDC_SECRET=$(rand 40)|" \
    -e "s|^N8N_ENCRYPTION_KEY=.*|N8N_ENCRYPTION_KEY=$(rand 48)|" \
    -e "s|^N8N_SIGNING_KEY=.*|N8N_SIGNING_KEY=$(cat secrets/n8n_signing_key)|" \
    -e "s|^LANGFUSE_NEXTAUTH_SECRET=.*|LANGFUSE_NEXTAUTH_SECRET=$(rand 48)|" \
    -e "s|^LANGFUSE_SALT=.*|LANGFUSE_SALT=$(rand 32)|" \
    -e "s|^SEARXNG_SECRET=.*|SEARXNG_SECRET=$(rand 40)|" \
    -e "s|^PGADMIN_PASSWORD=.*|PGADMIN_PASSWORD=$(rand 24)|" .env
  rm -f .env.bak
  chmod 600 .env
  echo "  wrote .env — set DOMAIN and ACME_EMAIL before starting"
else
  echo "  .env exists, left untouched"
fi

echo "==> vault TLS (self-signed bootstrap cert; replace with your CA)"
if [[ ! -f secrets/vault-tls/tls.crt ]]; then
  mkdir -p secrets/vault-tls
  openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes -subj "/CN=vault" -addext "subjectAltName=DNS:vault,DNS:localhost" \
    -keyout secrets/vault-tls/tls.key -out secrets/vault-tls/tls.crt 2>/dev/null
fi
grep -q "CHANGE_ME" .env && { echo "!! .env still contains CHANGE_ME values"; exit 1; } || true
echo "done. next: ./scripts/start.sh"
