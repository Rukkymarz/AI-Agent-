#!/usr/bin/env bash
# One-time Vault bootstrap: KV v2, transit (PII envelope encryption), AppRoles, audit device.
# Run: docker compose exec vault /vault/init.sh   (after `vault operator init` + unseal)
set -euo pipefail
: "${VAULT_TOKEN:?export a root/admin token for bootstrap, then revoke it}"
vault audit enable file file_path=/vault/logs/audit.log || true
vault secrets enable -path=secret kv-v2 || true
vault secrets enable transit || true
vault write -f transit/keys/aicos-pii type=aes256-gcm96 || true
vault auth enable approle || true
for p in aicos-api aicos-worker break-glass; do vault policy write "$p" "/vault/policies/$p.hcl"; done
vault write auth/approle/role/aicos-api token_policies=aicos-api token_ttl=1h token_max_ttl=4h secret_id_ttl=720h secret_id_num_uses=0
vault write auth/approle/role/aicos-worker token_policies=aicos-worker token_ttl=1h token_max_ttl=4h
echo "role_id (api): $(vault read -field=role_id auth/approle/role/aicos-api/role-id)"
echo "generate secret_id: vault write -f -field=secret_id auth/approle/role/aicos-api/secret-id > secrets/vault_secret_id"
