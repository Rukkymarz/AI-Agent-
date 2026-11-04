#!/usr/bin/env bash
# Restore from an encrypted backup. DESTRUCTIVE: replaces databases. Requires typing the backup name.
#   ./scripts/restore.sh backups/20260101T000000Z.tar.enc
set -euo pipefail
cd "$(dirname "$0")/.."
F="${1:?backup file}"
sha256sum -c "$F.sha256"
read -r -p "Type the backup file name to confirm destructive restore: " confirm
[[ "$confirm" == "$(basename "$F")" ]] || { echo "aborted"; exit 1; }
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
case "$F" in
  *.age) age -d -i "${BACKUP_AGE_IDENTITY:?}" -o "$WORK/b.tar" "$F" ;;
  *.enc) openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -in "$F" -out "$WORK/b.tar" -pass file:secrets/backup_passphrase ;;
  *) echo "unknown format"; exit 1 ;;
esac
tar xf "$WORK/b.tar" -C "$WORK"; D=$(find "$WORK" -mindepth 1 -maxdepth 1 -type d | head -1)
docker compose stop aicos-api aicos-worker n8n keycloak langfuse open-webui
gunzip -c "$D/postgres.sql.gz" | docker compose exec -T postgres psql -U postgres -v ON_ERROR_STOP=0 postgres
for v in n8n-data grafana-data worker-state openwebui-data; do
  [[ -f "$D/$v.tgz" ]] && docker run --rm -v "aicompany-os_${v}:/dst" -v "$D:/src:ro" alpine sh -c "rm -rf /dst/* && tar xzf /src/$v.tgz -C /dst"
done
[[ -f "$D/vault.snap" ]] && echo "Vault snapshot present: docker compose cp it in and run 'vault operator raft snapshot restore'"
docker compose up -d
echo "restored. verify audit chain: curl -H 'Authorization: Bearer ...' https://api.\$DOMAIN/v1/audit/verify"
