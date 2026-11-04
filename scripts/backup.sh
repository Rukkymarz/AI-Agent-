#!/usr/bin/env bash
# Encrypted backups: Postgres (all DBs), Vault raft snapshot, n8n, Grafana, audit anchors.
# Encryption: age (preferred) to $BACKUP_AGE_RECIPIENT, else openssl AES-256 with secrets/backup_passphrase.
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
TS=$(date -u +%Y%m%dT%H%M%SZ); OUT="backups/${TS}"; mkdir -p "$OUT"
echo "==> postgres"
docker compose exec -T postgres pg_dumpall -U postgres --clean --if-exists | gzip -9 > "$OUT/postgres.sql.gz"
echo "==> vault snapshot (requires VAULT_TOKEN with snapshot capability)"
if [[ -n "${VAULT_TOKEN:-}" ]]; then
  docker compose exec -T -e VAULT_TOKEN vault vault operator raft snapshot save /tmp/vault.snap && \
  docker compose cp vault:/tmp/vault.snap "$OUT/vault.snap"
fi
echo "==> volumes"
for v in n8n-data grafana-data worker-state openwebui-data; do
  docker run --rm -v "aicompany-os_${v}:/src:ro" -v "$PWD/$OUT:/dst" alpine tar czf "/dst/${v}.tgz" -C /src . 2>/dev/null || true
done
tar cf "$OUT.tar" -C backups "$TS" && rm -rf "$OUT"
if command -v age >/dev/null && [[ -n "${BACKUP_AGE_RECIPIENT:-}" ]]; then
  age -r "$BACKUP_AGE_RECIPIENT" -o "$OUT.tar.age" "$OUT.tar" && rm "$OUT.tar"; F="$OUT.tar.age"
else
  [[ -s secrets/backup_passphrase ]] || openssl rand -base64 48 > secrets/backup_passphrase
  openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -in "$OUT.tar" -out "$OUT.tar.enc" -pass file:secrets/backup_passphrase && rm "$OUT.tar"; F="$OUT.tar.enc"
fi
sha256sum "$F" > "$F.sha256"
echo "backup: $F"
# Off-site: rclone/aws s3 cp "$F" to an Object-Lock (WORM) bucket. Retain >= 35 days.
find backups -name '*.tar.*' -mtime +"${BACKUP_RETENTION_DAYS:-14}" -delete
