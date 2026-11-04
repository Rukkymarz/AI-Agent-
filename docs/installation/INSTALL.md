# Installation Guide

**Fast path (Ubuntu, Docker already installed):**

```bash
git clone https://github.com/aicompany-os/aicompany-os.git && cd aicompany-os
./scripts/bootstrap.sh          # random secrets -> ./secrets (0600) + .env
nano .env                       # set DOMAIN and ACME_EMAIL
./scripts/start.sh              # builds, starts, waits for health, pulls models
```

**Hardware sizing**

| Profile | CPU | RAM | GPU | Disk | Models |
|---|---|---|---|---|---|
| Evaluation | 8 vCPU | 32 GB | none (CPU inference, slow) | 100 GB SSD | `qwen3:4b`, `mistral:7b`, `bge-m3` |
| Team (≤25 users) | 16 vCPU | 64 GB | 1× 24 GB (RTX 4090 / L4) | 500 GB NVMe | defaults in `models/registry.yaml` |
| Department | 32 vCPU | 128 GB | 2× 48 GB (L40S / A6000) | 1 TB NVMe | + `qwen3-coder:30b`, larger R1 |

DNS: point `chat.`, `api.`, `auth.`, `flows.`, `trace.`, `metrics.` subdomains of `DOMAIN` at the host.

---

## 1. Ubuntu installation (22.04 / 24.04 LTS)

```bash
sudo apt update && sudo apt -y upgrade
sudo apt -y install git curl ca-certificates gnupg openssl jq ufw unattended-upgrades python3.12 python3.12-venv
sudo dpkg-reconfigure -plow unattended-upgrades
# host firewall: only SSH + HTTPS
sudo ufw default deny incoming && sudo ufw allow OpenSSH && sudo ufw allow 80,443/tcp && sudo ufw enable
# full-disk encryption: provision the data disk with LUKS, then set ENCRYPTION_AT_REST=true in .env
```

## 2. Windows installation

1. Windows 11 Pro/Enterprise (Hyper-V + virtualization enabled in BIOS).
2. Install **Docker Desktop**, **Git for Windows**, **VS Code**, **Python 3.12** (python.org, tick *Add to PATH*), **Node.js LTS**.
3. Run the stack **inside WSL 2** (section 3) — Docker Desktop's WSL backend shares the engine. Native Windows
   paths break Linux file permissions on `./secrets`.
4. NVIDIA GPU: install the latest Game Ready/Studio driver on Windows; CUDA is exposed to WSL automatically.

## 3. WSL installation

```powershell
# PowerShell (Admin)
wsl --install -d Ubuntu-24.04
wsl --set-default-version 2
```

Create `%UserProfile%\.wslconfig`:

```ini
[wsl2]
memory=48GB
processors=12
swap=8GB
```

Then inside Ubuntu: follow section 1, clone the repo **into the Linux filesystem** (`~/aicompany-os`, not `/mnt/c`),
and enable *Settings → Resources → WSL integration* for the distro in Docker Desktop. GPU check: `nvidia-smi`.

## 4. Docker installation

```bash
# Ubuntu: official repository (not the snap)
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt update && sudo apt -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker "$USER" && newgrp docker
docker compose version
```

Hardening (`/etc/docker/daemon.json`), then `sudo systemctl restart docker`:

```json
{ "live-restore": true, "no-new-privileges": true, "userland-proxy": false,
  "log-driver": "json-file", "log-opts": { "max-size": "20m", "max-file": "5" } }
```

GPU: `sudo apt install -y nvidia-container-toolkit && sudo nvidia-ctk runtime configure --runtime=docker && sudo systemctl restart docker`,
then uncomment the `deploy:` block of the `ollama` service. Optional gVisor for community plugins: install `runsc`
and register it as a Docker runtime.

## 5. Ollama installation

Ollama runs as the `ollama` container on the internal `aicos-models` network — no host install needed.

```bash
./scripts/pull-models.sh                                       # pulls OLLAMA_PULL from .env
docker compose exec ollama ollama run qwen3:14b "say hi"       # smoke test
```

Air-gapped: pull on a connected machine, copy the `ollama-models` volume, and remove `aicos-internet` from
the `ollama` service networks. To add a model: append to `models/registry.yaml` (`name`, `tasks`, `context_window`)
and its route list — no code change.

## 6. PostgreSQL installation

Image `pgvector/pgvector:pg16`. On first start `infra/postgres/init/` creates:

* databases `aicos`, `keycloak`, `n8n`, `langfuse` with **separate roles and passwords** (from `./secrets`)
* `aicos` schema with pgvector HNSW index, Row-Level Security on every tenant table,
  and an **append-only** `audit_log` (trigger blocks UPDATE/DELETE/TRUNCATE; `aicos_app` has INSERT/SELECT only)

```bash
docker compose exec postgres psql -U postgres -d aicos -c '\dt'
docker compose exec postgres psql -U postgres -d aicos -c "SELECT extname, extversion FROM pg_extension"
```

pgAdmin: `docker compose --profile tools up -d pgadmin` → `http://127.0.0.1:5050` (bound to localhost; use an SSH tunnel).
Changing embedding models with a different dimension requires `AICOS_EMBEDDING_DIM` + a migration of `memory_records.embedding`.

## 7. Keycloak installation

Keycloak 26 imports `infra/keycloak/aicompany-realm.json` on boot: realm `aicompany`, roles
`SuperAdmin, Admin, Manager, Operator, Reviewer, Viewer`, TOTP required on first login, brute-force protection,
14-char password policy, 5-minute access tokens, clients `aicos-api` (bearer-only), `aicos-console`
(Open WebUI / Grafana, PKCE), `aicos-n8n` (service account).

```text
https://auth.<DOMAIN>  → admin console, user: kcadmin, password: secrets/keycloak_admin_password
Realm aicompany → Users → Add user → Credentials → set temporary password
Role mapping → assign one of the six roles
Attributes → tenant = default
```

Approvers **must** enrol TOTP or WebAuthn — the approval gateway rejects decisions without an MFA `amr` claim.
Rotate the bootstrap admin to a named admin account and disable `kcadmin`.

## 8. Vault installation

```bash
docker compose up -d vault
docker compose exec vault vault operator init -key-shares=5 -key-threshold=3   # store shares with 5 different people
docker compose exec vault vault operator unseal   # x3
export VAULT_TOKEN=<initial root token>
docker compose exec -e VAULT_TOKEN vault /vault/init.sh       # KV v2, transit (PII), AppRoles, audit device
docker compose exec -e VAULT_TOKEN vault vault write -f -field=secret_id auth/approle/role/aicos-api/secret-id > secrets/vault_secret_id
# put role_id into .env as VAULT_ROLE_ID, set VAULT_ADDR=https://vault:8200, then:
docker compose exec -e VAULT_TOKEN vault vault kv put secret/aicos/plugins/hubspot token=<hubspot-private-app-token>
docker compose exec -e VAULT_TOKEN vault vault token revoke "$VAULT_TOKEN"   # never keep the root token
docker compose up -d aicos-api aicos-worker
```

Production: 3–5 node raft cluster, auto-unseal via cloud KMS/HSM, replace the bootstrap self-signed cert.

## 9. Open WebUI installation

Runs at `https://chat.<DOMAIN>` with **SSO only** (local signup/login disabled), roles mapped from Keycloak.

1. Log in via *AICOMPANY-OS SSO*.
2. *Admin → Functions → +* → paste `apps/openwebui-pipe/aicos_pipe.py` → enable.
3. Models named `AICOS: …` now route through the governed orchestrator using **the user's own token**,
   so RBAC, firewall, approvals and audit apply to chat exactly as to the API.
4. Raw Ollama models remain available for low-risk chat; disable them under *Admin → Models* for strict deployments.

## 10. n8n installation

`https://flows.<DOMAIN>` (internal networks only, via Traefik `internal-only` middleware).

1. Create the owner account on first visit; enable 2FA.
2. *Workflows → Import from file* → `infra/n8n/workflows/approval-notifications.json` and `lead-capture.json`.
3. Inbound events to AICOS go to `POST /v1/integrations/events`, **HMAC-signed** with `N8N_SIGNING_KEY`
   (see the *Sign Request* node). Unsigned or replayed requests get `401`.
4. Outbound: `aicos-worker` forwards `ApprovalRequested`, `SecurityAlert`, `ActionExecuted`, … to the n8n webhook.
   n8n **never** approves — approval links point to the console.

## 11. Langfuse installation

`https://trace.<DOMAIN>` (internal only). Langfuse v2 uses the `langfuse` Postgres database.

1. Create the admin user (signup is disabled afterwards via `AUTH_DISABLE_SIGNUP`).
2. Create project `aicompany-os` → *Settings → API keys*.
3. Store keys in Vault (`secret/aicos/runtime/langfuse`) or set `LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY`
   on `aicos-api`; set `LANGFUSE_OTEL_AUTH=base64(public:secret)` for the OTel collector.
4. Prompts and completions go to Langfuse (access-controlled); the OTel collector **strips** prompt attributes
   and auth headers from generic traces.

## 12. Grafana installation

`https://metrics.<DOMAIN>` (internal only, SSO via Keycloak; Admin role ⇒ Grafana Admin). Datasource and the
*AICOMPANY-OS Overview* dashboard (task throughput/success, latency p95 per agent & model, tokens, cost,
action outcomes, firewall blocks) are provisioned from `infra/grafana/provisioning`.
Break-glass admin password: `secrets/grafana_admin_password`.

## 13. Prometheus installation

Scrapes `aicos-api:/metrics`, Traefik and the OTel collector every 15 s; 30-day retention.
Alert rules (`infra/prometheus/alerts.yml`): prompt-injection spike, agent failure rate > 10 %, denied-action
spike, all LLM candidates failing, API down. Wire Alertmanager → n8n / PagerDuty / Slack for routing.

```bash
docker compose exec prometheus wget -qO- localhost:9090/api/v1/targets | jq '.data.activeTargets[].health'
```

---

## Operations

| Task | Command |
|---|---|
| Start / restart | `./scripts/start.sh` |
| Local dev (no stack) | `./scripts/dev.sh` → dev tokens `Bearer dev:alice:Operator:1` |
| Pin images to digests | `./scripts/pin-images.sh` |
| Backup (encrypted) | `./scripts/backup.sh` (set `BACKUP_AGE_RECIPIENT` for age) |
| Restore | `./scripts/restore.sh backups/<file>` (destructive, confirmation required) |
| Production deploy | `./scripts/deploy.sh <version> <proposal_id> <grant_token>` — requires an approved `deploy.production` proposal |
| Verify audit chain | `GET /v1/audit/verify` (Reviewer) |
| Compliance evidence | `GET /v1/compliance/report?framework=SOC2&format=markdown` |

## Post-install security checklist

- [ ] `DOMAIN` set, TLS certificates issued, HSTS active
- [ ] All `.env` values random (bootstrap fails on `CHANGE_ME`)
- [ ] Images pinned by digest
- [ ] Keycloak: TOTP/WebAuthn enforced, bootstrap admin disabled
- [ ] Vault initialised, unseal shares distributed, root token revoked
- [ ] `ENCRYPTION_AT_REST=true` only after disk encryption is in place
- [ ] Off-site, Object-Locked backups scheduled and a restore test performed
- [ ] `ollama` removed from `aicos-internet` after model download (air-gap models)
- [ ] `GET /v1/compliance/report` shows no FAIL controls
