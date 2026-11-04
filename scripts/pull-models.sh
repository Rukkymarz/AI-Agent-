#!/usr/bin/env bash
# Pull the routed models into the ollama volume. Override with OLLAMA_PULL="model:tag ...".
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f .env ]] && { set -a; . ./.env; set +a; }
MODELS="${OLLAMA_PULL:-qwen3:14b deepseek-r1:14b deepseek-coder-v2:16b mistral:7b bge-m3}"
for m in $MODELS; do
  echo "==> ollama pull $m"
  docker compose exec -T ollama ollama pull "$m"
done
docker compose exec -T ollama ollama list
