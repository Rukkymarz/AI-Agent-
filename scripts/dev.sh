#!/usr/bin/env bash
# Local development without the full stack: in-memory adapters, echo LLM (or real Ollama), dev tokens.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m venv .venv 2>/dev/null || true
. .venv/bin/activate
pip install -q -e ".[dev]"
export AICOS_ENV=development AICOS_AUTH_MODE=dev AICOS_LLM_PROVIDER="${AICOS_LLM_PROVIDER:-echo}" \
       AICOS_EMBEDDING_PROVIDER="${AICOS_EMBEDDING_PROVIDER:-hashing}" AICOS_EMBEDDING_DIM=384
echo "dev token example:  curl -H 'Authorization: Bearer dev:alice:Operator:1' localhost:8000/v1/agents"
exec uvicorn aicos_api.main:create_app --factory --reload --port 8000
