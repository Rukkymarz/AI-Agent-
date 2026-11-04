.PHONY: install check lint type test cov dev up down backup plugin-validate
install: ; pip install -e ".[dev]"
lint: ; ruff check . && ruff format --check .
type: ; mypy packages/core/src services/api/src
test: ; pytest -q
cov: ; pytest --cov --cov-report=term-missing
check: lint type cov
dev: ; ./scripts/dev.sh
up: ; ./scripts/start.sh
down: ; docker compose down
backup: ; ./scripts/backup.sh
plugin-validate: ; for p in plugins/examples/*/; do aicos-plugin validate "$$p"; done
