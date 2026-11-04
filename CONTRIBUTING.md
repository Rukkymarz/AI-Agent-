# Contributing

1. Fork, branch from `main`, keep PRs small.
2. `pip install -e ".[dev]"` then `make check` must pass (ruff, format, mypy --strict, pytest, coverage ≥ 80 %).
3. Security-relevant changes (`aicos/security`, `approvals`, `plugins`, `infra`, workflows) need a security-team review (CODEOWNERS).
4. New side-effecting capability ⇒ register an action in `ACTION_PERMISSIONS` with the right permission + tests proving it is gated.
5. New agent ⇒ YAML in `agents/catalog/`; `tests/unit/test_llm_agents.py::test_catalog_complete_and_valid` enforces tool/permission consistency.
6. No secrets in code, tests or fixtures. Use `AICOS_SECRET_*` env vars or Vault.
7. Commits: Conventional Commits (`feat:`, `fix:`, `sec:`, `docs:`). Sign commits (`git commit -S`).
8. Agent-authored PRs are welcome and are labelled `agent-authored`; they are reviewed like any other PR and never auto-merged.

By contributing you agree your contributions are licensed under the MIT License.
