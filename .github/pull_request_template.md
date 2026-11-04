## Summary

## Type
- [ ] feature  - [ ] fix  - [ ] security  - [ ] agent/catalog  - [ ] plugin  - [ ] infra  - [ ] docs

## Governance checklist
- [ ] No agent gains a permission in `AGENT_FORBIDDEN_PERMISSIONS`
- [ ] New side-effecting actions are registered in `ACTION_PERMISSIONS` with the correct permission
- [ ] Critical actions remain approval-gated (no bypass paths)
- [ ] No secrets, tokens or credentials in code, tests or fixtures
- [ ] Tests added; coverage ≥ 80%

## Agent-authored?
- [ ] This PR was proposed by an AICOS agent (`code.pull_request`) — requires human review, never auto-merge
