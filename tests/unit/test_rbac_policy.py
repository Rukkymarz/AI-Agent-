from __future__ import annotations

from itertools import pairwise

import pytest

from aicos.domain.identity import AGENT_FORBIDDEN_PERMISSIONS, Permission, Principal, PrincipalType, Role
from aicos.security.policy import ActionRequest, Condition, DeclarativeRule, Effect, PolicyEngine
from aicos.security.rbac import ROLE_PERMISSIONS, delegated_permissions, effective_permissions, has_permission
from tests.conftest import ROOT, human

P = Permission


def agent(*perms: Permission, tenant: str = "default") -> Principal:
    return Principal(id="agent:x", type=PrincipalType.AGENT, permissions=frozenset(perms), tenant_id=tenant)


def test_role_hierarchy_monotonic() -> None:
    order = [Role.VIEWER, Role.OPERATOR, Role.MANAGER, Role.ADMIN, Role.SUPER_ADMIN]
    for lo, hi in pairwise(order):
        assert ROLE_PERMISSIONS[lo] <= ROLE_PERMISSIONS[hi]
    assert ROLE_PERMISSIONS[Role.REVIEWER] <= ROLE_PERMISSIONS[Role.MANAGER]
    assert ROLE_PERMISSIONS[Role.SUPER_ADMIN] == frozenset(Permission)


def test_viewer_cannot_submit() -> None:
    v = human("v", Role.VIEWER)
    assert not has_permission(v, P.TASK_SUBMIT)
    assert has_permission(v, P.TASK_READ)


def test_agent_ignores_roles_and_forbidden() -> None:
    a = Principal(
        id="agent:y",
        type=PrincipalType.AGENT,
        roles=frozenset({Role.SUPER_ADMIN}),
        permissions=frozenset({P.TICKET_WRITE, P.APPROVAL_DECIDE}),
    )
    perms = effective_permissions(a)
    assert perms == {P.TICKET_WRITE}
    assert not (perms & AGENT_FORBIDDEN_PERMISSIONS)


def test_delegation_is_intersection() -> None:
    a = agent(P.TICKET_WRITE, P.DEPLOY_PRODUCTION)
    assert delegated_permissions(a, human("op", Role.OPERATOR)) == {P.TICKET_WRITE}
    assert delegated_permissions(a, None) == frozenset()
    assert delegated_permissions(a, agent(P.TICKET_WRITE)) == frozenset()
    assert delegated_permissions(a, human("op", Role.ADMIN, tenant="other")) == frozenset()


def _req(actor: Principal, perm: Permission, action: str = "x.do", **kw: object) -> ActionRequest:
    return ActionRequest(actor=actor, permission=perm, action=action, **kw)  # type: ignore[arg-type]


def test_policy_deny_by_default_without_permission() -> None:
    d = PolicyEngine().evaluate(_req(human("v", Role.VIEWER), P.TICKET_WRITE, "ticket.create"))
    assert d.effect is Effect.DENY and "missing_permission" in d.reasons[0]


def test_policy_allows_normal_action() -> None:
    d = PolicyEngine().evaluate(_req(human("op", Role.OPERATOR), P.TICKET_WRITE, "ticket.create"))
    assert d.allowed


def test_policy_critical_requires_approval_then_allows_with_grant() -> None:
    eng = PolicyEngine()
    r = _req(human("ad", Role.ADMIN), P.DEPLOY_PRODUCTION, "deploy.production")
    assert eng.evaluate(r).effect is Effect.REQUIRE_APPROVAL
    assert eng.evaluate(r, grant_valid=True).allowed


def test_policy_human_without_mfa_denied_for_critical() -> None:
    r = _req(human("ad", Role.ADMIN, mfa=False), P.DEPLOY_PRODUCTION, "deploy.production")
    assert PolicyEngine().evaluate(r).reasons == ["mfa_required"]


def test_policy_agent_without_delegator_denied() -> None:
    d = PolicyEngine().evaluate(_req(agent(P.TICKET_WRITE), P.TICKET_WRITE, "ticket.create"))
    assert d.reasons == ["agent_requires_human_delegator"]


def test_policy_tenant_mismatch() -> None:
    d = PolicyEngine().evaluate(_req(human("op", Role.OPERATOR, tenant="t2"), P.TICKET_WRITE, "ticket.create"))
    assert d.reasons == ["tenant_mismatch"]


def test_declarative_rules_and_deny_wins() -> None:
    eng = PolicyEngine(
        [
            DeclarativeRule(
                id="big", effect=Effect.REQUIRE_APPROVAL, actions=["crm.*"], when=[Condition(field="payload.n", op="gt", value=10)]
            ),
            DeclarativeRule(
                id="blocked", effect=Effect.DENY, actions=["crm.update"], when=[Condition(field="resource", op="eq", value="vip")]
            ),
        ]
    )
    op = human("op", Role.OPERATOR)
    assert eng.evaluate(_req(op, P.CRM_WRITE, "crm.update", payload={"n": 1})).allowed
    assert eng.evaluate(_req(op, P.CRM_WRITE, "crm.update", payload={"n": 11})).effect is Effect.REQUIRE_APPROVAL
    d = eng.evaluate(_req(op, P.CRM_WRITE, "crm.update", resource="vip", payload={"n": 11}))
    assert d.effect is Effect.DENY and d.matched_rules == ["big", "blocked"]


@pytest.mark.parametrize(
    ("op", "value", "actual", "expected"),
    [
        ("eq", 1, 1, True),
        ("ne", 1, 2, True),
        ("gte", 5, 5, True),
        ("lt", 5, 4, True),
        ("lte", 5, 6, False),
        ("in", [1, 2], 2, True),
        ("not_in", [1, 2], 3, True),
        ("contains", "x", "xyz", True),
        ("gt", 5, "str", False),
    ],
)
def test_condition_ops(op: str, value: object, actual: object, expected: bool) -> None:
    r = _req(human("op", Role.OPERATOR), P.CRM_WRITE, "crm.update", payload={"v": actual})
    assert Condition(field="payload.v", op=op, value=value).matches(r) is expected  # type: ignore[arg-type]


def test_condition_missing_field_is_false() -> None:
    r = _req(human("op", Role.OPERATOR), P.CRM_WRITE, "crm.update")
    assert not Condition(field="payload.nope.deep", op="eq", value=1).matches(r)


def test_payload_hash_binds_content() -> None:
    a = _req(human("op", Role.OPERATOR), P.CRM_WRITE, "crm.update", payload={"a": 1})
    b = _req(human("op", Role.OPERATOR), P.CRM_WRITE, "crm.update", payload={"a": 2})
    assert a.payload_hash() != b.payload_hash()


def test_default_policy_file_loads() -> None:
    eng = PolicyEngine.from_yaml(ROOT / "security/policies/default.yaml")
    assert {r.id for r in eng.rules} >= {"finance-hard-cap", "change-freeze"}
    eng.remove_rule("finance-hard-cap")
    assert "finance-hard-cap" not in {r.id for r in eng.rules}
