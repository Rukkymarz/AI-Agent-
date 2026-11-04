from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from aicos.approvals.gateway import ApprovalGateway, InMemoryProposalRepository, ProposalStatus, RiskLevel
from aicos.domain.errors import ApprovalError, AuthorizationError, NotFound
from aicos.domain.identity import Permission, Principal, PrincipalType, Role
from aicos.events.bus import EventType, InMemoryEventBus
from aicos.security.audit import AuditLog, InMemoryAuditStore
from aicos.security.policy import ActionRequest
from tests.conftest import human

KEY = b"z" * 32


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 1, 1, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def bus() -> InMemoryEventBus:
    return InMemoryEventBus()


@pytest.fixture
def gw(clock: Clock, bus: InMemoryEventBus) -> ApprovalGateway:
    return ApprovalGateway(InMemoryProposalRepository(), AuditLog(InMemoryAuditStore(), KEY), bus, KEY, clock=clock)


def deploy_req(requester: Principal, payload: dict[str, object] | None = None) -> ActionRequest:
    agent = Principal(id="agent:deployment-agent", type=PrincipalType.AGENT, permissions=frozenset({Permission.DEPLOY_PRODUCTION}))
    return ActionRequest(
        actor=agent,
        on_behalf_of=requester,
        action="deploy.production",
        permission=Permission.DEPLOY_PRODUCTION,
        resource="svc-api",
        payload=payload or {"version": "1.2.3"},
    )


async def test_full_flow_two_person_rule(gw: ApprovalGateway, bus: InMemoryEventBus) -> None:
    requester = human("req", Role.ADMIN)
    p = await gw.submit(deploy_req(requester))
    assert p.risk is RiskLevel.CRITICAL and p.required_approvals == 2
    d1 = await gw.decide(p.id, human("a1", Role.ADMIN), approve=True)
    assert d1.grant is None and d1.proposal.status is ProposalStatus.PENDING
    d2 = await gw.decide(p.id, human("a2", Role.ADMIN), approve=True, comment="lgtm")
    assert d2.grant is not None and d2.proposal.status is ProposalStatus.APPROVED
    executed = gw.consume_grant(d2.grant.token, deploy_req(requester))
    assert executed.status is ProposalStatus.EXECUTED
    types = [e.type for e in bus.history]
    assert EventType.APPROVAL_REQUESTED in types and EventType.APPROVAL_GRANTED in types
    gw.record_result(p.id, ok=True, result={"ok": True})
    assert gw.get(p.id, "default").execution_result == {"ok": True}


async def test_grant_single_use(gw: ApprovalGateway) -> None:
    req = deploy_req(human("req", Role.ADMIN))
    p = await gw.submit(req)
    await gw.decide(p.id, human("a1", Role.ADMIN), approve=True)
    grant = (await gw.decide(p.id, human("a2", Role.ADMIN), approve=True)).grant
    assert grant
    gw.consume_grant(grant.token, req)
    with pytest.raises(ApprovalError, match="executed"):
        gw.consume_grant(grant.token, req)


async def test_bait_and_switch_rejected(gw: ApprovalGateway) -> None:
    requester = human("req", Role.ADMIN)
    p = await gw.submit(deploy_req(requester, {"version": "1.2.3"}))
    await gw.decide(p.id, human("a1", Role.ADMIN), approve=True)
    grant = (await gw.decide(p.id, human("a2", Role.ADMIN), approve=True)).grant
    assert grant
    with pytest.raises(ApprovalError, match="differs"):
        gw.consume_grant(grant.token, deploy_req(requester, {"version": "6.6.6-malicious"}))


async def test_forged_and_malformed_grants(gw: ApprovalGateway) -> None:
    req = deploy_req(human("req", Role.ADMIN))
    p = await gw.submit(req)
    with pytest.raises(ApprovalError):
        gw.consume_grant("garbage", req)
    with pytest.raises(ApprovalError, match="signature"):
        gw.consume_grant(f"{p.id}.9999999999.{'0' * 64}", req)
    with pytest.raises(ApprovalError, match="invalid grant"):
        gw.consume_grant(f"prop_missing.1.{'0' * 64}", req)


@pytest.mark.parametrize(
    ("who", "match"),
    [
        (Principal(id="agent:x", type=PrincipalType.AGENT, permissions=frozenset({Permission.APPROVAL_DECIDE})), "only humans"),
        (human("v", Role.VIEWER), "approval:decide"),
        (human("nomfa", Role.ADMIN, mfa=False), "MFA"),
        (human("req", Role.ADMIN), "separation of duties"),
        (human("rev", Role.REVIEWER), "authority"),
    ],
)
async def test_reviewer_rules(gw: ApprovalGateway, who: Principal, match: str) -> None:
    p = await gw.submit(deploy_req(human("req", Role.ADMIN)))
    with pytest.raises(AuthorizationError, match=match):
        await gw.decide(p.id, who, approve=True)


async def test_double_vote_and_cross_tenant(gw: ApprovalGateway) -> None:
    p = await gw.submit(deploy_req(human("req", Role.ADMIN)))
    a1 = human("a1", Role.ADMIN)
    await gw.decide(p.id, a1, approve=True)
    with pytest.raises(ApprovalError, match="already voted"):
        await gw.decide(p.id, a1, approve=True)
    with pytest.raises(NotFound):
        await gw.decide(p.id, human("x", Role.ADMIN, tenant="other"), approve=True)


async def test_rejection_is_final(gw: ApprovalGateway) -> None:
    p = await gw.submit(deploy_req(human("req", Role.ADMIN)))
    d = await gw.decide(p.id, human("a1", Role.ADMIN), approve=False, comment="no")
    assert d.proposal.status is ProposalStatus.REJECTED
    with pytest.raises(ApprovalError):
        await gw.decide(p.id, human("a2", Role.ADMIN), approve=True)


async def test_expiry(gw: ApprovalGateway, clock: Clock) -> None:
    p = await gw.submit(deploy_req(human("req", Role.ADMIN)))
    clock.now += timedelta(days=2)
    assert gw.get(p.id, "default").status is ProposalStatus.EXPIRED
    assert gw.list("default", ProposalStatus.EXPIRED)


async def test_grant_expiry(gw: ApprovalGateway, clock: Clock) -> None:
    req = ActionRequest(actor=human("req", Role.ADMIN), action="code.merge", permission=Permission.CODE_MERGE, resource="pr/1")
    p = await gw.submit(req)
    assert p.required_approvals == 1
    grant = (await gw.decide(p.id, human("a1", Role.ADMIN), approve=True)).grant
    assert grant
    clock.now += timedelta(hours=2)
    with pytest.raises(ApprovalError, match="expired"):
        gw.consume_grant(grant.token, req)


async def test_reissue_and_cancel(gw: ApprovalGateway) -> None:
    requester = human("req", Role.ADMIN)
    req = ActionRequest(actor=requester, action="code.merge", permission=Permission.CODE_MERGE)
    p = await gw.submit(req)
    with pytest.raises(ApprovalError):
        gw.reissue_grant(p.id, requester)
    await gw.decide(p.id, human("a1", Role.ADMIN), approve=True)
    assert gw.reissue_grant(p.id, requester).payload_hash == p.payload_hash
    with pytest.raises(AuthorizationError):
        gw.reissue_grant(p.id, Principal(id="n", type=PrincipalType.HUMAN))
    p2 = await gw.submit(req)
    with pytest.raises(AuthorizationError):
        await gw.cancel(p2.id, human("other", Role.ADMIN))
    assert (await gw.cancel(p2.id, requester)).status is ProposalStatus.CANCELLED
    with pytest.raises(ApprovalError):
        await gw.cancel(p2.id, requester)


async def test_record_result_failure(gw: ApprovalGateway) -> None:
    p = await gw.submit(ActionRequest(actor=human("req", Role.ADMIN), action="code.merge", permission=Permission.CODE_MERGE))
    assert gw.record_result(p.id, ok=False, result={"e": 1}).status is ProposalStatus.FAILED
    with pytest.raises(NotFound):
        gw.record_result("nope", ok=True, result={})


def test_key_length() -> None:
    with pytest.raises(ValueError):
        ApprovalGateway(InMemoryProposalRepository(), AuditLog(InMemoryAuditStore(), KEY), InMemoryEventBus(), b"short")
