"""Human Approval Gateway.

Agent -> Proposal -> Approval Queue -> Human Review -> Execution Grant -> Execute

Invariants (enforced here, tested in tests/unit/test_approvals.py):
  * Only HUMAN principals with approval:decide and verified MFA may vote.
  * Separation of duties: the proposer and the delegating human cannot approve.
  * HIGH/CRITICAL proposals: the reviewer must themselves hold the target permission.
  * CRITICAL proposals need a quorum (default 2 distinct approvers). Any rejection is final.
  * Approval issues an HMAC execution grant bound to the exact payload hash, with expiry.
  * Grants are single-use; content changes after approval invalidate the grant.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from collections.abc import Callable
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, Field

from aicos.domain.common import new_id, utcnow
from aicos.domain.errors import ApprovalError, AuthorizationError, NotFound
from aicos.domain.identity import Permission, Principal
from aicos.events.bus import DomainEvent, EventBus, EventType
from aicos.security.audit import AuditLog, Outcome
from aicos.security.policy import ActionRequest
from aicos.security.rbac import effective_permissions


class ProposalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    EXECUTED = "executed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_RISK: dict[Permission, RiskLevel] = {
    Permission.DEPLOY_PRODUCTION: RiskLevel.CRITICAL,
    Permission.FINANCE_EXECUTE: RiskLevel.CRITICAL,
    Permission.PERMISSION_CHANGE: RiskLevel.CRITICAL,
    Permission.POLICY_WRITE: RiskLevel.CRITICAL,
    Permission.USER_DELETE: RiskLevel.CRITICAL,
    Permission.TENANT_MANAGE: RiskLevel.CRITICAL,
    Permission.SECRET_READ: RiskLevel.HIGH,
    Permission.INFRA_CHANGE: RiskLevel.HIGH,
    Permission.DB_SCHEMA_CHANGE: RiskLevel.HIGH,
    Permission.CONTRACT_SIGN: RiskLevel.HIGH,
    Permission.PLUGIN_INSTALL: RiskLevel.HIGH,
    Permission.CODE_MERGE: RiskLevel.MEDIUM,
    Permission.EMAIL_MASS_SEND: RiskLevel.MEDIUM,
    Permission.SOCIAL_PUBLISH: RiskLevel.MEDIUM,
}


def default_risk(action: ActionRequest) -> RiskLevel:
    return _RISK.get(action.permission, RiskLevel.MEDIUM)


def default_quorum(risk: RiskLevel) -> int:
    return 2 if risk is RiskLevel.CRITICAL else 1


class Vote(BaseModel):
    reviewer_id: str
    approve: bool
    comment: str = Field(default="", max_length=2000)
    ts: datetime = Field(default_factory=utcnow)


class Proposal(BaseModel):
    id: str = Field(default_factory=lambda: new_id("prop"))
    tenant_id: str
    action: ActionRequest
    payload_hash: str
    proposer_id: str
    delegator_id: str | None
    risk: RiskLevel
    required_approvals: int
    status: ProposalStatus = ProposalStatus.PENDING
    votes: list[Vote] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime
    decided_at: datetime | None = None
    executed_at: datetime | None = None
    execution_result: dict[str, object] | None = None

    @property
    def approvals(self) -> int:
        return sum(1 for v in self.votes if v.approve)


class ExecutionGrant(BaseModel):
    proposal_id: str
    payload_hash: str
    expires_at: datetime
    token: str


class Decision(BaseModel):
    proposal: Proposal
    grant: ExecutionGrant | None = None


class ProposalRepository(Protocol):
    def save(self, proposal: Proposal) -> None: ...
    def get(self, proposal_id: str) -> Proposal | None: ...
    def list(self, *, tenant_id: str, status: ProposalStatus | None = None, limit: int = 100) -> list[Proposal]: ...


class InMemoryProposalRepository:
    def __init__(self) -> None:
        self._items: dict[str, Proposal] = {}

    def save(self, proposal: Proposal) -> None:
        self._items[proposal.id] = proposal.model_copy(deep=True)

    def get(self, proposal_id: str) -> Proposal | None:
        p = self._items.get(proposal_id)
        return p.model_copy(deep=True) if p else None

    def list(self, *, tenant_id: str, status: ProposalStatus | None = None, limit: int = 100) -> list[Proposal]:
        rows = [p for p in self._items.values() if p.tenant_id == tenant_id and (status is None or p.status == status)]
        return [p.model_copy(deep=True) for p in sorted(rows, key=lambda p: p.created_at, reverse=True)[:limit]]


class ApprovalGateway:
    def __init__(
        self,
        repo: ProposalRepository,
        audit: AuditLog,
        bus: EventBus,
        signing_key: bytes,
        *,
        ttl: timedelta = timedelta(hours=24),
        grant_ttl: timedelta = timedelta(hours=1),
        risk_fn: Callable[[ActionRequest], RiskLevel] = default_risk,
        quorum_fn: Callable[[RiskLevel], int] = default_quorum,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        if len(signing_key) < 32:
            raise ValueError("approval signing key must be >= 32 bytes")
        self._repo, self._audit, self._bus, self._key = repo, audit, bus, signing_key
        self._ttl, self._grant_ttl = ttl, grant_ttl
        self._risk_fn, self._quorum_fn, self._clock = risk_fn, quorum_fn, clock
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ submit
    async def submit(self, action: ActionRequest) -> Proposal:
        risk = self._risk_fn(action)
        proposal = Proposal(
            tenant_id=action.tenant_id,
            action=action,
            payload_hash=action.payload_hash(),
            proposer_id=action.actor.id,
            delegator_id=action.on_behalf_of.id if action.on_behalf_of else None,
            risk=risk,
            required_approvals=max(1, self._quorum_fn(risk)),
            created_at=self._clock(),
            expires_at=self._clock() + self._ttl,
        )
        self._repo.save(proposal)
        self._audit.record(
            tenant_id=action.tenant_id,
            actor_id=action.actor.id,
            actor_type=action.actor.type,
            action=f"approval.submit:{action.action}",
            resource=action.resource,
            outcome=Outcome.PENDING,
            details={"proposal_id": proposal.id, "risk": risk, "payload_hash": proposal.payload_hash},
        )
        await self._bus.publish(
            DomainEvent(
                type=EventType.APPROVAL_REQUESTED,
                tenant_id=action.tenant_id,
                source="approval-gateway",
                correlation_id=proposal.id,
                payload={"proposal_id": proposal.id, "action": action.action, "risk": risk, "rationale": action.rationale},
            )
        )
        return proposal

    # ------------------------------------------------------------------ queries
    def get(self, proposal_id: str, tenant_id: str) -> Proposal:
        p = self._repo.get(proposal_id)
        if p is None or p.tenant_id != tenant_id:
            raise NotFound("proposal not found")
        return self._expire_if_needed(p)

    def list(self, tenant_id: str, status: ProposalStatus | None = None) -> list[Proposal]:
        return [self._expire_if_needed(p) for p in self._repo.list(tenant_id=tenant_id, status=status)]

    def _expire_if_needed(self, p: Proposal) -> Proposal:
        if p.status in (ProposalStatus.PENDING, ProposalStatus.APPROVED) and self._clock() >= p.expires_at:
            p.status = ProposalStatus.EXPIRED
            self._repo.save(p)
        return p

    # ------------------------------------------------------------------ decide
    def _check_reviewer(self, p: Proposal, reviewer: Principal) -> None:
        if not reviewer.is_human:
            raise AuthorizationError("only humans may decide approvals")
        if reviewer.tenant_id != p.tenant_id:
            raise NotFound("proposal not found")
        perms = effective_permissions(reviewer)
        if Permission.APPROVAL_DECIDE not in perms:
            raise AuthorizationError("missing approval:decide")
        if not reviewer.mfa_verified:
            raise AuthorizationError("MFA required to decide approvals")
        if reviewer.id in (p.proposer_id, p.delegator_id):
            raise AuthorizationError("separation of duties: requester cannot approve own proposal")
        if p.risk in (RiskLevel.HIGH, RiskLevel.CRITICAL) and p.action.permission not in perms:
            raise AuthorizationError(f"reviewer lacks authority over {p.action.permission}")
        if any(v.reviewer_id == reviewer.id for v in p.votes):
            raise ApprovalError("reviewer already voted")

    async def decide(self, proposal_id: str, reviewer: Principal, *, approve: bool, comment: str = "") -> Decision:
        with self._lock:
            p = self.get(proposal_id, reviewer.tenant_id)
            if p.status is not ProposalStatus.PENDING:
                raise ApprovalError(f"proposal is {p.status}")
            self._check_reviewer(p, reviewer)
            p.votes.append(Vote(reviewer_id=reviewer.id, approve=approve, comment=comment, ts=self._clock()))
            grant: ExecutionGrant | None = None
            if not approve:
                p.status, p.decided_at = ProposalStatus.REJECTED, self._clock()
            elif p.approvals >= p.required_approvals:
                p.status, p.decided_at = ProposalStatus.APPROVED, self._clock()
                p.expires_at = min(p.expires_at, self._clock() + self._grant_ttl)
                grant = self._issue_grant(p)
            self._repo.save(p)

        self._audit.record(
            tenant_id=p.tenant_id,
            actor_id=reviewer.id,
            actor_type=reviewer.type,
            action="approval.vote",
            resource=p.id,
            outcome=Outcome.SUCCESS if approve else Outcome.DENIED,
            details={"approve": approve, "status": p.status, "approvals": p.approvals, "required": p.required_approvals},
        )
        if p.status in (ProposalStatus.APPROVED, ProposalStatus.REJECTED):
            await self._bus.publish(
                DomainEvent(
                    type=EventType.APPROVAL_GRANTED if p.status is ProposalStatus.APPROVED else EventType.APPROVAL_REJECTED,
                    tenant_id=p.tenant_id,
                    source="approval-gateway",
                    correlation_id=p.id,
                    payload={"proposal_id": p.id, "action": p.action.action},
                )
            )
        return Decision(proposal=p, grant=grant)

    # ------------------------------------------------------------------ grants
    def _mac(self, proposal_id: str, payload_hash: str, exp: int) -> str:
        msg = f"{proposal_id}|{payload_hash}|{exp}".encode()
        return hmac.new(self._key, msg, hashlib.sha256).hexdigest()

    def _issue_grant(self, p: Proposal) -> ExecutionGrant:
        exp = int(p.expires_at.timestamp())
        return ExecutionGrant(
            proposal_id=p.id,
            payload_hash=p.payload_hash,
            expires_at=p.expires_at,
            token=f"{p.id}.{exp}.{self._mac(p.id, p.payload_hash, exp)}",
        )

    def reissue_grant(self, proposal_id: str, reviewer: Principal) -> ExecutionGrant:
        """Re-derive the grant for an APPROVED proposal (e.g. executor lost it)."""
        p = self.get(proposal_id, reviewer.tenant_id)
        if p.status is not ProposalStatus.APPROVED:
            raise ApprovalError(f"proposal is {p.status}")
        if Permission.APPROVAL_READ not in effective_permissions(reviewer):
            raise AuthorizationError("missing approval:read")
        return self._issue_grant(p)

    def consume_grant(self, token: str, action: ActionRequest) -> Proposal:
        """Atomically validate and burn a grant. Raises on any mismatch."""
        try:
            proposal_id, exp_s, mac = token.split(".")
            exp = int(exp_s)
        except ValueError:
            raise ApprovalError("malformed grant") from None
        with self._lock:
            p = self._repo.get(proposal_id)
            if p is None or p.tenant_id != action.tenant_id:
                raise ApprovalError("invalid grant")
            if not hmac.compare_digest(mac, self._mac(p.id, p.payload_hash, exp)):
                raise ApprovalError("invalid grant signature")
            if self._clock().timestamp() > exp:
                raise ApprovalError("grant expired")
            if p.status is not ProposalStatus.APPROVED:
                raise ApprovalError(f"grant not usable: proposal is {p.status}")
            if action.payload_hash() != p.payload_hash:
                raise ApprovalError("action content differs from approved proposal")
            p.status, p.executed_at = ProposalStatus.EXECUTED, self._clock()
            self._repo.save(p)
            return p

    def record_result(self, proposal_id: str, *, ok: bool, result: dict[str, object]) -> Proposal:
        with self._lock:
            p = self._repo.get(proposal_id)
            if p is None:
                raise NotFound("proposal not found")
            p.execution_result = result
            if not ok:
                p.status = ProposalStatus.FAILED
            self._repo.save(p)
            return p

    async def cancel(self, proposal_id: str, actor: Principal) -> Proposal:
        with self._lock:
            p = self.get(proposal_id, actor.tenant_id)
            if p.status is not ProposalStatus.PENDING:
                raise ApprovalError(f"proposal is {p.status}")
            if actor.id not in (p.proposer_id, p.delegator_id):
                raise AuthorizationError("only requester may cancel")
            p.status = ProposalStatus.CANCELLED
            self._repo.save(p)
        self._audit.record(
            tenant_id=p.tenant_id,
            actor_id=actor.id,
            actor_type=actor.type,
            action="approval.cancel",
            resource=p.id,
            outcome=Outcome.SUCCESS,
        )
        return p
