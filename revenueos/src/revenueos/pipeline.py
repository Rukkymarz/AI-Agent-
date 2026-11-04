"""Opportunity pipeline and recurring-revenue deals."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from aicos.domain.common import utcnow


class Stage(StrEnum):
    OPPORTUNITY = "opportunity"  # replied / inbound
    MEETING = "meeting"  # meeting booked
    PROPOSAL = "proposal"  # proposal sent
    NEGOTIATION = "negotiation"
    WON = "won"  # signed, recurring client
    LOST = "lost"
    CHURNED = "churned"  # was a client, cancelled


STAGE_PROBABILITY: dict[Stage, float] = {
    Stage.OPPORTUNITY: 0.10,
    Stage.MEETING: 0.25,
    Stage.PROPOSAL: 0.45,
    Stage.NEGOTIATION: 0.70,
    Stage.WON: 1.0,
    Stage.LOST: 0.0,
    Stage.CHURNED: 0.0,
}

_ALLOWED: dict[Stage, set[Stage]] = {
    Stage.OPPORTUNITY: {Stage.MEETING, Stage.PROPOSAL, Stage.LOST},
    Stage.MEETING: {Stage.PROPOSAL, Stage.LOST},
    Stage.PROPOSAL: {Stage.NEGOTIATION, Stage.WON, Stage.LOST},
    Stage.NEGOTIATION: {Stage.WON, Stage.LOST, Stage.PROPOSAL},
    Stage.WON: {Stage.CHURNED},
    Stage.LOST: {Stage.OPPORTUNITY},
    Stage.CHURNED: {Stage.OPPORTUNITY},
}


class Deal(BaseModel):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    tenant_id: str = "default"
    lead_id: uuid.UUID
    stage: Stage = Stage.OPPORTUNITY
    package: str | None = None
    monthly_value: float = Field(default=0, ge=0)
    setup_fee: float = Field(default=0, ge=0)
    contract_months: int = Field(default=12, ge=1)
    campaign_id: uuid.UUID | None = None
    proposal_sent_at: datetime | None = None
    won_at: datetime | None = None
    lost_reason: str | None = None
    churned_at: datetime | None = None
    created_at: datetime = Field(default_factory=utcnow)
    history: list[dict[str, str]] = Field(default_factory=list)

    @property
    def weighted_monthly_value(self) -> float:
        return self.monthly_value * STAGE_PROBABILITY[self.stage]

    def move(self, to: Stage, *, at: datetime | None = None, actor: str = "system", reason: str = "") -> None:
        if to == self.stage:
            return
        if to not in _ALLOWED[self.stage]:
            raise ValueError(f"illegal stage transition {self.stage} -> {to}")
        at = at or utcnow()
        if to is Stage.PROPOSAL:
            self.proposal_sent_at = self.proposal_sent_at or at
        if to is Stage.WON:
            if self.monthly_value <= 0:
                raise ValueError("a won deal needs a monthly_value (recurring revenue)")
            self.won_at = at
        if to is Stage.LOST:
            self.lost_reason = reason or "unspecified"
        if to is Stage.CHURNED:
            self.churned_at = at
        self.history.append({"from": self.stage, "to": to, "at": at.isoformat(), "actor": actor, "reason": reason})
        self.stage = to
