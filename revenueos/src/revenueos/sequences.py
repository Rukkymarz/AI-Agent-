"""Follow-up automation (Sequence 1).

    DAY 1   initial ("Quick observation about {business_name}")
    DAY 3   not opened            -> followup_1  (re-engagement)
            opened, no click      -> case_study
            clicked, no reply     -> audit_sample
    DAY 7   clicked (engaged)     -> meeting_invite (direct calendar link)
            otherwise             -> followup_2  ("Worth a quick conversation?")
    DAY 14  followup_3            ("Final follow-up", closes the loop)
    then    sequence completed    -> lead moves to NURTURE

    ANY TIME  replied         -> stop, lead -> OPPORTUNITY pipeline
              meeting booked  -> stop, deal stage -> MEETING
              unsubscribed / bounced / complained -> stop + suppress

`decide()` is a pure function of (enrollment, now) so every branch is unit-tested. Opens are a *weak* signal
(Apple Mail Privacy Protection pre-fetches pixels), so opens only change the day-3 variant, never stop a sequence.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from enum import StrEnum

from pydantic import BaseModel, Field

from revenueos.email import EmailStep, SendPolicy


class EngagementEvent(StrEnum):
    DELIVERED = "delivered"
    OPENED = "opened"
    CLICKED = "clicked"
    REPLIED = "replied"
    MEETING_BOOKED = "meeting_booked"
    BOUNCED = "bounced"
    COMPLAINED = "complained"
    UNSUBSCRIBED = "unsubscribed"


class EnrollmentStatus(StrEnum):
    ACTIVE = "active"
    COMPLETED = "completed"  # all touches sent, no reply
    REPLIED = "replied"
    MEETING_BOOKED = "meeting_booked"
    UNSUBSCRIBED = "unsubscribed"
    BOUNCED = "bounced"
    PAUSED = "paused"


TERMINAL = {
    EnrollmentStatus.COMPLETED,
    EnrollmentStatus.REPLIED,
    EnrollmentStatus.MEETING_BOOKED,
    EnrollmentStatus.UNSUBSCRIBED,
    EnrollmentStatus.BOUNCED,
}


class SentStep(BaseModel):
    step: EmailStep
    sent_at: datetime
    message_id: str


class Enrollment(BaseModel):
    """One lead in one campaign. Persisted as the `outreach` row (+ outreach_messages)."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    campaign_id: uuid.UUID
    lead_id: uuid.UUID
    email: str
    timezone: str = "America/New_York"
    started_at: datetime
    status: EnrollmentStatus = EnrollmentStatus.ACTIVE
    sent: list[SentStep] = Field(default_factory=list)
    opened_at: datetime | None = None
    clicked_at: datetime | None = None
    replied_at: datetime | None = None
    meeting_booked_at: datetime | None = None
    last_contact: datetime | None = None

    @property
    def thread_id(self) -> str | None:
        return self.sent[0].message_id if self.sent else None

    def apply(self, event: EngagementEvent, at: datetime) -> None:
        """Fold an engagement event into state. Idempotent; first timestamp wins."""
        if event is EngagementEvent.OPENED and self.opened_at is None:
            self.opened_at = at
        elif event is EngagementEvent.CLICKED:
            self.clicked_at = self.clicked_at or at
            self.opened_at = self.opened_at or at  # a click implies an open
        elif event is EngagementEvent.REPLIED:
            self.replied_at = self.replied_at or at
            self.status = EnrollmentStatus.REPLIED
        elif event is EngagementEvent.MEETING_BOOKED:
            self.meeting_booked_at = self.meeting_booked_at or at
            self.status = EnrollmentStatus.MEETING_BOOKED
        elif event in (EngagementEvent.UNSUBSCRIBED, EngagementEvent.COMPLAINED):
            self.status = EnrollmentStatus.UNSUBSCRIBED
        elif event is EngagementEvent.BOUNCED:
            self.status = EnrollmentStatus.BOUNCED


class DecisionKind(StrEnum):
    SEND = "send"
    WAIT = "wait"
    STOP = "stop"


class PipelineMove(StrEnum):
    OPPORTUNITY = "opportunity"
    MEETING = "meeting"
    NURTURE = "nurture"
    SUPPRESS = "suppress"


class Decision(BaseModel):
    kind: DecisionKind
    step: EmailStep | None = None
    send_at: datetime | None = None
    reason: str
    pipeline: PipelineMove | None = None


class Touch(BaseModel):
    day: int = Field(ge=1)  # "DAY n" in the playbook; offset = day - 1


SEQUENCE_1: list[Touch] = [Touch(day=1), Touch(day=3), Touch(day=7), Touch(day=14)]


def _variant(index: int, e: Enrollment) -> tuple[EmailStep, str]:
    if index == 0:
        return EmailStep.INITIAL, "day1_initial"
    if index == 1:
        if e.clicked_at:
            return EmailStep.AUDIT_SAMPLE, "clicked_no_reply"
        if e.opened_at:
            return EmailStep.CASE_STUDY, "opened_no_click"
        return EmailStep.FOLLOWUP_1, "not_opened"
    if index == 2:
        if e.clicked_at:
            return EmailStep.MEETING_INVITE, "engaged_meeting_invite"
        return EmailStep.FOLLOWUP_2, "meeting_request"
    return EmailStep.FOLLOWUP_3, "close_loop"


def decide(e: Enrollment, now: datetime, *, touches: list[Touch] = SEQUENCE_1, policy: SendPolicy | None = None) -> Decision:
    policy = policy or SendPolicy()
    if e.status is EnrollmentStatus.MEETING_BOOKED:
        return Decision(kind=DecisionKind.STOP, reason="meeting_booked", pipeline=PipelineMove.MEETING)
    if e.status is EnrollmentStatus.REPLIED:
        return Decision(kind=DecisionKind.STOP, reason="replied", pipeline=PipelineMove.OPPORTUNITY)
    if e.status in (EnrollmentStatus.UNSUBSCRIBED, EnrollmentStatus.BOUNCED):
        return Decision(kind=DecisionKind.STOP, reason=e.status.value, pipeline=PipelineMove.SUPPRESS)
    if e.status is EnrollmentStatus.PAUSED:
        return Decision(kind=DecisionKind.WAIT, reason="paused")
    if e.status is EnrollmentStatus.COMPLETED:
        return Decision(kind=DecisionKind.STOP, reason="completed", pipeline=PipelineMove.NURTURE)

    index = len(e.sent)
    if index >= len(touches):
        return Decision(kind=DecisionKind.STOP, reason="sequence_complete", pipeline=PipelineMove.NURTURE)
    due = e.started_at + timedelta(days=touches[index].day - 1)
    if index > 0:  # never two touches within 24h even if the schedule slipped
        due = max(due, e.sent[-1].sent_at + timedelta(hours=24))
    due = policy.next_window(due, e.timezone)
    step, reason = _variant(index, e)
    if now < due:
        return Decision(kind=DecisionKind.WAIT, step=step, send_at=due, reason=f"waiting:{reason}")
    return Decision(kind=DecisionKind.SEND, step=step, send_at=due, reason=reason)
