"""Event bus: typed domain events, at-least-once delivery, isolated handler failures.

InMemoryEventBus is for dev/tests. RedisStreamsEventBus (infrastructure/redis_bus.py)
provides consumer groups, persistence and horizontal scaling. NATS JetStream / Kafka
adapters implement the same `EventBus` protocol.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections import deque
from collections.abc import Awaitable, Callable
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, Field, field_validator

from aicos.domain.common import new_id, utcnow

log = logging.getLogger(__name__)


class EventType(StrEnum):
    LEAD_FOUND = "LeadFound"
    CUSTOMER_CREATED = "CustomerCreated"
    ISSUE_DETECTED = "IssueDetected"
    DEPLOYMENT_REQUESTED = "DeploymentRequested"
    DEPLOYMENT_COMPLETED = "DeploymentCompleted"
    TICKET_CREATED = "TicketCreated"
    PROPOSAL_GENERATED = "ProposalGenerated"
    AUDIT_COMPLETED = "AuditCompleted"
    TASK_SUBMITTED = "TaskSubmitted"
    TASK_COMPLETED = "TaskCompleted"
    TASK_FAILED = "TaskFailed"
    APPROVAL_REQUESTED = "ApprovalRequested"
    APPROVAL_GRANTED = "ApprovalGranted"
    APPROVAL_REJECTED = "ApprovalRejected"
    ACTION_EXECUTED = "ActionExecuted"
    ACTION_DENIED = "ActionDenied"
    SECURITY_ALERT = "SecurityAlert"
    PLUGIN_STATE_CHANGED = "PluginStateChanged"
    KNOWLEDGE_INGESTED = "KnowledgeIngested"


_TYPE_RX = re.compile(r"^[A-Z][A-Za-z0-9]{1,63}(\.[A-Z][A-Za-z0-9]{2,63})?$")


class DomainEvent(BaseModel):
    id: str = Field(default_factory=lambda: new_id("evt"))
    type: str
    tenant_id: str = "default"
    source: str = Field(min_length=1, max_length=200)
    occurred_at: datetime = Field(default_factory=utcnow)
    correlation_id: str | None = None
    schema_version: int = 1
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("type")
    @classmethod
    def _valid_type(cls, v: str) -> str:
        # core types are PascalCase; plugin types are namespaced: "<Plugin>.<Event>"
        if not _TYPE_RX.match(v):
            raise ValueError("event type must be PascalCase or Namespace.PascalCase")
        return v


Handler = Callable[[DomainEvent], Awaitable[None]]


class Subscription(BaseModel):
    id: str
    event_type: str
    name: str


class DeadLetter(BaseModel):
    event: DomainEvent
    subscription: str
    error: str
    attempts: int


class EventBus(Protocol):
    async def publish(self, event: DomainEvent) -> None: ...
    def subscribe(self, event_type: str, handler: Handler, *, name: str) -> Subscription: ...
    def unsubscribe(self, subscription_id: str) -> None: ...


class InMemoryEventBus:
    def __init__(self, *, max_attempts: int = 3, history: int = 1000) -> None:
        self._subs: dict[str, tuple[Subscription, Handler]] = {}
        self.max_attempts = max_attempts
        self.dead_letters: deque[DeadLetter] = deque(maxlen=history)
        self.history: deque[DomainEvent] = deque(maxlen=history)

    def subscribe(self, event_type: str, handler: Handler, *, name: str) -> Subscription:
        sub = Subscription(id=new_id("sub"), event_type=event_type, name=name)
        self._subs[sub.id] = (sub, handler)
        return sub

    def unsubscribe(self, subscription_id: str) -> None:
        self._subs.pop(subscription_id, None)

    async def _deliver(self, sub: Subscription, handler: Handler, event: DomainEvent) -> None:
        last_err = ""
        for attempt in range(1, self.max_attempts + 1):
            try:
                await handler(event)
                return
            except Exception as exc:  # noqa: BLE001 - isolate subscriber failures
                last_err = f"{type(exc).__name__}: {exc}"
                log.warning("event handler %s failed (attempt %d): %s", sub.name, attempt, last_err)
                await asyncio.sleep(0)
        self.dead_letters.append(DeadLetter(event=event, subscription=sub.name, error=last_err, attempts=self.max_attempts))

    async def publish(self, event: DomainEvent) -> None:
        self.history.append(event)
        targets = [(s, h) for s, h in self._subs.values() if s.event_type in (event.type, "*")]
        await asyncio.gather(*(self._deliver(s, h, event) for s, h in targets))
