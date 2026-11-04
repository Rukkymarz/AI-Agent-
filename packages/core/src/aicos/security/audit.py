"""Tamper-evident audit trail.

Each record carries HMAC-SHA256(key, canonical(record_without_hash)) where the record
includes the previous record's hash. Any edit, deletion or reorder breaks `verify()`.
Storage adapters MUST be append-only (Postgres adapter enforces with triggers + REVOKE).
Periodically anchor the head hash externally (S3 Object Lock / transparency log)
to defeat a full-chain rewrite by an attacker who holds the key.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from collections.abc import Iterable, Sequence
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, Field

from aicos.domain.common import canonical_json, utcnow

GENESIS_HASH = "0" * 64


class Outcome(StrEnum):
    SUCCESS = "success"
    DENIED = "denied"
    PENDING = "pending"
    FAILURE = "failure"
    BLOCKED = "blocked"


class AuditRecord(BaseModel):
    seq: int
    ts: datetime
    tenant_id: str
    actor_id: str
    actor_type: str
    action: str
    resource: str = "*"
    outcome: Outcome
    details: dict[str, Any] = Field(default_factory=dict)
    correlation_id: str | None = None
    prev_hash: str
    hash: str = ""

    def body(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"hash"})


class AuditStore(Protocol):
    def append(self, record: AuditRecord) -> None: ...
    def last(self) -> AuditRecord | None: ...
    def iter_all(self) -> Iterable[AuditRecord]: ...
    def query(self, *, tenant_id: str | None = None, limit: int = 100) -> Sequence[AuditRecord]: ...


class InMemoryAuditStore:
    def __init__(self) -> None:
        self._records: list[AuditRecord] = []

    def append(self, record: AuditRecord) -> None:
        self._records.append(record)

    def last(self) -> AuditRecord | None:
        return self._records[-1] if self._records else None

    def iter_all(self) -> Iterable[AuditRecord]:
        return iter(list(self._records))

    def query(self, *, tenant_id: str | None = None, limit: int = 100) -> Sequence[AuditRecord]:
        rows = [r for r in self._records if tenant_id is None or r.tenant_id == tenant_id]
        return rows[-limit:]


class ChainVerification(BaseModel):
    valid: bool
    records_checked: int
    first_invalid_seq: int | None = None
    reason: str | None = None
    head_hash: str = GENESIS_HASH


class AuditLog:
    def __init__(self, store: AuditStore, key: bytes) -> None:
        if len(key) < 32:
            raise ValueError("audit HMAC key must be >= 32 bytes")
        self._store = store
        self._key = key
        self._lock = threading.Lock()

    def _digest(self, body: dict[str, Any]) -> str:
        return hmac.new(self._key, canonical_json(body).encode(), hashlib.sha256).hexdigest()

    def record(
        self,
        *,
        tenant_id: str,
        actor_id: str,
        actor_type: str,
        action: str,
        outcome: Outcome,
        resource: str = "*",
        details: dict[str, Any] | None = None,
        correlation_id: str | None = None,
    ) -> AuditRecord:
        with self._lock:
            last = self._store.last()
            rec = AuditRecord(
                seq=(last.seq + 1) if last else 1,
                ts=utcnow(),
                tenant_id=tenant_id,
                actor_id=actor_id,
                actor_type=actor_type,
                action=action,
                resource=resource,
                outcome=outcome,
                details=details or {},
                correlation_id=correlation_id,
                prev_hash=last.hash if last else GENESIS_HASH,
            )
            rec.hash = self._digest(rec.body())
            self._store.append(rec)
            return rec

    def query(self, *, tenant_id: str | None = None, limit: int = 100) -> Sequence[AuditRecord]:
        return self._store.query(tenant_id=tenant_id, limit=limit)

    def verify(self) -> ChainVerification:
        prev, expected_seq, count = GENESIS_HASH, 1, 0
        for rec in self._store.iter_all():
            count += 1
            if rec.seq != expected_seq:
                return ChainVerification(valid=False, records_checked=count, first_invalid_seq=rec.seq, reason="sequence_gap")
            if rec.prev_hash != prev:
                return ChainVerification(valid=False, records_checked=count, first_invalid_seq=rec.seq, reason="broken_link")
            if not hmac.compare_digest(rec.hash, self._digest(rec.body())):
                return ChainVerification(valid=False, records_checked=count, first_invalid_seq=rec.seq, reason="hash_mismatch")
            prev, expected_seq = rec.hash, expected_seq + 1
        return ChainVerification(valid=True, records_checked=count, head_hash=prev)
