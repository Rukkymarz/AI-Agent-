"""PostgreSQL + pgvector adapters (psycopg 3). Schema: infra/postgres/init/001_schema.sql.

All queries are parameterised. Tenant isolation is double-enforced: WHERE tenant_id = %s
in code AND Row-Level Security policies keyed on `SET LOCAL app.tenant_id`.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import Any

from aicos.approvals.gateway import Proposal, ProposalStatus
from aicos.memory.store import MemoryRecord, ScopeKey, SearchHit
from aicos.security.audit import AuditRecord


def connect_pool(dsn: str) -> Any:
    from psycopg_pool import ConnectionPool

    return ConnectionPool(dsn, min_size=2, max_size=20, kwargs={"autocommit": False}, open=True)


def _vec(v: list[float]) -> str:
    return "[" + ",".join(f"{x:.7f}" for x in v) + "]"


class PgAuditStore:
    def __init__(self, pool: Any) -> None:
        self._pool = pool

    def append(self, record: AuditRecord) -> None:
        with self._pool.connection() as c:
            c.execute(
                "INSERT INTO audit_log (seq, ts, tenant_id, actor_id, actor_type, action, resource, outcome, details,"
                " correlation_id, prev_hash, hash) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (
                    record.seq,
                    record.ts,
                    record.tenant_id,
                    record.actor_id,
                    record.actor_type,
                    record.action,
                    record.resource,
                    record.outcome,
                    json.dumps(record.details),
                    record.correlation_id,
                    record.prev_hash,
                    record.hash,
                ),
            )

    def _row(self, r: tuple[Any, ...]) -> AuditRecord:
        return AuditRecord(
            seq=r[0],
            ts=r[1],
            tenant_id=r[2],
            actor_id=r[3],
            actor_type=r[4],
            action=r[5],
            resource=r[6],
            outcome=r[7],
            details=r[8],
            correlation_id=r[9],
            prev_hash=r[10],
            hash=r[11],
        )

    _COLS = "seq, ts, tenant_id, actor_id, actor_type, action, resource, outcome, details, correlation_id, prev_hash, hash"

    def last(self) -> AuditRecord | None:
        with self._pool.connection() as c:
            row = c.execute(f"SELECT {self._COLS} FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()  # noqa: S608 - constant columns
            return self._row(row) if row else None

    def iter_all(self) -> Iterable[AuditRecord]:
        with self._pool.connection() as c, c.cursor(name="audit_scan") as cur:
            cur.execute(f"SELECT {self._COLS} FROM audit_log ORDER BY seq")  # noqa: S608 - constant columns
            for row in cur:
                yield self._row(row)

    def query(self, *, tenant_id: str | None = None, limit: int = 100) -> Sequence[AuditRecord]:
        with self._pool.connection() as c:
            rows = c.execute(
                f"SELECT {self._COLS} FROM audit_log WHERE (%s::text IS NULL OR tenant_id = %s) ORDER BY seq DESC LIMIT %s",  # noqa: S608
                (tenant_id, tenant_id, limit),
            ).fetchall()
            return [self._row(r) for r in reversed(rows)]


class PgVectorStore:
    def __init__(self, pool: Any, dim: int) -> None:
        self._pool, self.dim = pool, dim

    async def upsert(self, records: Sequence[MemoryRecord]) -> None:
        with self._pool.connection() as c:
            for r in records:
                c.execute(
                    "INSERT INTO memory_records (id, tenant_id, scope, owner_id, content, embedding, metadata, importance,"
                    " created_at, expires_at) VALUES (%s,%s,%s,%s,%s,%s::vector,%s,%s,%s,%s)"
                    " ON CONFLICT (id) DO UPDATE SET content=EXCLUDED.content, embedding=EXCLUDED.embedding,"
                    " metadata=EXCLUDED.metadata, importance=EXCLUDED.importance, expires_at=EXCLUDED.expires_at",
                    (
                        r.id,
                        r.tenant_id,
                        r.scope,
                        r.owner_id,
                        r.content,
                        _vec(r.embedding),
                        json.dumps(r.metadata),
                        r.importance,
                        r.created_at,
                        r.expires_at,
                    ),
                )

    async def search(
        self,
        tenant_id: str,
        embedding: list[float],
        *,
        keys: Sequence[ScopeKey],
        k: int = 8,
        min_score: float = 0.0,
        exclude_quarantined: bool = True,
        now: datetime | None = None,
    ) -> list[SearchHit]:
        scopes = [key.scope.value for key in keys]
        owners = [key.owner_id for key in keys]
        with self._pool.connection() as c:
            c.execute("SET LOCAL app.tenant_id = %s", (tenant_id,))
            rows = c.execute(
                "SELECT id, tenant_id, scope, owner_id, content, metadata, importance, created_at, expires_at,"
                " 1 - (embedding <=> %s::vector) AS score FROM memory_records"
                " WHERE tenant_id = %s AND (scope, owner_id) IN (SELECT * FROM unnest(%s::text[], %s::text[]))"
                " AND (expires_at IS NULL OR expires_at > now())"
                " AND (NOT %s OR coalesce((metadata->>'quarantined')::boolean, false) = false)"
                " ORDER BY embedding <=> %s::vector LIMIT %s",
                (_vec(embedding), tenant_id, scopes, owners, exclude_quarantined, _vec(embedding), k),
            ).fetchall()
        return [
            SearchHit(
                record=MemoryRecord(
                    id=r[0],
                    tenant_id=r[1],
                    scope=r[2],
                    owner_id=r[3],
                    content=r[4],
                    metadata=r[5],
                    importance=r[6],
                    created_at=r[7],
                    expires_at=r[8],
                ),
                score=float(r[9]),
            )
            for r in rows
            if float(r[9]) >= min_score
        ]

    async def recent(self, tenant_id: str, key: ScopeKey, limit: int = 20) -> list[MemoryRecord]:
        with self._pool.connection() as c:
            rows = c.execute(
                "SELECT id, tenant_id, scope, owner_id, content, metadata, importance, created_at, expires_at FROM memory_records"
                " WHERE tenant_id=%s AND scope=%s AND owner_id=%s ORDER BY created_at DESC LIMIT %s",
                (tenant_id, key.scope.value, key.owner_id, limit),
            ).fetchall()
        return [
            MemoryRecord(
                id=r[0],
                tenant_id=r[1],
                scope=r[2],
                owner_id=r[3],
                content=r[4],
                metadata=r[5],
                importance=r[6],
                created_at=r[7],
                expires_at=r[8],
            )
            for r in rows
        ]

    async def purge_expired(self, now: datetime) -> int:
        with self._pool.connection() as c:
            return int(c.execute("DELETE FROM memory_records WHERE expires_at <= %s", (now,)).rowcount)


class PgProposalRepository:
    def __init__(self, pool: Any) -> None:
        self._pool = pool

    def save(self, proposal: Proposal) -> None:
        with self._pool.connection() as c:
            c.execute(
                "INSERT INTO approval_proposals (id, tenant_id, status, risk, body, created_at, expires_at)"
                " VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status,"
                " body=EXCLUDED.body, expires_at=EXCLUDED.expires_at, updated_at=now()",
                (
                    proposal.id,
                    proposal.tenant_id,
                    proposal.status,
                    proposal.risk,
                    proposal.model_dump_json(),
                    proposal.created_at,
                    proposal.expires_at,
                ),
            )

    def get(self, proposal_id: str) -> Proposal | None:
        with self._pool.connection() as c:
            row = c.execute("SELECT body FROM approval_proposals WHERE id=%s", (proposal_id,)).fetchone()
        return Proposal.model_validate(row[0]) if row else None

    def list(self, *, tenant_id: str, status: ProposalStatus | None = None, limit: int = 100) -> list[Proposal]:
        with self._pool.connection() as c:
            rows = c.execute(
                "SELECT body FROM approval_proposals WHERE tenant_id=%s AND (%s::text IS NULL OR status=%s)"
                " ORDER BY created_at DESC LIMIT %s",
                (tenant_id, status, status, limit),
            ).fetchall()
        return [Proposal.model_validate(r[0]) for r in rows]
