"""Memory records and vector store protocol (pgvector in production)."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, Field

from aicos.domain.common import new_id, utcnow
from aicos.memory.embeddings import cosine


class MemoryScope(StrEnum):
    SHORT_TERM = "short_term"  # working memory for a task run (TTL)
    CONVERSATION = "conversation"  # per conversation thread
    AGENT = "agent"  # an agent's private learned notes
    PROJECT = "project"  # shared by agents on a project
    COMPANY = "company"  # tenant-wide knowledge
    LONG_TERM = "long_term"  # durable, consolidated facts about a principal


class MemoryRecord(BaseModel):
    id: str = Field(default_factory=lambda: new_id("mem"))
    tenant_id: str
    scope: MemoryScope
    owner_id: str  # agent id / project id / conversation id / "company"
    content: str
    embedding: list[float] = Field(default_factory=list, repr=False)
    metadata: dict[str, Any] = Field(default_factory=dict)
    importance: float = Field(default=0.5, ge=0.0, le=1.0)
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime | None = None


class ScopeKey(BaseModel, frozen=True):
    scope: MemoryScope
    owner_id: str


class SearchHit(BaseModel):
    record: MemoryRecord
    score: float


class VectorStore(Protocol):
    async def upsert(self, records: Sequence[MemoryRecord]) -> None: ...
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
    ) -> list[SearchHit]: ...
    async def recent(self, tenant_id: str, key: ScopeKey, limit: int = 20) -> list[MemoryRecord]: ...
    async def purge_expired(self, now: datetime) -> int: ...


class InMemoryVectorStore:
    def __init__(self) -> None:
        self._rows: dict[str, MemoryRecord] = {}

    async def upsert(self, records: Sequence[MemoryRecord]) -> None:
        for r in records:
            self._rows[r.id] = r

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
        now = now or utcnow()
        allowed = {(key.scope, key.owner_id) for key in keys}
        hits: list[SearchHit] = []
        for r in self._rows.values():
            if r.tenant_id != tenant_id or (r.scope, r.owner_id) not in allowed:
                continue
            if r.expires_at and r.expires_at <= now:
                continue
            if exclude_quarantined and r.metadata.get("quarantined"):
                continue
            if not r.embedding:
                continue
            s = cosine(embedding, r.embedding)
            if s >= min_score:
                hits.append(SearchHit(record=r, score=s))
        hits.sort(key=lambda h: (h.score, h.record.importance), reverse=True)
        return hits[:k]

    async def recent(self, tenant_id: str, key: ScopeKey, limit: int = 20) -> list[MemoryRecord]:
        rows = [r for r in self._rows.values() if r.tenant_id == tenant_id and r.scope == key.scope and r.owner_id == key.owner_id]
        return sorted(rows, key=lambda r: r.created_at, reverse=True)[:limit]

    async def purge_expired(self, now: datetime) -> int:
        dead = [i for i, r in self._rows.items() if r.expires_at and r.expires_at <= now]
        for i in dead:
            del self._rows[i]
        return len(dead)
