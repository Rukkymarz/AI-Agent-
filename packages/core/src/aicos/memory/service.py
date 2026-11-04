"""Memory service: scoped write/recall with tenant isolation and agent visibility rules.

Visibility for an agent run:
  SHORT_TERM(run_id), CONVERSATION(conversation_id), AGENT(agent_id),
  PROJECT(project_id), COMPANY("company"), LONG_TERM(human_id)
An agent can never read another agent's AGENT scope.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from aicos.domain.common import utcnow
from aicos.memory.embeddings import Embedder
from aicos.memory.store import MemoryRecord, MemoryScope, ScopeKey, SearchHit, VectorStore

DEFAULT_TTL: dict[MemoryScope, timedelta | None] = {
    MemoryScope.SHORT_TERM: timedelta(hours=1),
    MemoryScope.CONVERSATION: timedelta(days=30),
    MemoryScope.AGENT: None,
    MemoryScope.PROJECT: None,
    MemoryScope.COMPANY: None,
    MemoryScope.LONG_TERM: None,
}


def visible_scopes(
    *,
    agent_id: str | None = None,
    run_id: str | None = None,
    conversation_id: str | None = None,
    project_id: str | None = None,
    human_id: str | None = None,
) -> list[ScopeKey]:
    keys = [ScopeKey(scope=MemoryScope.COMPANY, owner_id="company")]
    if run_id:
        keys.append(ScopeKey(scope=MemoryScope.SHORT_TERM, owner_id=run_id))
    if conversation_id:
        keys.append(ScopeKey(scope=MemoryScope.CONVERSATION, owner_id=conversation_id))
    if agent_id:
        keys.append(ScopeKey(scope=MemoryScope.AGENT, owner_id=agent_id))
    if project_id:
        keys.append(ScopeKey(scope=MemoryScope.PROJECT, owner_id=project_id))
    if human_id:
        keys.append(ScopeKey(scope=MemoryScope.LONG_TERM, owner_id=human_id))
    return keys


class MemoryService:
    def __init__(self, store: VectorStore, embedder: Embedder, clock: Callable[[], datetime] = utcnow) -> None:
        self.store, self.embedder, self._clock = store, embedder, clock

    async def remember(
        self,
        *,
        tenant_id: str,
        scope: MemoryScope,
        owner_id: str,
        content: str,
        metadata: dict[str, Any] | None = None,
        importance: float = 0.5,
        ttl: timedelta | None = None,
    ) -> MemoryRecord:
        [vec] = await self.embedder.embed([content])
        ttl = ttl if ttl is not None else DEFAULT_TTL[scope]
        rec = MemoryRecord(
            tenant_id=tenant_id,
            scope=scope,
            owner_id=owner_id,
            content=content,
            embedding=vec,
            metadata={**(metadata or {}), "embedding_model": self.embedder.model},
            importance=importance,
            created_at=self._clock(),
            expires_at=(self._clock() + ttl) if ttl else None,
        )
        await self.store.upsert([rec])
        return rec

    async def remember_many(self, records: list[MemoryRecord]) -> None:
        vecs = await self.embedder.embed([r.content for r in records])
        for r, v in zip(records, vecs, strict=True):
            r.embedding = v
            r.metadata.setdefault("embedding_model", self.embedder.model)
        await self.store.upsert(records)

    async def recall(
        self,
        *,
        tenant_id: str,
        query: str,
        keys: list[ScopeKey],
        k: int = 8,
        min_score: float = 0.05,
    ) -> list[SearchHit]:
        [vec] = await self.embedder.embed([query])
        return await self.store.search(tenant_id, vec, keys=keys, k=k, min_score=min_score, now=self._clock())

    async def history(self, *, tenant_id: str, key: ScopeKey, limit: int = 20) -> list[MemoryRecord]:
        return await self.store.recent(tenant_id, key, limit)

    async def purge_expired(self) -> int:
        return await self.store.purge_expired(self._clock())
