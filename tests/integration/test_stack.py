"""Integration tests against real Postgres(pgvector) + Redis. Run: pytest -m integration (CI job `integration`)."""

from __future__ import annotations

import asyncio
import os

import pytest

pytestmark = pytest.mark.integration
DB = os.environ.get("AICOS_IT_DATABASE_URL")
REDIS = os.environ.get("AICOS_IT_REDIS_URL")


@pytest.fixture
def pool():  # type: ignore[no-untyped-def]
    if not DB:
        pytest.skip("AICOS_IT_DATABASE_URL not set")
    from aicos.infrastructure.postgres import connect_pool

    p = connect_pool(DB)
    yield p
    p.close()


def test_audit_append_only_in_postgres(pool) -> None:  # type: ignore[no-untyped-def]
    from aicos.infrastructure.postgres import PgAuditStore
    from aicos.security.audit import AuditLog, Outcome

    log = AuditLog(PgAuditStore(pool), b"k" * 32)
    log.record(tenant_id="default", actor_id="it", actor_type="human", action="it.test", outcome=Outcome.SUCCESS)
    assert log.verify().valid
    with pool.connection() as c, pytest.raises(Exception, match=r"append-only|permission denied"):
        c.execute("UPDATE audit_log SET outcome='denied'")
    with pool.connection() as c, pytest.raises(Exception, match=r"append-only|permission denied"):
        c.execute("DELETE FROM audit_log")


async def test_pgvector_search_and_tenant_isolation(pool) -> None:  # type: ignore[no-untyped-def]
    from aicos.infrastructure.postgres import PgVectorStore
    from aicos.memory.embeddings import HashingEmbedder
    from aicos.memory.service import MemoryService
    from aicos.memory.store import MemoryScope, ScopeKey

    svc = MemoryService(PgVectorStore(pool, 1024), HashingEmbedder(1024))
    await svc.remember(tenant_id="default", scope=MemoryScope.COMPANY, owner_id="company", content="refund policy 30 days")
    hits = await svc.recall(tenant_id="default", query="refund policy", keys=[ScopeKey(scope=MemoryScope.COMPANY, owner_id="company")])
    assert hits and "refund" in hits[0].record.content
    assert not await svc.recall(tenant_id="other", query="refund", keys=[ScopeKey(scope=MemoryScope.COMPANY, owner_id="company")])


async def test_redis_streams_bus() -> None:
    if not REDIS:
        pytest.skip("AICOS_IT_REDIS_URL not set")
    from aicos.events.bus import DomainEvent
    from aicos.infrastructure.redis_bus import RedisStreamsEventBus

    bus = RedisStreamsEventBus(REDIS, block_ms=500)
    got: list[str] = []

    async def h(e: DomainEvent) -> None:
        got.append(e.id)

    sub = bus.subscribe("LeadFound", h, name="it")
    runner = asyncio.create_task(bus.run())
    await asyncio.sleep(0.5)
    evt = DomainEvent(type="LeadFound", source="it")
    await bus.publish(evt)
    for _ in range(20):
        if got:
            break
        await asyncio.sleep(0.2)
    bus.unsubscribe(sub.id)
    runner.cancel()
    assert evt.id in got
