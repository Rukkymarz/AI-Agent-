"""Redis Streams event bus: durable, consumer groups, horizontal scale, dead-letter stream.

Stream per event type: aicos:events:<Type>. Each subscription = consumer group.
Run `await bus.run()` in the worker service to consume.
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket

from aicos.domain.common import new_id
from aicos.events.bus import DomainEvent, Handler, Subscription

log = logging.getLogger(__name__)
PREFIX = "aicos:events:"
ALL = PREFIX + "_all"
DLQ = PREFIX + "_dead_letter"


class RedisStreamsEventBus:
    def __init__(self, url: str, *, maxlen: int = 1_000_000, max_attempts: int = 5, block_ms: int = 5000) -> None:
        import redis.asyncio as redis

        self._r = redis.from_url(url, decode_responses=True)
        self._subs: dict[str, tuple[Subscription, Handler]] = {}
        self.maxlen, self.max_attempts, self.block_ms = maxlen, max_attempts, block_ms
        self._consumer = f"{socket.gethostname()}-{new_id('c')[-8:]}"

    async def publish(self, event: DomainEvent) -> None:
        data = {"event": event.model_dump_json()}
        pipe = self._r.pipeline()
        pipe.xadd(PREFIX + event.type, data, maxlen=self.maxlen, approximate=True)
        pipe.xadd(ALL, data, maxlen=self.maxlen, approximate=True)
        await pipe.execute()

    def subscribe(self, event_type: str, handler: Handler, *, name: str) -> Subscription:
        sub = Subscription(id=new_id("sub"), event_type=event_type, name=name)
        self._subs[sub.id] = (sub, handler)
        return sub

    def unsubscribe(self, subscription_id: str) -> None:
        self._subs.pop(subscription_id, None)

    async def _ensure_group(self, stream: str, group: str) -> None:
        try:
            await self._r.xgroup_create(stream, group, id="$", mkstream=True)
        except Exception as exc:  # BUSYGROUP is fine
            if "BUSYGROUP" not in str(exc):
                raise

    async def _consume(self, sub: Subscription, handler: Handler) -> None:
        stream = ALL if sub.event_type == "*" else PREFIX + sub.event_type
        group = f"g:{sub.name}"
        await self._ensure_group(stream, group)
        while sub.id in self._subs:
            resp = await self._r.xreadgroup(group, self._consumer, {stream: ">"}, count=50, block=self.block_ms)
            for _, entries in resp or []:
                for msg_id, fields in entries:
                    event = DomainEvent.model_validate_json(fields["event"])
                    try:
                        await handler(event)
                        await self._r.xack(stream, group, msg_id)
                    except Exception as exc:  # noqa: BLE001
                        info = await self._r.xpending_range(stream, group, min=msg_id, max=msg_id, count=1)
                        if info and info[0]["times_delivered"] >= self.max_attempts:
                            await self._r.xadd(DLQ, {"event": fields["event"], "sub": sub.name, "error": str(exc)[:500]})
                            await self._r.xack(stream, group, msg_id)
                        log.warning("handler %s failed: %s", sub.name, exc)

    async def run(self) -> None:
        await asyncio.gather(*(self._consume(s, h) for s, h in list(self._subs.values())))

    async def dead_letters(self, count: int = 100) -> list[dict[str, str]]:
        return [json.loads(f["event"]) | {"error": f.get("error", "")} for _, f in await self._r.xrevrange(DLQ, count=count)]
