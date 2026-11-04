"""Token-bucket rate limiting. In-memory for single node; Redis adapter for clusters."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol


class RateLimiter(Protocol):
    def allow(self, key: str, cost: float = 1.0) -> bool: ...


@dataclass
class _Bucket:
    tokens: float
    updated: float


class TokenBucketLimiter:
    def __init__(
        self,
        capacity: float,
        refill_per_second: float,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = 100_000,
    ) -> None:
        if capacity <= 0 or refill_per_second <= 0:
            raise ValueError("capacity and refill must be positive")
        self.capacity, self.refill = capacity, refill_per_second
        self._clock, self._max_keys = clock, max_keys
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, cost: float = 1.0) -> bool:
        now = self._clock()
        with self._lock:
            b = self._buckets.get(key)
            if b is None:
                if len(self._buckets) >= self._max_keys:  # bound memory under key-flooding
                    self._buckets.clear()
                b = self._buckets[key] = _Bucket(self.capacity, now)
            b.tokens = min(self.capacity, b.tokens + (now - b.updated) * self.refill)
            b.updated = now
            if b.tokens >= cost:
                b.tokens -= cost
                return True
            return False
