"""HMAC request signing for service-to-service calls (n8n -> API, worker -> API).

Signature = HMAC-SHA256(key, METHOD \n PATH \n TIMESTAMP \n NONCE \n SHA256(body))
Headers: X-AICOS-Key-Id, X-AICOS-Timestamp, X-AICOS-Nonce, X-AICOS-Signature
Replay protection: bounded clock skew + nonce cache (use Redis SETNX in multi-replica deployments).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from typing import Protocol

from aicos.domain.errors import AuthenticationError


class NonceCache(Protocol):
    def add_if_absent(self, nonce: str, ttl_seconds: int) -> bool: ...


class InMemoryNonceCache:
    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()
        self._clock = clock

    def add_if_absent(self, nonce: str, ttl_seconds: int) -> bool:
        now = self._clock()
        with self._lock:
            for k in [k for k, exp in self._seen.items() if exp < now]:
                del self._seen[k]
            if nonce in self._seen:
                return False
            self._seen[nonce] = now + ttl_seconds
            return True


def _string_to_sign(method: str, path: str, ts: str, nonce: str, body: bytes) -> bytes:
    return "\n".join([method.upper(), path, ts, nonce, hashlib.sha256(body).hexdigest()]).encode()


class RequestSigner:
    def __init__(self, key_id: str, key: bytes, clock: Callable[[], float] = time.time) -> None:
        if len(key) < 32:
            raise ValueError("signing key must be >= 32 bytes")
        self.key_id, self._key, self._clock = key_id, key, clock

    def sign(self, method: str, path: str, body: bytes = b"") -> dict[str, str]:
        ts, nonce = str(int(self._clock())), secrets.token_hex(16)
        sig = hmac.new(self._key, _string_to_sign(method, path, ts, nonce, body), hashlib.sha256).hexdigest()
        return {
            "X-AICOS-Key-Id": self.key_id,
            "X-AICOS-Timestamp": ts,
            "X-AICOS-Nonce": nonce,
            "X-AICOS-Signature": sig,
        }


class RequestVerifier:
    def __init__(
        self,
        keys: Mapping[str, bytes],
        nonce_cache: NonceCache | None = None,
        *,
        max_skew_seconds: int = 300,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._keys = dict(keys)
        self._nonces = nonce_cache or InMemoryNonceCache(clock)
        self._skew = max_skew_seconds
        self._clock = clock

    def verify(self, method: str, path: str, body: bytes, headers: Mapping[str, str]) -> str:
        h = {k.lower(): v for k, v in headers.items()}
        try:
            key_id = h["x-aicos-key-id"]
            ts = h["x-aicos-timestamp"]
            nonce = h["x-aicos-nonce"]
            sig = h["x-aicos-signature"]
        except KeyError as exc:
            raise AuthenticationError(f"missing signature header: {exc.args[0]}") from None
        key = self._keys.get(key_id)
        if key is None:
            raise AuthenticationError("unknown key id")
        try:
            ts_int = int(ts)
        except ValueError:
            raise AuthenticationError("bad timestamp") from None
        if abs(self._clock() - ts_int) > self._skew:
            raise AuthenticationError("timestamp outside allowed skew")
        expected = hmac.new(key, _string_to_sign(method, path, ts, nonce, body), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            raise AuthenticationError("bad signature")
        if not self._nonces.add_if_absent(f"{key_id}:{nonce}", self._skew * 2):
            raise AuthenticationError("replayed request")
        return key_id
