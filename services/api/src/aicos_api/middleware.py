"""ASGI hardening middleware: request ids, security headers, body limits, rate limiting, HMAC signatures."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from aicos.domain.errors import AuthenticationError
from aicos.security.ratelimit import RateLimiter
from aicos.security.signing import RequestVerifier

SECURITY_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cache-control", b"no-store"),
    (b"strict-transport-security", b"max-age=63072000; includeSubDomains"),
]
_RID = re.compile(r"^[A-Za-z0-9_-]{8,64}$")


async def _reject(send: Send, status: int, code: str, detail: str, extra: list[tuple[bytes, bytes]] | None = None) -> None:
    body = json.dumps({"error": code, "detail": detail}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                *SECURITY_HEADERS,
                *(extra or []),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class HardeningMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        limiter: RateLimiter,
        max_body: int,
        verifier: RequestVerifier | None = None,
        signed_prefixes: tuple[str, ...] = ("/v1/integrations/",),
        exempt: tuple[str, ...] = ("/healthz", "/readyz"),
    ) -> None:
        self.app, self.limiter, self.max_body = app, limiter, max_body
        self.verifier, self.signed_prefixes, self.exempt = verifier, signed_prefixes, exempt

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        rid = headers.get("x-request-id", "")
        rid = rid if _RID.match(rid) else uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = rid
        path: str = scope["path"]

        # rate limit key: hashed credential if present, else client IP
        auth = headers.get("authorization", "")
        client = (scope.get("client") or ("unknown", 0))[0]
        key = "tok:" + hashlib.sha256(auth.encode()).hexdigest()[:32] if auth else f"ip:{client}"
        if path not in self.exempt and not self.limiter.allow(key):
            await _reject(send, 429, "rate_limited", "too many requests", [(b"retry-after", b"1")])
            return

        declared = headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > self.max_body:
            await _reject(send, 413, "payload_too_large", "request body too large")
            return

        # buffer body (bounded) so signature verification can see it
        chunks: list[bytes] = []
        size = 0
        more = True
        while more:
            msg = await receive()
            if msg["type"] == "http.disconnect":
                return
            body = msg.get("body", b"")
            size += len(body)
            if size > self.max_body:
                await _reject(send, 413, "payload_too_large", "request body too large")
                return
            chunks.append(body)
            more = msg.get("more_body", False)
        raw = b"".join(chunks)

        if path.startswith(self.signed_prefixes):
            if self.verifier is None:
                await _reject(send, 503, "signing_not_configured", "service signing keys not configured")
                return
            try:
                scope["state"]["service_key_id"] = self.verifier.verify(scope["method"], path, raw, headers)
            except AuthenticationError as exc:
                await _reject(send, 401, "bad_signature", str(exc))
                return

        sent = False

        async def replay() -> Message:
            nonlocal sent
            if sent:
                return {"type": "http.disconnect"}
            sent = True
            return {"type": "http.request", "body": raw, "more_body": False}

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                hdrs: list[Any] = list(message.get("headers", []))
                present = {h[0].lower() for h in hdrs}
                hdrs += [h for h in SECURITY_HEADERS if h[0] not in present]
                hdrs.append((b"x-request-id", rid.encode()))
                message["headers"] = hdrs
            await send(message)

        await self.app(scope, replay, send_with_headers)
