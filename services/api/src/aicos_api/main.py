"""Application factory. `uvicorn aicos_api.main:app` (production) or create_app(container) in tests."""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from aicos import __version__
from aicos.container import Container, build_container
from aicos.domain import errors as E
from aicos_api.auth import Authenticator, DevAuthenticator, OIDCAuthenticator
from aicos_api.middleware import HardeningMiddleware
from aicos_api.routers import health, router

log = logging.getLogger("aicos.api")

_STATUS: list[tuple[type[E.AicosError], int]] = [
    (E.AuthenticationError, 401),
    (E.PolicyViolation, 403),
    (E.AuthorizationError, 403),
    (E.SecurityViolation, 400),
    (E.NotFound, 404),
    (E.ApprovalRequired, 202),
    (E.ApprovalError, 409),
    (E.IntegrityError, 409),
    (E.PluginError, 409),
    (E.RateLimited, 429),
    (E.ValidationFailed, 422),
]


def _authenticator(c: Container) -> Authenticator:
    s = c.settings
    if s.auth_mode == "dev":
        return DevAuthenticator(s.env)
    return OIDCAuthenticator(s.oidc_issuer, s.oidc_audience, s.oidc_jwks_url)  # pragma: no cover


def create_app(container: Container | None = None, authenticator: Authenticator | None = None) -> FastAPI:
    c = container or build_container()
    prod = c.settings.env == "production"
    app = FastAPI(
        title="AICOMPANY-OS API",
        version=__version__,
        docs_url=None if prod else "/docs",
        redoc_url=None,
        openapi_url=None if prod else "/openapi.json",
    )
    app.state.container = c
    app.state.authenticator = authenticator or _authenticator(c)

    @app.exception_handler(E.AicosError)
    async def _domain_error(request: Request, exc: E.AicosError) -> JSONResponse:
        status = next((code for cls, code in _STATUS if isinstance(exc, cls)), 400)
        if status >= 401:
            log.info("request denied: %s %s -> %s (%s)", request.method, request.url.path, status, exc.code)
        return JSONResponse({"error": exc.code, "detail": str(exc)}, status_code=status)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        # never echo raw input back (may contain secrets / injection payloads)
        return JSONResponse(
            {"error": "validation_failed", "detail": [{"loc": e["loc"], "msg": e["msg"]} for e in exc.errors()]}, status_code=422
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:  # pragma: no cover
        log.exception("unhandled error")
        return JSONResponse({"error": "internal_error", "detail": "internal error"}, status_code=500)

    if c.settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=c.settings.cors_origins,
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type", "X-Request-Id"],
            allow_credentials=False,
        )
    app.add_middleware(HardeningMiddleware, limiter=c.rate_limiter, max_body=c.settings.max_body_bytes, verifier=c.request_verifier)
    app.include_router(health)
    app.include_router(router)
    return app


def __getattr__(name: str) -> FastAPI:  # lazy module-level `app` for uvicorn
    if name == "app":
        return create_app()
    raise AttributeError(name)
