"""FastAPI dependencies: container access, authentication, permission checks."""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from aicos.container import Container
from aicos.domain.errors import AuthenticationError, AuthorizationError
from aicos.domain.identity import Permission, Principal
from aicos.security.rbac import effective_permissions

_bearer = HTTPBearer(auto_error=False)


def get_container(request: Request) -> Container:
    return request.app.state.container  # type: ignore[no-any-return]


def current_principal(
    request: Request,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Principal:
    if creds is None or creds.scheme.lower() != "bearer" or not creds.credentials:
        raise AuthenticationError("missing bearer token")
    principal: Principal = request.app.state.authenticator.authenticate(creds.credentials)
    if principal.tenant_id != request.app.state.container.settings.tenant_id:
        raise AuthorizationError("token tenant does not match this deployment")
    request.state.principal_id = principal.id
    return principal


def require(*perms: Permission) -> Callable[[Principal], Principal]:
    def checker(principal: Annotated[Principal, Depends(current_principal)]) -> Principal:
        missing = set(perms) - effective_permissions(principal)
        if missing:
            raise AuthorizationError(f"missing permissions: {sorted(missing)}")
        return principal

    return checker


def require_mfa(principal: Annotated[Principal, Depends(current_principal)]) -> Principal:
    if not principal.mfa_verified:
        raise AuthenticationError("MFA required")
    return principal


ContainerDep = Annotated[Container, Depends(get_container)]
PrincipalDep = Annotated[Principal, Depends(current_principal)]
