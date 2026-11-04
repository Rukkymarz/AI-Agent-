"""Authentication: Keycloak OIDC (production) and dev tokens (development/test only).

OIDC: RS256/ES256 JWT verified against JWKS; issuer + audience + exp/nbf enforced.
Roles: realm_access.roles ∩ known Role names. MFA: `amr` contains otp/mfa/hwk/webauthn, or acr >= 2.
"""

from __future__ import annotations

import time
from typing import Any, Protocol

from aicos.domain.errors import AuthenticationError
from aicos.domain.identity import Principal, PrincipalType, Role

_ROLE_BY_NAME = {r.value.lower(): r for r in Role}
_MFA_AMR = {"otp", "mfa", "hwk", "webauthn", "totp"}


class Authenticator(Protocol):
    def authenticate(self, token: str) -> Principal: ...


def _roles(names: list[str]) -> frozenset[Role]:
    return frozenset(_ROLE_BY_NAME[n.lower()] for n in names if n.lower() in _ROLE_BY_NAME)


class DevAuthenticator:
    """Token format: dev:<user>:<Role[,Role]>:<mfa 0|1>[:<tenant>] — refused outside development/test."""

    def __init__(self, env: str) -> None:
        if env not in ("development", "test"):
            raise RuntimeError("DevAuthenticator is forbidden outside development/test")

    def authenticate(self, token: str) -> Principal:
        parts = token.split(":")
        if len(parts) not in (4, 5) or parts[0] != "dev":
            raise AuthenticationError("invalid dev token")
        _, user, roles, mfa, *tenant = parts
        if not user:
            raise AuthenticationError("invalid dev token")
        return Principal(
            id=user,
            type=PrincipalType.HUMAN,
            roles=_roles(roles.split(",")),
            mfa_verified=mfa == "1",
            tenant_id=tenant[0] if tenant else "default",
            display_name=user,
        )


class OIDCAuthenticator:  # pragma: no cover - exercised in integration tests against Keycloak
    def __init__(self, issuer: str, audience: str, jwks_url: str | None = None, leeway: int = 30) -> None:
        import jwt

        self.issuer, self.audience, self.leeway = issuer.rstrip("/"), audience, leeway
        self._jwks = jwt.PyJWKClient(jwks_url or f"{self.issuer}/protocol/openid-connect/certs", cache_keys=True, lifespan=300)

    def authenticate(self, token: str) -> Principal:
        import jwt

        try:
            key = self._jwks.get_signing_key_from_jwt(token).key
            claims: dict[str, Any] = jwt.decode(
                token,
                key,
                algorithms=["RS256", "ES256", "PS256"],
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.leeway,
                options={"require": ["exp", "iat", "iss", "sub", "aud"]},
            )
        except jwt.PyJWTError as exc:
            raise AuthenticationError(f"invalid token: {exc}") from None
        if claims.get("typ", "Bearer") != "Bearer":
            raise AuthenticationError("not an access token")
        amr = set(claims.get("amr", []) or [])
        acr = str(claims.get("acr", "0"))
        mfa = bool(amr & _MFA_AMR) or (acr.isdigit() and int(acr) >= 2)
        # Session freshness for MFA: require auth_time within 12h for elevated actions.
        if mfa and claims.get("auth_time") and time.time() - int(claims["auth_time"]) > 12 * 3600:
            mfa = False
        return Principal(
            id=claims["sub"],
            type=PrincipalType.HUMAN,
            tenant_id=claims.get("tenant", "default"),
            roles=_roles(claims.get("realm_access", {}).get("roles", [])),
            mfa_verified=mfa,
            display_name=claims.get("preferred_username"),
        )
