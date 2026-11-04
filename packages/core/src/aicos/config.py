"""Typed settings (env prefix AICOS_). Production refuses insecure configurations at boot."""

from __future__ import annotations

import logging
import os
import secrets
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

log = logging.getLogger(__name__)


class Settings(BaseSettings):
    # Docker secrets: file /run/secrets/aicos_<field> when AICOS_SECRETS_DIR=/run/secrets
    model_config = SettingsConfigDict(env_prefix="AICOS_", env_file=".env", extra="ignore", secrets_dir=os.environ.get("AICOS_SECRETS_DIR"))

    env: Literal["development", "test", "staging", "production"] = "development"
    tenant_id: str = "default"

    # authn
    auth_mode: Literal["oidc", "dev"] = "oidc"
    oidc_issuer: str = "http://keycloak:8080/realms/aicompany"
    oidc_audience: str = "aicos-api"
    oidc_jwks_url: str | None = None
    require_mfa: bool = True

    # keys (>= 32 bytes). Load from Vault/Docker secrets in production.
    audit_hmac_key: SecretStr | None = None
    approval_signing_key: SecretStr | None = None
    service_signing_keys: dict[str, SecretStr] = Field(default_factory=dict)  # key_id -> key

    # posture flags (reported by compliance engine)
    tls_enabled: bool = False
    encryption_at_rest: bool = False
    data_retention_days: int | None = 365

    # infrastructure
    database_url: SecretStr | None = None
    redis_url: str | None = None
    ollama_url: str = "http://ollama:11434"
    vault_addr: str | None = None
    vault_role_id: str | None = None
    vault_secret_id_file: str = "/run/secrets/vault_secret_id"  # noqa: S105 - file path

    # ai
    llm_provider: Literal["ollama", "echo"] = "ollama"
    embedding_provider: Literal["ollama", "hashing"] = "ollama"
    embedding_model: str = "bge-m3"
    embedding_dim: int = 1024
    models_file: str | None = "models/registry.yaml"

    # paths
    agent_catalog_dir: str = "agents/catalog"
    policy_file: str | None = "security/policies/default.yaml"
    plugin_dir: str | None = "plugins/installed"
    trusted_keys_dir: str | None = "security/trusted-keys"

    # api hardening
    rate_limit_capacity: float = 60
    rate_limit_refill_per_s: float = 1.0
    max_body_bytes: int = 30_000_000
    cors_origins: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _production_guardrails(self) -> Settings:
        if self.env in ("production", "staging"):
            problems = []
            if self.auth_mode != "oidc":
                problems.append("auth_mode must be 'oidc'")
            if not self.audit_hmac_key or not self.approval_signing_key:
                problems.append("audit_hmac_key and approval_signing_key are required")
            if self.env == "production" and not self.tls_enabled:
                problems.append("tls_enabled must be true")
            if self.llm_provider == "echo" or self.embedding_provider == "hashing":
                problems.append("echo/hashing providers are for development only")
            if problems:
                raise ValueError("insecure configuration: " + "; ".join(problems))
        for k in (self.audit_hmac_key, self.approval_signing_key, *self.service_signing_keys.values()):
            if k is not None and len(k.get_secret_value().encode()) < 32:
                raise ValueError("all keys must be >= 32 bytes")
        return self

    def key(self, name: Literal["audit_hmac_key", "approval_signing_key"]) -> bytes:
        value: SecretStr | None = getattr(self, name)
        if value is None:
            log.warning("%s not set; generating an ephemeral key (development only)", name)
            value = SecretStr(secrets.token_urlsafe(48))
            setattr(self, name, value)
        return value.get_secret_value().encode()
