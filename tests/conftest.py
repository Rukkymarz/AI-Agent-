from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aicos.config import Settings
from aicos.container import Container, build_container
from aicos.domain.identity import Principal, PrincipalType, Role
from aicos.llm.providers import EchoProvider, Message
from aicos.memory.embeddings import HashingEmbedder

ROOT = Path(__file__).resolve().parents[1]
KEY = "k" * 48


class Script:
    """Controls what the fake LLM answers. Set .actions to make agents propose actions."""

    def __init__(self) -> None:
        self.text = "Analysis complete."
        self.actions: list[dict[str, Any]] = []
        self.recommendations: list[str] = []

    def __call__(self, model: str, messages: list[Message]) -> str:
        if not self.actions and not self.recommendations:
            return self.text
        block = json.dumps({"recommendations": self.recommendations, "actions": self.actions})
        return f"{self.text}\n```json\n{block}\n```"


@pytest.fixture
def script() -> Script:
    return Script()


@pytest.fixture
def settings() -> Settings:
    return Settings(
        env="test",
        auth_mode="dev",
        llm_provider="echo",
        embedding_provider="hashing",
        embedding_dim=256,
        audit_hmac_key=KEY,
        approval_signing_key=KEY,
        service_signing_keys={"n8n": KEY},
        plugin_dir=None,
        rate_limit_capacity=10_000,
        rate_limit_refill_per_s=1000,
    )


@pytest.fixture
def container(settings: Settings, script: Script) -> Container:
    provider = EchoProvider(responder=script)
    return build_container(settings, root=ROOT, providers={"ollama": provider}, embedder=HashingEmbedder(256))


def human(uid: str, *roles: Role, mfa: bool = True, tenant: str = "default") -> Principal:
    return Principal(id=uid, type=PrincipalType.HUMAN, roles=frozenset(roles), mfa_verified=mfa, tenant_id=tenant)


@pytest.fixture
def alice() -> Principal:  # operator who submits work
    return human("alice", Role.OPERATOR)


@pytest.fixture
def admin1() -> Principal:
    return human("admin1", Role.ADMIN)


@pytest.fixture
def admin2() -> Principal:
    return human("admin2", Role.ADMIN)


@pytest.fixture
def reviewer() -> Principal:
    return human("rita", Role.REVIEWER)
