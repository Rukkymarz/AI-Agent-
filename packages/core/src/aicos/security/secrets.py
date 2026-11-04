"""Secret providers. Resolution order is explicit; values are never logged.

Production: Vault (infrastructure/vault.py) -> Docker secrets -> env (bootstrap only).
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Protocol

_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-/]{0,199}$")


def _validate(name: str) -> None:
    if not _NAME.match(name) or ".." in name:
        raise ValueError("invalid secret name")


class SecretProvider(Protocol):
    def get(self, name: str) -> str | None: ...


class EnvSecretProvider:
    def __init__(self, prefix: str = "AICOS_SECRET_") -> None:
        self.prefix = prefix

    def get(self, name: str) -> str | None:
        _validate(name)
        key = self.prefix + re.sub(r"[^A-Za-z0-9]", "_", name).upper()
        return os.environ.get(key)


class DockerSecretProvider:
    def __init__(self, directory: str | Path = "/run/secrets") -> None:
        self.directory = Path(directory)

    def get(self, name: str) -> str | None:
        _validate(name)
        path = (self.directory / name.replace("/", "_")).resolve()
        if self.directory.resolve() not in path.parents or not path.is_file():
            return None
        return path.read_text(encoding="utf-8").strip()


class ChainedSecretProvider:
    def __init__(self, *providers: SecretProvider) -> None:
        self.providers = providers

    def get(self, name: str) -> str | None:
        for p in self.providers:
            value = p.get(name)
            if value:
                return value
        return None

    def require(self, name: str) -> str:
        value = self.get(name)
        if not value:
            raise LookupError(f"secret '{name}' not configured")
        return value
