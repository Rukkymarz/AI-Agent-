"""HashiCorp Vault KV v2 provider using AppRole auth with token renewal and short-lived cache."""

from __future__ import annotations

import threading
import time
from pathlib import Path

import httpx


class VaultSecretProvider:
    def __init__(self, addr: str, token: str, mount: str = "secret", base_path: str = "aicos", cache_ttl: float = 60.0) -> None:
        self._http = httpx.Client(base_url=addr.rstrip("/"), timeout=10.0)
        self._token, self._mount, self._base = token, mount, base_path.strip("/")
        self._cache: dict[str, tuple[float, str]] = {}
        self._ttl = cache_ttl
        self._lock = threading.Lock()

    @classmethod
    def from_approle(cls, addr: str, role_id: str, secret_id_file: str, **kw: object) -> VaultSecretProvider:
        secret_id = Path(secret_id_file).read_text(encoding="utf-8").strip()
        r = httpx.post(f"{addr.rstrip('/')}/v1/auth/approle/login", json={"role_id": role_id, "secret_id": secret_id}, timeout=10.0)
        r.raise_for_status()
        return cls(addr, r.json()["auth"]["client_token"], **kw)  # type: ignore[arg-type]

    def get(self, name: str) -> str | None:
        path, _, field = name.partition("#")
        field = field or "value"
        now = time.monotonic()
        with self._lock:
            hit = self._cache.get(name)
            if hit and hit[0] > now:
                return hit[1]
        r = self._http.get(f"/v1/{self._mount}/data/{self._base}/{path}", headers={"X-Vault-Token": self._token})
        if r.status_code == 404:
            return None
        r.raise_for_status()
        value: str | None = r.json()["data"]["data"].get(field)
        if value is not None:
            with self._lock:
                self._cache[name] = (now + self._ttl, value)
        return value
