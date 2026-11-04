"""Shared helpers: ids, clocks, canonical serialisation, hashing."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

Clock = Callable[[], datetime]


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _default(o: Any) -> Any:
    if isinstance(o, datetime):
        return o.isoformat()
    if isinstance(o, (set, frozenset)):
        return sorted(str(x) for x in o)
    if hasattr(o, "model_dump"):
        return o.model_dump(mode="json")
    return str(o)


def canonical_json(data: Any) -> str:
    """Deterministic JSON (sorted keys, no whitespace) for hashing/signing."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=_default, ensure_ascii=False)


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()
