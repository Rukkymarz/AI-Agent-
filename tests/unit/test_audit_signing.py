from __future__ import annotations

from pathlib import Path

import pytest

from aicos.domain.errors import AuthenticationError
from aicos.security.audit import AuditLog, InMemoryAuditStore, Outcome
from aicos.security.ratelimit import TokenBucketLimiter
from aicos.security.secrets import ChainedSecretProvider, DockerSecretProvider, EnvSecretProvider
from aicos.security.signing import InMemoryNonceCache, RequestSigner, RequestVerifier

KEY = b"x" * 32


def _log() -> tuple[AuditLog, InMemoryAuditStore]:
    store = InMemoryAuditStore()
    log = AuditLog(store, KEY)
    for i in range(5):
        log.record(tenant_id="default", actor_id=f"u{i}", actor_type="human", action="a.b", outcome=Outcome.SUCCESS, details={"i": i})
    return log, store


def test_audit_chain_valid() -> None:
    log, _ = _log()
    v = log.verify()
    assert v.valid and v.records_checked == 5 and v.head_hash != "0" * 64


def test_audit_detects_modification() -> None:
    log, store = _log()
    store._records[2].details = {"i": 999}
    v = log.verify()
    assert not v.valid and v.first_invalid_seq == 3 and v.reason == "hash_mismatch"


def test_audit_detects_deletion_and_reorder() -> None:
    log, store = _log()
    del store._records[1]
    assert log.verify().reason == "sequence_gap"
    log2, store2 = _log()
    store2._records[1], store2._records[2] = store2._records[2], store2._records[1]
    assert not log2.verify().valid


def test_audit_detects_rehash_with_wrong_key() -> None:
    _, store = _log()
    forged = AuditLog(store, b"y" * 32)
    assert not forged.verify().valid


def test_audit_key_length_enforced() -> None:
    with pytest.raises(ValueError):
        AuditLog(InMemoryAuditStore(), b"short")


def test_audit_query_tenant_filter() -> None:
    log, _ = _log()
    log.record(tenant_id="t2", actor_id="z", actor_type="human", action="a.b", outcome=Outcome.DENIED)
    assert len(log.query(tenant_id="t2")) == 1
    assert len(log.query(limit=2)) == 2


class Clock:
    def __init__(self) -> None:
        self.t = 1_700_000_000.0

    def __call__(self) -> float:
        return self.t


def test_signing_roundtrip_and_replay() -> None:
    clock = Clock()
    signer = RequestSigner("n8n", KEY, clock=clock)
    verifier = RequestVerifier({"n8n": KEY}, InMemoryNonceCache(clock), clock=clock)
    h = signer.sign("POST", "/v1/integrations/events", b'{"a":1}')
    assert verifier.verify("POST", "/v1/integrations/events", b'{"a":1}', h) == "n8n"
    with pytest.raises(AuthenticationError, match="replayed"):
        verifier.verify("POST", "/v1/integrations/events", b'{"a":1}', h)


@pytest.mark.parametrize("mutate", ["body", "path", "skew", "key", "missing", "bad_ts"])
def test_signing_rejections(mutate: str) -> None:
    clock = Clock()
    h = RequestSigner("n8n", KEY, clock=clock).sign("POST", "/p", b"body")
    verifier = RequestVerifier({"n8n": KEY}, clock=clock)
    body, path = b"body", "/p"
    if mutate == "body":
        body = b"tampered"
    elif mutate == "path":
        path = "/other"
    elif mutate == "skew":
        clock.t += 10_000
    elif mutate == "key":
        h["X-AICOS-Key-Id"] = "unknown"
    elif mutate == "missing":
        del h["X-AICOS-Signature"]
    elif mutate == "bad_ts":
        h["X-AICOS-Timestamp"] = "abc"
    with pytest.raises(AuthenticationError):
        verifier.verify("POST", path, body, h)


def test_signer_key_length() -> None:
    with pytest.raises(ValueError):
        RequestSigner("k", b"short")


def test_nonce_cache_expiry() -> None:
    clock = Clock()
    cache = InMemoryNonceCache(clock)
    assert cache.add_if_absent("n", 10)
    assert not cache.add_if_absent("n", 10)
    clock.t += 11
    assert cache.add_if_absent("n", 10)


def test_token_bucket() -> None:
    clock = Clock()
    rl = TokenBucketLimiter(capacity=2, refill_per_second=1, clock=clock, max_keys=2)
    assert rl.allow("a") and rl.allow("a") and not rl.allow("a")
    clock.t += 1
    assert rl.allow("a")
    rl.allow("b")
    assert rl.allow("c")  # exceeds max_keys -> buckets reset, still bounded
    with pytest.raises(ValueError):
        TokenBucketLimiter(0, 1)


def test_secret_providers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "db_password").write_text("s3cret\n")
    monkeypatch.setenv("AICOS_SECRET_API_TOKEN", "tok")
    chain = ChainedSecretProvider(DockerSecretProvider(tmp_path), EnvSecretProvider())
    assert chain.get("db_password") == "s3cret"
    assert chain.get("api_token") == "tok"
    assert chain.get("nope") is None
    with pytest.raises(LookupError):
        chain.require("nope")
    with pytest.raises(ValueError):
        chain.get("../etc/passwd")
