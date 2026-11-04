"""Plugin supply-chain integrity: file hashes + Ed25519 publisher signatures.

Signed payload = canonical(manifest incl. `integrity` map). `integrity` must cover
EVERY file in the plugin directory (except plugin.sig), so code cannot change
without invalidating the signature. Signature file: plugin.sig (base64, "keyid:sig").
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict

from aicos.domain.common import canonical_json
from aicos.domain.errors import IntegrityError
from aicos.plugins.manifest import PluginManifest, TrustTier

SIG_FILE = "plugin.sig"
MANIFEST_FILE = "plugin.yaml"
_IGNORED_DIRS = {"__pycache__", ".git", ".pytest_cache"}


def compute_integrity(root: str | Path) -> dict[str, str]:
    root = Path(root)
    out: dict[str, str] = {}
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.name in {SIG_FILE, MANIFEST_FILE} or _IGNORED_DIRS & set(p.parts):
            continue
        if p.is_symlink():
            raise IntegrityError(f"symlinks are not allowed in plugins: {p}")
        out[p.relative_to(root).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def verify_integrity(root: str | Path, manifest: PluginManifest) -> None:
    actual = compute_integrity(root)
    declared = manifest.integrity
    missing = set(actual) - set(declared)
    if missing:
        raise IntegrityError(f"files not covered by integrity map: {sorted(missing)}")
    for rel, digest in declared.items():
        if actual.get(rel) != digest:
            raise IntegrityError(f"integrity mismatch: {rel}")


def _payload(manifest: PluginManifest) -> bytes:
    return canonical_json(manifest.model_dump(mode="json")).encode()


def sign_manifest(manifest: PluginManifest, key: Ed25519PrivateKey, key_id: str) -> str:
    sig = key.sign(_payload(manifest))
    return f"{key_id}:{base64.b64encode(sig).decode()}"


class TrustedKey(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    key_id: str
    public_key: Ed25519PublicKey
    tier: TrustTier
    publisher: str


class TrustStore:
    def __init__(self, keys: list[TrustedKey] | None = None) -> None:
        self._keys = {k.key_id: k for k in keys or []}

    @classmethod
    def from_directory(cls, directory: str | Path) -> TrustStore:
        """Load `<key-id>.pub` (PEM Ed25519) + `<key-id>.yaml` ({tier, publisher}) pairs."""
        store = cls()
        root = Path(directory)
        if not root.is_dir():
            return store
        for pub in sorted(root.glob("*.pub")):
            meta_path = pub.with_suffix(".yaml")
            if not meta_path.is_file():
                raise IntegrityError(f"trusted key {pub.name} has no {meta_path.name} sidecar")
            meta = yaml.safe_load(meta_path.read_text(encoding="utf-8")) or {}
            key = serialization.load_pem_public_key(pub.read_bytes())
            if not isinstance(key, Ed25519PublicKey):
                raise IntegrityError(f"{pub.name} is not an Ed25519 public key")
            store.add(TrustedKey(key_id=pub.stem, public_key=key, tier=TrustTier(meta["tier"]), publisher=str(meta["publisher"])))
        return store

    def add(self, key: TrustedKey) -> None:
        if key.tier is TrustTier.COMMUNITY:
            raise ValueError("community tier is the absence of trust; do not register keys for it")
        self._keys[key.key_id] = key

    def resolve_tier(self, manifest: PluginManifest, signature: str | None) -> TrustTier:
        """Return trust tier. Raises if a signature is present but invalid (tampering)."""
        if not signature:
            return TrustTier.COMMUNITY
        try:
            key_id, b64 = signature.strip().split(":", 1)
            raw = base64.b64decode(b64, validate=True)
        except ValueError:
            raise IntegrityError("malformed plugin signature") from None
        key = self._keys.get(key_id)
        if key is None:
            return TrustTier.COMMUNITY  # unknown signer == untrusted, but not tampered
        try:
            key.public_key.verify(raw, _payload(manifest))
        except InvalidSignature:
            raise IntegrityError("plugin signature verification failed") from None
        if key.tier is TrustTier.VERIFIED and key.publisher != manifest.publisher:
            raise IntegrityError("signing key not authorised for this publisher")
        return key.tier
