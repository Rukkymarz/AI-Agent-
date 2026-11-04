"""aicos-plugin CLI: keygen | hash | sign | validate | inspect.

aicos-plugin keygen  --out security/keys/publisher           (writes .key [0600] and .pub)
aicos-plugin hash    plugins/examples/hubspot-sync            (rewrites integrity map in plugin.yaml)
aicos-plugin sign    plugins/examples/hubspot-sync --key security/keys/publisher.key --key-id acme-2026
aicos-plugin validate plugins/examples/hubspot-sync
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aicos.plugins.manifest import PluginManifest
from aicos.plugins.signing import MANIFEST_FILE, SIG_FILE, compute_integrity, sign_manifest, verify_integrity


def _keygen(out: Path) -> None:
    key = Ed25519PrivateKey.generate()
    out.parent.mkdir(parents=True, exist_ok=True)
    priv = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    fd = os.open(f"{out}.key", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(priv)
    Path(f"{out}.pub").write_bytes(
        key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    print(f"wrote {out}.key (keep offline / in Vault) and {out}.pub (add to security/trusted-keys)")


def _hash(root: Path) -> None:
    raw = yaml.safe_load((root / MANIFEST_FILE).read_text(encoding="utf-8"))
    raw["integrity"] = compute_integrity(root)
    PluginManifest.model_validate(raw)
    (root / MANIFEST_FILE).write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    print(f"integrity map updated: {len(raw['integrity'])} files")


def _sign(root: Path, key_path: Path, key_id: str) -> None:
    manifest = PluginManifest.load(root / MANIFEST_FILE)
    verify_integrity(root, manifest)
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit("key must be Ed25519")
    (root / SIG_FILE).write_text(sign_manifest(manifest, key, key_id), encoding="utf-8")
    print(f"signed {manifest.name}@{manifest.version} with {key_id}")


def _validate(root: Path) -> None:
    m = PluginManifest.load(root / MANIFEST_FILE)
    verify_integrity(root, m)
    print(
        json.dumps(
            {
                "name": m.name,
                "version": m.version,
                "kinds": m.kinds,
                "isolation": m.isolation,
                "sensitive_capabilities": m.sensitive_capabilities(),
                "signed": (root / SIG_FILE).exists(),
                "digest": m.digest(),
            },
            indent=2,
            default=str,
        )
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="aicos-plugin")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen").add_argument("--out", type=Path, required=True)
    sub.add_parser("hash").add_argument("path", type=Path)
    sign = sub.add_parser("sign")
    sign.add_argument("path", type=Path)
    sign.add_argument("--key", type=Path, required=True)
    sign.add_argument("--key-id", required=True)
    sub.add_parser("validate").add_argument("path", type=Path)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "keygen":
            _keygen(a.out)
        elif a.cmd == "hash":
            _hash(a.path)
        elif a.cmd == "sign":
            _sign(a.path, a.key, a.key_id)
        else:
            _validate(a.path)
    except Exception as exc:  # noqa: BLE001 - CLI surface
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
