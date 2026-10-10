#!/usr/bin/env python3
"""Create, sign and verify KeyBridge update manifests (docs/UPDATES.md).

  generate --version 1.4.0 --mac dist/KeyBridge-macOS.pkg --windows dist/KeyBridge-Windows-Setup.exe --out update-manifest.txt
  sign     --in update-manifest.txt --out update-manifest.sig      (key PEM from $KEYBRIDGE_UPDATE_SIGNING_KEY or --key FILE)
  verify   --in update-manifest.txt --sig update-manifest.sig [--pubkey HEX]   (default: tools/update_pubkey.txt)
  keygen   --key-out test.pem --pub-out test.pub                   (throwaway keys for tests)
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
import re
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

REPO = "cameronmaclaurin/KeyBridge"
URL_PREFIX = f"https://github.com/{REPO}/releases/download/"
PUBKEY_FILE = Path(__file__).with_name("update_pubkey.txt")
VERSION_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


def build_manifest(version: str, mac: Path, windows: Path) -> bytes:
    if not VERSION_RE.match(version):
        raise SystemExit(f"bad version {version!r}")
    tag = f"v{version}"

    def entry(prefix: str, path: Path) -> list[str]:
        data = path.read_bytes()
        return [f"{prefix}-url {URL_PREFIX}{tag}/{path.name}",
                f"{prefix}-sha256 {hashlib.sha256(data).hexdigest()}",
                f"{prefix}-size {len(data)}"]

    lines = ["keybridge-update-manifest 1", f"version {version}",
             f"notes-url https://github.com/{REPO}/releases/tag/{tag}",
             *entry("mac", mac), *entry("windows", windows)]
    return ("\n".join(lines) + "\n").encode()


def sign(manifest: bytes, key_pem: bytes) -> bytes:
    key = serialization.load_pem_private_key(key_pem, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
        raise SystemExit("signing key must be an ECDSA P-256 private key")
    r, s = decode_dss_signature(key.sign(manifest, ec.ECDSA(hashes.SHA256())))
    return base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")) + b"\n"


def verify(manifest: bytes, sig_b64: bytes, pub_hex: str) -> bool:
    try:
        raw = base64.b64decode(sig_b64.strip(), validate=True)
    except ValueError:
        return False
    if len(raw) != 64:
        return False
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(pub_hex))
    der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    try:
        pub.verify(der, manifest, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate")
    g.add_argument("--version", required=True)
    g.add_argument("--mac", type=Path, required=True)
    g.add_argument("--windows", type=Path, required=True)
    g.add_argument("--out", type=Path, required=True)
    s = sub.add_parser("sign")
    s.add_argument("--in", dest="inp", type=Path, required=True)
    s.add_argument("--out", type=Path, required=True)
    s.add_argument("--key", type=Path)
    v = sub.add_parser("verify")
    v.add_argument("--in", dest="inp", type=Path, required=True)
    v.add_argument("--sig", type=Path, required=True)
    v.add_argument("--pubkey")
    k = sub.add_parser("keygen")
    k.add_argument("--key-out", type=Path, required=True)
    k.add_argument("--pub-out", type=Path, required=True)
    a = p.parse_args()

    if a.cmd == "generate":
        a.out.write_bytes(build_manifest(a.version, a.mac, a.windows))
    elif a.cmd == "sign":
        pem = a.key.read_bytes() if a.key else os.environ.get("KEYBRIDGE_UPDATE_SIGNING_KEY", "").encode()
        if not pem.strip():
            raise SystemExit("no signing key: set KEYBRIDGE_UPDATE_SIGNING_KEY or pass --key")
        a.out.write_bytes(sign(a.inp.read_bytes(), pem))
    elif a.cmd == "verify":
        pub = a.pubkey or PUBKEY_FILE.read_text().strip()
        ok = verify(a.inp.read_bytes(), a.sig.read_bytes(), pub)
        print("OK" if ok else "BAD SIGNATURE")
        return 0 if ok else 1
    elif a.cmd == "keygen":
        key = ec.generate_private_key(ec.SECP256R1())
        a.key_out.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption()))
        a.pub_out.write_text(key.public_key().public_bytes(serialization.Encoding.X962,
                                                           serialization.PublicFormat.UncompressedPoint).hex() + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
