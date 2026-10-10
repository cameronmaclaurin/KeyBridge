#!/usr/bin/env python3
"""Update-manifest verification conformance (docs/UPDATES.md §6).

    python tests/interop/test_update_verify.py <selftest-binary> --platform mac|windows

Signs manifests with a throwaway key (passed to the binary via --pubkey) and checks the
binary accepts exactly the valid ones and rejects every tampered or malformed variant.
"""
from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

import update_manifest as um  # noqa: E402

PREFIX = um.URL_PREFIX


def manifest(version="1.4.0", *, first="keybridge-update-manifest 1", drop=None, extra=(),
             mac_url=None, win_url=None, dup=None) -> bytes:
    tag = f"v{version}"
    fields = [
        ("version", version),
        ("notes-url", f"https://github.com/{um.REPO}/releases/tag/{tag}"),
        ("mac-url", mac_url or f"{PREFIX}{tag}/KeyBridge-macOS.pkg"),
        ("mac-sha256", hashlib.sha256(b"mac").hexdigest()),
        ("mac-size", "1395828"),
        ("windows-url", win_url or f"{PREFIX}{tag}/KeyBridge-Windows-Setup.exe"),
        ("windows-sha256", hashlib.sha256(b"win").hexdigest()),
        ("windows-size", "2391411"),
    ]
    lines = [first] + [f"{k} {v}" for k, v in fields if k != drop]
    if dup:
        lines += [f"{k} {v}" for k, v in fields if k == dup]
    lines += list(extra)
    return ("\n".join(lines) + "\n").encode()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--platform", choices=["mac", "windows"], required=True)
    a = ap.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="kb-update-test-"))
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.X962,
                                        serialization.PublicFormat.UncompressedPoint).hex()
    other = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

    plat_url = {"mac": f"{PREFIX}v1.4.0/KeyBridge-macOS.pkg",
                "windows": f"{PREFIX}v1.4.0/KeyBridge-Windows-Setup.exe"}[a.platform]
    plat_sha = hashlib.sha256(b"mac" if a.platform == "mac" else b"win").hexdigest()
    plat_size = "1395828" if a.platform == "mac" else "2391411"

    def tamper(m: bytes) -> bytes:
        i = m.index(b"version 1.4.0") + len("version 1.")
        return m[:i] + b"5" + m[i + 1:]

    valid = manifest()
    cases = [
        # (name, manifest bytes, signature bytes, --current, use test pubkey, expected stdout, exit)
        ("valid newer", valid, um.sign(valid, pem), "1.3.0", True,
         f"UPDATE 1.4.0 {plat_url} {plat_sha} {plat_size}", 0),
        ("valid same version", valid, um.sign(valid, pem), "1.4.0", True, "CURRENT", 0),
        ("valid older (no downgrade)", valid, um.sign(valid, pem), "2.0.0", True, "CURRENT", 0),
        ("numeric compare 1.10.0 > 1.9.0", manifest("1.10.0"), um.sign(manifest("1.10.0"), pem), "1.9.0", True,
         f"UPDATE 1.10.0 {plat_url.replace('v1.4.0', 'v1.10.0')} {plat_sha} {plat_size}", 0),
        ("byte changed after signing", tamper(valid), um.sign(valid, pem), "1.3.0", True, "INVALID", 2),
        ("signed by a different key", valid, um.sign(valid, other), "1.3.0", True, "INVALID", 2),
        ("embedded key rejects test-key signature", valid, um.sign(valid, pem), "1.3.0", False, "INVALID", 2),
        ("bad URL prefix", manifest(mac_url="https://evil.example/KeyBridge-macOS.pkg",
                                    win_url="https://evil.example/KeyBridge-Windows-Setup.exe"),
         None, "1.3.0", True, "INVALID", 2),
        ("lookalike URL host", manifest(mac_url="https://github.com.evil.example/x.pkg",
                                        win_url="https://github.com.evil.example/x.exe"),
         None, "1.3.0", True, "INVALID", 2),
        ("malformed version", manifest("1.04.0"), None, "1.3.0", True, "INVALID", 2),
        ("missing key", manifest(drop="windows-sha256" if a.platform == "windows" else "mac-sha256"),
         None, "1.3.0", True, "INVALID", 2),
        ("duplicate key", manifest(dup="version"), None, "1.3.0", True, "INVALID", 2),
        ("wrong first line", manifest(first="keybridge-update-manifest 2"), None, "1.3.0", True, "INVALID", 2),
        ("unknown keys ignored", manifest(extra=["future-key something"]), None, "1.3.0", True,
         f"UPDATE 1.4.0 {plat_url} {plat_sha} {plat_size}", 0),
        ("garbage signature", valid, b"not base64!!\n", "1.3.0", True, "INVALID", 2),
        ("short signature", valid, b"AAAA\n", "1.3.0", True, "INVALID", 2),
    ]

    failures = 0
    for name, m, sig, current, use_test_key, want_out, want_code in cases:
        if sig is None:
            sig = um.sign(m, pem)
        mf, sf = tmp / "m.txt", tmp / "m.sig"
        mf.write_bytes(m)
        sf.write_bytes(sig)
        cmd = [a.binary, "--selftest-verify-update", str(mf), str(sf), "--current", current]
        if use_test_key:
            cmd += ["--pubkey", pub]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            out, code = r.stdout.strip(), r.returncode
        except subprocess.TimeoutExpired:
            out, code = "<timeout>", -1
        ok = out == want_out and code == want_code
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else
              f"\n      want: {want_out!r} exit {want_code}\n      got:  {out!r} exit {code}"
              f"\n      stderr: {r.stderr.strip()[:300] if code != -1 else ''}"))
    print(f"== {len(cases) - failures}/{len(cases)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
