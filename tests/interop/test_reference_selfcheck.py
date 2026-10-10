#!/usr/bin/env python3
"""Reference client <-> reference server (docs/PROTOCOL.md Appendix A).

Usage: python tests/interop/test_reference_selfcheck.py
"""

from __future__ import annotations

import sys

from harness import (
    A2_TRANSCRIPT,
    Checks,
    free_port,
    kbp2,
    new_code,
    other_code,
    ref_client,
    ref_server,
    run_pair,
    run_tests,
)


def scenario(server_extra=(), client_extra=(), server_code=None, client_code=None):
    code = new_code()
    port = free_port()
    return run_pair(
        ref_server(port, server_code or code, *server_extra),
        ref_client(port, client_code or code, *client_extra),
    )


def test_positive():
    server, client = scenario()
    c = Checks(server, client)
    c.exit_code(client, 0)
    c.stdout_equals(client, A2_TRANSCRIPT)
    c.exit_code(server, 0)
    c.done()


def test_code_normalization():
    # Server gets the display form; client gets lowercase with O/I/L look-alikes and spaces.
    code = new_code()
    messy = " ".join(kbp2.format_code(code).lower().replace("0", "o").replace("1", "l").split("-"))
    port = free_port()
    server, client = run_pair(ref_server(port, kbp2.format_code(code)), ref_client(port, messy))
    c = Checks(server, client)
    c.exit_code(client, 0)
    c.stdout_equals(client, A2_TRANSCRIPT)
    c.exit_code(server, 0)
    c.done()


def test_wrong_code():
    code = new_code()
    server, client = scenario(server_code=code, client_code=other_code(code))
    c = Checks(server, client)
    c.exit_code(client, 2)
    c.stdout_equals(client, ["HANDSHAKE FAILED"])
    c.exit_code(server, 2)
    c.done()


def test_corrupted_client_finished():
    server, client = scenario(client_extra=["--corrupt-finished"])
    c = Checks(server, client)
    c.exit_code(client, 0)  # 0 == server closed without sending a record
    c.stdout_equals(client, ["REJECTED"])
    c.exit_code(server, 2)
    c.done()


def test_bad_magic():
    server, client = scenario(client_extra=["--bad-magic"])
    c = Checks(server, client)
    c.exit_code(client, 0)
    c.stdout_equals(client, ["REJECTED"])
    c.exit_code(server, 2)
    c.done()


def test_invalid_point():
    server, client = scenario(client_extra=["--invalid-point"])
    c = Checks(server, client)
    c.exit_code(client, 0)
    c.stdout_equals(client, ["REJECTED"])
    c.exit_code(server, 2)
    c.done()


def test_handshake_timeout():
    server, client = scenario(client_extra=["--stall"])
    c = Checks(server, client)
    c.exit_code(client, 0)
    c.stdout_equals(client, ["REJECTED"])
    c.exit_code(server, 2)
    c.require(4.0 <= server.elapsed <= 9.0, f"server should give up ~5 s after accept, took {server.elapsed:.1f} s")
    c.done()


def test_tampered_record():
    server, client = scenario(server_extra=["--tamper-record"])
    c = Checks(server, client)
    c.exit_code(client, 1)
    c.stdout_equals(client, ["HANDSHAKE OK"])
    c.exit_code(server, 3)
    c.done()


def test_replayed_record():
    server, client = scenario(server_extra=["--replay-record"])
    c = Checks(server, client)
    c.exit_code(client, 1)
    c.stdout_equals(client, ["HANDSHAKE OK", "KEY down=1 ext=0 vk=0x0041"])
    c.exit_code(server, 3)
    c.done()


def test_pairing_code_rules():
    c = Checks()
    for _ in range(200):
        code = kbp2.generate_code()
        c.require(len(code) == 20 and set(code) <= set(kbp2.ALPHABET), f"bad generated code {code!r}")
    c.require(kbp2.normalize_code("abcde-fghjk mnpqr\tstvwx") == "ABCDEFGHJKMNPQRSTVWX", "case/separators")
    c.require(kbp2.normalize_code("OIL00-11111-11111-11111") == "01100111111111111111", "O/I/L mapping")
    for bad in ["ABCDE-FGHJK-MNPQR-STVW", "ABCDE-FGHJK-MNPQR-STVWXY", "ABCDE-FGHJK-MNPQR-STVWU", ""]:
        try:
            kbp2.normalize_code(bad)
        except kbp2.InvalidCode:
            continue
        c.problems.append(f"{bad!r} should be rejected")
    c.done()


def test_kdf_is_rfc5869():
    # RFC 5869 Appendix A.1 (test case 1); Expand(prk, info) is the first 32 bytes of OKM.
    ikm = bytes([0x0B] * 22)
    salt = bytes(range(0x00, 0x0D))
    info = bytes(range(0xF0, 0xFA))
    prk = kbp2.extract(salt, ikm)
    okm = kbp2.expand(prk, info)
    c = Checks()
    c.require(prk.hex() == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", "Extract != RFC 5869 PRK")
    c.require(okm.hex() == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf", "Expand != RFC 5869 OKM")
    c.done()


TESTS = [
    ("HKDF helpers match RFC 5869 test vector", test_kdf_is_rfc5869),
    ("pairing code generation and normalization", test_pairing_code_rules),
    ("positive: exact A.2 transcript", test_positive),
    ("positive: pairing-code normalization", test_code_normalization),
    ("wrong code: HANDSHAKE FAILED", test_wrong_code),
    ("corrupted ClientFinished: silent close", test_corrupted_client_finished),
    ("bad magic: silent close", test_bad_magic),
    ("invalid P-256 point: silent close", test_invalid_point),
    ("stalled handshake: 5 s timeout", test_handshake_timeout),
    ("tampered record: client drops connection", test_tampered_record),
    ("replayed record: client drops connection", test_replayed_record),
]

if __name__ == "__main__":
    sys.exit(run_tests("KBP2 reference self-check", TESTS))
