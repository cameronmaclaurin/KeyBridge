#!/usr/bin/env python3
"""Reference client vs the Mac selftest server (docs/PROTOCOL.md Appendix A.1).

Build the selftest binary first:
    cd mac && swift build -Xswiftc -DKEYBRIDGE_SELFTEST
Then:
    python tests/interop/test_mac_server.py mac/.build/debug/KeyBridge
"""

from __future__ import annotations

import argparse
import sys

from harness import (
    A2_TRANSCRIPT,
    Checks,
    free_port,
    new_code,
    other_code,
    ref_client,
    require_binary,
    run_pair,
    run_tests,
)

BINARY = ""


def mac_server(port: int, code: str) -> list[str]:
    return [BINARY, "--selftest-server", "--port", str(port), "--code", code]


def scenario(client_extra=(), wrong_code=False):
    code = new_code()
    port = free_port()
    return run_pair(
        mac_server(port, code),
        ref_client(port, other_code(code) if wrong_code else code, *client_extra),
        server_name="mac-server",
        client_name="reference-client",
    )


def test_positive():
    server, client = scenario()
    c = Checks(server, client)
    c.exit_code(client, 0)
    c.stdout_equals(client, A2_TRANSCRIPT)
    c.exit_code(server, 0)
    c.done()


def test_wrong_code():
    server, client = scenario(wrong_code=True)
    c = Checks(server, client)
    c.exit_code(client, 2)
    c.stdout_equals(client, ["HANDSHAKE FAILED"])
    c.exit_code(server, 2)
    c.done()


def expect_silent_rejection(*client_extra: str) -> None:
    server, client = scenario(client_extra=client_extra)
    c = Checks(server, client)
    c.exit_code(client, 0)  # reference client exits 0 iff the server closed without sending anything more
    c.stdout_equals(client, ["REJECTED"])
    c.exit_code(server, 2)
    c.done()


def test_corrupted_client_finished():
    expect_silent_rejection("--corrupt-finished")


def test_bad_magic():
    expect_silent_rejection("--bad-magic")


def test_invalid_point():
    expect_silent_rejection("--invalid-point")


def test_handshake_timeout():
    expect_silent_rejection("--stall")


TESTS = [
    ("positive: exact A.2 transcript, server exit 0", test_positive),
    ("wrong code: client exit 2, server exit 2", test_wrong_code),
    ("corrupted ClientFinished: server exit 2, no records", test_corrupted_client_finished),
    ("bad magic: server exit 2, nothing sent", test_bad_magic),
    ("invalid P-256 point: server exit 2, nothing sent", test_invalid_point),
    ("stalled handshake: server times out (exit 2)", test_handshake_timeout),
]


def main() -> int:
    global BINARY
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("binary", help="path to the Mac selftest build (mac/.build/debug/KeyBridge)")
    BINARY = require_binary(parser.parse_args().binary, "Mac selftest binary")
    return run_tests(f"KBP2 interop: reference client vs {BINARY}", TESTS)


if __name__ == "__main__":
    sys.exit(main())
