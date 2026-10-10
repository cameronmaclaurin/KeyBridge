#!/usr/bin/env python3
"""Reference server vs the Windows selftest client (docs/PROTOCOL.md Appendix A.2).

Build the selftest client first (Developer Command Prompt / vcvars64 loaded):
    windows\\build.bat 0.0.0 selftest
Then:
    python tests\\interop\\test_windows_client.py windows\\build\\KeyBridge-selftest.exe
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
    ref_server,
    require_binary,
    run_pair,
    run_tests,
)

EXE = ""


def windows_client(port: int, code: str) -> list[str]:
    return [EXE, "--selftest-client", "--host", "127.0.0.1", "--port", str(port), "--code", code]


def scenario(server_extra=(), wrong_code=False):
    code = new_code()
    port = free_port()
    return run_pair(
        ref_server(port, code, *server_extra),
        windows_client(port, other_code(code) if wrong_code else code),
        server_name="reference-server",
        client_name="windows-client",
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
    c.exit_code(server, 2)  # the client must not send ClientFinished
    c.done()


# The spec requires the client to drop the connection on any record
# authentication failure (section 5) but does not fix the selftest's exit code
# or final line in that case, so these two checks only look at what was accepted.


def test_tampered_record():
    server, client = scenario(server_extra=["--tamper-record"])
    c = Checks(server, client)
    c.terminated(client)
    lines = [line.rstrip() for line in client.stdout]
    c.require(lines[:1] == ["HANDSHAKE OK"], "windows-client: first line should be HANDSHAKE OK")
    c.require(
        not any(line.startswith(("KEY", "PING", "RELEASE_ALL")) for line in lines),
        "windows-client: accepted a record after a tampered one (it must close the connection)",
    )
    c.exit_code(server, 3)  # no PONG: the client hung up at the bad record
    c.done()


def test_replayed_record():
    server, client = scenario(server_extra=["--replay-record"])
    c = Checks(server, client)
    c.terminated(client)
    lines = [line.rstrip() for line in client.stdout]
    accepted = [line for line in lines if line.startswith(("KEY", "PING", "RELEASE_ALL"))]
    c.require(lines[:1] == ["HANDSHAKE OK"], "windows-client: first line should be HANDSHAKE OK")
    c.require(
        accepted == ["KEY down=1 ext=0 vk=0x0041"],
        f"windows-client: expected only the first KEY before the replay was detected, got {accepted}",
    )
    c.exit_code(server, 3)
    c.done()


TESTS = [
    ("positive: exe prints exactly the A.2 transcript, both exit 0", test_positive),
    ("wrong code: exe exit 2, reference server exit 2", test_wrong_code),
    ("tampered record: exe drops the connection", test_tampered_record),
    ("replayed record: exe drops the connection", test_replayed_record),
]


def main() -> int:
    global EXE
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("exe", help="path to windows\\build\\KeyBridge-selftest.exe")
    EXE = require_binary(parser.parse_args().exe, "Windows selftest client")
    return run_tests(f"KBP2 interop: {EXE} vs reference server", TESTS)


if __name__ == "__main__":
    sys.exit(main())
