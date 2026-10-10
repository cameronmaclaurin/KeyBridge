#!/usr/bin/env python3
"""Bonjour discovery: the Windows selftest build must find a Mac advertised over mDNS
(docs/PROTOCOL.md section 1a and Appendix A.5).

python-zeroconf advertises a `_keybridge._tcp` instance the way the Mac app does
(TXT v=2) under a random test name and port, then this runs
    KeyBridge-selftest.exe --selftest-discover --timeout 8
and expects the line
    FOUND name=<test name> host=<test host> port=<test port>

Exit 3 (DNS-SD APIs unavailable) is a failure: every supported Windows has them.
mDNS can be flaky on CI runners, so a run that finds nothing is retried once.
If a second, independent python-zeroconf instance cannot see the advertisement
either, this host has no working multicast loopback: the test is reported as
SKIPPED (with a GitHub warning annotation), because no result would mean anything.

Usage:
    python -m pip install -r tests/requirements.txt
    python tests\\interop\\test_windows_discovery.py windows\\build\\KeyBridge-selftest.exe
"""

from __future__ import annotations

import argparse
import re
import secrets
import socket
import sys

from harness import Checks, Proc, TestFailure, TestSkipped, free_port, require_binary, run_tests

try:
    from zeroconf import IPVersion, ServiceInfo, Zeroconf
except ImportError:  # pragma: no cover
    sys.exit("test_windows_discovery.py needs python-zeroconf: python -m pip install -r tests/requirements.txt")

SERVICE_TYPE = "_keybridge._tcp.local."  # spec 1a
DISCOVER_TIMEOUT = 8  # seconds, passed to --selftest-discover
ATTEMPTS = 2  # one retry
FOUND_LINE = re.compile(r"FOUND name=(?P<name>.*) host=(?P<host>\S+) port=(?P<port>\d+)")

EXE = ""


def primary_ipv4() -> str:
    """The address of the interface with the default route (no packet is sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))  # TEST-NET-1; connect() on UDP only picks a route
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def same_host(a: str, b: str) -> bool:
    return a.rstrip(".").lower() == b.rstrip(".").lower()


class Advertisement:
    """A `_keybridge._tcp` instance like the Mac's: random name, host and port, TXT v=2."""

    def __init__(self) -> None:
        token = secrets.token_hex(3)
        # A space and an apostrophe, like real Mac names ("Cameron's MacBook Air").
        self.name = f"KeyBridge CI's Mac {token}"
        self.host = f"keybridge-ci-{token}.local."
        self.port = free_port()
        self.address = primary_ipv4()
        self.info = ServiceInfo(
            SERVICE_TYPE,
            f"{self.name}.{SERVICE_TYPE}",
            port=self.port,
            properties={"v": "2"},
            server=self.host,
            parsed_addresses=[self.address],
        )
        self.zc = Zeroconf(ip_version=IPVersion.V4Only)
        self.zc.register_service(self.info, allow_name_change=False)
        print(f"      advertising {self.name!r} host={self.host} port={self.port} address={self.address}", flush=True)

    def visible_to_another_responder(self) -> bool:
        """Can a separate mDNS stack on this host resolve it? (multicast loopback works)"""
        other = Zeroconf(ip_version=IPVersion.V4Only)
        try:
            info = other.get_service_info(SERVICE_TYPE, self.info.name, timeout=4000)
            return info is not None and info.port == self.port
        finally:
            other.close()

    def close(self) -> None:
        try:
            self.zc.unregister_service(self.info)
        finally:
            self.zc.close()


def run_discover() -> Proc:
    proc = Proc("windows-discover", [EXE, "--selftest-discover", "--timeout", str(DISCOVER_TIMEOUT)])
    proc.wait(DISCOVER_TIMEOUT + 20)
    return proc


def check_attempt(ad: Advertisement, proc: Proc) -> bool:
    """Fail hard on anything A.5 forbids. Returns True if the instance was found correctly."""
    c = Checks(proc)
    if proc.returncode == 3 and not proc.timed_out:
        c.problems.append("exit 3: the exe says the DNS-SD APIs (windns.h DnsServiceBrowse) are unavailable")
        c.done()
    c.exit_code(proc, 0)
    lines = [line.rstrip() for line in proc.stdout]
    found = []
    for line in lines:
        match = FOUND_LINE.fullmatch(line)
        if not match:
            c.problems.append(f"malformed line (A.5 allows only 'FOUND name=... host=... port=...'): {line!r}")
        else:
            found.append(match)
    c.done()

    ours = [m for m in found if m["name"] == ad.name]
    if not ours:
        near = [m.group(0) for m in found if ad.name.split()[-1] in m["name"] or int(m["port"]) == ad.port]
        if near:
            c.problems.append(
                f"the test instance was found, but its name is not exactly {ad.name!r} "
                f"(A.5 wants the bare instance name, unescaped): {near}"
            )
            c.done()
        return False
    for m in ours:
        c.require(int(m["port"]) == ad.port, f"wrong port for the test instance: {m.group(0)!r}, expected port={ad.port}")
        c.require(same_host(m["host"], ad.host), f"wrong host for the test instance: {m.group(0)!r}, expected host={ad.host}")
    c.done()
    return True


def test_discovers_advertised_mac():
    ad = Advertisement()
    try:
        procs = []
        for attempt in range(1, ATTEMPTS + 1):
            proc = run_discover()
            procs.append(proc)
            if check_attempt(ad, proc):
                if attempt > 1:
                    print(f"      found on attempt {attempt}", flush=True)
                return
            print(f"      attempt {attempt}: the test instance was not in the exe's output", flush=True)

        if not ad.visible_to_another_responder():
            raise TestSkipped(
                "mDNS multicast loopback does not work on this host: a second python-zeroconf instance "
                "could not resolve the advertisement either, so discovery cannot be tested here. "
                "NOT a pass: test discovery manually (KeyBridge-selftest.exe --selftest-discover next to a running Mac)."
            )
        details = "\n".join(p.report() for p in procs)
        raise TestFailure(
            f"{EXE} did not find {ad.name!r} in {ATTEMPTS} attempts of {DISCOVER_TIMEOUT} s, "
            f"although another mDNS responder on this host could resolve it\n{details}"
        )
    finally:
        ad.close()


TESTS = [
    ("discovery: exe finds the advertised _keybridge._tcp instance (A.5)", test_discovers_advertised_mac),
]


def main() -> int:
    global EXE
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("exe", help="path to windows\\build\\KeyBridge-selftest.exe")
    EXE = require_binary(parser.parse_args().exe, "Windows selftest build")
    return run_tests(f"KBP2 discovery: {EXE} vs python-zeroconf", TESTS)


if __name__ == "__main__":
    sys.exit(main())
