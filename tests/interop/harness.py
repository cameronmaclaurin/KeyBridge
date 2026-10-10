"""Shared plumbing for the KBP2 interop tests (stdlib only).

Every child process gets a hard timeout and is killed on the way out, and a
global watchdog aborts the whole run, so a hung peer can never hang CI.
"""

from __future__ import annotations

import os
import queue
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import traceback
from typing import Callable

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
REFERENCE = os.path.join(REPO, "tests", "reference", "kbp2.py")

sys.path.insert(0, os.path.dirname(REFERENCE))
import kbp2  # noqa: E402  (reference implementation; the self-check unit-tests it)

# docs/PROTOCOL.md Appendix A.2, copied literally (deliberately not imported
# from the reference, so a reference bug cannot hide behind itself).
A2_TRANSCRIPT = [
    "HANDSHAKE OK",
    "KEY down=1 ext=0 vk=0x0041",
    "KEY down=0 ext=0 vk=0x0041",
    "KEY down=1 ext=1 vk=0x000D",
    "KEY down=0 ext=1 vk=0x000D",
    "PING",
    "RELEASE_ALL",
    "CLOSED",
]

# Appendix A.3/A.4 line shapes.
SAS_LINE = re.compile(r"SAS (\d{6})")
PAIRED_LINE = re.compile(r"PAIRED ([0-9a-f]{64})")

# Display names for the pairing tests: a realistic one, and one that is longer
# than the 64-byte name field and not ASCII (exercises truncation at a UTF-8
# character boundary; the name is never printed, so this checks only that
# pairing still succeeds).
MAC_NAME = "Cameron's MacBook Air"
PC_NAME = "DESKTOP-KB1"
LONG_NAME = "Ordinateur de bureau très très long — ünïcödé ✓ " * 2

READY_TIMEOUT = 20.0  # server start-up until it prints LISTENING
PEER_TIMEOUT = 25.0  # any single process run
WATCHDOG_TIMEOUT = 300.0  # the whole test file

_live: set["Proc"] = set()
_live_lock = threading.Lock()


class TestFailure(AssertionError):
    pass


class TestSkipped(Exception):
    """The environment cannot run this scenario (not a product failure). Reported, never silent."""


def free_port() -> int:
    """A currently free TCP port on 127.0.0.1."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def new_psk() -> str:
    """A random 32-byte session psk (the ltk pairing would produce) as 64 hex digits."""
    return secrets.token_hex(32)


def other_psk(psk: str) -> str:
    while True:
        wrong = new_psk()
        if wrong != psk:
            return wrong


class Proc:
    """A child process whose stdout/stderr lines are collected by background threads."""

    def __init__(self, name: str, argv: list[str]):
        self.name = name
        self.argv = [str(a) for a in argv]
        self.stdout: list[str] = []
        self.stderr: list[str] = []
        self.returncode: int | None = None
        self.timed_out = False
        self._stdout_q: queue.Queue[str | None] = queue.Queue()
        self.started = time.monotonic()
        self.elapsed = 0.0
        self.popen = subprocess.Popen(
            self.argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
        with _live_lock:
            _live.add(self)
        self._threads = [
            threading.Thread(target=self._pump, args=(self.popen.stdout, self.stdout, self._stdout_q), daemon=True),
            threading.Thread(target=self._pump, args=(self.popen.stderr, self.stderr, None), daemon=True),
        ]
        for t in self._threads:
            t.start()

    @staticmethod
    def _pump(pipe, sink: list[str], q: queue.Queue | None) -> None:
        for line in pipe:
            line = line.rstrip("\r\n")
            sink.append(line)
            if q is not None:
                q.put(line)
        if q is not None:
            q.put(None)

    def wait_for_line(self, wanted: str, timeout: float) -> bool:
        """Block until stdout has a line equal to `wanted` (stripped). False on timeout/EOF."""
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            try:
                line = self._stdout_q.get(timeout=remaining)
            except queue.Empty:
                return False
            if line is None:
                return False
            if line.strip() == wanted:
                return True

    def wait(self, timeout: float) -> int | None:
        """Wait for exit; on timeout kill it and return None."""
        try:
            self.returncode = self.popen.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.timed_out = True
            self.kill()
        self._finish()
        return None if self.timed_out else self.returncode

    def kill(self) -> None:
        if self.popen.poll() is None:
            try:
                self.popen.kill()
            except OSError:
                pass
        try:
            self.popen.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        self._finish()

    def _finish(self) -> None:
        if self.returncode is None:
            self.returncode = self.popen.poll()
        if not self.elapsed:
            self.elapsed = time.monotonic() - self.started
        for t in self._threads:
            t.join(timeout=5)
        with _live_lock:
            _live.discard(self)

    def report(self) -> str:
        status = "killed after timeout" if self.timed_out else f"exit {self.returncode}"
        lines = [f"[{self.name}] {' '.join(self.argv)}", f"[{self.name}] {status} after {self.elapsed:.1f} s"]
        lines += [f"[{self.name} stdout] {line}" for line in self.stdout] or [f"[{self.name} stdout] (empty)"]
        lines += [f"[{self.name} stderr] {line}" for line in self.stderr]
        return "\n".join(lines)


def start_server(argv: list[str], name: str = "server") -> Proc:
    """Start a selftest server and wait for its LISTENING line."""
    server = Proc(name, argv)
    if not server.wait_for_line("LISTENING", READY_TIMEOUT):
        exited = server.popen.poll() is not None
        server.kill()
        why = "exited before printing LISTENING" if exited else f"did not print LISTENING within {READY_TIMEOUT:.0f} s"
        raise TestFailure(f"{name} {why}\n{server.report()}")
    return server


def run_pair(server_argv: list[str], client_argv: list[str], server_name="server", client_name="client"):
    """Start the server, run the client to completion, then wait for the server."""
    server = start_server(server_argv, server_name)
    client = None
    try:
        client = Proc(client_name, client_argv)
        client.wait(PEER_TIMEOUT)
        server.wait(PEER_TIMEOUT)
        return server, client
    finally:
        server.kill()
        if client is not None:
            client.kill()


def run_alone(argv: list[str], name: str) -> Proc:
    """Run one process to completion (e.g. a usage-error check)."""
    proc = Proc(name, argv)
    proc.wait(PEER_TIMEOUT)
    return proc


class Checks:
    """Collect every mismatch of a scenario, then fail once with both peers' output."""

    def __init__(self, *procs: Proc):
        self.procs = procs
        self.problems: list[str] = []

    def exit_code(self, proc: Proc, expected: int) -> None:
        if proc.timed_out:
            self.problems.append(f"{proc.name}: expected exit {expected}, but it hung and was killed")
        elif proc.returncode != expected:
            self.problems.append(f"{proc.name}: expected exit {expected}, got {proc.returncode}")

    def terminated(self, proc: Proc) -> None:
        if proc.timed_out:
            self.problems.append(f"{proc.name}: hung and was killed")

    def stdout_equals(self, proc: Proc, expected: list[str]) -> None:
        got = [line.rstrip() for line in proc.stdout]
        if got != expected:
            self.problems.append(
                f"{proc.name}: stdout mismatch\n  expected: {expected}\n  got:      {got}"
            )

    # -- Appendix A.3/A.4 outcomes ------------------------------------------

    def _lines(self, proc: Proc) -> list[str]:
        """stdout lines, without a responder's leading LISTENING."""
        lines = [line.rstrip() for line in proc.stdout]
        return lines[1:] if lines[:1] == ["LISTENING"] else lines

    def paired(self, proc: Proc) -> tuple[str | None, str | None]:
        """Expect stdout exactly [SAS dddddd, PAIRED <ltk>] and exit 0. Returns (sas, ltk)."""
        self.exit_code(proc, 0)
        lines = self._lines(proc)
        sas = SAS_LINE.fullmatch(lines[0]) if len(lines) == 2 else None
        ltk = PAIRED_LINE.fullmatch(lines[1]) if len(lines) == 2 else None
        if not (sas and ltk):
            self.problems.append(f"{proc.name}: expected ['SAS dddddd', 'PAIRED <64 lowercase hex>'], got {lines}")
            return None, None
        return sas.group(1), ltk.group(1)

    def cancelled(self, proc: Proc) -> str | None:
        """Expect stdout exactly [SAS dddddd, CANCELLED] and exit 0. Returns the SAS."""
        self.exit_code(proc, 0)
        lines = self._lines(proc)
        sas = SAS_LINE.fullmatch(lines[0]) if len(lines) == 2 and lines[1] == "CANCELLED" else None
        if not sas:
            self.problems.append(f"{proc.name}: expected ['SAS dddddd', 'CANCELLED'], got {lines}")
            return None
        return sas.group(1)

    def pair_failed(self, proc: Proc, sas_first: bool | None) -> str | None:
        """Expect exit 2 and stdout ending in PAIR FAILED.

        sas_first=True: exactly [SAS dddddd, PAIR FAILED] (failure after the number was shown).
        sas_first=False: exactly [PAIR FAILED] (failure before any number may be shown).
        sas_first=None: either. Returns the SAS if one was printed.
        """
        self.exit_code(proc, 2)
        lines = self._lines(proc)
        sas = SAS_LINE.fullmatch(lines[0]) if len(lines) == 2 else None
        ok_with = bool(sas) and lines[1] == "PAIR FAILED"
        ok_without = lines == ["PAIR FAILED"]
        allowed = {True: ok_with, False: ok_without, None: ok_with or ok_without}[sas_first]
        if not allowed:
            shape = {True: "['SAS dddddd', 'PAIR FAILED']", False: "['PAIR FAILED']", None: "[('SAS dddddd',) 'PAIR FAILED']"}
            self.problems.append(f"{proc.name}: expected {shape[sas_first]}, got {lines}")
        return sas.group(1) if sas else None

    def require(self, condition: bool, message: str) -> None:
        if not condition:
            self.problems.append(message)

    def done(self) -> None:
        if self.problems:
            details = "\n".join(p.report() for p in self.procs)
            raise TestFailure("\n".join(self.problems) + "\n" + details)


def ref_server(port: int, psk: str, *extra: str) -> list[str]:
    return [sys.executable, REFERENCE, "server", "--port", str(port), "--psk", psk, *extra]


def ref_client(port: int, psk: str, *extra: str) -> list[str]:
    return [sys.executable, REFERENCE, "client", "--host", "127.0.0.1", "--port", str(port), "--psk", psk, *extra]


def ref_pair_server(port: int, name: str = MAC_NAME, *extra: str) -> list[str]:
    return [sys.executable, REFERENCE, "pair-server", "--port", str(port), "--name", name, *extra]


def ref_pair_client(port: int, name: str = PC_NAME, *extra: str) -> list[str]:
    return [sys.executable, REFERENCE, "pair-client", "--host", "127.0.0.1", "--port", str(port), "--name", name, *extra]


def require_binary(path: str, what: str) -> str:
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        sys.exit(f"error: {what} not found: {path}")
    if not os.access(path, os.X_OK):
        sys.exit(f"error: {what} is not executable: {path}")
    return path


def _watchdog() -> None:
    print(f"\nWATCHDOG: tests exceeded {WATCHDOG_TIMEOUT:.0f} s; killing children and aborting.", flush=True)
    with _live_lock:
        procs = list(_live)
    for proc in procs:
        try:
            proc.popen.kill()
        except OSError:
            pass
        print(proc.report(), flush=True)
    os._exit(124)


def run_tests(title: str, tests: list[tuple[str, Callable[[], None]]]) -> int:
    """Run each scenario, print PASS/FAIL with full peer output on failure, return exit status."""
    watchdog = threading.Timer(WATCHDOG_TIMEOUT, _watchdog)
    watchdog.daemon = True
    watchdog.start()

    print(f"== {title}", flush=True)
    failed: list[str] = []
    skipped: list[str] = []
    for name, fn in tests:
        started = time.monotonic()
        try:
            fn()
        except TestSkipped as exc:
            skipped.append(name)
            print(f"SKIP  {name} ({time.monotonic() - started:.1f} s): {exc}", flush=True)
            if os.environ.get("GITHUB_ACTIONS") == "true":
                message = f"{name}: {exc}".replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
                print(f"::warning title=Interop test skipped::{message}", flush=True)
        except TestFailure as exc:
            failed.append(name)
            print(f"FAIL  {name} ({time.monotonic() - started:.1f} s)", flush=True)
            for line in str(exc).splitlines():
                print(f"      {line}", flush=True)
        except Exception:  # a harness bug: report it as a failure, keep going
            failed.append(name)
            print(f"ERROR {name}", flush=True)
            for line in traceback.format_exc().splitlines():
                print(f"      {line}", flush=True)
        else:
            print(f"PASS  {name} ({time.monotonic() - started:.1f} s)", flush=True)

    watchdog.cancel()
    passed = len(tests) - len(failed) - len(skipped)
    summary = f"== {passed}/{len(tests)} passed"
    if skipped:
        summary += f"; skipped: {', '.join(skipped)}"
    if failed:
        summary += f"; failed: {', '.join(failed)}"
    print(summary, flush=True)
    return 1 if failed else 0
