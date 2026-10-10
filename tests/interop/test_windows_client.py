#!/usr/bin/env python3
"""Reference vs the Windows selftest build (docs/PROTOCOL.md Appendix A.2 and A.4,
including the shared clipboard of section 5a).

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
    LIMIT_TEXT,
    LONG_NAME,
    MAC_NAME,
    MULTI_CHUNK_TEXT,
    NON_ASCII_SPLIT_TEXT,
    NON_ASCII_TEXT,
    OVER_LIMIT_TEXT,
    PC_NAME,
    SMALL_TEXT,
    Checks,
    a2_with_clip,
    clip_file,
    clip_line,
    free_port,
    new_psk,
    other_psk,
    ref_pair_server,
    ref_server,
    require_binary,
    run_alone,
    run_pair,
    run_tests,
)

EXE = ""


def windows_client(port: int, psk: str, *extra: str) -> list[str]:
    return [EXE, "--selftest-client", "--host", "127.0.0.1", "--port", str(port), "--psk", psk, *extra]


def windows_pair_client(port: int, *extra: str, name: str = PC_NAME) -> list[str]:
    return [EXE, "--selftest-pair-client", "--host", "127.0.0.1", "--port", str(port), "--name", name, *extra]


# ---------------------------------------------------------------------------
# Session (A.2)
# ---------------------------------------------------------------------------


def session(psk: str, client_psk: str | None = None, server_extra=(), client_extra=()):
    port = free_port()
    return run_pair(
        ref_server(port, psk, *server_extra),
        windows_client(port, client_psk or psk, *client_extra),
        server_name="reference-server",
        client_name="windows-client",
    )


def check_session_ok(psk: str, client_psk: str | None = None) -> None:
    server, client = session(psk, client_psk)
    c = Checks(server, client)
    c.exit_code(client, 0)
    c.stdout_equals(client, A2_TRANSCRIPT)
    c.exit_code(server, 0)
    c.done()


def test_positive():
    check_session_ok(new_psk())


def test_psk_case_insensitive():
    psk = new_psk()
    check_session_ok(psk, client_psk=psk.upper())


def test_wrong_psk():
    psk = new_psk()
    server, client = session(psk, client_psk=other_psk(psk))
    c = Checks(server, client)
    c.exit_code(client, 2)
    c.stdout_equals(client, ["HANDSHAKE FAILED"])
    c.exit_code(server, 2)  # the client must not send ClientFinished
    c.done()


# The spec requires the client to drop the connection on any record
# authentication failure (section 5). These two checks look at what was
# accepted and that the exe terminated (unchanged from v1.1; A.2's exit 1 for
# post-handshake failures is not asserted here).


def test_tampered_record():
    server, client = session(new_psk(), server_extra=["--tamper-record"])
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
    server, client = session(new_psk(), server_extra=["--replay-record"])
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


def test_psk_usage_error():
    c = Checks()
    for bad in ["00" * 31, "zz" * 32]:
        argv = [EXE, "--selftest-client", "--host", "127.0.0.1", "--port", str(free_port()), "--psk", bad]
        proc = run_alone(argv, f"windows-client --psk {bad[:6]}...")
        c.procs += (proc,)
        c.exit_code(proc, 64)
    c.done()


# ---------------------------------------------------------------------------
# Clipboard (5a, A.2 --clip-file / CLIP): reference server <-> Windows client
# ---------------------------------------------------------------------------


def check_exe_receives(data: bytes, *extra: str, delivered: bool = True) -> None:
    """Reference server --clip-file → the exe prints the A.2 transcript with a matching CLIP before PING (or none)."""
    server, client = session(new_psk(), server_extra=["--clip-file", clip_file(data), *extra])
    c = Checks(server, client)
    c.exit_code(client, 0)
    c.stdout_equals(client, a2_with_clip(data if delivered else None))
    c.exit_code(server, 0)
    c.done()


def check_exe_sends(data: bytes, delivered: bool = True, server_extra=(), caps: int | None = 1) -> None:
    """Exe --clip-file → the reference server prints a matching CLIP (or none)."""
    server, client = session(new_psk(), server_extra=server_extra, client_extra=["--clip-file", clip_file(data)])
    c = Checks(server, client)
    c.exit_code(client, 0)
    c.stdout_equals(client, a2_with_clip(None, caps=caps))
    c.exit_code(server, 0)
    c.stdout_equals(server, ["LISTENING"] + ([clip_line(data)] if delivered else []))
    c.done()


def test_clip_exe_receives_small():
    check_exe_receives(SMALL_TEXT)


def test_clip_exe_receives_multi_chunk():
    check_exe_receives(MULTI_CHUNK_TEXT)


def test_clip_exe_receives_non_ascii():
    check_exe_receives(NON_ASCII_TEXT)
    check_exe_receives(NON_ASCII_SPLIT_TEXT)  # an emoji straddles the 16384-byte chunk boundary


def test_clip_exe_receives_1mib():
    check_exe_receives(LIMIT_TEXT)


def test_clip_exe_discards_over_limit():
    check_exe_receives(OVER_LIMIT_TEXT, "--clip-ignore-limit", delivered=False)


def test_clip_exe_discards_invalid_utf8():
    check_exe_receives(MULTI_CHUNK_TEXT, "--clip-invalid-utf8", delivered=False)


def test_clip_exe_discards_chunk_without_first():
    check_exe_receives(MULTI_CHUNK_TEXT, "--clip-no-first", delivered=False)


def test_clip_exe_ignores_stray_transfer_id():
    check_exe_receives(MULTI_CHUNK_TEXT, "--clip-wrong-id")  # the stray chunk is dropped, the real text arrives


def test_clip_exe_drops_corrupt_chunk():
    server, client = session(new_psk(), server_extra=["--clip-file", clip_file(MULTI_CHUNK_TEXT), "--clip-corrupt-chunk"])
    c = Checks(server, client)
    c.terminated(client)
    lines = [line.rstrip() for line in client.stdout]
    c.require(lines[:6] == A2_TRANSCRIPT[:6], f"windows-client: expected {A2_TRANSCRIPT[:6]} before the bad chunk")
    c.require(
        not any(line.startswith(("CLIP", "PING", "RELEASE_ALL")) for line in lines),
        "windows-client: accepted something after a corrupted chunk (it must close the connection)",
    )
    c.exit_code(server, 3)  # no PONG: the exe hung up at the bad chunk
    c.done()


def test_clip_exe_sends_small_and_non_ascii():
    check_exe_sends(SMALL_TEXT)
    check_exe_sends(NON_ASCII_TEXT)


def test_clip_exe_sends_multi_chunk():
    check_exe_sends(MULTI_CHUNK_TEXT)
    check_exe_sends(NON_ASCII_SPLIT_TEXT)


def test_clip_exe_sends_1mib():
    check_exe_sends(LIMIT_TEXT)


def test_clip_exe_does_not_send_over_limit():
    check_exe_sends(OVER_LIMIT_TEXT, delivered=False)  # spec 5a: over 1,048,576 bytes is not sent at all


def test_clip_exe_respects_peer_caps():
    check_exe_sends(SMALL_TEXT, delivered=False, server_extra=["--caps", "0"], caps=0)  # sharing off on the Mac
    check_exe_sends(SMALL_TEXT, delivered=False, server_extra=["--no-caps"], caps=None)  # a v1.4 Mac


# ---------------------------------------------------------------------------
# Pairing (A.4): Windows initiator vs reference responder
# ---------------------------------------------------------------------------


def pairing(server_extra=(), exe_extra=(), mac_name=MAC_NAME, pc_name=PC_NAME):
    port = free_port()
    return run_pair(
        ref_pair_server(port, mac_name, *server_extra),
        windows_pair_client(port, *exe_extra, name=pc_name),
        server_name="reference-pair-server",
        client_name="windows-pair-client",
    )


def check_pairing_then_session(**names) -> None:
    ref, exe = pairing(**names)
    c = Checks(ref, exe)
    ref_sas, ref_ltk = c.paired(ref)
    exe_sas, exe_ltk = c.paired(exe)
    c.require(ref_sas == exe_sas, f"SAS differs: reference {ref_sas}, exe {exe_sas}")
    c.require(ref_ltk == exe_ltk, "PAIRED ltk differs between the reference and the exe")
    c.done()
    check_session_ok(exe_ltk)  # end to end: the ltk works as the session psk


def test_pair_positive():
    check_pairing_then_session()


def test_pair_long_names():
    check_pairing_then_session(mac_name=LONG_NAME, pc_name=LONG_NAME)


def test_pair_bad_commit():
    ref, exe = pairing(server_extra=["--bad-commit"])
    c = Checks(ref, exe)
    c.pair_failed(exe, sas_first=False)  # SAS is printed only after the commit verifies
    c.terminated(ref)
    c.done()


def test_pair_invalid_mac_point():
    ref, exe = pairing(server_extra=["--invalid-point"])
    c = Checks(ref, exe)
    c.pair_failed(exe, sas_first=False)
    c.terminated(ref)
    c.done()


def test_pair_wrong_mac_confirm():
    ref, exe = pairing(server_extra=["--corrupt-confirm"])
    c = Checks(ref, exe)
    c.pair_failed(exe, sas_first=True)
    c.terminated(ref)
    c.done()


def test_pair_pc_cancels():
    ref, exe = pairing(exe_extra=["--confirm", "no"])
    c = Checks(ref, exe)
    exe_sas = c.cancelled(exe)
    ref_sas = c.pair_failed(ref, sas_first=True)
    c.require(ref_sas == exe_sas, f"SAS differs: reference {ref_sas}, exe {exe_sas}")
    c.done()


def test_pair_mac_cancels():
    ref, exe = pairing(server_extra=["--confirm", "no"])
    c = Checks(ref, exe)
    ref_sas = c.cancelled(ref)
    exe_sas = c.pair_failed(exe, sas_first=True)
    c.require(ref_sas == exe_sas, f"SAS differs: reference {ref_sas}, exe {exe_sas}")
    c.done()


TESTS = [
    ("session positive: exe prints exactly the A.2 transcript, both exit 0", test_positive),
    ("session: --psk is case-insensitive", test_psk_case_insensitive),
    ("session wrong psk: exe exit 2, reference server exit 2", test_wrong_psk),
    ("session tampered record: exe drops the connection", test_tampered_record),
    ("session replayed record: exe drops the connection", test_replayed_record),
    ("session malformed --psk: exit 64", test_psk_usage_error),
    ("clipboard: reference --clip-file small → exe prints CLIP", test_clip_exe_receives_small),
    ("clipboard: reference --clip-file 40 KB (3 chunks) → exe prints CLIP", test_clip_exe_receives_multi_chunk),
    ("clipboard: reference --clip-file non-ASCII (emoji, CJK) → exe prints CLIP", test_clip_exe_receives_non_ascii),
    ("clipboard: exactly 1,048,576 bytes → exe prints CLIP", test_clip_exe_receives_1mib),
    ("clipboard: 1,048,577 bytes → exe discards (no CLIP)", test_clip_exe_discards_over_limit),
    ("clipboard: invalid UTF-8 → exe discards (no CLIP)", test_clip_exe_discards_invalid_utf8),
    ("clipboard: chunk without `first` → exe discards", test_clip_exe_discards_chunk_without_first),
    ("clipboard: stray chunk with another transfer_id → exe ignores it", test_clip_exe_ignores_stray_transfer_id),
    ("clipboard: corrupted chunk → exe drops the connection", test_clip_exe_drops_corrupt_chunk),
    ("clipboard: exe --clip-file small, non-ASCII → reference prints CLIP", test_clip_exe_sends_small_and_non_ascii),
    ("clipboard: exe --clip-file 40 KB, split emoji → reference prints CLIP", test_clip_exe_sends_multi_chunk),
    ("clipboard: exe --clip-file exactly 1,048,576 bytes → reference prints CLIP", test_clip_exe_sends_1mib),
    ("clipboard: exe does not send a 1,048,577-byte text", test_clip_exe_does_not_send_over_limit),
    ("clipboard: exe sends nothing to a Mac with CAPS 0 or no CAPS", test_clip_exe_respects_peer_caps),
    ("pairing positive: same SAS and ltk, then a session with that ltk", test_pair_positive),
    ("pairing positive with long UTF-8 names", test_pair_long_names),
    ("pairing bad commit: exe PAIR FAILED (no SAS), exit 2", test_pair_bad_commit),
    ("pairing invalid mac_pub: exe PAIR FAILED, exit 2", test_pair_invalid_mac_point),
    ("pairing wrong MacConfirm: exe PAIR FAILED, exit 2", test_pair_wrong_mac_confirm),
    ("pairing: exe --confirm no", test_pair_pc_cancels),
    ("pairing: Mac cancels", test_pair_mac_cancels),
]


def main() -> int:
    global EXE
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("exe", help="path to windows\\build\\KeyBridge-selftest.exe")
    EXE = require_binary(parser.parse_args().exe, "Windows selftest client")
    return run_tests(f"KBP2 interop: {EXE} vs reference", TESTS)


if __name__ == "__main__":
    sys.exit(main())
