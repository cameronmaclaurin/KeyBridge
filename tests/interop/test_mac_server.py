#!/usr/bin/env python3
"""Reference vs the Mac selftest build (docs/PROTOCOL.md Appendix A.1 and A.3,
including the shared clipboard of section 5a).

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
    ref_client,
    ref_pair_client,
    require_binary,
    run_alone,
    run_pair,
    run_tests,
)

BINARY = ""


def mac_server(port: int, psk: str, *extra: str) -> list[str]:
    return [BINARY, "--selftest-server", "--port", str(port), "--psk", psk, *extra]


def mac_pair_server(port: int, *extra: str, name: str = MAC_NAME) -> list[str]:
    return [BINARY, "--selftest-pair-server", "--port", str(port), "--name", name, *extra]


# ---------------------------------------------------------------------------
# Session (A.1)
# ---------------------------------------------------------------------------


def session(psk: str, client_psk: str | None = None, client_extra=(), server_extra=()):
    port = free_port()
    return run_pair(
        mac_server(port, psk, *server_extra),
        ref_client(port, client_psk or psk, *client_extra),
        server_name="mac-server",
        client_name="reference-client",
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
    check_session_ok(psk.upper(), client_psk=psk)


def test_wrong_psk():
    psk = new_psk()
    server, client = session(psk, client_psk=other_psk(psk))
    c = Checks(server, client)
    c.exit_code(client, 2)
    c.stdout_equals(client, ["HANDSHAKE FAILED"])
    c.exit_code(server, 2)
    c.done()


def expect_silent_rejection(*client_extra: str) -> None:
    server, client = session(new_psk(), client_extra=client_extra)
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


def test_psk_usage_error():
    c = Checks()
    for bad in ["00" * 31, "zz" * 32]:
        proc = run_alone([BINARY, "--selftest-server", "--port", str(free_port()), "--psk", bad], f"mac-server --psk {bad[:6]}...")
        c.procs += (proc,)
        c.exit_code(proc, 64)
    c.done()


# ---------------------------------------------------------------------------
# Clipboard (5a, A.1 --clip-file / CLIP): Mac server <-> reference client
# ---------------------------------------------------------------------------


def check_mac_sends(data: bytes, delivered: bool = True, client_extra=()) -> None:
    """Mac --clip-file → the reference client prints a matching CLIP before PING (or none)."""
    server, client = session(new_psk(), server_extra=["--clip-file", clip_file(data)], client_extra=client_extra)
    c = Checks(server, client)
    c.exit_code(client, 0)
    c.stdout_equals(client, a2_with_clip(data if delivered else None))
    c.exit_code(server, 0)
    c.done()


def check_mac_receives(data: bytes, *extra: str, delivered: bool = True) -> None:
    """Reference client --clip-file → the Mac prints a matching CLIP (or none); A.2 transcript unchanged."""
    server, client = session(new_psk(), client_extra=["--clip-file", clip_file(data), *extra])
    c = Checks(server, client)
    c.exit_code(client, 0)
    c.stdout_equals(client, A2_TRANSCRIPT)
    c.exit_code(server, 0)
    c.stdout_equals(server, ["LISTENING"] + ([clip_line(data)] if delivered else []))
    c.done()


def test_clip_mac_sends_small():
    check_mac_sends(SMALL_TEXT)


def test_clip_mac_sends_multi_chunk():
    check_mac_sends(MULTI_CHUNK_TEXT)


def test_clip_mac_sends_non_ascii():
    check_mac_sends(NON_ASCII_TEXT)
    check_mac_sends(NON_ASCII_SPLIT_TEXT)  # an emoji straddles the 16384-byte chunk boundary


def test_clip_mac_sends_1mib():
    check_mac_sends(LIMIT_TEXT)


def test_clip_mac_does_not_send_over_limit():
    check_mac_sends(OVER_LIMIT_TEXT, delivered=False)  # spec 5a: over 1,048,576 bytes is not sent at all


def test_clip_mac_respects_peer_caps():
    check_mac_sends(SMALL_TEXT, delivered=False, client_extra=["--caps", "0"])  # sharing off on the PC
    check_mac_sends(SMALL_TEXT, delivered=False, client_extra=["--no-caps"])  # a v1.4 PC


def test_clip_mac_receives_small():
    check_mac_receives(SMALL_TEXT)


def test_clip_mac_receives_multi_chunk_non_ascii():
    check_mac_receives(MULTI_CHUNK_TEXT)
    check_mac_receives(NON_ASCII_SPLIT_TEXT)


def test_clip_mac_receives_1mib():
    check_mac_receives(LIMIT_TEXT)


def test_clip_mac_discards_over_limit():
    check_mac_receives(OVER_LIMIT_TEXT, "--clip-ignore-limit", delivered=False)


def test_clip_mac_discards_invalid_utf8():
    check_mac_receives(MULTI_CHUNK_TEXT, "--clip-invalid-utf8", delivered=False)


def test_clip_mac_discards_chunk_without_first():
    check_mac_receives(MULTI_CHUNK_TEXT, "--clip-no-first", delivered=False)


def test_clip_mac_ignores_stray_transfer_id():
    check_mac_receives(MULTI_CHUNK_TEXT, "--clip-wrong-id")  # the stray chunk is dropped, the real text arrives


def test_clip_mac_drops_corrupt_chunk():
    server, client = session(new_psk(), client_extra=["--clip-file", clip_file(MULTI_CHUNK_TEXT), "--clip-corrupt-chunk"])
    c = Checks(server, client)
    c.exit_code(server, 3)  # A.1: a client record failed authentication
    c.stdout_equals(server, ["LISTENING"])
    c.terminated(client)
    c.require("RELEASE_ALL" not in client.stdout, "Mac sent RELEASE_ALL after a bad chunk (it must close at once)")
    c.done()


# ---------------------------------------------------------------------------
# Pairing (A.3): reference initiator vs Mac responder
# ---------------------------------------------------------------------------


def pairing(mac_extra=(), client_extra=(), mac_name=MAC_NAME, pc_name=PC_NAME):
    port = free_port()
    return run_pair(
        mac_pair_server(port, *mac_extra, name=mac_name),
        ref_pair_client(port, pc_name, *client_extra),
        server_name="mac-pair-server",
        client_name="reference-pair-client",
    )


def check_pairing_then_session(**names) -> None:
    mac, ref = pairing(**names)
    c = Checks(mac, ref)
    mac_sas, mac_ltk = c.paired(mac)
    ref_sas, ref_ltk = c.paired(ref)
    c.require(mac_sas == ref_sas, f"SAS differs: Mac {mac_sas}, reference {ref_sas}")
    c.require(mac_ltk == ref_ltk, "PAIRED ltk differs between the Mac and the reference")
    c.done()
    check_session_ok(mac_ltk)  # end to end: the ltk works as the session psk


def test_pair_positive():
    check_pairing_then_session()


def test_pair_long_names():
    check_pairing_then_session(mac_name=LONG_NAME, pc_name=LONG_NAME)


def test_pair_mac_cancels():
    mac, ref = pairing(mac_extra=["--confirm", "no"])
    c = Checks(mac, ref)
    mac_sas = c.cancelled(mac)
    ref_sas = c.pair_failed(ref, sas_first=True)
    c.require(mac_sas == ref_sas, f"SAS differs: Mac {mac_sas}, reference {ref_sas}")
    c.done()


def test_pair_pc_cancels():
    mac, ref = pairing(client_extra=["--confirm", "no"])
    c = Checks(mac, ref)
    ref_sas = c.cancelled(ref)
    mac_sas = c.pair_failed(mac, sas_first=True)
    c.require(mac_sas == ref_sas, f"SAS differs: Mac {mac_sas}, reference {ref_sas}")
    c.done()


def test_pair_wrong_pc_confirm():
    mac, ref = pairing(client_extra=["--corrupt-confirm"])
    c = Checks(mac, ref)
    c.pair_failed(mac, sas_first=True)
    c.terminated(ref)
    c.done()


def test_pair_invalid_pc_point():
    mac, ref = pairing(client_extra=["--invalid-point"])
    c = Checks(mac, ref)
    c.exit_code(ref, 0)
    c.stdout_equals(ref, ["REJECTED"])
    c.pair_failed(mac, sas_first=False)
    c.done()


def test_pair_withheld_nonce():
    # Spec 2.2: the Mac must not reveal mac_nonce before it has pc_nonce;
    # spec 2.4: it gives up 10 s after the connection was made.
    mac, ref = pairing(client_extra=["--withhold-nonce"])
    c = Checks(mac, ref)
    c.exit_code(ref, 0)
    c.stdout_equals(ref, ["REJECTED"])
    c.pair_failed(mac, sas_first=False)
    c.done()


def test_session_magic_to_pair_server():
    port = free_port()
    mac, ref = run_pair(
        mac_pair_server(port), ref_client(port, new_psk()), server_name="mac-pair-server", client_name="reference-client"
    )
    c = Checks(mac, ref)
    c.pair_failed(mac, sas_first=False)
    c.exit_code(ref, 2)
    c.stdout_equals(ref, ["HANDSHAKE FAILED"])
    c.done()


def test_pairing_magic_to_session_server():
    port = free_port()
    mac, ref = run_pair(
        mac_server(port, new_psk()), ref_pair_client(port), server_name="mac-server", client_name="reference-pair-client"
    )
    c = Checks(mac, ref)
    c.exit_code(mac, 2)
    c.pair_failed(ref, sas_first=False)
    c.done()


TESTS = [
    ("session positive: exact A.2 transcript, server exit 0", test_positive),
    ("session: --psk is case-insensitive", test_psk_case_insensitive),
    ("session wrong psk: client exit 2, server exit 2", test_wrong_psk),
    ("session corrupted ClientFinished: server exit 2, no records", test_corrupted_client_finished),
    ("session bad magic: server exit 2, nothing sent", test_bad_magic),
    ("session invalid P-256 point: server exit 2, nothing sent", test_invalid_point),
    ("session stalled handshake: server times out (exit 2)", test_handshake_timeout),
    ("session malformed --psk: exit 64", test_psk_usage_error),
    ("clipboard: Mac --clip-file small text → matching CLIP", test_clip_mac_sends_small),
    ("clipboard: Mac --clip-file 40 KB (3 chunks) → matching CLIP", test_clip_mac_sends_multi_chunk),
    ("clipboard: Mac --clip-file non-ASCII (emoji, CJK) → matching CLIP", test_clip_mac_sends_non_ascii),
    ("clipboard: Mac --clip-file exactly 1,048,576 bytes → matching CLIP", test_clip_mac_sends_1mib),
    ("clipboard: Mac does not send a 1,048,577-byte text", test_clip_mac_does_not_send_over_limit),
    ("clipboard: Mac sends nothing to a PC with CAPS 0 or no CAPS", test_clip_mac_respects_peer_caps),
    ("clipboard: reference --clip-file small → Mac prints CLIP", test_clip_mac_receives_small),
    ("clipboard: reference --clip-file 40 KB, non-ASCII → Mac prints CLIP", test_clip_mac_receives_multi_chunk_non_ascii),
    ("clipboard: reference sends exactly 1,048,576 bytes → Mac prints CLIP", test_clip_mac_receives_1mib),
    ("clipboard: 1,048,577 bytes → Mac discards (no CLIP)", test_clip_mac_discards_over_limit),
    ("clipboard: invalid UTF-8 → Mac discards (no CLIP)", test_clip_mac_discards_invalid_utf8),
    ("clipboard: chunk without `first` → Mac discards", test_clip_mac_discards_chunk_without_first),
    ("clipboard: stray chunk with another transfer_id → Mac ignores it", test_clip_mac_ignores_stray_transfer_id),
    ("clipboard: corrupted chunk → Mac drops the session (exit 3)", test_clip_mac_drops_corrupt_chunk),
    ("pairing positive: same SAS and ltk, then a session with that ltk", test_pair_positive),
    ("pairing positive with long UTF-8 names", test_pair_long_names),
    ("pairing: Mac --confirm no", test_pair_mac_cancels),
    ("pairing: PC cancels", test_pair_pc_cancels),
    ("pairing wrong PcConfirm: Mac PAIR FAILED, exit 2", test_pair_wrong_pc_confirm),
    ("pairing invalid pc_pub: Mac PAIR FAILED, nothing sent", test_pair_invalid_pc_point),
    ("pairing withheld PcNonce: Mac sends no MacNonce, times out", test_pair_withheld_nonce),
    ("session magic to the pairing responder: rejected", test_session_magic_to_pair_server),
    ("pairing magic to the session server: rejected", test_pairing_magic_to_session_server),
]


def main() -> int:
    global BINARY
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("binary", help="path to the Mac selftest build (mac/.build/debug/KeyBridge)")
    BINARY = require_binary(parser.parse_args().binary, "Mac selftest binary")
    return run_tests(f"KBP2 interop: reference vs {BINARY}", TESTS)


if __name__ == "__main__":
    sys.exit(main())
