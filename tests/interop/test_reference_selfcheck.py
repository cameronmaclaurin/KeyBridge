#!/usr/bin/env python3
"""Reference <-> reference (docs/PROTOCOL.md section 2 and Appendix A).

Usage: python tests/interop/test_reference_selfcheck.py
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import hmac
import io
import os
import socket
import sys
import threading

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from harness import (
    A2_TRANSCRIPT,
    CLIP_LIMIT,
    LIMIT_TEXT,
    LONG_NAME,
    MULTI_CHUNK_TEXT,
    NON_ASCII_SPLIT_TEXT,
    NON_ASCII_TEXT,
    OVER_LIMIT_TEXT,
    SMALL_TEXT,
    a2_with_clip,
    clip_file,
    clip_line,
    MAC_NAME,
    PC_NAME,
    REFERENCE,
    Checks,
    free_port,
    kbp2,
    new_psk,
    other_psk,
    ref_client,
    ref_pair_client,
    ref_pair_server,
    ref_server,
    run_alone,
    run_pair,
    run_tests,
)

# ---------------------------------------------------------------------------
# Unit checks of the reference against the spec text
# ---------------------------------------------------------------------------


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


def test_pairing_derivations_match_spec():
    """Recompute spec 2.2/2.3 straight from the formulas (no kbp2 helpers) and compare."""

    def h(key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, hashlib.sha256).digest()

    c = Checks()
    for _ in range(50):
        pc_priv, pc_pub = kbp2.new_ephemeral()
        mac_priv, mac_pub = kbp2.new_ephemeral()
        pc_nonce, mac_nonce = os.urandom(32), os.urandom(32)
        pair_hello = b"KBPR" + pc_pub + kbp2.encode_name("PC")
        commit = h(mac_nonce, b"KBPR commit" + mac_pub + pc_pub)
        pair_commit = b"KBPR" + mac_pub + kbp2.encode_name("Mac") + commit
        c.require(len(pair_hello) == 133 and len(pair_commit) == 165, "PairHello/PairCommit sizes")
        c.require(kbp2.commitment(mac_nonce, mac_pub, pc_pub) == commit, "commit formula")

        shared = kbp2.ecdh(pc_priv, kbp2.parse_public_key(mac_pub))
        c.require(shared == kbp2.ecdh(mac_priv, kbp2.parse_public_key(pc_pub)), "ECDH is not symmetric")
        th = hashlib.sha256(pair_hello + pair_commit + pc_nonce + mac_nonce).digest()
        sas = int.from_bytes(hashlib.sha256(b"KBPR sas" + th).digest()[:4], "big") % 1000000
        prk = h(th, shared)
        ltk = h(prk, b"KBPR long-term key\x01")
        pc_confirm = h(h(prk, b"KBPR pc confirm\x01"), th)
        mac_confirm = h(h(prk, b"KBPR mac confirm\x01"), th)

        keys = kbp2.pairing_keys(shared, pair_hello, pair_commit, pc_nonce, mac_nonce)
        c.require(keys.th == th, "TH formula")
        c.require(keys.sas == sas and 0 <= sas <= 999999, "sas formula")
        c.require(keys.ltk == ltk and len(ltk) == 32, "ltk formula")
        c.require(keys.pc_confirm == pc_confirm, "pc_confirm formula")
        c.require(keys.mac_confirm == mac_confirm, "mac_confirm formula")
        c.require(pc_confirm != mac_confirm, "pc_confirm and mac_confirm must differ")
    c.require(kbp2.format_sas(7) == "000 007" and kbp2.format_sas(482913) == "482 913", "SAS display format")
    c.done()


def test_name_field_rules():
    c = Checks()
    c.require(kbp2.encode_name("Mac") == b"Mac" + b"\x00" * 61, "short name is NUL-padded to 64 bytes")
    c.require(kbp2.encode_name("") == b"\x00" * 64, "empty name")
    c.require(kbp2.encode_name("a" * 70) == b"a" * 64, "ASCII name truncated to 64 bytes")
    # 63 ASCII bytes + a 2-byte character: the character does not fit and is dropped whole.
    c.require(kbp2.encode_name("a" * 63 + "é") == b"a" * 63 + b"\x00", "truncation at a character boundary")
    encoded = kbp2.encode_name(LONG_NAME)
    c.require(len(encoded) == 64, "encoded name is always 64 bytes")
    c.require(encoded.rstrip(b"\x00").decode("utf-8") == LONG_NAME.encode()[:64].decode("utf-8", "ignore"), "long UTF-8 name")
    c.require(kbp2.decode_name(b"Bad\x07Name\r\n\x00junk") == "BadName", "decode stops at NUL, drops controls")
    c.require(kbp2.decode_name(b"\xff\xfeMac" + b"\x00" * 59) == "��Mac", "decode is lenient")
    c.require(kbp2.decode_name(b"x" * 64) == "x" * 64, "a full 64-byte name has no NUL")
    c.done()


def test_psk_usage_errors():
    c = Checks()
    port = str(free_port())
    for bad in ["", "00" * 31, "00" * 33, "g" * 64, " " + "0" * 63, "00 " * 21 + "0"]:
        for role, extra in (("server", []), ("client", ["--host", "127.0.0.1"])):
            proc = run_alone([sys.executable, REFERENCE, role, "--port", port, "--psk", bad, *extra], f"{role} --psk {bad!r}")
            c.procs += (proc,)
            c.exit_code(proc, 64)
    c.done()


# ---------------------------------------------------------------------------
# Session (sections 4-6, A.1/A.2)
# ---------------------------------------------------------------------------


def session(psk: str | None = None, server_extra=(), client_extra=(), client_psk: str | None = None):
    psk = psk or new_psk()
    port = free_port()
    return run_pair(ref_server(port, psk, *server_extra), ref_client(port, client_psk or psk, *client_extra))


def check_session_ok(psk: str | None = None, client_psk: str | None = None) -> None:
    server, client = session(psk, client_psk=client_psk)
    c = Checks(server, client)
    c.exit_code(client, 0)
    c.stdout_equals(client, A2_TRANSCRIPT)
    c.exit_code(server, 0)
    c.done()


def test_positive():
    check_session_ok()


def test_psk_case_insensitive():
    psk = new_psk()
    check_session_ok(psk.upper(), client_psk=psk.lower())


def test_wrong_psk():
    psk = new_psk()
    server, client = session(psk, client_psk=other_psk(psk))
    c = Checks(server, client)
    c.exit_code(client, 2)
    c.stdout_equals(client, ["HANDSHAKE FAILED"])
    c.exit_code(server, 2)
    c.done()


def expect_silent_rejection(*client_extra: str):
    server, client = session(client_extra=client_extra)
    c = Checks(server, client)
    c.exit_code(client, 0)  # 0 == server closed without sending anything more
    c.stdout_equals(client, ["REJECTED"])
    c.exit_code(server, 2)
    c.done()
    return server


def test_corrupted_client_finished():
    expect_silent_rejection("--corrupt-finished")


def test_bad_magic():
    expect_silent_rejection("--bad-magic")


def test_invalid_point():
    expect_silent_rejection("--invalid-point")


def test_handshake_timeout():
    server = expect_silent_rejection("--stall")
    c = Checks(server)
    c.require(4.0 <= server.elapsed <= 9.0, f"server should give up ~5 s after accept, took {server.elapsed:.1f} s")
    c.done()


def test_tampered_record():
    server, client = session(server_extra=["--tamper-record"])
    c = Checks(server, client)
    c.exit_code(client, 1)
    c.stdout_equals(client, ["HANDSHAKE OK", "CAPS 1"])
    c.exit_code(server, 3)
    c.done()


def test_replayed_record():
    server, client = session(server_extra=["--replay-record"])
    c = Checks(server, client)
    c.exit_code(client, 1)
    c.stdout_equals(client, ["HANDSHAKE OK", "CAPS 1", "KEY down=1 ext=0 vk=0x0041"])
    c.exit_code(server, 3)
    c.done()


# ---------------------------------------------------------------------------
# Clipboard: unit checks of the record/chunk layer (spec 5a)
# ---------------------------------------------------------------------------


def clip_args(data: bytes, **negative) -> argparse.Namespace:
    """The attributes kbp2.send_clip reads, as the CLI would set them."""
    fields = {name: False for name in kbp2.CLIP_NEGATIVE}
    fields.update(negative)
    return argparse.Namespace(clip_file=data, caps=1, no_caps=False, **fields)


def chunk(flags: int, tid: int, payload: bytes, kind: int = 1) -> bytes:
    return bytes([kind, flags]) + tid.to_bytes(2, "big") + payload


def test_chunk_wire_format():
    """Seal a 40000-byte transfer with the reference, open it here straight from the spec text."""
    k = os.urandom(32)
    a, b = socket.socketpair()
    received = bytearray()

    def reader():
        while True:
            data = b.recv(65536)
            if not data:
                return
            received.extend(data)

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    records = kbp2.RecordLayer(a, send_key=k, recv_key=os.urandom(32))
    records.send(0x06, 0x01)  # CAPS
    text = MULTI_CHUNK_TEXT[:40000]
    kbp2.send_clip(records, clip_args(text), transfer_id=0, between=lambda: True)
    a.shutdown(socket.SHUT_WR)
    t.join(10)
    a.close()
    b.close()

    aead = AESGCM(k)
    nonce = lambda seq: bytes(4) + seq.to_bytes(8, "big")  # noqa: E731
    c = Checks()
    pos, seq = 0, 0
    caps = aead.decrypt(nonce(seq), bytes(received[pos : pos + 20]), None)
    c.require(caps == b"\x06\x01\x00\x00", f"CAPS record plaintext {caps.hex()}")
    pos, seq = pos + 20, seq + 1
    payloads = []
    expected = [(0x01, 16384), (0x00, 16384), (0x02, 40000 - 2 * 16384)]
    for flags, size in expected:
        header = aead.decrypt(nonce(seq), bytes(received[pos : pos + 20]), None)
        n = int.from_bytes(header[1:4], "big")
        c.require(header[0] == 0x05 and n == size + 4, f"DATA header {header.hex()}, expected N={size + 4}")
        pos, seq = pos + 20, seq + 1
        plain = aead.decrypt(nonce(seq), bytes(received[pos : pos + n + 16]), None)  # next seq, N + 16 bytes
        pos, seq = pos + n + 16, seq + 1
        c.require(plain[0] == 0x01 and plain[1] == flags and plain[2:4] == b"\x00\x00", f"chunk header {plain[:4].hex()}")
        payloads.append(plain[4:])
    c.require(pos == len(received), f"{len(received) - pos} unexpected trailing bytes")
    c.require(b"".join(payloads) == text, "reassembled payload differs")
    c.require(kbp2.clip_chunks(b"", 0) == [], "empty text has no chunks (a chunk carries at least one byte)")
    c.require(len(kbp2.clip_chunks(LIMIT_TEXT, 0)) == 64, "1 MiB is 64 chunks")
    c.done()


def test_receive_bad_chunk_length():
    """A DATA header announcing N outside 5..16388 closes the connection; N = 5 and 16388 are fine."""
    c = Checks()
    for n, ok in ((0, False), (4, False), (5, True), (16388, True), (16389, False)):
        k = os.urandom(32)
        a, b = socket.socketpair()
        sender = kbp2.RecordLayer(a, send_key=k, recv_key=k)
        receiver = kbp2.RecordLayer(b, send_key=k, recv_key=k)
        header = sender.seal(bytes([0x05, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF]))
        plain = chunk(3, 0, b"x" * (n - 4)) if n >= 4 else b""
        body = AESGCM(k).encrypt(sender.nonce(sender.send_seq), plain, None)

        def write():
            try:
                a.sendall(header + body)
                a.shutdown(socket.SHUT_WR)
            except OSError:
                pass  # the receiver hung up first, as it should for a bad N

        writer = threading.Thread(target=write, daemon=True)
        writer.start()
        try:
            message = receiver.recv(5.0)
            accepted = message is not None and len(message) == 4 + n
        except kbp2.RecordError:
            accepted = False
        c.require(accepted == ok, f"N={n}: expected {'accepted' if ok else 'RecordError'}")
        b.close()
        writer.join(5)
        a.close()
    c.done()


def test_reassembly_rules():
    with contextlib.redirect_stderr(io.StringIO()):  # the reference logs each discard
        check_reassembly_rules()


def check_reassembly_rules():
    c = Checks()

    def feed(*chunks):
        r = kbp2.ClipReceiver()
        return [r.feed(ch) for ch in chunks]

    c.require(feed(chunk(3, 0, b"hi")) == [b"hi"], "one-chunk transfer (first|last)")
    c.require(feed(chunk(2, 0, b"hi")) == [None], "a chunk without `first` and no transfer in progress is discarded")
    c.require(feed(chunk(1, 0, b"ab"), chunk(3, 1, b"xyz")) == [None, b"xyz"], "`first` abandons an unfinished transfer")
    c.require(
        feed(chunk(1, 0, b"ab"), chunk(2, 1, b"zz"), chunk(2, 0, b"cd")) == [None, None, b"abcd"],
        "a chunk with another transfer_id is discarded; the transfer continues",
    )
    c.require(feed(chunk(1, 7, b"ab"), chunk(2, 7, b"cd"), chunk(2, 7, b"ef"))[1:] == [b"abcd", None], "after `last`, nothing is in progress")
    c.require(feed(chunk(3, 0, b"a\xffb")) == [None], "invalid UTF-8 is discarded")
    emoji = "😀".encode()
    c.require(feed(chunk(1, 0, b"x" + emoji[:2]), chunk(2, 0, emoji[2:])) == [None, b"x" + emoji], "UTF-8 split across chunks")
    c.require(feed(chunk(1, 0, b"ab"), chunk(3, 0, b"zz", kind=2), chunk(2, 0, b"cd")) == [None, None, b"abcd"], "unknown kind ignored")

    full = [chunk(1, 0, b"a" * 16384)] + [chunk(0, 0, b"a" * 16384)] * 62 + [chunk(2, 0, b"a" * 16384)]
    c.require(feed(*full)[-1] == b"a" * CLIP_LIMIT, "exactly 1,048,576 bytes is accepted")
    over = full[:-1] + [chunk(0, 0, b"a" * 16384), chunk(2, 0, b"a")]
    results = feed(*over, chunk(3, 1, b"next"))
    c.require(results[-2] is None, "1,048,577 bytes is discarded")
    c.require(results[-1] == b"next", "after a discarded transfer, the next `first` starts afresh")
    r = kbp2.ClipReceiver()
    for ch in full[:-1] + [chunk(0, 0, b"a" * 16384), chunk(0, 0, b"a")]:  # 1 MiB, then 1 byte too many
        r.feed(ch)
    c.require(r.active and r.feed(chunk(2, 0, b"tail")) is None, "chunks of an oversized transfer stay ignored until its `last`")
    c.require(not r.active, "an oversized transfer ends at its `last`")
    c.done()


# ---------------------------------------------------------------------------
# Clipboard sessions: reference server <-> reference client (5a, A.1/A.2)
# ---------------------------------------------------------------------------


def check_server_clip(data: bytes, *extra: str, expect: bytes | None = None, delivered: bool = True) -> None:
    """Server --clip-file data → client prints the A.2 transcript with (or without) a matching CLIP."""
    server, client = session(server_extra=["--clip-file", clip_file(data), *extra])
    c = Checks(server, client)
    c.exit_code(client, 0)
    c.stdout_equals(client, a2_with_clip((expect if expect is not None else data) if delivered else None))
    c.exit_code(server, 0)
    c.stdout_equals(server, ["LISTENING"])
    c.done()


def check_client_clip(data: bytes, *extra: str, expect: bytes | None = None, delivered: bool = True, server_extra=()) -> None:
    """Client --clip-file data → server prints a matching CLIP (or none); the client transcript is unchanged."""
    server, client = session(server_extra=server_extra, client_extra=["--clip-file", clip_file(data), *extra])
    c = Checks(server, client)
    c.exit_code(client, 0)
    c.stdout_equals(client, A2_TRANSCRIPT)
    c.exit_code(server, 0)
    c.stdout_equals(server, ["LISTENING"] + ([clip_line(expect if expect is not None else data)] if delivered else []))
    c.done()


def test_clip_server_small():
    check_server_clip(SMALL_TEXT)


def test_clip_server_multi_chunk():
    check_server_clip(MULTI_CHUNK_TEXT)


def test_clip_server_non_ascii():
    check_server_clip(NON_ASCII_TEXT)
    check_server_clip(NON_ASCII_SPLIT_TEXT)


def test_clip_client_small_and_non_ascii():
    check_client_clip(SMALL_TEXT)
    check_client_clip(NON_ASCII_SPLIT_TEXT)


def test_clip_both_directions_1mib():
    """Exactly 1,048,576 bytes each way at once: both accepted, and nobody deadlocks."""
    other = bytes(reversed(LIMIT_TEXT))  # a different 1 MiB text for the other direction
    server, client = session(server_extra=["--clip-file", clip_file(LIMIT_TEXT)], client_extra=["--clip-file", clip_file(other)])
    c = Checks(server, client)
    c.exit_code(client, 0)
    c.stdout_equals(client, a2_with_clip(LIMIT_TEXT))
    c.exit_code(server, 0)
    c.stdout_equals(server, ["LISTENING", clip_line(other)])
    c.done()


def test_clip_over_limit_discarded():
    check_server_clip(OVER_LIMIT_TEXT, "--clip-ignore-limit", delivered=False)
    check_client_clip(OVER_LIMIT_TEXT, "--clip-ignore-limit", delivered=False)


def test_clip_over_limit_not_sent():
    check_server_clip(OVER_LIMIT_TEXT, delivered=False)
    check_client_clip(OVER_LIMIT_TEXT, delivered=False)


def test_clip_no_first():
    check_server_clip(MULTI_CHUNK_TEXT, "--clip-no-first", delivered=False)
    check_client_clip(SMALL_TEXT, "--clip-no-first", delivered=False)


def test_clip_wrong_transfer_id():
    check_server_clip(MULTI_CHUNK_TEXT, "--clip-wrong-id")
    check_client_clip(MULTI_CHUNK_TEXT, "--clip-wrong-id")


def test_clip_invalid_utf8():
    check_server_clip(SMALL_TEXT, "--clip-invalid-utf8", delivered=False)
    check_client_clip(MULTI_CHUNK_TEXT, "--clip-invalid-utf8", delivered=False)


def test_clip_corrupt_chunk_from_server():
    server, client = session(server_extra=["--clip-file", clip_file(MULTI_CHUNK_TEXT), "--clip-corrupt-chunk"])
    c = Checks(server, client)
    c.exit_code(client, 1)
    c.stdout_equals(client, A2_TRANSCRIPT[:6])  # up to the last KEY, then the bad chunk
    c.exit_code(server, 3)
    c.done()


def test_clip_corrupt_chunk_from_client():
    server, client = session(client_extra=["--clip-file", clip_file(MULTI_CHUNK_TEXT), "--clip-corrupt-chunk"])
    c = Checks(server, client)
    c.exit_code(server, 3)
    c.stdout_equals(server, ["LISTENING"])
    c.terminated(client)
    c.require("RELEASE_ALL" not in client.stdout, "server sent RELEASE_ALL after a bad chunk (it must close at once)")
    c.done()


def test_clip_peer_sharing_off():
    """A peer advertising CAPS 0 (sharing off) or no CAPS (v1.4) gets no DATA."""
    for extra in (["--caps", "0"], ["--no-caps"]):
        server, client = session(server_extra=["--clip-file", clip_file(SMALL_TEXT)], client_extra=extra)
        c = Checks(server, client)
        c.exit_code(client, 0)
        c.stdout_equals(client, A2_TRANSCRIPT)  # no CLIP
        c.exit_code(server, 0)
        c.done()
    for extra, caps in ((["--caps", "0"], 0), (["--no-caps"], None)):
        server, client = session(server_extra=extra, client_extra=["--clip-file", clip_file(SMALL_TEXT)])
        c = Checks(server, client)
        c.exit_code(client, 0)
        c.stdout_equals(client, a2_with_clip(None, caps=caps))
        c.exit_code(server, 0)
        c.stdout_equals(server, ["LISTENING"])  # no CLIP
        c.done()


def test_clip_usage_errors():
    c = Checks()
    port = str(free_port())
    psk = new_psk()
    for role, extra in (("server", []), ("client", ["--host", "127.0.0.1"])):
        for bad in (["--clip-file", "/nonexistent/kbp2-clip.txt"], ["--clip-no-first"], ["--clip-corrupt-chunk"], ["--caps", "256"]):
            proc = run_alone([sys.executable, REFERENCE, role, "--port", port, "--psk", psk, *extra, *bad], f"{role} {' '.join(bad)}")
            c.procs += (proc,)
            c.exit_code(proc, 64)
    c.done()


# ---------------------------------------------------------------------------
# Pairing (section 2, A.3/A.4)
# ---------------------------------------------------------------------------


def pairing(server_extra=(), client_extra=(), server_name=None, client_name=None):
    port = free_port()
    return run_pair(
        ref_pair_server(port, server_name or MAC_NAME, *server_extra),
        ref_pair_client(port, client_name or PC_NAME, *client_extra),
        server_name="pair-server",
        client_name="pair-client",
    )


def check_pairing_then_session(**names) -> None:
    server, client = pairing(**names)
    c = Checks(server, client)
    server_sas, server_ltk = c.paired(server)
    client_sas, client_ltk = c.paired(client)
    c.require(server_sas == client_sas, f"SAS differs: server {server_sas}, client {client_sas}")
    c.require(server_ltk == client_ltk, "PAIRED ltk differs between the two sides")
    c.done()
    # The ltk is the session psk (2.3): A.1/A.2 must pass with it.
    check_session_ok(server_ltk)


def test_pair_positive():
    check_pairing_then_session()


def test_pair_long_names():
    check_pairing_then_session(server_name=LONG_NAME, client_name=LONG_NAME)


def test_pair_fresh_each_time():
    ltks = set()
    for _ in range(2):
        server, client = pairing()
        c = Checks(server, client)
        _, ltk = c.paired(server)
        c.paired(client)
        c.done()
        ltks.add(ltk)
    c = Checks()
    c.require(len(ltks) == 2, "two pairings produced the same ltk")
    c.done()


def test_pair_cancel_on_mac():
    server, client = pairing(server_extra=["--confirm", "no"])
    c = Checks(server, client)
    server_sas = c.cancelled(server)
    client_sas = c.pair_failed(client, sas_first=True)
    c.require(server_sas == client_sas, f"SAS differs: server {server_sas}, client {client_sas}")
    c.done()


def test_pair_cancel_on_pc():
    server, client = pairing(client_extra=["--confirm", "no"])
    c = Checks(server, client)
    client_sas = c.cancelled(client)
    server_sas = c.pair_failed(server, sas_first=True)
    c.require(server_sas == client_sas, f"SAS differs: server {server_sas}, client {client_sas}")
    c.done()


def test_pair_bad_commit():
    server, client = pairing(server_extra=["--bad-commit"])
    c = Checks(server, client)
    c.pair_failed(client, sas_first=False)  # no number may be shown if the commit is wrong
    c.pair_failed(server, sas_first=True)  # it showed a number, then the PC hung up
    c.done()


def test_pair_invalid_mac_point():
    server, client = pairing(server_extra=["--invalid-point"])
    c = Checks(server, client)
    c.pair_failed(client, sas_first=False)
    c.pair_failed(server, sas_first=False)
    c.done()


def test_pair_corrupt_mac_confirm():
    server, client = pairing(server_extra=["--corrupt-confirm"])
    c = Checks(server, client)
    c.pair_failed(client, sas_first=True)
    # The PC sent a valid PcConfirm before reading the bad MacConfirm, so by 2.4 the
    # responder may legitimately store the key (the "last message" asymmetry).
    c.terminated(server)
    c.done()


def test_pair_corrupt_pc_confirm():
    server, client = pairing(client_extra=["--corrupt-confirm"])
    c = Checks(server, client)
    c.pair_failed(server, sas_first=True)
    c.terminated(client)
    c.done()


def test_pair_invalid_pc_point():
    server, client = pairing(client_extra=["--invalid-point"])
    c = Checks(server, client)
    c.exit_code(client, 0)
    c.stdout_equals(client, ["REJECTED"])
    c.pair_failed(server, sas_first=False)
    c.done()


def test_pair_withheld_nonce():
    server, client = pairing(client_extra=["--withhold-nonce"])
    c = Checks(server, client)
    c.exit_code(client, 0)
    c.stdout_equals(client, ["REJECTED"])  # no MacNonce before PcNonce, then a close
    c.pair_failed(server, sas_first=False)
    c.require(8.0 <= server.elapsed <= 14.0, f"responder should give up ~10 s after accept, took {server.elapsed:.1f} s")
    c.done()


def test_pairing_magic_to_session_server():
    port = free_port()
    server, client = run_pair(ref_server(port, new_psk()), ref_pair_client(port), client_name="pair-client")
    c = Checks(server, client)
    c.exit_code(server, 2)  # "KBPR" is a bad magic for the session-only A.1 server
    c.pair_failed(client, sas_first=False)
    c.done()


def test_session_magic_to_pair_server():
    port = free_port()
    server, client = run_pair(ref_pair_server(port), ref_client(port, new_psk()), server_name="pair-server")
    c = Checks(server, client)
    c.pair_failed(server, sas_first=False)
    c.exit_code(client, 2)
    c.stdout_equals(client, ["HANDSHAKE FAILED"])
    c.done()


TESTS = [
    ("HKDF helpers match RFC 5869 test vector", test_kdf_is_rfc5869),
    ("pairing derivations match the spec formulas", test_pairing_derivations_match_spec),
    ("name field: UTF-8, 64 bytes, NUL padding, lenient decode", test_name_field_rules),
    ("malformed --psk: exit 64", test_psk_usage_errors),
    ("session positive: exact A.2 transcript", test_positive),
    ("session: --psk is case-insensitive", test_psk_case_insensitive),
    ("session wrong psk: HANDSHAKE FAILED", test_wrong_psk),
    ("session corrupted ClientFinished: silent close", test_corrupted_client_finished),
    ("session bad magic: silent close", test_bad_magic),
    ("session invalid P-256 point: silent close", test_invalid_point),
    ("session stalled handshake: 5 s timeout", test_handshake_timeout),
    ("session tampered record: client drops connection", test_tampered_record),
    ("session replayed record: client drops connection", test_replayed_record),
    ("clipboard: chunk wire format (header seq, chunk on the next seq, N + 16 bytes)", test_chunk_wire_format),
    ("clipboard: DATA header length outside 5..16388 closes", test_receive_bad_chunk_length),
    ("clipboard: reassembly rules (first, transfer_id, 1 MiB, UTF-8, kind)", test_reassembly_rules),
    ("clipboard: server --clip-file small text", test_clip_server_small),
    ("clipboard: server --clip-file 40 KB, 3 chunks", test_clip_server_multi_chunk),
    ("clipboard: server --clip-file non-ASCII (emoji, CJK, split across chunks)", test_clip_server_non_ascii),
    ("clipboard: client --clip-file small and non-ASCII", test_clip_client_small_and_non_ascii),
    ("clipboard: exactly 1,048,576 bytes both ways at once", test_clip_both_directions_1mib),
    ("clipboard: 1,048,577 bytes sent anyway is discarded", test_clip_over_limit_discarded),
    ("clipboard: 1,048,577-byte --clip-file is not sent", test_clip_over_limit_not_sent),
    ("clipboard: chunk without `first` is discarded", test_clip_no_first),
    ("clipboard: stray chunk with another transfer_id is discarded", test_clip_wrong_transfer_id),
    ("clipboard: invalid UTF-8 is discarded", test_clip_invalid_utf8),
    ("clipboard: corrupted chunk from the server: client drops the connection", test_clip_corrupt_chunk_from_server),
    ("clipboard: corrupted chunk from the client: server drops the session", test_clip_corrupt_chunk_from_client),
    ("clipboard: no DATA to a peer with CAPS 0 or no CAPS", test_clip_peer_sharing_off),
    ("clipboard: bad --clip-file / negative option without it: exit 64", test_clip_usage_errors),
    ("pairing positive: same SAS and ltk, then a session with that ltk", test_pair_positive),
    ("pairing positive with long UTF-8 names", test_pair_long_names),
    ("pairing gives a fresh ltk each time", test_pair_fresh_each_time),
    ("pairing cancelled on the Mac", test_pair_cancel_on_mac),
    ("pairing cancelled on the PC", test_pair_cancel_on_pc),
    ("pairing bad commit: PC fails before showing a number", test_pair_bad_commit),
    ("pairing invalid mac_pub: PC fails", test_pair_invalid_mac_point),
    ("pairing wrong MacConfirm: PC fails", test_pair_corrupt_mac_confirm),
    ("pairing wrong PcConfirm: Mac fails", test_pair_corrupt_pc_confirm),
    ("pairing invalid pc_pub: Mac closes silently", test_pair_invalid_pc_point),
    ("pairing withheld PcNonce: no MacNonce, 10 s timeout", test_pair_withheld_nonce),
    ("pairing magic to the session-only server: rejected", test_pairing_magic_to_session_server),
    ("session magic to the pairing responder: rejected", test_session_magic_to_pair_server),
]

if __name__ == "__main__":
    sys.exit(run_tests("KBP2 reference self-check", TESTS))
