#!/usr/bin/env python3
"""KBP2 reference implementation (KeyBridge Protocol v2).

This file is the executable companion to docs/PROTOCOL.md, which is the source
of truth. It favours readability over speed: every step of pairing, the
handshake and the record layer maps to a numbered rule in the spec. When the
Mac and Windows apps disagree, this file (and then the spec) decides.

Roles (docs/PROTOCOL.md Appendix A):

  server       A.1 selftest server      kbp2.py server --port P --psk HEX64
  client       A.2 selftest client      kbp2.py client --host H --port P --psk HEX64
  pair-server  A.3 pairing responder    kbp2.py pair-server --port P --name NAME [--confirm yes|no]
  pair-client  A.4 pairing initiator    kbp2.py pair-client --host H --port P --name NAME [--confirm yes|no]

Negative-test options (not part of the spec; used by tests/interop/):

  client --corrupt-finished   complete the handshake but send a wrong ClientFinished.
  client --bad-magic          send a ClientHello whose magic is not "KBR2".
  client --invalid-point      send a ClientHello whose public key is not on P-256.
  client --stall              send ClientHello, verify ServerHello, never send ClientFinished.
      Each of these prints REJECTED and exits 0 iff the server closes the
      connection without sending any (further) byte; otherwise it prints
      NOT REJECTED and exits 1.

  server --tamper-record      flip one bit in the first KEY record after the handshake.
  server --replay-record      send the first KEY record twice (same ciphertext).
      A correct client must drop the connection at the bad record.

  pair-server --bad-commit       send a commit that does not match mac_nonce.
  pair-server --corrupt-confirm  send a wrong MacConfirm.
  pair-server --invalid-point    send a PairCommit whose mac_pub is not on P-256.
      A correct initiator prints PAIR FAILED and exits 2 (and, for the first
      and last, never prints SAS: SAS comes only after the commit checks out).
      The responder itself otherwise follows A.3.

  pair-client --corrupt-confirm  send a wrong PcConfirm (otherwise follows A.4).
      A correct responder prints PAIR FAILED and exits 2.
  pair-client --invalid-point    send a PairHello whose pc_pub is not on P-256.
  pair-client --withhold-nonce   read PairCommit, then never send PcNonce.
      These two print REJECTED and exit 0 iff the responder closes without
      sending any further byte (for --withhold-nonce: it must never send
      mac_nonce before pc_nonce, spec 2.2, and must give up after 10 s,
      spec 2.4); otherwise they print NOT REJECTED and exit 1.

Exit codes:
  server:      0 success, 2 handshake failed, 3 no PONG       (spec A.1)
  client:      0 success / CLOSED, 2 HANDSHAKE FAILED          (spec A.2)
               1 anything else (record authentication failure, liveness
                 timeout, connection error, negative-test expectation not met)
  pair-server, pair-client:
               0 PAIRED or CANCELLED, 2 PAIR FAILED            (spec A.3, A.4)
               1 negative-test expectation not met
  all:         64 usage error (bad arguments, e.g. a --psk that is not 64 hex digits)

Requires the `cryptography` package (see tests/requirements.txt).
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import re
import socket
import sys
import time
import unicodedata
from dataclasses import dataclass

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover
    sys.exit("kbp2.py needs the 'cryptography' package: python -m pip install -r tests/requirements.txt")

# ---------------------------------------------------------------------------
# Constants (spec sections 1-6)
# ---------------------------------------------------------------------------

DEFAULT_PORT = 9876
PSK_LEN = 32  # the session psk is the 32-byte ltk from pairing

# Pairing (spec section 2)
PAIR_MAGIC = b"KBPR"
NAME_LEN = 64  # UTF-8, truncated at a character boundary, NUL-padded
PAIR_HELLO_LEN = 4 + 65 + NAME_LEN  # "KBPR" || pc_pub || pc_name = 133
COMMIT_LEN = 32
PAIR_COMMIT_LEN = 4 + 65 + NAME_LEN + COMMIT_LEN  # "KBPR" || mac_pub || mac_name || commit = 165
PAIR_NONCE_LEN = 32
CONFIRM_LEN = 32

LABEL_COMMIT = b"KBPR commit"
LABEL_SAS = b"KBPR sas"
LABEL_LTK = b"KBPR long-term key"
LABEL_PC_CONFIRM = b"KBPR pc confirm"
LABEL_MAC_CONFIRM = b"KBPR mac confirm"

PAIR_SETUP_TIMEOUT = 10.0  # PairHello through MacNonce, from connecting (spec 2.4)
PAIR_CONFIRM_TIMEOUT = 120.0  # confirmation phase (spec 2.4)

# Session (spec sections 4-6)
MAGIC = b"KBR2"
PUBKEY_LEN = 65  # 0x04 || X(32) || Y(32)
NONCE_LEN = 32
FINISHED_LEN = 32
CLIENT_HELLO_LEN = len(MAGIC) + PUBKEY_LEN + NONCE_LEN  # 101
SERVER_HELLO_PREFIX_LEN = CLIENT_HELLO_LEN  # 101
SERVER_HELLO_LEN = SERVER_HELLO_PREFIX_LEN + FINISHED_LEN  # 133

LABEL_SERVER_FINISHED = b"KBR2 server finished"
LABEL_CLIENT_FINISHED = b"KBR2 client finished"
LABEL_TRAFFIC_S2C = b"KBR2 traffic s2c"
LABEL_TRAFFIC_C2S = b"KBR2 traffic c2s"

HANDSHAKE_TIMEOUT = 5.0  # seconds, server: from accept; client: for ServerHello

RECORD_PLAINTEXT_LEN = 4
RECORD_TAG_LEN = 16
RECORD_LEN = RECORD_PLAINTEXT_LEN + RECORD_TAG_LEN  # 20

TYPE_KEY = 0x01
TYPE_PING = 0x02
TYPE_PONG = 0x03
TYPE_RELEASE_ALL = 0x04

FLAG_DOWN = 0x01
FLAG_EXTENDED = 0x02

LIVENESS_TIMEOUT = 6.0  # seconds without any record
PONG_WAIT = 3.0  # A.1: wait up to 3 s for a PONG

# A.1: the records the selftest server sends after authentication.
SELFTEST_KEYS = [  # (flags, vk)
    (0x01, 0x0041),
    (0x00, 0x0041),
    (0x03, 0x000D),
    (0x02, 0x000D),
]

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_HANDSHAKE_FAILED = 2
EXIT_PAIR_FAILED = 2
EXIT_NO_PONG = 3
EXIT_USAGE = 64

DEBUG = False


def out(line: str) -> None:
    """Protocol event line on stdout (what the conformance tests compare)."""
    print(line, flush=True)


def log(message: str) -> None:
    """Human diagnostics on stderr (never compared by tests)."""
    print(f"kbp2: {message}", file=sys.stderr, flush=True)


def debug(name: str, value: bytes) -> None:
    if DEBUG:
        log(f"{name:16} {value.hex()}")


# ---------------------------------------------------------------------------
# Session psk on the command line (Appendix A.2)
# ---------------------------------------------------------------------------

_PSK_RE = re.compile(r"[0-9A-Fa-f]{64}")


def parse_psk(text: str) -> bytes:
    """--psk: exactly 64 hex digits, case-insensitive. Anything else is a usage error.

    (bytes.fromhex alone would also accept spaces, so check the shape first.)
    """
    if not _PSK_RE.fullmatch(text):
        raise argparse.ArgumentTypeError(f"--psk must be {2 * PSK_LEN} hex digits, got {len(text)} characters")
    return bytes.fromhex(text)


# ---------------------------------------------------------------------------
# Primitives (spec section 3)
# ---------------------------------------------------------------------------


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract: HMAC-SHA256(key = salt, data = ikm)."""
    return hmac_sha256(salt, ikm)


def expand(prk: bytes, info: bytes) -> bytes:
    """HKDF-Expand with one 32-byte output block: HMAC-SHA256(prk, info || 0x01)."""
    return hmac_sha256(prk, info + b"\x01")


def new_ephemeral() -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    """Fresh P-256 key pair; returns (private key, 65-byte uncompressed public key)."""
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    assert len(public) == PUBKEY_LEN
    return private, public


def parse_public_key(data: bytes) -> ec.EllipticCurvePublicKey:
    """Parse an uncompressed X9.63 point; raise ValueError unless it is a valid P-256 point."""
    if len(data) != PUBKEY_LEN or data[0] != 0x04:
        raise ValueError("public key is not a 65-byte uncompressed point")
    # from_encoded_point checks that the point is on the curve (and not infinity).
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data)


def ecdh(private: ec.EllipticCurvePrivateKey, peer: ec.EllipticCurvePublicKey) -> bytes:
    """32-byte big-endian X coordinate of the shared point."""
    return private.exchange(ec.ECDH(), peer)


# An uncompressed point that is not on P-256, for negative tests: (1, 1).
INVALID_POINT = b"\x04" + (1).to_bytes(32, "big") + (1).to_bytes(32, "big")


# ---------------------------------------------------------------------------
# Socket helpers (spec sections 1 and 5)
# ---------------------------------------------------------------------------


class PeerClosed(Exception):
    """The peer closed the connection (EOF or reset) before `wanted` bytes arrived."""

    def __init__(self, received: int, wanted: int):
        super().__init__(f"peer closed after {received} of {wanted} bytes")
        self.received = received
        self.wanted = wanted


def recv_exact(sock: socket.socket, n: int, deadline: float | None) -> bytes:
    """Read exactly n bytes. Raises PeerClosed on EOF/reset, TimeoutError past deadline."""
    buf = bytearray()
    while len(buf) < n:
        if deadline is None:
            sock.settimeout(None)
        else:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"timed out after {len(buf)} of {n} bytes")
            sock.settimeout(remaining)
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout as exc:  # socket.timeout is TimeoutError on 3.10+
            raise TimeoutError(f"timed out after {len(buf)} of {n} bytes") from exc
        except (ConnectionResetError, ConnectionAbortedError):
            raise PeerClosed(len(buf), n) from None
        if not chunk:
            raise PeerClosed(len(buf), n)
        buf += chunk
    return bytes(buf)


def graceful_close(sock: socket.socket) -> None:
    """Spec 5 graceful close: send FIN, drain whatever the peer still sends (briefly), then close.

    Closing a TCP socket with unread received data makes most stacks send RST,
    which can destroy data the peer has not read yet.
    """
    try:
        sock.shutdown(socket.SHUT_WR)
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            sock.settimeout(max(0.01, deadline - time.monotonic()))
            if not sock.recv(4096):
                break
    except OSError:
        pass
    finally:
        sock.close()


def expect_silent_close(sock: socket.socket, timeout: float, what: str) -> int:
    """Negative tests: succeed iff the peer closes without sending another byte."""
    started = time.monotonic()
    try:
        data = recv_exact(sock, 1, started + timeout)
    except PeerClosed:
        log(f"{what}: peer closed the connection after {time.monotonic() - started:.2f} s")
        out("REJECTED")
        return EXIT_OK
    except TimeoutError:
        out(f"NOT REJECTED: peer kept the connection open for {timeout:.0f} s")
        return EXIT_ERROR
    out(f"NOT REJECTED: peer sent data ({data.hex()}...)")
    return EXIT_ERROR


def listen_once(port: int) -> tuple[socket.socket, float]:
    """Listen on 127.0.0.1:port, print LISTENING, accept exactly one connection.

    Returns (connection, accept time).
    """
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(1)
    out("LISTENING")

    conn, peer = listener.accept()
    accepted_at = time.monotonic()
    listener.close()
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    log(f"accepted {peer[0]}:{peer[1]}")
    return conn, accepted_at


# ---------------------------------------------------------------------------
# Pairing: messages and derivations (spec sections 2.2, 2.3)
# ---------------------------------------------------------------------------


class PairingError(Exception):
    pass


def encode_name(name: str) -> bytes:
    """Display name -> 64 bytes: UTF-8, truncated at a character boundary, NUL-padded."""
    encoded = b""
    for ch in name:
        piece = ch.encode("utf-8")
        if len(encoded) + len(piece) > NAME_LEN:
            break
        encoded += piece
    return encoded.ljust(NAME_LEN, b"\x00")


def decode_name(field: bytes) -> str:
    """Bytes up to the first NUL, decoded leniently, with control characters removed."""
    text = field.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cc")


def commitment(mac_nonce: bytes, mac_pub: bytes, pc_pub: bytes) -> bytes:
    """commit = HMAC-SHA256(key = mac_nonce, data = "KBPR commit" || mac_pub || pc_pub)."""
    return hmac_sha256(mac_nonce, LABEL_COMMIT + mac_pub + pc_pub)


@dataclass
class PairingKeys:
    th: bytes
    sas: int  # 0..999999
    ltk: bytes  # 32 bytes; becomes the session psk
    pc_confirm: bytes
    mac_confirm: bytes


def pairing_keys(shared: bytes, pair_hello: bytes, pair_commit: bytes, pc_nonce: bytes, mac_nonce: bytes) -> PairingKeys:
    """Spec 2.3. Both sides run this identically once both nonces are known."""
    assert len(pair_hello) == PAIR_HELLO_LEN and len(pair_commit) == PAIR_COMMIT_LEN
    th = hashlib.sha256(pair_hello + pair_commit + pc_nonce + mac_nonce).digest()
    sas = int.from_bytes(hashlib.sha256(LABEL_SAS + th).digest()[0:4], "big") % 1_000_000
    prk = extract(salt=th, ikm=shared)
    ltk = expand(prk, LABEL_LTK)
    pc_confirm = hmac_sha256(expand(prk, LABEL_PC_CONFIRM), th)
    mac_confirm = hmac_sha256(expand(prk, LABEL_MAC_CONFIRM), th)

    debug("ecdh", shared)
    debug("TH", th)
    debug("prk", prk)
    debug("ltk", ltk)
    debug("pc_confirm", pc_confirm)
    debug("mac_confirm", mac_confirm)
    return PairingKeys(th, sas, ltk, pc_confirm, mac_confirm)


def format_sas(sas: int) -> str:
    """How the apps display the number: 6 digits with leading zeros, grouped "482 913"."""
    digits = f"{sas:06d}"
    return f"{digits[:3]} {digits[3:]}"


def flip_first_bit(data: bytes) -> bytes:
    return bytes([data[0] ^ 0x01]) + data[1:]


# ---------------------------------------------------------------------------
# Handshake (spec section 4)
# ---------------------------------------------------------------------------


class HandshakeError(Exception):
    pass


@dataclass
class KeySchedule:
    server_hello: bytes  # full 133-byte ServerHello (prefix || server_finished)
    server_finished: bytes
    client_finished: bytes
    k_s2c: bytes
    k_c2s: bytes


def key_schedule(psk: bytes, shared: bytes, client_hello: bytes, sh_prefix: bytes) -> KeySchedule:
    """Both sides run this identically once they know ClientHello and SH_prefix."""
    assert len(client_hello) == CLIENT_HELLO_LEN and len(sh_prefix) == SERVER_HELLO_PREFIX_LEN
    prk = extract(salt=psk, ikm=shared)
    th1 = hashlib.sha256(client_hello + sh_prefix).digest()
    server_finished = hmac_sha256(expand(prk, LABEL_SERVER_FINISHED), th1)
    server_hello = sh_prefix + server_finished
    th2 = hashlib.sha256(client_hello + server_hello).digest()
    client_finished = hmac_sha256(expand(prk, LABEL_CLIENT_FINISHED), th2)
    k_s2c = expand(prk, LABEL_TRAFFIC_S2C + th2)
    k_c2s = expand(prk, LABEL_TRAFFIC_C2S + th2)

    debug("psk", psk)
    debug("ecdh", shared)
    debug("prk", prk)
    debug("TH1", th1)
    debug("server_finished", server_finished)
    debug("TH2", th2)
    debug("client_finished", client_finished)
    debug("k_s2c", k_s2c)
    debug("k_c2s", k_c2s)
    return KeySchedule(server_hello, server_finished, client_finished, k_s2c, k_c2s)


def split_hello(data: bytes) -> tuple[bytes, bytes, bytes]:
    """Split the common 101-byte hello layout into (magic, pub, nonce)."""
    magic = data[0:4]
    pub = data[4 : 4 + PUBKEY_LEN]
    nonce = data[4 + PUBKEY_LEN : 4 + PUBKEY_LEN + NONCE_LEN]
    return magic, pub, nonce


def server_handshake(sock: socket.socket, psk: bytes, accepted_at: float) -> KeySchedule:
    """Spec 4 server steps 1-5. Raises HandshakeError; the caller closes silently."""
    deadline = accepted_at + HANDSHAKE_TIMEOUT
    try:
        # 1. ClientHello: magic and a valid P-256 point. Spec 1: dispatch on the
        #    first 4 bytes, so a wrong magic is rejected without waiting for more.
        #    This selftest server is session-only; "KBPR" (pairing) is a bad magic here.
        magic = recv_exact(sock, len(MAGIC), deadline)
        if magic != MAGIC:
            raise HandshakeError(f"bad magic {magic!r}")
        client_hello = magic + recv_exact(sock, CLIENT_HELLO_LEN - len(MAGIC), deadline)
        _magic, client_pub, _client_nonce = split_hello(client_hello)
        try:
            peer = parse_public_key(client_pub)
        except ValueError as exc:
            raise HandshakeError(f"invalid client public key: {exc}") from None

        # 2. Ephemeral key, nonce, server_finished; send ServerHello.
        private, server_pub = new_ephemeral()
        server_nonce = os.urandom(NONCE_LEN)
        sh_prefix = MAGIC + server_pub + server_nonce
        keys = key_schedule(psk, ecdh(private, peer), client_hello, sh_prefix)
        sock.sendall(keys.server_hello)

        # 3. ClientFinished within the same 5 s window, compared in constant time.
        client_finished = recv_exact(sock, FINISHED_LEN, deadline)
    except TimeoutError as exc:
        raise HandshakeError(f"timeout: {exc}") from None
    except PeerClosed as exc:
        raise HandshakeError(str(exc)) from None
    except OSError as exc:
        raise HandshakeError(f"socket error: {exc}") from None

    # 4./5. Mismatch -> HandshakeError (caller closes silently); match -> authenticated.
    if not hmac.compare_digest(client_finished, keys.client_finished):
        raise HandshakeError("ClientFinished mismatch")
    return keys


def client_hello_and_verify(sock: socket.socket, psk: bytes, hello_override: bytes | None = None):
    """Spec 4 client steps 1-2 (and 3: the caller reports a mismatch).

    Returns (keys, server_finished_ok). Raises HandshakeError on bad magic,
    invalid point, timeout or a closed connection.
    """
    # 1. Ephemeral key pair and nonce; send ClientHello.
    private, client_pub = new_ephemeral()
    client_nonce = os.urandom(NONCE_LEN)
    client_hello = MAGIC + client_pub + client_nonce
    sock.sendall(hello_override if hello_override is not None else client_hello)

    # 2. ServerHello within 5 s; check magic, point, server_finished.
    try:
        server_hello = recv_exact(sock, SERVER_HELLO_LEN, time.monotonic() + HANDSHAKE_TIMEOUT)
    except TimeoutError as exc:
        raise HandshakeError(f"timeout waiting for ServerHello: {exc}") from None
    except PeerClosed as exc:
        raise HandshakeError(f"waiting for ServerHello: {exc}") from None
    sh_prefix = server_hello[:SERVER_HELLO_PREFIX_LEN]
    magic, server_pub, _server_nonce = split_hello(sh_prefix)
    if magic != MAGIC:
        raise HandshakeError(f"bad magic {magic!r}")
    try:
        peer = parse_public_key(server_pub)
    except ValueError as exc:
        raise HandshakeError(f"invalid server public key: {exc}") from None
    keys = key_schedule(psk, ecdh(private, peer), client_hello, sh_prefix)
    ok = hmac.compare_digest(server_hello[SERVER_HELLO_PREFIX_LEN:], keys.server_finished)
    return keys, ok


# ---------------------------------------------------------------------------
# Records (spec section 5)
# ---------------------------------------------------------------------------


class RecordError(Exception):
    """Authentication failure or truncated record: the connection must be closed."""


class RecordLayer:
    """Fixed 20-byte AES-256-GCM records with per-direction 64-bit counters."""

    def __init__(self, sock: socket.socket, send_key: bytes, recv_key: bytes):
        self.sock = sock
        self._send = AESGCM(send_key)
        self._recv = AESGCM(recv_key)
        self.send_seq = 0
        self.recv_seq = 0

    @staticmethod
    def nonce(seq: int) -> bytes:
        return b"\x00\x00\x00\x00" + seq.to_bytes(8, "big")

    def seal(self, plaintext: bytes) -> bytes:
        assert len(plaintext) == RECORD_PLAINTEXT_LEN
        record = self._send.encrypt(self.nonce(self.send_seq), plaintext, None)
        self.send_seq += 1
        assert len(record) == RECORD_LEN
        return record

    def send(self, type_: int, b1: int = 0, b2: int = 0, b3: int = 0) -> None:
        self.sock.settimeout(HANDSHAKE_TIMEOUT)  # recv() may have left a tiny timeout behind
        self.sock.sendall(self.seal(bytes([type_, b1, b2, b3])))

    def recv(self, timeout: float | None) -> bytes | None:
        """Next plaintext, or None if the peer closed cleanly on a record boundary.

        Raises RecordError (bad tag / truncated) and TimeoutError.
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        try:
            record = recv_exact(self.sock, RECORD_LEN, deadline)
        except PeerClosed as exc:
            if exc.received == 0:
                return None
            raise RecordError(f"truncated record: {exc}") from None
        try:
            plaintext = self._recv.decrypt(self.nonce(self.recv_seq), record, None)
        except InvalidTag:
            raise RecordError(f"record {self.recv_seq} failed authentication") from None
        self.recv_seq += 1
        return plaintext


def key_record(flags: int, vk: int) -> tuple[int, int, int, int]:
    return (TYPE_KEY, flags, vk & 0xFF, (vk >> 8) & 0xFF)


# ---------------------------------------------------------------------------
# Selftest server (Appendix A.1)
# ---------------------------------------------------------------------------


def run_server(args: argparse.Namespace) -> int:
    conn, accepted_at = listen_once(args.port)
    try:
        keys = server_handshake(conn, args.psk, accepted_at)
    except HandshakeError as exc:
        log(f"handshake failed: {exc}")
        conn.close()  # silently: nothing else is sent
        return EXIT_HANDSHAKE_FAILED
    log("handshake ok")

    records = RecordLayer(conn, send_key=keys.k_s2c, recv_key=keys.k_c2s)
    try:
        for index, (flags, vk) in enumerate(SELFTEST_KEYS):
            record = records.seal(bytes(key_record(flags, vk)))
            if index == 0 and args.tamper_record:
                record = record[:-1] + bytes([record[-1] ^ 0x01])
                log("negative test: sent KEY record 0 with a flipped tag bit")
            conn.sendall(record)
            if index == 0 and args.replay_record:
                conn.sendall(record)
                log("negative test: replayed KEY record 0")
        records.send(TYPE_PING)
    except OSError as exc:
        log(f"peer went away while sending: {exc}")

    got_pong = False
    deadline = time.monotonic() + PONG_WAIT
    try:
        while not got_pong:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            plaintext = records.recv(remaining)
            if plaintext is None:
                log("peer closed before PONG")
                break
            if plaintext[0] == TYPE_PONG:
                got_pong = True
            # Unknown types are ignored.
    except TimeoutError:
        log("no PONG within 3 s")
    except RecordError as exc:
        log(f"closing: {exc}")
        conn.close()
        return EXIT_NO_PONG
    except OSError as exc:
        log(f"socket error waiting for PONG: {exc}")

    try:
        records.send(TYPE_RELEASE_ALL)
    except OSError as exc:
        log(f"could not send RELEASE_ALL: {exc}")
    graceful_close(conn)
    return EXIT_OK if got_pong else EXIT_NO_PONG


# ---------------------------------------------------------------------------
# Selftest client (Appendix A.2) and negative-test clients
# ---------------------------------------------------------------------------


def format_event(plaintext: bytes) -> str | None:
    """A.2 stdout line for a received record, or None if it is ignored."""
    type_, b1, b2, b3 = plaintext
    if type_ == TYPE_KEY:
        vk = b2 | (b3 << 8)
        if not 1 <= vk <= 254:
            return None  # spec 5: PC ignores KEY records with VK outside 1..254
        down = 1 if b1 & FLAG_DOWN else 0
        ext = 1 if b1 & FLAG_EXTENDED else 0
        return f"KEY down={down} ext={ext} vk=0x{vk:04X}"
    if type_ == TYPE_PING:
        return "PING"
    if type_ == TYPE_RELEASE_ALL:
        return "RELEASE_ALL"
    return None  # PONG is never sent to the PC; unknown types are ignored


def run_client(args: argparse.Namespace) -> int:
    try:
        sock = socket.create_connection((args.host, args.port), timeout=HANDSHAKE_TIMEOUT)
    except OSError as exc:
        log(f"connect to {args.host}:{args.port} failed: {exc}")
        return EXIT_ERROR
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    try:
        return client_session(sock, args.psk, args)
    finally:
        sock.close()


def client_session(sock: socket.socket, psk: bytes, args: argparse.Namespace) -> int:
    if args.bad_magic or args.invalid_point:
        _, pub = new_ephemeral()
        magic = MAGIC
        if args.bad_magic:
            magic = b"KBRX"
        if args.invalid_point:
            pub = INVALID_POINT
        sock.sendall(magic + pub + os.urandom(NONCE_LEN))
        what = "bad magic" if args.bad_magic else "invalid point"
        return expect_silent_close(sock, args.reject_timeout, what)

    try:
        keys, server_finished_ok = client_hello_and_verify(sock, psk)
    except HandshakeError as exc:
        log(f"handshake failed: {exc}")
        out("HANDSHAKE FAILED")
        return EXIT_HANDSHAKE_FAILED
    except OSError as exc:
        log(f"handshake failed: socket error: {exc}")
        out("HANDSHAKE FAILED")
        return EXIT_HANDSHAKE_FAILED
    if not server_finished_ok:
        log("Not paired with this Mac — pair again (server_finished mismatch)")
        out("HANDSHAKE FAILED")  # 3. do not send ClientFinished
        return EXIT_HANDSHAKE_FAILED

    if args.stall:
        return expect_silent_close(sock, args.reject_timeout, "stalled handshake")

    if args.corrupt_finished:
        sock.sendall(flip_first_bit(keys.client_finished))
        return expect_silent_close(sock, args.reject_timeout, "corrupted ClientFinished")

    # 4. Match: send ClientFinished; the session is authenticated.
    sock.sendall(keys.client_finished)
    out("HANDSHAKE OK")

    records = RecordLayer(sock, send_key=keys.k_c2s, recv_key=keys.k_s2c)
    while True:
        try:
            plaintext = records.recv(LIVENESS_TIMEOUT)
        except TimeoutError:
            log(f"no record for {LIVENESS_TIMEOUT:.0f} s, closing")
            return EXIT_ERROR
        except RecordError as exc:
            log(f"closing: {exc}")
            return EXIT_ERROR
        except OSError as exc:
            log(f"socket error: {exc}")
            return EXIT_ERROR
        if plaintext is None:
            out("CLOSED")
            return EXIT_OK
        line = format_event(plaintext)
        if line is not None:
            out(line)
        if plaintext[0] == TYPE_PING:
            try:
                records.send(TYPE_PONG)
            except OSError as exc:
                log(f"could not send PONG: {exc}")


# ---------------------------------------------------------------------------
# Pairing selftest responder (Appendix A.3) and initiator (Appendix A.4)
# ---------------------------------------------------------------------------


def run_pairing(sock: socket.socket, role) -> int:
    """Run one side of spec section 2; any failure -> PAIR FAILED, exit 2, nothing stored."""
    try:
        return role()
    except PairingError as exc:
        why = str(exc)
    except TimeoutError as exc:  # before OSError: TimeoutError is an OSError
        why = f"timeout: {exc}"
    except PeerClosed as exc:
        why = str(exc)
    except OSError as exc:
        why = f"socket error: {exc}"
    log(f"Pairing didn't complete: {why}")
    out("PAIR FAILED")
    sock.close()
    return EXIT_PAIR_FAILED


def run_pair_server(args: argparse.Namespace) -> int:
    conn, accepted_at = listen_once(args.port)  # A.3: always in pairing mode
    return run_pairing(conn, lambda: pair_responder(conn, accepted_at, args))


def pair_responder(conn: socket.socket, accepted_at: float, args: argparse.Namespace) -> int:
    """The Mac's side of spec 2.2-2.4."""
    setup_deadline = accepted_at + PAIR_SETUP_TIMEOUT

    # PairHello. Spec 1: dispatch on the first 4 bytes; this responder speaks only "KBPR".
    magic = recv_exact(conn, len(PAIR_MAGIC), setup_deadline)
    if magic != PAIR_MAGIC:
        raise PairingError(f"bad magic {magic!r}")
    pair_hello = magic + recv_exact(conn, PAIR_HELLO_LEN - len(PAIR_MAGIC), setup_deadline)
    pc_pub = pair_hello[4 : 4 + PUBKEY_LEN]
    pc_name = pair_hello[4 + PUBKEY_LEN :]
    try:
        peer = parse_public_key(pc_pub)
    except ValueError as exc:
        raise PairingError(f"invalid pc_pub: {exc}") from None
    log(f"PC name: {decode_name(pc_name)!r}")

    # PairCommit: fresh key pair and nonce; commit to mac_nonce before seeing pc_nonce.
    private, mac_pub = new_ephemeral()
    mac_nonce = os.urandom(PAIR_NONCE_LEN)
    if args.invalid_point:
        mac_pub = INVALID_POINT
        log("negative test: PairCommit carries a public key that is not on P-256")
    commit = commitment(mac_nonce, mac_pub, pc_pub)
    if args.bad_commit:
        commit = commitment(os.urandom(PAIR_NONCE_LEN), mac_pub, pc_pub)
        log("negative test: commit does not match the mac_nonce that will be sent")
    pair_commit = PAIR_MAGIC + mac_pub + encode_name(args.name) + commit
    conn.sendall(pair_commit)

    # PcNonce, and only then MacNonce (spec 2.2).
    pc_nonce = recv_exact(conn, PAIR_NONCE_LEN, setup_deadline)
    conn.sendall(mac_nonce)

    keys = pairing_keys(ecdh(private, peer), pair_hello, pair_commit, pc_nonce, mac_nonce)
    out(f"SAS {keys.sas:06d}")
    log(f"the Mac would show {format_sas(keys.sas)}")

    if args.confirm == "no":  # the user clicked Cancel
        out("CANCELLED")
        conn.close()
        return EXIT_OK

    # The user clicked Confirm: send MacConfirm, then wait for the PC's.
    mac_confirm = keys.mac_confirm
    if args.corrupt_confirm:
        mac_confirm = flip_first_bit(mac_confirm)
        log("negative test: sent a wrong MacConfirm")
    conn.sendall(mac_confirm)
    pc_confirm = recv_exact(conn, CONFIRM_LEN, time.monotonic() + PAIR_CONFIRM_TIMEOUT)
    if not hmac.compare_digest(pc_confirm, keys.pc_confirm):
        raise PairingError("PcConfirm mismatch")

    # Spec 2.4: own user confirmed and the peer's confirm verified -> store ltk.
    out(f"PAIRED {keys.ltk.hex()}")
    graceful_close(conn)
    return EXIT_OK


def run_pair_client(args: argparse.Namespace) -> int:
    try:
        sock = socket.create_connection((args.host, args.port), timeout=PAIR_SETUP_TIMEOUT)
    except OSError as exc:
        log(f"Pairing didn't complete: connect to {args.host}:{args.port} failed: {exc}")
        out("PAIR FAILED")
        return EXIT_PAIR_FAILED
    connected_at = time.monotonic()
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return run_pairing(sock, lambda: pair_initiator(sock, connected_at, args))


def pair_initiator(sock: socket.socket, connected_at: float, args: argparse.Namespace) -> int:
    """The PC's side of spec 2.2-2.4."""
    setup_deadline = connected_at + PAIR_SETUP_TIMEOUT
    reject_timeout = PAIR_SETUP_TIMEOUT + 3.0

    # PairHello.
    private, pc_pub = new_ephemeral()
    if args.invalid_point:
        pc_pub = INVALID_POINT
    pair_hello = PAIR_MAGIC + pc_pub + encode_name(args.name)
    sock.sendall(pair_hello)
    if args.invalid_point:
        return expect_silent_close(sock, reject_timeout, "invalid pc_pub")

    # PairCommit.
    pair_commit = recv_exact(sock, PAIR_COMMIT_LEN, setup_deadline)
    magic = pair_commit[0:4]
    mac_pub = pair_commit[4 : 4 + PUBKEY_LEN]
    mac_name = pair_commit[4 + PUBKEY_LEN : 4 + PUBKEY_LEN + NAME_LEN]
    commit = pair_commit[4 + PUBKEY_LEN + NAME_LEN :]
    if magic != PAIR_MAGIC:
        raise PairingError(f"bad magic {magic!r}")
    try:
        peer = parse_public_key(mac_pub)
    except ValueError as exc:
        raise PairingError(f"invalid mac_pub: {exc}") from None
    log(f"Mac name: {decode_name(mac_name)!r}")

    if args.withhold_nonce:
        # The responder must not reveal mac_nonce before it has pc_nonce, and must
        # give up 10 s after the connection was made.
        return expect_silent_close(sock, reject_timeout, "withheld PcNonce")

    # PcNonce only after PairCommit has arrived, so the commitment is fixed before
    # the responder can see pc_nonce. Then MacNonce, and check the commitment.
    pc_nonce = os.urandom(PAIR_NONCE_LEN)
    sock.sendall(pc_nonce)
    mac_nonce = recv_exact(sock, PAIR_NONCE_LEN, setup_deadline)
    if not hmac.compare_digest(commit, commitment(mac_nonce, mac_pub, pc_pub)):
        raise PairingError("commit does not match mac_nonce")

    keys = pairing_keys(ecdh(private, peer), pair_hello, pair_commit, pc_nonce, mac_nonce)
    out(f"SAS {keys.sas:06d}")
    log(f"the PC would show {format_sas(keys.sas)}")

    if args.confirm == "no":  # the user clicked Cancel
        out("CANCELLED")
        sock.close()
        return EXIT_OK

    # The user clicked Confirm: send PcConfirm, then wait for the Mac's.
    pc_confirm = keys.pc_confirm
    if args.corrupt_confirm:
        pc_confirm = flip_first_bit(pc_confirm)
        log("negative test: sent a wrong PcConfirm")
    sock.sendall(pc_confirm)
    mac_confirm = recv_exact(sock, CONFIRM_LEN, time.monotonic() + PAIR_CONFIRM_TIMEOUT)
    if not hmac.compare_digest(mac_confirm, keys.mac_confirm):
        raise PairingError("MacConfirm mismatch")

    out(f"PAIRED {keys.ltk.hex()}")
    graceful_close(sock)
    return EXIT_OK


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class Parser(argparse.ArgumentParser):
    def error(self, message: str):  # exit 64, never 2 (2 means "handshake/pairing failed")
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = Parser(description="KBP2 reference implementation (docs/PROTOCOL.md).")
    parser.add_argument("--debug", action="store_true", help="print key-schedule values to stderr")
    roles = parser.add_subparsers(dest="role", required=True, parser_class=Parser)

    server = roles.add_parser("server", help="Appendix A.1 selftest server")
    server.add_argument("--port", type=int, default=DEFAULT_PORT)
    server.add_argument("--psk", type=parse_psk, required=True, help="session key, 64 hex digits")
    bad = server.add_mutually_exclusive_group()
    bad.add_argument("--tamper-record", action="store_true", help="flip a bit in the first KEY record")
    bad.add_argument("--replay-record", action="store_true", help="send the first KEY record twice")

    client = roles.add_parser("client", help="Appendix A.2 selftest client")
    client.add_argument("--host", default="127.0.0.1")
    client.add_argument("--port", type=int, default=DEFAULT_PORT)
    client.add_argument("--psk", type=parse_psk, required=True, help="session key, 64 hex digits")
    client.add_argument(
        "--reject-timeout",
        type=float,
        default=HANDSHAKE_TIMEOUT + 3.0,
        help="negative tests: seconds to wait for the server to close (default 8)",
    )
    neg = client.add_mutually_exclusive_group()
    neg.add_argument("--corrupt-finished", action="store_true", help="send a wrong ClientFinished")
    neg.add_argument("--bad-magic", action="store_true", help="send a ClientHello with the wrong magic")
    neg.add_argument("--invalid-point", action="store_true", help="send a public key that is not on P-256")
    neg.add_argument("--stall", action="store_true", help="never send ClientFinished")

    pair_server = roles.add_parser("pair-server", help="Appendix A.3 pairing responder")
    pair_server.add_argument("--port", type=int, default=DEFAULT_PORT)
    pair_server.add_argument("--name", required=True, help="display name sent to the peer")
    pair_server.add_argument("--confirm", choices=["yes", "no"], default="yes")
    neg = pair_server.add_mutually_exclusive_group()
    neg.add_argument("--bad-commit", action="store_true", help="send a commit that does not match mac_nonce")
    neg.add_argument("--corrupt-confirm", action="store_true", help="send a wrong MacConfirm")
    neg.add_argument("--invalid-point", action="store_true", help="send a mac_pub that is not on P-256")

    pair_client = roles.add_parser("pair-client", help="Appendix A.4 pairing initiator")
    pair_client.add_argument("--host", default="127.0.0.1")
    pair_client.add_argument("--port", type=int, default=DEFAULT_PORT)
    pair_client.add_argument("--name", required=True, help="display name sent to the peer")
    pair_client.add_argument("--confirm", choices=["yes", "no"], default="yes")
    neg = pair_client.add_mutually_exclusive_group()
    neg.add_argument("--corrupt-confirm", action="store_true", help="send a wrong PcConfirm")
    neg.add_argument("--invalid-point", action="store_true", help="send a pc_pub that is not on P-256")
    neg.add_argument("--withhold-nonce", action="store_true", help="never send PcNonce")
    return parser


ROLES = {
    "server": run_server,
    "client": run_client,
    "pair-server": run_pair_server,
    "pair-client": run_pair_client,
}


def main(argv: list[str] | None = None) -> int:
    global DEBUG
    args = build_parser().parse_args(argv)
    DEBUG = args.debug
    return ROLES[args.role](args)


if __name__ == "__main__":
    sys.exit(main())
