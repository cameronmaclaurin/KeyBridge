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

Clipboard (spec 5a, A.1/A.2), for both server and client:

  --clip-file PATH    send the file's bytes as one clipboard transfer (16384-byte
                      chunks, transfer_id 0) once the peer's CAPS has bit0 set.
                      The bytes are sent as they are (no UTF-8 check), so a test
                      can send anything; a file over 1,048,576 bytes is not sent
                      at all (spec 5a) unless --clip-ignore-limit is given.
  Received transfers are printed as  CLIP <byte length> <sha256 hex>.

Compatibility options (not part of the spec; used by tests/interop/):

  --caps N            advertise CAPS b1 = N instead of 1 (0 = "sharing off"; the
                      reference then sends no DATA itself).
  --no-caps           never send CAPS, like a v1.4 peer.
      In both cases the reference still decodes and prints any transfer it
      receives, so a test can see a peer that sent DATA it should not have.

Negative-test options (not part of the spec; used by tests/interop/):

  server|client, each needs --clip-file (at most one of them):
  --clip-ignore-limit   send the file even if it is over 1,048,576 bytes.
      A correct receiver discards the transfer (no CLIP line).
  --clip-no-first       clear the `first` flag on the transfer's first chunk.
      A correct receiver discards every chunk of it (no CLIP line).
  --clip-wrong-id       right after the first chunk, insert a stray chunk with
      flags `last` and transfer_id 1 (the real transfer uses 0). A correct
      receiver discards the stray chunk and prints the file's normal CLIP line.
      (Use a file longer than 16384 bytes, so the transfer is still in progress.)
  --clip-invalid-utf8   insert a 0xFF byte in the middle of the file's bytes.
      A correct receiver discards the transfer (no CLIP line).
  --clip-corrupt-chunk  flip one tag bit in the first sealed chunk, then send
      no more chunks. A correct receiver closes the connection at once.


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
import select
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
TYPE_DATA = 0x05
TYPE_CAPS = 0x06

FLAG_DOWN = 0x01
FLAG_EXTENDED = 0x02

# Capabilities and data (spec 5a)
CAP_CLIPBOARD_TEXT = 0x01  # CAPS b1 bit0: "I can receive clipboard text"
CHUNK_HEADER_LEN = 4  # kind(1) || flags(1) || transfer_id(2)
CHUNK_PAYLOAD_MAX = 16384
CHUNK_MIN = CHUNK_HEADER_LEN + 1  # 5: N in the DATA header
CHUNK_MAX = CHUNK_HEADER_LEN + CHUNK_PAYLOAD_MAX  # 16388
KIND_CLIPBOARD_TEXT = 0x01
CHUNK_FIRST = 0x01
CHUNK_LAST = 0x02
CLIP_MAX = 1_048_576  # bytes of UTF-8 per transfer

LIVENESS_TIMEOUT = 6.0  # seconds without any record
PONG_WAIT = 3.0  # A.1: wait up to 3 s for a PONG
CLIP_GRACE = 1.0  # A.1: after the PONG, at most 1 s more for a transfer in progress
CAPS_WAIT = 2.0  # A.1 step 4a: how long the server waits for the client's CAPS (not in the spec)

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
    """Fixed 20-byte AES-256-GCM records with per-direction 64-bit counters (spec 5),
    plus the variable-length sealed chunk that follows each DATA header (spec 5a)."""

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

    def send_data(self, chunk: bytes, corrupt: bool = False) -> None:
        """Spec 5a: a DATA header (one seq) immediately followed by the sealed chunk (the next seq).

        Both go out in one sendall, so nothing can come between them.
        corrupt=True flips one tag bit of the sealed chunk (negative tests).
        """
        n = len(chunk)
        assert CHUNK_MIN <= n <= CHUNK_MAX
        header = self.seal(bytes([TYPE_DATA, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF]))
        sealed = self._send.encrypt(self.nonce(self.send_seq), chunk, None)
        self.send_seq += 1
        assert len(sealed) == n + RECORD_TAG_LEN
        if corrupt:
            sealed = sealed[:-1] + bytes([sealed[-1] ^ 0x01])
        self.sock.settimeout(HANDSHAKE_TIMEOUT)
        self.sock.sendall(header + sealed)

    def readable(self, timeout: float) -> bool:
        """True if a byte (or EOF) can be read within `timeout` seconds. Consumes nothing."""
        ready, _, _ = select.select([self.sock], [], [], max(0.0, timeout))
        return bool(ready)

    def _open(self, sealed: bytes, what: str) -> bytes:
        try:
            plaintext = self._recv.decrypt(self.nonce(self.recv_seq), sealed, None)
        except InvalidTag:
            raise RecordError(f"{what} {self.recv_seq} failed authentication") from None
        self.recv_seq += 1
        return plaintext

    def recv(self, timeout: float | None) -> bytes | None:
        """Next message, or None if the peer closed cleanly on a record boundary.

        A message is the 4-byte record plaintext; for DATA it is the header's 4 bytes
        followed by the chunk plaintext. Waits up to `timeout` for the message to
        start (TimeoutError, nothing consumed); once it has started, the rest must
        arrive within HANDSHAKE_TIMEOUT. Raises RecordError on a bad tag, a bad
        chunk length or a truncated record/chunk: the caller must close.
        """
        if timeout is not None and not self.readable(timeout):
            raise TimeoutError(f"nothing received for {timeout:.1f} s")
        deadline = time.monotonic() + HANDSHAKE_TIMEOUT
        try:
            record = recv_exact(self.sock, RECORD_LEN, deadline)
        except PeerClosed as exc:
            if exc.received == 0:
                return None
            raise RecordError(f"truncated record: {exc}") from None
        except TimeoutError as exc:
            raise RecordError(f"stalled inside a record: {exc}") from None
        plaintext = self._open(record, "record")
        if plaintext[0] != TYPE_DATA:
            return plaintext

        # Spec 5a: the sealed chunk follows immediately and uses the next seq.
        n = int.from_bytes(plaintext[1:4], "big")
        if not CHUNK_MIN <= n <= CHUNK_MAX:
            raise RecordError(f"DATA header announces a {n}-byte chunk (allowed {CHUNK_MIN}..{CHUNK_MAX})")
        try:
            sealed = recv_exact(self.sock, n + RECORD_TAG_LEN, deadline)
        except (PeerClosed, TimeoutError) as exc:
            raise RecordError(f"truncated DATA chunk: {exc}") from None
        return plaintext + self._open(sealed, "DATA chunk")


def key_record(flags: int, vk: int) -> tuple[int, int, int, int]:
    return (TYPE_KEY, flags, vk & 0xFF, (vk >> 8) & 0xFF)


# ---------------------------------------------------------------------------
# Clipboard transfers (spec 5a)
# ---------------------------------------------------------------------------


def clip_line(text: bytes) -> str:
    """A.1/A.2 stdout line for a completed clipboard transfer."""
    return f"CLIP {len(text)} {hashlib.sha256(text).hexdigest()}"


def make_chunk(flags: int, transfer_id: int, payload: bytes, kind: int = KIND_CLIPBOARD_TEXT) -> bytes:
    """Chunk plaintext = kind(1) || flags(1) || transfer_id(2, big-endian) || payload."""
    return bytes([kind, flags]) + (transfer_id & 0xFFFF).to_bytes(2, "big") + payload


def clip_chunks(text: bytes, transfer_id: int) -> list[bytes]:
    """Split one transfer into chunks of at most 16384 payload bytes with first/last flags.

    Empty text gives no chunks: a chunk carries at least one payload byte (N >= 5).
    """
    pieces = [text[i : i + CHUNK_PAYLOAD_MAX] for i in range(0, len(text), CHUNK_PAYLOAD_MAX)]
    chunks = []
    for index, piece in enumerate(pieces):
        flags = (CHUNK_FIRST if index == 0 else 0) | (CHUNK_LAST if index == len(pieces) - 1 else 0)
        chunks.append(make_chunk(flags, transfer_id, piece))
    return chunks


class ClipReceiver:
    """Reassembly rules of spec 5a. feed() returns the complete text, or None."""

    def __init__(self) -> None:
        self.active = False  # saw a `first` and no `last` yet (A.1: "a transfer in progress")
        self.transfer_id: int | None = None
        self.buffer: bytearray | None = None  # None while an oversized transfer is being ignored

    def feed(self, chunk: bytes) -> bytes | None:
        kind, flags = chunk[0], chunk[1]
        transfer_id = int.from_bytes(chunk[2:4], "big")
        payload = chunk[CHUNK_HEADER_LEN:]
        if kind != KIND_CLIPBOARD_TEXT:
            log(f"ignoring a DATA chunk of unknown kind 0x{kind:02x}")  # decrypted already, so still in sync
            return None
        if flags & CHUNK_FIRST:
            if self.active:
                log(f"transfer {transfer_id} starts; abandoning unfinished transfer {self.transfer_id}")
            self.active, self.transfer_id, self.buffer = True, transfer_id, bytearray()
        elif not self.active or transfer_id != self.transfer_id:
            log(f"discarding a chunk of transfer {transfer_id}: that transfer is not in progress")
            return None
        if self.buffer is not None and len(self.buffer) + len(payload) > CLIP_MAX:
            log(f"transfer {transfer_id} exceeds {CLIP_MAX} bytes; discarding it")
            self.buffer = None  # ignore its chunks until the next `first`
        if self.buffer is not None:
            self.buffer += payload
        if not flags & CHUNK_LAST:
            return None
        self.active = False
        text, self.buffer = self.buffer, None
        if text is None:
            return None
        try:
            bytes(text).decode("utf-8")
        except UnicodeDecodeError:
            log(f"discarding transfer {transfer_id}: not valid UTF-8")
            return None
        return bytes(text)


def send_clip(records: RecordLayer, args: argparse.Namespace, transfer_id: int, between) -> None:
    """Send args.clip_file as one transfer (spec 5a), applying any --clip-* negative option.

    between() runs after each header+chunk pair (the sender "yields", so the
    peer's records are read and answered); it returns False once the peer closed.
    """
    text = args.clip_file
    if args.clip_invalid_utf8:
        middle = len(text) // 2
        text = text[:middle] + b"\xff" + text[middle:]
        log("negative test: the transfer contains a 0xFF byte (invalid UTF-8)")
    if not text:
        log("--clip-file is empty: nothing to send (a chunk carries at least one byte)")
        return
    if len(text) > CLIP_MAX and not args.clip_ignore_limit:
        log(f"--clip-file is {len(text)} bytes, over {CLIP_MAX}: not sent (spec 5a)")
        return
    for index, chunk in enumerate(clip_chunks(text, transfer_id)):
        if index == 0 and args.clip_no_first:
            chunk = chunk[:1] + bytes([chunk[1] & ~CHUNK_FIRST]) + chunk[2:]
            log("negative test: the first chunk has no `first` flag")
        corrupt = index == 0 and args.clip_corrupt_chunk
        records.send_data(chunk, corrupt=corrupt)
        if corrupt:
            log("negative test: sent DATA chunk 0 with a flipped tag bit")
            return  # the peer must close now
        if index == 0 and args.clip_wrong_id:
            records.send_data(make_chunk(CHUNK_LAST, transfer_id + 1, b"stray chunk"))
            log(f"negative test: inserted a stray `last` chunk with transfer_id {transfer_id + 1}")
        if not between():
            log("peer closed during the transfer")
            return


def may_send_clip(args: argparse.Namespace, peer_caps: int | None) -> bool:
    """Spec 5a: send DATA only if the peer advertised clipboard text and sharing is on here."""
    sharing_on = not args.no_caps and bool(args.caps & CAP_CLIPBOARD_TEXT)
    return args.clip_file is not None and sharing_on and peer_caps is not None and bool(peer_caps & CAP_CLIPBOARD_TEXT)


class Peer:
    """Record dispatch shared by the selftest server and client."""

    def __init__(self, records: RecordLayer, on_record):
        self.records = records
        self.on_record = on_record  # called with each non-DATA plaintext
        self.clip = ClipReceiver()
        self.caps: int | None = None  # the peer's CAPS b1, once received
        self.closed = False

    def handle(self, message: bytes | None) -> None:
        if message is None:
            self.closed = True
            return
        if message[0] == TYPE_DATA:
            text = self.clip.feed(message[RECORD_PLAINTEXT_LEN:])
            if text is not None:
                out(clip_line(text))
            return
        if message[0] == TYPE_CAPS:
            self.caps = message[1]
        self.on_record(message)

    def pump(self, until, timeout: float) -> None:
        """Read and handle messages until until() is true, the peer closes, or `timeout` passes."""
        deadline = time.monotonic() + timeout
        while not until() and not self.closed:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            try:
                message = self.records.recv(remaining)
            except TimeoutError:
                return
            self.handle(message)

    def drain(self) -> bool:
        """Handle whatever has already arrived, without waiting. False once the peer closed."""
        while not self.closed and self.records.readable(0):
            self.handle(self.records.recv(None))
        return not self.closed


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
    pong = []
    peer = Peer(records, lambda message: pong.append(True) if message[0] == TYPE_PONG else None)
    try:
        try:
            # 0. CAPS, the first record after authentication (spec 5a).
            if not args.no_caps:
                records.send(TYPE_CAPS, args.caps)
            # 1.-4. KEY records.
            for index, (flags, vk) in enumerate(SELFTEST_KEYS):
                record = records.seal(bytes(key_record(flags, vk)))
                if index == 0 and args.tamper_record:
                    record = record[:-1] + bytes([record[-1] ^ 0x01])
                    log("negative test: sent KEY record 0 with a flipped tag bit")
                conn.sendall(record)
                if index == 0 and args.replay_record:
                    conn.sendall(record)
                    log("negative test: replayed KEY record 0")
            # 4a. The clipboard transfer, once the client's CAPS says it can receive it.
            if args.clip_file is not None and may_send_clip(args, CAP_CLIPBOARD_TEXT):
                peer.pump(lambda: peer.caps is not None, CAPS_WAIT)
                if may_send_clip(args, peer.caps):
                    send_clip(records, args, transfer_id=0, between=peer.drain)
                else:
                    log(f"client CAPS is {peer.caps}: no clipboard transfer")
            # 5. PING.
            records.send(TYPE_PING)
        except OSError as exc:
            log(f"peer went away while sending: {exc}")

        # Wait up to 3 s for the PONG, then at most 1 s more for a transfer in progress.
        try:
            peer.pump(lambda: bool(pong), PONG_WAIT)
            if pong and peer.clip.active:
                peer.pump(lambda: not peer.clip.active, CLIP_GRACE)
        except OSError as exc:
            log(f"socket error waiting for PONG: {exc}")
    except RecordError as exc:
        log(f"closing: {exc}")
        conn.close()
        return EXIT_NO_PONG
    if not pong:
        log("peer closed before PONG" if peer.closed else f"no PONG within {PONG_WAIT:.0f} s")

    try:
        records.send(TYPE_RELEASE_ALL)
    except OSError as exc:
        log(f"could not send RELEASE_ALL: {exc}")
    graceful_close(conn)
    return EXIT_OK if pong else EXIT_NO_PONG


# ---------------------------------------------------------------------------
# Selftest client (Appendix A.2) and negative-test clients
# ---------------------------------------------------------------------------


def format_event(plaintext: bytes) -> str | None:
    """A.2 stdout line for a received record, or None if it is ignored."""
    type_, b1, b2, b3 = plaintext[:RECORD_PLAINTEXT_LEN]
    if type_ == TYPE_CAPS:
        return f"CAPS {b1}"
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
    clip_sent = False

    def on_record(plaintext: bytes) -> None:
        nonlocal clip_sent
        line = format_event(plaintext)
        if line is not None:
            out(line)
        if plaintext[0] == TYPE_PING:
            try:
                records.send(TYPE_PONG)
            except OSError as exc:
                log(f"could not send PONG: {exc}")
        elif plaintext[0] == TYPE_CAPS and not clip_sent and may_send_clip(args, peer.caps):
            clip_sent = True  # A.2: one transfer, right after the server's CAPS arrives
            try:
                send_clip(records, args, transfer_id=0, between=peer.drain)
            except OSError as exc:
                log(f"could not send the clipboard transfer: {exc}")

    peer = Peer(records, on_record)
    try:
        # Spec 5a: CAPS is the client's first record, right after ClientFinished.
        if not args.no_caps:
            records.send(TYPE_CAPS, args.caps)
        while not peer.closed:
            peer.handle(records.recv(LIVENESS_TIMEOUT))
    except TimeoutError:  # before OSError: TimeoutError is an OSError
        log(f"no record for {LIVENESS_TIMEOUT:.0f} s, closing")
        return EXIT_ERROR
    except RecordError as exc:
        log(f"closing: {exc}")
        return EXIT_ERROR
    except OSError as exc:
        log(f"socket error: {exc}")
        return EXIT_ERROR
    out("CLOSED")
    return EXIT_OK


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


def read_clip_file(path: str) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as exc:
        raise argparse.ArgumentTypeError(f"cannot read --clip-file: {exc}") from None


def caps_byte(text: str) -> int:
    try:
        value = int(text, 0)
    except ValueError:
        value = -1
    if not 0 <= value <= 255:
        raise argparse.ArgumentTypeError(f"--caps must be 0..255, got {text!r}")
    return value


CLIP_NEGATIVE = ("clip_ignore_limit", "clip_no_first", "clip_wrong_id", "clip_invalid_utf8", "clip_corrupt_chunk")


def add_clip_options(role: argparse.ArgumentParser) -> None:
    """Spec 5a / A.1 / A.2 clipboard options, shared by server and client."""
    role.add_argument("--clip-file", type=read_clip_file, metavar="PATH", help="clipboard text to send (UTF-8 bytes)")
    role.add_argument("--caps", type=caps_byte, default=CAP_CLIPBOARD_TEXT, help="CAPS b1 to advertise (default 1)")
    role.add_argument("--no-caps", action="store_true", help="never send CAPS (behave like a v1.4 peer)")
    neg = role.add_mutually_exclusive_group()
    neg.add_argument("--clip-ignore-limit", action="store_true", help="send --clip-file even if over 1,048,576 bytes")
    neg.add_argument("--clip-no-first", action="store_true", help="clear `first` on the first chunk")
    neg.add_argument("--clip-wrong-id", action="store_true", help="insert a stray `last` chunk with transfer_id 1")
    neg.add_argument("--clip-invalid-utf8", action="store_true", help="insert a 0xFF byte into the transfer")
    neg.add_argument("--clip-corrupt-chunk", action="store_true", help="flip a tag bit in the first sealed chunk")


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
    add_clip_options(server)

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
    add_clip_options(client)

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
    parser = build_parser()
    args = parser.parse_args(argv)
    DEBUG = args.debug
    if args.role in ("server", "client") and args.clip_file is None:
        for name in CLIP_NEGATIVE:
            if getattr(args, name):
                parser.error(f"--{name.replace('_', '-')} needs --clip-file")
    return ROLES[args.role](args)


if __name__ == "__main__":
    sys.exit(main())
