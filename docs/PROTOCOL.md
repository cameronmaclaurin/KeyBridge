# KeyBridge Protocol v2 (KBP2)

This is the wire protocol between the KeyBridge Mac app (server) and the KeyBridge Windows app (client). Both implementations and the Python reference in `tests/reference/` MUST follow it exactly.

Goals: only a PC that knows the pairing code can receive keystrokes; only a Mac that knows the pairing code can inject keystrokes into the PC; keystrokes are confidential and tamper-proof on the network; recorded traffic stays secret even if the pairing code later leaks (forward secrecy).

Conventions: `||` is byte concatenation. Strings in quotes are ASCII bytes with no terminator. Multi-byte integers are big-endian unless stated otherwise.

---

## 1. Transport

- TCP, port **9876**. Mac listens on all interfaces; Windows connects.
- Both sides set `TCP_NODELAY`.
- One authenticated session at a time. A newly *authenticated* session replaces the old one. An unauthenticated connection never affects the existing session.

## 2. Pairing code

- Alphabet (Crockford Base32, 32 symbols): `0123456789ABCDEFGHJKMNPQRSTVWXYZ`
- Generated on the Mac: 20 symbols, each `alphabet[randomByte & 0x1F]` from a CSPRNG (≈100 bits of entropy).
- Displayed as 4 groups of 5: `ABCDE-FGHJK-MNPQR-STVWX`.
- **Normalization** (applied to user input before use and before storage):
  1. Uppercase.
  2. Remove `-` and all whitespace.
  3. Map `O`→`0`, `I`→`1`, `L`→`1`.
  4. Result must be exactly 20 characters, all in the alphabet; otherwise the code is invalid (show an error, don't connect).
- `psk = HMAC-SHA256(key = "KeyBridge v2 pairing", data = normalized_code)` — 32 bytes.
- Mac stores the code in the Keychain; Windows stores it encrypted with DPAPI (current user).

The pairing code's entropy is load-bearing: an attacker who connects can attempt *offline* guessing against `server_finished`. 100 bits makes that infeasible. Never shorten the code.

## 3. Primitives

| Purpose | Algorithm |
|---|---|
| Key agreement | ECDH on NIST P-256, fresh ephemeral key pair per connection on both sides |
| Public key encoding | Uncompressed X9.63: `0x04 || X(32) || Y(32)` = 65 bytes |
| ECDH output `ecdh` | 32-byte big-endian X coordinate of the shared point |
| Hash | SHA-256 |
| MAC / KDF | HMAC-SHA256 |
| Record cipher | AES-256-GCM, 12-byte nonce, 16-byte tag, empty AAD |
| Randomness | OS CSPRNG (`SecRandomCopyBytes` / CryptoKit, `BCryptGenRandom`) |

KDF helpers (RFC 5869 HKDF with a single output block):

```
Extract(salt, ikm) = HMAC-SHA256(key = salt, data = ikm)
Expand(prk, info)  = HMAC-SHA256(key = prk,  data = info || 0x01)      // = HKDF-Expand(prk, info, 32)
```

## 4. Handshake

```
Client                                              Server
------                                              ------
ClientHello  (101 bytes)  ───────────────────────►
             ◄───────────────────────  ServerHello (133 bytes)
ClientFinished (32 bytes) ───────────────────────►
             ◄═══════════  encrypted records  ═══════════►
```

**ClientHello** (101 bytes) = `"KBR2" || client_pub(65) || client_nonce(32)`

**ServerHello** (133 bytes) = `"KBR2" || server_pub(65) || server_nonce(32) || server_finished(32)`

Let `SH_prefix` = the first 101 bytes of ServerHello (everything before `server_finished`).

**Key schedule** (both sides compute identically):

```
ecdh  = ECDH(own_ephemeral_private, peer_pub)
prk   = Extract(salt = psk, ikm = ecdh)

TH1   = SHA-256(ClientHello || SH_prefix)
TH2   = SHA-256(ClientHello || ServerHello)            // full 133-byte ServerHello

server_finished = HMAC-SHA256(key = Expand(prk, "KBR2 server finished"), data = TH1)
client_finished = HMAC-SHA256(key = Expand(prk, "KBR2 client finished"), data = TH2)

k_s2c = Expand(prk, "KBR2 traffic s2c" || TH2)         // AES-256 key, Mac → PC
k_c2s = Expand(prk, "KBR2 traffic c2s" || TH2)         // AES-256 key, PC → Mac
```

**Server steps**

1. Read exactly 101 bytes (timeout 5 s from accept). Check magic `"KBR2"`; parse `client_pub` (must be a valid P-256 point; reject otherwise).
2. Generate ephemeral key pair and 32-byte `server_nonce`; compute `ecdh`, `prk`, `TH1`, `server_finished`; send ServerHello.
3. Read exactly 32 bytes (`ClientFinished`) within the same 5 s window. Compare to expected `client_finished` in **constant time**.
4. Mismatch, bad magic, invalid point, or timeout → close the socket silently. Nothing else is sent.
5. Match → session is authenticated. Derive traffic keys. It now replaces any existing session.

**Client steps**

1. Generate ephemeral key pair and 32-byte `client_nonce`; send ClientHello.
2. Read exactly 133 bytes (timeout 5 s). Check magic; parse `server_pub`; compute keys; verify `server_finished` in **constant time**.
3. Mismatch → close; report **"Pairing code doesn't match"** to the user. Do not send ClientFinished.
4. Match → send ClientFinished; derive traffic keys; session is authenticated.

**Limits**: the server keeps at most **4** unauthenticated connections at once; additional ones are closed immediately.

## 5. Records

After the handshake every message in either direction is a fixed **20-byte record**:

```
record = AES-256-GCM-Seal(key, nonce, plaintext(4), aad = empty)  →  ciphertext(4) || tag(16)
nonce  = 0x00000000 || seq                                         // seq: uint64 big-endian
```

- Each direction has its own key (`k_s2c` / `k_c2s`) and its own `seq`, starting at **0** and incrementing by 1 per record sent. The receiver tracks the expected `seq` for the peer's direction.
- Any authentication failure on decrypt → close the connection immediately.

**Plaintext** (4 bytes) = `type || b1 || b2 || b3`

| type | Name | Direction | Fields |
|---|---|---|---|
| `0x01` | KEY | Mac → PC | `b1` = flags (bit0 = key down, bit1 = extended key), `b2` = VK low byte, `b3` = VK high byte (Windows virtual-key code, little-endian) |
| `0x02` | PING | Mac → PC | zero |
| `0x03` | PONG | PC → Mac | zero; sent in reply to every PING |
| `0x04` | RELEASE_ALL | Mac → PC | zero; PC releases every key it is currently holding down |

- Unknown types are ignored (forward compatibility).
- PC ignores KEY records with VK outside `1..254`.
- **Graceful close**: to end a session, stop sending, half-close the write side (`shutdown(SD_SEND)` / Network.framework final message), read and discard until EOF or a 1 s timeout, then close. Closing with unread data in the receive buffer makes TCP send an RST, which can destroy records still in flight (such as a final RELEASE_ALL).
- PC tracks which VKs it has injected as down; it releases all of them on RELEASE_ALL, on disconnect, and on quit, so keys never stick.

## 6. Liveness

- Mac sends PING every **2 s** while a session is authenticated.
- PC: if no record arrives for **6 s**, close, release all keys, reconnect.
- Mac: if no record (PONG) arrives for **6 s**, close the session (and leave Windows mode if active).
- PC reconnect backoff: 1 s, 2 s, 4 s, 8 s, then every 10 s; reset after a successful handshake. After a "pairing code doesn't match" failure, retry no faster than every 10 s.

## 7. Security properties and limits

- **Mutual authentication** by the shared pairing code; neither side sends anything that depends on keystrokes before the other side has proven knowledge of the code.
- **Confidentiality and integrity** of every record (AES-GCM); **replay/reorder protection** (per-direction counters, fresh keys per session).
- **Forward secrecy** (ephemeral ECDH per connection).
- **Not hidden**: that KeyBridge is in use, and keystroke *timing* (one fixed-size record per key event).
- Ephemeral keys are used once, so invalid-curve leaks are limited to a discarded key; implementations should still reject invalid points.

---

## Appendix A. Conformance test hooks

Shipping builds MUST NOT contain these hooks. They are compiled only with the `KEYBRIDGE_SELFTEST` define (`swift build -Xswiftc -DKEYBRIDGE_SELFTEST`, MSVC `/DKEYBRIDGE_SELFTEST`). They must use the same handshake/record code as the real app.

### A.1 Selftest server (Mac selftest build and Python reference)

`KeyBridge --selftest-server --port <P> --code <CODE>`
`python tests/reference/kbp2.py server --port <P> --code <CODE>`

- Listen on `127.0.0.1:<P>`; print `LISTENING` on its own line to stdout and flush once ready.
- Accept exactly one connection and run the server handshake.
- After authentication send, in order:
  1. KEY flags=`0x01` vk=`0x0041`
  2. KEY flags=`0x00` vk=`0x0041`
  3. KEY flags=`0x03` vk=`0x000D`
  4. KEY flags=`0x02` vk=`0x000D`
  5. PING
- Wait up to 3 s for a PONG; then send RELEASE_ALL; then close gracefully (section 5).
- Exit codes: `0` success, `2` handshake failed (bad magic, invalid point, bad ClientFinished, timeout), `3` no valid PONG (timeout, client closed, or a client record failed authentication).

### A.2 Selftest client (Windows selftest build and Python reference)

`KeyBridge-selftest.exe --selftest-client --host <H> --port <P> --code <CODE>`
`python tests/reference/kbp2.py client --host <H> --port <P> --code <CODE>`

Runs the client handshake, replies PONG to each PING, does **not** inject keys, and prints one line per event to stdout:

```
HANDSHAKE OK
KEY down=1 ext=0 vk=0x0041
KEY down=0 ext=0 vk=0x0041
KEY down=1 ext=1 vk=0x000D
KEY down=0 ext=1 vk=0x000D
PING
RELEASE_ALL
CLOSED
```

- `vk` is printed as `0x` + 4 uppercase hex digits. KEY records with VK outside `1..254` are ignored and not printed.
- Any failure during the handshake (bad magic, invalid point, `server_finished` mismatch, timeout) → print `HANDSHAKE FAILED`, exit `2`.
- Any failure after `HANDSHAKE OK` (record authentication failure, liveness timeout, socket error) → close, write the reason to **stderr** (stdout carries only transcript lines), exit `1`.
- Otherwise exit `0` after printing `CLOSED` when the server closes the connection.
