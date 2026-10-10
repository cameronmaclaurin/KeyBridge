# KeyBridge Protocol v2 (KBP2)

This is the wire protocol between the KeyBridge Mac app (server) and the KeyBridge Windows app (client). Both implementations and the Python reference in `tests/reference/` MUST follow it exactly.

Goals: only the paired PC can receive keystrokes; only the paired Mac can inject keystrokes into the PC; keystrokes are confidential and tamper-proof on the network; recorded traffic stays secret even if the long-term pairing key later leaks (forward secrecy).

There are two sub-protocols on the same port, told apart by the first 4 bytes the client sends:

| Magic | Sub-protocol | When |
|---|---|---|
| `"KBPR"` | **Pairing** (section 2): Bluetooth-style numeric comparison that produces a 32-byte long-term key | Once, when the user pairs |
| `"KBR2"` | **Session** (sections 4–6): authenticated, encrypted keystroke stream using that key as `psk` | Every connection after pairing |

Conventions: `||` is byte concatenation. Strings in quotes are ASCII bytes with no terminator. Multi-byte integers are big-endian unless stated otherwise.

---

## 1. Transport

- TCP, port **9876**. Mac listens on all interfaces; Windows connects.
- Both sides set `TCP_NODELAY`.
- One authenticated session at a time. A newly *authenticated* session replaces the old one. An unauthenticated connection never affects the existing session.
- The server reads the first 4 bytes and dispatches on the magic; anything else → close.

## 1a. Discovery (Bonjour / mDNS)

So users can pick their Mac from a list instead of typing an address:

- The Mac advertises a DNS-SD service while the app runs: type **`_keybridge._tcp`**, domain `local.`, port **9876**, instance name = the Mac's computer name (e.g. "Cameron's MacBook Air"), TXT record `v=2`. (macOS: `NWListener.service`; Info.plist `NSBonjourServices` = `_keybridge._tcp`.)
- The PC browses `_keybridge._tcp.local` (Windows 10+: `DnsServiceBrowse` / `DnsServiceResolve` from `windns.h`, loaded at runtime with `GetProcAddress` so the app still works without them), lists instances by name, and resolves the chosen one to its host name (`Name.local`) and port. The PC stores the **host name**, not the IP, so a changing IP doesn't break reconnects.
- Manual entry (host name, IP, or `host:port`) always remains available.
- Discovery is **not trusted**: anyone can advertise any name. Security comes only from pairing (section 2) and the session handshake. The UI shows the Mac's name again on the compare screen so the user can confirm it.

## 2. Pairing (numeric comparison)

The PC (initiator) and Mac (responder) run an unauthenticated ECDH exchange with a hash commitment, both display the same 6-digit number, and the user confirms on **both** machines that the numbers match. The commitment means a man-in-the-middle cannot choose values that make the two numbers match; each attempt succeeds with probability 1 in 1,000,000, and every attempt needs the user to click Confirm. This is the design of Bluetooth LE Secure Connections "Numeric Comparison".

### 2.1 When pairing is allowed

- **Mac** accepts `"KBPR"` connections only while in **pairing mode**: the user opened the Pairing window, it is still open, and fewer than 3 minutes have passed since pairing mode started (the window offers "Start Again"). Pairing mode ends on success, on cancel, on timeout, or when the window closes. Outside pairing mode a `"KBPR"` connection is closed immediately. At most **one** pairing connection at a time; others are closed immediately.
- **PC** starts pairing only when the user clicks **Pair** in its setup window.

### 2.2 Messages

Names are the device's display name (Mac: computer name; PC: computer name) as UTF-8, truncated at a character boundary to at most 64 bytes, then NUL-padded to exactly 64 bytes. Receivers display the bytes up to the first NUL, decoded leniently, with control characters removed.

```
PC                                                 Mac
PairHello   (133)  "KBPR" || pc_pub(65) || pc_name(64)            ──►
            ◄──  PairCommit (165)  "KBPR" || mac_pub(65) || mac_name(64) || commit(32)
PcNonce     (32)   pc_nonce                                       ──►
            ◄──  MacNonce   (32)   mac_nonce
            [both compute and show the 6-digit number; users confirm]
PcConfirm   (32)   sent when the PC user clicks Confirm           ──►
            ◄──  MacConfirm (32)   sent when the Mac user clicks Confirm
```

- Each side generates a fresh P-256 key pair and a fresh 32-byte nonce per attempt.
- `commit = HMAC-SHA256(key = mac_nonce, data = "KBPR commit" || mac_pub || pc_pub)`
- The PC sends `pc_nonce` only **after** receiving PairCommit, and the Mac sends `mac_nonce` only **after** receiving `pc_nonce`. Both orderings are required: either nonce revealed early lets a man-in-the-middle search for matching numbers. The PC verifies `commit` (constant time) after receiving `mac_nonce` and aborts on mismatch.
- PcConfirm and MacConfirm may cross on the wire in either order; each side sends its own when its user clicks Confirm and independently waits for the peer's.

### 2.3 Derivations

```
TH          = SHA-256(PairHello || PairCommit || pc_nonce || mac_nonce)
ecdh        = ECDH(own_private, peer_pub)                      // as in section 3
sas         = uint32_be(SHA-256("KBPR sas" || TH)[0..4]) mod 1000000
prk         = Extract(salt = TH, ikm = ecdh)
ltk         = Expand(prk, "KBPR long-term key")                // 32 bytes → the session psk
pc_confirm  = HMAC-SHA256(key = Expand(prk, "KBPR pc confirm"),  data = TH)
mac_confirm = HMAC-SHA256(key = Expand(prk, "KBPR mac confirm"), data = TH)
```

Display `sas` as 6 digits with leading zeros, grouped `482 913`.

### 2.4 Completion

- A side **stores** `ltk` only when (a) its own user clicked Confirm **and** (b) it received the peer's confirm value and it verified (constant time). Then it closes gracefully (section 5).
- Cancel, a wrong confirm value, a bad magic or invalid point, the peer closing, or a timeout → close without storing anything and show "Pairing didn't complete".
- Timeouts: PairHello through MacNonce must complete within **10 s** of connecting; the confirmation phase allows **120 s**, counted from when MacNonce is sent/received. Pairing mode expiring (2.1) stops new pairing connections but does not cancel one already in progress. The pairing slot is separate from the 4 unauthenticated session slots.
- A successful pairing **replaces** any previous pairing on that device (the Mac pairs with one PC; the PC pairs with one Mac). The Mac also drops any current session.

### 2.5 Storage

- Mac: Keychain generic password, service `com.keybridge.app`, account `pairing-key`, value = `ltk` (32 raw bytes), plus the PC's display name for the UI. Remove any v1.1 `pairing-code` item.
- PC: DPAPI (current user) over the Mac's address (the resolved Bonjour host name when picked from the list, otherwise what the user typed), the Mac's display name, and `ltk`.
- "Forget" on either side deletes its stored key. The other side's session handshake then fails (`server_finished` / ClientFinished mismatch) and the PC tells the user to pair again.

### 2.6 Notes

- v1.1 typed-code pairing is gone; v1.1 users pair once more after upgrading.
- The 6-digit number is **not** a secret and is never typed; it only lets the user detect a man-in-the-middle. Users must actually compare it, so the UI says so plainly.

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
prk   = Extract(salt = psk, ikm = ecdh)                 // psk = ltk from pairing (section 2)

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
3. Mismatch → close; report **"Not paired with this Mac — pair again"** to the user. Do not send ClientFinished.
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
- PC reconnect backoff: 1 s, 2 s, 4 s, 8 s, then every 10 s; reset after a successful handshake. After a `server_finished` mismatch, stop retrying and ask the user to pair again (retry only on user action or app restart).

## 7. Security properties and limits

- **Mutual authentication** by the long-term key from pairing; neither side sends anything that depends on keystrokes before the other side has proven knowledge of it.
- **Pairing** resists man-in-the-middle attacks with probability 1 − 10⁻⁶ per attempt, provided the user really compares the numbers; it needs no secret to be typed.
- **Confidentiality and integrity** of every record (AES-GCM); **replay/reorder protection** (per-direction counters, fresh keys per session).
- **Forward secrecy** (ephemeral ECDH per connection).
- **Not hidden**: that KeyBridge is in use, and keystroke *timing* (one fixed-size record per key event).
- Ephemeral keys are used once, so invalid-curve leaks are limited to a discarded key; implementations should still reject invalid points.

---

## Appendix A. Conformance test hooks

Shipping builds MUST NOT contain these hooks. They are compiled only with the `KEYBRIDGE_SELFTEST` define (`swift build -Xswiftc -DKEYBRIDGE_SELFTEST`, MSVC `/DKEYBRIDGE_SELFTEST`). They must use the same handshake/record code as the real app.

### A.1 Selftest server (Mac selftest build and Python reference)

`KeyBridge --selftest-server --port <P> --psk <64 hex chars>`
`python tests/reference/kbp2.py server --port <P> --psk <64 hex chars>`

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

`KeyBridge-selftest.exe --selftest-client --host <H> --port <P> --psk <64 hex chars>`
`python tests/reference/kbp2.py client --host <H> --port <P> --psk <64 hex chars>`

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

`--psk` is the 32-byte key as 64 hex characters (case-insensitive); anything else is a usage error (exit 64).

### A.3 Pairing selftest responder (Mac selftest build and Python reference)

`KeyBridge --selftest-pair-server --port <P> --name <NAME> [--confirm yes|no]`
`python tests/reference/kbp2.py pair-server --port <P> --name <NAME> [--confirm yes|no]`

- Always in pairing mode. Listen on `127.0.0.1:<P>`; print `LISTENING` and flush; accept exactly one connection.
- Run the responder side of section 2. After MacNonce is sent, print `SAS dddddd` (6 digits, no space).
- `--confirm yes` (default): send MacConfirm immediately, wait for PcConfirm, then print `PAIRED <ltk as 64 lowercase hex>`, close gracefully, exit `0`.
- `--confirm no`: print `CANCELLED`, close, exit `0`.
- Any failure (bad magic, invalid point, wrong PcConfirm, peer closed, timeout) → print `PAIR FAILED`, exit `2`. Usage error → exit `64`.

### A.4 Pairing selftest initiator (Windows selftest build and Python reference)

`KeyBridge-selftest.exe --selftest-pair-client --host <H> --port <P> --name <NAME> [--confirm yes|no]`
`python tests/reference/kbp2.py pair-client --host <H> --port <P> --name <NAME> [--confirm yes|no]`

- Run the initiator side of section 2. After verifying `commit`, print `SAS dddddd`.
- `--confirm yes` (default): send PcConfirm immediately, wait for MacConfirm, then print `PAIRED <ltk hex>`, close gracefully, exit `0`.
- `--confirm no`: print `CANCELLED`, close, exit `0`.
- Any failure (bad magic, invalid point, commit mismatch, wrong MacConfirm, peer closed, timeout) → print `PAIR FAILED`, exit `2`. Usage error → exit `64`.

An end-to-end conformance run pairs with A.3/A.4, checks both sides printed the same `SAS` and `PAIRED` values, then runs A.1/A.2 with `--psk` set to that `ltk`.

### A.5 Discovery selftest (Windows selftest build)

`KeyBridge-selftest.exe --selftest-discover [--timeout <seconds, default 5>]`

Browses `_keybridge._tcp.local` for the timeout and prints one line per resolved instance, then exits `0`:

```
FOUND name=<instance name> host=<host name> port=<port>
```

Exit `3` if the DNS-SD APIs aren't available on this Windows build. (CI advertises a test instance with python-zeroconf and checks it is found.)
