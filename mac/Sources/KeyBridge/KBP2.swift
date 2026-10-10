import CryptoKit
import Foundation
import Security

// KeyBridge Protocol v2 (KBP2) — pure protocol and crypto, no networking or UI.
// docs/PROTOCOL.md is the source of truth; section numbers below refer to it.

enum KBP2 {
    static let port: UInt16 = 9876

    static let magic: [UInt8] = Array("KBR2".utf8)
    static let clientHelloLength = 101          // magic(4) + pub(65) + nonce(32)
    static let serverHelloLength = 133          // magic(4) + pub(65) + nonce(32) + finished(32)
    static let serverHelloPrefixLength = 101
    static let clientFinishedLength = 32
    static let recordLength = 20                // ciphertext(4) + tag(16)

    static let handshakeTimeout: TimeInterval = 5
    static let pingInterval: TimeInterval = 2
    static let livenessTimeout: TimeInterval = 6
    static let maxUnauthenticated = 4

    enum RecordType: UInt8 {
        case key = 0x01
        case ping = 0x02
        case pong = 0x03
        case releaseAll = 0x04
    }
}

// MARK: - §2 Pairing code

enum PairingCode {
    static let alphabet: [Character] = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
    static let length = 20

    /// 20 symbols, each `alphabet[randomByte & 0x1F]` from the OS CSPRNG.
    static func generate() -> String {
        var bytes = [UInt8](repeating: 0, count: length)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        precondition(status == errSecSuccess, "CSPRNG failure")
        return String(bytes.map { alphabet[Int($0 & 0x1F)] })
    }

    /// Uppercase, drop `-` and whitespace, map O→0 and I/L→1; must be 20 alphabet symbols.
    static func normalize(_ input: String) -> String? {
        var out = ""
        for ch in input.uppercased() {
            if ch == "-" || ch.isWhitespace { continue }
            switch ch {
            case "O": out.append("0")
            case "I", "L": out.append("1")
            default: out.append(ch)
            }
        }
        guard out.count == length, out.allSatisfy({ alphabet.contains($0) }) else { return nil }
        return out
    }

    /// `ABCDE-FGHJK-MNPQR-STVWX`
    static func display(_ normalized: String) -> String {
        var groups: [String] = []
        var current = ""
        for ch in normalized {
            current.append(ch)
            if current.count == 5 { groups.append(current); current = "" }
        }
        if !current.isEmpty { groups.append(current) }
        return groups.joined(separator: "-")
    }

    /// psk = HMAC-SHA256(key = "KeyBridge v2 pairing", data = normalized_code)
    static func psk(normalized: String) -> SymmetricKey {
        let mac = HMAC<SHA256>.authenticationCode(
            for: Data(normalized.utf8), using: SymmetricKey(data: Data("KeyBridge v2 pairing".utf8)))
        return SymmetricKey(data: Data(mac))
    }
}

// MARK: - §3 Primitives

enum KBP2Crypto {
    static func hmac(key: SymmetricKey, _ data: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: data, using: key))
    }

    /// Extract(salt, ikm) = HMAC-SHA256(key = salt, data = ikm)
    static func extract(salt: SymmetricKey, ikm: Data) -> SymmetricKey {
        SymmetricKey(data: hmac(key: salt, ikm))
    }

    /// Expand(prk, info) = HMAC-SHA256(key = prk, data = info || 0x01)
    static func expand(prk: SymmetricKey, info: Data) -> SymmetricKey {
        var d = info
        d.append(0x01)
        return SymmetricKey(data: hmac(key: prk, d))
    }

    static func sha256(_ parts: Data...) -> Data {
        var h = SHA256()
        for p in parts { h.update(data: p) }
        return Data(h.finalize())
    }

    static func randomBytes(_ n: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: n)
        let status = SecRandomCopyBytes(kSecRandomDefault, n, &bytes)
        precondition(status == errSecSuccess, "CSPRNG failure")
        return Data(bytes)
    }

    /// Constant-time equality for equal-length secrets (length itself is public).
    static func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<a.count {
            diff |= a[a.startIndex + i] ^ b[b.startIndex + i]
        }
        return diff == 0
    }
}

// MARK: - §4 Handshake (server side)

enum KBP2HandshakeError: Error {
    case badMagic
    case invalidPoint
    case badFinished
    case timeout
    case closed
}

/// Server half of the handshake. Feed it the ClientHello, send `serverHello`,
/// then verify the ClientFinished; on success it yields the record channel.
struct KBP2ServerHandshake {
    let serverHello: Data
    private let clientHello: Data
    private let prk: SymmetricKey
    private let th2: Data

    /// §4 server steps 1–2. Throws on bad magic or an invalid P-256 point.
    init(clientHello: Data, psk: SymmetricKey) throws {
        let ch = Data(clientHello)  // re-base indices at 0
        guard ch.count == KBP2.clientHelloLength else { throw KBP2HandshakeError.closed }
        guard ch.prefix(4).elementsEqual(KBP2.magic) else { throw KBP2HandshakeError.badMagic }

        let clientPubBytes = ch.subdata(in: 4..<69)
        guard clientPubBytes.first == 0x04,
              let clientPub = try? P256.KeyAgreement.PublicKey(x963Representation: clientPubBytes)
        else { throw KBP2HandshakeError.invalidPoint }

        let eph = P256.KeyAgreement.PrivateKey()
        let serverPub = eph.publicKey.x963Representation      // 0x04 || X || Y, 65 bytes
        let serverNonce = KBP2Crypto.randomBytes(32)

        guard let shared = try? eph.sharedSecretFromKeyAgreement(with: clientPub)
        else { throw KBP2HandshakeError.invalidPoint }
        let ecdh = shared.withUnsafeBytes { Data($0) }         // X coordinate, 32 bytes
        let prk = KBP2Crypto.extract(salt: psk, ikm: ecdh)

        var shPrefix = Data(KBP2.magic)
        shPrefix.append(serverPub)
        shPrefix.append(serverNonce)

        let th1 = KBP2Crypto.sha256(ch, shPrefix)
        let serverFinished = KBP2Crypto.hmac(
            key: KBP2Crypto.expand(prk: prk, info: Data("KBR2 server finished".utf8)), th1)

        var sh = shPrefix
        sh.append(serverFinished)

        self.clientHello = ch
        self.serverHello = sh
        self.prk = prk
        self.th2 = KBP2Crypto.sha256(ch, sh)
    }

    /// §4 server steps 3–5: constant-time check of ClientFinished, then derive traffic keys.
    func finish(clientFinished: Data) throws -> KBP2RecordChannel {
        let expected = KBP2Crypto.hmac(
            key: KBP2Crypto.expand(prk: prk, info: Data("KBR2 client finished".utf8)), th2)
        guard KBP2Crypto.constantTimeEqual(expected, clientFinished) else {
            throw KBP2HandshakeError.badFinished
        }
        let s2c = KBP2Crypto.expand(prk: prk, info: Data("KBR2 traffic s2c".utf8) + th2)
        let c2s = KBP2Crypto.expand(prk: prk, info: Data("KBR2 traffic c2s".utf8) + th2)
        return KBP2RecordChannel(sendKey: s2c, receiveKey: c2s)
    }
}

// MARK: - §5 Records

/// Per-direction AES-256-GCM with seq-based nonces (0x00000000 || seq_be64).
struct KBP2RecordChannel {
    private let sendKey: SymmetricKey
    private let receiveKey: SymmetricKey
    private var sendSeq: UInt64 = 0
    private var receiveSeq: UInt64 = 0

    init(sendKey: SymmetricKey, receiveKey: SymmetricKey) {
        self.sendKey = sendKey
        self.receiveKey = receiveKey
    }

    private static func nonce(_ seq: UInt64) -> AES.GCM.Nonce {
        var bytes = [UInt8](repeating: 0, count: 12)
        var s = seq.bigEndian
        withUnsafeBytes(of: &s) { raw in
            for i in 0..<8 { bytes[4 + i] = raw[i] }
        }
        return try! AES.GCM.Nonce(data: bytes)  // 12 bytes is always valid
    }

    /// Seals a 4-byte plaintext into a 20-byte record. Returns nil if the counter is exhausted.
    mutating func seal(_ type: UInt8, _ b1: UInt8 = 0, _ b2: UInt8 = 0, _ b3: UInt8 = 0) -> Data? {
        guard sendSeq != UInt64.max else { return nil }
        let plaintext: [UInt8] = [type, b1, b2, b3]
        guard let box = try? AES.GCM.seal(plaintext, using: sendKey, nonce: Self.nonce(sendSeq))
        else { return nil }
        sendSeq += 1
        var out = Data(capacity: KBP2.recordLength)
        out.append(box.ciphertext)
        out.append(box.tag)
        return out
    }

    /// Opens a 20-byte record. nil = authentication failure (caller must close).
    mutating func open(_ record: Data) -> [UInt8]? {
        let r = Data(record)
        guard r.count == KBP2.recordLength, receiveSeq != UInt64.max,
              let box = try? AES.GCM.SealedBox(
                nonce: Self.nonce(receiveSeq), ciphertext: r.prefix(4), tag: r.suffix(16)),
              let pt = try? AES.GCM.open(box, using: receiveKey)
        else { return nil }
        receiveSeq += 1
        return Array(pt)
    }

    static func keyFields(isDown: Bool, isExtended: Bool, vk: UInt16) -> (UInt8, UInt8, UInt8) {
        var flags: UInt8 = 0
        if isDown { flags |= 0x01 }
        if isExtended { flags |= 0x02 }
        return (flags, UInt8(vk & 0xFF), UInt8(vk >> 8))
    }
}
