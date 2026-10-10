import CryptoKit
import Foundation
import Security

// KeyBridge Protocol v2 (KBP2) — pure protocol and crypto, no networking or UI.
// docs/PROTOCOL.md is the source of truth; section numbers below refer to it.

enum KBP2 {
    static let port: UInt16 = 9876

    /// §1: the first 4 bytes a client sends pick the sub-protocol.
    static let magicLength = 4
    static let magic: [UInt8] = Array("KBR2".utf8)          // session (§4)
    static let pairingMagic: [UInt8] = Array("KBPR".utf8)   // pairing (§2)
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
    /// A "KBR2" connection arrived but no long-term key is stored (not paired yet).
    case notPaired
    /// A "KBPR" connection arrived outside pairing mode, or while another pairing ran.
    case pairingNotAllowed
}

/// Server half of the handshake. Feed it the ClientHello, send `serverHello`,
/// then verify the ClientFinished; on success it yields the record channel.
struct KBP2ServerHandshake {
    let serverHello: Data
    private let clientHello: Data
    private let prk: SymmetricKey
    private let th2: Data

    /// §4 server steps 1–2. Throws on bad magic or an invalid P-256 point.
    /// `psk` is the long-term key from pairing (§2).
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

// MARK: - §2 Pairing (numeric comparison), responder side

enum KBP2Pairing {
    static let nameLength = 64
    static let pairHelloLength = 133            // magic(4) + pc_pub(65) + pc_name(64)
    static let pairCommitLength = 165           // magic(4) + mac_pub(65) + mac_name(64) + commit(32)
    static let nonceLength = 32
    static let confirmLength = 32

    /// §2.4: PairHello through MacNonce within 10 s of connecting; then 120 s to confirm.
    static let exchangeTimeout: TimeInterval = 10
    static let confirmTimeout: TimeInterval = 120
    /// §2.1: pairing mode lasts at most 3 minutes.
    static let pairingModeDuration: TimeInterval = 180

    /// §2.2: UTF-8, truncated at a character boundary to at most 64 bytes, NUL-padded to 64.
    static func encodeName(_ name: String) -> Data {
        var out = Data()
        for ch in name where !ch.unicodeScalars.contains(where: { $0.value == 0 }) {
            let bytes = Data(String(ch).utf8)
            if out.count + bytes.count > nameLength { break }
            out.append(bytes)
        }
        out.append(contentsOf: [UInt8](repeating: 0, count: nameLength - out.count))
        return out
    }

    /// §2.2: bytes up to the first NUL, decoded leniently, control characters removed.
    /// Also drops bidi overrides so a name can't visually reorder the surrounding text.
    static func decodeName(_ field: Data) -> String {
        let bytes = Data(field).prefix { $0 != 0 }
        let decoded = String(decoding: bytes, as: UTF8.self)
        var scalars = String.UnicodeScalarView()
        for s in decoded.unicodeScalars {
            if s.properties.generalCategory == .control { continue }
            switch s.value {
            case 0x200E, 0x200F, 0x202A...0x202E, 0x2066...0x2069: continue
            default: scalars.append(s)
            }
        }
        return String(scalars).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// `482 913`
    static func formatSAS(_ sas: UInt32) -> String {
        let digits = String(format: "%06u", sas % 1_000_000)
        return String(digits.prefix(3)) + " " + String(digits.suffix(3))
    }
}

enum KBP2PairingError: Error {
    case badMagic
    case invalidPoint
    case badConfirm        // PcConfirm didn't verify
    case closed            // peer closed, or sent something it shouldn't have
    case timeout
    case cancelled         // the Mac user (or the app) cancelled
}

/// Everything both sides derive once the nonces are exchanged (§2.3).
struct KBP2PairingKeys {
    let sas: UInt32
    let ltk: SymmetricKey
    let expectedPcConfirm: Data
    let macConfirm: Data
}

/// Mac (responder) half of §2. Feed it the PairHello, send `pairCommit`; after receiving
/// pc_nonce, `finish` yields the keys and only then may `macNonce` be sent.
struct KBP2PairingResponder {
    let pairCommit: Data
    /// Sent only after pc_nonce has been received (§2.2).
    let macNonce: Data
    /// The PC's display name, sanitized for display.
    let pcName: String

    private let pairHello: Data
    private let privateKey: P256.KeyAgreement.PrivateKey
    private let pcPub: P256.KeyAgreement.PublicKey

    init(pairHello: Data, macName: String) throws {
        let ph = Data(pairHello)  // re-base indices at 0
        guard ph.count == KBP2Pairing.pairHelloLength else { throw KBP2PairingError.closed }
        guard ph.prefix(4).elementsEqual(KBP2.pairingMagic) else { throw KBP2PairingError.badMagic }

        let pcPubBytes = ph.subdata(in: 4..<69)
        guard pcPubBytes.first == 0x04,
              let pcPub = try? P256.KeyAgreement.PublicKey(x963Representation: pcPubBytes)
        else { throw KBP2PairingError.invalidPoint }

        let key = P256.KeyAgreement.PrivateKey()
        let macPub = key.publicKey.x963Representation         // 0x04 || X || Y, 65 bytes
        let nonce = KBP2Crypto.randomBytes(KBP2Pairing.nonceLength)

        // commit = HMAC-SHA256(key = mac_nonce, data = "KBPR commit" || mac_pub || pc_pub)
        let commit = KBP2Crypto.hmac(key: SymmetricKey(data: nonce),
                                     Data("KBPR commit".utf8) + macPub + pcPubBytes)

        var pc = Data(KBP2.pairingMagic)
        pc.append(macPub)
        pc.append(KBP2Pairing.encodeName(macName))
        pc.append(commit)

        self.pairHello = ph
        self.pairCommit = pc
        self.macNonce = nonce
        self.pcName = KBP2Pairing.decodeName(ph.subdata(in: 69..<133))
        self.privateKey = key
        self.pcPub = pcPub
    }

    /// §2.3 derivations, once pc_nonce has arrived.
    func finish(pcNonce: Data) throws -> KBP2PairingKeys {
        let nonce = Data(pcNonce)
        guard nonce.count == KBP2Pairing.nonceLength else { throw KBP2PairingError.closed }
        guard let shared = try? privateKey.sharedSecretFromKeyAgreement(with: pcPub)
        else { throw KBP2PairingError.invalidPoint }
        let ecdh = shared.withUnsafeBytes { Data($0) }         // X coordinate, 32 bytes

        let th = KBP2Crypto.sha256(pairHello, pairCommit, nonce, macNonce)

        let h = [UInt8](KBP2Crypto.sha256(Data("KBPR sas".utf8), th))
        let first4 = UInt32(h[0]) << 24 | UInt32(h[1]) << 16 | UInt32(h[2]) << 8 | UInt32(h[3])

        let prk = KBP2Crypto.extract(salt: SymmetricKey(data: th), ikm: ecdh)
        let ltk = KBP2Crypto.expand(prk: prk, info: Data("KBPR long-term key".utf8))
        let pcConfirm = KBP2Crypto.hmac(
            key: KBP2Crypto.expand(prk: prk, info: Data("KBPR pc confirm".utf8)), th)
        let macConfirm = KBP2Crypto.hmac(
            key: KBP2Crypto.expand(prk: prk, info: Data("KBPR mac confirm".utf8)), th)

        return KBP2PairingKeys(sas: first4 % 1_000_000, ltk: ltk,
                               expectedPcConfirm: pcConfirm, macConfirm: macConfirm)
    }
}
