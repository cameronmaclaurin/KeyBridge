#if KEYBRIDGE_SELFTEST
import CryptoKit
import Foundation

/// docs/PROTOCOL.md Appendix A.1 and A.3, compiled only with -DKEYBRIDGE_SELFTEST.
/// Uses the same KBP2Server / handshake / pairing / record code as the app; no NSApplication or UI.
enum SelfTest {
    private static func value(_ args: [String], _ flag: String) -> String? {
        guard let i = args.firstIndex(of: flag), i + 1 < args.count else { return nil }
        return args[i + 1]
    }

    private static func usage(_ text: String) -> Never {
        FileHandle.standardError.write(Data("usage: \(text)\n".utf8))
        exit(64)
    }

    private static func say(_ line: String) {
        FileHandle.standardOutput.write(Data((line + "\n").utf8))
    }

    /// 64 hex characters (case-insensitive) → 32-byte key.
    private static func parsePSK(_ hex: String) -> SymmetricKey? {
        let chars = Array(hex.utf8)
        guard chars.count == 64 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(32)
        func nibble(_ c: UInt8) -> UInt8? {
            switch c {
            case UInt8(ascii: "0")...UInt8(ascii: "9"): return c - UInt8(ascii: "0")
            case UInt8(ascii: "a")...UInt8(ascii: "f"): return c - UInt8(ascii: "a") + 10
            case UInt8(ascii: "A")...UInt8(ascii: "F"): return c - UInt8(ascii: "A") + 10
            default: return nil
            }
        }
        for i in stride(from: 0, to: 64, by: 2) {
            guard let hi = nibble(chars[i]), let lo = nibble(chars[i + 1]) else { return nil }
            bytes.append(hi << 4 | lo)
        }
        return SymmetricKey(data: bytes)
    }

    private static func parsePort(_ args: [String]) -> UInt16? {
        guard let arg = value(args, "--port"), let port = UInt16(arg), port != 0 else { return nil }
        return port
    }

    private static func loopbackOptions(port: UInt16) -> KBP2Server.Options {
        var opts = KBP2Server.Options()
        opts.port = port
        opts.loopbackOnly = true
        opts.acceptLimit = 1
        opts.autoPing = false
        return opts
    }

    // MARK: A.1

    /// `KeyBridge --selftest-server --port <P> --psk <64 hex> [--clip-file <path>]`
    /// Exit codes: 0 success, 2 handshake failed, 3 no valid PONG, 1 setup error, 64 usage.
    static func runServer(_ args: [String]) -> Never {
        let usageText = "KeyBridge --selftest-server --port <P> --psk <64 hex chars> [--clip-file <path>]"
        guard let port = parsePort(args), let pskArg = value(args, "--psk"), let psk = parsePSK(pskArg)
        else { usage(usageText) }

        var clip: Data?
        if args.contains("--clip-file") {
            guard let path = value(args, "--clip-file") else { usage(usageText) }
            guard let d = FileManager.default.contents(atPath: path) else {
                FileHandle.standardError.write(Data("can't read \(path)\n".utf8))
                exit(1)
            }
            clip = d
        }

        let server = KBP2Server(psk: psk, options: loopbackOptions(port: port))
        server.clipboardEnabled = true  // CAPS b1 = 0x01

        var gotPong = false
        var finishing = false
        var authenticated = false
        var pinged = false
        var clipPending = clip != nil

        // Send RELEASE_ALL, close gracefully (§5), then exit.
        func finish(_ status: Int32) {
            guard !finishing else { return }
            finishing = true
            server.sendReleaseAll()
            server.stop { exit(status) }
        }

        // After the PONG, allow at most 1 s more for a client transfer in progress
        // (until it completes, is discarded or is abandoned).
        func finishAfterPong(_ deadline: DispatchTime) {
            guard server.isReceivingClipboard, DispatchTime.now() < deadline else { finish(0); return }
            DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(10)) { finishAfterPong(deadline) }
        }

        func ping() {
            guard !pinged else { return }
            pinged = true
            server.sendPing()
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) { finish(3) }
        }

        // 4a: the transfer goes only to a client whose CAPS had bit0 set, so wait for it
        // (briefly) before sending; then PING.
        func sendClipThenPing() {
            guard authenticated, clipPending else { return }
            guard server.canSendClipboard, let clip else {
                return  // no CAPS yet; the availability callback or the fallback timer retries
            }
            clipPending = false
            server.sendClipboardText(clip) { _ in ping() }
        }

        server.onListenerEvent = { event in
            switch event {
            case .ready:
                say("LISTENING")
            case .failed(let msg):
                FileHandle.standardError.write(Data("listen failed: \(msg)\n".utf8))
                exit(1)
            }
        }
        server.onHandshakeFailed = { reason in
            FileHandle.standardError.write(Data("handshake failed: \(reason)\n".utf8))
            exit(2)
        }
        server.onAuthenticated = { _, _ in
            // CAPS has already gone out as the first record.
            authenticated = true
            server.sendKey(isDown: true, isExtended: false, vk: 0x0041)
            server.sendKey(isDown: false, isExtended: false, vk: 0x0041)
            server.sendKey(isDown: true, isExtended: true, vk: 0x000D)
            server.sendKey(isDown: false, isExtended: true, vk: 0x000D)
            guard clipPending else { ping(); return }
            sendClipThenPing()
            // A client that never advertises clipboard support gets no transfer.
            DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
                if clipPending { clipPending = false; ping() }
            }
        }
        server.onClipboardAvailabilityChanged = { _ in sendClipThenPing() }
        server.onPeerCaps = { caps in
            // A client with sharing off gets no transfer; go straight to PING.
            if caps & KBP2.capClipboardText == 0, authenticated, clipPending {
                clipPending = false
                ping()
            }
        }
        server.onClipboardText = { utf8 in
            let hex = SHA256.hash(data: utf8).map { String(format: "%02x", $0) }.joined()
            say("CLIP \(utf8.count) \(hex)")
            if gotPong { finish(0) }
        }
        server.onPong = {
            guard !gotPong else { return }
            gotPong = true
            finishAfterPong(.now() + 1)
        }
        // Client closed, or one of its records failed authentication, before a valid PONG.
        server.onSessionEnded = {
            if !finishing { exit(gotPong ? 0 : 3) }
        }

        server.start()
        dispatchMain()
    }

    // MARK: docs/UPDATES.md §6

    /// `KeyBridge --selftest-verify-update <manifest-file> <sig-file> --current <X.Y.Z> [--pubkey <130 hex>]`
    /// Prints `UPDATE <version> <mac-url> <mac-sha256> <mac-size>` or `CURRENT` (exit 0), or
    /// `INVALID` (exit 2). Same verification, parsing and comparison code as the app.
    static func runVerifyUpdate(_ args: [String]) -> Never {
        let usageText = "KeyBridge --selftest-verify-update <manifest-file> <sig-file> --current <X.Y.Z> [--pubkey <130 hex>]"
        guard let i = args.firstIndex(of: "--selftest-verify-update"), i + 2 < args.count,
              let currentArg = value(args, "--current"), let current = UpdateVersion(currentArg)
        else { usage(usageText) }
        let keyHex = value(args, "--pubkey") ?? UpdateVerifier.embeddedPublicKeyHex
        guard keyHex.utf8.count == 130, let key = UpdateVerifier.publicKey(hex: keyHex) else { usage(usageText) }

        func read(_ path: String) -> Data {
            guard let h = FileHandle(forReadingAtPath: path) else {
                FileHandle.standardError.write(Data("can't read \(path)\n".utf8))
                exit(1)
            }
            // One byte over the limit is enough to reject an oversized file.
            let d = h.readData(ofLength: Int(UpdateVerifier.maxResponseBytes) + 1)
            try? h.close()
            return d
        }
        let manifest = read(args[i + 1]), sig = read(args[i + 2])

        guard let m = UpdateVerifier.verifyAndParse(manifest: manifest, signature: sig, publicKey: key) else {
            say("INVALID")
            exit(2)
        }
        switch UpdateVerifier.decide(m, running: current) {
        case .update(let m):
            say("UPDATE \(m.version) \(m.mac.url.absoluteString) \(m.mac.sha256) \(m.mac.size)")
        case .current:
            say("CURRENT")
        }
        exit(0)
    }

    // MARK: A.3

    /// `KeyBridge --selftest-pair-server --port <P> --name <NAME> [--confirm yes|no]`
    /// Prints LISTENING, `SAS dddddd`, then `PAIRED <ltk hex>` (exit 0) or `CANCELLED` (exit 0);
    /// `PAIR FAILED` exit 2 on any failure; 1 setup error; 64 usage.
    static func runPairServer(_ args: [String]) -> Never {
        let usageText = "KeyBridge --selftest-pair-server --port <P> --name <NAME> [--confirm yes|no]"
        guard let port = parsePort(args), let name = value(args, "--name") else { usage(usageText) }
        let confirm: Bool
        switch value(args, "--confirm") {
        case nil where !args.contains("--confirm"), "yes"?: confirm = true
        case "no"?: confirm = false
        default: usage(usageText)
        }

        // Not paired (no psk): a "KBR2" connection is refused, which is a failure here.
        let server = KBP2Server(psk: nil, options: loopbackOptions(port: port))
        server.pairingModeEnabled = true
        server.macDisplayName = name

        var exitStatus: Int32 = 2

        func failed(_ why: String) -> Never {
            FileHandle.standardError.write(Data("pairing failed: \(why)\n".utf8))
            say("PAIR FAILED")
            exit(2)
        }

        server.onListenerEvent = { event in
            switch event {
            case .ready:
                say("LISTENING")
            case .failed(let msg):
                FileHandle.standardError.write(Data("listen failed: \(msg)\n".utf8))
                exit(1)
            }
        }
        server.onHandshakeFailed = { reason in failed("\(reason)") }
        server.onPairingEvent = { event in
            switch event {
            case .started:
                break
            case .compare(_, let sas):
                say(String(format: "SAS %06u", sas))
                if confirm {
                    server.confirmPairing()
                } else {
                    exitStatus = 0
                    say("CANCELLED")
                    server.cancelPairing()
                }
            case .paired(let ltk, _):
                let hex = ltk.withUnsafeBytes { $0.map { String(format: "%02x", $0) }.joined() }
                say("PAIRED \(hex)")
                exitStatus = 0
            case .failed(let reason):
                if reason == .cancelled && !confirm { return }  // we cancelled; already printed
                failed("\(reason)")
            }
        }
        // Exit once the pairing connection has closed gracefully.
        server.onPairingConnectionClosed = { exit(exitStatus) }

        server.start()
        dispatchMain()
    }
}
#endif
