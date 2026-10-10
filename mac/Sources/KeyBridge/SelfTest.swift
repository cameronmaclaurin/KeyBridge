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

    /// `KeyBridge --selftest-server --port <P> --psk <64 hex>`
    /// Exit codes: 0 success, 2 handshake failed, 3 no valid PONG, 1 setup error, 64 usage.
    static func runServer(_ args: [String]) -> Never {
        let usageText = "KeyBridge --selftest-server --port <P> --psk <64 hex chars>"
        guard let port = parsePort(args), let pskArg = value(args, "--psk"), let psk = parsePSK(pskArg)
        else { usage(usageText) }

        let server = KBP2Server(psk: psk, options: loopbackOptions(port: port))

        var gotPong = false
        var finishing = false

        // Send RELEASE_ALL, close gracefully (§5), then exit.
        func finish(_ status: Int32) {
            guard !finishing else { return }
            finishing = true
            server.sendReleaseAll()
            server.stop { exit(status) }
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
            server.sendKey(isDown: true, isExtended: false, vk: 0x0041)
            server.sendKey(isDown: false, isExtended: false, vk: 0x0041)
            server.sendKey(isDown: true, isExtended: true, vk: 0x000D)
            server.sendKey(isDown: false, isExtended: true, vk: 0x000D)
            server.sendPing()
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) { finish(3) }
        }
        server.onPong = {
            gotPong = true
            finish(0)
        }
        // Client closed, or one of its records failed authentication, before a valid PONG.
        server.onSessionEnded = {
            if !finishing { exit(gotPong ? 0 : 3) }
        }

        server.start()
        dispatchMain()
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
