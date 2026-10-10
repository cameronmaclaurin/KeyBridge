#if KEYBRIDGE_SELFTEST
import Foundation

/// docs/PROTOCOL.md Appendix A.1 — compiled only with -DKEYBRIDGE_SELFTEST.
/// Uses the same KBP2Server / handshake / record code as the app; no NSApplication or UI.
///
/// `KeyBridge --selftest-server --port <P> --code <CODE>`
/// Exit codes: 0 success, 2 handshake failed, 3 no valid PONG, 1 setup error, 64 usage.
enum SelfTest {
    static func runServer(_ args: [String]) -> Never {
        func value(_ flag: String) -> String? {
            guard let i = args.firstIndex(of: flag), i + 1 < args.count else { return nil }
            return args[i + 1]
        }
        guard let portArg = value("--port"), let port = UInt16(portArg), port != 0,
              let codeArg = value("--code"), let code = PairingCode.normalize(codeArg)
        else {
            FileHandle.standardError.write(Data("usage: KeyBridge --selftest-server --port <P> --code <CODE>\n".utf8))
            exit(64)
        }

        var opts = KBP2Server.Options()
        opts.port = port
        opts.loopbackOnly = true
        opts.acceptLimit = 1
        opts.autoPing = false
        let server = KBP2Server(psk: PairingCode.psk(normalized: code), options: opts)

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
                FileHandle.standardOutput.write(Data("LISTENING\n".utf8))
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
}
#endif
