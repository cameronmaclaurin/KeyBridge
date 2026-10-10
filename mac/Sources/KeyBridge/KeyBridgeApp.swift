import AppKit

@main
@MainActor
enum KeyBridgeApp {
    static func main() {
        #if KEYBRIDGE_SELFTEST
        if CommandLine.arguments.contains("--selftest-server") {
            SelfTest.runServer(CommandLine.arguments)  // never returns
        }
        if CommandLine.arguments.contains("--selftest-pair-server") {
            SelfTest.runPairServer(CommandLine.arguments)  // never returns
        }
        if CommandLine.arguments.contains("--selftest-verify-update") {
            SelfTest.runVerifyUpdate(CommandLine.arguments)  // never returns
        }
        #endif

        let app = NSApplication.shared
        let delegate = AppDelegate()
        app.delegate = delegate
        // NSApplication.delegate is weak; keep ours alive for the app's lifetime.
        withExtendedLifetime(delegate) { app.run() }
    }
}
