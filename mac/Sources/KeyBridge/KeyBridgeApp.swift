import AppKit

@main
@MainActor
enum KeyBridgeApp {
    static func main() {
        let app = NSApplication.shared
        let delegate = AppDelegate()
        app.delegate = delegate
        // NSApplication.delegate is weak; keep ours alive for the app's lifetime.
        withExtendedLifetime(delegate) { app.run() }
    }
}
