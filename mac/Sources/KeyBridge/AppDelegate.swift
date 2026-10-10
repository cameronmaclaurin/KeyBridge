import AppKit

private let kPort: UInt16 = 9876

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private let capture = KeyCapture()
    private let server = NetworkServer()
    private var remoteMode = false

    func applicationDidFinishLaunching(_ n: Notification) {
        NSApp.setActivationPolicy(.accessory)  // hide from dock
        buildMenu()
        server.onClientConnected    = { [weak self] ip in self?.onConnect(ip) }
        server.onClientDisconnected = { [weak self] in self?.onDisconnect() }
        server.start(port: kPort)
        capture.onKeyEvent      = { [weak self] evt in self?.server.send(evt) }
        capture.onHotkeyToggle  = { [weak self] in self?.toggle() }
        startLocalMode()

        NSApp.activate(ignoringOtherApps: false)
    }

    // MARK: – Mode

    private func startLocalMode() {
        remoteMode = false
        capture.start(suppress: false)
        updateUI()
    }

    private func startRemoteMode() {
        remoteMode = true
        capture.start(suppress: true)
        updateUI()
        if !server.isConnected {
            notify("No Windows client", "Start KeyBridge on your Windows PC first.")
        }
    }

    func toggle() {
        if remoteMode {
            // Release all held keys on remote before we stop capturing
            capture.flushRemoteKeys(send: server.send)
            startLocalMode()
        } else {
            startRemoteMode()
        }
    }

    // MARK: – UI

    private var toggleItem: NSMenuItem!
    private var statusLine: NSMenuItem!
    private var connLine: NSMenuItem!

    private func buildMenu() {
        let menu = NSMenu()

        statusLine = NSMenuItem(title: "", action: nil, keyEquivalent: "")
        statusLine.isEnabled = false
        menu.addItem(statusLine)

        connLine = NSMenuItem(title: "Windows: not connected", action: nil, keyEquivalent: "")
        connLine.isEnabled = false
        menu.addItem(connLine)

        menu.addItem(.separator())

        toggleItem = NSMenuItem(title: "", action: #selector(onToggle), keyEquivalent: "")
        toggleItem.target = self
        menu.addItem(toggleItem)

        menu.addItem(.separator())
        let hint = NSMenuItem(title: "Hotkey: Ctrl + Shift + `", action: nil, keyEquivalent: "")
        hint.isEnabled = false
        menu.addItem(hint)
        menu.addItem(.separator())
        menu.addItem(withTitle: "Quit KeyBridge", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")

        statusItem.menu = menu
        updateUI()
    }

    private func updateUI() {
        if remoteMode {
            statusItem.button?.title = "🟢"
            statusLine.title = "Mode: Windows  (keys → Windows PC)"
            toggleItem.title = "Switch to Local Mode"
        } else {
            statusItem.button?.title = "⌨️"
            statusLine.title = "Mode: Local  (keys → this Mac)"
            toggleItem.title = "Switch to Windows Mode"
        }
    }

    @objc private func onToggle() { toggle() }

    private func onConnect(_ ip: String) {
        connLine.title = "Windows: \(ip)"
        notify("KeyBridge", "Windows PC connected from \(ip)")
    }

    private func onDisconnect() {
        connLine.title = "Windows: disconnected"
        if remoteMode { startLocalMode() }
    }

    private func notify(_ title: String, _ body: String = "") {
        let n = NSUserNotification()
        n.title = title
        n.informativeText = body
        NSUserNotificationCenter.default.deliver(n)
    }
}
