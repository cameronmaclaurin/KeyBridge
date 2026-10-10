import AppKit
import ApplicationServices
import UserNotifications

private let kPort: UInt16 = 9876

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private let capture = KeyCapture()
    private let server = NetworkServer()
    private var remoteMode = false
    private var permissionTimer: Timer?

    private var statusLine: NSMenuItem!
    private var connLine: NSMenuItem!
    private var toggleItem: NSMenuItem!

    func applicationDidFinishLaunching(_ n: Notification) {
        buildMenu()

        if Bundle.main.bundleIdentifier != nil {
            UNUserNotificationCenter.current().requestAuthorization(options: [.alert]) { _, _ in }
        }

        server.onClientConnected = { [weak self] host in self?.clientConnected(host) }
        server.onClientDisconnected = { [weak self] in self?.clientDisconnected() }
        server.start(port: kPort)

        capture.onKeyEvent = { [weak self] evt in self?.server.send(evt) }
        capture.onHotkeyToggle = { [weak self] in self?.toggle() }
        startCapture()
    }

    // MARK: – Accessibility

    private func startCapture() {
        if capture.start() { updateUI(); return }

        // Shows the system "grant Accessibility" prompt, then retries until the user allows it.
        let opts = [kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: true] as CFDictionary
        _ = AXIsProcessTrustedWithOptions(opts)
        statusLine.title = "Needs Accessibility permission…"
        permissionTimer = Timer.scheduledTimer(timeInterval: 2, target: self,
                                               selector: #selector(retryCapture), userInfo: nil, repeats: true)
    }

    @objc private func retryCapture() {
        guard capture.start() else { return }
        permissionTimer?.invalidate()
        permissionTimer = nil
        updateUI()
    }

    // MARK: – Mode

    func toggle() {
        if remoteMode {
            capture.releaseAllRemote()
            setRemote(false)
        } else if server.isConnected {
            setRemote(true)
        } else {
            notify("No Windows PC connected", "Start keybridge.exe on your PC first.")
        }
    }

    private func setRemote(_ on: Bool) {
        remoteMode = on
        capture.suppress = on
        updateUI()
    }

    private func clientConnected(_ host: String) {
        connLine.title = "Windows: \(host)"
        notify("Windows PC connected", host)
    }

    private func clientDisconnected() {
        connLine.title = "Windows: not connected"
        if remoteMode { setRemote(false) }
    }

    // MARK: – UI

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

    private func notify(_ title: String, _ body: String) {
        guard Bundle.main.bundleIdentifier != nil else { return }
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        let req = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(req)
    }
}
