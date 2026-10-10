import AppKit
import ApplicationServices
import CryptoKit
import Carbon.HIToolbox  // IsSecureEventInputEnabled
import ServiceManagement
import UserNotifications

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    private let capture = KeyCapture()
    private var server: KBP2Server?
    private var pairingCode = ""  // normalized
    private var remoteMode = false
    private var accessibilityGranted = false
    private var secureInputOn = false
    private var listenerError: String?

    private var permissionTimer: Timer?
    private var secureInputTimer: Timer?
    private var listenerRetryTimer: Timer?
    private var pairingWindow: PairingWindowController?

    private var modeLine: NSMenuItem!
    private var connLine: NSMenuItem!
    private var warningLine: NSMenuItem!
    private var accessibilityItem: NSMenuItem!
    private var toggleItem: NSMenuItem!
    private var loginItem: NSMenuItem!

    func applicationDidFinishLaunching(_ n: Notification) {
        installEditMenu()
        buildMenu()
        if warnIfRunningFromDiskImage() { return }

        if Bundle.main.bundleIdentifier != nil {
            UNUserNotificationCenter.current().requestAuthorization(options: [.alert]) { _, _ in }
        }

        let (code, isNew) = PairingStore.loadOrCreate()
        pairingCode = code
        startServer(psk: PairingCode.psk(normalized: code))

        startCapture()
        updateUI()
        if isNew { showPairingWindow() }
    }

    /// Opening the app again (Finder, Launchpad, `open`) while it runs: a menu-bar app would
    /// otherwise show nothing, so show the pairing window.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if server != nil { showPairingWindow() }
        return false
    }

    /// Release the PC's keys and close the session gracefully (≤ 1 s) before quitting.
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let s = server, s.isAuthenticated else { return .terminateNow }
        if remoteMode { leaveWindowsMode(sendReleaseAll: true) }
        s.stop { NSApp.reply(toApplicationShouldTerminate: true) }
        return .terminateLater
    }

    // MARK: – Server

    private func startServer(psk: SymmetricKey) {
        let s = KBP2Server(psk: psk)
        s.onListenerEvent = { [weak self] e in self?.listenerEvent(e) }
        s.onAuthenticated = { [weak self] host, replaced in self?.pcConnected(host, replaced: replaced) }
        s.onSessionEnded = { [weak self] in self?.pcDisconnected() }
        server = s
        // Hot path: tap callback → seal → send, all on the main thread, no extra hops.
        capture.onKeyEvent = { [unowned s] evt in
            s.sendKey(isDown: evt.isDown, isExtended: evt.isExtended, vk: evt.vk)
        }
        capture.onHotkeyToggle = { [weak self] in self?.toggle() }
        s.start()
    }

    private func listenerEvent(_ e: KBP2Server.ListenerEvent) {
        switch e {
        case .ready:
            listenerError = nil
            listenerRetryTimer?.invalidate()
            listenerRetryTimer = nil
        case .failed(let msg):
            listenerError = msg
            NSLog("[KeyBridge] Listener failed: \(msg)")
            if listenerRetryTimer == nil {
                listenerRetryTimer = Timer.scheduledTimer(timeInterval: 5, target: self,
                                                          selector: #selector(retryListener),
                                                          userInfo: nil, repeats: true)
            }
        }
        updateUI()
    }

    @objc private func retryListener() { server?.start() }

    private func pcConnected(_ host: String, replaced: String?) {
        if remoteMode, let replaced, replaced != host {
            // A different PC took over: don't keep typing into it without the user noticing.
            leaveWindowsMode(sendReleaseAll: false)
        }
        if replaced != host { notify("Windows PC connected", host) }
        updateUI()
    }

    private func pcDisconnected() {
        if remoteMode {
            leaveWindowsMode(sendReleaseAll: false)
            notify("Windows PC disconnected", "Your keys are going to this Mac again.")
        }
        updateUI()
    }

    // MARK: – Accessibility

    private func startCapture() {
        if capture.start() { accessibilityGranted = true; return }

        // Shows the system "grant Accessibility" prompt, then retries until the user allows it.
        let opts = [kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: true] as CFDictionary
        _ = AXIsProcessTrustedWithOptions(opts)
        permissionTimer = Timer.scheduledTimer(timeInterval: 2, target: self,
                                               selector: #selector(retryCapture), userInfo: nil, repeats: true)
    }

    @objc private func retryCapture() {
        guard capture.start() else { return }
        permissionTimer?.invalidate()
        permissionTimer = nil
        accessibilityGranted = true
        updateUI()
    }

    @objc private func openAccessibilitySettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility") {
            NSWorkspace.shared.open(url)
        }
    }

    // MARK: – Mode

    func toggle() {
        if remoteMode {
            leaveWindowsMode(sendReleaseAll: true)
        } else if !accessibilityGranted {
            notify("KeyBridge needs Accessibility permission",
                   "Turn on KeyBridge in System Settings → Privacy & Security → Accessibility.")
            openAccessibilitySettings()
        } else if server?.isAuthenticated == true {
            enterWindowsMode()
        } else {
            notify("No Windows PC connected",
                   "Open KeyBridge on your PC and connect it to this Mac. Choose “Pair a Windows PC…” in the menu for the address and code.")
        }
        updateUI()
    }

    private func enterWindowsMode() {
        remoteMode = true
        capture.suppress = true
        secureInputOn = false
        checkSecureInput()
        secureInputTimer = Timer.scheduledTimer(timeInterval: 1, target: self,
                                                selector: #selector(checkSecureInput),
                                                userInfo: nil, repeats: true)
    }

    private func leaveWindowsMode(sendReleaseAll: Bool) {
        if sendReleaseAll {
            capture.releaseAllRemote()   // key-ups for everything still held
            server?.sendReleaseAll()     // and the PC drops anything else it holds
        }
        capture.suppress = false
        remoteMode = false
        secureInputTimer?.invalidate()
        secureInputTimer = nil
        secureInputOn = false
        updateUI()
    }

    // MARK: – Secure Input

    /// While another app has Secure Input on (a focused password field), the event tap sees
    /// no keystrokes, so typing silently goes to the Mac. Tell the user.
    @objc private func checkSecureInput() {
        let on = IsSecureEventInputEnabled()
        guard on != secureInputOn else { return }
        secureInputOn = on
        if on {
            notify("Keys are staying on this Mac",
                   "Another app’s password field has turned on Secure Input, which blocks KeyBridge. Click out of the password field or quit that app.")
        }
        updateUI()
    }

    // MARK: – Pairing

    @objc private func showPairingWindow() {
        if pairingWindow == nil {
            let (status, connected) = connectionStatus()
            let w = PairingWindowController(displayCode: PairingCode.display(pairingCode),
                                            status: status, connected: connected)
            w.onGenerateNewCode = { [weak self] in self?.generateNewCode() }
            w.onClose = { [weak self] in self?.pairingWindow = nil }
            pairingWindow = w
        } else {
            pairingWindow?.refreshAddresses()
        }
        pairingWindow?.show()
    }

    private func generateNewCode() {
        let code = PairingCode.generate()
        guard PairingStore.save(code) else {
            let alert = NSAlert()
            alert.messageText = "Couldn’t save the new code"
            alert.informativeText = "KeyBridge couldn’t store the code in your Keychain, so the current code is unchanged."
            alert.runModal()
            return
        }
        if remoteMode { leaveWindowsMode(sendReleaseAll: true) }
        pairingCode = code
        server?.setPSK(PairingCode.psk(normalized: code))  // disconnects the current PC
        pairingWindow?.setCode(PairingCode.display(code))
        updateUI()
    }

    private func connectionStatus() -> (String, Bool) {
        if let err = listenerError { return ("Can’t accept connections on port \(KBP2.port): \(err)", false) }
        if let host = server?.peerHost { return ("PC connected: \(host)", true) }
        return ("Waiting for your PC…", false)
    }

    // MARK: – Launch at Login

    @objc private func toggleLaunchAtLogin() {
        let svc = SMAppService.mainApp
        do {
            if svc.status == .enabled || svc.status == .requiresApproval {
                try svc.unregister()
            } else {
                try svc.register()
            }
        } catch {
            let alert = NSAlert()
            alert.messageText = "Couldn’t change Launch at Login"
            alert.informativeText = error.localizedDescription
            activate()
            alert.runModal()
        }
        if svc.status == .requiresApproval {
            notify("Approve KeyBridge in Login Items",
                   "Turn on KeyBridge in System Settings → General → Login Items.")
            SMAppService.openSystemSettingsLoginItems()
        }
        updateLoginItem()
    }

    private func updateLoginItem() {
        switch SMAppService.mainApp.status {
        case .enabled:
            loginItem.state = .on
            loginItem.title = "Launch at Login"
        case .requiresApproval:
            loginItem.state = .mixed
            loginItem.title = "Launch at Login (approve in System Settings)"
        default:
            loginItem.state = .off
            loginItem.title = "Launch at Login"
        }
    }

    // MARK: – Running from the disk image

    /// Returns true if the app is quitting.
    private func warnIfRunningFromDiskImage() -> Bool {
        let path = Bundle.main.bundlePath
        let fromVolume = path.hasPrefix("/Volumes/")
        guard fromVolume || path.contains("/AppTranslocation/") else { return false }

        activate()
        let alert = NSAlert()
        alert.messageText = "Move KeyBridge to your Applications folder"
        alert.informativeText = "KeyBridge is running from the disk image or Downloads. Drag KeyBridge into Applications, then open it from there so permissions and Launch at Login keep working."
        alert.addButton(withTitle: "Open Applications Folder")
        alert.addButton(withTitle: "Quit")
        alert.addButton(withTitle: "Run Anyway")
        switch alert.runModal() {
        case .alertFirstButtonReturn:
            if fromVolume { NSWorkspace.shared.activateFileViewerSelecting([Bundle.main.bundleURL]) }
            NSWorkspace.shared.open(URL(fileURLWithPath: "/Applications", isDirectory: true))
            NSApp.terminate(nil)
            return true
        case .alertSecondButtonReturn:
            NSApp.terminate(nil)
            return true
        default:
            return false
        }
    }

    // MARK: – UI

    private func buildMenu() {
        let menu = NSMenu()
        menu.delegate = self
        menu.autoenablesItems = false

        modeLine = info("")
        connLine = info("")
        warningLine = info("")
        warningLine.isHidden = true
        accessibilityItem = item("Grant Accessibility Permission…", #selector(openAccessibilitySettings))
        accessibilityItem.isHidden = true
        [modeLine, connLine, warningLine, accessibilityItem].forEach { menu.addItem($0) }
        menu.addItem(.separator())

        toggleItem = item("", #selector(onToggle))
        toggleItem.keyEquivalent = "`"
        toggleItem.keyEquivalentModifierMask = [.control, .shift]
        menu.addItem(toggleItem)
        menu.addItem(.separator())

        menu.addItem(item("Pair a Windows PC…", #selector(showPairingWindow)))
        loginItem = item("Launch at Login", #selector(toggleLaunchAtLogin))
        menu.addItem(loginItem)
        menu.addItem(.separator())

        menu.addItem(item("About KeyBridge", #selector(showAbout)))
        let quit = NSMenuItem(title: "Quit KeyBridge", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        menu.addItem(quit)

        statusItem.menu = menu
        updateUI()
    }

    func menuWillOpen(_ menu: NSMenu) {
        if remoteMode { checkSecureInput() }
        updateLoginItem()
        updateUI()
    }

    private func updateUI() {
        let symbol: String
        let label: String
        if remoteMode && secureInputOn {
            symbol = "exclamationmark.triangle"
            label = "KeyBridge: Windows mode, blocked by Secure Input"
        } else if remoteMode {
            symbol = "pc"
            label = "KeyBridge: Windows mode"
        } else {
            symbol = "keyboard"
            label = "KeyBridge: Local mode"
        }
        if let button = statusItem.button {
            if let img = NSImage(systemSymbolName: symbol, accessibilityDescription: label)?
                .withSymbolConfiguration(.init(pointSize: 15, weight: .regular)) {
                img.isTemplate = true
                button.image = img
                button.title = ""
            } else {
                button.image = nil
                button.title = remoteMode ? "WIN" : "KB"
            }
            button.toolTip = label
        }

        modeLine.title = remoteMode ? "Windows mode: typing on your PC" : "Local mode: typing on this Mac"

        let (status, connected) = connectionStatus()
        connLine.title = status
        pairingWindow?.setStatus(status, connected: connected)

        warningLine.isHidden = !(remoteMode && secureInputOn)
        warningLine.title = "⚠︎ Secure Input is on in another app; keys stay on this Mac"

        accessibilityItem.isHidden = accessibilityGranted
        if !accessibilityGranted { modeLine.title = "Needs Accessibility permission" }

        toggleItem.title = remoteMode ? "Switch to Local Mode" : "Switch to Windows Mode"
        updateLoginItem()
    }

    @objc private func onToggle() { toggle() }

    @objc private func showAbout() {
        activate()
        NSApp.orderFrontStandardAboutPanel(options: [
            .credits: NSAttributedString(string: "Use your Mac keyboard on your Windows PC.",
                                         attributes: [.font: NSFont.systemFont(ofSize: 11)]),
        ])
    }

    /// LSUIElement apps have no visible main menu, but key equivalents still route through it:
    /// this gives the pairing window ⌘C, ⌘A and ⌘W.
    private func installEditMenu() {
        let main = NSMenu()
        let appItem = NSMenuItem()
        appItem.submenu = NSMenu()
        main.addItem(appItem)
        let editItem = NSMenuItem()
        let edit = NSMenu(title: "Edit")
        edit.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        edit.addItem(withTitle: "Close Window", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        editItem.submenu = edit
        main.addItem(editItem)
        NSApp.mainMenu = main
    }

    private func info(_ title: String) -> NSMenuItem {
        let i = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        i.isEnabled = false
        return i
    }

    private func item(_ title: String, _ action: Selector) -> NSMenuItem {
        let i = NSMenuItem(title: title, action: action, keyEquivalent: "")
        i.target = self
        return i
    }

    private func activate() {
        if #available(macOS 14.0, *) { NSApp.activate() } else { NSApp.activate(ignoringOtherApps: true) }
    }

    private func notify(_ title: String, _ body: String) {
        guard Bundle.main.bundleIdentifier != nil else { return }
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        let req = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(req)
    }
}
