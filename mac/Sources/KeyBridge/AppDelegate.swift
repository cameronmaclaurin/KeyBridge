import AppKit
import ApplicationServices
import CryptoKit
import Carbon.HIToolbox  // IsSecureEventInputEnabled
import ServiceManagement
import UserNotifications

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate, SettingsWindowDelegate {
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    private let capture = KeyCapture()
    private var server: KBP2Server?
    /// Display name of the paired PC; nil = not paired (no long-term key stored).
    private var pairedPCName: String?
    private var remoteMode = false
    private var accessibilityGranted = false
    private var secureInputOn = false
    private var listenerError: String?

    private var permissionTimer: Timer?
    private var secureInputTimer: Timer?
    private var listenerRetryTimer: Timer?
    private var pairingWindow: PairingWindowController?
    private var pairingExpiryTimer: Timer?
    private var nameWatcher: SystemNameWatcher?
    private var settingsWindow: SettingsWindowController?
    private let updater = UpdateController()
    private let settings = AppSettings.shared
    private var clipboardSync: ClipboardSync?  // §5a shared clipboard

    private let menuHeader = MenuHeaderView()
    private var connLine: NSMenuItem!
    private var forgetItem: NSMenuItem!
    private var warningLine: NSMenuItem!
    private var accessibilityItem: NSMenuItem!
    private var toggleItem: NSMenuItem!
    private var loginItem: NSMenuItem!

    func applicationDidFinishLaunching(_ n: Notification) {
        installEditMenu()
        buildMenu()
        applySettings()
        settings.onChange = { [weak self] in self?.applySettings() }
        if warnIfRunningFromDiskImage() { return }

        if Bundle.main.bundleIdentifier != nil {
            UNUserNotificationCenter.current().requestAuthorization(options: [.alert]) { _, _ in }
        }

        PairingStore.deleteLegacyCode()
        var psk: SymmetricKey?
        switch PairingStore.load() {
        case .found(let pairing):
            psk = pairing.ltk
            pairedPCName = pairing.pcName
        case .notFound:
            break
        case .failed(let status):
            // e.g. the user denied Keychain access: run unpaired; pairing again replaces the item.
            NSLog("[KeyBridge] Keychain read failed: \(status)")
        }
        startServer(psk: psk)

        startCapture()
        updateUI()
        if psk == nil { showPairingWindow() }
        // `open KeyBridge.app --args -KBShowSettings YES` (handy for screenshots and support).
        if UserDefaults.standard.bool(forKey: "KBShowSettings") { showSettings() }
        updater.start()
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

    private func startServer(psk: SymmetricKey?) {
        let s = KBP2Server(psk: psk)
        s.onListenerEvent = { [weak self] e in self?.listenerEvent(e) }
        s.onAuthenticated = { [weak self] host, replaced in self?.pcConnected(host, replaced: replaced) }
        s.onSessionEnded = { [weak self] in self?.pcDisconnected() }
        s.onPairingEvent = { [weak self] e in self?.pairingEvent(e) }
        let name = NetworkInfo.computerName()
        s.macDisplayName = name
        s.setServiceName(name)  // §1a: advertise _keybridge._tcp as this Mac's name
        server = s
        s.clipboardEnabled = settings.shareClipboard
        clipboardSync = ClipboardSync(server: s)
        nameWatcher = SystemNameWatcher { [weak self] in self?.systemNamesChanged() }
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

    /// The computer was renamed (or its network name changed): follow it.
    private func systemNamesChanged() {
        let name = NetworkInfo.computerName()
        server?.macDisplayName = name
        server?.setServiceName(name)
        pairingWindow?.refreshAddresses()
    }

    private func pcConnected(_ host: String, replaced: String?) {
        if remoteMode, let replaced, replaced != host {
            // A different PC took over: don't keep typing into it without the user noticing.
            leaveWindowsMode(sendReleaseAll: false)
        }
        if replaced != host { notify("Windows PC connected", host, optional: true) }
        updateUI()
    }

    private func pcDisconnected() {
        if remoteMode {
            leaveWindowsMode(sendReleaseAll: false)
            notify("Windows PC disconnected", "Your keys are going to this Mac again.", optional: true)
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
        } else if pairedPCName == nil {
            notify("No Windows PC paired", "Pair your PC with this Mac first.")
            showPairingWindow()
        } else {
            notify("No Windows PC connected",
                   "Open KeyBridge on \(pairedPCName ?? "your PC") and make sure it’s on the same network as this Mac.")
        }
        updateUI()
    }

    private func enterWindowsMode() {
        remoteMode = true
        if settings.playSwitchSound { NSSound(named: "Pop")?.play() }
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
        if settings.playSwitchSound { NSSound(named: "Bottle")?.play() }
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

    // MARK: – Pairing (docs/PROTOCOL.md §2)

    /// Opening the window starts pairing mode; closing it ends pairing mode.
    @objc private func showPairingWindow() {
        guard server != nil else { return }
        if let w = pairingWindow {
            switch w.state {
            case .expired, .failed, .done: startPairingMode()
            default: w.refreshAddresses()
            }
        } else {
            let w = PairingWindowController(state: .expired)
            w.onStartAgain = { [weak self] in self?.startPairingMode() }
            w.onConfirm = { [weak self] in self?.confirmPairing() }
            w.onCancel = { [weak self] in self?.server?.cancelPairing() }
            w.onClose = { [weak self] in self?.pairingWindowClosed() }
            pairingWindow = w
            startPairingMode()
        }
        pairingWindow?.show()
    }

    /// §2.1: accept one pairing connection for at most 3 minutes.
    private func startPairingMode() {
        guard let server, !server.isPairing else { return }
        server.pairingModeEnabled = true
        pairingExpiryTimer?.invalidate()
        pairingExpiryTimer = Timer.scheduledTimer(timeInterval: KBP2Pairing.pairingModeDuration, target: self,
                                                  selector: #selector(pairingModeExpired),
                                                  userInfo: nil, repeats: false)
        pairingWindow?.setState(.waiting(deadline: Date().addingTimeInterval(KBP2Pairing.pairingModeDuration)))
    }

    /// No new pairing connections after 3 minutes. One already comparing numbers keeps its
    /// own 120 s confirmation timeout.
    @objc private func pairingModeExpired() {
        pairingExpiryTimer = nil
        server?.pairingModeEnabled = false
        if case .waiting = pairingWindow?.state { pairingWindow?.setState(.expired) }
    }

    private func endPairingMode() {
        pairingExpiryTimer?.invalidate()
        pairingExpiryTimer = nil
        server?.pairingModeEnabled = false
    }

    private func pairingWindowClosed() {
        pairingWindow = nil
        endPairingMode()
        server?.cancelPairing()
    }

    private func confirmPairing() {
        guard case .compare(let name, let sas) = pairingWindow?.state else { return }
        pairingWindow?.setState(.waitingForPC(pcName: name, sas: sas))
        server?.confirmPairing()  // may report .paired right away if the PC already confirmed
    }

    private func pairingEvent(_ e: KBP2Server.PairingEvent) {
        switch e {
        case .started:
            pairingWindow?.show()  // a PC connected: bring the window to the front
        case .compare(let name, let sas):
            pairingWindow?.setState(.compare(pcName: name, sas: sas))
            pairingWindow?.show()
        case .paired(let ltk, let name):
            endPairingMode()
            guard PairingStore.save(ltk: ltk, pcName: name) else {
                pairingWindow?.setState(.failed(detail:
                    "KeyBridge couldn’t save the pairing in your Keychain. Click Start Again to try again."))
                return
            }
            // Replaces any previous pairing; drop the current session (§2.4).
            if remoteMode { leaveWindowsMode(sendReleaseAll: true) }
            pairedPCName = name
            server?.setPSK(ltk)
            pairingWindow?.setState(.done(pcName: name))
            pairingWindow?.show()
            updateUI()
        case .failed(let reason):
            endPairingMode()
            pairingWindow?.setState(.failed(detail: Self.describe(reason)))
        }
    }

    private static func describe(_ reason: KBP2PairingError) -> String {
        switch reason {
        case .cancelled:
            return "Pairing was cancelled. Nothing was changed."
        case .badConfirm:
            return "The PC’s confirmation didn’t match. Make sure you chose this Mac on your PC, then try again."
        case .timeout:
            return "The PC didn’t respond in time. Make sure you click Confirm on both computers, then try again."
        case .closed:
            return "The PC cancelled pairing or disconnected."
        case .badMagic, .invalidPoint:
            return "The PC sent something KeyBridge didn’t understand. Make sure both computers have the latest KeyBridge."
        }
    }

    @objc private func forgetPC() {
        guard let name = pairedPCName else { return }
        activate()
        let alert = NSAlert()
        alert.messageText = "Forget \(name)?"
        alert.informativeText = "This Mac will stop sending keystrokes to \(name). To use them together again, pair again."
        let forget = alert.addButton(withTitle: "Forget This PC")
        forget.hasDestructiveAction = true
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        if remoteMode { leaveWindowsMode(sendReleaseAll: true) }
        PairingStore.delete()
        pairedPCName = nil
        server?.setPSK(nil)  // drops the current session; new ones are refused until paired
        updateUI()
    }

    private func connectionStatus() -> String? {
        if let err = listenerError { return "Can’t accept connections on port \(KBP2.port): \(err)" }
        if let host = server?.peerHost {
            if let rtt = server?.roundTrip {
                return "PC connected: \(host) · \(Self.formatLatency(rtt))"
            }
            return "PC connected: \(host)"
        }
        return pairedPCName == nil ? nil : "PC not connected"
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

        // Status: header, then any problem that needs attention.
        let header = NSMenuItem()
        header.view = menuHeader
        header.isEnabled = false
        menu.addItem(header)
        warningLine = info("Secure Input in another app is blocking KeyBridge", symbol: "exclamationmark.triangle")
        warningLine.isHidden = true
        connLine = info("", symbol: "exclamationmark.triangle")
        connLine.isHidden = true
        accessibilityItem = item("Grant Accessibility Permission…", #selector(openAccessibilitySettings), symbol: "lock.shield")
        accessibilityItem.isHidden = true
        [warningLine, connLine, accessibilityItem].forEach { menu.addItem($0) }
        menu.addItem(.separator())

        // Switching.
        toggleItem = item("", #selector(onToggle), symbol: "arrow.left.arrow.right")
        menu.addItem(toggleItem)
        menu.addItem(.separator())

        // Your PC.
        menu.addItem(item("Pair a Windows PC…", #selector(showPairingWindow), symbol: "link.badge.plus"))
        forgetItem = item("Forget This PC…", #selector(forgetPC), symbol: "minus.circle")
        menu.addItem(forgetItem)
        menu.addItem(.separator())

        // App.
        loginItem = item("Launch at Login", #selector(toggleLaunchAtLogin), symbol: "sunrise")
        menu.addItem(loginItem)
        let settingsItem = item("Settings…", #selector(showSettings), symbol: "gearshape")
        settingsItem.keyEquivalent = ","
        menu.addItem(settingsItem)
        menu.addItem(item("Check for Updates…", #selector(checkForUpdates), symbol: "arrow.down.circle"))
        menu.addItem(item("About KeyBridge", #selector(showAbout), symbol: "info.circle"))
        menu.addItem(.separator())
        let quit = NSMenuItem(title: "Quit KeyBridge", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        quit.image = NSMenuItem.symbolImage("power")
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

        updateMenuHeader()
        connLine.title = listenerError != nil ? (connectionStatus() ?? "") : ""
        connLine.isHidden = listenerError == nil
        forgetItem.isHidden = pairedPCName == nil
        forgetItem.title = pairedPCName.map { "Forget \($0)…" } ?? "Forget This PC…"
        warningLine.isHidden = !(remoteMode && secureInputOn)
        accessibilityItem.isHidden = accessibilityGranted

        toggleItem.title = remoteMode ? "Switch to Local Mode" : "Switch to Windows Mode"
        if let key = settings.hotkey.menuKeyEquivalent {
            toggleItem.keyEquivalent = key.key
            toggleItem.keyEquivalentModifierMask = key.modifiers
        } else {
            toggleItem.keyEquivalent = ""
            toggleItem.title += "   " + settings.hotkey.displayString
        }
        updateLoginItem()
    }

    /// Header: what the keyboard is typing on, and the paired PC's connection.
    private func updateMenuHeader() {
        let title: String
        let symbol: String
        if !accessibilityGranted {
            title = "Needs Accessibility permission"
            symbol = "lock"
        } else if remoteMode && secureInputOn {
            title = "Keys are staying on this Mac"
            symbol = "exclamationmark.triangle"
        } else if remoteMode {
            title = "Typing on your PC"
            symbol = "pc"
        } else {
            title = "Typing on this Mac"
            symbol = "keyboard"
        }

        let subtitle: String
        let dot: MenuHeaderView.Dot
        let c = settingsConnection
        let name = pairedPCName ?? c.host ?? "Windows PC"
        switch c.state {
        case .error:
            subtitle = "\(name) · Can’t accept connections"
            dot = .red
        case .connected:
            subtitle = "\(name) · Connected" + (c.latency.map { " · \($0)" } ?? "")
            dot = .green
        case .notConnected:
            subtitle = "\(name) · Not connected"
            dot = .gray
        case .notPaired:
            subtitle = "No PC paired"
            dot = .gray
        }
        menuHeader.update(title: title, subtitle: subtitle, symbol: symbol,
                          active: remoteMode && accessibilityGranted, dot: dot)
    }

    @objc private func onToggle() { toggle() }
    @objc private func checkForUpdates() { updater.checkNow() }

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

    private func info(_ title: String, symbol: String? = nil) -> NSMenuItem {
        let i = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        i.isEnabled = false
        i.image = symbol.flatMap(NSMenuItem.symbolImage)
        return i
    }

    private func item(_ title: String, _ action: Selector, symbol: String? = nil) -> NSMenuItem {
        let i = NSMenuItem(title: title, action: action, keyEquivalent: "")
        i.target = self
        i.image = symbol.flatMap(NSMenuItem.symbolImage)
        return i
    }

    private func activate() {
        if #available(macOS 14.0, *) { NSApp.activate() } else { NSApp.activate(ignoringOtherApps: true) }
    }

    /// `optional` notifications (connect/disconnect) respect the "Show notifications" setting;
    /// warnings and answers to something the user just did always show.
    private func notify(_ title: String, _ body: String, optional: Bool = false) {
        guard Bundle.main.bundleIdentifier != nil else { return }
        if optional && !settings.showNotifications { return }
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        let req = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(req)
    }

    // MARK: – Settings

    private func applySettings() {
        if remoteMode && capture.swapCommandControl != settings.swapCommandControl {
            // The mapping of held modifiers is about to change: drop everything on the PC first.
            capture.releaseAllRemote()
            server?.sendReleaseAll()
        }
        capture.hotkey = settings.hotkey
        capture.swapCommandControl = settings.swapCommandControl
        updater.applySchedule()
        server?.clipboardEnabled = settings.shareClipboard  // starts/stops clipboard polling
        updateUI()
    }

    @objc private func showSettings() {
        if settingsWindow == nil { settingsWindow = SettingsWindowController(host: self) }
        settingsWindow?.show()
    }

    static func formatLatency(_ rtt: TimeInterval) -> String {
        let ms = rtt * 1000
        return ms < 1 ? "<1 ms" : String(format: "%.0f ms", ms)
    }

    func settingsBeginHotkeyRecording(_ done: @escaping (Hotkey?) -> Void) -> Bool {
        if remoteMode {
            NSSound.beep()
            return false
        }
        if !accessibilityGranted {
            notify("KeyBridge needs Accessibility permission",
                   "Turn on KeyBridge in System Settings → Privacy & Security → Accessibility.")
            openAccessibilitySettings()
            return false
        }
        capture.onRecordHotkey = done
        return true
    }

    func settingsCancelHotkeyRecording() { capture.onRecordHotkey = nil }
    var settingsPairedName: String? { pairedPCName }
    var settingsConnectionStatus: String { connectionStatus() ?? "" }

    var settingsConnection: SettingsConnectionInfo {
        if let err = listenerError {
            return SettingsConnectionInfo(state: .error, detail: "Can’t accept connections on port \(KBP2.port): \(err)")
        }
        if let host = server?.peerHost {
            return SettingsConnectionInfo(state: .connected, host: host,
                                          latency: server?.roundTrip.map(Self.formatLatency))
        }
        return SettingsConnectionInfo(state: pairedPCName == nil ? .notPaired : .notConnected)
    }

    func settingsCheckForUpdates() { updater.checkNow() }

    var settingsLaunchAtLoginState: NSControl.StateValue {
        switch SMAppService.mainApp.status {
        case .enabled: return .on
        case .requiresApproval: return .mixed
        default: return .off
        }
    }

    func settingsToggleLaunchAtLogin() { toggleLaunchAtLogin() }
    func settingsForgetPC() { forgetPC() }
    func settingsPairPC() { showPairingWindow() }
}
