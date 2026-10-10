import AppKit

@MainActor
protocol SettingsWindowDelegate: AnyObject {
    /// Start capturing the next shortcut; returns false (and explains why) if it can't.
    func settingsBeginHotkeyRecording(_ done: @escaping (Hotkey?) -> Void) -> Bool
    func settingsCancelHotkeyRecording()
    var settingsPairedName: String? { get }
    var settingsConnectionStatus: String { get }
    var settingsLaunchAtLoginState: NSControl.StateValue { get }
    func settingsToggleLaunchAtLogin()
    func settingsForgetPC()
    func settingsPairPC()
}

/// Programmatic AppKit settings window (no SwiftUI/xib, to keep memory low).
@MainActor
final class SettingsWindowController: NSWindowController, NSWindowDelegate {
    private weak var host: SettingsWindowDelegate?
    private let settings = AppSettings.shared

    private let hotkeyField = NSTextField(labelWithString: "")
    private let recordButton = NSButton(title: "Record Shortcut", target: nil, action: nil)
    private let resetButton = NSButton(title: "Reset", target: nil, action: nil)
    private let hotkeyHint = NSTextField(labelWithString: "")
    private let swapBox = NSButton(checkboxWithTitle: "Use ⌘ Command as Ctrl on Windows", target: nil, action: nil)
    private let soundBox = NSButton(checkboxWithTitle: "Play a sound when switching", target: nil, action: nil)
    private let notifyBox = NSButton(checkboxWithTitle: "Show notifications", target: nil, action: nil)
    private let loginBox = NSButton(checkboxWithTitle: "Launch KeyBridge at login", target: nil, action: nil)
    private let updateBox = NSButton(checkboxWithTitle: "Automatically check for updates", target: nil, action: nil)
    private let lastChecked = NSTextField(labelWithString: "")
    private let pcName = NSTextField(labelWithString: "")
    private let pcStatus = NSTextField(labelWithString: "")
    private let pcButton = NSButton(title: "", target: nil, action: nil)
    private var recording = false
    private var refreshTimer: Timer?

    init(host: SettingsWindowDelegate) {
        self.host = host
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 460, height: 380),
                              styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = "KeyBridge Settings"
        window.isReleasedWhenClosed = false
        super.init(window: window)
        window.delegate = self
        buildUI()
        refresh()
        window.center()
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not used") }

    func show() {
        refresh()
        refreshTimer?.invalidate()
        refreshTimer = Timer.scheduledTimer(timeInterval: 2, target: self, selector: #selector(refresh),
                                            userInfo: nil, repeats: true)
        showWindow(nil)
        window?.makeKeyAndOrderFront(nil)
        if #available(macOS 14.0, *) { NSApp.activate() } else { NSApp.activate(ignoringOtherApps: true) }
    }

    func windowWillClose(_ notification: Notification) {
        refreshTimer?.invalidate()
        refreshTimer = nil
        if recording { stopRecording(nil) }
    }

    // MARK: – Layout

    private func buildUI() {
        hotkeyField.font = .monospacedSystemFont(ofSize: 15, weight: .medium)
        hotkeyHint.font = .systemFont(ofSize: 11)
        hotkeyHint.textColor = .secondaryLabelColor
        pcStatus.textColor = .secondaryLabelColor
        pcName.font = .systemFont(ofSize: 13, weight: .medium)
        lastChecked.font = .systemFont(ofSize: 11)
        lastChecked.textColor = .secondaryLabelColor

        for (b, sel) in [(recordButton, #selector(recordTapped)), (resetButton, #selector(resetTapped)),
                         (swapBox, #selector(swapChanged)), (soundBox, #selector(soundChanged)),
                         (notifyBox, #selector(notifyChanged)), (loginBox, #selector(loginChanged)),
                         (pcButton, #selector(pcButtonTapped)), (updateBox, #selector(updateChanged))] {
            b.target = self
            b.action = sel
        }
        recordButton.bezelStyle = .rounded
        resetButton.bezelStyle = .rounded
        pcButton.bezelStyle = .rounded

        let hotkeyRow = NSStackView(views: [hotkeyField, recordButton, resetButton])
        hotkeyRow.spacing = 10
        let hotkeyCol = column([hotkeyRow, hotkeyHint])

        let swapHelp = help("Lets ⌘C, ⌘V and other shortcuts work on the PC like on a Mac. ⌃ Control becomes the Windows key.")
        let keyboardCol = column([swapBox, swapHelp])
        let feedbackCol = column([soundBox, notifyBox, loginBox])
        let pcCol = column([pcName, pcStatus, pcButton])
        let updateCol = column([updateBox, lastChecked])

        let grid = NSGridView(views: [
            [label("Switch shortcut:"), hotkeyCol],
            [label("Keyboard:"), keyboardCol],
            [label("General:"), feedbackCol],
            [label("Windows PC:"), pcCol],
            [label("Updates:"), updateCol],
        ])
        grid.rowSpacing = 18
        grid.columnSpacing = 12
        grid.column(at: 0).xPlacement = .trailing
        grid.rowAlignment = .firstBaseline
        for r in 0..<grid.numberOfRows { grid.row(at: r).yPlacement = .top }
        grid.translatesAutoresizingMaskIntoConstraints = false

        let content = NSView()
        content.addSubview(grid)
        NSLayoutConstraint.activate([
            grid.topAnchor.constraint(equalTo: content.topAnchor, constant: 24),
            grid.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 24),
            grid.trailingAnchor.constraint(lessThanOrEqualTo: content.trailingAnchor, constant: -24),
            grid.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -24),
            swapHelp.widthAnchor.constraint(lessThanOrEqualToConstant: 280),
        ])
        window?.contentView = content
        window?.setContentSize(content.fittingSize)
    }

    private func column(_ views: [NSView]) -> NSStackView {
        let s = NSStackView(views: views)
        s.orientation = .vertical
        s.alignment = .leading
        s.spacing = 6
        return s
    }

    private func label(_ s: String) -> NSTextField {
        let l = NSTextField(labelWithString: s)
        l.alignment = .right
        return l
    }

    private func help(_ s: String) -> NSTextField {
        let l = NSTextField(wrappingLabelWithString: s)
        l.font = .systemFont(ofSize: 11)
        l.textColor = .secondaryLabelColor
        return l
    }

    // MARK: – State

    private static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        f.doesRelativeDateFormatting = true
        return f
    }()

    @objc func refresh() {
        if !recording {
            hotkeyField.stringValue = settings.hotkey.displayString
            hotkeyHint.stringValue = "Press it on the Mac to switch between typing on the Mac and the PC."
            recordButton.title = "Record Shortcut"
        }
        resetButton.isEnabled = !recording && settings.hotkey != .default
        swapBox.state = settings.swapCommandControl ? .on : .off
        soundBox.state = settings.playSwitchSound ? .on : .off
        notifyBox.state = settings.showNotifications ? .on : .off
        loginBox.state = host?.settingsLaunchAtLoginState ?? .off
        updateBox.state = settings.autoCheckUpdates ? .on : .off
        lastChecked.stringValue = "Last checked: " + (settings.lastUpdateCheck.map { Self.dateFormatter.string(from: $0) } ?? "Never")

        if let name = host?.settingsPairedName {
            pcName.stringValue = name
            pcStatus.stringValue = host?.settingsConnectionStatus ?? ""
            pcButton.title = "Forget This PC…"
        } else {
            pcName.stringValue = "Not paired"
            pcStatus.stringValue = "Pair your PC to start typing on it."
            pcButton.title = "Pair a Windows PC…"
        }
    }

    // MARK: – Actions

    @objc private func recordTapped() {
        if recording {
            host?.settingsCancelHotkeyRecording()
            stopRecording(nil)
            return
        }
        guard let host, host.settingsBeginHotkeyRecording({ [weak self] hk in self?.stopRecording(hk) }) else { return }
        recording = true
        hotkeyField.stringValue = "Press new shortcut…"
        hotkeyHint.stringValue = "Hold one or more of ⌃ ⌥ ⇧ ⌘ and press a key. Esc cancels."
        recordButton.title = "Cancel"
        resetButton.isEnabled = false
    }

    private func stopRecording(_ hotkey: Hotkey?) {
        guard recording else { return }
        recording = false
        if let hotkey {
            if hotkey.mods.isEmpty {
                NSSound.beep()
                hotkeyHint.stringValue = "Use at least one of ⌃ ⌥ ⇧ ⌘ so normal typing can’t trigger it."
                hotkeyField.stringValue = settings.hotkey.displayString
                recordButton.title = "Record Shortcut"
                return
            }
            settings.hotkey = hotkey
        }
        refresh()
    }

    @objc private func resetTapped() { settings.hotkey = .default; refresh() }
    @objc private func swapChanged() { settings.swapCommandControl = swapBox.state == .on }
    @objc private func soundChanged() { settings.playSwitchSound = soundBox.state == .on }
    @objc private func notifyChanged() { settings.showNotifications = notifyBox.state == .on }
    @objc private func updateChanged() { settings.autoCheckUpdates = updateBox.state == .on }
    @objc private func loginChanged() { host?.settingsToggleLaunchAtLogin(); refresh() }

    @objc private func pcButtonTapped() {
        if host?.settingsPairedName != nil { host?.settingsForgetPC() } else { host?.settingsPairPC() }
        refresh()
    }
}
