import AppKit

/// What the Settings window's PC tab shows about the connection.
struct SettingsConnectionInfo {
    enum State { case notPaired, connected, notConnected, error }
    var state: State
    /// The connected PC's address.
    var host: String?
    /// Smoothed round trip, already formatted (e.g. "3 ms").
    var latency: String?
    /// Why connections can't be accepted (state == .error).
    var detail: String?
}

@MainActor
protocol SettingsWindowDelegate: AnyObject {
    /// Start capturing the next shortcut; returns false (and explains why) if it can't.
    func settingsBeginHotkeyRecording(_ done: @escaping (Hotkey?) -> Void) -> Bool
    func settingsCancelHotkeyRecording()
    var settingsPairedName: String? { get }
    var settingsConnectionStatus: String { get }
    var settingsConnection: SettingsConnectionInfo { get }
    var settingsLaunchAtLoginState: NSControl.StateValue { get }
    func settingsToggleLaunchAtLogin()
    func settingsForgetPC()
    func settingsPairPC()
    func settingsCheckForUpdates()
}

/// Programmatic AppKit preferences window (no SwiftUI/xib, to keep memory low): a `.preference`
/// toolbar of tabs, each a label/control grid that the window resizes to fit.
@MainActor
final class SettingsWindowController: NSWindowController, NSWindowDelegate, NSToolbarDelegate {
    private enum Tab: String, CaseIterable {
        case general, keyboard, clipboard, updates, pc

        var title: String {
            switch self {
            case .general: return "General"
            case .keyboard: return "Keyboard"
            case .clipboard: return "Clipboard"
            case .updates: return "Updates"
            case .pc: return "PC"
            }
        }

        var symbol: String {
            switch self {
            case .general: return "gearshape"
            case .keyboard: return "keyboard"
            case .clipboard: return "list.clipboard"
            case .updates: return "arrow.down.circle"
            case .pc: return "pc"
            }
        }

        var identifier: NSToolbarItem.Identifier { .init("KeyBridge.Settings." + rawValue) }

        init?(identifier: NSToolbarItem.Identifier) {
            guard let tab = Tab.allCases.first(where: { $0.identifier == identifier }) else { return nil }
            self = tab
        }
    }

    // Layout metrics (HIG: 20 pt window margins; labels right-aligned against a shared column).
    private static let contentWidth: CGFloat = 540
    private static let margin: CGFloat = 20
    private static let labelColumnWidth: CGFloat = 150
    private static let columnSpacing: CGFloat = 8
    private static var controlColumnWidth: CGFloat { contentWidth - 2 * margin - labelColumnWidth - columnSpacing }
    /// Help text under a checkbox lines up with the checkbox's title.
    private static let checkboxIndent: CGFloat = 20
    private static let selectedTabKey = "KBSettingsTab"

    private weak var host: SettingsWindowDelegate?
    private let settings = AppSettings.shared
    private var tabViews: [Tab: NSView] = [:]
    private var currentTab: Tab = .general

    // General
    private let loginBox = NSButton(checkboxWithTitle: "Launch KeyBridge at login", target: nil, action: nil)
    private let loginHelp = SettingsWindowController.help("Approve KeyBridge in System Settings › General › Login Items.", indent: true)
    private let notifyBox = NSButton(checkboxWithTitle: "Notify when your PC connects or disconnects", target: nil, action: nil)
    private let soundBox = NSButton(checkboxWithTitle: "Play a sound when switching", target: nil, action: nil)
    // Keyboard
    private let shortcutField = ShortcutField()
    private let recordButton = NSButton(title: "Record Shortcut", target: nil, action: nil)
    private let resetButton = NSButton(title: "Reset", target: nil, action: nil)
    private let hotkeyHint = SettingsWindowController.help("")
    private let swapBox = NSButton(checkboxWithTitle: "Use ⌘ Command as Ctrl on Windows", target: nil, action: nil)
    // Clipboard
    private let clipboardBox = NSButton(checkboxWithTitle: "Share clipboard with your PC", target: nil, action: nil)
    // Updates
    private let updateBox = NSButton(checkboxWithTitle: "Automatically check for updates", target: nil, action: nil)
    private let lastChecked = NSTextField(labelWithString: "")
    private let checkNowButton = NSButton(title: "Check Now", target: nil, action: nil)
    // PC
    private let pcName = NSTextField(labelWithString: "")
    private let pcStatusDot = NSImageView()
    private let pcStatus = NSTextField(labelWithString: "")
    private let pcAddress = NSTextField(labelWithString: "")
    private let pcHelp = SettingsWindowController.help("")
    private let pcButton = NSButton(title: "", target: nil, action: nil)
    private var pcAddressRow: NSGridRow?
    private var pcHelpRow: NSGridRow?
    private var loginHelpRow: NSGridRow?

    private var recording = false
    private var refreshTimer: Timer?

    init(host: SettingsWindowDelegate) {
        self.host = host
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: Self.contentWidth, height: 200),
                              styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.toolbarStyle = .preference
        super.init(window: window)
        window.delegate = self

        configureControls()
        let toolbar = NSToolbar(identifier: "KeyBridge.Settings")
        toolbar.delegate = self
        toolbar.displayMode = .iconAndLabel
        toolbar.allowsUserCustomization = false
        window.toolbar = toolbar

        let saved = UserDefaults.standard.string(forKey: Self.selectedTabKey).flatMap(Tab.init(rawValue:))
        refresh()
        select(saved ?? .general, animated: false)
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

    // MARK: – Toolbar

    func toolbarAllowedItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        Tab.allCases.map(\.identifier)
    }

    func toolbarDefaultItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        Tab.allCases.map(\.identifier)
    }

    func toolbarSelectableItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        Tab.allCases.map(\.identifier)
    }

    func toolbar(_ toolbar: NSToolbar, itemForItemIdentifier itemIdentifier: NSToolbarItem.Identifier,
                 willBeInsertedIntoToolbar flag: Bool) -> NSToolbarItem? {
        guard let tab = Tab(identifier: itemIdentifier) else { return nil }
        let item = NSToolbarItem(itemIdentifier: itemIdentifier)
        item.label = tab.title
        item.paletteLabel = tab.title
        item.toolTip = tab.title
        item.image = NSImage(systemSymbolName: tab.symbol, accessibilityDescription: tab.title)
            ?? NSImage(systemSymbolName: "doc.on.clipboard", accessibilityDescription: tab.title)
        item.target = self
        item.action = #selector(tabClicked(_:))
        return item
    }

    @objc private func tabClicked(_ sender: NSToolbarItem) {
        guard let tab = Tab(identifier: sender.itemIdentifier), tab != currentTab else { return }
        select(tab, animated: true)
    }

    /// Shows `tab`, resizing the window around it while keeping its top edge in place.
    private func select(_ tab: Tab, animated: Bool) {
        guard let window else { return }
        if recording, tab != .keyboard {
            host?.settingsCancelHotkeyRecording()
            stopRecording(nil)
        }
        currentTab = tab
        UserDefaults.standard.set(tab.rawValue, forKey: Self.selectedTabKey)
        window.toolbar?.selectedItemIdentifier = tab.identifier
        window.title = tab.title

        let view = tabView(tab)
        if animated {
            view.alphaValue = 0
            window.contentView = view
            fitWindow(animated: true)
            NSAnimationContext.runAnimationGroup { ctx in
                ctx.duration = 0.15
                view.animator().alphaValue = 1
            }
        } else {
            window.contentView = view
            fitWindow(animated: false)
        }
    }

    /// Resizes the window to the current tab's fitting height (the width never changes).
    private func fitWindow(animated: Bool) {
        guard let window, let view = window.contentView else { return }
        view.layoutSubtreeIfNeeded()
        let target = view.fittingSize.height
        let delta = target - view.frame.height
        guard abs(delta) >= 0.5 else { return }
        var frame = window.frame
        frame.size.height += delta
        frame.origin.y -= delta
        window.setFrame(frame, display: true, animate: animated && window.isVisible)
    }

    private func tabView(_ tab: Tab) -> NSView {
        if let v = tabViews[tab] { return v }
        let grid: NSGridView
        switch tab {
        case .general: grid = generalGrid()
        case .keyboard: grid = keyboardGrid()
        case .clipboard: grid = clipboardGrid()
        case .updates: grid = updatesGrid()
        case .pc: grid = pcGrid()
        }
        let v = Self.container(for: grid)
        tabViews[tab] = v
        return v
    }

    // MARK: – Tabs

    private func generalGrid() -> NSGridView {
        let form = Form()
        form.row("Startup:", loginBox)
        loginHelpRow = form.row(nil, loginHelp, spacing: 4)
        form.row("Notifications:", notifyBox, groupStart: true)
        form.row("Sound:", soundBox, groupStart: true)
        loginHelpRow?.isHidden = host?.settingsLaunchAtLoginState != .mixed
        return form.grid
    }

    private func keyboardGrid() -> NSGridView {
        let shortcutRow = NSStackView(views: [shortcutField, recordButton, resetButton])
        shortcutRow.spacing = 8
        shortcutRow.alignment = .centerY
        let form = Form()
        form.row("Switch shortcut:", shortcutRow, centered: true)
        form.row(nil, hotkeyHint, spacing: 6)
        form.row("Modifier keys:", swapBox, groupStart: true)
        form.row(nil, Self.help("Lets ⌘C, ⌘V and other shortcuts work on the PC like they do on a Mac. ⌃ Control becomes the Windows key.", indent: true), spacing: 4)
        return form.grid
    }

    private func clipboardGrid() -> NSGridView {
        let form = Form()
        form.row("Clipboard:", clipboardBox)
        form.row(nil, Self.help("Copy on one computer, paste on the other. Text only. Passwords copied from password managers aren’t shared.", indent: true), spacing: 4)
        return form.grid
    }

    private func updatesGrid() -> NSGridView {
        let version = NSTextField(labelWithString: "KeyBridge \(UpdateVersion.running)")
        version.isSelectable = true
        let form = Form()
        form.row("Version:", version)
        form.row("Updates:", updateBox, groupStart: true)
        form.row("Last checked:", lastChecked, spacing: 10)
        form.row(nil, checkNowButton, spacing: 12)
        return form.grid
    }

    private func pcGrid() -> NSGridView {
        let status = NSStackView(views: [pcStatusDot, pcStatus])
        status.spacing = 6
        status.alignment = .centerY
        let form = Form()
        form.row("Windows PC:", pcName)
        form.row("Status:", status, spacing: 10)
        pcAddressRow = form.row("Address:", pcAddress, spacing: 10)
        pcHelpRow = form.row(nil, pcHelp, spacing: 4)
        form.row(nil, pcButton, spacing: 16)
        updatePCRows()
        return form.grid
    }

    // MARK: – Building blocks

    private func configureControls() {
        for (b, sel) in [(recordButton, #selector(recordTapped)), (resetButton, #selector(resetTapped)),
                         (swapBox, #selector(swapChanged)), (soundBox, #selector(soundChanged)),
                         (notifyBox, #selector(notifyChanged)), (loginBox, #selector(loginChanged)),
                         (pcButton, #selector(pcButtonTapped)), (updateBox, #selector(updateChanged)),
                         (clipboardBox, #selector(clipboardChanged)), (checkNowButton, #selector(checkNowTapped))] {
            b.target = self
            b.action = sel
        }
        for b in [recordButton, resetButton, pcButton, checkNowButton] { b.bezelStyle = .rounded }
        loginBox.allowsMixedState = true
        shortcutField.target = self
        shortcutField.action = #selector(recordTapped)

        pcName.font = .systemFont(ofSize: NSFont.systemFontSize, weight: .semibold)
        pcName.lineBreakMode = .byTruncatingTail
        pcName.isSelectable = true
        pcStatus.lineBreakMode = .byTruncatingTail
        pcAddress.isSelectable = true
        pcAddress.font = .monospacedDigitSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
        pcStatusDot.imageScaling = .scaleNone
        for f in [pcName, pcStatus, pcAddress, lastChecked] {
            f.widthAnchor.constraint(lessThanOrEqualToConstant: Self.controlColumnWidth).isActive = true
        }
    }

    /// Grid pinned to the top of a fixed-width view. The bottom constraint is not required, so
    /// the window can animate between tab heights without fighting Auto Layout.
    private static func container(for grid: NSGridView) -> NSView {
        let v = NSView()
        grid.translatesAutoresizingMaskIntoConstraints = false
        v.addSubview(grid)
        let bottom = grid.bottomAnchor.constraint(equalTo: v.bottomAnchor, constant: -margin)
        bottom.priority = .defaultLow
        NSLayoutConstraint.activate([
            v.widthAnchor.constraint(equalToConstant: contentWidth),
            grid.topAnchor.constraint(equalTo: v.topAnchor, constant: margin),
            grid.leadingAnchor.constraint(equalTo: v.leadingAnchor, constant: margin),
            bottom,
        ])
        return v
    }

    private static func help(_ s: String, indent: Bool = false) -> NSTextField {
        let l = NSTextField(wrappingLabelWithString: s)
        l.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        l.textColor = .secondaryLabelColor
        l.isSelectable = false
        let width = controlColumnWidth - (indent ? checkboxIndent : 0)
        l.preferredMaxLayoutWidth = width
        l.widthAnchor.constraint(equalToConstant: width).isActive = true
        if indent { l.identifier = Form.indentedIdentifier }
        return l
    }

    /// Two-column label/control grid with the app's shared metrics.
    @MainActor
    private final class Form {
        static let indentedIdentifier = NSUserInterfaceItemIdentifier("KeyBridge.indented")
        let grid = NSGridView(numberOfColumns: 2, rows: 0)

        init() {
            grid.columnSpacing = columnSpacing
            grid.rowSpacing = 0
            grid.column(at: 0).xPlacement = .trailing
            grid.column(at: 0).width = labelColumnWidth
            grid.column(at: 1).xPlacement = .leading
            grid.column(at: 1).width = controlColumnWidth
            grid.rowAlignment = .firstBaseline
        }

        /// Adds a row. `groupStart` leaves extra space above it to separate it from the group above.
        @discardableResult
        func row(_ label: String?, _ control: NSView, groupStart: Bool = false, spacing: CGFloat = 8,
                 centered: Bool = false) -> NSGridRow {
            let labelView: NSView
            if let label {
                let l = NSTextField(labelWithString: label)
                l.alignment = .right
                labelView = l
            } else {
                labelView = NSGridCell.emptyContentView
            }
            var content = control
            if control.identifier == Self.indentedIdentifier {
                // Help text under a checkbox starts where the checkbox's title does.
                let wrapper = NSView()
                control.translatesAutoresizingMaskIntoConstraints = false
                wrapper.addSubview(control)
                NSLayoutConstraint.activate([
                    control.topAnchor.constraint(equalTo: wrapper.topAnchor),
                    control.bottomAnchor.constraint(equalTo: wrapper.bottomAnchor),
                    control.leadingAnchor.constraint(equalTo: wrapper.leadingAnchor, constant: checkboxIndent),
                    control.trailingAnchor.constraint(equalTo: wrapper.trailingAnchor),
                ])
                content = wrapper
            }
            let row = grid.addRow(with: [labelView, content])
            if grid.numberOfRows > 1 { row.topPadding = groupStart ? 20 : spacing }
            if centered {
                row.rowAlignment = .none
                row.yPlacement = .center
            }
            return row
        }
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
            shortcutField.stringValue = settings.hotkey.displayString
            shortcutField.isRecording = false
            hotkeyHint.stringValue = "Press it to switch typing between this Mac and your PC."
            recordButton.title = "Record Shortcut"
        }
        resetButton.isEnabled = !recording && settings.hotkey != .default
        swapBox.state = settings.swapCommandControl ? .on : .off
        soundBox.state = settings.playSwitchSound ? .on : .off
        notifyBox.state = settings.showNotifications ? .on : .off
        clipboardBox.state = settings.shareClipboard ? .on : .off
        let login = host?.settingsLaunchAtLoginState ?? .off
        loginBox.state = login
        updateBox.state = settings.autoCheckUpdates ? .on : .off
        lastChecked.stringValue = settings.lastUpdateCheck.map { Self.dateFormatter.string(from: $0) } ?? "Never"

        var layoutChanged = false
        if let row = loginHelpRow, row.isHidden != (login != .mixed) {
            row.isHidden = login != .mixed
            layoutChanged = true
        }
        if updatePCRows() { layoutChanged = true }
        if layoutChanged, window?.contentView === tabViews[currentTab] { fitWindow(animated: true) }
    }

    /// Returns true if a row was shown or hidden.
    @discardableResult
    private func updatePCRows() -> Bool {
        let info = host?.settingsConnection ?? SettingsConnectionInfo(state: .notPaired)
        let color: NSColor
        switch info.state {
        case .notPaired:
            pcStatus.stringValue = "Not paired"
            color = .tertiaryLabelColor
        case .connected:
            pcStatus.stringValue = info.latency.map { "Connected · \($0)" } ?? "Connected"
            color = .systemGreen
        case .notConnected:
            pcStatus.stringValue = "Not connected"
            color = .tertiaryLabelColor
        case .error:
            pcStatus.stringValue = info.detail ?? "Can’t accept connections"
            color = .systemRed
        }
        pcStatus.toolTip = info.detail
        pcStatusDot.image = NSImage(systemSymbolName: "circle.fill", accessibilityDescription: nil)?
            .withSymbolConfiguration(.init(pointSize: 8, weight: .regular))
        pcStatusDot.contentTintColor = color

        if let name = host?.settingsPairedName {
            pcName.stringValue = name
            pcName.textColor = .labelColor
            pcButton.title = "Forget This PC…"
            pcHelp.stringValue = ""
        } else {
            pcName.stringValue = "None"
            pcName.textColor = .secondaryLabelColor
            pcButton.title = "Pair a Windows PC…"
            pcHelp.stringValue = "Pair your PC to start typing on it from this Mac."
        }
        pcAddress.stringValue = info.host ?? ""

        var changed = false
        let hideAddress = info.state != .connected || info.host == nil
        if let row = pcAddressRow, row.isHidden != hideAddress { row.isHidden = hideAddress; changed = true }
        let hideHelp = host?.settingsPairedName != nil
        if let row = pcHelpRow, row.isHidden != hideHelp { row.isHidden = hideHelp; changed = true }
        return changed
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
        shortcutField.stringValue = "Type shortcut…"
        shortcutField.isRecording = true
        hotkeyHint.stringValue = "Hold one or more of ⌃ ⌥ ⇧ ⌘ and press a key. Esc cancels."
        recordButton.title = "Cancel"
        resetButton.isEnabled = false
    }

    private func stopRecording(_ hotkey: Hotkey?) {
        guard recording else { return }
        recording = false
        shortcutField.isRecording = false
        if let hotkey {
            if hotkey.mods.isEmpty {
                NSSound.beep()
                hotkeyHint.stringValue = "Use at least one of ⌃ ⌥ ⇧ ⌘ so normal typing can’t trigger it."
                shortcutField.stringValue = settings.hotkey.displayString
                recordButton.title = "Record Shortcut"
                resetButton.isEnabled = settings.hotkey != .default
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
    @objc private func clipboardChanged() { settings.shareClipboard = clipboardBox.state == .on }
    @objc private func updateChanged() { settings.autoCheckUpdates = updateBox.state == .on }
    @objc private func loginChanged() { host?.settingsToggleLaunchAtLogin(); refresh() }
    @objc private func checkNowTapped() { host?.settingsCheckForUpdates(); refresh() }

    @objc private func pcButtonTapped() {
        if host?.settingsPairedName != nil { host?.settingsForgetPC() } else { host?.settingsPairPC() }
        refresh()
    }
}

/// Shows the current shortcut in a rounded, key-cap-like well; clicking it starts recording.
@MainActor
private final class ShortcutField: NSControl {
    private let label = NSTextField(labelWithString: "")

    var isRecording = false {
        didSet {
            label.textColor = isRecording ? .secondaryLabelColor : .labelColor
            needsDisplay = true
        }
    }

    override var stringValue: String {
        get { label.stringValue }
        set { label.stringValue = newValue; setAccessibilityValue(newValue) }
    }

    init() {
        super.init(frame: .zero)
        label.font = .systemFont(ofSize: 15, weight: .medium)
        label.alignment = .center
        label.lineBreakMode = .byTruncatingTail
        label.translatesAutoresizingMaskIntoConstraints = false
        addSubview(label)
        translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            widthAnchor.constraint(equalToConstant: 128),
            heightAnchor.constraint(equalToConstant: 28),
            label.centerYAnchor.constraint(equalTo: centerYAnchor),
            label.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 8),
            label.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -8),
        ])
        setAccessibilityRole(.button)
        setAccessibilityLabel("Switch shortcut")
        toolTip = "Click to record a new shortcut"
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not used") }

    override func draw(_ dirtyRect: NSRect) {
        let rect = bounds.insetBy(dx: 1, dy: 1)
        let path = NSBezierPath(roundedRect: rect, xRadius: 6, yRadius: 6)
        NSColor.controlBackgroundColor.setFill()
        path.fill()
        if isRecording {
            path.lineWidth = 2
            NSColor.controlAccentColor.setStroke()
        } else {
            path.lineWidth = 1
            NSColor.separatorColor.setStroke()
        }
        path.stroke()
    }

    override func mouseDown(with event: NSEvent) {
        sendAction(action, to: target)
    }

    override func accessibilityPerformPress() -> Bool {
        sendAction(action, to: target)
    }

    override func resetCursorRects() { addCursorRect(bounds, cursor: .pointingHand) }
}
