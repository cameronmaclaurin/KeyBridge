import AppKit

/// "Pair a Windows PC" window, built in code (no SwiftUI/xib). Created on demand and
/// released when closed so it costs nothing while hidden. It only displays state; the
/// AppDelegate drives pairing mode (docs/PROTOCOL.md §2.1) and the server.
@MainActor
final class PairingWindowController: NSObject, NSWindowDelegate {
    enum State: Equatable {
        /// Pairing mode is on until `deadline`.
        case waiting(deadline: Date)
        /// Pairing mode timed out with no PC.
        case expired
        case compare(pcName: String, sas: UInt32)
        /// The user confirmed; waiting for the PC's confirmation.
        case waitingForPC(pcName: String, sas: UInt32)
        case done(pcName: String)
        case failed(detail: String)
    }

    var onStartAgain: (() -> Void)?
    var onConfirm: (() -> Void)?
    var onCancel: (() -> Void)?
    var onClose: (() -> Void)?

    private(set) var state: State
    private let window: NSWindow
    /// Card layout: content width and side margins.
    private let width: CGFloat = 440
    private let inset: CGFloat = 40
    private var textWidth: CGFloat { width - 2 * inset }
    private var countdownField: NSTextField?
    private var countdownTimer: Timer?
    private var copyButtons: [NSButton] = []

    init(state: State) {
        self.state = state
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 440, height: 300),
                          styleMask: [.titled, .closable, .fullSizeContentView], backing: .buffered, defer: true)
        super.init()
        window.title = "Pair a Windows PC"
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.isMovableByWindowBackground = true
        window.isReleasedWhenClosed = false
        window.delegate = self
        render()
    }

    func show() {
        if #available(macOS 14.0, *) { NSApp.activate() } else { NSApp.activate(ignoringOtherApps: true) }
        if !window.isVisible { window.center() }
        window.makeKeyAndOrderFront(nil)
    }

    func setState(_ newState: State) {
        guard newState != state else { return }
        state = newState
        render()
    }

    /// Computer name or addresses changed: redraw the waiting screen.
    func refreshAddresses() {
        if case .waiting = state { render() }
    }

    func close() { window.performClose(nil) }

    // MARK: Rendering

    private func render() {
        countdownTimer?.invalidate()
        countdownTimer = nil
        countdownField = nil
        copyButtons.removeAll()
        NSObject.cancelPreviousPerformRequests(withTarget: self)

        let views: [NSView]
        let buttons: [NSButton]
        switch state {
        case .waiting(let deadline):
            views = waitingViews(deadline: deadline)
            buttons = [button("Cancel", #selector(closeWindow), isCancel: true)]
        case .expired:
            views = [
                Self.appIcon(),
                Self.title("Pair a Windows PC"),
                body("KeyBridge stopped waiting for your PC. Click Start Again, then choose this Mac on your PC within 3 minutes."),
            ]
            buttons = [button("Close", #selector(closeWindow), isCancel: true),
                       button("Start Again", #selector(startAgain), isDefault: true)]
        case .compare(let pcName, let sas):
            views = compareViews(pcName: pcName, sas: sas, waiting: false)
            buttons = [button("Cancel", #selector(cancel), isCancel: true),
                       button("Confirm", #selector(confirm), isDefault: true)]
        case .waitingForPC(let pcName, let sas):
            views = compareViews(pcName: pcName, sas: sas, waiting: true)
            buttons = [button("Cancel", #selector(cancel), isCancel: true)]
        case .done(let pcName):
            views = [
                Self.symbol("checkmark.circle.fill", color: .systemGreen, label: "Paired"),
                Self.title("Paired with \(pcName)"),
                body("To type on your PC, press \(AppSettings.shared.hotkey.displayString) or choose Switch to Windows Mode from the KeyBridge menu."),
            ]
            buttons = [button("Done", #selector(closeWindow), isDefault: true)]
            perform(#selector(closeWindow), with: nil, afterDelay: 2.5)
        case .failed(let detail):
            views = [
                Self.symbol("exclamationmark.triangle.fill", color: .systemOrange, label: "Warning"),
                Self.title("Pairing didn’t complete"),
                body(detail),
            ]
            buttons = [button("Close", #selector(closeWindow), isCancel: true),
                       button("Start Again", #selector(startAgain), isDefault: true)]
        }

        let card = NSStackView(views: views)
        card.orientation = .vertical
        card.alignment = .centerX
        card.spacing = 8
        // Icon → title → body get tighter spacing than the sections that follow.
        if views.count > 1 { card.setCustomSpacing(14, after: views[0]) }
        if views.count > 3 { card.setCustomSpacing(20, after: views[2]) }
        if views.count > 4 { card.setCustomSpacing(18, after: views[3]) }

        let buttonRow = NSStackView(views: buttons)
        buttonRow.spacing = 12
        let content = NSView()
        for v in [card, buttonRow] {
            v.translatesAutoresizingMaskIntoConstraints = false
            content.addSubview(v)
        }
        // Not required, so the window can animate between heights without layout conflicts.
        let bottom = buttonRow.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -20)
        bottom.priority = .defaultLow
        NSLayoutConstraint.activate([
            content.widthAnchor.constraint(equalToConstant: width),
            card.topAnchor.constraint(equalTo: content.topAnchor, constant: 36),
            card.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: inset),
            card.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -inset),
            buttonRow.topAnchor.constraint(equalTo: card.bottomAnchor, constant: 28),
            buttonRow.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20),
            bottom,
        ])

        let animate = window.isVisible
        window.contentView = content
        content.layoutSubtreeIfNeeded()
        let size = content.fittingSize
        var frame = window.frameRect(forContentRect: NSRect(origin: .zero, size: size))
        if animate {
            frame.origin = NSPoint(x: window.frame.minX, y: window.frame.maxY - frame.height)
            window.setFrame(frame, display: true, animate: true)
        } else {
            window.setContentSize(size)
        }
    }

    private func waitingViews(deadline: Date) -> [NSView] {
        let name = NetworkInfo.computerName()
        var views: [NSView] = [
            Self.appIcon(),
            Self.title("Pair a Windows PC"),
            body("On your PC, open KeyBridge, choose this Mac from the list, then click Pair."),
        ]

        // This Mac, prominently, with the live countdown.
        let macName = NSTextField(labelWithString: name)
        macName.font = .systemFont(ofSize: 17, weight: .semibold)
        macName.alignment = .center
        macName.lineBreakMode = .byTruncatingMiddle
        macName.isSelectable = true
        macName.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        let macSymbol = NSImageView()
        macSymbol.image = NSImage(systemSymbolName: "laptopcomputer", accessibilityDescription: "This Mac")?
            .withSymbolConfiguration(.init(pointSize: 26, weight: .light))
        macSymbol.contentTintColor = .secondaryLabelColor

        let spinner = NSProgressIndicator()
        spinner.style = .spinning
        spinner.controlSize = .small
        spinner.startAnimation(nil)
        let countdown = NSTextField(labelWithString: "")
        countdown.font = .monospacedDigitSystemFont(ofSize: NSFont.smallSystemFontSize, weight: .regular)
        countdown.textColor = .secondaryLabelColor
        countdownField = countdown
        let status = NSStackView(views: [spinner, countdown])
        status.spacing = 6
        status.alignment = .centerY

        let macStack = NSStackView(views: [macSymbol, macName, status])
        macStack.orientation = .vertical
        macStack.alignment = .centerX
        macStack.spacing = 6
        macStack.setCustomSpacing(4, after: macSymbol)
        macStack.setCustomSpacing(10, after: macName)
        views.append(Self.box(macStack, padding: NSEdgeInsets(top: 16, left: 16, bottom: 14, right: 16), width: textWidth))

        // Fallback: the address to type on the PC.
        let caption = NSTextField(labelWithString: "Not listed? Enter this Mac’s address on your PC:")
        caption.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        caption.textColor = .secondaryLabelColor
        views.append(caption)
        var rows: [NSView] = []
        let host = NetworkInfo.localHostName()
        rows.append(copyRow(host ?? "This Mac has no network name", copyValue: host))
        let ips = NetworkInfo.ipv4Addresses()
        if ips.isEmpty {
            rows.append(copyRow("No network connection", copyValue: nil))
        } else {
            for ip in ips.prefix(3) { rows.append(copyRow(ip, copyValue: ip)) }
        }
        let list = NSStackView(views: rows)
        list.orientation = .vertical
        list.spacing = 6
        views.append(list)

        updateCountdown()
        let t = Timer(timeInterval: 1, target: self, selector: #selector(updateCountdown), userInfo: nil, repeats: true)
        RunLoop.main.add(t, forMode: .common)
        countdownTimer = t
        return views
    }

    private func compareViews(pcName: String, sas: UInt32, waiting: Bool) -> [NSView] {
        let title = Self.title("Pair with \(pcName)?")
        var views: [NSView] = [Self.appIcon(), title, body("Make sure your PC shows the same number.")]

        let number = NSTextField(labelWithString: "")
        let centered = NSMutableParagraphStyle()
        centered.alignment = .center
        number.attributedStringValue = NSAttributedString(string: KBP2Pairing.formatSAS(sas), attributes: [
            .font: NSFont.monospacedDigitSystemFont(ofSize: 46, weight: .semibold),
            .paragraphStyle: centered,
            .kern: 3,
            .foregroundColor: NSColor.labelColor,
        ])
        number.alignment = .center
        number.isSelectable = false
        number.setAccessibilityLabel(String(format: "%06u", sas).map(String.init).joined(separator: " "))
        views.append(Self.box(number, padding: NSEdgeInsets(top: 14, left: 16, bottom: 14, right: 16), width: textWidth))

        if waiting {
            let spinner = NSProgressIndicator()
            spinner.style = .spinning
            spinner.controlSize = .small
            spinner.startAnimation(nil)
            let label = NSTextField(labelWithString: "Waiting for \(pcName) to confirm…")
            label.textColor = .secondaryLabelColor
            label.lineBreakMode = .byTruncatingTail
            label.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
            let status = NSStackView(views: [spinner, label])
            status.spacing = 8
            status.alignment = .centerY
            views.append(status)
        } else {
            let note = body("If the numbers are different, click Cancel: another device may be trying to listen in.")
            note.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
            views.append(note)
        }
        return views
    }

    @objc private func updateCountdown() {
        guard case .waiting(let deadline) = state, let field = countdownField else { return }
        let left = max(0, Int(deadline.timeIntervalSinceNow.rounded(.up)))
        field.stringValue = String(format: "Waiting for your PC… %d:%02d", left / 60, left % 60)
    }

    // MARK: Actions

    @objc private func startAgain() { onStartAgain?() }

    @objc private func confirm() { onConfirm?() }

    @objc private func cancel() { onCancel?() }

    @objc private func closeWindow() { window.performClose(nil) }

    func windowWillClose(_ notification: Notification) {
        countdownTimer?.invalidate()
        countdownTimer = nil
        NSObject.cancelPreviousPerformRequests(withTarget: self)
        onClose?()
    }

    @objc private func resetCopyButtons() {
        for b in copyButtons { Self.setCopyLook(b, copied: false) }
    }

    @objc private func copyValue(_ sender: NSButton) {
        guard let text = sender.identifier?.rawValue, !text.isEmpty else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        resetCopyButtons()
        Self.setCopyLook(sender, copied: true)
        NSObject.cancelPreviousPerformRequests(withTarget: self, selector: #selector(resetCopyButtons), object: nil)
        perform(#selector(resetCopyButtons), with: nil, afterDelay: 1.5)
    }

    // MARK: Building blocks

    /// A subtle rounded row: the address, selectable, with a copy button.
    private func copyRow(_ text: String, copyValue value: String?) -> NSView {
        let f = NSTextField(labelWithString: text)
        f.font = value != nil ? .monospacedSystemFont(ofSize: 12, weight: .regular) : .systemFont(ofSize: 12)
        f.textColor = value != nil ? .labelColor : .secondaryLabelColor
        f.isSelectable = value != nil
        f.lineBreakMode = .byTruncatingMiddle
        f.setContentHuggingPriority(.defaultLow, for: .horizontal)
        f.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        var views: [NSView] = [f]
        if let value {
            let b = NSButton(title: "", target: self, action: #selector(copyValue(_:)))
            b.identifier = NSUserInterfaceItemIdentifier(value)
            b.isBordered = false
            b.imagePosition = .imageOnly
            b.setButtonType(.momentaryChange)
            Self.setCopyLook(b, copied: false)
            copyButtons.append(b)
            views.append(b)
        }
        let r = NSStackView(views: views)
        r.orientation = .horizontal
        r.distribution = .fill
        r.alignment = .centerY
        r.spacing = 8
        return Self.box(r, padding: NSEdgeInsets(top: 6, left: 10, bottom: 6, right: 8), width: textWidth,
                        radius: 7, minHeight: 30)
    }

    private static func setCopyLook(_ b: NSButton, copied: Bool) {
        b.image = NSImage(systemSymbolName: copied ? "checkmark" : "doc.on.doc",
                          accessibilityDescription: copied ? "Copied" : "Copy")?
            .withSymbolConfiguration(.init(pointSize: 12, weight: .medium))
        b.contentTintColor = copied ? .systemGreen : .secondaryLabelColor
        b.toolTip = copied ? "Copied" : "Copy"
        b.setAccessibilityLabel(copied ? "Copied" : "Copy")
    }

    private func button(_ title: String, _ action: Selector, isDefault: Bool = false, isCancel: Bool = false) -> NSButton {
        let b = NSButton(title: title, target: self, action: action)
        b.bezelStyle = .rounded
        b.controlSize = .large
        if isDefault { b.keyEquivalent = "\r" } else if isCancel { b.keyEquivalent = "\u{1b}" }
        b.widthAnchor.constraint(greaterThanOrEqualToConstant: 96).isActive = true
        return b
    }

    private func body(_ text: String) -> NSTextField {
        let f = NSTextField(wrappingLabelWithString: text)
        f.alignment = .center
        f.textColor = .secondaryLabelColor
        f.preferredMaxLayoutWidth = textWidth
        f.isSelectable = false
        return f
    }

    private static func title(_ text: String) -> NSTextField {
        let f = NSTextField(wrappingLabelWithString: text)
        f.font = .systemFont(ofSize: 20, weight: .semibold)
        f.alignment = .center
        f.isSelectable = false
        f.maximumNumberOfLines = 2
        f.lineBreakMode = .byTruncatingTail
        f.preferredMaxLayoutWidth = 360
        return f
    }

    private static func appIcon() -> NSView {
        let v = NSImageView()
        v.image = NSApp.applicationIconImage
        v.imageScaling = .scaleProportionallyUpOrDown
        v.setAccessibilityElement(false)
        v.widthAnchor.constraint(equalToConstant: 72).isActive = true
        v.heightAnchor.constraint(equalToConstant: 72).isActive = true
        return v
    }

    private static func symbol(_ name: String, color: NSColor, label: String) -> NSView {
        let v = NSImageView()
        v.image = NSImage(systemSymbolName: name, accessibilityDescription: label)?
            .withSymbolConfiguration(.init(pointSize: 52, weight: .regular))
        v.contentTintColor = color
        v.heightAnchor.constraint(equalToConstant: 72).isActive = true
        return v
    }

    /// Rounded, lightly filled box around `content`, `width` wide.
    private static func box(_ content: NSView, padding: NSEdgeInsets, width: CGFloat,
                            radius: CGFloat = 12, minHeight: CGFloat = 0) -> NSView {
        let box = NSBox()
        box.boxType = .custom
        box.borderWidth = 0
        box.cornerRadius = radius
        box.fillColor = NSColor.labelColor.withAlphaComponent(0.08)
        box.contentViewMargins = .zero
        box.titlePosition = .noTitle
        let inner = NSView()
        content.translatesAutoresizingMaskIntoConstraints = false
        inner.addSubview(content)
        NSLayoutConstraint.activate([
            content.topAnchor.constraint(equalTo: inner.topAnchor, constant: padding.top),
            content.bottomAnchor.constraint(equalTo: inner.bottomAnchor, constant: -padding.bottom),
            content.leadingAnchor.constraint(equalTo: inner.leadingAnchor, constant: padding.left),
            content.trailingAnchor.constraint(equalTo: inner.trailingAnchor, constant: -padding.right),
            inner.heightAnchor.constraint(greaterThanOrEqualToConstant: minHeight),
        ])
        box.contentView = inner
        box.translatesAutoresizingMaskIntoConstraints = false
        box.widthAnchor.constraint(equalToConstant: width).isActive = true
        return box
    }
}
