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
    private let width: CGFloat = 460
    private var countdownField: NSTextField?
    private var countdownTimer: Timer?
    private var copyButtons: [NSButton] = []

    init(state: State) {
        self.state = state
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 460, height: 300),
                          styleMask: [.titled, .closable], backing: .buffered, defer: true)
        super.init()
        window.title = "Pair a Windows PC"
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
        switch state {
        case .waiting(let deadline):
            views = waitingViews(deadline: deadline)
        case .expired:
            views = [
                Self.title("Pair a Windows PC"),
                Self.wrapping("KeyBridge stopped waiting for your PC. Click Start Again, then choose this Mac on your PC within 3 minutes.", width: width - 40),
                buttonRow([button("Close", #selector(closeWindow)),
                           button("Start Again", #selector(startAgain), isDefault: true)]),
            ]
        case .compare(let pcName, let sas):
            views = compareViews(pcName: pcName, sas: sas, waiting: false)
        case .waitingForPC(let pcName, let sas):
            views = compareViews(pcName: pcName, sas: sas, waiting: true)
        case .done(let pcName):
            let check = NSImageView()
            if let img = NSImage(systemSymbolName: "checkmark.circle.fill", accessibilityDescription: "Paired")?
                .withSymbolConfiguration(.init(pointSize: 32, weight: .regular)) {
                check.image = img
                check.contentTintColor = .systemGreen
            }
            let title = Self.title("Paired with \(pcName)")
            title.lineBreakMode = .byTruncatingTail
            let header = NSStackView(views: [check, title])
            header.spacing = 10
            header.alignment = .centerY
            views = [
                header,
                Self.wrapping("Switch to Windows mode from the KeyBridge menu or with Control-Shift-` to type on your PC.", width: width - 40),
                buttonRow([button("Done", #selector(closeWindow), isDefault: true)]),
            ]
            perform(#selector(closeWindow), with: nil, afterDelay: 2.5)
        case .failed(let detail):
            views = [
                Self.title("Pairing didn’t complete"),
                Self.wrapping(detail, width: width - 40),
                buttonRow([button("Close", #selector(closeWindow)),
                           button("Start Again", #selector(startAgain), isDefault: true)]),
            ]
        }

        let stack = NSStackView(views: views)
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 12
        stack.edgeInsets = NSEdgeInsets(top: 20, left: 20, bottom: 20, right: 20)
        for v in views where v is NSStackView {
            v.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -40).isActive = true
        }
        if views.count >= 2 { stack.setCustomSpacing(20, after: views[views.count - 2]) }  // above buttons
        stack.widthAnchor.constraint(equalToConstant: width).isActive = true

        window.contentView = stack
        window.setContentSize(stack.fittingSize)
    }

    private func waitingViews(deadline: Date) -> [NSView] {
        let name = NetworkInfo.computerName()
        let instructions = Self.wrapping(
            "On your PC, open KeyBridge and choose this Mac (\(name)) from the list, then click Pair.",
            width: width - 40)
        instructions.font = .systemFont(ofSize: 13)

        var views: [NSView] = [Self.title("Pair a Windows PC"), instructions]

        views.append(Self.caption("If this Mac isn’t listed, enter its address on your PC"))
        let host = NetworkInfo.localHostName()
        views.append(copyRow(host ?? "This Mac has no network name", copyValue: host))
        let ips = NetworkInfo.ipv4Addresses()
        if ips.isEmpty {
            views.append(copyRow("No network connection", copyValue: nil))
        } else {
            for ip in ips.prefix(3) { views.append(copyRow(ip, copyValue: ip)) }
        }

        let spinner = NSProgressIndicator()
        spinner.style = .spinning
        spinner.controlSize = .small
        spinner.startAnimation(nil)
        let countdown = NSTextField(labelWithString: "")
        countdown.font = .monospacedDigitSystemFont(ofSize: 13, weight: .medium)
        countdown.textColor = .secondaryLabelColor
        countdownField = countdown
        let status = NSStackView(views: [spinner, countdown])
        status.spacing = 8
        status.alignment = .centerY
        views.append(status)

        views.append(buttonRow([button("Cancel", #selector(closeWindow))]))

        updateCountdown()
        let t = Timer(timeInterval: 1, target: self, selector: #selector(updateCountdown), userInfo: nil, repeats: true)
        RunLoop.main.add(t, forMode: .common)
        countdownTimer = t
        return views
    }

    private func compareViews(pcName: String, sas: UInt32, waiting: Bool) -> [NSView] {
        let title = Self.title("Pair with \(pcName)?")
        title.lineBreakMode = .byTruncatingTail
        let prompt = Self.wrapping("Make sure your PC shows the same number.", width: width - 40)
        prompt.font = .systemFont(ofSize: 13)

        let number = NSTextField(labelWithString: KBP2Pairing.formatSAS(sas))
        number.font = .monospacedDigitSystemFont(ofSize: 48, weight: .semibold)
        number.alignment = .center
        number.isSelectable = false
        number.setAccessibilityLabel(String(format: "%06u", sas).map(String.init).joined(separator: " "))
        let numberRow = NSStackView(views: [number])
        numberRow.alignment = .centerY
        numberRow.distribution = .fill

        var views: [NSView] = [title, prompt, numberRow]
        if waiting {
            let spinner = NSProgressIndicator()
            spinner.style = .spinning
            spinner.controlSize = .small
            spinner.startAnimation(nil)
            let label = NSTextField(labelWithString: "Waiting for \(pcName) to confirm…")
            label.textColor = .secondaryLabelColor
            label.lineBreakMode = .byTruncatingTail
            let status = NSStackView(views: [spinner, label])
            status.spacing = 8
            status.alignment = .centerY
            views.append(status)
            views.append(buttonRow([button("Cancel", #selector(cancel))]))
        } else {
            let note = Self.wrapping("If the numbers are different, click Cancel: another device may be trying to listen in.", width: width - 40)
            note.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
            note.textColor = .secondaryLabelColor
            views.append(note)
            views.append(buttonRow([button("Cancel", #selector(cancel)),
                                    button("Confirm", #selector(confirm), isDefault: true)]))
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
        for b in copyButtons { b.title = "Copy" }
    }

    @objc private func copyValue(_ sender: NSButton) {
        guard let text = sender.identifier?.rawValue, !text.isEmpty else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        resetCopyButtons()
        sender.title = "Copied"
        NSObject.cancelPreviousPerformRequests(withTarget: self, selector: #selector(resetCopyButtons), object: nil)
        perform(#selector(resetCopyButtons), with: nil, afterDelay: 1.5)
    }

    // MARK: Building blocks

    private func copyRow(_ text: String, copyValue value: String?) -> NSStackView {
        let f = NSTextField(labelWithString: text)
        f.font = .systemFont(ofSize: 14)
        f.isSelectable = value != nil
        f.lineBreakMode = .byTruncatingTail
        f.setContentHuggingPriority(.defaultLow, for: .horizontal)
        f.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        var views: [NSView] = [f]
        if let value {
            let b = NSButton(title: "Copy", target: self, action: #selector(copyValue(_:)))
            b.identifier = NSUserInterfaceItemIdentifier(value)
            b.widthAnchor.constraint(greaterThanOrEqualToConstant: 76).isActive = true
            copyButtons.append(b)
            views.append(b)
        }
        let r = NSStackView(views: views)
        r.orientation = .horizontal
        r.distribution = .fill
        r.alignment = .centerY
        r.spacing = 12
        return r
    }

    private func button(_ title: String, _ action: Selector, isDefault: Bool = false) -> NSButton {
        let b = NSButton(title: title, target: self, action: action)
        if isDefault { b.keyEquivalent = "\r" }
        b.widthAnchor.constraint(greaterThanOrEqualToConstant: 90).isActive = true
        return b
    }

    /// Right-aligned buttons, in the order given (default button last, macOS style).
    private func buttonRow(_ buttons: [NSButton]) -> NSStackView {
        let spacer = NSView()
        spacer.setContentHuggingPriority(.init(1), for: .horizontal)
        let row = NSStackView(views: [spacer] + buttons)
        row.distribution = .fill
        row.spacing = 12
        return row
    }

    private static func title(_ text: String) -> NSTextField {
        let f = NSTextField(labelWithString: text)
        f.font = .systemFont(ofSize: 17, weight: .semibold)
        return f
    }

    private static func wrapping(_ text: String, width: CGFloat) -> NSTextField {
        let f = NSTextField(wrappingLabelWithString: text)
        f.preferredMaxLayoutWidth = width
        f.isSelectable = false
        return f
    }

    private static func caption(_ text: String) -> NSTextField {
        let f = NSTextField(labelWithString: text.uppercased())
        f.font = .systemFont(ofSize: 11, weight: .semibold)
        f.textColor = .secondaryLabelColor
        return f
    }
}
