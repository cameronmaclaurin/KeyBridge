import AppKit

/// "Pair a Windows PC" window, built in code (no SwiftUI/xib). Created on demand and
/// released when closed so it costs nothing while hidden.
@MainActor
final class PairingWindowController: NSObject, NSWindowDelegate {
    var onGenerateNewCode: (() -> Void)?
    var onClose: (() -> Void)?

    private let window: NSWindow
    private let hostField: NSTextField
    private let ipField: NSTextField
    private let codeField: NSTextField
    private let statusField: NSTextField
    private var copyButtons: [NSButton] = []

    init(displayCode: String, status: String, connected: Bool) {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 480, height: 400),
                          styleMask: [.titled, .closable], backing: .buffered, defer: true)
        hostField = Self.valueField(font: .systemFont(ofSize: 15))
        ipField = Self.valueField(font: .systemFont(ofSize: 13))
        codeField = Self.valueField(font: .monospacedSystemFont(ofSize: 26, weight: .semibold))
        statusField = NSTextField(labelWithString: "")
        super.init()
        window.title = "Pair a Windows PC"
        window.isReleasedWhenClosed = false
        window.delegate = self

        let title = NSTextField(labelWithString: "Pair a Windows PC")
        title.font = .systemFont(ofSize: 17, weight: .semibold)

        let instructions = NSTextField(wrappingLabelWithString:
            "On your PC, open KeyBridge and enter this address and code.")
        instructions.preferredMaxLayoutWidth = 440

        let hostCopy = copyButton(#selector(copyHost))
        let ipCopy = copyButton(#selector(copyIP))
        let codeCopy = copyButton(#selector(copyCode))

        let generate = NSButton(title: "Generate New Code…", target: self, action: #selector(generateNewCode))
        let done = NSButton(title: "Done", target: self, action: #selector(closeWindow))
        done.keyEquivalent = "\r"

        let footnote = NSTextField(wrappingLabelWithString:
            "Keep this code private: anyone with it on your network could receive what you type in Windows mode.")
        footnote.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        footnote.textColor = .secondaryLabelColor
        footnote.preferredMaxLayoutWidth = 440

        statusField.font = .systemFont(ofSize: 13, weight: .medium)

        let spacer = NSView()
        spacer.setContentHuggingPriority(.init(1), for: .horizontal)
        let buttons = NSStackView(views: [generate, spacer, done])
        buttons.distribution = .fill

        let stack = NSStackView(views: [
            title,
            instructions,
            Self.caption("Mac address"),
            Self.row(hostField, hostCopy),
            Self.row(ipField, ipCopy),
            Self.caption("Pairing code"),
            Self.row(codeField, codeCopy),
            statusField,
            footnote,
            buttons,
        ])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 10
        stack.edgeInsets = NSEdgeInsets(top: 20, left: 20, bottom: 20, right: 20)
        stack.setCustomSpacing(4, after: stack.views[2])
        stack.setCustomSpacing(4, after: stack.views[3])
        stack.setCustomSpacing(4, after: stack.views[5])
        stack.setCustomSpacing(16, after: stack.views[6])
        stack.setCustomSpacing(16, after: footnote)
        for v in stack.views where v is NSStackView {
            v.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -40).isActive = true
        }
        stack.widthAnchor.constraint(equalToConstant: 480).isActive = true

        window.contentView = stack
        window.setContentSize(stack.fittingSize)

        refreshAddresses()
        setCode(displayCode)
        setStatus(status, connected: connected)
    }

    func show() {
        if #available(macOS 14.0, *) { NSApp.activate() } else { NSApp.activate(ignoringOtherApps: true) }
        if !window.isVisible { window.center() }
        window.makeKeyAndOrderFront(nil)
    }

    func setCode(_ displayCode: String) { codeField.stringValue = displayCode }

    func setStatus(_ text: String, connected: Bool) {
        statusField.stringValue = text
        statusField.textColor = connected ? .systemGreen : .secondaryLabelColor
    }

    func refreshAddresses() {
        hostField.stringValue = NetworkInfo.localHostName() ?? "This Mac has no network name"
        let ips = NetworkInfo.ipv4Addresses()
        ipField.stringValue = ips.isEmpty ? "No network connection" : "or IP address: " + ips.joined(separator: ", ")
        ipField.toolTip = ips.joined(separator: ", ")
    }

    // MARK: Actions

    @objc private func copyHost(_ sender: NSButton) { copy(hostField.stringValue, sender) }

    @objc private func copyIP(_ sender: NSButton) {
        copy(NetworkInfo.ipv4Addresses().first ?? "", sender)
    }

    @objc private func copyCode(_ sender: NSButton) { copy(codeField.stringValue, sender) }

    @objc private func generateNewCode() {
        let alert = NSAlert()
        alert.messageText = "Generate a new pairing code?"
        alert.informativeText = "The PC that is connected now will be disconnected and will need the new code to reconnect."
        alert.addButton(withTitle: "Generate New Code")
        alert.addButton(withTitle: "Cancel")
        if alert.runModal() == .alertFirstButtonReturn {
            onGenerateNewCode?()
        }
    }

    @objc private func closeWindow() { window.performClose(nil) }

    func windowWillClose(_ notification: Notification) {
        NSObject.cancelPreviousPerformRequests(withTarget: self)
        onClose?()
    }

    @objc private func resetCopyButtons() {
        for b in copyButtons { b.title = "Copy" }
    }

    private func copy(_ text: String, _ sender: NSButton) {
        guard !text.isEmpty else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        resetCopyButtons()
        sender.title = "Copied"
        NSObject.cancelPreviousPerformRequests(withTarget: self, selector: #selector(resetCopyButtons), object: nil)
        perform(#selector(resetCopyButtons), with: nil, afterDelay: 1.5)
    }

    // MARK: Building blocks

    private func copyButton(_ action: Selector) -> NSButton {
        let b = NSButton(title: "Copy", target: self, action: action)
        b.widthAnchor.constraint(greaterThanOrEqualToConstant: 76).isActive = true
        copyButtons.append(b)
        return b
    }

    private static func valueField(font: NSFont) -> NSTextField {
        let f = NSTextField(labelWithString: "")
        f.font = font
        f.isSelectable = true
        f.lineBreakMode = .byTruncatingTail
        f.setContentHuggingPriority(.defaultLow, for: .horizontal)
        f.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        return f
    }

    private static func caption(_ text: String) -> NSTextField {
        let f = NSTextField(labelWithString: text.uppercased())
        f.font = .systemFont(ofSize: 11, weight: .semibold)
        f.textColor = .secondaryLabelColor
        return f
    }

    private static func row(_ field: NSTextField, _ button: NSButton) -> NSStackView {
        let r = NSStackView(views: [field, button])
        r.orientation = .horizontal
        r.distribution = .fill
        r.alignment = .centerY
        r.spacing = 12
        return r
    }
}
