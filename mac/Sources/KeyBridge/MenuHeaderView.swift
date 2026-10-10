import AppKit

/// Non-interactive header at the top of the menu-bar menu: a round mode icon, what the
/// keyboard is typing on, and the paired PC with a colored connection dot.
@MainActor
final class MenuHeaderView: NSView {
    enum Dot { case green, gray, orange, red }

    private let icon = ModeIcon()
    private let titleField = NSTextField(labelWithString: "")
    private let subtitleField = NSTextField(labelWithString: "")
    private let dot = NSImageView()

    init() {
        super.init(frame: NSRect(x: 0, y: 0, width: 260, height: 48))
        autoresizingMask = [.width]

        titleField.font = .systemFont(ofSize: NSFont.systemFontSize, weight: .semibold)
        titleField.lineBreakMode = .byTruncatingTail
        subtitleField.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        subtitleField.textColor = .secondaryLabelColor
        subtitleField.lineBreakMode = .byTruncatingTail
        dot.image = NSImage(systemSymbolName: "circle.fill", accessibilityDescription: nil)?
            .withSymbolConfiguration(.init(pointSize: 7, weight: .regular))
        dot.imageScaling = .scaleNone

        let subtitleRow = NSStackView(views: [dot, subtitleField])
        subtitleRow.spacing = 4
        subtitleRow.alignment = .centerY
        let text = NSStackView(views: [titleField, subtitleRow])
        text.orientation = .vertical
        text.alignment = .leading
        text.spacing = 1
        let row = NSStackView(views: [icon, text])
        row.spacing = 8
        row.alignment = .centerY
        row.translatesAutoresizingMaskIntoConstraints = false
        addSubview(row)
        NSLayoutConstraint.activate([
            icon.widthAnchor.constraint(equalToConstant: 24),
            icon.heightAnchor.constraint(equalToConstant: 24),
            row.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 14),
            row.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -14),
            row.topAnchor.constraint(equalTo: topAnchor, constant: 6),
            row.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -6),
        ])
        setAccessibilityElement(true)
        setAccessibilityRole(.staticText)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not used") }

    func update(title: String, subtitle: String, symbol: String, active: Bool, dot color: Dot) {
        titleField.stringValue = title
        subtitleField.stringValue = subtitle
        icon.symbol = symbol
        icon.active = active
        switch color {
        case .green: dot.contentTintColor = .systemGreen
        case .gray: dot.contentTintColor = .tertiaryLabelColor
        case .orange: dot.contentTintColor = .systemOrange
        case .red: dot.contentTintColor = .systemRed
        }
        setAccessibilityLabel("\(title). \(subtitle)")
        let width = max(240, ceil(fittingSize.width))
        if frame.width < width { setFrameSize(NSSize(width: width, height: frame.height)) }
    }

    /// Circle with an SF Symbol: accent-filled while typing on the PC, neutral otherwise.
    private final class ModeIcon: NSView {
        var symbol = "keyboard" { didSet { needsDisplay = true } }
        var active = false { didSet { needsDisplay = true } }

        override func draw(_ dirtyRect: NSRect) {
            let circle = NSBezierPath(ovalIn: bounds)
            (active ? NSColor.controlAccentColor : NSColor.labelColor.withAlphaComponent(0.1)).setFill()
            circle.fill()
            let tint: NSColor = active ? .white : .labelColor
            guard let img = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)?
                .withSymbolConfiguration(NSImage.SymbolConfiguration(pointSize: 11, weight: .medium)
                    .applying(.init(paletteColors: [tint]))) else { return }
            let s = img.size
            img.draw(in: NSRect(x: (bounds.width - s.width) / 2, y: (bounds.height - s.height) / 2,
                                width: s.width, height: s.height))
        }
    }
}

extension NSMenuItem {
    /// Small template SF Symbol for a menu item.
    static func symbolImage(_ name: String) -> NSImage? {
        let img = NSImage(systemSymbolName: name, accessibilityDescription: nil)
        img?.isTemplate = true
        return img
    }
}

extension Hotkey {
    /// The shortcut as a menu key equivalent, so menus show it right-aligned like any other
    /// shortcut. nil when the key has no menu representation.
    var menuKeyEquivalent: (key: String, modifiers: NSEvent.ModifierFlags)? {
        var flags: NSEvent.ModifierFlags = []
        if mods.contains(.control) { flags.insert(.control) }
        if mods.contains(.option) { flags.insert(.option) }
        if mods.contains(.shift) { flags.insert(.shift) }
        if mods.contains(.command) { flags.insert(.command) }

        func scalar(_ v: Int) -> String { String(Character(UnicodeScalar(UInt16(v))!)) }
        let special: [CGKeyCode: Int] = [
            0x24: 0x0D, 0x30: 0x09, 0x31: 0x20, 0x33: 0x08, 0x35: 0x1B, 0x75: NSDeleteFunctionKey,
            0x7B: NSLeftArrowFunctionKey, 0x7C: NSRightArrowFunctionKey,
            0x7D: NSDownArrowFunctionKey, 0x7E: NSUpArrowFunctionKey,
            0x73: NSHomeFunctionKey, 0x77: NSEndFunctionKey,
            0x74: NSPageUpFunctionKey, 0x79: NSPageDownFunctionKey, 0x72: NSHelpFunctionKey,
        ]
        if let v = special[keyCode] { return (scalar(v), flags) }
        let name = Hotkey.keyName(keyCode)
        if name.count >= 2, name.hasPrefix("F"), let n = Int(name.dropFirst()), (1...35).contains(n) {
            return (scalar(NSF1FunctionKey + n - 1), flags)
        }
        guard name.count == 1 else { return nil }
        return (name.lowercased(), flags)
    }
}
