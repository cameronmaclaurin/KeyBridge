import Carbon.HIToolbox
import CoreGraphics
import Foundation

struct HotkeyMods: OptionSet, Hashable {
    let rawValue: Int
    static let control = HotkeyMods(rawValue: 1)
    static let option  = HotkeyMods(rawValue: 2)
    static let shift   = HotkeyMods(rawValue: 4)
    static let command = HotkeyMods(rawValue: 8)

    /// Either side's physical key counts.
    static let keyCodes: [(HotkeyMods, Set<CGKeyCode>)] = [
        (.control, [0x3B, 0x3E]),
        (.option,  [0x3A, 0x3D]),
        (.shift,   [0x38, 0x3C]),
        (.command, [0x37, 0x36]),
    ]

    static func isModifierKey(_ kc: CGKeyCode) -> Bool {
        kc == kCapsLock || kc == 0x3F || keyCodes.contains { $0.1.contains(kc) }
    }

    var symbols: String {
        var s = ""
        if contains(.control) { s += "⌃" }
        if contains(.option)  { s += "⌥" }
        if contains(.shift)   { s += "⇧" }
        if contains(.command) { s += "⌘" }
        return s
    }
}

struct Hotkey: Equatable {
    var keyCode: CGKeyCode
    var mods: HotkeyMods

    static let `default` = Hotkey(keyCode: kBacktick, mods: [.control, .shift])

    var displayString: String { mods.symbols + Hotkey.keyName(keyCode) }

    private static let specialNames: [CGKeyCode: String] = [
        0x24: "↩", 0x30: "⇥", 0x31: "Space", 0x33: "⌫", 0x35: "⎋", 0x75: "⌦",
        0x7B: "←", 0x7C: "→", 0x7D: "↓", 0x7E: "↑",
        0x73: "Home", 0x77: "End", 0x74: "Page Up", 0x79: "Page Down", 0x72: "Help",
        0x7A: "F1", 0x78: "F2", 0x63: "F3", 0x76: "F4", 0x60: "F5", 0x61: "F6",
        0x62: "F7", 0x64: "F8", 0x65: "F9", 0x6D: "F10", 0x67: "F11", 0x6F: "F12",
        0x69: "F13", 0x6B: "F14", 0x71: "F15", 0x6A: "F16", 0x40: "F17", 0x4F: "F18", 0x50: "F19",
    ]

    /// The key's label on the current keyboard layout (e.g. "`", "A", "F5").
    static func keyName(_ kc: CGKeyCode) -> String {
        if let s = specialNames[kc] { return s }
        guard let src = TISCopyCurrentKeyboardLayoutInputSource()?.takeRetainedValue(),
              let ptr = TISGetInputSourceProperty(src, kTISPropertyUnicodeKeyLayoutData) else {
            return "Key \(kc)"
        }
        let data = Unmanaged<CFData>.fromOpaque(ptr).takeUnretainedValue() as Data
        var dead: UInt32 = 0
        var length = 0
        var chars = [UniChar](repeating: 0, count: 4)
        let status = data.withUnsafeBytes { raw -> OSStatus in
            guard let layout = raw.bindMemory(to: UCKeyboardLayout.self).baseAddress else { return -1 }
            return UCKeyTranslate(layout, UInt16(kc), UInt16(kUCKeyActionDisplay), 0,
                                  UInt32(LMGetKbdType()), OptionBits(kUCKeyTranslateNoDeadKeysBit),
                                  &dead, chars.count, &length, &chars)
        }
        let s = String(utf16CodeUnits: chars, count: length).trimmingCharacters(in: .whitespacesAndNewlines)
        return status == noErr && !s.isEmpty ? s.uppercased() : "Key \(kc)"
    }
}

/// User preferences, stored in UserDefaults.
@MainActor
final class AppSettings {
    static let shared = AppSettings()
    var onChange: (() -> Void)?

    private let d = UserDefaults.standard
    private enum K {
        static let hotkeyKey = "hotkeyKeyCode", hotkeyMods = "hotkeyMods"
        static let swap = "swapCommandControl", sound = "playSwitchSound", notify = "showNotifications"
    }

    private init() {
        d.register(defaults: [
            K.hotkeyKey: Int(Hotkey.default.keyCode),
            K.hotkeyMods: Hotkey.default.mods.rawValue,
            K.swap: false,
            K.sound: false,
            K.notify: true,
        ])
    }

    var hotkey: Hotkey {
        get { Hotkey(keyCode: CGKeyCode(d.integer(forKey: K.hotkeyKey)), mods: HotkeyMods(rawValue: d.integer(forKey: K.hotkeyMods))) }
        set { d.set(Int(newValue.keyCode), forKey: K.hotkeyKey); d.set(newValue.mods.rawValue, forKey: K.hotkeyMods); onChange?() }
    }

    /// ⌘ Command sends Ctrl and ⌃ Control sends the Windows key, so ⌘C/⌘V work on the PC.
    var swapCommandControl: Bool {
        get { d.bool(forKey: K.swap) }
        set { d.set(newValue, forKey: K.swap); onChange?() }
    }

    var playSwitchSound: Bool {
        get { d.bool(forKey: K.sound) }
        set { d.set(newValue, forKey: K.sound); onChange?() }
    }

    var showNotifications: Bool {
        get { d.bool(forKey: K.notify) }
        set { d.set(newValue, forKey: K.notify); onChange?() }
    }
}
