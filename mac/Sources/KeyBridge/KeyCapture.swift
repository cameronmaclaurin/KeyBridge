import CoreGraphics
import Foundation

struct KeyEvent {
    var isDown: Bool
    var vk: UInt16
    var isExtended: Bool
}

private func tapCallback(
    _ proxy: CGEventTapProxy,
    _ type: CGEventType,
    _ event: CGEvent,
    _ userInfo: UnsafeMutableRawPointer?
) -> Unmanaged<CGEvent>? {
    guard let ptr = userInfo else { return Unmanaged.passUnretained(event) }
    let cap = Unmanaged<KeyCapture>.fromOpaque(ptr).takeUnretainedValue()
    return cap.handle(type: type, event: event)
}

/// One always-on active event tap. Switching modes just flips `suppress`, so there is no
/// tap teardown/recreate on toggle and `pressedKeys` keeps mirroring the physical keyboard.
final class KeyCapture {
    var onKeyEvent: ((KeyEvent) -> Void)?
    var onHotkeyToggle: (() -> Void)?

    /// true = swallow keys locally and forward them; false = let them reach the Mac.
    var suppress = false

    private var tap: CFMachPort?
    private var pressedKeys = Set<CGKeyCode>()

    /// Returns false if the tap could not be created (Accessibility not granted yet).
    @discardableResult
    func start() -> Bool {
        if tap != nil { return true }
        let mask: CGEventMask =
            (1 << CGEventType.keyDown.rawValue) |
            (1 << CGEventType.keyUp.rawValue) |
            (1 << CGEventType.flagsChanged.rawValue)

        guard let t = CGEvent.tapCreate(
            tap: .cghidEventTap,
            place: .headInsertEventTap,
            options: .defaultTap,
            eventsOfInterest: mask,
            callback: tapCallback,
            userInfo: Unmanaged.passUnretained(self).toOpaque()
        ) else { return false }

        tap = t
        let source = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, t, 0)
        CFRunLoopAddSource(CFRunLoopGetMain(), source, .commonModes)
        CGEvent.tapEnable(tap: t, enable: true)
        return true
    }

    func handle(type: CGEventType, event: CGEvent) -> Unmanaged<CGEvent>? {
        let pass = Unmanaged.passUnretained(event)

        if type == .tapDisabledByTimeout || type == .tapDisabledByUserInput {
            if let t = tap { CGEvent.tapEnable(tap: t, enable: true) }
            return pass
        }

        let keyCode = CGKeyCode(event.getIntegerValueField(.keyboardEventKeycode))

        switch type {
        case .keyDown:
            pressedKeys.insert(keyCode)
            if keyCode == kBacktick && isHotkeyHeld() {
                DispatchQueue.main.async { self.onHotkeyToggle?() }
                return nil
            }
            if suppress { dispatch(true, keyCode); return nil }

        case .keyUp:
            pressedKeys.remove(keyCode)
            if suppress { dispatch(false, keyCode); return nil }

        case .flagsChanged:
            if keyCode == kCapsLock {
                // macOS reports Caps Lock as a state toggle; Windows toggles on each press.
                if suppress { dispatch(true, keyCode); dispatch(false, keyCode); return nil }
                return pass
            }
            guard let bit = modifierMasks[keyCode] else { return pass }
            let isDown = event.flags.rawValue & bit != 0
            if isDown { pressedKeys.insert(keyCode) } else { pressedKeys.remove(keyCode) }
            if suppress { dispatch(isDown, keyCode); return nil }

        default:
            break
        }
        return pass
    }

    /// Send key-up for everything currently held so nothing sticks on the remote side.
    func releaseAllRemote() {
        for kc in pressedKeys { dispatch(false, kc) }
    }

    private func isHotkeyHeld() -> Bool {
        !pressedKeys.isDisjoint(with: kCtrlKeys) && !pressedKeys.isDisjoint(with: kShiftKeys)
    }

    private func dispatch(_ isDown: Bool, _ keyCode: CGKeyCode) {
        guard let vk = cgToVk[keyCode] else { return }
        onKeyEvent?(KeyEvent(isDown: isDown, vk: vk, isExtended: keyCode == kKeypadEnter))
    }
}
