import CoreGraphics
import Foundation

// MARK: – Protocol

struct KeyEvent {
    var isDown: Bool
    var vk: UInt16
    var isExtended: Bool  // numpad enter needs KEYEVENTF_EXTENDEDKEY on Windows
}

// C-compatible tap callback; userInfo points to the KeyCapture instance.
private func tapCallback(
    _ proxy: CGEventTapProxy,
    _ type: CGEventType,
    _ event: CGEvent,
    _ userInfo: UnsafeMutableRawPointer?
) -> Unmanaged<CGEvent>? {
    guard let ptr = userInfo else { return Unmanaged.passRetained(event) }
    let cap = Unmanaged<KeyCapture>.fromOpaque(ptr).takeUnretainedValue()
    return cap.handle(proxy: proxy, type: type, event: event)
}

// MARK: – KeyCapture

final class KeyCapture {
    var onKeyEvent: ((KeyEvent) -> Void)?
    var onHotkeyToggle: (() -> Void)?

    private(set) var suppressMode = false
    private var tap: CFMachPort?
    private var loopSource: CFRunLoopSource?
    private var pressedKeys = Set<CGKeyCode>()

    // Start or restart the tap. Call on main thread.
    func start(suppress: Bool) {
        stop()
        suppressMode = suppress

        let mask: CGEventMask =
            (1 << CGEventType.keyDown.rawValue) |
            (1 << CGEventType.keyUp.rawValue) |
            (1 << CGEventType.flagsChanged.rawValue)

        guard let t = CGEvent.tapCreate(
            tap: .cghidEventTap,
            place: .headInsertEventTap,
            options: suppress ? .defaultTap : .listenOnly,
            eventsOfInterest: mask,
            callback: tapCallback,
            userInfo: Unmanaged.passUnretained(self).toOpaque()
        ) else {
            NSLog("[KeyBridge] CGEventTap creation failed — grant Accessibility in System Settings.")
            return
        }
        tap = t
        loopSource = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, t, 0)
        CFRunLoopAddSource(CFRunLoopGetMain(), loopSource, .commonModes)
        CGEvent.tapEnable(tap: t, enable: true)
    }

    func stop() {
        if let t = tap { CGEvent.tapEnable(tap: t, enable: false) }
        if let s = loopSource { CFRunLoopRemoveSource(CFRunLoopGetMain(), s, .commonModes) }
        tap = nil; loopSource = nil
        pressedKeys.removeAll()
    }

    // Called from C tap callback.
    func handle(proxy: CGEventTapProxy, type: CGEventType, event: CGEvent) -> Unmanaged<CGEvent>? {
        let keyCode = CGKeyCode(event.getIntegerValueField(.keyboardEventKeycode))

        switch type {
        case .keyDown:
            pressedKeys.insert(keyCode)
            if isHotkey() {
                pressedKeys.removeAll()
                DispatchQueue.main.async { self.onHotkeyToggle?() }
                return nil  // consume
            }
            if suppressMode {
                dispatch(isDown: true, keyCode: keyCode)
                return nil
            }

        case .keyUp:
            pressedKeys.remove(keyCode)
            if suppressMode {
                dispatch(isDown: false, keyCode: keyCode)
                return nil
            }

        case .flagsChanged:
            let flags = event.flags
            if let modFlag = modifierFlags[keyCode] {
                let isDown = flags.contains(modFlag)
                if suppressMode {
                    if isDown { pressedKeys.insert(keyCode) } else { pressedKeys.remove(keyCode) }
                    dispatch(isDown: isDown, keyCode: keyCode)
                    return nil
                }
            }

        case .tapDisabledByUserInput, .tapDisabledByTimeout:
            if let t = tap { CGEvent.tapEnable(tap: t, enable: true) }

        default: break
        }

        return Unmanaged.passRetained(event)
    }

    // Release all tracked keys on the remote end before mode switch.
    func flushRemoteKeys(send: (KeyEvent) -> Void) {
        for kc in pressedKeys {
            guard let vk = cgToVk[kc] else { continue }
            send(KeyEvent(isDown: false, vk: vk, isExtended: kc == kKeypadEnter))
        }
        pressedKeys.removeAll()
    }

    private func isHotkey() -> Bool {
        pressedKeys.isSuperset(of: kSwitchHotkey)
    }

    private func dispatch(isDown: Bool, keyCode: CGKeyCode) {
        guard let vk = cgToVk[keyCode] else { return }
        onKeyEvent?(KeyEvent(isDown: isDown, vk: vk, isExtended: keyCode == kKeypadEnter))
    }
}
