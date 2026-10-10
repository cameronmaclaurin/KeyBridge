import Foundation
import Security

/// Pairing code in the Keychain (generic password, service `com.keybridge.app`,
/// account `pairing-code`, accessible after first unlock, this device only).
///
/// Prefers the data-protection keychain. Builds without a keychain entitlement (ad-hoc, or
/// Developer ID without a provisioning profile) get errSecMissingEntitlement there and fall
/// back to the login keychain, where the item's ACL trusts this app's signature.
enum PairingStore {
    private static let service = "com.keybridge.app"
    private static let account = "pairing-code"

    enum LoadResult {
        case found(String)      // normalized code
        case notFound
        case failed(OSStatus)
    }

    /// Set once the data-protection keychain reports errSecMissingEntitlement (main thread only).
    private static var dataProtectionUnavailable = false

    /// Runs a keychain operation against the data-protection keychain, falling back to the
    /// login keychain when this build isn't entitled to use it.
    private static func withKeychain(_ op: (_ base: [String: Any]) -> OSStatus) -> OSStatus {
        if !dataProtectionUnavailable {
            let status = op(baseQuery(dataProtection: true))
            if status != errSecMissingEntitlement { return status }
            dataProtectionUnavailable = true
        }
        return op(baseQuery(dataProtection: false))
    }

    private static func baseQuery(dataProtection: Bool) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        if dataProtection { q[kSecUseDataProtectionKeychain as String] = true }
        return q
    }

    static func load() -> LoadResult {
        var out: CFTypeRef?
        let status = withKeychain { base in
            var q = base
            q[kSecReturnData as String] = true
            q[kSecMatchLimit as String] = kSecMatchLimitOne
            out = nil
            return SecItemCopyMatching(q as CFDictionary, &out)
        }
        switch status {
        case errSecSuccess:
            guard let data = out as? Data, let raw = String(data: data, encoding: .utf8),
                  let code = PairingCode.normalize(raw) else { return .notFound }
            return .found(code)
        case errSecItemNotFound:
            return .notFound
        default:
            return .failed(status)
        }
    }

    @discardableResult
    static func save(_ normalizedCode: String) -> Bool {
        let data = Data(normalizedCode.utf8)
        let status = withKeychain { base in
            var add = base
            add[kSecValueData as String] = data
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            add[kSecAttrLabel as String] = "KeyBridge pairing code"
            let s = SecItemAdd(add as CFDictionary, nil)
            guard s == errSecDuplicateItem else { return s }
            let attrs: [String: Any] = [
                kSecValueData as String: data,
                kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            ]
            return SecItemUpdate(base as CFDictionary, attrs as CFDictionary)
        }
        if status != errSecSuccess {
            NSLog("[KeyBridge] Keychain save failed: \(status)")
        }
        return status == errSecSuccess
    }

    /// Returns the stored code, or generates and stores a new one (`isNew` = first launch).
    static func loadOrCreate() -> (code: String, isNew: Bool) {
        switch load() {
        case .found(let code):
            return (code, false)
        case .notFound:
            let code = PairingCode.generate()
            save(code)
            return (code, true)
        case .failed(let status):
            // Unreadable item (e.g. access denied): replace it so the PC can be paired again.
            NSLog("[KeyBridge] Keychain read failed: \(status)")
            _ = withKeychain { SecItemDelete($0 as CFDictionary) }
            let code = PairingCode.generate()
            save(code)
            return (code, true)
        }
    }
}
