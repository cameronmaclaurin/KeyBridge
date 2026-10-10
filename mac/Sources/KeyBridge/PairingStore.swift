import CryptoKit
import Foundation
import Security

/// The pairing in the Keychain (docs/PROTOCOL.md §2.5): generic passwords under service
/// `com.keybridge.app`, accessible after first unlock, this device only.
///   account `pairing-key`     the 32-byte long-term key (`ltk`, the session psk)
///   account `paired-pc-name`  the PC's display name, for the UI
/// The v1.1 `pairing-code` item is deleted.
///
/// Prefers the data-protection keychain. Builds without a keychain entitlement (ad-hoc, or
/// Developer ID without a provisioning profile) get errSecMissingEntitlement there and fall
/// back to the login keychain, where the item's ACL trusts this app's signature.
enum PairingStore {
    private static let service = "com.keybridge.app"
    private static let keyAccount = "pairing-key"
    private static let nameAccount = "paired-pc-name"
    private static let legacyCodeAccount = "pairing-code"

    struct Pairing {
        let ltk: SymmetricKey
        let pcName: String
    }

    enum LoadResult {
        case found(Pairing)
        case notFound
        case failed(OSStatus)
    }

    /// Set once the data-protection keychain reports errSecMissingEntitlement (main thread only).
    private static var dataProtectionUnavailable = false

    /// Runs a keychain operation against the data-protection keychain, falling back to the
    /// login keychain when this build isn't entitled to use it.
    private static func withKeychain(account: String, _ op: (_ base: [String: Any]) -> OSStatus) -> OSStatus {
        if !dataProtectionUnavailable {
            let status = op(baseQuery(account: account, dataProtection: true))
            if status != errSecMissingEntitlement { return status }
            dataProtectionUnavailable = true
        }
        return op(baseQuery(account: account, dataProtection: false))
    }

    private static func baseQuery(account: String, dataProtection: Bool) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        if dataProtection { q[kSecUseDataProtectionKeychain as String] = true }
        return q
    }

    private static func read(_ account: String) -> (Data?, OSStatus) {
        var out: CFTypeRef?
        let status = withKeychain(account: account) { base in
            var q = base
            q[kSecReturnData as String] = true
            q[kSecMatchLimit as String] = kSecMatchLimitOne
            out = nil
            return SecItemCopyMatching(q as CFDictionary, &out)
        }
        return (status == errSecSuccess ? out as? Data : nil, status)
    }

    private static func write(_ account: String, _ data: Data, label: String) -> OSStatus {
        withKeychain(account: account) { base in
            var add = base
            add[kSecValueData as String] = data
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            add[kSecAttrLabel as String] = label
            var s = SecItemAdd(add as CFDictionary, nil)
            guard s == errSecDuplicateItem else { return s }
            let attrs: [String: Any] = [
                kSecValueData as String: data,
                kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            ]
            s = SecItemUpdate(base as CFDictionary, attrs as CFDictionary)
            guard s != errSecSuccess else { return s }
            // An item we can't update (e.g. created by a differently signed build): replace it.
            SecItemDelete(base as CFDictionary)
            return SecItemAdd(add as CFDictionary, nil)
        }
    }

    @discardableResult
    private static func remove(_ account: String) -> OSStatus {
        withKeychain(account: account) { SecItemDelete($0 as CFDictionary) }
    }

    static func load() -> LoadResult {
        let (keyData, status) = read(keyAccount)
        switch status {
        case errSecSuccess:
            guard let keyData, keyData.count == 32 else { return .notFound }
            let (nameData, _) = read(nameAccount)
            let name = nameData.flatMap { String(data: $0, encoding: .utf8) } ?? ""
            return .found(Pairing(ltk: SymmetricKey(data: keyData), pcName: name.isEmpty ? "your PC" : name))
        case errSecItemNotFound:
            return .notFound
        default:
            return .failed(status)
        }
    }

    /// Replaces any previous pairing. Returns false if the key couldn't be stored.
    @discardableResult
    static func save(ltk: SymmetricKey, pcName: String) -> Bool {
        let keyData = ltk.withUnsafeBytes { Data($0) }
        let status = write(keyAccount, keyData, label: "KeyBridge pairing key")
        guard status == errSecSuccess else {
            NSLog("[KeyBridge] Keychain save failed: \(status)")
            return false
        }
        let nameStatus = write(nameAccount, Data(pcName.utf8), label: "KeyBridge paired PC name")
        if nameStatus != errSecSuccess { NSLog("[KeyBridge] Keychain name save failed: \(nameStatus)") }
        return true
    }

    /// "Forget This PC".
    static func delete() {
        remove(keyAccount)
        remove(nameAccount)
    }

    /// v1.1 stored a typed pairing code; it's meaningless now (§2.6).
    static func deleteLegacyCode() {
        let flag = "legacyPairingCodeRemoved"
        guard !UserDefaults.standard.bool(forKey: flag) else { return }
        let status = remove(legacyCodeAccount)
        if status == errSecSuccess || status == errSecItemNotFound {
            UserDefaults.standard.set(true, forKey: flag)
        }
    }
}
