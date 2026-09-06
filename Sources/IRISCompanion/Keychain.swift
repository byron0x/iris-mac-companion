import Foundation
import Security
import LocalAuthentication
import IRISCore

enum Keychain {
    #if DEBUG
    static let service = "io.undercoveriris.companion.development"
    #else
    static let service = "io.undercoveriris.companion"
    #endif
    static func load(_ account: String, allowPrompt: Bool = false) throws -> Data? {
        var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account, kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        if !allowPrompt { let context = LAContext(); context.interactionNotAllowed = true; query[kSecUseAuthenticationContext as String] = context }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw ScanError.commandFailed("Unlock IRIS’s saved keys to reopen your private review. This only accesses IRIS’s own encryption and connection keys.") }
        return result as? Data
    }
    static func save(_ account: String, data: Data) throws {
        // Never replace a saved key merely because access was denied or the Keychain is locked.
        _ = try load(account)
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
        let attributes: [String: Any] = [kSecAttrLabel as String: account == "local-report-key" ? "IRIS saved-scan encryption key" : "IRIS encrypted dashboard connection", kSecValueData as String: data, kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        let update = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if update == errSecSuccess { return }
        guard update == errSecItemNotFound, SecItemAdd(query.merging(attributes) { _, new in new } as CFDictionary, nil) == errSecSuccess else { throw ScanError.commandFailed("IRIS could not save this connection securely in Keychain.") }
    }
    static func remove(_ account: String) {
        SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account] as CFDictionary)
    }
}
