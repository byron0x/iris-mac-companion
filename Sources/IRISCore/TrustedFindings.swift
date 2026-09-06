import Foundation
import CryptoKit

/// An explicit user choice, bound to the inspected content and capabilities. Never a threat allowlist.
public struct TrustedFindings: Codable, Sendable {
    public var entries: [String: String] = [:]
    public init() {}
    public mutating func remember(_ finding: Finding, fingerprint: String) throws {
        guard finding.level != .threat, finding.category != "Malware scan", !finding.resolved,
              fingerprint.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil else { throw ScanError.unsafePath }
        guard entries.count < 1000 || entries[finding.id] != nil else { throw ScanError.commandFailed("Your trusted list is full. Remove an older choice before adding another.") }
        entries[finding.id] = fingerprint
    }
    public func recognizes(_ finding: Finding, fingerprint: String?) -> Bool {
        finding.level != .threat && finding.category != "Malware scan" && !finding.resolved && fingerprint != nil && entries[finding.id] == fingerprint
    }
    public static func fingerprint(_ finding: Finding, content: [String]) -> String {
        // Sorted evidence includes keyboard capabilities so changed access triggers a new review.
        let parts = [finding.id, finding.category, finding.signature ?? ""] + finding.evidence.sorted() + content
        return SHA256.hash(data: Data(parts.joined(separator: "\u{0}").utf8)).map { String(format: "%02x", $0) }.joined()
    }
}

public enum FindingContext {
    public static func explanation(path: String, category: String, verifiedTeam: String?, identifier: String?) -> String? {
        let name = URL(fileURLWithPath: path).lastPathComponent
        if [".zshenv", ".zshrc", ".zprofile", ".zlogin", ".bash_profile", ".bashrc", ".profile"].contains(name) {
            return "This is a Terminal setup file, not an installed app. It can set command shortcuts, development-tool paths and environment settings. " + (name == ".zshenv" ? "Zsh reads it whenever a shell starts. " : "Your shell can read it when you open a Terminal session. ") + "IRIS shows it because commands in startup files can run automatically. The filename is common; it does not establish whether its contents are safe. If you or a tool you installed created it, you can trust this version. A change brings it back for review."
        }
        if verifiedTeam == "2BUA8C4S2C", (identifier?.hasPrefix("com.agilebits.onepassword") == true || identifier?.hasPrefix("com.1password.") == true) {
            return "This component is signed by 1Password’s developer. It helps the password manager integrate with your Mac or browser, such as filling logins. IRIS found it in a location where software can load automatically. If you use 1Password and expect it here, you can trust this version; changes bring it back for review. A valid signature identifies the publisher, but is not a guarantee of safety."
        }
        if category.lowercased().contains("browser") || path.contains(".appex/") || path.hasSuffix(".appex") {
            return "This is a browser or app extension: a helper that adds features to another app. It may be installed as part of a password manager or another tool. Review the app it belongs to and whether you still use it. Being listed here does not mean it is malicious."
        }
        if category.lowercased().contains("launch") {
            return "This is a background startup item. Apps use these for updates, syncing and other work after you sign in. Unwanted software can use the same mechanism. Review the publisher and the app it belongs to before choosing to trust it or turn it off."
        }
        return nil
    }
}
