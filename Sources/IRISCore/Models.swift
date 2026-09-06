import Foundation
import CryptoKit

public enum FindingLevel: String, Codable, Sendable { case threat, review, information }
public enum FindingAction: String, Codable, Sendable { case quarantine, disableStartup, reveal, settings }
public struct Finding: Codable, Identifiable, Sendable, Equatable {
    public let id: String
    public var title: String
    public var category: String
    public var level: FindingLevel
    public var explanation: String
    public var evidence: [String]
    public var location: String
    public var action: FindingAction
    public var resolved: Bool = false
    public var signature: String?
    public var trusted: Bool?
    public var canTrust: Bool?
    public init(path: String, title: String, category: String, level: FindingLevel, explanation: String, evidence: [String], action: FindingAction, home: String = NSHomeDirectory(), signature: String? = nil) {
        self.id = SHA256.hash(data: Data((category + "\u{0}" + path).utf8)).map { String(format: "%02x", $0) }.joined()
        self.title = title; self.category = category; self.level = level; self.explanation = explanation; self.evidence = evidence
        self.location = path.hasPrefix(home + "/") ? "~" + path.dropFirst(home.count) : path
        self.action = action; self.signature = signature
    }
}
public struct Coverage: Codable, Sendable {
    public var inventory: String
    public var malware: String
    public var signaturesUpdatedAt: String?
    public var limitations: [String]
    public var keyboard: KeyboardCoverage?
    public var safeguards: [Safeguard]?
    public var filesChecked: Int?
    public var filesSelected: Int?
    public var skippedFiles: Int?
    public var inaccessibleLocations: Int?
    public init(inventory: String = "notStarted", malware: String = "notStarted", signaturesUpdatedAt: String? = nil, limitations: [String] = []) {
        self.inventory = inventory; self.malware = malware; self.signaturesUpdatedAt = signaturesUpdatedAt; self.limitations = limitations
    }
}
public struct ScanReport: Codable, Sendable {
    public var version = 1
    public var id = UUID().uuidString
    public var createdAt = ISO8601DateFormatter().string(from: Date())
    public var scannedItems: Int
    public var coverage: Coverage
    public var findings: [Finding]
    public init(scannedItems: Int, coverage: Coverage, findings: [Finding]) { self.scannedItems = scannedItems; self.coverage = coverage; self.findings = findings }
}
public struct LocalItem: Codable, Sendable {
    public let path: String
    public let sha256: String?
    public var reviewFingerprint: String?
    public init(path: String, sha256: String?, reviewFingerprint: String? = nil) { self.path = path; self.sha256 = sha256; self.reviewFingerprint = reviewFingerprint }
}
public struct InventoryResult: Sendable {
    public var findings: [Finding]
    public var paths: [String: String]
    public var scannedItems: Int
    public var scanPaths: [String]
    public var skippedItems: Int
}
public enum ScanError: LocalizedError {
    case invalidReport, unsafePath, changedFile, commandFailed(String), invalidPairing, invalidEnvelope
    public var errorDescription: String? {
        switch self {
        case .invalidReport: return "The scanner returned an incomplete report. Please try again."
        case .unsafePath: return "This item needs a manual review. IRIS has not changed it."
        case .changedFile: return "This file changed since the scan. Scan again before changing it."
        case .commandFailed(let message): return message
        case .invalidPairing: return "This connection link is invalid or has expired. Create a new one in IRIS."
        case .invalidEnvelope: return "IRIS could not verify this message. No action was taken."
        }
    }
}
public enum InventoryParser {
    public static func parse(_ data: Data, home: String = NSHomeDirectory()) throws -> InventoryResult {
        guard data.count <= 20_000_000, let groups = try JSONSerialization.jsonObject(with: data) as? [String: Any], !groups.isEmpty else { throw ScanError.invalidReport }
        var findings: [Finding] = []; var paths: [String: String] = [:]; var count = 0; var skipped = 0; var scanPaths = Set<String>()
        for category in groups.keys.sorted() {
            guard let entries = groups[category] as? [[String: Any]] else { throw ScanError.invalidReport }
            for item in entries {
                count += 1
                guard count <= 20_000, let path = item["path"] as? String, path.hasPrefix("/"), !path.contains("\u{0}") else { skipped += 1; continue }
                scanPaths.insert(path)
                let name = (item["name"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? URL(fileURLWithPath: path).lastPathComponent
                // Inventory, signing, and persistence are evidence, never a malware verdict.
                let signing = item["signature(s)"] as? [String: Any] ?? [:]
                let authorities = signing["signatureAuthorities"] as? [String] ?? []
                let signed = (signing["signatureStatus"] as? Int == 0) || (signing["signature status"] as? Int == 0)
                let plist = item["plist"] as? String ?? ""
                if plist.hasPrefix("/") { scanPaths.insert(plist) }
                let startup = plist.hasPrefix(home + "/Library/LaunchAgents/") && plist.hasSuffix(".plist")
                let finding = Finding(path: path, title: String(name.prefix(180)), category: String(category.prefix(100)), level: signed ? .information : .review,
                    explanation: signed ? "This software can run automatically. Its signature was valid when scanned; that alone does not prove it is safe." : "This software can run automatically. Review whether you recognize it; being listed or unsigned does not mean it is malware.",
                    evidence: authorities.isEmpty ? ["Found by KnockKnock in an automatic-start location"] : Array(authorities.prefix(3)), action: startup ? .disableStartup : .reveal, home: home)
                if paths[finding.id] == nil { findings.append(finding); paths[finding.id] = startup ? plist : path }
            }
        }
        return InventoryResult(findings: findings, paths: paths, scannedItems: count, scanPaths: Array(scanPaths), skippedItems: skipped)
    }
}
