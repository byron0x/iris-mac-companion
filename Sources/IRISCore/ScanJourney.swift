import Foundation

/// Progress measures work performed, never a percentage of safety.
public struct ScanProgress: Codable, Sendable {
    public var stage: String
    public var step: Int
    public var total: Int = 6
    public var message: String
    public var filesChecked: Int?
    public var filesTotal: Int?
    public init(_ stage: String, step: Int, message: String, filesChecked: Int? = nil, filesTotal: Int? = nil) {
        self.stage = stage; self.step = step; self.message = message
        self.filesChecked = filesChecked; self.filesTotal = filesTotal
    }
}
public struct Safeguard: Codable, Sendable, Identifiable {
    public let id: String
    public let title: String
    public let status: String
    public let detail: String
    public init(id: String, title: String, status: String, detail: String) {
        self.id = id; self.title = title; self.status = status; self.detail = detail
    }
}
public enum ScanAssessment {
    public static func startupFailure(_ stderr: Data) -> String {
        String(decoding: stderr, as: UTF8.self).contains("requires Full Disk Access") ? "needsPermission" : "incomplete"
    }
    public static func checked(_ value: String) -> Bool { ["complete", "checked", "available locations checked"].contains(value) }
    public static func needsAttention(_ report: ScanReport) -> Bool {
        !checked(report.coverage.inventory) || !checked(report.coverage.malware) || report.coverage.keyboard?.status != "checked" || report.findings.contains { !$0.resolved && ($0.trusted != true || $0.level == .threat) && $0.level != .information } || (report.coverage.safeguards ?? []).contains { $0.status != "enabled" }
    }
    public static func summary(_ report: ScanReport) -> String {
        let threats = report.findings.filter { !$0.resolved && $0.level == .threat }.count
        if threats > 0 { return "\(threats) known-threat match\(threats == 1 ? "" : "es"). Review these first below." }
        if report.coverage.inventory == "needsPermission" { return "Scan finished with a gap: enable Full Disk Access to check startup software. Your other results are saved." }
        if !checked(report.coverage.inventory) || !checked(report.coverage.malware) { return "Scan finished with gaps. See what was checked and the next steps below; a repeat scan alone may not fix them." }
        if needsAttention(report) { return "Scan finished. Review the highlighted items and protection settings below." }
        return "Checks finished. No known threats found in the files checked. Review the scan coverage below."
    }
    public static func safeguard(_ id: String, output: String, status: Int32) -> String {
        guard status == 0 else { return "unknown" }
        switch id {
        case "filevault": return output.contains("FileVault is On.") ? "enabled" : output.contains("FileVault is Off.") ? "disabled" : "unknown"
        case "firewall": return output.contains("State = 1") || output.contains("State = 2") ? "enabled" : output.contains("State = 0") ? "disabled" : "unknown"
        case "gatekeeper": return output.contains("assessments enabled") ? "enabled" : output.contains("assessments disabled") ? "disabled" : "unknown"
        default: return "unknown"
        }
    }
}
