import Foundation

/// Local evidence, not a filename reputation score. No contents are sent to a provider.
public struct FindingAssessment: Codable, Sendable, Equatable {
    public var verdict: String
    public var summary: String
    public var signals: [String]
    public var nextStep: String
    public init(verdict: String, summary: String, signals: [String], nextStep: String) {
        self.verdict = verdict; self.summary = summary; self.signals = signals; self.nextStep = nextStep
    }
}
public enum LocalAssessment {
    public static let shellFiles = Set([".zshenv", ".zshrc", ".zprofile", ".zlogin", ".bash_profile", ".bashrc", ".profile"])
    public static func assess(_ finding: Finding, verifiedTeam: String?, signatureInvalid: Bool, text: String?) -> FindingAssessment {
        if finding.level == .threat {
            return FindingAssessment(verdict: "Known-threat match", summary: "The local malware scanner matched a threat signature. Keep this item out of use while you review it.", signals: [finding.signature.map { "Scanner signature: " + $0 } ?? "A malware signature matched this file."], nextStep: "Quarantine the file if available. For an installed app, quit it and use its official removal instructions. A match can be a false positive; do not restore it simply because the name looks familiar.")
        }
        if finding.category == "Malware scan", finding.signature != nil {
            return FindingAssessment(verdict: "Scanner warning", summary: finding.explanation, signals: ["Scanner signature: " + (finding.signature ?? "Unknown")], nextStep: "This is a heuristic or potentially unwanted-file warning, not a confirmed malware verdict. If the file is unexpected, quarantine it while you verify its source.")
        }
        let name = URL(fileURLWithPath: finding.location).lastPathComponent
        var signals: [String] = []
        if signatureInvalid { signals.append("The code signature could not be validated. The file may have changed, be damaged, or use an unsupported signature.") }
        // Deliberately return descriptions only. Script lines may contain passwords or API keys.
        let lines = (text ?? "").split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.hasPrefix("#") }
        let code = lines.joined(separator: "\n")
        let patterns: [(String, String)] = [
            (#"(?im)\b(curl|wget)\b[^\n]*\|\s*(?:/bin/)?(?:ba|z)?sh\b"#, "Downloads code and immediately runs it in a shell. Some installers do this, but it deserves verification."),
            (#"(?im)\b(?:eval|exec)\b[^\n]*(?:base64|xxd\s+-r)|base64\b[^\n]*\|\s*(?:/bin/)?(?:ba|z)?sh\b"#, "Decodes and executes hidden script content. Verify the source before trusting it."),
            (#"(?im)/dev/tcp/|\b(?:nc|ncat)\b[^\n]*\s-[^\s]*e\s"#, "Contains a command pattern that can connect a shell to another machine. Investigate this before use."),
            (#"(?im)\b(?:spctl\s+--master-disable|csrutil\s+disable)\b"#, "Contains a command to disable a built-in Mac security protection.")
        ]
        for (pattern, explanation) in patterns where code.range(of: pattern, options: .regularExpression) != nil { signals.append(explanation) }
        if !signals.isEmpty {
            return FindingAssessment(verdict: "Investigate before trusting", summary: "IRIS found specific evidence worth checking. These signals are not proof of malware.", signals: signals, nextStep: "If you do not recognize this setup, quarantine the supported file to stop future loading from this location. Keep it available to restore while you verify who installed it.")
        }
        if let team = verifiedTeam {
            return FindingAssessment(verdict: "Verified publisher", summary: "The signature is valid and identifies the publisher. This helps establish origin, not whether every behavior is safe.", signals: ["Apple developer team: " + team], nextStep: "If you installed this app and expect its access, mark this version trusted. If you do not use it, quit it and remove it using the developer’s uninstaller or macOS settings.")
        }
        if shellFiles.contains(name) {
            let baseline = text == nil ? "IRIS could not read this standard shell setup file, so its contents have not been assessed." : lines.isEmpty ? "This file contains only comments or blank lines." : "This is a standard shell setup filename. IRIS found no matches to its limited high-risk command patterns."
            return FindingAssessment(verdict: text == nil ? "More information needed" : "Common setup file", summary: baseline, signals: [text == nil ? "Contents could not be inspected within the local size/access limits." : "Contents were inspected locally; the file itself is never uploaded."], nextStep: "Developer tools commonly create these files. Trust it only if the setup is expected. Quarantining it is reversible, but may stop Terminal shortcuts, tools or environment settings from loading. Existing Terminal sessions are not stopped.")
        }
        return FindingAssessment(verdict: "More information needed", summary: "IRIS cannot establish this item’s reputation from its name alone. No risk percentage is assigned without supporting evidence.", signals: ["No verified publisher was established for this item."], nextStep: "Check its location and the app it belongs to. If unexpected, use the available quarantine or system settings action. Keep an unfamiliar item untrusted while you investigate.")
    }
}
