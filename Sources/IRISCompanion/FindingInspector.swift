import Foundation
import Security
import IRISCore

enum FindingInspector {
    static func verifyFixtures() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("iris-review-fixture-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let file = folder.appendingPathComponent(".zshrc")
        try Data("# Harmless test fixture, never executed\n".utf8).write(to: file)
        let finding = Finding(path:file.path,title:".zshrc",category:"Shell startup",level:.review,explanation:"Fixture",evidence:[],action:.reveal)
        let original = inspect(finding,item:nil)
        guard original.0.canTrust == true, original.0.explanation.contains("Terminal setup file"), let fingerprint = original.1.reviewFingerprint else { throw ScanError.invalidReport }
        guard inspect(original.0,item:original.1).1.reviewFingerprint == fingerprint else { throw ScanError.invalidReport }
        try Data("# Changed fixture\n".utf8).write(to:file)
        guard inspect(original.0,item:original.1).1.reviewFingerprint != fingerprint else { throw ScanError.invalidReport }
        var threat = finding; threat.level = .threat
        guard inspect(threat,item:nil).0.canTrust == false else { throw ScanError.invalidReport }
        print("PASS: local inspection explains startup files, binds trust to contents, detects changes, and rejects threat trust.")
    }
    static func absolute(_ path: String) -> String { path.hasPrefix("~/") ? NSHomeDirectory() + path.dropFirst() : path }
    static func inspect(_ original: Finding, item: LocalItem?) -> (Finding, LocalItem) {
        var finding = original
        let path = absolute(finding.location), url = URL(fileURLWithPath: path)
        let actionPath = item?.path ?? path
        var content: [String] = []
        var team: String?, identifier: String?
        var signatureInvalid = false
        var code: SecStaticCode?
        let flags = SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode)
        if SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code {
          let status = SecStaticCodeCheckValidity(code, flags, nil)
          signatureInvalid = status != errSecSuccess && status != errSecCSUnsigned
          if status == errSecSuccess {
            var info: CFDictionary?
            if SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess, let values = info as? [String: Any],
               let digest = values[kSecCodeInfoUnique as String] as? Data {
                team = values[kSecCodeInfoTeamIdentifier as String] as? String
                identifier = values[kSecCodeInfoIdentifier as String] as? String
                content.append("signed:" + digest.base64EncodedString())
            }
          }
        }
        if let v = try? url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey]), v.isRegularFile == true, v.isSymbolicLink != true, (v.fileSize ?? Int.max) <= 100_000_000, let hash = try? fileSHA256(url) { content.append("file:" + hash) }
        if actionPath != path {
            // Both the startup instruction and the executable must stay unchanged.
            if let hash = try? fileSHA256(URL(fileURLWithPath: actionPath)) { content.append("startup:" + hash) } else { content = [] }
        }
        if finding.category != "Malware scan", let explanation = FindingContext.explanation(path: path, category: finding.category, verifiedTeam: team, identifier: identifier) { finding.explanation = explanation }
        if let team, let identifier {
            let publisher = "Verified signing identity: " + identifier + " · Team " + team
            if !finding.evidence.contains(publisher) { finding.evidence.append(publisher) }
        }
        let fingerprint = content.isEmpty ? nil : TrustedFindings.fingerprint(finding, content: content)
        var localText: String?
        if LocalAssessment.shellFiles.contains(url.lastPathComponent),
           let v = try? url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey]), v.isRegularFile == true, v.isSymbolicLink != true, (v.fileSize ?? Int.max) <= 262144 {
            localText = try? String(contentsOf: url, encoding: .utf8)
        }
        finding.assessment = LocalAssessment.assess(finding, verifiedTeam: team, signatureInvalid: signatureInvalid, text: localText)
        let actionHash = item?.sha256 ?? (try? fileSHA256(URL(fileURLWithPath: actionPath)))
        // Exact supported shell files can be isolated just like user LaunchAgents.
        if finding.action == .reveal, actionPath == path,
           LocalAssessment.shellFiles.contains(url.lastPathComponent), url.deletingLastPathComponent().path == NSHomeDirectory(), actionHash != nil {
            finding.action = .quarantine
        }
        finding.canTrust = fingerprint != nil && finding.level != .threat && finding.category != "Malware scan" && !finding.resolved
        return (finding, LocalItem(path: actionPath, sha256: actionHash, reviewFingerprint: fingerprint))
    }
    static func enrich(_ report: ScanReport, items: [String: LocalItem]) -> (ScanReport, [String: LocalItem]) {
        var next = report, local = items
        for index in next.findings.indices {
            let result = inspect(next.findings[index], item: local[next.findings[index].id])
            next.findings[index] = result.0; local[result.0.id] = result.1
        }
        return (next, local)
    }
}
