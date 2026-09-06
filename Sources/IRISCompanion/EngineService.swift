import Foundation
import CryptoKit
import IRISCore

final class EngineService: @unchecked Sendable {
    let runner = ProcessRunner()
    let root: URL
    let fm = FileManager.default
    init(root: URL) { self.root = root }
    var knock: URL { root.appendingPathComponent("KnockKnock-4.0.3/KnockKnock.app") }
    var clam: URL { Bundle.main.bundleURL.appendingPathComponent("Contents") }
    var database: URL { root.appendingPathComponent("signatures") }
    func verify(_ url: URL, team: String) throws {
        let r = try runner.run(URL(fileURLWithPath: "/usr/bin/codesign"), ["--verify", "--deep", "--strict", "-R", "=anchor apple generic and certificate leaf[subject.OU] = \"\(team)\"", url.path], timeout: 30)
        guard r.status == 0 else { throw ScanError.commandFailed("A scanner failed its security check. Reinstall IRIS before scanning.") }
    }
    func download(_ url: String, digest: String, target: URL, maximum: Int) async throws {
        let (temp, response) = try await URLSession.shared.download(from: URL(string: url)!)
        defer { try? fm.removeItem(at: temp) }
        guard let response = response as? HTTPURLResponse, response.statusCode == 200, (try fm.attributesOfItem(atPath: temp.path)[.size] as? Int ?? maximum + 1) <= maximum,
              try fileSHA256(temp) == digest else { throw ScanError.commandFailed("The scanner download could not be verified. Please try again.") }
        try fm.moveItem(at: temp, to: target)
    }
    func prepare(progress: @escaping @Sendable (String) -> Void) async throws {
        try fm.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        if !fm.fileExists(atPath: knock.path) {
            progress("Preparing the startup scanner…")
            let stage = root.appendingPathComponent(UUID().uuidString); try fm.createDirectory(at: stage, withIntermediateDirectories: false)
            defer { try? fm.removeItem(at: stage) }
            let zip = stage.appendingPathComponent("KnockKnock.zip")
            try await download("https://github.com/objective-see/KnockKnock/releases/download/v4.0.3/KnockKnock_4.0.3.zip", digest: "1e1371ff6eb62e0866266a0744e90aa3bdc6b22cca0599afbd330ddf52663c69", target: zip, maximum: 3_000_000)
            let output = stage.appendingPathComponent("expanded")
            let r = try runner.run(URL(fileURLWithPath: "/usr/bin/ditto"), ["-xk", zip.path, output.path])
            guard r.status == 0 else { throw ScanError.commandFailed("IRIS could not prepare the startup scanner.") }
            try verify(output.appendingPathComponent("KnockKnock.app"), team: "VBG97UB4TA")
            try fm.moveItem(at: output, to: knock.deletingLastPathComponent())
        }
        try verify(knock, team: "VBG97UB4TA")
        guard fm.fileExists(atPath: clam.appendingPathComponent("Helpers/clamscan").path) else { throw ScanError.commandFailed("The malware scanner is missing from this IRIS installation. Download the complete Mac app.") }
        #if DEBUG
        guard try runner.run(URL(fileURLWithPath: "/usr/bin/codesign"), ["--verify", "--deep", "--strict", Bundle.main.bundlePath], timeout: 30).status == 0 else { throw ScanError.commandFailed("This development build failed its signature check.") }
        #else
        guard let team = Bundle.main.object(forInfoDictionaryKey: "IRISSigningTeam") as? String, team.range(of: "^[A-Z0-9]{10}$", options: .regularExpression) != nil else { throw ScanError.commandFailed("This IRIS release is missing its signing identity.") }
        try verify(Bundle.main.bundleURL, team: team)
        #endif
    }
    func signatureDate() -> Date? {
        let names = ["daily.cvd", "daily.cld"]
        return names.compactMap { name -> Date? in
            guard let file = try? FileHandle(forReadingFrom: database.appendingPathComponent(name)) else { return nil }
            defer { try? file.close() }
            guard let bytes = try? file.read(upToCount: 512), let header = String(data: bytes, encoding: .utf8) else { return nil }
            let fields = header.trimmingCharacters(in: .whitespacesAndNewlines).components(separatedBy: ":")
            guard fields.count == 9, fields[0] == "ClamAV-VDB", let epoch = TimeInterval(fields[8]), epoch > 0, epoch < Date().timeIntervalSince1970 + 3600 else { return nil }
            return Date(timeIntervalSince1970: epoch)
        }.max()
    }
    func updateSignatures() throws {
        if let date = signatureDate(), Date().timeIntervalSince(date) < 86400 { return }
        try fm.createDirectory(at: database, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        guard !database.path.contains("\n"), !database.path.contains("\"") else { throw ScanError.unsafePath }
        let conf = root.appendingPathComponent("freshclam.conf")
        try "DatabaseDirectory \"\(database.path)\"\nDatabaseMirror database.clamav.net\nCVDCertsDirectory \"\(clam.appendingPathComponent("Resources/ClamAV/etc/certs").path)\"\nConnectTimeout 20\nReceiveTimeout 120\nScriptedUpdates yes\n".write(to: conf, atomically: true, encoding: .utf8)
        let _ = try runner.run(clam.appendingPathComponent("Helpers/freshclam"), ["--config-file=" + conf.path, "--stdout"], timeout: 600, environment: ["CVD_CERTS_DIR": clam.appendingPathComponent("Resources/ClamAV/etc/certs").path])
        guard (signatureDate().map { Date().timeIntervalSince($0) < 7 * 86400 } ?? false) else { throw ScanError.commandFailed("Malware definitions could not be updated. Check your connection and try again; the startup review is still available.") }
    }
    func checkChanges(_ changed: [String]) throws -> ([Finding], [String: LocalItem], Int, Bool) {
        guard signatureDate().map({ Date().timeIntervalSince($0) < 7 * 86400 }) == true else { throw ScanError.commandFailed("Run a scan to prepare current malware definitions before enabling monitoring.") }
        var paths: [String] = [], partial = changed.count > 200
        let allowed = ["Downloads/", "Desktop/", "Library/LaunchAgents/"].map { NSHomeDirectory() + "/" + $0 }
        for path in changed.prefix(200) {
            guard allowed.contains(where: { path.hasPrefix($0) }), !path.contains("\n"), !path.contains("\r"), !path.contains("/../") else { continue }
            let url = URL(fileURLWithPath: path)
            guard fm.fileExists(atPath: path) else { continue }
            guard let v = try? url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey]), v.isRegularFile == true, v.isSymbolicLink != true, (v.fileSize ?? Int.max) <= 100_000_000 else { partial = true; continue }
            // Do not inspect through a symlinked parent directory.
            guard url.resolvingSymlinksInPath().path == path else { partial = true; continue }
            paths.append(path)
        }
        guard !paths.isEmpty else { return ([], [:], 0, partial) }
        let list = root.appendingPathComponent("watch-" + UUID().uuidString + ".txt")
        try paths.joined(separator: "\n").write(to: list, atomically: true, encoding: .utf8); defer { try? fm.removeItem(at: list) }
        let result = try runner.run(clam.appendingPathComponent("Helpers/clamscan"), ["--cvdcertsdir=" + clam.appendingPathComponent("Resources/ClamAV/etc/certs").path, "--database=" + database.path, "--file-list=" + list.path, "--stdout", "--max-filesize=100M", "--max-scansize=200M", "--follow-file-symlinks=0", "--follow-dir-symlinks=0", "--alert-exceeds-max=yes"], timeout: 180, environment: ["CVD_CERTS_DIR": clam.appendingPathComponent("Resources/ClamAV/etc/certs").path])
        var findings: [Finding] = [], local: [String: LocalItem] = [:], checked = 0
        for line in String(decoding: result.data, as: UTF8.self).components(separatedBy: "\n") {
            if line.hasSuffix(": OK") { checked += 1 }
            guard line.hasSuffix(" FOUND"), let separator = line.range(of: ": ", options: .backwards) else { continue }
            let path = String(line[..<separator.lowerBound]), signature = String(line[separator.upperBound...].dropLast(6))
            guard paths.contains(path) else { continue }; checked += 1
            if signature.contains("Heuristics.Limits.Exceeded") { partial = true; continue }
            let heuristic = signature.hasPrefix("Heuristics.") || signature.hasPrefix("PUA.")
            let f = Finding(path: path, title: URL(fileURLWithPath: path).lastPathComponent, category: "Malware scan", level: heuristic ? .review : .threat, explanation: "Monitoring detected a changed file that matched a local scanner signature.", evidence: ["ClamAV signature: " + signature, "Detected after a file change"], action: .quarantine, signature: signature)
            let inspected = FindingInspector.inspect(f, item: LocalItem(path: path, sha256: try? fileSHA256(URL(fileURLWithPath: path))))
            findings.append(inspected.0); local[f.id] = inspected.1
        }
        for path in paths where path.hasPrefix(NSHomeDirectory() + "/Library/LaunchAgents/") && !findings.contains(where: { $0.location == "~" + path.dropFirst(NSHomeDirectory().count) }) {
            let f = Finding(path: path, title: URL(fileURLWithPath: path).lastPathComponent, category: "Startup change", level: .review, explanation: "A startup instruction was added or changed while monitoring was on. Confirm which app installed it before trusting this version.", evidence: ["Changed in your user LaunchAgents folder"], action: path.hasSuffix(".plist") ? .disableStartup : .quarantine)
            let inspected = FindingInspector.inspect(f, item: LocalItem(path: path, sha256: try? fileSHA256(URL(fileURLWithPath: path))))
            findings.append(inspected.0); local[f.id] = inspected.1
        }
        return (findings, local, checked, partial || result.status > 1 || checked < paths.count)
    }
    func scan(progress: @escaping @Sendable (ScanProgress) -> Void) throws -> (ScanReport, [String: LocalItem]) {
        var coverage = Coverage(); var findings: [Finding] = []; var local: [String: LocalItem] = [:]; var inventoryPaths: [String] = []; var scanned = 0
        progress(ScanProgress("startup", step: 4, message: "Checking software that starts with your Mac…"))
        let kk = try runner.run(knock.appendingPathComponent("Contents/MacOS/KnockKnock"), ["-whosthere", "-skipVT"], timeout: 240)
        if kk.status == 0, let inventory = try? InventoryParser.parse(kk.data) {
            findings = inventory.findings; scanned = inventory.scannedItems; inventoryPaths = inventory.scanPaths
            for (id, path) in inventory.paths { local[id] = LocalItem(path: path, sha256: try? fileSHA256(URL(fileURLWithPath: path))) }
            coverage.inventory = inventory.skippedItems == 0 ? "available locations checked" : "partial"
            if inventory.skippedItems > 0 { coverage.limitations.append("Some startup entries were not file paths and need a manual review in KnockKnock.") }
        } else {
            coverage.inventory = ScanAssessment.startupFailure(kk.errors)
            coverage.limitations.append(coverage.inventory == "needsPermission" ? "Startup review needs Full Disk Access. Add this IRIS app in System Settings, enable it, reopen IRIS, then scan again." : "The startup scanner could not finish. Try once more; if it still fails, contact support@joinhans.io. Full Disk Access has not been identified as the cause.")
        }
        try Task.checkCancellation(); try runner.checkCancellation()
        progress(ScanProgress("definitions", step: 5, message: "Updating threat definitions. The first download can take several minutes…"))
        do {
            try updateSignatures()
            coverage.signaturesUpdatedAt = signatureDate().map { ISO8601DateFormatter().string(from: $0) }
            progress(ScanProgress("malware", step: 6, message: "Finding accessible files in startup locations, Downloads and Desktop…"))
            var candidates = Set(inventoryPaths.filter { $0.hasPrefix("/") }.sorted().prefix(5000))
            var truncated = inventoryPaths.count > 5000; var skipped = max(0, inventoryPaths.count - 5000); var inaccessible = 0
            for folder in ["Downloads", "Desktop"] {
                let url = fm.homeDirectoryForCurrentUser.appendingPathComponent(folder)
                guard let enumerator = fm.enumerator(at: url, includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey], options: [.skipsHiddenFiles, .skipsPackageDescendants], errorHandler: { _, _ in truncated = true; inaccessible += 1; return true }) else { truncated = true; inaccessible += 1; continue }
                for case let path as URL in enumerator {
                    try runner.checkCancellation()
                    if candidates.count >= 5000 { truncated = true; skipped += 1; break }
                    if enumerator.level > 6 { enumerator.skipDescendants(); truncated = true; skipped += 1; continue }
                    let values = try? path.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
                    if values?.isSymbolicLink == true { enumerator.skipDescendants(); continue }
                    if values?.isRegularFile == true, (values?.fileSize ?? 0) <= 100_000_000 { candidates.insert(path.path) }
                    else if values?.isRegularFile == true { truncated = true; skipped += 1 }
                    else if values == nil { truncated = true; inaccessible += 1 }
                }
            }
            let paths = candidates.filter { path in
                guard !path.contains("\n"), !path.contains("\r"), !path.contains("\u{0}") else { skipped += 1; truncated = true; return false }
                guard let v = try? URL(fileURLWithPath: path).resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey]), v.isRegularFile == true, v.isSymbolicLink != true, (v.fileSize ?? 0) <= 100_000_000 else { skipped += 1; truncated = true; return false }
                return true
            }.sorted()
            coverage.filesSelected = paths.count
            guard !paths.isEmpty else { throw ScanError.commandFailed("No accessible files were selected. Check folder access before trying again.") }
            let tracker = MalwareProgress(paths: Set(paths), progress: progress)
            progress(ScanProgress("malware", step: 6, message: "Checking \(paths.count) files for known threats…", filesChecked: 0, filesTotal: paths.count))
            let list = root.appendingPathComponent("scan-\(UUID().uuidString).txt")
            defer { try? fm.removeItem(at: list) }
            try paths.joined(separator: "\n").write(to: list, atomically: true, encoding: .utf8)
            try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: list.path)
            let result = try runner.run(clam.appendingPathComponent("Helpers/clamscan"), ["--cvdcertsdir=" + clam.appendingPathComponent("Resources/ClamAV/etc/certs").path, "--database=" + database.path, "--file-list=" + list.path, "--stdout", "--max-filesize=100M", "--max-scansize=200M", "--follow-file-symlinks=0", "--follow-dir-symlinks=0", "--alert-exceeds-max=yes"], timeout: 900, environment: ["CVD_CERTS_DIR": clam.appendingPathComponent("Resources/ClamAV/etc/certs").path], onOutput: { tracker.receive($0) })
            tracker.finish()
            let text = String(decoding: result.data, as: UTF8.self)
            for line in text.split(separator: "\n") where line.hasSuffix(" FOUND") {
                guard let divider = line.range(of: ": ", options: .backwards) else { continue }
                let path = String(line[..<divider.lowerBound]); guard candidates.contains(path) else { continue }
                let signature = String(line[divider.upperBound...].dropLast(6))
                if signature.hasPrefix("Heuristics.Limits.Exceeded") { truncated = true; skipped += 1; continue }
                let heuristic = signature.hasPrefix("Heuristics.") || signature.hasPrefix("PUA.")
                let finding = Finding(path: path, title: URL(fileURLWithPath: path).lastPathComponent, category: "Malware scan", level: heuristic ? .review : .threat,
                    explanation: heuristic ? "The scanner found a potentially unwanted or suspicious pattern. Review it before making changes." : "This file matched a known-threat signature. Quarantine it if supported, or review its location with care.", evidence: ["ClamAV signature: " + signature], action: (path.hasPrefix(NSHomeDirectory() + "/Downloads/") || path.hasPrefix(NSHomeDirectory() + "/Desktop/")) ? .quarantine : .reveal, signature: signature)
                findings.append(finding); local[finding.id] = LocalItem(path: path, sha256: try? fileSHA256(URL(fileURLWithPath: path)))
            }
            coverage.filesChecked = tracker.checked
            coverage.skippedFiles = skipped; coverage.inaccessibleLocations = inaccessible
            if tracker.checked < paths.count { truncated = true }
            coverage.malware = result.status == 0 || result.status == 1 ? (truncated ? "partial" : "complete") : "partial"
            if paths.isEmpty { coverage.malware = "unavailable"; coverage.limitations.append("No accessible files were selected for the malware check. Check folder access before trying again.") }
            if skipped > 0 { coverage.limitations.append("At least \(skipped) files or folders were outside this quick check’s size, depth or item limits. Repeating the same scan will not expand these limits.") }
            if inaccessible > 0 { coverage.limitations.append("\(inaccessible) locations could not be read. Enable Full Disk Access and reopen IRIS before retrying.") }
            if result.status > 1 || truncated { coverage.limitations.append("Some files were inaccessible, too large, or outside this scan's limits. They have not been marked safe.") }
        } catch is CancellationError { throw CancellationError() }
        catch { coverage.malware = "unavailable"; coverage.limitations.append(error.localizedDescription) }
        coverage.limitations.append("This on-demand check covers startup software plus accessible files in Downloads and Desktop. It does not certify the whole Mac is clean or provide continuous monitoring.")
        coverage.limitations.append("KnockKnock may omit protected locations without Full Disk Access. System-owned items and app bundles use guided cleanup.")
        if findings.count > 500 { coverage.limitations.append("This dashboard shows the 500 highest-priority items. Some lower-priority startup entries are omitted from this summary.") }
        findings.sort { ($0.level == .threat ? 0 : $0.level == .review ? 1 : 2) < ($1.level == .threat ? 0 : $1.level == .review ? 1 : 2) }
        return (ScanReport(scannedItems: scanned, coverage: coverage, findings: Array(findings.prefix(500))), local)
    }
}
