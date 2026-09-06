import Foundation
import IRISCore

enum SafeguardScanner {
    static func check(runner: ProcessRunner) throws -> [Safeguard] {
        let checks: [(String, String, String, [String], String)] = [
            ("filevault", "Disk encryption", "/usr/bin/fdesetup", ["status"], "FileVault protects your files if your Mac is lost or stolen."),
            ("firewall", "Mac firewall", "/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"], "The firewall limits unsolicited incoming connections. It does not inspect outgoing traffic."),
            ("gatekeeper", "App download protection", "/usr/sbin/spctl", ["--status"], "Gatekeeper checks downloaded apps before they run.")
        ]
        return try checks.map { id, title, command, args, detail in
            try runner.checkCancellation()
            let result = try? runner.run(URL(fileURLWithPath: command), args, timeout: 15)
            return Safeguard(id: id, title: title, status: ScanAssessment.safeguard(id, output: result.map { String(decoding: $0.data, as: UTF8.self) } ?? "", status: result?.status ?? -1), detail: detail)
        }
    }
}
