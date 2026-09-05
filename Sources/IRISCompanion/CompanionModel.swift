import Foundation
import SwiftUI
import AppKit
import CryptoKit
import IRISCore

struct Connection: Codable { let id: String; let token: String; let key: String; let expiresAt: Double }
struct SavedScan: Codable { let report: ScanReport; let items: [String: LocalItem] }
struct SharedState: Codable { let version: Int; let status: String; let message: String; let report: ScanReport?; let updatedAt: Double }
struct PollResponse: Decodable { let command: Envelope?; let browserActive: Bool }
struct ClaimResponse: Decodable { let id: String; let token: String; let expiresAt: Double }

@MainActor final class CompanionModel: ObservableObject {
    @Published var message = "A clearer picture of what is running on your Mac."
    @Published var busy = false
    @Published var report: ScanReport?
    @Published var connected = false
    @Published var receipts: [QuarantineReceipt] = []
    @Published var problem: String?
    let support = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/IRIS Companion")
    lazy var engine = EngineService(root: support.appendingPathComponent("Engines"))
    private var localItems: [String: LocalItem] = [:]
    private var connection: Connection?
    private var scanTask: Task<Void, Never>?
    private var polling: Task<Void, Never>?
    private var lastUpload = Date.distantPast
    private var lastBrowserActivity = Date.distantPast
    private var seenCommands: [String] = UserDefaults.standard.stringArray(forKey: "processedCommands") ?? []
    private let relaySession: URLSession = { let config = URLSessionConfiguration.ephemeral; config.httpCookieStorage = nil; config.httpShouldSetCookies = false; return URLSession(configuration: config) }()
    private let endpoint = URL(string: "https://app.undercoveriris.io/api/device")!
    init() {
        try? FileManager.default.createDirectory(at: support, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        if let data = Keychain.load("connection"), let value = try? JSONDecoder().decode(Connection.self, from: data), value.expiresAt > Date().timeIntervalSince1970 * 1000 { connection = value; connected = true }
        loadScan(); refreshReceipts(); startPolling()
    }
    var unresolved: [Finding] { (report?.findings ?? []).filter { !$0.resolved }.sorted { rank($0.level) < rank($1.level) } }
    func rank(_ level: FindingLevel) -> Int { level == .threat ? 0 : level == .review ? 1 : 2 }
    func refreshReceipts() { receipts = (try? quarantineStore().receipts()) ?? [] }
    func quarantineStore() throws -> QuarantineStore { try QuarantineStore(directory: support.appendingPathComponent("Quarantine")) }
    func localKey() throws -> SymmetricKey {
        if let bytes = Keychain.load("local-report-key"), bytes.count == 32 { return SymmetricKey(data: bytes) }
        let key = SymmetricKey(size: .bits256); try Keychain.save("local-report-key", data: key.withUnsafeBytes { Data($0) }); return key
    }
    func loadScan() {
        guard let data = try? Data(contentsOf: support.appendingPathComponent("latest-scan.json")), let box = try? JSONDecoder().decode(Envelope.self, from: data), let key = try? localKey(), let value = try? RelayCrypto.open(box, as: SavedScan.self, key: key, direction: "local", maximumAge: 30 * 86400) else { return }
        report = value.report; localItems = value.items; message = "Your last review is ready. Scan again to check what changed."
    }
    func saveScan() {
        guard let report else { return }
        do {
            let box = try RelayCrypto.seal(SavedScan(report: report, items: localItems), key: localKey(), direction: "local")
            let file = support.appendingPathComponent("latest-scan.json"); try JSONEncoder().encode(box).write(to: file, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        } catch { problem = "The scan is available now, but IRIS could not save it securely for next time." }
    }
    func startScan() {
        guard !busy else { return }
        busy = true; problem = nil; message = "Preparing your Mac check…"
        let engine = self.engine
        engine.runner.resetCancellation()
        scanTask = Task {
            do {
                let progress: @Sendable (String) -> Void = { [weak self] text in Task { @MainActor in self?.message = text; await self?.publish() } }
                try await engine.prepare(progress: progress)
                try Task.checkCancellation()
                let work = Task.detached { try engine.scan(progress: progress) }
                let result = try await withTaskCancellationHandler { try await work.value } onCancel: { work.cancel(); engine.runner.cancel() }
                try Task.checkCancellation()
                report = result.0; localItems = result.1; saveScan()
                message = "Your review is ready. Start with the items that need attention."
            } catch is CancellationError { message = "Scan stopped. Your previous review is still available." }
            catch { problem = error.localizedDescription; message = "Your scan needs attention." }
            busy = false; await publish()
        }
    }
    func cancelScan() { scanTask?.cancel(); engine.runner.cancel(); message = "Stopping the scan…" }
    func clearReview() {
        guard !busy else { return }
        do { let file = support.appendingPathComponent("latest-scan.json"); if FileManager.default.fileExists(atPath: file.path) { try FileManager.default.removeItem(at: file) }; report = nil; localItems = [:]; message = "Your saved review was removed. Quarantined files remain available to restore."; Task { await publish() } }
        catch { problem = "IRIS could not remove the saved review. Please try again." }
    }
    func openWeb() { NSWorkspace.shared.open(URL(string: "https://app.undercoveriris.io/device")!) }
    func openFullDiskAccess() { NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")!) }
    func connect(_ url: URL) {
        guard url.scheme == "iris-companion", url.host == "connect", let parts = URLComponents(url: url, resolvingAgainstBaseURL: false), let query = parts.queryItems,
              query.count == 2, let ticket = query.first(where: { $0.name == "ticket" })?.value, let id = query.first(where: { $0.name == "id" })?.value,
              ticket.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil, id.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil,
              let key = parts.fragment, (try? RelayCrypto.decodeKey(key)) != nil else { problem = ScanError.invalidPairing.localizedDescription; return }
        let code = SHA256.hash(data: Data(key.utf8)).prefix(3).map { String(format: "%02X", $0) }.joined()
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert(); alert.messageText = "Connect this Mac to IRIS?"
        alert.informativeText = "Check that your IRIS browser shows connection code \(code). Encrypted reports will be shared with that browser for 30 days. Files stay on this Mac. You can disconnect at any time."
        alert.addButton(withTitle: "Connect Mac"); alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        Task {
            do {
                let value: ClaimResponse = try await request(["action": "claim", "ticket": ticket], token: nil)
                guard value.id == id else { throw ScanError.invalidPairing }
                let next = Connection(id: id, token: value.token, key: key, expiresAt: value.expiresAt)
                try Keychain.save("connection", data: JSONEncoder().encode(next)); connection = next; connected = true; problem = nil; lastBrowserActivity = Date(); startPolling()
                await publish(); openWeb()
            } catch { problem = error.localizedDescription }
        }
    }
    func disconnect() {
        let old = connection; connection = nil; connected = false; Keychain.remove("connection")
        if let old { Task { let _: EmptyResponse? = try? await request(["action": "disconnect", "id": old.id], token: old.token) } }
    }
    struct EmptyResponse: Decodable {}
    func request<T: Decodable>(_ payload: [String: Any], token: String?) async throws -> T {
        var req = URLRequest(url: endpoint); req.httpMethod = "POST"; req.timeoutInterval = 20
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let token { req.setValue("Bearer " + token, forHTTPHeaderField: "Authorization") }
        req.httpBody = try JSONSerialization.data(withJSONObject: payload)
        let (data, response) = try await relaySession.data(for: req)
        guard data.count <= 700_000 else { throw ScanError.invalidEnvelope }
        guard let http = response as? HTTPURLResponse else { throw ScanError.commandFailed("IRIS could not reach the web app.") }
        if http.statusCode == 404, let token, connection?.token == token { connection = nil; connected = false; Keychain.remove("connection") }
        guard http.statusCode == 200 else { throw ScanError.commandFailed("IRIS could not sync with the web app. Your local scan remains available.") }
        return try JSONDecoder().decode(T.self, from: data)
    }
    func publish() async {
        guard let c = connection else { return }
        do {
            var sharedReport = report
            if let initial = sharedReport, (try JSONEncoder().encode(initial)).count > 380_000 {
                sharedReport?.coverage.limitations.append("The web dashboard shows a shortened report. The complete review remains in the Mac app.")
                while let value = sharedReport, (try JSONEncoder().encode(value)).count > 380_000, !value.findings.isEmpty { sharedReport?.findings.removeLast() }
            }
            let state = SharedState(version: 1, status: busy ? "scanning" : problem == nil ? (report == nil ? "ready" : "complete") : "attention", message: message, report: sharedReport, updatedAt: Date().timeIntervalSince1970 * 1000)
            let box = try RelayCrypto.seal(state, key: RelayCrypto.decodeKey(c.key), direction: "report")
            let payload = try JSONSerialization.jsonObject(with: JSONEncoder().encode(box))
            let _: EmptyResponse = try await request(["action": "report", "id": c.id, "payload": payload], token: c.token)
            lastUpload = Date()
        } catch { /* Local work stays available; polling retries report synchronization. */ }
    }
    func startPolling() {
        polling?.cancel()
        polling = Task { [weak self] in
            while !Task.isCancelled {
                var pause: UInt64 = 60
                if let self, let c = self.connection {
                    do {
                        let r: PollResponse = try await self.request(["action": "poll", "id": c.id], token: c.token)
                        guard !Task.isCancelled, self.connection?.id == c.id else { continue }
                        if r.browserActive { self.lastBrowserActivity = Date() }
                        pause = self.busy || Date().timeIntervalSince(self.lastBrowserActivity) < 60 ? 5 : 60
                        if let box = r.command {
                            if !self.seenCommands.contains(box.id) {
                                let command = try RelayCrypto.open(box, as: DeviceCommand.self, key: RelayCrypto.decodeKey(c.key), direction: "command", maximumAge: 120)
                                self.seenCommands.append(box.id); self.seenCommands = Array(self.seenCommands.suffix(200)); UserDefaults.standard.set(self.seenCommands, forKey: "processedCommands")
                                self.perform(command)
                            }
                            let _: EmptyResponse = try await self.request(["action": "ack", "id": c.id, "payload": box.id], token: c.token)
                            await self.publish()
                        }
                        if Date().timeIntervalSince(self.lastUpload) > (r.browserActive ? 60 : 3600) { await self.publish() }
                    } catch { /* Offline Mac operation is intentionally independent of the relay. */ }
                }
                try? await Task.sleep(nanoseconds: pause * 1_000_000_000)
            }
        }
    }
    func perform(_ command: DeviceCommand) {
        if command.action == "scan" { startScan(); return }
        guard !busy, let report, command.reportId == report.id, let id = command.findingId, let finding = report.findings.first(where: { $0.id == id && !$0.resolved }), command.action == finding.action.rawValue else { return }
        act(finding)
    }
    func act(_ finding: Finding) {
        guard !busy, let item = localItems[finding.id] else { return }
        if finding.action == .reveal { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: item.path)]); return }
        guard finding.action == .quarantine || finding.action == .disableStartup, let hash = item.sha256 else { return }
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert(); alert.messageText = finding.action == .disableStartup ? "Stop this item starting automatically?" : "Quarantine this file?"
        alert.informativeText = "\(finding.title)\n\n\(finding.explanation)\n\nIRIS will move the file into a private quarantine. You can restore it from the Mac app."
        alert.addButton(withTitle: finding.action == .disableStartup ? "Disable startup item" : "Quarantine file"); alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        do {
            let store = try quarantineStore()
            engine.runner.resetCancellation()
            try store.validate(path: item.path, expectedHash: hash)
            if finding.action == .disableStartup {
                let result = try engine.runner.run(URL(fileURLWithPath: "/bin/launchctl"), ["bootout", "gui/\(getuid())", item.path], timeout: 15)
                // Exit 3 means the service was not loaded; moving its plist still prevents next-login startup.
                guard result.status == 0 || result.status == 3 else { throw ScanError.commandFailed("macOS could not stop this startup item. Review it in System Settings before trying again.") }
            }
            _ = try store.quarantine(path: item.path, expectedHash: hash)
            if let index = report?.findings.firstIndex(where: { $0.id == finding.id }) { report?.findings[index].resolved = true }
            message = "Item quarantined. You can restore it from the Mac app."; saveScan(); refreshReceipts(); Task { await publish() }
        } catch { problem = error.localizedDescription }
    }
    func restore(_ receipt: QuarantineReceipt) {
        let alert = NSAlert(); alert.messageText = "Restore this quarantined file?"; alert.informativeText = "Only restore files you trust. This puts the file back at its original location. Startup items may run again at your next login."
        alert.addButton(withTitle: "Restore file"); alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        do { try quarantineStore().restore(receipt); refreshReceipts(); message = "File restored. Run a new scan to update your review."; report = nil; localItems = [:]; try? FileManager.default.removeItem(at: support.appendingPathComponent("latest-scan.json")); Task { await publish() } }
        catch { problem = error.localizedDescription }
    }
}
