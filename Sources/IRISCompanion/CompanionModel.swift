import Foundation
import SwiftUI
import AppKit
import CryptoKit
import IRISCore

struct Connection: Codable { let id: String; let token: String; let key: String; let expiresAt: Double }
struct SavedScan: Codable { let report: ScanReport; let items: [String: LocalItem] }
struct SharedState: Codable { let version: Int; let status: String; let message: String; let report: ScanReport?; let updatedAt: Double; let capabilities: [String]; let progress: ScanProgress?; let access: CompanionAccess?; let monitoring: WatchState }
struct PollResponse: Decodable { let command: Envelope?; let browserActive: Bool }
struct ClaimResponse: Decodable { let id: String; let token: String; let expiresAt: Double }

@MainActor final class CompanionModel: ObservableObject {
    @Published var message = "A clearer picture of what is running on your Mac."
    @Published var busy = false
    @Published var progress: ScanProgress?
    private var scanRun: UUID?
    @Published var report: ScanReport?
    @Published var connected = false
    @Published var receipts: [QuarantineReceipt] = []
    @Published var problem: String?
    @Published var keychainLocked = false
    @Published var access: CompanionAccess?
    @Published var watchState = WatchState()
    private var watcher: ChangeWatcher?
    private var watchTask: Task<Void, Never>?
    private var pendingPaths = Set<String>()
    private var watchCoverageGap = false
    private var lastAccessCheck = Date.distantPast
    #if DEBUG
    let support = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/IRIS Companion Development")
    #else
    let support = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/IRIS Companion")
    #endif
    lazy var engine = EngineService(root: support.appendingPathComponent("Engines"))
    private var localItems: [String: LocalItem] = [:]
    private var trustedFindings = TrustedFindings()
    private var connectingID: String?
    private var connection: Connection?
    private var scanTask: Task<Void, Never>?
    private var polling: Task<Void, Never>?
    private var lastUpload = Date.distantPast
    private var publishing = false
    private var publishAgain = false
    private var lastBrowserActivity = Date.distantPast
    private var seenCommands: [String] = UserDefaults.standard.stringArray(forKey: "processedCommands") ?? []
    private let relaySession: URLSession = { let config = URLSessionConfiguration.ephemeral; config.httpCookieStorage = nil; config.httpShouldSetCookies = false; return URLSession(configuration: config) }()
    private let endpoint = URL(string: "https://app.undercoveriris.io/api/device")!
    init(initialize: Bool = true) {
        guard initialize else { return }
        try? FileManager.default.createDirectory(at: support, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        do { if let data = try Keychain.load("connection"), let value = try? JSONDecoder().decode(Connection.self, from: data), value.expiresAt > Date().timeIntervalSince1970 * 1000 { connection = value; connected = true } } catch { keychainLocked = true }
        loadTrust(); loadScan(); refreshReceipts(); startPolling()
        watchState.enabled = UserDefaults.standard.bool(forKey: "proMonitoring")
    }
    var unresolved: [Finding] { (report?.findings ?? []).filter { !$0.resolved && ($0.trusted != true || $0.level == .threat) }.sorted { rank($0.level) < rank($1.level) } }
    var trusted: [Finding] { (report?.findings ?? []).filter { $0.trusted == true && !$0.resolved } }
    func rank(_ level: FindingLevel) -> Int { level == .threat ? 0 : level == .review ? 1 : 2 }
    func refreshReceipts() { receipts = (try? quarantineStore().receipts()) ?? [] }
    func quarantineStore() throws -> QuarantineStore { try QuarantineStore(directory: support.appendingPathComponent("Quarantine")) }
    func localKey() throws -> SymmetricKey {
        if let bytes = try Keychain.load("local-report-key") { guard bytes.count == 32 else { throw ScanError.commandFailed("IRIS’s saved encryption key is unavailable. Your saved review has not been changed.") }; return SymmetricKey(data: bytes) }
        let key = SymmetricKey(size: .bits256); try Keychain.save("local-report-key", data: key.withUnsafeBytes { Data($0) }); return key
    }
    func loadScan() {
        guard let data = try? Data(contentsOf: support.appendingPathComponent("latest-scan.json")), let box = try? JSONDecoder().decode(Envelope.self, from: data) else { return }
        do {
            let key = try localKey()
            guard let value = try? RelayCrypto.open(box, as: SavedScan.self, key: key, direction: "local", maximumAge: 30 * 86400) else { return }
            let enriched = FindingInspector.enrich(value.report, items: value.items)
            report = enriched.0; localItems = enriched.1; applyTrust(); message = ScanAssessment.summary(report!)
        } catch { keychainLocked = true }
    }
    func unlockSavedReview() {
        guard !busy else { return }
        do {
            _ = try Keychain.load("local-report-key", allowPrompt: true)
            if let data = try Keychain.load("connection", allowPrompt: true), let value = try? JSONDecoder().decode(Connection.self, from: data), value.expiresAt > Date().timeIntervalSince1970 * 1000 { connection = value; connected = true; startPolling() }
            keychainLocked = false; problem = nil; loadTrust(); loadScan()
        } catch { keychainLocked = true; problem = "Your saved review remains locked. IRIS has not changed its encryption key." }
    }
    func saveScan() {
        guard let report else { return }
        do {
            let box = try RelayCrypto.seal(SavedScan(report: report, items: localItems), key: localKey(), direction: "local")
            let file = support.appendingPathComponent("latest-scan.json"); try JSONEncoder().encode(box).write(to: file, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        } catch { keychainLocked = true; problem = "The scan is available now, but IRIS could not save it securely. Unlock the saved IRIS keys to enable saving." }
    }
    func loadTrust() {
        guard let data = try? Data(contentsOf: support.appendingPathComponent("trusted-findings.json")), let box = try? JSONDecoder().decode(Envelope.self, from: data) else { return }
        do { trustedFindings = try RelayCrypto.open(box, as: TrustedFindings.self, key: localKey(), direction: "local-trust", maximumAge: 100 * 365 * 86400) }
        catch { keychainLocked = true }
    }
    func applyTrust() {
        guard var value = report else { return }
        for index in value.findings.indices { value.findings[index].trusted = trustedFindings.recognizes(value.findings[index], fingerprint: localItems[value.findings[index].id]?.reviewFingerprint) }
        report = value
    }
    func clearTrust() {
        guard !busy else { return }
        do {
            let file = support.appendingPathComponent("trusted-findings.json")
            if FileManager.default.fileExists(atPath:file.path) { try FileManager.default.removeItem(at:file) }
            trustedFindings = TrustedFindings(); applyTrust(); saveScan()
            message = "Saved trust choices were removed. These items can be reviewed again."; Task { await publish() }
        } catch { problem = "IRIS could not remove your saved trust choices. Please try again." }
    }
    func trust(_ finding: Finding, remove: Bool = false) {
        guard !busy, let current = report?.findings.first(where: { $0.id == finding.id }), !current.resolved else { return }
        do {
            var next = trustedFindings
            if remove { next.entries.removeValue(forKey: finding.id) }
            else {
                let inspected = FindingInspector.inspect(current, item: localItems[current.id])
                guard let fingerprint = inspected.1.reviewFingerprint, fingerprint == localItems[current.id]?.reviewFingerprint else { throw ScanError.changedFile }
                try next.remember(current, fingerprint: fingerprint)
            }
            let box = try RelayCrypto.seal(next, key: localKey(), direction: "local-trust")
            let file = support.appendingPathComponent("trusted-findings.json")
            try JSONEncoder().encode(box).write(to: file, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
            trustedFindings = next; applyTrust(); saveScan()
            message = remove ? "This item is back in your review." : "Trusted by you. IRIS will ask again if this item or its access changes. You can undo this under Trusted by you."
            Task { await publish() }
        } catch { problem = error.localizedDescription }
    }
    func startScan() {
        guard !busy else { return }
        guard connected else { message = "Connect your IRIS account once to use your monthly scan or Pro access. Your saved results and cleanup remain available."; openWeb(); return }
        busy = true; problem = nil; message = "Preparing your Mac check…"
        let run = UUID(); scanRun = run
        progress = ScanProgress("prepare", step: 1, message: message)
        let engine = self.engine
        engine.runner.resetCancellation()
        scanTask = Task {
            do {
                let update: @Sendable (ScanProgress) -> Void = { [weak self] value in
                    Task { @MainActor in
                        guard let self, self.scanRun == run, self.busy, value.step >= (self.progress?.step ?? 0) else { return }
                        self.progress = value; self.message = value.message
                        if Date().timeIntervalSince(self.lastUpload) >= 2 { await self.publish() }
                    }
                }
                try await engine.prepare(progress: { update(ScanProgress("prepare", step: 1, message: $0)) })
                try Task.checkCancellation()
                let requestID = UserDefaults.standard.string(forKey: "scanRequestID") ?? UUID().uuidString.lowercased()
                UserDefaults.standard.set(requestID, forKey: "scanRequestID")
                let scanConnectionID = connection?.id
                try await refreshAccess(action: "reserve", runId: requestID)
                progress = ScanProgress("keyboard", step: 2, message: "Checking keyboard access…"); message = progress!.message; await publish()
                let keyboard = await Task.detached { KeyboardScanner.check() }.value
                try Task.checkCancellation()
                progress = ScanProgress("protections", step: 3, message: "Checking disk encryption, firewall and app protection…"); message = progress!.message; await publish()
                let safeguards = try await Task.detached { try SafeguardScanner.check(runner: engine.runner) }.value
                try Task.checkCancellation()
                let work = Task.detached { try engine.scan(progress: update) }
                let result = try await withTaskCancellationHandler { try await work.value } onCancel: { work.cancel(); engine.runner.cancel() }
                try Task.checkCancellation()
                report = keyboard.merging(into: result.0); report?.coverage.safeguards = safeguards
                let enriched = await Task.detached { FindingInspector.enrich(keyboard.merging(into: result.0), items: result.1) }.value
                try Task.checkCancellation()
                report = enriched.0; report?.coverage.safeguards = safeguards; localItems = enriched.1; applyTrust(); saveScan()
                message = ScanAssessment.summary(report!)
                // Retry this small completion receipt after offline scans; no findings leave the Mac.
                if let scanConnectionID, connection?.id == scanConnectionID {
                    UserDefaults.standard.set(["id": scanConnectionID, "runId": requestID], forKey: "pendingEarnCompletion")
                    await syncEarnCompletion()
                }
                if report?.coverage.malware == "complete" && report?.coverage.inventory == "available locations checked" { watchCoverageGap = false; UserDefaults.standard.removeObject(forKey: "scanRequestID") }
            } catch is CancellationError { message = "Scan stopped before it finished. Any previous results below are unchanged." }
            catch { problem = error.localizedDescription; message = "Scan could not finish. Any previous results below are unchanged." }
            scanRun = nil; progress = nil; busy = false; await publish()
        }
    }
    func checkKeyboard() {
        guard !busy else { return }
        busy = true; problem = nil; progress = nil; message = "Checking keyboard access…"
        scanTask = Task {
            let keyboard = await Task.detached { KeyboardScanner.check() }.value
            if !Task.isCancelled {
                let enriched = FindingInspector.enrich(keyboard.merging(into: report), items: localItems)
                report = enriched.0; localItems = enriched.1; applyTrust(); saveScan()
                message = keyboard.coverage.status == "unavailable" ? "Keyboard access could not be checked. Your other results are still available." : "Keyboard review updated. Your other scan results are still available."
            } else { message = "Check stopped. Your previous review is still available." }
            busy = false; await publish()
        }
    }
    func cancelScan() { scanTask?.cancel(); engine.runner.cancel(); message = "Stopping the scan…" }
    func clearReview() {
        guard !busy else { return }
        do { let file = support.appendingPathComponent("latest-scan.json"); if FileManager.default.fileExists(atPath: file.path) { try FileManager.default.removeItem(at: file) }; report = nil; localItems = [:]; message = "Your saved review was removed. Quarantined files remain available to restore."; Task { await publish() } }
        catch { problem = "IRIS could not remove the saved review. Please try again." }
    }
    func openWeb() { NSWorkspace.shared.open(URL(string: "https://app.undercoveriris.io/device?companion=mac#device-content")!) }
    var appURL: URL { Bundle.main.bundleURL }
    var installedInApplications: Bool { appURL.path.hasPrefix("/Applications/") || appURL.path.hasPrefix(NSHomeDirectory() + "/Applications/") }
    func showAppInFinder() { NSWorkspace.shared.activateFileViewerSelecting([appURL]) }
    func reopenForPermissions() {
        guard !busy else { return }
        // The path is a separate argument, never interpolated into shell code.
        let helper = Process(); helper.executableURL = URL(fileURLWithPath: "/bin/sh")
        helper.arguments = ["-c", "sleep 2; /usr/bin/open \"$1\"", "iris-reopen", appURL.path]
        do { try helper.run(); NSApp.terminate(nil) }
        catch { problem = "Quit IRIS, then open it again from Finder to apply the permission." }
    }
    func openSafeguard(_ id: String) {
        let panes = ["filevault": "x-apple.systempreferences:com.apple.preference.security?FileVault", "firewall": "x-apple.systempreferences:com.apple.Network-Settings.extension?Firewall", "gatekeeper": "x-apple.systempreferences:com.apple.preference.security?General"]
        if let pane = panes[id], let url = URL(string: pane) { NSWorkspace.shared.open(url) }
    }
    func openFullDiskAccess() { NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")!) }
    func openKeyboardSettings() { NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_ListenEvent")!) }
    func openAccessibilitySettings() { NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")!) }
    func connect(_ url: URL) {
        guard url.scheme == "iris-companion", url.host == "connect", let parts = URLComponents(url: url, resolvingAgainstBaseURL: false), let query = parts.queryItems,
              query.count == 2, let ticket = query.first(where: { $0.name == "ticket" })?.value, let id = query.first(where: { $0.name == "id" })?.value,
              ticket.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil, id.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil,
              let key = parts.fragment, (try? RelayCrypto.decodeKey(key)) != nil else { problem = ScanError.invalidPairing.localizedDescription; return }
        if connection?.id == id || connectingID == id { return }
        connectingID = id
        let code = SHA256.hash(data: Data(key.utf8)).prefix(3).map { String(format: "%02X", $0) }.joined()
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert(); alert.messageText = "Connect this Mac to IRIS?"
        alert.informativeText = "Check that your IRIS browser shows connection code \(code). Encrypted reports will be shared with that browser for 30 days. Files stay on this Mac. You can disconnect at any time."
        alert.addButton(withTitle: "Connect Mac"); alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { connectingID = nil; return }
        Task {
            defer { connectingID = nil }
            do {
                let value: ClaimResponse = try await request(["action": "claim", "ticket": ticket], token: nil)
                guard value.id == id else { throw ScanError.invalidPairing }
                let next = Connection(id: id, token: value.token, key: key, expiresAt: value.expiresAt)
                try Keychain.save("connection", data: JSONEncoder().encode(next)); connection = next; connected = true; problem = nil; lastBrowserActivity = Date(); startPolling()
                message = "Connected. Your existing dashboard will update automatically."; await publish()
            } catch { problem = error.localizedDescription }
        }
    }
    func disconnect() {
        let old = connection; connection = nil; connected = false; Keychain.remove("connection")
        access = nil; UserDefaults.standard.removeObject(forKey: "scanRequestID"); UserDefaults.standard.removeObject(forKey: "pendingEarnCompletion"); syncWatcher()
        if let old { Task { let _: EmptyResponse? = try? await request(["action": "disconnect", "id": old.id], token: old.token) } }
    }
    struct EmptyResponse: Decodable {}
    func request<T: Decodable>(_ payload: [String: Any], token: String?, planCheck: Bool = false) async throws -> T {
        var req = URLRequest(url: planCheck ? URL(string: "https://app.undercoveriris.io/api/companion-access")! : endpoint); req.httpMethod = "POST"; req.timeoutInterval = payload["action"] as? String == "complete" ? 5 : 20
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let token { req.setValue("Bearer " + token, forHTTPHeaderField: "Authorization") }
        req.httpBody = try JSONSerialization.data(withJSONObject: payload)
        let (data, response) = try await relaySession.data(for: req)
        guard data.count <= 700_000 else { throw ScanError.invalidEnvelope }
        guard let http = response as? HTTPURLResponse else { throw ScanError.commandFailed("IRIS could not reach the web app.") }
        if http.statusCode == 404, let token, connection?.token == token { connection = nil; connected = false; Keychain.remove("connection") }
        guard http.statusCode == 200 else {
            if planCheck, let body = try? JSONSerialization.jsonObject(with: data) as? [String: Any], let error = body["error"] as? String { throw ScanError.commandFailed(String(error.prefix(400))) }
            throw ScanError.commandFailed("IRIS could not sync with the web app. Your saved results and cleanup remain available.")
        }
        return try JSONDecoder().decode(T.self, from: data)
    }
    func publish() async {
        guard let c = connection else { return }
        // Coalesce progress updates so a slow request cannot overwrite newer scan results.
        guard !publishing else { publishAgain = true; return }
        publishing = true
        defer {
            publishing = false
            if publishAgain { publishAgain = false; Task { await publish() } }
        }
        do {
            var sharedReport = report
            if let initial = sharedReport, (try JSONEncoder().encode(initial)).count > 380_000 {
                sharedReport?.coverage.limitations.append("The web dashboard shows a shortened report. The complete review remains in the Mac app.")
                while let value = sharedReport, (try JSONEncoder().encode(value)).count > 380_000, !value.findings.isEmpty { sharedReport?.findings.removeLast() }
            }
            let state = SharedState(version: 1, status: busy ? "scanning" : problem == nil ? (report.map { ScanAssessment.needsAttention($0) ? "attention" : "complete" } ?? "ready") : "attention", message: message, report: sharedReport, updatedAt: Date().timeIntervalSince1970 * 1000, capabilities: ["keyboardCheck", "fullDiskAccess", "trustFindings", "findingAssessment", "accountScans", "changeMonitoring"], progress: progress, access: access, monitoring: watchState)
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
                        if Date().timeIntervalSince(self.lastAccessCheck) > 180 { try? await self.refreshAccess() }
                        self.syncWatcher()
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
                    } catch { self.syncWatcher() /* Saved review and cleanup remain available offline. */ }
                }
                try? await Task.sleep(nanoseconds: pause * 1_000_000_000)
            }
        }
    }
    func perform(_ command: DeviceCommand) {
        if command.action == "scan" { startScan(); return }
        if command.action == "keyboardCheck" { checkKeyboard(); return }
        if command.action == "fullDiskAccess" { NSApp.activate(ignoringOtherApps: true); openFullDiskAccess(); return }
        guard !busy, let report, command.reportId == report.id, let id = command.findingId, let finding = report.findings.first(where: { $0.id == id && !$0.resolved }) else { return }
        if command.action == "trust" || command.action == "untrust" { trust(finding, remove: command.action == "untrust"); return }
        guard command.action == finding.action.rawValue else { return }
        act(finding)
    }
    func act(_ finding: Finding) {
        guard !busy else { return }
        if finding.action == .settings, finding.category == KeyboardReview.category {
            message = "Turn off access for apps you do not trust in Input Monitoring. If the app is not listed, check Accessibility. Quit that app, then recheck keyboard access."
            openKeyboardSettings(); Task { await publish() }; return
        }
        guard let item = localItems[finding.id] else { return }
        if finding.action == .reveal { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: item.path)]); return }
        guard finding.action == .quarantine || finding.action == .disableStartup, let hash = item.sha256 else { return }
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert(); alert.messageText = finding.action == .disableStartup ? "Stop this item starting automatically?" : "Quarantine this file?"
        alert.informativeText = "\(finding.title)\n\nIRIS will move this file into a private quarantine and remove its execute permission. You can restore it in Quarantine.\n\n" + (LocalAssessment.shellFiles.contains(URL(fileURLWithPath: item.path).lastPathComponent) ? "Terminal settings or tools may stop loading in new sessions. Existing Terminal sessions keep running." : "Already-running processes may keep running. For startup items, IRIS also asks macOS to unload the selected user service.")
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
            if let index = report?.findings.firstIndex(where: { $0.id == finding.id }) { report?.findings[index].resolved = true; report?.findings[index].cleanupStatus = "quarantined" }
            message = "Item quarantined. You can restore it from the Mac app."; saveScan(); refreshReceipts(); Task { await publish() }
        } catch { problem = error.localizedDescription }
    }
    func restore(_ receipt: QuarantineReceipt) {
        let alert = NSAlert(); alert.messageText = "Restore this quarantined file?"; alert.informativeText = "Only restore files you trust. This puts the file back at its original location. Startup items may run again at your next login."
        alert.addButton(withTitle: "Restore file"); alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        do {
            try quarantineStore().restore(receipt); refreshReceipts()
            updateCleanup(receipt, status: "restored"); message = "File restored. It is back in your review; your other results and trusted choices are unchanged."
            Task { await publish() }
        }
        catch { problem = error.localizedDescription }
    }
    func reveal(_ finding: Finding) {
        guard let item = localItems[finding.id] else { return }
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: item.path)])
    }
    func deleteQuarantined(_ receipt: QuarantineReceipt) {
        guard !busy else { return }
        let alert = NSAlert(); alert.alertStyle = .warning
        alert.messageText = "Permanently delete this quarantined file?"
        alert.informativeText = URL(fileURLWithPath: receipt.originalPath).lastPathComponent + "\n\nThis deletes the quarantined copy. IRIS will no longer be able to restore it. This does not erase other copies or stop already-running processes."
        alert.addButton(withTitle: "Delete permanently"); alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        do { try quarantineStore().remove(receipt); refreshReceipts(); updateCleanup(receipt, status: "deleted"); message = "Quarantined file permanently deleted."; Task { await publish() } }
        catch { problem = error.localizedDescription }
    }
    private func updateCleanup(_ receipt: QuarantineReceipt, status: String) {
        guard var value = report else { return }
        for index in value.findings.indices where localItems[value.findings[index].id]?.path == receipt.originalPath {
            value.findings[index].resolved = status != "restored"
            value.findings[index].cleanupStatus = status
            if status == "restored" { value.findings[index].trusted = false }
        }
        report = value; saveScan()
    }
    func refreshAccess(action: String = "status", runId: String? = nil) async throws {
        guard let c = connection else { access = nil; throw ScanError.commandFailed("Connect your Mac to IRIS to start a scan.") }
        var payload: [String: Any] = ["action":action,"kind":"mac","id":c.id]
        if let runId { payload["runId"] = runId }
        let value: CompanionAccess = try await request(payload, token: c.token, planCheck: true)
        guard connection?.id == c.id, value.current else { throw ScanError.invalidEnvelope }
        access = value; lastAccessCheck = Date(); syncWatcher()
        if action == "status" { await syncEarnCompletion() }
    }
    private func syncEarnCompletion() async {
        guard let c = connection, let pending = UserDefaults.standard.dictionary(forKey: "pendingEarnCompletion") as? [String: String], pending["id"] == c.id, let runId = pending["runId"] else { return }
        do {
            let _: CompanionAccess = try await request(["action":"complete","kind":"mac","id":c.id,"runId":runId], token:c.token, planCheck:true)
            if connection?.id == c.id, UserDefaults.standard.dictionary(forKey: "pendingEarnCompletion")?["runId"] as? String == runId { UserDefaults.standard.removeObject(forKey: "pendingEarnCompletion") }
        } catch { /* The next account refresh retries; saved scan results remain available. */ }
    }
    func setMonitoring(_ enabled: Bool) {
        watchState.enabled = enabled; UserDefaults.standard.set(enabled, forKey: "proMonitoring")
        if enabled { Task { do { try await refreshAccess(); syncWatcher(); await publish() } catch { problem = error.localizedDescription; syncWatcher() } } }
        else { syncWatcher(); Task { await publish() } }
    }
    func syncWatcher() {
        guard watchState.enabled, connected, access?.current == true, access?.monitoring == true else {
            watcher?.stop(); watchTask?.cancel(); pendingPaths.removeAll()
            watchState.status = watchState.enabled ? "paused" : "off"
            watchState.message = watchState.enabled ? "Monitoring paused. Connect an active Pro account; IRIS resumes when it can verify access." : "Monitoring is off. Manual scans and saved cleanup actions are available with your plan."
            return
        }
        if watcher == nil { watcher = ChangeWatcher(changed: { [weak self] paths in self?.queueChanges(paths) }, gap: { [weak self] in
            self?.watchCoverageGap = true; self?.watchState.status = "partial"; self?.watchState.message = "Some file-change events were missed or a watched folder moved. Run a full scan to check current files."
            Task { await self?.publish() }
        }) }
        let running = watcher?.start() == true
        if running && (busy || watchState.status == "partial") { return }
        watchState.status = running ? "watching" : "unavailable"
        watchState.message = watchState.status == "watching" ? "Watching Downloads, Desktop and your user LaunchAgents folder while IRIS is running. Changes trigger local checks; execution is not blocked." : "macOS could not start file-change notifications. Reopen IRIS and check folder access."
    }
    func queueChanges(_ paths: [String]) {
        guard access?.current == true, access?.monitoring == true, watchState.enabled else { syncWatcher(); return }
        if paths.count + pendingPaths.count > 200 { watchCoverageGap = true; watchState.status = "partial"; watchState.message = "Many files changed at once. Some changes need a full scan." }
        for path in paths.prefix(200) where pendingPaths.count < 200 { pendingPaths.insert(path) }
        guard watchTask == nil, !pendingPaths.isEmpty else { return }
        watchTask = Task { [weak self] in
            defer { self?.watchTask = nil; if let self, !self.pendingPaths.isEmpty { self.queueChanges([]) } }
            try? await Task.sleep(nanoseconds: 5_000_000_000)
            guard let self, !Task.isCancelled else { return }
            while self.busy && !Task.isCancelled { try? await Task.sleep(nanoseconds: 2_000_000_000) }
            guard !Task.isCancelled, self.access?.current == true, self.access?.monitoring == true else { return }
            let paths = Array(self.pendingPaths); self.pendingPaths.removeAll()
            self.busy = true; self.watchState.status = "checking"; self.watchState.message = "Checking changed files locally…"
            self.engine.runner.resetCancellation()
            do {
                try await self.engine.prepare(progress: { _ in })
                let engine = self.engine
                let result = try await Task.detached { try engine.checkChanges(paths) }.value
                if !Task.isCancelled {
                    var value = self.report ?? ScanReport(scannedItems: 0, coverage: Coverage(), findings: [])
                    for finding in result.0 { value.findings.removeAll { $0.id == finding.id }; value.findings.append(finding) }
                    self.report = value; self.localItems.merge(result.1) { _, new in new }; self.applyTrust(); self.saveScan()
                    self.watchState.checkedAt = Date().timeIntervalSince1970 * 1000; self.watchState.filesChecked += result.2
                    self.watchState.matches += result.0.filter { $0.level == .threat }.count
                    if !result.0.isEmpty { self.message = "Monitoring found \(result.0.count) changed items to review."; NSApp.requestUserAttention(.informationalRequest) }
                    self.watchState.message = (self.watchCoverageGap || result.3) ? "Changed files checked with coverage gaps. Some files were inaccessible or outside the 100 MB / 200-file limits." : "Changed files checked. Watching for the next change."
                    self.watchState.status = (self.watchCoverageGap || result.3) ? "partial" : "watching"
                }
            } catch { self.watchState.status = "partial"; self.watchCoverageGap = true; self.watchState.message = "A background check could not finish. Check folder access and malware definitions, then run a scan." }
            self.busy = false; await self.publish()
        }
    }
}
