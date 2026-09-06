import SwiftUI
import AppKit
import IRISCore
import Security

@MainActor final class CompanionDelegate: NSObject, NSApplicationDelegate {
    static var model: CompanionModel?
    static var showWindow: (() -> Void)?
    private var forwardingURLs = false
    static func existingInstance() -> NSRunningApplication? {
        guard let id = Bundle.main.bundleIdentifier else { return nil }
        let current = NSRunningApplication.current
        return NSRunningApplication.runningApplications(withBundleIdentifier: id)
            .filter { app in
                guard app.processIdentifier != getpid(), !app.isTerminated, samePublisher(app) else { return false }
                let earlier = app.launchDate ?? .distantFuture
                let ours = current.launchDate ?? .distantPast
                return earlier < ours || (earlier == ours && app.processIdentifier < getpid())
            }.min { lhs, rhs in
                let a = lhs.launchDate ?? .distantFuture, b = rhs.launchDate ?? .distantFuture
                return a == b ? lhs.processIdentifier < rhs.processIdentifier : a < b
            }
    }
    func applicationDidFinishLaunching(_ notification: Notification) {
        // Launch Services and an updater can reopen the app at the same time.
        // Allow the initial URL event to arrive before treating this as a plain reopen.
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { [weak self] in
            guard self?.forwardingURLs == false, let existing = Self.existingInstance(), let target = existing.bundleURL else { return }
            let configuration = NSWorkspace.OpenConfiguration(); configuration.createsNewApplicationInstance = false
            NSWorkspace.shared.openApplication(at: target, configuration: configuration) { _, error in
                DispatchQueue.main.async { if error == nil { NSApp.terminate(nil) } }
            }
        }
    }
    func application(_ application: NSApplication, open urls: [URL]) {
        // A signed release in Downloads can also be registered for the URL scheme.
        // Forward directly to the already running, same-team app; never broadcast pairing secrets.
        if let existing = Self.existingInstance(),
           let target = existing.bundleURL {
            forwardingURLs = true
            let configuration = NSWorkspace.OpenConfiguration(); configuration.createsNewApplicationInstance = false
            NSWorkspace.shared.open(urls, withApplicationAt: target, configuration: configuration) { _, error in
                DispatchQueue.main.async { if error == nil { NSApp.terminate(nil) } }
            }
            return
        }
        Self.showWindow?(); application.activate(ignoringOtherApps: true)
        for url in urls { Self.model?.connect(url) }
    }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        Self.showWindow?(); return true
    }
    private static func samePublisher(_ app: NSRunningApplication) -> Bool {
        var code: SecCode?, requirement: SecRequirement?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: app.processIdentifier] as CFDictionary, [], &code) == errSecSuccess, let code,
              SecRequirementCreateWithString("anchor apple generic and certificate leaf[subject.OU] = CDA39J55GH and identifier io.undercoveriris.companion" as CFString, [], &requirement) == errSecSuccess, let requirement else { return false }
        return SecCodeCheckValidity(code, [], requirement) == errSecSuccess
    }
}

@main struct IRISCompanionApp: App {
    @NSApplicationDelegateAdaptor(CompanionDelegate.self) private var delegate
    @StateObject private var model: CompanionModel
    @StateObject private var updater: CompanionUpdater
    private let secondary: Bool
    init() {
        if CommandLine.arguments.contains("--verify-review-fixtures") {
            do { try FindingInspector.verifyFixtures(); exit(0) }
            catch { print("Local review fixture verification failed."); exit(1) }
        }
        secondary = CompanionDelegate.existingInstance() != nil
        let value = CompanionModel(initialize: !secondary); _model = StateObject(wrappedValue: value); CompanionDelegate.model = value
        _updater = StateObject(wrappedValue: CompanionUpdater(model: value))
    }
    var body: some Scene {
        Window("IRIS · Your Mac guardian companion", id: "guardian") {
            if secondary { ProgressView("Opening your running IRIS companion…").padding(40) }
            else { GuardianView(model: model, updater: updater).onAppear { updater.start() } }
        }
            .defaultSize(width: 1000, height: 780)
            .commands {
                CommandGroup(after: .appInfo) {
                    Button("Check for Updates…") { updater.check() }.disabled(!updater.canCheck)
                }
            }
        MenuBarExtra("IRIS", systemImage: "shield.lefthalf.filled") {
            Button("Open IRIS") { CompanionDelegate.showWindow?(); NSApp.activate(ignoringOtherApps: true) }
            Button("Scan my Mac") { model.startScan() }.disabled(model.busy)
            Button("Open web dashboard") { model.openWeb() }
            Divider()
            Button("Check for Updates…") { updater.check() }.disabled(!updater.canCheck)
            Button("Quit IRIS") { NSApp.terminate(nil) }
        }
    }
}
struct GuardianView: View {
    @Environment(\.openWindow) private var openWindow
    @ObservedObject var model: CompanionModel
    @ObservedObject var updater: CompanionUpdater
    @State private var section = "Review"
    @State private var expandedFindings: [String: Bool] = [:]
    private let violet = Color(red: 0.78, green: 0.61, blue: 1)
    private let mint = Color(red: 0.59, green: 1, blue: 0.76)
    var body: some View {
        HStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 24) {
                HStack { brandImage; Text("IRIS").font(.system(size: 30, weight: .bold, design: .rounded)) }
                Text("YOUR MAC GUARDIAN COMPANION").font(.caption).tracking(2).foregroundStyle(.secondary)
                ForEach(["Review", "Quarantine", "About"], id: \.self) { value in Button { section = value } label: { Label(value, systemImage: value == "Review" ? "checkmark.shield" : value == "Quarantine" ? "archivebox" : "info.circle").frame(maxWidth: .infinity, alignment: .leading).padding(12).background(section == value ? violet.opacity(0.14) : .clear, in: RoundedRectangle(cornerRadius: 12)) }.buttonStyle(.plain) }
                Spacer()
                Link(destination: URL(string: "https://joinhans.io")!) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("powered by").font(.caption).foregroundStyle(.secondary)
                        HStack(spacing: 8) {
                            if let url = Bundle.main.url(forResource: "HANSIcon", withExtension: "png"), let icon = NSImage(contentsOf: url) {
                                Image(nsImage: icon).resizable().frame(width: 28, height: 28).accessibilityHidden(true)
                            }
                            Text("HANS Society").font(.system(size: 13, weight: .semibold)).foregroundStyle(.primary)
                        }
                    }
                }.buttonStyle(.plain).accessibilityLabel("Powered by HANS Society. Open HANS website")
                Button("Open web dashboard ↗") { model.openWeb() }.buttonStyle(.plain).foregroundStyle(violet)
            }.padding(24).frame(width: 220).background(Color(red: 0.065, green: 0.05, blue: 0.09))
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    if section == "About" { about }
                    else if section == "Quarantine" { quarantine }
                    else { review }
                    if let error = model.problem { Label(error, systemImage: "exclamationmark.circle").foregroundStyle(.orange).padding().frame(maxWidth: .infinity, alignment: .leading).background(.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 12)) }
                }.padding(32).frame(maxWidth: .infinity, alignment: .leading)
            }
        }.background(Color(red: 0.035, green: 0.025, blue: 0.06)).preferredColorScheme(.dark).tint(violet).frame(minWidth: 820, minHeight: 620)
            .onAppear { CompanionDelegate.showWindow = { openWindow(id: "guardian") } }
    }
    @ViewBuilder var brandImage: some View {
        if let url = Bundle.main.url(forResource: "IRISAvatar", withExtension: "jpg"), let icon = NSImage(contentsOf: url) {
            Image(nsImage: icon).resizable().scaledToFill().frame(width: 46, height: 46).clipShape(Circle())
        } else { Image(systemName: "shield.lefthalf.filled").font(.largeTitle).foregroundStyle(violet) }
    }
    var review: some View {
        VStack(alignment: .leading, spacing: 22) {
            Text("LESS EXPOSED. MORE IN CONTROL.").font(.caption).tracking(2).foregroundStyle(violet)
            Text(model.report == nil ? "Let's check your Mac." : "Your next step, made clear.").font(.system(size: 34, weight: .semibold, design: .rounded))
            Text(model.message).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            accessCard
            if model.keychainLocked {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Your saved IRIS review is locked").font(.headline)
                    Text("Unlock only IRIS’s own saved encryption keys. macOS may ask for your login password; IRIS does not receive it or request your other passwords.").font(.callout).foregroundStyle(.secondary)
                    Button("Unlock saved IRIS review") { model.unlockSavedReview() }
                }.padding().background(violet.opacity(0.1), in: RoundedRectangle(cornerRadius: 14))
            }
            HStack(spacing: 16) {
                Button { model.startScan() } label: {
                    Label(model.busy ? "Scanning your Mac…" : "Scan my Mac", systemImage: "shield.checkered")
                        .font(.system(size: 20, weight: .semibold)).frame(minWidth: 260, minHeight: 64)
                        .padding(.horizontal, 20).foregroundStyle(Color(red: 0.10, green: 0.05, blue: 0.17))
                        .background(violet, in: RoundedRectangle(cornerRadius: 14))
                }.buttonStyle(.plain).disabled(model.busy).opacity(model.busy ? 0.6 : 1)
                if model.busy { Button("Stop scan") { model.cancelScan() } }
                Spacer()
            }
            if let progress = model.progress { scanProgress(progress) }
            monitoringCard
            if !model.busy && (model.report?.coverage.inventory == "needsPermission" || model.report == nil || model.report?.coverage.inventory == "incomplete") { permissionSteps }
            if let report = model.report {
                scanCoverage(report)
                HStack(spacing: 14) {
                    metric("Threat matches", model.unresolved.filter { $0.level == .threat }.count, .orange)
                    metric("To review", model.unresolved.filter { $0.level == .review }.count, violet)
                    metric("Quarantined", model.receipts.count, .secondary)
                }
                let attention = model.unresolved.filter { $0.level != .information }
                if attention.isEmpty {
                    Label("No items flagged for cleanup in these results.", systemImage: "checkmark.circle").foregroundStyle(violet)
                    Text("This applies to the checks shown above. Any coverage gaps still need attention.").font(.caption).foregroundStyle(.secondary)
                } else { Text("Review these first").font(.title2).bold() }
                ForEach(attention) { findingCard($0) }
                if !model.trusted.isEmpty {
                    DisclosureGroup("Trusted by you · \(model.trusted.count)") {
                        Text("Your choices are saved on this Mac. Changed files or access return for review. Known-threat matches always stay visible.").font(.caption).foregroundStyle(.secondary)
                        ForEach(model.trusted) { finding in HStack { Label(finding.title, systemImage: "checkmark.seal").foregroundStyle(.green); Spacer(); Button("Review again") { model.trust(finding, remove: true) }.disabled(model.busy) }.padding(.vertical, 8) }
                    }
                }
                if let safeguards = report.coverage.safeguards { safeguardCards(safeguards) }
                DisclosureGroup("Other items · \(model.unresolved.filter { $0.level == .information }.count)") {
                    Text("Information only. These items were not flagged for cleanup.").font(.caption).foregroundStyle(.secondary)
                    ForEach(model.unresolved.filter { $0.level == .information }) { findingCard($0) }
                }
                if let keyboard = report.coverage.keyboard { DisclosureGroup("Keyboard check details") { keyboardCard(keyboard) } }
                DisclosureGroup("Scan coverage & limitations") { ForEach(report.coverage.limitations, id: \.self) { Text($0).font(.caption).foregroundStyle(.secondary).padding(.vertical, 4) } }
            } else {
                Text("One scan checks startup software, keyboard access, Mac protections and accessible files in Downloads and Desktop. First-time setup may take a few minutes.").foregroundStyle(.secondary)
            }
            HStack {
                Label(model.connected ? "Connected to your web dashboard" : "Next: connect your web dashboard", systemImage: model.connected ? "checkmark.circle.fill" : "link").foregroundStyle(violet)
                Spacer()
                Button(model.connected ? "Open dashboard ↗" : "Connect companions ↗") { model.openWeb() }
            }.padding().background(violet.opacity(0.08), in: RoundedRectangle(cornerRadius: 14))
        }
    }
    func scanProgress(_ progress: ScanProgress) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack { Text("Step \(progress.step) of \(progress.total)").font(.headline); Spacer(); ProgressView().controlSize(.small) }
            ProgressView(value: Double(progress.step - 1), total: Double(progress.total)).accessibilityLabel("Scan steps completed")
            Text(progress.message).font(.headline)
            if let checked = progress.filesChecked, let total = progress.filesTotal {
                ProgressView(value: Double(checked), total: Double(max(1, total))).accessibilityLabel("Files checked")
                Text("\(checked) of \(total) selected files checked").font(.caption).monospacedDigit()
            }
            Text("You can leave this window open. Results will appear here and in your connected dashboard.").font(.caption).foregroundStyle(.secondary)
        }.padding(20).background(violet.opacity(0.1), in: RoundedRectangle(cornerRadius: 16))
    }
    var accessCard: some View {
        HStack(alignment: .center, spacing: 12) {
            Image(systemName: "person.crop.circle.badge.checkmark").foregroundStyle(mint)
            VStack(alignment: .leading, spacing: 4) {
                Text(model.access?.unlimited == true ? "IRIS Pro · Unlimited scans" : "IRIS Free · One Mac scan per month").font(.headline)
                Text(!model.connected ? "Connect once with Google or a wallet to start. Your files stay local." : model.access?.unlimited == true ? "Your account includes background monitoring and no IRIS revoke fees." : model.access?.remaining == 0 ? "Monthly scan used. Incomplete scans can be retried within 24 hours. Cleanup stays available." : "Your account allowance is checked when you start a scan.").font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if !model.connected { Button("Connect account ↗") { model.openWeb() } }
            else if model.access?.unlimited != true { Link("Get Pro ↗", destination: URL(string: "https://app.undercoveriris.io/upgrade")!) }
        }.padding(16).background(violet.opacity(0.09), in: RoundedRectangle(cornerRadius: 14))
    }
    var monitoringCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack { Label("Keep watch with IRIS Pro", systemImage: "waveform.path.ecg").font(.headline); Spacer(); Toggle("Monitor changes", isOn: Binding(get: { model.watchState.enabled }, set: model.setMonitoring)).labelsHidden().accessibilityLabel("Monitor downloads and startup changes") }
            Text(model.watchState.message).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if let checked = model.watchState.checkedAt {
                Text("\(model.watchState.filesChecked) changed files checked · \(model.watchState.matches) threat matches · Last check \(Date(timeIntervalSince1970: checked / 1000).formatted(date: .omitted, time: .shortened))").font(.caption).foregroundStyle(mint)
            }
            Text("Keep IRIS open in the menu bar. Monitoring needs current malware definitions and a connected Pro account; it does not inspect every folder or block a file from running.").font(.caption).foregroundStyle(.secondary)
        }.padding(18).background(mint.opacity(0.045), in: RoundedRectangle(cornerRadius: 14)).overlay(RoundedRectangle(cornerRadius: 14).stroke(mint.opacity(0.2)))
    }
    var permissionSteps: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Unlock the startup check", systemImage: "lock.open").font(.title2).bold()
            Text("macOS asks you to allow Full Disk Access. IRIS uses it to inspect protected startup locations; your files stay on your Mac.").foregroundStyle(.secondary)
            HStack(spacing: 16) {
                Image(nsImage: NSWorkspace.shared.icon(forFile: model.appURL.path)).resizable().frame(width: 72, height: 72)
                    .onDrag { NSItemProvider(object: model.appURL as NSURL) }
                    .accessibilityLabel("IRIS app. Drag into Full Disk Access settings; Show IRIS in Finder is an alternative.")
                VStack(alignment: .leading, spacing: 6) {
                    Text("1. Here is your IRIS app").font(.headline)
                    Text("Drag this icon into the Full Disk Access list.").font(.callout)
                    Button("Show IRIS in Finder") { model.showAppInFinder() }
                }
            }
            if !model.installedInApplications {
                Text("IRIS is running outside Applications. For a permanent home, use Show IRIS in Finder, drag the app to Applications, then open that copy before granting access.").font(.caption).foregroundStyle(.secondary)
            }
            Text("2. Add IRIS and switch it on").font(.headline)
            Button("Open Full Disk Access settings ↗") { model.openFullDiskAccess() }.controlSize(.large)
            Text("If dragging is unavailable, click + in Settings and select the app shown in Finder. Enter your Mac password if macOS asks.").font(.caption).foregroundStyle(.secondary)
            Text("3. Reopen IRIS, then scan").font(.headline)
            Button("Reopen IRIS to apply access") { model.reopenForPermissions() }.disabled(model.busy)
            Text("IRIS confirms access when the startup scanner runs successfully. You only need to grant it once for this installed copy.").font(.caption).foregroundStyle(.secondary)
        }.padding(20).background(violet.opacity(0.07), in: RoundedRectangle(cornerRadius: 16))
    }
    func scanCoverage(_ report: ScanReport) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(model.busy ? "Previous scan results" : "What your scan completed").font(.title2).bold()
            checkRow("Startup software", status: report.coverage.inventory)
            checkRow("Known-threat check", status: report.coverage.malware)
            if let count = report.coverage.filesChecked { Text("\(count) files checked · \(report.scannedItems) startup entries reviewed").font(.caption).foregroundStyle(.secondary) }
            checkRow("Keyboard privacy", status: report.coverage.keyboard?.status ?? "notStarted")
            if report.coverage.malware == "partial" {
                Text((report.coverage.inaccessibleLocations ?? 0) > 0 ? "Next: enable folder access, reopen IRIS and retry. Large files and items outside the quick scan’s limits will still be skipped." : "Some files exceeded the quick scan’s limits or could not be checked. See coverage below. Scanning again does not remove these limits.").font(.callout).foregroundStyle(.orange)
            }
            Text("Last scan: \(ISO8601DateFormatter().date(from: report.createdAt)?.formatted(date: .abbreviated, time: .shortened) ?? "previous scan")").font(.caption).foregroundStyle(.secondary)
        }.padding(20).background(.white.opacity(0.035), in: RoundedRectangle(cornerRadius: 16))
    }
    func checkRow(_ name: String, status: String) -> some View {
        HStack {
            Image(systemName: ScanAssessment.checked(status) ? "checkmark.circle.fill" : "exclamationmark.circle").foregroundStyle(ScanAssessment.checked(status) ? mint : .orange)
            Text(name); Spacer()
            Text(status == "needsPermission" ? "Needs Full Disk Access" : coverageLabel(status)).font(.caption).foregroundStyle(.secondary)
        }
    }
    func safeguardCards(_ checks: [Safeguard]) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Your Mac’s built-in protections").font(.title2).bold()
            ForEach(checks) { check in
                HStack(alignment: .top) {
                    Image(systemName: check.status == "enabled" ? "checkmark.shield.fill" : "shield").foregroundStyle(check.status == "enabled" ? violet : .orange)
                    VStack(alignment: .leading, spacing: 5) {
                        Text(check.title + " · " + (check.status == "enabled" ? "On" : check.status == "disabled" ? "Off" : "Could not verify")).font(.headline)
                        Text(check.detail).font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    if check.status != "enabled" { Button("Open settings ↗") { model.openSafeguard(check.id) } }
                }
            }
            Text("After changing a setting, scan again to confirm. IRIS never changes these protections automatically.").font(.caption).foregroundStyle(.secondary)
        }.padding(20).background(.white.opacity(0.035), in: RoundedRectangle(cornerRadius: 16))
    }
    func findingCard(_ finding: Finding) -> some View {
        DisclosureGroup(isExpanded: Binding(get: { expandedFindings[finding.id] ?? (finding.level != .information) }, set: { expandedFindings[finding.id] = $0 })) {
            VStack(alignment: .leading, spacing: 10) {
                Text(finding.explanation).fixedSize(horizontal: false, vertical: true)
                if let assessment = finding.assessment {
                    VStack(alignment: .leading, spacing: 10) {
                        Label(assessment.verdict, systemImage: finding.level == .threat ? "exclamationmark.shield.fill" : "info.circle.fill").font(.headline).foregroundStyle(assessment.verdict == "Investigate before trusting" || finding.level == .threat ? .orange : mint)
                        Text(assessment.summary).font(.callout).fixedSize(horizontal: false, vertical: true)
                        ForEach(assessment.signals, id: \.self) { Text("• " + $0).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true) }
                        Text("Your next step").font(.subheadline).bold()
                        Text(assessment.nextStep).font(.callout).fixedSize(horizontal: false, vertical: true)
                    }.padding(14).background(violet.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
                }
                if finding.canTrust == true {
                    Button { model.trust(finding) } label: { Label("I trust this item", systemImage: "checkmark.seal") }.disabled(model.busy)
                    Text("Remember this version. Changes bring it back for review.").font(.caption).foregroundStyle(.secondary)
                }
                Button(finding.action == .quarantine ? "Quarantine file" : finding.action == .disableStartup ? "Disable startup item" : finding.action == .settings ? "Review keyboard access" : "Show in Finder") { model.act(finding) }.disabled(model.busy)
                if finding.action != .reveal { Button("Show file location") { model.reveal(finding) }.disabled(model.busy) }
                DisclosureGroup("Why this appeared") {
                    ForEach(finding.evidence, id: \.self) { Text($0).font(.caption).foregroundStyle(.secondary) }
                    Text(finding.location).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                }
            }.frame(maxWidth: .infinity, alignment: .leading).padding(.top, 8)
        } label: { Label(finding.title, systemImage: finding.level == .threat ? "exclamationmark.shield" : "app.badge").foregroundStyle(finding.level == .threat ? .orange : .primary) }.padding().background(.white.opacity(0.035), in: RoundedRectangle(cornerRadius: 12))
    }
    func keyboardCard(_ coverage: KeyboardCoverage) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Keyboard privacy", systemImage: "keyboard").font(.headline)
            Text(coverage.status == "unavailable" ? "This check could not finish. Try again." : coverage.activeApps == 0 && coverage.status == "checked" ? "No active keyboard listeners found in this check." : "\(coverage.activeApps) app\(coverage.activeApps == 1 ? " has" : "s have") active keyboard listeners\(coverage.status == "partial" ? " in this partial check" : "").")
            Text("Shortcut and accessibility apps can need this access. Review anything you do not recognize below. IRIS never records what you type.").font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            HStack {
                Button("Recheck keyboard access") { model.checkKeyboard() }.disabled(model.busy)
                Button("Accessibility settings") { model.openAccessibilitySettings() }
            }
            Text("Updated \(ISO8601DateFormatter().date(from: coverage.checkedAt)?.formatted(date: .abbreviated, time: .shortened) ?? "recently")\(coverage.status == "partial" ? " · Partial check" : "")").font(.caption2).foregroundStyle(.secondary)
            DisclosureGroup("What this check covers") { ForEach(coverage.limitations, id: \.self) { Text($0).font(.caption).foregroundStyle(.secondary).padding(.vertical, 4) } }
        }.padding().frame(maxWidth: .infinity, alignment: .leading).background(violet.opacity(0.07), in: RoundedRectangle(cornerRadius: 12))
    }
    func coverageLabel(_ value: String) -> String { value == "notStarted" ? "Not checked yet" : value == "complete" ? "Checked" : value.capitalized }
    func metric(_ title: String, _ count: Int, _ color: Color) -> some View { VStack(alignment: .leading) { Text("\(count)").font(.largeTitle).foregroundStyle(color); Text(title).font(.caption) }.frame(maxWidth: .infinity, alignment: .leading).padding().background(.white.opacity(0.035), in: RoundedRectangle(cornerRadius: 12)) }
    var quarantine: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("Quarantine").font(.largeTitle)
            Text("Files here have been moved away from their original location and their execute permission removed. Already-running processes are not necessarily stopped. Restore a trusted file, or permanently delete a file you no longer want.").foregroundStyle(.secondary)
            if model.receipts.isEmpty { Label("No quarantined files", systemImage: "checkmark.shield").padding(.vertical, 30) }
            ForEach(model.receipts) { receipt in VStack(alignment: .leading, spacing: 12) {
                Label(URL(fileURLWithPath: receipt.originalPath).lastPathComponent, systemImage: "archivebox.fill").font(.headline).foregroundStyle(mint)
                Text(receipt.originalPath.replacingOccurrences(of: NSHomeDirectory(), with: "~")).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                Text(receipt.date, style: .date).font(.caption).foregroundStyle(.secondary)
                HStack { Button("Restore…") { model.restore(receipt) }.disabled(model.busy); Button("Delete permanently…", role: .destructive) { model.deleteQuarantined(receipt) }.disabled(model.busy) }
            }.padding().frame(maxWidth: .infinity, alignment: .leading).background(.white.opacity(0.035), in: RoundedRectangle(cornerRadius: 12)) }
        }
    }
    var about: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Built to be on your side.").font(.largeTitle)
            CompanionUpdateSettings(updater: updater)
            Text("IRIS Mac Companion is open-source software from HANS Society Foundation, licensed under GPLv3. Official IRIS accounts include one monthly Mac scan on Free, or unlimited scans and change monitoring on Pro. Scanning happens locally. Your connected web dashboard receives an encrypted report.")
            Link("Startup scanning: KnockKnock by Objective-See Foundation ↗", destination: URL(string: "https://objective-see.org/products/knockknock.html")!)
            Link("Keyboard privacy: adapted from ReiKey by Objective-See Foundation ↗", destination: URL(string: "https://objective-see.org/products/reikey.html")!)
            Link("Known-threat scanning: ClamAV by Cisco Talos ↗", destination: URL(string: "https://www.clamav.net/")!)
            Text("These independent projects do not endorse IRIS. KnockKnock is downloaded unchanged; ClamAV is bundled with adjusted library paths and its source is supplied with each release. IRIS adapts ReiKey's event-tap enumeration into a local, on-demand keyboard review. VirusTotal is not contacted.").foregroundStyle(.secondary)
            Link("Verified app updates: Sparkle ↗", destination: URL(string: "https://sparkle-project.org/")!)
            Link("Source code and licenses ↗", destination: URL(string: "https://github.com/byron0x/iris-mac-companion")!)
            Link("Privacy and connection details ↗", destination: URL(string: "https://app.undercoveriris.io/device-privacy")!)
            Link("Help: support@joinhans.io", destination: URL(string: "mailto:support@joinhans.io")!)
            if model.report != nil { Button("Remove saved review") { model.clearReview() }.disabled(model.busy) }
            Button("Forget all trusted-item choices") { model.clearTrust() }.disabled(model.busy)
            if model.connected { Button("Disconnect web dashboard") { model.disconnect() } }
        }
    }
}
