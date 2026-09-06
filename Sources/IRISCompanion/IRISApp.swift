import SwiftUI
import AppKit
import IRISCore

@main struct IRISCompanionApp: App {
    @StateObject private var model = CompanionModel()
    var body: some Scene {
        WindowGroup("IRIS · Your Mac guardian companion") { GuardianView(model: model).onOpenURL { model.connect($0) } }
            .defaultSize(width: 1000, height: 780)
        MenuBarExtra("IRIS", systemImage: "shield.lefthalf.filled") {
            Button("Open IRIS") { NSApp.activate(ignoringOtherApps: true); NSApp.windows.first?.makeKeyAndOrderFront(nil) }
            Button("Scan my Mac") { model.startScan() }.disabled(model.busy)
            Button("Open web dashboard") { model.openWeb() }
            Divider()
            Button("Quit IRIS") { NSApp.terminate(nil) }
        }
    }
}
struct GuardianView: View {
    @ObservedObject var model: CompanionModel
    @State private var section = "Review"
    @State private var expandedFindings: [String: Bool] = [:]
    private let violet = Color(red: 0.76, green: 0.64, blue: 1)
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
            if !model.busy && (model.report?.coverage.inventory == "needsPermission" || model.report == nil || model.report?.coverage.inventory == "incomplete") { permissionSteps }
            if let report = model.report {
                scanCoverage(report)
                HStack(spacing: 14) {
                    metric("Threat matches", model.unresolved.filter { $0.level == .threat }.count, .orange)
                    metric("To review", model.unresolved.filter { $0.level == .review }.count, violet)
                    metric("Quarantined", report.findings.filter { $0.resolved }.count, .secondary)
                }
                let attention = model.unresolved.filter { $0.level != .information }
                if attention.isEmpty {
                    Label("No items flagged for cleanup in these results.", systemImage: "checkmark.circle").foregroundStyle(violet)
                    Text("This applies to the checks shown above. Any coverage gaps still need attention.").font(.caption).foregroundStyle(.secondary)
                } else { Text("Review these first").font(.title2).bold() }
                ForEach(attention) { findingCard($0) }
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
            Image(systemName: ScanAssessment.checked(status) ? "checkmark.circle.fill" : "exclamationmark.circle").foregroundStyle(ScanAssessment.checked(status) ? violet : .orange)
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
                Button(finding.action == .quarantine ? "Quarantine file" : finding.action == .disableStartup ? "Disable startup item" : finding.action == .settings ? "Review keyboard access" : "Show in Finder") { model.act(finding) }.disabled(model.busy)
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
            Text("Files here cannot run from their original location. They stay on your Mac so you can undo a change.").foregroundStyle(.secondary)
            if model.receipts.isEmpty { Label("No quarantined files", systemImage: "checkmark.shield").padding(.vertical, 30) }
            ForEach(model.receipts) { receipt in HStack { VStack(alignment: .leading) { Text(URL(fileURLWithPath: receipt.originalPath).lastPathComponent); Text(receipt.date, style: .date).font(.caption).foregroundStyle(.secondary) }; Spacer(); Button("Restore…") { model.restore(receipt) }.disabled(model.busy) }.padding().background(.white.opacity(0.035), in: RoundedRectangle(cornerRadius: 12)) }
        }
    }
    var about: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Built to be on your side.").font(.largeTitle)
            Text("IRIS Mac Companion is free, open-source software from HANS Society Foundation, licensed under GPLv3. Scanning happens locally. The web dashboard receives an encrypted report only after you connect it.")
            Link("Startup scanning: KnockKnock by Objective-See Foundation ↗", destination: URL(string: "https://objective-see.org/products/knockknock.html")!)
            Link("Keyboard privacy: adapted from ReiKey by Objective-See Foundation ↗", destination: URL(string: "https://objective-see.org/products/reikey.html")!)
            Link("Known-threat scanning: ClamAV by Cisco Talos ↗", destination: URL(string: "https://www.clamav.net/")!)
            Text("These independent projects do not endorse IRIS. KnockKnock is downloaded unchanged; ClamAV is bundled with adjusted library paths and its source is supplied with each release. IRIS adapts ReiKey's event-tap enumeration into a local, on-demand keyboard review. VirusTotal is not contacted.").foregroundStyle(.secondary)
            Link("Source code and licenses ↗", destination: URL(string: "https://github.com/byron0x/iris-mac-companion")!)
            Link("Privacy and connection details ↗", destination: URL(string: "https://app.undercoveriris.io/device-privacy")!)
            Link("Help: support@joinhans.io", destination: URL(string: "mailto:support@joinhans.io")!)
            if model.report != nil { Button("Remove saved review") { model.clearReview() }.disabled(model.busy) }
            if model.connected { Button("Disconnect web dashboard") { model.disconnect() } }
        }
    }
}
