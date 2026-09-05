import SwiftUI
import AppKit
import IRISCore

@main struct IRISCompanionApp: App {
    @StateObject private var model = CompanionModel()
    var body: some Scene {
        WindowGroup("IRIS · Your Mac guardian") { GuardianView(model: model).onOpenURL { model.connect($0) } }
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
    private let violet = Color(red: 0.76, green: 0.64, blue: 1)
    var body: some View {
        HStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 24) {
                HStack { brandImage; Text("IRIS").font(.system(size: 30, weight: .bold, design: .rounded)) }
                Text("YOUR MAC GUARDIAN").font(.caption).tracking(2).foregroundStyle(.secondary)
                ForEach(["Review", "Quarantine", "About"], id: \.self) { value in Button { section = value } label: { Label(value, systemImage: value == "Review" ? "checkmark.shield" : value == "Quarantine" ? "archivebox" : "info.circle").frame(maxWidth: .infinity, alignment: .leading).padding(12).background(section == value ? violet.opacity(0.14) : .clear, in: RoundedRectangle(cornerRadius: 12)) }.buttonStyle(.plain) }
                Spacer()
                Text("powered by HANS Society").font(.caption).foregroundStyle(.secondary)
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
            Text(model.report == nil ? "Let's check your Mac." : "Your Mac, explained.").font(.system(size: 36, weight: .semibold, design: .rounded))
            Text(model.message).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            HStack {
                Button(model.busy ? "Scanning…" : "Scan my Mac", systemImage: "shield.checkered") { model.startScan() }.buttonStyle(.borderedProminent).controlSize(.large).disabled(model.busy)
                if model.busy { ProgressView().controlSize(.small); Button("Cancel") { model.cancelScan() } }
                Spacer()
                Label(model.connected ? "Web dashboard connected" : "Local mode", systemImage: model.connected ? "link" : "lock.shield").foregroundStyle(.secondary).font(.caption)
            }
            GroupBox {
                VStack(alignment: .leading, spacing: 8) {
                    Text("A more complete check").font(.headline)
                    Text("Allow Full Disk Access so IRIS can inspect protected startup locations. macOS requires you to approve this yourself. Your files stay on this Mac.").foregroundStyle(.secondary)
                    Button("Open Full Disk Access settings") { model.openFullDiskAccess() }
                }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
            }
            if let report = model.report {
                HStack(spacing: 14) {
                    metric("Threat matches", model.unresolved.filter { $0.level == .threat }.count, .orange)
                    metric("To review", model.unresolved.filter { $0.level == .review }.count, violet)
                    metric("Other items", model.unresolved.filter { $0.level == .information }.count, .secondary)
                }
                Text("Startup check: \(report.coverage.inventory) · Malware check: \(report.coverage.malware)").font(.caption).foregroundStyle(.secondary)
                ForEach(model.unresolved) { finding in
                    DisclosureGroup {
                        VStack(alignment: .leading, spacing: 10) {
                            Text(finding.explanation)
                            ForEach(finding.evidence, id: \.self) { Text($0).font(.caption).foregroundStyle(.secondary) }
                            Text(finding.location).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                            Button(finding.action == .quarantine ? "Quarantine file" : finding.action == .disableStartup ? "Disable startup item" : "Show in Finder") { model.act(finding) }.disabled(model.busy)
                        }.frame(maxWidth: .infinity, alignment: .leading).padding(.top, 8)
                    } label: { Label(finding.title, systemImage: finding.level == .threat ? "exclamationmark.shield" : "app.badge").foregroundStyle(finding.level == .threat ? .orange : .primary) }.padding().background(.white.opacity(0.035), in: RoundedRectangle(cornerRadius: 12))
                }
                DisclosureGroup("What this scan covers") { ForEach(report.coverage.limitations, id: \.self) { Text($0).font(.caption).foregroundStyle(.secondary).padding(.vertical, 4) } }
            } else {
                Text("IRIS checks software that starts automatically and uses maintained malware definitions to scan common download locations. Review findings before changing unfamiliar software.").foregroundStyle(.secondary)
                Text("First scan: scanner downloads and threat definitions may take a few minutes. Future scans reuse them.").font(.caption).foregroundStyle(.secondary)
            }
        }
    }
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
            Link("Known-threat scanning: ClamAV by Cisco Talos ↗", destination: URL(string: "https://www.clamav.net/")!)
            Text("These independent projects provide the scanning tools; they do not endorse IRIS. IRIS uses verified upstream releases. KnockKnock is downloaded unchanged; ClamAV is bundled with adjusted library paths and its source is supplied with each release. VirusTotal is not contacted.").foregroundStyle(.secondary)
            Link("Source code and licenses ↗", destination: URL(string: "https://github.com/byron0x/iris-mac-companion")!)
            Link("Privacy and connection details ↗", destination: URL(string: "https://app.undercoveriris.io/device-privacy")!)
            Link("Help: support@joinhans.io", destination: URL(string: "mailto:support@joinhans.io")!)
            if model.report != nil { Button("Remove saved review") { model.clearReview() }.disabled(model.busy) }
            if model.connected { Button("Disconnect web dashboard") { model.disconnect() } }
        }
    }
}
