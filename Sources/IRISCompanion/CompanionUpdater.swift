import AppKit
import Combine
import Sparkle
import SwiftUI

/// Sparkle verifies the signed feed and update before extracting or installing it.
/// Preferences belong to Sparkle and persist across app launches.
@MainActor final class CompanionUpdater: NSObject, ObservableObject, SPUUpdaterDelegate {
    @Published private(set) var canCheck = false
    @Published private(set) var automaticChecks = false
    @Published private(set) var automaticDownloads = false
    @Published private(set) var lastCheck: Date?
    private var controller: SPUStandardUpdaterController!
    private weak var model: CompanionModel?
    private var scanObserver: AnyCancellable?
    private var pendingRelaunch: (() -> Void)?
    private var started = false

    init(model: CompanionModel) {
        self.model = model
        super.init()
        controller = SPUStandardUpdaterController(startingUpdater: false, updaterDelegate: self, userDriverDelegate: nil)
        let updater = controller.updater
        updater.publisher(for: \.canCheckForUpdates).assign(to: &$canCheck)
        updater.publisher(for: \.automaticallyChecksForUpdates).assign(to: &$automaticChecks)
        updater.publisher(for: \.automaticallyDownloadsUpdates).assign(to: &$automaticDownloads)
        updater.publisher(for: \.lastUpdateCheckDate).assign(to: &$lastCheck)
        scanObserver = model.$busy.dropFirst().sink { [weak self] busy in
            guard !busy else { return }
            // @Published emits before the property changes; finish the current save first.
            DispatchQueue.main.async { self?.resumePendingUpdate() }
        }
    }
    func start() {
        guard !started else { return }; started = true
        #if !DEBUG
        controller.startUpdater()
        #endif
    }
    func check() { controller.checkForUpdates(nil) }
    func setAutomaticChecks(_ enabled: Bool) { controller.updater.automaticallyChecksForUpdates = enabled }
    func setAutomaticDownloads(_ enabled: Bool) { controller.updater.automaticallyDownloadsUpdates = enabled }
    func updater(_ updater: SPUUpdater, shouldPostponeRelaunchForUpdate item: SUAppcastItem, untilInvokingBlock installHandler: @escaping () -> Void) -> Bool {
        guard model?.busy == true else { return false }
        pendingRelaunch = installHandler
        return true
    }
    private func resumePendingUpdate() {
        guard model?.busy != true, let resume = pendingRelaunch else { return }
        pendingRelaunch = nil; resume()
    }
    var version: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "Development" }
}

struct CompanionUpdateSettings: View {
    @ObservedObject var updater: CompanionUpdater
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Label("Keep your guardian up to date", systemImage: "arrow.triangle.2.circlepath").font(.headline)
                Spacer()
                Text("Version \(updater.version)").font(.caption).foregroundStyle(.secondary)
            }
            Button("Check for Updates…") { updater.check() }.disabled(!updater.canCheck)
            Toggle("Check for updates automatically", isOn: Binding(get: { updater.automaticChecks }, set: updater.setAutomaticChecks))
            Toggle("Download updates automatically", isOn: Binding(get: { updater.automaticDownloads }, set: updater.setAutomaticDownloads)).disabled(!updater.automaticChecks)
            Text("Updates are verified before installation. IRIS waits for an active scan to finish before restarting. Update checks contact GitHub; your scan results are not included.").font(.caption).foregroundStyle(.secondary)
            if let date = updater.lastCheck { Text("Last checked \(date.formatted(date: .abbreviated, time: .shortened))").font(.caption).foregroundStyle(.secondary) }
        }.padding(20).background(.white.opacity(0.04), in: RoundedRectangle(cornerRadius: 14))
    }
}
