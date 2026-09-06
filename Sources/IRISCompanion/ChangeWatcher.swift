import Foundation
import CoreServices

/// Notifications trigger bounded checks. This does not intercept or block execution.
final class ChangeWatcher {
    private var stream: FSEventStreamRef?
    private let changed: ([String]) -> Void
    private let gap: () -> Void
    init(changed: @escaping ([String]) -> Void, gap: @escaping () -> Void) { self.changed = changed; self.gap = gap }
    func start() -> Bool {
        if stream != nil { return true }
        let paths = ["Downloads", "Desktop", "Library/LaunchAgents"].map { NSHomeDirectory() + "/" + $0 }
        var context = FSEventStreamContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(), retain: nil, release: nil, copyDescription: nil)
        let callback: FSEventStreamCallback = { _, info, count, raw, flags, _ in
            guard let info else { return }
            let owner = Unmanaged<ChangeWatcher>.fromOpaque(info).takeUnretainedValue()
            let paths = unsafeBitCast(raw, to: NSArray.self) as? [String] ?? []
            let gaps = FSEventStreamEventFlags(kFSEventStreamEventFlagMustScanSubDirs | kFSEventStreamEventFlagUserDropped | kFSEventStreamEventFlagKernelDropped | kFSEventStreamEventFlagRootChanged)
            if count > 500 || (0..<count).contains(where: { flags[$0] & gaps != 0 }) { owner.gap() }
            let selected = paths.prefix(min(count, 500)).enumerated().compactMap { index, path -> String? in
                guard flags[index] & FSEventStreamEventFlags(kFSEventStreamEventFlagItemIsFile) != 0 else { return nil }; return path
            }
            owner.changed(selected)
        }
        stream = FSEventStreamCreate(nil, callback, &context, paths as CFArray, FSEventStreamEventId(kFSEventStreamEventIdSinceNow), 2, FSEventStreamCreateFlags(kFSEventStreamCreateFlagUseCFTypes | kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagWatchRoot))
        guard let stream else { return false }
        FSEventStreamSetDispatchQueue(stream, DispatchQueue.main)
        guard FSEventStreamStart(stream) else { stop(); return false }; return true
    }
    func stop() { if let stream { FSEventStreamStop(stream); FSEventStreamInvalidate(stream); FSEventStreamRelease(stream) }; stream = nil }
    deinit { stop() }
}
