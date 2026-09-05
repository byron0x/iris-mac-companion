// Keyboard event-tap filtering adapted from ReiKey's shared/EventTaps.m.
// Copyright © 2018 Objective-See / Patrick Wardle.
// Swift adaptation, grouping and review model © 2026 HANS Society Foundation.
// GPL-3.0-only. See THIRD_PARTY_NOTICES.md for the pinned upstream source.
import Foundation
import CoreGraphics

public struct KeyboardCoverage: Codable, Sendable {
    public var status: String
    public var checkedAt: String
    public var activeApps: Int
    public var limitations: [String]
}

public struct KeyboardListener: Sendable {
    public let processID: Int32
    public let path: String?
    public let name: String?
    public let appleSigned: Bool
    public let systemWide: Bool
    public let canFilter: Bool
    public init(processID: Int32, path: String?, name: String? = nil, appleSigned: Bool = false, systemWide: Bool = true, canFilter: Bool = false) {
        self.processID = processID; self.path = path; self.name = name; self.appleSigned = appleSigned
        self.systemWide = systemWide; self.canFilter = canFilter
    }
}

public struct KeyboardReview: Sendable {
    public static let category = "Keyboard privacy"
    public var coverage: KeyboardCoverage
    public var findings: [Finding]
    public static func isKeyboardTap(enabled: Bool, events: UInt64) -> Bool {
        let keyboardMask = (UInt64(1) << CGEventType.keyDown.rawValue) | (UInt64(1) << CGEventType.keyUp.rawValue)
        return enabled && events & keyboardMask != 0
    }
    public static func make(_ listeners: [KeyboardListener], available: Bool = true, truncated: Bool = false, now: Date = Date(), home: String = NSHomeDirectory()) -> KeyboardReview {
        var limits = ["A snapshot of active CoreGraphics keyboard listeners, not every way software can read keystrokes. IRIS does not record what you type.", "Accessibility tools, shortcuts and Apple features can legitimately listen to keyboard events. A listener is not a malware verdict."]
        if !available { limits.append("macOS could not provide the listener list. Try again; this does not mean no listeners are present.") }
        if truncated { limits.append("The listener list exceeded this check's limits. Some items are not shown.") }
        let groups = Dictionary(grouping: available ? listeners : []) { $0.path ?? "Unknown process \($0.processID)" }
        let findings = groups.keys.sorted().prefix(256).map { path -> Finding in
            let entries = groups[path]!
            let apple = entries.allSatisfy(\.appleSigned)
            let name = entries.first?.name ?? (path.hasPrefix("/") ? URL(fileURLWithPath: path).lastPathComponent : path)
            return Finding(path: path, title: String(name.prefix(180)), category: category, level: apple ? .information : .review,
                explanation: apple ? "This Apple-signed software has an active keyboard listener. macOS features can use this legitimately; review access if the behavior is unexpected." : "This software has an active keyboard listener. If you recognize it as a shortcut, accessibility or other tool you use, this may be expected. If you do not, quit the app and review its access in System Settings.",
                evidence: [entries.contains(where: \.systemWide) ? "Can receive keyboard events across applications" : "Listening for keyboard events in a specific process", entries.contains(where: \.canFilter) ? "Can filter or modify the events it receives" : "Listening without modifying events", apple ? "Apple code signature verified for the running process" : "Review whether this app needs keyboard access", "\(entries.count) active listener\(entries.count == 1 ? "" : "s") grouped into this item"], action: .settings, home: home)
        }
        if groups.count > 256 { limits.append("This review shows the first 256 applications with active listeners.") }
        let status = !available ? "unavailable" : truncated || groups.count > 256 ? "partial" : "checked"
        return KeyboardReview(coverage: KeyboardCoverage(status: status, checkedAt: ISO8601DateFormatter().string(from: now), activeApps: groups.count, limitations: limits), findings: findings)
    }
    // Refresh just this check without clearing startup/malware results or their original date.
    public func merging(into previous: ScanReport?) -> ScanReport {
        var result = previous ?? ScanReport(scannedItems: 0, coverage: Coverage(), findings: [])
        result.id = UUID().uuidString
        result.coverage.keyboard = coverage
        result.findings.removeAll { $0.category == Self.category }
        result.findings.append(contentsOf: findings)
        result.findings.sort {
            let priority: (Finding) -> Int = { $0.level == .threat ? 0 : $0.level == .review ? ($0.category == Self.category ? 1 : 2) : 3 }
            return priority($0) == priority($1) ? $0.title.localizedStandardCompare($1.title) == .orderedAscending : priority($0) < priority($1)
        }
        return result
    }
}
