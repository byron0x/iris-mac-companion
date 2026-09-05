// CoreGraphics enumeration adapted from ReiKey by Patrick Wardle / Objective-See.
// Copyright © 2018 Objective-See. Swift adaptation © 2026 HANS Society Foundation.
// GPL-3.0-only; see THIRD_PARTY_NOTICES.md. No event tap is installed by IRIS.
import AppKit
import CoreGraphics
import Security
import IRISCore

enum KeyboardScanner {
    static func check() -> KeyboardReview {
        // Bound allocation and report overflow as partial rather than silently returning clean.
        let capacity = 4096
        var taps = [CGEventTapInformation](repeating: CGEventTapInformation(), count: capacity)
        var count: UInt32 = 0
        let error = CGGetEventTapList(UInt32(capacity), &taps, &count)
        guard error == .success else { return KeyboardReview.make([], available: false) }
        var identities: [Int32: (String?, String?, Bool)] = [:]
        let listeners = taps.prefix(min(Int(count), capacity)).compactMap { tap -> KeyboardListener? in
            guard KeyboardReview.isKeyboardTap(enabled: tap.enabled, events: tap.eventsOfInterest) else { return nil }
            let pid = tap.tappingProcess
            if identities[pid] == nil {
                // PROC_PIDPATHINFO_MAXSIZE is (4 * MAXPATHLEN); Swift cannot import that macro.
                var pathBuffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
                let length = proc_pidpath(pid, &pathBuffer, UInt32(pathBuffer.count))
                let path = length > 0 ? String(cString: pathBuffer) : nil
                let app = NSRunningApplication(processIdentifier: pid)
                // Group helpers belonging to the same app, while verifying each running PID.
                identities[pid] = (app?.bundleURL?.path ?? path, app?.localizedName, isAppleProcess(pid))
            }
            let identity = identities[pid]!
            return KeyboardListener(processID: pid, path: identity.0, name: identity.1, appleSigned: identity.2, systemWide: tap.processBeingTapped == 0, canFilter: tap.options != .listenOnly)
        }
        return KeyboardReview.make(listeners, truncated: Int(count) >= capacity)
    }
    private static func isAppleProcess(_ pid: Int32) -> Bool {
        var code: SecCode?; var requirement: SecRequirement?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: NSNumber(value: pid)] as CFDictionary, [], &code) == errSecSuccess,
              let code, SecRequirementCreateWithString("anchor apple" as CFString, [], &requirement) == errSecSuccess,
              let requirement else { return false }
        return SecCodeCheckValidity(code, [], requirement) == errSecSuccess
    }
}
