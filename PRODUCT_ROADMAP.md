# One IRIS, fewer steps

Product direction agreed September 5, 2026: maximize meaningful security, privacy and OPSEC improvements per user action. The user should not have to understand the underlying tools or repeat setup to benefit from them.

## Experience rules

- One main check runs every installed, available on-demand check. Each engine does not get a separate setup wizard or mandatory scan button.
- Show the most actionable findings first; group repeated signals by application. Explain what was observed, why it matters and what the next action changes.
- Preserve reviews, connection state and completed actions across navigation. A focused recheck refreshes only that scope. Keep each check's time and coverage visible.
- Remember narrowly scoped choices when implemented, tied to verified software identity and relevant permissions; do not silently trust replacements at the same path.
- Request a macOS/browser permission when its feature needs it, explain the benefit once, and avoid repeating permission requests already granted.
- Prefer reversible disable/quarantine with a clear Undo. Never label every unfamiliar app, signature failure, permission or network request malware. Opening settings is not evidence of cleanup.
- No blanket “fix everything” that removes unfamiliar but legitimate software. Batch changes only after the user can review the exact supported changes and their impact.
- Existing access or download of the companion is not consent to capture keystrokes, microphone/camera recordings, clipboard contents, browsing history or wallet secrets.
- Existing review and local checks remain useful offline. A disconnected dashboard should show the last check's age, not reset the user to the beginning.

## Implemented in this development build

- IRIS avatar and Dock/app icon; official HANS Society icon and linked attribution matching the web brand.
- KnockKnock startup inventory, ClamAV known-threat checks and constrained reversible quarantine (existing).
- ReiKey-derived keyboard listener snapshot in the same scan. No keystrokes are recorded, no event tap is created, and no ReiKey installer or telemetry is bundled.
- Grouping by app, verified Apple running-code attribution, explicit unavailable/partial coverage, guided Input Monitoring/Accessibility review.
- Encrypted Mac-to-web findings; optional keyboard-only recheck preserves malware/startup findings and their date. Older reports still render.

This is development source, not a signed public download. Developer ID signing, notarization and a fresh-Mac release test remain required.

## Next delivery order

| Priority | User-facing feature | Source / implementation | Work still needed |
| --- | --- | --- | --- |
| 1 | Browser access review for Chrome, Brave and Edge | IRIS Manifest V3 extension using the browser management/permissions APIs; Objective-See does not supply a browser extension | Build extension, permission explanations, reversible disable/restore, stable store identity and authenticated connection. Validate each target browser. |
| 2 | Camera and microphone awareness | Evaluate OverSight, GPLv3 | Adapt monitoring and process attribution; verify supported macOS versions and permission behavior. Unknown process attribution must remain unknown. No audio/video capture. |
| 3 | New startup protection and fake-verification/paste defenses | Evaluate BlockBlock, GPLv3 | Apple Endpoint Security entitlement, signed privileged component, permission onboarding, rule identity and recovery. Paste protection needs separate Accessibility consent and a carefully bounded design. |
| 4 | App network privacy | Evaluate LuLu, GPLv3 | IRIS-owned Network Extension/System Extension provisioning, filter approval, destination explanation, reversible rules and connectivity recovery. Must not strand a user offline. |

Ransomware-specific automatic blocking is deferred until false-positive handling and recovery have been established. Detection should never overpromise complete protection.

## How the three interfaces will work together

The Mac companion performs device checks and locally authorized cleanup. The browser extension understands extensions and browser-specific access. The web dashboard provides one prioritized review and routes actions to the component that can perform them. Users should not need three separate accounts or three duplicate dashboards.

First browser milestone: review installed extensions and their granted permissions locally. Request only the permissions needed for that function; do not request blanket page access or browsing history for an extension audit. Browser-restricted actions must remain in an extension-owned trusted UI. Turning off extensions can affect password managers or wallets, so show the exact extension and provide undo rather than silently disabling security tools.

Connect the extension to the Mac through the documented native-messaging host with exact, store-issued extension IDs and an explicit initial connection. Install only the host registrations needed for browsers the user selects. No wildcard extension origins, arbitrary shell commands or unauthenticated local HTTP bridge. The existing web relay can carry typed, authenticated encrypted reports after device/source scoping is designed and tested. Do not treat every browser extension as a trusted Mac client.

Keep the first connected report in the existing Device section, grouped into Mac and Browser. Add a separate module only when it creates a clearer user task, not merely because another engine was integrated.

## Upstream references

- ReiKey and scope: https://objective-see.org/products/reikey.html
- OverSight and attribution limitations: https://objective-see.org/products/oversight.html
- BlockBlock and required privileges: https://objective-see.org/products/blockblock.html
- LuLu and network-filter approval: https://objective-see.org/products/lulu.html
- Apple Endpoint Security entitlement: https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client
- Chromium management API: https://developer.chrome.com/docs/extensions/reference/api/management
- Chromium native messaging: https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging

For every integrated upstream component, retain notices, identify modifications and publish the complete required corresponding source for the exact distributed build. Attribution is not a substitute for license compliance. Evaluate API/feed terms separately; no VirusTotal public-API integration is included.
