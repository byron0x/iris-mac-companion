# IRIS — Your browser guardian companion

Manifest V3 companion for Chrome, Brave and Edge. Version 0.1.0 is published at https://chromewebstore.google.com/detail/aeamoplfjgalmokafhkcapgpbofinmfg. Version 0.2.0 is the new release candidate; it requires a store update and review before these new features reach installed users.

## Browser security in one place

- Review extension access, keep recognized tools, and disable/restore supported extensions. Keep choices expire after 30 days or a version/permission change. Permissions are not malware verdicts.
- Opt into extension-change monitoring: browser events update a toolbar review-count badge even when the review page is closed.
- Opt into known-scam protection: declarative rules block top-level navigation to listed hostnames and their subdomains before the network request. A local warning offers dashboard, Mac-scan and wallet-approval follow-ups. Up to 100 already-open tabs are checked when enabling protection; these events are labeled already-open, not blocked-before-load.
- Link checks and optional recent-history checks run locally. History checks inspect up to 5,000 entries from seven days, only on a user click; only matched hostnames are saved locally. This is not transaction simulation or proof that a wallet was compromised.
- ScamSniffer's GPLv3 public database ships as a pinned snapshot. Protection updates it daily from the fixed public GitHub URL. The source has a seven-day delay. Updates are bounded, validated domain data, never executable code. Update failures keep installed protection and show a warning. Source metadata and license are in `data/`.

## Permissions and data

Required: management (extension review and explicit changes), storage (preferences, undo, consent and bounded reports), declarativeNetRequest (local blocking), alarms (daily database refresh). Optional: history (on-demand recent review), webNavigation (warning-page handoff and already-open tab review when protection is enabled). No page-content, clipboard, wallet-secret, native-messaging or broad host permissions.

Normal navigation URLs are processed transiently by navigation events and are not saved. Scam warning activity retains only hostnames, time and blocked/already-open status, at most 100 records for 30 days. Recent-history results expire after seven days. Expired records are pruned when the companion runs. Clear controls remove them immediately. No browsing URL is sent to the feed provider. GitHub sees normal request metadata for daily downloads.

An optional 30-day connection allows only top-level https://app.undercoveriris.io to display the extension report directly in this browser profile. Protection's consent explains sharing warning hostnames and times. Recent-history sharing includes aggregate counts/date only. The report is not uploaded to the Mac relay or attached to an IRIS account. Other origins, frames, incognito, extensions and web-requested mutations are rejected. Consent is rechecked after asynchronous work. The Mac uses its separate encrypted pairing; direct native messaging and cross-profile browser-report synchronization are not implemented.

## Build and verification

Use a fresh test profile and load this folder unpacked. Its public development key is separate from the published extension ID; the packager strips it.

```sh
node --test browser-extension/tests/*.test.mjs
python3 browser-extension/package.py
```

The web repository's `tests/browser-companion.e2e.cjs` tests the real Chromium extension and a harmless fixture, with production traffic blocked. Release checks also exercise optional history in an isolated profile and verify the complete phishing block → warning → activity → opt-out flow against a local HTTP server. Never use a developer's browsing history or visit live scam sites for tests.

Upload `dist/IRIS-Browser-Companion-0.2.0.zip` to the existing store item, update permissions/privacy disclosures and screenshots, and complete review. Keep `store/release.json` at the actually published version until Google serves the new package. The install link and extension ID remain unchanged.

Copyright © 2026 HANS Society Foundation. GPL-3.0-only. ScamSniffer provides the GPLv3 threat data; Objective-See provides the attributed Mac components. Neither independently endorses IRIS. Support: support@joinhans.io.
