# IRIS — Your browser guardian companion

A Manifest V3 companion for Chrome, Brave and Edge. It provides one local extension-access review, conservative permission explanations, remembered Keep choices and reversible disable/restore. The web app displays the same review after a one-time optional connection. The Mac app is not required for browser checks.

**Version 0.1.0 is published in the Chrome Web Store.** [Install the browser guardian companion](https://chromewebstore.google.com/detail/aeamoplfjgalmokafhkcapgpbofinmfg), then connect it from [IRIS Device & browser](https://app.undercoveriris.io/device). Developer mode is only for contributors.

The September 6, 2026 release was downloaded from Google's distribution service and matched against the submitted package. Its Chromium integration test passed for local review, saved choices, disable/restore, website connection and disconnection. Browser-specific confirmation behavior should still be checked on Chrome, Brave and Edge when updating the release.

## What works

- Installation opens the review automatically. The toolbar icon opens it again.
- Broad website access, clipboard, history, cookies, debugger, proxy, native messaging and other relevant permissions are explained without declaring an extension malware.
- Keep choices last 30 days and are bound to the exact reported extension version and permissions. Turn off runs inside the extension-owned page with a real user gesture. The browser can add its own confirmation.
- Restore is offered only for an IRIS-recorded disable with unchanged version/access, when browser policy permits it. Permission increases and managed extensions are sent to browser settings.
- Reports exclude IRIS itself and themes, have size limits and identify partial coverage. No page scripts, browsing history or file contents are scanned.
- No accounts, external dependencies, content scripts, host permissions, telemetry or server-side inventory storage.

## Web connection and trust

The optional 30-day connection permits only `https://app.undercoveriris.io` to request status and a sanitized extension report. Sharing remains local to this browser profile; the report is not attached to an IRIS account or uploaded to the Mac relay. The endpoint rejects other extensions, frames, incognito contexts, arbitrary URLs, and enable/disable commands. Report disclosure revalidates sharing after its asynchronous audit. Web requests may open the companion's trusted review page, where the user makes changes.

The website itself must be trusted: once connected, JavaScript served by that exact origin can read the report. The connection can be revoked in either interface. This is not end-to-end encryption to a server; data crosses directly from the extension to its authorized website in the same browser. Mac-to-browser native messaging is planned separately and is not enabled by this build.

## Permissions

- `management`: read extension metadata and perform the user's explicit changes inside the companion.
- `storage`: remember scoped review decisions, supported undo state and the optional expiring connection.

No `tabs`, `history`, clipboard, page-reading or network host permission is requested. Creating a tab does not require reading tab contents.

## Development and testing

Use a fresh test profile and load this directory unpacked for development only. `manifest.json` has a public development key so automated tests have a stable ID; it is not a store signing key.

```sh
node --test browser-extension/tests/*.test.mjs
python3 browser-extension/package.py
```

The web repository contains a real Chromium integration test. Set `IRIS_BROWSER_SOURCE` to this directory and run `node tests/browser-companion.e2e.cjs` there. It installs only IRIS and a harmless fixture in a temporary profile, uses mocked web responses, and does not touch the developer's own extensions or data. Production runtime has no npm dependencies.

## Store submission

1. Register a Chrome Web Store developer account and complete publisher verification using accurate details. The publisher makes the trader/non-trader declaration.
2. Upload `dist/IRIS-Browser-Companion-0.1.0.zip` as a new item. The packaging allowlist excludes tests and the development key.
3. Preserve the existing store listing and extension ID when uploading updates. `store/release.json` records its ID and public key. Production `IRIS_BROWSER_EXTENSION_ID` must match that ID; the unpacked development build intentionally uses a separate test identity.
4. Supply screenshots, a single-purpose description and permission justifications. Privacy URL: `https://app.undercoveriris.io/device-privacy`. Describe the optional direct website disclosure accurately in the store privacy questionnaire; do not claim data never leaves the extension context.
5. Verify a store-distributed build on Chrome, Brave and Edge, including native permission confirmations, restore and web connection. Then publish the listing and set `IRIS_BROWSER_STORE_URL` to the approved installable Chrome Web Store URL. Apple enrollment is unrelated to this release.

Single purpose: help users review and reduce access held by their installed browser extensions. No wallet transaction inspection, phishing detection, browsing surveillance, or device malware scanning is claimed for this release.

Copyright © 2026 HANS Society Foundation. GPL-3.0-only; the full license is included. This browser code is an IRIS implementation using Chromium APIs. Objective-See attribution remains attached to the Mac components derived from their projects; Objective-See did not supply or endorse this extension.
