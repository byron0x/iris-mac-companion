# IRIS Mac Companion

A free, open-source Mac companion for IRIS by HANS Society Foundation. It helps people understand startup software, check common download locations against malware signatures and perform supported, reversible cleanup. Dark purple SwiftUI interface; macOS 13+; Apple silicon and Intel.

**Development release. No signed public download is available yet.** Public distribution requires Developer ID Application signing, Apple notarization, and the release checks below.

## What works together

1. Run the app and choose **Scan my Mac**. It prepares the original, checksum- and signature-verified KnockKnock release and uses the ClamAV scanner included in the IRIS download. Malware definitions are downloaded on the first scan.
2. Grant Full Disk Access in System Settings for protected locations. Scans report limits instead of treating inaccessible files as safe.
3. Start a connection from the IRIS Device page and confirm the matching code on the Mac. The report appears in the web dashboard.
4. Review findings. File changes always require a native confirmation. User-owned regular files in Downloads, Desktop and user LaunchAgents can be quarantined and restored; other locations open in Finder for guided review.

KnockKnock inventories persistence; it does not label every listed program malware. ClamAV supplies maintained known-threat signatures. No VirusTotal requests or file uploads are made. This is an on-demand review, not continuous endpoint protection or a guarantee against infection.

## Build and test

Install a current, internally consistent Xcode toolchain (or matching Command Line Tools and Swift SDK).

```sh
swift run IRISCoreChecks
scripts/build-app.sh
open 'dist/IRIS Mac Companion.app'
```

The local app is ad-hoc signed and is for development only. Unit tests operate on generated temporary fixtures; they do not scan or clean the developer's personal files. Engine downloads are pinned in `EngineService.swift` and documented in `THIRD_PARTY_NOTICES.md`.

## Trusted public release

Enroll in the standard Apple Developer Program. Create a **Developer ID Application** certificate in the enrolled account and install its private key in the build machine's Keychain. Store notarization credentials with `xcrun notarytool store-credentials` using a dedicated Keychain profile. Do not commit credentials or share Apple account passwords.

```sh
export DEVELOPER_ID_APPLICATION='Developer ID Application: Your legal name (TEAMID)'
export NOTARY_KEYCHAIN_PROFILE='iris-notary'
scripts/release.sh
```

The script builds both architectures, signs with hardened runtime, submits to Apple's notary service, checks acceptance, staples the result and runs Gatekeeper assessment. Publish the resulting zip, checksum, `dist/clamav-1.5.4.tar.gz`, and the exact corresponding IRIS source under the same version tag. ClamAV is redistributed as a separate program with library paths adjusted by `prepare-clamav.py`; all original component notices and the corresponding source must accompany it. Test a freshly downloaded archive on a second Mac, including pairing, Full Disk Access, cancellation and restore, before enabling the web download. No user should need to disable Gatekeeper.

The web repository contains the separate relay and Device UI. Configure `IRIS_COMPANION_ENABLED=true` and a verified `IRIS_COMPANION_DOWNLOAD_URL` only after the signed release is ready. It uses the existing account-authenticated Redis service and `IDENTITY_PROTECTION_SECRET`; no new third-party API subscription is needed for this implementation.

## Security and privacy

- AES-256-GCM authenticates encrypted reports and typed commands, binding version, direction, UUID and timestamp as additional data. Browser and native CryptoKit use the same envelope.
- Pairing ticket: single use, five-minute TTL, tied to the account session that issued it. Verify the displayed code. Native credentials are stored in Keychain; browser key stays in that browser's local storage. IRIS servers do not receive the encryption key.
- Device connection: 30 days. Encrypted relay report: 24 hours since upload. Pending command: two minutes. Native command IDs are remembered to reject repeated execution.
- Server requests enforce account ownership and current account lineage. Native bearer credentials cannot be used through browser-origin requests. No shell or administrator helper accepts web instructions.
- Report contents can include personal file names despite home-prefix redaction. Local report is encrypted with a separate Keychain key. Quarantine directory is owner-only and files lose execution/read permissions. Paths, ownership, hard links, symlinks and content hashes are checked before moving files; restore refuses to overwrite replacements.
- Quarantine does not kill an arbitrary running process. User LaunchAgents are stopped before their plist is quarantined. Restoring a startup item can allow it to start again at login.
- The Mac polls more slowly when no dashboard is active. Network failures leave local scanning and existing local results available.

No background scanning starts on installation. See `THIRD_PARTY_NOTICES.md` for attribution, source links and release hashes. Help: support@joinhans.io.

## Removing the app

Restore any quarantined files you intend to keep, disconnect the web dashboard, quit IRIS and remove the application. The encrypted review and quarantine are in `~/Library/Application Support/IRIS Companion`; deleting that folder also permanently removes its quarantined copies. Keychain stores the connection credential and the local report key under `io.undercoveriris.companion`.

IRIS and HANS names and logos identify HANS Society's project. The software license does not grant trademark rights or imply endorsement by the credited upstream projects.
