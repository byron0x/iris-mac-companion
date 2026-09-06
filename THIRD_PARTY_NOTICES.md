# Third-party credits

IRIS Mac Companion is copyright © 2026 HANS Society Foundation and is released under GNU GPL version 3 only. See LICENSE. It is an independent project; inclusion does not imply endorsement.

## KnockKnock 4.0.3

Created by Patrick Wardle and Objective-See; maintained by the Objective-See Foundation. GNU GPL version 3. All original notices, branding, resources and signatures are retained in the original app downloaded directly from its official release. IRIS invokes its documented command-line interface with `-whosthere -skipVT` and translates its local JSON inventory into a guided review. No VirusTotal calls or uploads are requested.

- Project: https://objective-see.org/products/knockknock.html
- Source: https://github.com/objective-see/KnockKnock/tree/1e1d93d0394ebf4ce6e114a9448ce7af55dc44cc
- License: https://github.com/objective-see/KnockKnock/blob/1e1d93d0394ebf4ce6e114a9448ce7af55dc44cc/LICENSE
- Original release: https://github.com/objective-see/KnockKnock/releases/download/v4.0.3/KnockKnock_4.0.3.zip
- SHA-256: `1e1371ff6eb62e0866266a0744e90aa3bdc6b22cca0599afbd330ddf52663c69`
- Apple signing team: `VBG97UB4TA`

## ReiKey keyboard event-tap enumeration

Copyright © 2018 Objective-See / Patrick Wardle. GNU GPL version 3. IRIS adapts the enumeration and enabled-keyboard-tap filtering in ReiKey's `shared/EventTaps.m` into Swift. The adaptation adds bounded allocation, failure/partial coverage, verified Apple running-code attribution, grouping by application, encrypted reporting and guided macOS permission review. It does not bundle ReiKey's app, installer, login item, private notification observer, update checker or crash reporter. The complete adapted source is in `KeyboardScanner.swift` and `KeyboardReview.swift`; the full GPLv3 license accompanies IRIS.

- Project: https://objective-see.org/products/reikey.html
- Exact source: https://github.com/objective-see/ReiKey/blob/83ceb8fca9e08dbc4e92a43ddf6ecd39c36bb37f/shared/EventTaps.m
- License: https://github.com/objective-see/ReiKey/blob/83ceb8fca9e08dbc4e92a43ddf6ecd39c36bb37f/LICENSE.md
- Adaptation copyright © 2026 HANS Society Foundation. This feature is an on-demand CoreGraphics snapshot; it does not claim to detect all keyloggers or provide continuous ReiKey monitoring.

## ClamAV 1.5.4

Copyright Cisco Systems, Inc. and contributors. GNU GPL version 2, with the exceptions, component licenses and notices supplied by the upstream project. ClamAV remains a separate executable; IRIS does not link libclamav into its binary. The release build downloads and verifies the original universal macOS package, then unpacks it without running its installer. IRIS modifies only the Mach-O library search paths so the separate executables and libraries work inside the IRIS app, and signs those files with the IRIS release identity. This is a modified ClamAV distribution, with no changes to the scanner source code. The exact upstream corresponding source archive is supplied alongside every binary release; the complete path-adjustment and packaging scripts are in this repository. Upstream documentation and its component notices are retained in the bundled runtime.

- Project: https://www.clamav.net/
- Source and licenses: https://github.com/Cisco-Talos/clamav/tree/clamav-1.5.4
- Corresponding source archive: https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.5.4/clamav-1.5.4.tar.gz
- Original package: https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.5.4/clamav-1.5.4.macos.universal.pkg
- Package SHA-256: `df7fa753e2f9f67f3bc99b2a40a3be7ef559088c68ad6bdf66b4b5764e965bd6`
- Apple signing team: `DE8Y96K9QP`

The app fetches ClamAV definitions with the upstream `freshclam` updater. A signature match can be a false positive. Neither these scanners nor IRIS guarantee a device is free of malware.

## Distribution policy

Publish the complete corresponding IRIS source for each binary release, including build and installation scripts and this file. Also upload `dist/clamav-1.5.4.tar.gz` alongside the binary in the same release, preserving its full upstream source/build instructions and licenses. If future releases modify or bundle an upstream scanner, first include that scanner's required notices and complete corresponding source for the exact distributed binary. Do not substitute attribution for the applicable license obligations. Do not include VirusTotal API credentials without an agreement permitting the intended IRIS use.

## Browser threat data — ScamSniffer

Browser companion 0.2 includes the GPLv3 ScamSniffer Web3 Scam Database, initially pinned to commit `1bc0b0354537dc7c3511f3d26ca03d2e7504b67e`. Attribution, source hash and the unmodified license are included in `browser-extension/data`. Optional protection refreshes domain data from the same project's fixed public GitHub feed; its seven-day delay is disclosed. IRIS does not claim endorsement or real-time coverage. Source: https://github.com/scamsniffer/scam-database
