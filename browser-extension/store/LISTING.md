# IRIS browser companion 0.4.0 store update

The existing item aeamoplfjgalmokafhkcapgpbofinmfg has published version 0.1.0. This document describes the 0.4.0 release candidate, not the currently distributed package.

## Summary
Review extension access, block known crypto-scam sites, and get clear next steps. Security checks run locally.

## Description
IRIS is your browser guardian companion from HANS Society Foundation.

• Review extension access. Keep the tools you recognize, turn off ones you no longer need, and undo supported changes.
• With Pro, enable extension-change alerts. A toolbar badge highlights extensions that need review.
• With Pro, enable known-scam protection to block listed crypto-phishing hostnames and their subdomains. A warning guides you to your IRIS dashboard, a Mac scan, or wallet-approval review if needed.
• Check a link locally, or optionally review up to 5,000 browsing entries from the last seven days.
• Connect to your IRIS web dashboard to see extension reviews and scam-warning activity alongside your Mac companion.

ScamSniffer's open-source threat data updates daily when protection is on, but its free feed has a seven-day delay. It can miss new scams and contain false positives. No match is not a safety verdict. A blocked navigation is not proof of infection, and wallet-approval checks cannot reverse transfers or every signature.

IRIS does not read page contents, clipboard text, passwords or wallet secrets. History permission is optional and used only when you start that check. Matched history hostnames stay locally. Live scam warnings retain hostname/time only; normal navigation is not saved. An optional 30-day connection shares extension reports, protection state and warning activity directly with app.undercoveriris.io in this browser, plus recent-history aggregate counts. No scan data is uploaded to an IRIS server. Disconnect at any time.

Connect a Google or wallet account to start scans. Free includes one manual scan per calendar month (UTC). IRIS Pro ($10/month or $90/year, purchased on the IRIS website) includes unlimited scans and live scam / extension-change monitoring. Saved reviews, supported turn-off/restore/removal actions and local single-link lookups stay available on Free. Billing details are shown before checkout.

Account checks send only the linked credential and scan allowance request to IRIS, never browser history or extension inventories. Monthly usage identifiers expire after 40 days. Connection credentials expire after 30 days or are removed on disconnect.

Open-source GPLv3 software. Support: support@joinhans.io.
Privacy: https://app.undercoveriris.io/device-privacy
Source: https://github.com/byron0x/iris-mac-companion/tree/main/browser-extension

## Single purpose
Help users reduce browser security risks from extension access and known crypto-phishing sites, with understandable, locally performed checks and cleanup guidance.

## Permission justifications
- management: installed-extension metadata and explicit user-chosen disable/restore actions in the extension UI. Websites cannot change other extensions.
- storage: preferences, undo records, expiring dashboard consent and bounded security results/activity.
- declarativeNetRequest: block top-level requests to known scam hostnames locally before the request reaches a site. Only block rules; no traffic bodies or page contents are read.
- alarms: three-minute plan access refresh and once-daily refresh of the fixed ScamSniffer public domain feed while protection is enabled.
- OPTIONAL webNavigation: identify blocked navigations to show the IRIS warning and check up to 100 already-open tabs when the user enables protection. Save only matched hostname/time/status, not normal browsing.
- OPTIONAL history: user-started local check of up to 5,000 entries from the past seven days. No background collection; no raw URL storage or upload.

## Data and remote-code disclosures
Declare browsing-history/navigation handling and its limited local use plus explicit dashboard disclosure; do not claim the app never handles browsing data. Extension metadata is also disclosed. No advertising, sale, credit decisions or staff access. All executable code is packaged; the only downloaded feed is validated, size-bounded domain data, with no remote scripts or expressions. GitHub receives ordinary request metadata only.

Screenshots and review tests use harmless temporary profiles and a local HTTP fixture, never real scam navigation or personal browsing history.
