# IRIS browser companion store listing

Status: submitted to Chrome Web Store review on September 5, 2026. Publication is staged for final store-install verification after approval. Extension ID: `aeamoplfjgalmokafhkcapgpbofinmfg`. No approved public listing yet.

## Name

IRIS — Your browser guardian companion

## Summary

Understand extension access and turn off extensions you no longer need. Your review stays in this browser.

## Description

A simpler way to review what your browser extensions can access.

IRIS brings extension permissions into one clear review, explains what they mean, and helps you reduce access you no longer need.

• See which extensions request broad website, clipboard, history or other sensitive access.
• Keep extensions you recognize. IRIS remembers your choice for 30 days and asks you to review again if the version or reported permissions change.
• Turn off extensions from the companion. Restore supported changes when you need them again.
• Optionally connect your review to the IRIS web dashboard in the same browser. No separate account or Mac download is required for browser checks.

Your review runs locally. IRIS does not read browsing history, page contents, passwords or copied text. Permission explanations describe possible access; they are not a malware verdict. This companion does not scan extension code or certify an extension is safe. Your browser may require confirmation for changes, and organization-managed extensions may need an administrator.

An optional connection lets app.undercoveriris.io read extension names and permission summaries directly in your browser for 30 days. The report is not uploaded to an IRIS server. You can disconnect in either interface.

IRIS is a project of HANS Society Foundation. Open-source software under GPLv3.
Support: support@joinhans.io
Privacy: https://app.undercoveriris.io/device-privacy
Source: https://github.com/byron0x/iris-mac-companion/tree/main/browser-extension

## Single purpose

Help users review and reduce the access held by their installed browser extensions.

## Permission justifications

**management**: Read installed extension names, enabled status, installation type and reported API/website permissions to provide the local access review. Enable/disable operations occur only after the user clicks an action in the extension-owned review page. The connected website cannot enable, disable or uninstall extensions.

**storage**: Store local, version-and-permission-bound Keep choices, supported undo records and optional expiring website connection consent. No synchronized browser storage is used.

**Remote code**: None. All executable code is packaged with the extension. No remote scripts, remote execution, content scripts or third-party runtime dependencies.

**Website connection**: Only the top-level https://app.undercoveriris.io origin can communicate with the extension. Report disclosure requires the user's optional connection and rechecks consent after the asynchronous audit. Sharing happens directly within that browser profile, not through an inventory API or remote relay. Other extensions, frames and incognito contexts are rejected.

## Store privacy questionnaire notes

Answer according to the current store definitions. Disclose extension metadata and permission summaries plus the optional website disclosure. Do not claim that metadata never leaves the extension context or that this is an anonymous cloud malware service. No browsing history, website content, authentication details, financial information, location or personal communications are read by this extension.

Screenshots use a fresh test profile with clearly labeled example extensions. They do not show a user's personal inventory. Verify the store-distributed package in Chrome, Brave and Edge before enabling the public installation link.
