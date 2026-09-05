// Copyright © 2026 HANS Society Foundation. GPL-3.0-only.
import { buildReport, ID, REVIEW_AGE } from "./audit.mjs";
export const WEB_ORIGIN = "https://app.undercoveriris.io";
export function trustedWeb(sender) {
  try {
    return (
      !sender.id &&
      sender.frameId === 0 &&
      !sender.tab?.incognito &&
      new URL(sender.url).origin === WEB_ORIGIN &&
      (!sender.origin || sender.origin === WEB_ORIGIN)
    );
  } catch {
    return false;
  }
}
export function sharingActive(value, now = Date.now()) {
  return (
    value?.origin === WEB_ORIGIN &&
    Number.isSafeInteger(value.expiresAt) &&
    value.expiresAt > now &&
    value.expiresAt <= now + REVIEW_AGE
  );
}
export function createService(browser, now = Date.now) {
  let lastOpened = 0;
  async function report() {
    const [infos, state] = await Promise.all([
      browser.management.getAll(),
      browser.storage.local.get(["choices", "changes"]),
    ]);
    return buildReport(
      infos,
      browser.runtime.id,
      state.choices,
      state.changes,
      now(),
    );
  }
  async function external(message, sender) {
    if (
      !trustedWeb(sender) ||
      !message ||
      message.version !== 1 ||
      Object.keys(message).some(
        (x) => !["version", "action", "focusId"].includes(x),
      )
    )
      throw Error("This connection is not allowed.");
    if (
      !["status", "report", "openReview", "disconnect"].includes(message.action)
    )
      throw Error("Unsupported browser request.");
    const state = await browser.storage.local.get("sharing");
    if (message.action === "status")
      return { version: 1, connected: sharingActive(state.sharing, now()) };
    if (message.action === "disconnect") {
      await browser.storage.local.remove("sharing");
      return { version: 1, connected: false };
    }
    if (message.action === "openReview") {
      if (message.focusId !== undefined && !ID.test(message.focusId))
        throw Error("Invalid extension selection.");
      if (now() - lastOpened < 2000)
        throw Error("The IRIS extension review is already opening.");
      lastOpened = now();
      await browser.tabs.create({
        url:
          browser.runtime.getURL("review.html") +
          (message.focusId ? "#" + message.focusId : ""),
      });
      return { version: 1, opened: true };
    }
    if (!sharingActive(state.sharing, now()))
      return { version: 1, connected: false };
    const value = await report();
    // Revalidate after the asynchronous audit so revocation cannot race disclosure.
    const current = await browser.storage.local.get("sharing");
    if (!sharingActive(current.sharing, now()))
      return { version: 1, connected: false };
    return { version: 1, connected: true, report: value };
  }
  return { report, external };
}
