import { createService, WEB_ORIGIN, sharingActive } from "./service.mjs";
import { fingerprint, ID, REVIEW_AGE } from "./audit.mjs";
const service = createService(chrome);
const $ = (selector) => document.querySelector(selector);
let generation = 0;
let changing = false;
function node(tag, text, className) {
  const el = document.createElement(tag);
  if (text !== undefined) el.textContent = text;
  if (className) el.className = className;
  return el;
}
function message(text) {
  $("#message").textContent = text;
  $("#message").hidden = false;
}
function button(text, fn, style = "quiet") {
  const el = node("button", text, style);
  el.addEventListener("click", fn);
  return el;
}
function settings(id) {
  if (ID.test(id))
    void chrome.tabs.create({ url: "chrome://extensions/?id=" + id });
}
function change(item, enabled, el) {
  if (
    changing ||
    !ID.test(item.id) ||
    item.id === chrome.runtime.id ||
    (enabled ? !item.canRestore : !item.canDisable)
  )
    return;
  changing = true;
  el.disabled = true;
  // Call directly from this extension-owned click; the browser may require its own confirmation.
  chrome.management
    .setEnabled(item.id, enabled)
    .then(async () => {
      const { changes = {} } = await chrome.storage.local.get("changes");
      if (enabled) delete changes[item.id];
      else {
        const info = await chrome.management.get(item.id);
        changes[item.id] = { fingerprint: fingerprint(info), at: Date.now() };
      }
      await chrome.storage.local.set({ changes });
      message(
        enabled
          ? `${item.name} is back on.`
          : `${item.name} is turned off. You can restore it under “Other extensions”.`,
      );
    })
    .catch(() => {
      message(
        "The browser could not make that change. It may need confirmation or be managed by your organization. Use its extension settings to continue.",
      );
    })
    .finally(() => {
      changing = false;
      void refresh();
    });
}
async function keep(item, reset = false) {
  try {
    const info = await chrome.management.get(item.id);
    if (
      !reset &&
      (item.detailsLimited || fingerprint(info) !== fingerprint(item))
    ) {
      message(
        "This extension changed. Review its latest access before keeping it.",
      );
      await refresh();
      return;
    }
    const { choices = {} } = await chrome.storage.local.get("choices");
    if (reset) delete choices[item.id];
    else choices[item.id] = { fingerprint: fingerprint(info), at: Date.now() };
    await chrome.storage.local.set({ choices });
    message(
      reset
        ? "This extension is back in your review."
        : `IRIS will remember that you chose to keep ${item.name} for 30 days, unless its version or permissions change.`,
    );
    await refresh();
  } catch {
    message(
      "IRIS could not save that choice. Refresh your review and try again.",
    );
  }
}
function card(item) {
  const box = node(
    "article",
    undefined,
    "finding" + (item.enabled ? "" : " disabled"),
  );
  box.id = item.id;
  const head = node("div", undefined, "finding-header");
  head.append(
    node("h3", item.name),
    node(
      "span",
      !item.enabled
        ? "Turned off"
        : item.reviewed
          ? "Kept by you"
          : item.priority === "review"
            ? "Review access"
            : "For your information",
      "badge",
    ),
  );
  box.append(head);
  const reasons = node("ul");
  for (const r of item.reasons) {
    const li = node("li");
    li.append(
      node("strong", r.title + ". "),
      document.createTextNode(r.description),
    );
    reasons.append(li);
  }
  box.append(reasons);
  if (!item.reasons.length)
    box.append(
      node(
        "p",
        "No broad access was highlighted in this permissions review. This does not certify the extension is safe.",
        "muted",
      ),
    );
  const actions = node("div", undefined, "actions");
  if (item.canDisable) {
    const off = button("Turn off", () => change(item, false, off), "primary");
    actions.append(off);
  }
  if (item.canRestore) {
    const undo = button(
      "Restore extension",
      () => change(item, true, undo),
      "primary",
    );
    actions.append(undo);
  }
  if (item.enabled && !item.reviewed && !item.detailsLimited)
    actions.append(button("Keep this extension", () => keep(item)));
  if (item.reviewed)
    actions.append(button("Review again", () => keep(item, true)));
  actions.append(button("Browser settings ↗", () => settings(item.id)));
  box.append(actions);
  if (item.managed)
    box.append(
      node(
        "p",
        "Your organization or browser manages this extension. IRIS cannot turn it off.",
        "muted",
      ),
    );
  if (!item.enabled && !item.canRestore)
    box.append(
      node(
        "p",
        "Use browser settings to review whether this extension should be enabled.",
        "muted",
      ),
    );
  const details = node("details", undefined, "details");
  details.append(
    node("summary", "Version and permission details"),
    node("p", "Version " + item.version),
    node(
      "p",
      "Browser permissions: " +
        (item.permissions.join(", ") || "None reported"),
    ),
    node(
      "p",
      "Website patterns: " +
        (item.hostPermissions.join(", ") || "None reported"),
    ),
  );
  if (item.detailsLimited)
    details.append(
      node(
        "p",
        "This extension has more permissions than fit in this summary. Check its browser settings for the full list.",
      ),
    );
  box.append(details);
  return box;
}
async function refresh() {
  const g = ++generation;
  try {
    const [report, { sharing }] = await Promise.all([
      service.report(),
      chrome.storage.local.get("sharing"),
    ]);
    if (g !== generation) return;
    const connected = sharingActive(sharing);
    $("#connect").textContent = connected
      ? "Open IRIS dashboard ↗"
      : "Connect to IRIS ↗";
    $("#disconnect").hidden = !connected;
    $("#connection-title").textContent = connected
      ? "Your browser companion is connected"
      : "Bring this review into IRIS";
    $("#connection-copy").textContent = connected
      ? "This browser can show its extension review in the IRIS web app. Disconnect whenever you want."
      : "Connect once to share extension names and permission summaries with app.undercoveriris.io in this browser for 30 days. No separate login is needed.";
    const todo = report.extensions.filter((x) => x.priority === "review");
    const other = report.extensions.filter((x) => x.priority !== "review");
    $("#summary").textContent =
      `${todo.length} extension${todo.length === 1 ? "" : "s"} to review · ${report.extensions.filter((x) => x.enabled).length} enabled · ${report.extensions.filter((x) => !x.enabled).length} turned off` +
      (report.partial ? " · Partial list" : "");
    const oldOpen = $("#findings .other")?.open;
    const focusId = location.hash.slice(1);
    const list = document.createDocumentFragment();
    if (!todo.length)
      list.append(
        node(
          "p",
          "No unreviewed extensions with broad access were highlighted. You can still review the others below.",
          "muted",
        ),
      );
    todo.forEach((x) => list.append(card(x)));
    if (other.length) {
      const details = node("details", undefined, "other");
      details.open = !!oldOpen || other.some((x) => x.id === focusId);
      details.append(node("summary", `Other extensions (${other.length})`));
      other.forEach((x) => details.append(card(x)));
      list.append(details);
    }
    $("#findings").replaceChildren(list);
    if (ID.test(focusId))
      document.getElementById(focusId)?.scrollIntoView({ block: "start" });
  } catch {
    if (g === generation)
      message(
        "Your browser could not provide the extension list. Try refreshing; no extensions have been changed.",
      );
  }
}
$("#connect").addEventListener("click", async () => {
  try {
    const { sharing } = await chrome.storage.local.get("sharing");
    if (!sharingActive(sharing))
      await chrome.storage.local.set({
        sharing: { origin: WEB_ORIGIN, expiresAt: Date.now() + REVIEW_AGE },
      });
    await chrome.tabs.create({ url: WEB_ORIGIN + "/device" });
    await refresh();
  } catch {
    message(
      "IRIS could not save the connection. Your local review remains available.",
    );
  }
});
$("#disconnect").addEventListener("click", async () => {
  try {
    await chrome.storage.local.remove("sharing");
    message(
      "Disconnected from the IRIS website. Your local review remains available.",
    );
    await refresh();
  } catch {
    message("IRIS could not disconnect. Try again.");
  }
});
$("#clear").addEventListener("click", async () => {
  try {
    await chrome.storage.local.remove("choices");
    message(
      "Saved Keep choices were removed. Extensions turned off by IRIS can still be restored.",
    );
    await refresh();
  } catch {
    message("IRIS could not clear your saved choices. Try again.");
  }
});
$("#refresh").addEventListener("click", refresh);
chrome.storage.onChanged.addListener(() => void refresh());
for (const event of [
  chrome.management.onInstalled,
  chrome.management.onUninstalled,
  chrome.management.onEnabled,
  chrome.management.onDisabled,
])
  event.addListener(() => void refresh());
window.addEventListener("focus", () => void refresh());
void refresh();
