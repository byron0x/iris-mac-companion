import { loadDatabase, checkLink, reviewHistory, updateBadge } from "./protection.mjs";
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
  if (item.reasons.length) box.append(node("p", item.reasons[0].title + ". " + item.reasons[0].description));
  const why = node("details"); why.append(node("summary", "Why this needs a review"), reasons);
  if (item.reasons.length > 1) box.append(why);
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
    const [report, { sharing, extensionWatch, historyReview, scamGuard, scamActivity }] = await Promise.all([
      service.report(),
      chrome.storage.local.get(["sharing", "extensionWatch", "historyReview", "scamGuard", "scamActivity"]),
    ]);
    if (g !== generation) return;
    const connected = sharingActive(sharing);
    $("#scam-guard").checked = scamGuard?.enabled === true;
    $("#scam-guard-status").textContent = scamGuard?.enabled ? `Protection on · ${scamGuard.source?.domains?.toLocaleString() || 'Known'} hostnames${scamGuard.source?.fetchedAt ? ' · Updated '+new Date(scamGuard.source.fetchedAt).toLocaleString() : ' · Packaged snapshot'}${scamGuard.updateError ? ' · '+scamGuard.updateError : ''}` : 'Protection is off. Enable it to block known scam sites.';
    const events = report.security.activity; $("#scam-activity").replaceChildren();
    for(const event of events.slice(-5).reverse()) $("#scam-activity").append(node('p', `${event.kind === 'blocked' ? 'Blocked' : 'Found open'}: ${event.host} · ${new Date(event.at).toLocaleString()}`));
    $("#watch").checked = extensionWatch === true;
    const count = report.extensions.length; const left = report.extensions.filter(x => x.priority === "review").length;
    $("#journey-summary").textContent = left ? `${left} decision${left === 1 ? "" : "s"} left. Keep tools you recognize; turn off ones you no longer need.` : "Extension review up to date. You can still check links and recent browsing below.";
    $("#review-progress").max = Math.max(1,count); $("#review-progress").value = count ? count - left : 1;
    renderHistory(historyReview);
    await updateBadge(chrome, report);
    $("#connect").textContent = connected
      ? "Open IRIS dashboard ↗"
      : "Connect to IRIS ↗";
    $("#disconnect").hidden = !connected;
    $("#connection-title").textContent = connected
      ? "Your browser companion is connected"
      : "Bring this review into IRIS";
    $("#connection-copy").textContent = connected
      ? "This browser can show its extension review in the IRIS web app. Disconnect whenever you want."
      : "Connect once to share extension names, permission summaries and security-check counts with app.undercoveriris.io in this browser for 30 days. No separate login is needed.";
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

$("#watch").addEventListener("change", async event => {
  try { await chrome.storage.local.set({ extensionWatch: event.target.checked }); }
  catch { message("IRIS could not save monitoring preferences. Please try again."); }
});
let checkingHistory = false; let historyGeneration = 0;
$("#link-form").addEventListener("submit", async event => {
  event.preventDefault();
  const input = $("#link").value;
  $("#link-result").textContent = "Checking the local threat list…";
  try {
    const { domains } = await loadDatabase(); const result = checkLink(input, domains);
    $("#link-result").textContent = !result.host ? "Enter a valid http or https website link." : result.match ? `${result.host} is on the known crypto-phishing list. Do not connect your wallet or sign anything there.` : `${result.host}: no exact match in this snapshot. This does not establish that the site is safe.`;
    $("#link-result").className = result.match ? "warning" : "muted";
  } catch { $("#link-result").textContent = "The local list could not load. The link has not been checked."; }
});
function renderHistory(value) {
  const root = $("#history-result"); root.replaceChildren();
  if (!value || value.checkedAt < Date.now() - 7 * 86400000) return;
  root.append(node("p", `${value.checkedCount} history entries checked · ${value.matchCount} flagged hostnames · ${new Date(value.checkedAt).toLocaleString()}`));
  if (value.partial) root.append(node("p", "History limit reached. Some entries from the last 7 days were not checked.", "muted"));
  if (!value.matchCount) { root.append(node("p", "No matches in the checked history against this snapshot. Private browsing and other profiles are not included.", "muted")); return; }
  root.append(node("p", "A visit does not prove your wallet or device was compromised. If you entered a seed phrase, signed a transaction, or downloaded a file there, review the steps below.", "warning"));
  const list = node("ul");
  for (const item of value.matches.slice(0,100)) list.append(node("li", item.host));
  root.append(list);
  if (value.matchCount > 100) root.append(node("p", "Showing the first 100 flagged hostnames."));
  const link = node("a", "Review wallet approvals in IRIS ↗", "primary"); link.href = WEB_ORIGIN + "/wallet"; link.target = "_blank"; link.rel = "noopener noreferrer";
  root.append(link, node("p", "Downloaded something? Run the Mac scan from your IRIS dashboard. Clearing browser history does not undo wallet signatures or remove downloaded files.", "muted"));
}
$("#history-check").addEventListener("click", async () => {
  if (checkingHistory) return; const currentHistory = ++historyGeneration; checkingHistory = true; $("#history-check").disabled = true;
  try {
    // Request from this user gesture, never from the website or background worker.
    if (!await chrome.permissions.request({ permissions: ["history"] })) { message("History access was not granted. You can still check individual links."); return; }
    message("Checking recent browsing locally…");
    const { domains } = await loadDatabase();
    const rows = await chrome.history.search({ text: "", startTime: Date.now() - 7 * 86400000, maxResults: 5000 });
    if (currentHistory !== historyGeneration || !await chrome.permissions.contains({ permissions: ["history"] })) return;
    const historyReview = reviewHistory(rows, domains);
    await chrome.storage.local.set({ historyReview }); renderHistory(historyReview);
    message("Recent-browsing check finished. See the result and next steps below.");
  } catch { message("The history check could not finish. No browsing entries were changed."); }
  finally { checkingHistory = false; $("#history-check").disabled = false; }
});
$("#history-clear").addEventListener("click", async () => {
  try { historyGeneration++; await chrome.permissions.remove({ permissions: ["history"] }); await chrome.storage.local.remove("historyReview"); renderHistory(null); message("The saved check and history permission were removed. Your browser history was not changed."); }
  catch { message("Could not remove the saved check. Please try again."); }
});
loadDatabase().then(({source}) => { $("#phishing-source").textContent = `${source.domains.toLocaleString()} exact hostnames. Snapshot ${new Date(source.fetchedAt || source.sourceUpdatedAt).toLocaleDateString()}. ScamSniffer’s public data is delayed by ${source.sourceDelayDays} days.`; }).catch(() => { $("#phishing-source").textContent = "The packaged threat list is unavailable."; });

$("#scam-guard").addEventListener("change", async event=>{
  const control=event.target;const enabled=control.checked;control.disabled=true;
  try {
    if(enabled && !await chrome.permissions.request({permissions:['webNavigation']})){control.checked=false;message('Navigation permission was not granted. Local link and extension checks still work.');return;}
    const result=await chrome.runtime.sendMessage({action:'setScamGuard',enabled});
    if(!result?.ok)throw Error(result?.error || 'Protection could not be changed.');
    message(enabled?'Known-scam protection is on. IRIS will show a warning and next steps for listed sites.':'Known-scam protection is off.');
    await refresh();
  }catch(e){message(e.message);await refresh();}finally{control.disabled=false;}
});
$("#activity-clear").addEventListener("click",async()=>{await chrome.storage.local.remove('scamActivity');await refresh();});
