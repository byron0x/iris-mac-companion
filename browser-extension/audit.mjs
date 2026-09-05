// Copyright © 2026 HANS Society Foundation. GPL-3.0-only.
export const MAX_ITEMS = 1000;
export const REVIEW_AGE = 30 * 86400000;
export const ID = /^[a-p]{32}$/;
const access = {
  debugger: [
    "Browser debugging",
    "Can inspect and control browser tabs through debugging tools.",
  ],
  proxy: [
    "Connection routing",
    "Can change how browser traffic reaches the internet.",
  ],
  clipboardRead: [
    "Clipboard access",
    "Can read copied text, which may include sensitive information.",
  ],
  clipboardWrite: [
    "Clipboard changes",
    "Can replace copied text. Double-check wallet addresses before sending funds.",
  ],
  history: ["Browsing history", "Can read or change browsing history."],
  cookies: [
    "Website cookies",
    "Can access cookies on permitted websites, which may include sign-in sessions.",
  ],
  nativeMessaging: [
    "Mac or device connection",
    "Can communicate with a separately installed native application.",
  ],
  management: [
    "Other extensions",
    "Can review or manage other installed extensions.",
  ],
  downloads: [
    "Downloads",
    "Can manage downloads and read download information.",
  ],
  tabs: ["Tab information", "Can access information about open tabs."],
  scripting: [
    "Website scripts",
    "Can run scripts on websites where it has access.",
  ],
  webRequest: [
    "Network request information",
    "Can observe requests on websites where it has access.",
  ],
  webRequestBlocking: [
    "Network request changes",
    "Can block or change requests where its permissions allow.",
  ],
};
const bounded = (list, limit = 500) =>
  Array.isArray(list)
    ? [
        ...new Set(
          list.filter((x) => typeof x === "string").map((x) => x.slice(0, 500)),
        ),
      ]
        .sort()
        .slice(0, limit)
    : [];
export function fingerprint(info) {
  // Exact version/permission snapshot. Review choices never survive an access or version change.
  return JSON.stringify([
    info.id,
    info.version,
    info.installType,
    bounded(info.permissions),
    bounded(info.hostPermissions),
  ]);
}
export function canRestore(info, changed) {
  return (
    !info.enabled &&
    info.mayEnable !== false &&
    info.mayDisable !== false &&
    info.disabledReason !== "permissions_increase" &&
    changed?.fingerprint === fingerprint(info)
  );
}
export function buildReport(
  infos,
  selfId,
  choices = {},
  changes = {},
  now = Date.now(),
) {
  const all = infos.filter(
    (x) => x && x.type === "extension" && x.id !== selfId && ID.test(x.id),
  );
  const extensions = all.slice(0, MAX_ITEMS).map((info) => {
    const permissions = bounded(info.permissions);
    const hosts = bounded(info.hostPermissions);
    const broad = hosts.some(
      (h) => h === "<all_urls>" || /^(?:\*|https?|file):\/\/\*(?:\/|$)/.test(h),
    );
    const reasons = [];
    if (broad)
      reasons.push({
        title: "Broad website permission",
        description:
          "Reported permissions cover many websites. Review whether this extension needs that reach; browser site restrictions may narrow its access.",
      });
    else if (hosts.length)
      reasons.push({
        title: "Website access",
        description: `Reports permission for ${hosts.length} website pattern${hosts.length === 1 ? "" : "s"}. Expand the details to see which ones.`,
      });
    for (const p of permissions)
      if (access[p])
        reasons.push({ title: access[p][0], description: access[p][1] });
    if (info.installType === "development" || info.installType === "sideload")
      reasons.push({
        title: "Installed outside the usual store flow",
        description:
          "Keep this only if you recognize where it came from and still need it.",
      });
    const detailsLimited =
      (info.permissions?.length || 0) > 500 ||
      (info.hostPermissions?.length || 0) > 500 ||
      [...(info.permissions || []), ...(info.hostPermissions || [])].some(
        (x) => typeof x !== "string" || x.length > 500,
      );
    const choice = choices[info.id];
    const reviewed =
      !detailsLimited &&
      choice?.fingerprint === fingerprint(info) &&
      Number.isFinite(choice.at) &&
      now >= choice.at &&
      now - choice.at < REVIEW_AGE;
    const priority =
      info.enabled &&
      !reviewed &&
      (broad ||
        permissions.some((p) => access[p]) ||
        ["development", "sideload"].includes(info.installType))
        ? "review"
        : "information";
    return {
      id: info.id,
      name: String(info.name || "Unnamed extension").slice(0, 180),
      version: String(info.version || "").slice(0, 80),
      installType: info.installType,
      enabled: !!info.enabled,
      priority,
      reviewed,
      canDisable: !!info.enabled && info.mayDisable === true,
      canRestore: !detailsLimited && canRestore(info, changes[info.id]),
      managed: info.installType === "admin" || info.mayDisable === false,
      reasons,
      permissions,
      hostPermissions: hosts,
      detailsLimited,
    };
  });
  extensions.sort(
    (a, b) =>
      Number(b.enabled) - Number(a.enabled) ||
      Number(a.priority !== "review") - Number(b.priority !== "review") ||
      a.name.localeCompare(b.name),
  );
  let bytes = 0;
  const displayed = [];
  for (const item of extensions) {
    const size = JSON.stringify(item).length + 1;
    if (bytes + size > 450000) continue;
    bytes += size;
    displayed.push(item);
  }
  return {
    version: 1,
    checkedAt: now,
    total: all.length,
    partial: all.length > displayed.length,
    extensions: displayed,
    limitations: [
      "Permissions describe possible access, not proof that an extension is malicious or using that access.",
      "This review does not scan extension code, detect all malware, or change individual website permissions.",
      "Keep choices last 30 days and reset when an extension version or its reported permissions change.",
    ],
  };
}
