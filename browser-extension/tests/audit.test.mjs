import test from "node:test";
import assert from "node:assert/strict";
import { buildReport, fingerprint, REVIEW_AGE } from "../audit.mjs";
import { createService, WEB_ORIGIN, trustedWeb } from "../service.mjs";
const self = "a".repeat(32),
  id = "b".repeat(32),
  now = 1800000000000;
const info = (extra = {}) => ({
  id,
  name: "Example",
  version: "1.0",
  type: "extension",
  installType: "normal",
  enabled: true,
  mayDisable: true,
  permissions: ["clipboardRead"],
  hostPermissions: ["https://*/*"],
  ...extra,
});
test("permissions are explained conservatively; IRIS and themes are excluded", () => {
  const r = buildReport(
    [info(), info({ id: self }), info({ id: "c".repeat(32), type: "theme" })],
    self,
    {},
    {},
    now,
  );
  assert.equal(r.extensions.length, 1);
  assert.equal(r.extensions[0].priority, "review");
  assert.equal(r.extensions[0].canDisable, true);
  assert.ok(
    r.extensions[0].reasons.some((x) => x.title === "Clipboard access"),
  );
  assert.ok(
    r.extensions[0].reasons.some((x) => x.title === "Broad website permission"),
  );
  assert.ok(r.limitations.some((x) => x.includes("not proof")));
});
test("Keep choices expire and never survive version or permission changes", () => {
  const choices = { [id]: { fingerprint: fingerprint(info()), at: now } };
  const result = (i, date = now) =>
    buildReport([i], self, choices, {}, date).extensions[0];
  assert.equal(result(info()).reviewed, true);
  assert.equal(result(info()).priority, "information");
  assert.equal(result(info({ version: "2.0" })).reviewed, false);
  assert.equal(
    result(info({ permissions: ["clipboardRead", "history"] })).reviewed,
    false,
  );
  assert.equal(result(info(), now + REVIEW_AGE).reviewed, false);
  assert.equal(result(info(), now - 1).reviewed, false);
});
test("restore requires an IRIS change record and unchanged permissions; managed items stay protected", () => {
  const changed = { [id]: { fingerprint: fingerprint(info()) } };
  const result = (i, changes = changed) =>
    buildReport([i], self, {}, changes, now).extensions[0];
  assert.equal(result(info({ enabled: false })).canRestore, true);
  assert.equal(result(info({ enabled: false }), {}).canRestore, false);
  assert.equal(
    result(info({ enabled: false, disabledReason: "permissions_increase" }))
      .canRestore,
    false,
  );
  assert.equal(
    result(info({ enabled: false, version: "2.0" })).canRestore,
    false,
  );
  assert.equal(
    result(info({ mayDisable: false, installType: "admin" })).canDisable,
    false,
  );
});
test("oversize reports explicitly retain partial coverage and cannot silently certify clean", () => {
  const infos = Array.from({ length: 1002 }, (_, n) =>
    info({
      id: n
        .toString(16)
        .padStart(32, "0")
        .replace(/[0-9a-f]/g, (c) => String.fromCharCode(97 + parseInt(c, 16))),
      name: "x".repeat(180),
      hostPermissions: Array.from(
        { length: 50 },
        (_, i) => "https://" + i + "x".repeat(150) + ".example/*",
      ),
    }),
  );
  const r = buildReport(infos, self, {}, {}, now);
  assert.equal(r.partial, true);
  assert.ok(JSON.stringify(r).length < 460000);
});
test("web bridge rejects other origins, frames, extensions, incognito and all mutation commands", async () => {
  const sender = {
    url: WEB_ORIGIN + "/device",
    origin: WEB_ORIGIN,
    frameId: 0,
    tab: { incognito: false },
  };
  for (const other of [
    { ...sender, url: "https://evil.example/device" },
    { ...sender, origin: "https://evil.example" },
    { ...sender, frameId: 1 },
    { ...sender, id: self },
    { ...sender, tab: { incognito: true } },
  ])
    assert.equal(trustedWeb(other), false);
  let calls = 0,
    opens = 0;
  const state = {
    sharing: { origin: WEB_ORIGIN, expiresAt: now + REVIEW_AGE },
    scanExtensionIds: [id],
  };
  const browser = {
    runtime: {
      id: self,
      getURL: (p) => "chrome-extension://" + self + "/" + p,
    },
    storage: {
      local: {
        get: async () => structuredClone(state),
        remove: async () => {
          delete state.sharing;
        },
      },
    },
    management: {
      getAll: async () => {
        calls++;
        return [info()];
      },
    },
    tabs: {
      create: async () => {
        opens++;
      },
    },
  };
  const service = createService(browser, () => now);
  await assert.rejects(
    service.external({ version: 1, action: "disable", focusId: id }, sender),
  );
  assert.equal(calls, 0);
  await assert.rejects(
    service.external(
      { version: 1, action: "report" },
      { ...sender, frameId: 1 },
    ),
  );
  assert.equal(calls, 0);
  const r = await service.external({ version: 1, action: "report" }, sender);
  assert.equal(r.report.extensions.length, 1);
  await service.external({ version: 1, action: "disconnect" }, sender);
  assert.equal(
    (await service.external({ version: 1, action: "report" }, sender))
      .connected,
    false,
  );
  assert.equal(calls, 1);
  await service.external(
    { version: 1, action: "openReview", focusId: id },
    sender,
  );
  assert.equal(opens, 1);
  await assert.rejects(
    service.external(
      { version: 1, action: "openReview", focusId: "https://evil.example" },
      sender,
    ),
  );
});
test("disconnect during an asynchronous audit prevents disclosure", async () => {
  let shared = { origin: WEB_ORIGIN, expiresAt: now + REVIEW_AGE };
  const browser = {
    runtime: { id: self },
    storage: { local: { get: async () => ({ sharing: shared }) } },
    management: {
      getAll: async () => {
        shared = null;
        return [info()];
      },
    },
  };
  const result = await createService(browser, () => now).external(
    { version: 1, action: "report" },
    { url: WEB_ORIGIN + "/device", frameId: 0 },
  );
  assert.equal(result.connected, false);
  assert.equal(result.report, undefined);
});
