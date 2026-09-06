// Copyright © 2026 HANS Society Foundation. GPL-3.0-only.
// Threat data: ScamSniffer, GPLv3. See data/source.json and data/SCAMSNIFFER-LICENSE.
export function hostname(value) {
  if (typeof value !== 'string' || value.length > 8192) return null;
  try {
    const url = new URL(value.includes('://') ? value : 'https://' + value);
    if (!['https:', 'http:'].includes(url.protocol)) return null;
    return url.hostname.toLowerCase().replace(/\.$/, '');
  } catch { return null; }
}
export function checkLink(value, domains) {
  const host = hostname(value);
  // Exact matching avoids blocking unrelated tenants on shared hosting providers.
  return { host, match: !!host && domains.has(host) };
}
export function reviewHistory(rows, domains, now = Date.now(), limit = 5000) {
  const found = new Map(); let checked = 0;
  for (const row of rows.slice(0, limit)) {
    const result = checkLink(row.url, domains);
    if (!result.host) continue;
    checked++;
    if (result.match) found.set(result.host, { host: result.host, lastVisit: Math.min(now, Math.max(0, Number(row.lastVisitTime) || 0)) });
  }
  return { checkedAt: now, checkedCount: checked, matchCount: found.size, partial: rows.length >= limit, matches: [...found.values()].slice(0, 100), days: 7 };
}
export { currentFeed as loadDatabase } from './scam-guard.mjs';
export async function updateBadge(browser, report) {
  const { extensionWatch } = await browser.storage.local.get('extensionWatch');
  const count = report.extensions.filter(x => x.priority === 'review').length;
  await browser.action.setBadgeBackgroundColor({ color: '#9362cd' });
  await browser.action.setBadgeText({ text: extensionWatch ? count > 99 ? '99+' : count ? String(count) : '' : '' });
  await browser.action.setTitle({ title: extensionWatch && count ? `IRIS: ${count} extensions need an access review` : 'Open your IRIS browser guardian companion' });
}
