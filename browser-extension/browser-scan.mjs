// Copyright © 2026 HANS Society Foundation. GPL-3.0-only.
import { buildReport } from './audit.mjs';
import { reviewHistory } from './protection.mjs';

export function currentScan(value, now = Date.now()) {
  if (!value || value.version !== 1 || !Number.isSafeInteger(value.startedAt) || value.startedAt > now || value.startedAt <= now - 7 * 86400000) return null;
  if (value.status === 'scanning' && value.startedAt < now - 120000) return {...value, status:'interrupted', message:'The browser stopped this scan. Start another scan to finish.'};
  return value;
}

export function createBrowserScan(browser, loadDatabase, now = Date.now) {
  let running = null, generation = 0;
  async function scan() {
    const run = ++generation, startedAt = now();
    let result = {version:1, startedAt, status:'scanning', step:1, total:3, message:'Reviewing installed extensions…', historyStatus:'notChecked'};
    const save = async () => { if (run !== generation) throw Error('cancelled'); await browser.storage.local.set({browserScan:{...result}}); };
    try {
      await save();
      const [infos, state] = await Promise.all([browser.management.getAll(), browser.storage.local.get(['choices','changes'])]);
      const extensions = buildReport(infos, browser.runtime.id, state.choices, state.changes, now());
      await browser.storage.local.set({scanExtensionIds:extensions.extensions.map(x=>x.id)});
      result = {...result, extensionsChecked:extensions.extensions.length, extensionPartial:extensions.partial, step:2, message:'Checking recent browsing against the local scam list…'};
      await save();
      if (await browser.permissions.contains({permissions:['history']})) {
        try {
          const {domains} = await loadDatabase();
          const rows = await browser.history.search({text:'',startTime:now()-7*86400000,maxResults:5000});
          if (run !== generation || !await browser.permissions.contains({permissions:['history']})) throw Error('cancelled');
          const historyReview = reviewHistory(rows, domains, now());
          await browser.storage.local.set({historyReview});
          if (run !== generation) { await browser.storage.local.remove('historyReview'); throw Error('cancelled'); }
          result.historyStatus = historyReview.partial ? 'partial' : 'complete';
          result.historyCheckedAt = historyReview.checkedAt;
        } catch (error) { if (run !== generation) throw error; result.historyStatus = 'unavailable'; }
      } else result.historyStatus = 'permissionNeeded';
      result = {...result, checkedAt:now(), step:3, status:!extensions.partial && result.historyStatus === 'complete' ? 'complete' : 'partial'};
      result.message = result.status === 'complete' ? 'Scan finished. Your results and next steps are below.' : result.historyStatus === 'permissionNeeded' ? 'Extensions checked. Allow history access to complete the recent-browsing check.' : 'Scan finished with a coverage gap. Review the details below.';
      await save();
      return result;
    } catch (error) {
      if (run === generation) { result = {...result,status:'interrupted',message:'The scan could not finish. Start another scan to try again.'}; await save(); }
      return result;
    }
  }
  return {
    start() { if (!running) running = scan().finally(() => {running=null;}); return running; },
    async clear() { generation++; await browser.permissions.remove({permissions:['history']}); if (running) await running; await browser.storage.local.remove(['historyReview','browserScan']); },
    cancelHistory() { generation++; return browser.storage.local.remove(['historyReview','browserScan']); }
  };
}
