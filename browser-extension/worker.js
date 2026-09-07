import { ALARM, setGuard, refreshFeed, recentActivity, listedHost } from './scam-guard.mjs';
import { hostname, loadDatabase } from './protection.mjs';
import { createBrowserScan } from './browser-scan.mjs';
import {createAccess,currentAccess} from './account-access.mjs';
const accountAccess=createAccess(chrome);
import { updateBadge } from "./protection.mjs";
import { createService } from "./service.mjs";
const service = createService(chrome);
const scanner = createBrowserScan(chrome, loadDatabase);
chrome.runtime.onMessageExternal.addListener((message, sender, reply) => {
  service
    .external(message, sender)
    .then(reply, () =>
      reply({
        version: 1,
        error:
          "IRIS could not complete this browser request. Open the extension to continue.",
      }),
    );
  return true;
});
chrome.action.onClicked.addListener(() =>
  chrome.tabs.create({ url: chrome.runtime.getURL("review.html") }),
);
chrome.runtime.onInstalled.addListener((event) => {
  // Preserve the review available before account-based scan allowances launched.
  if(event.reason === 'update' && event.previousVersion && /^0\.[0-3]\./.test(event.previousVersion)) void chrome.management.getAll().then(infos=>chrome.storage.local.set({scanExtensionIds:infos.map(x=>x.id)}));
  if (event.reason === "install")
    void chrome.tabs.create({ url: chrome.runtime.getURL("review.html") });
});

// Browser events wake the service worker even when the review page is closed.
const watch = () => service.report().then(r => updateBadge(chrome, r)).catch(() => {});
for (const event of [chrome.management.onInstalled, chrome.management.onUninstalled, chrome.management.onEnabled, chrome.management.onDisabled]) event.addListener(watch);
chrome.storage.onChanged.addListener(changes=>{if(['choices','changes','extensionWatch','browserScan','scanExtensionIds'].some(k=>k in changes))void watch();});
chrome.runtime.onStartup.addListener(watch);
void watch();

let guardQueue = Promise.resolve();
const queueGuard = fn => { const result=guardQueue.then(fn); guardQueue=result.catch(()=>{}); return result; };
const navigations = new Map(); let registered = false; let activityQueue=Promise.resolve();
async function showScamWarning(details, kind='blocked') {
  const host=hostname(details.url); if (!host || details.frameId !== 0 || details.tabId < 0) return;
  const token=navigations.get(details.tabId);
  const {scamGuard}=await chrome.storage.local.get('scamGuard'); if (!scamGuard?.enabled) return;
  // Use the actually installed rules, even if a later feed download failed to install.
  const rules=await chrome.declarativeNetRequest.getDynamicRules();
  if (!rules.some(rule=>listedHost(host,new Set(rule.condition.requestDomains || [])))) return;
  if (navigations.get(details.tabId)!==token) return;
  const current=await chrome.webNavigation.getFrame({tabId:details.tabId,frameId:0}).catch(()=>null);
  if (kind==='visited' && (!current || current.url!==details.url)) return;
  if (navigations.get(details.tabId)!==token) return;
  const warning={host,at:Date.now(),kind};
  await chrome.storage.session.set({['warning:'+details.tabId]:warning});
  const persist = async()=>{
    const {scamActivity}=await chrome.storage.local.get('scamActivity'); const rows=recentActivity(scamActivity);
    if (!rows.some(x=>x.host===host && x.kind===kind && warning.at-x.at<60000)) rows.push(warning);
    await chrome.storage.local.set({scamActivity:rows.slice(-100)});
  };
  activityQueue=activityQueue.then(persist,persist); await activityQueue;
  if (navigations.get(details.tabId)!==token) return;
  await chrome.tabs.update(details.tabId,{url:chrome.runtime.getURL('warning.html')});
}
function navigationListeners() {
  if (registered || !chrome.webNavigation) return; registered=true;
  chrome.webNavigation.onBeforeNavigate.addListener(d=>{if(d.frameId===0)navigations.set(d.tabId,d.timeStamp);});
  chrome.webNavigation.onErrorOccurred.addListener(d=>{if(d.error==='net::ERR_BLOCKED_BY_CLIENT')void showScamWarning(d).catch(()=>{});});
  chrome.tabs.onRemoved.addListener(id=>{navigations.delete(id);void chrome.storage.session.remove('warning:'+id);});
}
async function checkOpenTabs() {
  const tabs=(await chrome.tabs.query({})).filter(tab=>!tab.incognito);
  for(const tab of tabs.slice(0,100)) {
    const frame=await chrome.webNavigation.getFrame({tabId:tab.id,frameId:0}).catch(()=>null);
    if(frame?.url)await showScamWarning({tabId:tab.id,frameId:0,url:frame.url},'visited');
  }
}
chrome.runtime.onMessage.addListener((message,sender,reply)=>{
  if(sender.id!==chrome.runtime.id || sender.url?.split('#')[0]!==chrome.runtime.getURL('review.html'))return;
  if(message?.action==='scanBrowser' || message?.action==='clearBrowserScan') {
    (message.action==='scanBrowser' ? accountAccess.reserve().then(()=>scanner.start()).then(async result=>{if(result.status==='complete')await accountAccess.complete().catch(()=>{});return result;}) : scanner.clear()).then(()=>reply({ok:true}),e=>reply({error:e.message || 'The browser check could not finish.'}));return true;
  }
  if(message?.action==='setExtensionWatch' && typeof message.enabled==='boolean') {
    (async()=>{if(message.enabled&&!((await accountAccess.status(true)).monitoring))throw Error('Extension monitoring is included with IRIS Pro.');await chrome.storage.local.set({extensionWatch:message.enabled});return {ok:true};})().then(reply,e=>reply({error:e.message}));return true;
  }
  if(message?.action!=='setScamGuard' || typeof message.enabled!=='boolean')return;
  queueGuard(async()=>{if(message.enabled&&!((await accountAccess.status(true)).monitoring))throw Error('Live scam protection is included with IRIS Pro.');navigationListeners();await setGuard(message.enabled);if(message.enabled)void checkOpenTabs().catch(()=>{});return {ok:true};}).then(reply,e=>reply({error:e.message || 'IRIS could not change scam protection. Check permissions and try again.'}));return true;
});
chrome.permissions.onAdded.addListener(navigationListeners);
chrome.permissions.onRemoved.addListener(p=>{if(p.permissions?.includes('webNavigation'))void queueGuard(()=>setGuard(false));if(p.permissions?.includes('history'))void scanner.cancelHistory();});
chrome.alarms.onAlarm.addListener(a=>{if(a.name===ALARM)void queueGuard(refreshFeed);});
chrome.runtime.onStartup.addListener(()=>void queueGuard(refreshFeed));
navigationListeners();
async function refreshPlan() {
  let allowed=false;
  try {allowed=(await accountAccess.status(true)).monitoring;}catch {const {companionAccess:a}=await chrome.storage.local.get('companionAccess');allowed=currentAccess(a)&&a.monitoring;}
  if(!allowed){const state=await chrome.storage.local.get(['scamGuard','extensionWatch']);if(state.scamGuard?.enabled)await queueGuard(()=>setGuard(false));if(state.extensionWatch)await chrome.storage.local.set({extensionWatch:false});}
}
chrome.alarms.create('iris-plan-check',{periodInMinutes:3});
chrome.alarms.onAlarm.addListener(a=>{if(a.name==='iris-plan-check')void refreshPlan();});
chrome.runtime.onStartup.addListener(()=>void refreshPlan());
void refreshPlan();
