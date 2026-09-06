import { ALARM, setGuard, refreshFeed, recentActivity, listedHost } from './scam-guard.mjs';
import { hostname } from './protection.mjs';
import { updateBadge } from "./protection.mjs";
import { createService } from "./service.mjs";
const service = createService(chrome);
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
  if (event.reason === "install")
    void chrome.tabs.create({ url: chrome.runtime.getURL("review.html") });
});

// Browser events wake the service worker even when the review page is closed.
const watch = () => service.report().then(r => updateBadge(chrome, r)).catch(() => {});
for (const event of [chrome.management.onInstalled, chrome.management.onUninstalled, chrome.management.onEnabled, chrome.management.onDisabled]) event.addListener(watch);
chrome.storage.onChanged.addListener(watch);
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
  if(sender.id!==chrome.runtime.id || sender.url!==chrome.runtime.getURL('review.html') || message?.action!=='setScamGuard' || typeof message.enabled!=='boolean')return;
  queueGuard(async()=>{navigationListeners();await setGuard(message.enabled);if(message.enabled)void checkOpenTabs().catch(()=>{});return {ok:true};}).then(reply,()=>reply({error:'IRIS could not change scam protection. Check permissions and try again.'}));return true;
});
chrome.permissions.onAdded.addListener(navigationListeners);
chrome.permissions.onRemoved.addListener(p=>{if(p.permissions?.includes('webNavigation'))void queueGuard(()=>setGuard(false));});
chrome.alarms.onAlarm.addListener(a=>{if(a.name===ALARM)void queueGuard(refreshFeed);});
chrome.runtime.onStartup.addListener(()=>void queueGuard(refreshFeed));
navigationListeners();
