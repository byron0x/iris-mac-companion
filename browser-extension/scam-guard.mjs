// Copyright © 2026 HANS Society Foundation. GPL-3.0-only.
import { hostname } from './protection.mjs';
export const FEED = 'https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json';
export const ALARM = 'iris-scam-list-update';
const DAY = 86400000;
export function normalizeDomains(values) {
  if (!Array.isArray(values) || values.length < 1000 || values.length > 500000) throw Error('Unexpected threat list size');
  const result = new Set();
  for (const value of values) {
    if (typeof value !== 'string' || value.length > 253 || !/^[a-z0-9.-]+$/i.test(value)) continue;
    const host = value.toLowerCase().replace(/\.$/, '');
    if (/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$/.test(host)) result.add(host);
  }
  if (result.size < 1000) throw Error('Threat list could not be validated');
  return [...result].sort();
}
export function blockRules(domains) {
  const rules = [];
  for (let i=0; i<domains.length; i+=1000) rules.push({id:1+rules.length,priority:1,action:{type:'block'},condition:{requestDomains:domains.slice(i,i+1000),resourceTypes:['main_frame']}});
  return rules;
}
export function listedHost(host, domains) {
  if (!host) return false;
  let name=host;
  while (name.includes('.')) { if (domains.has(name)) return true; name=name.slice(name.indexOf('.')+1); }
  return false;
}
export function recentActivity(rows, now=Date.now()) {
  return (Array.isArray(rows)?rows:[]).filter(x=>x && typeof x.host==='string' && hostname(x.host)===x.host && Number.isSafeInteger(x.at) && x.at > now-30*DAY && x.at <= now && ['blocked','visited'].includes(x.kind)).slice(-100);
}
function database() {
  return new Promise((resolve,reject)=>{
    const request=indexedDB.open('iris-threat-data',1);
    request.onupgradeneeded=()=>request.result.createObjectStore('feed');
    request.onsuccess=()=>resolve(request.result); request.onerror=()=>reject(request.error);
  });
}
export async function savedFeed() {
  const db=await database();
  try { return await new Promise((resolve,reject)=>{ const r=db.transaction('feed').objectStore('feed').get('current'); r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error); }); }
  finally { db.close(); }
}
async function saveFeed(value) {
  const db=await database();
  try { await new Promise((resolve,reject)=>{const t=db.transaction('feed','readwrite');t.objectStore('feed').put(value,'current');t.oncomplete=resolve;t.onerror=()=>reject(t.error);}); }
  finally { db.close(); }
}
let loaded;
export function currentFeed() {
  loaded ||= (async()=>{
    const cached=await savedFeed().catch(()=>null);
    if (cached?.domains?.length && cached.source) return {domains:new Set(cached.domains),source:cached.source};
    const [domains,source]=await Promise.all(['crypto-phishing.json','source.json'].map(name=>fetch(chrome.runtime.getURL('data/'+name)).then(r=>r.json())));
    return {domains:new Set(domains),source};
  })();
  return loaded;
}
async function installRules(domains) {
  const existing=await chrome.declarativeNetRequest.getDynamicRules();
  await chrome.declarativeNetRequest.updateDynamicRules({removeRuleIds:existing.map(x=>x.id),addRules:blockRules(domains)});
}
export async function setGuard(enabled) {
  if (enabled && !await chrome.permissions.contains({permissions:['webNavigation']})) throw Error('Allow navigation warnings to enable scam protection.');
  if (enabled) {
    const feed=await currentFeed(); await installRules([...feed.domains]);
    await chrome.storage.local.set({scamGuard:{enabled:true,source:feed.source}});
    await chrome.alarms.create(ALARM,{delayInMinutes:1,periodInMinutes:1440});
  } else {
    await installRules([]); await chrome.storage.local.set({scamGuard:{enabled:false}}); await chrome.alarms.clear(ALARM);
  }
}
export async function refreshFeed() {
  const {scamGuard}=await chrome.storage.local.get('scamGuard'); if (!scamGuard?.enabled) return;
  if (!await chrome.permissions.contains({permissions:['webNavigation']})) { await setGuard(false); return; }
  if (scamGuard.source?.fetchedAt && Date.now()-scamGuard.source.fetchedAt<DAY) return;
  try {
    const response=await fetch(FEED,{credentials:'omit',cache:'no-store',signal:AbortSignal.timeout(20000)});
    if (!response.ok) throw Error('Update unavailable');
    const reader=response.body.getReader(); const chunks=[]; let size=0;
    while (true) { const {done,value}=await reader.read(); if(done) break; size+=value.length; if(size>16000000) { await reader.cancel(); throw Error('Threat list exceeds the update limit'); } chunks.push(value); }
    const bytes=new Uint8Array(size); let offset=0;for(const c of chunks){bytes.set(c,offset);offset+=c.length;}
    const domains=normalizeDomains(JSON.parse(new TextDecoder().decode(bytes)));
    const source={source:'ScamSniffer Web3 Scam Database',sourceUrl:'https://github.com/scamsniffer/scam-database',sourceDelayDays:7,domains:domains.length,fetchedAt:Date.now(),license:'GPL-3.0'};
    // Persist a complete validated feed before switching rules; a failed update keeps the last working rules.
    await saveFeed({domains,source}); await installRules(domains);
    loaded=Promise.resolve({domains:new Set(domains),source});
    await chrome.storage.local.set({scamGuard:{enabled:true,source}});
  } catch {
    await chrome.storage.local.set({scamGuard:{...scamGuard,updateError:'List update unavailable. The last installed snapshot is still protecting this browser.'}});
  }
}

if (typeof chrome !== 'undefined') chrome.storage.onChanged.addListener(changes=>{if(changes.scamGuard)loaded=undefined;});
