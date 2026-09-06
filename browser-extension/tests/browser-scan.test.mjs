import test from 'node:test';
import assert from 'node:assert/strict';
import {createBrowserScan, currentScan} from '../browser-scan.mjs';
function fixture(granted=true) {
 const values={}, time=1800000000000; let historyCalls=0, pending=null;
 const browser={runtime:{id:'a'.repeat(32)},management:{getAll:async()=>[]},storage:{local:{get:async keys=>Object.fromEntries((Array.isArray(keys)?keys:[keys]).map(k=>[k,values[k]])),set:async value=>Object.assign(values,structuredClone(value)),remove:async keys=>{for(const k of Array.isArray(keys)?keys:[keys])delete values[k];}}},permissions:{contains:async()=>granted,remove:async()=>{granted=false;}},history:{search:async()=>{historyCalls++;if(pending)await pending;return [{url:'https://known.test/private?token=never-retain',lastVisitTime:time},{url:'https://ordinary.test'}];}}};
 const scanner=createBrowserScan(browser,async()=>({domains:new Set(['known.test'])}),()=>time);
 return {browser,scanner,values,time,calls:()=>historyCalls,delay:p=>pending=p};
}
test('one scan combines extension and history checks, saves counts, and coalesces duplicate starts',async()=>{
 const f=fixture();await Promise.all([f.scanner.start(),f.scanner.start()]);
 assert.equal(f.calls(),1);assert.equal(f.values.browserScan.status,'complete');assert.equal(f.values.browserScan.step,3);assert.equal(f.values.historyReview.matchCount,1);assert.equal(f.values.browserScan.historyCheckedAt,f.values.historyReview.checkedAt);
 assert.ok(!JSON.stringify(f.values).includes('never-retain'));assert.ok(!JSON.stringify(f.values).includes('ordinary.test'));
});
test('denied history permission still reviews extensions without pretending the scan is complete',async()=>{
 const f=fixture(false);await f.scanner.start();assert.equal(f.calls(),0);assert.equal(f.values.browserScan.status,'partial');assert.equal(f.values.browserScan.historyStatus,'permissionNeeded');assert.equal(f.values.historyReview,undefined);
});
test('clearing a running scan prevents late history and progress resurrection',async()=>{
 const f=fixture();let release;f.delay(new Promise(resolve=>{release=resolve;}));const run=f.scanner.start();
 while(!f.calls())await new Promise(resolve=>setTimeout(resolve,0));
 const clear=f.scanner.clear();release();await Promise.all([run,clear]);
 assert.equal(f.values.historyReview,undefined);assert.equal(f.values.browserScan,undefined);
});
test('interrupted scans and expired results cannot count as current completed work',()=>{
 const now=1800000000000;
 assert.equal(currentScan({version:1,status:'scanning',startedAt:now-121000},now).status,'interrupted');
 assert.equal(currentScan({version:1,status:'complete',startedAt:now-8*86400000},now),null);
});
