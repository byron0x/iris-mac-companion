import test from 'node:test';
import assert from 'node:assert/strict';
import { checkLink, reviewHistory, updateBadge } from '../protection.mjs';
import { createService, WEB_ORIGIN } from '../service.mjs';
test('phishing matching uses the actual exact hostname and never treats no match as a verdict', () => {
  const domains = new Set(['danger.example','xn--bcher-kva.example']);
  assert.equal(checkLink('https://DANGER.example./claim?seed=never-upload', domains).match, true);
  assert.equal(checkLink('https://danger.example@safe.example', domains).match, false);
  assert.equal(checkLink('https://safe.example/danger.example', domains).match, false);
  assert.equal(checkLink('https://sub.danger.example', domains).match, false);
  assert.equal(checkLink('https://bücher.example', domains).match, true);
  assert.equal(checkLink('file:///private/secrets', domains).host, null);
  assert.equal(checkLink('javascript:alert(1)', domains).host, null);
});
test('recent review retains only matched hostnames, deduplicates and reports caps', () => {
  const report = reviewHistory([{url:'https://danger.example/path?secret=one'},{url:'https://danger.example/other'},{url:'https://normal.example/private'}],new Set(['danger.example']),1800000000000,3);
  assert.equal(report.matchCount,1); assert.equal(report.checkedCount,3); assert.equal(report.partial,true);
  assert.deepEqual(report.matches,[{host:'danger.example',lastVisit:0}]);
  assert.ok(!JSON.stringify(report).includes('secret'));
});
test('web sharing receives counts only and expired history is removed', async () => {
  const now=1800000000000; const local={sharing:{origin:WEB_ORIGIN,expiresAt:now+1000},extensionWatch:true,historyReview:{checkedAt:now-1,checkedCount:2,matchCount:1,partial:false,matches:[{host:'private.example'}]}};
  const browser={runtime:{id:'a'.repeat(32)},management:{getAll:async()=>[]},storage:{local:{get:async()=>structuredClone(local),remove:async key=>delete local[key]}}};
  const service=createService(browser,()=>now);
  const shared=await service.external({version:1,action:'report'},{url:WEB_ORIGIN+'/device',frameId:0});
  assert.equal(shared.report.security.history.matchCount,1); assert.ok(!JSON.stringify(shared).includes('private.example'));
  local.historyReview.checkedAt=now-8*86400000;
  assert.equal((await service.report()).security.history,null); assert.equal(local.historyReview,undefined);
});
test('monitoring badge is opt-in and counts reviews rather than malware', async () => {
  let enabled=false; const calls=[]; const browser={storage:{local:{get:async()=>({extensionWatch:enabled})}},action:{setBadgeText:async v=>calls.push(v.text),setBadgeBackgroundColor:async()=>{},setTitle:async()=>{}}};
  await updateBadge(browser,{extensions:[{priority:'review'}]}); assert.equal(calls.at(-1),'');
  enabled=true; await updateBadge(browser,{extensions:[{priority:'review'}]}); assert.equal(calls.at(-1),'1');
});
