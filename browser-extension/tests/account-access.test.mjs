import test from 'node:test';
import assert from 'node:assert/strict';
import {createAccess,currentAccess} from '../account-access.mjs';
const now=1800000000000;
const status={version:1,plan:'free',unlimited:false,monitoring:false,remaining:1,checkedAt:now,validUntil:now+300000,resetsAt:now+86400000};
function fixture(){
 const state={companionAccount:{id:'a'.repeat(32),token:'t'.repeat(43),expiresAt:now+86400000}};
 const browser={storage:{local:{get:async()=>structuredClone(state),set:async data=>Object.assign(state,data),remove:async keys=>{for(const k of [].concat(keys))delete state[k]}}}};
 return {state,browser};
}
test('account checks reuse only short-lived verified access, never send history, and retain retry IDs',async()=>{
 const {state,browser}=fixture();let calls=0,request;
 const access=createAccess(browser,async(url,options)=>{calls++;request=JSON.parse(options.body);assert.equal(url,'https://app.undercoveriris.io/api/companion-access');assert.equal(options.credentials,'omit');assert.equal(Object.hasOwn(request,'history'),false);return {ok:true,json:async()=>status}},()=>now);
 await access.status();await access.status();assert.equal(calls,1);
 await access.reserve();const id=request.runId;await access.reserve();assert.equal(request.runId,id);
 await access.disconnect();assert.equal(state.companionAccount,undefined);assert.equal(state.scanRequestID,undefined);
 await assert.rejects(access.reserve(),/Connect/);
});
test('downgrades, plan outages and account switches never reuse indefinite Pro access',async()=>{
 const {state,browser}=fixture();state.companionAccess={...status,plan:'pro',unlimited:true,monitoring:true,validUntil:now-1};
 assert.equal(currentAccess(state.companionAccess,now),false);assert.equal(currentAccess({...status,validUntil:now+86400000},now),false);
 const denied=createAccess(browser,async()=>({ok:false,status:402,json:async()=>({error:'Monthly scan used'})}),()=>now);
 await assert.rejects(denied.reserve(),{status:402});assert.ok(state.scanRequestID);
 const switched=createAccess(browser,async()=>{delete state.companionAccount;return {ok:true,json:async()=>status}},()=>now);
 await assert.rejects(switched.status(true),/connection changed/);
});
