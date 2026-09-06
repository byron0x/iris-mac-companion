// Account checks contain no browser history, extension list, or wallet secrets.
const ENDPOINT='https://app.undercoveriris.io/api/companion-access';
export function currentAccess(value,now=Date.now()) {
  return value?.version===1 && ['free','pro','god_mode'].includes(value.plan) && typeof value.monitoring==='boolean' && typeof value.unlimited==='boolean' && Number.isSafeInteger(value.validUntil) && value.validUntil>now && value.validUntil<=now+330000;
}
export function createAccess(browser,fetchImpl=fetch,now=Date.now) {
  let checking;
  async function request(body,token) {
    const r=await fetchImpl(ENDPOINT,{method:'POST',credentials:'omit',headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},body:JSON.stringify(body),signal:AbortSignal.timeout(15000)});
    const value=await r.json();
    if(!r.ok)throw Object.assign(Error(value.error || 'Your plan could not be checked.'),{status:r.status});
    return value;
  }
  async function status(force=false) {
    const {companionAccount:c,companionAccess:a}=await browser.storage.local.get(['companionAccount','companionAccess']);
    if(!c||c.expiresAt<=now())throw Error('Connect your IRIS account once to start a scan. Saved results and cleanup stay available.');
    if(!force&&currentAccess(a,now()))return a;
    if(!checking)checking=request({kind:'browser',id:c.id,action:'status'},c.token).then(async value=>{
      const current=await browser.storage.local.get('companionAccount');if(current.companionAccount?.id!==c.id||!currentAccess(value,now()))throw Error('Your account connection changed.');
      await browser.storage.local.set({companionAccess:value});return value;
    }).finally(()=>{checking=null;});
    return checking;
  }
  async function claim(ticket) {
    if(!/^[A-Za-z0-9_-]{43}$/.test(ticket||''))throw Error('Invalid account invitation.');
    const c=await request({action:'claimBrowser',ticket});
    if(!/^[a-f0-9]{32}$/.test(c.id||'')||!/^[A-Za-z0-9_-]{43}$/.test(c.token||'')||!Number.isSafeInteger(c.expiresAt)||c.expiresAt<=now())throw Error('Invalid account response.');
    await browser.storage.local.remove('companionAccess');await browser.storage.local.set({companionAccount:c});
    return status(true);
  }
  async function reserve() {
    const {companionAccount:c,scanRequestID:prior}=await browser.storage.local.get(['companionAccount','scanRequestID']);
    if(!c||c.expiresAt<=now())throw Error('Connect your IRIS account to start your monthly scan or use Pro.');
    const runId=/^[a-f0-9-]{36}$/.test(prior||'')?prior:crypto.randomUUID();
    await browser.storage.local.set({scanRequestID:runId});
    const a=await request({kind:'browser',id:c.id,action:'reserve',runId},c.token);
    const current=await browser.storage.local.get('companionAccount');if(current.companionAccount?.id!==c.id||!currentAccess(a,now()))throw Error('Your account connection changed.');
    await browser.storage.local.set({companionAccess:a}); return a;
  }
  async function disconnect() {
    const {companionAccount:c}=await browser.storage.local.get('companionAccount');
    await browser.storage.local.remove(['companionAccount','companionAccess','scanRequestID']);
    if(c)await request({kind:'browser',id:c.id,action:'disconnect'},c.token).catch(()=>{});
  }
  return {status,claim,reserve,disconnect};
}
