const tab=await chrome.tabs.getCurrent();
const key='warning:'+tab.id;
const value=(await chrome.storage.session.get(key))[key];
if(value && value.at > Date.now()-86400000){
  document.querySelector('#heading').textContent=value.kind==='blocked'?'IRIS stopped this page.':'This open site is on a scam list.';
  document.querySelector('#host').textContent=value.host;
  document.querySelector('#explanation').textContent=value.kind==='blocked'?'This hostname matches a known crypto-phishing list. The attempted navigation was blocked. If you did not interact with it earlier, this warning alone is not a reason to assume an infection.':'This site was already open when protection checked it. Avoid entering information or signing anything. Use the next steps below if you interacted with it.';
}else{
  document.querySelector('#host').textContent='No recent warning is available for this tab.';
  document.querySelector('#explanation').textContent='Open your dashboard to review recent security activity.';
}
