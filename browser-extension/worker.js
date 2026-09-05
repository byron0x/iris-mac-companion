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
