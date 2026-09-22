/**
 * background/service-worker.js
 *
 * Two jobs only:
 *   1. Perform the /api/analyze call on behalf of content scripts. A
 *      Gmail content script's fetch() is bound by mail.google.com's CORS
 *      policy; a fetch from this background context, with host_permissions
 *      for the backend origin (see manifest.json), is not — so this is
 *      where the actual network call happens. No new analysis logic here,
 *      just relaying to the EXISTING /api/analyze and reshaping the
 *      response with the shared mapper.
 *   2. Open "View Full Investigation" as a deep link into the existing
 *      web app (mailscope-ai-v5.html), passing ?case=<case_id> so that
 *      app can fetch the same case from the backend's existing
 *      GET /api/reports/{case_id} and render it with its OWN existing
 *      investigation UI — no second investigation page is created here.
 */
importScripts('../shared/config.js', '../shared/api.js');

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === 'MAILSCOPE_ANALYZE') {
    (async () => {
      try {
        const backendBase = await self.MailScopeConfig.getBackendBase();
        const api = await self.MailScopeApi.callAnalyze(backendBase, message.emailText);
        const snapshot = self.MailScopeApi.mapAnalyzeResponse(api);
        sendResponse({ ok: true, snapshot });
      } catch (err) {
        sendResponse({ ok: false, error: String(err && err.message ? err.message : err) });
      }
    })();
    return true; // keep the message channel open for the async response
  }

  if (message?.type === 'MAILSCOPE_OPEN_INVESTIGATION') {
    (async () => {
      const webAppUrl = await self.MailScopeConfig.getWebAppUrl();
      let url;
      if (webAppUrl) {
        // Configured full investigation UI — deep link with ?case=<id>,
        // which that app resolves via GET /api/reports/{case_id}.
        url = webAppUrl + (webAppUrl.includes('?') ? '&' : '?') + 'case=' + encodeURIComponent(message.caseId);
      } else {
        // No frontend deployed yet (see shared/config.js). Rather than
        // breaking the button or sending judges to localhost, open the
        // EXISTING live backend report endpoint for this case — same
        // case data, served by the same deployed backend.
        const backendBase = await self.MailScopeConfig.getBackendBase();
        url = backendBase.replace(/\/$/, '') + '/api/reports/' + encodeURIComponent(message.caseId);
      }
      chrome.tabs.create({ url });
      sendResponse({ ok: true });
    })();
    return true;
  }

  if (message?.type === 'MAILSCOPE_GET_CONFIG') {
    (async () => {
      const backendBase = await self.MailScopeConfig.getBackendBase();
      const webAppUrl = await self.MailScopeConfig.getWebAppUrl();
      sendResponse({ ok: true, backendBase, webAppUrl });
    })();
    return true;
  }
});
