/**
 * shared/config.js
 *
 * SINGLE SOURCE OF TRUTH for MailScope URLs. No secrets, no API keys —
 * MailScope's /api/analyze endpoint does not require authentication in
 * this prototype, matching the existing web app (mailscope-ai-v5.html),
 * which calls the same endpoint the same way.
 *
 * Both values below are overridable at runtime from the popup's Settings
 * fields, which write to chrome.storage.local — those stored values are
 * checked FIRST, before falling back to these defaults. For local
 * development, set the backend field to http://127.0.0.1:8000 in the
 * popup (the localhost host_permissions in manifest.json are retained
 * for exactly that purpose).
 */

// Production default: the live deployed MailScope backend on Render.
// Judges need no local server — this works out of the box.
const MAILSCOPE_DEFAULT_BACKEND = 'https://mailscope-api.onrender.com';

// The full investigation web app (mailscope-ai-v5.html) is now publicly
// deployed on GitHub Pages. "View Full Investigation" deep-links here
// with ?case=<id>. If this ever becomes unset/unreachable, the
// background worker falls back to the live backend's forensic report
// endpoint (GET /api/reports/{case_id}) — real backend data, never
// localhost. See background/service-worker.js.
const MAILSCOPE_DEFAULT_WEBAPP = 'https://kirtisharma-sudo.github.io/SIH26/frontend/mailscope-ai-v5.html';

async function getBackendBase() {
  try {
    const stored = await chrome.storage.local.get('mailscope_backend_base');
    return stored.mailscope_backend_base || MAILSCOPE_DEFAULT_BACKEND;
  } catch (err) {
    return MAILSCOPE_DEFAULT_BACKEND;
  }
}

async function setBackendBase(url) {
  await chrome.storage.local.set({ mailscope_backend_base: url });
}

async function getWebAppUrl() {
  try {
    const stored = await chrome.storage.local.get('mailscope_webapp_url');
    return stored.mailscope_webapp_url || MAILSCOPE_DEFAULT_WEBAPP;
  } catch (err) {
    return MAILSCOPE_DEFAULT_WEBAPP;
  }
}

async function setWebAppUrl(url) {
  await chrome.storage.local.set({ mailscope_webapp_url: url });
}

// Exposed for use in non-module contexts (content scripts load as classic
// scripts, not ES modules, so these are attached to the shared global).
self.MailScopeConfig = { getBackendBase, setBackendBase, getWebAppUrl, setWebAppUrl, MAILSCOPE_DEFAULT_BACKEND, MAILSCOPE_DEFAULT_WEBAPP };
