/**
 * shared/config.js
 *
 * Backend URL configuration. No secrets, no API keys — MailScope's
 * /api/analyze endpoint does not require authentication in this
 * prototype, matching the existing web app (mailscope-ai-v5.html),
 * which calls the same endpoint the same way.
 *
 * Default: local dev backend (matches the web app's default
 * MAILSCOPE_API_BASE). Override via the popup's Settings field, which
 * writes to chrome.storage.local under 'mailscope_backend_base' —
 * checked first, before falling back to this default.
 */
const MAILSCOPE_DEFAULT_BACKEND = 'http://127.0.0.1:8000';
const MAILSCOPE_DEFAULT_WEBAPP = 'http://127.0.0.1:5500/mailscope-ai-v5.html';

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
