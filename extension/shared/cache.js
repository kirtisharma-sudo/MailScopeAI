/**
 * shared/cache.js
 *
 * Caches analysis RESULTS keyed by fingerprint, using chrome.storage.local.
 * Deliberately does NOT store raw email content — only:
 *   - the fingerprint (already a one-way hash)
 *   - case_id
 *   - the mapped snapshot fields (risk_score, classification, confidence,
 *     evidence, auth, urls/attachments summary, geo, related_activity)
 *   - the real analysis_timestamp returned by the backend
 *
 * Same fingerprint -> cache hit -> no network call. This mirrors the web
 * app's in-memory SNAPSHOT_CACHE, just backed by chrome.storage.local so
 * it survives across Gmail page navigations within the same browser.
 */
const MAILSCOPE_CACHE_PREFIX = 'mailscope_snapshot_';
const MAILSCOPE_CACHE_MAX_ENTRIES = 200;

async function getCachedSnapshot(fingerprint) {
  const key = MAILSCOPE_CACHE_PREFIX + fingerprint;
  const result = await chrome.storage.local.get(key);
  return result[key] || null;
}

async function setCachedSnapshot(fingerprint, snapshot) {
  const key = MAILSCOPE_CACHE_PREFIX + fingerprint;
  await chrome.storage.local.set({ [key]: snapshot });
  await _enforceCacheCap();
}

async function _enforceCacheCap() {
  const all = await chrome.storage.local.get(null);
  const entries = Object.entries(all)
    .filter(([k]) => k.startsWith(MAILSCOPE_CACHE_PREFIX))
    .map(([k, v]) => ({ key: k, cachedAt: (v && v._cachedAt) || 0 }));
  if (entries.length <= MAILSCOPE_CACHE_MAX_ENTRIES) return;
  entries.sort((a, b) => a.cachedAt - b.cachedAt);
  const toRemove = entries.slice(0, entries.length - MAILSCOPE_CACHE_MAX_ENTRIES).map(e => e.key);
  if (toRemove.length) await chrome.storage.local.remove(toRemove);
}

self.MailScopeCache = { getCachedSnapshot, setCachedSnapshot, MAILSCOPE_CACHE_PREFIX };
