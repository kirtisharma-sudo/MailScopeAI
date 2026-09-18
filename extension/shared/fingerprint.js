/**
 * shared/fingerprint.js
 *
 * Same technique as the existing web app's sha256Hex() in
 * mailscope-ai-v5.html: SHA-256 via the browser's native Web Crypto API.
 * No custom/insecure hashing.
 */

async function mailscopeSha256Hex(text) {
  const enc = new TextEncoder().encode(text);
  const buf = await crypto.subtle.digest('SHA-256', enc);
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Builds a deterministic fingerprint for a normalized Gmail email object
 * (see gmail-adapter.js's getCurrentEmail() shape). Preferred: hash the
 * raw email if genuinely available (rawEmailAvailable === true). Gmail's
 * rendered DOM does NOT expose the raw RFC-5322 source in the MVP scrape
 * path, so in practice this falls back to hashing the canonicalized
 * normalized fields actually obtained — sender + subject + body text —
 * which is still deterministic and still prevents duplicate analysis of
 * the same message.
 */
async function fingerprintEmail(email) {
  const canonical = email.rawEmailAvailable && email.raw
    ? email.raw.trim().replace(/\r\n/g, '\n')
    : [email.sender || '', email.subject || '', (email.body || '').trim()].join('\u0001');
  return mailscopeSha256Hex(canonical);
}

self.MailScopeFingerprint = { sha256Hex: mailscopeSha256Hex, fingerprintEmail };
