/**
 * content/quick-preview.js
 *
 * "MailScope Quick Preview" — a compact hint shown when hovering an
 * UNOPENED row in the Gmail inbox list. This is explicitly NOT an
 * analysis: no backend call is made, no risk score is shown, and no
 * SPF/DKIM/DMARC/geolocation is claimed, because none of that evidence
 * exists until the user opens the email and explicitly scans it (see
 * content/snapshot.js for that real, backend-driven result).
 *
 * The "visible indicators" below are a small, purely lexical check over
 * text already painted in the inbox row (sender/subject/snippet) — not a
 * second detection engine and not a substitute for the backend model.
 * They exist only to make the preview more useful than a blank card.
 */

const MAILSCOPE_QUICKPREVIEW_ID = 'mailscope-quickpreview-card';

// Small, transparent, non-scoring keyword hints. Intentionally coarse —
// these only ever produce descriptive labels, never a number or verdict.
const QP_URGENCY_WORDS = /\b(urgent|immediately|act now|verify now|final notice|action required|suspend(ed)?|expire[sd]?|limited time|last chance)\b/i;
const QP_LURE_WORDS = /\b(internship|congratulations|selected|winner|prize|free|gift card|job offer|work from home|earn \$|claim your)\b/i;
const QP_CRED_WORDS = /\b(password|verify your account|confirm your identity|login|log in|otp|bank account|update your payment|billing)\b/i;

function computeVisibleIndicators(row) {
  const hay = [row.subject || '', row.snippet || ''].join(' ');
  const indicators = [];
  if (QP_URGENCY_WORDS.test(hay)) indicators.push('Urgency / pressure language in subject or preview');
  if (QP_LURE_WORDS.test(hay)) indicators.push('Recruitment / reward lure language');
  if (QP_CRED_WORDS.test(hay)) indicators.push('Requests credentials, login, or payment info');
  if (row.senderEmail && row.senderName && !row.senderEmail.toLowerCase().includes(row.senderName.split(' ')[0].toLowerCase())) {
    // Weak signal only — display name unrelated to the address's local part.
    // Not surfaced as "spoofing"; framed as context to check once opened.
  }
  return indicators;
}

function ensureQuickPreviewElement() {
  let card = document.getElementById(MAILSCOPE_QUICKPREVIEW_ID);
  if (!card) {
    card = document.createElement('div');
    card.id = MAILSCOPE_QUICKPREVIEW_ID;
    card.className = 'mailscope-qp';
    card.setAttribute('role', 'status');
    card.setAttribute('aria-label', 'MailScope Quick Preview');
    document.body.appendChild(card);
  }
  return card;
}

function renderQuickPreview(card, row) {
  const indicators = computeVisibleIndicators(row);
  card.innerHTML = `
    <div class="mailscope-qp-head">🛡 MailScope Quick Preview</div>
    <div class="mailscope-qp-badge">${indicators.length ? 'Potentially Suspicious' : 'No obvious lure language detected'}</div>
    ${row.sender ? `<div class="mailscope-qp-line"><b>Sender:</b> ${_esc(row.sender)}</div>` : ''}
    ${row.subject ? `<div class="mailscope-qp-line"><b>Subject:</b> ${_esc(row.subject)}</div>` : ''}
    ${indicators.length ? '<div class="mailscope-qp-section">Visible indicators:</div>' +
        indicators.map(i => `<div class="mailscope-qp-indicator">• ${_esc(i)}</div>`).join('') : ''}
    <div class="mailscope-qp-disclaimer">Quick Preview — visible-content triage only. No SPF/DKIM/DMARC, infrastructure, or risk score is available until you open and scan this email.</div>
    <div class="mailscope-qp-cta">Open the email, then click "Scan with MailScope" for a full investigation →</div>
  `;
}

function _esc(s) {
  const d = document.createElement('div');
  d.textContent = s == null ? '' : String(s);
  return d.innerHTML;
}

function positionQuickPreview(card, rowEl) {
  const r = rowEl.getBoundingClientRect();
  const vw = window.innerWidth, vh = window.innerHeight;
  const cw = 300;
  let left = Math.min(r.left + 24, vw - cw - 12);
  left = Math.max(12, left);
  let top = r.bottom + 6;
  if (top + 160 > vh) top = Math.max(12, r.top - 166);
  card.style.left = left + 'px';
  card.style.top = top + 'px';
}

function hideQuickPreview() {
  const card = document.getElementById(MAILSCOPE_QUICKPREVIEW_ID);
  if (card) card.classList.remove('show');
}

self.MailScopeQuickPreview = {
  ensureQuickPreviewElement, renderQuickPreview, positionQuickPreview, hideQuickPreview,
};
