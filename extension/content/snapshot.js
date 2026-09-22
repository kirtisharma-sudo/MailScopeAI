/**
 * content/snapshot.js
 *
 * Renders the compact "MailScope Security Snapshot" floating card inside
 * the Gmail page. Presentation only — every value it shows comes from
 * shared/api.js's mapAnalyzeResponse() output (backend-derived), never
 * computed here. Mirrors the wording/labels used by the existing web
 * app's snapshot (mailscope-ai-v5.html) for a consistent product feel.
 */

const MAILSCOPE_CARD_ID = 'mailscope-snapshot-card';

function ensureCardElement() {
  let card = document.getElementById(MAILSCOPE_CARD_ID);
  if (!card) {
    card = document.createElement('div');
    card.id = MAILSCOPE_CARD_ID;
    card.className = 'mailscope-card';
    card.setAttribute('role', 'dialog');
    card.setAttribute('aria-label', 'MailScope Security Snapshot');
    card.tabIndex = -1;
    document.body.appendChild(card);
    card.addEventListener('mouseenter', () => { window.__mailscopeCancelHide && window.__mailscopeCancelHide(); });
    card.addEventListener('mouseleave', () => { window.__mailscopeScheduleHide && window.__mailscopeScheduleHide(); });
  }
  return card;
}

function bandLabel(band) {
  return { critical: '🔴 HIGH RISK', high: '🟠 HIGH RISK', medium: '🟡 MEDIUM RISK', low: '🟢 LOW RISK' }[band] || '⚪ UNKNOWN';
}
function bandColor(band) {
  return { critical: '#e05a3f', high: '#e0873f', medium: '#e0c23f', low: '#3fe0a0' }[band] || '#93a0c2';
}

function authRowHtml(label, status) {
  const s = status || 'unavailable';
  let color = '#93a0c2', text = 'UNAVAILABLE';
  if (s === 'pass') { color = '#3fe0a0'; text = 'PASS'; }
  else if (s === 'fail') { color = '#e0873f'; text = 'FAIL'; }
  else if (s === 'unavailable') { color = '#93a0c2'; text = 'UNAVAILABLE'; }
  else { color = '#e0c23f'; text = s.toUpperCase(); }
  return `<div class="mailscope-auth-row"><span>${label}</span><span style="color:${color};font-weight:700;">${text}</span></div>`;
}

function headerHtml(showClose) {
  return `<div class="mailscope-head">
    <span class="mailscope-title">🛡 MailScope Security Snapshot</span>
    ${showClose ? '<span class="mailscope-close" data-mailscope-action="close" tabindex="0" role="button" aria-label="Close">✕</span>' : ''}
  </div>`;
}

function renderEmptyState(card, opts) {
  card.innerHTML = `
    ${headerHtml(true)}
    <div class="mailscope-empty">
      <div class="mailscope-empty-title">Analysis not available</div>
      <div class="mailscope-empty-desc">Scan this email with MailScope to generate a security snapshot.</div>
      <button class="mailscope-btn" data-mailscope-action="scan">Scan with MailScope</button>
      <div class="mailscope-privacy">Email content is sent for analysis only when you choose to scan.</div>
    </div>`;
  card.querySelector('[data-mailscope-action="scan"]').addEventListener('click', opts.onScan);
  card.querySelector('[data-mailscope-action="close"]').addEventListener('click', () => window.__mailscopeCloseNow && window.__mailscopeCloseNow());
}

function renderLoadingState(card) {
  card.innerHTML = `
    ${headerHtml(false)}
    <div class="mailscope-loading"><span class="mailscope-spinner"></span>Analyzing email...</div>`;
}

function renderErrorState(card, opts) {
  card.innerHTML = `
    ${headerHtml(true)}
    <div class="mailscope-empty">
      <div class="mailscope-empty-title">Analysis could not be completed.</div>
      <button class="mailscope-btn" data-mailscope-action="retry">Retry Scan</button>
    </div>`;
  card.querySelector('[data-mailscope-action="retry"]').addEventListener('click', opts.onRetry);
  card.querySelector('[data-mailscope-action="close"]').addEventListener('click', () => window.__mailscopeCloseNow && window.__mailscopeCloseNow());
}

function renderReadyState(card, snapshot, opts) {
  const geoLine = snapshot.geo
    ? [snapshot.geo.country, snapshot.geo.region, snapshot.geo.city, snapshot.geo.isp]
        .filter(v => v && v !== 'unavailable').join(' · ') || 'Geolocation unavailable'
    : 'Geolocation unavailable';

  const relatedLine = snapshot.related_activity.locked
    ? '🔒 Sentinel feature'
    : (snapshot.related_activity.count > 0
        ? snapshot.related_activity.count + ' potentially related case' + (snapshot.related_activity.count === 1 ? '' : 's')
        : 'None found');

  const analyzedWhen = snapshot.analysis_timestamp ? new Date(snapshot.analysis_timestamp).toLocaleString() : 'Analyzed just now';

  card.innerHTML = `
    ${headerHtml(true)}
    <div class="mailscope-risk-row">
      <span style="color:${bandColor(snapshot.band)};font-weight:800;font-size:13px;">${bandLabel(snapshot.band)}</span>
      <span style="color:${bandColor(snapshot.band)};font-weight:800;font-family:monospace;font-size:15px;">${snapshot.risk_score}/100</span>
    </div>
    <div class="mailscope-classification">${snapshot.classification} · ${snapshot.confidence}% confidence · <span style="opacity:.6;">${analyzedWhen}</span></div>

    ${snapshot.top_evidence.length ? '<div class="mailscope-section"><div class="mailscope-section-title">Why this email is flagged</div>' + snapshot.top_evidence.map(e => '<div class="mailscope-evidence-item">• ' + e + '</div>').join('') + '</div>' : ''}

    <div class="mailscope-section">
      <div class="mailscope-section-title">Authentication</div>
      ${authRowHtml('SPF', snapshot.auth.spf)}
      ${authRowHtml('DKIM', snapshot.auth.dkim)}
      ${authRowHtml('DMARC', snapshot.auth.dmarc)}
    </div>

    ${(snapshot.suspicious_url_count > 0 || snapshot.suspicious_attachment) ? '<div class="mailscope-section">' +
      (snapshot.suspicious_url_count > 0 ? '<div class="mailscope-line">⚠ Suspicious URL detected' + (snapshot.suspicious_url_count > 1 ? ' (' + snapshot.suspicious_url_count + ')' : '') + '</div>' : '') +
      (snapshot.suspicious_attachment ? '<div class="mailscope-line">⚠ Suspicious attachment detected</div>' : '') +
      '</div>' : ''}

    <div class="mailscope-section">
      <div class="mailscope-section-title">Observed Infrastructure</div>
      <div class="mailscope-line">${geoLine}</div>
      <div class="mailscope-disclaimer">Geolocation reflects observed network infrastructure and does not establish attacker identity or physical location.</div>
    </div>

    <div class="mailscope-section">
      <div class="mailscope-section-title">Related Activity</div>
      <div class="mailscope-line">${relatedLine}</div>
    </div>

    <button class="mailscope-btn mailscope-cta" data-mailscope-action="investigate">View Full Investigation →</button>
  `;
  card.querySelector('[data-mailscope-action="investigate"]').addEventListener('click', opts.onViewInvestigation);
  card.querySelector('[data-mailscope-action="close"]').addEventListener('click', () => window.__mailscopeCloseNow && window.__mailscopeCloseNow());
}

function positionCard(card, anchorEl) {
  const r = anchorEl.getBoundingClientRect();
  const vw = window.innerWidth, vh = window.innerHeight;
  if (vw <= 720) return; // mobile: CSS pins it as a bottom sheet
  const cw = 328;
  let left = r.right + 12;
  if (left + cw > vw - 12) left = Math.max(12, r.left - cw - 12);
  const top = Math.min(Math.max(12, r.top), vh - 100);
  card.style.left = left + 'px';
  card.style.top = top + 'px';
  card.style.maxHeight = Math.max(160, vh - top - 12) + 'px';
}

self.MailScopeSnapshot = {
  ensureCardElement, renderEmptyState, renderLoadingState, renderErrorState, renderReadyState, positionCard,
};
