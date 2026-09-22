/**
 * shared/api.js
 *
 * Talks to the SAME /api/analyze endpoint the existing web app
 * (mailscope-ai-v5.html) already uses, with the same request shape
 * (multipart/form-data, field name "email_text"). This file does not
 * reimplement risk scoring, classification, or confidence — it only
 * calls the backend and reshapes its response for the compact snapshot
 * card. The backend remains the single source of truth.
 *
 * The actual fetch happens in the background service worker (see
 * background/service-worker.js) — a Gmail content script's fetch() is
 * subject to the PAGE's CORS policy, but a request made from the
 * extension's background context with host_permissions for the backend
 * origin is not, so no backend CORS configuration changes were needed.
 */

async function mailscopeCallAnalyze(backendBase, emailText) {
  const fd = new FormData();
  fd.append('email_text', emailText);
  const res = await fetch(backendBase.replace(/\/$/, '') + '/api/analyze', {
    method: 'POST',
    body: fd,
  });
  if (!res.ok) {
    let detail = 'HTTP ' + res.status;
    try { const b = await res.json(); detail = b.detail || detail; } catch (_) {}
    throw new Error(detail);
  }
  return res.json();
}

/**
 * Maps a raw /api/analyze response into the compact snapshot shape.
 * Mirrors the field selection already used by the web app's
 * mapApiToEmail() (mailscope-ai-v5.html) — same signal-sorting, same
 * pass/fail/unavailable handling, same "observed infrastructure" wording
 * — kept intentionally small since the popup/snapshot card only needs a
 * subset of what the full investigation page renders.
 */
function mailscopeMapAnalyzeResponse(api) {
  const topEvidence = (api.signals || [])
    .slice()
    .sort((a, b) => (b.weight || 0) - (a.weight || 0))
    .slice(0, 3)
    .map(s => s.explanation);

  const urls = api.urls || [];
  const suspiciousUrlCount = urls.filter(u => u.lookalike_of || u.is_ip_based || (u.notes && u.notes.length)).length;

  const attachments = api.attachments || [];
  const suspiciousAttachment = attachments.some(a => a.indicators && a.indicators.length > 0);

  const infra = (api.infrastructure && api.infrastructure[0]) || null;
  const geo = infra
    ? { country: infra.country, region: infra.region, city: infra.city, isp: infra.isp, asn: infra.asn }
    : null;

  const relatedActivity = api.related_activity || { locked: true, related_cases: [] };

  return {
    case_id: api.case_id,
    classification: api.classification,
    risk_score: api.risk_score,
    confidence: api.confidence,
    band: api.risk_score >= 75 ? 'critical' : api.risk_score >= 50 ? 'high' : api.risk_score >= 25 ? 'medium' : 'low',
    top_evidence: topEvidence,
    auth: {
      spf: (api.authentication && api.authentication.spf) || 'unavailable',
      dkim: (api.authentication && api.authentication.dkim) || 'unavailable',
      dmarc: (api.authentication && api.authentication.dmarc) || 'unavailable',
    },
    suspicious_url_count: suspiciousUrlCount,
    suspicious_attachment: suspiciousAttachment,
    geo,
    related_activity: {
      locked: !!relatedActivity.locked,
      count: relatedActivity.locked ? 0 : (relatedActivity.related_cases || []).length,
      cases: relatedActivity.locked ? [] : (relatedActivity.related_cases || []),
    },
    analysis_timestamp: (api.evidence && api.evidence.analysis_timestamp) || null,
    _cachedAt: Date.now(),
  };
}

self.MailScopeApi = { callAnalyze: mailscopeCallAnalyze, mapAnalyzeResponse: mailscopeMapAnalyzeResponse };
