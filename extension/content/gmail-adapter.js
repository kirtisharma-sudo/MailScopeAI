/**
 * content/gmail-adapter.js
 *
 * Isolates ALL Gmail-specific DOM logic. Nothing else in the extension
 * should reference a Gmail CSS selector directly — everything else talks
 * to the normalized getCurrentEmail() shape, so a future Outlook/other
 * adapter can be dropped in without touching snapshot.js or content.js.
 *
 * HONESTY NOTE (see also README.md "Known limitations"): Gmail's rendered
 * DOM does not expose the raw RFC-5322 source of a message (no Received
 * chain, no raw Authentication-Results, no raw Message-ID header, no
 * attachment bytes/hashes). This adapter only reads what is genuinely
 * visible in the page. Every field below is either populated from a real
 * DOM read or left null/empty — nothing here is invented. For full
 * forensic depth (headers, SPF/DKIM/DMARC, relay chain, attachment
 * hashing), the existing MailScope .eml upload / paste-email workflow in
 * the web app remains the authoritative path — see README.md.
 *
 * Gmail's DOM/class names are unstable and can change without notice;
 * the selectors below reflect Gmail's structure at the time of writing
 * and should be re-verified against a live Gmail account before demo.
 */

const GMAIL_SELECTORS = {
  openMessage: 'div.adn.ads',              // an expanded message container
  senderNode: 'span.gD',                   // has [email] and [name] attributes
  subjectNode: 'h2.hP',
  bodyNode: 'div.a3s.aiL',
  timeNode: 'span.g3',
  attachmentNameNodes: 'span.aV3',
  toolbarAnchor: 'div.iH',                 // area near the open message's action row (reply/forward icons)

  // Inbox LIST rows (unopened emails) — used only for the Quick Preview.
  // These render nothing forensic; only what's already painted in the list.
  inboxRow: 'tr.zA',
  inboxRowSenderName: 'span.yP, span.zF',  // has [email] attribute
  inboxRowSubject: 'span.bog',
  inboxRowSnippet: 'span.y2',
  inboxRowTime: 'td.xW span[title]',
};

function _text(el) { return el ? el.textContent.trim() : ''; }

function _extractLinks(bodyEl) {
  if (!bodyEl) return [];
  return Array.from(bodyEl.querySelectorAll('a[href]'))
    .map(a => a.getAttribute('href'))
    .filter(href => href && /^https?:\/\//i.test(href));
}

function _extractAttachmentNames(messageEl) {
  if (!messageEl) return [];
  return Array.from(messageEl.querySelectorAll(GMAIL_SELECTORS.attachmentNameNodes))
    .map(el => _text(el))
    .filter(Boolean);
}

/**
 * Returns the currently-open Gmail message container, or null if no
 * message is open (e.g. user is looking at the inbox list).
 */
function getOpenMessageElement() {
  const nodes = document.querySelectorAll(GMAIL_SELECTORS.openMessage);
  return nodes.length ? nodes[nodes.length - 1] : null; // last = most recently expanded
}

/**
 * Normalized interface. Only populates fields that are genuinely
 * available from the Gmail DOM right now — never fabricates headers,
 * IPs, authentication results, or timestamps.
 */
function getCurrentEmail() {
  const messageEl = getOpenMessageElement();
  if (!messageEl) return null;

  const senderEl = messageEl.querySelector(GMAIL_SELECTORS.senderNode);
  const subjectEl = document.querySelector(GMAIL_SELECTORS.subjectNode);
  const bodyEl = messageEl.querySelector(GMAIL_SELECTORS.bodyNode);
  const timeEl = messageEl.querySelector(GMAIL_SELECTORS.timeNode);

  const senderEmail = senderEl ? senderEl.getAttribute('email') : null;
  const senderName = senderEl ? senderEl.getAttribute('name') : null;
  const bodyText = _text(bodyEl);

  return {
    sender: senderEmail || senderName || null,
    senderName: senderName || null,
    recipients: [], // not reliably exposed in the collapsed header row without extra clicks; left empty rather than guessed
    subject: subjectEl ? _text(subjectEl) : null,
    body: bodyText || null,
    links: _extractLinks(bodyEl),
    attachments: _extractAttachmentNames(messageEl),
    messageId: null, // Gmail's DOM does not expose the RFC Message-ID header — never fabricated
    gmailInternalId: messageEl.getAttribute('data-legacy-message-id') || messageEl.getAttribute('data-message-id') || null,
    displayedTime: timeEl ? (timeEl.getAttribute('title') || _text(timeEl)) : null,
    rawEmailAvailable: false, // Gmail's rendered DOM never exposes raw RFC-5322 source
    raw: null,
    source: 'gmail',
  };
}

/**
 * Builds the plain-text payload actually sent to /api/analyze — the SAME
 * "email_text" field format the web app's paste-email flow already uses
 * (From/Subject header lines + a blank line + body), constructed only
 * from fields getCurrentEmail() genuinely found. This is not a real raw
 * email (no Received/Authentication-Results/Message-ID are invented) —
 * the backend's header/auth analyzers will correctly report those as
 * unavailable, exactly as they do for any header-less pasted text today.
 */
function buildAnalyzableText(email) {
  const lines = [];
  if (email.sender) lines.push(`From: ${email.sender}`);
  if (email.subject) lines.push(`Subject: ${email.subject}`);
  lines.push('');
  lines.push(email.body || '');
  if (email.links && email.links.length) {
    lines.push('');
    lines.push(email.links.join('\n'));
  }
  return lines.join('\n');
}

/**
 * Finds a stable place near the open message's action row to inject the
 * MailScope shield control. Falls back gracefully if Gmail's layout
 * doesn't match the expected selector.
 */
function getShieldMountPoint() {
  const messageEl = getOpenMessageElement();
  if (!messageEl) return null;
  return messageEl.querySelector(GMAIL_SELECTORS.toolbarAnchor) || messageEl;
}

/**
 * Reads ONLY what's already visible for an unopened inbox row (list view).
 * Used by the hover Quick Preview — never triggers a backend call and
 * never reads anything the opened-message path would (no body, no links,
 * no attachments, no headers). Returns null if the row isn't recognized.
 */
function getInboxRowSummary(rowEl) {
  if (!rowEl || !rowEl.matches || !rowEl.matches(GMAIL_SELECTORS.inboxRow)) return null;
  const senderEl = rowEl.querySelector(GMAIL_SELECTORS.inboxRowSenderName);
  const subjectEl = rowEl.querySelector(GMAIL_SELECTORS.inboxRowSubject);
  const snippetEl = rowEl.querySelector(GMAIL_SELECTORS.inboxRowSnippet);
  const timeEl = rowEl.querySelector(GMAIL_SELECTORS.inboxRowTime);
  const senderEmail = senderEl ? senderEl.getAttribute('email') : null;
  const senderName = senderEl ? (senderEl.getAttribute('name') || _text(senderEl)) : null;
  if (!senderName && !subjectEl) return null; // not a real row (e.g. a divider)
  return {
    sender: senderEmail || senderName || null,
    senderName: senderName || null,
    senderEmail: senderEmail || null,
    subject: subjectEl ? _text(subjectEl) : null,
    snippet: snippetEl ? _text(snippetEl) : null,
    displayedTime: timeEl ? (timeEl.getAttribute('title') || _text(timeEl)) : null,
    source: 'gmail-inbox-row',
  };
}

self.MailScopeGmailAdapter = {
  getCurrentEmail, buildAnalyzableText, getShieldMountPoint, getOpenMessageElement,
  getInboxRowSummary, GMAIL_SELECTORS,
};
