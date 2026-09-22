/**
 * content/content.js
 *
 * Orchestrates the MailScope shield + snapshot card inside Gmail.
 * Depends only on the normalized gmail-adapter.js interface (never a raw
 * Gmail selector directly), shared/fingerprint.js, and the background
 * service worker for the actual /api/analyze call. No independent risk
 * logic lives here.
 */
(function () {
  let currentEmail = null;
  let currentFingerprint = null;
  let hideTimer = null;
  let scanInFlight = false;
  let shieldEl = null;
  let lastObservedMessageEl = null;

  const isHoverCapable = window.matchMedia('(hover: hover)').matches;

  function scheduleHide() {
    clearTimeout(hideTimer);
    hideTimer = setTimeout(() => {
      const card = document.getElementById('mailscope-snapshot-card');
      if (card) card.classList.remove('show');
    }, 220);
  }
  function cancelHide() { clearTimeout(hideTimer); }
  function closeNow() {
    clearTimeout(hideTimer);
    const card = document.getElementById('mailscope-snapshot-card');
    if (card) card.classList.remove('show');
  }
  window.__mailscopeScheduleHide = scheduleHide;
  window.__mailscopeCancelHide = cancelHide;
  window.__mailscopeCloseNow = closeNow;

  async function openSnapshot(anchorEl) {
    cancelHide();
    const email = self.MailScopeGmailAdapter.getCurrentEmail();
    if (!email) return;
    currentEmail = email;
    currentFingerprint = await self.MailScopeFingerprint.fingerprintEmail(email);

    const card = self.MailScopeSnapshot.ensureCardElement();
    const cached = await getCachedSnapshotLocal(currentFingerprint);

    if (cached) {
      self.MailScopeSnapshot.renderReadyState(card, cached, { onViewInvestigation: () => viewFullInvestigation(cached.case_id) });
    } else {
      self.MailScopeSnapshot.renderEmptyState(card, { onScan: () => runScan(email, currentFingerprint) });
    }
    card.classList.add('show');
    self.MailScopeSnapshot.positionCard(card, anchorEl);
  }

  async function getCachedSnapshotLocal(fingerprint) {
    try {
      const result = await self.MailScopeCache.getCachedSnapshot(fingerprint);
      return result;
    } catch (err) {
      return null;
    }
  }
  async function setCachedSnapshotLocal(fingerprint, snapshot) {
    try { await self.MailScopeCache.setCachedSnapshot(fingerprint, snapshot); } catch (err) { /* non-fatal */ }
  }

  async function runScan(email, fingerprint) {
    if (scanInFlight) return; // never trigger a second concurrent analysis for the same interaction
    scanInFlight = true;
    // Use ensureCardElement() rather than getElementById(): a scan can be
    // triggered from the popup (MAILSCOPE_SCAN_CURRENT) before the in-page
    // card has ever been opened/created, in which case getElementById
    // would return null and the next render() call would throw
    // "Cannot set properties of null (setting 'innerHTML')".
    const card = self.MailScopeSnapshot.ensureCardElement();
    currentFingerprint = fingerprint;
    self.MailScopeSnapshot.renderLoadingState(card);
    if (!card.classList.contains('show')) {
      // Scan was triggered from the popup, not a shield hover/click, so
      // the card was never positioned/shown. Anchor it to the shield if
      // one exists on the page, else let CSS's default fixed position
      // stand, and reveal it so the result is actually visible in Gmail.
      if (shieldEl && document.body.contains(shieldEl)) {
        self.MailScopeSnapshot.positionCard(card, shieldEl);
      }
      card.classList.add('show');
    }

    const emailText = self.MailScopeGmailAdapter.buildAnalyzableText(email);
    chrome.runtime.sendMessage({ type: 'MAILSCOPE_ANALYZE', emailText }, async (response) => {
      scanInFlight = false;
      if (chrome.runtime.lastError || !response || !response.ok) {
        self.MailScopeSnapshot.renderErrorState(card, { onRetry: () => runScan(email, fingerprint) });
        return;
      }
      await setCachedSnapshotLocal(fingerprint, response.snapshot);
      // Only render if this snapshot is still the one the user is looking at.
      const stillCurrent = currentFingerprint === fingerprint;
      if (stillCurrent) {
        self.MailScopeSnapshot.renderReadyState(card, response.snapshot, {
          onViewInvestigation: () => viewFullInvestigation(response.snapshot.case_id),
        });
      }
    });
  }

  function viewFullInvestigation(caseId) {
    if (!caseId) return;
    chrome.runtime.sendMessage({ type: 'MAILSCOPE_OPEN_INVESTIGATION', caseId });
    closeNow();
  }

  function injectShield(mountEl) {
    if (!mountEl || mountEl.querySelector('.mailscope-shield-btn')) return; // already injected for this message
    const shield = document.createElement('span');
    shield.className = 'mailscope-shield-btn';
    shield.title = 'MailScope Security Snapshot';
    shield.setAttribute('role', 'button');
    shield.setAttribute('aria-label', 'MailScope Security Snapshot');
    shield.tabIndex = 0;
    shield.textContent = '🛡';
    mountEl.appendChild(shield);
    shieldEl = shield;

    if (isHoverCapable) {
      shield.addEventListener('mouseenter', () => openSnapshot(shield));
      shield.addEventListener('mouseleave', scheduleHide);
    }
    shield.addEventListener('click', () => openSnapshot(shield));
    shield.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openSnapshot(shield); }
    });
  }

  function checkForOpenMessage() {
    const messageEl = self.MailScopeGmailAdapter.getOpenMessageElement();
    if (!messageEl) return;
    if (messageEl === lastObservedMessageEl) return;
    lastObservedMessageEl = messageEl;
    const mount = self.MailScopeGmailAdapter.getShieldMountPoint();
    injectShield(mount);
  }

  // Gmail is a single-page app; poll lightly (debounced) rather than
  // wiring a heavy MutationObserver across the whole page. This never
  // triggers analysis — it only decides whether to show the shield icon.
  let pollTimer = null;
  const observer = new MutationObserver(() => {
    clearTimeout(pollTimer);
    pollTimer = setTimeout(checkForOpenMessage, 250);
  });
  observer.observe(document.body, { childList: true, subtree: true });
  checkForOpenMessage();

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeNow();
  });

  // ---- Hover Quick Preview (unopened inbox rows) ----------------------
  // Passive, event-delegated, debounced. Never calls the backend, never
  // reads anything beyond what getInboxRowSummary() exposes (visible
  // sender/subject/snippet/time). Purely additive listeners — no
  // preventDefault/stopPropagation anywhere here, so Gmail's own click,
  // select, open, compose, hover-card and scroll behavior is untouched.
  if (isHoverCapable && self.MailScopeQuickPreview) {
    let qpTimer = null;
    let qpHideTimer = null;
    let qpCurrentRow = null;

    function qpShowFor(rowEl) {
      const row = self.MailScopeGmailAdapter.getInboxRowSummary(rowEl);
      if (!row) return;
      const card = self.MailScopeQuickPreview.ensureQuickPreviewElement();
      self.MailScopeQuickPreview.renderQuickPreview(card, row);
      self.MailScopeQuickPreview.positionQuickPreview(card, rowEl);
      card.classList.add('show');
    }

    document.body.addEventListener('mouseover', (e) => {
      const row = e.target.closest && e.target.closest(self.MailScopeGmailAdapter.GMAIL_SELECTORS.inboxRow);
      if (!row) return;
      if (row === qpCurrentRow) { clearTimeout(qpHideTimer); return; }
      qpCurrentRow = row;
      clearTimeout(qpTimer);
      clearTimeout(qpHideTimer);
      // Debounce so rapid mouse travel across many rows doesn't flicker
      // a preview for every row passed over.
      qpTimer = setTimeout(() => { qpShowFor(row); }, 380);
    }, { passive: true });

    document.body.addEventListener('mouseout', (e) => {
      const row = e.target.closest && e.target.closest(self.MailScopeGmailAdapter.GMAIL_SELECTORS.inboxRow);
      if (!row || row !== qpCurrentRow) return;
      // Only hide once the pointer actually leaves the row (not just a
      // child-element boundary) to avoid flicker.
      if (row.contains(e.relatedTarget)) return;
      qpCurrentRow = null;
      clearTimeout(qpTimer);
      clearTimeout(qpHideTimer);
      qpHideTimer = setTimeout(() => self.MailScopeQuickPreview.hideQuickPreview(), 150);
    }, { passive: true });

    // Opening an email, scrolling, or starting a compose should never
    // leave a stale preview on screen.
    document.body.addEventListener('mousedown', () => self.MailScopeQuickPreview.hideQuickPreview(), { passive: true });
    window.addEventListener('scroll', () => self.MailScopeQuickPreview.hideQuickPreview(), { passive: true, capture: true });
  }

  // Lets popup.js ask "what's the state for whatever email is currently open in this tab?"
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message?.type === 'MAILSCOPE_GET_CURRENT_STATE') {
      (async () => {
        const email = self.MailScopeGmailAdapter.getCurrentEmail();
        if (!email) { sendResponse({ ok: true, hasOpenEmail: false }); return; }
        const fingerprint = await self.MailScopeFingerprint.fingerprintEmail(email);
        const cached = await getCachedSnapshotLocal(fingerprint);
        sendResponse({ ok: true, hasOpenEmail: true, subject: email.subject, sender: email.sender, fingerprint, cached });
      })();
      return true;
    }
    if (message?.type === 'MAILSCOPE_SCAN_CURRENT') {
      (async () => {
        const email = self.MailScopeGmailAdapter.getCurrentEmail();
        if (!email) { sendResponse({ ok: false, error: 'No email open in this tab.' }); return; }
        const fingerprint = await self.MailScopeFingerprint.fingerprintEmail(email);
        await runScan(email, fingerprint);
        sendResponse({ ok: true });
      })();
      return true;
    }
  });
})();
