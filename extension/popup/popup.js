const gmailStatusEl = document.getElementById('ms-gmail-status');
const currentContentEl = document.getElementById('ms-current-content');
const openInvestigationBtn = document.getElementById('ms-open-investigation');
const scanBtn = document.getElementById('ms-scan');
const backendInput = document.getElementById('ms-backend-input');
const webappInput = document.getElementById('ms-webapp-input');
const saveBtn = document.getElementById('ms-save-settings');
const saveNote = document.getElementById('ms-save-note');

let activeTabId = null;
let lastState = null;

function bandColor(band) {
  return { critical: '#e05a3f', high: '#e0873f', medium: '#e0c23f', low: '#3fe0a0' }[band] || '#93a0c2';
}

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const isGmail = !!(tab && tab.url && tab.url.startsWith('https://mail.google.com/'));
  gmailStatusEl.textContent = isGmail ? '● Connected' : '○ Not on Gmail';
  gmailStatusEl.className = 'ms-status ' + (isGmail ? 'connected' : 'disconnected');

  if (!isGmail || !tab) {
    currentContentEl.textContent = 'Open Gmail to use MailScope.';
    return;
  }
  activeTabId = tab.id;

  chrome.tabs.sendMessage(tab.id, { type: 'MAILSCOPE_GET_CURRENT_STATE' }, (response) => {
    if (chrome.runtime.lastError || !response || !response.ok) {
      currentContentEl.textContent = 'MailScope is not active on this page yet. Try reloading Gmail.';
      return;
    }
    lastState = response;
    renderState(response);
  });

  const cfg = await new Promise((resolve) => chrome.runtime.sendMessage({ type: 'MAILSCOPE_GET_CONFIG' }, resolve));
  if (cfg && cfg.ok) {
    backendInput.value = cfg.backendBase;
    webappInput.value = cfg.webAppUrl;
  }
}

function renderState(state) {
  if (!state.hasOpenEmail) {
    currentContentEl.textContent = 'No email currently open in Gmail.';
    openInvestigationBtn.style.display = 'none';
    scanBtn.style.display = 'none';
    return;
  }
  if (state.cached) {
    const c = state.cached;
    currentContentEl.innerHTML =
      '<div>' + (state.subject || '(no subject)') + '</div>' +
      '<div class="risk-line" style="color:' + bandColor(c.band) + '">' + c.classification + ' \u00b7 ' + c.risk_score + '/100</div>';
    openInvestigationBtn.style.display = 'block';
    scanBtn.style.display = 'none';
    openInvestigationBtn.onclick = () => {
      chrome.runtime.sendMessage({ type: 'MAILSCOPE_OPEN_INVESTIGATION', caseId: c.case_id });
    };
  } else {
    currentContentEl.textContent = 'No MailScope analysis for this email.';
    openInvestigationBtn.style.display = 'none';
    scanBtn.style.display = 'block';
    scanBtn.onclick = () => {
      scanBtn.textContent = 'Analyzing...';
      scanBtn.disabled = true;
      chrome.tabs.sendMessage(activeTabId, { type: 'MAILSCOPE_SCAN_CURRENT' }, (res) => {
        scanBtn.disabled = false;
        scanBtn.textContent = 'Scan with MailScope';
        if (res && res.ok) {
          chrome.tabs.sendMessage(activeTabId, { type: 'MAILSCOPE_GET_CURRENT_STATE' }, (r2) => {
            if (r2 && r2.ok) renderState(r2);
          });
        }
      });
    };
  }
}

saveBtn.addEventListener('click', async () => {
  const backend = backendInput.value.trim();
  const webapp = webappInput.value.trim();
  if (backend) await chrome.storage.local.set({ mailscope_backend_base: backend });
  if (webapp) await chrome.storage.local.set({ mailscope_webapp_url: webapp });
  saveNote.textContent = 'Saved.';
  setTimeout(() => { saveNote.textContent = ''; }, 1800);
});

init();
