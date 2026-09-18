# MailScope AI — Chrome Extension (MVP)

An **interface/adapter layer** on top of the existing MailScope AI backend and
web app. It is **not** a second forensic engine — every risk score,
classification, confidence value, and evidence item shown here comes from the
same `/api/analyze` and `/api/reports/{case_id}` endpoints the web app
(`mailscope-ai-v5.html`) already uses.

```
GMAIL
  ↓
MailScope Chrome Extension (content script: reads the open message's DOM)
  ↓
MailScope Security Snapshot (compact card — presentation only)
  ↓
Explicit user click: "Scan with MailScope"
  ↓
EXISTING POST /api/analyze   (called from background/service-worker.js)
  ↓
EXISTING MailScope forensic engine (risk_engine.py, auth_analyzer.py, etc. — unmodified)
  ↓
"View Full Investigation →" → EXISTING web app, opened at ?case=<id>
```

## Structure

```
extension/
├── manifest.json              Manifest V3
├── background/service-worker.js   Performs the /api/analyze fetch (bypasses Gmail-page CORS), opens deep links
├── content/
│   ├── gmail-adapter.js       ALL Gmail DOM selectors live here — nowhere else
│   ├── snapshot.js            Compact card renderer (presentation only)
│   ├── content.js             Orchestrator: shield injection, hover/click state machine, cache
│   └── styles.css             Scoped 'mailscope-' prefixed styles
├── popup/                     Small status popup (not a second dashboard)
├── shared/
│   ├── config.js              Backend URL + web app URL, stored in chrome.storage.local
│   ├── fingerprint.js         SHA-256 fingerprinting (same technique as the web app's sha256Hex)
│   └── cache.js                chrome.storage.local cache helpers, used by content.js
├── icons/                     Placeholder icons (replace before shipping)
└── README.md                  this file
```

## Install (Developer Mode)

1. Start the MailScope backend (`cd backend && uvicorn app:app --reload --port 8000`).
2. Open `chrome://extensions`, enable **Developer Mode**.
3. **Load unpacked** → select the `extension/` folder.
4. Open Gmail. Open any email. A small 🛡 shield icon should appear near the message's action row.
5. Click the popup icon to check backend URL settings (defaults to `http://127.0.0.1:8000` and `http://127.0.0.1:5500/mailscope-ai-v5.html` — change these if your backend/web app run elsewhere).

## Permissions — and why each one is needed

| Permission | Why |
|---|---|
| `storage` | Caches fingerprint → analysis result in `chrome.storage.local`, so re-opening an already-scanned email is instant and never re-calls the backend. No raw email content is stored. |
| `activeTab` | Only active while the popup is open, to check whether the current tab is Gmail and relay a status query to the content script. No background tab access. |
| `host_permissions` (backend origin only) | Lets the background service worker call `/api/analyze` / `/api/reports` without being blocked by Gmail's page-level CORS policy. This is why the fetch happens in `background/service-worker.js`, not in `content.js` directly. |

**Explicitly not requested:** `cookies`, `history`, `webRequest`, the broad `tabs` permission, `scripting`, `downloads`, `notifications`, or any Gmail OAuth scope. No OAuth flow was implemented in this phase, per the instruction not to spend the SIH timeline on it.

## Privacy

Hovering/opening an email **never** sends anything to the backend. Only clicking **"Scan with MailScope"** does — the same rule already enforced in the web app's Inbox feature. The card always shows: *"Email content is sent for analysis only when you choose to scan."*

## Fingerprinting & cache

`SHA-256` via `crypto.subtle.digest`, same technique as the web app. Gmail's rendered DOM does not expose the raw RFC-5322 source of a message, so the fingerprint is computed over the normalized fields actually read (sender + subject + body text) rather than a true raw-byte hash — this is documented in `shared/fingerprint.js` rather than silently pretended to be a raw-email hash. It is still fully deterministic: the same displayed email always produces the same fingerprint, and a different email always produces a different one.

## "View Full Investigation" — how the deep link works

This was the specific point called out as previously fragile. The button sends `MAILSCOPE_OPEN_INVESTIGATION` to the background worker, which opens the **existing** `mailscope-ai-v5.html` at `?case=<case_id>`. A small, additive block was added to the web app (search for `EXTENSION DEEP LINK` in `mailscope-ai-v5.html`) that, on load, checks for `?case=`, fetches that case from the **existing** `GET /api/reports/{case_id}`, reshapes it back into the exact object shape `/api/analyze` already returns, and hands it to the **existing** `mapApiToEmail()` + `resultsHTML()` — no second investigation view was built. Trace Origin, the Investigation Timeline, and everything else on that page work identically for a deep-linked case, because it's the same rendering path as a normal in-app analysis.

## Known limitations (honest, not hidden)

- **Not tested against a live Gmail account.** This was built and verified in a sandboxed environment with no internet access to `mail.google.com`. The `gmail-adapter.js` selectors (`span.gD`, `h2.hP`, `div.a3s.aiL`, etc.) reflect Gmail's DOM structure as documented/commonly used at the time of writing, but Gmail's class names are known to change without notice and **must be re-verified against a real Gmail inbox** before a live demo. If a selector is stale, `getCurrentEmail()` degrades gracefully (returns `null` for that field, never a fabricated one) rather than crashing, but the shield may simply fail to appear until selectors are corrected.
- **No raw email access.** Gmail's DOM does not expose Received headers, raw `Authentication-Results`, a true `Message-ID`, or attachment bytes. The backend correctly reports these as `unavailable` (not `fail`) for extension-sourced scans — full forensic depth still requires the existing `.eml` upload / paste-email workflow in the web app.
- **No dedicated JS test suite.** Like the web app's own frontend features, this extension has no unit-test framework in the repo (the project's 148 automated tests are all backend/pytest, unaffected by this addition). Verification here was done by syntax-checking every file (`node --check`) and by exercising the shared backend contract end-to-end (deep-link fetch → `mapApiToEmail` → `resultsHTML`, confirmed via headless browser against the real backend).
- **Popup's "Scan" button re-derives the current email from the DOM at click time** — if Gmail has navigated to a different message between opening the popup and clicking Scan, it will scan whatever is currently open, not a stale snapshot.
- **Recipients field** is intentionally left empty (`[]`) — Gmail's collapsed header row doesn't reliably expose the full "To" list without extra clicks, and it was left unpopulated rather than guessed.
