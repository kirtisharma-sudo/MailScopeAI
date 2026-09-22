# MailScope AI — Judge Demo Guide

**SIH26106 · Developer-mode judging installation.**
This is a developer-mode install for SIH judging. It does **not** require
Chrome Web Store installation, and it does **not** require our laptop or any
local server to be running — the extension talks to our **live deployed
backend** at `https://mailscope-api.onrender.com`.

---

## REQUIREMENTS

- Google Chrome
- Internet connection
- A Gmail account

---

## INSTALLATION

1. Download the MailScope extension ZIP.
2. Extract it.
3. Open `chrome://extensions`.
4. Enable **Developer mode** (toggle, top-right).
5. Click **Load unpacked**.
6. Select the extracted `extension` folder.
7. Pin **MailScope AI** to the toolbar (puzzle-piece icon → pin).

No API key, no login, no OAuth, no payment.

> **First scan may take up to ~50 seconds.** The backend is on Render's free
> tier and sleeps when idle, so the very first request has to wake it. Every
> scan after that is fast. To pre-warm it, open
> `https://mailscope-api.onrender.com/api/health` in a tab before the demo.

---

## DEMO

1. Open Gmail.
2. Open the prepared suspicious email.
3. Click **Scan with MailScope**.
4. Wait for the analysis to complete.
5. Show the **Security Snapshot** — risk score, classification, confidence
   and the top evidence signals.
6. Click **View Full Investigation**.
7. Show the investigation view for that case.
8. Show **Trace Origin / Timeline** if available.
9. Optionally scan the second prepared related email.
10. Show **Potentially Related Activity** if the backend returns it.

Two synthetic demo emails are included in `demo/`:

| File | Theme |
|---|---|
| `demo-email-A-internship.eml` | Fake internship offer — lookalike sender domain, urgency, suspicious URL, fee request |
| `demo-email-B-hr-verification.eml` | Fake HR document verification — shares a **Reply-To domain and relay IP** with Email A |

Because B shares indicators with A, scanning **A first, then B** is what makes
related-activity correlation appear.

To use them: send each `.eml` body to your own Gmail account (or paste the
content into a Gmail draft/message you open), then scan it in place.

---

## WHAT IS REAL

Everything shown in the snapshot is returned by the live backend:

- Risk score, classification and confidence are **computed by the backend**,
  not hardcoded in the extension.
- Evidence signals are derived from the email's actual headers, authentication
  results (SPF/DKIM/DMARC), URLs and attachments.
- Nothing is faked in the UI.

## PRIVACY BEHAVIOUR (worth pointing out to judges)

- **Opening or hovering an email sends nothing.** Analysis happens *only* when
  **Scan with MailScope** is explicitly clicked.
- Re-opening an already-scanned email is served from a local cache
  (`chrome.storage.local`) — **no repeat network call**.
- The cache stores only the analysis result and a one-way SHA-256 fingerprint.
  **Raw email content is never stored.**
- Permissions are deliberately narrow: `storage` and `activeTab` only, plus
  host access to the MailScope backend. No `<all_urls>`, no Gmail OAuth
  scopes, no history, no cookies.
- The extension contains **no API keys or secrets** — all threat-intelligence
  credentials stay server-side.

---

## TROUBLESHOOTING

| Symptom | Fix |
|---|---|
| First scan hangs ~50s | Render free-tier cold start — wait, or pre-warm `/api/health` |
| "Analysis failed" | Check internet; confirm `https://mailscope-api.onrender.com/api/health` returns `{"status":"ok"}`, then click Retry |
| Scan button missing | Refresh the Gmail tab (the content script injects on load) |
| Want to point at a local backend | Open the popup → Backend field → `http://127.0.0.1:8000` → Save Settings |

**Note on "View Full Investigation":** the full investigation web app is not
publicly deployed yet, so this button currently opens the live backend's
forensic report for that case (`/api/reports/<case_id>`) — real data from the
same deployed backend. Once the web app is hosted, set its URL once in the
popup's second settings field (or in `shared/config.js`) and the button deep
-links into the full UI instead. No other change is needed.
