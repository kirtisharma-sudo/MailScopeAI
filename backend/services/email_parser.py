"""
Parses a raw RFC-5322 email (pasted text or .eml upload) using Python's
standard `email` package. Never assumes a header exists — every field is
returned as None/"" when absent rather than fabricated.
"""
from __future__ import annotations
from email import message_from_bytes, message_from_string, policy
from email.message import EmailMessage
from dataclasses import dataclass, field
from utils.sanitization import strip_html_to_text


@dataclass
class ParsedEmail:
    raw_bytes: bytes
    from_addr: str | None = None
    to_addr: str | None = None
    cc: str | None = None
    reply_to: str | None = None
    return_path: str | None = None
    subject: str | None = None
    date: str | None = None
    message_id: str | None = None
    received_headers: list[str] = field(default_factory=list)
    authentication_results: list[str] = field(default_factory=list)
    dkim_signature_headers: list[str] = field(default_factory=list)
    x_originating_ip: str | None = None
    x_mailer: str | None = None
    user_agent: str | None = None
    all_headers: dict = field(default_factory=dict)
    duplicate_headers: list[str] = field(default_factory=list)
    body_text: str = ""
    body_html: str | None = None
    attachments: list[dict] = field(default_factory=list)   # metadata + transient "_bytes" (never serialized to API)
    parse_warnings: list[str] = field(default_factory=list)


def _recover_utf8_if_mojibake(text: str, raw_bytes: bytes | None) -> str:
    """When a part has no declared charset, Python's email package defaults
    to decoding as us-ascii/latin-1 with lossy 'replace' handling, which
    corrupts real UTF-8 text (e.g. pasted Hindi content with no MIME
    headers at all). If the decoded text is suspiciously replacement-heavy
    and we still have the raw bytes, retry decoding them as UTF-8 — this is
    a real, deterministic fix, not a language-specific hack."""
    if not text or not raw_bytes:
        return text
    replacement_ratio = text.count("\ufffd") / max(1, len(text))
    if replacement_ratio < 0.05:
        return text
    try:
        return raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return text


def _get_raw_payload(part) -> bytes | None:
    try:
        payload = part.get_payload(decode=True)
        return payload if isinstance(payload, bytes) else None
    except Exception:
        return None


def _get(msg: EmailMessage, name: str) -> str | None:
    val = msg.get(name)
    return str(val) if val is not None else None


def parse_email(raw: bytes) -> ParsedEmail:
    """raw: the exact bytes supplied by the user (pasted text encoded as utf-8,
    or the uploaded .eml file's bytes). Nothing here fabricates data."""
    warnings: list[str] = []
    try:
        msg = message_from_bytes(raw, policy=policy.default)
    except Exception as exc:  # extremely malformed input
        warnings.append(f"Primary MIME parser failed ({exc}); falling back to lenient text parsing.")
        try:
            msg = message_from_string(raw.decode("utf-8", errors="replace"), policy=policy.default)
        except Exception as exc2:
            # Absolute fallback: treat everything as an unstructured body so we
            # still return *something* rather than crashing the request.
            return ParsedEmail(
                raw_bytes=raw,
                body_text=raw.decode("utf-8", errors="replace"),
                parse_warnings=[f"Could not parse as RFC-5322 email ({exc2}). Treated as plain text body only."],
            )

    body_text = ""
    body_html = None
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            cdisp = str(part.get("Content-Disposition") or "")
            ctype = part.get_content_type()
            if "attachment" in cdisp or part.get_filename():
                try:
                    payload = part.get_payload(decode=True) or b""
                except Exception:
                    payload = b""
                attachments.append({
                    "filename": part.get_filename() or "unnamed",
                    "content_type": ctype,
                    "size_bytes": len(payload),
                    "content_disposition": cdisp or "not_present",
                    "content_transfer_encoding": str(part.get("Content-Transfer-Encoding") or "not_present"),
                    "_bytes": payload,   # transient — used only for hashing, stripped before the API response
                })
                continue
            if ctype == "text/plain" and not body_text:
                try:
                    body_text = part.get_content()
                    body_text = _recover_utf8_if_mojibake(body_text, _get_raw_payload(part))
                except Exception:
                    body_text = ""
            elif ctype == "text/html" and body_html is None:
                try:
                    body_html = part.get_content()
                    body_html = _recover_utf8_if_mojibake(body_html, _get_raw_payload(part))
                except Exception:
                    body_html = None
    else:
        ctype = msg.get_content_type()
        try:
            content = msg.get_content()
            content = _recover_utf8_if_mojibake(content, _get_raw_payload(msg))
        except Exception:
            content = ""
        if ctype == "text/html":
            body_html = content
        else:
            body_text = content

    if not body_text and body_html:
        body_text = strip_html_to_text(body_html)
        warnings.append("No text/plain part found; body_text derived from HTML.")

    received_headers = [str(v) for v in msg.get_all("Received", [])]
    auth_results = [str(v) for v in msg.get_all("Authentication-Results", [])]
    dkim_sig_headers = [str(v) for v in msg.get_all("DKIM-Signature", [])]
    all_headers = {k: str(v) for k, v in msg.items()}

    x_orig_ip = _get(msg, "X-Originating-IP")
    x_mailer = _get(msg, "X-Mailer")
    user_agent = _get(msg, "User-Agent")

    # Detect headers that legitimately should appear at most once but occur
    # more than once — a mild but real forensic signal (header injection /
    # malformed relaying), not proof of anything on its own.
    _single_instance_headers = {"from", "subject", "date", "message-id", "reply-to", "return-path", "to"}
    seen_counts: dict[str, int] = {}
    for k in msg.keys():
        lk = k.lower()
        seen_counts[lk] = seen_counts.get(lk, 0) + 1
    duplicate_headers = [k for k, c in seen_counts.items() if c > 1 and k in _single_instance_headers]

    if not all_headers:
        warnings.append("No RFC-5322 headers detected at all — input may be a body-only paste.")

    return ParsedEmail(
        raw_bytes=raw,
        from_addr=_get(msg, "From"),
        to_addr=_get(msg, "To"),
        cc=_get(msg, "Cc"),
        reply_to=_get(msg, "Reply-To"),
        return_path=_get(msg, "Return-Path"),
        subject=_get(msg, "Subject"),
        date=_get(msg, "Date"),
        message_id=_get(msg, "Message-ID"),
        received_headers=received_headers,
        authentication_results=auth_results,
        dkim_signature_headers=dkim_sig_headers,
        x_originating_ip=x_orig_ip,
        x_mailer=x_mailer,
        user_agent=user_agent,
        all_headers=all_headers,
        duplicate_headers=duplicate_headers,
        body_text=body_text or "",
        body_html=body_html,
        attachments=attachments,
        parse_warnings=warnings,
    )
