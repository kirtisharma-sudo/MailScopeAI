"""
Deterministic preprocessing: raw (subject, body[, is_html]) -> single model
input string. Intentionally self-contained (no import from backend/) so the
ml/ pipeline can run standalone for dataset prep/training without the
FastAPI app's config/env requirements.

Design goals (SECTION 5):
- Never destroy phishing-relevant signal: URLs, urgency language, and
  suspicious phrasing are preserved verbatim.
- Deterministic: same input always produces the same output (required for
  reproducible splits/dedup).
- Bounded: very long emails are truncated with an explicit, visible marker
  rather than crashing the tokenizer or silently losing the truncation fact.
"""
from __future__ import annotations
import re
import hashlib

MAX_CHARS_DEFAULT = 4000  # generous relative to DeBERTa's typical 512-token window;
                          # the tokenizer truncates further at train/inference time.
TRUNCATION_MARKER = " …[TRUNCATED]"


def strip_html(html: str) -> str:
    """Small, dependency-free HTML→text conversion. Removes tags but keeps
    all visible text (including link text), and does not execute anything."""
    if not html:
        return ""
    text = re.sub(r"(?is)<script.*?</script>", " ", html)
    text = re.sub(r"(?is)<style.*?</style>", " ", text)
    text = re.sub(r"(?is)<(br|p|div|li|tr)\b[^>]*>", "\n", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def looks_like_html(body: str) -> bool:
    if not body:
        return False
    return bool(re.search(r"(?is)<(html|body|div|table|p|br|a\s+href)", body))


def normalize_whitespace(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n[ \t]+", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def build_model_text(subject: str | None, body: str | None, max_chars: int = MAX_CHARS_DEFAULT) -> str:
    """Combines subject + body into the exact model input format (SECTION 5):

        [SUBJECT]
        <subject>
        [BODY]
        <body>

    Missing subject/body are represented explicitly, never silently dropped
    (an empty [SUBJECT] block is itself potentially meaningful signal).
    """
    subject = (subject or "").strip()
    body = body or ""

    if looks_like_html(body):
        body = strip_html(body)
    body = normalize_whitespace(body)
    subject = normalize_whitespace(subject)

    text = f"[SUBJECT]\n{subject if subject else '(no subject)'}\n[BODY]\n{body if body else '(empty body)'}"

    if len(text) > max_chars:
        text = text[:max_chars].rstrip() + TRUNCATION_MARKER

    return text


def content_hash(text: str) -> str:
    """Used for duplicate detection (SECTION 6/7) — deterministic, based on
    the FINAL preprocessed text so near-duplicate raw records that normalize
    to the same text are still caught."""
    normalized = re.sub(r"\s+", " ", text).strip().lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
