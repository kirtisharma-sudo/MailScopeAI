import re

# Patterns for things that must never be forwarded to an external NLP/AI API
# or written to logs. This is deliberately conservative (over-redact rather
# than under-redact).
_SECRET_PATTERNS = [
    re.compile(r"\b\d{6}\b"),                                   # 6-digit OTP-style codes
    re.compile(r"(?i)\bpassword\s*[:=]\s*\S+"),
    re.compile(r"(?i)\botp\s*[:=]?\s*\d{4,8}"),
    re.compile(r"(?i)\bapi[_-]?key\s*[:=]\s*[\w\-]{8,}"),
    re.compile(r"(?i)\b(bearer|token)\s+[\w\-.]{10,}"),
    re.compile(r"\b(?:\d[ -]*?){13,19}\b"),                     # credit-card-like digit runs
    re.compile(r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
]


def redact_secrets(text: str) -> str:
    """Best-effort redaction of credentials/OTP/secret-like substrings before
    the text is sent to any external inference/API call or logged."""
    redacted = text
    for pat in _SECRET_PATTERNS:
        redacted = pat.sub("[REDACTED]", redacted)
    return redacted


def strip_html_to_text(html: str) -> str:
    """Very small, dependency-free HTML→text fallback used when bs4/lxml are
    unavailable. Never executes scripts or renders the HTML."""
    text = re.sub(r"(?is)<script.*?</script>", " ", html)
    text = re.sub(r"(?is)<style.*?</style>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def sanitize_analyst_note(text: str, max_len: int = 4000) -> str:
    """Strips ALL HTML/script content from analyst-supplied notes before
    they're stored or ever rendered — notes are plain text only, no markup,
    no script execution, regardless of what's typed in."""
    if not text:
        return ""
    plain = strip_html_to_text(text)
    return plain[:max_len]


def safe_log_snippet(text: str, max_len: int = 120) -> str:
    """Redact + truncate for logging. Never log full email content."""
    return redact_secrets(text)[:max_len]
