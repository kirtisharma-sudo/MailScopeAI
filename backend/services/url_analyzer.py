"""
Extracts URLs from plain text and HTML (including anchor href vs visible
text mismatches), then applies deterministic, explainable heuristics.
Nothing here claims a URL is "malicious" — only that specific structural
indicators were observed.
"""
import re
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s\"'<>()]+", re.I)
HREF_RE = re.compile(r'<a\b[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.I | re.S)
IP_HOST_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

SUSPICIOUS_TLDS = {"zip", "xyz", "top", "gq", "tk", "ml", "cf", "work", "click", "country", "kim"}
KNOWN_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"}
COMMON_BRANDS = ["google", "microsoft", "paypal", "amazon", "apple", "facebook", "instagram", "bankofamerica", "netflix", "irctc", "sbi", "hdfc"]


STANDARD_PORTS = {None, 80, 443}
# Naive "registered domain" approximation: last two labels. This is NOT a
# real public-suffix-list implementation (e.g. it mishandles co.uk-style
# multi-part TLDs) — documented limitation, not silently assumed correct.
def _naive_registered_domain(domain: str) -> str:
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def looks_lookalike_of_brand(domain: str) -> str | None:
    """Exported so identity/domain-comparison code (sender/reply-to/message-id
    domains) can reuse the exact same conservative check used for URLs."""
    return _looks_lookalike(domain)


def _strip_tags(html_fragment: str) -> str:
    return re.sub(r"<[^>]+>", "", html_fragment).strip()


def extract_urls(body_text: str, body_html: str | None) -> list[dict]:
    """Returns raw (url, visible_text) pairs before analysis is applied."""
    found: dict[str, str | None] = {}

    for m in URL_RE.finditer(body_text or ""):
        found.setdefault(m.group(0), None)

    if body_html:
        for m in HREF_RE.finditer(body_html):
            href, inner = m.group(1), _strip_tags(m.group(2))
            found[href] = inner or found.get(href)
        for m in URL_RE.finditer(body_html):
            found.setdefault(m.group(0), None)

    return [{"url": u, "visible_text": v} for u, v in found.items()]


def _looks_lookalike(domain: str) -> str | None:
    """Very conservative check: domain contains a known brand name but is
    NOT that brand's actual domain (e.g. 'paypal-secure-login.com')."""
    core = domain.split(".")[0].lower()
    for brand in COMMON_BRANDS:
        if brand in core and core != brand:
            return brand
    return None


def analyze_urls(body_text: str, body_html: str | None) -> list[dict]:
    raw = extract_urls(body_text, body_html)
    analyzed = []
    for entry in raw:
        url = entry["url"]
        visible = entry["visible_text"]
        try:
            parsed = urlparse(url)
        except Exception:
            parsed = None

        domain = parsed.hostname.lower() if parsed and parsed.hostname else None
        notes = []
        is_ip_based = bool(domain and IP_HOST_RE.match(domain))
        is_shortener = bool(domain and domain in KNOWN_SHORTENERS)
        tld = domain.split(".")[-1] if domain and "." in domain else None
        suspicious_tld = bool(tld and tld in SUSPICIOUS_TLDS)
        lookalike = _looks_lookalike(domain) if domain else None
        obfuscated = bool(re.search(r"%[0-9a-fA-F]{2}", url)) or "xn--" in (domain or "")
        subdomain_count = max(0, (domain.count(".") - 1)) if domain and not is_ip_based else 0
        excessive_subdomains = subdomain_count >= 3
        port = parsed.port if parsed else None
        unusual_port = bool(port and port not in STANDARD_PORTS)
        registered_domain = _naive_registered_domain(domain) if domain else None

        if is_ip_based:
            notes.append("Destination host is a raw IP address rather than a domain name.")
        if is_shortener:
            notes.append("URL uses a known link-shortening service; the real destination is hidden.")
        if suspicious_tld:
            notes.append(f"TLD '.{tld}' is frequently associated with low-cost, low-verification registrations (not proof of malicious intent on its own).")
        if lookalike:
            notes.append(f"Domain contains the brand name '{lookalike}' but does not appear to be that brand's official domain.")
        if obfuscated:
            notes.append("URL contains percent-encoding or punycode, which can be used to obscure the real destination.")
        if excessive_subdomains:
            notes.append(f"Domain has an unusually high number of subdomain labels ({subdomain_count}), a pattern sometimes used to obscure the true registered domain.")
        if unusual_port:
            notes.append(f"URL specifies a non-standard port ({port}).")
        if visible and domain and visible.strip().lower() not in (url.lower(), domain.lower()) and ("http" in visible or "." in visible):
            notes.append(f"Visible link text ('{visible.strip()[:60]}') does not match the actual destination domain.")

        analyzed.append({
            "url": url,
            "visible_text": visible,
            "domain": domain,
            "is_ip_based": is_ip_based,
            "is_shortener": is_shortener,
            "suspicious_tld": suspicious_tld,
            "obfuscated": obfuscated,
            "lookalike_of": lookalike,
            "notes": notes,
            # --- additive forensic fields (SECTION 7) ---
            "normalized_url": url.strip().rstrip("/"),
            "scheme": parsed.scheme if parsed else "not_available",
            "path": (parsed.path or "/") if parsed else "not_available",
            "query": parsed.query if parsed else "not_available",
            "port": port if port else ("443 (default)" if (parsed and parsed.scheme == "https") else "80 (default)" if parsed else "not_available"),
            "registered_domain": registered_domain or "not_available",
            "subdomain_count": subdomain_count,
            "excessive_subdomains": excessive_subdomains,
            "unusual_port": unusual_port,
        })
    return analyzed


def url_signals(urls: list[dict]) -> list[dict]:
    signals = []
    for u in urls:
        if u["lookalike_of"]:
            signals.append({"name": "lookalike_domain", "severity": "high", "weight": 15,
                             "explanation": f"URL to '{u['domain']}' appears to imitate the brand '{u['lookalike_of']}'.",
                             "brand": u["lookalike_of"]})
        if u["is_ip_based"]:
            signals.append({"name": "ip_based_url", "severity": "medium", "weight": 9,
                             "explanation": f"Link points directly to an IP address ({u['domain']}) instead of a domain name."})
        if u["is_shortener"]:
            signals.append({"name": "url_shortener", "severity": "low", "weight": 5,
                             "explanation": f"Link uses the shortening service '{u['domain']}', hiding the real destination."})
        if u["notes"] and any("does not match" in n for n in u["notes"]):
            signals.append({"name": "visible_text_mismatch", "severity": "high", "weight": 12,
                             "explanation": "Visible link text does not match where the link actually goes."})
        if u.get("excessive_subdomains"):
            signals.append({"name": "excessive_subdomains", "severity": "medium", "weight": 8,
                             "explanation": f"URL domain '{u['domain']}' has an unusually high number of subdomain labels."})
        if u.get("unusual_port"):
            signals.append({"name": "unusual_port", "severity": "medium", "weight": 7,
                             "explanation": f"URL '{u['url']}' specifies a non-standard port."})
    return signals
