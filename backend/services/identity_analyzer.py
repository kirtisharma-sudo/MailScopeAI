"""
Cross-compares every domain observed in the message (From, Reply-To,
Return-Path, Message-ID, and URL destinations) and reports lookalike
patterns on the SENDER domain itself (distinct from url_analyzer's
per-URL lookalike check, which only looks at link destinations).

Conservative by design: a lookalike match is reported as an observation
with a severity, never as a certainty that the domain is malicious.
"""
from services.url_analyzer import looks_lookalike_of_brand


def _domain_of(addr: str | None) -> str | None:
    if not addr or "@" not in addr:
        return None
    return addr.split("@")[-1].strip().strip(">").lower()


def compare_identity_domains(from_addr, reply_to, return_path, message_id, url_domains: list[str]) -> dict:
    """Returns an explicit, explainable comparison table — useful even when
    no single anomaly rises to the level of a scored signal."""
    from_domain = _domain_of(from_addr)
    reply_domain = _domain_of(reply_to)
    return_path_domain = _domain_of(return_path)
    message_id_domain = None
    if message_id and "@" in message_id:
        message_id_domain = message_id.split("@")[-1].strip().strip(">").lower()

    distinct_url_domains = sorted(set(d for d in url_domains if d))

    return {
        "from_domain": from_domain or "not_available",
        "reply_to_domain": reply_domain or "not_available",
        "return_path_domain": return_path_domain or "not_available",
        "message_id_domain": message_id_domain or "not_available",
        "url_domains": distinct_url_domains or "not_available",
        "from_reply_to_match": (from_domain == reply_domain) if (from_domain and reply_domain) else "not_available",
        "from_return_path_match": (from_domain == return_path_domain) if (from_domain and return_path_domain) else "not_available",
        "from_message_id_match": (from_domain == message_id_domain) if (from_domain and message_id_domain) else "not_available",
        "from_matches_any_url_domain": (from_domain in distinct_url_domains) if (from_domain and distinct_url_domains) else "not_available",
    }


def identity_signals(from_addr: str | None) -> list[dict]:
    """Checks whether the VISIBLE SENDER domain itself looks like a brand
    impersonation attempt (e.g. 'paypal-security.com'), independent of any
    URL in the body."""
    from_domain = _domain_of(from_addr)
    if not from_domain:
        return []
    brand = looks_lookalike_of_brand(from_domain)
    if not brand:
        return []
    return [{
        "name": "sender_domain_lookalike",
        "severity": "high",
        "weight": 16,
        "explanation": f"The visible sender domain ('{from_domain}') contains the brand name '{brand}' but does not appear to be that brand's official domain.",
        "brand": brand,
    }]
