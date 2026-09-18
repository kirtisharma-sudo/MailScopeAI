"""
Reconstructs the OBSERVABLE relay path from `Received` headers and flags
header-level anomalies. Deliberately conservative terminology throughout —
see project brief: never say "attacker IP", only "earliest observable
external IP" / "observed relay" / "associated infrastructure".

Each raw finding is computed once (_raw_findings) and exposed in two shapes:
- header_signals()            -> flat {name,severity,weight,explanation} shape
                                  consumed by risk_engine.py (existing, unchanged contract)
- header_forensic_findings()  -> richer {type,severity,title,description,
                                  evidence,source} shape for the new forensic
                                  evidence API field (additive, doesn't
                                  replace anything the frontend already reads)
"""
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from services.email_parser import ParsedEmail

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
HOSTNAME_RE = re.compile(r"from\s+([a-zA-Z0-9.\-]+)")
BY_RE = re.compile(r"by\s+([a-zA-Z0-9.\-]+)")
DATE_TAIL_RE = re.compile(r";\s*(.+)$")
PROTOCOL_RE = re.compile(r"\bwith\s+([A-Za-z0-9/.\-]+)")
DKIM_D_RE = re.compile(r"\bd=([\w.\-]+)", re.I)

PRIVATE_IP_PREFIXES = ("10.", "127.", "192.168.")


def _is_private_ip(ip: str) -> bool:
    if ip.startswith(PRIVATE_IP_PREFIXES):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            return 16 <= second <= 31
        except (IndexError, ValueError):
            return False
    return False


def _domain_of(addr: str | None) -> str | None:
    if not addr or "@" not in addr:
        return None
    return addr.split("@")[-1].strip().strip(">").lower()


def reconstruct_relay_path(parsed: ParsedEmail) -> list[dict]:
    """Received headers are listed newest-first by convention; we reverse them
    to approximate chronological (sender → recipient) order. This is a
    best-effort reconstruction, not a guaranteed accurate one — the notes
    field on each hop, and `chain_reliability`, say so explicitly."""
    hops = []
    headers_chronological = list(reversed(parsed.received_headers))
    for idx, header in enumerate(headers_chronological):
        ip_matches = IP_RE.findall(header)
        public_ips = [ip for ip in ip_matches if not _is_private_ip(ip)]
        from_host = HOSTNAME_RE.search(header)
        by_host = BY_RE.search(header)
        date_tail = DATE_TAIL_RE.search(header)
        protocol = PROTOCOL_RE.search(header)
        hops.append({
            # --- existing keys (unchanged; frontend/tests already rely on these) ---
            "hop_index": idx + 1,
            "from_host": from_host.group(1) if from_host else None,
            "by_host": by_host.group(1) if by_host else None,
            "ips_observed": ip_matches,
            "public_ips_observed": public_ips,
            "timestamp_raw": date_tail.group(1).strip() if date_tail else None,
            "raw_header": header,
            # --- additive convenience/forensic keys ---
            "hop": idx + 1,
            "hostname": from_host.group(1) if from_host else "not_available",
            "ip": public_ips[0] if public_ips else "not_available",
            "protocol": protocol.group(1) if protocol else "not_available",
        })
    return hops


def relay_chain_reliability(parsed: ParsedEmail, hops: list[dict]) -> dict:
    """Explicit, honest statement of how much the reconstructed chain can be
    trusted — Received headers can be missing, reordered, or forged by any
    hop prior to the first trustworthy relay."""
    if not parsed.received_headers:
        return {"reliable": False, "reason": "No Received headers were present; no relay chain could be reconstructed."}
    hops_with_ip = [h for h in hops if h["public_ips_observed"]]
    if not hops_with_ip:
        return {"reliable": False, "reason": "Received headers were present but no public IP address could be extracted from any of them."}
    if len(hops) == 1:
        return {"reliable": "partial", "reason": "Only a single Received header was present; the full relay path cannot be confirmed."}
    return {"reliable": "partial", "reason": "A relay chain was reconstructed from available Received headers, but any hop could theoretically be spoofed, "
                                             "and headers added before the first hop under your mail provider's control cannot be independently verified."}


def earliest_observable_external_ip(hops: list[dict]) -> str | None:
    """The first public IP seen walking from sender-side hops onward.
    Reported strictly as 'earliest observable external IP', never as an
    attacker identity — spoofing, relays, and shared infrastructure all mean
    this is contextual evidence only."""
    for hop in hops:
        if hop["public_ips_observed"]:
            return hop["public_ips_observed"][0]
    return None


def _is_suspicious_private_or_reserved(ip: str) -> bool:
    return _is_private_ip(ip) or ip.startswith(("0.", "169.254."))


def _raw_findings(parsed: ParsedEmail) -> list[dict]:
    """Each item: {name, severity, weight, explanation, evidence(dict)}."""
    findings = []

    from_domain = _domain_of(parsed.from_addr)
    reply_domain = _domain_of(parsed.reply_to)
    return_path_domain = _domain_of(parsed.return_path)
    message_id_domain = None
    if parsed.message_id and "@" in parsed.message_id:
        message_id_domain = parsed.message_id.split("@")[-1].strip().strip(">").lower()

    if reply_domain and from_domain and reply_domain != from_domain:
        findings.append({"name": "reply_to_mismatch", "severity": "high", "weight": 18,
                          "explanation": f"Reply-To domain ('{reply_domain}') differs from the visible sender domain ('{from_domain}').",
                          "evidence": {"from_domain": from_domain, "reply_to_domain": reply_domain}})

    if return_path_domain and from_domain and return_path_domain != from_domain:
        findings.append({"name": "return_path_mismatch", "severity": "medium", "weight": 10,
                          "explanation": f"Return-Path domain ('{return_path_domain}') differs from the visible sender domain ('{from_domain}').",
                          "evidence": {"from_domain": from_domain, "return_path_domain": return_path_domain}})

    if message_id_domain and from_domain and message_id_domain != from_domain:
        findings.append({"name": "message_id_domain_mismatch", "severity": "low", "weight": 6,
                          "explanation": f"Message-ID domain ('{message_id_domain}') differs from the visible sender domain ('{from_domain}'). "
                                         "This is common with mailing-list/relay software and is weak evidence on its own.",
                          "evidence": {"from_domain": from_domain, "message_id_domain": message_id_domain}})

    if not parsed.message_id:
        findings.append({"name": "missing_message_id", "severity": "low", "weight": 5,
                          "explanation": "No Message-ID header was present. Legitimate mail servers almost always add one.",
                          "evidence": {}})

    if not parsed.received_headers:
        findings.append({"name": "no_received_headers", "severity": "low", "weight": 4,
                          "explanation": "No Received headers were found, so the relay path could not be reconstructed. "
                                         "This is expected for a body-only paste, but reduces available evidence.",
                          "evidence": {}})

    if parsed.duplicate_headers:
        findings.append({"name": "duplicate_headers", "severity": "medium", "weight": 8,
                          "explanation": f"Header(s) that should normally appear once were found more than once: {', '.join(parsed.duplicate_headers)}. "
                                         "This can indicate header injection or a malformed relay, but can also be a benign parsing artifact.",
                          "evidence": {"duplicate_headers": parsed.duplicate_headers}})

    if parsed.x_originating_ip:
        ip_match = IP_RE.search(parsed.x_originating_ip)
        if ip_match and _is_suspicious_private_or_reserved(ip_match.group(0)):
            findings.append({"name": "x_originating_ip_private", "severity": "low", "weight": 4,
                              "explanation": f"X-Originating-IP ('{ip_match.group(0)}') is a private/reserved address, which is unusual for a header meant to expose a public originating IP.",
                              "evidence": {"x_originating_ip": parsed.x_originating_ip}})

    if parsed.x_mailer or parsed.user_agent:
        mailer = (parsed.x_mailer or parsed.user_agent or "").lower()
        if any(tok in mailer for tok in ("python", "curl", "phpmailer", "sendgrid-bulk", "mass mail")):
            findings.append({"name": "automated_mailer_signature", "severity": "low", "weight": 5,
                              "explanation": f"The X-Mailer/User-Agent header ('{parsed.x_mailer or parsed.user_agent}') indicates the message was sent by "
                                             "scripted/bulk-mail software rather than a typical end-user mail client. This is common for both legitimate "
                                             "transactional mail and phishing campaigns, so it is weak evidence on its own.",
                              "evidence": {"mailer": parsed.x_mailer or parsed.user_agent}})

    if parsed.dkim_signature_headers:
        for sig in parsed.dkim_signature_headers:
            d_match = DKIM_D_RE.search(sig)
            if d_match and from_domain and d_match.group(1).lower() != from_domain:
                findings.append({"name": "dkim_signature_domain_mismatch", "severity": "medium", "weight": 9,
                                  "explanation": f"A DKIM-Signature header signs for domain '{d_match.group(1).lower()}', which differs from the visible sender domain ('{from_domain}').",
                                  "evidence": {"dkim_signature_domain": d_match.group(1).lower(), "from_domain": from_domain}})
                break

    if parsed.date:
        try:
            dt = parsedate_to_datetime(parsed.date)
            if dt is not None:
                now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.utcnow()
                if dt > now.replace(year=now.year + 1):
                    findings.append({"name": "date_far_future", "severity": "low", "weight": 4,
                                      "explanation": f"The Date header ('{parsed.date}') is implausibly far in the future.",
                                      "evidence": {"date": parsed.date}})
        except Exception:
            findings.append({"name": "date_unparseable", "severity": "low", "weight": 2,
                              "explanation": f"The Date header ('{parsed.date}') could not be parsed as a valid RFC-5322 date.",
                              "evidence": {"date": parsed.date}})

    return findings


def header_signals(parsed: ParsedEmail) -> list[dict]:
    """Existing flat shape consumed by risk_engine.py — unchanged contract,
    now backed by the shared, richer finding set above."""
    return [{"name": f["name"], "severity": f["severity"], "weight": f["weight"], "explanation": f["explanation"]}
            for f in _raw_findings(parsed)]


def header_forensic_findings(parsed: ParsedEmail) -> list[dict]:
    """New, richer machine-readable shape (project SECTION 10). Additive —
    does not replace header_signals()."""
    out = []
    for f in _raw_findings(parsed):
        out.append({
            "category": "header",
            "indicator": f["name"],
            "severity": f["severity"],
            "title": f["name"].replace("_", " ").title(),
            "description": f["explanation"],
            "evidence": f["evidence"],
            "risk_weight": f["weight"],
            "source": "header",
        })
    return out
