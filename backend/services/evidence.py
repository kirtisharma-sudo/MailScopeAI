from datetime import datetime, timezone
from utils.hashing import sha256_bytes


def build_evidence(raw_bytes: bytes, input_type: str, analysis_version: str, indicator_count: int, case_id: str | None = None) -> dict:
    ts = datetime.now(timezone.utc).isoformat()
    return {
        # --- existing keys (unchanged) ---
        "sha256": sha256_bytes(raw_bytes),
        "input_type": input_type,               # "pasted_text" | "eml_upload"
        "analysis_version": analysis_version,
        "timestamp": ts,
        "indicators_extracted": indicator_count,
        # --- additive spec-aliased keys (SECTION 11) ---
        "case_id": case_id or "not_available",
        "analysis_timestamp": ts,
        "engine_version": analysis_version,
        "integrity_note": "SHA-256 is computed from the exact bytes supplied for analysis. This establishes data integrity for this "
                           "analysis session only and is not, by itself, a claim of legal admissibility or chain-of-custody.",
    }


def build_indicator_set(from_addr, reply_to, return_path, domains: list[str], urls: list[dict], ips: list[str], message_id, attachment_hashes: list[str] | None = None) -> list[dict]:
    """Normalized indicator list used both for the evidence count and for
    campaign correlation (campaign_engine.py)."""
    indicators = []
    if from_addr:
        indicators.append({"type": "sender_address", "value": from_addr})
    if reply_to:
        indicators.append({"type": "reply_to_domain", "value": reply_to})
    if return_path:
        indicators.append({"type": "return_path_domain", "value": return_path})
    for d in domains:
        indicators.append({"type": "domain", "value": d})
    for u in urls:
        indicators.append({"type": "url", "value": u["url"]})
        if u.get("domain"):
            indicators.append({"type": "url_domain", "value": u["domain"]})
    for ip in ips:
        indicators.append({"type": "ip", "value": ip})
    if message_id:
        indicators.append({"type": "message_id", "value": message_id})
    for h in (attachment_hashes or []):
        if h and h != "not_available":
            indicators.append({"type": "attachment_sha256", "value": h})
    return indicators
