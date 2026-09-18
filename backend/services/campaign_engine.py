"""
Builds relationship-level "possible campaign" records between the current
case and prior cases (Supabase-backed or in-memory — see case_source.py),
based on shared indicators. Never claims common attacker identity — only
"potential campaign relationship" / "shared infrastructure observed".

Confidence per relationship is derived from the ACTUAL indicator type that
was shared, using an explicit, explainable weight table below — not a
black-box score. Multiple shared indicators between the same pair of cases
combine (non-linearly, capped) into a higher combined confidence, but the
underlying per-indicator relationships are still all reported individually
so nothing is hidden.
"""
import hashlib
import networkx as nx

# Indicator types considered too common to be meaningful on their own
# (a shared "domain" of e.g. gmail.com proves nothing).
_LOW_VALUE_VALUES = {
    "gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "icloud.com",
    "amazonaws.com", "cloudflare.com", "googleusercontent.com", "azurewebsites.net",
}

# Explicit, explainable per-indicator-type confidence weights (0-1).
# Rationale: an identical attachment byte-for-byte is very strong evidence
# two messages share a source; a bare shared IP is the weakest (shared
# hosting/CDNs are extremely common and prove little on their own).
RELATIONSHIP_WEIGHTS = {
    "attachment_sha256": 0.95,
    "url": 0.85,
    "url_domain": 0.55,
    "domain": 0.55,
    "message_id": 0.5,
    "reply_to_domain": 0.45,
    "return_path_domain": 0.45,
    "ip": 0.40,
    "sender_address": 0.35,
}

_TYPE_TO_RELATIONSHIP = {
    "attachment_sha256": "shared_attachment_hash",
    "url": "shared_url",
    "url_domain": "shared_domain",
    "domain": "shared_domain",
    "message_id": "shared_message_id",
    "reply_to_domain": "shared_sender_infrastructure",
    "return_path_domain": "shared_sender_infrastructure",
    "ip": "shared_ip",
    "sender_address": "shared_sender_infrastructure",
}


def _is_low_value(indicator_type: str, value: str) -> bool:
    return value in _LOW_VALUE_VALUES


def _combine_confidence(weights: list[float]) -> float:
    """Combines multiple independent-ish pieces of evidence for the same
    case pair using 1 - Π(1 - w_i), capped so nothing claims false certainty."""
    combined = 1.0
    for w in weights:
        combined *= (1 - w)
    return round(min(0.97, 1 - combined), 3)


def _deterministic_campaign_id(case_ids: set[str]) -> str:
    """Same set of correlated cases always yields the same campaign_id,
    regardless of which case triggered the correlation or call order."""
    key = ",".join(sorted(case_ids))
    digest = hashlib.sha256(key.encode()).hexdigest()[:10].upper()
    return f"CAMP-{digest}"


def find_relationships(case_id: str, indicators: list[dict], prior_cases: list[dict]) -> list[dict]:
    """Returns a list of relationship records:
    {campaign_id, relationship_type, source_case, target_case, shared_indicator,
     indicator_type, confidence}
    One record per (prior_case, shared indicator) pair — nothing aggregated
    away, so the frontend/report can show exactly what was actually shared.
    """
    own_values = {(i["type"], i["value"]) for i in indicators if not _is_low_value(i["type"], i["value"])}
    if not own_values or not prior_cases:
        return []

    relationships = []
    pair_weights: dict[str, list[float]] = {}

    for prior in prior_cases:
        pid = prior["case_id"]
        if pid == case_id:
            continue
        prior_values = {(i["type"], i["value"]) for i in prior.get("indicators", []) if not _is_low_value(i["type"], i["value"])}
        shared = own_values & prior_values
        for itype, value in shared:
            weight = RELATIONSHIP_WEIGHTS.get(itype, 0.3)
            rel_type = _TYPE_TO_RELATIONSHIP.get(itype, "shared_indicator")
            relationships.append({
                "relationship_type": rel_type,
                "source_case": case_id,
                "target_case": pid,
                "shared_indicator": value,
                "indicator_type": itype,
                "confidence": weight,
            })
            pair_weights.setdefault(pid, []).append(weight)

    if not relationships:
        return []

    # All cases connected (directly or transitively, via NetworkX) to case_id
    # through any shared relationship get the SAME campaign_id.
    g = nx.Graph()
    for rel in relationships:
        g.add_edge(rel["source_case"], rel["target_case"])
    component = nx.node_connected_component(g, case_id)
    campaign_id = _deterministic_campaign_id(component)

    for rel in relationships:
        rel["campaign_id"] = campaign_id
        # Overwrite the single-indicator confidence with the pair's combined
        # confidence when multiple indicators link the same two cases, so
        # the "headline" confidence reflects the full weight of evidence —
        # per-relationship indicator_type/shared_indicator stay individually visible.
        rel["confidence"] = _combine_confidence(pair_weights[rel["target_case"]])

    return relationships


def correlate(case_id: str, indicators: list[dict], prior_cases: list[dict]) -> dict:
    """Backward-compatible aggregate summary (existing consumers: analyze.py
    response's `campaign` field, frontend mapApiToEmail) PLUS the new
    `relationships` list for anything that wants relationship-level detail."""
    relationships = find_relationships(case_id, indicators, prior_cases)
    if not relationships:
        return {"status": "isolated", "campaign_id": None, "shared_indicators": [], "related_case_count": 0, "relationships": []}

    shared_indicators = sorted({f"{r['indicator_type']}:{r['shared_indicator']}" for r in relationships})
    related_cases = sorted({r["target_case"] for r in relationships})

    return {
        "status": "possible_campaign",
        "campaign_id": relationships[0]["campaign_id"],
        "shared_indicators": shared_indicators,
        "related_case_count": len(related_cases),
        "relationships": relationships,
    }
