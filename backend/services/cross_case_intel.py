"""
"Have I Seen This Before?" — cross-case intelligence.

Deliberately NOT a new matching engine: this is a thin adapter over
services/campaign_engine.py, which already does shared-indicator matching,
low-value-indicator exclusion, and weighted per-indicator confidence. This
module only (a) groups those per-indicator relationship records by target
case, and (b) maps the numeric combined confidence to a deterministic,
explainable strength label — no new correlation logic, no parallel case
store.
"""
from __future__ import annotations
from services.campaign_engine import find_relationships
from services.policy import ATTRIBUTION_LIMITATION, RELATIONSHIP_LABEL, RELATIONSHIP_BASIS


def relationship_strength_label(confidence: float) -> str:
    """Deterministic, documented thresholds on the existing 0-1 combined-
    confidence scale from campaign_engine._combine_confidence. Not claimed
    to be statistically calibrated — just an explainable bucketing of the
    same transparent weight table already used for campaign correlation."""
    if confidence >= 0.65:
        return "strong"
    if confidence >= 0.35:
        return "moderate"
    if confidence > 0:
        return "weak"
    return "no_meaningful_relationship"


def _why_text(evidence_categories: list[str], shared_count: int) -> str:
    if shared_count == 0:
        return "No shared observable indicators were found against previously analyzed cases."
    cats = ", ".join(evidence_categories)
    return (f"Both cases contain {shared_count} matching observable technical indicator(s) "
            f"across the following evidence type(s): {cats}.")


_TYPE_TO_CATEGORY = {
    "attachment_sha256": "attachment", "url": "url", "url_domain": "domain", "domain": "domain",
    "message_id": "identity", "reply_to_domain": "identity", "return_path_domain": "identity",
    "ip": "infrastructure", "sender_address": "identity",
}


def build_related_cases(case_id: str, indicators: list[dict], prior_cases: list[dict]) -> list[dict]:
    """Returns a list matching the requested schema:
    [{case_id, relationship, shared_indicators, shared_indicator_count,
      evidence_categories, relationship_strength, why, limitation}, ...]
    Sorted strongest-first, deterministic given the same inputs.
    """
    relationships = find_relationships(case_id, indicators, prior_cases)
    if not relationships:
        return []

    by_target: dict[str, list[dict]] = {}
    for rel in relationships:
        by_target.setdefault(rel["target_case"], []).append(rel)

    results = []
    for target_case_id, rels in by_target.items():
        shared_indicators = [{"type": r["indicator_type"], "value": r["shared_indicator"]} for r in rels]
        evidence_categories = sorted({_TYPE_TO_CATEGORY.get(r["indicator_type"], "other") for r in rels})
        confidence = rels[0]["confidence"]  # already the pair's combined confidence (see campaign_engine.py)
        strength = relationship_strength_label(confidence)

        results.append({
            "case_id": target_case_id,
            "relationship": "potentially_related",
            "shared_indicators": shared_indicators,
            "shared_indicator_count": len(shared_indicators),
            "evidence_categories": evidence_categories,
            "relationship_strength": strength,
            "relationship_confidence": confidence,
            "why": _why_text(evidence_categories, len(shared_indicators)),
            "limitation": ATTRIBUTION_LIMITATION,
        })

    results.sort(key=lambda r: r["relationship_confidence"], reverse=True)
    return results


def related_activity_summary(related_cases: list[dict]) -> dict:
    """Top-level wrapper for the API response — headline label + basis text
    come from the centralized policy module, never re-typed ad hoc."""
    return {
        "has_related_activity": len(related_cases) > 0,
        "label": RELATIONSHIP_LABEL if related_cases else "No Related Activity Found",
        "basis": RELATIONSHIP_BASIS,
        "related_cases": related_cases,
    }
