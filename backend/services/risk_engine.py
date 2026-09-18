"""
ONE authoritative risk-calculation pipeline.

RAW EVIDENCE -> SIGNAL NORMALIZATION -> OVERLAP/DUPLICATE HANDLING ->
WEIGHTED EVIDENCE -> SCORE NORMALIZATION/CAP -> FINAL RISK SCORE -> CLASSIFICATION

separately:

EVIDENCE SUPPORT -> CONFIDENCE (never derived from risk_score itself)

Design fix (previous bug): the old engine capped each category's subtotal
and silently discarded the excess, so the individually-displayed signal
weights no longer summed to the final score (evidence "looked like" 83 but
scored 55). That is fixed here by NEVER truncating a category silently —
instead:
  1. Known-overlapping evidence is merged into a single signal BEFORE
     scoring (deduplicate_overlapping_signals), so the same underlying
     fact is never counted twice.
  2. Every remaining (deduped) signal's weight is added directly to the
     total. There is no hidden per-category cap.
  3. The only clamp is the final 0-100 bound on the total.

This guarantees: sum(signal["weight"] for signal in signals) == risk_score
whenever that sum is <= 100, and risk_score == 100 otherwise. That
invariant is asserted in tests/test_risk_engine.py.
"""
from __future__ import annotations

# Evidence categories used for score_breakdown and confidence. Chosen to
# match how an investigator actually reasons about evidence (identity,
# authentication, url, attachment, infrastructure, content) rather than
# the previous ad-hoc "header"/"auth"/"network"/"nlp" split.
CATEGORIES = ["identity", "authentication", "url", "attachment", "infrastructure", "content"]

_SIGNAL_CATEGORY = {
    # identity: sender/header identity integrity
    "reply_to_mismatch": "identity", "return_path_mismatch": "identity",
    "missing_message_id": "identity", "no_received_headers": "identity",
    "message_id_domain_mismatch": "identity", "duplicate_headers": "identity",
    "automated_mailer_signature": "identity", "dkim_signature_domain_mismatch": "identity",
    "date_far_future": "identity", "date_unparseable": "identity",
    "sender_domain_lookalike": "identity", "identity_impersonation": "identity",
    # authentication: SPF/DKIM/DMARC verdicts only (never "unavailable")
    "spf_fail": "authentication", "dkim_fail": "authentication", "dmarc_fail": "authentication",
    "dkim_alignment_issue": "authentication",
    # url
    "lookalike_domain": "url", "ip_based_url": "url", "url_shortener": "url",
    "visible_text_mismatch": "url", "excessive_subdomains": "url", "unusual_port": "url",
    # infrastructure (network/IP-level)
    "ip_abuse_reports": "infrastructure", "vpn_proxy_tor_infrastructure": "infrastructure",
    "x_originating_ip_private": "infrastructure",
    # content/NLP
    "nlp_content_classification": "content", "keyword_heuristic_match": "content",
    # attachment
    "suspicious_attachment_extension": "attachment", "double_extension_attachment": "attachment",
    "macro_enabled_attachment": "attachment",
}

# Signals that are, by design, weak/informational and must never by
# themselves push a case into a high-risk bucket — see requirement:
# "Message-ID mismatch must remain weak/informational evidence."
_WEAK_INFORMATIONAL_SIGNALS = {"message_id_domain_mismatch", "missing_message_id", "no_received_headers",
                               "duplicate_headers", "automated_mailer_signature", "date_far_future", "date_unparseable"}


def deduplicate_overlapping_signals(signals: list[dict]) -> list[dict]:
    """Merges signals that describe the SAME underlying fact observed from
    two different code paths, so it is never counted twice.

    Currently handles: a URL-level 'lookalike_domain' finding and an
    identity-level 'sender_domain_lookalike' finding that name the SAME
    brand. Both are really just "this message impersonates brand X via a
    similar-looking domain" — one fact, not two independent ones.

    Merge rule (documented, not a black box): take the stronger of the two
    weights, plus a partial (30%) credit for the weaker one as corroboration
    — never the full sum of both. This rewards two independent detectors
    agreeing without double-counting the same evidence.
    """
    lookalike = [s for s in signals if s["name"] == "lookalike_domain"]
    sender_lookalike = [s for s in signals if s["name"] == "sender_domain_lookalike"]

    if not lookalike or not sender_lookalike:
        return signals

    merged_out = []
    consumed_ids = set()

    for a in lookalike:
        for b in sender_lookalike:
            if id(b) in consumed_ids:
                continue
            if a.get("brand") and a.get("brand") == b.get("brand"):
                hi, lo = (a, b) if a["weight"] >= b["weight"] else (b, a)
                combined_weight = round(hi["weight"] + 0.3 * lo["weight"])
                merged = {
                    "name": "identity_impersonation",
                    "severity": "critical" if combined_weight >= 25 else "high",
                    "weight": combined_weight,
                    "explanation": f"Both the visible sender domain and a URL destination in this message match the pattern of impersonating "
                                   f"the brand '{a.get('brand')}'. These two observations describe the same underlying impersonation, "
                                   f"and have been combined into a single weighted signal rather than counted twice "
                                   f"(sender-domain evidence: {b['weight']} pts, URL evidence: {a['weight']} pts).",
                }
                merged_out.append(merged)
                consumed_ids.add(id(a))
                consumed_ids.add(id(b))
                break

    if not merged_out:
        return signals

    return [s for s in signals if id(s) not in consumed_ids] + merged_out


def fuse_signals(all_signals: list[dict]) -> tuple[int, list[dict], dict]:
    """Returns (risk_score, deduplicated_signals, score_breakdown).

    risk_score is DIRECTLY reproducible from the returned signals:
        risk_score == min(100, round(sum(s["weight"] for s in deduplicated_signals)))
    No per-category truncation is applied — see module docstring for why.
    """
    deduped = deduplicate_overlapping_signals(all_signals)

    breakdown: dict[str, float] = {cat: 0.0 for cat in CATEGORIES}
    for sig in deduped:
        cat = _SIGNAL_CATEGORY.get(sig["name"], "identity")
        breakdown[cat] = breakdown.get(cat, 0.0) + sig["weight"]

    raw_total = sum(breakdown.values())
    score = max(0, min(100, round(raw_total)))

    breakdown_rounded = {cat: round(val) for cat, val in breakdown.items() if val > 0}
    return score, deduped, breakdown_rounded


def classify_from_score(score: int, signals: list[dict], auth: dict) -> str:
    """Deterministic classification bucket, unchanged thresholds from the
    prior implementation (benign <25, suspicious <50) — not adjusted here
    since the brief asks not to invent new thresholds without cause. What
    changed is WHICH signals feed the phishing/impersonation sub-rules,
    updated to the new signal names (lookalike_domain / sender_domain_lookalike
    are now mergeable into identity_impersonation)."""
    if score < 25:
        return "benign"
    if score < 50:
        return "suspicious"

    has_brand_impersonation = any(s["name"] in ("lookalike_domain", "sender_domain_lookalike", "identity_impersonation") for s in signals)
    has_url_risk = any(_SIGNAL_CATEGORY.get(s["name"]) == "url" or s["name"] == "identity_impersonation" for s in signals)
    auth_failed = auth.get("dmarc") == "fail" or auth.get("spf") == "fail"

    if has_brand_impersonation and auth_failed:
        return "phishing"
    if has_url_risk and score >= 65:
        return "phishing"
    if auth_failed and not has_url_risk:
        return "impersonation"
    return "suspicious"


def confidence_from_evidence(signals: list[dict], auth: dict, relay_chain_reliable) -> int:
    """Confidence reflects how strongly the AVAILABLE evidence supports the
    assessment — completely independent of the risk_score value. It is
    possible to have high risk + low confidence (a strong single signal but
    little corroborating context) or low risk + high confidence (multiple
    independent categories all agree the message looks clean).

    Formula (documented, deterministic):
      base 40
      + 15 per DISTINCT evidence category present (max 3 categories counted -> +45)
      - 15 if authentication data is entirely unavailable (no Authentication-Results header)
      - 10 if the relay chain could not be reliably reconstructed
      clamped to [20, 95]
    """
    categories_present = {_SIGNAL_CATEGORY.get(s["name"], "identity") for s in signals}
    category_bonus = min(3, len(categories_present)) * 15

    confidence = 40 + category_bonus

    auth_unavailable = auth.get("spf") == "unavailable" and auth.get("dkim") == "unavailable" and auth.get("dmarc") == "unavailable"
    if auth_unavailable:
        confidence -= 15

    if relay_chain_reliable is not True:
        confidence -= 10

    return max(20, min(95, confidence))
