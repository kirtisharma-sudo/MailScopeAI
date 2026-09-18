"""
Turns a stored case (whatever /api/analyze produced + indicators/analyst_notes,
see case_store.py) into the structured forensic-report shape used by
GET /api/reports/{case_id}. Pure data reshaping — no new intelligence is
generated here, and any field the underlying case doesn't have is reported
as "unavailable"/[] rather than invented.
"""


def build_forensic_report(case: dict) -> dict:
    return {
        "case_id": case.get("case_id", "unavailable"),
        "summary": {
            "classification": case.get("classification", "unavailable"),
            "risk_score": case.get("risk_score", "unavailable"),
            "confidence": case.get("confidence", "unavailable"),
            "mode": case.get("mode", "unavailable"),
            "source_input_type": case.get("evidence", {}).get("input_type", "unavailable"),
            "score_breakdown": case.get("score_breakdown", {}),
        },
        "engine": {
            "engine_version": case.get("evidence", {}).get("engine_version", "unavailable"),
            "analysis_timestamp": case.get("evidence", {}).get("analysis_timestamp", "unavailable"),
            "nlp_model_status": case.get("content_analysis", {}).get("nlp_model_status", "unavailable"),
            "nlp_model_version": case.get("content_analysis", {}).get("nlp_model_version", "unavailable"),
        },
        "key_findings": case.get("signals", []),
        "language": case.get("language", {"detected": "unavailable"}),
        "headers": case.get("headers", {}),
        "authentication": case.get("authentication", {}),
        "relay_path": case.get("relay_path", []),
        "relay_chain_reliability": case.get("relay_chain_reliability", {"reliable": "unavailable"}),
        "network_intelligence": case.get("infrastructure", []),
        "domain_intelligence": case.get("domains", []),
        "urls": case.get("urls", []),
        "attachments": case.get("attachments", []),
        "identity": case.get("identity", {}),
        "forensic_findings": case.get("forensic_findings", []),
        "campaign": case.get("campaign", {"status": "not_evaluated"}),
        "related_activity": case.get("related_activity", {"locked": True, "related_cases": []}),
        "evidence": case.get("evidence", {}),
        "timeline": case.get("timeline", []),
        "limitations": case.get("limitations", []),
        "analyst_notes": case.get("analyst_notes", ""),
    }
