"""
Builds the Investigation Timeline from data the rest of the pipeline has
ALREADY parsed/computed — this module does not re-parse Received headers
or re-derive anything; it only sequences and normalizes what
email_parser.py / header_analyzer.py / auth_analyzer.py / url_analyzer.py /
attachment_analyzer.py / domain_intel.py / ip_intel.py / risk_engine.py
already produced for this request.

Two kinds of events:
  - EMAIL EVIDENCE (source="email_header"): the message's own Date header
    and each Received hop. These get REAL timestamps when parseable from
    the message itself — never invented — and are sorted chronologically
    among themselves when timestamps are available.
  - ANALYSIS / ENRICHMENT events (source="analysis" | "enrichment"): things
    this backend DID while analyzing the message (auth check, URL/attachment
    analysis, domain/IP enrichment, evidence fusion, final assessment).
    These did not happen at the email's transport time, so they are never
    given a fabricated historical timestamp — they share the single real
    `analysis_timestamp` for this request (all part of one atomic analysis
    pass) and are ordered with an explicit `order` field, not a fake clock.
"""
from __future__ import annotations
from email.utils import parsedate_to_datetime


def _parse_timestamp(raw: str | None) -> tuple[str | None, str]:
    """Returns (iso_timestamp_or_None, status). Never invents a timestamp —
    'unavailable' is returned rather than guessing."""
    if not raw:
        return None, "unavailable"
    try:
        dt = parsedate_to_datetime(raw)
        if dt is None:
            return None, "unavailable"
        return dt.isoformat(), "parsed"
    except Exception:
        return None, "unavailable"


def build_timeline(
    parsed,                       # ParsedEmail
    relay_path: list[dict],
    chain_reliability: dict,
    auth: dict,
    urls: list[dict],
    attachments: list[dict],
    domain_intel_results: list[dict],
    infrastructure: list[dict],
    signals: list[dict],
    score_breakdown: dict,
    risk_score: int,
    classification: str,
    confidence: int,
    analysis_timestamp: str,
) -> list[dict]:
    events: list[dict] = []
    order = 0

    # ---------------------------------------------------------------- EMAIL EVIDENCE
    date_iso, date_status = _parse_timestamp(parsed.date)
    events.append({
        "event_type": "email_received",
        "title": "Email received",
        "description": "The message's own Date header, as supplied. This reflects what the sender's system reported, "
                        "not an independently verified delivery time.",
        "source": "email_header",
        "timestamp": date_iso,
        "timestamp_raw": parsed.date or "not_present",
        "timestamp_status": date_status,
        "order": order,
        "reliability": "not_applicable",
        "evidence": ["Date header"] if parsed.date else [],
        "metadata": {"from": parsed.from_addr or "unavailable", "subject": parsed.subject or "unavailable"},
    })
    order += 1

    for hop in relay_path:
        ts_iso, ts_status = _parse_timestamp(hop.get("timestamp_raw"))
        has_public_ip = bool(hop.get("public_ips_observed"))
        hop_reliability = "reliable" if has_public_ip else "incomplete"
        events.append({
            "event_type": "received_hop",
            "title": f"Received hop {hop['hop_index']}",
            "description": f"Relay hop reconstructed from a Received header — "
                            f"from {hop.get('hostname') or 'not_available'} to {hop.get('by_host') or 'not_available'}.",
            "source": "email_header",
            "timestamp": ts_iso,
            "timestamp_raw": hop.get("timestamp_raw") or "not_present",
            "timestamp_status": ts_status,
            "order": order,
            "reliability": hop_reliability,
            "evidence": ["Received header"],
            "metadata": {
                "source_hostname": hop.get("hostname") or "not_available",
                "source_ip": hop.get("ip") or "not_available",
                "destination_hostname": hop.get("by_host") or "not_available",
                "protocol": hop.get("protocol") or "not_available",
                "hop_index": hop["hop_index"],
            },
        })
        order += 1

    # A single, honest statement about how much the reconstructed chain as a
    # WHOLE can be trusted — reusing the existing reliability assessment
    # rather than inventing a second one.
    chain_note_evidence = [] if relay_path else []
    events.append({
        "event_type": "relay_chain_assessment",
        "title": "Relay chain reliability",
        "description": chain_reliability.get("reason", "Relay chain reliability could not be determined."),
        "source": "analysis",
        "timestamp": analysis_timestamp,
        "timestamp_raw": "not_applicable",
        "timestamp_status": "not_applicable",
        "order": order,
        "reliability": "reliable" if chain_reliability.get("reliable") is True else ("partial" if chain_reliability.get("reliable") == "partial" else "unavailable"),
        "evidence": ["Received headers (aggregate assessment)"] if relay_path else [],
        "metadata": {"hop_count": len(relay_path)},
    })
    order += 1

    # ---------------------------------------------------------------- CHRONOLOGICAL RE-SORT (email evidence only)
    # Only re-sort by timestamp when EVERY email-evidence event has a real,
    # parsed timestamp. If even one is missing, the existing header-position
    # order (already chronological-by-convention from header_analyzer.py) is
    # kept as-is rather than guessing where the untimed event belongs.
    email_evidence = [e for e in events if e["source"] == "email_header"]
    rest = [e for e in events if e["source"] != "email_header"]
    if email_evidence and all(e["timestamp_status"] == "parsed" for e in email_evidence):
        email_evidence.sort(key=lambda e: e["timestamp"])
    events = email_evidence + rest
    for i, ev in enumerate(events):
        ev["order"] = i

    # ---------------------------------------------------------------- ANALYSIS EVENTS
    auth_unavailable = auth.get("spf") == "unavailable" and auth.get("dkim") == "unavailable" and auth.get("dmarc") == "unavailable"
    events.append({
        "event_type": "authentication_check",
        "title": "Authentication evaluated",
        "description": "SPF, DKIM, and DMARC results were checked against the Authentication-Results header."
                        if not auth_unavailable else
                        "No Authentication-Results header was present, so SPF/DKIM/DMARC could not be evaluated.",
        "source": "analysis",
        "timestamp": analysis_timestamp,
        "timestamp_raw": "not_applicable",
        "timestamp_status": "not_applicable",
        "order": order,
        "reliability": "unavailable" if auth_unavailable else "reliable",
        "evidence": ["Authentication-Results header"] if not auth_unavailable else [],
        "metadata": {"spf": auth.get("spf"), "dkim": auth.get("dkim"), "dmarc": auth.get("dmarc")},
    })
    order += 1

    url_risk_count = sum(1 for u in urls if u.get("lookalike_of") or u.get("is_ip_based") or u.get("notes"))
    events.append({
        "event_type": "url_analysis",
        "title": "URL analysis",
        "description": f"{len(urls)} URL(s) extracted from the message body; {url_risk_count} showed at least one structural indicator."
                        if urls else "No URLs were found in the message body.",
        "source": "analysis",
        "timestamp": analysis_timestamp,
        "timestamp_raw": "not_applicable",
        "timestamp_status": "not_applicable",
        "order": order,
        "reliability": "reliable" if urls else "not_applicable",
        "evidence": ["URLs extracted from message body"] if urls else [],
        "metadata": {"url_count": len(urls), "urls_with_indicators": url_risk_count},
    })
    order += 1

    att_risk_count = sum(1 for a in attachments if a.get("indicators"))
    events.append({
        "event_type": "attachment_analysis",
        "title": "Attachment analysis",
        "description": f"{len(attachments)} attachment(s) inspected (metadata + SHA-256 only, nothing executed); {att_risk_count} flagged."
                        if attachments else "No attachments were present.",
        "source": "analysis",
        "timestamp": analysis_timestamp,
        "timestamp_raw": "not_applicable",
        "timestamp_status": "not_applicable",
        "order": order,
        "reliability": "reliable" if attachments else "not_applicable",
        "evidence": ["Attachment metadata and SHA-256 (no execution)"] if attachments else [],
        "metadata": {"attachment_count": len(attachments), "attachments_flagged": att_risk_count},
    })
    order += 1

    domains_enriched = sum(1 for d in domain_intel_results if d.get("a_records") not in (None, "unavailable"))
    infra_enriched = sum(1 for i in infrastructure if i.get("country") not in (None, "unavailable"))
    enrichment_available = bool(domain_intel_results) or bool(infrastructure)
    events.append({
        "event_type": "domain_ip_enrichment",
        "title": "Domain / IP enrichment",
        "description": (f"DNS/RDAP checked for {len(domain_intel_results)} domain(s); network intelligence checked for "
                         f"{len(infrastructure)} observed IP(s). Results depend on external service/API-key availability.")
                        if enrichment_available else "No domains or observable IPs were available to enrich.",
        "source": "enrichment",
        "timestamp": analysis_timestamp,
        "timestamp_raw": "not_applicable",
        "timestamp_status": "not_applicable",
        "order": order,
        "reliability": "partial" if enrichment_available else "not_applicable",
        "evidence": ["DNS/RDAP lookup", "IP geolocation/reputation lookup"] if enrichment_available else [],
        "metadata": {"domains_checked": len(domain_intel_results), "domains_with_dns_data": domains_enriched,
                     "ips_checked": len(infrastructure), "ips_with_geo_data": infra_enriched},
    })
    order += 1

    events.append({
        "event_type": "evidence_fusion",
        "title": "Evidence fusion",
        "description": f"{len(signals)} signal(s) combined across {len(score_breakdown)} evidence categor{'y' if len(score_breakdown)==1 else 'ies'} "
                        "to produce a single risk score. See score_breakdown in the analysis response for the exact per-category contribution.",
        "source": "analysis",
        "timestamp": analysis_timestamp,
        "timestamp_raw": "not_applicable",
        "timestamp_status": "not_applicable",
        "order": order,
        "reliability": "reliable",
        "evidence": [f"{cat}: +{val}" for cat, val in score_breakdown.items()],
        "metadata": {"signal_count": len(signals), "categories": list(score_breakdown.keys())},
    })
    order += 1

    events.append({
        "event_type": "final_assessment",
        "title": "Assessment generated",
        "description": f"Classified as '{classification}' with a risk score of {risk_score}/100 and {confidence}% confidence in this assessment.",
        "source": "analysis",
        "timestamp": analysis_timestamp,
        "timestamp_raw": "not_applicable",
        "timestamp_status": "not_applicable",
        "order": order,
        "reliability": "reliable",
        "evidence": ["risk_engine fusion of all signals above"],
        "metadata": {"classification": classification, "risk_score": risk_score, "confidence": confidence},
    })

    return events
