from fastapi import APIRouter, UploadFile, File, Form, HTTPException
import logging

from config import get_settings
from utils.validation import validate_pasted_text, validate_upload
from utils.hashing import new_case_id
from utils.sanitization import safe_log_snippet
from services.email_parser import parse_email
from services.header_analyzer import (
    reconstruct_relay_path, earliest_observable_external_ip, header_signals,
    header_forensic_findings, relay_chain_reliability,
)
from services.auth_analyzer import analyze_authentication, auth_signals
from services.url_analyzer import analyze_urls, url_signals
from services.domain_intel import gather_domain_intel
from services.ip_intel import gather_ip_intel, network_signals
from services.nlp_detector import classify_content, nlp_signals
from services.language_detector import detect_language
from services.risk_engine import fuse_signals, classify_from_score, confidence_from_evidence
from services.evidence import build_evidence, build_indicator_set
from services.campaign_engine import correlate
from services.cross_case_intel import build_related_cases, related_activity_summary
from services.plans import feature_available
from services.attachment_analyzer import analyze_attachments, attachment_signals
from services.identity_analyzer import compare_identity_domains, identity_signals
from services import supabase_client
from services import case_store
from services import case_source
from services.timeline_builder import build_timeline

router = APIRouter()
settings = get_settings()
logger = logging.getLogger("mailscope.analyze")


@router.post("/api/analyze")
async def analyze(
    email_text: str | None = Form(default=None),
    file: UploadFile | None = File(default=None),
):
    if file is not None:
        raw = await file.read()
        validate_upload(file.filename, len(raw))
        input_type = "eml_upload"
    else:
        validate_pasted_text(email_text)
        raw = email_text.encode("utf-8")
        input_type = "pasted_text"

    logger.info("Analyzing input (%s, %d bytes): %s", input_type, len(raw), safe_log_snippet(raw.decode("utf-8", "ignore")))

    parsed = parse_email(raw)

    # --- Header forensics -------------------------------------------------
    relay_path = reconstruct_relay_path(parsed)
    earliest_ip = earliest_observable_external_ip(relay_path)
    chain_reliability = relay_chain_reliability(parsed, relay_path)
    hdr_signals = header_signals(parsed)
    hdr_findings = header_forensic_findings(parsed)

    # --- Authentication -----------------------------------------------------
    auth = analyze_authentication(parsed)
    a_signals = auth_signals(auth)

    # --- URLs -----------------------------------------------------------
    urls = analyze_urls(parsed.body_text, parsed.body_html)
    u_signals = url_signals(urls)

    # --- Attachments (metadata + hashes only; nothing is executed/opened) ---
    attachments = analyze_attachments(parsed.attachments)
    att_signals = attachment_signals(attachments)

    # --- Identity / domain cross-comparison ----------------------------------
    identity = compare_identity_domains(
        parsed.from_addr, parsed.reply_to, parsed.return_path, parsed.message_id,
        [u["domain"] for u in urls if u.get("domain")],
    )
    id_signals = identity_signals(parsed.from_addr)

    # --- Domains (from sender + URLs) --------------------------------------
    domains_seen = set()
    if parsed.from_addr and "@" in parsed.from_addr:
        domains_seen.add(parsed.from_addr.split("@")[-1].strip().strip(">").lower())
    for u in urls:
        if u["domain"]:
            domains_seen.add(u["domain"])
    domain_intel_results = [gather_domain_intel(d) for d in list(domains_seen)[:5]]  # capped to limit external calls

    # --- Network/IP intel (only for the earliest observable external IP) ----
    infrastructure = []
    if earliest_ip:
        infra = gather_ip_intel(earliest_ip)
        infra["role"] = "earliest_observable_external_ip"
        infrastructure.append(infra)
    net_signals = network_signals(infrastructure)

    # --- Language detection (content-only; NEVER contributes to risk_score) ---
    language = detect_language((parsed.subject or "") + "\n" + (parsed.body_text or ""))

    # --- NLP content analysis -----------------------------------------------
    nlp_result = classify_content(parsed.body_text, language=language["detected"])
    n_signals = nlp_signals(nlp_result)

    # --- Fuse everything into a risk score -----------------------------------
    all_signals = hdr_signals + a_signals + u_signals + net_signals + n_signals + att_signals + id_signals
    risk_score, all_signals, score_breakdown = fuse_signals(all_signals)
    classification = classify_from_score(risk_score, all_signals, auth)
    confidence = confidence_from_evidence(all_signals, auth, chain_reliability.get("reliable"))

    case_id = new_case_id()

    # --- Evidence + indicators -----------------------------------------------
    attachment_hashes = [a["sha256"] for a in attachments]
    indicators = build_indicator_set(
        from_addr=parsed.from_addr, reply_to=parsed.reply_to, return_path=parsed.return_path,
        domains=list(domains_seen), urls=urls,
        ips=[ip for hop in relay_path for ip in hop["public_ips_observed"]],
        message_id=parsed.message_id, attachment_hashes=attachment_hashes,
    )
    evidence = build_evidence(raw, input_type, settings.ANALYSIS_VERSION, len(indicators), case_id=case_id)

    timeline = build_timeline(
        parsed=parsed, relay_path=relay_path, chain_reliability=chain_reliability, auth=auth,
        urls=urls, attachments=attachments, domain_intel_results=domain_intel_results,
        infrastructure=infrastructure, signals=all_signals, score_breakdown=score_breakdown,
        risk_score=risk_score, classification=classification, confidence=confidence,
        analysis_timestamp=evidence["analysis_timestamp"],
    )

    # --- Campaign correlation (Supabase-backed if configured, else in-memory) ---
    prior_cases = case_source.get_all_case_indicators(exclude_case_id=case_id)
    campaign = correlate(case_id, indicators, prior_cases)

    # --- "Have I Seen This Before?" — Sentinel-tier feature, gated but never hidden dishonestly ---
    cross_case_gate = feature_available("cross_case_intelligence")
    if cross_case_gate["available"]:
        related_cases = build_related_cases(case_id, indicators, prior_cases)
        related_activity = {**related_activity_summary(related_cases), "locked": False, "gate": cross_case_gate}
    else:
        related_activity = {"locked": True, "gate": cross_case_gate, "related_cases": [],
                             "note": "Cross-case correlation ('Have I Seen This Before?') is a MailScope Sentinel feature."}

    limitations = list(parsed.parse_warnings)
    if auth["spf"] == "unavailable" and auth["dkim"] == "unavailable" and auth["dmarc"] == "unavailable":
        limitations.append("No Authentication-Results header was present — SPF/DKIM/DMARC status is unavailable, not failed. This reduces confidence but does not itself add risk.")
    if not settings.SUPABASE_URL:
        limitations.append("Supabase not configured — this case is held in an in-memory store for the lifetime of this backend process only (campaign correlation and report retrieval work, but the case will be lost on restart).")
    if nlp_result.model_status == "not_loaded":
        limitations.append("No fine-tuned NLP model is loaded; content analysis used a placeholder keyword heuristic, not a trained classifier.")
    if language["analysis_support"] == "limited":
        limitations.append(f"Detected content language is '{language['display_name']}'. Hindi NLP support is architecturally enabled (language never affects risk_score), but dedicated Hindi content-classification performance has not been trained or evaluated — deterministic signals (headers, authentication, URLs, attachments, identity) remain fully language-independent and are unaffected.")
    for d in domain_intel_results:
        if d["reputation"] == "unavailable":
            limitations.append(f"Domain reputation for '{d['domain']}' unavailable (no VIRUSTOTAL_API_KEY configured or lookup failed).")
    if infrastructure and infrastructure[0].get("country") == "unavailable":
        limitations.append("IP geolocation unavailable (no IPINFO_TOKEN configured or lookup failed).")
    if chain_reliability["reliable"] is not True:
        limitations.append(f"Relay-chain reliability: {chain_reliability['reason']}")
    if any(a["sha256"] == "not_available" for a in attachments):
        limitations.append("One or more attachments could not be read/decoded, so no SHA-256 hash is available for them.")

    response = {
        # --- existing top-level fields (unchanged contract; frontend depends on these) ---
        "case_id": case_id,
        "classification": classification,
        "risk_score": risk_score,
        "confidence": confidence,
        "signals": all_signals,
        "content_analysis": {
            "nlp_model_status": nlp_result.model_status,
            "nlp_model_version": nlp_result.model_version,
            "label": nlp_result.label,
            "probabilities": nlp_result.probabilities,
            "matched_terms": nlp_result.matched_terms,
        },
        "headers": {
            "from": parsed.from_addr, "to": parsed.to_addr, "cc": parsed.cc,
            "reply_to": parsed.reply_to, "return_path": parsed.return_path,
            "subject": parsed.subject, "date": parsed.date, "message_id": parsed.message_id,
            # --- additive header fields (SECTION 4) ---
            "x_originating_ip": parsed.x_originating_ip or "not_present",
            "x_mailer": parsed.x_mailer or "not_present",
            "user_agent": parsed.user_agent or "not_present",
            "duplicate_headers": parsed.duplicate_headers or [],
        },
        "authentication": auth,
        "urls": urls,
        "domains": domain_intel_results,
        "infrastructure": infrastructure,
        "relay_path": relay_path,
        "campaign": campaign,
        "related_activity": related_activity,
        "evidence": evidence,
        "limitations": limitations,
        "timeline": timeline,
        "mode": "demo" if settings.DEMO_MODE else "live",
        # --- additive fields (this upgrade; frontend can ignore safely) ---
        "attachments": attachments,
        "identity": identity,
        "relay_chain_reliability": chain_reliability,
        "forensic_findings": hdr_findings,   # richer {category,indicator,severity,title,description,evidence,risk_weight} shape
        "language": language,   # content-only language detection; NEVER a risk_score input — see services/language_detector.py
        # --- score transparency (additive; risk_score is exactly reproducible from these) ---
        "score_breakdown": score_breakdown,
        "evidence_summary": {
            "total_signals": len(all_signals),
            "categories_with_evidence": sorted(score_breakdown.keys()),
            "scoring_note": "risk_score = min(100, round(sum of each signal's weight)) after overlap deduplication. "
                             "Every weight shown in 'signals' is the exact number that was added — nothing is hidden or truncated.",
        },
    }

    # --- Persist: in-memory store ALWAYS (so campaign correlation and report
    # retrieval work even with zero Supabase setup), Supabase ADDITIONALLY
    # when configured (durable across restarts). Raw email bytes are never
    # stored in either place — only this structured response + indicators.
    case_store.save_case(case_id, {
        **response,
        "indicators": indicators,
        "analyst_notes": "",
    })

    if settings.SUPABASE_URL:
        supabase_client.save_case({
            "id": case_id, "classification": classification, "risk_score": risk_score,
            "confidence": confidence, "source": input_type, "analysis_version": settings.ANALYSIS_VERSION,
        })
        supabase_client.save_related("email_headers", [{
            "case_id": case_id, "from_address": parsed.from_addr, "reply_to": parsed.reply_to,
            "return_path": parsed.return_path, "message_id": parsed.message_id, "subject": parsed.subject,
            "received_headers": parsed.received_headers, "authentication_results": parsed.authentication_results,
        }])
        supabase_client.save_related("urls", [{
            "case_id": case_id, "url": u["url"], "domain": u["domain"], "indicators": u["notes"],
        } for u in urls])
        supabase_client.save_related("infrastructure", [{
            "case_id": case_id, "ip": n["ip"], "asn": n.get("asn"), "isp": n.get("isp"),
            "country": n.get("country"), "region": n.get("region"), "city": n.get("city"),
            "hosting": n.get("hosting"), "vpn_proxy_tor": n.get("vpn_proxy_tor"),
        } for n in infrastructure])
        supabase_client.save_related("indicators", [{
            "case_id": case_id, "type": i["type"], "value": i["value"],
        } for i in indicators])
        supabase_client.save_related("evidence", [{
            "case_id": case_id, "sha256": evidence["sha256"], "evidence_type": input_type,
            "timestamp": evidence["timestamp"], "description": f"{len(indicators)} indicators extracted.",
        }])

    return response
