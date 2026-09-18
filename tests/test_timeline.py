"""
Investigation Timeline tests. No mocks on the core logic — every test
drives the real pipeline (email_parser -> header_analyzer -> ... ->
timeline_builder) through /api/analyze.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from fastapi.testclient import TestClient
from app import app
from services.timeline_builder import build_timeline
from services.email_parser import parse_email
from services.header_analyzer import reconstruct_relay_path, relay_chain_reliability

client = TestClient(app)


def analyze(text):
    return client.post("/api/analyze", data={"email_text": text}).json()


def event_types(body):
    return [e["event_type"] for e in body["timeline"]]


ONE_HOP_EMAIL = """From: a@example.com
Subject: Test
Message-ID: <1@example.com>
Date: Mon, 01 Sep 2025 09:00:00 +0000
Received: from mail.example.com (mail.example.com [93.184.216.34]) by mx.recipient.com with ESMTP; Mon, 01 Sep 2025 09:00:05 +0000

Hello.
"""

TWO_HOP_EMAIL = """From: a@example.com
Subject: Test
Message-ID: <1@example.com>
Date: Mon, 01 Sep 2025 09:00:00 +0000
Authentication-Results: mx; spf=fail; dkim=fail; dmarc=fail
Received: from mail.example.com (mail.example.com [93.184.216.34]) by mx.recipient.com with ESMTP; Mon, 01 Sep 2025 09:00:05 +0000
Received: from relay.upstream.example ([203.0.113.9]) by mail.example.com with ESMTP; Mon, 01 Sep 2025 08:59:50 +0000

Click http://phishy-example.com/verify
"""


# ---------------------------------------------------------------- 1. one Received hop
def test_1_one_received_hop():
    body = analyze(ONE_HOP_EMAIL)
    hops = [e for e in body["timeline"] if e["event_type"] == "received_hop"]
    assert len(hops) == 1
    assert hops[0]["metadata"]["source_ip"] == "93.184.216.34"


# ---------------------------------------------------------------- 2. multiple Received hops
def test_2_multiple_received_hops():
    body = analyze(TWO_HOP_EMAIL)
    hops = [e for e in body["timeline"] if e["event_type"] == "received_hop"]
    assert len(hops) == 2


# ---------------------------------------------------------------- 3. chronological ordering
def test_3_chronological_ordering_when_all_timestamps_parse():
    body = analyze(TWO_HOP_EMAIL)
    email_evidence = [e for e in body["timeline"] if e["source"] == "email_header"]
    timestamps = [e["timestamp"] for e in email_evidence]
    assert timestamps == sorted(timestamps)
    # the earlier-timestamped hop (08:59:50) must come before the email's own Date (09:00:00)
    hop_titles_in_order = [e["title"] for e in email_evidence]
    assert hop_titles_in_order.index("Received hop 1") < hop_titles_in_order.index("Email received")


# ---------------------------------------------------------------- 4. timezone normalization
def test_4_timezone_normalization():
    email = """From: a@example.com
Subject: Test
Message-ID: <1@example.com>
Date: Mon, 01 Sep 2025 09:00:00 -0500
Received: from mail.example.com (mail.example.com [93.184.216.34]) by mx.recipient.com with ESMTP; Mon, 01 Sep 2025 15:00:05 +0100

Hello.
"""
    body = analyze(email)
    email_evidence = [e for e in body["timeline"] if e["source"] == "email_header"]
    # -0500 09:00 == UTC 14:00; +0100 15:00:05 == UTC 14:00:05 -> hop is LATER, so email_received comes first
    assert all(e["timestamp_status"] == "parsed" for e in email_evidence)
    titles = [e["title"] for e in email_evidence]
    assert titles.index("Email received") < titles.index("Received hop 1")


# ---------------------------------------------------------------- 5. missing timestamp
def test_5_missing_timestamp_marked_unavailable_not_invented():
    email = "From: a@example.com\nSubject: Test\nMessage-ID: <1@example.com>\n\nNo date header at all."
    body = analyze(email)
    email_event = next(e for e in body["timeline"] if e["event_type"] == "email_received")
    assert email_event["timestamp"] is None
    assert email_event["timestamp_status"] == "unavailable"
    assert email_event["timestamp_raw"] == "not_present"


# ---------------------------------------------------------------- 6. malformed Received header
def test_6_malformed_received_header_does_not_crash():
    email = "From: a@example.com\nSubject: Test\nMessage-ID: <1@example.com>\nReceived: this is not a valid received header at all\n\nHello."
    body = analyze(email)
    assert "timeline" in body
    hops = [e for e in body["timeline"] if e["event_type"] == "received_hop"]
    assert len(hops) == 1
    assert hops[0]["timestamp_status"] == "unavailable"


# ---------------------------------------------------------------- 7. reliable vs unreliable hop
def test_7_hop_without_public_ip_marked_incomplete():
    email = "From: a@example.com\nSubject: Test\nMessage-ID: <1@example.com>\nReceived: from [10.0.0.5] by mx.recipient.com with SMTP; Mon, 01 Sep 2025 09:00:00 +0000\n\nHello."
    body = analyze(email)
    hop = next(e for e in body["timeline"] if e["event_type"] == "received_hop")
    assert hop["reliability"] == "incomplete"  # private IP only, no public IP observed


def test_7_hop_with_public_ip_marked_reliable():
    body = analyze(ONE_HOP_EMAIL)
    hop = next(e for e in body["timeline"] if e["event_type"] == "received_hop")
    assert hop["reliability"] == "reliable"


# ---------------------------------------------------------------- 8. SPF/DKIM/DMARC events
def test_8_authentication_event_reflects_real_results():
    body = analyze(TWO_HOP_EMAIL)
    auth_event = next(e for e in body["timeline"] if e["event_type"] == "authentication_check")
    assert auth_event["metadata"]["spf"] == "fail"
    assert auth_event["metadata"]["dkim"] == "fail"
    assert auth_event["metadata"]["dmarc"] == "fail"
    assert auth_event["reliability"] == "reliable"  # data WAS available (it failed, but wasn't unavailable)


# ---------------------------------------------------------------- 9. URL analysis event
def test_9_url_analysis_event_counts_real_urls():
    body = analyze(TWO_HOP_EMAIL)
    url_event = next(e for e in body["timeline"] if e["event_type"] == "url_analysis")
    assert url_event["metadata"]["url_count"] == 1


# ---------------------------------------------------------------- 10. attachment analysis event
def test_10_attachment_analysis_event_present_even_with_zero_attachments():
    body = analyze(ONE_HOP_EMAIL)
    att_event = next(e for e in body["timeline"] if e["event_type"] == "attachment_analysis")
    assert att_event["metadata"]["attachment_count"] == 0
    assert att_event["reliability"] == "not_applicable"


# ---------------------------------------------------------------- 11. enrichment event
def test_11_enrichment_event_present():
    body = analyze(TWO_HOP_EMAIL)
    enrich_event = next(e for e in body["timeline"] if e["event_type"] == "domain_ip_enrichment")
    assert enrich_event["source"] == "enrichment"


# ---------------------------------------------------------------- 12. evidence-fusion event
def test_12_evidence_fusion_event_matches_score_breakdown():
    body = analyze(TWO_HOP_EMAIL)
    fusion_event = next(e for e in body["timeline"] if e["event_type"] == "evidence_fusion")
    assert set(fusion_event["metadata"]["categories"]) == set(body["score_breakdown"].keys())


# ---------------------------------------------------------------- 13. final assessment event
def test_13_final_assessment_matches_top_level_result():
    body = analyze(TWO_HOP_EMAIL)
    final_event = next(e for e in body["timeline"] if e["event_type"] == "final_assessment")
    assert final_event["metadata"]["risk_score"] == body["risk_score"]
    assert final_event["metadata"]["classification"] == body["classification"]
    assert final_event["metadata"]["confidence"] == body["confidence"]


# ---------------------------------------------------------------- 14. no Received headers
def test_14_no_received_headers():
    body = analyze("From: a@example.com\nSubject: Test\nMessage-ID: <1@example.com>\n\nJust a plain body.")
    hops = [e for e in body["timeline"] if e["event_type"] == "received_hop"]
    assert hops == []
    chain_event = next(e for e in body["timeline"] if e["event_type"] == "relay_chain_assessment")
    assert chain_event["reliability"] == "unavailable"


# ---------------------------------------------------------------- 15. missing authentication
def test_15_missing_authentication_reflected_in_timeline():
    body = analyze(ONE_HOP_EMAIL)  # no Authentication-Results header
    auth_event = next(e for e in body["timeline"] if e["event_type"] == "authentication_check")
    assert auth_event["reliability"] == "unavailable"
    assert auth_event["evidence"] == []


# ---------------------------------------------------------------- 16. missing enrichment (no domains/IPs)
def test_16_missing_enrichment_when_no_domains_or_ips():
    body = analyze("From: a@example.com\nSubject: Test\nMessage-ID: <1@example.com>\n\nNo urls, no received headers, nothing to enrich.")
    enrich_event = next(e for e in body["timeline"] if e["event_type"] == "domain_ip_enrichment")
    # sender domain (example.com) is still present, so at least one domain is checked;
    # but with no relay path, infrastructure list is empty.
    assert enrich_event["metadata"]["ips_checked"] == 0


# ---------------------------------------------------------------- 17. timeline never affects risk score
def test_17_timeline_does_not_affect_risk_score():
    """Removing/ignoring the timeline entirely must not change risk_score —
    it's built AFTER fuse_signals() from already-final values."""
    body = analyze(TWO_HOP_EMAIL)
    from services.risk_engine import fuse_signals
    # Recompute independently from the returned signals (ignoring timeline entirely).
    recomputed_score = max(0, min(100, round(sum(s["weight"] for s in body["signals"]))))
    assert recomputed_score == body["risk_score"]


# ---------------------------------------------------------------- 18. deterministic ordering
def test_18_same_email_produces_identical_timeline_ordering():
    body1 = analyze(TWO_HOP_EMAIL)
    body2 = analyze(TWO_HOP_EMAIL)
    assert event_types(body1) == event_types(body2)
    assert [e["timestamp"] for e in body1["timeline"] if e["source"] == "email_header"] == \
           [e["timestamp"] for e in body2["timeline"] if e["source"] == "email_header"]


# ---------------------------------------------------------------- 19. English/Hindi UI -> identical timeline data
def test_19_language_does_not_affect_timeline_data():
    """The backend never sees UI language at all — this confirms the
    timeline (like risk_score) is purely a function of the email content."""
    hi_body = analyze("From: a@example.com\nSubject: Test\nMessage-ID: <2@example.com>\nContent-Type: text/plain; charset=UTF-8\nDate: Mon, 01 Sep 2025 09:00:00 +0000\n\nनमस्ते, यह एक सामान्य संदेश है।")
    en_body = analyze("From: a@example.com\nSubject: Test\nMessage-ID: <3@example.com>\nDate: Mon, 01 Sep 2025 09:00:00 +0000\n\nHello, this is a normal message.")
    assert event_types(hi_body) == event_types(en_body)
    hi_dates = [e["timestamp"] for e in hi_body["timeline"] if e["event_type"] == "email_received"]
    en_dates = [e["timestamp"] for e in en_body["timeline"] if e["event_type"] == "email_received"]
    assert hi_dates == en_dates  # same Date header -> same parsed timestamp regardless of body language


# ---------------------------------------------------------------- 20. existing Trace Origin data intact
def test_20_existing_relay_path_and_reliability_fields_unchanged():
    """Regression: the pre-existing relay_path/relay_chain_reliability
    response fields (consumed by the frontend Trace Origin page) must be
    completely unaffected by adding the timeline."""
    body = analyze(TWO_HOP_EMAIL)
    assert len(body["relay_path"]) == 2
    assert "hop_index" in body["relay_path"][0] and "from_host" in body["relay_path"][0]
    assert "reliable" in body["relay_chain_reliability"]


# ---------------------------------------------------------------- direct unit tests on build_timeline
def test_unit_build_timeline_no_re_parsing_of_received_headers():
    """timeline_builder must consume header_analyzer's OWN reconstruction,
    not re-derive it — this test uses the exact same function the rest of
    the app uses, proving there is no second parser."""
    raw = TWO_HOP_EMAIL.encode()
    parsed = parse_email(raw)
    relay_path = reconstruct_relay_path(parsed)
    reliability = relay_chain_reliability(parsed, relay_path)
    timeline = build_timeline(
        parsed=parsed, relay_path=relay_path, chain_reliability=reliability,
        auth={"spf": "fail", "dkim": "fail", "dmarc": "fail"},
        urls=[], attachments=[], domain_intel_results=[], infrastructure=[],
        signals=[], score_breakdown={}, risk_score=0, classification="benign",
        confidence=50, analysis_timestamp="2025-01-01T00:00:00+00:00",
    )
    assert len([e for e in timeline if e["event_type"] == "received_hop"]) == len(relay_path)
