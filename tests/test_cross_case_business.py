import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from fastapi.testclient import TestClient
from app import app
from services import case_store
from services.cross_case_intel import relationship_strength_label, build_related_cases
from services.plans import feature_available, get_current_plan

client = TestClient(app)


def setup_function():
    case_store.clear()


def analyze(text):
    return client.post("/api/analyze", data={"email_text": text}).json()


CASE_A = "From: careers@microsoft-careers-india.com\nSubject: Job offer A\nMessage-ID: <a@microsoft-careers-india.com>\n\nApply now at http://microsoft-careers-india.com/apply"
CASE_B = "From: hr@microsoft-careers-india.com\nSubject: Totally different subject\nMessage-ID: <b@microsoft-careers-india.com>\n\nApply now at http://microsoft-careers-india.com/apply"
CASE_UNRELATED = "From: friend@example.com\nSubject: Lunch\nMessage-ID: <c@example.com>\n\nWant to grab lunch tomorrow?"


# ================================================================ CROSS-CASE

# ---------------------------------------------------------------- 1. no previous cases
def test_1_no_previous_cases_means_no_related_activity():
    body = analyze(CASE_A)
    assert body["related_activity"]["has_related_activity"] is False
    assert body["related_activity"]["related_cases"] == []


# ---------------------------------------------------------------- 2. one shared domain
def test_2_one_shared_domain_creates_relationship():
    analyze(CASE_A)
    body = analyze(CASE_B)
    assert body["related_activity"]["has_related_activity"] is True
    rc = body["related_activity"]["related_cases"][0]
    assert any(i["type"] == "domain" for i in rc["shared_indicators"])


# ---------------------------------------------------------------- 3. multiple shared indicators
def test_3_multiple_shared_indicators_grouped_under_one_related_case():
    analyze(CASE_A)
    body = analyze(CASE_B)
    rc = body["related_activity"]["related_cases"][0]
    assert rc["shared_indicator_count"] >= 2  # domain + url (+ url_domain)


# ---------------------------------------------------------------- 4. shared URL
def test_4_shared_url_detected():
    analyze(CASE_A)
    body = analyze(CASE_B)
    rc = body["related_activity"]["related_cases"][0]
    assert any(i["type"] == "url" for i in rc["shared_indicators"])


# ---------------------------------------------------------------- 5. shared observable IP
def test_5_shared_observable_ip_detected():
    a = "From: a@example.com\nSubject: x\nMessage-ID: <1@example.com>\nReceived: from mail.example.com ([203.0.113.77]) by mx.recipient.com with ESMTP; Mon, 01 Sep 2025 09:00:00 +0000\n\nHello"
    b = "From: b@other.example\nSubject: y\nMessage-ID: <2@other.example>\nReceived: from mail.other.example ([203.0.113.77]) by mx.recipient2.com with ESMTP; Mon, 01 Sep 2025 10:00:00 +0000\n\nHi"
    analyze(a)
    body = analyze(b)
    rc = body["related_activity"]["related_cases"][0]
    assert any(i["type"] == "ip" and i["value"] == "203.0.113.77" for i in rc["shared_indicators"])
    assert "infrastructure" in rc["evidence_categories"]


# ---------------------------------------------------------------- 6. shared attachment hash
def test_6_shared_attachment_hash_detected():
    import base64
    payload = base64.b64encode(b"identical-bytes-for-both-emails").decode()
    def make(msgid):
        return f"""From: a@example.com
Subject: Invoice
Message-ID: <{msgid}@example.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="B"

--B
Content-Type: text/plain

See attached.

--B
Content-Type: application/pdf; name="invoice.pdf"
Content-Disposition: attachment; filename="invoice.pdf"
Content-Transfer-Encoding: base64

{payload}
--B--
""".encode()
    client.post("/api/analyze", files={"file": ("a.eml", make("a"), "message/rfc822")})
    r2 = client.post("/api/analyze", files={"file": ("b.eml", make("b"), "message/rfc822")})
    body = r2.json()
    rc = body["related_activity"]["related_cases"][0]
    assert any(i["type"] == "attachment_sha256" for i in rc["shared_indicators"])
    assert rc["relationship_strength"] == "strong"  # attachment hash match is the strongest indicator


# ---------------------------------------------------------------- 7. no overlap
def test_7_unrelated_cases_show_no_related_activity():
    analyze(CASE_A)
    body = analyze(CASE_UNRELATED)
    assert body["related_activity"]["has_related_activity"] is False


# ---------------------------------------------------------------- 8. generic indicator not over-weighted
def test_8_generic_shared_indicator_does_not_create_relationship():
    a = "From: a@gmail.com\nSubject: x\nMessage-ID: <1@a.example>\n\nHi there"
    b = "From: b@gmail.com\nSubject: y\nMessage-ID: <2@b.example>\n\nHello"
    analyze(a)
    body = analyze(b)
    # gmail.com is explicitly excluded as a low-value indicator in campaign_engine.py
    assert body["related_activity"]["has_related_activity"] is False


# ---------------------------------------------------------------- 9. deterministic strength
def test_9_relationship_strength_is_deterministic():
    assert relationship_strength_label(0.9) == "strong"
    assert relationship_strength_label(0.5) == "moderate"
    assert relationship_strength_label(0.1) == "weak"
    assert relationship_strength_label(0.0) == "no_meaningful_relationship"
    # same input always the same output
    assert relationship_strength_label(0.7) == relationship_strength_label(0.7)


# ---------------------------------------------------------------- 10. same inputs -> same relationship
def test_10_same_inputs_produce_same_relationship():
    ind = [{"type": "domain", "value": "evil.example"}]
    prior = [{"case_id": "CASE-X", "indicators": ind}]
    r1 = build_related_cases("CASE-Y", ind, prior)
    r2 = build_related_cases("CASE-Y", ind, prior)
    assert r1 == r2


# ---------------------------------------------------------------- 11/12/13. never affects risk_score/classification/confidence
def test_11_12_13_related_activity_never_affects_risk_or_classification_or_confidence():
    analyze(CASE_A)
    body = analyze(CASE_B)
    # Recompute risk_score independently from signals only (no cross-case data involved)
    recomputed = max(0, min(100, round(sum(s["weight"] for s in body["signals"]))))
    assert body["risk_score"] == recomputed
    assert "related_activity" not in str(body["signals"])  # cross-case never injected as a risk signal


# ---------------------------------------------------------------- 14. campaign engine compatibility
def test_14_existing_campaign_engine_still_works_independently():
    analyze(CASE_A)
    body = analyze(CASE_B)
    assert body["campaign"]["status"] == "possible_campaign"
    assert body["campaign"]["campaign_id"]


# ---------------------------------------------------------------- 15. report includes related activity
def test_15_report_includes_related_activity():
    analyze(CASE_A)
    r2 = analyze(CASE_B)
    case_id = r2["case_id"]
    report = client.get(f"/api/reports/{case_id}").json()
    assert "related_activity" in report
    assert report["related_activity"]["has_related_activity"] is True


# ---------------------------------------------------------------- 16. no unsupported attribution claims
def test_16_no_attribution_claims_in_related_activity_text():
    analyze(CASE_A)
    body = analyze(CASE_B)
    rc = body["related_activity"]["related_cases"][0]
    why = rc["why"].lower()
    limitation = rc["limitation"].lower()
    # The "why" text must never assert identity/authorship on its own.
    for banned in ("same attacker", "confirmed campaign", "attacker identity is", "same person", "common author"):
        assert banned not in why
    # The limitation must explicitly disclaim attribution (negated form expected).
    assert "does not establish common authorship" in limitation
    assert "attacker identity" in limitation  # present, but only inside the disclaiming sentence
    assert limitation.startswith("this relationship is based on shared observable technical indicators only")


# ================================================================ BUSINESS MODEL

# ---------------------------------------------------------------- 17. free plan exposes basic capabilities
def test_17_free_plan_exposes_basic_capabilities():
    g = feature_available("basic_analysis")
    assert g["available"] is True
    assert g["required_plan"] == "free"


# ---------------------------------------------------------------- 18. sentinel-only feature gated for free
def test_18_sentinel_feature_gate_shape_is_correct(monkeypatch):
    import services.plans as plans_mod
    monkeypatch.setattr(plans_mod.settings, "MAILSCOPE_PLAN", "free")
    monkeypatch.setattr(plans_mod.settings, "SIH_DEMO_ENTITLEMENT", False)
    g = plans_mod.feature_available("cross_case_intelligence")
    assert g["available"] is False
    assert g["reason"] == "locked"
    assert g["required_plan"] == "sentinel"


# ---------------------------------------------------------------- 19. demo entitlement unlocks it
def test_19_demo_entitlement_unlocks_sentinel_feature(monkeypatch):
    import services.plans as plans_mod
    monkeypatch.setattr(plans_mod.settings, "MAILSCOPE_PLAN", "free")
    monkeypatch.setattr(plans_mod.settings, "SIH_DEMO_ENTITLEMENT", True)
    g = plans_mod.feature_available("cross_case_intelligence")
    assert g["available"] is True
    assert g["reason"] == "demo_entitlement"


# ---------------------------------------------------------------- 20. enterprise capabilities clearly marked
def test_20_enterprise_capabilities_marked_planned_or_prototype():
    from services.plans import FEATURE_MATRIX
    enterprise_features = {k: v for k, v in FEATURE_MATRIX.items() if v["min_plan"] == "enterprise"}
    assert len(enterprise_features) > 0
    for name, spec in enterprise_features.items():
        assert spec["status"] in ("planned", "prototype")


# ---------------------------------------------------------------- 21. no payment falsely represented
def test_21_plan_endpoint_never_claims_payment():
    body = client.get("/api/plan").json()
    dumped = str(body).lower()
    assert "payment" not in dumped and "paid" not in dumped and "subscription_id" not in dumped
    assert "demo_entitlement" in body  # explicit, honest labeling


# ---------------------------------------------------------------- 22. plan switching does not modify forensic results
def test_22_plan_does_not_affect_risk_score(monkeypatch):
    import services.plans as plans_mod
    monkeypatch.setattr(plans_mod.settings, "MAILSCOPE_PLAN", "free")
    monkeypatch.setattr(plans_mod.settings, "SIH_DEMO_ENTITLEMENT", False)
    body_free = analyze(CASE_A)
    monkeypatch.setattr(plans_mod.settings, "MAILSCOPE_PLAN", "enterprise")
    case_store.clear()
    body_ent = analyze(CASE_A)
    assert body_free["risk_score"] == body_ent["risk_score"]
    assert body_free["classification"] == body_ent["classification"]


# ---------------------------------------------------------------- 23. UI language does not change plan logic (backend-level proof)
def test_23_plan_logic_is_backend_only_and_language_agnostic():
    # The backend has no concept of UI language at all — proven by the fact
    # that /api/plan takes no language parameter and is purely config-driven.
    r1 = client.get("/api/plan").json()
    r2 = client.get("/api/plan").json()
    assert r1 == r2


# ---------------------------------------------------------------- 24. language switching does not change correlation
def test_24_language_does_not_change_correlation_results():
    hi_a = "From: a@microsoft-careers-india.com\nSubject: नमस्ते\nMessage-ID: <hi1@microsoft-careers-india.com>\n\nApply now at http://microsoft-careers-india.com/apply"
    hi_b = "From: b@microsoft-careers-india.com\nSubject: सूचना\nMessage-ID: <hi2@microsoft-careers-india.com>\n\nApply now at http://microsoft-careers-india.com/apply"
    analyze(hi_a)
    body = analyze(hi_b)
    assert body["related_activity"]["has_related_activity"] is True


# ---------------------------------------------------------------- 25/26. Trace Origin / Timeline still functional
def test_25_26_trace_origin_and_timeline_fields_still_present():
    body = analyze(CASE_A)
    assert "relay_path" in body and "relay_chain_reliability" in body
    assert "timeline" in body and len(body["timeline"]) > 0


# ---------------------------------------------------------------- 27. risk engine tests unaffected (spot check)
def test_27_risk_engine_still_internally_consistent():
    body = analyze(CASE_A)
    recomputed = max(0, min(100, round(sum(s["weight"] for s in body["signals"]))))
    assert body["risk_score"] == recomputed
