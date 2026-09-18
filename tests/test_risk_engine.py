"""
Regression tests for the risk-engine rewrite. Central invariant tested
everywhere: risk_score is EXACTLY reproducible from the returned signals
(sum of weights, clamped to 100) — this is the fix for the reported bug
where displayed evidence summed to 83 but the UI showed 55.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from fastapi.testclient import TestClient
from app import app
from services.risk_engine import fuse_signals, classify_from_score, confidence_from_evidence, deduplicate_overlapping_signals

client = TestClient(app)


def recompute_score(signals):
    """The exact formula documented in risk_engine.py — used to
    independently verify the API's risk_score without importing internals."""
    return max(0, min(100, round(sum(s["weight"] for s in signals))))


# ---------------------------------------------------------------- A. known synthetic phishing email
KNOWN_PHISHING_EMAIL = """From: "Microsoft Security" <alert@microsoft-secure-alert.com>
Reply-To: support@totally-different-relay.example
Subject: Verify your account
Message-ID: <abc123@some-other-domain.example>
Authentication-Results: mx; spf=fail; dkim=fail; dmarc=fail

Dear user, your account requires verification. Click here to verify: http://microsoft-secure-alert.com/verify
"""

def test_a_known_phishing_email_score_matches_evidence_sum():
    r = client.post("/api/analyze", data={"email_text": KNOWN_PHISHING_EMAIL})
    body = r.json()
    assert body["risk_score"] == recompute_score(body["signals"])
    assert body["classification"] == "phishing"
    # The two overlapping impersonation signals (lookalike URL + lookalike
    # sender domain) must have been merged into ONE signal, not two.
    names = [s["name"] for s in body["signals"]]
    assert "identity_impersonation" in names
    assert "lookalike_domain" not in names
    assert "sender_domain_lookalike" not in names
    assert names.count("identity_impersonation") == 1


# ---------------------------------------------------------------- B. legitimate email
def test_b_legitimate_email_is_low_risk_and_consistent():
    email = "From: alice@example.com\nTo: bob@example.com\nSubject: Lunch\nMessage-ID: <1@example.com>\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\nReceived: from mail.example.com (mail.example.com [93.184.216.34]) by mx.recipient.com with ESMTP; Mon, 01 Sep 2025 10:00:05 +0000\n\nWant to grab lunch Thursday?"
    r = client.post("/api/analyze", data={"email_text": email})
    body = r.json()
    assert body["classification"] == "benign"
    assert body["risk_score"] == recompute_score(body["signals"])
    assert body["risk_score"] < 25


# ---------------------------------------------------------------- C. Reply-To mismatch alone
def test_c_reply_to_mismatch_alone_is_weak_not_decisive():
    email = "From: billing@genuine.example\nReply-To: payouts@different.example\nSubject: Invoice\nMessage-ID: <1@genuine.example>\n\nInvoice attached."
    r = client.post("/api/analyze", data={"email_text": email})
    body = r.json()
    names = [s["name"] for s in body["signals"]]
    assert "reply_to_mismatch" in names
    assert body["risk_score"] == recompute_score(body["signals"])
    assert body["classification"] != "phishing"  # one weak-to-moderate signal alone shouldn't reach phishing


# ---------------------------------------------------------------- D. SPF/DKIM/DMARC failures
def test_d_auth_failures_parsed_and_scored_consistently():
    email = "From: a@example.com\nSubject: x\nMessage-ID: <1@example.com>\nAuthentication-Results: mx; spf=fail; dkim=fail; dmarc=fail\n\nbody"
    r = client.post("/api/analyze", data={"email_text": email})
    body = r.json()
    assert body["authentication"]["spf"] == "fail"
    assert body["score_breakdown"].get("authentication") == 28  # 8+8+12, undamaged by any cap
    assert body["risk_score"] == recompute_score(body["signals"])


# ---------------------------------------------------------------- E. authentication unavailable != fail
def test_e_authentication_unavailable_is_not_treated_as_fail():
    email = "From: a@example.com\nSubject: x\nMessage-ID: <1@example.com>\n\nJust a normal note, nothing suspicious here."
    r = client.post("/api/analyze", data={"email_text": email})
    body = r.json()
    assert body["authentication"]["spf"] == "unavailable"
    assert body["authentication"]["dkim"] == "unavailable"
    assert body["authentication"]["dmarc"] == "unavailable"
    names = [s["name"] for s in body["signals"]]
    assert "spf_fail" not in names and "dkim_fail" not in names and "dmarc_fail" not in names
    assert "authentication" not in body["score_breakdown"]  # zero risk weight contributed
    assert any("unavailable" in lim.lower() for lim in body["limitations"])
    # Confidence should be reduced because authentication data is missing.
    assert body["confidence"] < 85


# ---------------------------------------------------------------- F. lookalike domain (URL only, no sender overlap)
def test_f_lookalike_domain_url_only():
    email = "From: a@genuinesender.example\nSubject: x\nMessage-ID: <1@genuinesender.example>\n\nClick http://paypal-secure-login.example/verify"
    r = client.post("/api/analyze", data={"email_text": email})
    body = r.json()
    names = [s["name"] for s in body["signals"]]
    assert "lookalike_domain" in names
    assert "identity_impersonation" not in names  # no matching sender-domain signal to merge with
    assert body["risk_score"] == recompute_score(body["signals"])


# ---------------------------------------------------------------- G. Message-ID mismatch alone
def test_g_message_id_mismatch_alone_stays_weak():
    email = "From: a@example.com\nSubject: x\nMessage-ID: <xyz@totally-different.example>\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\nReceived: from mail.example.com (mail.example.com [93.184.216.34]) by mx.recipient.com with ESMTP; Mon, 01 Sep 2025 10:00:05 +0000\n\nRoutine update."
    r = client.post("/api/analyze", data={"email_text": email})
    body = r.json()
    names = [s["name"] for s in body["signals"]]
    assert "message_id_domain_mismatch" in names
    assert body["classification"] == "benign"
    assert body["risk_score"] < 25
    # It must never be the majority contributor when paired with any real evidence.
    mid_weight = next(s["weight"] for s in body["signals"] if s["name"] == "message_id_domain_mismatch")
    assert mid_weight <= 8


# ---------------------------------------------------------------- H. overlapping identity/domain/URL evidence
def test_h_overlapping_evidence_is_deduplicated_not_summed():
    signals = [
        {"name": "lookalike_domain", "severity": "high", "weight": 15, "explanation": "x", "brand": "microsoft"},
        {"name": "sender_domain_lookalike", "severity": "high", "weight": 16, "explanation": "y", "brand": "microsoft"},
    ]
    deduped = deduplicate_overlapping_signals(signals)
    assert len(deduped) == 1
    assert deduped[0]["name"] == "identity_impersonation"
    assert deduped[0]["weight"] < 15 + 16  # never the naive sum
    assert deduped[0]["weight"] >= max(15, 16)  # but at least as strong as the stronger single observation


def test_h_no_merge_when_brands_differ():
    signals = [
        {"name": "lookalike_domain", "severity": "high", "weight": 15, "explanation": "x", "brand": "paypal"},
        {"name": "sender_domain_lookalike", "severity": "high", "weight": 16, "explanation": "y", "brand": "microsoft"},
    ]
    deduped = deduplicate_overlapping_signals(signals)
    assert len(deduped) == 2  # different brands = genuinely different evidence, not merged


# ---------------------------------------------------------------- I. suspicious attachment
def test_i_suspicious_attachment_scored_and_consistent():
    import base64
    payload = base64.b64encode(b"MZfakebinary").decode()
    raw = f"""From: a@example.com
Subject: Invoice
Message-ID: <1@example.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="B"

--B
Content-Type: text/plain

See attached.

--B
Content-Type: application/octet-stream; name="invoice.pdf.exe"
Content-Disposition: attachment; filename="invoice.pdf.exe"
Content-Transfer-Encoding: base64

{payload}
--B--
""".encode()
    r = client.post("/api/analyze", files={"file": ("sample.eml", raw, "message/rfc822")})
    body = r.json()
    names = [s["name"] for s in body["signals"]]
    assert "suspicious_attachment_extension" in names
    assert "double_extension_attachment" in names
    assert body["score_breakdown"].get("attachment", 0) > 0
    assert body["risk_score"] == recompute_score(body["signals"])


# ---------------------------------------------------------------- J. high-risk evidence with incomplete metadata
def test_j_high_risk_with_incomplete_metadata_has_lower_confidence():
    """No Received headers, no Authentication-Results at all, but strong
    identity+content evidence — risk can still be high, but confidence
    should reflect the missing corroborating context."""
    email = "From: \"Bank Security\" <alert@paypal-account-verify.example>\nReply-To: x@other.example\nSubject: Verify your account now urgent\nMessage-ID: <1@other.example>\n\nURGENT: verify your account immediately by clicking here: http://paypal-account-verify.example/login"
    r = client.post("/api/analyze", data={"email_text": email})
    body = r.json()
    assert body["risk_score"] >= 50
    assert body["confidence"] <= 80  # capped down due to missing auth + missing relay chain
    assert body["risk_score"] == recompute_score(body["signals"])


# ---------------------------------------------------------------- K. determinism
def test_k_same_email_analyzed_twice_produces_the_same_score():
    r1 = client.post("/api/analyze", data={"email_text": KNOWN_PHISHING_EMAIL})
    r2 = client.post("/api/analyze", data={"email_text": KNOWN_PHISHING_EMAIL})
    assert r1.json()["risk_score"] == r2.json()["risk_score"]
    assert r1.json()["classification"] == r2.json()["classification"]
    assert r1.json()["confidence"] == r2.json()["confidence"]


# ---------------------------------------------------------------- L. score always 0-100
def test_l_score_never_leaves_0_100_bounds():
    huge_signals = [{"name": f"sig{i}", "severity": "high", "weight": 30, "explanation": "x"} for i in range(10)]
    score, deduped, breakdown = fuse_signals(huge_signals)
    assert 0 <= score <= 100
    empty_score, _, _ = fuse_signals([])
    assert empty_score == 0


# ---------------------------------------------------------------- M. UI language never changes the score
def test_m_language_does_not_affect_risk_score():
    en = "From: a@example.com\nSubject: Update\nMessage-ID: <1@example.com>\n\nYour account has been suspended. Verify now."
    hi = "From: a@example.com\nSubject: Update\nMessage-ID: <2@example.com>\nContent-Type: text/plain; charset=UTF-8\n\nआपका खाता निलंबित कर दिया गया है। अभी सत्यापित करें।"
    r_en = client.post("/api/analyze", data={"email_text": en}).json()
    r_hi = client.post("/api/analyze", data={"email_text": hi}).json()
    # Both are a single weak keyword match with no header/auth evidence —
    # language choice itself must not move the score into a different bracket.
    assert r_en["risk_score"] < 25
    assert r_hi["risk_score"] < 25


# ---------------------------------------------------------------- Section 15: displayed sum == authoritative score
def test_displayed_signal_weights_always_reproduce_the_final_score():
    """The exact bug from the report: evidence summed to 83 while the UI
    showed 55. This test asserts that can never happen again, across a
    range of representative cases."""
    cases = [KNOWN_PHISHING_EMAIL,
             "From: a@example.com\nSubject: hi\nMessage-ID: <1@example.com>\n\nRoutine message, nothing notable.",
             "From: a@example.com\nReply-To: b@other.example\nSubject: x\nMessage-ID: <1@example.com>\nAuthentication-Results: mx; spf=fail; dkim=fail; dmarc=fail\n\nClick http://totally-fake-bank-login.example/verify now"]
    for email in cases:
        body = client.post("/api/analyze", data={"email_text": email}).json()
        assert body["risk_score"] == recompute_score(body["signals"]), \
            f"Displayed evidence sum does not match risk_score for: {email[:40]}..."


# ---------------------------------------------------------------- confidence/risk decoupling
def test_confidence_is_not_a_function_of_risk_score_value():
    """Two very different risk scores can share similar confidence, and
    conversely — confidence must come from evidence breadth/completeness,
    not from how high or low the score itself is."""
    low_risk_high_confidence_signals = [
        {"name": "spf_fail", "severity": "medium", "weight": 8, "explanation": "x"},
    ]
    high_risk_signals = [
        {"name": "reply_to_mismatch", "severity": "high", "weight": 18, "explanation": "x"},
        {"name": "spf_fail", "severity": "medium", "weight": 8, "explanation": "x"},
        {"name": "dkim_fail", "severity": "medium", "weight": 8, "explanation": "x"},
        {"name": "dmarc_fail", "severity": "high", "weight": 12, "explanation": "x"},
        {"name": "lookalike_domain", "severity": "high", "weight": 15, "explanation": "x", "brand": "test"},
    ]
    auth_available = {"spf": "fail", "dkim": "fail", "dmarc": "fail"}
    c_low = confidence_from_evidence(low_risk_high_confidence_signals, auth_available, True)
    c_high = confidence_from_evidence(high_risk_signals, auth_available, True)
    # More distinct categories of agreeing evidence -> higher confidence,
    # regardless of what the resulting risk_score number happens to be.
    assert c_high > c_low
