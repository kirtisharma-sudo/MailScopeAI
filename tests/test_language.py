import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from fastapi.testclient import TestClient
from app import app
from services.language_detector import detect_language
from services import case_store

client = TestClient(app)


def setup_function():
    case_store.clear()


ENGLISH_TEXT = "Your account has been suspended. Verify now."
HINDI_TEXT = "आपका खाता निलंबित कर दिया गया है। अभी सत्यापित करें।"
MIXED_TEXT = "Your account बंद कर दिया गया है. Please verify immediately."

HINDI_PHISHING_EMAIL = """From: security@examplebank.com
Subject: सुरक्षा चेतावनी
Message-ID: <hi1@examplebank.com>

प्रिय ग्राहक,

आपके बैंक खाते में संदिग्ध गतिविधि पाई गई है।
अपना खाता सत्यापित करने के लिए नीचे दिए गए लिंक पर क्लिक करें।

धन्यवाद
"""

HINDI_BENIGN_EMAIL = """From: friend@example.com
Subject: कल का प्लान
Message-ID: <hi2@example.com>

नमस्ते, क्या हम कल दोपहर के भोजन के लिए मिल सकते हैं?
"""


# ---------------------------------------------------------------- unit-level detector tests

def test_english_detection():
    result = detect_language(ENGLISH_TEXT)
    assert result["detected"] == "en"
    assert result["analysis_support"] == "supported"


def test_hindi_detection():
    result = detect_language(HINDI_TEXT)
    assert result["detected"] == "hi"
    assert result["analysis_support"] == "limited"
    assert result["display_name"] == "Hindi"


def test_mixed_language_detection():
    result = detect_language(MIXED_TEXT)
    assert result["detected"] == "mixed"
    assert result["analysis_support"] == "limited"


def test_empty_text_detection():
    result = detect_language("")
    assert result["detected"] == "unknown"


def test_detector_never_returns_fabricated_confidence_for_empty_input():
    result = detect_language("   ")
    assert "confidence" not in result


def test_detector_confidence_is_a_real_measured_ratio():
    result = detect_language(HINDI_TEXT)
    assert 0.0 <= result["confidence"] <= 1.0
    assert result["devanagari_char_count"] > 0


# ---------------------------------------------------------------- full pipeline tests

def test_hindi_phishing_email_is_analyzed_not_skipped():
    resp = client.post("/api/analyze", data={"email_text": HINDI_PHISHING_EMAIL})
    assert resp.status_code == 200
    body = resp.json()
    assert body["language"]["detected"] == "hi"
    assert body["risk_score"] >= 0  # analysis actually ran, didn't crash/skip


def test_hindi_benign_email_stays_low_risk():
    resp = client.post("/api/analyze", data={"email_text": HINDI_BENIGN_EMAIL})
    body = resp.json()
    assert body["language"]["detected"] == "hi"
    assert body["classification"] == "benign"
    assert body["risk_score"] < 25


def test_language_never_appears_as_a_risk_signal():
    """Language must contribute ZERO risk points — verified structurally: no
    signal in the signals list may be named/derived from language."""
    resp_en = client.post("/api/analyze", data={"email_text": "From: a@example.com\nSubject: hi\nMessage-ID: <1@example.com>\n\nJust checking in about lunch tomorrow."})
    resp_hi = client.post("/api/analyze", data={"email_text": "From: a@example.com\nSubject: नमस्ते\nMessage-ID: <2@example.com>\n\nकल दोपहर के भोजन के बारे में पूछ रहा हूँ।"})

    for body in (resp_en.json(), resp_hi.json()):
        for sig in body["signals"]:
            assert "language" not in sig["name"].lower()
            assert "hindi" not in sig["explanation"].lower()
            assert "english" not in sig["explanation"].lower()

    # Two near-identical benign messages (one EN, one HI) should both land
    # in the same low-risk territory — language alone doesn't move the score.
    assert resp_en.json()["risk_score"] < 25
    assert resp_hi.json()["risk_score"] < 25


def test_mixed_language_email_is_analyzed():
    email = "From: a@example.com\nSubject: Update\nMessage-ID: <3@example.com>\n\nYour account बंद कर दिया गया है. Please verify immediately."
    resp = client.post("/api/analyze", data={"email_text": email})
    body = resp.json()
    assert resp.status_code == 200
    assert body["language"]["detected"] == "mixed"


def test_existing_english_analysis_unchanged():
    """Regression: a known English phishing sample should still classify the
    same way it did before language detection was added."""
    email = "From: security@paypa1-verify.com\nReply-To: security@relay.example\nSubject: Verify your password now\nAuthentication-Results: mx; spf=fail; dkim=fail; dmarc=fail\n\nYour account will be suspended. Click here to verify your password: http://paypa1-verify.com/login"
    resp = client.post("/api/analyze", data={"email_text": email})
    body = resp.json()
    assert body["language"]["detected"] == "en"
    assert body["risk_score"] > 30
    assert body["authentication"]["spf"] == "fail"


def test_limitations_mention_hindi_support_status():
    resp = client.post("/api/analyze", data={"email_text": HINDI_BENIGN_EMAIL})
    limitations = " ".join(resp.json()["limitations"])
    assert "Hindi" in limitations
