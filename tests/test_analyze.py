"""
Run with:  cd backend && pytest ../tests -v

These tests exercise the deterministic parts of the pipeline (parsing,
headers, auth, URLs, risk fusion) without requiring Supabase or any
external API key — those degrade to "unavailable" as designed.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from fastapi.testclient import TestClient
from app import app

client = TestClient(app)

SAMPLE_PHISHING = """From: "IT Security" <it-security@paypal-secure-login.com>
Reply-To: attacker@relay-mail.example
To: victim@example.com
Subject: Urgent: Verify your password within 24 hours
Message-ID: <abc123@paypal-secure-login.com>
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=paypal-secure-login.com; dkim=fail; dmarc=fail

Dear Customer,

Your account has been suspended. Click here to verify your password and confirm your identity:
http://paypal-secure-login.com/verify

Act now or lose access.
"""

SAMPLE_BENIGN = """From: alice@example.com
To: bob@example.com
Subject: Lunch tomorrow?
Message-ID: <xyz@example.com>

Hey Bob, are we still on for lunch tomorrow at 1pm?
"""


def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert "mode" in r.json()


def test_analyze_rejects_empty_input():
    r = client.post("/api/analyze", data={"email_text": ""})
    assert r.status_code == 400


def test_analyze_phishing_sample():
    r = client.post("/api/analyze", data={"email_text": SAMPLE_PHISHING})
    assert r.status_code == 200
    body = r.json()
    assert body["risk_score"] > 0
    assert body["classification"] in ("phishing", "suspicious", "impersonation")
    assert body["authentication"]["spf"] == "fail"
    assert any(u["lookalike_of"] for u in body["urls"])
    assert body["evidence"]["sha256"]  # real hash present


def test_analyze_benign_sample():
    r = client.post("/api/analyze", data={"email_text": SAMPLE_BENIGN})
    assert r.status_code == 200
    body = r.json()
    assert body["classification"] == "benign"
    assert body["risk_score"] < 25


def test_analytics_no_supabase_returns_zero_not_fake():
    r = client.get("/api/analytics")
    assert r.status_code == 200
    body = r.json()
    if body["mode"] == "live" and body["persistence"] == "unavailable":
        assert body["emails_analyzed"] == 0
