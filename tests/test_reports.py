import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from fastapi.testclient import TestClient
from app import app
from services import case_store
from services.report_builder import build_forensic_report

client = TestClient(app)


def setup_function():
    case_store.clear()


def test_report_generation_from_real_analysis():
    analyze_resp = client.post("/api/analyze", data={"email_text": "From: a@example.com\nSubject: hi\nMessage-ID: <1@example.com>\n\nhello there"})
    case_id = analyze_resp.json()["case_id"]

    report_resp = client.get(f"/api/reports/{case_id}")
    assert report_resp.status_code == 200
    report = report_resp.json()
    assert report["case_id"] == case_id
    assert report["summary"]["classification"] == analyze_resp.json()["classification"]
    assert report["evidence"]["sha256"] == analyze_resp.json()["evidence"]["sha256"]


def test_report_retrieval_works_without_supabase():
    # In this test environment SUPABASE_URL is unset, so this exercises the
    # in-memory-store path end to end.
    analyze_resp = client.post("/api/analyze", data={"email_text": "From: b@example.com\nSubject: test\nMessage-ID: <2@example.com>\n\nbody text"})
    case_id = analyze_resp.json()["case_id"]
    report = client.get(f"/api/reports/{case_id}").json()
    assert report["engine"]["engine_version"] != "unavailable"


def test_missing_case_returns_404_not_fake_report():
    resp = client.get("/api/reports/CASE-DOES-NOT-EXIST")
    assert resp.status_code == 404


def test_report_builder_missing_field_handling():
    minimal_case = {"case_id": "CASE-MIN"}
    report = build_forensic_report(minimal_case)
    assert report["summary"]["classification"] == "unavailable"
    assert report["headers"] == {}
    assert report["urls"] == []
    assert report["analyst_notes"] == ""


def test_evidence_hash_present_in_report():
    resp = client.post("/api/analyze", data={"email_text": "From: c@example.com\nSubject: x\nMessage-ID: <3@example.com>\n\ncontent"})
    case_id = resp.json()["case_id"]
    report = client.get(f"/api/reports/{case_id}").json()
    assert len(report["evidence"]["sha256"]) == 64  # real sha256 hex digest length


def test_analyst_notes_update_and_retrieval():
    resp = client.post("/api/analyze", data={"email_text": "From: d@example.com\nSubject: x\nMessage-ID: <4@example.com>\n\ncontent"})
    case_id = resp.json()["case_id"]

    update_resp = client.post(f"/api/reports/{case_id}/notes", json={"notes": "Confirmed with the user; benign."})
    assert update_resp.status_code == 200
    assert update_resp.json()["analyst_notes"] == "Confirmed with the user; benign."

    report = client.get(f"/api/reports/{case_id}").json()
    assert report["analyst_notes"] == "Confirmed with the user; benign."


def test_analyst_notes_strip_html_injection():
    resp = client.post("/api/analyze", data={"email_text": "From: e@example.com\nSubject: x\nMessage-ID: <5@example.com>\n\ncontent"})
    case_id = resp.json()["case_id"]

    malicious = "<script>alert('xss')</script>Looks like phishing"
    update_resp = client.post(f"/api/reports/{case_id}/notes", json={"notes": malicious})
    stored = update_resp.json()["analyst_notes"]
    assert "<script>" not in stored
    assert "Looks like phishing" in stored


def test_analyst_notes_on_missing_case_returns_404():
    resp = client.post("/api/reports/CASE-NOPE/notes", json={"notes": "test"})
    assert resp.status_code == 404


def test_analyst_notes_does_not_overwrite_evidence():
    resp = client.post("/api/analyze", data={"email_text": "From: f@example.com\nSubject: x\nMessage-ID: <6@example.com>\n\ncontent"})
    case_id = resp.json()["case_id"]
    original_hash = resp.json()["evidence"]["sha256"]

    client.post(f"/api/reports/{case_id}/notes", json={"notes": "a note"})
    report = client.get(f"/api/reports/{case_id}").json()
    assert report["evidence"]["sha256"] == original_hash
