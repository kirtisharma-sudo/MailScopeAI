import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from services.campaign_engine import correlate, find_relationships


def ind(type_, value):
    return {"type": type_, "value": value}


def test_two_cases_sharing_a_domain():
    case_a_indicators = [ind("domain", "evil-example.com"), ind("sender_address", "a@x.com")]
    prior = [{"case_id": "CASE-A", "indicators": [ind("domain", "evil-example.com")]}]
    result = correlate("CASE-B", case_a_indicators, prior)
    assert result["status"] == "possible_campaign"
    assert result["related_case_count"] == 1
    assert any(r["relationship_type"] == "shared_domain" for r in result["relationships"])


def test_two_cases_sharing_an_ip():
    prior = [{"case_id": "CASE-A", "indicators": [ind("ip", "203.0.113.9")]}]
    result = correlate("CASE-B", [ind("ip", "203.0.113.9")], prior)
    assert result["status"] == "possible_campaign"
    rel = result["relationships"][0]
    assert rel["relationship_type"] == "shared_ip"
    assert rel["shared_indicator"] == "203.0.113.9"


def test_two_cases_sharing_an_attachment_hash():
    h = "a" * 64
    prior = [{"case_id": "CASE-A", "indicators": [ind("attachment_sha256", h)]}]
    result = correlate("CASE-B", [ind("attachment_sha256", h)], prior)
    assert result["status"] == "possible_campaign"
    rel = result["relationships"][0]
    assert rel["relationship_type"] == "shared_attachment_hash"
    # Attachment hash match should be the highest-confidence relationship type
    assert rel["confidence"] >= 0.9


def test_two_unrelated_cases_are_isolated():
    prior = [{"case_id": "CASE-A", "indicators": [ind("domain", "somewhere-else.example")]}]
    result = correlate("CASE-B", [ind("domain", "totally-different.example")], prior)
    assert result["status"] == "isolated"
    assert result["campaign_id"] is None
    assert result["relationships"] == []


def test_low_value_shared_indicator_is_ignored():
    prior = [{"case_id": "CASE-A", "indicators": [ind("reply_to_domain", "gmail.com")]}]
    result = correlate("CASE-B", [ind("reply_to_domain", "gmail.com")], prior)
    assert result["status"] == "isolated"


def test_multiple_shared_indicators_increase_combined_confidence():
    prior = [{"case_id": "CASE-A", "indicators": [ind("domain", "evil.example"), ind("ip", "203.0.113.5")]}]
    single = correlate("CASE-B", [ind("domain", "evil.example")], prior)
    multi = correlate("CASE-C", [ind("domain", "evil.example"), ind("ip", "203.0.113.5")], prior)
    assert multi["relationships"][0]["confidence"] > single["relationships"][0]["confidence"]


def test_in_memory_correlation_without_supabase_end_to_end():
    """Exercises correlate() the same way analyze.py does — pure function,
    no Supabase or network dependency at all."""
    prior = [{"case_id": "CASE-A", "indicators": [ind("url", "http://phish.example/login")]}]
    result = correlate("CASE-B", [ind("url", "http://phish.example/login")], prior)
    assert result["status"] == "possible_campaign"


def test_relationship_output_schema():
    prior = [{"case_id": "CASE-A", "indicators": [ind("domain", "evil.example")]}]
    result = correlate("CASE-B", [ind("domain", "evil.example")], prior)
    rel = result["relationships"][0]
    for key in ("campaign_id", "relationship_type", "source_case", "target_case", "shared_indicator", "confidence"):
        assert key in rel


def test_confidence_is_generated_not_constant_across_types():
    prior_ip = [{"case_id": "CASE-A", "indicators": [ind("ip", "203.0.113.5")]}]
    prior_hash = [{"case_id": "CASE-B", "indicators": [ind("attachment_sha256", "b" * 64)]}]
    r_ip = correlate("CASE-X", [ind("ip", "203.0.113.5")], prior_ip)
    r_hash = correlate("CASE-Y", [ind("attachment_sha256", "b" * 64)], prior_hash)
    assert r_hash["relationships"][0]["confidence"] > r_ip["relationships"][0]["confidence"]


def test_campaign_separation_unrelated_clusters_get_different_ids():
    prior = [
        {"case_id": "CASE-A", "indicators": [ind("domain", "cluster-one.example")]},
        {"case_id": "CASE-C", "indicators": [ind("domain", "cluster-two.example")]},
    ]
    r1 = correlate("CASE-B", [ind("domain", "cluster-one.example")], prior)
    r2 = correlate("CASE-D", [ind("domain", "cluster-two.example")], prior)
    assert r1["campaign_id"] != r2["campaign_id"]


def test_find_relationships_returns_empty_for_no_indicators():
    assert find_relationships("CASE-X", [], [{"case_id": "CASE-A", "indicators": [ind("domain", "x.com")]}]) == []
