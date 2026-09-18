"""
Phase 4 threat-intelligence tests. Run in an environment with NO API keys
configured and (typically) no outbound access to rdap.org/virustotal.com/
ipinfo.io/abuseipdb.com — every assertion here is about graceful
degradation, not about successfully reaching a real external service.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from services.domain_intel import gather_domain_intel, is_plausible_domain, _extract_registrar, _extract_domain_age_days
from services.ip_intel import gather_ip_intel, is_plausible_ip


def test_malformed_domain_short_circuits_without_crashing():
    result = gather_domain_intel("not a domain !! ###")
    assert result["a_records"] == "unavailable"
    assert result["reputation"] == "unavailable"
    assert result["registrar"] == "unavailable"
    assert result["age_days"] == "unavailable"
    assert "note" in result


def test_empty_domain_does_not_crash():
    result = gather_domain_intel("")
    assert result["a_records"] == "unavailable"


def test_is_plausible_domain():
    assert is_plausible_domain("example.com") is True
    assert is_plausible_domain("sub.example.co.uk") is True
    assert is_plausible_domain("not a domain") is False
    assert is_plausible_domain("") is False
    assert is_plausible_domain(None) is False


def test_domain_intel_never_crashes_even_without_network(monkeypatch):
    # No API keys set in this environment by default — reputation must be "unavailable".
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    import config
    config.get_settings.cache_clear()
    result = gather_domain_intel("example.com")
    assert result["reputation"] == "unavailable"
    assert isinstance(result["interpretation"], list)


def test_registrar_extraction_returns_unavailable_for_missing_data():
    assert _extract_registrar("unavailable") == "unavailable"
    assert _extract_registrar({}) == "unavailable"
    assert _extract_registrar({"entities": []}) == "unavailable"


def test_registrar_extraction_from_real_rdap_shape():
    rdap = {"entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar Inc."]]]}]}
    assert _extract_registrar(rdap) == "Example Registrar Inc."


def test_domain_age_extraction_never_fabricates():
    assert _extract_domain_age_days("unavailable") == "unavailable"
    assert _extract_domain_age_days({"events": []}) == "unavailable"
    assert _extract_domain_age_days({"events": [{"eventAction": "last changed", "eventDate": "2020-01-01T00:00:00Z"}]}) == "unavailable"


def test_domain_age_computed_from_real_registration_event():
    rdap = {"events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}]}
    age = _extract_domain_age_days(rdap)
    assert isinstance(age, int)
    assert age > 1000  # more than ~3 years ago relative to any plausible "now"


def test_malformed_ip_short_circuits_without_crashing():
    result = gather_ip_intel("999.999.999.999")
    assert result["country"] == "unavailable"
    assert result["reputation"] == "unavailable"
    assert "note" in result


def test_non_ip_string_does_not_crash():
    result = gather_ip_intel("definitely-not-an-ip")
    assert result["asn"] == "unavailable"


def test_is_plausible_ip():
    assert is_plausible_ip("8.8.8.8") is True
    assert is_plausible_ip("2001:4860:4860::8888") is True
    assert is_plausible_ip("999.999.999.999") is False
    assert is_plausible_ip("") is False
    assert is_plausible_ip(None) is False


def test_ip_intel_no_keys_returns_unavailable_not_fake(monkeypatch):
    monkeypatch.delenv("IPINFO_TOKEN", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    import config
    config.get_settings.cache_clear()
    result = gather_ip_intel("8.8.8.8")
    assert result["reputation"] == "unavailable"
    assert isinstance(result["interpretation"], list)


def test_no_secrets_leak_into_result():
    result = gather_domain_intel("example.com")
    dumped = str(result)
    assert "VIRUSTOTAL_API_KEY" not in dumped
    assert "IPINFO_TOKEN" not in dumped
