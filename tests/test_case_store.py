import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from services import case_store


def setup_function():
    case_store.clear()


def test_save_and_retrieve_case():
    case_store.save_case("CASE-1", {"case_id": "CASE-1", "risk_score": 42})
    result = case_store.get_case("CASE-1")
    assert result["risk_score"] == 42


def test_missing_case_returns_none():
    assert case_store.get_case("CASE-DOES-NOT-EXIST") is None


def test_update_case_merges_fields():
    case_store.save_case("CASE-2", {"case_id": "CASE-2", "analyst_notes": ""})
    updated = case_store.update_case("CASE-2", {"analyst_notes": "Looks suspicious."})
    assert updated["analyst_notes"] == "Looks suspicious."
    assert case_store.get_case("CASE-2")["analyst_notes"] == "Looks suspicious."


def test_update_missing_case_returns_none():
    assert case_store.update_case("CASE-NOPE", {"analyst_notes": "x"}) is None


def test_capacity_limit_evicts_oldest_first(monkeypatch):
    import config
    settings = config.get_settings()
    monkeypatch.setattr(settings, "MAX_IN_MEMORY_CASES", 3)
    for i in range(5):
        case_store.save_case(f"CASE-{i}", {"case_id": f"CASE-{i}"})
    assert case_store.case_count() == 3
    # oldest (CASE-0, CASE-1) should have been evicted; newest 3 remain
    assert case_store.get_case("CASE-0") is None
    assert case_store.get_case("CASE-1") is None
    assert case_store.get_case("CASE-4") is not None


def test_returned_case_is_a_copy_not_a_live_reference():
    case_store.save_case("CASE-3", {"case_id": "CASE-3", "notes": "original"})
    fetched = case_store.get_case("CASE-3")
    fetched["notes"] = "mutated locally"
    assert case_store.get_case("CASE-3")["notes"] == "original"
