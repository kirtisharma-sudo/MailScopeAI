"""
Lightweight, thread-safe, process-lifetime case store.

Purpose: campaign correlation and forensic-report retrieval must work in a
demo with no Supabase configured. This store holds the FULL structured
analysis result (everything /api/analyze already returns, minus raw email
bytes — those are never stored here or anywhere) keyed by case_id.

Not a database: cleared on process restart, capped at MAX_IN_MEMORY_CASES
(oldest evicted first, deterministic FIFO via OrderedDict). When Supabase
IS configured, it remains the durable backend (see supabase_client.py);
this store is used transparently in both cases so campaign correlation and
report retrieval have a single, always-available source to read from.
"""
from __future__ import annotations
import threading
from collections import OrderedDict
from config import get_settings

settings = get_settings()

_lock = threading.RLock()
_store: "OrderedDict[str, dict]" = OrderedDict()


def save_case(case_id: str, case_data: dict) -> None:
    """Stores/updates a case. Evicts the oldest case(s) once capacity is
    exceeded — deterministic, not random or time-based."""
    with _lock:
        _store[case_id] = case_data
        _store.move_to_end(case_id)
        while len(_store) > settings.MAX_IN_MEMORY_CASES:
            _store.popitem(last=False)


def get_case(case_id: str) -> dict | None:
    with _lock:
        case = _store.get(case_id)
        return dict(case) if case is not None else None


def update_case(case_id: str, updates: dict) -> dict | None:
    """Merges `updates` into an existing case. Returns the updated case, or
    None if the case doesn't exist (caller should 404, never fabricate)."""
    with _lock:
        case = _store.get(case_id)
        if case is None:
            return None
        case.update(updates)
        _store.move_to_end(case_id)
        return dict(case)


def list_all_cases() -> list[dict]:
    with _lock:
        return [dict(c) for c in _store.values()]


def case_count() -> int:
    with _lock:
        return len(_store)


def clear() -> None:
    """Test-only helper — clears the store between test runs."""
    with _lock:
        _store.clear()
