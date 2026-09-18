"""
Single place campaign correlation (and anything else that needs "all prior
cases") asks for indicator data. Automatically prefers Supabase when
configured (durable, survives restarts); falls back to the in-memory
case_store otherwise — so campaign correlation works in a Supabase-less
demo without any special-casing at the call site.
"""
from config import get_settings
from services import supabase_client, case_store

settings = get_settings()


def get_all_case_indicators(exclude_case_id: str | None = None) -> list[dict]:
    """Returns [{"case_id": ..., "indicators": [{"type":..., "value":...}, ...]}, ...]."""
    if settings.SUPABASE_URL:
        rows = supabase_client.fetch_all_case_indicators()
        if rows:
            return [r for r in rows if r["case_id"] != exclude_case_id]
        # Supabase configured but empty/unreachable for this call — fall
        # through to in-memory so a demo isn't silently broken by a flaky
        # Supabase connection.

    cases = case_store.list_all_cases()
    return [
        {"case_id": c["case_id"], "indicators": c.get("indicators", [])}
        for c in cases
        if c.get("case_id") != exclude_case_id
    ]


def get_case(case_id: str) -> dict | None:
    """Report retrieval: Supabase first if configured (per spec), else the
    in-memory store. Supabase's case row is thin (see supabase_client.fetch_case)
    — if it exists but the in-memory copy is richer, prefer the richer one."""
    in_memory = case_store.get_case(case_id)
    if settings.SUPABASE_URL:
        remote = supabase_client.fetch_case(case_id)
        if remote:
            # Merge: prefer full structured data from memory if this process
            # happens to still have it, otherwise use what Supabase has.
            return in_memory if in_memory else remote
    return in_memory
