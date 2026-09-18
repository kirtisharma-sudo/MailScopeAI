"""
Thin Supabase wrapper. All writes use structured findings, not raw email
bodies (data minimization — see project brief section 3).

If SUPABASE_URL / SUPABASE_SERVICE_KEY are not set, every function becomes a
no-op that returns None, and callers must treat that as "persistence
unavailable", not an error that crashes the request.
"""
from config import get_settings

settings = get_settings()

_client = None
_INIT_ATTEMPTED = False


def get_client():
    global _client, _INIT_ATTEMPTED
    if _INIT_ATTEMPTED:
        return _client
    _INIT_ATTEMPTED = True
    if not settings.SUPABASE_URL or not settings.SUPABASE_SERVICE_KEY:
        return None
    try:
        from supabase import create_client
        _client = create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_KEY)
    except Exception:
        _client = None
    return _client


def save_case(case_row: dict) -> bool:
    client = get_client()
    if not client:
        return False
    try:
        client.table("cases").insert(case_row).execute()
        return True
    except Exception:
        return False


def save_related(table: str, rows: list[dict]) -> bool:
    client = get_client()
    if not client or not rows:
        return False
    try:
        client.table(table).insert(rows).execute()
        return True
    except Exception:
        return False


def fetch_all_case_indicators() -> list[dict]:
    """Used by campaign_engine to correlate against prior cases."""
    client = get_client()
    if not client:
        return []
    try:
        resp = client.table("indicators").select("case_id, type, value").execute()
        grouped: dict[str, list[dict]] = {}
        for row in resp.data or []:
            grouped.setdefault(row["case_id"], []).append({"type": row["type"], "value": row["value"]})
        return [{"case_id": cid, "indicators": inds} for cid, inds in grouped.items()]
    except Exception:
        return []


def fetch_analytics_counts() -> dict | None:
    client = get_client()
    if not client:
        return None
    try:
        cases = client.table("cases").select("id, classification, risk_score, created_at").execute().data or []
        campaigns = client.table("campaigns").select("id").execute().data or []
        return {"cases": cases, "campaign_count": len(campaigns)}
    except Exception:
        return None


def update_case_notes(case_id: str, notes: str) -> bool:
    client = get_client()
    if not client:
        return False
    try:
        client.table("cases").update({"analyst_notes": notes}).eq("id", case_id).execute()
        return True
    except Exception:
        return False


def fetch_case(case_id: str) -> dict | None:
    client = get_client()
    if not client:
        return None
    try:
        resp = client.table("cases").select("*").eq("id", case_id).single().execute()
        return resp.data
    except Exception:
        return None
