from fastapi import APIRouter
from config import get_settings
from services import supabase_client

router = APIRouter()
settings = get_settings()


@router.get("/api/analytics")
async def analytics():
    if settings.DEMO_MODE:
        return _demo_analytics()

    data = supabase_client.fetch_analytics_counts()
    if data is None:
        # Supabase not configured / unreachable — honestly report zero/unavailable,
        # never fabricate numbers.
        return {
            "mode": "live",
            "persistence": "unavailable",
            "emails_analyzed": 0,
            "threats_detected": 0,
            "active_campaigns": 0,
            "note": "Supabase is not configured, so no historical analytics exist yet. Each /api/analyze call still returns full results.",
        }

    cases = data["cases"]
    threats = [c for c in cases if c.get("classification") not in ("benign", None)]
    return {
        "mode": "live",
        "persistence": "available",
        "emails_analyzed": len(cases),
        "threats_detected": len(threats),
        "active_campaigns": data["campaign_count"],
    }


def _demo_analytics():
    return {
        "mode": "demo",
        "persistence": "n/a",
        "emails_analyzed": 1284,
        "threats_detected": 187,
        "active_campaigns": 7,
        "note": "DEMO_MODE is enabled — these are illustrative numbers for offline UI demonstration, not real analysis results.",
    }
