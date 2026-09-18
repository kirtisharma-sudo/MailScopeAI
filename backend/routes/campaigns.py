from fastapi import APIRouter, HTTPException
from services import case_source
from services.campaign_engine import correlate

router = APIRouter()


@router.get("/api/campaigns")
async def list_campaigns():
    """Works with or without Supabase — uses whichever case source is
    available (case_source.py). Returns an honest empty list, never a
    fabricated demo campaign, when nothing correlates."""
    all_cases = case_source.get_all_case_indicators()
    if len(all_cases) < 2:
        return {"campaigns": [], "note": "Fewer than two analyzed cases are available to correlate."}

    seen_campaigns: dict[str, dict] = {}
    for case in all_cases:
        others = [c for c in all_cases if c["case_id"] != case["case_id"]]
        result = correlate(case["case_id"], case["indicators"], others)
        if result["status"] == "possible_campaign" and result["campaign_id"]:
            existing = seen_campaigns.get(result["campaign_id"])
            if existing:
                seen_pairs = {frozenset((r["source_case"], r["target_case"])) | {r["shared_indicator"]} for r in existing["relationships"]}
                for r in result["relationships"]:
                    key = frozenset((r["source_case"], r["target_case"])) | {r["shared_indicator"]}
                    if key not in seen_pairs:
                        existing["relationships"].append(r)
                        seen_pairs.add(key)
                existing["related_case_count"] = len({r["target_case"] for r in existing["relationships"]} | {r["source_case"] for r in existing["relationships"]}) - 1
            else:
                seen_campaigns[result["campaign_id"]] = result

    return {"campaigns": list(seen_campaigns.values())}


@router.get("/api/campaigns/{campaign_id}")
async def campaign_detail(campaign_id: str):
    all_cases = case_source.get_all_case_indicators()
    for case in all_cases:
        others = [c for c in all_cases if c["case_id"] != case["case_id"]]
        result = correlate(case["case_id"], case["indicators"], others)
        if result.get("campaign_id") == campaign_id:
            return result
    raise HTTPException(status_code=404, detail=f"Campaign '{campaign_id}' not found among currently known cases.")
