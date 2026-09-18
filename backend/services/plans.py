"""
Business-model / feature-gating scaffolding for the prototype.

IMPORTANT — what this is and isn't:
  - There is no real billing, no real user accounts, no real subscriptions.
  - `MAILSCOPE_PLAN` (config) simulates "what plan is this deployment on"
    for demonstration purposes.
  - `SIH_DEMO_ENTITLEMENT` is a SEPARATE, explicitly-labeled override that
    lets SIH judges experience Sentinel/Enterprise-preview capabilities
    without a real subscription. It is always reported honestly in the API
    as `"demo_entitlement": true` — never disguised as a real upgrade.
  - Enterprise features listed here are ROADMAP/CONCEPT only unless
    explicitly marked "prototype" — see FEATURE_MATRIX comments.

Kept intentionally simple/modular so real auth+billing could replace
`get_current_plan()` later without touching call sites.
"""
from __future__ import annotations
from config import get_settings

settings = get_settings()

PLANS = ["free", "sentinel", "enterprise"]

# Each feature flag maps to whichever plan tier first includes it.
# "status" documents whether the capability is actually implemented in this
# prototype ("prototype") or is roadmap-only messaging ("planned") — see
# requirement: never claim planned Enterprise capabilities are production-ready.
FEATURE_MATRIX = {
    "basic_analysis":            {"min_plan": "free",       "status": "prototype"},
    "trace_origin":               {"min_plan": "free",       "status": "prototype"},
    "investigation_timeline":     {"min_plan": "free",       "status": "prototype"},
    "basic_forensic_evidence":    {"min_plan": "free",       "status": "prototype"},

    "cross_case_intelligence":    {"min_plan": "sentinel",   "status": "prototype"},  # "Have I Seen This Before?"
    "saved_investigation_history": {"min_plan": "sentinel",  "status": "planned"},     # no persistence-by-user yet
    "advanced_forensic_reports":  {"min_plan": "sentinel",   "status": "prototype"},

    "organizational_intelligence": {"min_plan": "enterprise", "status": "planned"},
    "cross_user_correlation":     {"min_plan": "enterprise", "status": "planned"},
    "campaign_intelligence":      {"min_plan": "enterprise", "status": "prototype"},   # campaign_engine.py exists, but is not yet org/user-scoped
    "investigation_workflows":    {"min_plan": "enterprise", "status": "planned"},
    "centralized_case_management": {"min_plan": "enterprise", "status": "planned"},
    "configurable_retention":     {"min_plan": "enterprise", "status": "planned"},
}


def get_current_plan() -> str:
    plan = settings.MAILSCOPE_PLAN.lower()
    return plan if plan in PLANS else "free"


def has_demo_entitlement() -> bool:
    return bool(settings.SIH_DEMO_ENTITLEMENT)


def _plan_rank(plan: str) -> int:
    return PLANS.index(plan) if plan in PLANS else 0


def feature_available(feature: str) -> dict:
    """Returns {"available": bool, "reason": "plan" | "demo_entitlement" | "locked",
    "required_plan": str, "status": "prototype"|"planned"}. Never silently
    grants access — every check states WHY it granted or denied it."""
    spec = FEATURE_MATRIX.get(feature)
    if not spec:
        return {"available": False, "reason": "unknown_feature", "required_plan": "unknown", "status": "unknown"}

    current_plan = get_current_plan()
    plan_grants = _plan_rank(current_plan) >= _plan_rank(spec["min_plan"])
    demo_grants = has_demo_entitlement()

    if plan_grants:
        return {"available": True, "reason": "plan", "required_plan": spec["min_plan"], "status": spec["status"]}
    if demo_grants:
        return {"available": True, "reason": "demo_entitlement", "required_plan": spec["min_plan"], "status": spec["status"]}
    return {"available": False, "reason": "locked", "required_plan": spec["min_plan"], "status": spec["status"]}


def plan_summary() -> dict:
    current_plan = get_current_plan()
    return {
        "current_plan": current_plan,
        "demo_entitlement": has_demo_entitlement(),
        "plans": PLANS,
        "features": {name: feature_available(name) for name in FEATURE_MATRIX},
    }
