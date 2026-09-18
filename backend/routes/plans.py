from fastapi import APIRouter
from services.plans import plan_summary

router = APIRouter()


@router.get("/api/plan")
async def get_plan():
    """Current plan + feature availability. No real billing/auth — see
    services/plans.py docstring for exactly what this does and doesn't mean."""
    return plan_summary()
