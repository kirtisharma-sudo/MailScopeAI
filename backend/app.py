import logging
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import get_settings
from routes import analyze, analytics, campaigns, reports, plans

logging.basicConfig(level=logging.INFO)
settings = get_settings()

app = FastAPI(
    title="MailScope AI Backend",
    version=settings.ANALYSIS_VERSION,
    description="AI-Powered Email Threat Detection, Geolocation and Forensic Intelligence Platform — backend for SIH26106.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(analyze.router)
app.include_router(analytics.router)
app.include_router(campaigns.router)
app.include_router(reports.router)
app.include_router(plans.router)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Never crash the whole process because one downstream call (e.g. an
    # external threat-intel API) misbehaves — always return a structured error.
    logging.exception("Unhandled error on %s", request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal error. See server logs. No email content is included in logs."})


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "mode": "demo" if settings.DEMO_MODE else "live",
        "supabase_configured": bool(settings.SUPABASE_URL),
        "nlp_model_path_exists": __import__("os").path.isdir(settings.NLP_MODEL_PATH),
        "analysis_version": settings.ANALYSIS_VERSION,
    }
