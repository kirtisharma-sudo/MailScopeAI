"""
Central configuration. Everything secret comes from the environment.
Never hardcode API keys or Supabase service keys here.
"""
import os
from functools import lru_cache


class Settings:
    # --- Mode -------------------------------------------------------
    DEMO_MODE: bool = os.getenv("DEMO_MODE", "false").lower() == "true"

    # --- Supabase -----------------------------------------------------
    SUPABASE_URL: str | None = os.getenv("SUPABASE_URL")
    SUPABASE_SERVICE_KEY: str | None = os.getenv("SUPABASE_SERVICE_KEY")  # server-side only, never sent to frontend

    # --- External threat-intel APIs (all optional; features degrade to
    #     "unavailable" if a key is missing rather than faking data) ----
    VIRUSTOTAL_API_KEY: str | None = os.getenv("VIRUSTOTAL_API_KEY")
    ABUSEIPDB_API_KEY: str | None = os.getenv("ABUSEIPDB_API_KEY")
    IPINFO_TOKEN: str | None = os.getenv("IPINFO_TOKEN")

    # --- NLP model ------------------------------------------------------
    NLP_MODEL_PATH: str = os.getenv("NLP_MODEL_PATH", "../models/deberta-phishing")
    NLP_MODEL_VERSION: str = os.getenv("NLP_MODEL_VERSION", "not_loaded")

    # --- Risk engine weights (configurable, NOT hardcoded "accuracy" claims) --
    RISK_WEIGHTS = {
        "nlp": float(os.getenv("RISK_WEIGHT_NLP", 0.35)),
        "auth": float(os.getenv("RISK_WEIGHT_AUTH", 0.20)),
        "url": float(os.getenv("RISK_WEIGHT_URL", 0.20)),
        "header": float(os.getenv("RISK_WEIGHT_HEADER", 0.15)),
        "network": float(os.getenv("RISK_WEIGHT_NETWORK", 0.10)),
        "attachment": float(os.getenv("RISK_WEIGHT_ATTACHMENT", 0.10)),
    }

    ANALYSIS_VERSION: str = os.getenv("ANALYSIS_VERSION", "mailscope-backend-0.1.0")

    # --- Limits --------------------------------------------------------
    MAX_UPLOAD_BYTES: int = int(os.getenv("MAX_UPLOAD_BYTES", 5 * 1024 * 1024))  # 5MB
    MAX_IN_MEMORY_CASES: int = int(os.getenv("MAX_IN_MEMORY_CASES", 200))  # process-lifetime case store cap

    # --- Business model / feature gating (prototype-level, no real billing) ---
    # The product itself always runs as "free" by default; SIH_DEMO_ENTITLEMENT
    # is a SEPARATE, explicitly-labeled flag that lets judges see Sentinel/
    # Enterprise-preview capabilities without a real subscription. It must
    # never be confused with an actual paid plan — see services/plans.py.
    MAILSCOPE_PLAN: str = os.getenv("MAILSCOPE_PLAN", "free")
    SIH_DEMO_ENTITLEMENT: bool = os.getenv("SIH_DEMO_ENTITLEMENT", "true").lower() == "true"
    ALLOWED_EXTENSIONS = {".eml", ".msg", ".txt"}

    # --- CORS ------------------------------------------------------------
    ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:5500,http://127.0.0.1:5500").split(",")


@lru_cache
def get_settings() -> Settings:
    return Settings()
