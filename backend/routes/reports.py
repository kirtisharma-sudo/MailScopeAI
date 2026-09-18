from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from services import case_source, case_store, supabase_client
from services.report_builder import build_forensic_report
from utils.sanitization import sanitize_analyst_note
from config import get_settings

router = APIRouter()
settings = get_settings()


class AnalystNoteUpdate(BaseModel):
    notes: str = Field(default="", max_length=4000)


@router.get("/api/reports/{case_id}")
async def get_report(case_id: str):
    """1. Try Supabase (if configured). 2. Otherwise the in-memory case
    store. Never fabricates a report — 404 if the case isn't found in
    either place."""
    case = case_source.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found in Supabase or the in-memory case store.")
    return build_forensic_report(case)


@router.post("/api/reports/{case_id}/notes")
async def update_analyst_notes(case_id: str, body: AnalystNoteUpdate):
    """Adds/updates a plain-text analyst note on an existing case. Notes are
    stripped of all HTML/markup before storage — never rendered as HTML,
    never allowed to inject script. Does not touch or overwrite any
    evidence/analysis field."""
    clean_notes = sanitize_analyst_note(body.notes)

    updated = case_store.update_case(case_id, {"analyst_notes": clean_notes})
    if updated is None:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found in the in-memory case store.")

    if settings.SUPABASE_URL:
        # Best-effort only: the `cases` table may not have an analyst_notes
        # column in every deployment (see supabase_schema.sql). A failure
        # here must never break the primary (in-memory) update above.
        try:
            supabase_client.update_case_notes(case_id, clean_notes)
        except Exception:
            pass

    return build_forensic_report(updated)
