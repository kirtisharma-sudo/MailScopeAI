from fastapi import HTTPException
from config import get_settings

settings = get_settings()


def validate_pasted_text(text: str | None):
    if text is None or not text.strip():
        raise HTTPException(status_code=400, detail="No email content supplied. Paste an email or upload a .eml file.")
    if len(text.encode("utf-8", errors="ignore")) > settings.MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Pasted content exceeds the maximum allowed size.")


def validate_upload(filename: str, size: int):
    import os
    ext = os.path.splitext(filename or "")[1].lower()
    if ext not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=415, detail=f"Unsupported file type '{ext}'. Allowed: {sorted(settings.ALLOWED_EXTENSIONS)}")
    if size > settings.MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Uploaded file exceeds the maximum allowed size.")
