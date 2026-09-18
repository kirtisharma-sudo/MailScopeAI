"""
Attachment forensics. Operates only on metadata + bytes already extracted by
email_parser.py (in-memory, transient) — nothing here opens, executes, or
renders an attachment's content.
"""
import os
from utils.hashing import sha256_bytes

EXECUTABLE_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".msi", ".jar", ".vbs", ".ps1", ".js", ".jse", ".wsf", ".hta"}
SCRIPT_EXTENSIONS = {".js", ".vbs", ".ps1", ".sh", ".py", ".wsf", ".jse"}
MACRO_ENABLED_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".gz", ".tar"}


def _ext(filename: str) -> str:
    return os.path.splitext(filename or "")[1].lower()


def _has_double_extension(filename: str) -> bool:
    """e.g. 'invoice.pdf.exe' — a classic disguise technique."""
    parts = (filename or "").split(".")
    if len(parts) < 3:
        return False
    inner_ext = "." + parts[-2].lower()
    outer_ext = "." + parts[-1].lower()
    return inner_ext in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt"} and outer_ext in EXECUTABLE_EXTENSIONS


def analyze_attachments(attachments: list[dict]) -> list[dict]:
    """Returns clean, API-safe attachment metadata (no raw bytes retained)."""
    results = []
    for att in attachments:
        filename = att.get("filename") or "unnamed"
        content_type = att.get("content_type") or "application/octet-stream"
        raw = att.get("_bytes") or b""
        ext = _ext(filename)

        indicators = []
        if ext in EXECUTABLE_EXTENSIONS:
            indicators.append(f"Extension '{ext}' is a Windows-executable/script type.")
        if ext in SCRIPT_EXTENSIONS:
            indicators.append(f"Extension '{ext}' is a script type that can run code if opened.")
        if ext in MACRO_ENABLED_EXTENSIONS:
            indicators.append(f"Extension '{ext}' denotes a macro-enabled Office document.")
        if _has_double_extension(filename):
            indicators.append(f"Filename '{filename}' uses a double extension, a common technique to disguise an executable as a document/image.")
        if ext in ARCHIVE_EXTENSIONS:
            indicators.append(f"Extension '{ext}' is an archive; its contents were not inspected (no archive extraction is performed).")
        # MIME/extension mismatch — conservative, only flags clear conflicts
        if content_type.startswith("image/") and ext and ext not in {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg"}:
            indicators.append(f"Declared content type ('{content_type}') does not match the file extension ('{ext}').")

        results.append({
            "filename": filename,
            "mime_type": content_type,
            "size": len(raw),
            "content_disposition": att.get("content_disposition", "not_present"),
            "content_transfer_encoding": att.get("content_transfer_encoding", "not_present"),
            "extension": ext or "none",
            "sha256": sha256_bytes(raw) if raw else "not_available",
            "indicators": indicators,
        })
    return results


def attachment_signals(analyzed: list[dict]) -> list[dict]:
    signals = []
    for a in analyzed:
        ext = a["extension"]
        if ext in EXECUTABLE_EXTENSIONS:
            signals.append({"name": "suspicious_attachment_extension", "severity": "high", "weight": 20,
                             "explanation": f"Attachment '{a['filename']}' has an executable/script extension ('{ext}')."})
        if any("double extension" in i for i in a["indicators"]):
            signals.append({"name": "double_extension_attachment", "severity": "critical", "weight": 25,
                             "explanation": f"Attachment '{a['filename']}' uses a double extension to disguise its real type."})
        if ext in MACRO_ENABLED_EXTENSIONS:
            signals.append({"name": "macro_enabled_attachment", "severity": "medium", "weight": 12,
                             "explanation": f"Attachment '{a['filename']}' is a macro-enabled Office document ('{ext}'), a common malware-delivery vector."})
    return signals
