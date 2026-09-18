import hashlib
import uuid


def sha256_bytes(data: bytes) -> str:
    """SHA-256 of the ACTUAL supplied input bytes. Never derived from time or IDs."""
    return hashlib.sha256(data).hexdigest()


def new_case_id() -> str:
    """Random, non-sequential case identifier (not derived from content, not a fake hash)."""
    return "CASE-" + uuid.uuid4().hex[:12].upper()
