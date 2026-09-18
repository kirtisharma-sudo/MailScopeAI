"""
Deterministic language detection for MailScope's two supported UI/content
languages (English, Hindi). No external model, no network call, no
fabricated confidence — this is a real, measured character-script ratio,
not a probabilistic classifier's output.

IMPORTANT: language must NEVER be treated as a risk signal. This module
returns a plain descriptive dict; nothing here feeds risk_engine.py, and
callers must not synthesize a "language" entry in the signals list.
"""
import re

_DEVANAGARI_RE = re.compile(r"[\u0900-\u097F]")
_LATIN_RE = re.compile(r"[A-Za-z]")

DISPLAY_NAMES = {"en": "English", "hi": "Hindi", "mixed": "Mixed (English/Hindi)", "unknown": "Unknown"}


def detect_language(text: str) -> dict:
    """Counts Devanagari-script vs Latin-script letters in the supplied text.
    Classification is a simple, explainable threshold on the real ratio —
    never guessed, never a black box.

    Returns:
        {
          "detected": "en" | "hi" | "mixed" | "unknown",
          "display_name": "...",
          "confidence": <real devanagari-or-latin share of detected letters>,
          "analysis_support": "supported" | "limited",
          "devanagari_char_count": int,
          "latin_char_count": int,
        }
    """
    if not text or not text.strip():
        return {
            "detected": "unknown", "display_name": DISPLAY_NAMES["unknown"],
            "analysis_support": "limited",
            "devanagari_char_count": 0, "latin_char_count": 0,
        }

    devanagari_count = len(_DEVANAGARI_RE.findall(text))
    latin_count = len(_LATIN_RE.findall(text))
    total = devanagari_count + latin_count

    if total == 0:
        return {
            "detected": "unknown", "display_name": DISPLAY_NAMES["unknown"],
            "analysis_support": "limited",
            "devanagari_char_count": 0, "latin_char_count": 0,
        }

    devanagari_ratio = devanagari_count / total

    # Thresholds are simple and explainable: >=85% of one script -> that
    # language; otherwise genuinely mixed content.
    if devanagari_ratio >= 0.85:
        detected, support, confidence = "hi", "limited", round(devanagari_ratio, 3)
    elif devanagari_ratio <= 0.15:
        detected, support, confidence = "en", "supported", round(1 - devanagari_ratio, 3)
    else:
        detected, support, confidence = "mixed", "limited", round(max(devanagari_ratio, 1 - devanagari_ratio), 3)

    return {
        "detected": detected,
        "display_name": DISPLAY_NAMES[detected],
        "confidence": confidence,
        "analysis_support": support,
        "devanagari_char_count": devanagari_count,
        "latin_char_count": latin_count,
    }
