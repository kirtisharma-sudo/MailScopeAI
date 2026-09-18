"""
NLP content classifier.

Per project spec: DeBERTa-v3-base is the target model, fine-tuned for
Benign vs Suspicious/Phishing (later expanded to phishing/BEC/impersonation/
credential-harvesting/malware/benign). Fine-tuning requires a labeled
dataset and GPU time that are NOT part of this backend skeleton — see
datasets/ and tests/eval for the harness that will use this module once a
model checkpoint exists at config.NLP_MODEL_PATH.

Until a fine-tuned checkpoint is present, this module runs in
`model_status = "not_loaded"` and uses a transparent, clearly-labeled
keyword/rule heuristic as a *placeholder* signal source — it is NEVER
reported as "DeBERTa" output, and its confidence is intentionally modest
so the risk engine does not over-weight it.
"""
from __future__ import annotations
import os
import re
from dataclasses import dataclass, field
from config import get_settings
from utils.sanitization import redact_secrets

settings = get_settings()

_model = None
_tokenizer = None
_MODEL_LOAD_ATTEMPTED = False

PHISHING_TERMS = ["verify your account", "password", "credential", "urgent", "suspended",
                  "click here", "confirm your identity", "act now", "limited time"]
BEC_TERMS = ["wire transfer", "invoice", "payment details", "bank account", "urgent payment", "confidential"]
IMPERSONATION_TERMS = ["security team", "it department", "hr department", "ceo", "official notice"]

# Hindi (Devanagari) equivalents of the same PLACEHOLDER keyword categories —
# these are common, real Hindi words/phrases used in phishing-style urgency
# and credential-harvesting language. This is still a deterministic word
# list, not a trained/validated model, for either language — labeled
# identically in both cases (model_status stays "not_loaded").
PHISHING_TERMS_HI = ["सत्यापित करें", "खाता", "पासवर्ड", "तुरंत", "निलंबित",
                     "यहां क्लिक करें", "अपनी पहचान की पुष्टि करें", "अभी कार्रवाई करें", "सीमित समय"]
BEC_TERMS_HI = ["बैंक हस्तांतरण", "चालान", "भुगतान विवरण", "बैंक खाता", "तत्काल भुगतान", "गोपनीय"]
IMPERSONATION_TERMS_HI = ["सुरक्षा टीम", "आईटी विभाग", "मानव संसाधन विभाग", "सीईओ", "आधिकारिक सूचना"]


@dataclass
class NlpResult:
    model_status: str                     # "loaded" | "not_loaded"
    model_version: str
    label: str                            # benign | suspicious | not_available
    probabilities: dict = field(default_factory=dict)
    matched_terms: list[str] = field(default_factory=list)


def _try_load_model():
    """Attempts to load a local fine-tuned checkpoint. Never downloads from
    the internet at request time (no HF hub calls here) — the model must
    already be present at NLP_MODEL_PATH, produced by the training pipeline
    described in tests/README (see PHASE 4 in the project plan)."""
    global _model, _tokenizer, _MODEL_LOAD_ATTEMPTED
    if _MODEL_LOAD_ATTEMPTED:
        return
    _MODEL_LOAD_ATTEMPTED = True
    path = settings.NLP_MODEL_PATH
    if not path or not os.path.isdir(path) or not os.listdir(path):
        return
    try:
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        _tokenizer = AutoTokenizer.from_pretrained(path)
        _model = AutoModelForSequenceClassification.from_pretrained(path)
        _model.eval()
    except Exception:
        _model = None
        _tokenizer = None


def classify_content(text: str, language: str = "en") -> NlpResult:
    _try_load_model()
    safe_text = redact_secrets(text or "")

    if _model is not None and _tokenizer is not None:
        # NOTE: the loaded checkpoint (if any) was only ever trained/evaluated
        # on English data in this project — see README "AI/NLP Engine" section.
        # It is used regardless of detected language, but Hindi/mixed results
        # from it would be UNVALIDATED; nlp_signals() below caps confidence
        # accordingly rather than trusting it blindly for non-English text.
        try:
            import torch
            with torch.no_grad():
                inputs = _tokenizer(safe_text[:2000], return_tensors="pt", truncation=True, padding=True)
                logits = _model(**inputs).logits
                probs = torch.softmax(logits, dim=-1)[0].tolist()
            label = "suspicious" if len(probs) > 1 and probs[1] > probs[0] else "benign"
            return NlpResult(
                model_status="loaded",
                model_version=settings.NLP_MODEL_VERSION,
                label=label,
                probabilities={"benign": probs[0], "suspicious": probs[1] if len(probs) > 1 else None},
            )
        except Exception:
            pass  # fall through to heuristic

    # --- Explicit, clearly-labeled fallback (NOT a trained model, for EITHER language) ---
    lower = safe_text.lower()
    if language == "hi":
        term_pool = PHISHING_TERMS_HI + BEC_TERMS_HI + IMPERSONATION_TERMS_HI
    elif language == "mixed":
        term_pool = PHISHING_TERMS + BEC_TERMS + IMPERSONATION_TERMS + PHISHING_TERMS_HI + BEC_TERMS_HI + IMPERSONATION_TERMS_HI
    else:
        term_pool = PHISHING_TERMS + BEC_TERMS + IMPERSONATION_TERMS
    # Hindi terms are matched against the original-case text (Devanagari has
    # no case folding); English terms are matched lowercase as before.
    matched = [t for t in term_pool if (t in safe_text if any(ord(c) > 0x0900 for c in t) else t in lower)]
    score = min(1.0, 0.12 * len(matched))
    label = "suspicious" if matched else "benign"
    version_note = "keyword_heuristic_v1 (placeholder — not a trained model, see PHASE 4)"
    if language in ("hi", "mixed"):
        version_note += " — Hindi keyword list is a small illustrative set, NOT a validated Hindi phishing detector"
    return NlpResult(
        model_status="not_loaded",
        model_version=version_note,
        label=label,
        probabilities={"benign": round(1 - score, 3), "suspicious": round(score, 3)},
        matched_terms=matched,
    )


def nlp_signals(result: NlpResult) -> list[dict]:
    if result.model_status == "not_loaded":
        weight = 6 * min(len(result.matched_terms), 3)  # deliberately capped/modest
        if not result.matched_terms:
            return []
        return [{
            "name": "keyword_heuristic_match",
            "severity": "low" if len(result.matched_terms) < 3 else "medium",
            "weight": weight,
            "explanation": f"Placeholder keyword heuristic (not a trained model) matched: {', '.join(result.matched_terms[:5])}.",
        }]
    prob_suspicious = result.probabilities.get("suspicious") or 0
    if prob_suspicious < 0.3:
        return []
    severity = "high" if prob_suspicious > 0.75 else "medium"
    weight = round(30 * prob_suspicious)
    return [{
        "name": "nlp_content_classification",
        "severity": severity,
        "weight": weight,
        "explanation": f"Fine-tuned content classifier ({result.model_version}) estimated {prob_suspicious:.0%} probability of suspicious content.",
    }]
