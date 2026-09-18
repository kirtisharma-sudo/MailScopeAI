"""
Internal schema every ingested dataset record is normalized into, regardless
of its original CSV/JSON column names. This is the single contract the
preprocessing, splitting, training, and evaluation code all agree on.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict

# Phase 3A trains a binary task only. The label set below is the FUTURE
# target vocabulary (SECTION 4) — LABEL_MAP_BINARY is what's actually used
# right now, and every other label is folded into "suspicious" for training.
LABELS_FUTURE = ["benign", "phishing", "bec", "impersonation", "credential_harvesting", "malware"]
LABELS_BINARY = ["benign", "suspicious"]

# Any raw label containing these substrings is treated as "suspicious" for
# the current binary task. Extend this, don't rewrite it, when multi-class
# training is added later.
_SUSPICIOUS_ALIASES = {"phishing", "spam", "malicious", "suspicious", "bec", "impersonation",
                        "credential_harvesting", "malware", "fraud", "scam", "1", "true", "yes"}
_BENIGN_ALIASES = {"benign", "ham", "legit", "legitimate", "safe", "0", "false", "no"}


def normalize_label(raw_label: str) -> str | None:
    """Maps an arbitrary source label string to 'benign' or 'suspicious'.
    Returns None (never a guess) if the label is unrecognized — such records
    are dropped and counted in the dataset-quality report, not silently kept."""
    if raw_label is None:
        return None
    key = str(raw_label).strip().lower()
    if key in _SUSPICIOUS_ALIASES:
        return "suspicious"
    if key in _BENIGN_ALIASES:
        return "benign"
    return None


@dataclass
class EmailRecord:
    """One normalized training/eval sample."""
    id: str
    subject: str
    body: str
    text: str                 # preprocessed model input (subject + body combined)
    label: str                # "benign" | "suspicious" (Phase 3A binary task)
    raw_label: str             # original label string, preserved for audit
    source: str                # e.g. "kaggle_nazario", "manual_ai_generated"
    dataset: str                # dataset file/name this record came from
    origin_type: str = "unknown"   # "human_written" | "ai_generated" | "benign" | "unknown"
                                    # used for the AI-generated-phishing generalization experiment (SECTION 11)

    def to_dict(self) -> dict:
        return asdict(self)
