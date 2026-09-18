"""
Reusable predictor: email text -> tokenizer -> DeBERTa -> structured
prediction (SECTION 13). This class is intentionally separate from
backend/services/nlp_detector.py — that module is the FastAPI-facing
service interface (SECTION 14) and currently uses a placeholder heuristic
because no checkpoint exists yet. This class is what nlp_detector.py (or a
future version of it) would call once a real checkpoint is trained.

If no trained checkpoint is available, `predict()` returns a result with
`"available": False` and a clear reason — it never fabricates probabilities.
"""
from __future__ import annotations
import os
from dataclasses import dataclass, field
from ml.schemas import LABELS_BINARY
from ml.preprocessing.email_preprocessor import build_model_text


@dataclass
class PredictionResult:
    available: bool
    label: str                      # "benign" | "suspicious" | "not_available"
    probabilities: dict = field(default_factory=dict)
    model_name: str = "not_available"
    model_version: str = "not_available"
    reason: str | None = None       # populated when available=False


class DebertaPredictor:
    """Lazily loads a fine-tuned checkpoint from `model_dir`. Safe to
    instantiate even when the checkpoint doesn't exist — loading is only
    attempted once, lazily, and failures are cached so repeated calls don't
    repeatedly retry a doomed import/load."""

    def __init__(self, model_dir: str, max_seq_length: int = 256):
        self.model_dir = model_dir
        self.max_seq_length = max_seq_length
        self._model = None
        self._tokenizer = None
        self._load_attempted = False
        self._unavailable_reason: str | None = None

    def _try_load(self):
        if self._load_attempted:
            return
        self._load_attempted = True

        if not os.path.isdir(self.model_dir) or not os.listdir(self.model_dir):
            self._unavailable_reason = f"No trained checkpoint found at '{self.model_dir}'."
            return
        try:
            import torch  # noqa: F401
            from transformers import AutoTokenizer, AutoModelForSequenceClassification
        except ImportError as exc:
            self._unavailable_reason = f"transformers/torch not installed ({exc})."
            return
        try:
            self._tokenizer = AutoTokenizer.from_pretrained(self.model_dir)
            self._model = AutoModelForSequenceClassification.from_pretrained(self.model_dir)
            self._model.eval()
        except Exception as exc:
            self._unavailable_reason = f"Failed to load model/tokenizer from '{self.model_dir}': {exc}"
            self._model = None
            self._tokenizer = None

    @property
    def is_available(self) -> bool:
        self._try_load()
        return self._model is not None and self._tokenizer is not None

    def predict(self, subject: str | None, body: str | None) -> PredictionResult:
        self._try_load()
        if self._model is None or self._tokenizer is None:
            return PredictionResult(
                available=False, label="not_available",
                reason=self._unavailable_reason or "Model not loaded.",
            )

        import torch
        text = build_model_text(subject, body)
        with torch.no_grad():
            enc = self._tokenizer(text, truncation=True, max_length=self.max_seq_length,
                                   padding=True, return_tensors="pt")
            logits = self._model(**enc).logits
            probs = torch.softmax(logits, dim=-1)[0].tolist()

        id_to_label = {i: l for i, l in enumerate(LABELS_BINARY)}
        prob_map = {id_to_label.get(i, f"class_{i}"): round(p, 4) for i, p in enumerate(probs)}
        label = max(prob_map, key=prob_map.get) if prob_map else "not_available"

        return PredictionResult(
            available=True,
            label=label,
            probabilities=prob_map,
            model_name="microsoft/deberta-v3-base",
            model_version=os.path.basename(os.path.normpath(self.model_dir)),
        )
