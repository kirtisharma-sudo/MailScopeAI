"""
Evaluates a trained checkpoint against an untouched test set (SECTION 10/11).

Usage:
    python -m ml.evaluation.evaluate --model-dir models/deberta/checkpoint \\
        --test ml/data/splits/test.jsonl --output ml/data/processed/eval_report.json

Every number in the output is computed from real model predictions against
real labels. If the model directory doesn't exist or the test file is
missing/empty, this exits with a clear error rather than printing invented
metrics. This script NEVER hardcodes accuracy/precision/recall/F1.
"""
from __future__ import annotations
import argparse
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from ml.schemas import LABELS_BINARY, EmailRecord
from ml.preprocessing.dataset_ingest import load_records_jsonl


class EvaluationUnavailableError(RuntimeError):
    pass


def _require_ml_deps():
    try:
        import torch  # noqa: F401
        import transformers  # noqa: F401
    except ImportError as exc:
        raise EvaluationUnavailableError(
            "transformers/torch are not installed. Run `pip install -r backend/requirements.txt` first.\n"
            f"Original error: {exc}"
        ) from exc


def _load_test_set(path: str) -> list[EmailRecord]:
    if not os.path.isfile(path):
        raise EvaluationUnavailableError(f"Test split not found: {path}. Run ml/preprocessing/build_dataset.py first.")
    records = load_records_jsonl(path)
    if not records:
        raise EvaluationUnavailableError(f"Test split {path} exists but is empty.")
    return records


def confusion_matrix(y_true: list[str], y_pred: list[str], labels: list[str]) -> dict:
    matrix = {t: {p: 0 for p in labels} for t in labels}
    for t, p in zip(y_true, y_pred):
        matrix[t][p] += 1
    return matrix


def precision_recall_f1(y_true: list[str], y_pred: list[str], positive_label: str) -> dict:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == positive_label and p == positive_label)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t != positive_label and p == positive_label)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == positive_label and p != positive_label)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t != positive_label and p != positive_label)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return {"true_positive": tp, "false_positive": fp, "false_negative": fn, "true_negative": tn,
            "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4)}


def accuracy(y_true: list[str], y_pred: list[str]) -> float:
    if not y_true:
        return 0.0
    correct = sum(1 for t, p in zip(y_true, y_pred) if t == p)
    return round(correct / len(y_true), 4)


def _predict_all(model_dir: str, records: list[EmailRecord], max_seq_length: int, batch_size: int) -> list[str]:
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification

    if not os.path.isdir(model_dir) or not os.listdir(model_dir):
        raise EvaluationUnavailableError(
            f"Model directory '{model_dir}' does not exist or is empty. No trained checkpoint is available to "
            "evaluate — run ml/training/train.py first. Refusing to report fabricated metrics."
        )
    try:
        tokenizer = AutoTokenizer.from_pretrained(model_dir)
        model = AutoModelForSequenceClassification.from_pretrained(model_dir)
        model.eval()
    except Exception as exc:
        raise EvaluationUnavailableError(f"Could not load model/tokenizer from '{model_dir}': {exc}") from exc

    id_to_label = {i: l for i, l in enumerate(LABELS_BINARY)}
    predictions = []
    with torch.no_grad():
        for i in range(0, len(records), batch_size):
            batch = records[i:i + batch_size]
            enc = tokenizer([r.text for r in batch], truncation=True, max_length=max_seq_length,
                             padding=True, return_tensors="pt")
            logits = model(**enc).logits
            batch_preds = torch.argmax(logits, dim=-1).tolist()
            predictions.extend(id_to_label.get(p, "unknown") for p in batch_preds)
    return predictions


def evaluate(model_dir: str, test_records: list[EmailRecord], max_seq_length: int = 256, batch_size: int = 8) -> dict:
    _require_ml_deps()
    y_true = [r.label for r in test_records]
    y_pred = _predict_all(model_dir, test_records, max_seq_length, batch_size)

    overall = {
        "n_samples": len(test_records),
        "accuracy": accuracy(y_true, y_pred),
        "confusion_matrix": confusion_matrix(y_true, y_pred, LABELS_BINARY),
        "per_class": {label: precision_recall_f1(y_true, y_pred, label) for label in LABELS_BINARY},
    }

    # --- Research Question 1: human-written vs AI-generated phishing (SECTION 11) ---
    by_origin: dict[str, dict] = {}
    origin_types = sorted(set(r.origin_type for r in test_records))
    for origin in origin_types:
        idx = [i for i, r in enumerate(test_records) if r.origin_type == origin]
        if not idx:
            continue
        sub_true = [y_true[i] for i in idx]
        sub_pred = [y_pred[i] for i in idx]
        by_origin[origin] = {
            "n_samples": len(idx),
            "accuracy": accuracy(sub_true, sub_pred),
            "suspicious_recall": precision_recall_f1(sub_true, sub_pred, "suspicious")["recall"],
            "suspicious_precision": precision_recall_f1(sub_true, sub_pred, "suspicious")["precision"],
        }

    generalization_note = (
        "This breakdown lets you compare 'suspicious' recall across origin_type groups "
        "(human_written vs ai_generated phishing). A meaningfully lower recall on "
        "ai_generated than human_written would support the concern behind Research "
        "Question 1 (traditional-phishing-trained models may not generalize to "
        "AI-generated phishing) — but only if the test set actually contains labeled "
        "ai_generated samples (origin_type distribution above says how many)."
        if "ai_generated" in by_origin else
        "No records with origin_type='ai_generated' were present in this test set, so "
        "Research Question 1 cannot be evaluated from this run. Add labeled AI-generated "
        "phishing samples with origin_type='ai_generated' to ml/data/raw/ and rebuild the dataset."
    )

    return {
        "overall": overall,
        "by_origin_type": by_origin,
        "research_question_1_note": generalization_note,
        "labels": LABELS_BINARY,
    }


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Evaluate a trained DeBERTa checkpoint on an untouched test set.")
    p.add_argument("--model-dir", default="models/deberta/checkpoint")
    p.add_argument("--test", default="ml/data/splits/test.jsonl")
    p.add_argument("--output", default="ml/data/processed/eval_report.json")
    p.add_argument("--max-seq-length", type=int, default=256)
    p.add_argument("--batch-size", type=int, default=8)
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        test_records = _load_test_set(args.test)
        report = evaluate(args.model_dir, test_records, args.max_seq_length, args.batch_size)
    except EvaluationUnavailableError as exc:
        print(f"Evaluation did not run:\n{exc}", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(report, indent=2))
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nSaved to {args.output}")


if __name__ == "__main__":
    main()
