"""
Fine-tunes microsoft/deberta-v3-base for BENIGN vs SUSPICIOUS classification
(SECTION 8/9). CPU-compatible by default; uses GPU automatically if
available via `--device cuda`.

Usage:
    python -m ml.training.train --train ml/data/splits/train.jsonl \\
        --val ml/data/splits/val.jsonl --output-dir models/deberta/checkpoint

This script does NOT fabricate a trained model. If required dependencies
(`transformers`, `torch`) are missing, or the base model cannot be
downloaded (e.g. no internet access), or the training data doesn't exist,
it exits with a clear, actionable error — never a fake "success".
"""
from __future__ import annotations
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from ml.schemas import LABELS_BINARY, EmailRecord
from ml.preprocessing.dataset_ingest import load_records_jsonl


class TrainingUnavailableError(RuntimeError):
    """Raised when training genuinely cannot proceed. The message is meant
    to be read and acted on by a human, not swallowed."""


def _require_ml_deps():
    try:
        import torch  # noqa: F401
        import transformers  # noqa: F401
    except ImportError as exc:
        raise TrainingUnavailableError(
            "Required ML dependencies are not installed. Run:\n"
            "    pip install -r backend/requirements.txt\n"
            "(This installs transformers + torch, which are optional/heavy and not required for the "
            "deterministic forensics engine — only for this training script.)\n"
            f"Original error: {exc}"
        ) from exc


def _load_split(path: str) -> list[EmailRecord]:
    if not os.path.isfile(path):
        raise TrainingUnavailableError(
            f"Split file not found: {path}\n"
            "Run `python -m ml.preprocessing.build_dataset` first to generate train/val/test splits "
            "from data placed in ml/data/raw/ (see ml/data/raw/README.md)."
        )
    records = load_records_jsonl(path)
    if not records:
        raise TrainingUnavailableError(f"Split file {path} exists but contains zero records.")
    return records


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Fine-tune DeBERTa-v3-base for benign vs suspicious email classification.")
    p.add_argument("--model-name", default="microsoft/deberta-v3-base")
    p.add_argument("--train", default="ml/data/splits/train.jsonl")
    p.add_argument("--val", default="ml/data/splits/val.jsonl")
    p.add_argument("--output-dir", default="models/deberta/checkpoint")
    p.add_argument("--learning-rate", type=float, default=2e-5)
    p.add_argument("--batch-size", type=int, default=8)
    p.add_argument("--epochs", type=int, default=3)
    p.add_argument("--max-seq-length", type=int, default=256)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--device", default="cpu", choices=["cpu", "cuda"])
    return p.parse_args(argv)


def train(args) -> dict:
    """Returns a dict describing what actually happened. Raises
    TrainingUnavailableError (never a silent no-op) if it cannot proceed."""
    _require_ml_deps()
    import torch
    from transformers import (
        AutoTokenizer, AutoModelForSequenceClassification,
        TrainingArguments, Trainer, set_seed,
    )

    set_seed(args.seed)

    train_records = _load_split(args.train)
    val_records = _load_split(args.val)

    label_to_id = {l: i for i, l in enumerate(LABELS_BINARY)}

    try:
        tokenizer = AutoTokenizer.from_pretrained(args.model_name)
        model = AutoModelForSequenceClassification.from_pretrained(args.model_name, num_labels=len(LABELS_BINARY))
    except Exception as exc:
        raise TrainingUnavailableError(
            f"Could not load base model '{args.model_name}' from Hugging Face. This usually means no internet "
            "access to huggingface.co in the current environment, or the model name is wrong. "
            "Training cannot proceed without the base model weights — nothing was fabricated.\n"
            f"Original error: {exc}"
        ) from exc

    class EmailDataset(torch.utils.data.Dataset):
        def __init__(self, records: list[EmailRecord]):
            self.records = records

        def __len__(self):
            return len(self.records)

        def __getitem__(self, idx):
            r = self.records[idx]
            enc = tokenizer(r.text, truncation=True, max_length=args.max_seq_length, padding="max_length")
            enc["labels"] = label_to_id[r.label]
            return {k: torch.tensor(v) for k, v in enc.items()}

    train_ds = EmailDataset(train_records)
    val_ds = EmailDataset(val_records)

    training_args = TrainingArguments(
        output_dir=args.output_dir,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        num_train_epochs=args.epochs,
        learning_rate=args.learning_rate,
        eval_strategy="epoch",
        save_strategy="epoch",
        seed=args.seed,
        no_cuda=(args.device == "cpu"),
        logging_steps=25,
        report_to=[],
    )

    trainer = Trainer(model=model, args=training_args, train_dataset=train_ds, eval_dataset=val_ds)
    train_result = trainer.train()

    os.makedirs(args.output_dir, exist_ok=True)
    trainer.save_model(args.output_dir)
    tokenizer.save_pretrained(args.output_dir)

    metadata = {
        "model_name": args.model_name,
        "labels": LABELS_BINARY,
        "train_samples": len(train_records),
        "val_samples": len(val_records),
        "epochs": args.epochs,
        "learning_rate": args.learning_rate,
        "batch_size": args.batch_size,
        "max_seq_length": args.max_seq_length,
        "seed": args.seed,
        "final_train_loss": getattr(train_result, "training_loss", None),
    }
    with open(os.path.join(args.output_dir, "training_metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2)

    return metadata


def main(argv=None):
    args = parse_args(argv)
    try:
        metadata = train(args)
    except TrainingUnavailableError as exc:
        print(f"Training did not run:\n{exc}", file=sys.stderr)
        sys.exit(1)
    print("Training complete. Metadata:")
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
