"""
End-to-end dataset build. Run from the `mailscope/` project root:

    python -m ml.preprocessing.build_dataset

Reads every .csv/.json/.jsonl file directly under ml/data/raw/, normalizes
them into EmailRecord, deduplicates, writes a real statistics report, splits
deterministically, verifies zero hash-overlap across splits, and writes
train/val/test JSONL files to ml/data/splits/.

If ml/data/raw/ is empty, this exits with a clear message rather than
fabricating a dataset — see ml/data/raw/README.md for how to add real data.
"""
from __future__ import annotations
import os
import sys
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))  # allow `python ml/preprocessing/build_dataset.py`

from ml.preprocessing.dataset_ingest import ingest_directory, deduplicate, save_records_jsonl
from ml.preprocessing.dataset_stats import compute_stats, format_report
from ml.preprocessing.split import stratified_split, verify_no_leakage, split_summary

RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")
PROCESSED_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "processed")
SPLITS_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "splits")


def main(seed: int = 42):
    records, rejected = ingest_directory(RAW_DIR)

    if not records:
        print(f"No usable dataset files found in {os.path.abspath(RAW_DIR)}.")
        print("This is expected on a fresh checkout — see ml/data/raw/README.md for how to add a real, "
              "licensed dataset before running training. Nothing was fabricated.")
        return

    deduped, dup_count = deduplicate(records)
    stats = compute_stats(deduped, rejected)
    stats["duplicate_count_removed_during_dedup"] = dup_count
    report = format_report(stats)
    print(report)

    os.makedirs(PROCESSED_DIR, exist_ok=True)
    save_records_jsonl(deduped, os.path.join(PROCESSED_DIR, "all_records.jsonl"))
    with open(os.path.join(PROCESSED_DIR, "dataset_stats.json"), "w") as f:
        json.dump(stats, f, indent=2)
    with open(os.path.join(PROCESSED_DIR, "dataset_stats.txt"), "w") as f:
        f.write(report)

    splits = stratified_split(deduped, seed=seed)
    overlaps = verify_no_leakage(splits)
    if any(v > 0 for v in overlaps.values()):
        # Fail loudly rather than silently shipping a leaky split.
        raise RuntimeError(f"Leakage detected across splits (should be impossible post-dedup): {overlaps}")

    summary = split_summary(splits)
    print("\nSplit summary (leakage-verified, all overlaps == 0):")
    print(json.dumps(summary, indent=2))

    os.makedirs(SPLITS_DIR, exist_ok=True)
    for name, recs in splits.items():
        save_records_jsonl(recs, os.path.join(SPLITS_DIR, f"{name}.jsonl"))
    with open(os.path.join(SPLITS_DIR, "split_summary.json"), "w") as f:
        json.dump({"seed": seed, "overlaps": overlaps, "summary": summary}, f, indent=2)

    print(f"\nWrote splits to {os.path.abspath(SPLITS_DIR)}")


if __name__ == "__main__":
    main()
