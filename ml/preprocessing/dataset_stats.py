"""
Computes a dataset-quality report from ACTUAL records, per SECTION 6. Every
number here is measured, not estimated or guessed.
"""
from __future__ import annotations
from collections import Counter
from ml.schemas import EmailRecord
from ml.preprocessing.email_preprocessor import content_hash

MAX_REASONABLE_CHARS = 20000  # flagged as "extremely long", not rejected outright


def compute_stats(records: list[EmailRecord], rejected: list[dict]) -> dict:
    label_counts = Counter(r.label for r in records)
    source_counts = Counter(r.source for r in records)
    dataset_counts = Counter(r.dataset for r in records)
    origin_counts = Counter(r.origin_type for r in records)

    hashes = [content_hash(r.text) for r in records]
    dup_count = len(hashes) - len(set(hashes))

    extremely_long = sum(1 for r in records if len(r.text) > MAX_REASONABLE_CHARS)
    empty_body = sum(1 for r in records if not r.body.strip())
    missing_subject = sum(1 for r in records if not r.subject.strip())

    rejection_reasons = Counter(row["reason"].split(":")[0] for row in rejected)

    return {
        "total_samples": len(records),
        "samples_per_class": dict(label_counts),
        "duplicate_count_within_final_set": dup_count,
        "missing_subject_count": missing_subject,
        "empty_body_count": empty_body,
        "extremely_long_samples": extremely_long,
        "source_distribution": dict(source_counts),
        "dataset_distribution": dict(dataset_counts),
        "origin_type_distribution": dict(origin_counts),
        "rejected_rows_total": len(rejected),
        "rejected_rows_by_reason": dict(rejection_reasons),
    }


def format_report(stats: dict) -> str:
    lines = [
        "MailScope NLP dataset statistics report",
        "=" * 44,
        f"Total samples (post-dedup, valid label+body): {stats['total_samples']}",
        f"Samples per class: {stats['samples_per_class']}",
        f"Duplicate count found within final set (should be 0 after dedup): {stats['duplicate_count_within_final_set']}",
        f"Missing subject: {stats['missing_subject_count']}",
        f"Empty body: {stats['empty_body_count']}",
        f"Extremely long samples (> {MAX_REASONABLE_CHARS} chars): {stats['extremely_long_samples']}",
        f"Source distribution: {stats['source_distribution']}",
        f"Dataset file distribution: {stats['dataset_distribution']}",
        f"Origin-type distribution (human_written / ai_generated / benign / unknown): {stats['origin_type_distribution']}",
        f"Rejected rows (missing/invalid, excluded before this report): {stats['rejected_rows_total']}",
        f"Rejection reasons: {stats['rejected_rows_by_reason']}",
    ]
    return "\n".join(lines)
