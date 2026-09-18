"""
Ingests curated/public dataset files (CSV or JSON/JSONL) into the internal
EmailRecord schema (ml/schemas.py). Does NOT download anything automatically
— the person running this points it at files they've already obtained and
are licensed to use (see ml/data/raw/README.md).

Expected loose input shape per record (flexible column names, see
_FIELD_ALIASES below): subject, body, label, source, dataset_name.
"""
from __future__ import annotations
import csv
import json
import os
from ml.schemas import EmailRecord, normalize_label
from ml.preprocessing.email_preprocessor import build_model_text, content_hash

# Accept common column-name variants seen across public phishing datasets
# without guessing wildly — unrecognized columns are simply ignored.
_FIELD_ALIASES = {
    "subject": ["subject", "Subject", "title"],
    "body": ["body", "Body", "text", "email_text", "content", "message"],
    "label": ["label", "Label", "class", "Class", "target", "type"],
    "source": ["source", "Source"],
    "origin_type": ["origin_type", "type_detail", "generation"],
}


def _first_present(row: dict, keys: list[str]) -> str | None:
    for k in keys:
        if k in row and row[k] not in (None, ""):
            return row[k]
    return None


def _load_csv(path: str) -> list[dict]:
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        return list(csv.DictReader(f))


def _load_json(path: str) -> list[dict]:
    with open(path, encoding="utf-8", errors="replace") as f:
        data = json.load(f)
    if isinstance(data, dict):
        # tolerate {"records": [...]}-style wrappers
        for key in ("records", "data", "items"):
            if key in data and isinstance(data[key], list):
                return data[key]
        return [data]
    return data


def _load_jsonl(path: str) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def load_raw_file(path: str) -> list[dict]:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".csv":
        return _load_csv(path)
    if ext == ".jsonl":
        return _load_jsonl(path)
    if ext == ".json":
        return _load_json(path)
    raise ValueError(f"Unsupported dataset file extension '{ext}' for {path}. Supported: .csv, .json, .jsonl")


def ingest_file(path: str, dataset_name: str | None = None, default_source: str = "unknown") -> tuple[list[EmailRecord], list[dict]]:
    """Returns (records, rejected_rows). rejected_rows carries the reason so
    dataset-quality reporting is based on real counts, never estimated."""
    dataset_name = dataset_name or os.path.basename(path)
    rows = load_raw_file(path)
    records: list[EmailRecord] = []
    rejected: list[dict] = []

    for i, row in enumerate(rows):
        subject = _first_present(row, _FIELD_ALIASES["subject"]) or ""
        body = _first_present(row, _FIELD_ALIASES["body"])
        raw_label = _first_present(row, _FIELD_ALIASES["label"])
        source = _first_present(row, _FIELD_ALIASES["source"]) or default_source
        origin_type = _first_present(row, _FIELD_ALIASES["origin_type"]) or "unknown"

        if body is None or not str(body).strip():
            rejected.append({"row_index": i, "reason": "missing_or_empty_body", "dataset": dataset_name})
            continue

        label = normalize_label(raw_label)
        if label is None:
            rejected.append({"row_index": i, "reason": f"unrecognized_label:{raw_label!r}", "dataset": dataset_name})
            continue

        text = build_model_text(subject, body)
        rec_id = f"{dataset_name}:{i}"
        records.append(EmailRecord(
            id=rec_id, subject=subject, body=str(body), text=text,
            label=label, raw_label=str(raw_label), source=source,
            dataset=dataset_name, origin_type=origin_type,
        ))

    return records, rejected


def ingest_directory(raw_dir: str) -> tuple[list[EmailRecord], list[dict]]:
    """Ingests every supported file directly under raw_dir (non-recursive,
    explicit and predictable rather than magically walking subfolders)."""
    all_records: list[EmailRecord] = []
    all_rejected: list[dict] = []
    if not os.path.isdir(raw_dir):
        return all_records, all_rejected
    for fname in sorted(os.listdir(raw_dir)):
        if fname.startswith("."):
            continue
        ext = os.path.splitext(fname)[1].lower()
        if ext not in (".csv", ".json", ".jsonl"):
            continue
        path = os.path.join(raw_dir, fname)
        records, rejected = ingest_file(path, dataset_name=fname)
        all_records.extend(records)
        all_rejected.extend(rejected)
    return all_records, all_rejected


def deduplicate(records: list[EmailRecord]) -> tuple[list[EmailRecord], int]:
    """Removes exact duplicate preprocessed text, keeping the first
    occurrence. Returns (deduped_records, duplicate_count) — the count is
    real, not estimated, and feeds directly into the stats report."""
    seen: set[str] = set()
    out: list[EmailRecord] = []
    dup_count = 0
    for r in records:
        h = content_hash(r.text)
        if h in seen:
            dup_count += 1
            continue
        seen.add(h)
        out.append(r)
    return out, dup_count


def save_records_jsonl(records: list[EmailRecord], path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r.to_dict(), ensure_ascii=False) + "\n")


def load_records_jsonl(path: str) -> list[EmailRecord]:
    records = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                d = json.loads(line)
                records.append(EmailRecord(**d))
    return records
