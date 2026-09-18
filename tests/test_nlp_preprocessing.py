"""
Tests for ml/preprocessing/* and ml/schemas.py. None of these require a
downloaded model — they exercise real preprocessing/splitting/dedup logic
directly, no mocks on the core behavior.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ml.preprocessing.email_preprocessor import (
    build_model_text, strip_html, looks_like_html, normalize_whitespace,
    content_hash, MAX_CHARS_DEFAULT, TRUNCATION_MARKER,
)
from ml.schemas import normalize_label, EmailRecord, LABELS_BINARY
from ml.preprocessing.dataset_ingest import ingest_file, deduplicate
from ml.preprocessing.dataset_stats import compute_stats
from ml.preprocessing.split import stratified_split, verify_no_leakage


# ---------------------------------------------------------------- preprocessing

def test_missing_subject_handled_explicitly():
    text = build_model_text(None, "Click here to verify your account.")
    assert "[SUBJECT]" in text and "(no subject)" in text
    assert "Click here to verify" in text


def test_missing_body_handled_explicitly():
    text = build_model_text("Hello", "")
    assert "(empty body)" in text


def test_html_email_is_converted_to_text_and_preserves_links():
    html = "<html><body><p>Please <a href='http://evil.example/verify'>verify now</a></p></body></html>"
    assert looks_like_html(html) is True
    text = build_model_text("Verify", html)
    assert "verify now" in text
    assert "<a" not in text and "<html>" not in text


def test_long_email_is_truncated_with_explicit_marker():
    huge_body = "urgent " * 5000  # far beyond MAX_CHARS_DEFAULT
    text = build_model_text("subj", huge_body)
    assert len(text) <= MAX_CHARS_DEFAULT + len(TRUNCATION_MARKER) + 20
    assert text.endswith(TRUNCATION_MARKER)


def test_whitespace_normalization_is_deterministic():
    messy = "Hello\r\n\r\n\r\nWorld   \t\t  !"
    a = normalize_whitespace(messy)
    b = normalize_whitespace(messy)
    assert a == b
    assert "\r" not in a


def test_preprocessing_preserves_urls_and_urgency_language():
    body = "URGENT: verify now at http://paypal-verify.example/login or your account will be suspended."
    text = build_model_text("Account Alert", body)
    assert "http://paypal-verify.example/login" in text
    assert "URGENT" in text
    assert "suspended" in text


# ---------------------------------------------------------------- label validation

def test_normalize_label_recognizes_common_aliases():
    assert normalize_label("phishing") == "suspicious"
    assert normalize_label("Ham") == "benign"
    assert normalize_label("1") == "suspicious"
    assert normalize_label("0") == "benign"


def test_normalize_label_rejects_unknown_values():
    assert normalize_label("banana") is None
    assert normalize_label(None) is None


# ---------------------------------------------------------------- ingestion + dedup

def test_ingest_csv_rejects_missing_body_and_invalid_label(tmp_path):
    csv_path = tmp_path / "sample.csv"
    csv_path.write_text(
        "subject,body,label\n"
        "Hi,Hello there this is fine,benign\n"
        "Bad,,phishing\n"                      # missing body -> rejected
        "Weird,Some text,not_a_real_label\n"    # invalid label -> rejected
        "Verify,Verify your account now,phishing\n"
    )
    records, rejected = ingest_file(str(csv_path), dataset_name="sample.csv")
    assert len(records) == 2
    assert len(rejected) == 2
    reasons = [r["reason"] for r in rejected]
    assert any("missing_or_empty_body" in r for r in reasons)
    assert any("unrecognized_label" in r for r in reasons)


def test_duplicate_detection_is_real_not_estimated():
    r1 = EmailRecord(id="1", subject="Hi", body="Same text here",
                      text=build_model_text("Hi", "Same text here"),
                      label="benign", raw_label="benign", source="x", dataset="d")
    r2 = EmailRecord(id="2", subject="Hi", body="Same text here",
                      text=build_model_text("Hi", "Same text here"),
                      label="benign", raw_label="benign", source="x", dataset="d")
    r3 = EmailRecord(id="3", subject="Hi", body="Different text",
                      text=build_model_text("Hi", "Different text"),
                      label="benign", raw_label="benign", source="x", dataset="d")
    deduped, dup_count = deduplicate([r1, r2, r3])
    assert dup_count == 1
    assert len(deduped) == 2


def test_dataset_stats_are_computed_not_invented():
    records = [
        EmailRecord(id=str(i), subject="s", body="b" * (i + 1),
                    text=build_model_text("s", "b" * (i + 1)),
                    label=("benign" if i % 2 == 0 else "suspicious"),
                    raw_label="x", source="src_a" if i < 3 else "src_b", dataset="d1")
        for i in range(6)
    ]
    stats = compute_stats(records, rejected=[{"row_index": 0, "reason": "missing_or_empty_body:x"}])
    assert stats["total_samples"] == 6
    assert stats["samples_per_class"]["benign"] == 3
    assert stats["samples_per_class"]["suspicious"] == 3
    assert stats["rejected_rows_total"] == 1
    assert set(stats["source_distribution"].keys()) == {"src_a", "src_b"}


# ---------------------------------------------------------------- splitting

def _make_records(n_benign=30, n_suspicious=30):
    records = []
    for i in range(n_benign):
        body = f"This is a normal benign email number {i} about lunch plans."
        records.append(EmailRecord(id=f"b{i}", subject="Lunch", body=body,
                                    text=build_model_text("Lunch", body),
                                    label="benign", raw_label="benign",
                                    source="benign_src", dataset="benign_set", origin_type="benign"))
    for i in range(n_suspicious):
        body = f"URGENT verify your account now, unique token {i}."
        origin = "human_written" if i % 2 == 0 else "ai_generated"
        records.append(EmailRecord(id=f"s{i}", subject="Verify", body=body,
                                    text=build_model_text("Verify", body),
                                    label="suspicious", raw_label="phishing",
                                    source="phish_src", dataset="phish_set", origin_type=origin))
    return records


def test_split_is_deterministic_given_same_seed():
    records = _make_records()
    split_a = stratified_split(records, seed=42, group_by_source=False)
    split_b = stratified_split(records, seed=42, group_by_source=False)
    assert [r.id for r in split_a["train"]] == [r.id for r in split_b["train"]]
    assert [r.id for r in split_a["test"]] == [r.id for r in split_b["test"]]


def test_split_has_no_leakage_across_train_val_test():
    records = _make_records()
    splits = stratified_split(records, seed=7, group_by_source=False)
    overlaps = verify_no_leakage(splits)
    assert all(v == 0 for v in overlaps.values())


def test_split_is_stratified_by_label():
    records = _make_records(n_benign=40, n_suspicious=40)
    splits = stratified_split(records, train_frac=0.7, val_frac=0.15, test_frac=0.15, seed=1, group_by_source=False)
    for name, recs in splits.items():
        labels = [r.label for r in recs]
        if labels:
            benign_frac = labels.count("benign") / len(labels)
            assert 0.3 < benign_frac < 0.7, f"{name} split is not reasonably stratified: {benign_frac}"
