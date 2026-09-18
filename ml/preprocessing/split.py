"""
Deterministic train/validation/test splitting (SECTION 7).

Strategy (documented, not just implemented):
1. Records are deduplicated by preprocessed-text hash BEFORE splitting
   (ml/preprocessing/dataset_ingest.deduplicate) — this is the primary
   defense against leakage.
2. Splitting is stratified by `label` so both classes appear in every split
   in roughly their overall proportion.
3. Within each label stratum, records are additionally grouped by `dataset`
   (source-aware) when `group_by_source=True`: entire dataset-groups are
   assigned to a split together where the group is small, which reduces the
   risk of near-duplicate template phishing emails from the same source
   leaking across train/test. This is a heuristic, not a guarantee — exact
   dedup (step 1) remains the hard guarantee against literal duplicate leakage.
4. A fixed random seed makes the split fully reproducible.

IMPORTANT: this operates on the post-dedup record list. If you re-ingest
raw data and the underlying files change, re-run dedup before re-splitting.
"""
from __future__ import annotations
import random
from collections import defaultdict
from ml.schemas import EmailRecord


def stratified_split(
    records: list[EmailRecord],
    train_frac: float = 0.7,
    val_frac: float = 0.15,
    test_frac: float = 0.15,
    seed: int = 42,
    group_by_source: bool = True,
) -> dict[str, list[EmailRecord]]:
    assert abs((train_frac + val_frac + test_frac) - 1.0) < 1e-6, "split fractions must sum to 1.0"

    rng = random.Random(seed)
    by_label: dict[str, list[EmailRecord]] = defaultdict(list)
    for r in records:
        by_label[r.label].append(r)

    splits: dict[str, list[EmailRecord]] = {"train": [], "val": [], "test": []}

    for label, label_records in by_label.items():
        groups: dict[str, list[EmailRecord]] = defaultdict(list)
        for r in label_records:
            groups[r.dataset].append(r)

        # Source-aware grouping only helps when there are enough distinct
        # sources to actually distribute across train/val/test. With too few
        # groups (most commonly: a single-source dataset), grouping would
        # dump the entire stratum into one split and leave others empty —
        # so fall back to a plain per-record shuffle-split for that stratum.
        use_grouping = group_by_source and len(groups) >= 3

        if use_grouping:
            group_keys = list(groups.keys())
            rng.shuffle(group_keys)

            total = len(label_records)
            train_target, val_target = total * train_frac, total * val_frac

            train_count = val_count = 0
            for gkey in group_keys:
                group = groups[gkey]
                if train_count < train_target:
                    splits["train"].extend(group)
                    train_count += len(group)
                elif val_count < val_target:
                    splits["val"].extend(group)
                    val_count += len(group)
                else:
                    splits["test"].extend(group)
        else:
            shuffled = label_records[:]
            rng.shuffle(shuffled)
            n = len(shuffled)
            n_train = int(n * train_frac)
            n_val = int(n * val_frac)
            splits["train"].extend(shuffled[:n_train])
            splits["val"].extend(shuffled[n_train:n_train + n_val])
            splits["test"].extend(shuffled[n_train + n_val:])

    for split_name in splits:
        rng.shuffle(splits[split_name])

    return splits


def verify_no_leakage(splits: dict[str, list[EmailRecord]]) -> dict:
    """Returns real, measured overlap counts — 0 is the expected/required
    result, but this is checked, never assumed."""
    from ml.preprocessing.email_preprocessor import content_hash
    hash_sets = {name: set(content_hash(r.text) for r in recs) for name, recs in splits.items()}
    overlaps = {}
    names = list(hash_sets.keys())
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = names[i], names[j]
            overlap = hash_sets[a] & hash_sets[b]
            overlaps[f"{a}_vs_{b}"] = len(overlap)
    return overlaps


def split_summary(splits: dict[str, list[EmailRecord]]) -> dict:
    from collections import Counter
    return {
        name: {
            "count": len(recs),
            "label_distribution": dict(Counter(r.label for r in recs)),
            "origin_type_distribution": dict(Counter(r.origin_type for r in recs)),
        }
        for name, recs in splits.items()
    }
