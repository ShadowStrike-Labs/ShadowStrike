"""
ShadowStrike PhantomCortex -- Dataset Merge Bridge
====================================================
Merges newly extracted ``.npz`` feature archives from the extraction step
into existing cumulative training datasets, with SHA-256 deduplication,
configurable size caps, and stratified class balancing.

``pipeline.py`` calls ``merge(processed_dir, dataset_dir)`` after feature
extraction to grow the training sets incrementally without duplicates or
unbounded growth.

Usage (from pipeline.py)::

    from PhantomCortex.training.features.merge import merge
    stats = merge(
        processed_dir=Path("data/processed"),
        dataset_dir=Path("data/datasets"),
    )
"""

from __future__ import annotations

import logging
import time
from collections import Counter
from pathlib import Path
from typing import Any, Optional

import numpy as np

logger = logging.getLogger("phantomcortex.features.merge")

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------

# Maximum samples per model dataset.  Can be overridden per model via the
# ``caps`` parameter to ``merge()``.
_DEFAULT_MAX_SAMPLES: int = 1_000_000

# Per-model defaults (override if a model benefits from different sizes).
_MODEL_CAPS: dict[str, int] = {
    "static": 1_000_000,
    "behavioral": 500_000,
    "memory": 500_000,
    "network": 500_000,
    "emulation": 500_000,
}

# Maps the npz filenames produced by extract.py to model names.
_NPZ_TO_MODEL: dict[str, str] = {
    "static_features.npz": "static",
    "behavioral_features.npz": "behavioral",
    "memory_features.npz": "memory",
    "network_features.npz": "network",
    "emulation_features.npz": "emulation",
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _load_npz(path: Path) -> Optional[dict[str, np.ndarray]]:
    """Load an npz archive, returning None on failure."""
    if not path.is_file():
        return None
    try:
        data = np.load(str(path), allow_pickle=False)
        return dict(data)
    except Exception as exc:
        logger.warning("Failed to load %s: %s", path, exc)
        return None


def _deduplicate(
    features: np.ndarray,
    sha256: np.ndarray,
    labels: np.ndarray,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, int]:
    """Remove duplicate rows by SHA-256 hash.

    Returns (features, sha256, labels, duplicates_removed).
    """
    if len(sha256) == 0:
        return features, sha256, labels, 0

    seen: set[str] = set()
    keep_indices: list[int] = []

    for i, h in enumerate(sha256):
        h_str = str(h)
        if h_str not in seen:
            seen.add(h_str)
            keep_indices.append(i)

    removed = len(sha256) - len(keep_indices)
    if removed == 0:
        return features, sha256, labels, 0

    idx = np.array(keep_indices, dtype=np.intp)
    return features[idx], sha256[idx], labels[idx], removed


def _cap_dataset(
    features: np.ndarray,
    sha256: np.ndarray,
    labels: np.ndarray,
    max_samples: int,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Trim a dataset to at most *max_samples* using stratified sampling.

    Keeps the most recent entries (tail) per class, proportionally.  For
    unlabeled data (label == -1) a uniform random subset is kept.
    """
    n = len(sha256)
    if n <= max_samples:
        return features, sha256, labels

    logger.info(
        "Capping dataset from %d to %d samples (stratified)", n, max_samples
    )

    unique_labels = np.unique(labels)

    # If every label is -1 (unlabeled), keep the tail.
    if len(unique_labels) == 1 and unique_labels[0] == -1:
        return features[-max_samples:], sha256[-max_samples:], labels[-max_samples:]

    # Stratified selection: allocate slots proportionally per class.
    label_indices: dict[int, np.ndarray] = {}
    for lbl in unique_labels:
        label_indices[int(lbl)] = np.where(labels == lbl)[0]

    keep_indices: list[int] = []

    # First pass: proportional allocation.
    labeled_total = sum(
        len(idx) for lbl, idx in label_indices.items() if lbl != -1
    )
    unlabeled_indices = label_indices.get(-1, np.array([], dtype=np.intp))

    # Reserve a share for unlabeled data proportional to its occurrence.
    total_for_ratio = n
    unlabeled_budget = 0
    if len(unlabeled_indices) > 0:
        unlabeled_ratio = len(unlabeled_indices) / total_for_ratio
        unlabeled_budget = max(1, int(max_samples * unlabeled_ratio))

    labeled_budget = max_samples - unlabeled_budget

    for lbl, indices in label_indices.items():
        if lbl == -1:
            # Take the tail (most recent) from unlabeled.
            budget = min(unlabeled_budget, len(indices))
            if budget > 0:
                keep_indices.extend(indices[-budget:].tolist())
            continue

        if labeled_total > 0:
            class_share = len(indices) / labeled_total
        else:
            class_share = 1.0 / max(len(label_indices) - (1 if -1 in label_indices else 0), 1)

        budget = max(1, int(labeled_budget * class_share))
        budget = min(budget, len(indices))
        # Take the tail (most recent) per class.
        keep_indices.extend(indices[-budget:].tolist())

    # If rounding left us under budget, fill from the overall tail.
    if len(keep_indices) < max_samples:
        all_idx_set = set(keep_indices)
        for i in range(n - 1, -1, -1):
            if len(keep_indices) >= max_samples:
                break
            if i not in all_idx_set:
                keep_indices.append(i)
                all_idx_set.add(i)

    # If over budget due to rounding, trim.
    if len(keep_indices) > max_samples:
        keep_indices = keep_indices[:max_samples]

    keep_indices.sort()
    idx = np.array(keep_indices, dtype=np.intp)

    return features[idx], sha256[idx], labels[idx]


def _merge_arrays(
    existing: Optional[dict[str, np.ndarray]],
    new_data: dict[str, np.ndarray],
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Concatenate existing and new feature/hash/label arrays.

    Handles mismatched feature dimensions gracefully by zero-padding the
    narrower array.
    """
    if existing is None or "features" not in existing or existing["features"].size == 0:
        feat = new_data.get("features", np.empty((0, 0), dtype=np.float32))
        sha = new_data.get("sha256", np.array([], dtype="<U64"))
        lbl = new_data.get("labels", np.full(len(sha), -1, dtype=np.int32))
        return feat, sha, lbl

    e_feat = existing["features"]
    e_sha = existing.get("sha256", np.array([], dtype="<U64"))
    e_lbl = existing.get("labels", np.full(len(e_sha), -1, dtype=np.int32))

    n_feat = new_data.get("features", np.empty((0, 0), dtype=np.float32))
    n_sha = new_data.get("sha256", np.array([], dtype="<U64"))
    n_lbl = new_data.get("labels", np.full(len(n_sha), -1, dtype=np.int32))

    if n_feat.size == 0:
        return e_feat, e_sha, e_lbl

    # Handle feature dimension mismatch.
    if e_feat.ndim == 2 and n_feat.ndim == 2 and e_feat.shape[1] != n_feat.shape[1]:
        max_dim = max(e_feat.shape[1], n_feat.shape[1])
        if e_feat.shape[1] < max_dim:
            pad = np.zeros(
                (e_feat.shape[0], max_dim - e_feat.shape[1]), dtype=np.float32
            )
            e_feat = np.hstack([e_feat, pad])
        if n_feat.shape[1] < max_dim:
            pad = np.zeros(
                (n_feat.shape[0], max_dim - n_feat.shape[1]), dtype=np.float32
            )
            n_feat = np.hstack([n_feat, pad])
        logger.info(
            "Padded feature dimension mismatch to %d columns", max_dim
        )

    # Ensure label arrays match their feature arrays.
    if len(e_lbl) != len(e_sha):
        e_lbl = np.full(len(e_sha), -1, dtype=np.int32)
    if len(n_lbl) != len(n_sha):
        n_lbl = np.full(len(n_sha), -1, dtype=np.int32)

    merged_feat = np.vstack([e_feat, n_feat]).astype(np.float32)
    merged_sha = np.concatenate([e_sha, n_sha])
    merged_lbl = np.concatenate([e_lbl, n_lbl])

    return merged_feat, merged_sha, merged_lbl


def _per_class_counts(labels: np.ndarray) -> dict[str, int]:
    """Return label distribution as a dict."""
    counts: Counter[int] = Counter(labels.tolist())
    return {str(k): v for k, v in sorted(counts.items())}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def merge(
    processed_dir: Path,
    dataset_dir: Path,
    caps: Optional[dict[str, int]] = None,
) -> dict[str, Any]:
    """Merge newly extracted features into cumulative training datasets.

    This is the entry-point consumed by ``pipeline.py``.

    Parameters
    ----------
    processed_dir : Path
        Directory containing per-model ``.npz`` files produced by
        ``extract_all`` (e.g. ``static_features.npz``).
    dataset_dir : Path
        Destination for cumulative merged datasets.  Existing datasets
        are loaded, appended to, deduplicated, capped, and re-saved.
    caps : dict[str, int], optional
        Per-model maximum sample counts.  Falls back to built-in defaults
        (1M for static, 500K for others).

    Returns
    -------
    dict
        Merge statistics::

            {
                "per_model": {
                    "<model>": {
                        "samples_before": int,
                        "samples_after": int,
                        "new_added": int,
                        "duplicates_removed": int,
                        "capped_from": int | None,
                        "per_class_counts": dict,
                    },
                    ...
                },
                "samples_before": int,
                "samples_after": int,
                "duplicates_removed": int,
                "duration_sec": float,
            }
    """
    processed_dir = Path(processed_dir)
    dataset_dir = Path(dataset_dir)
    dataset_dir.mkdir(parents=True, exist_ok=True)

    effective_caps = dict(_MODEL_CAPS)
    if caps:
        effective_caps.update(caps)

    t0 = time.monotonic()
    per_model: dict[str, dict[str, Any]] = {}
    grand_before = 0
    grand_after = 0
    grand_dupes = 0

    # Discover new .npz files in processed_dir.
    npz_files: list[Path] = sorted(processed_dir.glob("*.npz"))
    if not npz_files:
        logger.info("No .npz files found in %s -- nothing to merge", processed_dir)
        return {
            "per_model": {},
            "samples_before": 0,
            "samples_after": 0,
            "duplicates_removed": 0,
            "duration_sec": round(time.monotonic() - t0, 3),
        }

    for npz_path in npz_files:
        model_name = _NPZ_TO_MODEL.get(npz_path.name)
        if model_name is None:
            logger.debug("Skipping unrecognised npz: %s", npz_path.name)
            continue

        logger.info("Merging model '%s' from %s", model_name, npz_path.name)

        new_data = _load_npz(npz_path)
        if new_data is None or "features" not in new_data:
            logger.warning("Skipping empty/corrupt file: %s", npz_path)
            continue

        new_count = new_data["features"].shape[0] if new_data["features"].ndim >= 1 else 0
        if new_count == 0:
            logger.info("No new features in %s -- skipping", npz_path.name)
            continue

        # Load existing dataset.
        existing_path = dataset_dir / f"{model_name}_dataset.npz"
        existing_data = _load_npz(existing_path)

        samples_before = 0
        if existing_data is not None and "features" in existing_data:
            samples_before = existing_data["features"].shape[0]

        grand_before += samples_before

        # Merge new into existing.
        feat, sha, lbl = _merge_arrays(existing_data, new_data)

        # Deduplicate by SHA-256.
        feat, sha, lbl, dupes = _deduplicate(feat, sha, lbl)
        grand_dupes += dupes

        # Cap dataset size via stratified sampling.
        max_cap = effective_caps.get(model_name, _DEFAULT_MAX_SAMPLES)
        pre_cap_count = len(sha)
        feat, sha, lbl = _cap_dataset(feat, sha, lbl, max_cap)

        samples_after = len(sha)
        grand_after += samples_after

        class_counts = _per_class_counts(lbl)

        per_model[model_name] = {
            "samples_before": samples_before,
            "samples_after": samples_after,
            "new_added": max(0, samples_after - samples_before + dupes),
            "duplicates_removed": dupes,
            "capped_from": pre_cap_count if pre_cap_count > samples_after else None,
            "per_class_counts": class_counts,
        }

        # Save merged dataset.
        save_dict: dict[str, Any] = {
            "features": feat,
            "sha256": sha,
            "labels": lbl,
        }
        np.savez_compressed(str(existing_path), **save_dict)

        logger.info(
            "Model '%s': %d before, %d after, %d dupes removed, classes=%s",
            model_name,
            samples_before,
            samples_after,
            dupes,
            class_counts,
        )

    duration = round(time.monotonic() - t0, 3)

    result: dict[str, Any] = {
        "per_model": per_model,
        "samples_before": grand_before,
        "samples_after": grand_after,
        "duplicates_removed": grand_dupes,
        "duration_sec": duration,
    }

    logger.info(
        "Dataset merge complete: %d before -> %d after, %d dupes, %.1fs",
        grand_before,
        grand_after,
        grand_dupes,
        duration,
    )

    return result
