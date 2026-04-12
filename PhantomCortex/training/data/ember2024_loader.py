"""
EMBER2024 PE Loader for PhantomCortex
=====================================

Memory-efficient loader for the EMBER 2024 dataset (4.68M train + 1.08M test,
2568 features).  Uses numpy memory-mapped files directly so the full 45 GB
training matrix never needs to be copied into physical RAM.

When the caller specifies *max_samples*, the loader performs stratified
subsampling on the memmap and returns only the selected rows as contiguous
in-memory arrays — safe for downstream LightGBM / PyTorch consumption.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import numpy as np
from numpy.typing import NDArray

logger = logging.getLogger("PhantomCortex.Data.EMBER2024")

_DEFAULT_DIR = Path(__file__).resolve().parent / "raw" / "ember2024_pe"

# EMBER 2024 PE feature vector dimension (thrember.PEFeatureExtractor.dim)
EMBER2024_FEATURE_DIM: int = 2568


def _resolve_data_dir(data_dir: str | Path | None) -> Path:
    if data_dir is None:
        return _DEFAULT_DIR
    return Path(data_dir).expanduser().resolve()


def _validate_binary_labels(name: str, labels: NDArray[np.int32]) -> None:
    unique = np.unique(labels)
    if not np.array_equal(unique, np.array([0, 1], dtype=np.int32)):
        raise RuntimeError(
            f"Expected binary labels [0, 1] for {name}, got {unique.tolist()}"
        )


def _read_memmap_subset(
    data_dir: Path,
    subset: str,
    ndim: int,
) -> tuple[NDArray[np.float32], NDArray[np.int32]]:
    """Read a vectorized .dat pair as memory-mapped arrays (zero-copy)."""
    x_path = data_dir / f"X_{subset}.dat"
    y_path = data_dir / f"y_{subset}.dat"

    if not x_path.exists() or not y_path.exists():
        raise FileNotFoundError(
            f"Vectorized EMBER 2024 files missing: {x_path} and/or {y_path}. "
            "Run vectorize_ember2024.py first."
        )

    x_flat = np.memmap(str(x_path), dtype=np.float32, mode="r")
    n_samples = len(x_flat) // ndim
    remainder = len(x_flat) % ndim
    if remainder != 0:
        raise RuntimeError(
            f"X_{subset}.dat element count ({len(x_flat):,}) is not divisible "
            f"by feature dim ({ndim}). Remainder={remainder}. "
            "Dataset may be corrupt or feature dimension may have changed."
        )

    X = x_flat.reshape(n_samples, ndim)

    y_raw = np.memmap(str(y_path), dtype=np.int32, mode="r")
    if len(y_raw) < n_samples:
        raise RuntimeError(
            f"y_{subset}.dat has {len(y_raw):,} labels but X has {n_samples:,} rows"
        )
    y = y_raw[:n_samples]

    return X, y


def _stratified_subsample(
    X: NDArray[np.float32],
    y: NDArray[np.int32],
    max_samples: int,
    rng: np.random.Generator,
) -> tuple[NDArray[np.float32], NDArray[np.int32]]:
    """Stratified subsample keeping class balance, returning contiguous arrays."""
    if X.shape[0] <= max_samples:
        return np.ascontiguousarray(X), np.ascontiguousarray(y)

    half = max_samples // 2
    idx_0 = np.where(y == 0)[0]
    idx_1 = np.where(y == 1)[0]

    n_0 = min(half, len(idx_0))
    n_1 = min(max_samples - n_0, len(idx_1))
    # Rebalance if one class had fewer than half
    if n_1 < half and len(idx_0) > n_0:
        n_0 = min(max_samples - n_1, len(idx_0))

    sel_0 = rng.choice(idx_0, size=n_0, replace=False)
    sel_1 = rng.choice(idx_1, size=n_1, replace=False)
    sel = np.sort(np.concatenate([sel_0, sel_1]))

    return np.ascontiguousarray(X[sel]), np.ascontiguousarray(y[sel])


def load_ember2024(
    data_dir: str | Path | None = None,
    *,
    download: bool = True,
    file_type: str = "PE",
    label_type: str = "label",
    class_min: int = 10,
    max_train_samples: int = 0,
    max_test_samples: int = 0,
    seed: int = 42,
) -> tuple[
    NDArray[np.float32],
    NDArray[np.int32],
    NDArray[np.float32],
    NDArray[np.int32],
]:
    """Load EMBER 2024 PE vectors and malicious/benign labels.

    Uses memory-mapped I/O so the full 45 GB training matrix is never
    allocated in physical RAM.  When *max_train_samples* or *max_test_samples*
    are > 0 the returned arrays are stratified subsamples that fit in RAM.

    Returns:
        (X_train, y_train, X_test, y_test) as contiguous float32/int32 arrays.
    """
    base_dir = _resolve_data_dir(data_dir)
    base_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Using EMBER 2024 directory: %s", base_dir)

    # Check if vectorized files exist; if not, create them
    x_train_path = base_dir / "X_train.dat"
    if not x_train_path.exists():
        try:
            import thrember
        except ImportError as exc:
            raise RuntimeError(
                "EMBER 2024 support requires the 'thrember' package."
            ) from exc

        if download and not any(
            f.suffix == ".jsonl" for f in base_dir.iterdir()
        ):
            logger.info("Downloading EMBER 2024 subset '%s' ...", file_type)
            thrember.download_dataset(str(base_dir), file_type=file_type)

        logger.info(
            "Vectorizing EMBER 2024 features (label_type=%s, class_min=%d) ...",
            label_type, class_min,
        )
        thrember.create_vectorized_features(
            str(base_dir),
            label_type=label_type,
            class_min=class_min,
        )

    # Read via memmap (zero-copy, no RAM explosion)
    ndim = EMBER2024_FEATURE_DIM
    X_train_mm, y_train_mm = _read_memmap_subset(base_dir, "train", ndim)
    X_test_mm, y_test_mm = _read_memmap_subset(base_dir, "test", ndim)

    logger.info(
        "EMBER 2024 memmap: train=%d test=%d features=%d",
        X_train_mm.shape[0], X_test_mm.shape[0], ndim,
    )

    rng = np.random.default_rng(seed)

    # Subsample if requested
    if max_train_samples > 0:
        X_train_np, y_train_np = _stratified_subsample(
            X_train_mm, y_train_mm, max_train_samples, rng,
        )
    else:
        X_train_np = np.ascontiguousarray(X_train_mm)
        y_train_np = np.ascontiguousarray(y_train_mm)

    if max_test_samples > 0:
        X_test_np, y_test_np = _stratified_subsample(
            X_test_mm, y_test_mm, max_test_samples, rng,
        )
    else:
        X_test_np = np.ascontiguousarray(X_test_mm)
        y_test_np = np.ascontiguousarray(y_test_mm)

    # Release memmap references
    del X_train_mm, y_train_mm, X_test_mm, y_test_mm

    _validate_binary_labels("train", y_train_np)
    _validate_binary_labels("test", y_test_np)

    logger.info(
        "EMBER 2024 loaded: train=%d test=%d features=%d",
        X_train_np.shape[0], X_test_np.shape[0], X_train_np.shape[1],
    )
    return X_train_np, y_train_np, X_test_np, y_test_np
