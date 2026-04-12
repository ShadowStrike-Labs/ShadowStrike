"""
EMBER2024 PE Loader for PhantomCortex
=====================================

Downloads and loads the EMBER2024 PE subsets through the upstream ``thrember``
package. The loader keeps ShadowStrike decoupled from the reference training
code while reusing the published dataset packaging and vectorization flow.
"""

from __future__ import annotations

import logging
from pathlib import Path

import numpy as np
from numpy.typing import NDArray

logger = logging.getLogger("PhantomCortex.Data.EMBER2024")

_DEFAULT_DIR = Path(__file__).resolve().parent / "raw" / "ember2024_pe"


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


def load_ember2024(
    data_dir: str | Path | None = None,
    *,
    download: bool = True,
    file_type: str = "PE",
    label_type: str = "label",
    class_min: int = 10,
) -> tuple[
    NDArray[np.float32],
    NDArray[np.int32],
    NDArray[np.float32],
    NDArray[np.int32],
]:
    """Load EMBER2024 PE vectors and malicious/benign labels."""
    base_dir = _resolve_data_dir(data_dir)
    base_dir.mkdir(parents=True, exist_ok=True)

    try:
        import thrember
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "EMBER2024 support requires the 'thrember' package. "
            "Install PhantomCortex requirements before training."
        ) from exc

    logger.info("Using EMBER2024 directory: %s", base_dir)

    if download and not any(base_dir.iterdir()):
        logger.info("Downloading EMBER2024 subset '%s' ...", file_type)
        thrember.download_dataset(str(base_dir), file_type=file_type)

    try:
        X_train, y_train = thrember.read_vectorized_features(
            str(base_dir), subset="train"
        )
        X_test, y_test = thrember.read_vectorized_features(
            str(base_dir), subset="test"
        )
    except Exception:
        logger.info(
            "Vectorized EMBER2024 features missing — creating them "
            "(label_type=%s, class_min=%d)",
            label_type,
            class_min,
        )
        thrember.create_vectorized_features(
            str(base_dir),
            label_type=label_type,
            class_min=class_min,
        )
        X_train, y_train = thrember.read_vectorized_features(
            str(base_dir), subset="train"
        )
        X_test, y_test = thrember.read_vectorized_features(
            str(base_dir), subset="test"
        )

    X_train_np = np.ascontiguousarray(np.asarray(X_train, dtype=np.float32))
    y_train_np = np.ascontiguousarray(np.asarray(y_train, dtype=np.int32))
    X_test_np = np.ascontiguousarray(np.asarray(X_test, dtype=np.float32))
    y_test_np = np.ascontiguousarray(np.asarray(y_test, dtype=np.int32))

    if X_train_np.ndim != 2 or X_test_np.ndim != 2:
        raise RuntimeError(
            f"Expected 2-D EMBER2024 feature matrices, got {X_train_np.ndim}-D and {X_test_np.ndim}-D"
        )
    if X_train_np.shape[1] != X_test_np.shape[1]:
        raise RuntimeError(
            "EMBER2024 train/test feature counts differ: "
            f"{X_train_np.shape[1]} vs {X_test_np.shape[1]}"
        )
    if X_train_np.shape[0] == 0 or X_test_np.shape[0] == 0:
        raise RuntimeError("EMBER2024 returned an empty train/test split")

    _validate_binary_labels("train", y_train_np)
    _validate_binary_labels("test", y_test_np)

    logger.info(
        "EMBER2024 loaded: train=%d test=%d features=%d",
        X_train_np.shape[0],
        X_test_np.shape[0],
        X_train_np.shape[1],
    )
    return X_train_np, y_train_np, X_test_np, y_test_np
