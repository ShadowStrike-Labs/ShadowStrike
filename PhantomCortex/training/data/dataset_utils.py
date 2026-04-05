"""
Common Dataset Utilities for PhantomCortex Training
=====================================================

Reusable data loading, splitting, standardization, and persistence utilities
shared across all Cortex model training pipelines.

Provides:
    - Stratified train/val/test splitting with reproducibility
    - DataLoader creation with configurable workers and pinning
    - Inverse-frequency class weight computation
    - Feature standardization (z-score) with serializable scaler parameters
    - NPZ-based dataset serialization and loading
    - Dataset statistics reporting
    - Custom Dataset wrapper supporting optional transforms
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, Sequence, Tuple, Union

import numpy as np
import torch
from numpy.typing import NDArray
from torch.utils.data import DataLoader, Dataset

logger = logging.getLogger("PhantomCortex.DatasetUtils")


# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

SplitTuple = Tuple[NDArray[np.float32], NDArray[np.int64]]


# ---------------------------------------------------------------------------
# Scaler parameters
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScalerParams:
    """Statistics captured during training-set standardization.

    Stored alongside datasets so validation/test sets can be scaled
    identically without data leakage.
    """

    mean: NDArray[np.float64]
    std: NDArray[np.float64]

    def to_dict(self) -> dict[str, list[float]]:
        return {
            "mean": self.mean.tolist(),
            "std": self.std.tolist(),
        }


# ---------------------------------------------------------------------------
# Custom Dataset
# ---------------------------------------------------------------------------


class TensorDatasetWithTransform(Dataset):
    """Pairs feature and label tensors with an optional per-sample transform.

    Parameters
    ----------
    X : torch.Tensor
        Feature tensor of any shape ``(N, ...)``.
    y : torch.Tensor
        Label tensor of shape ``(N,)``.
    transform : callable, optional
        Applied to each ``X[i]`` at access time.  Must accept and return
        a :class:`torch.Tensor`.
    """

    def __init__(
        self,
        X: torch.Tensor,
        y: torch.Tensor,
        transform: Optional[Callable[[torch.Tensor], torch.Tensor]] = None,
    ) -> None:
        if X.shape[0] != y.shape[0]:
            raise ValueError(
                f"Feature/label size mismatch: X has {X.shape[0]} samples, "
                f"y has {y.shape[0]} samples"
            )
        self._X = X
        self._y = y
        self._transform = transform

    def __len__(self) -> int:
        return self._X.shape[0]

    def __getitem__(self, index: int) -> tuple[torch.Tensor, torch.Tensor]:
        x_item = self._X[index]
        if self._transform is not None:
            x_item = self._transform(x_item)
        return x_item, self._y[index]


# ---------------------------------------------------------------------------
# Splitting
# ---------------------------------------------------------------------------


def split_data(
    X: NDArray[np.float32],
    y: NDArray[np.int64],
    train_ratio: float = 0.8,
    val_ratio: float = 0.1,
    test_ratio: float = 0.1,
    seed: int = 42,
) -> tuple[SplitTuple, SplitTuple, SplitTuple]:
    """Stratified split into train / validation / test sets.

    Maintains class proportions across all three partitions.

    Parameters
    ----------
    X : ndarray (N, ...)
        Features.
    y : ndarray (N,)
        Integer class labels.
    train_ratio, val_ratio, test_ratio : float
        Must sum to 1.0 (±1e-6).
    seed : int
        Random seed for reproducibility.

    Returns
    -------
    (X_train, y_train), (X_val, y_val), (X_test, y_test)
    """
    ratio_sum = train_ratio + val_ratio + test_ratio
    if abs(ratio_sum - 1.0) > 1e-6:
        raise ValueError(
            f"Split ratios must sum to 1.0, got {ratio_sum:.6f} "
            f"({train_ratio} + {val_ratio} + {test_ratio})"
        )
    if X.shape[0] != y.shape[0]:
        raise ValueError(
            f"X and y length mismatch: {X.shape[0]} vs {y.shape[0]}"
        )
    n = X.shape[0]
    if n < 3:
        raise ValueError(f"Need at least 3 samples to split, got {n}")

    rng = np.random.default_rng(seed)

    unique_classes = np.unique(y)
    train_indices: list[int] = []
    val_indices: list[int] = []
    test_indices: list[int] = []

    for cls in unique_classes:
        cls_mask = y == cls
        cls_indices = np.where(cls_mask)[0]
        rng.shuffle(cls_indices)

        n_cls = len(cls_indices)
        n_train = max(1, int(round(n_cls * train_ratio)))
        n_val = max(1, int(round(n_cls * val_ratio)))
        n_test = n_cls - n_train - n_val

        if n_test < 1:
            n_test = 1
            n_train = n_cls - n_val - n_test
        if n_train < 1:
            n_train = 1
            n_val = n_cls - n_train - n_test

        train_indices.extend(cls_indices[:n_train].tolist())
        val_indices.extend(cls_indices[n_train : n_train + n_val].tolist())
        test_indices.extend(cls_indices[n_train + n_val :].tolist())

    rng.shuffle(np.asarray(train_indices))
    rng.shuffle(np.asarray(val_indices))
    rng.shuffle(np.asarray(test_indices))

    train_idx = np.array(train_indices)
    val_idx = np.array(val_indices)
    test_idx = np.array(test_indices)

    rng.shuffle(train_idx)
    rng.shuffle(val_idx)
    rng.shuffle(test_idx)

    logger.info(
        "Split %d samples -> train=%d, val=%d, test=%d",
        n,
        len(train_idx),
        len(val_idx),
        len(test_idx),
    )

    return (
        (X[train_idx], y[train_idx]),
        (X[val_idx], y[val_idx]),
        (X[test_idx], y[test_idx]),
    )


# ---------------------------------------------------------------------------
# DataLoader creation
# ---------------------------------------------------------------------------


def create_dataloader(
    X: NDArray[np.float32],
    y: NDArray[np.int64],
    batch_size: int = 128,
    shuffle: bool = True,
    num_workers: int = 0,
    *,
    transform: Optional[Callable[[torch.Tensor], torch.Tensor]] = None,
    pin_memory: bool = True,
    drop_last: bool = False,
) -> DataLoader:
    """Wrap numpy arrays in a :class:`DataLoader`.

    Parameters
    ----------
    X : ndarray
        Feature array of shape ``(N, ...)``.
    y : ndarray
        Label array of shape ``(N,)``.
    batch_size : int
        Batch size for the loader.
    shuffle : bool
        Whether to shuffle each epoch.
    num_workers : int
        Parallel data-loading workers (0 = main process only).
    transform : callable, optional
        Per-sample transform applied to X items.
    pin_memory : bool
        Pin tensors in CPU memory for faster GPU transfer.
    drop_last : bool
        Drop incomplete final batch.

    Returns
    -------
    DataLoader
    """
    X_tensor = torch.as_tensor(X, dtype=torch.float32)
    y_tensor = torch.as_tensor(y, dtype=torch.long)
    dataset = TensorDatasetWithTransform(X_tensor, y_tensor, transform=transform)
    return DataLoader(
        dataset,
        batch_size=batch_size,
        shuffle=shuffle,
        num_workers=num_workers,
        pin_memory=pin_memory and torch.cuda.is_available(),
        drop_last=drop_last,
        persistent_workers=num_workers > 0,
    )


# ---------------------------------------------------------------------------
# Class weights
# ---------------------------------------------------------------------------


def compute_class_weights(y: NDArray[np.int64]) -> torch.Tensor:
    """Compute inverse-frequency class weights for imbalanced datasets.

    For class *c* with count *n_c* and total *N*:
        ``weight_c = N / (num_classes * n_c)``

    Parameters
    ----------
    y : ndarray (N,)
        Integer class labels.

    Returns
    -------
    torch.Tensor of shape ``(num_classes,)`` with float32 weights.
    """
    classes, counts = np.unique(y, return_counts=True)
    n_total = float(len(y))
    n_classes = len(classes)

    weights = np.zeros(int(classes.max()) + 1, dtype=np.float64)
    for cls_id, count in zip(classes, counts):
        weights[int(cls_id)] = n_total / (n_classes * count)

    logger.info(
        "Class weights (inverse frequency): %s",
        {int(c): round(float(weights[int(c)]), 4) for c in classes},
    )
    return torch.tensor(weights, dtype=torch.float32)


# ---------------------------------------------------------------------------
# Standardization
# ---------------------------------------------------------------------------


def standardize_features(
    X_train: NDArray[np.float32],
    X_val: NDArray[np.float32],
    X_test: NDArray[np.float32],
    *,
    epsilon: float = 1e-8,
) -> tuple[NDArray[np.float32], NDArray[np.float32], NDArray[np.float32], ScalerParams]:
    """Z-score standardize features using training-set statistics.

    Computes mean and std from ``X_train`` only, then applies the same
    transform to validation and test sets to prevent data leakage.

    Parameters
    ----------
    X_train, X_val, X_test : ndarray
        Feature arrays.  Must share the same trailing dimensions.
    epsilon : float
        Floor for standard deviation to avoid division by zero.

    Returns
    -------
    X_train_std, X_val_std, X_test_std, scaler_params
    """
    original_shape = X_train.shape

    X_flat = X_train.reshape(X_train.shape[0], -1).astype(np.float64)
    mean = X_flat.mean(axis=0)
    std = X_flat.std(axis=0)
    std = np.maximum(std, epsilon)

    def _apply(arr: NDArray[np.float32]) -> NDArray[np.float32]:
        flat = arr.reshape(arr.shape[0], -1).astype(np.float64)
        scaled = ((flat - mean) / std).astype(np.float32)
        return scaled.reshape(arr.shape)

    scaler = ScalerParams(mean=mean, std=std)
    logger.info(
        "Standardized features: shape=%s, mean_range=[%.4f, %.4f], std_range=[%.4f, %.4f]",
        original_shape[1:],
        float(mean.min()),
        float(mean.max()),
        float(std.min()),
        float(std.max()),
    )

    return _apply(X_train), _apply(X_val), _apply(X_test), scaler


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def save_dataset(
    path: Union[str, Path],
    X_train: NDArray[np.float32],
    y_train: NDArray[np.int64],
    X_val: NDArray[np.float32],
    y_val: NDArray[np.int64],
    X_test: NDArray[np.float32],
    y_test: NDArray[np.int64],
) -> None:
    """Persist a train/val/test dataset as a compressed ``.npz`` archive.

    Parameters
    ----------
    path : str or Path
        Output file path (the ``.npz`` extension is appended if absent).
    X_train, y_train, X_val, y_val, X_test, y_test : ndarray
        Arrays produced by :func:`split_data`.
    """
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.suffix != ".npz":
        out = out.with_suffix(".npz")

    np.savez_compressed(
        str(out),
        X_train=X_train,
        y_train=y_train,
        X_val=X_val,
        y_val=y_val,
        X_test=X_test,
        y_test=y_test,
    )

    size_mb = out.stat().st_size / (1024 * 1024)
    logger.info("Dataset saved to %s (%.2f MB)", out, size_mb)


def load_dataset(
    path: Union[str, Path],
) -> tuple[
    NDArray[np.float32],
    NDArray[np.int64],
    NDArray[np.float32],
    NDArray[np.int64],
    NDArray[np.float32],
    NDArray[np.int64],
]:
    """Load a dataset saved by :func:`save_dataset`.

    Parameters
    ----------
    path : str or Path
        Path to the ``.npz`` archive.

    Returns
    -------
    X_train, y_train, X_val, y_val, X_test, y_test
    """
    p = Path(path)
    if p.suffix != ".npz":
        p = p.with_suffix(".npz")
    if not p.exists():
        raise FileNotFoundError(f"Dataset file not found: {p}")

    data = np.load(str(p))
    required_keys = {"X_train", "y_train", "X_val", "y_val", "X_test", "y_test"}
    missing = required_keys - set(data.files)
    if missing:
        raise ValueError(f"Dataset missing keys: {missing}")

    logger.info("Dataset loaded from %s", p)
    return (
        data["X_train"].astype(np.float32),
        data["y_train"].astype(np.int64),
        data["X_val"].astype(np.float32),
        data["y_val"].astype(np.int64),
        data["X_test"].astype(np.float32),
        data["y_test"].astype(np.int64),
    )


# ---------------------------------------------------------------------------
# Statistics reporting
# ---------------------------------------------------------------------------


def print_dataset_stats(
    y: NDArray[np.int64],
    class_names: Sequence[str],
) -> None:
    """Print class distribution table to the logger and stdout.

    Parameters
    ----------
    y : ndarray (N,)
        Integer class labels.
    class_names : sequence of str
        Human-readable class names indexed by label value.
    """
    classes, counts = np.unique(y, return_counts=True)
    total = int(y.shape[0])

    header = f"{'Class':<25s} {'Count':>8s} {'Pct':>7s}"
    separator = "-" * len(header)

    lines = [separator, header, separator]
    for cls_id, count in zip(classes, counts):
        idx = int(cls_id)
        name = class_names[idx] if idx < len(class_names) else f"Unknown({idx})"
        pct = 100.0 * count / total
        lines.append(f"{name:<25s} {count:>8d} {pct:>6.2f}%")
    lines.append(separator)
    lines.append(f"{'Total':<25s} {total:>8d} {'100.00%':>7s}")
    lines.append(separator)

    report = "\n".join(lines)
    print(report)
    logger.info("Dataset distribution:\n%s", report)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="PhantomCortex dataset utility — inspect or split saved datasets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", help="Sub-command")

    # --- inspect ---
    p_inspect = sub.add_parser("inspect", help="Print statistics for a saved .npz dataset")
    p_inspect.add_argument("path", type=str, help="Path to .npz dataset file")
    p_inspect.add_argument(
        "--class-names",
        type=str,
        nargs="+",
        default=None,
        help="Class names in order (e.g., Benign Suspicious Malicious)",
    )

    # --- split ---
    p_split = sub.add_parser("split", help="Split a raw X/y .npz into train/val/test")
    p_split.add_argument("input", type=str, help="Input .npz with X and y arrays")
    p_split.add_argument("output", type=str, help="Output .npz for split dataset")
    p_split.add_argument("--train-ratio", type=float, default=0.8)
    p_split.add_argument("--val-ratio", type=float, default=0.1)
    p_split.add_argument("--test-ratio", type=float, default=0.1)
    p_split.add_argument("--seed", type=int, default=42)

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    if args.command == "inspect":
        data = np.load(args.path)
        for key in data.files:
            arr = data[key]
            print(f"  {key}: shape={arr.shape}, dtype={arr.dtype}")

        for split_name in ("y_train", "y_val", "y_test", "y"):
            if split_name in data.files:
                names = args.class_names or [f"Class_{i}" for i in range(int(data[split_name].max()) + 1)]
                print(f"\n--- {split_name} ---")
                print_dataset_stats(data[split_name].astype(np.int64), names)

    elif args.command == "split":
        raw = np.load(args.input)
        if "X" not in raw.files or "y" not in raw.files:
            print("ERROR: Input .npz must contain 'X' and 'y' arrays.", file=sys.stderr)
            sys.exit(1)

        X = raw["X"].astype(np.float32)
        y = raw["y"].astype(np.int64)

        (X_tr, y_tr), (X_v, y_v), (X_te, y_te) = split_data(
            X, y,
            train_ratio=args.train_ratio,
            val_ratio=args.val_ratio,
            test_ratio=args.test_ratio,
            seed=args.seed,
        )
        save_dataset(args.output, X_tr, y_tr, X_v, y_v, X_te, y_te)
        print(f"Saved split dataset to {args.output}")

    else:
        parser.print_help()
        sys.exit(1)
