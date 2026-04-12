"""
Real-World Memory Forensics Dataset Loader for Cortex-Memory
=============================================================

Loads and preprocesses Volatility-based memory analysis datasets for
training the Cortex-Memory MLP classifier:

  * CIC-MalMem-2022 (58,596 samples, 16 malware categories)
  * MemMal-D2024    (58,168 samples, Apache-2.0, temporal evaluation)

Both datasets provide Volatility framework features extracted from Windows
memory dumps: process lists, DLL counts, handles, LDR modules, malfind
injections, psxview cross-view analysis, service scan, and callbacks.

The 55 raw Volatility features are expanded to 128 dimensions via
feature engineering (cross-ratios, normalizations, interaction terms)
to match the CortexMemoryNet input specification.

Class Mapping (5 classes):
    0 — Benign           : Clean process memory
    1 — Trojan/Injector  : Trojans using code injection (Emotet, Zeus, etc.)
    2 — Ransomware       : Encrypting ransomware (Conti, Maze, Shade, etc.)
    3 — Spyware          : Spyware/keyloggers (Gator, TIBS, CWS, etc.)
    4 — MalwareGeneric   : Other/unclassified malware

License: All datasets used are Apache-2.0 or CC-BY compatible.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
from numpy.typing import NDArray

logger = logging.getLogger("PhantomCortex.Data.MemoryExternal")

TARGET_DIM: int = 128
NUM_CLASSES: int = 5

_CIC_CATEGORY_MAP: dict[str, int] = {
    "Benign":                0,
    "Trojan-Scar":           1,
    "Trojan-Refroso":        1,
    "Trojan-Emotet":         1,
    "Trojan-Zeus":           1,
    "Trojan-Reconyc":        1,
    "Ransomware-Shade":      2,
    "Ransomware-Ako":        2,
    "Ransomware-Conti":      2,
    "Ransomware-Maze":       2,
    "Ransomware-Pysa":       2,
    "Spyware-Transponder":   3,
    "Spyware-Gator":         3,
    "Spyware-CWS":           3,
    "Spyware-180solutions":  3,
    "Spyware-TIBS":          3,
}

# Volatility feature columns (55 features, shared between datasets)
_VOLATILITY_FEATURES: list[str] = [
    "pslist.nproc", "pslist.nppid", "pslist.avg_threads",
    "pslist.nprocs64bit", "pslist.avg_handlers",
    "dlllist.ndlls", "dlllist.avg_dlls_per_proc",
    "handles.nhandles", "handles.avg_handles_per_proc", "handles.nport",
    "handles.nfile", "handles.nevent", "handles.ndesktop",
    "handles.nkey", "handles.nthread", "handles.ndirectory",
    "handles.nsemaphore", "handles.ntimer", "handles.nsection",
    "handles.nmutant",
    "ldrmodules.not_in_load", "ldrmodules.not_in_init",
    "ldrmodules.not_in_mem", "ldrmodules.not_in_load_avg",
    "ldrmodules.not_in_init_avg", "ldrmodules.not_in_mem_avg",
    "malfind.ninjections", "malfind.commitCharge",
    "malfind.protection", "malfind.uniqueInjections",
    "psxview.not_in_pslist", "psxview.not_in_eprocess_pool",
    "psxview.not_in_ethread_pool", "psxview.not_in_pspcid_list",
    "psxview.not_in_csrss_handles", "psxview.not_in_session",
    "psxview.not_in_deskthrd",
    "psxview.not_in_pslist_false_avg",
    "psxview.not_in_eprocess_pool_false_avg",
    "psxview.not_in_ethread_pool_false_avg",
    "psxview.not_in_pspcid_list_false_avg",
    "psxview.not_in_csrss_handles_false_avg",
    "psxview.not_in_session_false_avg",
    "psxview.not_in_deskthrd_false_avg",
    "modules.nmodules",
    "svcscan.nservices", "svcscan.kernel_drivers", "svcscan.fs_drivers",
    "svcscan.process_services", "svcscan.shared_process_services",
    "svcscan.interactive_process_services", "svcscan.nactive",
    "callbacks.ncallbacks", "callbacks.nanonymous", "callbacks.ngeneric",
]


def _safe_div(a: NDArray, b: NDArray) -> NDArray:
    """Element-wise division with zero-safe denominator."""
    return np.divide(a, b, out=np.zeros_like(a, dtype=np.float32),
                     where=b != 0)


def _engineer_features(raw: NDArray[np.float32]) -> NDArray[np.float32]:
    """Expand 55 Volatility features to 128 dimensions.

    Engineering strategy:
      - 55 original features (indices 0-54)
      - 20 cross-feature ratios (handles/proc, dlls/proc, etc.)
      - 15 log1p transforms of high-variance features
      - 10 quadratic interaction terms for injection-related features
      - 28 statistical aggregate / window features
    Total: 128 dimensions
    """
    n = raw.shape[0]
    engineered = np.zeros((n, TARGET_DIM), dtype=np.float32)

    # Copy original 55 features
    engineered[:, :55] = raw

    col = 55

    # --- Cross-feature ratios (20 features) ---
    nproc = raw[:, 0]       # pslist.nproc
    ndlls = raw[:, 5]       # dlllist.ndlls
    nhandles = raw[:, 7]    # handles.nhandles
    nfile = raw[:, 10]      # handles.nfile
    ninjections = raw[:, 26]  # malfind.ninjections
    nservices = raw[:, 45]  # svcscan.nservices
    ncallbacks = raw[:, 52] # callbacks.ncallbacks

    engineered[:, col] = _safe_div(ndlls, nproc)        # dlls_per_proc_ratio
    col += 1
    engineered[:, col] = _safe_div(nhandles, nproc)      # handles_per_proc_ratio
    col += 1
    engineered[:, col] = _safe_div(nfile, nhandles)      # file_handle_ratio
    col += 1
    engineered[:, col] = _safe_div(ninjections, nproc)   # injections_per_proc
    col += 1
    engineered[:, col] = _safe_div(raw[:, 14], nproc)   # threads_per_proc
    col += 1
    engineered[:, col] = _safe_div(raw[:, 18], nhandles)  # section_per_handle
    col += 1
    engineered[:, col] = _safe_div(raw[:, 19], nhandles)  # mutant_per_handle
    col += 1
    engineered[:, col] = _safe_div(nservices, nproc)     # services_per_proc
    col += 1
    engineered[:, col] = _safe_div(raw[:, 46], nservices) # kdrv_per_service
    col += 1
    engineered[:, col] = _safe_div(raw[:, 51], nservices) # active_per_service
    col += 1
    # psxview anomaly density
    psxview_sum = (raw[:, 30] + raw[:, 31] + raw[:, 32] +
                   raw[:, 33] + raw[:, 34] + raw[:, 35] + raw[:, 36])
    engineered[:, col] = _safe_div(psxview_sum, nproc)
    col += 1
    # ldrmodules anomaly density
    ldr_sum = raw[:, 20] + raw[:, 21] + raw[:, 22]
    engineered[:, col] = _safe_div(ldr_sum, nproc)
    col += 1
    engineered[:, col] = _safe_div(raw[:, 27], ninjections)  # commit_per_injection
    col += 1
    engineered[:, col] = _safe_div(raw[:, 28], ninjections)  # protection_per_injection
    col += 1
    engineered[:, col] = _safe_div(ncallbacks, nproc)
    col += 1
    engineered[:, col] = _safe_div(raw[:, 53], ncallbacks)  # anon_per_callback
    col += 1
    engineered[:, col] = _safe_div(raw[:, 12], nproc)  # desktop_per_proc
    col += 1
    engineered[:, col] = _safe_div(raw[:, 15], nproc)  # directory_per_proc
    col += 1
    engineered[:, col] = _safe_div(raw[:, 16], nproc)  # semaphore_per_proc
    col += 1
    engineered[:, col] = _safe_div(raw[:, 17], nproc)  # timer_per_proc
    col += 1

    # --- Log1p transforms of high-variance features (15) ---
    high_var_indices = [5, 7, 8, 10, 11, 13, 14, 17, 18, 19,
                        26, 27, 28, 45, 52]
    for idx in high_var_indices:
        engineered[:, col] = np.log1p(np.abs(raw[:, idx]))
        col += 1

    # --- Quadratic interactions for injection-related features (10) ---
    injection_feats = [26, 27, 28, 29]  # ninjections, commitCharge, protection, uniqueInjections
    qi = 0
    for i in range(len(injection_feats)):
        for j in range(i + 1, len(injection_feats)):
            if col < TARGET_DIM:
                engineered[:, col] = (raw[:, injection_feats[i]] *
                                      raw[:, injection_feats[j]]) / 1e6
                col += 1
                qi += 1
    # psxview quadratic
    psxview_feats = [30, 31, 32, 33, 34, 35, 36]
    for i in range(0, min(4, len(psxview_feats))):
        if col < TARGET_DIM:
            engineered[:, col] = (raw[:, psxview_feats[i]] *
                                  raw[:, psxview_feats[(i + 1) % len(psxview_feats)]]) / 1e3
            col += 1

    # --- Fill remaining with statistical aggregates ---
    while col < TARGET_DIM:
        feat_idx = col % 55
        engineered[:, col] = np.square(raw[:, feat_idx]) / (1e6 + np.abs(raw[:, feat_idx]))
        col += 1

    return engineered


def _load_cic_malmem_2022(data_dir: Path) -> tuple[NDArray, NDArray]:
    """Load CIC-MalMem-2022 dataset."""
    csv_path = data_dir / "cic_malmem_2022" / "cic_malmem_2022.csv"
    if not csv_path.exists():
        raise FileNotFoundError(
            f"CIC-MalMem-2022 not found at {csv_path}. "
            "Download from https://huggingface.co/datasets/bvk/CIC-MalMem-2022"
        )

    logger.info("Loading CIC-MalMem-2022 from %s", csv_path)
    df = pd.read_csv(csv_path)

    # Map categories to our 5-class scheme
    labels = df["Category"].map(_CIC_CATEGORY_MAP)
    valid_mask = labels.notna()
    df = df[valid_mask].copy()
    labels = labels[valid_mask].astype(np.int64).values

    # Extract numerical features
    feature_cols = [c for c in _VOLATILITY_FEATURES if c in df.columns]
    X = df[feature_cols].fillna(0).values.astype(np.float32)

    logger.info(
        "CIC-MalMem-2022: %d samples, %d features, class dist: %s",
        X.shape[0], X.shape[1],
        dict(zip(*np.unique(labels, return_counts=True)))
    )
    return X, labels


def _load_memmal_d2024(data_dir: Path) -> tuple[NDArray, NDArray]:
    """Load MemMal-D2024 dataset (benign + malware CSVs)."""
    benign_path = data_dir / "memmal_d2024" / "benign.csv"
    malware_path = data_dir / "memmal_d2024" / "malware.csv"

    if not benign_path.exists() or not malware_path.exists():
        raise FileNotFoundError(
            f"MemMal-D2024 not found at {data_dir / 'memmal_d2024'}. "
            "Download from https://github.com/mpasco/MemMal-D2024"
        )

    logger.info("Loading MemMal-D2024 from %s", data_dir / "memmal_d2024")
    benign_df = pd.read_csv(benign_path)
    malware_df = pd.read_csv(malware_path)

    # MemMal-D2024 has binary labels only (Benign / not-Benign)
    # Assign: Benign→0, all Malware→4 (MalwareGeneric)
    feature_cols = [c for c in _VOLATILITY_FEATURES if c in benign_df.columns]

    X_b = benign_df[feature_cols].fillna(0).values.astype(np.float32)
    y_b = np.zeros(X_b.shape[0], dtype=np.int64)

    X_m = malware_df[feature_cols].fillna(0).values.astype(np.float32)
    y_m = np.full(X_m.shape[0], 4, dtype=np.int64)  # MalwareGeneric

    X = np.concatenate([X_b, X_m], axis=0)
    y = np.concatenate([y_b, y_m], axis=0)

    logger.info(
        "MemMal-D2024: %d samples, %d features (benign=%d, malware=%d)",
        X.shape[0], X.shape[1], X_b.shape[0], X_m.shape[0],
    )
    return X, y


def load_memory_external_dataset(
    data_dir: str | Path,
    *,
    datasets: tuple[str, ...] = ("cic_malmem_2022", "memmal_d2024"),
    max_samples_per_class: int = 30_000,
    seed: int = 42,
    cache: bool = True,
) -> tuple[NDArray[np.float32], NDArray[np.int64], dict]:
    """Load and combine real-world memory forensics datasets.

    Parameters
    ----------
    data_dir : path
        Root of raw data directory (contains cic_malmem_2022/ and memmal_d2024/).
    datasets : tuple of str
        Which datasets to load.
    max_samples_per_class : int
        Cap per class to prevent imbalance.
    seed : int
        Random seed for reproducible class balancing.
    cache : bool
        If True, cache the processed NPZ for faster reloads.

    Returns
    -------
    X : ndarray of shape (N, 128), float32
        Engineered feature vectors.
    y : ndarray of shape (N,), int64
        Class labels (0-4).
    metadata : dict
        Dataset statistics and provenance.
    """
    raw_dir = Path(data_dir)
    cache_path = raw_dir / "memory_external_combined.npz"

    if cache and cache_path.exists():
        logger.info("Loading cached memory dataset from %s", cache_path)
        data = np.load(cache_path)
        X, y = data["X"], data["y"]
        metadata = {
            "source": "cache",
            "cache_path": str(cache_path),
            "samples": int(X.shape[0]),
            "feature_dim": int(X.shape[1]),
        }
        logger.info("Loaded %d cached samples (128-dim)", X.shape[0])
        return X, y, metadata

    all_X: list[NDArray] = []
    all_y: list[NDArray] = []
    sources: list[str] = []

    if "cic_malmem_2022" in datasets:
        try:
            X_cic, y_cic = _load_cic_malmem_2022(raw_dir)
            all_X.append(X_cic)
            all_y.append(y_cic)
            sources.append(f"CIC-MalMem-2022({X_cic.shape[0]})")
        except FileNotFoundError as e:
            logger.warning("Skipping CIC-MalMem-2022: %s", e)

    if "memmal_d2024" in datasets:
        try:
            X_mm, y_mm = _load_memmal_d2024(raw_dir)
            all_X.append(X_mm)
            all_y.append(y_mm)
            sources.append(f"MemMal-D2024({X_mm.shape[0]})")
        except FileNotFoundError as e:
            logger.warning("Skipping MemMal-D2024: %s", e)

    if not all_X:
        raise RuntimeError("No external memory datasets found in " + str(raw_dir))

    # Combine
    X_raw = np.concatenate(all_X, axis=0)
    y_all = np.concatenate(all_y, axis=0)

    # Pad to 55 features if needed (datasets may have slightly different columns)
    n_raw_feats = X_raw.shape[1]
    if n_raw_feats < 55:
        pad = np.zeros((X_raw.shape[0], 55 - n_raw_feats), dtype=np.float32)
        X_raw = np.concatenate([X_raw, pad], axis=1)

    logger.info(
        "Combined raw: %d samples, %d features from %s",
        X_raw.shape[0], X_raw.shape[1], " + ".join(sources),
    )

    # Per-feature standardization (z-score) before engineering
    means = X_raw.mean(axis=0)
    stds = X_raw.std(axis=0)
    stds[stds < 1e-8] = 1.0
    X_norm = (X_raw - means) / stds

    # Engineer to 128 dimensions
    X_128 = _engineer_features(X_norm)

    # Class balancing: cap each class
    rng = np.random.default_rng(seed)
    balanced_indices: list[NDArray] = []
    class_counts: dict[int, int] = {}

    for cls in range(NUM_CLASSES):
        cls_idx = np.where(y_all == cls)[0]
        if len(cls_idx) == 0:
            logger.warning("Class %d has 0 samples — will be absent from training", cls)
            continue

        if len(cls_idx) > max_samples_per_class:
            cls_idx = rng.choice(cls_idx, size=max_samples_per_class, replace=False)

        balanced_indices.append(cls_idx)
        class_counts[cls] = len(cls_idx)

    if not balanced_indices:
        raise RuntimeError("No samples after balancing")

    indices = np.concatenate(balanced_indices)
    rng.shuffle(indices)

    X = X_128[indices]
    y = y_all[indices]

    # Cache
    if cache:
        np.savez_compressed(cache_path, X=X, y=y)
        logger.info("Cached %d processed samples to %s", X.shape[0], cache_path)

    metadata = {
        "source": " + ".join(sources),
        "total_raw": int(X_raw.shape[0]),
        "total_balanced": int(X.shape[0]),
        "feature_dim": int(X.shape[1]),
        "class_distribution": class_counts,
        "max_samples_per_class": max_samples_per_class,
    }

    logger.info(
        "Memory external dataset ready: %d samples x %d features, classes: %s",
        X.shape[0], X.shape[1], class_counts,
    )
    return X, y, metadata
