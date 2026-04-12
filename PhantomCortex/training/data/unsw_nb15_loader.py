"""
UNSW-NB15 Network Intrusion Detection Dataset Loader
=====================================================

Loads and preprocesses the UNSW-NB15 network intrusion detection dataset
for training the Cortex-Network autoencoder + classifier model.

Supports two source formats:
    - Parquet shards (~2.2M records, 49 columns) — preferred, more data
    - CSV training set (~175K records, 45 columns) — fallback

The raw columns are mapped to 64 engineered features matching the
Cortex-Network input specification:
    - 38 standardized numerical features
    -  5 protocol one-hot features (tcp, udp, icmp, arp, other)
    -  8 service one-hot features (http, ftp, dns, smtp, ssh, ssl, dhcp, other)
    -  6 state one-hot features (top 5 + other)
    -  7 derived ratio features

UNSW-NB15 Attack Categories → NetworkThreatClass mapping:
    Normal / empty    → Normal (0)
    Backdoors         → C2Beacon (1)
    Shellcode         → C2Beacon (1)
    Worms             → Exfiltration (2)
    Exploits          → LateralMovement (3)
    Fuzzers           → Scanning (4)
    Analysis          → Scanning (4)
    Reconnaissance    → Scanning (4)
    DoS               → Normal (0)   — autoencoder anomaly detection handles this
    Generic           → Normal (0)   — too vague for direct classification

License: UNSW-NB15 is publicly available for research purposes.
"""

from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from numpy.typing import NDArray

logger = logging.getLogger("PhantomCortex.Data.UNSW_NB15")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TARGET_DIM: int = 64
NUM_CLASSES: int = 8

_CACHE_VERSION: int = 2

_CLASS_NAMES: list[str] = [
    "Normal",
    "C2Beacon",
    "Exfiltration",
    "LateralMovement",
    "Scanning",
    "DGADomain",
    "DNSTunnel",
    "CryptoMining",
]

# Case-insensitive attack_cat → our 8-class taxonomy.
# Keys are lowercase; lookup must lowercase the raw value first.
_ATTACK_CAT_MAP: dict[str, int] = {
    "normal":         0,
    "":               0,
    "backdoor":       1,
    "backdoors":      1,
    "shellcode":      1,
    "worms":          2,
    "exploits":       3,
    "fuzzers":        4,
    "analysis":       4,
    "reconnaissance": 4,
    "dos":            0,  # no DoS class; autoencoder handles anomaly
    "generic":        0,  # too vague
}

# --- Column name canonicalization ---
# The parquet files use mixed-case column names that differ from the CSV.
# We normalize everything to lowercase canonical names for uniform processing.

_CANONICAL_COL_MAP: dict[str, str] = {
    # Parquet mixed-case → canonical lowercase
    "srcip":           "srcip",
    "sport":           "sport",
    "dstip":           "dstip",
    "dsport":          "dsport",
    "sload":           "sload",
    "dload":           "dload",
    "spkts":           "spkts",
    "dpkts":           "dpkts",
    "sjit":            "sjit",
    "djit":            "djit",
    "sintpkt":         "sintpkt",
    "dintpkt":         "dintpkt",
    "smeansz":         "smeansz",
    "dmeansz":         "dmeansz",
    "stime":           "stime",
    "ltime":           "ltime",
    "res_bdy_len":     "res_bdy_len",
    # CSV uses different names for some columns
    "sinpkt":          "sintpkt",
    "dinpkt":          "dintpkt",
    "smean":           "smeansz",
    "dmean":           "dmeansz",
    "response_body_len": "res_bdy_len",
    "attack_cat":      "attack_cat",
    "label":           "label",
}

# 38 numerical features to extract (canonical lowercase names)
_NUMERICAL_FEATURES: list[str] = [
    "dur", "sbytes", "dbytes", "sttl", "dttl", "sloss", "dloss",
    "sload", "dload", "spkts", "dpkts", "swin", "dwin",
    "stcpb", "dtcpb", "smeansz", "dmeansz", "trans_depth",
    "res_bdy_len", "sjit", "djit", "sintpkt", "dintpkt",
    "tcprtt", "synack", "ackdat", "is_sm_ips_ports",
    "ct_state_ttl", "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd",
    "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm",
    "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
]

_TOP_PROTOCOLS: list[str] = ["tcp", "udp", "icmp", "arp"]       # + other = 5
_TOP_SERVICES: list[str] = ["http", "ftp", "dns", "smtp", "ssh", "ssl", "dhcp"]  # + other = 8
_TOP_STATES: list[str] = ["fin", "con", "int", "req", "rst"]    # + other = 6

# Outlier clipping percentile
_CLIP_PERCENTILE: float = 99.9

# Epsilon for numerical stability in division and standardization
_EPS: float = 1e-8

# Default data directory relative to this file
_DEFAULT_DATA_DIR: Path = Path(__file__).resolve().parent / "raw" / "unsw_nb15"


# ---------------------------------------------------------------------------
# Column canonicalization
# ---------------------------------------------------------------------------


def _canonicalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize all column names to lowercase canonical form.

    Handles the mixed-case discrepancies between CSV and parquet formats
    (e.g. ``Sload`` → ``sload``, ``smean`` → ``smeansz``).
    """
    # First: lowercase everything
    rename_map: dict[str, str] = {}
    for col in df.columns:
        lower = col.strip().lower()
        canonical = _CANONICAL_COL_MAP.get(lower, lower)
        rename_map[col] = canonical

    return df.rename(columns=rename_map)


# ---------------------------------------------------------------------------
# Data loading (parquet and CSV)
# ---------------------------------------------------------------------------


def _load_parquet_shards(data_dir: Path) -> pd.DataFrame:
    """Load all parquet shards from the data/ subdirectory.

    Returns a single concatenated DataFrame with canonicalized columns.

    Raises:
        FileNotFoundError: If no parquet files are found.
    """
    parquet_dir = data_dir / "data"
    if not parquet_dir.is_dir():
        raise FileNotFoundError(
            f"Parquet data directory not found: {parquet_dir}. "
            "Expected parquet shards in data/ subdirectory."
        )

    shards = sorted(parquet_dir.glob("*.parquet"))
    if not shards:
        raise FileNotFoundError(
            f"No parquet files found in {parquet_dir}."
        )

    frames: list[pd.DataFrame] = []
    for shard_path in shards:
        logger.info("Loading parquet shard: %s", shard_path.name)
        shard_df = pd.read_parquet(shard_path)
        frames.append(shard_df)

    df = pd.concat(frames, axis=0, ignore_index=True)
    df = _canonicalize_columns(df)

    logger.info(
        "Loaded %d records from %d parquet shards (%d columns)",
        len(df), len(shards), len(df.columns),
    )
    return df


def _load_csv(data_dir: Path) -> pd.DataFrame:
    """Load UNSW_NB15_training-set.csv.

    Returns a DataFrame with canonicalized columns.

    Raises:
        FileNotFoundError: If the CSV file is not found.
    """
    csv_path = data_dir / "UNSW_NB15_training-set.csv"
    if not csv_path.exists():
        raise FileNotFoundError(
            f"CSV training set not found: {csv_path}."
        )

    logger.info("Loading CSV: %s", csv_path.name)
    df = pd.read_csv(csv_path, low_memory=False)
    df = _canonicalize_columns(df)

    logger.info(
        "Loaded %d records from CSV (%d columns)", len(df), len(df.columns),
    )
    return df


# ---------------------------------------------------------------------------
# Label mapping
# ---------------------------------------------------------------------------


def _map_labels(df: pd.DataFrame) -> NDArray[np.int64]:
    """Map attack_cat column to our 8-class labels.

    Performs case-insensitive matching with whitespace stripping.
    Rows with unmapped categories are assigned to Normal (0) with a warning.

    Returns:
        Integer label array of shape (N,).
    """
    if "attack_cat" not in df.columns:
        logger.warning(
            "No 'attack_cat' column found — falling back to 'label' column"
        )
        if "label" in df.columns:
            return df["label"].fillna(0).astype(np.int64).values
        raise ValueError("Neither 'attack_cat' nor 'label' column found in data")

    raw_cats = df["attack_cat"].fillna("").astype(str).str.strip().str.lower()
    labels = np.zeros(len(df), dtype=np.int64)

    unmapped_counts: dict[str, int] = {}

    for i, cat in enumerate(raw_cats):
        mapped = _ATTACK_CAT_MAP.get(cat)
        if mapped is not None:
            labels[i] = mapped
        else:
            # Unknown category → Normal (0), but track it
            labels[i] = 0
            unmapped_counts[cat] = unmapped_counts.get(cat, 0) + 1

    if unmapped_counts:
        logger.warning(
            "Unmapped attack categories assigned to Normal(0): %s",
            {k: v for k, v in sorted(unmapped_counts.items(), key=lambda x: -x[1])},
        )

    return labels


# ---------------------------------------------------------------------------
# Feature engineering
# ---------------------------------------------------------------------------


def _safe_ratio(a: NDArray[np.float32], b: NDArray[np.float32]) -> NDArray[np.float32]:
    """Element-wise a / b with zero-safe denominator."""
    return np.divide(
        a, b,
        out=np.zeros_like(a, dtype=np.float32),
        where=np.abs(b) > _EPS,
    )


def _one_hot_encode(
    series: pd.Series,
    categories: list[str],
) -> NDArray[np.float32]:
    """One-hot encode a categorical series against known categories + 'other'.

    Args:
        series: Pandas Series with string values (already lowercased).
        categories: Ordered list of known categories (excluding 'other').

    Returns:
        Array of shape (N, len(categories) + 1) with float32 one-hot encoding.
    """
    n = len(series)
    n_cats = len(categories) + 1  # +1 for 'other'
    result = np.zeros((n, n_cats), dtype=np.float32)

    cat_to_idx = {cat: i for i, cat in enumerate(categories)}
    other_idx = len(categories)

    values = series.fillna("").astype(str).str.strip().str.lower()
    for i, val in enumerate(values):
        idx = cat_to_idx.get(val, other_idx)
        result[i, idx] = 1.0

    return result


def _extract_numerical(df: pd.DataFrame) -> NDArray[np.float32]:
    """Extract the 38 numerical features, filling NaN with 0.

    Returns:
        Array of shape (N, 38) with float32 values.
    """
    n = len(df)
    result = np.zeros((n, len(_NUMERICAL_FEATURES)), dtype=np.float32)

    for i, col_name in enumerate(_NUMERICAL_FEATURES):
        if col_name in df.columns:
            col_data = pd.to_numeric(df[col_name], errors="coerce")
            result[:, i] = col_data.fillna(0.0).values.astype(np.float32)
        else:
            logger.warning(
                "Numerical feature '%s' not found in data — filled with zeros", col_name
            )

    return result


def _compute_ratios(numerical: NDArray[np.float32]) -> NDArray[np.float32]:
    """Compute 7 derived ratio features from the numerical features.

    Ratios:
        0. sbytes / dbytes
        1. spkts / dpkts
        2. sload / dload
        3. sjit / djit
        4. sloss / dloss
        5. smeansz / dmeansz
        6. rate = (spkts + dpkts) / (dur + eps)

    Returns:
        Array of shape (N, 7) with float32 values.
    """
    n = numerical.shape[0]
    ratios = np.zeros((n, 7), dtype=np.float32)

    # Column index lookup within _NUMERICAL_FEATURES
    idx = {name: i for i, name in enumerate(_NUMERICAL_FEATURES)}

    # sbytes / dbytes
    ratios[:, 0] = _safe_ratio(numerical[:, idx["sbytes"]], numerical[:, idx["dbytes"]])
    # spkts / dpkts
    ratios[:, 1] = _safe_ratio(numerical[:, idx["spkts"]], numerical[:, idx["dpkts"]])
    # sload / dload
    ratios[:, 2] = _safe_ratio(numerical[:, idx["sload"]], numerical[:, idx["dload"]])
    # sjit / djit
    ratios[:, 3] = _safe_ratio(numerical[:, idx["sjit"]], numerical[:, idx["djit"]])
    # sloss / dloss
    ratios[:, 4] = _safe_ratio(numerical[:, idx["sloss"]], numerical[:, idx["dloss"]])
    # smeansz / dmeansz
    ratios[:, 5] = _safe_ratio(numerical[:, idx["smeansz"]], numerical[:, idx["dmeansz"]])
    # rate = (spkts + dpkts) / (dur + eps)
    total_pkts = numerical[:, idx["spkts"]] + numerical[:, idx["dpkts"]]
    dur = numerical[:, idx["dur"]]
    ratios[:, 6] = _safe_ratio(total_pkts, dur + np.float32(_EPS))

    return ratios


def _engineer_features(df: pd.DataFrame) -> NDArray[np.float32]:
    """Engineer 64 features from the raw DataFrame.

    Layout (64 total):
        [0:38]   — 38 numerical features (z-score standardized later)
        [38:43]  —  5 protocol one-hot (tcp, udp, icmp, arp, other)
        [43:51]  —  8 service one-hot (http, ftp, dns, smtp, ssh, ssl, dhcp, other)
        [51:57]  —  6 state one-hot (fin, con, int, req, rst, other)
        [57:64]  —  7 derived ratios

    Returns:
        Array of shape (N, 64) with float32 values (not yet standardized).
    """
    n = len(df)
    X = np.zeros((n, TARGET_DIM), dtype=np.float32)

    # 1. Numerical features (38)
    numerical = _extract_numerical(df)
    X[:, 0:38] = numerical

    # 2. Protocol one-hot (5)
    proto_col = "proto" if "proto" in df.columns else None
    if proto_col is not None:
        X[:, 38:43] = _one_hot_encode(df[proto_col], _TOP_PROTOCOLS)
    else:
        logger.warning("Protocol column not found — encoding zeros")

    # 3. Service one-hot (8)
    service_col = "service" if "service" in df.columns else None
    if service_col is not None:
        X[:, 43:51] = _one_hot_encode(df[service_col], _TOP_SERVICES)
    else:
        logger.warning("Service column not found — encoding zeros")

    # 4. State one-hot (6)
    state_col = "state" if "state" in df.columns else None
    if state_col is not None:
        X[:, 51:57] = _one_hot_encode(df[state_col], _TOP_STATES)
    else:
        logger.warning("State column not found — encoding zeros")

    # 5. Derived ratios (7)
    X[:, 57:64] = _compute_ratios(numerical)

    return X


# ---------------------------------------------------------------------------
# Standardization
# ---------------------------------------------------------------------------


def _clip_outliers(
    X: NDArray[np.float32],
    percentile: float = _CLIP_PERCENTILE,
) -> NDArray[np.float32]:
    """Clip each feature to its [1-p, p] percentile range.

    Reduces the effect of extreme outliers on z-score standardization
    without completely removing them.
    """
    lo = 100.0 - percentile
    for col in range(X.shape[1]):
        col_data = X[:, col]
        p_lo, p_hi = np.percentile(col_data, [lo, percentile])
        X[:, col] = np.clip(col_data, p_lo, p_hi)
    return X


def _standardize(
    X: NDArray[np.float32],
) -> tuple[NDArray[np.float32], NDArray[np.float64], NDArray[np.float64]]:
    """Z-score standardize all features.

    Computes mean and std from the entire dataset (since we return a single
    X array and the caller will split later via dataset_utils.split_data).

    One-hot features (columns 38-56) will have near-zero mean/unit std after
    standardization — this is intentional and does not harm the model.

    Returns:
        (X_standardized, means, stds)
    """
    means = X.mean(axis=0).astype(np.float64)
    stds = X.std(axis=0).astype(np.float64)
    stds[stds < _EPS] = 1.0  # Prevent division by zero for constant features

    X_normed = ((X.astype(np.float64) - means) / stds).astype(np.float32)

    return X_normed, means, stds


# ---------------------------------------------------------------------------
# Stratified subsampling
# ---------------------------------------------------------------------------


def _stratified_subsample(
    X: NDArray[np.float32],
    y: NDArray[np.int64],
    max_samples: int,
    rng: np.random.Generator,
) -> tuple[NDArray[np.float32], NDArray[np.int64]]:
    """Stratified subsample to at most max_samples total.

    Maintains class proportions from the original dataset.  If a class
    has fewer samples than its proportional share, all samples are kept
    and the excess budget is distributed to other classes.
    """
    n = X.shape[0]
    if n <= max_samples:
        return X, y

    unique_classes, class_counts = np.unique(y, return_counts=True)
    class_fracs = class_counts / n

    # Initial allocation proportional to class frequency
    target_per_class = np.round(class_fracs * max_samples).astype(np.int64)

    # Cap at actual class counts and redistribute surplus
    surplus = 0
    for i, (cls, count) in enumerate(zip(unique_classes, class_counts)):
        if target_per_class[i] > count:
            surplus += target_per_class[i] - count
            target_per_class[i] = count

    # Distribute surplus to classes that can absorb it
    if surplus > 0:
        for i in range(len(unique_classes)):
            can_absorb = class_counts[i] - target_per_class[i]
            give = min(surplus, can_absorb)
            target_per_class[i] += give
            surplus -= give
            if surplus <= 0:
                break

    selected_indices: list[NDArray[np.intp]] = []
    for i, cls in enumerate(unique_classes):
        cls_idx = np.where(y == cls)[0]
        n_select = int(target_per_class[i])
        if n_select >= len(cls_idx):
            selected_indices.append(cls_idx)
        else:
            chosen = rng.choice(cls_idx, size=n_select, replace=False)
            selected_indices.append(chosen)

    indices = np.concatenate(selected_indices)
    rng.shuffle(indices)

    logger.info(
        "Subsampled %d → %d samples (%.1f%% reduction)",
        n, len(indices), 100.0 * (1.0 - len(indices) / n),
    )

    return X[indices], y[indices]


# ---------------------------------------------------------------------------
# Cache management
# ---------------------------------------------------------------------------


def _cache_fingerprint(data_dir: Path, use_parquet: bool, max_samples: int) -> str:
    """Compute a deterministic cache key from configuration parameters.

    Changes to the data directory, source format, or sample limit invalidate
    the cache automatically.
    """
    key = f"v{_CACHE_VERSION}|{data_dir.resolve()}|pq={use_parquet}|max={max_samples}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _cache_path(data_dir: Path, use_parquet: bool, max_samples: int) -> Path:
    """Build the NPZ cache file path."""
    cache_dir = data_dir / ".cache"
    fingerprint = _cache_fingerprint(data_dir, use_parquet, max_samples)
    return cache_dir / f"unsw_nb15_{fingerprint}.npz"


def _load_cache(
    path: Path,
) -> tuple[NDArray[np.float32], NDArray[np.int64], dict[str, Any]] | None:
    """Attempt to load processed data from NPZ cache.

    Returns None if cache is missing, corrupt, or incompatible.
    """
    if not path.exists():
        return None

    try:
        data = np.load(str(path), allow_pickle=False)
    except Exception as exc:
        logger.warning("NPZ cache corrupt or incompatible — ignoring: %s", exc)
        return None

    required = {"X", "y", "means", "stds"}
    if not required.issubset(set(data.files)):
        logger.warning(
            "NPZ cache missing keys (need %s, have %s) — rebuilding",
            required, set(data.files),
        )
        return None

    X = data["X"]
    y = data["y"]

    # Validate shapes
    if X.ndim != 2 or X.shape[1] != TARGET_DIM:
        logger.warning(
            "Cached X has wrong shape %s (expected (N, %d)) — rebuilding",
            X.shape, TARGET_DIM,
        )
        return None

    if y.ndim != 1 or y.shape[0] != X.shape[0]:
        logger.warning("Cached y shape mismatch — rebuilding")
        return None

    unique_cls, cls_counts = np.unique(y, return_counts=True)
    class_dist = {int(c): int(n) for c, n in zip(unique_cls, cls_counts)}

    metadata = {
        "source": "cache",
        "cache_path": str(path),
        "samples": int(X.shape[0]),
        "feature_dim": int(X.shape[1]),
        "num_classes": NUM_CLASSES,
        "class_names": _CLASS_NAMES,
        "class_distribution": class_dist,
        "scaler_mean": data["means"].tolist(),
        "scaler_std": data["stds"].tolist(),
    }

    logger.info(
        "Loaded %d samples from NPZ cache: %s", X.shape[0], path.name,
    )
    return X.astype(np.float32), y.astype(np.int64), metadata


def _save_cache(
    path: Path,
    X: NDArray[np.float32],
    y: NDArray[np.int64],
    means: NDArray[np.float64],
    stds: NDArray[np.float64],
) -> None:
    """Persist processed data to NPZ cache."""
    path.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(str(path), X=X, y=y, means=means, stds=stds)
    size_mb = path.stat().st_size / (1024 * 1024)
    logger.info("Cached processed dataset to %s (%.2f MB)", path.name, size_mb)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_unsw_nb15(
    data_dir: str | Path | None = None,
    seed: int = 42,
    max_samples: int = 500_000,
    input_dim: int = 64,
    use_parquet: bool = True,
) -> tuple[NDArray[np.float32], NDArray[np.int64], dict[str, Any]]:
    """Load the UNSW-NB15 dataset, preprocessed for Cortex-Network training.

    Loading precedence:
        1. NPZ cache (near-instant reload)
        2. Parquet shards (2.2M+ records, preferred)
        3. CSV training set (~175K records, fallback)

    The 49 raw columns are mapped to 64 engineered features:
        - 38 z-score standardized numerical features
        -  5 protocol one-hot features
        -  8 service one-hot features
        -  6 state one-hot features
        -  7 derived ratio features

    Parameters
    ----------
    data_dir : str, Path, or None
        Root directory containing the UNSW-NB15 data files.
        Defaults to ``PhantomCortex/training/data/raw/unsw_nb15/``.
    seed : int
        Random seed for reproducible subsampling and shuffling.
    max_samples : int
        Maximum total samples to return.  Stratified subsampling
        preserves class proportions when the dataset exceeds this limit.
    input_dim : int
        Expected feature dimension.  Must be 64 for Cortex-Network.
        Included for interface consistency — raises ValueError otherwise.
    use_parquet : bool
        If True, prefer parquet shards over CSV.  Falls back to CSV
        if parquet files are not available.

    Returns
    -------
    X : ndarray of shape (N, 64), float32
        Z-score standardized feature vectors.
    y : ndarray of shape (N,), int64
        Class labels ∈ {0, 1, 2, 3, 4, 5, 6, 7}.
    metadata : dict
        Dataset provenance and statistics including:
        - ``scaler_mean``: per-feature means for inference-time normalization
        - ``scaler_std``: per-feature stds for inference-time normalization
        - ``class_distribution``: sample counts per class
        - ``source``: data format used (parquet/csv/cache)

    Raises
    ------
    ValueError
        If ``input_dim != 64``.
    FileNotFoundError
        If neither parquet nor CSV data files are found.
    RuntimeError
        If the loaded data contains no valid samples after label mapping.
    """
    t_start = time.monotonic()

    if input_dim != TARGET_DIM:
        raise ValueError(
            f"UNSW-NB15 loader produces {TARGET_DIM}-dim features, "
            f"but input_dim={input_dim} was requested"
        )

    raw_dir = Path(data_dir) if data_dir is not None else _DEFAULT_DATA_DIR
    if not raw_dir.is_dir():
        raise FileNotFoundError(
            f"UNSW-NB15 data directory not found: {raw_dir}"
        )

    rng = np.random.default_rng(seed)

    # --- Step 0: Try cache ---
    cache_file = _cache_path(raw_dir, use_parquet, max_samples)
    cached = _load_cache(cache_file)
    if cached is not None:
        X_c, y_c, meta_c = cached
        meta_c["load_time_sec"] = round(time.monotonic() - t_start, 3)
        _log_class_distribution(y_c)
        return X_c, y_c, meta_c

    # --- Step 1: Load raw data ---
    source_format = "unknown"
    df: pd.DataFrame | None = None

    if use_parquet:
        try:
            df = _load_parquet_shards(raw_dir)
            source_format = "parquet"
        except FileNotFoundError:
            logger.info("Parquet shards not found — falling back to CSV")

    if df is None:
        try:
            df = _load_csv(raw_dir)
            source_format = "csv"
        except FileNotFoundError:
            pass

    if df is None:
        raise FileNotFoundError(
            f"No UNSW-NB15 data files found in {raw_dir}. "
            "Expected parquet shards in data/ or UNSW_NB15_training-set.csv"
        )

    logger.info(
        "Raw data loaded: %d records, %d columns (source: %s)",
        len(df), len(df.columns), source_format,
    )

    # --- Step 2: Map labels ---
    y = _map_labels(df)

    # Validate we have actual data
    if len(y) == 0:
        raise RuntimeError("No valid samples after label mapping")

    # --- Step 3: Engineer features ---
    logger.info("Engineering %d features from raw columns...", TARGET_DIM)
    X_raw = _engineer_features(df)

    # Free the DataFrame to reduce memory pressure
    del df

    # --- Step 4: Clip outliers ---
    X_clipped = _clip_outliers(X_raw)

    # --- Step 5: Stratified subsample ---
    X_sub, y_sub = _stratified_subsample(X_clipped, y, max_samples, rng)

    # --- Step 6: Standardize ---
    X_final, means, stds = _standardize(X_sub)

    # Replace any residual NaN/inf from degenerate distributions
    nan_count = int(np.isnan(X_final).sum())
    inf_count = int(np.isinf(X_final).sum())
    if nan_count > 0 or inf_count > 0:
        logger.warning(
            "Replacing %d NaN and %d Inf values in final features",
            nan_count, inf_count,
        )
        X_final = np.nan_to_num(X_final, nan=0.0, posinf=0.0, neginf=0.0)

    # --- Step 7: Shuffle ---
    shuffle_idx = rng.permutation(X_final.shape[0])
    X_final = X_final[shuffle_idx]
    y_sub = y_sub[shuffle_idx]

    # --- Step 8: Cache ---
    _save_cache(cache_file, X_final, y_sub, means, stds)

    # --- Build metadata ---
    t_elapsed = time.monotonic() - t_start

    unique_classes, class_counts = np.unique(y_sub, return_counts=True)
    class_dist = {int(cls): int(cnt) for cls, cnt in zip(unique_classes, class_counts)}

    metadata: dict[str, Any] = {
        "source": source_format,
        "source_dir": str(raw_dir),
        "total_raw_records": int(len(y)),
        "samples": int(X_final.shape[0]),
        "feature_dim": int(X_final.shape[1]),
        "num_classes": NUM_CLASSES,
        "class_names": _CLASS_NAMES,
        "class_distribution": class_dist,
        "scaler_mean": means.tolist(),
        "scaler_std": stds.tolist(),
        "seed": seed,
        "max_samples": max_samples,
        "cache_path": str(cache_file),
        "cache_version": _CACHE_VERSION,
        "load_time_sec": round(t_elapsed, 3),
    }

    _log_class_distribution(y_sub)

    logger.info(
        "UNSW-NB15 ready: %d samples × %d features in %.2fs (source: %s)",
        X_final.shape[0], X_final.shape[1], t_elapsed, source_format,
    )

    return X_final, y_sub, metadata


# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------


def _log_class_distribution(y: NDArray[np.int64]) -> None:
    """Log per-class sample counts and percentages."""
    unique, counts = np.unique(y, return_counts=True)
    total = int(y.shape[0])

    lines = [
        f"  {'Class':<20s} {'Name':<18s} {'Count':>8s} {'Pct':>7s}",
        "  " + "-" * 55,
    ]
    for cls_id, count in zip(unique, counts):
        idx = int(cls_id)
        name = _CLASS_NAMES[idx] if idx < len(_CLASS_NAMES) else f"Unknown({idx})"
        pct = 100.0 * count / total
        lines.append(f"  {idx:<20d} {name:<18s} {count:>8d} {pct:>6.2f}%")
    lines.append("  " + "-" * 55)
    lines.append(f"  {'Total':<20s} {'':<18s} {total:>8d} {'100.00%':>7s}")

    logger.info("UNSW-NB15 class distribution:\n%s", "\n".join(lines))


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(
        description="UNSW-NB15 dataset loader for PhantomCortex Cortex-Network",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--data-dir", type=str, default=None,
        help="Path to UNSW-NB15 data directory (default: auto-detect)",
    )
    parser.add_argument(
        "--max-samples", type=int, default=500_000,
        help="Maximum total samples (default: 500000)",
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="Random seed (default: 42)",
    )
    parser.add_argument(
        "--no-parquet", action="store_true",
        help="Force CSV loading instead of parquet",
    )
    parser.add_argument(
        "--no-cache", action="store_true",
        help="Skip cache and reprocess from raw data",
    )
    parser.add_argument(
        "--stats-only", action="store_true",
        help="Print dataset statistics and exit",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    data_path = args.data_dir
    if args.no_cache and data_path is not None:
        cache_dir = Path(data_path) / ".cache"
        if cache_dir.is_dir():
            for f in cache_dir.glob("unsw_nb15_*.npz"):
                f.unlink()
                logger.info("Deleted cache: %s", f.name)

    X, y, meta = load_unsw_nb15(
        data_dir=data_path,
        seed=args.seed,
        max_samples=args.max_samples,
        use_parquet=not args.no_parquet,
    )

    print(f"\nDataset shape: X={X.shape}, y={y.shape}")
    print(f"Feature dtype: {X.dtype}, Label dtype: {y.dtype}")
    print(f"Label range: [{y.min()}, {y.max()}]")
    print(f"Load time: {meta.get('load_time_sec', 'N/A')}s")
    print(f"Source: {meta.get('source', 'N/A')}")

    if args.stats_only:
        print("\nMetadata:")
        safe_meta = {k: v for k, v in meta.items()
                     if not isinstance(v, (list,)) or len(v) < 20}
        print(json.dumps(safe_meta, indent=2, default=str))
        sys.exit(0)
