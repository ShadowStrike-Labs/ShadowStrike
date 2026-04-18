"""
Quo Vadis Speakeasy Dataset Loader for PhantomCortex
=====================================================

Loads and featurizes the Quo Vadis Windows emulation dataset (Speakeasy)
for training TWO Cortex models:

  * **Cortex-Behavioral** (CNN + Attention)
      - 20-class malware family classification
      - Input shape: ``(N, 512, 4)``
      - Features: ``[api_name_id, arg_summary_hash, return_value_code, timing_delta]``

  * **Cortex-Emulation** (BiGRU)
      - 3-class verdict (Benign / Suspicious / Malicious)
      - Input shape: ``(N, 1024, 4)``
      - Features: ``[opcode_cat, mem_access, api_id, raw_feature]``

The raw data consists of ~75K JSON files organized by malware family under
``windows_emulation_trainset/`` and ``windows_emulation_testset/`` directories.
Each JSON is a list of Speakeasy emulation report entries containing API call
traces. This loader flattens all API calls across entries into a single
sequence per sample.

Parallel JSON loading via ``ProcessPoolExecutor`` and NPZ caching ensure
the 75K-file corpus loads efficiently on repeated runs.

License: Dataset distributed under original Quo Vadis terms.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import warnings
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from enum import IntEnum
from pathlib import Path
from typing import Any

import numpy as np
from numpy.typing import NDArray

from PhantomCortex.training.models.behavioral_cnn import BehaviorCategory
from PhantomCortex.training.models.emulation_gru import EmulationVerdict

logger = logging.getLogger("PhantomCortex.Data.QuoVadis")

# ═══════════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════════

_DEFAULT_DIR = Path(__file__).resolve().parent / "raw" / "quovadis_speakeasy"
_CACHE_VERSION = 1
_MAX_JSON_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB — skip pathologically large files
_MAX_WORKERS_DEFAULT = max(1, min(os.cpu_count() or 4, 8))

# Speakeasy folder → BehaviorCategory (20-class)
_BEHAVIORAL_FOLDER_MAP: dict[str, BehaviorCategory] = {
    "report_clean": BehaviorCategory.Benign,
    "report_windows_syswow64": BehaviorCategory.Benign,
    "report_backdoor": BehaviorCategory.Backdoor,
    "report_coinminer": BehaviorCategory.Miner,
    "report_dropper": BehaviorCategory.Dropper,
    "report_keylogger": BehaviorCategory.Keylogger,
    "report_ransomware": BehaviorCategory.Ransomware,
    "report_rat": BehaviorCategory.RAT,
    "report_trojan": BehaviorCategory.InfoStealer,
}

# Speakeasy folder → EmulationVerdict (3-class)
_EMULATION_FOLDER_MAP: dict[str, EmulationVerdict] = {
    "report_clean": EmulationVerdict.Benign,
    "report_windows_syswow64": EmulationVerdict.Benign,
    "report_backdoor": EmulationVerdict.Malicious,
    "report_coinminer": EmulationVerdict.Malicious,
    "report_dropper": EmulationVerdict.Malicious,
    "report_keylogger": EmulationVerdict.Malicious,
    "report_ransomware": EmulationVerdict.Malicious,
    "report_rat": EmulationVerdict.Malicious,
    "report_trojan": EmulationVerdict.Malicious,
}

# Known API module prefixes for emulation opcode categorization
_MODULE_PREFIX_CAT: dict[str, int] = {
    "kernel32": 0,
    "ntdll": 1,
    "advapi32": 2,
    "user32": 3,
    "ws2_32": 4,
    "wsock32": 5,
    "wininet": 6,
    "winhttp": 7,
    "ole32": 8,
    "oleaut32": 9,
    "shell32": 10,
    "urlmon": 11,
    "crypt32": 12,
    "gdi32": 13,
    "msvcrt": 14,
    "shlwapi": 15,
    "comctl32": 16,
    "secur32": 17,
    "netapi32": 18,
    "iphlpapi": 19,
    "dnsapi": 20,
    "mpr": 21,
    "version": 22,
    "psapi": 23,
    "dbghelp": 24,
    "cabinet": 25,
    "wtsapi32": 26,
    "bcrypt": 27,
    "ncrypt": 28,
    "setupapi": 29,
    "sspicli": 30,
    "rstrtmgr": 31,
}
_MODULE_PREFIX_UNKNOWN = 255


# ═══════════════════════════════════════════════════════════════════════════
# Utility — deterministic hashing
# ═══════════════════════════════════════════════════════════════════════════


def _stable_hash(value: str, modulus: int) -> int:
    """SHA-256 based deterministic hash into [0, modulus)."""
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).digest()
    return int.from_bytes(digest[:8], "little") % modulus


def _resolve_data_dir(data_dir: str | Path | None) -> Path:
    if data_dir is None:
        return _DEFAULT_DIR
    return Path(data_dir).expanduser().resolve()


def _parse_hex_int(value: str | int | None, default: int = 0) -> int:
    """Parse a hex string like '0x1234' or integer to int, defaulting on failure."""
    if value is None:
        return default
    if isinstance(value, int):
        return value
    try:
        value_str = str(value).strip()
        if value_str.startswith(("0x", "0X")):
            return int(value_str, 16)
        return int(value_str)
    except (ValueError, TypeError, OverflowError):
        return default


# ═══════════════════════════════════════════════════════════════════════════
# JSON parsing — runs in worker processes
# ═══════════════════════════════════════════════════════════════════════════


def _extract_api_calls_from_json(file_path: str) -> list[dict[str, Any]] | None:
    """Parse a Speakeasy JSON report and flatten all API calls.

    Returns a flat list of API call dicts or None on error.
    Each dict has: api_name (str), args (list), ret_val (str/int), index (int).
    """
    p = Path(file_path)
    try:
        file_size = p.stat().st_size
        if file_size == 0:
            return None
        if file_size > _MAX_JSON_SIZE_BYTES:
            return None

        with open(p, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return None

    if not isinstance(data, list):
        data = [data]

    api_calls: list[dict[str, Any]] = []
    global_index = 0

    for entry in data:
        if not isinstance(entry, dict):
            continue

        apis = entry.get("apis")
        if not isinstance(apis, list):
            continue

        for api_record in apis:
            if not isinstance(api_record, dict):
                continue

            api_name = api_record.get("api_name", "")
            if not isinstance(api_name, str) or not api_name:
                continue

            args = api_record.get("args")
            if not isinstance(args, list):
                args = []

            ret_val = api_record.get("ret_val", "0x0")

            api_calls.append({
                "api_name": api_name,
                "args": args,
                "ret_val": ret_val,
                "index": global_index,
            })
            global_index += 1

    return api_calls if api_calls else None


def _worker_load_file(file_path: str) -> tuple[str, list[dict[str, Any]] | None]:
    """Worker function for ProcessPoolExecutor — returns (path, api_calls | None)."""
    return file_path, _extract_api_calls_from_json(file_path)


# ═══════════════════════════════════════════════════════════════════════════
# File discovery
# ═══════════════════════════════════════════════════════════════════════════


def _discover_json_files(
    base_dir: Path,
    folder_map: dict[str, Any],
) -> list[tuple[Path, str]]:
    """Discover JSON files and their parent folder labels.

    Searches both ``windows_emulation_trainset/`` and ``windows_emulation_testset/``
    directories for each folder name in *folder_map*.

    Returns list of (file_path, folder_name) tuples.
    """
    results: list[tuple[Path, str]] = []

    split_dirs = [
        base_dir / "windows_emulation_trainset",
        base_dir / "windows_emulation_testset",
    ]

    for split_dir in split_dirs:
        if not split_dir.is_dir():
            continue
        for folder_name in folder_map:
            folder_path = split_dir / folder_name
            if not folder_path.is_dir():
                continue

            # Search recursively — HuggingFace stores files in numbered
            # shard subdirectories (e.g. report_backdoor/0/*.json).
            json_files = sorted(folder_path.rglob("*.json"))
            for json_file in json_files:
                results.append((json_file, folder_name))

    return results


# ═══════════════════════════════════════════════════════════════════════════
# Parallel loading engine
# ═══════════════════════════════════════════════════════════════════════════


def _load_json_files_parallel(
    file_folder_pairs: list[tuple[Path, str]],
    max_workers: int = _MAX_WORKERS_DEFAULT,
) -> dict[str, list[dict[str, Any]]]:
    """Load and parse JSON files in parallel.

    Returns a dict mapping ``str(file_path)`` to the extracted API call list.
    Files that fail to parse are silently excluded.
    """
    path_to_folder: dict[str, str] = {}
    file_paths: list[str] = []
    for fp, folder in file_folder_pairs:
        path_str = str(fp)
        file_paths.append(path_str)
        path_to_folder[path_str] = folder

    results: dict[str, list[dict[str, Any]]] = {}
    n_total = len(file_paths)
    n_loaded = 0
    n_failed = 0
    log_interval = max(1, n_total // 20)
    t_start = time.monotonic()

    if max_workers <= 1 or n_total < 50:
        # Sequential fallback for small datasets or single-worker
        for idx, fp in enumerate(file_paths):
            _, api_calls = _worker_load_file(fp)
            if api_calls is not None:
                results[fp] = api_calls
                n_loaded += 1
            else:
                n_failed += 1
            if (idx + 1) % log_interval == 0:
                logger.info(
                    "Loading progress: %d / %d (%.1f%%)",
                    idx + 1, n_total, 100.0 * (idx + 1) / n_total,
                )
    else:
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_worker_load_file, fp): fp
                for fp in file_paths
            }
            for idx, future in enumerate(as_completed(futures)):
                try:
                    fp, api_calls = future.result()
                    if api_calls is not None:
                        results[fp] = api_calls
                        n_loaded += 1
                    else:
                        n_failed += 1
                except Exception:
                    n_failed += 1

                if (idx + 1) % log_interval == 0:
                    elapsed = time.monotonic() - t_start
                    rate = (idx + 1) / max(elapsed, 0.001)
                    logger.info(
                        "Loading progress: %d / %d (%.1f%%) — %.0f files/sec",
                        idx + 1, n_total, 100.0 * (idx + 1) / n_total, rate,
                    )

    elapsed = time.monotonic() - t_start
    logger.info(
        "JSON loading complete: %d loaded, %d failed/empty out of %d total (%.1fs)",
        n_loaded, n_failed, n_total, elapsed,
    )
    return results


# ═══════════════════════════════════════════════════════════════════════════
# Feature extraction — Behavioral (20-class)
# ═══════════════════════════════════════════════════════════════════════════


def _featurize_behavioral(
    api_calls: list[dict[str, Any]],
    sequence_length: int,
    feature_dim: int,
) -> NDArray[np.float32]:
    """Encode API calls into a behavioral feature tensor.

    Returns shape ``(sequence_length, feature_dim)`` with columns:
        0: api_name_id — hash of full API name (e.g. "KERNEL32.ReadFile") → [0, 2000)
        1: arg_summary_hash — hash of serialized args → [0, 256)
        2: return_value_code — parsed ret_val clamped to [0, 256)
        3: timing_delta — sequential position index normalized to [0, 100)
    """
    out = np.zeros((sequence_length, feature_dim), dtype=np.float32)
    n = min(len(api_calls), sequence_length)

    for i in range(n):
        call = api_calls[i]
        api_name: str = call["api_name"]

        # Feature 0: api_name_id
        out[i, 0] = float(_stable_hash(api_name.lower(), 2000))

        # Feature 1: arg_summary_hash
        args = call.get("args", [])
        args_str = "|".join(str(a) for a in args) if args else ""
        out[i, 1] = float(_stable_hash(args_str, 256))

        # Feature 2: return_value_code
        ret_raw = _parse_hex_int(call.get("ret_val", "0x0"), default=0)
        out[i, 2] = float(min(abs(ret_raw) % 256, 255))

        # Feature 3: timing_delta (position-based, normalized)
        position_index = call.get("index", i)
        out[i, 3] = float(min(position_index, 99))

    return out


# ═══════════════════════════════════════════════════════════════════════════
# Feature extraction — Emulation (3-class)
# ═══════════════════════════════════════════════════════════════════════════


def _get_module_category(api_name: str) -> int:
    """Derive module category from the API name prefix (e.g. 'KERNEL32.ReadFile' → 0)."""
    dot_pos = api_name.find(".")
    if dot_pos <= 0:
        return _MODULE_PREFIX_UNKNOWN
    module = api_name[:dot_pos].lower()
    return _MODULE_PREFIX_CAT.get(module, _MODULE_PREFIX_UNKNOWN)


def _derive_mem_access(args: list[Any]) -> int:
    """Heuristic: derive memory access type from API arguments.

    Checks if any argument looks like a memory address (hex starting with 0x
    and >= 0x10000). Returns a value in [0, 8).

    Encoding:
        0: no memory-like arguments
        1: single memory address
        2: multiple memory addresses
        3: contains null pointer (0x0)
        4: contains high address (>= 0x70000000, likely kernel space)
        5: mixed (kernel + user addresses)
        6: very large arg count (>8 args, complex call)
        7: reserved
    """
    if not args:
        return 0

    mem_count = 0
    has_null = False
    has_high = False
    for arg in args:
        val = _parse_hex_int(arg, default=-1)
        if val < 0:
            continue
        if val == 0:
            has_null = True
        elif val >= 0x10000:
            mem_count += 1
            if val >= 0x70000000:
                has_high = True

    if mem_count == 0:
        if has_null:
            return 3
        return 0
    if has_high and mem_count > 1:
        return 5
    if has_high:
        return 4
    if mem_count > 1:
        return 2
    if len(args) > 8:
        return 6
    return 1


def _featurize_emulation(
    api_calls: list[dict[str, Any]],
    sequence_length: int,
    feature_dim: int,
) -> NDArray[np.float32]:
    """Encode API calls into an emulation feature tensor.

    Returns shape ``(sequence_length, feature_dim)`` with columns:
        0: opcode_cat — module prefix category [0, 256)
        1: mem_access — derived from args [0, 8)
        2: api_id — hash of full API name [0, 2000)
        3: raw_feature — length of args list normalized to [0, 100)
    """
    out = np.zeros((sequence_length, feature_dim), dtype=np.float32)
    n = min(len(api_calls), sequence_length)

    for i in range(n):
        call = api_calls[i]
        api_name: str = call["api_name"]
        args = call.get("args", [])

        # Feature 0: opcode_cat (module prefix category)
        out[i, 0] = float(_get_module_category(api_name))

        # Feature 1: mem_access (derived from args)
        out[i, 1] = float(_derive_mem_access(args))

        # Feature 2: api_id (same hash as behavioral)
        out[i, 2] = float(_stable_hash(api_name.lower(), 2000))

        # Feature 3: raw_feature (args count, clamped)
        out[i, 3] = float(min(len(args), 99))

    return out


# ═══════════════════════════════════════════════════════════════════════════
# Cache management
# ═══════════════════════════════════════════════════════════════════════════


def _cache_paths(
    base_dir: Path,
    model_tag: str,
    sequence_length: int,
) -> tuple[Path, Path]:
    """Return (npz_path, meta_path) for cached dataset files."""
    processed_dir = base_dir / "processed"
    processed_dir.mkdir(parents=True, exist_ok=True)
    stem = f"quovadis_{model_tag}_v{_CACHE_VERSION}_seq{sequence_length}"
    return processed_dir / f"{stem}.npz", processed_dir / f"{stem}_meta.json"


def _load_cache(
    npz_path: Path,
    meta_path: Path,
) -> tuple[NDArray[np.float32], NDArray[np.int64], dict[str, Any]] | None:
    """Attempt to load a cached dataset. Returns None if cache is absent or stale."""
    if not npz_path.exists() or not meta_path.exists():
        return None

    try:
        with np.load(npz_path, allow_pickle=False) as payload:
            X = np.asarray(payload["X"], dtype=np.float32)
            y = np.asarray(payload["y"], dtype=np.int64)
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if meta.get("cache_version") != _CACHE_VERSION:
            logger.info("Cache version mismatch, rebuilding.")
            return None
        logger.info("Loaded cached Quo Vadis %s corpus: %s (%d samples)", meta.get("model_tag", ""), npz_path, X.shape[0])
        return X, y, meta
    except Exception as exc:
        logger.warning("Cache load failed (%s), will rebuild: %s", npz_path, exc)
        return None


def _save_cache(
    npz_path: Path,
    meta_path: Path,
    X: NDArray[np.float32],
    y: NDArray[np.int64],
    meta: dict[str, Any],
) -> None:
    """Persist processed arrays and metadata to disk."""
    npz_path.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(str(npz_path), X=X, y=y)
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    size_mb = npz_path.stat().st_size / (1024 * 1024)
    logger.info("Cached Quo Vadis dataset to %s (%.2f MB)", npz_path, size_mb)


# ═══════════════════════════════════════════════════════════════════════════
# Class balancing
# ═══════════════════════════════════════════════════════════════════════════


def _balance_and_subsample(
    features_list: list[NDArray[np.float32]],
    labels_list: list[int],
    max_samples_per_class: int,
    seed: int,
) -> tuple[NDArray[np.float32], NDArray[np.int64]]:
    """Stack, balance per-class counts, and shuffle."""
    if not features_list:
        raise RuntimeError("No samples available for balancing")

    X_all = np.ascontiguousarray(np.stack(features_list, axis=0).astype(np.float32, copy=False))
    y_all = np.asarray(labels_list, dtype=np.int64)

    rng = np.random.default_rng(seed)
    balanced_indices: list[NDArray[np.int64]] = []
    unique_classes = np.unique(y_all)

    for cls in unique_classes:
        cls_indices = np.where(y_all == cls)[0]
        if len(cls_indices) > max_samples_per_class:
            cls_indices = rng.choice(cls_indices, size=max_samples_per_class, replace=False)
        balanced_indices.append(cls_indices)

    indices = np.concatenate(balanced_indices)
    rng.shuffle(indices)

    return X_all[indices], y_all[indices]


# ═══════════════════════════════════════════════════════════════════════════
# Class distribution helper
# ═══════════════════════════════════════════════════════════════════════════


def _class_distribution_behavioral(y: NDArray[np.int64]) -> dict[str, int]:
    counts = Counter(int(label) for label in y.tolist())
    return {
        BehaviorCategory(label).name: count
        for label, count in sorted(counts.items())
    }


def _class_distribution_emulation(y: NDArray[np.int64]) -> dict[str, int]:
    counts = Counter(int(label) for label in y.tolist())
    return {
        EmulationVerdict(label).name: count
        for label, count in sorted(counts.items())
    }


# ═══════════════════════════════════════════════════════════════════════════
# Data availability check
# ═══════════════════════════════════════════════════════════════════════════


def _validate_data_dir(base_dir: Path) -> None:
    """Raise a clear error if the Quo Vadis dataset is not present."""
    if not base_dir.exists():
        raise FileNotFoundError(
            f"Quo Vadis Speakeasy dataset directory not found: {base_dir}\n"
            "Expected structure:\n"
            "  {base_dir}/windows_emulation_trainset/report_clean/\n"
            "  {base_dir}/windows_emulation_trainset/report_backdoor/\n"
            "  ... (see PhantomCortex documentation for download instructions)"
        )

    trainset_dir = base_dir / "windows_emulation_trainset"
    if not trainset_dir.is_dir():
        raise FileNotFoundError(
            f"Quo Vadis training split not found: {trainset_dir}\n"
            "Download the dataset and extract it so that "
            "'windows_emulation_trainset/' is directly inside:\n"
            f"  {base_dir}"
        )

    has_any_folder = False
    for folder_name in _BEHAVIORAL_FOLDER_MAP:
        folder_path = trainset_dir / folder_name
        if folder_path.is_dir():
            json_count = sum(1 for _ in folder_path.rglob("*.json"))
            if json_count > 0:
                has_any_folder = True
                break

    if not has_any_folder:
        raise FileNotFoundError(
            f"No JSON files found in any expected Quo Vadis subdirectory under {trainset_dir}\n"
            "Expected folders: " + ", ".join(sorted(_BEHAVIORAL_FOLDER_MAP.keys()))
        )


# ═══════════════════════════════════════════════════════════════════════════
# Core pipeline — shared load + featurize logic
# ═══════════════════════════════════════════════════════════════════════════


def _build_dataset(
    base_dir: Path,
    folder_map: dict[str, Any],
    featurize_fn: Any,
    sequence_length: int,
    feature_dim: int,
    max_samples_per_class: int,
    seed: int,
    max_workers: int,
) -> tuple[NDArray[np.float32], NDArray[np.int64], dict[str, int], dict[str, int]]:
    """Discover, load, featurize, balance — returns (X, y, source_counts, skipped_counts)."""
    file_folder_pairs = _discover_json_files(base_dir, folder_map)
    if not file_folder_pairs:
        raise RuntimeError(
            f"No JSON files discovered in {base_dir}. "
            "Ensure the dataset is extracted correctly."
        )

    logger.info(
        "Discovered %d JSON files across %d categories",
        len(file_folder_pairs),
        len({folder for _, folder in file_folder_pairs}),
    )

    # Build path → folder lookup
    path_to_folder: dict[str, str] = {
        str(fp): folder for fp, folder in file_folder_pairs
    }

    # Parallel load
    parsed = _load_json_files_parallel(file_folder_pairs, max_workers=max_workers)

    # Featurize
    features_list: list[NDArray[np.float32]] = []
    labels_list: list[int] = []
    source_counts: Counter[str] = Counter()
    skipped: Counter[str] = Counter()
    t_feat_start = time.monotonic()

    for path_str, api_calls in parsed.items():
        folder_name = path_to_folder.get(path_str)
        if folder_name is None:
            skipped["unknown_folder"] += 1
            continue

        label_enum = folder_map.get(folder_name)
        if label_enum is None:
            skipped[f"unmapped_{folder_name}"] += 1
            continue

        try:
            tensor = featurize_fn(api_calls, sequence_length, feature_dim)
        except Exception as exc:
            skipped[f"featurize_error_{folder_name}"] += 1
            logger.debug("Featurization error for %s: %s", path_str, exc)
            continue

        features_list.append(tensor)
        labels_list.append(int(label_enum))
        source_counts[folder_name] += 1

    t_feat_elapsed = time.monotonic() - t_feat_start
    logger.info("Featurization complete: %d samples in %.1fs", len(features_list), t_feat_elapsed)

    if not features_list:
        raise RuntimeError(
            "No valid samples were extracted. "
            f"Source counts: {dict(source_counts)}, Skipped: {dict(skipped)}"
        )

    X, y = _balance_and_subsample(features_list, labels_list, max_samples_per_class, seed)

    return X, y, dict(source_counts), dict(skipped)


# ═══════════════════════════════════════════════════════════════════════════
# Public API — Behavioral (20-class)
# ═══════════════════════════════════════════════════════════════════════════


def load_quovadis_behavioral(
    data_dir: str | Path | None = None,
    seed: int = 42,
    max_samples_per_class: int = 10_000,
    sequence_length: int = 512,
    feature_dim: int = 4,
    *,
    cache: bool = True,
    max_workers: int = _MAX_WORKERS_DEFAULT,
) -> tuple[NDArray[np.float32], NDArray[np.int64], dict[str, Any]]:
    """Load the Quo Vadis Speakeasy dataset for Cortex-Behavioral training.

    Parses emulation report JSONs, extracts API call sequences, and encodes
    them as ``(N, 512, 4)`` float32 tensors with 20-class behavioral labels.

    Parameters
    ----------
    data_dir : str, Path, or None
        Root directory containing the extracted Quo Vadis dataset.
        Defaults to ``PhantomCortex/training/data/raw/quovadis_speakeasy/``.
    seed : int
        Random seed for reproducible class balancing and shuffling.
    max_samples_per_class : int
        Maximum samples retained per behavior class to prevent imbalance.
    sequence_length : int
        API call sequence length (truncated or zero-padded). Default 512.
    feature_dim : int
        Features per API call step. Default 4.
    cache : bool
        If True, cache processed arrays as ``.npz`` for fast reloading.
    max_workers : int
        Maximum parallel workers for JSON parsing.

    Returns
    -------
    X : ndarray of shape (N, sequence_length, feature_dim), float32
        Feature tensors.
    y : ndarray of shape (N,), int64
        BehaviorCategory labels (0–19).
    metadata : dict
        Dataset provenance and statistics.

    Raises
    ------
    FileNotFoundError
        If the dataset directory or expected subdirectories are missing.
    RuntimeError
        If no valid samples could be extracted.
    """
    base_dir = _resolve_data_dir(data_dir)

    # Check cache first
    npz_path, meta_path = _cache_paths(base_dir, "behavioral", sequence_length)
    if cache:
        cached = _load_cache(npz_path, meta_path)
        if cached is not None:
            return cached

    # Validate data presence
    _validate_data_dir(base_dir)

    logger.info(
        "Building Quo Vadis behavioral dataset: seq_len=%d, feat_dim=%d, max_per_class=%d",
        sequence_length, feature_dim, max_samples_per_class,
    )

    X, y, source_counts, skipped = _build_dataset(
        base_dir=base_dir,
        folder_map=_BEHAVIORAL_FOLDER_MAP,
        featurize_fn=_featurize_behavioral,
        sequence_length=sequence_length,
        feature_dim=feature_dim,
        max_samples_per_class=max_samples_per_class,
        seed=seed,
        max_workers=max_workers,
    )

    class_dist = _class_distribution_behavioral(y)
    metadata: dict[str, Any] = {
        "model_tag": "behavioral",
        "source": "quovadis_speakeasy",
        "sequence_length": sequence_length,
        "feature_dim": feature_dim,
        "num_samples": int(y.shape[0]),
        "num_classes": len(class_dist),
        "class_distribution": class_dist,
        "source_counts": source_counts,
        "skipped": skipped,
        "max_samples_per_class": max_samples_per_class,
        "seed": seed,
        "cache_version": _CACHE_VERSION,
    }

    logger.info(
        "Quo Vadis behavioral corpus ready: %d samples, %d classes, dist=%s",
        y.shape[0], len(class_dist), class_dist,
    )

    if cache:
        _save_cache(npz_path, meta_path, X, y, metadata)

    return X, y, metadata


# ═══════════════════════════════════════════════════════════════════════════
# Public API — Emulation (3-class)
# ═══════════════════════════════════════════════════════════════════════════


def load_quovadis_emulation(
    data_dir: str | Path | None = None,
    seed: int = 42,
    max_samples_per_class: int = 30_000,
    sequence_length: int = 1024,
    feature_dim: int = 4,
    *,
    cache: bool = True,
    max_workers: int = _MAX_WORKERS_DEFAULT,
) -> tuple[NDArray[np.float32], NDArray[np.int64], dict[str, Any]]:
    """Load the Quo Vadis Speakeasy dataset for Cortex-Emulation training.

    Parses emulation report JSONs, extracts API call sequences, and encodes
    them as ``(N, 1024, 4)`` float32 tensors with 3-class emulation verdicts.

    Parameters
    ----------
    data_dir : str, Path, or None
        Root directory containing the extracted Quo Vadis dataset.
        Defaults to ``PhantomCortex/training/data/raw/quovadis_speakeasy/``.
    seed : int
        Random seed for reproducible class balancing and shuffling.
    max_samples_per_class : int
        Maximum samples retained per verdict class to prevent imbalance.
    sequence_length : int
        API call sequence length (truncated or zero-padded). Default 1024.
    feature_dim : int
        Features per API call step. Default 4.
    cache : bool
        If True, cache processed arrays as ``.npz`` for fast reloading.
    max_workers : int
        Maximum parallel workers for JSON parsing.

    Returns
    -------
    X : ndarray of shape (N, sequence_length, feature_dim), float32
        Feature tensors.
    y : ndarray of shape (N,), int64
        EmulationVerdict labels (0=Benign, 1=Suspicious, 2=Malicious).
    metadata : dict
        Dataset provenance and statistics.

    Raises
    ------
    FileNotFoundError
        If the dataset directory or expected subdirectories are missing.
    RuntimeError
        If no valid samples could be extracted.
    """
    base_dir = _resolve_data_dir(data_dir)

    # Check cache first
    npz_path, meta_path = _cache_paths(base_dir, "emulation", sequence_length)
    if cache:
        cached = _load_cache(npz_path, meta_path)
        if cached is not None:
            return cached

    # Validate data presence
    _validate_data_dir(base_dir)

    logger.info(
        "Building Quo Vadis emulation dataset: seq_len=%d, feat_dim=%d, max_per_class=%d",
        sequence_length, feature_dim, max_samples_per_class,
    )

    X, y, source_counts, skipped = _build_dataset(
        base_dir=base_dir,
        folder_map=_EMULATION_FOLDER_MAP,
        featurize_fn=_featurize_emulation,
        sequence_length=sequence_length,
        feature_dim=feature_dim,
        max_samples_per_class=max_samples_per_class,
        seed=seed,
        max_workers=max_workers,
    )

    class_dist = _class_distribution_emulation(y)
    metadata: dict[str, Any] = {
        "model_tag": "emulation",
        "source": "quovadis_speakeasy",
        "sequence_length": sequence_length,
        "feature_dim": feature_dim,
        "num_samples": int(y.shape[0]),
        "num_classes": len(class_dist),
        "class_distribution": class_dist,
        "source_counts": source_counts,
        "skipped": skipped,
        "max_samples_per_class": max_samples_per_class,
        "seed": seed,
        "cache_version": _CACHE_VERSION,
    }

    logger.info(
        "Quo Vadis emulation corpus ready: %d samples, %d classes, dist=%s",
        y.shape[0], len(class_dist), class_dist,
    )

    if cache:
        _save_cache(npz_path, meta_path, X, y, metadata)

    return X, y, metadata
