"""
ShadowStrike PhantomCortex -- Feature Extraction Bridge
========================================================
Bridge module that connects the pipeline orchestrator to every feature
extractor in the ``features/`` package.  ``pipeline.py`` calls
``extract_all`` which dispatches to the correct extractor for each
requested model type, processes all samples found in ``raw_dir``, and
writes per-model ``.npz`` archives into ``output_dir``.

Supported model types:
    - **static**      : PE features via :class:`PEFeatureExtractor` (2381 dims)
    - **behavioral**  : API call sequences via :class:`BehavioralFeatureExtractor`
    - **memory**      : Memory region dumps via :class:`MemoryFeatureExtractor`
    - **network**     : Network flow metadata via :class:`NetworkFeatureExtractor`
    - **emulation**   : Emulation traces via :class:`EmulationFeatureExtractor`

Usage (from pipeline.py)::

    from PhantomCortex.training.features.extract import extract_all
    stats = extract_all(
        raw_dir=Path("data/raw"),
        output_dir=Path("data/processed"),
        models=["static", "behavioral", "memory", "network", "emulation"],
    )
"""

from __future__ import annotations

import hashlib
import json
import logging
import multiprocessing
import os
import time
from pathlib import Path
from typing import Any, Callable, Optional

import numpy as np

from PhantomCortex.training.features.pe_features import PEFeatureExtractor
from PhantomCortex.training.features.behavioral_features import (
    ApiCallRecord,
    BehavioralFeatureExtractor,
)
from PhantomCortex.training.features.memory_features import MemoryFeatureExtractor
from PhantomCortex.training.features.network_features import NetworkFeatureExtractor, NetworkFlow
from PhantomCortex.training.features.emulation_features import EmulationFeatureExtractor, EmulationEvent

logger = logging.getLogger("phantomcortex.features.extract")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_FILE_SIZE: int = 256 * 1024 * 1024  # 256 MiB
_PE_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".dll", ".sys", ".drv", ".scr", ".cpl", ".ocx", ".efi", ".mui",
})
_BATCH_SIZE: int = 500
_DEFAULT_WORKERS: int = max(1, (os.cpu_count() or 4) // 2)

# Map of model name -> default npz filename
_MODEL_OUTPUT_NAMES: dict[str, str] = {
    "static": "static_features.npz",
    "behavioral": "behavioral_features.npz",
    "memory": "memory_features.npz",
    "network": "network_features.npz",
    "emulation": "emulation_features.npz",
}

_VALID_MODELS: frozenset[str] = frozenset(_MODEL_OUTPUT_NAMES.keys())


# ---------------------------------------------------------------------------
# File discovery helpers
# ---------------------------------------------------------------------------

def _sha256_of_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().lower()


def _is_pe_file(path: Path) -> bool:
    """Quick heuristic: extension OR MZ header."""
    if path.suffix.lower() in _PE_EXTENSIONS:
        return True
    try:
        with open(path, "rb") as fh:
            return fh.read(2) == b"MZ"
    except OSError:
        return False


def _collect_files(directory: Path, recursive: bool = True) -> list[Path]:
    """Collect all regular files under *directory*."""
    results: list[Path] = []
    if not directory.is_dir():
        return results
    if recursive:
        for root, _dirs, files in os.walk(directory):
            for name in files:
                p = Path(root) / name
                if p.is_file():
                    results.append(p)
    else:
        for p in directory.iterdir():
            if p.is_file():
                results.append(p)
    return results


def _safe_read(path: Path) -> Optional[bytes]:
    """Read a file with size cap.  Returns None on failure."""
    try:
        size = path.stat().st_size
        if size == 0 or size > _MAX_FILE_SIZE:
            return None
        with open(path, "rb") as fh:
            return fh.read()
    except OSError:
        return None


def _load_json_sidecar(path: Path) -> Optional[dict[str, Any]]:
    """Load a JSON sidecar file (e.g. sample_sha256.json) if it exists."""
    json_path = path.with_suffix(".json")
    if not json_path.is_file():
        return None
    try:
        with open(json_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None


# ---------------------------------------------------------------------------
# Per-model extraction
# ---------------------------------------------------------------------------

def _extract_static(
    raw_dir: Path,
    output_dir: Path,
    existing_hashes: set[str],
) -> dict[str, Any]:
    """Extract 2381-dim PE features from all PE files in raw_dir."""
    t0 = time.monotonic()
    all_files = _collect_files(raw_dir)
    pe_files = [p for p in all_files if _is_pe_file(p)]

    logger.info("Static extraction: found %d PE files in %s", len(pe_files), raw_dir)

    extractor = PEFeatureExtractor(feature_version=2, print_feature_warning=False)
    features_list: list[np.ndarray] = []
    hashes_list: list[str] = []
    labels_list: list[int] = []
    errors = 0

    for path in pe_files:
        bytez = _safe_read(path)
        if bytez is None:
            errors += 1
            continue

        sha = _sha256_of_bytes(bytez)
        if sha in existing_hashes:
            continue

        try:
            raw = extractor.raw_features(bytez)
            vec = extractor.process_raw_features(raw)
            features_list.append(vec)
            hashes_list.append(sha)
            existing_hashes.add(sha)

            sidecar = _load_json_sidecar(path)
            labels_list.append(sidecar.get("label", -1) if sidecar else -1)
        except Exception as exc:
            logger.debug(
                "Static extraction failed for %s: %s", path.name, exc
            )
            errors += 1

    out_path = output_dir / _MODEL_OUTPUT_NAMES["static"]
    _save_features(out_path, features_list, hashes_list, labels_list, extractor.dim)

    duration = round(time.monotonic() - t0, 3)
    logger.info(
        "Static extraction: %d vectors, %d errors, %.1fs",
        len(hashes_list), errors, duration,
    )
    return {
        "samples_processed": len(pe_files),
        "features_extracted": len(hashes_list),
        "errors": errors,
        "duration_sec": duration,
        "feature_dim": extractor.dim,
        "output_file": str(out_path),
    }


def _extract_behavioral(
    raw_dir: Path,
    output_dir: Path,
    existing_hashes: set[str],
) -> dict[str, Any]:
    """Extract behavioral features from API call trace sidecars."""
    t0 = time.monotonic()
    extractor = BehavioralFeatureExtractor()
    all_files = _collect_files(raw_dir)

    features_list: list[np.ndarray] = []
    hashes_list: list[str] = []
    labels_list: list[int] = []
    errors = 0
    processed = 0

    for path in all_files:
        sidecar = _load_json_sidecar(path)
        if sidecar is None:
            continue

        api_trace = sidecar.get("api_trace") or sidecar.get("behavioral_trace")
        if not api_trace or not isinstance(api_trace, list):
            continue

        processed += 1
        bytez = _safe_read(path)
        if bytez is None:
            sha = path.stem.lower()
        else:
            sha = _sha256_of_bytes(bytez)

        if sha in existing_hashes:
            continue

        try:
            calls = []
            for entry in api_trace:
                if isinstance(entry, dict):
                    calls.append(ApiCallRecord(
                        api_name=str(entry.get("api_name", entry.get("name", ""))),
                        arguments=str(entry.get("arguments", entry.get("args", ""))),
                        return_value=int(entry.get("return_value", entry.get("retval", 0))),
                        timestamp_ms=float(entry.get("timestamp_ms", entry.get("ts", 0.0))),
                    ))
            if not calls:
                continue

            vec = extractor.extract(calls)
            features_list.append(vec.flatten())
            hashes_list.append(sha)
            existing_hashes.add(sha)
            labels_list.append(sidecar.get("label", -1))
        except Exception as exc:
            logger.debug(
                "Behavioral extraction failed for %s: %s", path.name, exc
            )
            errors += 1

    out_path = output_dir / _MODEL_OUTPUT_NAMES["behavioral"]
    feat_dim = extractor.max_sequence_length * extractor.feature_dim
    _save_features(out_path, features_list, hashes_list, labels_list, feat_dim)

    duration = round(time.monotonic() - t0, 3)
    logger.info(
        "Behavioral extraction: %d vectors, %d errors, %.1fs",
        len(hashes_list), errors, duration,
    )
    return {
        "samples_processed": processed,
        "features_extracted": len(hashes_list),
        "errors": errors,
        "duration_sec": duration,
        "feature_dim": feat_dim,
        "output_file": str(out_path),
    }


def _extract_memory(
    raw_dir: Path,
    output_dir: Path,
    existing_hashes: set[str],
) -> dict[str, Any]:
    """Extract memory region features from .mem / .dmp / raw dump files."""
    t0 = time.monotonic()
    extractor = MemoryFeatureExtractor()
    all_files = _collect_files(raw_dir)

    memory_extensions = frozenset({".mem", ".dmp", ".dump", ".bin", ".raw"})
    mem_files = [
        p for p in all_files
        if p.suffix.lower() in memory_extensions
        or (p.parent.name == "memory" and p.is_file())
    ]

    features_list: list[np.ndarray] = []
    hashes_list: list[str] = []
    labels_list: list[int] = []
    errors = 0

    for path in mem_files:
        bytez = _safe_read(path)
        if bytez is None:
            errors += 1
            continue

        sha = _sha256_of_bytes(bytez)
        if sha in existing_hashes:
            continue

        try:
            sidecar = _load_json_sidecar(path)
            perms: tuple[bool, bool, bool] | None = None
            if sidecar and "permissions" in sidecar:
                p = sidecar["permissions"]
                perms = (bool(p.get("r", False)), bool(p.get("w", False)), bool(p.get("x", False)))

            vec = extractor.extract(bytez, permissions=perms)
            features_list.append(vec)
            hashes_list.append(sha)
            existing_hashes.add(sha)
            labels_list.append(sidecar.get("label", -1) if sidecar else -1)
        except Exception as exc:
            logger.debug(
                "Memory extraction failed for %s: %s", path.name, exc
            )
            errors += 1

    out_path = output_dir / _MODEL_OUTPUT_NAMES["memory"]
    _save_features(out_path, features_list, hashes_list, labels_list, MemoryFeatureExtractor.FEATURE_COUNT)

    duration = round(time.monotonic() - t0, 3)
    logger.info(
        "Memory extraction: %d vectors, %d errors, %.1fs",
        len(hashes_list), errors, duration,
    )
    return {
        "samples_processed": len(mem_files),
        "features_extracted": len(hashes_list),
        "errors": errors,
        "duration_sec": duration,
        "feature_dim": MemoryFeatureExtractor.FEATURE_COUNT,
        "output_file": str(out_path),
    }


def _extract_network(
    raw_dir: Path,
    output_dir: Path,
    existing_hashes: set[str],
) -> dict[str, Any]:
    """Extract network flow features from PCAP metadata sidecars."""
    t0 = time.monotonic()
    extractor = NetworkFeatureExtractor()
    all_files = _collect_files(raw_dir)

    features_list: list[np.ndarray] = []
    hashes_list: list[str] = []
    labels_list: list[int] = []
    errors = 0
    processed = 0

    for path in all_files:
        sidecar = _load_json_sidecar(path)
        if sidecar is None:
            continue

        flows_raw = sidecar.get("network_flows") or sidecar.get("flows")
        if not flows_raw or not isinstance(flows_raw, list):
            continue

        processed += 1
        bytez = _safe_read(path)
        if bytez is None:
            sha = path.stem.lower()
        else:
            sha = _sha256_of_bytes(bytez)

        if sha in existing_hashes:
            continue

        try:
            per_sample_features: list[np.ndarray] = []
            for flow_dict in flows_raw:
                if not isinstance(flow_dict, dict):
                    continue
                flow = NetworkFlow(
                    src_ip=str(flow_dict.get("src_ip", "0.0.0.0")),
                    dst_ip=str(flow_dict.get("dst_ip", "0.0.0.0")),
                    src_port=int(flow_dict.get("src_port", 0)),
                    dst_port=int(flow_dict.get("dst_port", 0)),
                    protocol=str(flow_dict.get("protocol", "tcp")),
                    duration_ms=float(flow_dict.get("duration_ms", 0.0)),
                    bytes_sent=int(flow_dict.get("bytes_sent", 0)),
                    bytes_received=int(flow_dict.get("bytes_received", 0)),
                    packets_sent=int(flow_dict.get("packets_sent", 0)),
                    packets_received=int(flow_dict.get("packets_received", 0)),
                    inter_arrival_times_ms=list(flow_dict.get("inter_arrival_times_ms", [])),
                    payload_sizes=list(flow_dict.get("payload_sizes", [])),
                    payload_entropy=float(flow_dict.get("payload_entropy", 0.0)),
                    ja3_hash=str(flow_dict.get("ja3_hash", "")),
                    ja3s_hash=str(flow_dict.get("ja3s_hash", "")),
                    dns_queries=list(flow_dict.get("dns_queries", [])),
                    timestamp_start_ms=float(flow_dict.get("timestamp_start_ms", 0.0)),
                    timestamp_end_ms=float(flow_dict.get("timestamp_end_ms", 0.0)),
                )
                per_sample_features.append(extractor.extract(flow))

            if not per_sample_features:
                continue

            # Aggregate: mean across all flows for this sample
            stacked = np.vstack(per_sample_features)
            aggregated = np.mean(stacked, axis=0).astype(np.float32)

            features_list.append(aggregated)
            hashes_list.append(sha)
            existing_hashes.add(sha)
            labels_list.append(sidecar.get("label", -1))
        except Exception as exc:
            logger.debug(
                "Network extraction failed for %s: %s", path.name, exc
            )
            errors += 1

    out_path = output_dir / _MODEL_OUTPUT_NAMES["network"]
    _save_features(out_path, features_list, hashes_list, labels_list, NetworkFeatureExtractor.FEATURE_COUNT)

    duration = round(time.monotonic() - t0, 3)
    logger.info(
        "Network extraction: %d vectors, %d errors, %.1fs",
        len(hashes_list), errors, duration,
    )
    return {
        "samples_processed": processed,
        "features_extracted": len(hashes_list),
        "errors": errors,
        "duration_sec": duration,
        "feature_dim": NetworkFeatureExtractor.FEATURE_COUNT,
        "output_file": str(out_path),
    }


def _extract_emulation(
    raw_dir: Path,
    output_dir: Path,
    existing_hashes: set[str],
) -> dict[str, Any]:
    """Extract emulation trace features from JSON sidecars."""
    t0 = time.monotonic()
    extractor = EmulationFeatureExtractor()
    all_files = _collect_files(raw_dir)

    features_list: list[np.ndarray] = []
    hashes_list: list[str] = []
    labels_list: list[int] = []
    errors = 0
    processed = 0

    for path in all_files:
        sidecar = _load_json_sidecar(path)
        if sidecar is None:
            continue

        trace_raw = sidecar.get("emulation_trace") or sidecar.get("trace")
        if not trace_raw or not isinstance(trace_raw, list):
            continue

        processed += 1
        bytez = _safe_read(path)
        if bytez is None:
            sha = path.stem.lower()
        else:
            sha = _sha256_of_bytes(bytez)

        if sha in existing_hashes:
            continue

        try:
            events: list[EmulationEvent] = []
            for evt in trace_raw:
                if not isinstance(evt, dict):
                    continue
                events.append(EmulationEvent(
                    mnemonic=str(evt.get("mnemonic", "")),
                    memory_access=int(evt.get("memory_access", 0)),
                    api_call_name=str(evt.get("api_call_name", evt.get("api", ""))),
                    eflags_before=int(evt.get("eflags_before", 0)),
                    eflags_after=int(evt.get("eflags_after", 0)),
                ))

            if not events:
                continue

            result = extractor.extract_with_summary(events)
            tensor_flat = result["tensor"].flatten()
            summary = result["summary"]
            combined = np.concatenate([tensor_flat, summary]).astype(np.float32)

            features_list.append(combined)
            hashes_list.append(sha)
            existing_hashes.add(sha)
            labels_list.append(sidecar.get("label", -1))
        except Exception as exc:
            logger.debug(
                "Emulation extraction failed for %s: %s", path.name, exc
            )
            errors += 1

    feat_dim = (extractor.max_events * extractor.feature_dim) + extractor._SUMMARY_DIM
    out_path = output_dir / _MODEL_OUTPUT_NAMES["emulation"]
    _save_features(out_path, features_list, hashes_list, labels_list, feat_dim)

    duration = round(time.monotonic() - t0, 3)
    logger.info(
        "Emulation extraction: %d vectors, %d errors, %.1fs",
        len(hashes_list), errors, duration,
    )
    return {
        "samples_processed": processed,
        "features_extracted": len(hashes_list),
        "errors": errors,
        "duration_sec": duration,
        "feature_dim": feat_dim,
        "output_file": str(out_path),
    }


# ---------------------------------------------------------------------------
# Save helper
# ---------------------------------------------------------------------------

def _save_features(
    out_path: Path,
    features_list: list[np.ndarray],
    hashes_list: list[str],
    labels_list: list[int],
    feature_dim: int,
) -> None:
    """Write feature vectors, hashes, and labels to a compressed .npz."""
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if features_list:
        features = np.vstack(features_list).astype(np.float32)
    else:
        features = np.empty((0, feature_dim), dtype=np.float32)

    save_dict: dict[str, Any] = {
        "features": features,
        "sha256": np.array(hashes_list, dtype="<U64"),
        "labels": np.array(labels_list, dtype=np.int32),
    }

    np.savez_compressed(str(out_path), **save_dict)
    logger.debug("Saved %d vectors to %s", len(hashes_list), out_path)


# ---------------------------------------------------------------------------
# Extractor dispatch
# ---------------------------------------------------------------------------

_EXTRACTORS: dict[str, Callable[[Path, Path, set[str]], dict[str, Any]]] = {
    "static": _extract_static,
    "behavioral": _extract_behavioral,
    "memory": _extract_memory,
    "network": _extract_network,
    "emulation": _extract_emulation,
}


def _load_existing_hashes(output_dir: Path, model: str) -> set[str]:
    """Load SHA-256 hashes already present in the output .npz (if any)."""
    npz_name = _MODEL_OUTPUT_NAMES.get(model)
    if npz_name is None:
        return set()
    npz_path = output_dir / npz_name
    if not npz_path.exists():
        return set()
    try:
        data = np.load(str(npz_path), allow_pickle=False)
        if "sha256" in data:
            return set(data["sha256"].tolist())
    except Exception:
        logger.debug("Could not load existing hashes from %s", npz_path, exc_info=True)
    return set()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_all(
    raw_dir: Path,
    output_dir: Path,
    models: list[str],
) -> dict[str, Any]:
    """Extract features for all requested model types.

    This is the entry-point consumed by ``pipeline.py``.

    Parameters
    ----------
    raw_dir : Path
        Directory containing raw sample files (searched recursively).
    output_dir : Path
        Destination for per-model ``.npz`` feature archives.
    models : list[str]
        Model types to extract for.  Must be a subset of
        ``{"static", "behavioral", "memory", "network", "emulation"}``.

    Returns
    -------
    dict
        Per-model extraction statistics::

            {
                "per_model": {
                    "static": {samples_processed, features_extracted, errors, ...},
                    ...
                },
                "total_features": int,
                "total_errors": int,
                "duration_sec": float,
            }
    """
    raw_dir = Path(raw_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if not raw_dir.is_dir():
        logger.warning("Raw sample directory does not exist: %s", raw_dir)
        return {
            "per_model": {},
            "total_features": 0,
            "total_errors": 0,
            "duration_sec": 0.0,
        }

    # Validate requested models.
    invalid = set(models) - _VALID_MODELS
    if invalid:
        logger.error(
            "Unknown model types requested: %s (valid: %s)",
            sorted(invalid),
            sorted(_VALID_MODELS),
        )
        models = [m for m in models if m in _VALID_MODELS]

    t0 = time.monotonic()
    per_model: dict[str, dict[str, Any]] = {}
    total_features = 0
    total_errors = 0

    for model in models:
        extractor_fn = _EXTRACTORS.get(model)
        if extractor_fn is None:
            logger.error("No extractor registered for model '%s'", model)
            continue

        logger.info("Starting feature extraction for model: %s", model)
        existing_hashes = _load_existing_hashes(output_dir, model)

        try:
            stats = extractor_fn(raw_dir, output_dir, existing_hashes)
            per_model[model] = stats
            total_features += stats.get("features_extracted", 0)
            total_errors += stats.get("errors", 0)
        except Exception as exc:
            logger.exception(
                "Feature extraction for model '%s' failed: %s", model, exc
            )
            per_model[model] = {
                "samples_processed": 0,
                "features_extracted": 0,
                "errors": 1,
                "duration_sec": 0.0,
                "error_message": str(exc),
            }
            total_errors += 1

    duration = round(time.monotonic() - t0, 3)

    result: dict[str, Any] = {
        "per_model": per_model,
        "total_features": total_features,
        "total_errors": total_errors,
        "duration_sec": duration,
    }

    logger.info(
        "Feature extraction complete: %d total vectors, %d errors, %.1fs",
        total_features,
        total_errors,
        duration,
    )

    return result
