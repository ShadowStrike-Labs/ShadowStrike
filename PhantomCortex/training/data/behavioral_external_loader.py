"""
External behavioral dataset loader for Cortex-Behavioral.

Builds a conservative public augmentation corpus from MIT-licensed sources:

* Mal-API-2019 family-labelled API traces
* MalbehavD-V1 benign traces

Only directly mappable public labels are imported into ShadowStrike's internal
behavioral taxonomy. Ambiguous labels are skipped instead of being forced into
incorrect classes.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from collections import Counter
from itertools import zip_longest
from pathlib import Path
from typing import Any, Iterable
from zipfile import ZipFile

import numpy as np
import requests
from numpy.typing import NDArray

from PhantomCortex.training.features.behavioral_features import (
    ApiCallRecord,
    BehavioralFeatureExtractor,
)
from PhantomCortex.training.models.behavioral_cnn import BehaviorCategory

logger = logging.getLogger("PhantomCortex.Data.BehavioralExternal")

_DEFAULT_DIR = Path(__file__).resolve().parent / "raw" / "behavioral_external"
_CACHE_VERSION = 1
_DOWNLOAD_CHUNK_BYTES = 4 * 1024 * 1024
_REQUEST_TIMEOUT = (30, 300)

_MAL_API_ZIP_URL = (
    "https://raw.githubusercontent.com/ocatak/malware_api_class/master/mal-api-2019.zip"
)
_MAL_API_LABELS_URL = (
    "https://raw.githubusercontent.com/ocatak/malware_api_class/master/labels.csv"
)
_MALBEHAVD_URL = (
    "https://raw.githubusercontent.com/mpasco/MalbehavD-V1/main/MalBehavD-V1-dataset.csv"
)

_MAL_API_LABEL_MAP: dict[str, BehaviorCategory] = {
    "Backdoor": BehaviorCategory.Backdoor,
    "Downloader": BehaviorCategory.Downloader,
    "Worms": BehaviorCategory.Worm,
    "Spyware": BehaviorCategory.Spyware,
    "Adware": BehaviorCategory.Adware,
    "Dropper": BehaviorCategory.Dropper,
}


def _resolve_data_dir(data_dir: str | Path | None) -> Path:
    if data_dir is None:
        return _DEFAULT_DIR
    return Path(data_dir).expanduser().resolve()


def _download_if_needed(url: str, path: Path) -> None:
    if path.exists() and path.stat().st_size > 0:
        logger.info("Using existing dataset artifact: %s", path)
        return

    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".part")
    logger.info("Downloading %s -> %s", url, path)

    with requests.get(url, stream=True, timeout=_REQUEST_TIMEOUT) as response:
        response.raise_for_status()
        with open(temp_path, "wb") as handle:
            for chunk in response.iter_content(chunk_size=_DOWNLOAD_CHUNK_BYTES):
                if chunk:
                    handle.write(chunk)

    if temp_path.stat().st_size == 0:
        temp_path.unlink(missing_ok=True)
        raise RuntimeError(f"Downloaded empty dataset artifact from {url}")

    temp_path.replace(path)


def _cache_paths(base_dir: Path, sequence_length: int) -> tuple[Path, Path]:
    stem = f"behavioral_external_v{_CACHE_VERSION}_seq{sequence_length}"
    return base_dir / f"{stem}.npz", base_dir / f"{stem}_meta.json"


def _load_cache(npz_path: Path, meta_path: Path) -> tuple[
    NDArray[np.float32],
    NDArray[np.int64],
    dict[str, Any],
] | None:
    if not npz_path.exists() or not meta_path.exists():
        return None

    with np.load(npz_path, allow_pickle=False) as payload:
        X = np.asarray(payload["X"], dtype=np.float32)
        y = np.asarray(payload["y"], dtype=np.int64)
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    logger.info("Loaded cached external behavioral corpus: %s", npz_path)
    return X, y, meta


def _save_cache(
    npz_path: Path,
    meta_path: Path,
    X: NDArray[np.float32],
    y: NDArray[np.int64],
    meta: dict[str, Any],
) -> None:
    np.savez_compressed(npz_path, X=X, y=y)
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")


def _normalize_api_name(value: str) -> str:
    return value.strip().strip('"').replace("\x00", "")


def _make_calls(api_names: list[str]) -> list[ApiCallRecord]:
    calls: list[ApiCallRecord] = []
    for index, api_name in enumerate(api_names):
        prev_api = api_names[index - 1] if index > 0 else "<start>"
        next_api = api_names[index + 1] if index + 1 < len(api_names) else "<end>"
        calls.append(
            ApiCallRecord(
                api_name=api_name,
                arguments=f"prev={prev_api}|next={next_api}",
                return_value=0,
                timestamp_ms=float(index),
            )
        )
    return calls


def _iter_mal_api_sequences(zip_path: Path) -> Iterable[str]:
    with ZipFile(zip_path) as archive:
        entries = [entry for entry in archive.namelist() if entry.endswith(".txt")]
        if len(entries) != 1:
            raise RuntimeError(
                f"Expected exactly one .txt payload in {zip_path.name}, found {entries}"
            )

        with archive.open(entries[0], "r") as raw_stream:
            reader = io.TextIOWrapper(raw_stream, encoding="utf-8", errors="replace")
            for line in reader:
                yield line.rstrip("\r\n")


def _load_mal_api_labels(labels_path: Path) -> list[str]:
    labels = [
        row.strip()
        for row in labels_path.read_text(encoding="utf-8").splitlines()
        if row.strip()
    ]
    if not labels:
        raise RuntimeError(f"No labels found in {labels_path}")
    return labels


def _parse_space_delimited_sequence(line: str) -> list[str]:
    return [_normalize_api_name(token) for token in line.split() if _normalize_api_name(token)]


def _extract_malbehavd_sequence(row: dict[str, str], api_columns: list[str]) -> list[str]:
    api_names: list[str] = []
    for column in api_columns:
        value = _normalize_api_name(row.get(column, ""))
        if value:
            api_names.append(value)
    return api_names


def _class_counts(y: NDArray[np.int64]) -> dict[str, int]:
    counts = Counter(int(label) for label in y.tolist())
    return {
        BehaviorCategory(label).name: counts.get(label, 0)
        for label in range(len(BehaviorCategory))
        if counts.get(label, 0) > 0
    }


def load_behavioral_external_dataset(
    data_dir: str | Path | None = None,
    *,
    sequence_length: int = 512,
    download: bool = True,
    cache: bool = True,
) -> tuple[
    NDArray[np.float32],
    NDArray[np.int64],
    dict[str, Any],
]:
    """Load public external behavioral traces encoded for Cortex-Behavioral."""
    base_dir = _resolve_data_dir(data_dir)
    base_dir.mkdir(parents=True, exist_ok=True)

    npz_cache, meta_cache = _cache_paths(base_dir, sequence_length)
    if cache:
        cached = _load_cache(npz_cache, meta_cache)
        if cached is not None:
            return cached

    mal_api_zip = base_dir / "mal-api-2019.zip"
    mal_api_labels = base_dir / "mal-api-2019-labels.csv"
    malbehavd_csv = base_dir / "MalBehavD-V1-dataset.csv"

    if download:
        _download_if_needed(_MAL_API_ZIP_URL, mal_api_zip)
        _download_if_needed(_MAL_API_LABELS_URL, mal_api_labels)
        _download_if_needed(_MALBEHAVD_URL, malbehavd_csv)
    elif not all(path.exists() for path in (mal_api_zip, mal_api_labels, malbehavd_csv)):
        raise RuntimeError(
            "External behavioral datasets are missing locally and download was disabled."
        )

    extractor = BehavioralFeatureExtractor(max_sequence_length=sequence_length)
    features: list[NDArray[np.float32]] = []
    labels: list[int] = []
    skipped: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()

    mal_api_label_rows = _load_mal_api_labels(mal_api_labels)
    for family_name, line in zip_longest(
        mal_api_label_rows,
        _iter_mal_api_sequences(mal_api_zip),
        fillvalue=None,
    ):
        if family_name is None or line is None:
            raise RuntimeError("Mal-API-2019 label/trace count mismatch")

        mapped_label = _MAL_API_LABEL_MAP.get(family_name)
        if mapped_label is None:
            skipped[f"mal_api_unmapped_{family_name}"] += 1
            continue

        api_names = _parse_space_delimited_sequence(line)
        if not api_names:
            skipped["mal_api_empty_sequence"] += 1
            continue

        features.append(extractor.extract(_make_calls(api_names)))
        labels.append(int(mapped_label))
        source_counts["Mal-API-2019"] += 1

    with open(malbehavd_csv, "r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        api_columns = sorted(
            [column for column in reader.fieldnames or [] if column.isdigit()],
            key=int,
        )
        for row in reader:
            if row.get("labels", "").strip() != "0":
                skipped["malbehavd_malicious_skipped"] += 1
                continue

            api_names = _extract_malbehavd_sequence(row, api_columns)
            if not api_names:
                skipped["malbehavd_empty_sequence"] += 1
                continue

            features.append(extractor.extract(_make_calls(api_names)))
            labels.append(int(BehaviorCategory.Benign))
            source_counts["MalbehavD-V1"] += 1

    if not features:
        raise RuntimeError("No external behavioral samples were loaded")

    X = np.ascontiguousarray(np.stack(features).astype(np.float32, copy=False))
    y = np.ascontiguousarray(np.asarray(labels, dtype=np.int64))

    meta: dict[str, Any] = {
        "sequence_length": sequence_length,
        "sources": dict(source_counts),
        "class_counts": _class_counts(y),
        "skipped": dict(skipped),
        "cache_version": _CACHE_VERSION,
    }

    logger.info(
        "External behavioral corpus ready: samples=%d classes=%s sources=%s skipped=%s",
        y.shape[0],
        meta["class_counts"],
        meta["sources"],
        meta["skipped"],
    )

    if cache:
        _save_cache(npz_cache, meta_cache, X, y, meta)

    return X, y, meta
