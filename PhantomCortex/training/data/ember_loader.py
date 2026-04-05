"""
EMBER 2018 Dataset Loader for PhantomCortex
============================================

Downloads, extracts, and loads the EMBER 2018 dataset (1.1M PE samples with
2381 pre-extracted features each) for training the Cortex-Static LightGBM
malware classifier.

Dataset format priority:
    1. NPZ cache — compressed numpy archive for near-instant reload
    2. Memory-mapped .dat files — zero-copy read of pre-vectorized features
    3. JSONL shard parsing — raw feature JSON (slowest, first-time fallback)

Reference:
    Anderson & Roth, "EMBER: An Open Dataset for Training Static PE Malware
    Machine Learning Models", 2018.

Usage:
    from PhantomCortex.training.data.ember_loader import load_ember
    X_train, y_train, X_test, y_test = load_ember("/path/to/data")
"""

from __future__ import annotations

import hashlib
import json
import logging
import tarfile
from pathlib import Path
from typing import Optional

import numpy as np
from numpy.typing import NDArray

logger = logging.getLogger("PhantomCortex.Data.EMBER")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EMBER_URL: str = "https://ember.elastic.co/ember_dataset_2018_2.tar.bz2"
EMBER_SHA256: str = (
    "b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812"
)
EMBER_ARCHIVE_NAME: str = "ember_dataset_2018_2.tar.bz2"
EMBER_DIR_NAME: str = "ember_dataset_2018_2"

FEATURE_COUNT: int = 2381
TRAIN_SAMPLE_COUNT: int = 600_000
TEST_SAMPLE_COUNT: int = 200_000

_DOWNLOAD_CHUNK_BYTES: int = 8 * 1024 * 1024  # 8 MiB
_SHA256_CHUNK_BYTES: int = 4 * 1024 * 1024  # 4 MiB
_NPZ_CACHE_NAME: str = "ember_2018_labeled.npz"

_TRAIN_SHARD_NAMES: list[str] = [
    f"train_features_{i}.jsonl" for i in range(6)
]
_TEST_SHARD_NAME: str = "test_features.jsonl"


# ---------------------------------------------------------------------------
# SHA-256 verification
# ---------------------------------------------------------------------------


def _verify_sha256(path: Path, expected: str) -> bool:
    """Verify file integrity via SHA-256 digest comparison."""
    sha = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(_SHA256_CHUNK_BYTES)
            if not chunk:
                break
            sha.update(chunk)
    digest = sha.hexdigest()
    match = digest == expected
    if match:
        logger.info("SHA-256 verified: %s…", digest[:16])
    else:
        logger.error(
            "SHA-256 mismatch: expected %s…, got %s…",
            expected[:16],
            digest[:16],
        )
    return match


# ---------------------------------------------------------------------------
# Download with resume support
# ---------------------------------------------------------------------------


def download_ember(
    dest_dir: Path,
    *,
    url: str = EMBER_URL,
    expected_sha256: str = EMBER_SHA256,
    resume: bool = True,
) -> Path:
    """Download the EMBER 2018 dataset archive with progress and resume.

    Args:
        dest_dir: Directory to save the archive.
        url: Download URL.
        expected_sha256: Expected SHA-256 hash of the completed archive.
        resume: Attempt to resume an interrupted download when a partial
            file already exists on disk.

    Returns:
        Path to the downloaded (and verified) archive.

    Raises:
        RuntimeError: If the download fails or the hash does not match.
    """
    import requests
    from tqdm import tqdm

    dest_dir.mkdir(parents=True, exist_ok=True)
    archive_path = dest_dir / EMBER_ARCHIVE_NAME

    # Fast-path: archive already present and valid
    if archive_path.exists() and archive_path.stat().st_size > 0:
        if _verify_sha256(archive_path, expected_sha256):
            logger.info(
                "Archive already downloaded and verified: %s", archive_path
            )
            return archive_path
        if not resume:
            logger.warning("Hash mismatch on existing archive — re-downloading")
            archive_path.unlink()

    existing_size = 0
    if resume and archive_path.exists():
        existing_size = archive_path.stat().st_size

    headers: dict[str, str] = {}
    if existing_size > 0:
        headers["Range"] = f"bytes={existing_size}-"
        logger.info("Resuming download from byte %d", existing_size)

    logger.info("Downloading EMBER dataset from %s", url)
    response = requests.get(url, headers=headers, stream=True, timeout=120)

    # Handle 416 Range Not Satisfiable — file may already be complete
    if response.status_code == 416:
        if _verify_sha256(archive_path, expected_sha256):
            return archive_path
        archive_path.unlink(missing_ok=True)
        existing_size = 0
        response = requests.get(url, stream=True, timeout=120)

    if response.status_code not in (200, 206):
        raise RuntimeError(
            f"Download failed: HTTP {response.status_code} {response.reason}"
        )

    content_length = response.headers.get("content-length")
    total_size: Optional[int] = (
        int(content_length) + existing_size if content_length else None
    )

    write_mode = (
        "ab" if existing_size > 0 and response.status_code == 206 else "wb"
    )

    with (
        open(archive_path, write_mode) as fh,
        tqdm(
            total=total_size,
            initial=existing_size,
            unit="B",
            unit_scale=True,
            unit_divisor=1024,
            desc="EMBER download",
        ) as pbar,
    ):
        for chunk in response.iter_content(chunk_size=_DOWNLOAD_CHUNK_BYTES):
            if chunk:
                fh.write(chunk)
                pbar.update(len(chunk))

    if not _verify_sha256(archive_path, expected_sha256):
        archive_path.unlink(missing_ok=True)
        raise RuntimeError(
            "SHA-256 verification failed after download — archive is corrupt"
        )

    logger.info("Download complete: %s", archive_path)
    return archive_path


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def _extract_archive(archive_path: Path, dest_dir: Path) -> Path:
    """Extract the EMBER tar.bz2 archive with path-traversal protection.

    Args:
        archive_path: Path to the .tar.bz2 file.
        dest_dir: Directory to extract into.

    Returns:
        Path to the extracted dataset directory.

    Raises:
        RuntimeError: If extraction fails or a path-traversal member is
            detected inside the archive.
    """
    ember_dir = dest_dir / EMBER_DIR_NAME
    if ember_dir.exists() and any(ember_dir.iterdir()):
        logger.info("Dataset already extracted: %s", ember_dir)
        return ember_dir

    logger.info("Extracting %s …", archive_path.name)

    try:
        with tarfile.open(archive_path, "r:bz2") as tar:
            for member in tar.getmembers():
                member_path = Path(member.name)
                if member_path.is_absolute() or ".." in member_path.parts:
                    raise RuntimeError(
                        f"Refusing to extract path-traversal member: "
                        f"{member.name}"
                    )
            tar.extractall(path=str(dest_dir))  # noqa: S202
    except (tarfile.TarError, OSError) as exc:
        raise RuntimeError(
            f"Failed to extract EMBER archive: {exc}"
        ) from exc

    if not ember_dir.exists():
        candidates = [
            d
            for d in dest_dir.iterdir()
            if d.is_dir() and d.name.startswith("ember")
        ]
        if candidates:
            ember_dir = candidates[0]
        else:
            raise RuntimeError(
                f"Extraction succeeded but expected directory "
                f"'{EMBER_DIR_NAME}' not found in {dest_dir}"
            )

    logger.info("Extraction complete: %s", ember_dir)
    return ember_dir


# ---------------------------------------------------------------------------
# Loading from .dat (memory-mapped numpy) — preferred fast path
# ---------------------------------------------------------------------------


def _load_from_dat(
    ember_dir: Path,
) -> Optional[
    tuple[
        NDArray[np.float32],
        NDArray[np.int32],
        NDArray[np.float32],
        NDArray[np.int32],
    ]
]:
    """Load EMBER from pre-computed memory-mapped .dat files.

    Returns ``None`` if the required .dat files are not present.
    """
    x_train_path = ember_dir / "X_train.dat"
    y_train_path = ember_dir / "y_train.dat"
    x_test_path = ember_dir / "X_test.dat"
    y_test_path = ember_dir / "y_test.dat"

    if not all(
        p.exists()
        for p in (x_train_path, y_train_path, x_test_path, y_test_path)
    ):
        return None

    logger.info("Loading EMBER from memory-mapped .dat files (fast path)")

    X_train_mm = np.memmap(
        x_train_path,
        dtype=np.float32,
        mode="r",
        shape=(TRAIN_SAMPLE_COUNT, FEATURE_COUNT),
    )
    y_train_mm = np.memmap(
        y_train_path,
        dtype=np.float32,
        mode="r",
        shape=(TRAIN_SAMPLE_COUNT,),
    )
    X_test_mm = np.memmap(
        x_test_path,
        dtype=np.float32,
        mode="r",
        shape=(TEST_SAMPLE_COUNT, FEATURE_COUNT),
    )
    y_test_mm = np.memmap(
        y_test_path,
        dtype=np.float32,
        mode="r",
        shape=(TEST_SAMPLE_COUNT,),
    )

    # Filter out unlabeled samples (label == -1.0)
    train_labeled = y_train_mm[:] != -1.0
    test_labeled = y_test_mm[:] != -1.0

    X_train = np.array(X_train_mm[train_labeled], dtype=np.float32)
    y_train = np.array(y_train_mm[train_labeled], dtype=np.int32)
    X_test = np.array(X_test_mm[test_labeled], dtype=np.float32)
    y_test = np.array(y_test_mm[test_labeled], dtype=np.int32)

    del X_train_mm, y_train_mm, X_test_mm, y_test_mm

    logger.info(
        "Loaded from .dat: train=%d (of %d), test=%d (of %d)",
        X_train.shape[0],
        TRAIN_SAMPLE_COUNT,
        X_test.shape[0],
        TEST_SAMPLE_COUNT,
    )
    return X_train, y_train, X_test, y_test


# ---------------------------------------------------------------------------
# Loading from JSONL — fallback path
# ---------------------------------------------------------------------------


def _parse_jsonl_shard(
    path: Path,
) -> tuple[list[list[float]], list[int]]:
    """Parse a single EMBER JSONL shard, keeping only labeled samples.

    Each line is expected to contain at minimum:
        {"features": [<2381 floats>], "label": 0|1|-1, ...}
    """
    features: list[list[float]] = []
    labels: list[int] = []
    line_num = 0

    with open(path, "r", encoding="utf-8") as fh:
        for raw_line in fh:
            line_num += 1
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                record = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                logger.warning(
                    "Skipping malformed JSON at %s:%d: %s",
                    path.name,
                    line_num,
                    exc,
                )
                continue

            label = record.get("label")
            if label is None or int(label) == -1:
                continue

            feat = record.get("features")
            if feat is None or len(feat) != FEATURE_COUNT:
                logger.warning(
                    "Skipping sample at %s:%d — expected %d features, "
                    "got %s",
                    path.name,
                    line_num,
                    FEATURE_COUNT,
                    len(feat) if feat is not None else "None",
                )
                continue

            features.append(feat)
            labels.append(int(label))

    return features, labels


def _load_from_jsonl(
    ember_dir: Path,
) -> Optional[
    tuple[
        NDArray[np.float32],
        NDArray[np.int32],
        NDArray[np.float32],
        NDArray[np.int32],
    ]
]:
    """Load EMBER from JSONL shards. Returns ``None`` if shards are missing."""
    from tqdm import tqdm

    train_paths = [ember_dir / name for name in _TRAIN_SHARD_NAMES]
    test_path = ember_dir / _TEST_SHARD_NAME

    existing_train = [p for p in train_paths if p.exists()]
    if not existing_train:
        return None
    if not test_path.exists():
        logger.warning("Test shard %s not found", _TEST_SHARD_NAME)
        return None

    logger.info(
        "Loading EMBER from JSONL shards (%d train + 1 test)",
        len(existing_train),
    )

    all_train_features: list[list[float]] = []
    all_train_labels: list[int] = []

    for shard_path in tqdm(existing_train, desc="Parsing train shards"):
        feats, labs = _parse_jsonl_shard(shard_path)
        all_train_features.extend(feats)
        all_train_labels.extend(labs)
        logger.info(
            "Parsed %s: %d labeled samples", shard_path.name, len(feats)
        )

    test_features, test_labels = _parse_jsonl_shard(test_path)
    logger.info(
        "Parsed %s: %d labeled samples", test_path.name, len(test_features)
    )

    if not all_train_features or not test_features:
        logger.error("No labeled samples found in JSONL shards")
        return None

    X_train = np.array(all_train_features, dtype=np.float32)
    y_train = np.array(all_train_labels, dtype=np.int32)
    X_test = np.array(test_features, dtype=np.float32)
    y_test = np.array(test_labels, dtype=np.int32)

    logger.info(
        "Loaded from JSONL: train=%d, test=%d",
        X_train.shape[0],
        X_test.shape[0],
    )
    return X_train, y_train, X_test, y_test


# ---------------------------------------------------------------------------
# NPZ cache — fastest reload path
# ---------------------------------------------------------------------------


def _save_npz_cache(
    cache_path: Path,
    X_train: NDArray[np.float32],
    y_train: NDArray[np.int32],
    X_test: NDArray[np.float32],
    y_test: NDArray[np.int32],
) -> None:
    """Persist processed arrays as a compressed .npz archive."""
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(
        cache_path,
        X_train=X_train,
        y_train=y_train,
        X_test=X_test,
        y_test=y_test,
    )
    size_mb = cache_path.stat().st_size / (1024 * 1024)
    logger.info("NPZ cache saved: %s (%.1f MB)", cache_path, size_mb)


def _load_npz_cache(
    cache_path: Path,
) -> Optional[
    tuple[
        NDArray[np.float32],
        NDArray[np.int32],
        NDArray[np.float32],
        NDArray[np.int32],
    ]
]:
    """Load arrays from an existing NPZ cache. Returns ``None`` on miss."""
    if not cache_path.exists():
        return None

    logger.info("Loading from NPZ cache: %s", cache_path)
    try:
        data = np.load(cache_path, allow_pickle=False)
        X_train = data["X_train"].astype(np.float32)
        y_train = data["y_train"].astype(np.int32)
        X_test = data["X_test"].astype(np.float32)
        y_test = data["y_test"].astype(np.int32)
    except Exception as exc:
        logger.warning(
            "NPZ cache corrupt or incompatible — ignoring: %s", exc
        )
        return None

    if X_train.ndim != 2 or X_train.shape[1] != FEATURE_COUNT:
        logger.warning(
            "NPZ cache feature dimension mismatch: %s (expected ?, %d)",
            X_train.shape,
            FEATURE_COUNT,
        )
        return None

    logger.info(
        "Loaded from NPZ cache: train=%d, test=%d",
        X_train.shape[0],
        X_test.shape[0],
    )
    return X_train, y_train, X_test, y_test


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_ember(
    data_dir: Optional[str | Path] = None,
    *,
    download: bool = True,
    cache: bool = True,
) -> tuple[
    NDArray[np.float32],
    NDArray[np.int32],
    NDArray[np.float32],
    NDArray[np.int32],
]:
    """Load the EMBER 2018 dataset, downloading if necessary.

    Returns only labeled samples (benign=0, malicious=1). Unlabeled
    samples (label=-1) are excluded.

    Loading precedence:
        1. NPZ cache (near-instant)
        2. Memory-mapped ``.dat`` files (fast, preferred for first load)
        3. JSONL shard parsing (slow, first-time fallback)
        4. Download → extract → load (automatic when ``download=True``)

    Args:
        data_dir: Root directory containing (or to receive) the EMBER data.
            Defaults to ``PhantomCortex/training/data/raw``.
        download: Automatically download if data is not found locally.
        cache: Persist / reload a ``.npz`` cache after the first parse.

    Returns:
        ``(X_train, y_train, X_test, y_test)`` where:
            - ``X_train``: float32 ``(N_train, 2381)``
            - ``y_train``: int32 ``(N_train,)`` ∈ {0, 1}
            - ``X_test``:  float32 ``(N_test, 2381)``
            - ``y_test``:  int32 ``(N_test,)`` ∈ {0, 1}

    Raises:
        FileNotFoundError: Data is absent and ``download=False``.
        RuntimeError: Download or extraction fails.
    """
    if data_dir is None:
        data_dir = Path(__file__).resolve().parent / "raw"
    else:
        data_dir = Path(data_dir)

    data_dir.mkdir(parents=True, exist_ok=True)
    ember_dir = data_dir / EMBER_DIR_NAME

    cache_dir = Path(__file__).resolve().parent / "processed"
    cache_path = cache_dir / _NPZ_CACHE_NAME

    # ---- 1. NPZ cache (fastest) ------------------------------------------
    if cache:
        cached = _load_npz_cache(cache_path)
        if cached is not None:
            return cached

    # ---- 2. .dat memory-mapped files (fast) -------------------------------
    if ember_dir.exists():
        result = _load_from_dat(ember_dir)
        if result is not None:
            if cache:
                _save_npz_cache(cache_path, *result)
            return result

    # ---- 3. JSONL shards (slow) -------------------------------------------
    if ember_dir.exists():
        result = _load_from_jsonl(ember_dir)
        if result is not None:
            if cache:
                _save_npz_cache(cache_path, *result)
            return result

    # ---- 4. Download + extract + load -------------------------------------
    if not download:
        raise FileNotFoundError(
            f"EMBER dataset not found at {ember_dir} and download=False. "
            f"Download manually from {EMBER_URL} or pass download=True."
        )

    archive_path = download_ember(data_dir)
    ember_dir = _extract_archive(archive_path, data_dir)

    result = _load_from_dat(ember_dir)
    if result is not None:
        if cache:
            _save_npz_cache(cache_path, *result)
        return result

    result = _load_from_jsonl(ember_dir)
    if result is not None:
        if cache:
            _save_npz_cache(cache_path, *result)
        return result

    raise RuntimeError(
        f"EMBER dataset extracted to {ember_dir} but contains neither "
        ".dat files nor valid JSONL shards — archive may be corrupted"
    )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="EMBER 2018 Dataset Loader — download, verify, and cache",
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default=None,
        help="Root directory for EMBER data (default: training/data/raw)",
    )
    parser.add_argument(
        "--download-only",
        action="store_true",
        help="Download and extract without loading into memory",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable NPZ caching of processed arrays",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify existing archive SHA-256 and exit",
    )
    args = parser.parse_args()

    data_path = Path(args.data_dir) if args.data_dir else None

    if args.verify:
        raw_dir = data_path or Path(__file__).resolve().parent / "raw"
        archive = raw_dir / EMBER_ARCHIVE_NAME
        if not archive.exists():
            logger.error("Archive not found: %s", archive)
            sys.exit(1)
        ok = _verify_sha256(archive, EMBER_SHA256)
        sys.exit(0 if ok else 1)

    if args.download_only:
        raw_dir = data_path or Path(__file__).resolve().parent / "raw"
        archive = download_ember(raw_dir)
        ember = _extract_archive(archive, raw_dir)
        logger.info("Dataset ready at %s", ember)
        sys.exit(0)

    X_train, y_train, X_test, y_test = load_ember(
        data_dir=data_path,
        download=True,
        cache=not args.no_cache,
    )

    logger.info("Train: X=%s  y=%s", X_train.shape, y_train.shape)
    logger.info("Test:  X=%s  y=%s", X_test.shape, y_test.shape)
    logger.info(
        "Train labels: benign=%d  malicious=%d",
        int((y_train == 0).sum()),
        int((y_train == 1).sum()),
    )
    logger.info(
        "Test labels:  benign=%d  malicious=%d",
        int((y_test == 0).sum()),
        int((y_test == 1).sum()),
    )
