"""
Feature Extraction Pipeline Orchestrator
==========================================
Reads raw PE files from disk, runs EMBER-compatible feature extraction in
parallel, and writes vectorised features to compressed numpy archives.

Usage::

    python -m PhantomCortex.training.features.feature_pipeline \\
        --input  data/raw/ \\
        --output data/processed/ \\
        [--batch-size 1000] \\
        [--workers 8] \\
        [--labels labels.jsonl] \\
        [--append]

The pipeline:
    1. Scans --input for PE files (by extension or MZ header).
    2. Processes files in batches through PEFeatureExtractor (multiprocessing).
    3. Saves per-batch .npz files (features, sha256 hashes, optional labels).
    4. Optionally merges into a single features.npz at --output.

Designed for throughput: >1 000 PE files / minute on modern hardware.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import multiprocessing
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from PhantomCortex.training.features.pe_features import PEFeatureExtractor

logger = logging.getLogger("phantomcortex.pipeline")

# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════
_PE_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".dll", ".sys", ".drv", ".scr", ".cpl", ".ocx", ".efi", ".mui",
})

# Maximum single-file size to load (256 MiB) — defence against zip-bombs
_MAX_FILE_SIZE: int = 256 * 1024 * 1024


def _is_pe_file(path: Path) -> bool:
    """Quick check: extension OR MZ header."""
    if path.suffix.lower() in _PE_EXTENSIONS:
        return True
    try:
        with open(path, "rb") as f:
            return f.read(2) == b"MZ"
    except OSError:
        return False


def _collect_pe_paths(input_dir: Path) -> List[Path]:
    """Recursively collect all PE files under *input_dir*."""
    pe_files: List[Path] = []
    for root, _dirs, files in os.walk(input_dir):
        for name in files:
            p = Path(root) / name
            if _is_pe_file(p):
                pe_files.append(p)
    return pe_files


def _load_labels(label_path: Path) -> Dict[str, Dict[str, Any]]:
    """
    Load a JSONL label file.  Each line: {"sha256": "...", "label": 0/1, "family": "..."}
    Returns dict keyed by sha256.
    """
    labels: Dict[str, Dict[str, Any]] = {}
    with open(label_path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                sha = obj.get("sha256", "").lower()
                if sha:
                    labels[sha] = obj
            except json.JSONDecodeError:
                logger.warning("Skipping malformed label at line %d", line_no)
    return labels


# ═══════════════════════════════════════════════════════════════════════════
# Worker function (runs in child process)
# ═══════════════════════════════════════════════════════════════════════════
def _extract_one(args: Tuple[str, int]) -> Tuple[Optional[str], Optional[np.ndarray]]:
    """
    Extract features from a single PE file.

    Returns (sha256_hex, feature_vector) or (None, None) on failure.
    This function is the multiprocessing target — it must be picklable.
    """
    file_path_str, feature_version = args
    try:
        file_path = Path(file_path_str)
        file_size = file_path.stat().st_size
        if file_size == 0:
            return (None, None)
        if file_size > _MAX_FILE_SIZE:
            logger.warning(
                "Skipping oversized file (%d bytes): %s",
                file_size,
                file_path.name,
            )
            return (None, None)

        with open(file_path, "rb") as f:
            bytez = f.read()

        extractor = PEFeatureExtractor(
            feature_version=feature_version,
            print_feature_warning=False,
        )
        raw = extractor.raw_features(bytez)
        vec = extractor.process_raw_features(raw)
        sha256 = raw["sha256"]
        return (sha256, vec)

    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        logger.debug("Failed to extract %s: %s", file_path_str, exc, exc_info=True)
        return (None, None)


# ═══════════════════════════════════════════════════════════════════════════
# Pipeline
# ═══════════════════════════════════════════════════════════════════════════
class FeaturePipeline:
    """
    Orchestrates parallel PE feature extraction over a directory of samples.

    Parameters
    ----------
    input_dir : Path
        Directory containing raw PE files (searched recursively).
    output_dir : Path
        Directory for output .npz archives.
    batch_size : int
        Number of files per processing batch (default 1000).
    num_workers : int
        Multiprocessing pool size.  0 → os.cpu_count().
    feature_version : int
        EMBER feature version (1 or 2; default 2).
    label_path : Path | None
        Optional JSONL label file.
    append : bool
        If True, append to existing features.npz instead of overwriting.
    """

    def __init__(
        self,
        input_dir: Path,
        output_dir: Path,
        batch_size: int = 1000,
        num_workers: int = 0,
        feature_version: int = 2,
        label_path: Optional[Path] = None,
        append: bool = False,
    ) -> None:
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.batch_size = max(batch_size, 1)
        self.num_workers = num_workers if num_workers > 0 else (os.cpu_count() or 4)
        self.feature_version = feature_version
        self.label_path = label_path
        self.append = append

    def run(self) -> Path:
        """
        Execute the pipeline.  Returns the path to the final .npz output file.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)

        logger.info("Scanning %s for PE files …", self.input_dir)
        pe_files = _collect_pe_paths(self.input_dir)
        total = len(pe_files)
        logger.info("Found %d PE files", total)
        if total == 0:
            logger.warning("No PE files found — nothing to do")
            out_path = self.output_dir / "features.npz"
            np.savez_compressed(
                str(out_path),
                features=np.empty((0, 0), dtype=np.float32),
                sha256=np.array([], dtype="<U64"),
            )
            return out_path

        # Load labels if provided
        labels: Dict[str, Dict[str, Any]] = {}
        if self.label_path and self.label_path.is_file():
            labels = _load_labels(self.label_path)
            logger.info("Loaded %d labels", len(labels))

        all_features: List[np.ndarray] = []
        all_hashes: List[str] = []
        all_labels: List[int] = []
        all_families: List[str] = []

        # Load existing data if appending
        final_path = self.output_dir / "features.npz"
        if self.append and final_path.exists():
            existing = np.load(str(final_path), allow_pickle=True)
            if "features" in existing and existing["features"].ndim == 2:
                all_features.append(existing["features"])
                all_hashes.extend(existing["sha256"].tolist())
                if "labels" in existing:
                    all_labels.extend(existing["labels"].tolist())
                if "families" in existing:
                    all_families.extend(existing["families"].tolist())
            logger.info(
                "Loaded %d existing feature vectors for append",
                len(all_hashes),
            )

        # Skip already-processed hashes
        seen_hashes: set[str] = set(all_hashes)

        # Process in batches
        t0 = time.monotonic()
        processed = 0
        skipped = 0

        for batch_start in range(0, total, self.batch_size):
            batch_end = min(batch_start + self.batch_size, total)
            batch_paths = pe_files[batch_start:batch_end]
            tasks = [(str(p), self.feature_version) for p in batch_paths]

            batch_features: List[np.ndarray] = []
            batch_hashes: List[str] = []

            with multiprocessing.Pool(processes=self.num_workers) as pool:
                for sha, vec in pool.imap_unordered(_extract_one, tasks, chunksize=16):
                    if sha is None or vec is None:
                        skipped += 1
                        continue
                    if sha in seen_hashes:
                        skipped += 1
                        continue
                    seen_hashes.add(sha)
                    batch_hashes.append(sha)
                    batch_features.append(vec)

            if batch_features:
                stacked = np.vstack(batch_features)
                all_features.append(stacked)
                all_hashes.extend(batch_hashes)

                # Resolve labels
                for sha in batch_hashes:
                    info = labels.get(sha, {})
                    all_labels.append(info.get("label", -1))
                    all_families.append(info.get("family", ""))

            processed += len(batch_paths)
            elapsed = time.monotonic() - t0
            rate = processed / elapsed if elapsed > 0 else 0
            logger.info(
                "Progress: %d/%d (%.0f files/min) — batch %d–%d, skipped %d",
                processed, total, rate * 60,
                batch_start, batch_end, skipped,
            )

        # Merge and save
        if all_features:
            merged = np.vstack(all_features).astype(np.float32)
        else:
            merged = np.empty((0, 0), dtype=np.float32)

        save_dict: Dict[str, Any] = {
            "features": merged,
            "sha256": np.array(all_hashes, dtype="<U64"),
        }
        if all_labels:
            save_dict["labels"] = np.array(all_labels, dtype=np.int32)
        if all_families:
            save_dict["families"] = np.array(all_families, dtype="<U64")

        np.savez_compressed(str(final_path), **save_dict)

        elapsed_total = time.monotonic() - t0
        logger.info(
            "Pipeline complete: %d vectors in %.1fs (%.0f files/min) → %s",
            len(all_hashes),
            elapsed_total,
            len(all_hashes) / elapsed_total * 60 if elapsed_total > 0 else 0,
            final_path,
        )
        return final_path


# ═══════════════════════════════════════════════════════════════════════════
# CLI entry point
# ═══════════════════════════════════════════════════════════════════════════
def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="PhantomCortex.training.features.feature_pipeline",
        description="Extract EMBER-compatible PE features in parallel.",
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        type=Path,
        help="Directory containing raw PE files.",
    )
    parser.add_argument(
        "--output", "-o",
        required=True,
        type=Path,
        help="Output directory for features.npz.",
    )
    parser.add_argument(
        "--batch-size", "-b",
        type=int,
        default=1000,
        help="Files per processing batch (default: 1000).",
    )
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=0,
        help="Number of parallel workers (default: CPU count).",
    )
    parser.add_argument(
        "--labels", "-l",
        type=Path,
        default=None,
        help="JSONL label file (sha256, label, family per line).",
    )
    parser.add_argument(
        "--feature-version",
        type=int,
        default=2,
        choices=[1, 2],
        help="EMBER feature version (default: 2).",
    )
    parser.add_argument(
        "--append",
        action="store_true",
        help="Append to existing features.npz instead of overwriting.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging.",
    )

    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if not args.input.is_dir():
        logger.error("Input path is not a directory: %s", args.input)
        return 1

    pipeline = FeaturePipeline(
        input_dir=args.input,
        output_dir=args.output,
        batch_size=args.batch_size,
        num_workers=args.workers,
        feature_version=args.feature_version,
        label_path=args.labels,
        append=args.append,
    )
    pipeline.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
