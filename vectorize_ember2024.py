"""
EMBER 2024 Vectorization Script
================================

Converts raw EMBER 2024 JSONL files (99GB, 256 shards) into vectorized
.dat feature matrices suitable for LightGBM training.

Must be run with __main__ guard on Windows due to multiprocessing.

Usage:
    python vectorize_ember2024.py [--data-dir path/to/ember2024_pe]
"""
import multiprocessing
import sys
from pathlib import Path


def main():
    import argparse
    import logging
    import time

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    logger = logging.getLogger("VectorizeEMBER2024")

    parser = argparse.ArgumentParser(description="Vectorize EMBER 2024 PE dataset")
    parser.add_argument(
        "--data-dir",
        type=str,
        default=str(
            Path(__file__).resolve().parent
            / "PhantomCortex"
            / "training"
            / "data"
            / "raw"
            / "ember2024_pe"
        ),
        help="Path to raw EMBER 2024 JSONL directory",
    )
    args = parser.parse_args()
    data_dir = Path(args.data_dir)

    if not data_dir.exists():
        logger.error("EMBER 2024 directory not found: %s", data_dir)
        sys.exit(1)

    jsonl_files = sorted(data_dir.glob("*.jsonl"))
    if not jsonl_files:
        logger.error("No JSONL files found in %s", data_dir)
        sys.exit(1)

    logger.info("Found %d JSONL shards in %s", len(jsonl_files), data_dir)

    # Check if already vectorized
    x_train = data_dir / "X_train.dat"
    y_train = data_dir / "y_train.dat"
    if x_train.exists() and y_train.exists():
        logger.info(
            "Already vectorized: %s (%.1f GB), %s",
            x_train,
            x_train.stat().st_size / (1024**3),
            y_train,
        )
        logger.info("Delete X_train.dat and y_train.dat to re-vectorize")
        return

    try:
        import thrember
    except ImportError:
        logger.error("thrember not installed. Run: pip install thrember")
        sys.exit(1)

    t0 = time.perf_counter()
    logger.info("Starting EMBER 2024 vectorization (this may take several hours)...")
    logger.info("Data directory: %s", data_dir)

    try:
        thrember.create_vectorized_features(str(data_dir), label_type="label")
    except Exception as exc:
        logger.error("Vectorization failed: %s", exc)
        import traceback
        traceback.print_exc()
        sys.exit(1)

    elapsed = time.perf_counter() - t0
    logger.info("Vectorization complete in %.1f minutes (%.1f hours)", elapsed / 60, elapsed / 3600)

    for f in ["X_train.dat", "y_train.dat", "X_test.dat", "y_test.dat"]:
        p = data_dir / f
        if p.exists():
            logger.info("  %s: %.2f GB", f, p.stat().st_size / (1024**3))
        else:
            logger.warning("  %s: NOT CREATED", f)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
