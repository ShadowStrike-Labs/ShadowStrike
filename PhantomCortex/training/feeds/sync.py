"""
ShadowStrike PhantomCortex -- Feed Sync Bridge
================================================
Synchronous bridge between the pipeline orchestrator and the async
:class:`FeedManager`.  Provides the ``sync_all`` entry-point consumed by
``pipeline.py`` to download samples and IOCs from all enabled threat-intel
feeds, deduplicate by SHA-256, organise artefacts into per-source
subdirectories, and return aggregate statistics.

Usage (from pipeline.py)::

    from PhantomCortex.training.feeds.sync import sync_all
    stats = sync_all(data_dir=Path("data/feeds"))
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import platform
import shutil
import time
from pathlib import Path
from typing import Any, Optional

from PhantomCortex.training.feeds.base_feed import (
    DownloadTracker,
    FeedProgress,
    load_config,
    resolve_path,
)
from PhantomCortex.training.feeds.feed_manager import FeedManager

logger = logging.getLogger("phantomcortex.feeds.sync")

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------

_NETWORK_TIMEOUT_S: int = 600
_MAX_SAMPLE_SIZE: int = 256 * 1024 * 1024  # 256 MiB cap per sample


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_event_loop() -> asyncio.AbstractEventLoop:
    """Return a usable event loop, creating one if necessary.

    On Windows the default ``ProactorEventLoop`` is used.  If a loop
    already exists (e.g. Jupyter) the coroutine is scheduled with
    ``asyncio.run`` in a fresh loop to avoid nesting issues.
    """
    if platform.system() == "Windows":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    return asyncio.new_event_loop()


def _sha256_of_file(path: Path) -> str:
    """Compute SHA-256 of an on-disk file in 64 KiB chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(65_536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest().lower()


def _collect_sample_files(directory: Path) -> list[Path]:
    """Recursively collect all regular files under *directory*."""
    results: list[Path] = []
    if not directory.is_dir():
        return results
    for root, _dirs, files in os.walk(directory):
        for name in files:
            p = Path(root) / name
            if p.is_file() and p.stat().st_size > 0:
                results.append(p)
    return results


def _organise_samples(
    source_dir: Path,
    dest_dir: Path,
    feed_name: str,
    seen_hashes: set[str],
) -> tuple[int, int]:
    """Move samples into ``dest_dir/<feed_name>/`` with SHA-256 dedup.

    Returns (total_moved, duplicates_skipped).
    """
    feed_dest = dest_dir / feed_name
    feed_dest.mkdir(parents=True, exist_ok=True)

    moved = 0
    dupes = 0

    for sample in _collect_sample_files(source_dir):
        try:
            if sample.stat().st_size > _MAX_SAMPLE_SIZE:
                logger.warning(
                    "Skipping oversized sample (%d bytes): %s",
                    sample.stat().st_size,
                    sample.name,
                )
                continue

            sha = _sha256_of_file(sample)
            if sha in seen_hashes:
                dupes += 1
                continue

            seen_hashes.add(sha)
            target = feed_dest / sha
            if not target.exists():
                shutil.copy2(str(sample), str(target))
            moved += 1
        except OSError as exc:
            logger.warning(
                "Failed to organise sample %s: %s", sample.name, exc
            )

    return moved, dupes


# ---------------------------------------------------------------------------
# Async runner
# ---------------------------------------------------------------------------

async def _run_all_feeds(
    manager: FeedManager,
    data_dir: Path,
    tracker: DownloadTracker,
) -> dict[str, Any]:
    """Execute all feeds via the manager and compile statistics.

    This coroutine is the core async work-unit wrapped by ``sync_all``.
    """
    t0 = time.monotonic()

    # Snapshot hashes known before this run for "new_samples" accounting.
    hashes_before: set[str] = tracker.get_all_hashes()

    # Run all feeds -- run_all handles per-feed exception isolation already.
    results: dict[str, FeedProgress] = await manager.run_all()

    # Collect per-feed statistics from FeedProgress objects.
    per_feed: dict[str, dict[str, Any]] = {}
    total_new_items = 0
    total_errors = 0
    total_skipped = 0

    for name, prog in results.items():
        per_feed[name] = {
            "new_items": prog.new_items,
            "skipped": prog.skipped,
            "errors": prog.errors,
            "processed": prog.processed,
            "elapsed_sec": round(prog.elapsed_seconds, 2),
        }
        total_new_items += prog.new_items
        total_errors += prog.errors
        total_skipped += prog.skipped

    # Organise downloaded samples into data_dir/ with per-source subdirs and
    # global SHA-256 deduplication.
    seen_hashes: set[str] = set()
    organised_total = 0
    duplicates_total = 0

    cfg = manager._cfg  # noqa: SLF001 -- accessing config for storage paths
    storage_cfg = cfg.get("storage", {})
    raw_dir = resolve_path(storage_cfg.get("raw_samples_dir", "../data/raw"))
    feed_cache_dir = resolve_path(storage_cfg.get("feed_cache_dir", "../data/feeds"))

    data_dir.mkdir(parents=True, exist_ok=True)

    # Organise from raw_dir (where individual feeds drop samples)
    for name in results:
        # Feeds store samples under raw_dir and/or feed_cache_dir.
        for src in (raw_dir / name, feed_cache_dir / name, raw_dir, feed_cache_dir):
            if src.is_dir():
                moved, dupes = _organise_samples(src, data_dir, name, seen_hashes)
                organised_total += moved
                duplicates_total += dupes

    # Tally totals after the run.
    hashes_after = tracker.get_all_hashes()
    new_samples = len(hashes_after - hashes_before)

    total_samples = tracker.count_downloads()
    total_iocs = tracker.count_iocs()

    duration = round(time.monotonic() - t0, 3)

    stats: dict[str, Any] = {
        "total_samples": total_samples,
        "total_iocs": total_iocs,
        "per_feed": per_feed,
        "new_samples": new_samples,
        "duration_sec": duration,
        "organised_samples": organised_total,
        "duplicates_removed": duplicates_total,
        "feed_errors": total_errors,
        "feed_skipped": total_skipped,
    }

    logger.info(
        "Feed sync complete: %d total samples, %d IOCs, %d new, %.1fs",
        total_samples,
        total_iocs,
        new_samples,
        duration,
    )

    return stats


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def sync_all(
    data_dir: Path,
    config: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Synchronously run all enabled threat-intel feeds.

    This is the entry-point consumed by ``pipeline.py``.  It wraps the
    async :class:`FeedManager` with ``asyncio.run`` so the caller does not
    need to manage an event loop.

    Parameters
    ----------
    data_dir : Path
        Destination directory for organised, deduplicated samples.  Each feed
        gets a sub-directory (e.g. ``data_dir/malwarebazaar/``).
    config : dict, optional
        Pre-parsed feed configuration.  When *None* the default
        ``feeds.yaml`` is loaded.

    Returns
    -------
    dict
        Aggregate statistics::

            {
                "total_samples": int,
                "total_iocs": int,
                "per_feed": {<feed_name>: {new_items, skipped, errors, ...}},
                "new_samples": int,
                "duration_sec": float,
                "organised_samples": int,
                "duplicates_removed": int,
                "feed_errors": int,
                "feed_skipped": int,
            }

    Raises
    ------
    RuntimeError
        If the async event loop cannot be created.
    """
    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)

    cfg = config if config is not None else load_config()
    manager = FeedManager(cfg)

    # Resolve the DownloadTracker for statistics queries.
    storage_cfg = cfg.get("storage", {})
    db_path = resolve_path(
        storage_cfg.get("db_path", "../data/feeds/feed_tracker.db")
    )
    tracker = DownloadTracker(db_path)

    loop = _get_event_loop()
    try:
        stats = loop.run_until_complete(
            _run_all_feeds(manager, data_dir, tracker)
        )
    except KeyboardInterrupt:
        logger.warning("Feed sync interrupted by user")
        stats = {
            "total_samples": tracker.count_downloads(),
            "total_iocs": tracker.count_iocs(),
            "per_feed": {},
            "new_samples": 0,
            "duration_sec": 0.0,
            "organised_samples": 0,
            "duplicates_removed": 0,
            "feed_errors": 0,
            "feed_skipped": 0,
        }
    except Exception:
        logger.exception("Feed sync failed with unhandled exception")
        raise
    finally:
        # Ensure all feed HTTP sessions are closed.
        try:
            loop.run_until_complete(manager.close_all())
        except Exception:
            logger.debug("Error closing feed sessions", exc_info=True)
        loop.close()

    return stats
