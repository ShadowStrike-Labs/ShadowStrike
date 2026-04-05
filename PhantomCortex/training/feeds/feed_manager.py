"""
ShadowStrike PhantomCortex — Feed Manager (Orchestrator)

Central orchestrator that manages all threat-intelligence feed instances,
runs them on their configured schedules, deduplicates samples across feeds,
collects statistics, and exports combined datasets for the feature-extraction
pipeline.

Usage::

    python -m PhantomCortex.training.feeds.feed_manager --run-all
    python -m PhantomCortex.training.feeds.feed_manager --feed malwarebazaar
    python -m PhantomCortex.training.feeds.feed_manager --stats
    python -m PhantomCortex.training.feeds.feed_manager --export combined.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import signal
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional, Sequence

from .base_feed import (
    BaseFeed,
    DownloadTracker,
    FeedProgress,
    load_config,
    resolve_path,
    setup_feed_logger,
)
from .ember_sync import EmberSyncFeed
from .feodo_tracker import FeodoTrackerFeed
from .malwarebazaar import MalwareBazaarFeed
from .otx_alienvault import OTXAlienVaultFeed
from .threatfox import ThreatFoxFeed
from .urlhaus import URLhausFeed

# ---------------------------------------------------------------------------
# Feed registry
# ---------------------------------------------------------------------------

_FEED_CLASSES: dict[str, type[BaseFeed]] = {
    "malwarebazaar": MalwareBazaarFeed,
    "threatfox": ThreatFoxFeed,
    "otx": OTXAlienVaultFeed,
    "urlhaus": URLhausFeed,
    "ember": EmberSyncFeed,
    "feodo": FeodoTrackerFeed,
}


# ---------------------------------------------------------------------------
# Feed Manager
# ---------------------------------------------------------------------------

class FeedManager:
    """Orchestrates all threat-intelligence feed instances.

    Manages lifecycle, scheduling, cross-feed deduplication, and statistics
    for every configured feed source.

    Args:
        config: Parsed configuration dict.  Loaded from ``feeds.yaml`` when
            *None*.
    """

    def __init__(self, config: Optional[dict[str, Any]] = None) -> None:
        self._cfg: dict[str, Any] = config or load_config()
        self._log = setup_feed_logger("manager", self._cfg)
        self._feeds: dict[str, BaseFeed] = {}
        self._results: dict[str, FeedProgress] = {}
        self._shutdown: bool = False

        storage_cfg = self._cfg.get("storage", {})
        db_path = resolve_path(
            storage_cfg.get("db_path", "../data/feeds/feed_tracker.db")
        )
        self._tracker = DownloadTracker(db_path)

        self._instantiate_feeds()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _instantiate_feeds(self) -> None:
        """Create feed instances for every enabled feed in the config."""
        feeds_cfg = self._cfg.get("feeds", {})
        for name, cls in _FEED_CLASSES.items():
            section = feeds_cfg.get(name, {})
            if not section.get("enabled", True):
                self._log.info("Feed '%s' is disabled — skipping", name)
                continue
            try:
                self._feeds[name] = cls(self._cfg)
                self._log.debug("Instantiated feed: %s", name)
            except Exception:
                self._log.exception("Failed to instantiate feed '%s'", name)

    @property
    def feed_names(self) -> list[str]:
        """List of active (enabled) feed names."""
        return list(self._feeds.keys())

    def get_feed(self, name: str) -> Optional[BaseFeed]:
        """Retrieve a specific feed instance by name.

        Args:
            name: Feed identifier.

        Returns:
            The :class:`BaseFeed` subclass instance, or *None*.
        """
        return self._feeds.get(name)

    # ------------------------------------------------------------------
    # Run feeds
    # ------------------------------------------------------------------

    async def run_feed(
        self,
        name: str,
        progress_callback: Optional[callable] = None,
    ) -> Optional[FeedProgress]:
        """Execute a single feed sync.

        Args:
            name: Feed identifier.
            progress_callback: Optional progress callback.

        Returns:
            Final progress snapshot, or *None* if the feed is not found.
        """
        feed = self._feeds.get(name)
        if feed is None:
            self._log.error("Unknown or disabled feed: %s", name)
            return None

        self._log.info("Running feed: %s", name)
        try:
            progress = await feed.run(progress_callback)
            self._results[name] = progress
            return progress
        except Exception:
            self._log.exception("Feed '%s' raised an unhandled exception", name)
            return None

    async def run_all(
        self,
        progress_callback: Optional[callable] = None,
    ) -> dict[str, FeedProgress]:
        """Execute all enabled feeds sequentially.

        Feeds are run one at a time to respect aggregate rate limits and to
        provide clear log output.  Use :meth:`run_concurrent` for parallel
        execution.

        Args:
            progress_callback: Optional progress callback applied to each feed.

        Returns:
            Map of feed name → final progress snapshot.
        """
        self._log.info(
            "Starting full feed sync — %d feeds enabled", len(self._feeds)
        )
        results: dict[str, FeedProgress] = {}

        for name in self._feeds:
            if self._shutdown:
                self._log.info("Shutdown requested — aborting remaining feeds")
                break
            result = await self.run_feed(name, progress_callback)
            if result is not None:
                results[name] = result

        self._results.update(results)
        self._log.info("Full feed sync complete — %d feeds processed", len(results))
        return results

    async def run_concurrent(
        self,
        feed_names: Optional[Sequence[str]] = None,
        max_concurrency: int = 3,
        progress_callback: Optional[callable] = None,
    ) -> dict[str, FeedProgress]:
        """Execute feeds concurrently with bounded parallelism.

        Args:
            feed_names: Subset of feeds to run; defaults to all enabled.
            max_concurrency: Maximum simultaneous feed tasks.
            progress_callback: Optional progress callback.

        Returns:
            Map of feed name → final progress.
        """
        names = list(feed_names or self._feeds.keys())
        semaphore = asyncio.Semaphore(max_concurrency)
        results: dict[str, FeedProgress] = {}

        async def _guarded(n: str) -> None:
            async with semaphore:
                if self._shutdown:
                    return
                result = await self.run_feed(n, progress_callback)
                if result is not None:
                    results[n] = result

        tasks = [asyncio.create_task(_guarded(n)) for n in names]
        await asyncio.gather(*tasks, return_exceptions=True)

        self._results.update(results)
        return results

    async def run_scheduled(self) -> None:
        """Run feeds on their configured intervals in a continuous loop.

        Intended for long-running daemon mode.  Respects each feed's
        ``update_interval_hours`` and skips feeds that were recently synced.
        Handles SIGINT / SIGTERM for graceful shutdown.
        """
        self._install_signal_handlers()
        self._log.info("Feed scheduler started — press Ctrl+C to stop")

        while not self._shutdown:
            for name, feed in self._feeds.items():
                if self._shutdown:
                    break

                interval = feed.get_update_interval()
                state = self._tracker.get_feed_state(name)

                if state and state.get("last_success"):
                    try:
                        last = datetime.fromisoformat(state["last_success"])
                        if last.tzinfo is None:
                            last = last.replace(tzinfo=timezone.utc)
                        if datetime.now(timezone.utc) - last < timedelta(seconds=interval):
                            continue
                    except (ValueError, TypeError):
                        pass

                self._log.info("Scheduled run for feed: %s", name)
                await self.run_feed(name)

            # Sleep in small increments so we can detect shutdown promptly
            for _ in range(60):
                if self._shutdown:
                    break
                await asyncio.sleep(1)

        self._log.info("Feed scheduler shut down gracefully")

    def request_shutdown(self) -> None:
        """Signal the manager to stop after the current feed completes."""
        self._shutdown = True
        self._log.info("Shutdown requested")

    def _install_signal_handlers(self) -> None:
        """Install SIGINT/SIGTERM handlers for graceful shutdown."""
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self.request_shutdown)
            except NotImplementedError:
                # Windows doesn't support add_signal_handler — use fallback
                signal.signal(sig, lambda s, f: self.request_shutdown())

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    def deduplicate_hashes(self) -> dict[str, list[str]]:
        """Identify SHA-256 hashes that appear in multiple feeds.

        Returns:
            Mapping of SHA-256 → list of feed names where it was seen.
        """
        hash_feeds: dict[str, list[str]] = {}
        for name in self._feeds:
            for h in self._tracker.get_all_hashes(feed=name):
                hash_feeds.setdefault(h, []).append(name)

        duplicates = {h: feeds for h, feeds in hash_feeds.items() if len(feeds) > 1}
        self._log.info(
            "Deduplication: %d unique hashes, %d appear in multiple feeds",
            len(hash_feeds),
            len(duplicates),
        )
        return duplicates

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_statistics(self) -> dict[str, Any]:
        """Compile aggregate statistics across all feeds.

        Returns:
            Dictionary of stats including totals, per-feed counts, top
            malware families, and recent activity.
        """
        today_iso = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        ).isoformat()

        per_feed: dict[str, dict[str, int]] = {}
        for name in self._feeds:
            per_feed[name] = {
                "downloads": self._tracker.count_downloads(feed=name),
                "iocs": self._tracker.count_iocs(feed=name),
            }

        top_malware = self._tracker.stats_by_malware()[:25]

        stats: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_downloads": self._tracker.count_downloads(),
            "total_iocs": self._tracker.count_iocs(),
            "new_today": self._tracker.downloads_since(today_iso),
            "per_feed": per_feed,
            "top_malware_families": [
                {"family": fam, "count": cnt} for fam, cnt in top_malware
            ],
            "enabled_feeds": list(self._feeds.keys()),
        }

        return stats

    def print_statistics(self) -> None:
        """Print human-readable statistics to stdout."""
        stats = self.get_statistics()
        print("\n" + "=" * 60)
        print("  ShadowStrike PhantomCortex — Feed Statistics")
        print("=" * 60)
        print(f"  Timestamp:        {stats['timestamp']}")
        print(f"  Total Downloads:  {stats['total_downloads']:,}")
        print(f"  Total IOCs:       {stats['total_iocs']:,}")
        print(f"  New Today:        {stats['new_today']:,}")
        print(f"  Enabled Feeds:    {', '.join(stats['enabled_feeds'])}")
        print()

        if stats["per_feed"]:
            print("  Per-Feed Breakdown:")
            for name, counts in stats["per_feed"].items():
                print(f"    {name:20s}  downloads={counts['downloads']:>7,}  iocs={counts['iocs']:>7,}")

        if stats["top_malware_families"]:
            print()
            print("  Top Malware Families:")
            for entry in stats["top_malware_families"][:15]:
                print(f"    {entry['family']:30s}  {entry['count']:>7,}")

        print("=" * 60 + "\n")

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    async def export_combined_dataset(
        self, output_path: Optional[Path] = None
    ) -> Path:
        """Export a combined JSON dataset of all ingested data.

        Merges downloads and IOCs from all feeds into a single file suitable
        for the feature-extraction pipeline.

        Args:
            output_path: Destination path.  Defaults to
                ``data/feeds/combined_dataset.json``.

        Returns:
            Path to the written file.
        """
        if output_path is None:
            storage = self._cfg.get("storage", {})
            feed_dir = resolve_path(storage.get("feed_cache_dir", "../data/feeds"))
            output_path = feed_dir / "combined_dataset.json"

        output_path.parent.mkdir(parents=True, exist_ok=True)

        all_hashes = self._tracker.get_all_hashes()
        dedup = self.deduplicate_hashes()
        stats = self.get_statistics()

        dataset: dict[str, Any] = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "statistics": stats,
            "unique_hashes": len(all_hashes),
            "multi_source_hashes": len(dedup),
            "hashes": sorted(all_hashes),
            "multi_source": {h: feeds for h, feeds in sorted(dedup.items())},
        }

        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(dataset, fh, indent=2, default=str)

        self._log.info(
            "Exported combined dataset → %s (%d hashes)",
            output_path,
            len(all_hashes),
        )
        return output_path

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    async def close_all(self) -> None:
        """Close all feed HTTP sessions."""
        for feed in self._feeds.values():
            try:
                await feed.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser for the CLI entry-point."""
    parser = argparse.ArgumentParser(
        prog="feed_manager",
        description="ShadowStrike PhantomCortex — Threat Feed Manager",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to feeds.yaml configuration file",
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--run-all",
        action="store_true",
        help="Run all enabled feeds sequentially",
    )
    group.add_argument(
        "--run-concurrent",
        action="store_true",
        help="Run all enabled feeds concurrently",
    )
    group.add_argument(
        "--feed",
        type=str,
        metavar="NAME",
        help="Run a single feed by name",
    )
    group.add_argument(
        "--scheduled",
        action="store_true",
        help="Run feeds continuously on their configured intervals",
    )
    group.add_argument(
        "--stats",
        action="store_true",
        help="Print aggregate statistics and exit",
    )
    group.add_argument(
        "--export",
        type=Path,
        metavar="PATH",
        nargs="?",
        const=Path(""),
        help="Export combined dataset to a JSON file",
    )
    group.add_argument(
        "--list-feeds",
        action="store_true",
        help="List all configured feeds and their status",
    )

    parser.add_argument(
        "--concurrency",
        type=int,
        default=3,
        help="Max concurrent feeds (for --run-concurrent)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable debug-level logging",
    )

    return parser


def _progress_printer(progress: FeedProgress) -> None:
    """Default progress callback that prints to stderr."""
    pct = progress.percent
    sys.stderr.write(
        f"\r  [{progress.feed_name}] {pct:5.1f}%  "
        f"new={progress.new_items} skip={progress.skipped} err={progress.errors} "
        f"({progress.processed}/{progress.total})      "
    )
    sys.stderr.flush()


async def _async_main(args: argparse.Namespace) -> int:
    """Async entry-point dispatching CLI sub-commands.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Exit code (0 for success).
    """
    cfg = load_config(args.config) if args.config else load_config()

    if args.verbose:
        cfg.setdefault("logging", {})["level"] = "DEBUG"

    mgr = FeedManager(cfg)

    try:
        if args.run_all:
            results = await mgr.run_all(progress_callback=_progress_printer)
            print()
            for name, prog in results.items():
                print(
                    f"  {name:20s}  new={prog.new_items:>5}  "
                    f"skip={prog.skipped:>5}  err={prog.errors:>3}  "
                    f"time={prog.elapsed_seconds:.1f}s"
                )

        elif args.run_concurrent:
            results = await mgr.run_concurrent(
                max_concurrency=args.concurrency,
                progress_callback=_progress_printer,
            )
            print()
            for name, prog in results.items():
                print(
                    f"  {name:20s}  new={prog.new_items:>5}  "
                    f"skip={prog.skipped:>5}  err={prog.errors:>3}  "
                    f"time={prog.elapsed_seconds:.1f}s"
                )

        elif args.feed:
            result = await mgr.run_feed(args.feed, progress_callback=_progress_printer)
            print()
            if result:
                print(
                    f"  {args.feed}: new={result.new_items}, "
                    f"skip={result.skipped}, err={result.errors}, "
                    f"time={result.elapsed_seconds:.1f}s"
                )
            else:
                print(f"  Feed '{args.feed}' not found or disabled.")
                return 1

        elif args.scheduled:
            await mgr.run_scheduled()

        elif args.stats:
            mgr.print_statistics()

        elif args.export is not None:
            out = args.export if str(args.export) else None
            path = await mgr.export_combined_dataset(out if out else None)
            print(f"  Exported → {path}")

        elif args.list_feeds:
            feeds_cfg = cfg.get("feeds", {})
            print("\n  Configured Feeds:")
            for name, section in feeds_cfg.items():
                enabled = section.get("enabled", True)
                interval = section.get("update_interval_hours", "n/a")
                status = "enabled" if enabled else "DISABLED"
                print(f"    {name:20s}  [{status:>8s}]  interval={interval}h")
            print()

    finally:
        await mgr.close_all()

    return 0


def main() -> None:
    """Synchronous CLI entry-point."""
    parser = _build_parser()
    args = parser.parse_args()
    exit_code = asyncio.run(_async_main(args))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
