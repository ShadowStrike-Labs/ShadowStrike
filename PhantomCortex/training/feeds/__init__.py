"""
ShadowStrike PhantomCortex — Threat Feed Ingestion Package

Exports all feed classes and the :class:`FeedManager` orchestrator for
convenient programmatic access::

    from PhantomCortex.training.feeds import FeedManager, MalwareBazaarFeed

Run the manager from the command line::

    python -m PhantomCortex.training.feeds.feed_manager --run-all
"""

from .base_feed import (
    AsyncRateLimiter,
    BaseFeed,
    DownloadTracker,
    FeedProgress,
    load_config,
    resolve_path,
    setup_feed_logger,
)
from .ember_sync import EmberSyncFeed
from .feodo_tracker import FeodoTrackerFeed
from .feed_manager import FeedManager
from .malwarebazaar import MalwareBazaarFeed
from .otx_alienvault import OTXAlienVaultFeed
from .threatfox import ThreatFoxFeed
from .urlhaus import URLhausFeed

__all__: list[str] = [
    # Base infrastructure
    "BaseFeed",
    "AsyncRateLimiter",
    "DownloadTracker",
    "FeedProgress",
    "load_config",
    "resolve_path",
    "setup_feed_logger",
    # Feeds
    "MalwareBazaarFeed",
    "ThreatFoxFeed",
    "OTXAlienVaultFeed",
    "URLhausFeed",
    "EmberSyncFeed",
    "FeodoTrackerFeed",
    # Orchestrator
    "FeedManager",
]
