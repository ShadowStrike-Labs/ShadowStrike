"""
ShadowStrike PhantomCortex — Threat Feed Base Module

Abstract base class providing common infrastructure for all threat feed
downloaders: retry logic with exponential backoff, token-bucket rate limiting,
SQLite-backed download tracking, SHA-256 verification, structured logging,
and progress reporting.

This module is the foundation of the feed ingestion pipeline that feeds
training data into PhantomCortex's ML models.
"""

from __future__ import annotations

import abc
import asyncio
import hashlib
import logging
import os
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional, Sequence

import aiohttp
import yaml

# ---------------------------------------------------------------------------
# Configuration loader
# ---------------------------------------------------------------------------

_CONFIG_CACHE: dict[str, Any] = {}


def load_config(config_path: Optional[Path] = None) -> dict[str, Any]:
    """Load and cache the feeds.yaml configuration.

    Args:
        config_path: Explicit path to feeds.yaml.  When *None* the default
            location ``PhantomCortex/training/config/feeds.yaml`` relative to
            this file is used.

    Returns:
        Parsed configuration dictionary.

    Raises:
        FileNotFoundError: If the config file does not exist.
        yaml.YAMLError: If the YAML is malformed.
    """
    if config_path is None:
        config_path = Path(__file__).resolve().parent.parent / "config" / "feeds.yaml"

    key = str(config_path)
    if key in _CONFIG_CACHE:
        return _CONFIG_CACHE[key]

    if not config_path.exists():
        raise FileNotFoundError(f"Feed config not found: {config_path}")

    with open(config_path, "r", encoding="utf-8") as fh:
        cfg: dict[str, Any] = yaml.safe_load(fh)

    _CONFIG_CACHE[key] = cfg
    return cfg


def resolve_path(relative: str, anchor: Optional[Path] = None) -> Path:
    """Resolve a path from config relative to the training directory.

    Args:
        relative: The path string from configuration (may be relative).
        anchor: Base directory.  Defaults to ``training/``.

    Returns:
        Resolved absolute ``Path``.
    """
    if anchor is None:
        anchor = Path(__file__).resolve().parent.parent
    p = Path(relative)
    if not p.is_absolute():
        p = (anchor / p).resolve()
    return p


# ---------------------------------------------------------------------------
# Structured logging helpers
# ---------------------------------------------------------------------------

def setup_feed_logger(
    name: str,
    cfg: dict[str, Any],
) -> logging.Logger:
    """Create a logger that writes to both console and a rotating log file.

    Args:
        name: Logger name (typically the feed name).
        cfg: Full config dict (uses the ``logging`` section).

    Returns:
        Configured ``logging.Logger``.
    """
    log_cfg = cfg.get("logging", {})
    level_name: str = log_cfg.get("level", "INFO")
    log_file: Optional[str] = log_cfg.get("file")
    fmt: str = log_cfg.get("format", "%(asctime)s [%(name)s] %(levelname)s %(message)s")
    rotate_mb: int = log_cfg.get("rotate_mb", 100)

    logger = logging.getLogger(f"phantomcortex.feeds.{name}")
    if logger.handlers:
        return logger

    logger.setLevel(getattr(logging, level_name.upper(), logging.INFO))
    formatter = logging.Formatter(fmt)

    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(console)

    if log_file:
        log_path = resolve_path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        from logging.handlers import RotatingFileHandler
        fh = RotatingFileHandler(
            str(log_path),
            maxBytes=rotate_mb * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    return logger


# ---------------------------------------------------------------------------
# Token-bucket rate limiter (async)
# ---------------------------------------------------------------------------

class AsyncRateLimiter:
    """Async token-bucket rate limiter.

    Enforces a maximum number of requests per minute by sleeping the
    caller when the bucket is exhausted.

    Args:
        requests_per_minute: Maximum allowed requests in a 60-second window.
    """

    def __init__(self, requests_per_minute: int) -> None:
        self._rpm: int = max(1, requests_per_minute)
        self._interval: float = 60.0 / self._rpm
        self._lock: asyncio.Lock = asyncio.Lock()
        self._last: float = 0.0

    async def acquire(self) -> None:
        """Wait until a request slot is available."""
        async with self._lock:
            now = time.monotonic()
            wait = self._interval - (now - self._last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()


# ---------------------------------------------------------------------------
# Download tracker — SQLite persistence
# ---------------------------------------------------------------------------

class DownloadTracker:
    """SQLite-backed registry of previously downloaded artefacts.

    Provides deduplication and incremental download support by recording
    every fetched hash/IOC with metadata and timestamps.

    Args:
        db_path: Path to the SQLite database file.
    """

    _DDL: str = """
    CREATE TABLE IF NOT EXISTS downloads (
        sha256        TEXT NOT NULL,
        feed          TEXT NOT NULL,
        fetched_at    TEXT NOT NULL,
        file_type     TEXT,
        signature     TEXT,
        tags          TEXT,
        malware       TEXT,
        reporter      TEXT,
        first_seen    TEXT,
        extra_json    TEXT,
        PRIMARY KEY (sha256, feed)
    );

    CREATE TABLE IF NOT EXISTS iocs (
        ioc_value     TEXT NOT NULL,
        ioc_type      TEXT NOT NULL,
        feed          TEXT NOT NULL,
        fetched_at    TEXT NOT NULL,
        threat_type   TEXT,
        malware       TEXT,
        confidence    INTEGER,
        tags          TEXT,
        extra_json    TEXT,
        PRIMARY KEY (ioc_value, ioc_type, feed)
    );

    CREATE TABLE IF NOT EXISTS feed_state (
        feed          TEXT PRIMARY KEY,
        last_run      TEXT,
        last_success  TEXT,
        cursor        TEXT,
        extra_json    TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_downloads_feed ON downloads(feed);
    CREATE INDEX IF NOT EXISTS idx_downloads_fetched ON downloads(fetched_at);
    CREATE INDEX IF NOT EXISTS idx_iocs_feed ON iocs(feed);
    CREATE INDEX IF NOT EXISTS idx_iocs_malware ON iocs(malware);
    """

    def __init__(self, db_path: Path) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db_path = db_path
        self._local = __import__("threading").local()
        self._init_schema()

    def _get_conn(self) -> sqlite3.Connection:
        """Return a per-thread connection (thread-safe access)."""
        conn: Optional[sqlite3.Connection] = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(str(self._db_path), timeout=30)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    def _init_schema(self) -> None:
        conn = self._get_conn()
        conn.executescript(self._DDL)
        conn.commit()

    # -- downloads ----------------------------------------------------------

    def has_download(self, sha256: str, feed: str) -> bool:
        """Check if a hash has already been downloaded for a given feed."""
        row = self._get_conn().execute(
            "SELECT 1 FROM downloads WHERE sha256=? AND feed=?",
            (sha256.lower(), feed),
        ).fetchone()
        return row is not None

    def record_download(
        self,
        sha256: str,
        feed: str,
        *,
        file_type: str = "",
        signature: str = "",
        tags: str = "",
        malware: str = "",
        reporter: str = "",
        first_seen: str = "",
        extra_json: str = "",
    ) -> None:
        """Insert or update a download record."""
        conn = self._get_conn()
        conn.execute(
            """INSERT OR REPLACE INTO downloads
               (sha256,feed,fetched_at,file_type,signature,tags,malware,reporter,first_seen,extra_json)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                sha256.lower(),
                feed,
                datetime.now(timezone.utc).isoformat(),
                file_type,
                signature,
                tags,
                malware,
                reporter,
                first_seen,
                extra_json,
            ),
        )
        conn.commit()

    def count_downloads(self, feed: Optional[str] = None) -> int:
        """Count downloads, optionally filtered by feed."""
        conn = self._get_conn()
        if feed:
            row = conn.execute(
                "SELECT COUNT(*) FROM downloads WHERE feed=?", (feed,)
            ).fetchone()
        else:
            row = conn.execute("SELECT COUNT(*) FROM downloads").fetchone()
        return int(row[0]) if row else 0

    def get_all_hashes(self, feed: Optional[str] = None) -> set[str]:
        """Return the set of all known SHA-256 hashes."""
        conn = self._get_conn()
        if feed:
            rows = conn.execute(
                "SELECT sha256 FROM downloads WHERE feed=?", (feed,)
            ).fetchall()
        else:
            rows = conn.execute("SELECT DISTINCT sha256 FROM downloads").fetchall()
        return {r[0] for r in rows}

    # -- IOCs ---------------------------------------------------------------

    def has_ioc(self, ioc_value: str, ioc_type: str, feed: str) -> bool:
        """Check whether an IOC has been recorded."""
        row = self._get_conn().execute(
            "SELECT 1 FROM iocs WHERE ioc_value=? AND ioc_type=? AND feed=?",
            (ioc_value, ioc_type, feed),
        ).fetchone()
        return row is not None

    def record_ioc(
        self,
        ioc_value: str,
        ioc_type: str,
        feed: str,
        *,
        threat_type: str = "",
        malware: str = "",
        confidence: int = 0,
        tags: str = "",
        extra_json: str = "",
    ) -> None:
        """Insert or update an IOC record."""
        conn = self._get_conn()
        conn.execute(
            """INSERT OR REPLACE INTO iocs
               (ioc_value,ioc_type,feed,fetched_at,threat_type,malware,confidence,tags,extra_json)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                ioc_value,
                ioc_type,
                feed,
                datetime.now(timezone.utc).isoformat(),
                threat_type,
                malware,
                confidence,
                tags,
                extra_json,
            ),
        )
        conn.commit()

    def count_iocs(self, feed: Optional[str] = None) -> int:
        """Count IOC records, optionally filtered by feed."""
        conn = self._get_conn()
        if feed:
            row = conn.execute(
                "SELECT COUNT(*) FROM iocs WHERE feed=?", (feed,)
            ).fetchone()
        else:
            row = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()
        return int(row[0]) if row else 0

    # -- feed state ---------------------------------------------------------

    def get_feed_state(self, feed: str) -> Optional[dict[str, Any]]:
        """Retrieve persisted state for a feed (cursor, last run, etc.)."""
        row = self._get_conn().execute(
            "SELECT * FROM feed_state WHERE feed=?", (feed,)
        ).fetchone()
        if row is None:
            return None
        return dict(row)

    def set_feed_state(
        self,
        feed: str,
        *,
        last_run: Optional[str] = None,
        last_success: Optional[str] = None,
        cursor: Optional[str] = None,
        extra_json: Optional[str] = None,
    ) -> None:
        """Upsert feed-level state."""
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO feed_state (feed, last_run, last_success, cursor, extra_json)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(feed) DO UPDATE SET
                 last_run    = COALESCE(excluded.last_run, feed_state.last_run),
                 last_success= COALESCE(excluded.last_success, feed_state.last_success),
                 cursor      = COALESCE(excluded.cursor, feed_state.cursor),
                 extra_json  = COALESCE(excluded.extra_json, feed_state.extra_json)""",
            (feed, last_run, last_success, cursor, extra_json),
        )
        conn.commit()

    # -- statistics ---------------------------------------------------------

    def stats_by_malware(self) -> list[tuple[str, int]]:
        """Return download counts grouped by malware family."""
        rows = self._get_conn().execute(
            "SELECT malware, COUNT(*) FROM downloads WHERE malware != '' "
            "GROUP BY malware ORDER BY COUNT(*) DESC"
        ).fetchall()
        return [(r[0], r[1]) for r in rows]

    def downloads_since(self, since_iso: str) -> int:
        """Count downloads after a given ISO timestamp."""
        row = self._get_conn().execute(
            "SELECT COUNT(*) FROM downloads WHERE fetched_at >= ?", (since_iso,)
        ).fetchone()
        return int(row[0]) if row else 0


# ---------------------------------------------------------------------------
# Progress reporting
# ---------------------------------------------------------------------------

@dataclass
class FeedProgress:
    """Tracks progress for a single feed run."""
    feed_name: str
    total: int = 0
    processed: int = 0
    new_items: int = 0
    skipped: int = 0
    errors: int = 0
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    _callbacks: list[Callable[["FeedProgress"], None]] = field(
        default_factory=list, repr=False
    )

    def add_callback(self, cb: Callable[["FeedProgress"], None]) -> None:
        """Register a progress callback."""
        self._callbacks.append(cb)

    def advance(self, *, new: int = 0, skipped: int = 0, errors: int = 0) -> None:
        """Advance counters and fire callbacks."""
        self.processed += new + skipped + errors
        self.new_items += new
        self.skipped += skipped
        self.errors += errors
        for cb in self._callbacks:
            cb(self)

    @property
    def elapsed_seconds(self) -> float:
        return (datetime.now(timezone.utc) - self.started_at).total_seconds()

    @property
    def percent(self) -> float:
        if self.total <= 0:
            return 0.0
        return min(100.0, (self.processed / self.total) * 100.0)


# ---------------------------------------------------------------------------
# Abstract base feed
# ---------------------------------------------------------------------------

class BaseFeed(abc.ABC):
    """Abstract base class for all PhantomCortex threat-intelligence feeds.

    Subclasses must implement:
        - :meth:`get_feed_name`
        - :meth:`get_update_interval`
        - :meth:`fetch_new`

    Provides retry with exponential back-off, async rate limiting, SQLite
    download tracking, SHA-256 verification, and structured logging out of
    the box.
    """

    def __init__(self, config: Optional[dict[str, Any]] = None) -> None:
        self._cfg: dict[str, Any] = config or load_config()
        self._feed_cfg: dict[str, Any] = self._cfg.get("feeds", {}).get(
            self.get_feed_name(), {}
        )

        retry_cfg = self._cfg.get("retry", {})
        self._max_retries: int = retry_cfg.get("max_retries", 3)
        self._base_delay: float = retry_cfg.get("base_delay_seconds", 2.0)
        self._max_delay: float = retry_cfg.get("max_delay_seconds", 60.0)
        self._backoff_factor: float = retry_cfg.get("backoff_factor", 2.0)

        net_cfg = self._cfg.get("network", {})
        self._request_timeout: int = net_cfg.get("request_timeout_seconds", 30)
        self._download_timeout: int = net_cfg.get("download_timeout_seconds", 300)
        self._user_agent: str = net_cfg.get(
            "user_agent", "ShadowStrike-PhantomCortex/1.0"
        )
        self._verify_ssl: bool = net_cfg.get("verify_ssl", True)

        storage_cfg = self._cfg.get("storage", {})
        self._data_dir = resolve_path(storage_cfg.get("data_dir", "../data"))
        self._raw_dir = resolve_path(storage_cfg.get("raw_samples_dir", "../data/raw"))
        self._feed_dir = resolve_path(
            storage_cfg.get("feed_cache_dir", "../data/feeds")
        )
        self._processed_dir = resolve_path(
            storage_cfg.get("processed_dir", "../data/processed")
        )
        db_path = resolve_path(storage_cfg.get("db_path", "../data/feeds/feed_tracker.db"))

        for d in (self._data_dir, self._raw_dir, self._feed_dir, self._processed_dir):
            d.mkdir(parents=True, exist_ok=True)

        self._tracker = DownloadTracker(db_path)

        rpm = self._feed_cfg.get("rate_limit_rpm", 60)
        self._limiter = AsyncRateLimiter(rpm)

        self._log = setup_feed_logger(self.get_feed_name(), self._cfg)

        self._session: Optional[aiohttp.ClientSession] = None

    # -- Abstract interface -------------------------------------------------

    @abc.abstractmethod
    def get_feed_name(self) -> str:
        """Return a short, unique identifier for this feed."""

    @abc.abstractmethod
    def get_update_interval(self) -> int:
        """Return the recommended update interval in seconds."""

    @abc.abstractmethod
    async def fetch_new(self, progress: FeedProgress) -> int:
        """Fetch new items from the feed.

        Args:
            progress: Mutable progress tracker.

        Returns:
            Number of new items ingested.
        """

    # -- HTTP session management --------------------------------------------

    async def _ensure_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(
                total=self._download_timeout,
                sock_read=self._request_timeout,
            )
            connector = aiohttp.TCPConnector(
                limit=10,
                ssl=self._verify_ssl if self._verify_ssl else False,
            )
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers={"User-Agent": self._user_agent},
            )
        return self._session

    async def close(self) -> None:
        """Close the underlying HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    # -- Retry + backoff ----------------------------------------------------

    async def _request_with_retry(
        self,
        method: str,
        url: str,
        *,
        json_body: Optional[dict[str, Any]] = None,
        params: Optional[dict[str, str]] = None,
        headers: Optional[dict[str, str]] = None,
        raw_response: bool = False,
    ) -> Any:
        """Issue an HTTP request with retries and exponential back-off.

        Args:
            method: HTTP method (``GET``, ``POST``, …).
            url: Target URL.
            json_body: Optional JSON body for POST requests.
            params: Optional query parameters.
            headers: Extra headers merged with session defaults.
            raw_response: If *True*, return the raw ``aiohttp.ClientResponse``
                (caller is responsible for reading/closing it).

        Returns:
            Parsed JSON (default) or the raw response object.

        Raises:
            aiohttp.ClientError: After exhausting all retries.
        """
        session = await self._ensure_session()
        last_exc: Optional[Exception] = None

        for attempt in range(self._max_retries + 1):
            await self._limiter.acquire()
            try:
                kwargs: dict[str, Any] = {}
                if json_body is not None:
                    kwargs["json"] = json_body
                if params is not None:
                    kwargs["params"] = params
                if headers is not None:
                    kwargs["headers"] = headers

                resp = await session.request(method, url, **kwargs)

                if resp.status == 429:
                    retry_after = int(resp.headers.get("Retry-After", "60"))
                    self._log.warning(
                        "Rate-limited (429) on %s — sleeping %ds (attempt %d/%d)",
                        url, retry_after, attempt + 1, self._max_retries + 1,
                    )
                    await resp.release()
                    await asyncio.sleep(retry_after)
                    continue

                if resp.status >= 500:
                    body = await resp.text()
                    self._log.warning(
                        "Server error %d on %s — %s (attempt %d/%d)",
                        resp.status, url, body[:200], attempt + 1, self._max_retries + 1,
                    )
                    await resp.release()
                    raise aiohttp.ClientResponseError(
                        resp.request_info,
                        resp.history,
                        status=resp.status,
                        message=body[:200],
                    )

                resp.raise_for_status()

                if raw_response:
                    return resp
                return await resp.json(content_type=None)

            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                last_exc = exc
                if attempt < self._max_retries:
                    delay = min(
                        self._base_delay * (self._backoff_factor ** attempt),
                        self._max_delay,
                    )
                    self._log.warning(
                        "Request to %s failed (%s) — retrying in %.1fs (attempt %d/%d)",
                        url, exc, delay, attempt + 1, self._max_retries + 1,
                    )
                    await asyncio.sleep(delay)

        self._log.error("All %d retries exhausted for %s", self._max_retries + 1, url)
        raise last_exc  # type: ignore[misc]

    # -- Convenience HTTP helpers -------------------------------------------

    async def _get_json(
        self, url: str, *, params: Optional[dict[str, str]] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> Any:
        """Shorthand for a GET request returning JSON."""
        return await self._request_with_retry(
            "GET", url, params=params, headers=headers,
        )

    async def _post_json(
        self, url: str, body: dict[str, Any], *,
        headers: Optional[dict[str, str]] = None,
    ) -> Any:
        """Shorthand for a POST request returning JSON."""
        return await self._request_with_retry(
            "POST", url, json_body=body, headers=headers,
        )

    # -- Download + hash verification ---------------------------------------

    async def _download_file(
        self,
        url: str,
        dest: Path,
        *,
        expected_sha256: Optional[str] = None,
        chunk_size: int = 65_536,
    ) -> str:
        """Stream-download a file to disk with optional SHA-256 verification.

        Args:
            url: URL to download.
            dest: Destination file path.
            expected_sha256: If provided, the file's SHA-256 must match.
            chunk_size: Read chunk size in bytes.

        Returns:
            The computed SHA-256 hex digest of the file.

        Raises:
            ValueError: If the SHA-256 does not match the expected value.
            aiohttp.ClientError: On network errors after retries.
        """
        dest.parent.mkdir(parents=True, exist_ok=True)
        resp = await self._request_with_retry("GET", url, raw_response=True)

        sha = hashlib.sha256()
        try:
            with open(dest, "wb") as fh:
                async for chunk in resp.content.iter_chunked(chunk_size):
                    fh.write(chunk)
                    sha.update(chunk)
        finally:
            resp.release()

        digest = sha.hexdigest()

        if expected_sha256 and digest.lower() != expected_sha256.lower():
            dest.unlink(missing_ok=True)
            raise ValueError(
                f"SHA-256 mismatch for {url}: expected {expected_sha256}, got {digest}"
            )

        return digest

    @staticmethod
    def verify_sha256(path: Path, expected: str) -> bool:
        """Verify that a file on disk matches an expected SHA-256 digest.

        Args:
            path: File to check.
            expected: Expected lowercase hex digest.

        Returns:
            ``True`` if the digest matches.
        """
        sha = hashlib.sha256()
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(65_536)
                if not chunk:
                    break
                sha.update(chunk)
        return sha.hexdigest().lower() == expected.lower()

    # -- High-level run interface -------------------------------------------

    async def run(
        self,
        progress_callback: Optional[Callable[[FeedProgress], None]] = None,
    ) -> FeedProgress:
        """Execute a full feed-sync cycle.

        Args:
            progress_callback: Optional callable invoked on every progress tick.

        Returns:
            Final :class:`FeedProgress` snapshot.
        """
        progress = FeedProgress(feed_name=self.get_feed_name())
        if progress_callback:
            progress.add_callback(progress_callback)

        self._log.info("Starting feed sync: %s", self.get_feed_name())
        self._tracker.set_feed_state(
            self.get_feed_name(),
            last_run=datetime.now(timezone.utc).isoformat(),
        )

        try:
            new_count = await self.fetch_new(progress)
            self._tracker.set_feed_state(
                self.get_feed_name(),
                last_success=datetime.now(timezone.utc).isoformat(),
            )
            self._log.info(
                "Feed sync complete: %s — %d new, %d skipped, %d errors in %.1fs",
                self.get_feed_name(),
                progress.new_items,
                progress.skipped,
                progress.errors,
                progress.elapsed_seconds,
            )
        except Exception:
            self._log.exception("Feed sync failed: %s", self.get_feed_name())
            raise
        finally:
            await self.close()

        return progress

    # -- Utility ------------------------------------------------------------

    @property
    def tracker(self) -> DownloadTracker:
        """Access the shared download tracker."""
        return self._tracker

    @property
    def feed_config(self) -> dict[str, Any]:
        """Access feed-specific configuration section."""
        return self._feed_cfg

    @property
    def enabled(self) -> bool:
        """Whether this feed is enabled in configuration."""
        return bool(self._feed_cfg.get("enabled", True))
