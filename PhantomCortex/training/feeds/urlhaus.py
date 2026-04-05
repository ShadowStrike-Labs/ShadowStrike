"""
ShadowStrike PhantomCortex — URLhaus Feed

Ingests malicious URL and payload data from URLhaus (abuse.ch).
Collects active malicious URLs, their associated payloads, and tags.
Downloads payload samples by SHA-256 when configured.

API Reference: https://urlhaus.abuse.ch/api/
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .base_feed import BaseFeed, FeedProgress


class URLhausFeed(BaseFeed):
    """URLhaus malicious URL and payload feed.

    Tracks malicious distribution URLs and their payload hashes, downloads
    payload samples when available.
    """

    def get_feed_name(self) -> str:  # noqa: D401
        """Unique feed identifier."""
        return "urlhaus"

    def get_update_interval(self) -> int:
        """Recommended polling interval in seconds."""
        hours: int = self._feed_cfg.get("update_interval_hours", 2)
        return hours * 3600

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def fetch_new(self, progress: FeedProgress) -> int:
        """Ingest recent URLhaus URLs and payloads.

        Fetches recent malicious URLs and their associated payload metadata.
        Records each unique URL/payload as an IOC and optionally downloads
        the payload sample.

        Args:
            progress: Mutable progress tracker.

        Returns:
            Total number of newly ingested items.
        """
        api_url: str = self._feed_cfg.get(
            "api_url", "https://urlhaus-api.abuse.ch/v1/"
        ).rstrip("/")
        max_urls: int = self._feed_cfg.get("max_urls_per_run", 2000)

        self._log.info("Querying URLhaus for recent URLs and payloads")

        new_count = 0

        # --- Recent URLs ---
        urls_data = await self._fetch_recent_urls(api_url)
        url_items = urls_data[:max_urls] if urls_data else []
        progress.total = len(url_items)

        for entry in url_items:
            url_value: str = entry.get("url", "").strip()
            if not url_value:
                progress.advance(errors=1)
                continue

            if self._tracker.has_ioc(url_value, "url", self.get_feed_name()):
                progress.advance(skipped=1)
                continue

            tags_raw = entry.get("tags") or []
            tags_str = ",".join(str(t) for t in tags_raw if t) if tags_raw else ""
            threat_str: str = entry.get("threat", "") or ""

            self._tracker.record_ioc(
                url_value,
                "url",
                self.get_feed_name(),
                threat_type=entry.get("url_status", ""),
                malware=threat_str,
                confidence=0,
                tags=tags_str,
                extra_json=json.dumps(
                    {
                        "urlhaus_id": entry.get("id", ""),
                        "host": entry.get("host", ""),
                        "date_added": entry.get("date_added", ""),
                        "reporter": entry.get("reporter", ""),
                        "url_status": entry.get("url_status", ""),
                    },
                    separators=(",", ":"),
                ),
            )
            new_count += 1
            progress.advance(new=1)

        # --- Recent Payloads ---
        payloads_data = await self._fetch_recent_payloads(api_url)
        if payloads_data:
            payload_new = await self._process_payloads(api_url, payloads_data, progress)
            new_count += payload_new

        self._log.info(
            "URLhaus run complete — %d new items, %d skipped, %d errors",
            progress.new_items,
            progress.skipped,
            progress.errors,
        )

        await self._save_feed_snapshot(url_items, payloads_data or [])
        return new_count

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _fetch_recent_urls(self, api_url: str) -> list[dict[str, Any]]:
        """Query recently added URLs.

        Args:
            api_url: URLhaus API base URL.

        Returns:
            List of URL metadata dicts.
        """
        url = f"{api_url}/urls/recent/"
        try:
            resp = await self._get_json(url)
        except Exception:
            self._log.exception("Failed to fetch recent URLs from URLhaus")
            return []

        urls = resp.get("urls", []) if isinstance(resp, dict) else []
        self._log.info("URLhaus returned %d recent URLs", len(urls))
        return urls

    async def _fetch_recent_payloads(self, api_url: str) -> list[dict[str, Any]]:
        """Query recently observed payloads.

        Args:
            api_url: URLhaus API base URL.

        Returns:
            List of payload metadata dicts.
        """
        url = f"{api_url}/payloads/recent/"
        try:
            resp = await self._get_json(url)
        except Exception:
            self._log.exception("Failed to fetch recent payloads from URLhaus")
            return []

        payloads = resp.get("payloads", []) if isinstance(resp, dict) else []
        self._log.info("URLhaus returned %d recent payloads", len(payloads))
        return payloads

    async def _process_payloads(
        self,
        api_url: str,
        payloads: list[dict[str, Any]],
        progress: FeedProgress,
    ) -> int:
        """Process payload entries: record metadata and optionally download.

        Args:
            api_url: URLhaus API base URL.
            payloads: List of payload metadata dicts.
            progress: Mutable progress tracker.

        Returns:
            Count of newly processed payloads.
        """
        new_count = 0
        progress.total += len(payloads)

        for payload in payloads:
            sha256: str = (payload.get("sha256_hash") or "").lower()
            if not sha256 or len(sha256) != 64:
                progress.advance(errors=1)
                continue

            if self._tracker.has_download(sha256, self.get_feed_name()):
                progress.advance(skipped=1)
                continue

            tags_list = payload.get("tags") or []
            tags_str = ",".join(str(t) for t in tags_list if t) if tags_list else ""
            file_type: str = payload.get("file_type", "") or ""
            signature: str = payload.get("signature") or ""

            self._tracker.record_download(
                sha256,
                self.get_feed_name(),
                file_type=file_type,
                signature=signature,
                tags=tags_str,
                malware=signature,
                first_seen=payload.get("firstseen", ""),
                extra_json=json.dumps(
                    {
                        "md5": payload.get("md5_hash", ""),
                        "content_type": payload.get("content_type", ""),
                        "urlcount": payload.get("urlcount", 0),
                        "urls": [
                            u.get("url", "") for u in (payload.get("urls") or [])[:5]
                        ],
                    },
                    separators=(",", ":"),
                ),
            )

            # Also record the hash as an IOC
            self._tracker.record_ioc(
                sha256,
                "sha256",
                self.get_feed_name(),
                threat_type="payload",
                malware=signature,
                tags=tags_str,
            )

            # Download the payload sample
            await self._download_payload(api_url, sha256)

            new_count += 1
            progress.advance(new=1)
            self._log.debug(
                "Ingested payload %s (%s / %s)", sha256[:16], file_type, signature
            )

        return new_count

    async def _download_payload(self, api_url: str, sha256: str) -> Optional[Path]:
        """Download a payload sample by SHA-256.

        Args:
            api_url: URLhaus API base URL.
            sha256: SHA-256 of the payload to download.

        Returns:
            Path to the downloaded file, or *None* on failure.
        """
        dest = self._raw_dir / f"{sha256}.bin"
        if dest.exists():
            return dest

        download_url = f"https://mb-api.abuse.ch/api/v1/"
        try:
            session = await self._ensure_session()
            await self._limiter.acquire()
            resp = await session.post(
                download_url,
                data={"query": "get_file", "sha256_hash": sha256},
            )
            if resp.status != 200:
                self._log.debug(
                    "Payload download HTTP %d for %s", resp.status, sha256[:16]
                )
                await resp.release()
                return None

            content_type = resp.headers.get("Content-Type", "")
            if "json" in content_type or "text" in content_type:
                await resp.release()
                return None

            dest.parent.mkdir(parents=True, exist_ok=True)
            with open(dest, "wb") as fh:
                async for chunk in resp.content.iter_chunked(65_536):
                    fh.write(chunk)

            self._log.debug("Downloaded payload %s → %s", sha256[:16], dest.name)
            return dest

        except Exception:
            self._log.debug("Payload download failed for %s", sha256[:16])
            dest.unlink(missing_ok=True)
            return None

    async def _save_feed_snapshot(
        self,
        urls: list[dict[str, Any]],
        payloads: list[dict[str, Any]],
    ) -> None:
        """Persist a JSON snapshot of the latest fetch.

        Args:
            urls: URL metadata dicts.
            payloads: Payload metadata dicts.
        """
        snapshot_dir = self._feed_dir / "urlhaus"
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = snapshot_dir / f"urlhaus_{ts}.json"

        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "fetched_at": ts,
                        "url_count": len(urls),
                        "payload_count": len(payloads),
                        "urls": urls[:200],
                        "payloads": payloads[:200],
                    },
                    fh,
                    indent=2,
                    default=str,
                )
            self._log.debug("Saved URLhaus snapshot → %s", path.name)
        except OSError:
            self._log.exception("Failed to write URLhaus snapshot")
