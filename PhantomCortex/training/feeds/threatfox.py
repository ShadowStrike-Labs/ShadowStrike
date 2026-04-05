"""
ShadowStrike PhantomCortex — ThreatFox Feed

Ingests Indicators of Compromise (IOCs) from ThreatFox (abuse.ch):
file hashes, IP addresses, domains, and URLs associated with known
malware families.

API Reference: https://threatfox.abuse.ch/api/
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

from .base_feed import BaseFeed, FeedProgress


class ThreatFoxFeed(BaseFeed):
    """ThreatFox IOC feed.

    Collects structured IOC data — hashes, IPs, domains, URLs — tagged with
    malware families, threat types, and confidence levels.
    """

    def get_feed_name(self) -> str:  # noqa: D401
        """Unique feed identifier."""
        return "threatfox"

    def get_update_interval(self) -> int:
        """Recommended polling interval in seconds."""
        hours: int = self._feed_cfg.get("update_interval_hours", 1)
        return hours * 3600

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def fetch_new(self, progress: FeedProgress) -> int:
        """Ingest recent ThreatFox IOCs.

        Queries the recent-IOC endpoint and records each indicator in the
        tracker database, skipping duplicates.

        Args:
            progress: Mutable progress tracker.

        Returns:
            Count of newly recorded IOCs.
        """
        api_url: str = self._feed_cfg.get(
            "api_url", "https://threatfox-api.abuse.ch/api/v1/"
        )
        max_iocs: int = self._feed_cfg.get("max_iocs_per_run", 1000)

        self._log.info("Querying ThreatFox for recent IOCs (max %d)", max_iocs)

        iocs = await self._query_recent(api_url, days=1)
        if not iocs:
            self._log.info("No new IOCs returned from ThreatFox")
            return 0

        progress.total = min(len(iocs), max_iocs)
        new_count = 0

        for entry in iocs[:max_iocs]:
            ioc_value: str = entry.get("ioc", "").strip()
            ioc_type: str = entry.get("ioc_type", "").strip()
            if not ioc_value or not ioc_type:
                progress.advance(errors=1)
                continue

            if self._tracker.has_ioc(ioc_value, ioc_type, self.get_feed_name()):
                progress.advance(skipped=1)
                continue

            tags_raw = entry.get("tags") or []
            tags_str = ",".join(str(t) for t in tags_raw) if tags_raw else ""
            malware_name: str = entry.get("malware") or entry.get("malware_printable") or ""
            confidence: int = int(entry.get("confidence_level", 0) or 0)

            self._tracker.record_ioc(
                ioc_value,
                ioc_type,
                self.get_feed_name(),
                threat_type=entry.get("threat_type", ""),
                malware=malware_name,
                confidence=confidence,
                tags=tags_str,
                extra_json=json.dumps(
                    {
                        "id": entry.get("id", ""),
                        "reporter": entry.get("reporter", ""),
                        "reference": entry.get("reference", ""),
                        "first_seen": entry.get("first_seen_utc", ""),
                        "last_seen": entry.get("last_seen_utc", ""),
                        "malware_alias": entry.get("malware_alias", ""),
                    },
                    separators=(",", ":"),
                ),
            )

            # If the IOC is a file hash, also record it in downloads table
            if ioc_type in ("md5_hash", "sha256_hash") and len(ioc_value) == 64:
                if not self._tracker.has_download(ioc_value, self.get_feed_name()):
                    self._tracker.record_download(
                        ioc_value,
                        self.get_feed_name(),
                        malware=malware_name,
                        tags=tags_str,
                    )

            new_count += 1
            progress.advance(new=1)

        self._log.info(
            "ThreatFox run complete — %d new IOCs, %d skipped, %d errors",
            progress.new_items,
            progress.skipped,
            progress.errors,
        )

        await self._save_feed_snapshot(iocs[:max_iocs])
        return new_count

    async def query_by_malware(
        self, malware: str, limit: int = 100
    ) -> list[dict[str, Any]]:
        """Query IOCs associated with a specific malware family.

        Args:
            malware: Malware family name (e.g. ``"Emotet"``).
            limit: Maximum results.

        Returns:
            List of IOC dicts.
        """
        api_url: str = self._feed_cfg.get(
            "api_url", "https://threatfox-api.abuse.ch/api/v1/"
        )
        body = {"query": "malwareinfo", "malware": malware, "limit": limit}
        resp = await self._post_json(api_url, body)
        if resp.get("query_status") != "ok":
            self._log.warning(
                "ThreatFox malware query failed: %s", resp.get("query_status")
            )
            return []
        return resp.get("data", [])

    async def query_by_tag(self, tag: str, limit: int = 100) -> list[dict[str, Any]]:
        """Query IOCs matching a specific tag.

        Args:
            tag: Tag string (e.g. ``"cobalt-strike"``).
            limit: Maximum results.

        Returns:
            List of IOC dicts.
        """
        api_url: str = self._feed_cfg.get(
            "api_url", "https://threatfox-api.abuse.ch/api/v1/"
        )
        body = {"query": "taginfo", "tag": tag, "limit": limit}
        resp = await self._post_json(api_url, body)
        if resp.get("query_status") != "ok":
            self._log.warning(
                "ThreatFox tag query failed: %s", resp.get("query_status")
            )
            return []
        return resp.get("data", [])

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _query_recent(
        self, api_url: str, days: int = 1
    ) -> list[dict[str, Any]]:
        """Fetch IOCs from the last *days* days.

        Args:
            api_url: ThreatFox API endpoint URL.
            days: Look-back window in days (max 7).

        Returns:
            List of IOC metadata dicts.
        """
        body = {"query": "get_iocs", "days": min(days, 7)}
        try:
            resp = await self._post_json(api_url, body)
        except Exception:
            self._log.exception("Failed to query recent IOCs from ThreatFox")
            return []

        if resp.get("query_status") != "ok":
            self._log.warning(
                "ThreatFox query_status=%s", resp.get("query_status")
            )
            return []

        data = resp.get("data", [])
        self._log.info("ThreatFox returned %d recent IOCs", len(data))
        return data

    async def _save_feed_snapshot(self, iocs: list[dict[str, Any]]) -> None:
        """Persist the latest batch as a JSON snapshot for offline analysis.

        Args:
            iocs: List of IOC dicts to serialize.
        """
        snapshot_dir = self._feed_dir / "threatfox"
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = snapshot_dir / f"threatfox_{ts}.json"

        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(
                    {"fetched_at": ts, "count": len(iocs), "iocs": iocs},
                    fh,
                    indent=2,
                    default=str,
                )
            self._log.debug("Saved ThreatFox snapshot → %s", path.name)
        except OSError:
            self._log.exception("Failed to write ThreatFox snapshot")
