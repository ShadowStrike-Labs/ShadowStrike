"""
ShadowStrike PhantomCortex — Feodo Tracker + SSL Blocklist Feed

Ingests C2 IP addresses and SSL certificate block indicators from the
abuse.ch Feodo Tracker and SSL Blocklist services.

- Feodo Tracker: Botnet C2 IP blocklist (Emotet, Dridex, TrickBot, QakBot).
- SSL Blocklist: Certificates associated with malicious C2 servers.

References:
  https://feodotracker.abuse.ch/
  https://sslbl.abuse.ch/
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .base_feed import BaseFeed, FeedProgress


class FeodoTrackerFeed(BaseFeed):
    """Feodo Tracker and SSL Blocklist threat-intelligence feed.

    Collects botnet C2 IP addresses with associated malware families and
    ports, plus SSL certificate hashes flagged as malicious.
    """

    def get_feed_name(self) -> str:  # noqa: D401
        """Unique feed identifier."""
        return "feodo"

    def get_update_interval(self) -> int:
        """Recommended polling interval in seconds."""
        hours: int = self._feed_cfg.get("update_interval_hours", 1)
        return hours * 3600

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def fetch_new(self, progress: FeedProgress) -> int:
        """Ingest new C2 IPs and SSL cert hashes.

        Fetches both the Feodo IP blocklist JSON and the SSL Blocklist CSV,
        deduplicates against the tracker database, and records new entries.

        Args:
            progress: Mutable progress tracker.

        Returns:
            Count of newly ingested indicators.
        """
        new_count = 0

        feodo_new = await self._ingest_feodo(progress)
        new_count += feodo_new

        ssl_new = await self._ingest_ssl_blocklist(progress)
        new_count += ssl_new

        self._log.info(
            "Feodo/SSL run complete — %d new (%d feodo + %d ssl), %d skipped, %d errors",
            new_count,
            feodo_new,
            ssl_new,
            progress.skipped,
            progress.errors,
        )

        return new_count

    # ------------------------------------------------------------------
    # Feodo IP blocklist
    # ------------------------------------------------------------------

    async def _ingest_feodo(self, progress: FeedProgress) -> int:
        """Fetch and process the Feodo Tracker recommended IP blocklist.

        Args:
            progress: Mutable progress tracker.

        Returns:
            Count of new C2 IP entries.
        """
        feodo_url: str = self._feed_cfg.get(
            "feodo_url",
            "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json",
        )

        self._log.info("Fetching Feodo Tracker IP blocklist")

        try:
            data = await self._get_json(feodo_url)
        except Exception:
            self._log.exception("Failed to fetch Feodo Tracker blocklist")
            return 0

        entries: list[dict[str, Any]] = []
        if isinstance(data, list):
            entries = data
        elif isinstance(data, dict):
            entries = data.get("data", data.get("entries", []))
            if not entries and "ip_address" in data:
                entries = [data]

        progress.total += len(entries)
        new_count = 0

        for entry in entries:
            ip: str = (entry.get("ip_address") or entry.get("dst_ip") or "").strip()
            if not ip:
                progress.advance(errors=1)
                continue

            port: str = str(entry.get("dst_port") or entry.get("port") or "")
            malware: str = entry.get("malware", "") or ""
            ioc_key = f"{ip}:{port}" if port else ip

            if self._tracker.has_ioc(ioc_key, "c2_ip", self.get_feed_name()):
                progress.advance(skipped=1)
                continue

            self._tracker.record_ioc(
                ioc_key,
                "c2_ip",
                self.get_feed_name(),
                threat_type="c2",
                malware=malware,
                confidence=90,
                tags=f"feodo,{malware.lower()}" if malware else "feodo",
                extra_json=json.dumps(
                    {
                        "ip": ip,
                        "port": port,
                        "first_seen": entry.get("first_seen", ""),
                        "last_online": entry.get("last_online", ""),
                        "status": entry.get("status", ""),
                    },
                    separators=(",", ":"),
                ),
            )

            new_count += 1
            progress.advance(new=1)

        self._log.info("Feodo Tracker: %d new C2 IPs from %d entries", new_count, len(entries))

        await self._save_snapshot("feodo", entries)
        return new_count

    # ------------------------------------------------------------------
    # SSL Blocklist
    # ------------------------------------------------------------------

    async def _ingest_ssl_blocklist(self, progress: FeedProgress) -> int:
        """Fetch and parse the SSL Blocklist CSV.

        Args:
            progress: Mutable progress tracker.

        Returns:
            Count of new SSL certificate indicators.
        """
        ssl_url: str = self._feed_cfg.get(
            "ssl_url",
            "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
        )

        self._log.info("Fetching SSL Blocklist")

        try:
            session = await self._ensure_session()
            await self._limiter.acquire()
            resp = await session.get(ssl_url)
            resp.raise_for_status()
            text = await resp.text()
        except Exception:
            self._log.exception("Failed to fetch SSL Blocklist")
            return 0

        new_count = 0
        lines = text.splitlines()

        data_lines: list[str] = []
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            data_lines.append(stripped)

        progress.total += len(data_lines)

        reader = csv.reader(data_lines)
        for row in reader:
            if len(row) < 3:
                progress.advance(errors=1)
                continue

            timestamp_str: str = row[0].strip()
            sha1_cert: str = row[1].strip()
            reason: str = row[2].strip() if len(row) > 2 else ""

            if not sha1_cert:
                progress.advance(errors=1)
                continue

            if self._tracker.has_ioc(sha1_cert, "ssl_cert_sha1", self.get_feed_name()):
                progress.advance(skipped=1)
                continue

            self._tracker.record_ioc(
                sha1_cert,
                "ssl_cert_sha1",
                self.get_feed_name(),
                threat_type="ssl_cert",
                malware=reason,
                confidence=85,
                tags=f"sslbl,{reason.lower()}" if reason else "sslbl",
                extra_json=json.dumps(
                    {"listing_date": timestamp_str, "reason": reason},
                    separators=(",", ":"),
                ),
            )

            new_count += 1
            progress.advance(new=1)

        self._log.info("SSL Blocklist: %d new cert hashes from %d entries", new_count, len(data_lines))
        return new_count

    # ------------------------------------------------------------------
    # Snapshot persistence
    # ------------------------------------------------------------------

    async def _save_snapshot(
        self, source: str, entries: list[dict[str, Any]]
    ) -> None:
        """Persist a JSON snapshot of fetched entries.

        Args:
            source: Sub-source name (``"feodo"`` or ``"sslbl"``).
            entries: Data entries to serialize.
        """
        snapshot_dir = self._feed_dir / "feodo"
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = snapshot_dir / f"{source}_{ts}.json"

        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(
                    {"fetched_at": ts, "source": source, "count": len(entries), "entries": entries},
                    fh,
                    indent=2,
                    default=str,
                )
            self._log.debug("Saved %s snapshot → %s", source, path.name)
        except OSError:
            self._log.exception("Failed to write %s snapshot", source)
