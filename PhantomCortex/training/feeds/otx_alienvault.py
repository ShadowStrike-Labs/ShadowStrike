"""
ShadowStrike PhantomCortex — AlienVault OTX Feed

Ingests threat-intelligence pulses and file indicators from AlienVault's
Open Threat Exchange (OTX).  Supports both authenticated and anonymous
access (public pulses only when no API key is configured).

API Reference: https://otx.alienvault.com/assets/static/external_api.html
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .base_feed import BaseFeed, FeedProgress


class OTXAlienVaultFeed(BaseFeed):
    """AlienVault OTX threat-intelligence feed.

    Collects pulse indicators (file hashes, IPs, domains, URLs), malware
    family associations, and embedded YARA rules.
    """

    def get_feed_name(self) -> str:  # noqa: D401
        """Unique feed identifier."""
        return "otx"

    def get_update_interval(self) -> int:
        """Recommended polling interval in seconds."""
        hours: int = self._feed_cfg.get("update_interval_hours", 6)
        return hours * 3600

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def fetch_new(self, progress: FeedProgress) -> int:
        """Ingest new OTX pulses and their indicators.

        Iterates over subscribed (or public) pulses, extracting indicators
        and YARA rules.

        Args:
            progress: Mutable progress tracker.

        Returns:
            Count of newly ingested indicators.
        """
        api_url: str = self._feed_cfg.get(
            "api_url", "https://otx.alienvault.com/api/v1/"
        ).rstrip("/")
        max_pulses: int = self._feed_cfg.get("max_pulses_per_run", 200)
        api_key: str = self._resolve_api_key()
        headers = self._auth_headers(api_key)

        self._log.info(
            "Querying OTX for recent pulses (max %d, auth=%s)",
            max_pulses,
            "yes" if api_key else "no",
        )

        pulses = await self._fetch_pulses(api_url, headers, max_pulses)
        if not pulses:
            self._log.info("No new pulses from OTX")
            return 0

        progress.total = len(pulses)
        new_count = 0

        for pulse in pulses:
            pulse_id: str = pulse.get("id", "")
            pulse_name: str = pulse.get("name", "")
            indicators: list[dict[str, Any]] = pulse.get("indicators", [])
            malware_families = self._extract_malware_families(pulse)
            malware_str = ",".join(malware_families) if malware_families else ""

            yara_rules = self._extract_yara_rules(pulse)
            if yara_rules:
                await self._save_yara_rules(pulse_id, pulse_name, yara_rules)

            pulse_new = 0
            for ind in indicators:
                ioc_type: str = ind.get("type", "")
                ioc_value: str = ind.get("indicator", "")
                if not ioc_type or not ioc_value:
                    continue

                canonical_type = self._normalize_ioc_type(ioc_type)

                if self._tracker.has_ioc(ioc_value, canonical_type, self.get_feed_name()):
                    continue

                self._tracker.record_ioc(
                    ioc_value,
                    canonical_type,
                    self.get_feed_name(),
                    threat_type=pulse.get("adversary", ""),
                    malware=malware_str,
                    confidence=0,
                    tags=",".join(pulse.get("tags", [])[:20]),
                    extra_json=json.dumps(
                        {
                            "pulse_id": pulse_id,
                            "pulse_name": pulse_name,
                            "created": pulse.get("created", ""),
                            "description": ind.get("description", "")[:500],
                        },
                        separators=(",", ":"),
                    ),
                )

                # Cross-reference hashes into downloads table
                if canonical_type in ("sha256", "sha1", "md5") and len(ioc_value) == 64:
                    if not self._tracker.has_download(ioc_value, self.get_feed_name()):
                        self._tracker.record_download(
                            ioc_value,
                            self.get_feed_name(),
                            malware=malware_str,
                            tags=",".join(pulse.get("tags", [])[:20]),
                        )

                pulse_new += 1
                new_count += 1

            if pulse_new > 0:
                progress.advance(new=1)
                self._log.debug(
                    "Pulse %s: %d new indicators from '%s'",
                    pulse_id[:8],
                    pulse_new,
                    pulse_name[:60],
                )
            else:
                progress.advance(skipped=1)

        self._log.info(
            "OTX run complete — %d new indicators from %d pulses, %d skipped",
            new_count,
            progress.new_items,
            progress.skipped,
        )
        return new_count

    async def query_file_indicator(
        self, file_hash: str
    ) -> Optional[dict[str, Any]]:
        """Look up a file hash against OTX's indicator database.

        Args:
            file_hash: MD5, SHA-1, or SHA-256 hash string.

        Returns:
            OTX analysis response dict, or *None* if not found.
        """
        api_url: str = self._feed_cfg.get(
            "api_url", "https://otx.alienvault.com/api/v1/"
        ).rstrip("/")
        api_key: str = self._resolve_api_key()
        headers = self._auth_headers(api_key)

        hash_type = self._classify_hash(file_hash)
        if not hash_type:
            self._log.warning("Cannot classify hash length %d", len(file_hash))
            return None

        url = f"{api_url}/indicators/file/{file_hash}/analysis"
        try:
            return await self._get_json(url, headers=headers)
        except Exception:
            self._log.exception("OTX file indicator lookup failed for %s", file_hash[:16])
            return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_api_key(self) -> str:
        """Resolve the OTX API key from env var or config."""
        key = os.environ.get("PHANTOM_OTX_API_KEY", "")
        if not key:
            key = self._feed_cfg.get("api_key", "")
        return key

    @staticmethod
    def _auth_headers(api_key: str) -> Optional[dict[str, str]]:
        """Build authentication headers if a key is available."""
        if api_key:
            return {"X-OTX-API-KEY": api_key}
        return None

    async def _fetch_pulses(
        self,
        api_url: str,
        headers: Optional[dict[str, str]],
        max_pulses: int,
    ) -> list[dict[str, Any]]:
        """Page through subscribed or modified pulses.

        Args:
            api_url: OTX API base URL.
            headers: Auth headers (may be *None*).
            max_pulses: Maximum number of pulses to retrieve.

        Returns:
            Aggregated list of pulse dicts.
        """
        # Determine cursor from saved state
        state = self._tracker.get_feed_state(self.get_feed_name())
        modified_since: str = ""
        if state and state.get("cursor"):
            modified_since = state["cursor"]

        url = f"{api_url}/pulses/subscribed"
        params: dict[str, str] = {"limit": str(min(max_pulses, 50))}
        if modified_since:
            params["modified_since"] = modified_since

        all_pulses: list[dict[str, Any]] = []
        pages_fetched = 0
        max_pages = (max_pulses // 50) + 1

        while len(all_pulses) < max_pulses and pages_fetched < max_pages:
            try:
                data = await self._get_json(url, params=params, headers=headers)
            except Exception:
                self._log.exception("Failed to fetch OTX pulses page %d", pages_fetched)
                break

            results = data.get("results", [])
            if not results:
                break

            all_pulses.extend(results)
            pages_fetched += 1

            next_url = data.get("next")
            if not next_url:
                break
            url = next_url
            params = {}

        # Save cursor for incremental fetches
        if all_pulses:
            latest = max(
                (p.get("modified", "") for p in all_pulses),
                default="",
            )
            if latest:
                self._tracker.set_feed_state(
                    self.get_feed_name(), cursor=latest
                )

        self._log.info("OTX returned %d pulses across %d pages", len(all_pulses), pages_fetched)
        return all_pulses[:max_pulses]

    @staticmethod
    def _extract_malware_families(pulse: dict[str, Any]) -> list[str]:
        """Extract malware family names from pulse metadata."""
        families: list[str] = []
        for family in pulse.get("malware_families", []):
            name = family if isinstance(family, str) else family.get("display_name", "")
            if name:
                families.append(name)
        # Also check tags for family hints
        for tag in pulse.get("tags", []):
            tag_lower = tag.lower()
            if any(kw in tag_lower for kw in ("malware", "trojan", "ransomware", "rat", "backdoor")):
                if tag not in families:
                    families.append(tag)
        return families[:20]

    @staticmethod
    def _extract_yara_rules(pulse: dict[str, Any]) -> list[str]:
        """Extract YARA rule strings embedded in pulse indicators or descriptions."""
        rules: list[str] = []
        for ind in pulse.get("indicators", []):
            content = ind.get("content", "")
            if isinstance(content, str) and "rule " in content and "{" in content:
                rules.append(content)
        description = pulse.get("description", "")
        if isinstance(description, str) and "rule " in description and "condition:" in description:
            rules.append(description)
        return rules

    async def _save_yara_rules(
        self, pulse_id: str, pulse_name: str, rules: list[str]
    ) -> None:
        """Persist extracted YARA rules to disk.

        Args:
            pulse_id: OTX pulse identifier.
            pulse_name: Human-readable pulse name.
            rules: List of YARA rule source strings.
        """
        yara_dir = self._feed_dir / "otx" / "yara"
        yara_dir.mkdir(parents=True, exist_ok=True)

        safe_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in pulse_id)[:64]
        path = yara_dir / f"{safe_id}.yar"
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(f"// Pulse: {pulse_name}\n")
                fh.write(f"// Source: OTX {pulse_id}\n")
                fh.write(f"// Extracted: {datetime.now(timezone.utc).isoformat()}\n\n")
                for rule in rules:
                    fh.write(rule)
                    fh.write("\n\n")
            self._log.debug("Saved YARA rules → %s", path.name)
        except OSError:
            self._log.exception("Failed to write YARA rules for pulse %s", pulse_id[:8])

    @staticmethod
    def _normalize_ioc_type(otx_type: str) -> str:
        """Map OTX indicator types to canonical names."""
        mapping: dict[str, str] = {
            "FileHash-SHA256": "sha256",
            "FileHash-SHA1": "sha1",
            "FileHash-MD5": "md5",
            "IPv4": "ipv4",
            "IPv6": "ipv6",
            "domain": "domain",
            "hostname": "hostname",
            "URL": "url",
            "email": "email",
            "CVE": "cve",
            "YARA": "yara",
            "Mutex": "mutex",
            "FilePath": "filepath",
        }
        return mapping.get(otx_type, otx_type.lower().replace("-", "_"))

    @staticmethod
    def _classify_hash(h: str) -> Optional[str]:
        """Classify a hash string by its length."""
        match len(h):
            case 32:
                return "md5"
            case 40:
                return "sha1"
            case 64:
                return "sha256"
            case _:
                return None
