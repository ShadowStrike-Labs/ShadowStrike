"""
ShadowStrike PhantomCortex — EMBER Dataset Sync

One-time download and extraction of the EMBER (Endgame Malware BEnchmark
for Research) dataset.  The dataset provides pre-vectorized PE feature
arrays (X_train, y_train, X_test, y_test) used to bootstrap PhantomCortex's
static-analysis ML models.

Dataset: https://github.com/elastic/ember
"""

from __future__ import annotations

import bz2
import hashlib
import io
import os
import struct
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .base_feed import BaseFeed, FeedProgress, resolve_path


class EmberSyncFeed(BaseFeed):
    """EMBER dataset download and extraction feed.

    This feed performs a one-time download of the EMBER dataset archive,
    verifies its SHA-256 digest, extracts the vectorised feature arrays,
    and stores them under ``data/processed/ember/``.

    Subsequent runs are no-ops unless the extracted data is missing.
    """

    def get_feed_name(self) -> str:  # noqa: D401
        """Unique feed identifier."""
        return "ember"

    def get_update_interval(self) -> int:
        """EMBER is a one-shot download — returns a very large interval."""
        return 365 * 24 * 3600  # effectively once

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def fetch_new(self, progress: FeedProgress) -> int:
        """Download and extract the EMBER dataset if not already present.

        Performs:
        1. Check for an existing, valid extracted dataset.
        2. Download the ``tar.bz2`` archive (with resume support).
        3. Verify SHA-256 against the known-good digest.
        4. Extract feature files into ``data/processed/ember/``.

        Args:
            progress: Mutable progress tracker.

        Returns:
            ``1`` if new data was fetched, ``0`` if already up to date.
        """
        ember_dir = self._processed_dir / "ember"
        ember_dir.mkdir(parents=True, exist_ok=True)

        marker = ember_dir / ".download_complete"
        if marker.exists():
            self._log.info("EMBER dataset already extracted — skipping")
            progress.total = 1
            progress.advance(skipped=1)
            return 0

        download_url: str = self._feed_cfg.get(
            "download_url",
            "https://ember.elastic.co/ember_dataset_2018_2.tar.bz2",
        )
        expected_sha256: str = self._feed_cfg.get(
            "expected_sha256",
            "b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812",
        )
        version: str = self._feed_cfg.get("dataset_version", "2018_2")

        archive_path = self._feed_dir / f"ember_dataset_{version}.tar.bz2"
        progress.total = 3  # download, verify, extract

        # --- Step 1: Download -----------------------------------------------
        if archive_path.exists() and self.verify_sha256(archive_path, expected_sha256):
            self._log.info("EMBER archive already on disk and verified")
        else:
            self._log.info("Downloading EMBER dataset from %s", download_url)
            try:
                digest = await self._download_file(
                    download_url,
                    archive_path,
                    expected_sha256=expected_sha256,
                )
                self._log.info("EMBER download complete — SHA-256: %s", digest)
            except ValueError as exc:
                self._log.error("EMBER SHA-256 verification failed: %s", exc)
                progress.advance(errors=1)
                return 0
            except Exception:
                self._log.exception("EMBER download failed")
                progress.advance(errors=1)
                return 0

        progress.advance(new=1)  # download done

        # --- Step 2: Verify again -------------------------------------------
        if not self.verify_sha256(archive_path, expected_sha256):
            self._log.error("EMBER archive failed post-download hash check")
            archive_path.unlink(missing_ok=True)
            progress.advance(errors=1)
            return 0

        progress.advance(new=1)  # verify done

        # --- Step 3: Extract ------------------------------------------------
        self._log.info("Extracting EMBER dataset → %s", ember_dir)
        try:
            await self._extract_archive(archive_path, ember_dir)
        except Exception:
            self._log.exception("EMBER extraction failed")
            progress.advance(errors=1)
            return 0

        # Write marker file
        marker.write_text(
            f"extracted={datetime.now(timezone.utc).isoformat()}\n"
            f"archive_sha256={expected_sha256}\n"
            f"version={version}\n",
            encoding="utf-8",
        )

        progress.advance(new=1)  # extract done

        self._tracker.set_feed_state(
            self.get_feed_name(),
            last_success=datetime.now(timezone.utc).isoformat(),
            cursor=version,
        )

        self._log.info("EMBER dataset ready at %s", ember_dir)
        return 1

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _extract_archive(self, archive: Path, dest_dir: Path) -> None:
        """Extract a tar.bz2 archive, enforcing safety checks.

        Guards against path-traversal (zip-slip) attacks and caps individual
        extracted file sizes to prevent resource exhaustion.

        Args:
            archive: Path to the ``.tar.bz2`` archive.
            dest_dir: Destination directory.

        Raises:
            RuntimeError: On extraction errors.
        """
        import asyncio

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._extract_sync, archive, dest_dir)

    def _extract_sync(self, archive: Path, dest_dir: Path) -> None:
        """Synchronous tar.bz2 extraction with security hardening.

        Args:
            archive: Path to the archive file.
            dest_dir: Target extraction directory.
        """
        max_file_size: int = 10 * 1024 * 1024 * 1024  # 10 GB cap per file
        max_total_size: int = 50 * 1024 * 1024 * 1024  # 50 GB total cap
        total_extracted: int = 0
        dest_resolved = dest_dir.resolve()

        with tarfile.open(str(archive), "r:bz2") as tf:
            for member in tf:
                # Path-traversal guard
                member_path = (dest_dir / member.name).resolve()
                if not str(member_path).startswith(str(dest_resolved)):
                    self._log.warning(
                        "Skipping path-traversal attempt: %s", member.name
                    )
                    continue

                # Size guard
                if member.size > max_file_size:
                    self._log.warning(
                        "Skipping oversized member %s (%d bytes)",
                        member.name,
                        member.size,
                    )
                    continue

                total_extracted += member.size
                if total_extracted > max_total_size:
                    raise RuntimeError(
                        f"Total extraction size exceeds {max_total_size} bytes — aborting"
                    )

                if member.isdir():
                    member_path.mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    member_path.parent.mkdir(parents=True, exist_ok=True)
                    src = tf.extractfile(member)
                    if src is None:
                        continue
                    with open(member_path, "wb") as out:
                        while True:
                            chunk = src.read(65_536)
                            if not chunk:
                                break
                            out.write(chunk)
                    src.close()

        self._log.info(
            "Extracted %d bytes to %s", total_extracted, dest_dir
        )
