"""
Network Flow Feature Extractor
================================
Extracts features from network connection metadata and payload statistics
for the Cortex-Network classifier.  Designed to detect C2 beaconing,
data exfiltration, and lateral movement patterns.

Feature groups:
    Flow basics       (8)   duration, bytes sent/recv, pkt counts, protocol
    Timing stats     (10)   IAT mean/std/min/max/median/skew/kurtosis, …
    Payload features (20)   entropy, size dist, content-type heuristics
    Beaconing        (6)    regularity, jitter, periodicity
    TLS / JA3        (10)   JA3/JA3S hash features (hashed into bins)
    DNS              (10)   domain length, entropy, n-gram, TLD encoding
    Total            (64)
"""

from __future__ import annotations

import hashlib
import logging
import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

import numpy as np

logger = logging.getLogger("phantomcortex.features.network")

# ═══════════════════════════════════════════════════════════════════════════
# Protocol encoding
# ═══════════════════════════════════════════════════════════════════════════
_PROTOCOL_MAP: Dict[str, int] = {
    "tcp": 1,
    "udp": 2,
    "dns": 3,
    "http": 4,
    "https": 5,
    "icmp": 6,
    "tls": 5,  # alias
}

# Well-known TLDs mapped to integer IDs
_TLD_MAP: Dict[str, int] = {
    "com": 1, "net": 2, "org": 3, "edu": 4, "gov": 5,
    "io": 6, "co": 7, "info": 8, "biz": 9, "xyz": 10,
    "ru": 11, "cn": 12, "tk": 13, "top": 14, "cc": 15,
    "pw": 16, "ga": 17, "cf": 18, "ml": 19, "gq": 20,
    "onion": 21, "bit": 22, "local": 23, "arpa": 24, "in": 25,
}


def _stable_hash(value: str, modulus: int) -> int:
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).digest()
    return int.from_bytes(digest[:8], "little") % modulus


def _safe_log(x: float) -> float:
    return math.log1p(max(x, 0.0))


# ═══════════════════════════════════════════════════════════════════════════
# Data models
# ═══════════════════════════════════════════════════════════════════════════
@dataclass(frozen=True, slots=True)
class NetworkFlow:
    """A single network flow (uni- or bi-directional)."""
    src_ip: str = "0.0.0.0"
    dst_ip: str = "0.0.0.0"
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "tcp"
    duration_ms: float = 0.0
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    inter_arrival_times_ms: list[float] = field(default_factory=list)
    payload_sizes: list[int] = field(default_factory=list)
    payload_entropy: float = 0.0
    ja3_hash: str = ""
    ja3s_hash: str = ""
    dns_queries: list[str] = field(default_factory=list)
    timestamp_start_ms: float = 0.0
    timestamp_end_ms: float = 0.0


# ═══════════════════════════════════════════════════════════════════════════
# Extractor
# ═══════════════════════════════════════════════════════════════════════════
class NetworkFeatureExtractor:
    """
    Extract a 64-dimensional feature vector from a :class:`NetworkFlow`.
    """

    FEATURE_COUNT: int = 64

    def extract(self, flow: NetworkFlow) -> np.ndarray:
        """Return float32 vector of length 64."""
        features = np.zeros(self.FEATURE_COUNT, dtype=np.float32)

        # -- Flow basics (0-7) ------------------------------------------------
        features[0] = _safe_log(flow.duration_ms)
        features[1] = _safe_log(float(flow.bytes_sent))
        features[2] = _safe_log(float(flow.bytes_received))
        features[3] = _safe_log(float(flow.packets_sent))
        features[4] = _safe_log(float(flow.packets_received))
        features[5] = float(_PROTOCOL_MAP.get(flow.protocol.lower(), 0))
        features[6] = float(flow.dst_port)
        total_bytes = flow.bytes_sent + flow.bytes_received
        features[7] = (
            float(flow.bytes_sent) / total_bytes if total_bytes > 0 else 0.5
        )

        # -- Timing statistics (8-17) -----------------------------------------
        features[8:18] = self._timing_stats(flow.inter_arrival_times_ms)

        # -- Payload features (18-37) ------------------------------------------
        features[18:38] = self._payload_features(flow)

        # -- Beaconing metrics (38-43) -----------------------------------------
        features[38:44] = self._beaconing_metrics(flow.inter_arrival_times_ms)

        # -- TLS / JA3 features (44-53) ----------------------------------------
        features[44:54] = self._tls_features(flow)

        # -- DNS features (54-63) ----------------------------------------------
        features[54:64] = self._dns_features(flow.dns_queries)

        return features

    def extract_batch(self, flows: Sequence[NetworkFlow]) -> np.ndarray:
        """Process multiple flows, returning (N, 64) array."""
        out = np.zeros((len(flows), self.FEATURE_COUNT), dtype=np.float32)
        for i, flow in enumerate(flows):
            out[i] = self.extract(flow)
        return out

    # -- internal ----------------------------------------------------------

    @staticmethod
    def _timing_stats(iats: list[float]) -> np.ndarray:
        """10 features from inter-arrival times."""
        result = np.zeros(10, dtype=np.float32)
        if not iats:
            return result
        arr = np.array(iats, dtype=np.float64)
        result[0] = float(np.mean(arr))
        result[1] = float(np.std(arr))
        result[2] = float(np.min(arr))
        result[3] = float(np.max(arr))
        result[4] = float(np.median(arr))
        n = len(arr)
        if n >= 3 and np.std(arr) > 0:
            m3 = float(np.mean(((arr - np.mean(arr)) / np.std(arr)) ** 3))
            result[5] = m3  # skewness
        if n >= 4 and np.std(arr) > 0:
            m4 = float(np.mean(((arr - np.mean(arr)) / np.std(arr)) ** 4))
            result[6] = m4  # kurtosis
        result[7] = float(np.percentile(arr, 25))
        result[8] = float(np.percentile(arr, 75))
        result[9] = float(np.percentile(arr, 75) - np.percentile(arr, 25))  # IQR
        return result

    @staticmethod
    def _payload_features(flow: NetworkFlow) -> np.ndarray:
        """20 features from payload statistics."""
        result = np.zeros(20, dtype=np.float32)
        result[0] = flow.payload_entropy
        sizes = flow.payload_sizes
        if sizes:
            arr = np.array(sizes, dtype=np.float64)
            result[1] = float(np.mean(arr))
            result[2] = float(np.std(arr))
            result[3] = float(np.min(arr))
            result[4] = float(np.max(arr))
            result[5] = float(np.median(arr))
            result[6] = _safe_log(float(np.sum(arr)))
            result[7] = float(len(arr))
            # Payload size distribution buckets
            buckets = [0, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 65536]
            for bi in range(len(buckets) - 1):
                count = int(np.sum((arr >= buckets[bi]) & (arr < buckets[bi + 1])))
                result[8 + bi] = count / len(arr) if len(arr) > 0 else 0.0
            # Coefficient of variation
            if result[1] > 0:
                result[17] = result[2] / result[1]
            # Log total payload
            result[18] = _safe_log(float(flow.bytes_sent + flow.bytes_received))
            # Payload ratio (sent vs total)
            total = flow.bytes_sent + flow.bytes_received
            result[19] = float(flow.bytes_sent) / total if total > 0 else 0.5
        return result

    @staticmethod
    def _beaconing_metrics(iats: list[float]) -> np.ndarray:
        """6 beaconing features: regularity, jitter, periodicity indicators."""
        result = np.zeros(6, dtype=np.float32)
        if len(iats) < 3:
            return result

        arr = np.array(iats, dtype=np.float64)
        mean_iat = float(np.mean(arr))
        std_iat = float(np.std(arr))

        # Regularity score: 1.0 = perfectly regular, 0.0 = chaotic
        if mean_iat > 0:
            cv = std_iat / mean_iat
            result[0] = max(0.0, 1.0 - cv)
        # Jitter ratio
        if mean_iat > 0:
            result[1] = std_iat / mean_iat

        # Median absolute deviation
        median_iat = float(np.median(arr))
        mad = float(np.median(np.abs(arr - median_iat)))
        result[2] = mad

        # Mode-based periodicity: check if many IATs cluster near the median
        tolerance = max(median_iat * 0.1, 1.0)  # 10% window
        near_median = np.sum(np.abs(arr - median_iat) < tolerance)
        result[3] = float(near_median) / len(arr)

        # Auto-correlation at lag 1
        if len(arr) > 1 and std_iat > 0:
            shifted = arr[1:]
            original = arr[:-1]
            cov = float(np.mean((original - mean_iat) * (shifted - mean_iat)))
            result[4] = cov / (std_iat ** 2) if std_iat > 0 else 0.0

        # Count of distinct IAT clusters (crude: within 5% buckets)
        if mean_iat > 0:
            bucketized = np.round(arr / max(mean_iat * 0.05, 0.001))
            result[5] = float(len(np.unique(bucketized)))

        return result

    @staticmethod
    def _tls_features(flow: NetworkFlow) -> np.ndarray:
        """10 features from JA3/JA3S hashes and TLS metadata."""
        result = np.zeros(10, dtype=np.float32)
        result[0] = 1.0 if flow.ja3_hash else 0.0
        result[1] = 1.0 if flow.ja3s_hash else 0.0

        if flow.ja3_hash:
            # Hash JA3 into 4 feature bins
            for i in range(4):
                h = _stable_hash(flow.ja3_hash + f"_bin{i}", 1000)
                result[2 + i] = float(h)

        if flow.ja3s_hash:
            for i in range(4):
                h = _stable_hash(flow.ja3s_hash + f"_bin{i}", 1000)
                result[6 + i] = float(h)

        return result

    @staticmethod
    def _dns_features(queries: list[str]) -> np.ndarray:
        """10 features from DNS query patterns."""
        result = np.zeros(10, dtype=np.float32)
        if not queries:
            return result

        result[0] = float(len(queries))

        # Aggregate domain statistics
        lengths: list[int] = []
        entropies: list[float] = []
        label_counts: list[int] = []

        for domain in queries[:1000]:  # cap to prevent abuse
            domain_lower = domain.lower().strip(".")
            lengths.append(len(domain_lower))
            label_counts.append(domain_lower.count(".") + 1)

            # Per-domain character entropy
            if domain_lower:
                freq: Dict[str, int] = {}
                for ch in domain_lower:
                    freq[ch] = freq.get(ch, 0) + 1
                n = len(domain_lower)
                ent = 0.0
                for count in freq.values():
                    p = count / n
                    if p > 0:
                        ent -= p * math.log2(p)
                entropies.append(ent)

        if lengths:
            arr_len = np.array(lengths, dtype=np.float64)
            result[1] = float(np.mean(arr_len))
            result[2] = float(np.max(arr_len))
            result[3] = float(np.std(arr_len))

        if entropies:
            arr_ent = np.array(entropies, dtype=np.float64)
            result[4] = float(np.mean(arr_ent))
            result[5] = float(np.max(arr_ent))

        if label_counts:
            result[6] = float(np.mean(label_counts))
            result[7] = float(np.max(label_counts))

        # TLD encoding of the last query
        last_domain = queries[-1].lower().strip(".")
        parts = last_domain.rsplit(".", 1)
        tld = parts[-1] if parts else ""
        result[8] = float(_TLD_MAP.get(tld, 0))

        # N-gram suspicion score: ratio of consonant sequences (DGA heuristic)
        vowels = set("aeiouy")
        consonant_runs = 0
        total_chars = 0
        for domain in queries[:100]:
            domain_lower = domain.lower().strip(".")
            name_part = domain_lower.split(".")[0] if "." in domain_lower else domain_lower
            total_chars += len(name_part)
            run = 0
            for ch in name_part:
                if ch.isalpha() and ch not in vowels:
                    run += 1
                    if run >= 4:
                        consonant_runs += 1
                else:
                    run = 0
        result[9] = consonant_runs / max(total_chars, 1)

        return result
