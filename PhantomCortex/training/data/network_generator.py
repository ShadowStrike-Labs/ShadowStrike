"""
PhantomCortex Synthetic Network Flow Data Generator
=====================================================

Generates synthetic 64-dimensional feature vectors for 8 network threat
classes used to train the Cortex-Network autoencoder + classifier.  Each
class has a statistically realistic profile derived from real-world network
telemetry: C2 beacons, data exfiltration, lateral movement, port scanning,
DGA domains, DNS tunnels, and crypto-mining traffic.

Classes (from NetworkThreatClass):
    0 — Normal          : standard HTTP/HTTPS, DNS, SMTP
    1 — C2Beacon        : periodic callbacks, constant payloads
    2 — Exfiltration    : large outbound, non-standard ports
    3 — LateralMovement : SMB/WMI/RPC to internal IPs
    4 — Scanning        : many connections, tiny payloads
    5 — DGADomain       : algorithmically generated domains
    6 — DNSTunnel       : large DNS queries, TXT records
    7 — CryptoMining    : Stratum protocol, specific ports

Usage:
    python -m PhantomCortex.training.data.network_generator \\
        --samples-per-class 10000 --seed 42 --output-dir ./data/processed
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import numpy as np
import torch
from numpy.typing import NDArray
from torch.utils.data import DataLoader, TensorDataset

logger = logging.getLogger("PhantomCortex.Data.NetworkGenerator")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FEATURE_DIM: int = 64
NUM_CLASSES: int = 8
DEFAULT_SAMPLES_PER_CLASS: int = 10_000
DEFAULT_SEED: int = 42
DEFAULT_BATCH_SIZE: int = 256

# Well-known port threshold
_PORT_MAX: float = 65535.0
_LOG_SCALE_MAX: float = 30.0  # log(bytes) cap


# ---------------------------------------------------------------------------
# Dataclass for split datasets
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NetworkDataSplit:
    """Holds train/val/test tensors and loaders for network flow data."""

    X_train: torch.Tensor
    y_train: torch.Tensor
    X_val: torch.Tensor
    y_val: torch.Tensor
    X_test: torch.Tensor
    y_test: torch.Tensor
    train_loader: DataLoader
    val_loader: DataLoader
    test_loader: DataLoader
    feature_dim: int
    num_classes: int
    class_names: list[str]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clip01(arr: NDArray[np.float64]) -> NDArray[np.float64]:
    """Clip array values to [0, 1]."""
    return np.clip(arr, 0.0, 1.0)


def _bounded_normal(
    rng: np.random.Generator,
    mean: float,
    std: float,
    size: int,
    lo: float = 0.0,
    hi: float = 1.0,
) -> NDArray[np.float64]:
    """Draw from a normal distribution clipped to [lo, hi]."""
    return np.clip(rng.normal(mean, std, size), lo, hi)


def _norm_port(port: float) -> float:
    """Normalize a port number to [0, 1]."""
    return port / _PORT_MAX


def _log_norm(val: NDArray[np.float64], cap: float = _LOG_SCALE_MAX) -> NDArray[np.float64]:
    """Apply log1p and normalize by cap."""
    return np.clip(np.log1p(np.maximum(val, 0.0)) / cap, 0.0, 1.0)


# ---------------------------------------------------------------------------
# Per-class generators
# ---------------------------------------------------------------------------


def _generate_normal(rng: np.random.Generator, n: int) -> NDArray[np.float64]:
    """Generate normal traffic flow feature vectors.

    Profile: standard HTTP/HTTPS/DNS/SMTP, moderate duration, balanced
    send/receive, well-known ports, regular TLS, low periodicity.
    """
    data = np.zeros((n, FEATURE_DIM), dtype=np.float64)

    # [0] duration_seconds (log): moderate 1s-300s
    data[:, 0] = _log_norm(rng.exponential(30.0, n))

    # [1] src_port: ephemeral (49152-65535)
    data[:, 1] = rng.uniform(49152.0, 65535.0, n) / _PORT_MAX

    # [2] dst_port: well-known (80, 443, 53, 25)
    common_ports = np.array([80, 443, 443, 443, 53, 25, 8080, 993])
    data[:, 2] = rng.choice(common_ports, n).astype(np.float64) / _PORT_MAX

    # [3] protocol: mostly TCP(0), some UDP(1) for DNS
    data[:, 3] = rng.choice([0.0, 0.0, 0.0, 1.0], n) / 2.0

    # [4] bytes_sent (log): moderate
    data[:, 4] = _log_norm(rng.lognormal(8.0, 1.5, n))

    # [5] bytes_received (log): moderate-high (downloads)
    data[:, 5] = _log_norm(rng.lognormal(9.0, 1.8, n))

    # [6] packets_sent (log)
    data[:, 6] = _log_norm(rng.lognormal(3.5, 1.0, n))

    # [7] packets_received (log)
    data[:, 7] = _log_norm(rng.lognormal(4.0, 1.2, n))

    # [8] bytes_ratio: balanced (~0.3-0.5)
    data[:, 8] = _bounded_normal(rng, 0.35, 0.12, n)

    # [9] packet_ratio
    data[:, 9] = _bounded_normal(rng, 0.4, 0.1, n)

    # [10] avg_packet_size_sent: typical (~200-1000 bytes → normalized)
    data[:, 10] = _bounded_normal(rng, 0.35, 0.12, n)

    # [11] avg_packet_size_received
    data[:, 11] = _bounded_normal(rng, 0.45, 0.15, n)

    # [12] std_packet_size_sent
    data[:, 12] = _bounded_normal(rng, 0.25, 0.1, n)

    # [13] std_packet_size_received
    data[:, 13] = _bounded_normal(rng, 0.3, 0.12, n)

    # [14-19] inter_arrival_time_stats outbound
    data[:, 14] = _bounded_normal(rng, 0.3, 0.12, n)   # mean
    data[:, 15] = _bounded_normal(rng, 0.35, 0.15, n)   # std
    data[:, 16] = _bounded_normal(rng, 0.01, 0.005, n)  # min
    data[:, 17] = _bounded_normal(rng, 0.6, 0.2, n)     # max
    data[:, 18] = _bounded_normal(rng, 0.25, 0.1, n)    # median
    data[:, 19] = _bounded_normal(rng, 0.5, 0.15, n)    # skew

    # [20-25] inter_arrival_time_stats inbound
    data[:, 20] = _bounded_normal(rng, 0.25, 0.1, n)
    data[:, 21] = _bounded_normal(rng, 0.3, 0.12, n)
    data[:, 22] = _bounded_normal(rng, 0.01, 0.005, n)
    data[:, 23] = _bounded_normal(rng, 0.55, 0.2, n)
    data[:, 24] = _bounded_normal(rng, 0.2, 0.1, n)
    data[:, 25] = _bounded_normal(rng, 0.5, 0.15, n)

    # [26] payload_entropy: moderate
    data[:, 26] = _bounded_normal(rng, 0.55, 0.15, n)

    # [27] has_tls: often
    data[:, 27] = (rng.random(n) < 0.7).astype(np.float64)

    # [28] tls_version: mostly TLS 1.2/1.3
    data[:, 28] = _bounded_normal(rng, 0.8, 0.1, n)

    # [29] cipher_suite_category: standard
    data[:, 29] = _bounded_normal(rng, 0.7, 0.1, n)

    # [30] dns_query_count: low
    data[:, 30] = _bounded_normal(rng, 0.05, 0.03, n)

    # [31] dns_avg_query_length: typical (15-30 chars)
    data[:, 31] = _bounded_normal(rng, 0.25, 0.08, n)

    # [32] dns_max_query_length
    data[:, 32] = _bounded_normal(rng, 0.3, 0.1, n)

    # [33] dns_unique_domains: low
    data[:, 33] = _bounded_normal(rng, 0.04, 0.03, n)

    # [34] dns_entropy_mean: moderate (human-readable domains)
    data[:, 34] = _bounded_normal(rng, 0.45, 0.1, n)

    # [35] http_request_count
    data[:, 35] = _bounded_normal(rng, 0.15, 0.1, n)

    # [36] http_response_count
    data[:, 36] = _bounded_normal(rng, 0.15, 0.1, n)

    # [37] http_avg_content_length
    data[:, 37] = _bounded_normal(rng, 0.3, 0.15, n)

    # [38] connection_count_to_dst: low
    data[:, 38] = _bounded_normal(rng, 0.08, 0.05, n)

    # [39] unique_dst_ips_from_src: low
    data[:, 39] = _bounded_normal(rng, 0.05, 0.03, n)

    # [40] is_internal_dst: sometimes
    data[:, 40] = (rng.random(n) < 0.3).astype(np.float64)

    # [41] is_well_known_port: yes
    data[:, 41] = (rng.random(n) < 0.85).astype(np.float64)

    # [42] tcp_flags_syn_ratio: normal
    data[:, 42] = _bounded_normal(rng, 0.08, 0.03, n)

    # [43] tcp_flags_fin_ratio
    data[:, 43] = _bounded_normal(rng, 0.06, 0.02, n)

    # [44] tcp_flags_rst_ratio: low
    data[:, 44] = _bounded_normal(rng, 0.02, 0.01, n)

    # [45] tcp_retransmit_ratio: low
    data[:, 45] = _bounded_normal(rng, 0.02, 0.015, n)

    # [46] idle_time_ratio: moderate
    data[:, 46] = _bounded_normal(rng, 0.4, 0.15, n)

    # [47] burst_count
    data[:, 47] = _bounded_normal(rng, 0.15, 0.08, n)

    # [48] burst_avg_duration
    data[:, 48] = _bounded_normal(rng, 0.2, 0.1, n)

    # [49] burst_avg_bytes
    data[:, 49] = _bounded_normal(rng, 0.3, 0.12, n)

    # [50] periodicity_score: low (irregular human traffic)
    data[:, 50] = _bounded_normal(rng, 0.15, 0.08, n)

    # [51] jitter_coefficient: high (variable human timing)
    data[:, 51] = _bounded_normal(rng, 0.6, 0.15, n)

    # [52] payload_printable_ratio
    data[:, 52] = _bounded_normal(rng, 0.5, 0.15, n)

    # [53] payload_null_ratio
    data[:, 53] = _bounded_normal(rng, 0.05, 0.03, n)

    # [54] has_known_c2_pattern: no
    data[:, 54] = 0.0

    # [55] domain_length: moderate
    data[:, 55] = _bounded_normal(rng, 0.25, 0.08, n)

    # [56] domain_consonant_ratio: normal English
    data[:, 56] = _bounded_normal(rng, 0.5, 0.08, n)

    # [57] domain_digit_ratio: low
    data[:, 57] = _bounded_normal(rng, 0.08, 0.05, n)

    # [58] domain_entropy: moderate
    data[:, 58] = _bounded_normal(rng, 0.5, 0.1, n)

    # [59] subdomain_count: 1-3
    data[:, 59] = _bounded_normal(rng, 0.15, 0.08, n)

    # [60] geo_distance_score
    data[:, 60] = _bounded_normal(rng, 0.4, 0.2, n)

    # [61] time_of_day_encoded (sin)
    data[:, 61] = _bounded_normal(rng, 0.0, 0.5, n, lo=-1.0, hi=1.0) * 0.5 + 0.5

    # [62] time_of_day_encoded (cos)
    data[:, 62] = _bounded_normal(rng, 0.0, 0.5, n, lo=-1.0, hi=1.0) * 0.5 + 0.5

    # [63] session_duration_anomaly_score: low
    data[:, 63] = _bounded_normal(rng, 0.1, 0.06, n)

    return _clip01(data)


def _generate_c2beacon(rng: np.random.Generator, n: int) -> NDArray[np.float64]:
    """Generate C2 beacon flow feature vectors.

    Profile: high periodicity (0.7-0.95), consistent payload sizes,
    moderate bytes, specific ports, low jitter coefficient.
    """
    data = np.zeros((n, FEATURE_DIM), dtype=np.float64)

    # [0] duration: long sessions (minutes to hours)
    data[:, 0] = _log_norm(rng.lognormal(7.0, 1.0, n))

    # [1] src_port: ephemeral
    data[:, 1] = rng.uniform(49152.0, 65535.0, n) / _PORT_MAX

    # [2] dst_port: common C2 ports (443, 8443, 8080, 4443, 1337)
    c2_ports = np.array([443, 443, 8443, 8080, 4443, 1337, 9090])
    data[:, 2] = rng.choice(c2_ports, n).astype(np.float64) / _PORT_MAX

    # [3] protocol: TCP
    data[:, 3] = 0.0

    # [4] bytes_sent: moderate (small check-ins)
    data[:, 4] = _log_norm(rng.lognormal(6.5, 0.8, n))

    # [5] bytes_received: moderate (commands are small)
    data[:, 5] = _log_norm(rng.lognormal(6.0, 0.8, n))

    # [6] packets_sent
    data[:, 6] = _log_norm(rng.lognormal(3.0, 0.6, n))

    # [7] packets_received
    data[:, 7] = _log_norm(rng.lognormal(2.8, 0.6, n))

    # [8] bytes_ratio: slightly more sent (beacons out)
    data[:, 8] = _bounded_normal(rng, 0.55, 0.08, n)

    # [9] packet_ratio
    data[:, 9] = _bounded_normal(rng, 0.52, 0.08, n)

    # [10] avg_packet_size_sent: CONSISTENT (key C2 indicator)
    data[:, 10] = _bounded_normal(rng, 0.2, 0.03, n)

    # [11] avg_packet_size_received: CONSISTENT
    data[:, 11] = _bounded_normal(rng, 0.18, 0.03, n)

    # [12] std_packet_size_sent: VERY LOW (constant payloads)
    data[:, 12] = _bounded_normal(rng, 0.04, 0.02, n)

    # [13] std_packet_size_received: VERY LOW
    data[:, 13] = _bounded_normal(rng, 0.05, 0.02, n)

    # [14-19] outbound IAT: regular with low variance
    data[:, 14] = _bounded_normal(rng, 0.45, 0.08, n)   # mean (regular interval)
    data[:, 15] = _bounded_normal(rng, 0.06, 0.03, n)   # std — very low
    data[:, 16] = _bounded_normal(rng, 0.35, 0.08, n)   # min close to mean
    data[:, 17] = _bounded_normal(rng, 0.55, 0.08, n)   # max close to mean
    data[:, 18] = _bounded_normal(rng, 0.45, 0.08, n)   # median ≈ mean
    data[:, 19] = _bounded_normal(rng, 0.5, 0.05, n)    # skew near 0

    # [20-25] inbound IAT: similar regularity
    data[:, 20] = _bounded_normal(rng, 0.42, 0.08, n)
    data[:, 21] = _bounded_normal(rng, 0.07, 0.03, n)
    data[:, 22] = _bounded_normal(rng, 0.33, 0.08, n)
    data[:, 23] = _bounded_normal(rng, 0.52, 0.08, n)
    data[:, 24] = _bounded_normal(rng, 0.42, 0.08, n)
    data[:, 25] = _bounded_normal(rng, 0.5, 0.05, n)

    # [26] payload_entropy: moderate-high (encrypted C2)
    data[:, 26] = _bounded_normal(rng, 0.75, 0.08, n)

    # [27] has_tls: often (encrypted C2)
    data[:, 27] = (rng.random(n) < 0.8).astype(np.float64)

    # [28] tls_version: varied (some use older TLS)
    data[:, 28] = _bounded_normal(rng, 0.7, 0.15, n)

    # [29] cipher_suite_category
    data[:, 29] = _bounded_normal(rng, 0.6, 0.15, n)

    # [30-34] DNS: minimal
    data[:, 30] = _bounded_normal(rng, 0.02, 0.01, n)
    data[:, 31] = _bounded_normal(rng, 0.2, 0.08, n)
    data[:, 32] = _bounded_normal(rng, 0.25, 0.08, n)
    data[:, 33] = _bounded_normal(rng, 0.02, 0.01, n)
    data[:, 34] = _bounded_normal(rng, 0.45, 0.1, n)

    # [35-37] HTTP: minimal
    data[:, 35] = _bounded_normal(rng, 0.05, 0.03, n)
    data[:, 36] = _bounded_normal(rng, 0.05, 0.03, n)
    data[:, 37] = _bounded_normal(rng, 0.15, 0.08, n)

    # [38] connection_count_to_dst: single persistent
    data[:, 38] = _bounded_normal(rng, 0.02, 0.01, n)

    # [39] unique_dst_ips: very few (1-2 C2 servers)
    data[:, 39] = _bounded_normal(rng, 0.01, 0.005, n)

    # [40] is_internal_dst: no (external C2)
    data[:, 40] = (rng.random(n) < 0.05).astype(np.float64)

    # [41] is_well_known_port: sometimes (443)
    data[:, 41] = (rng.random(n) < 0.5).astype(np.float64)

    # [42-45] TCP flags: normal
    data[:, 42] = _bounded_normal(rng, 0.05, 0.02, n)
    data[:, 43] = _bounded_normal(rng, 0.04, 0.02, n)
    data[:, 44] = _bounded_normal(rng, 0.01, 0.005, n)
    data[:, 45] = _bounded_normal(rng, 0.02, 0.01, n)

    # [46] idle_time_ratio: high (mostly waiting between beacons)
    data[:, 46] = _bounded_normal(rng, 0.75, 0.08, n)

    # [47] burst_count: many (each beacon = burst)
    data[:, 47] = _bounded_normal(rng, 0.5, 0.12, n)

    # [48] burst_avg_duration: very short
    data[:, 48] = _bounded_normal(rng, 0.05, 0.025, n)

    # [49] burst_avg_bytes: CONSISTENT
    data[:, 49] = _bounded_normal(rng, 0.15, 0.03, n)

    # [50] periodicity_score: HIGH — key C2 indicator
    data[:, 50] = _bounded_normal(rng, 0.82, 0.06, n)

    # [51] jitter_coefficient: LOW (regular timing)
    data[:, 51] = _bounded_normal(rng, 0.15, 0.06, n)

    # [52] payload_printable_ratio: low (encrypted/binary)
    data[:, 52] = _bounded_normal(rng, 0.25, 0.1, n)

    # [53] payload_null_ratio: low
    data[:, 53] = _bounded_normal(rng, 0.03, 0.02, n)

    # [54] has_known_c2_pattern: sometimes
    data[:, 54] = (rng.random(n) < 0.35).astype(np.float64)

    # [55-59] domain features: minimal (direct IP or single domain)
    data[:, 55] = _bounded_normal(rng, 0.2, 0.08, n)
    data[:, 56] = _bounded_normal(rng, 0.5, 0.1, n)
    data[:, 57] = _bounded_normal(rng, 0.1, 0.06, n)
    data[:, 58] = _bounded_normal(rng, 0.5, 0.1, n)
    data[:, 59] = _bounded_normal(rng, 0.1, 0.06, n)

    # [60] geo_distance: often foreign
    data[:, 60] = _bounded_normal(rng, 0.7, 0.15, n)

    # [61-62] time_of_day: spread (bots work 24/7)
    data[:, 61] = rng.random(n)
    data[:, 62] = rng.random(n)

    # [63] session_duration_anomaly: moderate (long sessions unusual)
    data[:, 63] = _bounded_normal(rng, 0.45, 0.12, n)

    return _clip01(data)


def _generate_exfiltration(rng: np.random.Generator, n: int) -> NDArray[np.float64]:
    """Generate data exfiltration flow feature vectors.

    Profile: very high bytes_sent, low bytes_received, long sessions,
    non-standard ports, many connections.
    """
    data = np.zeros((n, FEATURE_DIM), dtype=np.float64)

    # [0] duration: long
    data[:, 0] = _log_norm(rng.lognormal(8.0, 1.2, n))

    # [1] src_port: ephemeral
    data[:, 1] = rng.uniform(49152.0, 65535.0, n) / _PORT_MAX

    # [2] dst_port: non-standard or cloud storage
    exfil_ports = np.array([443, 8443, 993, 5222, 22, 21, 3128, 8888, 9001])
    data[:, 2] = rng.choice(exfil_ports, n).astype(np.float64) / _PORT_MAX

    # [3] protocol: TCP
    data[:, 3] = 0.0

    # [4] bytes_sent: VERY HIGH — key exfil indicator
    data[:, 4] = _log_norm(rng.lognormal(14.0, 1.5, n))

    # [5] bytes_received: low (acks only)
    data[:, 5] = _log_norm(rng.lognormal(6.0, 1.0, n))

    # [6] packets_sent: high
    data[:, 6] = _log_norm(rng.lognormal(6.0, 1.0, n))

    # [7] packets_received: low
    data[:, 7] = _log_norm(rng.lognormal(3.5, 0.8, n))

    # [8] bytes_ratio: VERY HIGH (mostly outbound)
    data[:, 8] = _bounded_normal(rng, 0.88, 0.05, n)

    # [9] packet_ratio: high
    data[:, 9] = _bounded_normal(rng, 0.75, 0.08, n)

    # [10] avg_packet_size_sent: large (bulk data)
    data[:, 10] = _bounded_normal(rng, 0.8, 0.08, n)

    # [11] avg_packet_size_received: small (acks)
    data[:, 11] = _bounded_normal(rng, 0.08, 0.04, n)

    # [12] std_packet_size_sent: moderate
    data[:, 12] = _bounded_normal(rng, 0.2, 0.08, n)

    # [13] std_packet_size_received: low
    data[:, 13] = _bounded_normal(rng, 0.05, 0.03, n)

    # [14-19] outbound IAT: continuous streaming
    data[:, 14] = _bounded_normal(rng, 0.05, 0.03, n)   # mean — very low
    data[:, 15] = _bounded_normal(rng, 0.08, 0.04, n)   # std
    data[:, 16] = _bounded_normal(rng, 0.001, 0.001, n)  # min
    data[:, 17] = _bounded_normal(rng, 0.15, 0.08, n)    # max
    data[:, 18] = _bounded_normal(rng, 0.03, 0.02, n)    # median
    data[:, 19] = _bounded_normal(rng, 0.65, 0.1, n)     # skew (right-skewed bursts)

    # [20-25] inbound IAT: sparse ACKs
    data[:, 20] = _bounded_normal(rng, 0.08, 0.04, n)
    data[:, 21] = _bounded_normal(rng, 0.1, 0.05, n)
    data[:, 22] = _bounded_normal(rng, 0.002, 0.001, n)
    data[:, 23] = _bounded_normal(rng, 0.2, 0.1, n)
    data[:, 24] = _bounded_normal(rng, 0.06, 0.03, n)
    data[:, 25] = _bounded_normal(rng, 0.6, 0.1, n)

    # [26] payload_entropy: high (often encrypted/compressed data)
    data[:, 26] = _bounded_normal(rng, 0.82, 0.06, n)

    # [27] has_tls: often
    data[:, 27] = (rng.random(n) < 0.7).astype(np.float64)

    # [28] tls_version
    data[:, 28] = _bounded_normal(rng, 0.75, 0.12, n)

    # [29] cipher_suite
    data[:, 29] = _bounded_normal(rng, 0.65, 0.12, n)

    # [30-34] DNS: minimal
    data[:, 30] = _bounded_normal(rng, 0.03, 0.02, n)
    data[:, 31] = _bounded_normal(rng, 0.2, 0.08, n)
    data[:, 32] = _bounded_normal(rng, 0.25, 0.1, n)
    data[:, 33] = _bounded_normal(rng, 0.02, 0.01, n)
    data[:, 34] = _bounded_normal(rng, 0.45, 0.1, n)

    # [35-37] HTTP: some
    data[:, 35] = _bounded_normal(rng, 0.1, 0.05, n)
    data[:, 36] = _bounded_normal(rng, 0.08, 0.04, n)
    data[:, 37] = _bounded_normal(rng, 0.7, 0.12, n)  # large content

    # [38] connection_count_to_dst: many (parallel exfil)
    data[:, 38] = _bounded_normal(rng, 0.45, 0.15, n)

    # [39] unique_dst_ips: few (staging servers)
    data[:, 39] = _bounded_normal(rng, 0.04, 0.03, n)

    # [40] is_internal_dst: no
    data[:, 40] = (rng.random(n) < 0.05).astype(np.float64)

    # [41] is_well_known_port: sometimes
    data[:, 41] = (rng.random(n) < 0.45).astype(np.float64)

    # [42-45] TCP flags: normal
    data[:, 42] = _bounded_normal(rng, 0.06, 0.02, n)
    data[:, 43] = _bounded_normal(rng, 0.04, 0.02, n)
    data[:, 44] = _bounded_normal(rng, 0.015, 0.008, n)
    data[:, 45] = _bounded_normal(rng, 0.03, 0.015, n)

    # [46] idle_time_ratio: low (continuous transfer)
    data[:, 46] = _bounded_normal(rng, 0.1, 0.05, n)

    # [47] burst_count: few long bursts
    data[:, 47] = _bounded_normal(rng, 0.08, 0.04, n)

    # [48] burst_avg_duration: long
    data[:, 48] = _bounded_normal(rng, 0.7, 0.1, n)

    # [49] burst_avg_bytes: very high
    data[:, 49] = _bounded_normal(rng, 0.85, 0.07, n)

    # [50] periodicity: low (sustained transfer, not periodic)
    data[:, 50] = _bounded_normal(rng, 0.12, 0.06, n)

    # [51] jitter: moderate
    data[:, 51] = _bounded_normal(rng, 0.4, 0.12, n)

    # [52] payload_printable_ratio: low (binary/encrypted data)
    data[:, 52] = _bounded_normal(rng, 0.2, 0.08, n)

    # [53] payload_null_ratio: low
    data[:, 53] = _bounded_normal(rng, 0.02, 0.01, n)

    # [54] has_known_c2_pattern: no
    data[:, 54] = (rng.random(n) < 0.05).astype(np.float64)

    # [55-59] domain features: minimal
    data[:, 55] = _bounded_normal(rng, 0.2, 0.08, n)
    data[:, 56] = _bounded_normal(rng, 0.5, 0.1, n)
    data[:, 57] = _bounded_normal(rng, 0.08, 0.05, n)
    data[:, 58] = _bounded_normal(rng, 0.5, 0.1, n)
    data[:, 59] = _bounded_normal(rng, 0.1, 0.06, n)

    # [60] geo_distance: often far
    data[:, 60] = _bounded_normal(rng, 0.65, 0.15, n)

    # [61-62] time_of_day: often after-hours
    data[:, 61] = _bounded_normal(rng, 0.8, 0.12, n)
    data[:, 62] = _bounded_normal(rng, 0.3, 0.15, n)

    # [63] session_duration_anomaly: high (unusually long)
    data[:, 63] = _bounded_normal(rng, 0.65, 0.12, n)

    return _clip01(data)


def _generate_lateral_movement(rng: np.random.Generator, n: int) -> NDArray[np.float64]:
    """Generate lateral movement flow feature vectors.

    Profile: SMB/WMI/RPC to internal IPs, credential relay,
    internal-only destinations, specific ports.
    """
    data = np.zeros((n, FEATURE_DIM), dtype=np.float64)

    # [0] duration: short-moderate
    data[:, 0] = _log_norm(rng.lognormal(4.0, 1.5, n))

    # [1] src_port: ephemeral
    data[:, 1] = rng.uniform(49152.0, 65535.0, n) / _PORT_MAX

    # [2] dst_port: SMB(445), RPC(135), WMI(5985/5986), WinRM, RDP(3389)
    lat_ports = np.array([445, 445, 135, 135, 5985, 5986, 3389, 139])
    data[:, 2] = rng.choice(lat_ports, n).astype(np.float64) / _PORT_MAX

    # [3] protocol: TCP
    data[:, 3] = 0.0

    # [4] bytes_sent: moderate (commands, cred hashes)
    data[:, 4] = _log_norm(rng.lognormal(8.0, 1.2, n))

    # [5] bytes_received: moderate (responses)
    data[:, 5] = _log_norm(rng.lognormal(8.5, 1.3, n))

    # [6-7] packets
    data[:, 6] = _log_norm(rng.lognormal(3.5, 0.8, n))
    data[:, 7] = _log_norm(rng.lognormal(3.5, 0.8, n))

    # [8-9] ratios: roughly balanced
    data[:, 8] = _bounded_normal(rng, 0.45, 0.08, n)
    data[:, 9] = _bounded_normal(rng, 0.48, 0.08, n)

    # [10-13] packet sizes: moderate
    data[:, 10] = _bounded_normal(rng, 0.35, 0.1, n)
    data[:, 11] = _bounded_normal(rng, 0.4, 0.12, n)
    data[:, 12] = _bounded_normal(rng, 0.25, 0.1, n)
    data[:, 13] = _bounded_normal(rng, 0.28, 0.1, n)

    # [14-19] outbound IAT
    data[:, 14] = _bounded_normal(rng, 0.15, 0.08, n)
    data[:, 15] = _bounded_normal(rng, 0.2, 0.1, n)
    data[:, 16] = _bounded_normal(rng, 0.005, 0.003, n)
    data[:, 17] = _bounded_normal(rng, 0.4, 0.15, n)
    data[:, 18] = _bounded_normal(rng, 0.1, 0.06, n)
    data[:, 19] = _bounded_normal(rng, 0.55, 0.1, n)

    # [20-25] inbound IAT
    data[:, 20] = _bounded_normal(rng, 0.12, 0.06, n)
    data[:, 21] = _bounded_normal(rng, 0.18, 0.08, n)
    data[:, 22] = _bounded_normal(rng, 0.004, 0.002, n)
    data[:, 23] = _bounded_normal(rng, 0.35, 0.15, n)
    data[:, 24] = _bounded_normal(rng, 0.08, 0.05, n)
    data[:, 25] = _bounded_normal(rng, 0.55, 0.1, n)

    # [26] payload_entropy: moderate
    data[:, 26] = _bounded_normal(rng, 0.55, 0.12, n)

    # [27] has_tls: sometimes (WinRM HTTPS)
    data[:, 27] = (rng.random(n) < 0.3).astype(np.float64)

    # [28-29] TLS: when present
    data[:, 28] = _bounded_normal(rng, 0.6, 0.2, n)
    data[:, 29] = _bounded_normal(rng, 0.5, 0.2, n)

    # [30-34] DNS: minimal
    data[:, 30] = _bounded_normal(rng, 0.01, 0.008, n)
    data[:, 31] = _bounded_normal(rng, 0.15, 0.06, n)
    data[:, 32] = _bounded_normal(rng, 0.2, 0.08, n)
    data[:, 33] = _bounded_normal(rng, 0.01, 0.005, n)
    data[:, 34] = _bounded_normal(rng, 0.4, 0.1, n)

    # [35-37] HTTP: minimal
    data[:, 35] = _bounded_normal(rng, 0.03, 0.02, n)
    data[:, 36] = _bounded_normal(rng, 0.03, 0.02, n)
    data[:, 37] = _bounded_normal(rng, 0.15, 0.08, n)

    # [38] connection_count_to_dst: multiple internal hosts
    data[:, 38] = _bounded_normal(rng, 0.35, 0.12, n)

    # [39] unique_dst_ips: MANY (spreading across network)
    data[:, 39] = _bounded_normal(rng, 0.4, 0.15, n)

    # [40] is_internal_dst: YES — key indicator
    data[:, 40] = (rng.random(n) < 0.92).astype(np.float64)

    # [41] is_well_known_port: no (non-web ports)
    data[:, 41] = (rng.random(n) < 0.15).astype(np.float64)

    # [42-45] TCP flags
    data[:, 42] = _bounded_normal(rng, 0.1, 0.04, n)   # more SYN (new connections)
    data[:, 43] = _bounded_normal(rng, 0.08, 0.03, n)
    data[:, 44] = _bounded_normal(rng, 0.04, 0.02, n)   # some RST (failed attempts)
    data[:, 45] = _bounded_normal(rng, 0.025, 0.012, n)

    # [46] idle_time: moderate
    data[:, 46] = _bounded_normal(rng, 0.35, 0.12, n)

    # [47] burst_count: several
    data[:, 47] = _bounded_normal(rng, 0.3, 0.1, n)

    # [48] burst_avg_duration
    data[:, 48] = _bounded_normal(rng, 0.15, 0.08, n)

    # [49] burst_avg_bytes
    data[:, 49] = _bounded_normal(rng, 0.3, 0.1, n)

    # [50] periodicity: low-moderate
    data[:, 50] = _bounded_normal(rng, 0.25, 0.1, n)

    # [51] jitter: moderate
    data[:, 51] = _bounded_normal(rng, 0.45, 0.12, n)

    # [52] payload_printable: moderate (SMB commands have structure)
    data[:, 52] = _bounded_normal(rng, 0.35, 0.1, n)

    # [53] payload_null: moderate (SMB padding)
    data[:, 53] = _bounded_normal(rng, 0.1, 0.04, n)

    # [54] has_known_c2_pattern: no
    data[:, 54] = (rng.random(n) < 0.08).astype(np.float64)

    # [55-59] domain: not applicable (IP-based)
    data[:, 55] = _bounded_normal(rng, 0.05, 0.03, n)
    data[:, 56] = _bounded_normal(rng, 0.3, 0.15, n)
    data[:, 57] = _bounded_normal(rng, 0.3, 0.15, n)
    data[:, 58] = _bounded_normal(rng, 0.3, 0.12, n)
    data[:, 59] = _bounded_normal(rng, 0.02, 0.01, n)

    # [60] geo_distance: LOCAL
    data[:, 60] = _bounded_normal(rng, 0.05, 0.03, n)

    # [61-62] time_of_day: often after-hours
    data[:, 61] = _bounded_normal(rng, 0.75, 0.15, n)
    data[:, 62] = _bounded_normal(rng, 0.35, 0.15, n)

    # [63] session_duration_anomaly: moderate
    data[:, 63] = _bounded_normal(rng, 0.35, 0.12, n)

    return _clip01(data)


def _generate_scanning(rng: np.random.Generator, n: int) -> NDArray[np.float64]:
    """Generate port/network scanning flow feature vectors.

    Profile: many connections, small payloads, sequential ports/IPs,
    short duration, high SYN ratio, many unique destinations.
    """
    data = np.zeros((n, FEATURE_DIM), dtype=np.float64)

    # [0] duration: very short per connection
    data[:, 0] = _log_norm(rng.exponential(0.5, n))

    # [1] src_port: ephemeral
    data[:, 1] = rng.uniform(49152.0, 65535.0, n) / _PORT_MAX

    # [2] dst_port: sequential or common
    data[:, 2] = rng.uniform(1.0, 65535.0, n) / _PORT_MAX

    # [3] protocol: TCP (SYN scan)
    data[:, 3] = rng.choice([0.0, 0.0, 0.0, 1.0], n) / 2.0

    # [4] bytes_sent: TINY (SYN packets only)
    data[:, 4] = _log_norm(rng.lognormal(3.5, 0.8, n))

    # [5] bytes_received: tiny or zero (RST or no response)
    data[:, 5] = _log_norm(rng.lognormal(3.0, 1.0, n))

    # [6] packets_sent: one per target
    data[:, 6] = _log_norm(rng.lognormal(1.5, 0.6, n))

    # [7] packets_received: few
    data[:, 7] = _log_norm(rng.lognormal(1.0, 0.8, n))

    # [8] bytes_ratio: slightly more sent
    data[:, 8] = _bounded_normal(rng, 0.6, 0.12, n)

    # [9] packet_ratio
    data[:, 9] = _bounded_normal(rng, 0.6, 0.1, n)

    # [10] avg_packet_size_sent: TINY (SYN = ~60 bytes)
    data[:, 10] = _bounded_normal(rng, 0.04, 0.02, n)

    # [11] avg_packet_size_received: tiny
    data[:, 11] = _bounded_normal(rng, 0.04, 0.02, n)

    # [12] std_packet_size_sent: very low
    data[:, 12] = _bounded_normal(rng, 0.02, 0.01, n)

    # [13] std_packet_size_received: very low
    data[:, 13] = _bounded_normal(rng, 0.02, 0.01, n)

    # [14-19] outbound IAT: very rapid
    data[:, 14] = _bounded_normal(rng, 0.01, 0.005, n)   # mean — very fast
    data[:, 15] = _bounded_normal(rng, 0.02, 0.01, n)    # std
    data[:, 16] = _bounded_normal(rng, 0.0005, 0.0003, n)  # min
    data[:, 17] = _bounded_normal(rng, 0.05, 0.03, n)    # max
    data[:, 18] = _bounded_normal(rng, 0.008, 0.004, n)   # median
    data[:, 19] = _bounded_normal(rng, 0.7, 0.1, n)      # skew

    # [20-25] inbound IAT: sparse (most targets don't respond)
    data[:, 20] = _bounded_normal(rng, 0.15, 0.08, n)
    data[:, 21] = _bounded_normal(rng, 0.25, 0.12, n)
    data[:, 22] = _bounded_normal(rng, 0.01, 0.005, n)
    data[:, 23] = _bounded_normal(rng, 0.5, 0.2, n)
    data[:, 24] = _bounded_normal(rng, 0.1, 0.06, n)
    data[:, 25] = _bounded_normal(rng, 0.65, 0.12, n)

    # [26] payload_entropy: very low (no real payload)
    data[:, 26] = _bounded_normal(rng, 0.1, 0.06, n)

    # [27] has_tls: no
    data[:, 27] = (rng.random(n) < 0.02).astype(np.float64)

    # [28-29] TLS: N/A
    data[:, 28] = 0.0
    data[:, 29] = 0.0

    # [30-34] DNS: no
    data[:, 30:35] = 0.0

    # [35-37] HTTP: no
    data[:, 35:38] = 0.0

    # [38] connection_count_to_dst: very high (many attempts)
    data[:, 38] = _bounded_normal(rng, 0.85, 0.08, n)

    # [39] unique_dst_ips: VERY HIGH — key scanning indicator
    data[:, 39] = _bounded_normal(rng, 0.9, 0.06, n)

    # [40] is_internal_dst: mixed
    data[:, 40] = (rng.random(n) < 0.5).astype(np.float64)

    # [41] is_well_known_port: mixed
    data[:, 41] = (rng.random(n) < 0.4).astype(np.float64)

    # [42] tcp_flags_syn_ratio: VERY HIGH
    data[:, 42] = _bounded_normal(rng, 0.85, 0.06, n)

    # [43] fin_ratio: low
    data[:, 43] = _bounded_normal(rng, 0.02, 0.01, n)

    # [44] rst_ratio: high (connection refused)
    data[:, 44] = _bounded_normal(rng, 0.4, 0.12, n)

    # [45] retransmit: low
    data[:, 45] = _bounded_normal(rng, 0.01, 0.005, n)

    # [46] idle_time: very low (rapid fire)
    data[:, 46] = _bounded_normal(rng, 0.05, 0.03, n)

    # [47] burst_count: essentially one long burst
    data[:, 47] = _bounded_normal(rng, 0.05, 0.03, n)

    # [48] burst_avg_duration: short
    data[:, 48] = _bounded_normal(rng, 0.03, 0.02, n)

    # [49] burst_avg_bytes: tiny
    data[:, 49] = _bounded_normal(rng, 0.02, 0.01, n)

    # [50] periodicity: moderate (machine-gun timing)
    data[:, 50] = _bounded_normal(rng, 0.45, 0.12, n)

    # [51] jitter: low (automated)
    data[:, 51] = _bounded_normal(rng, 0.15, 0.08, n)

    # [52] payload_printable: N/A
    data[:, 52] = _bounded_normal(rng, 0.1, 0.06, n)

    # [53] payload_null: N/A
    data[:, 53] = _bounded_normal(rng, 0.02, 0.01, n)

    # [54] has_known_c2_pattern: no
    data[:, 54] = 0.0

    # [55-59] domain: N/A (IP-based scanning)
    data[:, 55] = _bounded_normal(rng, 0.02, 0.01, n)
    data[:, 56] = 0.0
    data[:, 57] = 0.0
    data[:, 58] = _bounded_normal(rng, 0.1, 0.06, n)
    data[:, 59] = 0.0

    # [60] geo_distance: mixed
    data[:, 60] = _bounded_normal(rng, 0.4, 0.2, n)

    # [61-62] time_of_day: any
    data[:, 61] = rng.random(n)
    data[:, 62] = rng.random(n)

    # [63] session_duration_anomaly: low (short is normal for scans)
    data[:, 63] = _bounded_normal(rng, 0.15, 0.08, n)

    return _clip01(data)


def _generate_dga_domain(rng: np.random.Generator, n: int) -> NDArray[np.float64]:
    """Generate DGA domain flow feature vectors.

    Profile: high-entropy domains (>3.5), high consonant ratio, many
    unique domains, algorithmically generated names, frequent DNS lookups.
    """
    data = np.zeros((n, FEATURE_DIM), dtype=np.float64)

    # [0] duration: short (DNS queries)
    data[:, 0] = _log_norm(rng.exponential(2.0, n))

    # [1] src_port: ephemeral
    data[:, 1] = rng.uniform(49152.0, 65535.0, n) / _PORT_MAX

    # [2] dst_port: DNS (53)
    data[:, 2] = 53.0 / _PORT_MAX

    # [3] protocol: UDP for DNS
    data[:, 3] = 1.0 / 2.0

    # [4] bytes_sent: small (DNS queries)
    data[:, 4] = _log_norm(rng.lognormal(5.0, 0.8, n))

    # [5] bytes_received: small (DNS responses, mostly NXDOMAIN)
    data[:, 5] = _log_norm(rng.lognormal(5.5, 0.8, n))

    # [6-7] packets
    data[:, 6] = _log_norm(rng.lognormal(2.5, 0.6, n))
    data[:, 7] = _log_norm(rng.lognormal(2.5, 0.6, n))

    # [8-9] ratios: balanced
    data[:, 8] = _bounded_normal(rng, 0.45, 0.06, n)
    data[:, 9] = _bounded_normal(rng, 0.48, 0.06, n)

    # [10-13] packet sizes: small DNS
    data[:, 10] = _bounded_normal(rng, 0.08, 0.03, n)
    data[:, 11] = _bounded_normal(rng, 0.1, 0.04, n)
    data[:, 12] = _bounded_normal(rng, 0.03, 0.02, n)
    data[:, 13] = _bounded_normal(rng, 0.04, 0.02, n)

    # [14-19] outbound IAT: rapid DNS queries
    data[:, 14] = _bounded_normal(rng, 0.03, 0.015, n)
    data[:, 15] = _bounded_normal(rng, 0.04, 0.02, n)
    data[:, 16] = _bounded_normal(rng, 0.001, 0.0005, n)
    data[:, 17] = _bounded_normal(rng, 0.1, 0.05, n)
    data[:, 18] = _bounded_normal(rng, 0.02, 0.01, n)
    data[:, 19] = _bounded_normal(rng, 0.6, 0.1, n)

    # [20-25] inbound IAT
    data[:, 20] = _bounded_normal(rng, 0.03, 0.015, n)
    data[:, 21] = _bounded_normal(rng, 0.04, 0.02, n)
    data[:, 22] = _bounded_normal(rng, 0.001, 0.0005, n)
    data[:, 23] = _bounded_normal(rng, 0.1, 0.05, n)
    data[:, 24] = _bounded_normal(rng, 0.02, 0.01, n)
    data[:, 25] = _bounded_normal(rng, 0.6, 0.1, n)

    # [26] payload_entropy: moderate (DNS query format)
    data[:, 26] = _bounded_normal(rng, 0.5, 0.1, n)

    # [27] has_tls: no (plain DNS)
    data[:, 27] = (rng.random(n) < 0.05).astype(np.float64)

    # [28-29] TLS: N/A
    data[:, 28] = 0.0
    data[:, 29] = 0.0

    # [30] dns_query_count: HIGH
    data[:, 30] = _bounded_normal(rng, 0.7, 0.1, n)

    # [31] dns_avg_query_length: long (DGA generates 15-30 char domains)
    data[:, 31] = _bounded_normal(rng, 0.55, 0.08, n)

    # [32] dns_max_query_length: long
    data[:, 32] = _bounded_normal(rng, 0.65, 0.08, n)

    # [33] dns_unique_domains: VERY HIGH (each DGA query is different)
    data[:, 33] = _bounded_normal(rng, 0.85, 0.06, n)

    # [34] dns_entropy_mean: HIGH — key DGA indicator
    data[:, 34] = _bounded_normal(rng, 0.8, 0.06, n)

    # [35-37] HTTP: minimal
    data[:, 35] = _bounded_normal(rng, 0.02, 0.01, n)
    data[:, 36] = _bounded_normal(rng, 0.02, 0.01, n)
    data[:, 37] = _bounded_normal(rng, 0.05, 0.03, n)

    # [38] connection_count: moderate
    data[:, 38] = _bounded_normal(rng, 0.2, 0.08, n)

    # [39] unique_dst_ips: low (all go to DNS resolver)
    data[:, 39] = _bounded_normal(rng, 0.02, 0.01, n)

    # [40] is_internal_dst: going to DNS (internal resolver)
    data[:, 40] = (rng.random(n) < 0.6).astype(np.float64)

    # [41] is_well_known_port: yes (53)
    data[:, 41] = 1.0

    # [42-45] TCP flags: N/A (UDP)
    data[:, 42:46] = 0.0

    # [46] idle_time: low (rapid queries)
    data[:, 46] = _bounded_normal(rng, 0.08, 0.04, n)

    # [47] burst_count
    data[:, 47] = _bounded_normal(rng, 0.4, 0.1, n)

    # [48] burst_avg_duration
    data[:, 48] = _bounded_normal(rng, 0.05, 0.03, n)

    # [49] burst_avg_bytes
    data[:, 49] = _bounded_normal(rng, 0.05, 0.03, n)

    # [50] periodicity: moderate (DGA runs in cycles)
    data[:, 50] = _bounded_normal(rng, 0.35, 0.1, n)

    # [51] jitter: low (automated)
    data[:, 51] = _bounded_normal(rng, 0.2, 0.08, n)

    # [52] payload_printable: moderate (domain names are printable)
    data[:, 52] = _bounded_normal(rng, 0.6, 0.1, n)

    # [53] payload_null: low
    data[:, 53] = _bounded_normal(rng, 0.02, 0.01, n)

    # [54] has_known_c2_pattern: sometimes (known DGA families)
    data[:, 54] = (rng.random(n) < 0.2).astype(np.float64)

    # [55] domain_length: LONG (DGA domains)
    data[:, 55] = _bounded_normal(rng, 0.6, 0.08, n)

    # [56] domain_consonant_ratio: HIGH — key DGA indicator
    data[:, 56] = _bounded_normal(rng, 0.72, 0.06, n)

    # [57] domain_digit_ratio: sometimes high (some DGAs use digits)
    data[:, 57] = _bounded_normal(rng, 0.25, 0.12, n)

    # [58] domain_entropy: HIGH — key DGA indicator (>3.5/max)
    data[:, 58] = _bounded_normal(rng, 0.82, 0.05, n)

    # [59] subdomain_count: low (DGA generates base domains)
    data[:, 59] = _bounded_normal(rng, 0.08, 0.04, n)

    # [60] geo_distance: varied (TLDs from anywhere)
    data[:, 60] = _bounded_normal(rng, 0.5, 0.2, n)

    # [61-62] time_of_day: any
    data[:, 61] = rng.random(n)
    data[:, 62] = rng.random(n)

    # [63] session_duration_anomaly: low
    data[:, 63] = _bounded_normal(rng, 0.15, 0.08, n)

    return _clip01(data)


def _generate_dns_tunnel(rng: np.random.Generator, n: int) -> NDArray[np.float64]:
    """Generate DNS tunnel flow feature vectors.

    Profile: large DNS queries (>50 chars), TXT record queries, high DNS
    entropy, many queries, high data volume through DNS.
    """
    data = np.zeros((n, FEATURE_DIM), dtype=np.float64)

    # [0] duration: moderate-long
    data[:, 0] = _log_norm(rng.lognormal(6.0, 1.0, n))

    # [1] src_port: ephemeral
    data[:, 1] = rng.uniform(49152.0, 65535.0, n) / _PORT_MAX

    # [2] dst_port: DNS (53)
    data[:, 2] = 53.0 / _PORT_MAX

    # [3] protocol: UDP
    data[:, 3] = 1.0 / 2.0

    # [4] bytes_sent: HIGH for DNS (encoded data in queries)
    data[:, 4] = _log_norm(rng.lognormal(9.0, 1.0, n))

    # [5] bytes_received: HIGH (TXT record responses with data)
    data[:, 5] = _log_norm(rng.lognormal(9.5, 1.0, n))

    # [6-7] packets: many
    data[:, 6] = _log_norm(rng.lognormal(5.0, 0.8, n))
    data[:, 7] = _log_norm(rng.lognormal(5.0, 0.8, n))

    # [8-9] ratios: slightly more received (TXT responses are larger)
    data[:, 8] = _bounded_normal(rng, 0.42, 0.06, n)
    data[:, 9] = _bounded_normal(rng, 0.48, 0.06, n)

    # [10-11] avg_packet_size: LARGE for DNS
    data[:, 10] = _bounded_normal(rng, 0.3, 0.06, n)
    data[:, 11] = _bounded_normal(rng, 0.4, 0.08, n)

    # [12-13] std_packet_size
    data[:, 12] = _bounded_normal(rng, 0.12, 0.05, n)
    data[:, 13] = _bounded_normal(rng, 0.15, 0.06, n)

    # [14-19] outbound IAT: rapid continuous
    data[:, 14] = _bounded_normal(rng, 0.05, 0.025, n)
    data[:, 15] = _bounded_normal(rng, 0.06, 0.03, n)
    data[:, 16] = _bounded_normal(rng, 0.002, 0.001, n)
    data[:, 17] = _bounded_normal(rng, 0.12, 0.06, n)
    data[:, 18] = _bounded_normal(rng, 0.04, 0.02, n)
    data[:, 19] = _bounded_normal(rng, 0.6, 0.1, n)

    # [20-25] inbound IAT
    data[:, 20] = _bounded_normal(rng, 0.05, 0.025, n)
    data[:, 21] = _bounded_normal(rng, 0.06, 0.03, n)
    data[:, 22] = _bounded_normal(rng, 0.002, 0.001, n)
    data[:, 23] = _bounded_normal(rng, 0.12, 0.06, n)
    data[:, 24] = _bounded_normal(rng, 0.04, 0.02, n)
    data[:, 25] = _bounded_normal(rng, 0.6, 0.1, n)

    # [26] payload_entropy: HIGH (base32/base64 encoded)
    data[:, 26] = _bounded_normal(rng, 0.78, 0.06, n)

    # [27] has_tls: no (plain DNS)
    data[:, 27] = (rng.random(n) < 0.03).astype(np.float64)

    # [28-29] TLS: N/A
    data[:, 28] = 0.0
    data[:, 29] = 0.0

    # [30] dns_query_count: VERY HIGH — key indicator
    data[:, 30] = _bounded_normal(rng, 0.88, 0.05, n)

    # [31] dns_avg_query_length: VERY LONG (>50 chars → >0.5 normalized)
    data[:, 31] = _bounded_normal(rng, 0.75, 0.06, n)

    # [32] dns_max_query_length: VERY LONG
    data[:, 32] = _bounded_normal(rng, 0.88, 0.04, n)

    # [33] dns_unique_domains: HIGH (each query encodes different data)
    data[:, 33] = _bounded_normal(rng, 0.8, 0.06, n)

    # [34] dns_entropy_mean: VERY HIGH
    data[:, 34] = _bounded_normal(rng, 0.85, 0.04, n)

    # [35-37] HTTP: none
    data[:, 35:38] = 0.0

    # [38] connection_count: high
    data[:, 38] = _bounded_normal(rng, 0.55, 0.12, n)

    # [39] unique_dst_ips: low (single DNS resolver)
    data[:, 39] = _bounded_normal(rng, 0.02, 0.01, n)

    # [40] is_internal_dst: mostly internal DNS
    data[:, 40] = (rng.random(n) < 0.7).astype(np.float64)

    # [41] is_well_known_port: yes (53)
    data[:, 41] = 1.0

    # [42-45] TCP flags: N/A (UDP)
    data[:, 42:46] = 0.0

    # [46] idle_time: low (continuous)
    data[:, 46] = _bounded_normal(rng, 0.1, 0.05, n)

    # [47] burst_count: many
    data[:, 47] = _bounded_normal(rng, 0.6, 0.1, n)

    # [48] burst_avg_duration: short
    data[:, 48] = _bounded_normal(rng, 0.08, 0.04, n)

    # [49] burst_avg_bytes: moderate (each burst = chunk of data)
    data[:, 49] = _bounded_normal(rng, 0.2, 0.08, n)

    # [50] periodicity: moderate
    data[:, 50] = _bounded_normal(rng, 0.4, 0.1, n)

    # [51] jitter: low (automated tool)
    data[:, 51] = _bounded_normal(rng, 0.18, 0.08, n)

    # [52] payload_printable: HIGH (base32/64 are printable)
    data[:, 52] = _bounded_normal(rng, 0.8, 0.06, n)

    # [53] payload_null: very low
    data[:, 53] = _bounded_normal(rng, 0.01, 0.005, n)

    # [54] has_known_c2_pattern: sometimes
    data[:, 54] = (rng.random(n) < 0.15).astype(np.float64)

    # [55] domain_length: VERY LONG (encoded data)
    data[:, 55] = _bounded_normal(rng, 0.85, 0.05, n)

    # [56] domain_consonant_ratio: high (base32/hex)
    data[:, 56] = _bounded_normal(rng, 0.65, 0.08, n)

    # [57] domain_digit_ratio: moderate-high (hex encoding)
    data[:, 57] = _bounded_normal(rng, 0.35, 0.1, n)

    # [58] domain_entropy: VERY HIGH
    data[:, 58] = _bounded_normal(rng, 0.88, 0.04, n)

    # [59] subdomain_count: HIGH (data in subdomains)
    data[:, 59] = _bounded_normal(rng, 0.7, 0.08, n)

    # [60] geo_distance: varied
    data[:, 60] = _bounded_normal(rng, 0.5, 0.2, n)

    # [61-62] time_of_day
    data[:, 61] = rng.random(n)
    data[:, 62] = rng.random(n)

    # [63] session_duration_anomaly: moderate
    data[:, 63] = _bounded_normal(rng, 0.35, 0.12, n)

    return _clip01(data)


def _generate_cryptomining(rng: np.random.Generator, n: int) -> NDArray[np.float64]:
    """Generate crypto-mining flow feature vectors.

    Profile: Stratum protocol, specific ports (3333/4444/8333),
    long duration, high bandwidth, specific payload patterns.
    """
    data = np.zeros((n, FEATURE_DIM), dtype=np.float64)

    # [0] duration: VERY LONG (persistent mining sessions)
    data[:, 0] = _log_norm(rng.lognormal(10.0, 0.8, n))

    # [1] src_port: ephemeral
    data[:, 1] = rng.uniform(49152.0, 65535.0, n) / _PORT_MAX

    # [2] dst_port: SPECIFIC mining ports
    mining_ports = np.array([3333, 4444, 8333, 3334, 14444, 45560, 9999])
    data[:, 2] = rng.choice(mining_ports, n).astype(np.float64) / _PORT_MAX

    # [3] protocol: TCP
    data[:, 3] = 0.0

    # [4] bytes_sent: moderate (share submissions)
    data[:, 4] = _log_norm(rng.lognormal(9.0, 1.0, n))

    # [5] bytes_received: moderate-high (job assignments)
    data[:, 5] = _log_norm(rng.lognormal(9.5, 1.0, n))

    # [6-7] packets: many over long session
    data[:, 6] = _log_norm(rng.lognormal(5.5, 0.8, n))
    data[:, 7] = _log_norm(rng.lognormal(5.5, 0.8, n))

    # [8] bytes_ratio: roughly balanced (JSON-RPC bidirectional)
    data[:, 8] = _bounded_normal(rng, 0.45, 0.06, n)

    # [9] packet_ratio
    data[:, 9] = _bounded_normal(rng, 0.48, 0.06, n)

    # [10] avg_packet_size_sent: moderate (JSON submissions)
    data[:, 10] = _bounded_normal(rng, 0.2, 0.06, n)

    # [11] avg_packet_size_received: moderate
    data[:, 11] = _bounded_normal(rng, 0.25, 0.06, n)

    # [12] std_packet_size_sent: moderate
    data[:, 12] = _bounded_normal(rng, 0.12, 0.05, n)

    # [13] std_packet_size_received
    data[:, 13] = _bounded_normal(rng, 0.15, 0.06, n)

    # [14-19] outbound IAT: somewhat periodic (share submissions)
    data[:, 14] = _bounded_normal(rng, 0.2, 0.08, n)
    data[:, 15] = _bounded_normal(rng, 0.15, 0.06, n)
    data[:, 16] = _bounded_normal(rng, 0.01, 0.005, n)
    data[:, 17] = _bounded_normal(rng, 0.5, 0.15, n)
    data[:, 18] = _bounded_normal(rng, 0.15, 0.06, n)
    data[:, 19] = _bounded_normal(rng, 0.55, 0.1, n)

    # [20-25] inbound IAT
    data[:, 20] = _bounded_normal(rng, 0.15, 0.06, n)
    data[:, 21] = _bounded_normal(rng, 0.12, 0.05, n)
    data[:, 22] = _bounded_normal(rng, 0.008, 0.004, n)
    data[:, 23] = _bounded_normal(rng, 0.4, 0.12, n)
    data[:, 24] = _bounded_normal(rng, 0.12, 0.05, n)
    data[:, 25] = _bounded_normal(rng, 0.55, 0.1, n)

    # [26] payload_entropy: moderate (JSON-RPC is structured text)
    data[:, 26] = _bounded_normal(rng, 0.55, 0.08, n)

    # [27] has_tls: sometimes (Stratum over TLS)
    data[:, 27] = (rng.random(n) < 0.35).astype(np.float64)

    # [28-29] TLS: when present
    data[:, 28] = _bounded_normal(rng, 0.6, 0.2, n)
    data[:, 29] = _bounded_normal(rng, 0.5, 0.2, n)

    # [30-34] DNS: minimal
    data[:, 30] = _bounded_normal(rng, 0.02, 0.01, n)
    data[:, 31] = _bounded_normal(rng, 0.2, 0.08, n)
    data[:, 32] = _bounded_normal(rng, 0.25, 0.1, n)
    data[:, 33] = _bounded_normal(rng, 0.01, 0.005, n)
    data[:, 34] = _bounded_normal(rng, 0.4, 0.1, n)

    # [35-37] HTTP: none (Stratum protocol)
    data[:, 35:38] = 0.0

    # [38] connection_count: low (single persistent)
    data[:, 38] = _bounded_normal(rng, 0.02, 0.01, n)

    # [39] unique_dst_ips: very few (1-2 mining pools)
    data[:, 39] = _bounded_normal(rng, 0.01, 0.005, n)

    # [40] is_internal_dst: no
    data[:, 40] = (rng.random(n) < 0.03).astype(np.float64)

    # [41] is_well_known_port: no (mining-specific)
    data[:, 41] = (rng.random(n) < 0.05).astype(np.float64)

    # [42-45] TCP flags: normal
    data[:, 42] = _bounded_normal(rng, 0.03, 0.015, n)
    data[:, 43] = _bounded_normal(rng, 0.02, 0.01, n)
    data[:, 44] = _bounded_normal(rng, 0.01, 0.005, n)
    data[:, 45] = _bounded_normal(rng, 0.015, 0.008, n)

    # [46] idle_time: low (continuous mining)
    data[:, 46] = _bounded_normal(rng, 0.15, 0.06, n)

    # [47] burst_count: moderate (share submissions)
    data[:, 47] = _bounded_normal(rng, 0.35, 0.1, n)

    # [48] burst_avg_duration: moderate
    data[:, 48] = _bounded_normal(rng, 0.2, 0.08, n)

    # [49] burst_avg_bytes: moderate
    data[:, 49] = _bounded_normal(rng, 0.25, 0.08, n)

    # [50] periodicity: MODERATE-HIGH (regular share submissions)
    data[:, 50] = _bounded_normal(rng, 0.55, 0.1, n)

    # [51] jitter: low-moderate
    data[:, 51] = _bounded_normal(rng, 0.25, 0.08, n)

    # [52] payload_printable: HIGH (JSON text)
    data[:, 52] = _bounded_normal(rng, 0.75, 0.06, n)

    # [53] payload_null: low
    data[:, 53] = _bounded_normal(rng, 0.02, 0.01, n)

    # [54] has_known_c2_pattern: no (mining, not C2)
    data[:, 54] = (rng.random(n) < 0.03).astype(np.float64)

    # [55] domain_length: moderate (pool.domain.com)
    data[:, 55] = _bounded_normal(rng, 0.3, 0.08, n)

    # [56] domain_consonant_ratio: normal
    data[:, 56] = _bounded_normal(rng, 0.5, 0.08, n)

    # [57] domain_digit_ratio: low
    data[:, 57] = _bounded_normal(rng, 0.08, 0.04, n)

    # [58] domain_entropy: moderate
    data[:, 58] = _bounded_normal(rng, 0.5, 0.1, n)

    # [59] subdomain_count: 1-2
    data[:, 59] = _bounded_normal(rng, 0.15, 0.06, n)

    # [60] geo_distance: often far (international mining pools)
    data[:, 60] = _bounded_normal(rng, 0.65, 0.15, n)

    # [61-62] time_of_day: 24/7
    data[:, 61] = rng.random(n)
    data[:, 62] = rng.random(n)

    # [63] session_duration_anomaly: HIGH (extremely long sessions)
    data[:, 63] = _bounded_normal(rng, 0.8, 0.08, n)

    return _clip01(data)


# ---------------------------------------------------------------------------
# Main generation function
# ---------------------------------------------------------------------------

_CLASS_GENERATORS = {
    0: _generate_normal,
    1: _generate_c2beacon,
    2: _generate_exfiltration,
    3: _generate_lateral_movement,
    4: _generate_scanning,
    5: _generate_dga_domain,
    6: _generate_dns_tunnel,
    7: _generate_cryptomining,
}

CLASS_NAMES: list[str] = [
    "Normal",
    "C2Beacon",
    "Exfiltration",
    "LateralMovement",
    "Scanning",
    "DGADomain",
    "DNSTunnel",
    "CryptoMining",
]


def generate_network_dataset(
    *,
    samples_per_class: int = DEFAULT_SAMPLES_PER_CLASS,
    seed: int = DEFAULT_SEED,
    batch_size: int = DEFAULT_BATCH_SIZE,
    train_ratio: float = 0.8,
    val_ratio: float = 0.1,
    num_workers: int = 0,
    output_dir: Optional[str] = None,
) -> NetworkDataSplit:
    """Generate synthetic network flow dataset and return split DataLoaders.

    Args:
        samples_per_class: Number of samples per class.
        seed: Random seed for reproducibility.
        batch_size: Batch size for DataLoaders.
        train_ratio: Fraction for training set.
        val_ratio: Fraction for validation set.
        num_workers: DataLoader worker count.
        output_dir: If set, save raw tensors to this directory.

    Returns:
        NetworkDataSplit with train/val/test loaders and tensors.
    """
    rng = np.random.default_rng(seed)
    total_per_class = samples_per_class

    logger.info(
        "Generating network dataset: %d samples/class × %d classes = %d total",
        total_per_class,
        NUM_CLASSES,
        total_per_class * NUM_CLASSES,
    )

    start_time = time.monotonic()

    all_features: list[NDArray[np.float64]] = []
    all_labels: list[NDArray[np.int64]] = []

    for cls_idx in range(NUM_CLASSES):
        generator = _CLASS_GENERATORS[cls_idx]
        features = generator(rng, total_per_class)
        labels = np.full(total_per_class, cls_idx, dtype=np.int64)

        all_features.append(features)
        all_labels.append(labels)

        logger.info(
            "  Class %d (%s): %d samples, mean_entropy=%.4f, mean_bytes_ratio=%.4f",
            cls_idx,
            CLASS_NAMES[cls_idx],
            total_per_class,
            float(features[:, 26].mean()),
            float(features[:, 8].mean()),
        )

    X = np.concatenate(all_features, axis=0)
    y = np.concatenate(all_labels, axis=0)

    # Shuffle deterministically
    shuffle_idx = rng.permutation(len(X))
    X = X[shuffle_idx]
    y = y[shuffle_idx]

    # Split
    n_total = len(X)
    n_train = int(n_total * train_ratio)
    n_val = int(n_total * val_ratio)

    X_train = torch.tensor(X[:n_train], dtype=torch.float32)
    y_train = torch.tensor(y[:n_train], dtype=torch.long)
    X_val = torch.tensor(X[n_train : n_train + n_val], dtype=torch.float32)
    y_val = torch.tensor(y[n_train : n_train + n_val], dtype=torch.long)
    X_test = torch.tensor(X[n_train + n_val :], dtype=torch.float32)
    y_test = torch.tensor(y[n_train + n_val :], dtype=torch.long)

    train_loader = DataLoader(
        TensorDataset(X_train, y_train),
        batch_size=batch_size,
        shuffle=True,
        num_workers=num_workers,
        pin_memory=True,
        drop_last=False,
    )
    val_loader = DataLoader(
        TensorDataset(X_val, y_val),
        batch_size=batch_size,
        shuffle=False,
        num_workers=num_workers,
        pin_memory=True,
    )
    test_loader = DataLoader(
        TensorDataset(X_test, y_test),
        batch_size=batch_size,
        shuffle=False,
        num_workers=num_workers,
        pin_memory=True,
    )

    elapsed = time.monotonic() - start_time

    logger.info(
        "Dataset ready: train=%d val=%d test=%d (%.2fs)",
        len(X_train),
        len(X_val),
        len(X_test),
        elapsed,
    )

    if output_dir is not None:
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        torch.save(X_train, out_path / "network_X_train.pt")
        torch.save(y_train, out_path / "network_y_train.pt")
        torch.save(X_val, out_path / "network_X_val.pt")
        torch.save(y_val, out_path / "network_y_val.pt")
        torch.save(X_test, out_path / "network_X_test.pt")
        torch.save(y_test, out_path / "network_y_test.pt")

        metadata = {
            "feature_dim": FEATURE_DIM,
            "num_classes": NUM_CLASSES,
            "class_names": CLASS_NAMES,
            "samples_per_class": total_per_class,
            "train_size": len(X_train),
            "val_size": len(X_val),
            "test_size": len(X_test),
            "seed": seed,
            "generation_time_sec": round(elapsed, 3),
        }
        (out_path / "network_metadata.json").write_text(
            json.dumps(metadata, indent=2), encoding="utf-8"
        )
        logger.info("Tensors saved to %s", out_path)

    return NetworkDataSplit(
        X_train=X_train,
        y_train=y_train,
        X_val=X_val,
        y_val=y_val,
        X_test=X_test,
        y_test=y_test,
        train_loader=train_loader,
        val_loader=val_loader,
        test_loader=test_loader,
        feature_dim=FEATURE_DIM,
        num_classes=NUM_CLASSES,
        class_names=CLASS_NAMES,
    )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate synthetic network flow feature data for Cortex-Network",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--samples-per-class",
        type=int,
        default=DEFAULT_SAMPLES_PER_CLASS,
        help="Number of samples to generate per class",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
        help="Random seed for reproducibility",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help="Batch size for DataLoaders",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Directory to save generated tensors (optional)",
    )
    parser.add_argument(
        "--train-ratio",
        type=float,
        default=0.8,
        help="Fraction of data for training",
    )
    parser.add_argument(
        "--val-ratio",
        type=float,
        default=0.1,
        help="Fraction of data for validation",
    )
    return parser


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    args = _build_parser().parse_args()

    split = generate_network_dataset(
        samples_per_class=args.samples_per_class,
        seed=args.seed,
        batch_size=args.batch_size,
        train_ratio=args.train_ratio,
        val_ratio=args.val_ratio,
        output_dir=args.output_dir,
    )

    logger.info("Generation complete:")
    logger.info("  Feature dim:  %d", split.feature_dim)
    logger.info("  Num classes:  %d", split.num_classes)
    logger.info("  Train:        %d samples", len(split.X_train))
    logger.info("  Validation:   %d samples", len(split.X_val))
    logger.info("  Test:         %d samples", len(split.X_test))

    for cls_idx, cls_name in enumerate(split.class_names):
        mask = split.y_train == cls_idx
        count = int(mask.sum())
        if count > 0:
            cls_data = split.X_train[mask]
            logger.info(
                "  %s (train): n=%d entropy=%.3f bytes_ratio=%.3f periodicity=%.3f",
                cls_name,
                count,
                float(cls_data[:, 26].mean()),
                float(cls_data[:, 8].mean()),
                float(cls_data[:, 50].mean()),
            )


if __name__ == "__main__":
    main()
