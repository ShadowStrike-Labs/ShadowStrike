"""
PhantomCortex Synthetic Memory Region Data Generator
=====================================================

Generates synthetic 128-dimensional feature vectors for 5 memory region
classes used to train the Cortex-Memory MLP classifier.  Each class has
a statistically realistic profile derived from real-world memory analysis
of benign applications, shellcode injectors, ROP exploit chains, encrypted
payloads, and packed executables.

Classes (from MemoryRegionClass):
    0 — Benign       : normal application memory
    1 — Shellcode    : injected code with NOP sleds, syscalls, stack pivots
    2 — ROP          : gadget chains with many RET and tiny basic blocks
    3 — Encrypted    : near-maximum entropy, uniform byte distribution
    4 — Packed       : compressed PE with mixed section entropies

Usage:
    python -m PhantomCortex.training.data.memory_generator \\
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

logger = logging.getLogger("PhantomCortex.Data.MemoryGenerator")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FEATURE_DIM: int = 128
NUM_CLASSES: int = 5
DEFAULT_SAMPLES_PER_CLASS: int = 10_000
DEFAULT_SEED: int = 42
DEFAULT_BATCH_SIZE: int = 512
RESERVED_START: int = 120
RESERVED_END: int = 128

# Protection encoding: 0=R, 1=RW, 2=RX, 3=RWX, 4=NOACCESS
# Allocation type: 0=commit, 1=reserve, 2=image, 3=mapped


# ---------------------------------------------------------------------------
# Dataclass for split datasets
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MemoryDataSplit:
    """Holds train/val/test tensors and loaders for memory region data."""

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
# Per-class generators
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


def _generate_benign(rng: np.random.Generator, n: int) -> NDArray[np.float64]:
    """Generate benign memory region feature vectors.

    Profile: moderate entropy (2-5), standard RW or R protection,
    structured data, many printable characters, no suspicious patterns.
    """
    data = np.zeros((n, FEATURE_DIM), dtype=np.float64)

    # [0] region_size log2: typical 12-22 (4KB-4MB)
    data[:, 0] = rng.uniform(12.0, 22.0, n) / 32.0

    # [1] protection: mostly R(0) or RW(1)
    prot_choices = np.array([0, 1, 1, 1, 0], dtype=np.float64)
    data[:, 1] = rng.choice(prot_choices, n) / 4.0

    # [2] allocation_type: commit(0) or image(2) or mapped(3)
    alloc_choices = np.array([0, 0, 2, 3], dtype=np.float64)
    data[:, 2] = rng.choice(alloc_choices, n) / 3.0

    # [3] is_executable: rarely
    data[:, 3] = (rng.random(n) < 0.05).astype(np.float64)

    # [4] is_writable: often for RW regions
    data[:, 4] = (rng.random(n) < 0.6).astype(np.float64)

    # [5] is_readable: always
    data[:, 5] = 1.0

    # [6-13] byte_entropy_per_eighth: moderate (2-5)/8
    for i in range(8):
        data[:, 6 + i] = _bounded_normal(rng, 0.45, 0.12, n)

    # [14] overall_entropy: 2-5 out of 8
    data[:, 14] = _bounded_normal(rng, 0.44, 0.12, n)

    # [15] chi_squared: moderate deviation from uniform
    data[:, 15] = _bounded_normal(rng, 0.65, 0.15, n)

    # [16-31] byte_bigram_top16: structured, some dominant bigrams
    for i in range(16):
        data[:, 16 + i] = _bounded_normal(rng, 0.04 + 0.02 * (15 - i) / 15.0, 0.02, n)

    # [32-47] first_16_bytes: common PE/data headers or structured
    for i in range(16):
        data[:, 32 + i] = _bounded_normal(rng, 0.3, 0.2, n)

    # [48-63] last_16_bytes
    for i in range(16):
        data[:, 48 + i] = _bounded_normal(rng, 0.25, 0.18, n)

    # [64] has_pe_header: sometimes
    data[:, 64] = (rng.random(n) < 0.15).astype(np.float64)

    # [65] has_elf_header: rarely on Windows
    data[:, 65] = 0.0

    # [66] null_bytes_ratio: moderate
    data[:, 66] = _bounded_normal(rng, 0.15, 0.08, n)

    # [67] printable_ratio: high for benign
    data[:, 67] = _bounded_normal(rng, 0.65, 0.12, n)

    # [68] longest_printable_run: long
    data[:, 68] = _bounded_normal(rng, 0.6, 0.15, n)

    # [69] unique_bytes/256: moderate
    data[:, 69] = _bounded_normal(rng, 0.55, 0.15, n)

    # [70] mean_byte_value/255: around 0.35 for text-heavy
    data[:, 70] = _bounded_normal(rng, 0.35, 0.1, n)

    # [71] std_byte_value/128: moderate
    data[:, 71] = _bounded_normal(rng, 0.4, 0.1, n)

    # [72-77] instruction ratios: very low for data regions
    data[:, 72] = _bounded_normal(rng, 0.005, 0.003, n)  # RET
    data[:, 73] = _bounded_normal(rng, 0.003, 0.002, n)  # CALL
    data[:, 74] = _bounded_normal(rng, 0.004, 0.002, n)  # JMP
    data[:, 75] = _bounded_normal(rng, 0.002, 0.001, n)  # NOP
    data[:, 76] = _bounded_normal(rng, 0.001, 0.001, n)  # INT3
    data[:, 77] = _bounded_normal(rng, 0.0005, 0.0003, n)  # syscall

    # [78] has_stack_pivot: no
    data[:, 78] = 0.0

    # [79] avg_basic_block_size: large if code, 0 if data
    data[:, 79] = _bounded_normal(rng, 0.1, 0.08, n)

    # [80-95] n_gram_4_features
    for i in range(16):
        data[:, 80 + i] = _bounded_normal(rng, 0.03, 0.02, n)

    # [96-111] section_entropy_features: mostly zero or moderate
    for i in range(16):
        if i < 4:
            data[:, 96 + i] = _bounded_normal(rng, 0.4, 0.15, n)
        else:
            data[:, 96 + i] = _bounded_normal(rng, 0.02, 0.02, n)

    # [112] imports_count
    data[:, 112] = _bounded_normal(rng, 0.15, 0.1, n)

    # [113] exports_count
    data[:, 113] = _bounded_normal(rng, 0.02, 0.02, n)

    # [114] has_tls_callbacks
    data[:, 114] = (rng.random(n) < 0.02).astype(np.float64)

    # [115] reloc_count
    data[:, 115] = _bounded_normal(rng, 0.1, 0.08, n)

    # [116] suspicious_api_import_ratio: very low
    data[:, 116] = _bounded_normal(rng, 0.02, 0.015, n)

    # [117] string_obfuscation_score: very low
    data[:, 117] = _bounded_normal(rng, 0.05, 0.03, n)

    # [118] code_to_data_ratio: low (mostly data)
    data[:, 118] = _bounded_normal(rng, 0.2, 0.1, n)

    # [119] alignment_score: high
    data[:, 119] = _bounded_normal(rng, 0.85, 0.08, n)

    # [120-127] reserved padding
    data[:, RESERVED_START:RESERVED_END] = 0.0

    return _clip01(data)


def _generate_shellcode(rng: np.random.Generator, n: int) -> NDArray[np.float64]:
    """Generate shellcode memory region feature vectors.

    Profile: high entropy (6.5-7.8), RWX/RX protection, high NOP/INT3
    ratios, stack pivots, small region sizes, syscall stubs.
    """
    data = np.zeros((n, FEATURE_DIM), dtype=np.float64)

    # [0] region_size log2: small 10-16 (1KB-64KB)
    data[:, 0] = rng.uniform(10.0, 16.0, n) / 32.0

    # [1] protection: RWX(3) or RX(2)
    prot = rng.choice([2.0, 3.0, 3.0, 3.0, 2.0], n)
    data[:, 1] = prot / 4.0

    # [2] allocation_type: commit(0)
    data[:, 2] = 0.0

    # [3] is_executable: always
    data[:, 3] = 1.0

    # [4] is_writable: often (RWX)
    data[:, 4] = (rng.random(n) < 0.75).astype(np.float64)

    # [5] is_readable: always
    data[:, 5] = 1.0

    # [6-13] byte_entropy_per_eighth: high (6.5-7.8)/8
    for i in range(8):
        data[:, 6 + i] = _bounded_normal(rng, 0.89, 0.05, n)

    # [14] overall_entropy: high
    data[:, 14] = _bounded_normal(rng, 0.89, 0.04, n)

    # [15] chi_squared: moderately high (non-uniform but high entropy)
    data[:, 15] = _bounded_normal(rng, 0.35, 0.12, n)

    # [16-31] byte_bigram_top16: somewhat flat
    for i in range(16):
        data[:, 16 + i] = _bounded_normal(rng, 0.015, 0.008, n)

    # [32-47] first_16_bytes: may contain decoder stubs
    for i in range(16):
        data[:, 32 + i] = _bounded_normal(rng, 0.5, 0.25, n)

    # [48-63] last_16_bytes: often NOPs or terminators
    for i in range(16):
        data[:, 48 + i] = _bounded_normal(rng, 0.45, 0.22, n)

    # [64] has_pe_header: no
    data[:, 64] = 0.0

    # [65] has_elf_header: no
    data[:, 65] = 0.0

    # [66] null_bytes_ratio: low-moderate
    data[:, 66] = _bounded_normal(rng, 0.08, 0.04, n)

    # [67] printable_ratio: low
    data[:, 67] = _bounded_normal(rng, 0.25, 0.1, n)

    # [68] longest_printable_run: short
    data[:, 68] = _bounded_normal(rng, 0.1, 0.06, n)

    # [69] unique_bytes/256: high
    data[:, 69] = _bounded_normal(rng, 0.85, 0.07, n)

    # [70] mean_byte_value/255: centered
    data[:, 70] = _bounded_normal(rng, 0.5, 0.08, n)

    # [71] std_byte_value/128: high
    data[:, 71] = _bounded_normal(rng, 0.58, 0.08, n)

    # [72-77] instruction ratios: shellcode patterns
    data[:, 72] = _bounded_normal(rng, 0.015, 0.008, n)   # RET
    data[:, 73] = _bounded_normal(rng, 0.025, 0.012, n)   # CALL
    data[:, 74] = _bounded_normal(rng, 0.02, 0.01, n)     # JMP
    data[:, 75] = _bounded_normal(rng, 0.06, 0.025, n)    # NOP — high
    data[:, 76] = _bounded_normal(rng, 0.03, 0.015, n)    # INT3 — elevated
    data[:, 77] = _bounded_normal(rng, 0.015, 0.008, n)   # syscall — present

    # [78] has_stack_pivot: common
    data[:, 78] = (rng.random(n) < 0.55).astype(np.float64)

    # [79] avg_basic_block_size: moderate (8-20 insns)
    data[:, 79] = _bounded_normal(rng, 0.35, 0.12, n)

    # [80-95] n_gram_4_features: shellcode patterns (xor decoder stubs, etc.)
    for i in range(16):
        data[:, 80 + i] = _bounded_normal(rng, 0.025, 0.015, n)

    # [96-111] section_entropy_features: not PE, mostly zeros
    data[:, 96:112] = 0.0

    # [112-115] PE fields: zeros (not a PE)
    data[:, 112:116] = 0.0

    # [116] suspicious_api_import_ratio: N/A (direct syscalls)
    data[:, 116] = 0.0

    # [117] string_obfuscation_score: moderate
    data[:, 117] = _bounded_normal(rng, 0.45, 0.15, n)

    # [118] code_to_data_ratio: high (mostly code)
    data[:, 118] = _bounded_normal(rng, 0.85, 0.08, n)

    # [119] alignment_score: low (hand-crafted code, no compiler alignment)
    data[:, 119] = _bounded_normal(rng, 0.3, 0.12, n)

    # [120-127] reserved
    data[:, RESERVED_START:RESERVED_END] = 0.0

    return _clip01(data)


def _generate_rop(rng: np.random.Generator, n: int) -> NDArray[np.float64]:
    """Generate ROP chain memory region feature vectors.

    Profile: many 0xC3 (RET) bytes, very small avg basic block (2-6 bytes),
    variable entropy, often found in image regions.
    """
    data = np.zeros((n, FEATURE_DIM), dtype=np.float64)

    # [0] region_size: medium — often from loaded image sections
    data[:, 0] = rng.uniform(14.0, 24.0, n) / 32.0

    # [1] protection: RX(2) or R(0) — image sections
    prot = rng.choice([0.0, 2.0, 2.0, 2.0, 2.0], n)
    data[:, 1] = prot / 4.0

    # [2] allocation_type: image(2) — from loaded DLLs/EXEs
    alloc = rng.choice([2.0, 2.0, 2.0, 0.0], n)
    data[:, 2] = alloc / 3.0

    # [3] is_executable: yes
    data[:, 3] = (rng.random(n) < 0.85).astype(np.float64)

    # [4] is_writable: no (image sections)
    data[:, 4] = (rng.random(n) < 0.1).astype(np.float64)

    # [5] is_readable: always
    data[:, 5] = 1.0

    # [6-13] byte_entropy: moderate-high, variable
    for i in range(8):
        data[:, 6 + i] = _bounded_normal(rng, 0.72, 0.1, n)

    # [14] overall_entropy: 5-7
    data[:, 14] = _bounded_normal(rng, 0.75, 0.08, n)

    # [15] chi_squared: moderate
    data[:, 15] = _bounded_normal(rng, 0.45, 0.12, n)

    # [16-31] bigrams: 0xC3-heavy patterns
    for i in range(16):
        data[:, 16 + i] = _bounded_normal(rng, 0.02, 0.01, n)
    # Boost RET-adjacent bigrams
    data[:, 16] = _bounded_normal(rng, 0.08, 0.03, n)  # top bigram (likely C3-related)
    data[:, 17] = _bounded_normal(rng, 0.06, 0.02, n)

    # [32-47] first_16_bytes: code prologue patterns
    for i in range(16):
        data[:, 32 + i] = _bounded_normal(rng, 0.4, 0.2, n)

    # [48-63] last_16_bytes
    for i in range(16):
        data[:, 48 + i] = _bounded_normal(rng, 0.4, 0.2, n)

    # [64] has_pe_header: yes (from image)
    data[:, 64] = (rng.random(n) < 0.7).astype(np.float64)

    # [65] has_elf_header
    data[:, 65] = 0.0

    # [66] null_bytes_ratio: low
    data[:, 66] = _bounded_normal(rng, 0.06, 0.03, n)

    # [67] printable_ratio: moderate
    data[:, 67] = _bounded_normal(rng, 0.35, 0.1, n)

    # [68] longest_printable_run
    data[:, 68] = _bounded_normal(rng, 0.2, 0.1, n)

    # [69] unique_bytes/256: high (diverse code)
    data[:, 69] = _bounded_normal(rng, 0.8, 0.08, n)

    # [70] mean_byte_value/255
    data[:, 70] = _bounded_normal(rng, 0.45, 0.08, n)

    # [71] std_byte_value/128
    data[:, 71] = _bounded_normal(rng, 0.5, 0.08, n)

    # [72] RET ratio: VERY HIGH — hallmark of ROP
    data[:, 72] = _bounded_normal(rng, 0.12, 0.04, n)

    # [73] CALL
    data[:, 73] = _bounded_normal(rng, 0.01, 0.005, n)

    # [74] JMP: moderate (gadgets may end in jmp)
    data[:, 74] = _bounded_normal(rng, 0.03, 0.015, n)

    # [75] NOP: low
    data[:, 75] = _bounded_normal(rng, 0.008, 0.004, n)

    # [76] INT3: low
    data[:, 76] = _bounded_normal(rng, 0.004, 0.003, n)

    # [77] syscall: low
    data[:, 77] = _bounded_normal(rng, 0.002, 0.001, n)

    # [78] has_stack_pivot: sometimes
    data[:, 78] = (rng.random(n) < 0.35).astype(np.float64)

    # [79] avg_basic_block_size: VERY SMALL (2-6 bytes) — key ROP feature
    data[:, 79] = _bounded_normal(rng, 0.06, 0.025, n)

    # [80-95] n_gram_4_features
    for i in range(16):
        data[:, 80 + i] = _bounded_normal(rng, 0.02, 0.012, n)

    # [96-111] section_entropy: present if PE
    for i in range(16):
        if i < 3:
            data[:, 96 + i] = _bounded_normal(rng, 0.75, 0.1, n)
        elif i < 6:
            data[:, 96 + i] = _bounded_normal(rng, 0.3, 0.15, n)
        else:
            data[:, 96 + i] = _bounded_normal(rng, 0.02, 0.02, n)

    # [112] imports_count: moderate
    data[:, 112] = _bounded_normal(rng, 0.3, 0.15, n)

    # [113] exports_count
    data[:, 113] = _bounded_normal(rng, 0.1, 0.08, n)

    # [114] has_tls_callbacks
    data[:, 114] = (rng.random(n) < 0.05).astype(np.float64)

    # [115] reloc_count
    data[:, 115] = _bounded_normal(rng, 0.2, 0.1, n)

    # [116] suspicious_api_import_ratio: low-moderate
    data[:, 116] = _bounded_normal(rng, 0.08, 0.04, n)

    # [117] string_obfuscation_score: low
    data[:, 117] = _bounded_normal(rng, 0.1, 0.06, n)

    # [118] code_to_data_ratio: high (mostly code)
    data[:, 118] = _bounded_normal(rng, 0.8, 0.1, n)

    # [119] alignment_score: moderate (compiler-generated gadgets)
    data[:, 119] = _bounded_normal(rng, 0.6, 0.12, n)

    # [120-127] reserved
    data[:, RESERVED_START:RESERVED_END] = 0.0

    return _clip01(data)


def _generate_encrypted(rng: np.random.Generator, n: int) -> NDArray[np.float64]:
    """Generate encrypted payload memory region feature vectors.

    Profile: entropy > 7.5/8, near-uniform byte distribution,
    chi-squared close to expected, no structure, no headers.
    """
    data = np.zeros((n, FEATURE_DIM), dtype=np.float64)

    # [0] region_size: variable
    data[:, 0] = rng.uniform(10.0, 24.0, n) / 32.0

    # [1] protection: RW(1) or R(0) — data, not yet executed
    prot = rng.choice([0.0, 1.0, 1.0, 1.0], n)
    data[:, 1] = prot / 4.0

    # [2] allocation_type: commit(0)
    data[:, 2] = 0.0

    # [3] is_executable: no (encrypted data not yet decoded)
    data[:, 3] = (rng.random(n) < 0.05).astype(np.float64)

    # [4] is_writable: yes
    data[:, 4] = (rng.random(n) < 0.85).astype(np.float64)

    # [5] is_readable: always
    data[:, 5] = 1.0

    # [6-13] byte_entropy_per_eighth: very high (>7.5/8 = 0.9375)
    for i in range(8):
        data[:, 6 + i] = _bounded_normal(rng, 0.96, 0.015, n)

    # [14] overall_entropy: >7.5/8
    data[:, 14] = _bounded_normal(rng, 0.96, 0.012, n)

    # [15] chi_squared: close to expected (uniform) — low deviation
    data[:, 15] = _bounded_normal(rng, 0.12, 0.06, n)

    # [16-31] bigrams: very flat (near uniform distribution)
    for i in range(16):
        data[:, 16 + i] = _bounded_normal(rng, 0.006, 0.002, n)

    # [32-47] first_16_bytes: random-looking
    for i in range(16):
        data[:, 32 + i] = rng.random(n)

    # [48-63] last_16_bytes: random-looking
    for i in range(16):
        data[:, 48 + i] = rng.random(n)

    # [64] has_pe_header: no
    data[:, 64] = 0.0

    # [65] has_elf_header: no
    data[:, 65] = 0.0

    # [66] null_bytes_ratio: close to 1/256 ≈ 0.0039
    data[:, 66] = _bounded_normal(rng, 0.004, 0.002, n)

    # [67] printable_ratio: ~37% of byte space is printable
    data[:, 67] = _bounded_normal(rng, 0.37, 0.03, n)

    # [68] longest_printable_run: short (random data)
    data[:, 68] = _bounded_normal(rng, 0.03, 0.015, n)

    # [69] unique_bytes/256: very high (near 256/256)
    data[:, 69] = _bounded_normal(rng, 0.98, 0.01, n)

    # [70] mean_byte_value/255: centered at 0.5
    data[:, 70] = _bounded_normal(rng, 0.5, 0.02, n)

    # [71] std_byte_value/128: ~73.9/128 for uniform
    data[:, 71] = _bounded_normal(rng, 0.578, 0.02, n)

    # [72-77] instruction ratios: near background rate for random bytes
    data[:, 72] = _bounded_normal(rng, 0.004, 0.001, n)   # RET (1/256)
    data[:, 73] = _bounded_normal(rng, 0.004, 0.001, n)   # CALL
    data[:, 74] = _bounded_normal(rng, 0.008, 0.002, n)   # JMP (2 opcodes)
    data[:, 75] = _bounded_normal(rng, 0.004, 0.001, n)   # NOP
    data[:, 76] = _bounded_normal(rng, 0.004, 0.001, n)   # INT3
    data[:, 77] = _bounded_normal(rng, 0.00002, 0.00001, n)  # syscall (2-byte, ~1/65536)

    # [78] has_stack_pivot: no
    data[:, 78] = 0.0

    # [79] avg_basic_block_size: N/A or noise
    data[:, 79] = _bounded_normal(rng, 0.02, 0.01, n)

    # [80-95] n_gram_4_features: flat
    for i in range(16):
        data[:, 80 + i] = _bounded_normal(rng, 0.005, 0.003, n)

    # [96-111] section_entropy: no PE structure
    data[:, 96:112] = 0.0

    # [112-115] PE fields: none
    data[:, 112:116] = 0.0

    # [116] suspicious_api_import_ratio: none
    data[:, 116] = 0.0

    # [117] string_obfuscation_score: high (looks totally random)
    data[:, 117] = _bounded_normal(rng, 0.9, 0.05, n)

    # [118] code_to_data_ratio: 0 (pure data)
    data[:, 118] = _bounded_normal(rng, 0.02, 0.01, n)

    # [119] alignment_score: random
    data[:, 119] = _bounded_normal(rng, 0.5, 0.2, n)

    # [120-127] reserved
    data[:, RESERVED_START:RESERVED_END] = 0.0

    return _clip01(data)


def _generate_packed(rng: np.random.Generator, n: int) -> NDArray[np.float64]:
    """Generate packed executable memory region feature vectors.

    Profile: PE header present, mixed section entropies (some high, some
    low — compressed code vs metadata), UPX/ASPack/MPRESS patterns.
    """
    data = np.zeros((n, FEATURE_DIM), dtype=np.float64)

    # [0] region_size: medium-large (PE images)
    data[:, 0] = rng.uniform(16.0, 26.0, n) / 32.0

    # [1] protection: RX(2) or RWX(3) — unpacking needs write+execute
    prot = rng.choice([1.0, 2.0, 3.0, 3.0, 2.0], n)
    data[:, 1] = prot / 4.0

    # [2] allocation_type: image(2) or commit(0)
    alloc = rng.choice([0.0, 2.0, 2.0, 0.0], n)
    data[:, 2] = alloc / 3.0

    # [3] is_executable: often
    data[:, 3] = (rng.random(n) < 0.8).astype(np.float64)

    # [4] is_writable: often (unpacking)
    data[:, 4] = (rng.random(n) < 0.6).astype(np.float64)

    # [5] is_readable: always
    data[:, 5] = 1.0

    # [6-13] byte_entropy_per_eighth: mixed — some sections high, some low
    data[:, 6] = _bounded_normal(rng, 0.5, 0.15, n)    # header region low
    data[:, 7] = _bounded_normal(rng, 0.92, 0.04, n)   # compressed section high
    data[:, 8] = _bounded_normal(rng, 0.93, 0.03, n)
    data[:, 9] = _bounded_normal(rng, 0.91, 0.04, n)
    data[:, 10] = _bounded_normal(rng, 0.88, 0.06, n)
    data[:, 11] = _bounded_normal(rng, 0.85, 0.08, n)
    data[:, 12] = _bounded_normal(rng, 0.3, 0.15, n)   # metadata/relocs low
    data[:, 13] = _bounded_normal(rng, 0.2, 0.12, n)   # padding low

    # [14] overall_entropy: high but not max (mixed)
    data[:, 14] = _bounded_normal(rng, 0.82, 0.06, n)

    # [15] chi_squared: moderate (neither uniform nor structured)
    data[:, 15] = _bounded_normal(rng, 0.3, 0.12, n)

    # [16-31] bigrams: semi-structured
    for i in range(16):
        data[:, 16 + i] = _bounded_normal(rng, 0.01, 0.006, n)

    # [32-47] first_16_bytes: PE header: MZ (0x4D, 0x5A)
    data[:, 32] = _bounded_normal(rng, 0.302, 0.01, n)  # 0x4D/255
    data[:, 33] = _bounded_normal(rng, 0.353, 0.01, n)  # 0x5A/255
    data[:, 34] = _bounded_normal(rng, 0.353, 0.02, n)  # 0x90/255
    data[:, 35] = _bounded_normal(rng, 0.0, 0.02, n)
    for i in range(4, 16):
        data[:, 32 + i] = _bounded_normal(rng, 0.1, 0.08, n)

    # [48-63] last_16_bytes: padding or overlay
    for i in range(16):
        data[:, 48 + i] = _bounded_normal(rng, 0.15, 0.1, n)

    # [64] has_pe_header: YES — defining feature
    data[:, 64] = 1.0

    # [65] has_elf_header: no
    data[:, 65] = 0.0

    # [66] null_bytes_ratio: low-moderate
    data[:, 66] = _bounded_normal(rng, 0.1, 0.05, n)

    # [67] printable_ratio: low (compressed)
    data[:, 67] = _bounded_normal(rng, 0.28, 0.08, n)

    # [68] longest_printable_run: short
    data[:, 68] = _bounded_normal(rng, 0.12, 0.06, n)

    # [69] unique_bytes/256: high
    data[:, 69] = _bounded_normal(rng, 0.88, 0.05, n)

    # [70] mean_byte_value/255
    data[:, 70] = _bounded_normal(rng, 0.48, 0.06, n)

    # [71] std_byte_value/128
    data[:, 71] = _bounded_normal(rng, 0.55, 0.06, n)

    # [72-77] instruction ratios: moderate (some code sections present)
    data[:, 72] = _bounded_normal(rng, 0.008, 0.004, n)   # RET
    data[:, 73] = _bounded_normal(rng, 0.006, 0.003, n)   # CALL
    data[:, 74] = _bounded_normal(rng, 0.005, 0.003, n)   # JMP
    data[:, 75] = _bounded_normal(rng, 0.003, 0.002, n)   # NOP
    data[:, 76] = _bounded_normal(rng, 0.002, 0.001, n)   # INT3
    data[:, 77] = _bounded_normal(rng, 0.001, 0.0005, n)  # syscall

    # [78] has_stack_pivot: rarely
    data[:, 78] = (rng.random(n) < 0.1).astype(np.float64)

    # [79] avg_basic_block_size: moderate (decompressed stubs)
    data[:, 79] = _bounded_normal(rng, 0.25, 0.1, n)

    # [80-95] n_gram_4_features: packer signatures (UPX!, .aspack, etc.)
    for i in range(16):
        data[:, 80 + i] = _bounded_normal(rng, 0.018, 0.01, n)
    # Boost packer-specific 4-grams
    data[:, 80] = _bounded_normal(rng, 0.06, 0.02, n)
    data[:, 81] = _bounded_normal(rng, 0.05, 0.02, n)

    # [96-111] section_entropy: MIXED — key packed indicator
    data[:, 96] = _bounded_normal(rng, 0.4, 0.1, n)    # .text header
    data[:, 97] = _bounded_normal(rng, 0.95, 0.02, n)  # UPX0 — compressed
    data[:, 98] = _bounded_normal(rng, 0.93, 0.03, n)  # UPX1 — compressed
    data[:, 99] = _bounded_normal(rng, 0.25, 0.12, n)  # .rsrc — resources
    data[:, 100] = _bounded_normal(rng, 0.15, 0.1, n)  # .reloc
    for i in range(5, 16):
        data[:, 96 + i] = _bounded_normal(rng, 0.02, 0.02, n)

    # [112] imports_count: very few (packed binaries import minimally)
    data[:, 112] = _bounded_normal(rng, 0.03, 0.02, n)

    # [113] exports_count: zero usually
    data[:, 113] = _bounded_normal(rng, 0.005, 0.005, n)

    # [114] has_tls_callbacks: sometimes (anti-debug)
    data[:, 114] = (rng.random(n) < 0.15).astype(np.float64)

    # [115] reloc_count: low
    data[:, 115] = _bounded_normal(rng, 0.05, 0.04, n)

    # [116] suspicious_api_import_ratio: moderate (VirtualAlloc, etc.)
    data[:, 116] = _bounded_normal(rng, 0.35, 0.12, n)

    # [117] string_obfuscation_score: high (strings are packed)
    data[:, 117] = _bounded_normal(rng, 0.7, 0.1, n)

    # [118] code_to_data_ratio: mixed
    data[:, 118] = _bounded_normal(rng, 0.4, 0.12, n)

    # [119] alignment_score: packer-typical (non-standard alignment)
    data[:, 119] = _bounded_normal(rng, 0.45, 0.15, n)

    # [120-127] reserved
    data[:, RESERVED_START:RESERVED_END] = 0.0

    return _clip01(data)


# ---------------------------------------------------------------------------
# Main generation function
# ---------------------------------------------------------------------------

_CLASS_GENERATORS = {
    0: _generate_benign,
    1: _generate_shellcode,
    2: _generate_rop,
    3: _generate_encrypted,
    4: _generate_packed,
}

CLASS_NAMES: list[str] = ["Benign", "Shellcode", "ROP", "Encrypted", "Packed"]


def generate_memory_dataset(
    *,
    samples_per_class: int = DEFAULT_SAMPLES_PER_CLASS,
    seed: int = DEFAULT_SEED,
    batch_size: int = DEFAULT_BATCH_SIZE,
    train_ratio: float = 0.8,
    val_ratio: float = 0.1,
    num_workers: int = 0,
    output_dir: Optional[str] = None,
) -> MemoryDataSplit:
    """Generate synthetic memory region dataset and return split DataLoaders.

    Args:
        samples_per_class: Number of samples per class.
        seed: Random seed for reproducibility.
        batch_size: Batch size for DataLoaders.
        train_ratio: Fraction of data for training.
        val_ratio: Fraction of data for validation.
        num_workers: DataLoader worker count.
        output_dir: If set, save raw tensors to this directory.

    Returns:
        MemoryDataSplit with train/val/test loaders and tensors.
    """
    rng = np.random.default_rng(seed)
    total_per_class = samples_per_class

    logger.info(
        "Generating memory dataset: %d samples/class × %d classes = %d total",
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
            "  Class %d (%s): %d samples, mean_entropy=%.4f",
            cls_idx,
            CLASS_NAMES[cls_idx],
            total_per_class,
            float(features[:, 14].mean()),
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
        torch.save(X_train, out_path / "memory_X_train.pt")
        torch.save(y_train, out_path / "memory_y_train.pt")
        torch.save(X_val, out_path / "memory_X_val.pt")
        torch.save(y_val, out_path / "memory_y_val.pt")
        torch.save(X_test, out_path / "memory_X_test.pt")
        torch.save(y_test, out_path / "memory_y_test.pt")

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
        (out_path / "memory_metadata.json").write_text(
            json.dumps(metadata, indent=2), encoding="utf-8"
        )
        logger.info("Tensors saved to %s", out_path)

    return MemoryDataSplit(
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
        description="Generate synthetic memory region feature data for Cortex-Memory",
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

    split = generate_memory_dataset(
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

    # Print per-class statistics from training set
    for cls_idx, cls_name in enumerate(split.class_names):
        mask = split.y_train == cls_idx
        count = int(mask.sum())
        if count > 0:
            cls_data = split.X_train[mask]
            logger.info(
                "  %s (train): n=%d entropy=%.3f exec=%.2f ret_ratio=%.4f",
                cls_name,
                count,
                float(cls_data[:, 14].mean()),
                float(cls_data[:, 3].mean()),
                float(cls_data[:, 72].mean()),
            )


if __name__ == "__main__":
    main()
