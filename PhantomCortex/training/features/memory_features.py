"""
Memory Region Feature Extractor (128 features)
================================================
Analyses raw memory region dumps to detect injected code, shellcode,
unpacked payloads, and other suspicious memory patterns for the
Cortex-Memory classifier.

Feature vector layout (128 total):
     0       byte entropy (Shannon, base-2)
   1-16      compressed byte histogram (16 bins — every 16 values averaged)
    17       instruction density (valid x86 opcode ratio)
    18       NOP sled score (longest NOP run / region size)
    19       API reference density (API-address–like pattern count / size)
    20       string density (printable chars / total bytes)
    21       null byte ratio
    22       alignment pattern ratio (DWORD-aligned zero runs)
    23       ROP gadget density (ret/jmp-reg pattern count / size)
    24       repetition score (zlib compression ratio)
  25-74      top-50 bigram frequencies
  75-77      section-like permissions (R, W, X)  — 0/1 when known
  78-127     reserved / zero-padded for future expansion
"""

from __future__ import annotations

import logging
import math
import zlib
from typing import Optional

import numpy as np

logger = logging.getLogger("phantomcortex.features.memory")

# ═══════════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════════
_FEATURE_COUNT: int = 128
_COMPRESSED_HIST_SIZE: int = 16
_NGRAM_FEATURES: int = 50
_RESERVED_START: int = 78
_RESERVED_END: int = 128

# Common x86 one-byte opcodes (covers a large fraction of real instructions)
_VALID_X86_OPCODES: frozenset[int] = frozenset(
    list(range(0x00, 0x06))      # ADD variants
    + list(range(0x08, 0x0E))    # OR variants
    + list(range(0x10, 0x16))    # ADC
    + list(range(0x18, 0x1E))    # SBB
    + list(range(0x20, 0x26))    # AND
    + list(range(0x28, 0x2E))    # SUB
    + list(range(0x30, 0x36))    # XOR
    + list(range(0x38, 0x3E))    # CMP
    + list(range(0x40, 0x60))    # INC/DEC/PUSH/POP regs
    + [0x68, 0x6A]               # PUSH imm
    + list(range(0x70, 0x80))    # Jcc short
    + list(range(0x80, 0x84))    # group arith
    + [0x84, 0x85, 0x86, 0x87]  # TEST, XCHG
    + [0x88, 0x89, 0x8A, 0x8B, 0x8D]  # MOV, LEA
    + [0x90]                     # NOP
    + list(range(0x91, 0x98))    # XCHG with eax
    + [0x99, 0x9C, 0x9D]        # CDQ, PUSHFD, POPFD
    + [0xA0, 0xA1, 0xA2, 0xA3]  # MOV moffs
    + [0xA4, 0xA5, 0xA6, 0xA7]  # MOVS/CMPS
    + [0xAA, 0xAB, 0xAC, 0xAD]  # STOS/LODS
    + list(range(0xB0, 0xC0))    # MOV imm to reg
    + [0xC2, 0xC3]               # RET
    + [0xC6, 0xC7]               # MOV r/m, imm
    + [0xC9]                     # LEAVE
    + [0xCC, 0xCD]               # INT3, INT
    + [0xE8, 0xE9, 0xEB]        # CALL, JMP near/short
    + [0xF6, 0xF7]               # group 3 (TEST/NOT/NEG/MUL/DIV)
    + [0xFC, 0xFD]               # CLD, STD
    + [0xFE, 0xFF]               # INC/DEC/CALL/JMP r/m
    + [0x0F]                     # two-byte escape
)

# NOP / NOP-equivalent single bytes
_NOP_BYTES: frozenset[int] = frozenset([0x90, 0x00])

# ROP gadget terminators
_RET_OPCODES: frozenset[int] = frozenset([0xC2, 0xC3, 0xCB, 0xCA])
_JMP_REG_PATTERNS: list[bytes] = [
    b"\xFF\xE0", b"\xFF\xE1", b"\xFF\xE2", b"\xFF\xE3",  # jmp eax..ebx
    b"\xFF\xE4", b"\xFF\xE5", b"\xFF\xE6", b"\xFF\xE7",  # jmp esp..edi
    b"\xFF\xD0", b"\xFF\xD1", b"\xFF\xD2", b"\xFF\xD3",  # call eax..ebx
    b"\xFF\xD4", b"\xFF\xD5", b"\xFF\xD6", b"\xFF\xD7",  # call esp..edi
]


# ═══════════════════════════════════════════════════════════════════════════
# Extractor
# ═══════════════════════════════════════════════════════════════════════════
class MemoryFeatureExtractor:
    """
    Extract 128 features from a raw memory region dump.

    Parameters
    ----------
    feature_count : int
        Output vector length (default 128).
    permissions : tuple[bool, bool, bool] | None
        Known (readable, writable, executable) flags for the region.
        Pass None when permissions are unavailable.
    """

    FEATURE_COUNT: int = _FEATURE_COUNT

    def __init__(
        self,
        feature_count: int = _FEATURE_COUNT,
        permissions: Optional[tuple[bool, bool, bool]] = None,
    ) -> None:
        if feature_count != _FEATURE_COUNT:
            raise ValueError(f"feature_count must be {_FEATURE_COUNT}")
        self._permissions = permissions

    def extract(
        self,
        region: bytes,
        permissions: Optional[tuple[bool, bool, bool]] = None,
    ) -> np.ndarray:
        """
        Analyse *region* and return a float32 vector of 128 features.

        Parameters
        ----------
        region : bytes
            Raw memory bytes.
        permissions : tuple[bool, bool, bool] | None
            (R, W, X) flags.  Overrides constructor default if provided.
        """
        features = np.zeros(_FEATURE_COUNT, dtype=np.float32)
        if len(region) == 0:
            return features

        arr = np.frombuffer(region, dtype=np.uint8)
        size = len(arr)

        # [0] byte entropy
        features[0] = self._shannon_entropy(arr)

        # [1-16] compressed byte histogram
        full_hist = np.bincount(arr, minlength=256).astype(np.float64)
        total = full_hist.sum()
        if total > 0:
            full_hist /= total
        compressed = full_hist.reshape(16, 16).mean(axis=1).astype(np.float32)
        features[1:17] = compressed

        # [17] instruction density
        valid_count = sum(1 for b in arr if int(b) in _VALID_X86_OPCODES)
        features[17] = valid_count / size

        # [18] NOP sled detection
        features[18] = self._longest_nop_run(arr) / size

        # [19] API reference density (heuristic: count of aligned 4-byte values
        # in typical kernel32/ntdll VA ranges 0x7FFx_xxxx or 0x7Cx_xxxx)
        features[19] = self._api_reference_density(region, size)

        # [20] string density
        printable = np.sum((arr >= 0x20) & (arr <= 0x7E))
        features[20] = float(printable) / size

        # [21] null byte ratio
        features[21] = float(np.sum(arr == 0)) / size

        # [22] alignment pattern ratio
        features[22] = self._alignment_pattern_ratio(arr, size)

        # [23] ROP gadget density
        features[23] = self._rop_gadget_density(region, size)

        # [24] repetition score (compression ratio)
        features[24] = self._compression_ratio(region)

        # [25-74] top-50 bigram frequencies
        features[25:75] = self._bigram_features(arr, size)

        # [75-77] section-like permissions
        perms = permissions if permissions is not None else self._permissions
        if perms is not None:
            features[75] = float(perms[0])  # R
            features[76] = float(perms[1])  # W
            features[77] = float(perms[2])  # X

        # [78-127] reserved, already zero
        return features

    def extract_batch(
        self,
        regions: list[bytes],
        permissions_list: Optional[list[Optional[tuple[bool, bool, bool]]]] = None,
    ) -> np.ndarray:
        """Process multiple regions, returning (N, 128) array."""
        n = len(regions)
        out = np.zeros((n, _FEATURE_COUNT), dtype=np.float32)
        for i in range(n):
            perms = permissions_list[i] if permissions_list is not None else None
            out[i] = self.extract(regions[i], perms)
        return out

    # -- internal ----------------------------------------------------------

    @staticmethod
    def _shannon_entropy(arr: np.ndarray) -> float:
        counts = np.bincount(arr, minlength=256).astype(np.float64)
        total = counts.sum()
        if total == 0:
            return 0.0
        p = counts / total
        nz = p > 0
        return float(-np.sum(p[nz] * np.log2(p[nz])))

    @staticmethod
    def _longest_nop_run(arr: np.ndarray) -> int:
        max_run = 0
        current_run = 0
        for b in arr:
            if int(b) in _NOP_BYTES:
                current_run += 1
                if current_run > max_run:
                    max_run = current_run
            else:
                current_run = 0
        return max_run

    @staticmethod
    def _api_reference_density(region: bytes, size: int) -> float:
        if size < 4:
            return 0.0
        count = 0
        # Scan DWORD-aligned offsets for values resembling Windows user-mode VA
        step = 4
        upper = size - 3
        for off in range(0, upper, step):
            val = int.from_bytes(region[off:off + 4], "little")
            # Typical Windows DLL load addresses
            high_byte = (val >> 24) & 0xFF
            if high_byte in (0x7C, 0x7D, 0x7E, 0x7F, 0x75, 0x76, 0x77):
                count += 1
        return count / (size / step)

    @staticmethod
    def _alignment_pattern_ratio(arr: np.ndarray, size: int) -> float:
        if size < 4:
            return 0.0
        aligned_zeros = 0
        total_dwords = size // 4
        for i in range(0, total_dwords * 4, 4):
            if arr[i] == 0 and arr[i + 1] == 0 and arr[i + 2] == 0 and arr[i + 3] == 0:
                aligned_zeros += 1
        return aligned_zeros / total_dwords if total_dwords > 0 else 0.0

    @staticmethod
    def _rop_gadget_density(region: bytes, size: int) -> float:
        count = 0
        for b in region:
            if b in _RET_OPCODES:
                count += 1
        for pattern in _JMP_REG_PATTERNS:
            start = 0
            while True:
                idx = region.find(pattern, start)
                if idx == -1:
                    break
                count += 1
                start = idx + 1
        return count / size if size > 0 else 0.0

    @staticmethod
    def _compression_ratio(region: bytes) -> float:
        if len(region) == 0:
            return 0.0
        try:
            compressed = zlib.compress(region, level=1)
            return len(compressed) / len(region)
        except Exception:
            return 1.0

    @staticmethod
    def _bigram_features(arr: np.ndarray, size: int) -> np.ndarray:
        result = np.zeros(_NGRAM_FEATURES, dtype=np.float32)
        if size < 2:
            return result
        # Compute bigram frequencies via vectorised pairing
        first = arr[:-1].astype(np.uint16)
        second = arr[1:].astype(np.uint16)
        bigrams = (first << 8) | second  # 65536 possible bigrams
        counts = np.bincount(bigrams, minlength=65536).astype(np.float64)
        total = counts.sum()
        if total == 0:
            return result
        counts /= total
        # Top 50 most frequent bigrams
        top_indices = np.argpartition(counts, -_NGRAM_FEATURES)[-_NGRAM_FEATURES:]
        top_indices = top_indices[np.argsort(-counts[top_indices])]
        for i in range(_NGRAM_FEATURES):
            result[i] = float(counts[top_indices[i]])
        return result
