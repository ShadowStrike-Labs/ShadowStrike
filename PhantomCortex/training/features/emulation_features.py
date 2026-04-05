"""
PhantomEmulator Execution Trace Feature Extractor
===================================================
Encodes instruction-level emulation traces from PhantomEmulator into
fixed-length sequences for the Cortex-Emulation GRU model.

Each emulation event is encoded as a 4-tuple:
    (opcode_category, memory_access_type, api_call_id, eflags_change)

The output is a float32 array of shape (max_events, 4) plus aggregate
statistics appended as a summary vector.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional, Sequence

import numpy as np

logger = logging.getLogger("phantomcortex.features.emulation")


# ═══════════════════════════════════════════════════════════════════════════
# Enumerations
# ═══════════════════════════════════════════════════════════════════════════
class OpcodeCategory(IntEnum):
    """Coarse instruction category, matching common disassembler taxonomies."""
    UNKNOWN = 0
    DATA_TRANSFER = 1   # MOV, PUSH, POP, LEA, XCHG, MOVSX, MOVZX
    ARITHMETIC = 2      # ADD, SUB, MUL, DIV, INC, DEC, NEG, ADC, SBB
    LOGIC = 3           # AND, OR, XOR, NOT, TEST, SHL, SHR, SAR, ROL, ROR
    COMPARE = 4         # CMP, TEST
    BRANCH = 5          # JMP, Jcc, LOOP
    CALL = 6            # CALL (near / far)
    RETURN = 7          # RET, RETF
    STRING = 8          # REP MOVS, REP STOS, REP CMPS, REP SCAS
    STACK = 9           # PUSH, POP, ENTER, LEAVE
    SYSTEM = 10         # SYSCALL, SYSENTER, INT, IRET, HLT
    NOP = 11            # NOP, FNOP
    FLOAT = 12          # FLD, FST, FADD, FSUB, FMUL, FDIV, …
    SIMD = 13           # SSE/AVX: MOVAPS, ADDPS, PXOR, …
    CRYPTO = 14         # AES-NI, SHA, PCLMUL
    PRIVILEGED = 15     # IN, OUT, RDMSR, WRMSR, LGDT, …


class MemoryAccessType(IntEnum):
    """Memory access pattern for an instruction."""
    NONE = 0
    READ = 1
    WRITE = 2
    READ_WRITE = 3
    EXECUTE = 4    # self-modifying code / code fetch from writable page


# Mnemonic → OpcodeCategory mapping (lowercase)
_MNEMONIC_MAP: Dict[str, OpcodeCategory] = {}
_DATA_TRANSFER = [
    "mov", "movzx", "movsx", "movsxd", "lea", "xchg", "bswap", "cmov",
    "cmove", "cmovne", "cmovz", "cmovnz", "cmova", "cmovae", "cmovb",
    "cmovbe", "cmovg", "cmovge", "cmovl", "cmovle", "cmovs", "cmovns",
    "movbe", "cmpxchg", "xadd",
]
_ARITHMETIC = [
    "add", "sub", "imul", "mul", "idiv", "div", "inc", "dec", "neg",
    "adc", "sbb", "cbw", "cwde", "cdqe", "cwd", "cdq", "cqo",
]
_LOGIC = [
    "and", "or", "xor", "not", "shl", "shr", "sar", "sal", "rol", "ror",
    "rcl", "rcr", "bt", "bts", "btr", "btc", "bsf", "bsr", "popcnt",
    "lzcnt", "tzcnt", "shld", "shrd",
]
_COMPARE = ["cmp", "test"]
_BRANCH = [
    "jmp", "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe",
    "jg", "jge", "jl", "jle", "js", "jns", "jo", "jno", "jp", "jnp",
    "jcxz", "jecxz", "jrcxz", "loop", "loope", "loopne",
]
_CALL = ["call"]
_RETURN = ["ret", "retf", "retn"]
_STRING = [
    "movsb", "movsw", "movsd", "movsq", "stosb", "stosw", "stosd",
    "stosq", "cmpsb", "cmpsw", "cmpsd", "cmpsq", "scasb", "scasw",
    "scasd", "scasq", "lodsb", "lodsw", "lodsd", "lodsq",
    "rep", "repe", "repne", "repz", "repnz",
]
_STACK = ["push", "pop", "pusha", "pushad", "popa", "popad", "enter", "leave", "pushf", "popf", "pushfd", "popfd"]
_SYSTEM = ["syscall", "sysenter", "int", "int3", "iret", "iretd", "hlt", "cpuid", "rdtsc", "rdtscp"]
_NOP = ["nop", "fnop"]
_FLOAT = [
    "fld", "fst", "fstp", "fadd", "fsub", "fmul", "fdiv", "fcom", "fcomp",
    "fcompp", "fild", "fist", "fistp", "fabs", "fchs", "fsqrt", "fxch",
    "finit", "fninit", "fwait", "wait",
]
_SIMD = [
    "movaps", "movups", "movdqa", "movdqu", "addps", "subps", "mulps",
    "divps", "addpd", "subpd", "mulpd", "divpd", "pxor", "por", "pand",
    "pandn", "paddb", "paddw", "paddd", "paddq", "psubb", "psubw",
    "psubd", "psubq", "pmullw", "pmulld", "pshufd", "pshufb", "pcmpeqb",
    "pcmpeqw", "pcmpeqd", "pcmpgtb", "pcmpgtw", "pcmpgtd",
    "vaddps", "vsubps", "vmulps", "vdivps", "vmovaps", "vmovups",
    "vmovdqa", "vmovdqu", "vpxor", "vpor", "vpand", "vpandn",
]
_CRYPTO_INSNS = ["aesenc", "aesenclast", "aesdec", "aesdeclast", "aesimc", "aeskeygenassist", "pclmulqdq", "sha256msg1", "sha256msg2", "sha256rnds2"]
_PRIVILEGED = ["in", "out", "rdmsr", "wrmsr", "lgdt", "sgdt", "lidt", "sidt", "ltr", "str", "clts", "invlpg", "invd", "wbinvd"]

for _mnemonic in _DATA_TRANSFER:
    _MNEMONIC_MAP[_mnemonic] = OpcodeCategory.DATA_TRANSFER
for _mnemonic in _ARITHMETIC:
    _MNEMONIC_MAP[_mnemonic] = OpcodeCategory.ARITHMETIC
for _mnemonic in _LOGIC:
    _MNEMONIC_MAP[_mnemonic] = OpcodeCategory.LOGIC
for _mnemonic in _COMPARE:
    _MNEMONIC_MAP[_mnemonic] = OpcodeCategory.COMPARE
for _mnemonic in _BRANCH:
    _MNEMONIC_MAP[_mnemonic] = OpcodeCategory.BRANCH
for _mnemonic in _CALL:
    _MNEMONIC_MAP[_mnemonic] = OpcodeCategory.CALL
for _mnemonic in _RETURN:
    _MNEMONIC_MAP[_mnemonic] = OpcodeCategory.RETURN
for _mnemonic in _STRING:
    _MNEMONIC_MAP[_mnemonic] = OpcodeCategory.STRING
for _mnemonic in _STACK:
    _MNEMONIC_MAP[_mnemonic] = OpcodeCategory.STACK
for _mnemonic in _SYSTEM:
    _MNEMONIC_MAP[_mnemonic] = OpcodeCategory.SYSTEM
for _mnemonic in _NOP:
    _MNEMONIC_MAP[_mnemonic] = OpcodeCategory.NOP
for _mnemonic in _FLOAT:
    _MNEMONIC_MAP[_mnemonic] = OpcodeCategory.FLOAT
for _mnemonic in _SIMD:
    _MNEMONIC_MAP[_mnemonic] = OpcodeCategory.SIMD
for _mnemonic in _CRYPTO_INSNS:
    _MNEMONIC_MAP[_mnemonic] = OpcodeCategory.CRYPTO
for _mnemonic in _PRIVILEGED:
    _MNEMONIC_MAP[_mnemonic] = OpcodeCategory.PRIVILEGED


def _classify_mnemonic(mnemonic: str) -> int:
    """Map an x86 mnemonic to its OpcodeCategory integer."""
    base = mnemonic.lower().split()[0]  # strip prefix like "rep "
    return int(_MNEMONIC_MAP.get(base, OpcodeCategory.UNKNOWN))


def _stable_hash(value: str, modulus: int) -> int:
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).digest()
    return int.from_bytes(digest[:8], "little") % modulus


# ═══════════════════════════════════════════════════════════════════════════
# Data model
# ═══════════════════════════════════════════════════════════════════════════
@dataclass(frozen=True, slots=True)
class EmulationEvent:
    """Single instruction execution event from PhantomEmulator."""
    mnemonic: str = "nop"
    memory_access: int = 0       # MemoryAccessType value
    api_call_name: str = ""      # non-empty when this instruction triggers an API stub
    eflags_before: int = 0
    eflags_after: int = 0


# ═══════════════════════════════════════════════════════════════════════════
# Extractor
# ═══════════════════════════════════════════════════════════════════════════
class EmulationFeatureExtractor:
    """
    Encode an emulation trace into a fixed-length tensor for the
    Cortex-Emulation GRU model.

    Output shape: (max_events, feature_dim=4)
    Columns:
        0  opcode_category     (int mapped via OpcodeCategory)
        1  memory_access_type  (int from MemoryAccessType)
        2  api_call_id         (hash of API name, 0 if no API call)
        3  eflags_change       (XOR of before/after → popcount of changed bits)

    Additionally, :meth:`extract_with_summary` appends an aggregate stats
    vector for two-stream architectures.
    """

    # Aggregate summary feature count
    _SUMMARY_DIM: int = 32

    def __init__(
        self,
        max_events: int = 1024,
        feature_dim: int = 4,
        api_hash_space: int = 2000,
    ) -> None:
        if max_events < 1:
            raise ValueError("max_events must be >= 1")
        self.max_events = max_events
        self.feature_dim = feature_dim
        self.api_hash_space = api_hash_space

    @property
    def output_shape(self) -> tuple[int, int]:
        return (self.max_events, self.feature_dim)

    def extract(self, events: Sequence[EmulationEvent]) -> np.ndarray:
        """
        Encode *events* into a float32 tensor of shape (max_events, 4).

        Truncates if len(events) > max_events; zero-pads otherwise.
        """
        out = np.zeros(self.output_shape, dtype=np.float32)
        n = min(len(events), self.max_events)

        for i in range(n):
            ev = events[i]
            out[i, 0] = float(_classify_mnemonic(ev.mnemonic))
            out[i, 1] = float(np.clip(ev.memory_access, 0, 4))
            if ev.api_call_name:
                out[i, 2] = float(_stable_hash(ev.api_call_name.lower(), self.api_hash_space))
            # eflags change: popcount of changed bits
            changed = ev.eflags_before ^ ev.eflags_after
            out[i, 3] = float(bin(changed).count("1"))

        return out

    def extract_with_summary(
        self,
        events: Sequence[EmulationEvent],
    ) -> Dict[str, np.ndarray]:
        """
        Return both the sequence tensor and a 32-dim aggregate summary.

        Summary features:
            [0]       total event count (capped at max_events)
            [1-16]    instruction category distribution (16 categories)
            [17]      unique API call count
            [18]      API call ratio (api_calls / total_events)
            [19]      memory write ratio
            [20]      memory read ratio
            [21]      branch taken ratio (branch instructions / total)
            [22]      call instruction ratio
            [23]      return instruction ratio
            [24]      average eflags change magnitude
            [25]      system instruction ratio
            [26]      NOP instruction ratio
            [27]      string instruction ratio
            [28]      unique memory access pattern count
            [29]      crypto instruction ratio
            [30]      SIMD instruction ratio
            [31]      privileged instruction ratio
        """
        tensor = self.extract(events)
        summary = np.zeros(self._SUMMARY_DIM, dtype=np.float32)
        n = min(len(events), self.max_events)
        summary[0] = float(n)

        if n == 0:
            return {"tensor": tensor, "summary": summary}

        # Category distribution
        category_counts = np.zeros(16, dtype=np.float64)
        unique_apis: set[str] = set()
        api_calls = 0
        mem_writes = 0
        mem_reads = 0
        total_eflags_change = 0.0
        unique_mem_patterns: set[int] = set()

        for i in range(n):
            ev = events[i]
            cat = _classify_mnemonic(ev.mnemonic)
            if cat < 16:
                category_counts[cat] += 1
            if ev.api_call_name:
                api_calls += 1
                unique_apis.add(ev.api_call_name.lower())
            if ev.memory_access == MemoryAccessType.WRITE or ev.memory_access == MemoryAccessType.READ_WRITE:
                mem_writes += 1
            if ev.memory_access == MemoryAccessType.READ or ev.memory_access == MemoryAccessType.READ_WRITE:
                mem_reads += 1
            total_eflags_change += bin(ev.eflags_before ^ ev.eflags_after).count("1")
            unique_mem_patterns.add(ev.memory_access)

        cat_dist = category_counts / n
        summary[1:17] = cat_dist.astype(np.float32)
        summary[17] = float(len(unique_apis))
        summary[18] = api_calls / n
        summary[19] = mem_writes / n
        summary[20] = mem_reads / n
        summary[21] = cat_dist[int(OpcodeCategory.BRANCH)]
        summary[22] = cat_dist[int(OpcodeCategory.CALL)]
        summary[23] = cat_dist[int(OpcodeCategory.RETURN)]
        summary[24] = total_eflags_change / n
        summary[25] = cat_dist[int(OpcodeCategory.SYSTEM)]
        summary[26] = cat_dist[int(OpcodeCategory.NOP)]
        summary[27] = cat_dist[int(OpcodeCategory.STRING)]
        summary[28] = float(len(unique_mem_patterns))
        summary[29] = cat_dist[int(OpcodeCategory.CRYPTO)]
        summary[30] = cat_dist[int(OpcodeCategory.SIMD)]
        summary[31] = cat_dist[int(OpcodeCategory.PRIVILEGED)]

        return {"tensor": tensor, "summary": summary}

    def extract_batch(self, batch: Sequence[Sequence[EmulationEvent]]) -> np.ndarray:
        """Process multiple traces, returning (batch_size, max_events, feature_dim)."""
        result = np.zeros((len(batch), *self.output_shape), dtype=np.float32)
        for idx, events in enumerate(batch):
            result[idx] = self.extract(events)
        return result
