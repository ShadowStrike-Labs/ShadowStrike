"""
Emulation Trace Generator for PhantomCortex Cortex-Emulation Model
===================================================================

Generates synthetic emulation trace sequences that mimic real x86 code
execution as observed by PhantomEmulator.  Each sample is a fixed-length
sequence of 1024 emulation events with four features per event:

    [opcode_category, memory_access_type, api_id, eflags_snapshot]

Three verdict classes (see :class:`EmulationVerdict`):
    0 — Benign    :  standard application execution patterns
    1 — Suspicious:  anti-debugging, sandbox detection, obfuscation
    2 — Malicious :  process injection, shellcode, credential theft

Attack patterns encode **real** malware TTPs observed in the wild.
Opcode distributions, memory access patterns, and API call sequences
mirror genuine execution traces to maximize model transferability.

Usage::

    from PhantomCortex.training.data.emulation_generator import (
        generate_emulation_dataset,
        get_emulation_dataloaders,
    )

    X, y = generate_emulation_dataset(n_samples=60000, seed=42)
    train_loader, val_loader, test_loader = get_emulation_dataloaders(
        X, y, batch_size=128, seed=42,
    )
"""

from __future__ import annotations

import hashlib
import logging
from enum import IntEnum
from typing import Optional, Sequence

import numpy as np
import torch
from numpy.typing import NDArray
from torch.utils.data import DataLoader

from PhantomCortex.training.data.dataset_utils import (
    compute_class_weights,
    create_dataloader,
    print_dataset_stats,
    split_data,
)

logger = logging.getLogger("PhantomCortex.Data.EmulationGenerator")

# ═══════════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════════

SEQUENCE_LENGTH: int = 1024
FEATURE_DIM: int = 4
API_HASH_SPACE: int = 2000


class EmulationVerdict(IntEnum):
    """Verdict classes for emulation trace classification."""

    Benign = 0
    Suspicious = 1
    Malicious = 2


VERDICT_NAMES: list[str] = [v.name for v in EmulationVerdict]


# ═══════════════════════════════════════════════════════════════════════════
# Deterministic API hashing
# ═══════════════════════════════════════════════════════════════════════════


def _api_hash(name: str) -> int:
    """Map a Windows API name to a stable integer in [1, 1999]."""
    digest = hashlib.sha256(name.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "little") % 1999 + 1


# Pre-compute frequently referenced API IDs
_API: dict[str, int] = {}

_API_NAMES: list[str] = [
    # Process / Thread
    "OpenProcess", "CreateRemoteThread", "CreateRemoteThreadEx",
    "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory",
    "NtUnmapViewOfSection", "SetThreadContext", "ResumeThread",
    "QueueUserAPC", "CreateProcessW", "CreateProcessA",
    "TerminateProcess", "NtCreateThreadEx", "OpenThread",
    # Memory
    "VirtualAlloc", "VirtualProtect", "VirtualFree", "HeapAlloc",
    "HeapFree", "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
    "MapViewOfFile", "NtMapViewOfSection",
    # File I/O
    "CreateFileW", "CreateFileA", "ReadFile", "WriteFile",
    "CloseHandle", "FindFirstFileW", "FindNextFileW",
    "MoveFileW", "DeleteFileW", "SetFilePointer",
    "GetFileSize", "NtCreateFile", "NtReadFile", "NtWriteFile",
    # Registry
    "RegOpenKeyExW", "RegQueryValueExW", "RegSetValueExW",
    "RegCloseKey", "RegCreateKeyExW", "RegDeleteKeyW",
    "NtOpenKey", "NtQueryValueKey",
    # Network
    "WSAStartup", "socket", "connect", "bind", "listen",
    "accept", "send", "recv", "closesocket", "WSACleanup",
    "InternetOpenW", "InternetConnectW", "HttpOpenRequestW",
    "HttpSendRequestW", "InternetReadFile", "URLDownloadToFileW",
    "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
    "getaddrinfo", "gethostbyname",
    # Loader / Library
    "LoadLibraryW", "LoadLibraryA", "GetProcAddress",
    "FreeLibrary", "LdrLoadDll", "LdrGetProcedureAddress",
    # System info / anti-debug
    "IsDebuggerPresent", "NtQueryInformationProcess",
    "NtQuerySystemInformation", "GetTickCount", "GetTickCount64",
    "QueryPerformanceCounter", "QueryPerformanceFrequency",
    "GetSystemMetrics", "GetCursorPos", "GetSystemInfo",
    "GlobalMemoryStatusEx", "GetVersionExW",
    # Crypto
    "CryptAcquireContextW", "CryptEncrypt", "CryptDecrypt",
    "CryptGenKey", "CryptDeriveKey", "CryptDestroyKey",
    "BCryptOpenAlgorithmProvider", "BCryptEncrypt", "BCryptDecrypt",
    # Synchronization
    "WaitForSingleObject", "WaitForMultipleObjects",
    "CreateMutexW", "ReleaseMutex", "Sleep", "SleepEx",
    "NtDelayExecution", "CreateEventW", "SetEvent",
    # Token / Privilege
    "OpenProcessToken", "LookupPrivilegeValueW",
    "AdjustTokenPrivileges", "DuplicateTokenEx",
    "ImpersonateLoggedOnUser", "RevertToSelf",
    # Service
    "OpenSCManagerW", "CreateServiceW", "StartServiceW",
    "OpenServiceW", "ControlService", "DeleteService",
    "NtLoadDriver",
    # Hooking / Injection
    "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState",
    "DeviceIoControl",
    # Network sharing
    "NetShareEnum", "WNetAddConnection2W", "CopyFileW",
]

for _name in _API_NAMES:
    _API[_name] = _api_hash(_name)


# ═══════════════════════════════════════════════════════════════════════════
# Opcode category ranges (matching the 0-255 encoding spec)
# ═══════════════════════════════════════════════════════════════════════════
# 0-15: Data transfer   16-31: Arithmetic   32-47: Logic
# 48-63: Control flow    64-79: String ops   80-95: Stack
# 96-111: System        112-127: FPU/SSE    128-143: Crypto
# 144-159: Privileged   160-175: NOP/padding

_R_DATA = (0, 15)
_R_ARITH = (16, 31)
_R_LOGIC = (32, 47)
_R_CTRL = (48, 63)
_R_STRING = (64, 79)
_R_STACK = (80, 95)
_R_SYSTEM = (96, 111)
_R_FPU = (112, 127)
_R_CRYPTO = (128, 143)
_R_PRIV = (144, 159)
_R_NOP = (160, 175)


def _rand_opcode(rng: np.random.Generator, lo: int, hi: int) -> int:
    return int(rng.integers(lo, hi + 1))


def _rand_opcodes(rng: np.random.Generator, lo: int, hi: int, n: int) -> NDArray[np.int32]:
    return rng.integers(lo, hi + 1, size=n, dtype=np.int32)


# Memory access types
_M_NONE = 0
_M_SREAD = 1
_M_SWRITE = 2
_M_HREAD = 3
_M_HWRITE = 4
_M_CODE = 5
_M_EXTREAD = 6
_M_EXTWRITE = 7


# ═══════════════════════════════════════════════════════════════════════════
# Event builder helpers
# ═══════════════════════════════════════════════════════════════════════════


def _make_event(
    opcode: int, mem: int, api: int, eflags: int,
) -> NDArray[np.float32]:
    return np.array([opcode, mem, api, eflags], dtype=np.float32)


def _api_call_events(
    rng: np.random.Generator,
    api_name: str,
    n_setup: int = 3,
    n_cleanup: int = 2,
) -> list[NDArray[np.float32]]:
    """Generate a realistic API call sequence: setup → call → cleanup."""
    events: list[NDArray[np.float32]] = []

    for _ in range(n_setup):
        events.append(_make_event(
            _rand_opcode(rng, *_R_STACK), _M_SWRITE, 0,
            int(rng.integers(0, 256)),
        ))

    events.append(_make_event(
        _rand_opcode(rng, *_R_CTRL), _M_EXTREAD, _API.get(api_name, 0),
        int(rng.integers(0, 256)),
    ))

    for _ in range(n_cleanup):
        events.append(_make_event(
            _rand_opcode(rng, *_R_DATA), _M_SREAD, 0,
            int(rng.integers(0, 256)),
        ))
    return events


def _benign_noise(rng: np.random.Generator, n: int) -> list[NDArray[np.float32]]:
    """Generate benign filler instructions (arithmetic, data transfer, logic)."""
    events: list[NDArray[np.float32]] = []
    for _ in range(n):
        cat = rng.choice([_R_DATA, _R_ARITH, _R_LOGIC, _R_STACK], p=[0.40, 0.25, 0.20, 0.15])
        mem = int(rng.choice([_M_NONE, _M_SREAD, _M_SWRITE, _M_HREAD], p=[0.4, 0.25, 0.2, 0.15]))
        events.append(_make_event(
            _rand_opcode(rng, cat[0], cat[1]), mem, 0,
            int(rng.integers(0, 256)),
        ))
    return events


def _pad_or_truncate(
    events: list[NDArray[np.float32]], length: int, rng: np.random.Generator,
) -> NDArray[np.float32]:
    """Ensure exactly ``length`` events by padding with NOPs or truncating."""
    if len(events) >= length:
        return np.stack(events[:length])

    padding_needed = length - len(events)
    for _ in range(padding_needed):
        events.append(_make_event(
            _rand_opcode(rng, *_R_NOP), _M_NONE, 0,
            int(rng.integers(0, 64)),
        ))
    return np.stack(events)


# ═══════════════════════════════════════════════════════════════════════════
# BENIGN templates
# ═══════════════════════════════════════════════════════════════════════════


def _benign_app_startup(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """Standard app startup: LoadLibrary, GetProcAddress, init, message loop."""
    events: list[NDArray[np.float32]] = []
    for dll in ["LoadLibraryW", "LoadLibraryW", "LoadLibraryA"]:
        events.extend(_api_call_events(rng, dll, n_setup=4, n_cleanup=3))
        for _ in range(rng.integers(2, 5)):
            events.extend(_api_call_events(rng, "GetProcAddress", n_setup=2, n_cleanup=2))
        events.extend(_benign_noise(rng, rng.integers(10, 25)))

    events.extend(_api_call_events(rng, "CreateMutexW"))
    events.extend(_benign_noise(rng, rng.integers(20, 50)))

    for _ in range(rng.integers(40, 80)):
        events.extend(_api_call_events(rng, "WaitForSingleObject", n_setup=2, n_cleanup=1))
        events.extend(_benign_noise(rng, rng.integers(5, 15)))
    return events


def _benign_file_processing(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """File I/O pattern: open, read loop, process, write, close."""
    events: list[NDArray[np.float32]] = []
    events.extend(_api_call_events(rng, "CreateFileW", n_setup=5, n_cleanup=3))

    for _ in range(rng.integers(30, 60)):
        events.extend(_api_call_events(rng, "ReadFile", n_setup=3, n_cleanup=2))
        events.extend(_benign_noise(rng, rng.integers(8, 20)))

    events.extend(_api_call_events(rng, "SetFilePointer"))
    events.extend(_api_call_events(rng, "WriteFile", n_setup=3, n_cleanup=2))
    events.extend(_benign_noise(rng, rng.integers(5, 15)))
    events.extend(_api_call_events(rng, "CloseHandle"))
    return events


def _benign_registry_access(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """Registry read pattern: open key, query values, close."""
    events: list[NDArray[np.float32]] = []
    events.extend(_api_call_events(rng, "RegOpenKeyExW", n_setup=4, n_cleanup=2))
    for _ in range(rng.integers(5, 15)):
        events.extend(_api_call_events(rng, "RegQueryValueExW", n_setup=3, n_cleanup=2))
        events.extend(_benign_noise(rng, rng.integers(3, 10)))
    events.extend(_api_call_events(rng, "RegCloseKey"))
    events.extend(_benign_noise(rng, rng.integers(20, 50)))

    events.extend(_api_call_events(rng, "RegOpenKeyExW"))
    for _ in range(rng.integers(3, 8)):
        events.extend(_api_call_events(rng, "RegQueryValueExW"))
    events.extend(_api_call_events(rng, "RegCloseKey"))
    return events


def _benign_network_client(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """Simple network client: connect, send/recv loop, close."""
    events: list[NDArray[np.float32]] = []
    events.extend(_api_call_events(rng, "WSAStartup", n_setup=4, n_cleanup=2))
    events.extend(_api_call_events(rng, "socket"))
    events.extend(_api_call_events(rng, "getaddrinfo"))
    events.extend(_api_call_events(rng, "connect", n_setup=3, n_cleanup=2))

    for _ in range(rng.integers(20, 50)):
        if rng.random() < 0.5:
            events.extend(_api_call_events(rng, "send", n_setup=2, n_cleanup=1))
        else:
            events.extend(_api_call_events(rng, "recv", n_setup=2, n_cleanup=1))
        events.extend(_benign_noise(rng, rng.integers(3, 8)))

    events.extend(_api_call_events(rng, "closesocket"))
    events.extend(_api_call_events(rng, "WSACleanup"))
    return events


def _benign_service_worker(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """Service worker: wait loop, process items, sleep."""
    events: list[NDArray[np.float32]] = []
    events.extend(_api_call_events(rng, "CreateEventW"))

    for _ in range(rng.integers(50, 100)):
        events.extend(_api_call_events(rng, "WaitForSingleObject", n_setup=2, n_cleanup=1))

        events.extend(_benign_noise(rng, rng.integers(5, 15)))

        if rng.random() < 0.3:
            events.extend(_api_call_events(rng, "HeapAlloc", n_setup=2, n_cleanup=1))
            events.extend(_benign_noise(rng, rng.integers(5, 12)))
            events.extend(_api_call_events(rng, "HeapFree", n_setup=2, n_cleanup=1))

        if rng.random() < 0.2:
            events.extend(_api_call_events(rng, "Sleep", n_setup=1, n_cleanup=1))
    return events


def _benign_crypto_file(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """Legitimate crypto: open context, derive key, encrypt file data, cleanup."""
    events: list[NDArray[np.float32]] = []
    events.extend(_api_call_events(rng, "CryptAcquireContextW", n_setup=4, n_cleanup=3))
    events.extend(_api_call_events(rng, "CryptDeriveKey", n_setup=3, n_cleanup=2))
    events.extend(_api_call_events(rng, "CreateFileW", n_setup=3, n_cleanup=2))

    for _ in range(rng.integers(15, 30)):
        events.extend(_api_call_events(rng, "ReadFile", n_setup=2, n_cleanup=1))
        events.extend(_api_call_events(rng, "CryptEncrypt", n_setup=2, n_cleanup=1))
        events.extend(_api_call_events(rng, "WriteFile", n_setup=2, n_cleanup=1))
        events.extend(_benign_noise(rng, rng.integers(2, 6)))

    events.extend(_api_call_events(rng, "CloseHandle"))
    events.extend(_api_call_events(rng, "CryptDestroyKey"))
    return events


def _benign_dll_load_sequence(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """DLL loading: multiple LoadLibrary/GetProcAddress cycles."""
    events: list[NDArray[np.float32]] = []
    for _ in range(rng.integers(4, 10)):
        events.extend(_api_call_events(rng, "LoadLibraryW", n_setup=3, n_cleanup=2))
        for _ in range(rng.integers(3, 8)):
            events.extend(_api_call_events(rng, "GetProcAddress", n_setup=2, n_cleanup=2))
        events.extend(_benign_noise(rng, rng.integers(10, 30)))
    events.extend(_benign_noise(rng, rng.integers(40, 80)))
    return events


def _benign_memory_mapped_io(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """Memory-mapped file I/O."""
    events: list[NDArray[np.float32]] = []
    events.extend(_api_call_events(rng, "CreateFileW", n_setup=4, n_cleanup=2))
    events.extend(_api_call_events(rng, "GetFileSize"))
    events.extend(_api_call_events(rng, "MapViewOfFile", n_setup=3, n_cleanup=2))

    for _ in range(rng.integers(30, 60)):
        events.append(_make_event(
            _rand_opcode(rng, *_R_DATA), _M_HREAD, 0,
            int(rng.integers(0, 256)),
        ))
        events.extend(_benign_noise(rng, rng.integers(2, 6)))

    events.extend(_api_call_events(rng, "CloseHandle"))
    return events


_BENIGN_TEMPLATES = [
    _benign_app_startup,
    _benign_file_processing,
    _benign_registry_access,
    _benign_network_client,
    _benign_service_worker,
    _benign_crypto_file,
    _benign_dll_load_sequence,
    _benign_memory_mapped_io,
]


# ═══════════════════════════════════════════════════════════════════════════
# SUSPICIOUS templates
# ═══════════════════════════════════════════════════════════════════════════


def _suspicious_anti_debug(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """Anti-debugging: RDTSC pairs, IsDebuggerPresent, timing checks."""
    events: list[NDArray[np.float32]] = []
    events.extend(_benign_noise(rng, rng.integers(10, 30)))

    for _ in range(rng.integers(3, 6)):
        events.append(_make_event(_rand_opcode(rng, *_R_SYSTEM), _M_NONE, 0, int(rng.integers(0, 256))))
        events.extend(_benign_noise(rng, rng.integers(15, 40)))
        events.append(_make_event(_rand_opcode(rng, *_R_SYSTEM), _M_NONE, 0, int(rng.integers(0, 256))))
        events.append(_make_event(_rand_opcode(rng, *_R_ARITH), _M_SWRITE, 0, int(rng.integers(0, 256))))
        events.append(_make_event(_rand_opcode(rng, *_R_LOGIC), _M_NONE, 0, int(rng.integers(128, 256))))
        events.append(_make_event(_rand_opcode(rng, *_R_CTRL), _M_NONE, 0, int(rng.integers(0, 256))))

    events.extend(_api_call_events(rng, "IsDebuggerPresent", n_setup=2, n_cleanup=2))
    events.append(_make_event(_rand_opcode(rng, *_R_LOGIC), _M_NONE, 0, int(rng.integers(0, 256))))
    events.append(_make_event(_rand_opcode(rng, *_R_CTRL), _M_NONE, 0, int(rng.integers(0, 256))))

    events.extend(_api_call_events(rng, "NtQueryInformationProcess", n_setup=5, n_cleanup=3))
    events.extend(_benign_noise(rng, rng.integers(20, 50)))
    return events


def _suspicious_env_check(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """VM/sandbox detection: CPUID, registry checks, process enumeration."""
    events: list[NDArray[np.float32]] = []

    for _ in range(rng.integers(2, 5)):
        events.append(_make_event(_rand_opcode(rng, *_R_SYSTEM), _M_NONE, 0, int(rng.integers(0, 256))))
        events.extend(_benign_noise(rng, rng.integers(3, 8)))

    events.extend(_api_call_events(rng, "NtQuerySystemInformation", n_setup=4, n_cleanup=3))
    events.extend(_benign_noise(rng, rng.integers(10, 20)))

    events.extend(_api_call_events(rng, "RegOpenKeyExW", n_setup=3, n_cleanup=2))
    events.extend(_api_call_events(rng, "RegQueryValueExW"))
    events.extend(_api_call_events(rng, "RegCloseKey"))

    events.extend(_api_call_events(rng, "GetSystemInfo"))
    events.extend(_api_call_events(rng, "GlobalMemoryStatusEx"))
    events.extend(_api_call_events(rng, "GetVersionExW"))
    events.extend(_benign_noise(rng, rng.integers(30, 60)))
    return events


def _suspicious_obfuscated_code(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """Obfuscated code: heavy XOR, self-modifying patterns."""
    events: list[NDArray[np.float32]] = []

    for _ in range(rng.integers(80, 160)):
        events.append(_make_event(
            _rand_opcode(rng, *_R_LOGIC), _M_HREAD, 0,
            int(rng.integers(0, 256)),
        ))
        if rng.random() < 0.3:
            events.append(_make_event(
                _rand_opcode(rng, *_R_DATA), _M_HWRITE, 0,
                int(rng.integers(0, 256)),
            ))

    for _ in range(rng.integers(5, 15)):
        events.append(_make_event(
            _rand_opcode(rng, *_R_LOGIC), _M_HREAD, 0,
            int(rng.integers(0, 256)),
        ))
        events.append(_make_event(
            _rand_opcode(rng, *_R_DATA), _M_HWRITE, 0,
            int(rng.integers(0, 256)),
        ))
        events.append(_make_event(
            _rand_opcode(rng, *_R_CTRL), _M_CODE, 0,
            int(rng.integers(0, 256)),
        ))

    events.extend(_benign_noise(rng, rng.integers(30, 60)))
    return events


def _suspicious_sandbox_detection(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """Sandbox evasion: timing loops, cursor checks, system metrics."""
    events: list[NDArray[np.float32]] = []

    for _ in range(rng.integers(3, 7)):
        events.extend(_api_call_events(rng, "GetTickCount", n_setup=1, n_cleanup=1))
        events.extend(_api_call_events(rng, "Sleep", n_setup=1, n_cleanup=1))
        events.extend(_api_call_events(rng, "GetTickCount", n_setup=1, n_cleanup=1))
        events.append(_make_event(_rand_opcode(rng, *_R_ARITH), _M_NONE, 0, int(rng.integers(0, 256))))
        events.append(_make_event(_rand_opcode(rng, *_R_LOGIC), _M_NONE, 0, int(rng.integers(128, 256))))
        events.append(_make_event(_rand_opcode(rng, *_R_CTRL), _M_NONE, 0, int(rng.integers(0, 256))))

    for _ in range(rng.integers(5, 12)):
        events.extend(_api_call_events(rng, "GetCursorPos", n_setup=2, n_cleanup=1))
        events.extend(_api_call_events(rng, "Sleep", n_setup=1, n_cleanup=1))

    events.extend(_api_call_events(rng, "GetSystemMetrics"))
    events.extend(_benign_noise(rng, rng.integers(20, 50)))
    return events


def _suspicious_encrypted_strings(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """Encrypted string use: AES-NI decrypt → API call → re-encrypt."""
    events: list[NDArray[np.float32]] = []

    for _ in range(rng.integers(8, 16)):
        for _ in range(rng.integers(4, 8)):
            events.append(_make_event(
                _rand_opcode(rng, *_R_CRYPTO), _M_HREAD, 0,
                int(rng.integers(0, 256)),
            ))
            events.append(_make_event(
                _rand_opcode(rng, *_R_DATA), _M_HWRITE, 0,
                int(rng.integers(0, 256)),
            ))

        api_name = rng.choice(["LoadLibraryW", "GetProcAddress", "CreateFileW", "RegOpenKeyExW"])
        events.extend(_api_call_events(rng, api_name, n_setup=2, n_cleanup=1))

        for _ in range(rng.integers(3, 6)):
            events.append(_make_event(
                _rand_opcode(rng, *_R_CRYPTO), _M_HWRITE, 0,
                int(rng.integers(0, 256)),
            ))

    events.extend(_benign_noise(rng, rng.integers(15, 30)))
    return events


def _suspicious_api_resolution(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """Dynamic API resolution: GetProcAddress chains for suspicious APIs."""
    events: list[NDArray[np.float32]] = []
    events.extend(_api_call_events(rng, "LoadLibraryW", n_setup=3, n_cleanup=2))

    for _ in range(rng.integers(10, 25)):
        events.extend(_api_call_events(rng, "GetProcAddress", n_setup=2, n_cleanup=1))
        events.append(_make_event(
            _rand_opcode(rng, *_R_DATA), _M_HWRITE, 0,
            int(rng.integers(0, 256)),
        ))
        events.extend(_benign_noise(rng, rng.integers(1, 4)))

    events.extend(_api_call_events(rng, "LoadLibraryW"))
    for _ in range(rng.integers(8, 15)):
        events.extend(_api_call_events(rng, "GetProcAddress", n_setup=2, n_cleanup=1))
        events.append(_make_event(
            _rand_opcode(rng, *_R_DATA), _M_HWRITE, 0,
            int(rng.integers(0, 256)),
        ))

    events.extend(_benign_noise(rng, rng.integers(20, 40)))
    return events


def _suspicious_delay_loop(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """Anti-analysis delay: long Sleep/NtDelayExecution loops."""
    events: list[NDArray[np.float32]] = []
    events.extend(_benign_noise(rng, rng.integers(10, 30)))

    for _ in range(rng.integers(15, 30)):
        api_name = rng.choice(["Sleep", "NtDelayExecution", "WaitForSingleObject"])
        events.extend(_api_call_events(rng, api_name, n_setup=2, n_cleanup=1))
        events.extend(_benign_noise(rng, rng.integers(2, 6)))

    events.extend(_benign_noise(rng, rng.integers(30, 60)))
    return events


def _suspicious_polymorphic_decoder(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """Polymorphic decoder: XOR/ADD/SUB loop modifying memory, then JMP."""
    events: list[NDArray[np.float32]] = []
    events.extend(_benign_noise(rng, rng.integers(10, 25)))

    for _ in range(rng.integers(40, 80)):
        op = rng.choice([_R_LOGIC, _R_ARITH])
        events.append(_make_event(
            _rand_opcode(rng, op[0], op[1]), _M_HREAD, 0,
            int(rng.integers(0, 256)),
        ))
        events.append(_make_event(
            _rand_opcode(rng, op[0], op[1]), _M_HWRITE, 0,
            int(rng.integers(0, 256)),
        ))
        events.append(_make_event(
            _rand_opcode(rng, *_R_ARITH), _M_NONE, 0,
            int(rng.integers(0, 256)),
        ))
        events.append(_make_event(
            _rand_opcode(rng, *_R_CTRL), _M_NONE, 0,
            int(rng.integers(0, 128)),
        ))

    events.append(_make_event(
        _rand_opcode(rng, *_R_CTRL), _M_CODE, 0,
        int(rng.integers(0, 256)),
    ))
    events.extend(_benign_noise(rng, rng.integers(20, 40)))
    return events


def _suspicious_process_enumeration(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """Process enumeration with string comparison checks."""
    events: list[NDArray[np.float32]] = []
    events.extend(_api_call_events(rng, "NtQuerySystemInformation", n_setup=5, n_cleanup=3))

    for _ in range(rng.integers(20, 40)):
        events.extend(_benign_noise(rng, rng.integers(3, 8)))
        for _ in range(rng.integers(4, 10)):
            events.append(_make_event(
                _rand_opcode(rng, *_R_STRING), _M_HREAD, 0,
                int(rng.integers(0, 256)),
            ))
        events.append(_make_event(
            _rand_opcode(rng, *_R_CTRL), _M_NONE, 0,
            int(rng.integers(0, 256)),
        ))

    events.extend(_benign_noise(rng, rng.integers(20, 40)))
    return events


def _suspicious_timing_check_perf(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """High-resolution timing check via QueryPerformanceCounter."""
    events: list[NDArray[np.float32]] = []
    events.extend(_api_call_events(rng, "QueryPerformanceFrequency"))

    for _ in range(rng.integers(4, 8)):
        events.extend(_api_call_events(rng, "QueryPerformanceCounter", n_setup=2, n_cleanup=1))
        events.extend(_benign_noise(rng, rng.integers(20, 50)))
        events.extend(_api_call_events(rng, "QueryPerformanceCounter", n_setup=2, n_cleanup=1))
        events.append(_make_event(_rand_opcode(rng, *_R_ARITH), _M_SREAD, 0, int(rng.integers(0, 256))))
        events.append(_make_event(_rand_opcode(rng, *_R_LOGIC), _M_NONE, 0, int(rng.integers(128, 256))))
        events.append(_make_event(_rand_opcode(rng, *_R_CTRL), _M_NONE, 0, int(rng.integers(0, 256))))

    events.extend(_benign_noise(rng, rng.integers(30, 60)))
    return events


def _suspicious_ntquery_debug(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """Multiple NtQueryInformationProcess calls with debug class checks."""
    events: list[NDArray[np.float32]] = []
    events.extend(_benign_noise(rng, rng.integers(15, 30)))

    for _ in range(rng.integers(3, 7)):
        events.extend(_api_call_events(rng, "NtQueryInformationProcess", n_setup=4, n_cleanup=3))
        events.append(_make_event(_rand_opcode(rng, *_R_LOGIC), _M_SREAD, 0, int(rng.integers(0, 256))))
        events.append(_make_event(_rand_opcode(rng, *_R_CTRL), _M_NONE, 0, int(rng.integers(0, 256))))
        events.extend(_benign_noise(rng, rng.integers(5, 15)))

    events.extend(_api_call_events(rng, "IsDebuggerPresent"))
    events.extend(_benign_noise(rng, rng.integers(30, 50)))
    return events


_SUSPICIOUS_TEMPLATES = [
    _suspicious_anti_debug,
    _suspicious_env_check,
    _suspicious_obfuscated_code,
    _suspicious_sandbox_detection,
    _suspicious_encrypted_strings,
    _suspicious_api_resolution,
    _suspicious_delay_loop,
    _suspicious_polymorphic_decoder,
    _suspicious_process_enumeration,
    _suspicious_timing_check_perf,
    _suspicious_ntquery_debug,
]


# ═══════════════════════════════════════════════════════════════════════════
# MALICIOUS templates
# ═══════════════════════════════════════════════════════════════════════════


def _malicious_classic_injection(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """Classic injection: OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread."""
    events: list[NDArray[np.float32]] = []
    events.extend(_benign_noise(rng, rng.integers(10, 25)))
    events.extend(_api_call_events(rng, "OpenProcess", n_setup=4, n_cleanup=2))
    events.extend(_api_call_events(rng, "VirtualAllocEx", n_setup=5, n_cleanup=3))

    for _ in range(rng.integers(5, 15)):
        events.extend(_api_call_events(rng, "WriteProcessMemory", n_setup=3, n_cleanup=2))
        events.extend(_benign_noise(rng, rng.integers(2, 5)))

    events.extend(_api_call_events(rng, "CreateRemoteThread", n_setup=5, n_cleanup=3))
    events.extend(_benign_noise(rng, rng.integers(15, 30)))
    return events


def _malicious_apc_injection(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """APC injection: OpenThread → VirtualAllocEx → WriteProcessMemory → QueueUserAPC."""
    events: list[NDArray[np.float32]] = []
    events.extend(_benign_noise(rng, rng.integers(5, 20)))
    events.extend(_api_call_events(rng, "OpenProcess", n_setup=3, n_cleanup=2))
    events.extend(_api_call_events(rng, "OpenThread", n_setup=3, n_cleanup=2))
    events.extend(_api_call_events(rng, "VirtualAllocEx", n_setup=5, n_cleanup=3))

    for _ in range(rng.integers(3, 10)):
        events.extend(_api_call_events(rng, "WriteProcessMemory", n_setup=3, n_cleanup=2))

    events.extend(_api_call_events(rng, "QueueUserAPC", n_setup=4, n_cleanup=2))
    events.extend(_api_call_events(rng, "ResumeThread", n_setup=2, n_cleanup=2))
    events.extend(_benign_noise(rng, rng.integers(10, 25)))
    return events


def _malicious_process_hollowing(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """Process hollowing: CreateProcess(SUSPENDED) → Unmap → Alloc → Write → SetContext → Resume."""
    events: list[NDArray[np.float32]] = []
    events.extend(_benign_noise(rng, rng.integers(5, 15)))
    events.extend(_api_call_events(rng, "CreateProcessW", n_setup=6, n_cleanup=3))
    events.extend(_api_call_events(rng, "NtUnmapViewOfSection", n_setup=3, n_cleanup=2))
    events.extend(_api_call_events(rng, "VirtualAllocEx", n_setup=5, n_cleanup=3))

    for _ in range(rng.integers(8, 20)):
        events.extend(_api_call_events(rng, "WriteProcessMemory", n_setup=3, n_cleanup=2))
        events.extend(_benign_noise(rng, rng.integers(1, 4)))

    events.extend(_api_call_events(rng, "SetThreadContext", n_setup=5, n_cleanup=3))
    events.extend(_api_call_events(rng, "ResumeThread", n_setup=2, n_cleanup=2))
    events.extend(_benign_noise(rng, rng.integers(10, 20)))
    return events


def _malicious_shellcode_loader(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """Shellcode loader: VirtualAlloc(RWX) → memcpy loop → VirtualProtect → execute."""
    events: list[NDArray[np.float32]] = []
    events.extend(_benign_noise(rng, rng.integers(5, 20)))
    events.extend(_api_call_events(rng, "VirtualAlloc", n_setup=5, n_cleanup=3))

    for _ in range(rng.integers(20, 50)):
        events.append(_make_event(
            _rand_opcode(rng, *_R_DATA), _M_HWRITE, 0,
            int(rng.integers(0, 256)),
        ))
        events.append(_make_event(
            _rand_opcode(rng, *_R_ARITH), _M_NONE, 0,
            int(rng.integers(0, 256)),
        ))
        events.append(_make_event(
            _rand_opcode(rng, *_R_CTRL), _M_NONE, 0,
            int(rng.integers(0, 128)),
        ))

    events.extend(_api_call_events(rng, "VirtualProtect", n_setup=4, n_cleanup=2))

    events.append(_make_event(
        _rand_opcode(rng, *_R_CTRL), _M_CODE, 0,
        int(rng.integers(0, 256)),
    ))
    events.extend(_benign_noise(rng, rng.integers(10, 25)))
    return events


def _malicious_credential_dump(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """Credential dump: OpenProcess(lsass) → ReadProcessMemory loop → write to file."""
    events: list[NDArray[np.float32]] = []
    events.extend(_benign_noise(rng, rng.integers(5, 15)))
    events.extend(_api_call_events(rng, "NtQuerySystemInformation", n_setup=4, n_cleanup=3))
    events.extend(_benign_noise(rng, rng.integers(5, 10)))
    events.extend(_api_call_events(rng, "OpenProcess", n_setup=4, n_cleanup=2))

    for _ in range(rng.integers(30, 60)):
        events.extend(_api_call_events(rng, "ReadProcessMemory", n_setup=3, n_cleanup=2))
        events.extend(_benign_noise(rng, rng.integers(2, 6)))

    events.extend(_api_call_events(rng, "CreateFileW", n_setup=3, n_cleanup=2))
    events.extend(_api_call_events(rng, "WriteFile", n_setup=2, n_cleanup=1))
    events.extend(_api_call_events(rng, "CloseHandle"))
    events.extend(_benign_noise(rng, rng.integers(5, 15)))
    return events


def _malicious_ransomware(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """Ransomware: FindFirstFile → Read → Encrypt → Write → MoveFile loop."""
    events: list[NDArray[np.float32]] = []
    events.extend(_benign_noise(rng, rng.integers(5, 15)))
    events.extend(_api_call_events(rng, "CryptAcquireContextW", n_setup=3, n_cleanup=2))
    events.extend(_api_call_events(rng, "CryptGenKey", n_setup=3, n_cleanup=2))

    for _ in range(rng.integers(3, 7)):
        events.extend(_api_call_events(rng, "FindFirstFileW", n_setup=3, n_cleanup=2))
        for _ in range(rng.integers(3, 8)):
            events.extend(_api_call_events(rng, "CreateFileW", n_setup=2, n_cleanup=1))
            events.extend(_api_call_events(rng, "ReadFile", n_setup=2, n_cleanup=1))
            events.extend(_api_call_events(rng, "CryptEncrypt", n_setup=2, n_cleanup=1))
            events.extend(_api_call_events(rng, "WriteFile", n_setup=2, n_cleanup=1))
            events.extend(_api_call_events(rng, "MoveFileW", n_setup=2, n_cleanup=1))
            events.extend(_api_call_events(rng, "FindNextFileW", n_setup=1, n_cleanup=1))

    events.extend(_benign_noise(rng, rng.integers(5, 15)))
    return events


def _malicious_rootkit_install(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """Rootkit install: NtLoadDriver → DeviceIoControl → service registration."""
    events: list[NDArray[np.float32]] = []
    events.extend(_benign_noise(rng, rng.integers(10, 25)))

    events.extend(_api_call_events(rng, "RegCreateKeyExW", n_setup=4, n_cleanup=2))
    events.extend(_api_call_events(rng, "RegSetValueExW", n_setup=3, n_cleanup=2))
    events.extend(_api_call_events(rng, "RegSetValueExW", n_setup=3, n_cleanup=2))
    events.extend(_api_call_events(rng, "RegCloseKey"))
    events.extend(_api_call_events(rng, "NtLoadDriver", n_setup=4, n_cleanup=3))

    for _ in range(rng.integers(5, 12)):
        events.extend(_api_call_events(rng, "DeviceIoControl", n_setup=4, n_cleanup=3))
        events.extend(_benign_noise(rng, rng.integers(3, 8)))

    events.extend(_api_call_events(rng, "OpenSCManagerW", n_setup=3, n_cleanup=2))
    events.extend(_api_call_events(rng, "CreateServiceW", n_setup=5, n_cleanup=3))
    events.extend(_api_call_events(rng, "StartServiceW", n_setup=3, n_cleanup=2))
    events.extend(_benign_noise(rng, rng.integers(10, 20)))
    return events


def _malicious_c2_communication(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """C2 loop: connect → recv(cmd) → execute → send(result)."""
    events: list[NDArray[np.float32]] = []
    events.extend(_api_call_events(rng, "WSAStartup"))
    events.extend(_api_call_events(rng, "socket"))
    events.extend(_api_call_events(rng, "connect", n_setup=4, n_cleanup=2))

    for _ in range(rng.integers(8, 20)):
        events.extend(_api_call_events(rng, "recv", n_setup=2, n_cleanup=1))
        events.extend(_benign_noise(rng, rng.integers(5, 12)))

        if rng.random() < 0.5:
            events.extend(_api_call_events(rng, "CreateProcessW", n_setup=4, n_cleanup=2))
        else:
            events.extend(_api_call_events(rng, "CreateFileW", n_setup=3, n_cleanup=2))
            events.extend(_api_call_events(rng, "WriteFile", n_setup=2, n_cleanup=1))

        events.extend(_api_call_events(rng, "send", n_setup=2, n_cleanup=1))

    events.extend(_api_call_events(rng, "closesocket"))
    events.extend(_benign_noise(rng, rng.integers(5, 15)))
    return events


def _malicious_priv_escalation(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """Privilege escalation: OpenProcessToken → LookupPrivilege → AdjustToken."""
    events: list[NDArray[np.float32]] = []
    events.extend(_benign_noise(rng, rng.integers(10, 25)))
    events.extend(_api_call_events(rng, "OpenProcessToken", n_setup=4, n_cleanup=2))

    for priv_api in ["LookupPrivilegeValueW", "LookupPrivilegeValueW", "LookupPrivilegeValueW"]:
        events.extend(_api_call_events(rng, priv_api, n_setup=3, n_cleanup=2))

    events.extend(_api_call_events(rng, "AdjustTokenPrivileges", n_setup=5, n_cleanup=3))
    events.extend(_api_call_events(rng, "DuplicateTokenEx", n_setup=4, n_cleanup=2))
    events.extend(_api_call_events(rng, "ImpersonateLoggedOnUser", n_setup=3, n_cleanup=2))
    events.extend(_benign_noise(rng, rng.integers(20, 50)))
    events.extend(_api_call_events(rng, "RevertToSelf", n_setup=2, n_cleanup=2))
    events.extend(_benign_noise(rng, rng.integers(10, 20)))
    return events


def _malicious_dll_sideloading(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """DLL side-loading: CreateFile(dll) → LoadLibrary → GetProcAddress → call."""
    events: list[NDArray[np.float32]] = []
    events.extend(_benign_noise(rng, rng.integers(5, 15)))
    events.extend(_api_call_events(rng, "CreateFileW", n_setup=4, n_cleanup=2))
    events.extend(_api_call_events(rng, "WriteFile", n_setup=3, n_cleanup=2))
    for _ in range(rng.integers(5, 15)):
        events.extend(_api_call_events(rng, "WriteFile", n_setup=2, n_cleanup=1))
    events.extend(_api_call_events(rng, "CloseHandle"))

    events.extend(_api_call_events(rng, "LoadLibraryW", n_setup=3, n_cleanup=2))
    events.extend(_api_call_events(rng, "GetProcAddress", n_setup=2, n_cleanup=2))

    events.append(_make_event(
        _rand_opcode(rng, *_R_CTRL), _M_CODE, 0,
        int(rng.integers(0, 256)),
    ))
    events.extend(_benign_noise(rng, rng.integers(20, 40)))
    return events


def _malicious_keylogger(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """Keylogger: SetWindowsHookEx → GetAsyncKeyState loop → write log file."""
    events: list[NDArray[np.float32]] = []
    events.extend(_benign_noise(rng, rng.integers(5, 15)))
    events.extend(_api_call_events(rng, "SetWindowsHookExW", n_setup=5, n_cleanup=3))

    for _ in range(rng.integers(60, 120)):
        events.extend(_api_call_events(rng, "GetAsyncKeyState", n_setup=1, n_cleanup=1))
        events.append(_make_event(
            _rand_opcode(rng, *_R_LOGIC), _M_NONE, 0,
            int(rng.integers(0, 256)),
        ))
        events.append(_make_event(
            _rand_opcode(rng, *_R_CTRL), _M_NONE, 0,
            int(rng.integers(0, 256)),
        ))
        if rng.random() < 0.1:
            events.extend(_api_call_events(rng, "CreateFileW", n_setup=2, n_cleanup=1))
            events.extend(_api_call_events(rng, "WriteFile", n_setup=2, n_cleanup=1))
            events.extend(_api_call_events(rng, "CloseHandle", n_setup=1, n_cleanup=1))

    events.extend(_benign_noise(rng, rng.integers(5, 15)))
    return events


def _malicious_worm_spread(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """Worm spread: NetShareEnum → connect → copy → install service."""
    events: list[NDArray[np.float32]] = []
    events.extend(_benign_noise(rng, rng.integers(5, 15)))
    events.extend(_api_call_events(rng, "NetShareEnum", n_setup=4, n_cleanup=3))

    for _ in range(rng.integers(3, 7)):
        events.extend(_api_call_events(rng, "WNetAddConnection2W", n_setup=4, n_cleanup=2))
        events.extend(_api_call_events(rng, "CopyFileW", n_setup=3, n_cleanup=2))
        events.extend(_api_call_events(rng, "OpenSCManagerW", n_setup=3, n_cleanup=2))
        events.extend(_api_call_events(rng, "CreateServiceW", n_setup=5, n_cleanup=3))
        events.extend(_api_call_events(rng, "StartServiceW", n_setup=3, n_cleanup=2))
        events.extend(_benign_noise(rng, rng.integers(5, 12)))

    events.extend(_benign_noise(rng, rng.integers(10, 20)))
    return events


def _malicious_reflective_dll(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """Reflective DLL injection: alloc → manual PE mapping → execute entry point."""
    events: list[NDArray[np.float32]] = []
    events.extend(_benign_noise(rng, rng.integers(5, 15)))
    events.extend(_api_call_events(rng, "VirtualAlloc", n_setup=5, n_cleanup=3))

    for _ in range(rng.integers(15, 30)):
        events.append(_make_event(
            _rand_opcode(rng, *_R_DATA), _M_HWRITE, 0,
            int(rng.integers(0, 256)),
        ))
        events.append(_make_event(
            _rand_opcode(rng, *_R_ARITH), _M_HREAD, 0,
            int(rng.integers(0, 256)),
        ))

    for _ in range(rng.integers(3, 8)):
        events.extend(_api_call_events(rng, "GetProcAddress", n_setup=2, n_cleanup=1))
        events.append(_make_event(
            _rand_opcode(rng, *_R_DATA), _M_HWRITE, 0,
            int(rng.integers(0, 256)),
        ))

    events.extend(_api_call_events(rng, "VirtualProtect", n_setup=4, n_cleanup=2))
    events.append(_make_event(
        _rand_opcode(rng, *_R_CTRL), _M_CODE, 0,
        int(rng.integers(0, 256)),
    ))
    events.extend(_benign_noise(rng, rng.integers(10, 25)))
    return events


def _malicious_token_impersonation(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """Token impersonation: enum processes → steal token → impersonate → spawn."""
    events: list[NDArray[np.float32]] = []
    events.extend(_benign_noise(rng, rng.integers(5, 15)))
    events.extend(_api_call_events(rng, "NtQuerySystemInformation", n_setup=4, n_cleanup=3))

    for _ in range(rng.integers(5, 10)):
        events.extend(_api_call_events(rng, "OpenProcess", n_setup=3, n_cleanup=2))
        events.extend(_api_call_events(rng, "OpenProcessToken", n_setup=3, n_cleanup=2))
        events.extend(_benign_noise(rng, rng.integers(2, 6)))

    events.extend(_api_call_events(rng, "DuplicateTokenEx", n_setup=4, n_cleanup=2))
    events.extend(_api_call_events(rng, "ImpersonateLoggedOnUser", n_setup=3, n_cleanup=2))
    events.extend(_api_call_events(rng, "CreateProcessW", n_setup=5, n_cleanup=3))
    events.extend(_benign_noise(rng, rng.integers(10, 25)))
    return events


def _malicious_download_execute(rng: np.random.Generator) -> list[NDArray[np.float32]]:
    """Download and execute: HTTP fetch → write to disk → execute."""
    events: list[NDArray[np.float32]] = []
    events.extend(_benign_noise(rng, rng.integers(5, 15)))
    events.extend(_api_call_events(rng, "InternetOpenW", n_setup=3, n_cleanup=2))
    events.extend(_api_call_events(rng, "InternetConnectW", n_setup=4, n_cleanup=2))
    events.extend(_api_call_events(rng, "HttpOpenRequestW", n_setup=4, n_cleanup=2))
    events.extend(_api_call_events(rng, "HttpSendRequestW", n_setup=3, n_cleanup=2))

    for _ in range(rng.integers(10, 25)):
        events.extend(_api_call_events(rng, "InternetReadFile", n_setup=2, n_cleanup=1))
        events.extend(_benign_noise(rng, rng.integers(1, 4)))

    events.extend(_api_call_events(rng, "CreateFileW", n_setup=3, n_cleanup=2))
    events.extend(_api_call_events(rng, "WriteFile", n_setup=2, n_cleanup=1))
    events.extend(_api_call_events(rng, "CloseHandle"))
    events.extend(_api_call_events(rng, "CreateProcessW", n_setup=4, n_cleanup=3))
    events.extend(_benign_noise(rng, rng.integers(5, 15)))
    return events


_MALICIOUS_TEMPLATES = [
    _malicious_classic_injection,
    _malicious_apc_injection,
    _malicious_process_hollowing,
    _malicious_shellcode_loader,
    _malicious_credential_dump,
    _malicious_ransomware,
    _malicious_rootkit_install,
    _malicious_c2_communication,
    _malicious_priv_escalation,
    _malicious_dll_sideloading,
    _malicious_keylogger,
    _malicious_worm_spread,
    _malicious_reflective_dll,
    _malicious_token_impersonation,
    _malicious_download_execute,
]


# ═══════════════════════════════════════════════════════════════════════════
# Sample generation
# ═══════════════════════════════════════════════════════════════════════════


def _generate_single_sample(
    rng: np.random.Generator,
    verdict: EmulationVerdict,
    seq_length: int,
) -> NDArray[np.float32]:
    """Generate one emulation trace sequence for the given verdict class.

    Selects a random template, generates the core attack/benign pattern,
    injects 10-20% benign noise for realism, then pads or truncates to
    ``seq_length``.
    """
    if verdict == EmulationVerdict.Benign:
        template_fn = rng.choice(_BENIGN_TEMPLATES)
    elif verdict == EmulationVerdict.Suspicious:
        template_fn = rng.choice(_SUSPICIOUS_TEMPLATES)
    else:
        template_fn = rng.choice(_MALICIOUS_TEMPLATES)

    events = template_fn(rng)

    noise_ratio = rng.uniform(0.10, 0.20)
    noise_count = max(1, int(len(events) * noise_ratio))
    noise_events = _benign_noise(rng, noise_count)

    insert_positions = sorted(
        rng.choice(len(events) + 1, size=min(noise_count, len(events) + 1), replace=False)
    )
    merged: list[NDArray[np.float32]] = []
    prev_pos = 0
    for i, pos in enumerate(insert_positions):
        merged.extend(events[prev_pos:pos])
        if i < len(noise_events):
            merged.append(noise_events[i])
        prev_pos = pos
    merged.extend(events[prev_pos:])

    return _pad_or_truncate(merged, seq_length, rng)


def generate_emulation_dataset(
    n_samples: int = 60000,
    seq_length: int = SEQUENCE_LENGTH,
    seed: int = 42,
    *,
    n_benign: Optional[int] = None,
    n_suspicious: Optional[int] = None,
    n_malicious: Optional[int] = None,
) -> tuple[NDArray[np.float32], NDArray[np.int64]]:
    """Generate a synthetic emulation trace dataset.

    Default class distribution is imbalanced toward threats:
        - 15 000 Benign (25%)
        - 15 000 Suspicious (25%)
        - 30 000 Malicious (50%)

    Parameters
    ----------
    n_samples : int
        Total number of samples (used only when per-class counts are None).
    seq_length : int
        Events per trace sequence (default 1024).
    seed : int
        Random seed for reproducibility.
    n_benign, n_suspicious, n_malicious : int, optional
        Override per-class sample counts.

    Returns
    -------
    X : ndarray of shape (N, seq_length, 4), dtype float32
    y : ndarray of shape (N,), dtype int64
    """
    if n_benign is None:
        n_benign = n_samples // 4
    if n_suspicious is None:
        n_suspicious = n_samples // 4
    if n_malicious is None:
        n_malicious = n_samples - n_benign - n_suspicious

    total = n_benign + n_suspicious + n_malicious
    if total < 1:
        raise ValueError("Total samples must be >= 1")

    rng = np.random.default_rng(seed)

    logger.info(
        "Generating emulation dataset: %d benign, %d suspicious, %d malicious "
        "(total=%d, seq_length=%d, seed=%d)",
        n_benign, n_suspicious, n_malicious, total, seq_length, seed,
    )

    X = np.empty((total, seq_length, FEATURE_DIM), dtype=np.float32)
    y = np.empty(total, dtype=np.int64)

    class_plan: list[tuple[EmulationVerdict, int]] = [
        (EmulationVerdict.Benign, n_benign),
        (EmulationVerdict.Suspicious, n_suspicious),
        (EmulationVerdict.Malicious, n_malicious),
    ]

    idx = 0
    for verdict, count in class_plan:
        for _ in range(count):
            X[idx] = _generate_single_sample(rng, verdict, seq_length)
            y[idx] = int(verdict)
            idx += 1

            if idx % 5000 == 0:
                logger.info("  Generated %d / %d samples...", idx, total)

    shuffle_idx = rng.permutation(total)
    X = X[shuffle_idx]
    y = y[shuffle_idx]

    logger.info("Dataset generation complete: X=%s, y=%s", X.shape, y.shape)
    return X, y


# ═══════════════════════════════════════════════════════════════════════════
# DataLoader factory
# ═══════════════════════════════════════════════════════════════════════════


def get_emulation_dataloaders(
    X: NDArray[np.float32],
    y: NDArray[np.int64],
    batch_size: int = 128,
    seed: int = 42,
    num_workers: int = 0,
    train_ratio: float = 0.8,
    val_ratio: float = 0.1,
    test_ratio: float = 0.1,
) -> tuple[DataLoader, DataLoader, DataLoader]:
    """Split data and return train / val / test DataLoaders.

    Parameters
    ----------
    X, y : ndarray
        Full dataset from :func:`generate_emulation_dataset`.
    batch_size : int
        Batch size for all loaders.
    seed : int
        Reproducibility seed for the split.
    num_workers : int
        DataLoader workers.
    train_ratio, val_ratio, test_ratio : float
        Split proportions (must sum to 1.0).

    Returns
    -------
    train_loader, val_loader, test_loader
    """
    (X_tr, y_tr), (X_val, y_val), (X_te, y_te) = split_data(
        X, y,
        train_ratio=train_ratio,
        val_ratio=val_ratio,
        test_ratio=test_ratio,
        seed=seed,
    )

    train_loader = create_dataloader(
        X_tr, y_tr, batch_size=batch_size, shuffle=True, num_workers=num_workers,
    )
    val_loader = create_dataloader(
        X_val, y_val, batch_size=batch_size, shuffle=False, num_workers=num_workers,
    )
    test_loader = create_dataloader(
        X_te, y_te, batch_size=batch_size, shuffle=False, num_workers=num_workers,
    )

    logger.info(
        "DataLoaders ready: train=%d batches, val=%d batches, test=%d batches",
        len(train_loader), len(val_loader), len(test_loader),
    )
    return train_loader, val_loader, test_loader


# ═══════════════════════════════════════════════════════════════════════════
# CLI entry point
# ═══════════════════════════════════════════════════════════════════════════


if __name__ == "__main__":
    import argparse
    import sys
    import time as _time

    parser = argparse.ArgumentParser(
        description="Generate synthetic emulation trace data for Cortex-Emulation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--n-samples", type=int, default=60000, help="Total samples (default 60000)")
    parser.add_argument("--n-benign", type=int, default=None, help="Benign count override")
    parser.add_argument("--n-suspicious", type=int, default=None, help="Suspicious count override")
    parser.add_argument("--n-malicious", type=int, default=None, help="Malicious count override")
    parser.add_argument("--seq-length", type=int, default=1024, help="Sequence length (default 1024)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--output", type=str, default=None, help="Save dataset to .npz file")
    parser.add_argument("--batch-size", type=int, default=128, help="DataLoader batch size")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    t0 = _time.perf_counter()
    X, y = generate_emulation_dataset(
        n_samples=args.n_samples,
        seq_length=args.seq_length,
        seed=args.seed,
        n_benign=args.n_benign,
        n_suspicious=args.n_suspicious,
        n_malicious=args.n_malicious,
    )
    elapsed = _time.perf_counter() - t0

    print(f"\nGeneration complete in {elapsed:.1f}s")
    print(f"  X shape: {X.shape}")
    print(f"  y shape: {y.shape}")
    print_dataset_stats(y, VERDICT_NAMES)

    if args.output:
        from PhantomCortex.training.data.dataset_utils import save_dataset

        (X_tr, y_tr), (X_v, y_v), (X_te, y_te) = split_data(X, y, seed=args.seed)
        save_dataset(args.output, X_tr, y_tr, X_v, y_v, X_te, y_te)
        print(f"Saved to {args.output}")

    print("\nSample verification — first 3 events of sample 0:")
    for i in range(min(3, X.shape[1])):
        print(f"  event[{i}]: opcode={X[0, i, 0]:.0f}  mem={X[0, i, 1]:.0f}  "
              f"api={X[0, i, 2]:.0f}  eflags={X[0, i, 3]:.0f}")
