"""
Behavioral Feature Extractor — API Call Sequence Encoding
=========================================================
Encodes sandbox / PhantomEmulator API call traces into fixed-length tensors
for the Cortex-Behavioral CNN model.

Input:  sequence of API call records (name, args, return_value, timestamp)
Output: numpy array of shape (max_sequence_length, 4)

Each call is encoded as:
    [api_name_id, arg_summary_hash, return_value_code, timestamp_delta_ms]
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

import numpy as np

logger = logging.getLogger("phantomcortex.features.behavioral")

# ═══════════════════════════════════════════════════════════════════════════
# API taxonomy
# ═══════════════════════════════════════════════════════════════════════════
API_CATEGORIES: Dict[str, List[str]] = {
    "File": [
        "CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "DeleteFileA",
        "DeleteFileW", "CopyFileA", "CopyFileW", "MoveFileA", "MoveFileW",
        "SetFileAttributesA", "SetFileAttributesW", "GetFileAttributesA",
        "GetFileAttributesW", "FindFirstFileA", "FindFirstFileW",
        "FindNextFileA", "FindNextFileW", "GetTempPathA", "GetTempPathW",
        "GetTempFileNameA", "GetTempFileNameW", "SetEndOfFile",
        "SetFilePointer", "SetFilePointerEx", "LockFile", "UnlockFile",
        "FlushFileBuffers", "CreateDirectoryA", "CreateDirectoryW",
        "RemoveDirectoryA", "RemoveDirectoryW", "GetFileSize",
        "GetFileSizeEx", "GetFileType", "GetFileInformationByHandle",
        "NtCreateFile", "NtReadFile", "NtWriteFile", "NtDeleteFile",
        "NtSetInformationFile", "NtQueryInformationFile",
        "NtQueryDirectoryFile", "NtOpenFile",
    ],
    "Registry": [
        "RegOpenKeyExA", "RegOpenKeyExW", "RegCreateKeyExA",
        "RegCreateKeyExW", "RegSetValueExA", "RegSetValueExW",
        "RegQueryValueExA", "RegQueryValueExW", "RegDeleteKeyA",
        "RegDeleteKeyW", "RegDeleteValueA", "RegDeleteValueW",
        "RegEnumKeyExA", "RegEnumKeyExW", "RegEnumValueA",
        "RegEnumValueW", "RegCloseKey", "RegFlushKey",
        "NtOpenKey", "NtCreateKey", "NtSetValueKey",
        "NtQueryValueKey", "NtDeleteKey", "NtEnumerateKey",
    ],
    "Process": [
        "CreateProcessA", "CreateProcessW", "CreateProcessInternalW",
        "OpenProcess", "TerminateProcess", "ExitProcess",
        "GetExitCodeProcess", "GetCurrentProcessId", "GetProcessId",
        "NtCreateProcess", "NtCreateProcessEx", "NtOpenProcess",
        "NtTerminateProcess", "NtCreateUserProcess",
        "CreateProcessAsUserA", "CreateProcessAsUserW",
        "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA",
        "ShellExecuteExW", "WinExec", "NtResumeProcess",
        "NtSuspendProcess",
    ],
    "Thread": [
        "CreateThread", "CreateRemoteThread", "CreateRemoteThreadEx",
        "ResumeThread", "SuspendThread", "TerminateThread",
        "ExitThread", "GetThreadContext", "SetThreadContext",
        "NtCreateThread", "NtCreateThreadEx", "NtOpenThread",
        "NtTerminateThread", "NtSetContextThread", "NtGetContextThread",
        "NtResumeThread", "NtSuspendThread", "QueueUserAPC",
        "NtQueueApcThread", "NtQueueApcThreadEx",
    ],
    "Network": [
        "socket", "connect", "bind", "listen", "accept", "send", "recv",
        "sendto", "recvfrom", "closesocket", "WSAStartup", "WSACleanup",
        "WSASocketA", "WSASocketW", "WSASend", "WSARecv", "WSAConnect",
        "getaddrinfo", "gethostbyname", "gethostbyaddr",
        "InternetOpenA", "InternetOpenW", "InternetConnectA",
        "InternetConnectW", "InternetOpenUrlA", "InternetOpenUrlW",
        "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA",
        "HttpSendRequestW", "InternetReadFile", "InternetWriteFile",
        "InternetCloseHandle", "URLDownloadToFileA", "URLDownloadToFileW",
        "HttpQueryInfoA", "HttpQueryInfoW",
        "DnsQuery_A", "DnsQuery_W", "DNSQuery_UTF8",
        "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest",
        "WinHttpSendRequest", "WinHttpReceiveResponse",
        "WinHttpReadData", "WinHttpCloseHandle",
    ],
    "Memory": [
        "VirtualAlloc", "VirtualAllocEx", "VirtualFree", "VirtualFreeEx",
        "VirtualProtect", "VirtualProtectEx", "VirtualQuery",
        "VirtualQueryEx", "NtAllocateVirtualMemory",
        "NtFreeVirtualMemory", "NtProtectVirtualMemory",
        "NtReadVirtualMemory", "NtWriteVirtualMemory",
        "ReadProcessMemory", "WriteProcessMemory",
        "HeapCreate", "HeapDestroy", "HeapAlloc", "HeapReAlloc",
        "HeapFree", "GlobalAlloc", "GlobalFree", "LocalAlloc", "LocalFree",
        "MapViewOfFile", "UnmapViewOfFile", "CreateFileMappingA",
        "CreateFileMappingW", "NtMapViewOfSection", "NtUnmapViewOfSection",
        "NtCreateSection",
    ],
    "Crypto": [
        "CryptAcquireContextA", "CryptAcquireContextW",
        "CryptReleaseContext", "CryptGenKey", "CryptDeriveKey",
        "CryptDestroyKey", "CryptEncrypt", "CryptDecrypt",
        "CryptHashData", "CryptCreateHash", "CryptDestroyHash",
        "CryptExportKey", "CryptImportKey", "CryptGenRandom",
        "CryptSignHashA", "CryptSignHashW", "CryptVerifySignatureA",
        "CryptVerifySignatureW", "BCryptOpenAlgorithmProvider",
        "BCryptCloseAlgorithmProvider", "BCryptGenerateSymmetricKey",
        "BCryptEncrypt", "BCryptDecrypt", "BCryptHash",
        "BCryptCreateHash", "BCryptHashData", "BCryptDestroyHash",
    ],
    "COM": [
        "CoInitialize", "CoInitializeEx", "CoUninitialize",
        "CoCreateInstance", "CoCreateInstanceEx", "CoGetClassObject",
        "OleInitialize", "CLSIDFromProgID", "CLSIDFromString",
        "CoTaskMemAlloc", "CoTaskMemFree",
    ],
    "WMI": [
        "IWbemLocator_ConnectServer", "IWbemServices_ExecQuery",
        "IWbemServices_ExecMethod", "IWbemServices_GetObject",
        "IEnumWbemClassObject_Next",
    ],
}

# Build flat lookup: api_name → category
_API_TO_CATEGORY: Dict[str, str] = {}
for _cat, _apis in API_CATEGORIES.items():
    for _api in _apis:
        _API_TO_CATEGORY[_api.lower()] = _cat

# Category → integer ID
_CATEGORY_IDS: Dict[str, int] = {name: idx for idx, name in enumerate(API_CATEGORIES.keys())}
_UNKNOWN_CATEGORY_ID: int = len(_CATEGORY_IDS)


def _stable_hash_to_int(value: str, modulus: int) -> int:
    """Deterministic hash of a string into [0, modulus)."""
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).digest()
    return int.from_bytes(digest[:8], "little") % modulus


# ═══════════════════════════════════════════════════════════════════════════
# Data model
# ═══════════════════════════════════════════════════════════════════════════
@dataclass(frozen=True, slots=True)
class ApiCallRecord:
    """Single API call observation from a sandbox or emulator trace."""
    api_name: str
    arguments: str = ""
    return_value: int = 0
    timestamp_ms: float = 0.0


# ═══════════════════════════════════════════════════════════════════════════
# Extractor
# ═══════════════════════════════════════════════════════════════════════════
class BehavioralFeatureExtractor:
    """
    Encode an API call trace into a fixed-size tensor for Cortex-Behavioral CNN.

    Parameters
    ----------
    max_sequence_length : int
        Maximum number of API calls retained (default 512).
    api_vocabulary_size : int
        Hash-space for API name IDs (default 2000).
    feature_dim : int
        Columns per call (default 4): [api_id, arg_hash, retval, dt_ms].
    """

    def __init__(
        self,
        max_sequence_length: int = 512,
        api_vocabulary_size: int = 2000,
        feature_dim: int = 4,
    ) -> None:
        if max_sequence_length < 1:
            raise ValueError("max_sequence_length must be >= 1")
        if api_vocabulary_size < 1:
            raise ValueError("api_vocabulary_size must be >= 1")
        self.max_sequence_length = max_sequence_length
        self.api_vocabulary_size = api_vocabulary_size
        self.feature_dim = feature_dim

    @property
    def output_shape(self) -> tuple[int, int]:
        return (self.max_sequence_length, self.feature_dim)

    def extract(self, calls: Sequence[ApiCallRecord]) -> np.ndarray:
        """
        Encode *calls* into a float32 array of shape (max_sequence_length, 4).

        Columns:
            0  api_name_id     — hashed API name mod api_vocabulary_size
            1  arg_summary     — hashed argument string mod api_vocabulary_size
            2  return_value    — raw return code (clamped to int32 range)
            3  timestamp_delta — milliseconds since previous call (0 for first)

        If len(calls) > max_sequence_length the tail is truncated.
        If shorter, rows are zero-padded.
        """
        out = np.zeros(self.output_shape, dtype=np.float32)
        n = min(len(calls), self.max_sequence_length)
        if n == 0:
            return out

        prev_ts: float = calls[0].timestamp_ms
        for i in range(n):
            call = calls[i]
            api_id = _stable_hash_to_int(call.api_name.lower(), self.api_vocabulary_size)
            arg_hash = _stable_hash_to_int(call.arguments, self.api_vocabulary_size)
            retval = np.clip(call.return_value, np.iinfo(np.int32).min, np.iinfo(np.int32).max)
            dt = max(call.timestamp_ms - prev_ts, 0.0)
            prev_ts = call.timestamp_ms

            out[i, 0] = float(api_id)
            out[i, 1] = float(arg_hash)
            out[i, 2] = float(retval)
            out[i, 3] = dt

        return out

    def extract_with_categories(self, calls: Sequence[ApiCallRecord]) -> Dict[str, Any]:
        """
        Return the encoded tensor plus per-category call counts for
        explainability / secondary features.
        """
        tensor = self.extract(calls)
        category_counts: Dict[str, int] = {cat: 0 for cat in API_CATEGORIES}
        category_counts["Unknown"] = 0

        n = min(len(calls), self.max_sequence_length)
        for i in range(n):
            cat = _API_TO_CATEGORY.get(calls[i].api_name.lower())
            if cat is not None:
                category_counts[cat] += 1
            else:
                category_counts["Unknown"] += 1

        return {"tensor": tensor, "category_counts": category_counts}

    def extract_batch(self, batch: Sequence[Sequence[ApiCallRecord]]) -> np.ndarray:
        """Process multiple traces, returning (batch_size, max_seq, feature_dim)."""
        result = np.zeros((len(batch), *self.output_shape), dtype=np.float32)
        for idx, calls in enumerate(batch):
            result[idx] = self.extract(calls)
        return result
