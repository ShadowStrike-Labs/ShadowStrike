/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * HashResolver.cpp — API hash-based import resolver for shellcode analysis
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "HashResolver.hpp"

#include <algorithm>
#include <cstring>

namespace Phantom {

// ============================================================================
// Constants
// ============================================================================

// Cap on total interned strings to prevent unbounded growth from adversarial input
static constexpr uint32_t kMaxInternedModules   = 256;
static constexpr uint32_t kMaxInternedFunctions  = 65536;
static constexpr uint32_t kMaxBatchSize          = 4096;

// ============================================================================
// ASCII helpers (no locale dependency — PE export names are always ASCII)
// ============================================================================

static char ToLowerASCII(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c;
}

static char ToUpperASCII(char c) noexcept {
    return (c >= 'a' && c <= 'z') ? static_cast<char>(c - ('a' - 'A')) : c;
}

// ============================================================================
// CRC32 lookup table — IEEE 802.3, polynomial 0xEDB88320 (reflected)
// ============================================================================

static constexpr std::array<uint32_t, 256> BuildCRC32Table() noexcept {
    std::array<uint32_t, 256> table{};
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t crc = i;
        for (int j = 0; j < 8; ++j) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320u;
            } else {
                crc >>= 1;
            }
        }
        table[i] = crc;
    }
    return table;
}

static constexpr auto kCRC32Table = BuildCRC32Table();

// ============================================================================
// Hash Algorithm Implementations
// ============================================================================
// Each function must produce EXACTLY the same output as real malware toolkits.
// A single bit difference means total failure to resolve shellcode imports.
// ============================================================================

// ROR13 (Metasploit block_api.asm convention):
//   module_hash = ror13 over UPPERCASE UNICODE (wchar_t) bytes of module name
//   func_hash   = ror13 over ASCII bytes of function name
//   final_hash  = module_hash + func_hash
//
// The ROR13 operation: hash = ((hash >> 13) | (hash << 19)) then hash += char_byte

static uint32_t HashROR13_Unicode(std::string_view name) noexcept {
    uint32_t hash = 0;
    for (const char c : name) {
        const auto wc = static_cast<uint16_t>(ToUpperASCII(c));
        // Low byte of the wchar_t
        hash = ((hash >> 13) | (hash << 19));
        hash += static_cast<uint8_t>(wc & 0xFF);
        // High byte of the wchar_t (always 0 for ASCII, but must be processed)
        hash = ((hash >> 13) | (hash << 19));
        hash += static_cast<uint8_t>((wc >> 8) & 0xFF);
    }
    return hash;
}

static uint32_t HashROR13_ASCII(std::string_view name) noexcept {
    uint32_t hash = 0;
    for (const char c : name) {
        hash = ((hash >> 13) | (hash << 19));
        hash += static_cast<uint8_t>(c);
    }
    return hash;
}

static uint32_t ComputeROR13(std::string_view moduleName,
                              std::string_view funcName) noexcept {
    return HashROR13_Unicode(moduleName) + HashROR13_ASCII(funcName);
}

// CRC32 — standard IEEE 802.3, function name only (ASCII bytes)
static uint32_t ComputeCRC32(std::string_view name) noexcept {
    uint32_t crc = 0xFFFFFFFFu;
    for (const char c : name) {
        crc = kCRC32Table[static_cast<uint8_t>(crc ^ static_cast<uint8_t>(c))] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

// CRC32Full — CRC32 of "module.dll!FunctionName" combined string
static uint32_t ComputeCRC32Full(std::string_view moduleName,
                                  std::string_view funcName) noexcept {
    uint32_t crc = 0xFFFFFFFFu;
    for (const char c : moduleName) {
        crc = kCRC32Table[static_cast<uint8_t>(crc ^ static_cast<uint8_t>(c))] ^ (crc >> 8);
    }
    constexpr uint8_t sep = '!';
    crc = kCRC32Table[static_cast<uint8_t>(crc ^ sep)] ^ (crc >> 8);
    for (const char c : funcName) {
        crc = kCRC32Table[static_cast<uint8_t>(crc ^ static_cast<uint8_t>(c))] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

// DJB2 — Dan Bernstein's hash: hash = hash * 33 + c, seed = 5381
static uint32_t ComputeDJB2(std::string_view name) noexcept {
    uint32_t hash = 5381;
    for (const char c : name) {
        hash = ((hash << 5) + hash) + static_cast<uint8_t>(c);
    }
    return hash;
}

// FNV-1a 32-bit — offset basis 2166136261, prime 16777619
static uint32_t ComputeFNV1a(std::string_view name) noexcept {
    uint32_t hash = 2166136261u;
    for (const char c : name) {
        hash ^= static_cast<uint8_t>(c);
        hash *= 16777619u;
    }
    return hash;
}

// SDBM — hash = c + (hash << 6) + (hash << 16) - hash
static uint32_t ComputeSDBM(std::string_view name) noexcept {
    uint32_t hash = 0;
    for (const char c : name) {
        hash = static_cast<uint8_t>(c) + (hash << 6) + (hash << 16) - hash;
    }
    return hash;
}

// Paul Hsieh's SuperFastHash
// Reference: http://www.azillionmonkeys.com/qed/hash.html
static uint32_t ComputeSuperFast(std::string_view name) noexcept {
    auto len = static_cast<uint32_t>(name.size());
    if (len == 0) return 0;

    const auto* data = reinterpret_cast<const uint8_t*>(name.data());
    uint32_t hash = len;
    uint32_t rem = len & 3;
    len >>= 2;

    for (; len > 0; --len) {
        uint16_t lo = 0;
        uint16_t hi = 0;
        std::memcpy(&lo, data, sizeof(uint16_t));
        std::memcpy(&hi, data + 2, sizeof(uint16_t));
        hash += lo;
        uint32_t tmp = (static_cast<uint32_t>(hi) << 11) ^ hash;
        hash = (hash << 16) ^ tmp;
        data += 4;
        hash += hash >> 11;
    }

    switch (rem) {
        case 3: {
            uint16_t lo = 0;
            std::memcpy(&lo, data, sizeof(uint16_t));
            hash += lo;
            hash ^= hash << 16;
            hash ^= static_cast<uint32_t>(static_cast<int8_t>(data[2])) << 18;
            hash += hash >> 11;
            break;
        }
        case 2: {
            uint16_t lo = 0;
            std::memcpy(&lo, data, sizeof(uint16_t));
            hash += lo;
            hash ^= hash << 11;
            hash += hash >> 17;
            break;
        }
        case 1:
            hash += static_cast<int8_t>(*data);
            hash ^= hash << 10;
            hash += hash >> 1;
            break;
        default:
            break;
    }

    hash ^= hash << 3;
    hash += hash >> 5;
    hash ^= hash << 4;
    hash += hash >> 17;
    hash ^= hash << 25;
    hash += hash >> 6;

    return hash;
}

// MurmurHash one-at-a-time variant (MurmurOAAT_32)
static uint32_t ComputeMurmurOAAT(std::string_view name) noexcept {
    uint32_t hash = 0;
    for (const char c : name) {
        hash ^= static_cast<uint8_t>(c);
        hash *= 0x5BD1E995u;
        hash ^= hash >> 15;
    }
    return hash;
}

// Jenkins one-at-a-time
static uint32_t ComputeJenkinsOAAT(std::string_view name) noexcept {
    uint32_t hash = 0;
    for (const char c : name) {
        hash += static_cast<uint8_t>(c);
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}

// ROR13Wide — ROR13 on wide-char representations of both module and function name
static uint32_t HashROR13Wide_Impl(std::string_view name) noexcept {
    uint32_t hash = 0;
    for (const char c : name) {
        const auto wc = static_cast<uint16_t>(static_cast<uint8_t>(c));
        hash = ((hash >> 13) | (hash << 19));
        hash += static_cast<uint8_t>(wc & 0xFF);
        hash = ((hash >> 13) | (hash << 19));
        hash += static_cast<uint8_t>((wc >> 8) & 0xFF);
    }
    return hash;
}

static uint32_t ComputeROR13Wide(std::string_view moduleName,
                                  std::string_view funcName) noexcept {
    return HashROR13Wide_Impl(moduleName) + HashROR13Wide_Impl(funcName);
}

// ============================================================================
// Comprehensive list of Windows API names commonly resolved via hash
// ============================================================================
// Covers: process injection, file I/O, networking, registry, crypto,
// anti-debug, memory, synchronization, and system information APIs.
// These are the functions that real-world shellcode, packers, and implants
// need at runtime. Coverage of this table directly determines detection rate.
// ============================================================================

struct APINameEntry {
    const char* dll;
    const char* func;
};

// clang-format off
static constexpr APINameEntry kCommonAPIs[] = {
    // ====== kernel32.dll — Process, memory, file, module ======
    {"kernel32.dll", "LoadLibraryA"},
    {"kernel32.dll", "LoadLibraryW"},
    {"kernel32.dll", "LoadLibraryExA"},
    {"kernel32.dll", "LoadLibraryExW"},
    {"kernel32.dll", "GetProcAddress"},
    {"kernel32.dll", "FreeLibrary"},
    {"kernel32.dll", "GetModuleHandleA"},
    {"kernel32.dll", "GetModuleHandleW"},
    {"kernel32.dll", "GetModuleHandleExA"},
    {"kernel32.dll", "GetModuleHandleExW"},
    {"kernel32.dll", "GetModuleFileNameA"},
    {"kernel32.dll", "GetModuleFileNameW"},
    {"kernel32.dll", "VirtualAlloc"},
    {"kernel32.dll", "VirtualAllocEx"},
    {"kernel32.dll", "VirtualFree"},
    {"kernel32.dll", "VirtualFreeEx"},
    {"kernel32.dll", "VirtualProtect"},
    {"kernel32.dll", "VirtualProtectEx"},
    {"kernel32.dll", "VirtualQuery"},
    {"kernel32.dll", "VirtualQueryEx"},
    {"kernel32.dll", "ReadProcessMemory"},
    {"kernel32.dll", "WriteProcessMemory"},
    {"kernel32.dll", "CreateProcessA"},
    {"kernel32.dll", "CreateProcessW"},
    {"kernel32.dll", "CreateProcessInternalA"},
    {"kernel32.dll", "CreateProcessInternalW"},
    {"kernel32.dll", "OpenProcess"},
    {"kernel32.dll", "TerminateProcess"},
    {"kernel32.dll", "ExitProcess"},
    {"kernel32.dll", "GetCurrentProcess"},
    {"kernel32.dll", "GetCurrentProcessId"},
    {"kernel32.dll", "GetCurrentThreadId"},
    {"kernel32.dll", "GetCurrentThread"},
    {"kernel32.dll", "CreateThread"},
    {"kernel32.dll", "CreateRemoteThread"},
    {"kernel32.dll", "CreateRemoteThreadEx"},
    {"kernel32.dll", "ResumeThread"},
    {"kernel32.dll", "SuspendThread"},
    {"kernel32.dll", "TerminateThread"},
    {"kernel32.dll", "ExitThread"},
    {"kernel32.dll", "QueueUserAPC"},
    {"kernel32.dll", "GetThreadContext"},
    {"kernel32.dll", "SetThreadContext"},
    {"kernel32.dll", "CreateFileA"},
    {"kernel32.dll", "CreateFileW"},
    {"kernel32.dll", "ReadFile"},
    {"kernel32.dll", "WriteFile"},
    {"kernel32.dll", "DeleteFileA"},
    {"kernel32.dll", "DeleteFileW"},
    {"kernel32.dll", "MoveFileA"},
    {"kernel32.dll", "MoveFileW"},
    {"kernel32.dll", "MoveFileExA"},
    {"kernel32.dll", "MoveFileExW"},
    {"kernel32.dll", "CopyFileA"},
    {"kernel32.dll", "CopyFileW"},
    {"kernel32.dll", "GetFileSize"},
    {"kernel32.dll", "GetFileSizeEx"},
    {"kernel32.dll", "SetFilePointer"},
    {"kernel32.dll", "SetFilePointerEx"},
    {"kernel32.dll", "CreateFileMappingA"},
    {"kernel32.dll", "CreateFileMappingW"},
    {"kernel32.dll", "MapViewOfFile"},
    {"kernel32.dll", "UnmapViewOfFile"},
    {"kernel32.dll", "CloseHandle"},
    {"kernel32.dll", "GetLastError"},
    {"kernel32.dll", "SetLastError"},
    {"kernel32.dll", "Sleep"},
    {"kernel32.dll", "SleepEx"},
    {"kernel32.dll", "WaitForSingleObject"},
    {"kernel32.dll", "WaitForSingleObjectEx"},
    {"kernel32.dll", "WaitForMultipleObjects"},
    {"kernel32.dll", "WaitForMultipleObjectsEx"},
    {"kernel32.dll", "CreateMutexA"},
    {"kernel32.dll", "CreateMutexW"},
    {"kernel32.dll", "OpenMutexA"},
    {"kernel32.dll", "OpenMutexW"},
    {"kernel32.dll", "CreateEventA"},
    {"kernel32.dll", "CreateEventW"},
    {"kernel32.dll", "SetEvent"},
    {"kernel32.dll", "ResetEvent"},
    {"kernel32.dll", "CreatePipe"},
    {"kernel32.dll", "CreateNamedPipeA"},
    {"kernel32.dll", "CreateNamedPipeW"},
    {"kernel32.dll", "ConnectNamedPipe"},
    {"kernel32.dll", "PeekNamedPipe"},
    {"kernel32.dll", "WinExec"},
    {"kernel32.dll", "GetCommandLineA"},
    {"kernel32.dll", "GetCommandLineW"},
    {"kernel32.dll", "GetStartupInfoA"},
    {"kernel32.dll", "GetStartupInfoW"},
    {"kernel32.dll", "GetEnvironmentVariableA"},
    {"kernel32.dll", "GetEnvironmentVariableW"},
    {"kernel32.dll", "SetEnvironmentVariableA"},
    {"kernel32.dll", "SetEnvironmentVariableW"},
    {"kernel32.dll", "ExpandEnvironmentStringsA"},
    {"kernel32.dll", "ExpandEnvironmentStringsW"},
    {"kernel32.dll", "GetTempPathA"},
    {"kernel32.dll", "GetTempPathW"},
    {"kernel32.dll", "GetTempFileNameA"},
    {"kernel32.dll", "GetTempFileNameW"},
    {"kernel32.dll", "GetWindowsDirectoryA"},
    {"kernel32.dll", "GetWindowsDirectoryW"},
    {"kernel32.dll", "GetSystemDirectoryA"},
    {"kernel32.dll", "GetSystemDirectoryW"},
    {"kernel32.dll", "GetSystemInfo"},
    {"kernel32.dll", "GetNativeSystemInfo"},
    {"kernel32.dll", "IsWow64Process"},
    {"kernel32.dll", "GetVersionExA"},
    {"kernel32.dll", "GetVersionExW"},
    {"kernel32.dll", "GetTickCount"},
    {"kernel32.dll", "GetTickCount64"},
    {"kernel32.dll", "QueryPerformanceCounter"},
    {"kernel32.dll", "QueryPerformanceFrequency"},
    {"kernel32.dll", "GetSystemTime"},
    {"kernel32.dll", "GetLocalTime"},
    {"kernel32.dll", "GetSystemTimeAsFileTime"},
    {"kernel32.dll", "FileTimeToSystemTime"},
    {"kernel32.dll", "SystemTimeToFileTime"},
    {"kernel32.dll", "FindFirstFileA"},
    {"kernel32.dll", "FindFirstFileW"},
    {"kernel32.dll", "FindNextFileA"},
    {"kernel32.dll", "FindNextFileW"},
    {"kernel32.dll", "FindClose"},
    {"kernel32.dll", "GetFileAttributesA"},
    {"kernel32.dll", "GetFileAttributesW"},
    {"kernel32.dll", "SetFileAttributesA"},
    {"kernel32.dll", "SetFileAttributesW"},
    {"kernel32.dll", "CreateDirectoryA"},
    {"kernel32.dll", "CreateDirectoryW"},
    {"kernel32.dll", "RemoveDirectoryA"},
    {"kernel32.dll", "RemoveDirectoryW"},
    {"kernel32.dll", "HeapCreate"},
    {"kernel32.dll", "HeapDestroy"},
    {"kernel32.dll", "HeapAlloc"},
    {"kernel32.dll", "HeapFree"},
    {"kernel32.dll", "HeapReAlloc"},
    {"kernel32.dll", "GlobalAlloc"},
    {"kernel32.dll", "GlobalFree"},
    {"kernel32.dll", "GlobalLock"},
    {"kernel32.dll", "GlobalUnlock"},
    {"kernel32.dll", "LocalAlloc"},
    {"kernel32.dll", "LocalFree"},
    {"kernel32.dll", "FlushFileBuffers"},
    {"kernel32.dll", "DeviceIoControl"},
    {"kernel32.dll", "GetComputerNameA"},
    {"kernel32.dll", "GetComputerNameW"},
    {"kernel32.dll", "GetComputerNameExA"},
    {"kernel32.dll", "GetComputerNameExW"},
    {"kernel32.dll", "CreateToolhelp32Snapshot"},
    {"kernel32.dll", "Process32First"},
    {"kernel32.dll", "Process32FirstW"},
    {"kernel32.dll", "Process32Next"},
    {"kernel32.dll", "Process32NextW"},
    {"kernel32.dll", "Thread32First"},
    {"kernel32.dll", "Thread32Next"},
    {"kernel32.dll", "Module32First"},
    {"kernel32.dll", "Module32FirstW"},
    {"kernel32.dll", "Module32Next"},
    {"kernel32.dll", "Module32NextW"},
    {"kernel32.dll", "OutputDebugStringA"},
    {"kernel32.dll", "OutputDebugStringW"},
    {"kernel32.dll", "IsDebuggerPresent"},
    {"kernel32.dll", "CheckRemoteDebuggerPresent"},
    {"kernel32.dll", "DebugBreak"},
    {"kernel32.dll", "GetDiskFreeSpaceExA"},
    {"kernel32.dll", "GetDriveTypeA"},
    {"kernel32.dll", "GetLogicalDrives"},
    {"kernel32.dll", "GetVolumeInformationA"},
    {"kernel32.dll", "GetVolumeInformationW"},
    {"kernel32.dll", "MultiByteToWideChar"},
    {"kernel32.dll", "WideCharToMultiByte"},
    {"kernel32.dll", "lstrlenA"},
    {"kernel32.dll", "lstrlenW"},
    {"kernel32.dll", "lstrcmpA"},
    {"kernel32.dll", "lstrcmpiA"},
    {"kernel32.dll", "lstrcpyA"},
    {"kernel32.dll", "lstrcatA"},
    {"kernel32.dll", "FlushInstructionCache"},
    {"kernel32.dll", "Wow64DisableWow64FsRedirection"},
    {"kernel32.dll", "Wow64RevertWow64FsRedirection"},
    {"kernel32.dll", "SetFileTime"},
    {"kernel32.dll", "GetProcessHeap"},

    // ====== ntdll.dll — Native API (direct syscall wrappers) ======
    {"ntdll.dll", "NtAllocateVirtualMemory"},
    {"ntdll.dll", "NtFreeVirtualMemory"},
    {"ntdll.dll", "NtProtectVirtualMemory"},
    {"ntdll.dll", "NtReadVirtualMemory"},
    {"ntdll.dll", "NtWriteVirtualMemory"},
    {"ntdll.dll", "NtCreateThread"},
    {"ntdll.dll", "NtCreateThreadEx"},
    {"ntdll.dll", "NtCreateProcess"},
    {"ntdll.dll", "NtCreateProcessEx"},
    {"ntdll.dll", "NtCreateSection"},
    {"ntdll.dll", "NtMapViewOfSection"},
    {"ntdll.dll", "NtUnmapViewOfSection"},
    {"ntdll.dll", "NtOpenProcess"},
    {"ntdll.dll", "NtOpenThread"},
    {"ntdll.dll", "NtClose"},
    {"ntdll.dll", "NtQueryInformationProcess"},
    {"ntdll.dll", "NtQueryInformationThread"},
    {"ntdll.dll", "NtSetInformationProcess"},
    {"ntdll.dll", "NtSetInformationThread"},
    {"ntdll.dll", "NtQuerySystemInformation"},
    {"ntdll.dll", "NtQueryVirtualMemory"},
    {"ntdll.dll", "NtCreateFile"},
    {"ntdll.dll", "NtReadFile"},
    {"ntdll.dll", "NtWriteFile"},
    {"ntdll.dll", "NtDeleteFile"},
    {"ntdll.dll", "NtCreateKey"},
    {"ntdll.dll", "NtOpenKey"},
    {"ntdll.dll", "NtSetValueKey"},
    {"ntdll.dll", "NtQueryValueKey"},
    {"ntdll.dll", "NtDeleteKey"},
    {"ntdll.dll", "NtDeleteValueKey"},
    {"ntdll.dll", "NtQueueApcThread"},
    {"ntdll.dll", "NtQueueApcThreadEx"},
    {"ntdll.dll", "NtResumeThread"},
    {"ntdll.dll", "NtSuspendThread"},
    {"ntdll.dll", "NtTerminateProcess"},
    {"ntdll.dll", "NtTerminateThread"},
    {"ntdll.dll", "NtWaitForSingleObject"},
    {"ntdll.dll", "NtWaitForMultipleObjects"},
    {"ntdll.dll", "NtDelayExecution"},
    {"ntdll.dll", "NtGetContextThread"},
    {"ntdll.dll", "NtSetContextThread"},
    {"ntdll.dll", "NtContinue"},
    {"ntdll.dll", "NtDuplicateObject"},
    {"ntdll.dll", "NtCreateMutant"},
    {"ntdll.dll", "NtOpenMutant"},
    {"ntdll.dll", "NtCreateEvent"},
    {"ntdll.dll", "NtDeviceIoControlFile"},
    {"ntdll.dll", "NtQueryObject"},
    {"ntdll.dll", "RtlInitUnicodeString"},
    {"ntdll.dll", "RtlAllocateHeap"},
    {"ntdll.dll", "RtlFreeHeap"},
    {"ntdll.dll", "RtlReAllocateHeap"},
    {"ntdll.dll", "RtlCreateHeap"},
    {"ntdll.dll", "RtlDestroyHeap"},
    {"ntdll.dll", "RtlExitUserThread"},
    {"ntdll.dll", "RtlExitUserProcess"},
    {"ntdll.dll", "RtlGetVersion"},
    {"ntdll.dll", "RtlCopyMemory"},
    {"ntdll.dll", "RtlMoveMemory"},
    {"ntdll.dll", "RtlZeroMemory"},
    {"ntdll.dll", "RtlFillMemory"},
    {"ntdll.dll", "RtlCompareMemory"},
    {"ntdll.dll", "RtlDecompressBuffer"},
    {"ntdll.dll", "RtlCompressBuffer"},
    {"ntdll.dll", "RtlAddVectoredExceptionHandler"},
    {"ntdll.dll", "RtlRemoveVectoredExceptionHandler"},
    {"ntdll.dll", "LdrLoadDll"},
    {"ntdll.dll", "LdrGetProcedureAddress"},
    {"ntdll.dll", "LdrGetDllHandle"},
    {"ntdll.dll", "NtYieldExecution"},
    {"ntdll.dll", "NtQueryPerformanceCounter"},
    {"ntdll.dll", "NtCreateUserProcess"},
    {"ntdll.dll", "NtAdjustPrivilegesToken"},
    {"ntdll.dll", "NtOpenProcessToken"},
    {"ntdll.dll", "NtOpenThreadToken"},

    // ====== user32.dll — Window management, message passing ======
    {"user32.dll", "MessageBoxA"},
    {"user32.dll", "MessageBoxW"},
    {"user32.dll", "FindWindowA"},
    {"user32.dll", "FindWindowW"},
    {"user32.dll", "FindWindowExA"},
    {"user32.dll", "FindWindowExW"},
    {"user32.dll", "GetForegroundWindow"},
    {"user32.dll", "GetDesktopWindow"},
    {"user32.dll", "ShowWindow"},
    {"user32.dll", "SetWindowPos"},
    {"user32.dll", "GetWindowTextA"},
    {"user32.dll", "GetWindowTextW"},
    {"user32.dll", "GetWindowTextLengthA"},
    {"user32.dll", "GetWindowTextLengthW"},
    {"user32.dll", "SendMessageA"},
    {"user32.dll", "SendMessageW"},
    {"user32.dll", "PostMessageA"},
    {"user32.dll", "PostMessageW"},
    {"user32.dll", "EnumWindows"},
    {"user32.dll", "GetKeyState"},
    {"user32.dll", "GetAsyncKeyState"},
    {"user32.dll", "GetKeyboardState"},
    {"user32.dll", "SetWindowsHookExA"},
    {"user32.dll", "SetWindowsHookExW"},
    {"user32.dll", "UnhookWindowsHookEx"},
    {"user32.dll", "CallNextHookEx"},
    {"user32.dll", "keybd_event"},
    {"user32.dll", "mouse_event"},
    {"user32.dll", "GetClipboardData"},
    {"user32.dll", "SetClipboardData"},
    {"user32.dll", "OpenClipboard"},
    {"user32.dll", "CloseClipboard"},
    {"user32.dll", "EmptyClipboard"},
    {"user32.dll", "RegisterClassExA"},
    {"user32.dll", "RegisterClassExW"},
    {"user32.dll", "CreateWindowExA"},
    {"user32.dll", "CreateWindowExW"},
    {"user32.dll", "DestroyWindow"},
    {"user32.dll", "GetWindowThreadProcessId"},
    {"user32.dll", "GetDC"},
    {"user32.dll", "ReleaseDC"},
    {"user32.dll", "GetSystemMetrics"},
    {"user32.dll", "CharUpperA"},
    {"user32.dll", "wsprintfA"},

    // ====== advapi32.dll — Registry, security, service control ======
    {"advapi32.dll", "RegOpenKeyExA"},
    {"advapi32.dll", "RegOpenKeyExW"},
    {"advapi32.dll", "RegCreateKeyExA"},
    {"advapi32.dll", "RegCreateKeyExW"},
    {"advapi32.dll", "RegSetValueExA"},
    {"advapi32.dll", "RegSetValueExW"},
    {"advapi32.dll", "RegQueryValueExA"},
    {"advapi32.dll", "RegQueryValueExW"},
    {"advapi32.dll", "RegDeleteValueA"},
    {"advapi32.dll", "RegDeleteValueW"},
    {"advapi32.dll", "RegDeleteKeyA"},
    {"advapi32.dll", "RegDeleteKeyW"},
    {"advapi32.dll", "RegCloseKey"},
    {"advapi32.dll", "RegEnumKeyExA"},
    {"advapi32.dll", "RegEnumKeyExW"},
    {"advapi32.dll", "RegEnumValueA"},
    {"advapi32.dll", "RegEnumValueW"},
    {"advapi32.dll", "OpenProcessToken"},
    {"advapi32.dll", "OpenThreadToken"},
    {"advapi32.dll", "AdjustTokenPrivileges"},
    {"advapi32.dll", "LookupPrivilegeValueA"},
    {"advapi32.dll", "LookupPrivilegeValueW"},
    {"advapi32.dll", "GetTokenInformation"},
    {"advapi32.dll", "GetUserNameA"},
    {"advapi32.dll", "GetUserNameW"},
    {"advapi32.dll", "LogonUserA"},
    {"advapi32.dll", "LogonUserW"},
    {"advapi32.dll", "ImpersonateLoggedOnUser"},
    {"advapi32.dll", "RevertToSelf"},
    {"advapi32.dll", "CreateServiceA"},
    {"advapi32.dll", "CreateServiceW"},
    {"advapi32.dll", "OpenServiceA"},
    {"advapi32.dll", "OpenServiceW"},
    {"advapi32.dll", "StartServiceA"},
    {"advapi32.dll", "StartServiceW"},
    {"advapi32.dll", "ControlService"},
    {"advapi32.dll", "DeleteService"},
    {"advapi32.dll", "OpenSCManagerA"},
    {"advapi32.dll", "OpenSCManagerW"},
    {"advapi32.dll", "CloseServiceHandle"},
    {"advapi32.dll", "CryptAcquireContextA"},
    {"advapi32.dll", "CryptAcquireContextW"},
    {"advapi32.dll", "CryptReleaseContext"},
    {"advapi32.dll", "CryptGenRandom"},
    {"advapi32.dll", "CryptCreateHash"},
    {"advapi32.dll", "CryptHashData"},
    {"advapi32.dll", "CryptDeriveKey"},
    {"advapi32.dll", "CryptEncrypt"},
    {"advapi32.dll", "CryptDecrypt"},
    {"advapi32.dll", "CryptDestroyHash"},
    {"advapi32.dll", "CryptDestroyKey"},
    {"advapi32.dll", "CryptImportKey"},
    {"advapi32.dll", "CryptExportKey"},
    {"advapi32.dll", "CryptGenKey"},
    {"advapi32.dll", "CryptSetKeyParam"},
    {"advapi32.dll", "CryptGetKeyParam"},

    // ====== ws2_32.dll — Winsock networking ======
    {"ws2_32.dll", "WSAStartup"},
    {"ws2_32.dll", "WSACleanup"},
    {"ws2_32.dll", "WSAGetLastError"},
    {"ws2_32.dll", "WSASocketA"},
    {"ws2_32.dll", "WSASocketW"},
    {"ws2_32.dll", "WSAConnect"},
    {"ws2_32.dll", "WSASend"},
    {"ws2_32.dll", "WSARecv"},
    {"ws2_32.dll", "socket"},
    {"ws2_32.dll", "connect"},
    {"ws2_32.dll", "bind"},
    {"ws2_32.dll", "listen"},
    {"ws2_32.dll", "accept"},
    {"ws2_32.dll", "send"},
    {"ws2_32.dll", "recv"},
    {"ws2_32.dll", "sendto"},
    {"ws2_32.dll", "recvfrom"},
    {"ws2_32.dll", "select"},
    {"ws2_32.dll", "closesocket"},
    {"ws2_32.dll", "shutdown"},
    {"ws2_32.dll", "ioctlsocket"},
    {"ws2_32.dll", "setsockopt"},
    {"ws2_32.dll", "getsockopt"},
    {"ws2_32.dll", "getaddrinfo"},
    {"ws2_32.dll", "freeaddrinfo"},
    {"ws2_32.dll", "gethostbyname"},
    {"ws2_32.dll", "gethostname"},
    {"ws2_32.dll", "inet_addr"},
    {"ws2_32.dll", "inet_ntoa"},
    {"ws2_32.dll", "htons"},
    {"ws2_32.dll", "htonl"},
    {"ws2_32.dll", "ntohs"},
    {"ws2_32.dll", "ntohl"},

    // ====== wininet.dll — High-level internet APIs ======
    {"wininet.dll", "InternetOpenA"},
    {"wininet.dll", "InternetOpenW"},
    {"wininet.dll", "InternetConnectA"},
    {"wininet.dll", "InternetConnectW"},
    {"wininet.dll", "InternetOpenUrlA"},
    {"wininet.dll", "InternetOpenUrlW"},
    {"wininet.dll", "InternetReadFile"},
    {"wininet.dll", "InternetWriteFile"},
    {"wininet.dll", "InternetCloseHandle"},
    {"wininet.dll", "InternetSetOptionA"},
    {"wininet.dll", "InternetQueryOptionA"},
    {"wininet.dll", "HttpOpenRequestA"},
    {"wininet.dll", "HttpOpenRequestW"},
    {"wininet.dll", "HttpSendRequestA"},
    {"wininet.dll", "HttpSendRequestW"},
    {"wininet.dll", "HttpQueryInfoA"},
    {"wininet.dll", "HttpQueryInfoW"},
    {"wininet.dll", "HttpAddRequestHeadersA"},
    {"wininet.dll", "InternetQueryDataAvailable"},
    {"wininet.dll", "FtpOpenFileA"},
    {"wininet.dll", "FtpGetFileA"},
    {"wininet.dll", "FtpPutFileA"},

    // ====== winhttp.dll — WinHTTP APIs ======
    {"winhttp.dll", "WinHttpOpen"},
    {"winhttp.dll", "WinHttpConnect"},
    {"winhttp.dll", "WinHttpOpenRequest"},
    {"winhttp.dll", "WinHttpSendRequest"},
    {"winhttp.dll", "WinHttpReceiveResponse"},
    {"winhttp.dll", "WinHttpQueryDataAvailable"},
    {"winhttp.dll", "WinHttpReadData"},
    {"winhttp.dll", "WinHttpWriteData"},
    {"winhttp.dll", "WinHttpCloseHandle"},
    {"winhttp.dll", "WinHttpSetOption"},
    {"winhttp.dll", "WinHttpQueryOption"},
    {"winhttp.dll", "WinHttpAddRequestHeaders"},
    {"winhttp.dll", "WinHttpSetCredentials"},
    {"winhttp.dll", "WinHttpQueryHeaders"},
    {"winhttp.dll", "WinHttpCrackUrl"},

    // ====== urlmon.dll — URL download ======
    {"urlmon.dll", "URLDownloadToFileA"},
    {"urlmon.dll", "URLDownloadToFileW"},
    {"urlmon.dll", "URLDownloadToCacheFileA"},

    // ====== shell32.dll — Shell operations ======
    {"shell32.dll", "ShellExecuteA"},
    {"shell32.dll", "ShellExecuteW"},
    {"shell32.dll", "ShellExecuteExA"},
    {"shell32.dll", "ShellExecuteExW"},
    {"shell32.dll", "SHGetFolderPathA"},
    {"shell32.dll", "SHGetFolderPathW"},
    {"shell32.dll", "SHGetSpecialFolderPathA"},
    {"shell32.dll", "SHGetSpecialFolderPathW"},

    // ====== ole32.dll — COM ======
    {"ole32.dll", "CoInitialize"},
    {"ole32.dll", "CoInitializeEx"},
    {"ole32.dll", "CoUninitialize"},
    {"ole32.dll", "CoCreateInstance"},
    {"ole32.dll", "CoGetClassObject"},

    // ====== oleaut32.dll — OLE Automation ======
    {"oleaut32.dll", "SysAllocString"},
    {"oleaut32.dll", "SysFreeString"},
    {"oleaut32.dll", "VariantInit"},
    {"oleaut32.dll", "VariantClear"},

    // ====== crypt32.dll — Certificate/crypto APIs ======
    {"crypt32.dll", "CryptStringToBinaryA"},
    {"crypt32.dll", "CryptStringToBinaryW"},
    {"crypt32.dll", "CryptBinaryToStringA"},
    {"crypt32.dll", "CryptBinaryToStringW"},
    {"crypt32.dll", "CertOpenStore"},
    {"crypt32.dll", "CertCloseStore"},
    {"crypt32.dll", "CertFindCertificateInStore"},
    {"crypt32.dll", "CertFreeCertificateContext"},
    {"crypt32.dll", "PFXImportCertStore"},

    // ====== bcrypt.dll — CNG crypto ======
    {"bcrypt.dll", "BCryptOpenAlgorithmProvider"},
    {"bcrypt.dll", "BCryptCloseAlgorithmProvider"},
    {"bcrypt.dll", "BCryptGenerateSymmetricKey"},
    {"bcrypt.dll", "BCryptEncrypt"},
    {"bcrypt.dll", "BCryptDecrypt"},
    {"bcrypt.dll", "BCryptDestroyKey"},
    {"bcrypt.dll", "BCryptGenRandom"},
    {"bcrypt.dll", "BCryptDeriveKeyPBKDF2"},
    {"bcrypt.dll", "BCryptHashData"},
    {"bcrypt.dll", "BCryptCreateHash"},
    {"bcrypt.dll", "BCryptFinishHash"},
    {"bcrypt.dll", "BCryptDestroyHash"},

    // ====== shlwapi.dll — Shell lightweight utility ======
    {"shlwapi.dll", "PathAppendA"},
    {"shlwapi.dll", "PathAppendW"},
    {"shlwapi.dll", "PathCombineA"},
    {"shlwapi.dll", "PathCombineW"},
    {"shlwapi.dll", "PathFindFileNameA"},
    {"shlwapi.dll", "PathFileExistsA"},
    {"shlwapi.dll", "PathFileExistsW"},
    {"shlwapi.dll", "StrStrA"},
    {"shlwapi.dll", "StrStrIA"},
    {"shlwapi.dll", "StrStrW"},

    // ====== gdi32.dll — Graphics (screenshot capture) ======
    {"gdi32.dll", "CreateCompatibleDC"},
    {"gdi32.dll", "CreateCompatibleBitmap"},
    {"gdi32.dll", "SelectObject"},
    {"gdi32.dll", "BitBlt"},
    {"gdi32.dll", "DeleteDC"},
    {"gdi32.dll", "DeleteObject"},
    {"gdi32.dll", "GetDIBits"},

    // ====== psapi.dll — Process status API ======
    {"psapi.dll", "EnumProcesses"},
    {"psapi.dll", "EnumProcessModules"},
    {"psapi.dll", "EnumProcessModulesEx"},
    {"psapi.dll", "GetModuleBaseNameA"},
    {"psapi.dll", "GetModuleBaseNameW"},
    {"psapi.dll", "GetModuleFileNameExA"},
    {"psapi.dll", "GetModuleFileNameExW"},
    {"psapi.dll", "GetProcessMemoryInfo"},

    // ====== dbghelp.dll — Debug help (MiniDumpWriteDump for credential theft) ======
    {"dbghelp.dll", "MiniDumpWriteDump"},

    // ====== secur32.dll / sspicli.dll — SSPI/credential access ======
    {"secur32.dll", "AcquireCredentialsHandleA"},
    {"secur32.dll", "AcquireCredentialsHandleW"},
    {"secur32.dll", "InitializeSecurityContextA"},
    {"secur32.dll", "InitializeSecurityContextW"},

    // ====== iphlpapi.dll — IP helper (network reconnaissance) ======
    {"iphlpapi.dll", "GetAdaptersInfo"},
    {"iphlpapi.dll", "GetAdaptersAddresses"},
    {"iphlpapi.dll", "GetIpForwardTable"},
    {"iphlpapi.dll", "GetTcpTable"},
    {"iphlpapi.dll", "GetUdpTable"},

    // ====== netapi32.dll — Network management (lateral movement) ======
    {"netapi32.dll", "NetUserEnum"},
    {"netapi32.dll", "NetShareEnum"},
    {"netapi32.dll", "NetScheduleJobAdd"},
    {"netapi32.dll", "NetApiBufferFree"},

    // ====== dnsapi.dll — DNS resolution ======
    {"dnsapi.dll", "DnsQuery_A"},
    {"dnsapi.dll", "DnsQuery_W"},
    {"dnsapi.dll", "DnsFree"},

    // ====== wtsapi32.dll — Terminal Services (session enumeration) ======
    {"wtsapi32.dll", "WTSEnumerateSessionsA"},
    {"wtsapi32.dll", "WTSEnumerateSessionsW"},
    {"wtsapi32.dll", "WTSFreeMemory"},

    // ====== cabinet.dll — Cabinet decompression ======
    {"cabinet.dll", "FDICreate"},
    {"cabinet.dll", "FDICopy"},
    {"cabinet.dll", "FDIDestroy"},
};
// clang-format on

static constexpr uint32_t kCommonAPICount =
    static_cast<uint32_t>(sizeof(kCommonAPIs) / sizeof(kCommonAPIs[0]));

// ============================================================================
// HashResolver — Construction / Reset
// ============================================================================

HashResolver::HashResolver() noexcept {
    m_moduleNames.reserve(32);
    m_functionNames.reserve(512);
}

void HashResolver::Reset() noexcept {
    for (auto& table : m_tables) {
        table.clear();
    }
    m_moduleNames.clear();
    m_functionNames.clear();
    m_moduleCount = 0;
}

// ============================================================================
// InsertExport — Hash a (module, function) pair with every algorithm and store
// ============================================================================

void HashResolver::InsertExport(
    uint16_t moduleIdx, uint16_t nameIdx,
    std::string_view moduleName, std::string_view funcName,
    GuestAddress address) noexcept
{
    HashEntry entry{};
    entry.address     = address;
    entry.moduleIndex = moduleIdx;
    entry.nameIndex   = nameIdx;

    // Build a lowercase copy of the module name for case-insensitive algorithms
    // (CRC32Full uses the original casing convention of the module name)
    std::string moduleLower;
    moduleLower.reserve(moduleName.size());
    for (const char c : moduleName) {
        moduleLower += ToLowerASCII(c);
    }

    auto insert = [&](HashAlgorithm algo, uint32_t h) noexcept {
        const auto idx = static_cast<uint32_t>(algo);
        // First-insert wins: if a collision exists, the first registered export
        // is kept. Collisions are rare for real APIs with well-distributed hashes.
        m_tables[idx].try_emplace(h, entry);
    };

    // ROR13 — Metasploit convention: uppercase unicode module + ASCII function
    insert(HashAlgorithm::ROR13, ComputeROR13(moduleName, funcName));

    // CRC32 — function name only
    insert(HashAlgorithm::CRC32, ComputeCRC32(funcName));

    // DJB2 — function name only
    insert(HashAlgorithm::DJB2, ComputeDJB2(funcName));

    // FNV-1a — function name only
    insert(HashAlgorithm::FNV1a, ComputeFNV1a(funcName));

    // SDBM — function name only
    insert(HashAlgorithm::SDBM, ComputeSDBM(funcName));

    // SuperFastHash — function name only
    insert(HashAlgorithm::SuperFast, ComputeSuperFast(funcName));

    // MurmurOAAT — function name only
    insert(HashAlgorithm::MurmurOAAT, ComputeMurmurOAAT(funcName));

    // JenkinsOAAT — function name only
    insert(HashAlgorithm::JenkinsOAAT, ComputeJenkinsOAAT(funcName));

    // ROR13Wide — wide-char module + wide-char function
    insert(HashAlgorithm::ROR13Wide, ComputeROR13Wide(moduleName, funcName));

    // CRC32Full — "module.dll!FunctionName"
    insert(HashAlgorithm::CRC32Full, ComputeCRC32Full(moduleLower, funcName));
}

// ============================================================================
// BuildFromExports — Pre-compute hash tables from ExportResolver
// ============================================================================
//
// Strategy: iterate a comprehensive static list of known Windows API names.
// For each entry, call ExportResolver::ResolveByName() to get the guest
// address. If the module exists and the function resolves, compute all hash
// variants and store them.
//
// This approach avoids requiring enumeration access to ExportResolver's
// private data while covering the ~400 APIs that shellcode actually uses.

void HashResolver::BuildFromExports(const ExportResolver& exports) noexcept {
    Reset();

    // Pre-size hash maps: each algorithm will store up to kCommonAPICount entries
    for (auto& table : m_tables) {
        table.reserve(kCommonAPICount);
    }

    // Track module names to assign indices (dedup via linear scan — small N)
    auto internModule = [this](std::string_view name) -> uint16_t {
        for (uint16_t i = 0; i < static_cast<uint16_t>(m_moduleNames.size()); ++i) {
            if (m_moduleNames[i] == name) return i;
        }
        if (m_moduleNames.size() >= kMaxInternedModules) return 0;
        auto idx = static_cast<uint16_t>(m_moduleNames.size());
        m_moduleNames.emplace_back(name);
        return idx;
    };

    auto internFunction = [this](std::string_view name) -> uint16_t {
        // Function names are more numerous — linear scan is acceptable at build
        // time (this is not a hot path; runs once during session initialization)
        for (uint16_t i = 0; i < static_cast<uint16_t>(m_functionNames.size()); ++i) {
            if (m_functionNames[i] == name) return i;
        }
        if (m_functionNames.size() >= kMaxInternedFunctions) return 0;
        auto idx = static_cast<uint16_t>(m_functionNames.size());
        m_functionNames.emplace_back(name);
        return idx;
    };

    for (uint32_t i = 0; i < kCommonAPICount; ++i) {
        const auto& api = kCommonAPIs[i];
        const std::string_view dll  = api.dll;
        const std::string_view func = api.func;

        // Check if module is loaded in the emulator
        if (!exports.HasModule(dll)) {
            continue;
        }

        // Try to resolve the function to a guest address
        const auto addr = exports.ResolveByName(dll, func);
        if (!addr.has_value()) {
            continue;
        }

        const uint16_t modIdx  = internModule(dll);
        const uint16_t funcIdx = internFunction(func);

        InsertExport(modIdx, funcIdx, dll, func, *addr);
    }

    // Count unique modules
    m_moduleCount = static_cast<uint32_t>(m_moduleNames.size());
}

// ============================================================================
// ResolveByHashExact — Lookup with a specific algorithm
// ============================================================================

std::optional<HashResolution> HashResolver::ResolveByHashExact(
    uint32_t hash, HashAlgorithm algo) const noexcept
{
    if (algo >= HashAlgorithm::Unknown) {
        return std::nullopt;
    }

    const auto idx = static_cast<uint32_t>(algo);
    const auto& table = m_tables[idx];
    const auto it = table.find(hash);
    if (it == table.end()) {
        return std::nullopt;
    }

    const auto& entry = it->second;

    // Validate indices before access
    if (entry.moduleIndex >= m_moduleNames.size() ||
        entry.nameIndex >= m_functionNames.size()) {
        return std::nullopt;
    }

    HashResolution result{};
    result.address      = entry.address;
    result.moduleName   = m_moduleNames[entry.moduleIndex];
    result.functionName = m_functionNames[entry.nameIndex];
    result.algorithm    = algo;
    result.hash         = hash;
    return result;
}

// ============================================================================
// ResolveByHash — Try all algorithms if algo==Unknown, else exact match
// ============================================================================
//
// Algorithm priority order reflects prevalence in real-world malware:
//   ROR13 > CRC32 > DJB2 > FNV-1a > Jenkins > SDBM > others
// If a hash resolves in multiple algorithms (collision), the highest-priority
// algorithm wins. This is correct behaviour: ROR13 is by far the most common.

std::optional<HashResolution> HashResolver::ResolveByHash(
    uint32_t hash, HashAlgorithm algo) const noexcept
{
    if (algo != HashAlgorithm::Unknown) {
        return ResolveByHashExact(hash, algo);
    }

    // Priority order matching real-world prevalence
    static constexpr HashAlgorithm kPriority[] = {
        HashAlgorithm::ROR13,
        HashAlgorithm::CRC32,
        HashAlgorithm::DJB2,
        HashAlgorithm::FNV1a,
        HashAlgorithm::JenkinsOAAT,
        HashAlgorithm::SDBM,
        HashAlgorithm::CRC32Full,
        HashAlgorithm::ROR13Wide,
        HashAlgorithm::MurmurOAAT,
        HashAlgorithm::SuperFast,
    };

    for (const auto a : kPriority) {
        auto result = ResolveByHashExact(hash, a);
        if (result.has_value()) {
            return result;
        }
    }

    return std::nullopt;
}

// ============================================================================
// DetectAlgorithm — Determine which algorithm a set of hashes uses
// ============================================================================
//
// For each candidate algorithm, count how many of the input hashes resolve.
// The algorithm with the highest match count wins, provided it meets the
// minimum threshold. Ties are broken by algorithm priority order.

HashAlgorithm HashResolver::DetectAlgorithm(
    const uint32_t* hashes, uint32_t count,
    uint32_t minMatches) const noexcept
{
    if (hashes == nullptr || count == 0) {
        return HashAlgorithm::Unknown;
    }

    // Cap count to prevent excessive iteration from hostile input
    if (count > kMaxBatchSize) {
        count = kMaxBatchSize;
    }

    struct AlgoScore {
        HashAlgorithm algo;
        uint32_t      matches;
    };

    // Priority order for tie-breaking
    static constexpr HashAlgorithm kOrder[] = {
        HashAlgorithm::ROR13,
        HashAlgorithm::CRC32,
        HashAlgorithm::DJB2,
        HashAlgorithm::FNV1a,
        HashAlgorithm::JenkinsOAAT,
        HashAlgorithm::SDBM,
        HashAlgorithm::CRC32Full,
        HashAlgorithm::ROR13Wide,
        HashAlgorithm::MurmurOAAT,
        HashAlgorithm::SuperFast,
    };

    HashAlgorithm bestAlgo  = HashAlgorithm::Unknown;
    uint32_t      bestScore = 0;

    for (const auto algo : kOrder) {
        const auto idx = static_cast<uint32_t>(algo);
        const auto& table = m_tables[idx];
        if (table.empty()) continue;

        uint32_t matches = 0;
        for (uint32_t i = 0; i < count; ++i) {
            if (table.find(hashes[i]) != table.end()) {
                ++matches;
            }
        }

        if (matches > bestScore) {
            bestScore = matches;
            bestAlgo  = algo;
        }
    }

    if (bestScore < minMatches) {
        return HashAlgorithm::Unknown;
    }

    return bestAlgo;
}

// ============================================================================
// BatchResolve — Resolve multiple hashes at once
// ============================================================================
//
// If algo==Unknown, auto-detect first, then resolve all with the detected
// algorithm. This is more efficient and more accurate than resolving each
// hash individually with the "try all" strategy.

std::vector<HashResolution> HashResolver::BatchResolve(
    const uint32_t* hashes, uint32_t count,
    HashAlgorithm algo) const noexcept
{
    std::vector<HashResolution> results;

    if (hashes == nullptr || count == 0) {
        return results;
    }

    if (count > kMaxBatchSize) {
        count = kMaxBatchSize;
    }

    // Auto-detect algorithm if not specified
    HashAlgorithm resolveAlgo = algo;
    if (resolveAlgo == HashAlgorithm::Unknown) {
        resolveAlgo = DetectAlgorithm(hashes, count, 1);
        if (resolveAlgo == HashAlgorithm::Unknown) {
            // Fall back to per-hash multi-algorithm resolution
            results.reserve(count);
            for (uint32_t i = 0; i < count; ++i) {
                auto r = ResolveByHash(hashes[i], HashAlgorithm::Unknown);
                if (r.has_value()) {
                    results.push_back(std::move(*r));
                }
            }
            return results;
        }
    }

    results.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        auto r = ResolveByHashExact(hashes[i], resolveAlgo);
        if (r.has_value()) {
            results.push_back(std::move(*r));
        }
    }

    return results;
}

// ============================================================================
// Statistics
// ============================================================================

uint32_t HashResolver::GetTotalHashes() const noexcept {
    // Return the count from the most-populated table (ROR13 typically)
    uint32_t maxCount = 0;
    for (const auto& table : m_tables) {
        const auto sz = static_cast<uint32_t>(table.size());
        if (sz > maxCount) {
            maxCount = sz;
        }
    }
    return maxCount;
}

uint32_t HashResolver::GetModuleCount() const noexcept {
    return m_moduleCount;
}

} // namespace Phantom
