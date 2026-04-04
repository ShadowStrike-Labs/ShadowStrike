/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * APIDatabase.hpp — Static database of known Windows APIs and their metadata
 *
 * Provides compile-time tables of known Windows API functions, their parameter
 * counts, categories, and syscall numbers. Used by APIDispatcher for
 * classification and by the analysis engine for behavioral pattern matching.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "APITypes.hpp"
#include <cstdint>
#include <string_view>
#include <array>

namespace Phantom {

// ============================================================================
// Known API Entry — Compile-time metadata for a Windows API
// ============================================================================

struct KnownAPIEntry {
    const char*  dllName;
    const char*  funcName;
    uint8_t      argCount;
    APICategory  category;
    BehaviorFlag suspiciousFlag;   // Flag to raise if this API is called
    uint16_t     syscallNumber;    // NT syscall number (0 = not a syscall)
};

// ============================================================================
// Ntdll Syscall Numbers (Windows 10 22H2 x64)
// ============================================================================
// These are the syscall numbers for the most commonly emulated Nt* functions.
// Malware that uses direct syscalls bypasses kernel32/ntdll wrappers, so we
// need to intercept at the syscall level too.

namespace Syscall {
    static constexpr uint16_t NtAllocateVirtualMemory      = 0x0018;
    static constexpr uint16_t NtProtectVirtualMemory       = 0x0050;
    static constexpr uint16_t NtFreeVirtualMemory          = 0x001E;
    static constexpr uint16_t NtReadVirtualMemory          = 0x003F;
    static constexpr uint16_t NtWriteVirtualMemory         = 0x003A;
    static constexpr uint16_t NtCreateFile                 = 0x0055;
    static constexpr uint16_t NtReadFile                   = 0x0006;
    static constexpr uint16_t NtWriteFile                  = 0x0008;
    static constexpr uint16_t NtClose                      = 0x000F;
    static constexpr uint16_t NtCreateSection              = 0x004A;
    static constexpr uint16_t NtMapViewOfSection           = 0x0028;
    static constexpr uint16_t NtUnmapViewOfSection         = 0x002A;
    static constexpr uint16_t NtOpenProcess                = 0x0026;
    static constexpr uint16_t NtCreateThreadEx             = 0x00C1;
    static constexpr uint16_t NtResumeThread               = 0x0052;
    static constexpr uint16_t NtSuspendThread              = 0x0199;
    static constexpr uint16_t NtTerminateProcess           = 0x002C;
    static constexpr uint16_t NtTerminateThread            = 0x0053;
    static constexpr uint16_t NtQuerySystemInformation     = 0x0036;
    static constexpr uint16_t NtQueryInformationProcess    = 0x0019;
    static constexpr uint16_t NtQueryInformationThread     = 0x0025;
    static constexpr uint16_t NtQueryVirtualMemory         = 0x0023;
    static constexpr uint16_t NtSetInformationThread       = 0x000D;
    static constexpr uint16_t NtOpenKey                    = 0x0012;
    static constexpr uint16_t NtCreateKey                  = 0x001D;
    static constexpr uint16_t NtSetValueKey                = 0x0060;
    static constexpr uint16_t NtQueryValueKey              = 0x0017;
    static constexpr uint16_t NtDeleteKey                  = 0x003E;
    static constexpr uint16_t NtDeleteValueKey             = 0x0041;
    static constexpr uint16_t NtEnumerateKey               = 0x0032;
    static constexpr uint16_t NtEnumerateValueKey          = 0x0013;
    static constexpr uint16_t NtCreateEvent                = 0x0048;
    static constexpr uint16_t NtSetEvent                   = 0x000E;
    static constexpr uint16_t NtWaitForSingleObject        = 0x0004;
    static constexpr uint16_t NtWaitForMultipleObjects     = 0x001B;
    static constexpr uint16_t NtDelayExecution             = 0x0034;
    static constexpr uint16_t NtQueryPerformanceCounter    = 0x0031;
    static constexpr uint16_t NtDuplicateObject            = 0x003C;
    static constexpr uint16_t NtOpenKeyEx                  = 0x010F;
    static constexpr uint16_t NtOpenSection                = 0x0037;
    static constexpr uint16_t NtCreateMutant               = 0x004E;
    static constexpr uint16_t NtOpenMutant                 = 0x0012;
    static constexpr uint16_t NtQueryObject                = 0x0010;
    static constexpr uint16_t NtSetInformationFile         = 0x0027;
    static constexpr uint16_t NtQueryInformationFile       = 0x0011;
    static constexpr uint16_t NtQueryDirectoryFile         = 0x0035;
    static constexpr uint16_t NtDeviceIoControlFile        = 0x0007;
    static constexpr uint16_t NtOpenProcessToken           = 0x012A;
    static constexpr uint16_t NtOpenThreadToken            = 0x0024;
    static constexpr uint16_t NtQueryInformationToken      = 0x0021;
    static constexpr uint16_t NtAdjustPrivilegesToken      = 0x0041;
} // namespace Syscall

// ============================================================================
// Static Known API Table
// ============================================================================
// This table contains ALL APIs we recognize for behavioral analysis, even if
// some don't have full handler implementations yet. The classifier uses this
// to categorize observed API call patterns.

static constexpr KnownAPIEntry kKnownAPIs[] = {
    // === Ntdll: Memory ===
    { "ntdll.dll", "NtAllocateVirtualMemory",   6, APICategory::Memory,   BehaviorFlag::MemoryManipulation, Syscall::NtAllocateVirtualMemory },
    { "ntdll.dll", "NtProtectVirtualMemory",     5, APICategory::Memory,   BehaviorFlag::MemoryManipulation, Syscall::NtProtectVirtualMemory },
    { "ntdll.dll", "NtFreeVirtualMemory",        4, APICategory::Memory,   BehaviorFlag::None,               Syscall::NtFreeVirtualMemory },
    { "ntdll.dll", "NtReadVirtualMemory",        5, APICategory::Memory,   BehaviorFlag::ProcessInjection,   Syscall::NtReadVirtualMemory },
    { "ntdll.dll", "NtWriteVirtualMemory",       5, APICategory::Memory,   BehaviorFlag::CodeInjection,      Syscall::NtWriteVirtualMemory },
    { "ntdll.dll", "NtQueryVirtualMemory",       6, APICategory::Memory,   BehaviorFlag::None,               Syscall::NtQueryVirtualMemory },
    { "ntdll.dll", "NtCreateSection",            7, APICategory::Memory,   BehaviorFlag::MemoryManipulation, Syscall::NtCreateSection },
    { "ntdll.dll", "NtMapViewOfSection",        10, APICategory::Memory,   BehaviorFlag::MemoryManipulation, Syscall::NtMapViewOfSection },
    { "ntdll.dll", "NtUnmapViewOfSection",       2, APICategory::Memory,   BehaviorFlag::None,               Syscall::NtUnmapViewOfSection },

    // === Ntdll: File ===
    { "ntdll.dll", "NtCreateFile",              11, APICategory::FileSystem, BehaviorFlag::None,             Syscall::NtCreateFile },
    { "ntdll.dll", "NtReadFile",                 9, APICategory::FileSystem, BehaviorFlag::None,             Syscall::NtReadFile },
    { "ntdll.dll", "NtWriteFile",                9, APICategory::FileSystem, BehaviorFlag::FileDropped,      Syscall::NtWriteFile },
    { "ntdll.dll", "NtClose",                    1, APICategory::FileSystem, BehaviorFlag::None,             Syscall::NtClose },
    { "ntdll.dll", "NtSetInformationFile",       5, APICategory::FileSystem, BehaviorFlag::None,             Syscall::NtSetInformationFile },
    { "ntdll.dll", "NtQueryInformationFile",     5, APICategory::FileSystem, BehaviorFlag::None,             Syscall::NtQueryInformationFile },
    { "ntdll.dll", "NtQueryDirectoryFile",      11, APICategory::FileSystem, BehaviorFlag::None,             Syscall::NtQueryDirectoryFile },
    { "ntdll.dll", "NtDeviceIoControlFile",     10, APICategory::FileSystem, BehaviorFlag::None,             Syscall::NtDeviceIoControlFile },

    // === Ntdll: Process ===
    { "ntdll.dll", "NtOpenProcess",              4, APICategory::Process,    BehaviorFlag::ProcessInjection,  Syscall::NtOpenProcess },
    { "ntdll.dll", "NtTerminateProcess",         2, APICategory::Process,    BehaviorFlag::None,              Syscall::NtTerminateProcess },
    { "ntdll.dll", "NtQueryInformationProcess",  5, APICategory::Process,    BehaviorFlag::None,              Syscall::NtQueryInformationProcess },

    // === Ntdll: Thread ===
    { "ntdll.dll", "NtCreateThreadEx",          11, APICategory::Thread,     BehaviorFlag::RemoteThreadCreation, Syscall::NtCreateThreadEx },
    { "ntdll.dll", "NtResumeThread",             2, APICategory::Thread,     BehaviorFlag::None,              Syscall::NtResumeThread },
    { "ntdll.dll", "NtSuspendThread",            2, APICategory::Thread,     BehaviorFlag::None,              Syscall::NtSuspendThread },
    { "ntdll.dll", "NtTerminateThread",          2, APICategory::Thread,     BehaviorFlag::None,              Syscall::NtTerminateThread },
    { "ntdll.dll", "NtQueryInformationThread",   5, APICategory::Thread,     BehaviorFlag::None,              Syscall::NtQueryInformationThread },
    { "ntdll.dll", "NtSetInformationThread",     4, APICategory::Thread,     BehaviorFlag::AntiAnalysis,      Syscall::NtSetInformationThread },

    // === Ntdll: Registry ===
    { "ntdll.dll", "NtOpenKey",                  3, APICategory::Registry,   BehaviorFlag::None,              Syscall::NtOpenKey },
    { "ntdll.dll", "NtCreateKey",                7, APICategory::Registry,   BehaviorFlag::RegistryPersistence, Syscall::NtCreateKey },
    { "ntdll.dll", "NtSetValueKey",              6, APICategory::Registry,   BehaviorFlag::RegistryPersistence, Syscall::NtSetValueKey },
    { "ntdll.dll", "NtQueryValueKey",            6, APICategory::Registry,   BehaviorFlag::None,              Syscall::NtQueryValueKey },
    { "ntdll.dll", "NtDeleteKey",                1, APICategory::Registry,   BehaviorFlag::None,              Syscall::NtDeleteKey },
    { "ntdll.dll", "NtDeleteValueKey",           2, APICategory::Registry,   BehaviorFlag::None,              Syscall::NtDeleteValueKey },
    { "ntdll.dll", "NtEnumerateKey",             6, APICategory::Registry,   BehaviorFlag::None,              Syscall::NtEnumerateKey },
    { "ntdll.dll", "NtEnumerateValueKey",        6, APICategory::Registry,   BehaviorFlag::None,              Syscall::NtEnumerateValueKey },

    // === Ntdll: System Info (anti-evasion critical) ===
    { "ntdll.dll", "NtQuerySystemInformation",   4, APICategory::SystemInfo, BehaviorFlag::AntiAnalysis,      Syscall::NtQuerySystemInformation },
    { "ntdll.dll", "NtQueryPerformanceCounter",  2, APICategory::Time,       BehaviorFlag::AntiAnalysis,      Syscall::NtQueryPerformanceCounter },
    { "ntdll.dll", "NtDelayExecution",           2, APICategory::Time,       BehaviorFlag::AntiAnalysis,      Syscall::NtDelayExecution },

    // === Ntdll: Sync ===
    { "ntdll.dll", "NtWaitForSingleObject",      3, APICategory::Synchronization, BehaviorFlag::None,         Syscall::NtWaitForSingleObject },
    { "ntdll.dll", "NtWaitForMultipleObjects",   5, APICategory::Synchronization, BehaviorFlag::None,         Syscall::NtWaitForMultipleObjects },
    { "ntdll.dll", "NtCreateEvent",              5, APICategory::Synchronization, BehaviorFlag::None,         Syscall::NtCreateEvent },
    { "ntdll.dll", "NtCreateMutant",             4, APICategory::Synchronization, BehaviorFlag::None,         Syscall::NtCreateMutant },

    // === Ntdll: Token/Security ===
    { "ntdll.dll", "NtOpenProcessToken",         3, APICategory::Security,   BehaviorFlag::PrivilegeEscalation, Syscall::NtOpenProcessToken },
    { "ntdll.dll", "NtQueryInformationToken",    5, APICategory::Security,   BehaviorFlag::None,              Syscall::NtQueryInformationToken },
    { "ntdll.dll", "NtAdjustPrivilegesToken",    6, APICategory::Security,   BehaviorFlag::PrivilegeEscalation, Syscall::NtAdjustPrivilegesToken },

    // === Ntdll: Object ===
    { "ntdll.dll", "NtDuplicateObject",          7, APICategory::Process,    BehaviorFlag::None,              Syscall::NtDuplicateObject },
    { "ntdll.dll", "NtQueryObject",              5, APICategory::SystemInfo, BehaviorFlag::None,              Syscall::NtQueryObject },

    // === Ntdll: RTL (non-syscall helpers) ===
    { "ntdll.dll", "RtlAllocateHeap",            3, APICategory::Memory,     BehaviorFlag::None,              0 },
    { "ntdll.dll", "RtlFreeHeap",                3, APICategory::Memory,     BehaviorFlag::None,              0 },
    { "ntdll.dll", "RtlReAllocateHeap",          4, APICategory::Memory,     BehaviorFlag::None,              0 },
    { "ntdll.dll", "RtlSizeHeap",                3, APICategory::Memory,     BehaviorFlag::None,              0 },
    { "ntdll.dll", "RtlCreateHeap",              6, APICategory::Memory,     BehaviorFlag::None,              0 },
    { "ntdll.dll", "RtlDestroyHeap",             1, APICategory::Memory,     BehaviorFlag::None,              0 },
    { "ntdll.dll", "RtlInitUnicodeString",       2, APICategory::Unknown,    BehaviorFlag::None,              0 },
    { "ntdll.dll", "RtlInitAnsiString",          2, APICategory::Unknown,    BehaviorFlag::None,              0 },
    { "ntdll.dll", "RtlUnicodeStringToAnsiString", 3, APICategory::Unknown,  BehaviorFlag::None,              0 },
    { "ntdll.dll", "RtlAnsiStringToUnicodeString", 3, APICategory::Unknown,  BehaviorFlag::None,              0 },
    { "ntdll.dll", "RtlFreeUnicodeString",       1, APICategory::Unknown,    BehaviorFlag::None,              0 },
    { "ntdll.dll", "RtlFreeAnsiString",          1, APICategory::Unknown,    BehaviorFlag::None,              0 },
    { "ntdll.dll", "RtlCopyMemory",              3, APICategory::Memory,     BehaviorFlag::None,              0 },
    { "ntdll.dll", "RtlMoveMemory",              3, APICategory::Memory,     BehaviorFlag::None,              0 },
    { "ntdll.dll", "RtlZeroMemory",              2, APICategory::Memory,     BehaviorFlag::None,              0 },
    { "ntdll.dll", "RtlFillMemory",              3, APICategory::Memory,     BehaviorFlag::None,              0 },
    { "ntdll.dll", "RtlCompareMemory",           3, APICategory::Memory,     BehaviorFlag::None,              0 },
    { "ntdll.dll", "RtlDecompressBuffer",        6, APICategory::Memory,     BehaviorFlag::DefenseEvasion,    0 },
    { "ntdll.dll", "RtlGetVersion",              1, APICategory::SystemInfo, BehaviorFlag::AntiAnalysis,      0 },
    { "ntdll.dll", "RtlGetNtVersionNumbers",     3, APICategory::SystemInfo, BehaviorFlag::AntiAnalysis,      0 },

    // === Ntdll: Loader ===
    { "ntdll.dll", "LdrLoadDll",                 4, APICategory::ModuleLoading, BehaviorFlag::DLLInjection,   0 },
    { "ntdll.dll", "LdrGetProcedureAddress",     4, APICategory::ModuleLoading, BehaviorFlag::None,           0 },
    { "ntdll.dll", "LdrGetDllHandle",            4, APICategory::ModuleLoading, BehaviorFlag::None,           0 },
    { "ntdll.dll", "LdrUnloadDll",               1, APICategory::ModuleLoading, BehaviorFlag::None,           0 },

    // === Kernel32: File ===
    { "kernel32.dll", "CreateFileA",             7, APICategory::FileSystem, BehaviorFlag::None,              0 },
    { "kernel32.dll", "CreateFileW",             7, APICategory::FileSystem, BehaviorFlag::None,              0 },
    { "kernel32.dll", "ReadFile",                5, APICategory::FileSystem, BehaviorFlag::None,              0 },
    { "kernel32.dll", "WriteFile",               5, APICategory::FileSystem, BehaviorFlag::FileDropped,       0 },
    { "kernel32.dll", "CloseHandle",             1, APICategory::FileSystem, BehaviorFlag::None,              0 },
    { "kernel32.dll", "DeleteFileA",             1, APICategory::FileSystem, BehaviorFlag::DefenseEvasion,    0 },
    { "kernel32.dll", "DeleteFileW",             1, APICategory::FileSystem, BehaviorFlag::DefenseEvasion,    0 },
    { "kernel32.dll", "MoveFileA",               2, APICategory::FileSystem, BehaviorFlag::None,              0 },
    { "kernel32.dll", "MoveFileW",               2, APICategory::FileSystem, BehaviorFlag::None,              0 },
    { "kernel32.dll", "CopyFileA",               3, APICategory::FileSystem, BehaviorFlag::FileDropped,       0 },
    { "kernel32.dll", "CopyFileW",               3, APICategory::FileSystem, BehaviorFlag::FileDropped,       0 },
    { "kernel32.dll", "GetFileSize",             2, APICategory::FileSystem, BehaviorFlag::None,              0 },
    { "kernel32.dll", "GetFileSizeEx",           2, APICategory::FileSystem, BehaviorFlag::None,              0 },
    { "kernel32.dll", "SetFilePointer",          4, APICategory::FileSystem, BehaviorFlag::None,              0 },
    { "kernel32.dll", "SetFilePointerEx",        4, APICategory::FileSystem, BehaviorFlag::None,              0 },
    { "kernel32.dll", "GetFileAttributesA",      1, APICategory::FileSystem, BehaviorFlag::None,              0 },
    { "kernel32.dll", "GetFileAttributesW",      1, APICategory::FileSystem, BehaviorFlag::None,              0 },
    { "kernel32.dll", "FindFirstFileA",          2, APICategory::FileSystem, BehaviorFlag::None,              0 },
    { "kernel32.dll", "FindFirstFileW",          2, APICategory::FileSystem, BehaviorFlag::None,              0 },
    { "kernel32.dll", "FindNextFileA",           2, APICategory::FileSystem, BehaviorFlag::None,              0 },
    { "kernel32.dll", "FindNextFileW",           2, APICategory::FileSystem, BehaviorFlag::None,              0 },
    { "kernel32.dll", "FindClose",               1, APICategory::FileSystem, BehaviorFlag::None,              0 },
    { "kernel32.dll", "GetTempPathA",            2, APICategory::FileSystem, BehaviorFlag::None,              0 },
    { "kernel32.dll", "GetTempPathW",            2, APICategory::FileSystem, BehaviorFlag::None,              0 },

    // === Kernel32: Process ===
    { "kernel32.dll", "CreateProcessA",         10, APICategory::Process,    BehaviorFlag::ProcessInjection,  0 },
    { "kernel32.dll", "CreateProcessW",         10, APICategory::Process,    BehaviorFlag::ProcessInjection,  0 },
    { "kernel32.dll", "OpenProcess",             3, APICategory::Process,    BehaviorFlag::ProcessInjection,  0 },
    { "kernel32.dll", "TerminateProcess",        2, APICategory::Process,    BehaviorFlag::None,              0 },
    { "kernel32.dll", "ExitProcess",             1, APICategory::Process,    BehaviorFlag::None,              0 },
    { "kernel32.dll", "GetCurrentProcessId",     0, APICategory::Process,    BehaviorFlag::None,              0 },
    { "kernel32.dll", "GetCurrentProcess",       0, APICategory::Process,    BehaviorFlag::None,              0 },
    { "kernel32.dll", "GetExitCodeProcess",      2, APICategory::Process,    BehaviorFlag::None,              0 },
    { "kernel32.dll", "IsWow64Process",          2, APICategory::Process,    BehaviorFlag::AntiAnalysis,      0 },
    { "kernel32.dll", "GetProcessHeap",          0, APICategory::Memory,     BehaviorFlag::None,              0 },

    // === Kernel32: Memory ===
    { "kernel32.dll", "VirtualAlloc",            4, APICategory::Memory,     BehaviorFlag::MemoryManipulation, 0 },
    { "kernel32.dll", "VirtualAllocEx",          5, APICategory::Memory,     BehaviorFlag::CodeInjection,     0 },
    { "kernel32.dll", "VirtualFree",             3, APICategory::Memory,     BehaviorFlag::None,              0 },
    { "kernel32.dll", "VirtualFreeEx",           4, APICategory::Memory,     BehaviorFlag::None,              0 },
    { "kernel32.dll", "VirtualProtect",          4, APICategory::Memory,     BehaviorFlag::MemoryManipulation, 0 },
    { "kernel32.dll", "VirtualProtectEx",        5, APICategory::Memory,     BehaviorFlag::CodeInjection,     0 },
    { "kernel32.dll", "VirtualQuery",            3, APICategory::Memory,     BehaviorFlag::None,              0 },
    { "kernel32.dll", "VirtualQueryEx",          4, APICategory::Memory,     BehaviorFlag::None,              0 },
    { "kernel32.dll", "ReadProcessMemory",       5, APICategory::Memory,     BehaviorFlag::ProcessInjection,  0 },
    { "kernel32.dll", "WriteProcessMemory",      5, APICategory::Memory,     BehaviorFlag::CodeInjection,     0 },
    { "kernel32.dll", "HeapCreate",              3, APICategory::Memory,     BehaviorFlag::None,              0 },
    { "kernel32.dll", "HeapDestroy",             1, APICategory::Memory,     BehaviorFlag::None,              0 },
    { "kernel32.dll", "HeapAlloc",               3, APICategory::Memory,     BehaviorFlag::None,              0 },
    { "kernel32.dll", "HeapFree",                3, APICategory::Memory,     BehaviorFlag::None,              0 },
    { "kernel32.dll", "HeapReAlloc",             4, APICategory::Memory,     BehaviorFlag::None,              0 },
    { "kernel32.dll", "HeapSize",                3, APICategory::Memory,     BehaviorFlag::None,              0 },
    { "kernel32.dll", "GlobalAlloc",             2, APICategory::Memory,     BehaviorFlag::None,              0 },
    { "kernel32.dll", "GlobalFree",              1, APICategory::Memory,     BehaviorFlag::None,              0 },
    { "kernel32.dll", "LocalAlloc",              2, APICategory::Memory,     BehaviorFlag::None,              0 },
    { "kernel32.dll", "LocalFree",               1, APICategory::Memory,     BehaviorFlag::None,              0 },

    // === Kernel32: Module/Library ===
    { "kernel32.dll", "LoadLibraryA",            1, APICategory::ModuleLoading, BehaviorFlag::DLLInjection,   0 },
    { "kernel32.dll", "LoadLibraryW",            1, APICategory::ModuleLoading, BehaviorFlag::DLLInjection,   0 },
    { "kernel32.dll", "LoadLibraryExA",          3, APICategory::ModuleLoading, BehaviorFlag::DLLInjection,   0 },
    { "kernel32.dll", "LoadLibraryExW",          3, APICategory::ModuleLoading, BehaviorFlag::DLLInjection,   0 },
    { "kernel32.dll", "FreeLibrary",             1, APICategory::ModuleLoading, BehaviorFlag::None,           0 },
    { "kernel32.dll", "GetProcAddress",          2, APICategory::ModuleLoading, BehaviorFlag::None,           0 },
    { "kernel32.dll", "GetModuleHandleA",        1, APICategory::ModuleLoading, BehaviorFlag::None,           0 },
    { "kernel32.dll", "GetModuleHandleW",        1, APICategory::ModuleLoading, BehaviorFlag::None,           0 },
    { "kernel32.dll", "GetModuleFileNameA",      3, APICategory::ModuleLoading, BehaviorFlag::None,           0 },
    { "kernel32.dll", "GetModuleFileNameW",      3, APICategory::ModuleLoading, BehaviorFlag::None,           0 },

    // === Kernel32: Thread ===
    { "kernel32.dll", "CreateThread",            6, APICategory::Thread,     BehaviorFlag::None,              0 },
    { "kernel32.dll", "CreateRemoteThread",      7, APICategory::Thread,     BehaviorFlag::RemoteThreadCreation, 0 },
    { "kernel32.dll", "CreateRemoteThreadEx",    8, APICategory::Thread,     BehaviorFlag::RemoteThreadCreation, 0 },
    { "kernel32.dll", "ResumeThread",            1, APICategory::Thread,     BehaviorFlag::None,              0 },
    { "kernel32.dll", "SuspendThread",           1, APICategory::Thread,     BehaviorFlag::None,              0 },
    { "kernel32.dll", "TerminateThread",         2, APICategory::Thread,     BehaviorFlag::None,              0 },
    { "kernel32.dll", "ExitThread",              1, APICategory::Thread,     BehaviorFlag::None,              0 },
    { "kernel32.dll", "GetCurrentThreadId",      0, APICategory::Thread,     BehaviorFlag::None,              0 },
    { "kernel32.dll", "GetCurrentThread",        0, APICategory::Thread,     BehaviorFlag::None,              0 },
    { "kernel32.dll", "SetThreadContext",        2, APICategory::Thread,     BehaviorFlag::CodeInjection,     0 },
    { "kernel32.dll", "GetThreadContext",        2, APICategory::Thread,     BehaviorFlag::ProcessInjection,  0 },

    // === Kernel32: Synchronization ===
    { "kernel32.dll", "WaitForSingleObject",     2, APICategory::Synchronization, BehaviorFlag::None,         0 },
    { "kernel32.dll", "WaitForMultipleObjects",  4, APICategory::Synchronization, BehaviorFlag::None,         0 },
    { "kernel32.dll", "CreateMutexA",            3, APICategory::Synchronization, BehaviorFlag::None,         0 },
    { "kernel32.dll", "CreateMutexW",            3, APICategory::Synchronization, BehaviorFlag::None,         0 },
    { "kernel32.dll", "CreateEventA",            4, APICategory::Synchronization, BehaviorFlag::None,         0 },
    { "kernel32.dll", "CreateEventW",            4, APICategory::Synchronization, BehaviorFlag::None,         0 },
    { "kernel32.dll", "SetEvent",                1, APICategory::Synchronization, BehaviorFlag::None,         0 },
    { "kernel32.dll", "ResetEvent",              1, APICategory::Synchronization, BehaviorFlag::None,         0 },
    { "kernel32.dll", "Sleep",                   1, APICategory::Time,       BehaviorFlag::AntiAnalysis,      0 },
    { "kernel32.dll", "SleepEx",                 2, APICategory::Time,       BehaviorFlag::AntiAnalysis,      0 },

    // === Kernel32: Time ===
    { "kernel32.dll", "GetTickCount",            0, APICategory::Time,       BehaviorFlag::AntiAnalysis,      0 },
    { "kernel32.dll", "GetTickCount64",          0, APICategory::Time,       BehaviorFlag::AntiAnalysis,      0 },
    { "kernel32.dll", "QueryPerformanceCounter", 1, APICategory::Time,       BehaviorFlag::AntiAnalysis,      0 },
    { "kernel32.dll", "QueryPerformanceFrequency",1, APICategory::Time,      BehaviorFlag::None,              0 },
    { "kernel32.dll", "GetSystemTime",           1, APICategory::Time,       BehaviorFlag::None,              0 },
    { "kernel32.dll", "GetLocalTime",            1, APICategory::Time,       BehaviorFlag::None,              0 },
    { "kernel32.dll", "GetSystemTimeAsFileTime", 1, APICategory::Time,       BehaviorFlag::None,              0 },

    // === Kernel32: Environment / System Info ===
    { "kernel32.dll", "GetComputerNameA",        2, APICategory::Environment, BehaviorFlag::AntiAnalysis,     0 },
    { "kernel32.dll", "GetComputerNameW",        2, APICategory::Environment, BehaviorFlag::AntiAnalysis,     0 },
    { "kernel32.dll", "GetUserNameA",            2, APICategory::Environment, BehaviorFlag::None,             0 },
    { "kernel32.dll", "GetUserNameW",            2, APICategory::Environment, BehaviorFlag::None,             0 },
    { "kernel32.dll", "GetSystemDirectoryA",     2, APICategory::Environment, BehaviorFlag::None,             0 },
    { "kernel32.dll", "GetSystemDirectoryW",     2, APICategory::Environment, BehaviorFlag::None,             0 },
    { "kernel32.dll", "GetWindowsDirectoryA",    2, APICategory::Environment, BehaviorFlag::None,             0 },
    { "kernel32.dll", "GetWindowsDirectoryW",    2, APICategory::Environment, BehaviorFlag::None,             0 },
    { "kernel32.dll", "GetEnvironmentVariableA", 3, APICategory::Environment, BehaviorFlag::None,             0 },
    { "kernel32.dll", "GetEnvironmentVariableW", 3, APICategory::Environment, BehaviorFlag::None,             0 },
    { "kernel32.dll", "GetVersionExA",           1, APICategory::SystemInfo,  BehaviorFlag::AntiAnalysis,     0 },
    { "kernel32.dll", "GetVersionExW",           1, APICategory::SystemInfo,  BehaviorFlag::AntiAnalysis,     0 },
    { "kernel32.dll", "GetVersion",              0, APICategory::SystemInfo,  BehaviorFlag::AntiAnalysis,     0 },
    { "kernel32.dll", "GetSystemInfo",           1, APICategory::SystemInfo,  BehaviorFlag::AntiAnalysis,     0 },
    { "kernel32.dll", "GetNativeSystemInfo",     1, APICategory::SystemInfo,  BehaviorFlag::AntiAnalysis,     0 },
    { "kernel32.dll", "IsProcessorFeaturePresent",1, APICategory::SystemInfo, BehaviorFlag::None,             0 },
    { "kernel32.dll", "GetDiskFreeSpaceExA",     4, APICategory::SystemInfo,  BehaviorFlag::AntiAnalysis,     0 },

    // === Kernel32: Error / Console / String ===
    { "kernel32.dll", "SetLastError",            1, APICategory::Unknown,    BehaviorFlag::None,              0 },
    { "kernel32.dll", "GetLastError",            0, APICategory::Unknown,    BehaviorFlag::None,              0 },
    { "kernel32.dll", "OutputDebugStringA",      1, APICategory::Console,    BehaviorFlag::None,              0 },
    { "kernel32.dll", "OutputDebugStringW",      1, APICategory::Console,    BehaviorFlag::None,              0 },
    { "kernel32.dll", "IsDebuggerPresent",       0, APICategory::AntiDebug,  BehaviorFlag::AntiAnalysis,      0 },
    { "kernel32.dll", "CheckRemoteDebuggerPresent",2, APICategory::AntiDebug,BehaviorFlag::AntiAnalysis,      0 },
    { "kernel32.dll", "lstrlenA",                1, APICategory::Unknown,    BehaviorFlag::None,              0 },
    { "kernel32.dll", "lstrlenW",                1, APICategory::Unknown,    BehaviorFlag::None,              0 },
    { "kernel32.dll", "lstrcmpA",                2, APICategory::Unknown,    BehaviorFlag::None,              0 },
    { "kernel32.dll", "lstrcmpW",                2, APICategory::Unknown,    BehaviorFlag::None,              0 },
    { "kernel32.dll", "lstrcpyA",                2, APICategory::Unknown,    BehaviorFlag::None,              0 },
    { "kernel32.dll", "lstrcpyW",                2, APICategory::Unknown,    BehaviorFlag::None,              0 },
    { "kernel32.dll", "MultiByteToWideChar",     6, APICategory::Unknown,    BehaviorFlag::None,              0 },
    { "kernel32.dll", "WideCharToMultiByte",     8, APICategory::Unknown,    BehaviorFlag::None,              0 },

    // === Advapi32: Registry ===
    { "advapi32.dll", "RegOpenKeyExA",           5, APICategory::Registry,   BehaviorFlag::None,              0 },
    { "advapi32.dll", "RegOpenKeyExW",           5, APICategory::Registry,   BehaviorFlag::None,              0 },
    { "advapi32.dll", "RegCreateKeyExA",         9, APICategory::Registry,   BehaviorFlag::RegistryPersistence, 0 },
    { "advapi32.dll", "RegCreateKeyExW",         9, APICategory::Registry,   BehaviorFlag::RegistryPersistence, 0 },
    { "advapi32.dll", "RegSetValueExA",          6, APICategory::Registry,   BehaviorFlag::RegistryPersistence, 0 },
    { "advapi32.dll", "RegSetValueExW",          6, APICategory::Registry,   BehaviorFlag::RegistryPersistence, 0 },
    { "advapi32.dll", "RegQueryValueExA",        6, APICategory::Registry,   BehaviorFlag::None,              0 },
    { "advapi32.dll", "RegQueryValueExW",        6, APICategory::Registry,   BehaviorFlag::None,              0 },
    { "advapi32.dll", "RegDeleteKeyA",           2, APICategory::Registry,   BehaviorFlag::None,              0 },
    { "advapi32.dll", "RegDeleteKeyW",           2, APICategory::Registry,   BehaviorFlag::None,              0 },
    { "advapi32.dll", "RegDeleteValueA",         2, APICategory::Registry,   BehaviorFlag::None,              0 },
    { "advapi32.dll", "RegDeleteValueW",         2, APICategory::Registry,   BehaviorFlag::None,              0 },
    { "advapi32.dll", "RegCloseKey",             1, APICategory::Registry,   BehaviorFlag::None,              0 },
    { "advapi32.dll", "RegEnumKeyExA",           8, APICategory::Registry,   BehaviorFlag::None,              0 },
    { "advapi32.dll", "RegEnumKeyExW",           8, APICategory::Registry,   BehaviorFlag::None,              0 },
    { "advapi32.dll", "RegEnumValueA",           8, APICategory::Registry,   BehaviorFlag::None,              0 },
    { "advapi32.dll", "RegEnumValueW",           8, APICategory::Registry,   BehaviorFlag::None,              0 },

    // === Advapi32: Security ===
    { "advapi32.dll", "OpenProcessToken",        3, APICategory::Security,   BehaviorFlag::PrivilegeEscalation, 0 },
    { "advapi32.dll", "AdjustTokenPrivileges",   6, APICategory::Security,   BehaviorFlag::PrivilegeEscalation, 0 },
    { "advapi32.dll", "LookupPrivilegeValueA",   3, APICategory::Security,   BehaviorFlag::PrivilegeEscalation, 0 },
    { "advapi32.dll", "LookupPrivilegeValueW",   3, APICategory::Security,   BehaviorFlag::PrivilegeEscalation, 0 },
    { "advapi32.dll", "GetTokenInformation",     5, APICategory::Security,   BehaviorFlag::None,              0 },
    { "advapi32.dll", "ImpersonateLoggedOnUser", 1, APICategory::Security,   BehaviorFlag::PrivilegeEscalation, 0 },
    { "advapi32.dll", "RevertToSelf",            0, APICategory::Security,   BehaviorFlag::None,              0 },

    // === Advapi32: Service ===
    { "advapi32.dll", "OpenSCManagerA",          3, APICategory::Service,    BehaviorFlag::ServiceManipulation, 0 },
    { "advapi32.dll", "OpenSCManagerW",          3, APICategory::Service,    BehaviorFlag::ServiceManipulation, 0 },
    { "advapi32.dll", "CreateServiceA",         13, APICategory::Service,    BehaviorFlag::ServiceManipulation, 0 },
    { "advapi32.dll", "CreateServiceW",         13, APICategory::Service,    BehaviorFlag::ServiceManipulation, 0 },
    { "advapi32.dll", "StartServiceA",           3, APICategory::Service,    BehaviorFlag::ServiceManipulation, 0 },
    { "advapi32.dll", "StartServiceW",           3, APICategory::Service,    BehaviorFlag::ServiceManipulation, 0 },
    { "advapi32.dll", "OpenServiceA",            3, APICategory::Service,    BehaviorFlag::ServiceManipulation, 0 },
    { "advapi32.dll", "OpenServiceW",            3, APICategory::Service,    BehaviorFlag::ServiceManipulation, 0 },
    { "advapi32.dll", "DeleteService",           1, APICategory::Service,    BehaviorFlag::ServiceManipulation, 0 },
    { "advapi32.dll", "CloseServiceHandle",      1, APICategory::Service,    BehaviorFlag::None,              0 },

    // === Advapi32: Crypto ===
    { "advapi32.dll", "CryptAcquireContextA",    5, APICategory::Crypto,     BehaviorFlag::None,              0 },
    { "advapi32.dll", "CryptAcquireContextW",    5, APICategory::Crypto,     BehaviorFlag::None,              0 },
    { "advapi32.dll", "CryptGenRandom",          3, APICategory::Crypto,     BehaviorFlag::None,              0 },
    { "advapi32.dll", "CryptEncrypt",            7, APICategory::Crypto,     BehaviorFlag::None,              0 },
    { "advapi32.dll", "CryptDecrypt",            6, APICategory::Crypto,     BehaviorFlag::None,              0 },
    { "advapi32.dll", "CryptCreateHash",         5, APICategory::Crypto,     BehaviorFlag::None,              0 },
    { "advapi32.dll", "CryptHashData",           4, APICategory::Crypto,     BehaviorFlag::None,              0 },
    { "advapi32.dll", "CryptReleaseContext",     2, APICategory::Crypto,     BehaviorFlag::None,              0 },

    // === Ws2_32: Network ===
    { "ws2_32.dll", "WSAStartup",               2, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },
    { "ws2_32.dll", "WSACleanup",               0, APICategory::Network,    BehaviorFlag::None,              0 },
    { "ws2_32.dll", "socket",                    3, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },
    { "ws2_32.dll", "connect",                   3, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },
    { "ws2_32.dll", "send",                      4, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },
    { "ws2_32.dll", "recv",                      4, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },
    { "ws2_32.dll", "bind",                      3, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },
    { "ws2_32.dll", "listen",                    2, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },
    { "ws2_32.dll", "accept",                    3, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },
    { "ws2_32.dll", "closesocket",               1, APICategory::Network,    BehaviorFlag::None,              0 },
    { "ws2_32.dll", "getaddrinfo",               4, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },
    { "ws2_32.dll", "freeaddrinfo",              1, APICategory::Network,    BehaviorFlag::None,              0 },
    { "ws2_32.dll", "gethostbyname",             1, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },
    { "ws2_32.dll", "inet_addr",                 1, APICategory::Network,    BehaviorFlag::None,              0 },
    { "ws2_32.dll", "htons",                     1, APICategory::Network,    BehaviorFlag::None,              0 },
    { "ws2_32.dll", "ntohs",                     1, APICategory::Network,    BehaviorFlag::None,              0 },
    { "ws2_32.dll", "WSAGetLastError",           0, APICategory::Network,    BehaviorFlag::None,              0 },
    { "ws2_32.dll", "select",                    5, APICategory::Network,    BehaviorFlag::None,              0 },
    { "ws2_32.dll", "ioctlsocket",               3, APICategory::Network,    BehaviorFlag::None,              0 },
    { "ws2_32.dll", "setsockopt",                5, APICategory::Network,    BehaviorFlag::None,              0 },

    // === Wininet ===
    { "wininet.dll", "InternetOpenA",            5, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },
    { "wininet.dll", "InternetOpenW",            5, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },
    { "wininet.dll", "InternetConnectA",         8, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },
    { "wininet.dll", "InternetConnectW",         8, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },
    { "wininet.dll", "HttpOpenRequestA",         8, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },
    { "wininet.dll", "HttpOpenRequestW",         8, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },
    { "wininet.dll", "HttpSendRequestA",         5, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },
    { "wininet.dll", "HttpSendRequestW",         5, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },
    { "wininet.dll", "InternetReadFile",         4, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },
    { "wininet.dll", "InternetCloseHandle",      1, APICategory::Network,    BehaviorFlag::None,              0 },
    { "wininet.dll", "InternetOpenUrlA",         6, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },
    { "wininet.dll", "InternetOpenUrlW",         6, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },

    // === Winhttp ===
    { "winhttp.dll", "WinHttpOpen",              5, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },
    { "winhttp.dll", "WinHttpConnect",           4, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },
    { "winhttp.dll", "WinHttpOpenRequest",       7, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },
    { "winhttp.dll", "WinHttpSendRequest",       7, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },
    { "winhttp.dll", "WinHttpReceiveResponse",   2, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },
    { "winhttp.dll", "WinHttpReadData",          4, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },
    { "winhttp.dll", "WinHttpCloseHandle",       1, APICategory::Network,    BehaviorFlag::None,              0 },

    // === User32 ===
    { "user32.dll", "MessageBoxA",               4, APICategory::Console,    BehaviorFlag::None,              0 },
    { "user32.dll", "MessageBoxW",               4, APICategory::Console,    BehaviorFlag::None,              0 },
    { "user32.dll", "FindWindowA",               2, APICategory::AntiDebug,  BehaviorFlag::AntiAnalysis,      0 },
    { "user32.dll", "FindWindowW",               2, APICategory::AntiDebug,  BehaviorFlag::AntiAnalysis,      0 },
    { "user32.dll", "GetForegroundWindow",       0, APICategory::Unknown,    BehaviorFlag::None,              0 },
    { "user32.dll", "GetDesktopWindow",          0, APICategory::Unknown,    BehaviorFlag::None,              0 },
    { "user32.dll", "EnumWindows",               2, APICategory::Unknown,    BehaviorFlag::None,              0 },
    { "user32.dll", "GetWindowTextA",            3, APICategory::Unknown,    BehaviorFlag::None,              0 },
    { "user32.dll", "GetWindowTextW",            3, APICategory::Unknown,    BehaviorFlag::None,              0 },
    { "user32.dll", "SetWindowsHookExA",         4, APICategory::Unknown,    BehaviorFlag::Keylogging,        0 },
    { "user32.dll", "SetWindowsHookExW",         4, APICategory::Unknown,    BehaviorFlag::Keylogging,        0 },

    // === Shell32 ===
    { "shell32.dll", "ShellExecuteA",            6, APICategory::Process,    BehaviorFlag::ProcessInjection,  0 },
    { "shell32.dll", "ShellExecuteW",            6, APICategory::Process,    BehaviorFlag::ProcessInjection,  0 },
    { "shell32.dll", "ShellExecuteExA",          1, APICategory::Process,    BehaviorFlag::ProcessInjection,  0 },
    { "shell32.dll", "ShellExecuteExW",          1, APICategory::Process,    BehaviorFlag::ProcessInjection,  0 },
    { "shell32.dll", "SHGetFolderPathA",         5, APICategory::FileSystem, BehaviorFlag::None,              0 },
    { "shell32.dll", "SHGetFolderPathW",         5, APICategory::FileSystem, BehaviorFlag::None,              0 },

    // === Ole32 ===
    { "ole32.dll", "CoInitializeEx",             2, APICategory::COM,        BehaviorFlag::None,              0 },
    { "ole32.dll", "CoUninitialize",             0, APICategory::COM,        BehaviorFlag::None,              0 },
    { "ole32.dll", "CoCreateInstance",           5, APICategory::COM,        BehaviorFlag::SuspiciousAPI,     0 },
    { "ole32.dll", "CoGetClassObject",           5, APICategory::COM,        BehaviorFlag::SuspiciousAPI,     0 },

    // === Urlmon ===
    { "urlmon.dll", "URLDownloadToFileA",        5, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },
    { "urlmon.dll", "URLDownloadToFileW",        5, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },
    { "urlmon.dll", "URLDownloadToCacheFileA",   5, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },
    { "urlmon.dll", "URLDownloadToCacheFileW",   5, APICategory::Network,    BehaviorFlag::NetworkC2,         0 },
};

static constexpr uint32_t kKnownAPICount = static_cast<uint32_t>(
    sizeof(kKnownAPIs) / sizeof(kKnownAPIs[0]));

// ============================================================================
// Lookup Helpers
// ============================================================================

// Find a known API entry by DLL + function name (linear scan; called only at init)
[[nodiscard]] inline const KnownAPIEntry* FindKnownAPI(
    std::string_view dll, std::string_view func) noexcept
{
    for (uint32_t i = 0; i < kKnownAPICount; ++i) {
        // Case-insensitive DLL comparison
        std::string_view d{ kKnownAPIs[i].dllName };
        if (d.size() != dll.size()) continue;
        bool match = true;
        for (size_t j = 0; j < d.size(); ++j) {
            char a = d[j]; if (a >= 'A' && a <= 'Z') a += 32;
            char b = dll[j]; if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) { match = false; break; }
        }
        if (!match) continue;
        if (func == kKnownAPIs[i].funcName)
            return &kKnownAPIs[i];
    }
    return nullptr;
}

// Find a known API entry by syscall number
[[nodiscard]] inline const KnownAPIEntry* FindKnownBySyscall(uint16_t number) noexcept {
    for (uint32_t i = 0; i < kKnownAPICount; ++i) {
        if (kKnownAPIs[i].syscallNumber == number && number != 0)
            return &kKnownAPIs[i];
    }
    return nullptr;
}

} // namespace Phantom
