/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/*++
    ShadowStrike Next-Generation Antivirus
    Module: NtdllIntegrity.h - Ntdll integrity monitoring

    Provides kernel-mode NTDLL integrity verification by comparing
    per-process ntdll.dll memory against a clean on-disk baseline.
    Detects inline hooks, syscall stub tampering, and PE modifications.

    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntifs.h>
#include <ntddk.h>

//
// Distinct pool tags for different allocation categories (aids debugging)
//
#define NI_POOL_TAG_MONITOR     'mNIs'  // Monitor structure
#define NI_POOL_TAG_PROCESS     'pNIs'  // Process state
#define NI_POOL_TAG_FUNCTION    'fNIs'  // Function state
#define NI_POOL_TAG_NTDLL       'nNIs'  // Clean NTDLL copy
#define NI_POOL_TAG_TEMP        'tNIs'  // Temporary buffers

typedef enum _NI_MODIFICATION {
    NiMod_None = 0,
    NiMod_HookInstalled,                // Detour/inline hook
    NiMod_InstructionPatch,             // Arbitrary instruction modification
    NiMod_SyscallStubModified,          // mov eax, X; syscall pattern broken
    NiMod_ImportModified,               // IAT hooking
    NiMod_ExportModified,               // EAT hooking
    NiMod_HeaderModified,               // PE header tampered
    NiMod_Unhooked,                     // Someone unhooked our hook
} NI_MODIFICATION;

typedef struct _NI_FUNCTION_STATE {
    CHAR FunctionName[64];
    PVOID ExpectedAddress;
    PVOID CurrentAddress;
    UCHAR ExpectedPrologue[16];
    UCHAR CurrentPrologue[16];
    BOOLEAN IsModified;
    NI_MODIFICATION ModificationType;
    LIST_ENTRY ListEntry;
} NI_FUNCTION_STATE, *PNI_FUNCTION_STATE;

typedef struct _NI_PROCESS_NTDLL {
    HANDLE ProcessId;
    PVOID NtdllBase;
    SIZE_T NtdllSize;
    UCHAR Hash[32];                     // SHA-256 of .text section
    BOOLEAN HashValid;                  // TRUE if Hash was computed successfully
    
    // Function states - protected by FunctionLock (push lock, PASSIVE/APC safe)
    LIST_ENTRY FunctionList;
    EX_PUSH_LOCK FunctionLock;
    ULONG FunctionCount;
    
    // Modification tracking
    ULONG ModificationCount;
    ULONG HookCount;                    // Count of NiMod_HookInstalled specifically
    LARGE_INTEGER LastCheck;
    
    LIST_ENTRY ListEntry;
} NI_PROCESS_NTDLL, *PNI_PROCESS_NTDLL;

typedef struct _NI_MONITOR {
    volatile LONG Initialized;
    
    // Clean ntdll reference
    PVOID CleanNtdllCopy;
    SIZE_T CleanNtdllSize;
    BOOLEAN CleanHashValid;             // TRUE if clean hash was computed
    
    // Process tracking
    LIST_ENTRY ProcessList;
    EX_PUSH_LOCK ProcessLock;
    volatile LONG ProcessCount;
    
    // Active operation count for safe shutdown drain
    volatile LONG ActiveOperations;
    KEVENT DrainEvent;
    
    struct {
        volatile LONG64 ProcessesMonitored;
        volatile LONG64 ModificationsFound;
        volatile LONG64 HooksDetected;
        LARGE_INTEGER StartTime;
    } Stats;
} NI_MONITOR, *PNI_MONITOR;

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS NiInitialize(_Out_ PNI_MONITOR* Monitor);

_IRQL_requires_(PASSIVE_LEVEL)
VOID NiShutdown(_Inout_ PNI_MONITOR Monitor);

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS NiScanProcess(_In_ PNI_MONITOR Monitor, _In_ HANDLE ProcessId, _Out_ PNI_PROCESS_NTDLL* State);

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS NiCheckFunction(_In_ PNI_MONITOR Monitor, _In_ HANDLE ProcessId, _In_ PCSTR FunctionName, _Out_ PNI_FUNCTION_STATE* State);

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS NiDetectHooks(_In_ PNI_MONITOR Monitor, _In_ HANDLE ProcessId, _Out_writes_to_(Max, *Count) PNI_FUNCTION_STATE* Hooks, _In_ ULONG Max, _Out_ PULONG Count);

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS NiCompareToClean(_In_ PNI_MONITOR Monitor, _In_ HANDLE ProcessId, _Out_ PBOOLEAN IsModified);

_IRQL_requires_(PASSIVE_LEVEL)
VOID NiFreeState(_In_ PNI_MONITOR Monitor, _In_ PNI_PROCESS_NTDLL State);

_IRQL_requires_(PASSIVE_LEVEL)
VOID NiFreeFunctionState(_In_ PNI_MONITOR Monitor, _In_ PNI_FUNCTION_STATE FunctionState);

#ifdef __cplusplus
}
#endif
