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
    Module: NtdllIntegrity.c

    Purpose: Enterprise-grade NTDLL integrity monitoring and hook detection
             for identifying API hooking, inline patching, and syscall stub
             modifications used by malware for evasion.

    Architecture:
    - Clean NTDLL reference from disk (\SystemRoot\System32\ntdll.dll)
    - Per-process NTDLL state tracking with function-level granularity
    - Inline hook detection (JMP, CALL, MOV patterns)
    - Syscall stub validation (mov eax, X; syscall sequence)
    - SHA-256 hash comparison for .text section integrity
    - Export table enumeration for comprehensive coverage
    - Lookaside list allocation for performance

    Detection Capabilities:
    - Inline/detour hooks (JMP REL32, JMP ABS, hotpatch)
    - Trampoline hooks (MOV R10/RAX + JMP)
    - Syscall number tampering
    - IAT/EAT modifications
    - PE header tampering
    - Unhooking detection (monitoring our own hooks)

    MITRE ATT&CK Coverage:
    - T1055: Process Injection (hook-based injection)
    - T1106: Native API (syscall hooking detection)
    - T1562: Impair Defenses (security tool hooking)
    - T1574: Hijack Execution Flow (API hooking)

    Copyright (c) ShadowStrike Team
--*/

#include "NtdllIntegrity.h"
#include "../../Shared/KernelProcessTypes.h"
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/HashUtils.h"
#include <ntimage.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, NiInitialize)
#pragma alloc_text(PAGE, NiShutdown)
#pragma alloc_text(PAGE, NiScanProcess)
#pragma alloc_text(PAGE, NiCheckFunction)
#pragma alloc_text(PAGE, NiDetectHooks)
#pragma alloc_text(PAGE, NiCompareToClean)
#pragma alloc_text(PAGE, NiFreeState)
#pragma alloc_text(PAGE, NiFreeFunctionState)
#endif

//=============================================================================
// Internal Constants
//=============================================================================

#define NI_SIGNATURE                    'TNIM'  // 'MINT' reversed

#define NI_MAX_PROCESSES                256
#define NI_MAX_FUNCTIONS                2048
#define NI_PROLOGUE_SIZE                16
#define NI_SYSCALL_STUB_SIZE            24

#define NI_MIN_VALID_USER_ADDRESS       0x10000ULL
#define NI_MAX_USER_ADDRESS             0x7FFFFFFFFFFFULL

//
// Sane upper bound for ntdll.dll (real ntdll is ~2MB, allow 16MB for safety)
//
#define NI_MAX_NTDLL_SIZE               (16ULL * 1024 * 1024)

//
// Maximum modules to enumerate in PEB LDR walk (prevents infinite loop on
// corrupted list from hostile process)
//
#define NI_MAX_LDR_MODULES              4096

//
// Hook detection patterns
//
#define NI_JMP_REL32_OPCODE             0xE9    // JMP rel32
#define NI_JMP_ABS_PREFIX               0xFF    // JMP r/m64
#define NI_CALL_REL32_OPCODE            0xE8    // CALL rel32
#define NI_MOV_EAX_IMM32               0xB8    // mov eax, imm32 (syscall number)
#define NI_NOP_OPCODE                   0x90    // NOP

//
// Critical ntdll functions to monitor
//
static const CHAR* const NI_CRITICAL_FUNCTIONS[] = {
    "NtCreateFile",
    "NtOpenFile",
    "NtReadFile",
    "NtWriteFile",
    "NtClose",
    "NtCreateProcess",
    "NtCreateProcessEx",
    "NtCreateUserProcess",
    "NtOpenProcess",
    "NtTerminateProcess",
    "NtCreateThread",
    "NtCreateThreadEx",
    "NtOpenThread",
    "NtTerminateThread",
    "NtSuspendThread",
    "NtResumeThread",
    "NtAllocateVirtualMemory",
    "NtFreeVirtualMemory",
    "NtProtectVirtualMemory",
    "NtReadVirtualMemory",
    "NtWriteVirtualMemory",
    "NtQueryVirtualMemory",
    "NtMapViewOfSection",
    "NtUnmapViewOfSection",
    "NtCreateSection",
    "NtOpenSection",
    "NtQueryInformationProcess",
    "NtSetInformationProcess",
    "NtQueryInformationThread",
    "NtSetInformationThread",
    "NtQuerySystemInformation",
    "NtSetSystemInformation",
    "NtCreateKey",
    "NtOpenKey",
    "NtSetValueKey",
    "NtQueryValueKey",
    "NtDeleteKey",
    "NtDeleteValueKey",
    "NtEnumerateKey",
    "NtEnumerateValueKey",
    "NtLoadDriver",
    "NtUnloadDriver",
    "NtDeviceIoControlFile",
    "NtFsControlFile",
    "NtSetContextThread",
    "NtGetContextThread",
    "NtQueueApcThread",
    "NtQueueApcThreadEx",
    "NtTestAlert",
    "NtContinue",
    "NtRaiseException",
    "NtCreateMutant",
    "NtOpenMutant",
    "NtCreateEvent",
    "NtOpenEvent",
    "NtWaitForSingleObject",
    "NtWaitForMultipleObjects",
    "NtDelayExecution",
    "NtYieldExecution",
    "LdrLoadDll",
    "LdrUnloadDll",
    "LdrGetProcedureAddress",
    "LdrGetDllHandle",
    "RtlCreateHeap",
    "RtlAllocateHeap",
    "RtlFreeHeap",
    "RtlDestroyHeap",
    NULL
};

#define NI_CRITICAL_FUNCTION_COUNT (sizeof(NI_CRITICAL_FUNCTIONS) / sizeof(NI_CRITICAL_FUNCTIONS[0]) - 1)

//=============================================================================
// Internal Structures
//=============================================================================

typedef struct _NI_MONITOR_INTERNAL {
    ULONG Signature;
    NI_MONITOR Monitor;

    //
    // Clean NTDLL information
    //
    PVOID CleanTextSection;
    SIZE_T CleanTextSize;
    ULONG_PTR CleanTextRva;
    UCHAR CleanTextHash[32];

    //
    // Export table from clean NTDLL (pointers into CleanNtdllCopy)
    //
    struct {
        PVOID ExportDirectory;
        ULONG NumberOfFunctions;
        ULONG NumberOfNames;
        PULONG AddressOfFunctions;
        PULONG AddressOfNames;
        PUSHORT AddressOfNameOrdinals;
    } CleanExports;

    //
    // Lookaside lists for high-frequency allocations
    //
    PAGED_LOOKASIDE_LIST ProcessLookaside;
    PAGED_LOOKASIDE_LIST FunctionLookaside;

    //
    // Shutdown flag (interlocked access only)
    //
    volatile LONG ShuttingDown;

} NI_MONITOR_INTERNAL, *PNI_MONITOR_INTERNAL;

//
// Helpers: acquire/release active operation count for safe shutdown drain
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static __forceinline BOOLEAN
NipAcquireOperation(
    _In_ PNI_MONITOR Monitor
    )
{
    if (!InterlockedCompareExchange(&Monitor->Initialized, 1, 1)) {
        return FALSE;
    }

    InterlockedIncrement(&Monitor->ActiveOperations);

    //
    // Re-check after increment: if shutdown raced in, undo and fail
    //
    if (!InterlockedCompareExchange(&Monitor->Initialized, 1, 1)) {
        if (InterlockedDecrement(&Monitor->ActiveOperations) == 0) {
            KeSetEvent(&Monitor->DrainEvent, IO_NO_INCREMENT, FALSE);
        }
        return FALSE;
    }

    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static __forceinline VOID
NipReleaseOperation(
    _In_ PNI_MONITOR Monitor
    )
{
    if (InterlockedDecrement(&Monitor->ActiveOperations) == 0) {
        KeSetEvent(&Monitor->DrainEvent, IO_NO_INCREMENT, FALSE);
    }
}

//=============================================================================
// Forward Declarations
//=============================================================================

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
NipCaptureCleanNtdll(
    _Inout_ PNI_MONITOR_INTERNAL MonitorInternal
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
NipGetProcessNtdll(
    _In_ HANDLE ProcessId,
    _Out_ PVOID* NtdllBase,
    _Out_ PSIZE_T NtdllSize
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
NipReadProcessMemory(
    _In_ HANDLE ProcessId,
    _In_ PVOID SourceAddress,
    _Out_writes_bytes_(Size) PVOID Destination,
    _In_ SIZE_T Size
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
NipGetTextSection(
    _In_ PVOID ModuleBase,
    _In_ SIZE_T ModuleSize,
    _Out_ PVOID* TextBase,
    _Out_ PSIZE_T TextSize,
    _Out_ PULONG_PTR TextRva
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
NipParseExportTable(
    _In_ PVOID ModuleBase,
    _In_ SIZE_T ModuleSize,
    _Out_ PVOID* ExportDirectory,
    _Out_ PULONG NumberOfFunctions,
    _Out_ PULONG NumberOfNames,
    _Out_ PULONG* AddressOfFunctions,
    _Out_ PULONG* AddressOfNames,
    _Out_ PUSHORT* AddressOfNameOrdinals
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
NipLookupExportByName(
    _In_ PNI_MONITOR_INTERNAL MonitorInternal,
    _In_ PCSTR FunctionName,
    _Out_ PULONG_PTR FunctionRva,
    _Out_ PUCHAR ExpectedPrologue
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static NI_MODIFICATION
NipDetectHookType(
    _In_ PUCHAR CurrentPrologue,
    _In_ PUCHAR ExpectedPrologue,
    _In_ SIZE_T Size
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static BOOLEAN
NipIsSyscallStub(
    _In_ PUCHAR Prologue,
    _In_ SIZE_T Size,
    _Out_opt_ PULONG SyscallNumber
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static BOOLEAN
NipValidateSyscallStub(
    _In_ PUCHAR CurrentPrologue,
    _In_ PUCHAR ExpectedPrologue,
    _In_ SIZE_T Size
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static PNI_PROCESS_NTDLL
NipFindProcessStateLocked(
    _In_ PNI_MONITOR Monitor,
    _In_ HANDLE ProcessId
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
NipFreeProcessState(
    _In_ PNI_MONITOR_INTERNAL MonitorInternal,
    _Inout_ PNI_PROCESS_NTDLL State
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
NipComputeTextSectionHash(
    _In_ HANDLE ProcessId,
    _In_ PVOID NtdllBase,
    _In_ ULONG_PTR TextRva,
    _In_ SIZE_T TextSize,
    _Out_writes_(32) PUCHAR Hash
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
NipReadNtdllFromDisk(
    _Out_ PVOID* Buffer,
    _Out_ PSIZE_T BufferSize
    );

//=============================================================================
// Initialization / Shutdown
//=============================================================================

_Use_decl_annotations_
NTSTATUS
NiInitialize(
    _Out_ PNI_MONITOR* Monitor
    )
/*++

Routine Description:

    Initializes the NTDLL integrity monitor. Reads a clean copy of NTDLL
    from disk (\SystemRoot\System32\ntdll.dll) for use as a reference baseline.

Arguments:

    Monitor - Receives pointer to initialized monitor.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PNI_MONITOR_INTERNAL monitorInternal = NULL;
    PNI_MONITOR monitor = NULL;
    NTSTATUS status;

    PAGED_CODE();

    if (Monitor == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Monitor = NULL;

    //
    // Allocate internal monitor structure from paged pool — all access is
    // at PASSIVE_LEVEL so no need to consume precious non-paged pool.
    //
    monitorInternal = (PNI_MONITOR_INTERNAL)ShadowStrikeAllocatePoolWithTag(
        PagedPool,
        sizeof(NI_MONITOR_INTERNAL),
        NI_POOL_TAG_MONITOR
        );

    if (monitorInternal == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(monitorInternal, sizeof(NI_MONITOR_INTERNAL));

    monitorInternal->Signature = NI_SIGNATURE;
    monitor = &monitorInternal->Monitor;

    //
    // Initialize process list and lock
    //
    InitializeListHead(&monitor->ProcessList);
    FltInitializePushLock(&monitor->ProcessLock);
    monitor->ProcessCount = 0;
    monitor->ActiveOperations = 0;
    KeInitializeEvent(&monitor->DrainEvent, NotificationEvent, TRUE);

    //
    // Initialize lookaside lists (paged — all callers at PASSIVE_LEVEL)
    //
    ExInitializePagedLookasideList(
        &monitorInternal->ProcessLookaside,
        NULL,
        NULL,
        0,
        sizeof(NI_PROCESS_NTDLL),
        NI_POOL_TAG_PROCESS,
        0
        );

    ExInitializePagedLookasideList(
        &monitorInternal->FunctionLookaside,
        NULL,
        NULL,
        0,
        sizeof(NI_FUNCTION_STATE),
        NI_POOL_TAG_FUNCTION,
        0
        );

    //
    // Capture clean NTDLL from disk (trusted source)
    //
    status = NipCaptureCleanNtdll(monitorInternal);
    if (!NT_SUCCESS(status)) {
        ExDeletePagedLookasideList(&monitorInternal->ProcessLookaside);
        ExDeletePagedLookasideList(&monitorInternal->FunctionLookaside);
        ShadowStrikeFreePoolWithTag(monitorInternal, NI_POOL_TAG_MONITOR);
        return status;
    }

    //
    // Initialize statistics
    //
    KeQuerySystemTimePrecise(&monitor->Stats.StartTime);
    monitor->Stats.ProcessesMonitored = 0;
    monitor->Stats.ModificationsFound = 0;
    monitor->Stats.HooksDetected = 0;

    InterlockedExchange(&monitor->Initialized, TRUE);
    InterlockedExchange(&monitorInternal->ShuttingDown, FALSE);

    *Monitor = monitor;

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
NiShutdown(
    _Inout_ PNI_MONITOR Monitor
    )
/*++

Routine Description:

    Shuts down the NTDLL integrity monitor. Drains active operations,
    frees all process states, and releases the clean NTDLL copy.

Arguments:

    Monitor - Monitor to shutdown.

--*/
{
    PNI_MONITOR_INTERNAL monitorInternal;
    PNI_PROCESS_NTDLL processState;
    PLIST_ENTRY entry;
    LIST_ENTRY statesToFree;

    PAGED_CODE();

    if (Monitor == NULL) {
        return;
    }

    //
    // Atomically mark as not initialized. If already not initialized, bail.
    //
    if (!InterlockedCompareExchange(&Monitor->Initialized, FALSE, TRUE)) {
        return;
    }

    monitorInternal = CONTAINING_RECORD(Monitor, NI_MONITOR_INTERNAL, Monitor);

    if (monitorInternal->Signature != NI_SIGNATURE) {
        return;
    }

    InterlockedExchange(&monitorInternal->ShuttingDown, TRUE);
    KeMemoryBarrier();

    //
    // Wait for all in-flight operations to complete (drain).
    // Clear event BEFORE checking count to prevent race: an operation
    // completing between check and clear would set the event, then
    // we'd clear it and wait forever (deadlock).
    //
    KeClearEvent(&Monitor->DrainEvent);

    if (Monitor->ActiveOperations > 0) {
        LARGE_INTEGER drainTimeout;
        NTSTATUS waitStatus;

        drainTimeout.QuadPart = -10LL * 1000 * 1000 * 10; // 10 seconds

        waitStatus = KeWaitForSingleObject(
            &Monitor->DrainEvent,
            Executive,
            KernelMode,
            FALSE,
            &drainTimeout
            );

        if (waitStatus == STATUS_TIMEOUT) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike] NtdllIntegrity: drain timeout, %ld ops still active\n",
                       Monitor->ActiveOperations);
        }
    }

    //
    // All operations drained — collect process states for cleanup
    //
    InitializeListHead(&statesToFree);

    FltAcquirePushLockExclusive(&Monitor->ProcessLock);

    while (!IsListEmpty(&Monitor->ProcessList)) {
        entry = RemoveHeadList(&Monitor->ProcessList);
        InsertTailList(&statesToFree, entry);
    }

    Monitor->ProcessCount = 0;

    FltReleasePushLock(&Monitor->ProcessLock);

    //
    // Free all process states outside of lock
    //
    while (!IsListEmpty(&statesToFree)) {
        entry = RemoveHeadList(&statesToFree);
        processState = CONTAINING_RECORD(entry, NI_PROCESS_NTDLL, ListEntry);
        NipFreeProcessState(monitorInternal, processState);
    }

    //
    // Free clean NTDLL copy
    //
    if (Monitor->CleanNtdllCopy != NULL) {
        ShadowStrikeFreePoolWithTag(Monitor->CleanNtdllCopy, NI_POOL_TAG_NTDLL);
        Monitor->CleanNtdllCopy = NULL;
        Monitor->CleanNtdllSize = 0;
    }

    //
    // Delete lookaside lists
    //
    ExDeletePagedLookasideList(&monitorInternal->ProcessLookaside);
    ExDeletePagedLookasideList(&monitorInternal->FunctionLookaside);

    //
    // Clear signature and free monitor
    //
    monitorInternal->Signature = 0;
    ShadowStrikeFreePoolWithTag(monitorInternal, NI_POOL_TAG_MONITOR);
}


//=============================================================================
// Process Scanning
//=============================================================================

_Use_decl_annotations_
NTSTATUS
NiScanProcess(
    _In_ PNI_MONITOR Monitor,
    _In_ HANDLE ProcessId,
    _Out_ PNI_PROCESS_NTDLL* State
    )
/*++

Routine Description:

    Scans a process's NTDLL for modifications and hooks. Creates or updates
    the process state with current function prologues and modification flags.

    Thread-safe: uses push lock for process list and function list access.
    The find-or-create is performed atomically under the process list lock.

Arguments:

    Monitor - NTDLL integrity monitor.
    ProcessId - Process to scan.
    State - Receives the process NTDLL state.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PNI_MONITOR_INTERNAL monitorInternal;
    PNI_PROCESS_NTDLL processState = NULL;
    PNI_FUNCTION_STATE functionState;
    NTSTATUS status;
    PVOID ntdllBase = NULL;
    SIZE_T ntdllSize = 0;
    ULONG i;
    BOOLEAN newState = FALSE;

    PAGED_CODE();

    if (Monitor == NULL || State == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ProcessId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *State = NULL;

    if (!NipAcquireOperation(Monitor)) {
        return STATUS_SHUTDOWN_IN_PROGRESS;
    }

    monitorInternal = CONTAINING_RECORD(Monitor, NI_MONITOR_INTERNAL, Monitor);

    //
    // Atomic find-or-create under exclusive lock to prevent duplicate entries
    //
    FltAcquirePushLockExclusive(&Monitor->ProcessLock);

    processState = NipFindProcessStateLocked(Monitor, ProcessId);

    if (processState == NULL) {
        //
        // Enforce max process count to bound memory usage
        //
        if (Monitor->ProcessCount >= NI_MAX_PROCESSES) {
            FltReleasePushLock(&Monitor->ProcessLock);
            NipReleaseOperation(Monitor);
            return STATUS_QUOTA_EXCEEDED;
        }

        //
        // Create new process state
        //
        processState = (PNI_PROCESS_NTDLL)ExAllocateFromPagedLookasideList(
            &monitorInternal->ProcessLookaside
            );

        if (processState == NULL) {
            FltReleasePushLock(&Monitor->ProcessLock);
            NipReleaseOperation(Monitor);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(processState, sizeof(NI_PROCESS_NTDLL));

        processState->ProcessId = ProcessId;
        InitializeListHead(&processState->FunctionList);
        FltInitializePushLock(&processState->FunctionLock);
        processState->FunctionCount = 0;
        processState->ModificationCount = 0;
        processState->HookCount = 0;
        processState->HashValid = FALSE;

        //
        // Insert into list while we hold the exclusive lock
        //
        InsertTailList(&Monitor->ProcessList, &processState->ListEntry);
        InterlockedIncrement(&Monitor->ProcessCount);
        InterlockedIncrement64(&Monitor->Stats.ProcessesMonitored);

        newState = TRUE;
    }

    FltReleasePushLock(&Monitor->ProcessLock);

    //
    // Get NTDLL base for this process
    //
    status = NipGetProcessNtdll(ProcessId, &ntdllBase, &ntdllSize);
    if (!NT_SUCCESS(status)) {
        if (newState) {
            //
            // Remove the state we just inserted
            //
            FltAcquirePushLockExclusive(&Monitor->ProcessLock);
            RemoveEntryList(&processState->ListEntry);
            InterlockedDecrement(&Monitor->ProcessCount);
            FltReleasePushLock(&Monitor->ProcessLock);
            NipFreeProcessState(monitorInternal, processState);
        }
        NipReleaseOperation(Monitor);
        return status;
    }

    processState->NtdllBase = ntdllBase;
    processState->NtdllSize = ntdllSize;

    //
    // Compute hash of .text section
    //
    status = NipComputeTextSectionHash(
        ProcessId,
        ntdllBase,
        monitorInternal->CleanTextRva,
        monitorInternal->CleanTextSize,
        processState->Hash
        );

    processState->HashValid = NT_SUCCESS(status);

    //
    // Clear existing function states if updating
    //
    if (!newState) {
        PLIST_ENTRY entry;
        LIST_ENTRY toFree;

        InitializeListHead(&toFree);

        FltAcquirePushLockExclusive(&processState->FunctionLock);

        while (!IsListEmpty(&processState->FunctionList)) {
            entry = RemoveHeadList(&processState->FunctionList);
            InsertTailList(&toFree, entry);
        }
        processState->FunctionCount = 0;

        FltReleasePushLock(&processState->FunctionLock);

        while (!IsListEmpty(&toFree)) {
            entry = RemoveHeadList(&toFree);
            functionState = CONTAINING_RECORD(entry, NI_FUNCTION_STATE, ListEntry);
            ExFreeToPagedLookasideList(&monitorInternal->FunctionLookaside, functionState);
        }
    }

    //
    // Scan critical functions
    //
    processState->ModificationCount = 0;
    processState->HookCount = 0;

    for (i = 0; i < NI_CRITICAL_FUNCTION_COUNT; i++) {
        PCSTR functionName = NI_CRITICAL_FUNCTIONS[i];
        ULONG_PTR functionRva = 0;
        UCHAR expectedPrologue[NI_PROLOGUE_SIZE] = {0};
        UCHAR currentPrologue[NI_PROLOGUE_SIZE] = {0};
        PVOID functionAddress;
        NI_MODIFICATION modType;
        SIZE_T nameLen;

        //
        // Look up function in clean NTDLL
        //
        status = NipLookupExportByName(
            monitorInternal,
            functionName,
            &functionRva,
            expectedPrologue
            );

        if (!NT_SUCCESS(status)) {
            continue;
        }

        //
        // Calculate function address in target process
        //
        functionAddress = (PVOID)((ULONG_PTR)ntdllBase + functionRva);

        //
        // Read current prologue from process
        //
        status = NipReadProcessMemory(
            ProcessId,
            functionAddress,
            currentPrologue,
            NI_PROLOGUE_SIZE
            );

        if (!NT_SUCCESS(status)) {
            continue;
        }

        //
        // Allocate function state
        //
        functionState = (PNI_FUNCTION_STATE)ExAllocateFromPagedLookasideList(
            &monitorInternal->FunctionLookaside
            );

        if (functionState == NULL) {
            continue;
        }

        RtlZeroMemory(functionState, sizeof(NI_FUNCTION_STATE));

        //
        // Fill function state with bounded string copy
        //
        nameLen = strnlen(functionName, sizeof(functionState->FunctionName) - 1);
        RtlCopyMemory(functionState->FunctionName, functionName, nameLen);
        functionState->FunctionName[nameLen] = '\0';

        functionState->ExpectedAddress = (PVOID)((ULONG_PTR)Monitor->CleanNtdllCopy + functionRva);
        functionState->CurrentAddress = functionAddress;

        RtlCopyMemory(functionState->ExpectedPrologue, expectedPrologue, NI_PROLOGUE_SIZE);
        RtlCopyMemory(functionState->CurrentPrologue, currentPrologue, NI_PROLOGUE_SIZE);

        //
        // Detect modification type
        //
        modType = NipDetectHookType(currentPrologue, expectedPrologue, NI_PROLOGUE_SIZE);

        functionState->IsModified = (modType != NiMod_None);
        functionState->ModificationType = modType;

        if (functionState->IsModified) {
            processState->ModificationCount++;
            InterlockedIncrement64(&Monitor->Stats.ModificationsFound);

            if (modType == NiMod_HookInstalled) {
                processState->HookCount++;
                InterlockedIncrement64(&Monitor->Stats.HooksDetected);
            }
        }

        //
        // Add to function list under push lock
        //
        FltAcquirePushLockExclusive(&processState->FunctionLock);
        InsertTailList(&processState->FunctionList, &functionState->ListEntry);
        processState->FunctionCount++;
        FltReleasePushLock(&processState->FunctionLock);
    }

    KeQuerySystemTimePrecise(&processState->LastCheck);

    *State = processState;

    NipReleaseOperation(Monitor);

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
NiCheckFunction(
    _In_ PNI_MONITOR Monitor,
    _In_ HANDLE ProcessId,
    _In_ PCSTR FunctionName,
    _Out_ PNI_FUNCTION_STATE* State
    )
/*++

Routine Description:

    Checks a specific function in a process's NTDLL for modifications.

Arguments:

    Monitor - NTDLL integrity monitor.
    ProcessId - Target process.
    FunctionName - Name of function to check.
    State - Receives function state (caller must free via lookaside).

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PNI_MONITOR_INTERNAL monitorInternal;
    PNI_FUNCTION_STATE functionState = NULL;
    NTSTATUS status;
    PVOID ntdllBase = NULL;
    SIZE_T ntdllSize = 0;
    ULONG_PTR functionRva = 0;
    UCHAR expectedPrologue[NI_PROLOGUE_SIZE] = {0};
    UCHAR currentPrologue[NI_PROLOGUE_SIZE] = {0};
    PVOID functionAddress;
    NI_MODIFICATION modType;
    SIZE_T nameLen;

    PAGED_CODE();

    if (Monitor == NULL || FunctionName == NULL || State == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ProcessId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *State = NULL;

    if (!NipAcquireOperation(Monitor)) {
        return STATUS_SHUTDOWN_IN_PROGRESS;
    }

    monitorInternal = CONTAINING_RECORD(Monitor, NI_MONITOR_INTERNAL, Monitor);

    //
    // Get NTDLL base for this process
    //
    status = NipGetProcessNtdll(ProcessId, &ntdllBase, &ntdllSize);
    if (!NT_SUCCESS(status)) {
        NipReleaseOperation(Monitor);
        return status;
    }

    //
    // Look up function in clean NTDLL
    //
    status = NipLookupExportByName(
        monitorInternal,
        FunctionName,
        &functionRva,
        expectedPrologue
        );

    if (!NT_SUCCESS(status)) {
        NipReleaseOperation(Monitor);
        return status;
    }

    //
    // Calculate function address in target process
    //
    functionAddress = (PVOID)((ULONG_PTR)ntdllBase + functionRva);

    //
    // Read current prologue from process
    //
    status = NipReadProcessMemory(
        ProcessId,
        functionAddress,
        currentPrologue,
        NI_PROLOGUE_SIZE
        );

    if (!NT_SUCCESS(status)) {
        NipReleaseOperation(Monitor);
        return status;
    }

    //
    // Allocate function state
    //
    functionState = (PNI_FUNCTION_STATE)ExAllocateFromPagedLookasideList(
        &monitorInternal->FunctionLookaside
        );

    if (functionState == NULL) {
        NipReleaseOperation(Monitor);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(functionState, sizeof(NI_FUNCTION_STATE));

    //
    // Fill function state with bounded string copy
    //
    nameLen = strnlen(FunctionName, sizeof(functionState->FunctionName) - 1);
    RtlCopyMemory(functionState->FunctionName, FunctionName, nameLen);
    functionState->FunctionName[nameLen] = '\0';

    functionState->ExpectedAddress = (PVOID)((ULONG_PTR)Monitor->CleanNtdllCopy + functionRva);
    functionState->CurrentAddress = functionAddress;

    RtlCopyMemory(functionState->ExpectedPrologue, expectedPrologue, NI_PROLOGUE_SIZE);
    RtlCopyMemory(functionState->CurrentPrologue, currentPrologue, NI_PROLOGUE_SIZE);

    //
    // Detect modification type
    //
    modType = NipDetectHookType(currentPrologue, expectedPrologue, NI_PROLOGUE_SIZE);

    functionState->IsModified = (modType != NiMod_None);
    functionState->ModificationType = modType;

    *State = functionState;

    NipReleaseOperation(Monitor);

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
NiDetectHooks(
    _In_ PNI_MONITOR Monitor,
    _In_ HANDLE ProcessId,
    _Out_writes_to_(Max, *Count) PNI_FUNCTION_STATE* Hooks,
    _In_ ULONG Max,
    _Out_ PULONG Count
    )
/*++

Routine Description:

    Detects all hooked functions in a process's NTDLL.

Arguments:

    Monitor - NTDLL integrity monitor.
    ProcessId - Target process.
    Hooks - Array to receive hooked function states.
    Max - Maximum entries in Hooks array.
    Count - Receives actual count of hooks found.

Return Value:

    STATUS_SUCCESS on success.
    STATUS_BUFFER_TOO_SMALL if more hooks exist than Max.

--*/
{
    PNI_MONITOR_INTERNAL monitorInternal;
    PNI_PROCESS_NTDLL processState = NULL;
    NTSTATUS status;
    ULONG hookIndex = 0;
    ULONG totalHooks = 0;

    PAGED_CODE();

    if (Monitor == NULL || Hooks == NULL || Count == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Count = 0;

    if (Max == 0) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (!NipAcquireOperation(Monitor)) {
        return STATUS_SHUTDOWN_IN_PROGRESS;
    }

    monitorInternal = CONTAINING_RECORD(Monitor, NI_MONITOR_INTERNAL, Monitor);

    //
    // Scan the process to get current state
    //
    status = NiScanProcess(Monitor, ProcessId, &processState);
    if (!NT_SUCCESS(status)) {
        NipReleaseOperation(Monitor);
        return status;
    }

    //
    // Iterate function states and collect hooked ones (push lock, PASSIVE safe)
    //
    if (processState != NULL) {
        PLIST_ENTRY entry;
        PNI_FUNCTION_STATE funcState;
        ULONG walkCount = 0;

        FltAcquirePushLockShared(&processState->FunctionLock);

        for (entry = processState->FunctionList.Flink;
             entry != &processState->FunctionList && walkCount < NI_MAX_FUNCTIONS;
             entry = entry->Flink) {

            walkCount++;
            funcState = CONTAINING_RECORD(entry, NI_FUNCTION_STATE, ListEntry);

            if (funcState->IsModified &&
                funcState->ModificationType == NiMod_HookInstalled) {

                totalHooks++;

                if (hookIndex < Max) {
                    //
                    // Allocate a copy for the caller
                    //
                    PNI_FUNCTION_STATE hookCopy = (PNI_FUNCTION_STATE)ExAllocateFromPagedLookasideList(
                        &monitorInternal->FunctionLookaside
                        );

                    if (hookCopy != NULL) {
                        RtlCopyMemory(hookCopy, funcState, sizeof(NI_FUNCTION_STATE));
                        InitializeListHead(&hookCopy->ListEntry);
                        Hooks[hookIndex++] = hookCopy;
                    }
                }
            }
        }

        FltReleasePushLock(&processState->FunctionLock);
    }

    *Count = hookIndex;

    NipReleaseOperation(Monitor);

    //
    // Report overflow based on actual hook count, not ModificationCount
    //
    if (totalHooks > Max) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
NiCompareToClean(
    _In_ PNI_MONITOR Monitor,
    _In_ HANDLE ProcessId,
    _Out_ PBOOLEAN IsModified
    )
/*++

Routine Description:

    Compares a process's NTDLL .text section to the clean reference
    using SHA-256 hash comparison.

Arguments:

    Monitor - NTDLL integrity monitor.
    ProcessId - Target process.
    IsModified - Receives TRUE if NTDLL has been modified.

Return Value:

    STATUS_SUCCESS on success.
    STATUS_NOT_SUPPORTED if clean hash is unavailable.

--*/
{
    PNI_MONITOR_INTERNAL monitorInternal;
    NTSTATUS status;
    PVOID ntdllBase = NULL;
    SIZE_T ntdllSize = 0;
    UCHAR processHash[32] = {0};

    PAGED_CODE();

    if (Monitor == NULL || IsModified == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsModified = TRUE;  // Assume modified until proven otherwise

    if (!NipAcquireOperation(Monitor)) {
        return STATUS_SHUTDOWN_IN_PROGRESS;
    }

    monitorInternal = CONTAINING_RECORD(Monitor, NI_MONITOR_INTERNAL, Monitor);

    //
    // Cannot compare if clean hash was never computed successfully
    //
    if (!Monitor->CleanHashValid) {
        NipReleaseOperation(Monitor);
        return STATUS_NOT_SUPPORTED;
    }

    //
    // Get NTDLL base for this process
    //
    status = NipGetProcessNtdll(ProcessId, &ntdllBase, &ntdllSize);
    if (!NT_SUCCESS(status)) {
        NipReleaseOperation(Monitor);
        return status;
    }

    //
    // Compute hash of process .text section
    //
    status = NipComputeTextSectionHash(
        ProcessId,
        ntdllBase,
        monitorInternal->CleanTextRva,
        monitorInternal->CleanTextSize,
        processHash
        );

    if (!NT_SUCCESS(status)) {
        NipReleaseOperation(Monitor);
        return status;
    }

    //
    // Compare hashes
    //
    *IsModified = (RtlCompareMemory(processHash, monitorInternal->CleanTextHash, 32) != 32);

    NipReleaseOperation(Monitor);

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
NiFreeState(
    _In_ PNI_MONITOR Monitor,
    _In_ PNI_PROCESS_NTDLL State
    )
/*++

Routine Description:

    Removes a process NTDLL state from the monitor and frees it along
    with all associated function states.

Arguments:

    Monitor - The owning monitor (needed for lookaside lists and process list).
    State - State to free.

--*/
{
    PNI_MONITOR_INTERNAL monitorInternal;

    PAGED_CODE();

    if (Monitor == NULL || State == NULL) {
        return;
    }

    monitorInternal = CONTAINING_RECORD(Monitor, NI_MONITOR_INTERNAL, Monitor);

    if (monitorInternal->Signature != NI_SIGNATURE) {
        return;
    }

    //
    // Remove from process list under exclusive lock
    //
    FltAcquirePushLockExclusive(&Monitor->ProcessLock);
    RemoveEntryList(&State->ListEntry);
    InterlockedDecrement(&Monitor->ProcessCount);
    FltReleasePushLock(&Monitor->ProcessLock);

    //
    // Free the state and all its function children
    //
    NipFreeProcessState(monitorInternal, State);
}


_Use_decl_annotations_
VOID
NiFreeFunctionState(
    _In_ PNI_MONITOR Monitor,
    _In_ PNI_FUNCTION_STATE FunctionState
    )
/*++

Routine Description:

    Frees a single function state returned by NiCheckFunction or NiDetectHooks.
    The caller MUST pass the same monitor that produced the state.

Arguments:

    Monitor - The owning monitor (needed for lookaside list).
    FunctionState - Function state to free.

--*/
{
    PNI_MONITOR_INTERNAL monitorInternal;

    PAGED_CODE();

    if (Monitor == NULL || FunctionState == NULL) {
        return;
    }

    monitorInternal = CONTAINING_RECORD(Monitor, NI_MONITOR_INTERNAL, Monitor);

    if (monitorInternal->Signature != NI_SIGNATURE) {
        return;
    }

    RtlSecureZeroMemory(FunctionState, sizeof(NI_FUNCTION_STATE));
    ExFreeToPagedLookasideList(&monitorInternal->FunctionLookaside, FunctionState);
}


//=============================================================================
// Internal Functions - NTDLL Capture
//=============================================================================

static
_Use_decl_annotations_
NTSTATUS
NipCaptureCleanNtdll(
    _Inout_ PNI_MONITOR_INTERNAL MonitorInternal
    )
/*++

Routine Description:

    Captures a clean copy of NTDLL by reading it from disk
    (\SystemRoot\System32\ntdll.dll). This is the only trusted source;
    reading from any process address space would be vulnerable to
    pre-existing hooks.

--*/
{
    NTSTATUS status;
    PVOID cleanCopy = NULL;
    SIZE_T cleanSize = 0;
    PVOID textBase = NULL;
    SIZE_T textSize = 0;
    ULONG_PTR textRva = 0;

    //
    // Read ntdll.dll from disk — trusted baseline
    //
    status = NipReadNtdllFromDisk(&cleanCopy, &cleanSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    MonitorInternal->Monitor.CleanNtdllCopy = cleanCopy;
    MonitorInternal->Monitor.CleanNtdllSize = cleanSize;

    //
    // Parse .text section from clean copy
    //
    status = NipGetTextSection(
        cleanCopy,
        cleanSize,
        &textBase,
        &textSize,
        &textRva
        );

    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreePoolWithTag(cleanCopy, NI_POOL_TAG_NTDLL);
        MonitorInternal->Monitor.CleanNtdllCopy = NULL;
        MonitorInternal->Monitor.CleanNtdllSize = 0;
        return status;
    }

    MonitorInternal->CleanTextSection = textBase;
    MonitorInternal->CleanTextSize = textSize;
    MonitorInternal->CleanTextRva = textRva;

    //
    // Compute hash of clean .text section
    //
    if (textSize <= MAXULONG) {
        status = ShadowStrikeComputeSha256(
            textBase,
            (ULONG)textSize,
            MonitorInternal->CleanTextHash
            );
    } else {
        status = STATUS_INTEGER_OVERFLOW;
    }

    if (!NT_SUCCESS(status)) {
        //
        // Hash failure is tracked — NiCompareToClean will check this flag
        //
        RtlZeroMemory(MonitorInternal->CleanTextHash, sizeof(MonitorInternal->CleanTextHash));
        MonitorInternal->Monitor.CleanHashValid = FALSE;
    } else {
        MonitorInternal->Monitor.CleanHashValid = TRUE;
    }

    //
    // Parse export table
    //
    status = NipParseExportTable(
        cleanCopy,
        cleanSize,
        &MonitorInternal->CleanExports.ExportDirectory,
        &MonitorInternal->CleanExports.NumberOfFunctions,
        &MonitorInternal->CleanExports.NumberOfNames,
        &MonitorInternal->CleanExports.AddressOfFunctions,
        &MonitorInternal->CleanExports.AddressOfNames,
        &MonitorInternal->CleanExports.AddressOfNameOrdinals
        );

    if (!NT_SUCCESS(status)) {
        //
        // Export parsing failure is critical — cannot monitor functions
        //
        ShadowStrikeFreePoolWithTag(cleanCopy, NI_POOL_TAG_NTDLL);
        MonitorInternal->Monitor.CleanNtdllCopy = NULL;
        MonitorInternal->Monitor.CleanNtdllSize = 0;
        return status;
    }

    return STATUS_SUCCESS;
}


static
_Use_decl_annotations_
NTSTATUS
NipGetProcessNtdll(
    _In_ HANDLE ProcessId,
    _Out_ PVOID* NtdllBase,
    _Out_ PSIZE_T NtdllSize
    )
/*++

Routine Description:

    Gets the base address and size of ntdll.dll in a process by walking
    the PEB loader data structures.

    Security:
    - Iterates at most NI_MAX_LDR_MODULES to prevent infinite loops on
      corrupted lists from hostile processes.
    - Validates returned base address and size against sane bounds.

--*/
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PPEB peb = NULL;
    PKM_PEB_LDR_DATA ldrData = NULL;
    PLIST_ENTRY listHead;
    PLIST_ENTRY listEntry;
    KAPC_STATE apcState;
    BOOLEAN found = FALSE;
    UNICODE_STRING ntdllName;
    ULONG iterationCount = 0;

    PAGED_CODE();

    *NtdllBase = NULL;
    *NtdllSize = 0;

    RtlInitUnicodeString(&ntdllName, L"ntdll.dll");

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    peb = PsGetProcessPeb(process);
    if (peb == NULL) {
        ObDereferenceObject(process);
        return STATUS_NOT_FOUND;
    }

    KeStackAttachProcess(process, &apcState);

    __try {
        ProbeForRead(peb, KM_PEB_PROBE_SIZE, sizeof(PVOID));
        ldrData = ((PKM_PEB)peb)->Ldr;

        if (ldrData == NULL) {
            status = STATUS_NOT_FOUND;
            __leave;
        }

        ProbeForRead(ldrData, KM_PEB_LDR_PROBE_SIZE, sizeof(PVOID));

        listHead = &ldrData->InMemoryOrderModuleList;
        listEntry = listHead->Flink;

        while (listEntry != listHead && iterationCount < NI_MAX_LDR_MODULES) {
            PKM_LDR_DATA_TABLE_ENTRY ldrEntry;

            iterationCount++;

            ldrEntry = CONTAINING_RECORD(
                listEntry,
                KM_LDR_DATA_TABLE_ENTRY,
                InMemoryOrderLinks
                );

            ProbeForRead(ldrEntry, KM_LDR_ENTRY_PROBE_SIZE, sizeof(PVOID));

            if (ldrEntry->BaseDllName.Buffer != NULL &&
                ldrEntry->BaseDllName.Length > 0) {

                ProbeForRead(
                    ldrEntry->BaseDllName.Buffer,
                    ldrEntry->BaseDllName.Length,
                    sizeof(WCHAR)
                    );

                if (RtlCompareUnicodeString(&ldrEntry->BaseDllName, &ntdllName, TRUE) == 0) {
                    ULONG_PTR baseAddr = (ULONG_PTR)ldrEntry->DllBase;
                    SIZE_T imageSize = ldrEntry->SizeOfImage;

                    //
                    // Validate address is in valid user-mode range
                    //
                    if (baseAddr < NI_MIN_VALID_USER_ADDRESS ||
                        baseAddr > NI_MAX_USER_ADDRESS) {
                        status = STATUS_INVALID_ADDRESS;
                        __leave;
                    }

                    //
                    // Validate size is sane (ntdll is typically 1-4 MB)
                    //
                    if (imageSize == 0 || imageSize > NI_MAX_NTDLL_SIZE) {
                        status = STATUS_INVALID_IMAGE_FORMAT;
                        __leave;
                    }

                    //
                    // Validate base + size doesn't overflow or exceed user range
                    //
                    if (baseAddr + imageSize < baseAddr ||
                        baseAddr + imageSize > NI_MAX_USER_ADDRESS) {
                        status = STATUS_INVALID_ADDRESS;
                        __leave;
                    }

                    *NtdllBase = ldrEntry->DllBase;
                    *NtdllSize = imageSize;
                    found = TRUE;
                    break;
                }
            }

            listEntry = listEntry->Flink;
        }

        status = found ? STATUS_SUCCESS : STATUS_NOT_FOUND;

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);

    return status;
}


static
_Use_decl_annotations_
NTSTATUS
NipReadProcessMemory(
    _In_ HANDLE ProcessId,
    _In_ PVOID SourceAddress,
    _Out_writes_bytes_(Size) PVOID Destination,
    _In_ SIZE_T Size
    )
/*++

Routine Description:

    Safely reads memory from a process's address space.
    Uses SEH to handle faults — MmIsAddressValid is NOT used as it
    is fundamentally racy (TOCTOU) and cannot protect multi-page reads.

--*/
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    KAPC_STATE apcState;

    PAGED_CODE();

    if (Size == 0) {
        return STATUS_SUCCESS;
    }

    //
    // Validate source is in user-mode range
    //
    if ((ULONG_PTR)SourceAddress < NI_MIN_VALID_USER_ADDRESS ||
        (ULONG_PTR)SourceAddress > NI_MAX_USER_ADDRESS ||
        (ULONG_PTR)SourceAddress + Size < (ULONG_PTR)SourceAddress ||
        (ULONG_PTR)SourceAddress + Size > NI_MAX_USER_ADDRESS) {
        return STATUS_INVALID_ADDRESS;
    }

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    KeStackAttachProcess(process, &apcState);

    __try {
        ProbeForRead(SourceAddress, Size, 1);
        RtlCopyMemory(Destination, SourceAddress, Size);
        status = STATUS_SUCCESS;

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);

    return status;
}


static
_Use_decl_annotations_
NTSTATUS
NipGetTextSection(
    _In_ PVOID ModuleBase,
    _In_ SIZE_T ModuleSize,
    _Out_ PVOID* TextBase,
    _Out_ PSIZE_T TextSize,
    _Out_ PULONG_PTR TextRva
    )
/*++

Routine Description:

    Parses PE headers to find the .text section.
    Validates all offsets and sizes against ModuleSize bounds.

--*/
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS64 ntHeaders;
    PIMAGE_SECTION_HEADER sectionHeader;
    ULONG i;

    *TextBase = NULL;
    *TextSize = 0;
    *TextRva = 0;

    if (ModuleSize < sizeof(IMAGE_DOS_HEADER)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    dosHeader = (PIMAGE_DOS_HEADER)ModuleBase;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    //
    // e_lfanew is LONG (signed). Reject negative values and values that
    // would place NT headers before the DOS header ends.
    //
    if (dosHeader->e_lfanew < (LONG)sizeof(IMAGE_DOS_HEADER)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if ((SIZE_T)(ULONG)dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > ModuleSize) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    ntHeaders = (PIMAGE_NT_HEADERS64)((PUCHAR)ModuleBase + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    //
    // Find section headers
    //
    sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    for (i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        SIZE_T sectionEnd;
        SIZE_T effectiveSize;

        if ((PUCHAR)&sectionHeader[i] + sizeof(IMAGE_SECTION_HEADER) >
            (PUCHAR)ModuleBase + ModuleSize) {
            break;
        }

        //
        // Look for .text or first executable code section
        //
        if (RtlCompareMemory(sectionHeader[i].Name, ".text", 5) == 5 ||
            (sectionHeader[i].Characteristics & IMAGE_SCN_CNT_CODE)) {

            ULONG virtualAddress = sectionHeader[i].VirtualAddress;
            ULONG virtualSize = sectionHeader[i].Misc.VirtualSize;
            ULONG rawSize = sectionHeader[i].SizeOfRawData;

            //
            // Use the smaller of VirtualSize and SizeOfRawData to avoid
            // reading uninitialized memory beyond the actual section data
            //
            if (virtualSize == 0) {
                continue;
            }

            effectiveSize = (SIZE_T)min(virtualSize, rawSize);
            if (effectiveSize == 0) {
                effectiveSize = (SIZE_T)virtualSize;
            }

            //
            // Validate section fits within module bounds
            //
            sectionEnd = (SIZE_T)virtualAddress + effectiveSize;
            if (sectionEnd < (SIZE_T)virtualAddress || sectionEnd > ModuleSize) {
                continue;
            }

            *TextRva = virtualAddress;
            *TextSize = effectiveSize;
            *TextBase = (PVOID)((PUCHAR)ModuleBase + virtualAddress);

            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}


static
_Use_decl_annotations_
NTSTATUS
NipParseExportTable(
    _In_ PVOID ModuleBase,
    _In_ SIZE_T ModuleSize,
    _Out_ PVOID* ExportDirectory,
    _Out_ PULONG NumberOfFunctions,
    _Out_ PULONG NumberOfNames,
    _Out_ PULONG* AddressOfFunctions,
    _Out_ PULONG* AddressOfNames,
    _Out_ PUSHORT* AddressOfNameOrdinals
    )
/*++

Routine Description:

    Parses the PE export directory with full bounds checking on all
    array pointers to prevent out-of-bounds reads on malformed PEs.

--*/
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS64 ntHeaders;
    PIMAGE_DATA_DIRECTORY exportDataDir;
    PIMAGE_EXPORT_DIRECTORY exportDir;
    ULONG exportDirRva;
    ULONG exportDirSize;
    SIZE_T arrayEnd;

    *ExportDirectory = NULL;
    *NumberOfFunctions = 0;
    *NumberOfNames = 0;
    *AddressOfFunctions = NULL;
    *AddressOfNames = NULL;
    *AddressOfNameOrdinals = NULL;

    if (ModuleSize < sizeof(IMAGE_DOS_HEADER)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    dosHeader = (PIMAGE_DOS_HEADER)ModuleBase;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (dosHeader->e_lfanew < (LONG)sizeof(IMAGE_DOS_HEADER)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if ((SIZE_T)(ULONG)dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > ModuleSize) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    ntHeaders = (PIMAGE_NT_HEADERS64)((PUCHAR)ModuleBase + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    //
    // Get export directory
    //
    exportDataDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    exportDirRva = exportDataDir->VirtualAddress;
    exportDirSize = exportDataDir->Size;

    if (exportDirRva == 0 || exportDirSize == 0) {
        return STATUS_NOT_FOUND;
    }

    if ((SIZE_T)exportDirRva + sizeof(IMAGE_EXPORT_DIRECTORY) > ModuleSize) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    exportDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ModuleBase + exportDirRva);

    *ExportDirectory = exportDir;
    *NumberOfFunctions = exportDir->NumberOfFunctions;
    *NumberOfNames = exportDir->NumberOfNames;

    //
    // Validate AddressOfFunctions array fits within module
    //
    if (exportDir->AddressOfFunctions != 0) {
        arrayEnd = (SIZE_T)exportDir->AddressOfFunctions +
                   (SIZE_T)exportDir->NumberOfFunctions * sizeof(ULONG);

        if (arrayEnd > ModuleSize || arrayEnd < (SIZE_T)exportDir->AddressOfFunctions) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        *AddressOfFunctions = (PULONG)((PUCHAR)ModuleBase + exportDir->AddressOfFunctions);
    }

    //
    // Validate AddressOfNames array fits within module
    //
    if (exportDir->AddressOfNames != 0) {
        arrayEnd = (SIZE_T)exportDir->AddressOfNames +
                   (SIZE_T)exportDir->NumberOfNames * sizeof(ULONG);

        if (arrayEnd > ModuleSize || arrayEnd < (SIZE_T)exportDir->AddressOfNames) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        *AddressOfNames = (PULONG)((PUCHAR)ModuleBase + exportDir->AddressOfNames);
    }

    //
    // Validate AddressOfNameOrdinals array fits within module
    //
    if (exportDir->AddressOfNameOrdinals != 0) {
        arrayEnd = (SIZE_T)exportDir->AddressOfNameOrdinals +
                   (SIZE_T)exportDir->NumberOfNames * sizeof(USHORT);

        if (arrayEnd > ModuleSize || arrayEnd < (SIZE_T)exportDir->AddressOfNameOrdinals) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        *AddressOfNameOrdinals = (PUSHORT)((PUCHAR)ModuleBase + exportDir->AddressOfNameOrdinals);
    }

    return STATUS_SUCCESS;
}


static
_Use_decl_annotations_
NTSTATUS
NipLookupExportByName(
    _In_ PNI_MONITOR_INTERNAL MonitorInternal,
    _In_ PCSTR FunctionName,
    _Out_ PULONG_PTR FunctionRva,
    _Out_ PUCHAR ExpectedPrologue
    )
/*++

Routine Description:

    Looks up an export by name in the clean NTDLL copy.
    Validates all RVAs and ordinals against module bounds.

--*/
{
    PULONG addressOfNames;
    PUSHORT addressOfOrdinals;
    PULONG addressOfFunctions;
    ULONG i;
    PVOID cleanBase;
    SIZE_T cleanSize;
    SIZE_T nameLen;

    *FunctionRva = 0;
    RtlZeroMemory(ExpectedPrologue, NI_PROLOGUE_SIZE);

    if (MonitorInternal->CleanExports.AddressOfNames == NULL ||
        MonitorInternal->CleanExports.AddressOfFunctions == NULL ||
        MonitorInternal->CleanExports.AddressOfNameOrdinals == NULL) {
        return STATUS_NOT_FOUND;
    }

    cleanBase = MonitorInternal->Monitor.CleanNtdllCopy;
    cleanSize = MonitorInternal->Monitor.CleanNtdllSize;
    addressOfNames = MonitorInternal->CleanExports.AddressOfNames;
    addressOfOrdinals = MonitorInternal->CleanExports.AddressOfNameOrdinals;
    addressOfFunctions = MonitorInternal->CleanExports.AddressOfFunctions;

    //
    // Use bounded length for function name
    //
    nameLen = strnlen(FunctionName, 256);
    if (nameLen == 0 || nameLen >= 256) {
        return STATUS_INVALID_PARAMETER;
    }

    for (i = 0; i < MonitorInternal->CleanExports.NumberOfNames; i++) {
        ULONG nameRva = addressOfNames[i];
        PCSTR exportName;
        USHORT ordinal;
        ULONG functionRva;

        //
        // Validate name RVA points within module and leaves room for at least
        // one character + null terminator
        //
        if ((SIZE_T)nameRva + nameLen + 1 > cleanSize) {
            continue;
        }

        exportName = (PCSTR)((PUCHAR)cleanBase + nameRva);

        if (RtlCompareMemory(exportName, FunctionName, nameLen + 1) == nameLen + 1) {
            //
            // Found it — validate ordinal is within functions array
            //
            ordinal = addressOfOrdinals[i];

            if (ordinal >= MonitorInternal->CleanExports.NumberOfFunctions) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }

            functionRva = addressOfFunctions[ordinal];

            //
            // Validate function RVA is within module
            //
            if ((SIZE_T)functionRva + NI_PROLOGUE_SIZE > cleanSize) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }

            *FunctionRva = functionRva;

            //
            // Copy the prologue bytes (already bounds-checked above)
            //
            RtlCopyMemory(
                ExpectedPrologue,
                (PUCHAR)cleanBase + functionRva,
                NI_PROLOGUE_SIZE
                );

            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}


//=============================================================================
// Internal Functions - Hook Detection
//=============================================================================

static
_Use_decl_annotations_
NI_MODIFICATION
NipDetectHookType(
    _In_ PUCHAR CurrentPrologue,
    _In_ PUCHAR ExpectedPrologue,
    _In_ SIZE_T Size
    )
/*++

Routine Description:

    Detects the type of modification in a function prologue by comparing
    against known hook patterns.

--*/
{
    ULONG expectedSyscall = 0;
    ULONG currentSyscall = 0;
    BOOLEAN expectedIsSyscall;
    BOOLEAN currentIsSyscall;

    //
    // First check if they match exactly
    //
    if (RtlCompareMemory(CurrentPrologue, ExpectedPrologue, Size) == Size) {
        return NiMod_None;
    }

    //
    // Check for JMP rel32 (E9 xx xx xx xx) — most common inline hook
    //
    if (CurrentPrologue[0] == NI_JMP_REL32_OPCODE) {
        return NiMod_HookInstalled;
    }

    //
    // Check for JMP [rip+offset] (FF 25 xx xx xx xx)
    //
    if (CurrentPrologue[0] == NI_JMP_ABS_PREFIX && CurrentPrologue[1] == 0x25) {
        return NiMod_HookInstalled;
    }

    //
    // Check for MOV RAX, imm64; JMP RAX (48 B8 ... FF E0)
    //
    if (Size >= 12 &&
        CurrentPrologue[0] == 0x48 && CurrentPrologue[1] == 0xB8 &&
        CurrentPrologue[10] == 0xFF && CurrentPrologue[11] == 0xE0) {
        return NiMod_HookInstalled;
    }

    //
    // Check for MOV R10, imm64; JMP R10 (49 BA ... 41 FF E2)
    //
    if (Size >= 13 &&
        CurrentPrologue[0] == 0x49 && CurrentPrologue[1] == 0xBA &&
        CurrentPrologue[10] == 0x41 &&
        CurrentPrologue[11] == 0xFF && CurrentPrologue[12] == 0xE2) {
        return NiMod_HookInstalled;
    }

    //
    // Check for PUSH imm64 + RET pattern — only flag as hook if the expected
    // prologue does NOT start with the same PUSH register (reduces false
    // positives from ICF / tail-call optimizations)
    //
    if (Size >= 2 &&
        (CurrentPrologue[0] >= 0x50 && CurrentPrologue[0] <= 0x57) &&
        CurrentPrologue[1] == 0xC3 &&
        !(ExpectedPrologue[0] >= 0x50 && ExpectedPrologue[0] <= 0x57 &&
          ExpectedPrologue[1] == 0xC3)) {
        return NiMod_HookInstalled;
    }

    //
    // Check if this is a syscall stub that has been modified
    //
    expectedIsSyscall = NipIsSyscallStub(ExpectedPrologue, Size, &expectedSyscall);
    currentIsSyscall = NipIsSyscallStub(CurrentPrologue, Size, &currentSyscall);

    if (expectedIsSyscall) {
        if (!currentIsSyscall) {
            //
            // Syscall stub was replaced with something else
            //
            return NiMod_HookInstalled;
        }

        if (expectedSyscall != currentSyscall) {
            //
            // Syscall number was changed
            //
            return NiMod_SyscallStubModified;
        }

        //
        // Syscall stub exists but bytes differ — instruction patch
        //
        if (!NipValidateSyscallStub(CurrentPrologue, ExpectedPrologue, Size)) {
            return NiMod_InstructionPatch;
        }
    }

    //
    // Generic instruction modification
    //
    return NiMod_InstructionPatch;
}


static
_Use_decl_annotations_
BOOLEAN
NipIsSyscallStub(
    _In_ PUCHAR Prologue,
    _In_ SIZE_T Size,
    _Out_opt_ PULONG SyscallNumber
    )
/*++

Routine Description:

    Checks if a prologue represents a syscall stub.

    Expected pattern (x64):
    4C 8B D1        mov r10, rcx
    B8 XX XX XX XX  mov eax, syscall_number
    0F 05           syscall
    C3              ret

--*/
{
    if (Size < 12) {
        return FALSE;
    }

    //
    // Check for mov r10, rcx (4C 8B D1)
    //
    if (Prologue[0] != 0x4C || Prologue[1] != 0x8B || Prologue[2] != 0xD1) {
        return FALSE;
    }

    //
    // Check for mov eax, imm32 (B8)
    //
    if (Prologue[3] != NI_MOV_EAX_IMM32) {
        return FALSE;
    }

    if (SyscallNumber != NULL) {
        *SyscallNumber = *(PULONG)&Prologue[4];
    }

    //
    // Check for syscall (0F 05) - may be at different offsets
    // depending on Windows version
    //
    for (SIZE_T i = 8; i < Size - 1; i++) {
        if (Prologue[i] == 0x0F && Prologue[i + 1] == 0x05) {
            return TRUE;
        }
    }

    return FALSE;
}


static
_Use_decl_annotations_
BOOLEAN
NipValidateSyscallStub(
    _In_ PUCHAR CurrentPrologue,
    _In_ PUCHAR ExpectedPrologue,
    _In_ SIZE_T Size
    )
/*++

Routine Description:

    Validates that a syscall stub's critical bytes are intact.

--*/
{
    //
    // Check mov r10, rcx
    //
    if (CurrentPrologue[0] != ExpectedPrologue[0] ||
        CurrentPrologue[1] != ExpectedPrologue[1] ||
        CurrentPrologue[2] != ExpectedPrologue[2]) {
        return FALSE;
    }

    //
    // Check mov eax opcode
    //
    if (CurrentPrologue[3] != ExpectedPrologue[3]) {
        return FALSE;
    }

    //
    // Check syscall number
    //
    if (RtlCompareMemory(&CurrentPrologue[4], &ExpectedPrologue[4], 4) != 4) {
        return FALSE;
    }

    //
    // Look for syscall instruction in both
    //
    BOOLEAN foundCurrentSyscall = FALSE;
    BOOLEAN foundExpectedSyscall = FALSE;

    for (SIZE_T i = 8; i < Size - 1; i++) {
        if (CurrentPrologue[i] == 0x0F && CurrentPrologue[i + 1] == 0x05) {
            foundCurrentSyscall = TRUE;
        }
        if (ExpectedPrologue[i] == 0x0F && ExpectedPrologue[i + 1] == 0x05) {
            foundExpectedSyscall = TRUE;
        }
    }

    return (foundCurrentSyscall && foundExpectedSyscall);
}


//=============================================================================
// Internal Functions - Process State Management
//=============================================================================

static
_Use_decl_annotations_
PNI_PROCESS_NTDLL
NipFindProcessStateLocked(
    _In_ PNI_MONITOR Monitor,
    _In_ HANDLE ProcessId
    )
/*++

Routine Description:

    Finds an existing process state in the monitor's list.
    CALLER MUST HOLD Monitor->ProcessLock (shared or exclusive).
    Returns pointer valid only while lock is held.

--*/
{
    PLIST_ENTRY entry;
    PNI_PROCESS_NTDLL processState;
    ULONG iterations = 0;

    for (entry = Monitor->ProcessList.Flink;
         entry != &Monitor->ProcessList && iterations < NI_MAX_PROCESSES;
         entry = entry->Flink) {

        iterations++;
        processState = CONTAINING_RECORD(entry, NI_PROCESS_NTDLL, ListEntry);

        if (processState->ProcessId == ProcessId) {
            return processState;
        }
    }

    return NULL;
}


static
_Use_decl_annotations_
VOID
NipFreeProcessState(
    _In_ PNI_MONITOR_INTERNAL MonitorInternal,
    _Inout_ PNI_PROCESS_NTDLL State
    )
/*++

Routine Description:

    Frees a process state and all its function states.
    State must already be removed from the monitor's process list.

--*/
{
    PLIST_ENTRY entry;
    PNI_FUNCTION_STATE functionState;
    LIST_ENTRY toFree;

    InitializeListHead(&toFree);

    //
    // Collect all function states under push lock
    //
    FltAcquirePushLockExclusive(&State->FunctionLock);

    while (!IsListEmpty(&State->FunctionList)) {
        entry = RemoveHeadList(&State->FunctionList);
        InsertTailList(&toFree, entry);
    }

    State->FunctionCount = 0;

    FltReleasePushLock(&State->FunctionLock);

    //
    // Free function states outside of lock
    //
    while (!IsListEmpty(&toFree)) {
        entry = RemoveHeadList(&toFree);
        functionState = CONTAINING_RECORD(entry, NI_FUNCTION_STATE, ListEntry);
        ExFreeToPagedLookasideList(&MonitorInternal->FunctionLookaside, functionState);
    }

    //
    // Free process state
    //
    ExFreeToPagedLookasideList(&MonitorInternal->ProcessLookaside, State);
}


static
_Use_decl_annotations_
NTSTATUS
NipComputeTextSectionHash(
    _In_ HANDLE ProcessId,
    _In_ PVOID NtdllBase,
    _In_ ULONG_PTR TextRva,
    _In_ SIZE_T TextSize,
    _Out_writes_(32) PUCHAR Hash
    )
/*++

Routine Description:

    Computes SHA-256 hash of a process's NTDLL .text section.

--*/
{
    NTSTATUS status;
    PVOID textBuffer = NULL;
    PVOID textAddress;

    PAGED_CODE();

    RtlZeroMemory(Hash, 32);

    if (TextSize == 0 || TextSize > 16 * 1024 * 1024) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // ShadowStrikeComputeSha256 takes ULONG Length — validate no truncation
    //
    if (TextSize > MAXULONG) {
        return STATUS_INTEGER_OVERFLOW;
    }

    //
    // Allocate buffer for .text section
    //
    textBuffer = ShadowStrikeAllocatePoolWithTag(
        PagedPool,
        TextSize,
        NI_POOL_TAG_TEMP
        );

    if (textBuffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Calculate .text address in process
    //
    textAddress = (PVOID)((ULONG_PTR)NtdllBase + TextRva);

    //
    // Read .text section from process
    //
    status = NipReadProcessMemory(ProcessId, textAddress, textBuffer, TextSize);

    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreePoolWithTag(textBuffer, NI_POOL_TAG_TEMP);
        return status;
    }

    //
    // Compute hash (3 arguments: Buffer, Length, Hash)
    //
    status = ShadowStrikeComputeSha256(textBuffer, (ULONG)TextSize, Hash);

    ShadowStrikeFreePoolWithTag(textBuffer, NI_POOL_TAG_TEMP);

    return status;
}


//=============================================================================
// Internal Functions - Disk-based NTDLL Capture
//=============================================================================

static
_Use_decl_annotations_
NTSTATUS
NipReadNtdllFromDisk(
    _Out_ PVOID* Buffer,
    _Out_ PSIZE_T BufferSize
    )
/*++

Routine Description:

    Reads ntdll.dll from the known system path on disk.
    This provides a trusted, unhookable baseline for integrity comparison.

    Uses ZwOpenFile / ZwReadFile at PASSIVE_LEVEL.

--*/
{
    NTSTATUS status;
    UNICODE_STRING filePath;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE fileHandle = NULL;
    FILE_STANDARD_INFORMATION fileInfo;
    PVOID buffer = NULL;
    LARGE_INTEGER fileSize;
    LARGE_INTEGER byteOffset;

    PAGED_CODE();

    *Buffer = NULL;
    *BufferSize = 0;

    RtlInitUnicodeString(&filePath, L"\\SystemRoot\\System32\\ntdll.dll");

    InitializeObjectAttributes(
        &objAttr,
        &filePath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
        );

    status = ZwOpenFile(
        &fileHandle,
        FILE_READ_DATA | SYNCHRONIZE,
        &objAttr,
        &ioStatusBlock,
        FILE_SHARE_READ,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
        );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Query file size
    //
    status = ZwQueryInformationFile(
        fileHandle,
        &ioStatusBlock,
        &fileInfo,
        sizeof(fileInfo),
        FileStandardInformation
        );

    if (!NT_SUCCESS(status)) {
        ZwClose(fileHandle);
        return status;
    }

    fileSize = fileInfo.EndOfFile;

    //
    // Validate file size is sane
    //
    if (fileSize.QuadPart == 0 || (ULONGLONG)fileSize.QuadPart > NI_MAX_NTDLL_SIZE) {
        ZwClose(fileHandle);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    //
    // Allocate buffer (paged pool — only accessed at PASSIVE_LEVEL)
    //
    buffer = ShadowStrikeAllocatePoolWithTag(
        PagedPool,
        (SIZE_T)fileSize.QuadPart,
        NI_POOL_TAG_NTDLL
        );

    if (buffer == NULL) {
        ZwClose(fileHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Read the entire file
    //
    byteOffset.QuadPart = 0;

    status = ZwReadFile(
        fileHandle,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        buffer,
        (ULONG)fileSize.QuadPart,
        &byteOffset,
        NULL
        );

    ZwClose(fileHandle);

    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreePoolWithTag(buffer, NI_POOL_TAG_NTDLL);
        return status;
    }

    //
    // Verify we read the expected amount
    //
    if (ioStatusBlock.Information != (ULONG_PTR)fileSize.QuadPart) {
        ShadowStrikeFreePoolWithTag(buffer, NI_POOL_TAG_NTDLL);
        return STATUS_FILE_CORRUPT_ERROR;
    }

    *Buffer = buffer;
    *BufferSize = (SIZE_T)fileSize.QuadPart;

    return STATUS_SUCCESS;
}

