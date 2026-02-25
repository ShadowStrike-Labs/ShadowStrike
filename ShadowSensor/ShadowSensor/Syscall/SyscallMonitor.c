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
/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE SYSCALL MONITOR
 * ============================================================================
 *
 * @file SyscallMonitor.c
 * @brief Syscall monitoring orchestration layer implementation.
 *
 * This module coordinates the syscall monitoring subsystem by delegating
 * to SyscallTable, DirectSyscallDetector, and SyscallHooks modules.
 * It manages per-process syscall context, NTDLL integrity verification,
 * call stack analysis, and behavioral event emission.
 *
 * Thread Safety:
 * - Global state protected by EX_PUSH_LOCK with critical region.
 * - Process contexts are reference-counted with deferred deletion.
 * - All statistics use interlocked operations.
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "SyscallMonitor.h"
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/ProcessUtils.h"
#include "../Utilities/HashUtils.h"
#include "../Behavioral/BehaviorEngine.h"
#include "../../Shared/KernelProcessTypes.h"
#include <ntimage.h>
#include <ntstrsafe.h>

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define SC_MONITOR_MAGIC                    0x53634D6F  // 'ScMo'

#define SC_CONTEXT_LOOKASIDE_DEPTH          128
#define SC_EVENT_LOOKASIDE_DEPTH            256

#define SC_MAX_ARGUMENT_COUNT               8

#define SC_USER_SPACE_LIMIT                 0x00007FFFFFFFFFFF
#define SC_MIN_USER_ADDRESS                 0x10000

#define SC_MAX_FUNCTION_NAME_LENGTH         63

// Allowlisted function names for ScMonitorRestoreNtdllFunction
static const CHAR* ScpAllowedRestoreFunctions[] = {
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtWriteVirtualMemory",
    "NtCreateThreadEx",
    "NtMapViewOfSection",
    "NtQueueApcThread",
    "NtSetContextThread",
    "NtCreateSection",
    "NtOpenProcess",
    "NtSuspendThread",
    "NtResumeThread",
    "NtReadVirtualMemory",
    "NtCreateFile",
    "NtDeviceIoControlFile",
    NULL
};

// ============================================================================
// PRIVATE FUNCTION PROTOTYPES
// ============================================================================

static VOID
ScpAcquireReference(VOID);

static VOID
ScpReleaseReference(VOID);

static PSC_PROCESS_CONTEXT
ScpAllocateProcessContext(VOID);

static VOID
ScpFreeProcessContext(
    _In_ PSC_PROCESS_CONTEXT Context
);

static PSC_PROCESS_CONTEXT
ScpFindProcessContextLocked(
    _In_ UINT32 ProcessId
);

static NTSTATUS
ScpCreateProcessContext(
    _In_ UINT32 ProcessId,
    _Out_ PSC_PROCESS_CONTEXT* Context
);

static VOID
ScpAddSuspiciousCaller(
    _Inout_ PSC_PROCESS_CONTEXT Context,
    _In_ UINT64 CallerAddress
);

static BOOLEAN
ScpIsAddressInRange(
    _In_ UINT64 Address,
    _In_ UINT64 Base,
    _In_ UINT64 Size
);

static BOOLEAN
ScpValidateUserAddress(
    _In_ UINT64 Address
);

static NTSTATUS
ScpSafeReadUserMemory(
    _In_ PVOID SourceAddress,
    _Out_writes_bytes_(Length) PVOID Destination,
    _In_ SIZE_T Length
);

static BOOLEAN
ScpIsFunctionNameAllowed(
    _In_z_ PCSTR FunctionName
);

static VOID
ScpEmitEvasionEvent(
    _In_ UINT32 ProcessId,
    _In_ BEHAVIOR_EVENT_TYPE EventType,
    _In_ EVASION_TECHNIQUE Technique,
    _In_ UINT32 ThreatScore,
    _In_ UINT64 TargetAddress
);

static NTSTATUS
ScpPopulateNtdllInfo(
    _Inout_ PSC_PROCESS_CONTEXT Context
);

// ============================================================================
// PAGE ALLOCATION
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, ScMonitorInitialize)
#pragma alloc_text(PAGE, ScMonitorShutdown)
#pragma alloc_text(PAGE, ScMonitorSetEnabled)
#pragma alloc_text(PAGE, ScMonitorAnalyzeSyscall)
#pragma alloc_text(PAGE, ScMonitorIsFromNtdll)
#pragma alloc_text(PAGE, ScMonitorDetectHeavensGate)
#pragma alloc_text(PAGE, ScMonitorAnalyzeCallStack)
#pragma alloc_text(PAGE, ScMonitorVerifyNtdllIntegrity)
#pragma alloc_text(PAGE, ScMonitorGetNtdllHooks)
#pragma alloc_text(PAGE, ScMonitorRestoreNtdllFunction)
#pragma alloc_text(PAGE, ScMonitorGetProcessContext)
#pragma alloc_text(PAGE, ScMonitorReleaseProcessContext)
#pragma alloc_text(PAGE, ScMonitorRemoveProcessContext)
#pragma alloc_text(PAGE, ScMonitorGetSyscallName)
#pragma alloc_text(PAGE, ScMonitorGetSyscallNumber)
#pragma alloc_text(PAGE, ScMonitorGetSyscallDefinition)
#pragma alloc_text(PAGE, ScMonitorGetStatistics)
#pragma alloc_text(PAGE, ScMonitorGetProcessStats)
#endif

// ============================================================================
// GLOBAL STATE
// ============================================================================

static SYSCALL_MONITOR_GLOBALS g_ScState;

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ScMonitorInitialize(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();

    if (g_ScState.Initialized) {
        return STATUS_ALREADY_INITIALIZED;
    }

    RtlZeroMemory(&g_ScState, sizeof(g_ScState));

    //
    // Initialize process context list and lock
    //
    InitializeListHead(&g_ScState.ProcessContextList);
    ExInitializePushLock(&g_ScState.ProcessLock);

    //
    // Initialize known good caller list and lock
    //
    InitializeListHead(&g_ScState.KnownGoodCallers);
    ExInitializePushLock(&g_ScState.CallerCacheLock);

    //
    // Initialize lookaside list for process contexts
    //
    ExInitializeNPagedLookasideList(
        &g_ScState.ContextLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(SC_PROCESS_CONTEXT),
        SC_POOL_TAG_GENERAL,
        SC_CONTEXT_LOOKASIDE_DEPTH
    );
    g_ScState.ContextLookasideInitialized = TRUE;

    //
    // Initialize lookaside list for event contexts
    //
    ExInitializeNPagedLookasideList(
        &g_ScState.EventLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(SYSCALL_CALL_CONTEXT),
        SC_POOL_TAG_EVENT,
        SC_EVENT_LOOKASIDE_DEPTH
    );
    g_ScState.EventLookasideInitialized = TRUE;

    //
    // Initialize syscall table subsystem
    //
    status = SstInitialize(&g_ScState.SyscallTableHandle);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Table is auto-populated from build-matched definitions.
    // No manual ntdll parsing needed.
    //

    //
    // Initialize direct syscall detector
    //
    status = DsdInitialize(&g_ScState.DirectSyscallDetector);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Initialize reference counting and shutdown coordination
    //
    g_ScState.ReferenceCount = 1;
    g_ScState.ShuttingDown = 0;
    KeInitializeEvent(&g_ScState.ShutdownEvent, NotificationEvent, FALSE);

    //
    // Set magic and mark initialized
    //
    g_ScState.Magic = SC_MONITOR_MAGIC;
    g_ScState.Enabled = TRUE;
    g_ScState.Initialized = TRUE;

    return STATUS_SUCCESS;

Cleanup:
    //
    // Reverse partial initialization
    //
    if (g_ScState.DirectSyscallDetector != NULL) {
        DsdShutdown(g_ScState.DirectSyscallDetector);
        g_ScState.DirectSyscallDetector = NULL;
    }

    if (g_ScState.SyscallTableHandle != NULL) {
        SstShutdown(g_ScState.SyscallTableHandle);
        g_ScState.SyscallTableHandle = NULL;
    }

    if (g_ScState.EventLookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_ScState.EventLookaside);
        g_ScState.EventLookasideInitialized = FALSE;
    }

    if (g_ScState.ContextLookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_ScState.ContextLookaside);
        g_ScState.ContextLookasideInitialized = FALSE;
    }

    RtlZeroMemory(&g_ScState, sizeof(g_ScState));

    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ScMonitorShutdown(VOID)
{
    PLIST_ENTRY entry;
    PSC_PROCESS_CONTEXT context;
    PSC_KNOWN_GOOD_CALLER caller;
    LARGE_INTEGER timeout;

    PAGED_CODE();

    if (!g_ScState.Initialized) {
        return;
    }

    if (g_ScState.Magic != SC_MONITOR_MAGIC) {
        return;
    }

    //
    // Signal shutdown
    //
    InterlockedExchange(&g_ScState.ShuttingDown, 1);
    g_ScState.Enabled = FALSE;

    //
    // Wait for outstanding references to drain (max 5 seconds)
    //
    timeout.QuadPart = -50000000;  // 5 seconds in 100ns units
    if (g_ScState.ReferenceCount > 1) {
        KeWaitForSingleObject(
            &g_ScState.ShutdownEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout
        );
    }

    //
    // Shutdown direct syscall detector
    //
    if (g_ScState.DirectSyscallDetector != NULL) {
        DsdShutdown(g_ScState.DirectSyscallDetector);
        g_ScState.DirectSyscallDetector = NULL;
    }

    //
    // Shutdown syscall table
    //
    if (g_ScState.SyscallTableHandle != NULL) {
        SstShutdown(g_ScState.SyscallTableHandle);
        g_ScState.SyscallTableHandle = NULL;
    }

    //
    // Free all process contexts
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ScState.ProcessLock);

    while (!IsListEmpty(&g_ScState.ProcessContextList)) {
        entry = RemoveHeadList(&g_ScState.ProcessContextList);
        context = CONTAINING_RECORD(entry, SC_PROCESS_CONTEXT, ListEntry);
        InitializeListHead(&context->ListEntry);
        context->Removed = TRUE;

        //
        // Force-release regardless of refcount during shutdown
        //
        if (context->ProcessObject != NULL) {
            ObDereferenceObject(context->ProcessObject);
            context->ProcessObject = NULL;
        }

        ScpFreeProcessContext(context);
    }

    g_ScState.ProcessContextCount = 0;

    ExReleasePushLockExclusive(&g_ScState.ProcessLock);
    KeLeaveCriticalRegion();

    //
    // Free known good caller cache
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ScState.CallerCacheLock);

    while (!IsListEmpty(&g_ScState.KnownGoodCallers)) {
        entry = RemoveHeadList(&g_ScState.KnownGoodCallers);
        caller = CONTAINING_RECORD(entry, SC_KNOWN_GOOD_CALLER, ListEntry);
        ShadowStrikeFreePoolWithTag(caller, SC_POOL_TAG_CACHE);
    }

    g_ScState.KnownGoodCallerCount = 0;

    ExReleasePushLockExclusive(&g_ScState.CallerCacheLock);
    KeLeaveCriticalRegion();

    //
    // Delete lookaside lists
    //
    if (g_ScState.EventLookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_ScState.EventLookaside);
        g_ScState.EventLookasideInitialized = FALSE;
    }

    if (g_ScState.ContextLookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_ScState.ContextLookaside);
        g_ScState.ContextLookasideInitialized = FALSE;
    }

    //
    // Clear state
    //
    g_ScState.Magic = 0;
    g_ScState.Initialized = FALSE;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ScMonitorSetEnabled(
    _In_ BOOLEAN Enable
)
{
    PAGED_CODE();

    if (!g_ScState.Initialized || g_ScState.Magic != SC_MONITOR_MAGIC) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (g_ScState.ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    g_ScState.Enabled = Enable;

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - SYSCALL ANALYSIS
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ScMonitorAnalyzeSyscall(
    _In_ UINT32 ProcessId,
    _In_ UINT32 ThreadId,
    _In_ UINT32 SyscallNumber,
    _In_ UINT64 ReturnAddress,
    _In_reads_opt_(ArgumentCount) PUINT64 Arguments,
    _In_ UINT32 ArgumentCount,
    _Out_opt_ PSYSCALL_CALL_CONTEXT Context
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PSC_PROCESS_CONTEXT procCtx = NULL;
    BOOLEAN isFromNtdll = FALSE;
    BOOLEAN isFromWoW64Ntdll = FALSE;
    UINT32 detectionFlags = 0;
    UINT32 threatScore = 0;
    UINT32 argCount;
    PDSD_DETECTION dsdDetection = NULL;

    PAGED_CODE();

    //
    // Initialize output
    //
    if (Context != NULL) {
        RtlZeroMemory(Context, sizeof(SYSCALL_CALL_CONTEXT));
    }

    //
    // Validate state
    //
    if (!g_ScState.Initialized || g_ScState.Magic != SC_MONITOR_MAGIC) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (!g_ScState.Enabled) {
        return STATUS_SUCCESS;
    }

    if (g_ScState.ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Cap argument count
    //
    argCount = (ArgumentCount > SC_MAX_ARGUMENT_COUNT)
        ? SC_MAX_ARGUMENT_COUNT
        : ArgumentCount;

    //
    // Validate return address is in user space
    //
    if (!ScpValidateUserAddress(ReturnAddress)) {
        return STATUS_INVALID_ADDRESS;
    }

    ScpAcquireReference();

    //
    // Update global statistics
    //
    InterlockedIncrement64(&g_ScState.TotalSyscallsMonitored);

    //
    // Get or create process context
    //
    status = ScMonitorGetProcessContext(ProcessId, &procCtx);
    if (!NT_SUCCESS(status)) {
        ScpReleaseReference();
        return status;
    }

    //
    // Update per-process statistics
    //
    InterlockedIncrement64(&procCtx->TotalSyscalls);

    //
    // Check if return address is from ntdll
    //
    isFromNtdll = ScpIsAddressInRange(
        ReturnAddress,
        procCtx->NtdllBase,
        procCtx->NtdllSize
    );

    if (!isFromNtdll && procCtx->IsWoW64) {
        isFromWoW64Ntdll = ScpIsAddressInRange(
            ReturnAddress,
            procCtx->Wow64NtdllBase,
            procCtx->Wow64NtdllSize
        );
    }

    //
    // Direct syscall detection
    //
    if (!isFromNtdll && !isFromWoW64Ntdll) {
        detectionFlags |= SC_DETECT_DIRECT_SYSCALL;
        InterlockedIncrement64(&procCtx->DirectSyscalls);
        InterlockedIncrement64(&g_ScState.TotalDirectSyscalls);
        threatScore += 60;

        procCtx->Flags |= SC_PROC_FLAG_DIRECT_SYSCALLS;
    }

    //
    // Delegate to DirectSyscallDetector for deeper analysis
    //
    if (g_ScState.DirectSyscallDetector != NULL &&
        (detectionFlags & SC_DETECT_DIRECT_SYSCALL)) {

        NTSTATUS dsdStatus = DsdAnalyzeSyscall(
            g_ScState.DirectSyscallDetector,
            ULongToHandle(ProcessId),
            ULongToHandle(ThreadId),
            (PVOID)(ULONG_PTR)ReturnAddress,
            SyscallNumber,
            &dsdDetection
        );

        if (NT_SUCCESS(dsdStatus) && dsdDetection != NULL) {
            if (dsdDetection->Technique == DsdTechnique_HeavensGate) {
                detectionFlags |= SC_DETECT_HEAVENS_GATE;
                InterlockedIncrement64(&g_ScState.TotalHeavensGate);
                procCtx->Flags |= SC_PROC_FLAG_HEAVENS_GATE;
                threatScore += 30;
            }

            if (!dsdDetection->CallFromKnownModule) {
                detectionFlags |= SC_DETECT_UNBACKED_CALLER;
                detectionFlags |= SC_DETECT_SHELLCODE_CALLER;
                threatScore += 25;
            }

            if (dsdDetection->SuspicionScore > 0) {
                threatScore = max(threatScore, dsdDetection->SuspicionScore);
            }

            DsdFreeDetection(dsdDetection);
            dsdDetection = NULL;
        }
    }

    //
    // Track suspicious callers
    //
    if (detectionFlags != 0) {
        InterlockedIncrement64(&procCtx->SuspiciousSyscalls);
        InterlockedIncrement64(&g_ScState.TotalSuspiciousCalls);

        ScpAddSuspiciousCaller(procCtx, ReturnAddress);

        //
        // Mark process as high risk if threshold exceeded
        //
        if (procCtx->DirectSyscalls > 5) {
            procCtx->Flags |= SC_PROC_FLAG_HIGH_RISK;
        }
    }

    //
    // Populate output context if requested
    //
    if (Context != NULL) {
        Context->SyscallNumber = SyscallNumber;
        KeQuerySystemTimePrecise((PLARGE_INTEGER)&Context->Timestamp);
        Context->ProcessId = ProcessId;
        Context->ThreadId = ThreadId;
        Context->ReturnAddress = ReturnAddress;
        Context->IsFromNtdll = isFromNtdll || isFromWoW64Ntdll;
        Context->IsFromWoW64 = procCtx->IsWoW64;
        Context->ThreatScore = threatScore;
        Context->DetectionFlags = detectionFlags;

        if (Arguments != NULL && argCount > 0) {
            __try {
                ProbeForRead(
                    Arguments,
                    argCount * sizeof(UINT64),
                    sizeof(UINT64)
                );
                RtlCopyMemory(
                    Context->Arguments,
                    Arguments,
                    argCount * sizeof(UINT64)
                );
                Context->ArgumentCount = argCount;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                Context->ArgumentCount = 0;
            }
        }
    }

    //
    // Emit behavioral events for significant detections
    //
    if (detectionFlags & SC_DETECT_DIRECT_SYSCALL) {
        ScpEmitEvasionEvent(
            ProcessId,
            BehaviorEvent_DirectSyscall,
            Evasion_DirectSyscall,
            threatScore,
            ReturnAddress
        );
    }

    if (detectionFlags & SC_DETECT_HEAVENS_GATE) {
        ScpEmitEvasionEvent(
            ProcessId,
            BehaviorEvent_HeavensGate,
            Evasion_HeavensGate,
            threatScore,
            ReturnAddress
        );
    }

    ScMonitorReleaseProcessContext(procCtx);
    ScpReleaseReference();

    //
    // Block if threat score is critical
    //
    if (threatScore >= 90) {
        InterlockedIncrement64(&g_ScState.TotalBlocked);
        return STATUS_ACCESS_DENIED;
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
ScMonitorIsFromNtdll(
    _In_ UINT32 ProcessId,
    _In_ UINT64 ReturnAddress,
    _In_ BOOLEAN IsWoW64
)
{
    PSC_PROCESS_CONTEXT procCtx = NULL;
    BOOLEAN result = FALSE;
    NTSTATUS status;

    PAGED_CODE();

    if (!g_ScState.Initialized || g_ScState.ShuttingDown) {
        return FALSE;
    }

    status = ScMonitorGetProcessContext(ProcessId, &procCtx);
    if (!NT_SUCCESS(status) || procCtx == NULL) {
        return FALSE;
    }

    if (IsWoW64 && procCtx->IsWoW64) {
        result = ScpIsAddressInRange(
            ReturnAddress,
            procCtx->Wow64NtdllBase,
            procCtx->Wow64NtdllSize
        );
    } else {
        result = ScpIsAddressInRange(
            ReturnAddress,
            procCtx->NtdllBase,
            procCtx->NtdllSize
        );
    }

    ScMonitorReleaseProcessContext(procCtx);

    return result;
}

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ScMonitorDetectHeavensGate(
    _In_ UINT32 ProcessId,
    _In_ PSYSCALL_CALL_CONTEXT Context
)
{
    PSC_PROCESS_CONTEXT procCtx = NULL;
    BOOLEAN detected = FALSE;
    NTSTATUS status;

    PAGED_CODE();

    if (Context == NULL) {
        return FALSE;
    }

    if (!g_ScState.Initialized || g_ScState.ShuttingDown) {
        return FALSE;
    }

    status = ScMonitorGetProcessContext(ProcessId, &procCtx);
    if (!NT_SUCCESS(status) || procCtx == NULL) {
        return FALSE;
    }

    //
    // Heaven's Gate: 32-bit process invoking 64-bit syscalls
    // Indicators:
    // 1. Process is WoW64 but syscall return is NOT from Wow64 ntdll
    // 2. Return address is in 64-bit address space from a 32-bit process
    //
    if (procCtx->IsWoW64) {
        BOOLEAN inWow64Ntdll = ScpIsAddressInRange(
            Context->ReturnAddress,
            procCtx->Wow64NtdllBase,
            procCtx->Wow64NtdllSize
        );

        BOOLEAN in64BitNtdll = ScpIsAddressInRange(
            Context->ReturnAddress,
            procCtx->NtdllBase,
            procCtx->NtdllSize
        );

        if (!inWow64Ntdll && !in64BitNtdll) {
            //
            // Syscall not from either ntdll - direct syscall from WoW64 process.
            // If the return address is in 64-bit space, strong Heaven's Gate signal.
            //
            if (Context->ReturnAddress > 0xFFFFFFFF) {
                detected = TRUE;
            }
        }

        //
        // Also delegate to the DSD detector for instruction-level analysis
        //
        if (!detected && g_ScState.DirectSyscallDetector != NULL) {
            BOOLEAN isValid = TRUE;
            DSD_TECHNIQUE technique = DsdTechnique_None;

            status = DsdValidateCallstack(
                g_ScState.DirectSyscallDetector,
                ULongToHandle(ProcessId),
                ULongToHandle(Context->ThreadId),
                &isValid,
                &technique
            );

            if (NT_SUCCESS(status) && technique == DsdTechnique_HeavensGate) {
                detected = TRUE;
            }
        }
    }

    if (detected) {
        Context->DetectionFlags |= SC_DETECT_HEAVENS_GATE;
        Context->ThreatScore = max(Context->ThreatScore, 85);
        procCtx->Flags |= SC_PROC_FLAG_HEAVENS_GATE;
        InterlockedIncrement64(&g_ScState.TotalHeavensGate);

        ScpEmitEvasionEvent(
            ProcessId,
            BehaviorEvent_HeavensGate,
            Evasion_HeavensGate,
            Context->ThreatScore,
            Context->ReturnAddress
        );
    }

    ScMonitorReleaseProcessContext(procCtx);

    return detected;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ScMonitorAnalyzeCallStack(
    _In_ UINT32 ProcessId,
    _In_ UINT32 ThreadId,
    _Out_writes_to_(MaxFrames, *FrameCount) PUINT64 StackFrames,
    _In_ UINT32 MaxFrames,
    _Out_ PUINT32 FrameCount,
    _Out_ PUINT32 AnomalyFlags
)
{
    NTSTATUS status;
    PSC_PROCESS_CONTEXT procCtx = NULL;
    BOOLEAN callstackValid = TRUE;
    DSD_TECHNIQUE technique = DsdTechnique_None;
    ULONG i;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (StackFrames == NULL || FrameCount == NULL || AnomalyFlags == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *FrameCount = 0;
    *AnomalyFlags = 0;

    if (MaxFrames == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(StackFrames, MaxFrames * sizeof(UINT64));

    if (!g_ScState.Initialized || g_ScState.ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    ScpAcquireReference();

    //
    // Delegate call stack validation to the DSD detector
    //
    if (g_ScState.DirectSyscallDetector != NULL) {
        status = DsdValidateCallstack(
            g_ScState.DirectSyscallDetector,
            ULongToHandle(ProcessId),
            ULongToHandle(ThreadId),
            &callstackValid,
            &technique
        );

        if (!NT_SUCCESS(status)) {
            ScpReleaseReference();
            return status;
        }
    }

    //
    // Capture frames using RtlCaptureStackBackTrace
    // Maximum supported by the API is 63
    //
    {
        ULONG capturedFrames;
        ULONG maxCapture = (MaxFrames > 62) ? 62 : MaxFrames;

        capturedFrames = RtlCaptureStackBackTrace(
            0,
            maxCapture,
            (PVOID*)StackFrames,
            NULL
        );

        *FrameCount = capturedFrames;
    }

    //
    // Analyze captured frames for anomalies
    //
    status = ScMonitorGetProcessContext(ProcessId, &procCtx);
    if (NT_SUCCESS(status) && procCtx != NULL) {
        BOOLEAN hasNtdllFrame = FALSE;

        for (i = 0; i < *FrameCount; i++) {
            UINT64 frame = StackFrames[i];

            if (frame == 0) {
                continue;
            }

            //
            // Check if frame is in NTDLL
            //
            if (ScpIsAddressInRange(frame, procCtx->NtdllBase, procCtx->NtdllSize) ||
                (procCtx->IsWoW64 &&
                 ScpIsAddressInRange(frame, procCtx->Wow64NtdllBase, procCtx->Wow64NtdllSize))) {
                hasNtdllFrame = TRUE;
            }

            //
            // Check for return to unbacked/suspicious memory
            // User-space addresses outside the typical DLL load range are suspicious
            //
            if (frame > SC_MIN_USER_ADDRESS && frame <= SC_USER_SPACE_LIMIT) {
                if (frame < 0x00007FF000000000 && frame > 0x80000000) {
                    *AnomalyFlags |= SC_STACK_ANOMALY_UNBACKED;
                }
            }
        }

        if (!hasNtdllFrame && *FrameCount > 0) {
            *AnomalyFlags |= SC_STACK_ANOMALY_UNBACKED;
        }

        ScMonitorReleaseProcessContext(procCtx);
    }

    //
    // Map DSD technique to anomaly flags
    //
    if (!callstackValid) {
        *AnomalyFlags |= SC_STACK_ANOMALY_CORRUPTED;
    }

    if (technique == DsdTechnique_HeavensGate) {
        *AnomalyFlags |= SC_STACK_ANOMALY_PIVOT;
    }

    ScpReleaseReference();

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - NTDLL INTEGRITY
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ScMonitorVerifyNtdllIntegrity(
    _In_ UINT32 ProcessId,
    _Out_ PNTDLL_INTEGRITY_STATE IntegrityState
)
{
    NTSTATUS status;
    PSC_PROCESS_CONTEXT procCtx = NULL;
    PEPROCESS process = NULL;
    KAPC_STATE apcState;
    UCHAR currentHash[32];

    PAGED_CODE();

    if (IntegrityState == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(IntegrityState, sizeof(NTDLL_INTEGRITY_STATE));

    if (!g_ScState.Initialized || g_ScState.ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    ScpAcquireReference();

    //
    // Get process context
    //
    status = ScMonitorGetProcessContext(ProcessId, &procCtx);
    if (!NT_SUCCESS(status)) {
        ScpReleaseReference();
        return status;
    }

    if (procCtx->NtdllBase == 0 || procCtx->NtdllSize == 0) {
        ScpPopulateNtdllInfo(procCtx);

        if (procCtx->NtdllBase == 0) {
            ScMonitorReleaseProcessContext(procCtx);
            ScpReleaseReference();
            return STATUS_NOT_FOUND;
        }
    }

    IntegrityState->NtdllBase = procCtx->NtdllBase;
    IntegrityState->NtdllSize = procCtx->NtdllSize;

    //
    // Attach to the target process to read its NTDLL .text section
    //
    status = ShadowStrikeGetProcessObject(
        ULongToHandle(ProcessId),
        &process
    );

    if (!NT_SUCCESS(status)) {
        ScMonitorReleaseProcessContext(procCtx);
        ScpReleaseReference();
        return status;
    }

    KeStackAttachProcess(process, &apcState);

    __try {
        PVOID ntdllBase = (PVOID)(ULONG_PTR)procCtx->NtdllBase;
        ULONG ntdllSize = (ULONG)procCtx->NtdllSize;
        PIMAGE_DOS_HEADER dosHeader;
        PIMAGE_NT_HEADERS ntHeaders;
        PIMAGE_SECTION_HEADER sectionHeader;
        USHORT sectionCount;
        USHORT idx;

        ProbeForRead(ntdllBase, sizeof(IMAGE_DOS_HEADER), sizeof(USHORT));
        dosHeader = (PIMAGE_DOS_HEADER)ntdllBase;

        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            status = STATUS_INVALID_IMAGE_FORMAT;
            __leave;
        }

        //
        // Validate e_lfanew bounds before use
        //
        if (dosHeader->e_lfanew < (LONG)sizeof(IMAGE_DOS_HEADER) ||
            (ULONG)dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > ntdllSize) {
            status = STATUS_INVALID_IMAGE_FORMAT;
            __leave;
        }

        ntHeaders = (PIMAGE_NT_HEADERS)(
            (PUCHAR)ntdllBase + dosHeader->e_lfanew
        );
        ProbeForRead(ntHeaders, sizeof(IMAGE_NT_HEADERS), sizeof(ULONG));

        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            status = STATUS_INVALID_IMAGE_FORMAT;
            __leave;
        }

        sectionCount = ntHeaders->FileHeader.NumberOfSections;
        if (sectionCount > 96) {
            status = STATUS_INVALID_IMAGE_FORMAT;
            __leave;
        }

        sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        ProbeForRead(
            sectionHeader,
            sectionCount * sizeof(IMAGE_SECTION_HEADER),
            sizeof(ULONG)
        );

        for (idx = 0; idx < sectionCount; idx++) {
            if (sectionHeader[idx].Name[0] == '.' &&
                sectionHeader[idx].Name[1] == 't' &&
                sectionHeader[idx].Name[2] == 'e' &&
                sectionHeader[idx].Name[3] == 'x' &&
                sectionHeader[idx].Name[4] == 't') {

                ULONG textRva = sectionHeader[idx].VirtualAddress;
                ULONG textSize = sectionHeader[idx].Misc.VirtualSize;
                PVOID textBase;

                //
                // Validate .text section bounds within module
                //
                if (textRva == 0 || textSize == 0 ||
                    textRva + textSize > ntdllSize) {
                    status = STATUS_INVALID_IMAGE_FORMAT;
                    __leave;
                }

                textBase = (PUCHAR)ntdllBase + textRva;

                //
                // Cap to 16MB to prevent excessive hashing
                //
                if (textSize > 0x1000000) {
                    textSize = 0x1000000;
                }

                IntegrityState->TextSectionBase =
                    (UINT64)(ULONG_PTR)textBase;
                IntegrityState->TextSectionSize = textSize;

                ProbeForRead(textBase, textSize, 1);

                status = ShadowStrikeComputeSha256(
                    textBase,
                    textSize,
                    currentHash
                );

                if (NT_SUCCESS(status)) {
                    RtlCopyMemory(
                        IntegrityState->TextSectionHash,
                        currentHash,
                        32
                    );

                    if (g_ScState.SystemNtdllHash[0] != 0) {
                        IntegrityState->IsIntact = (BOOLEAN)RtlEqualMemory(
                            currentHash,
                            g_ScState.SystemNtdllHash,
                            32
                        );

                        if (!IntegrityState->IsIntact) {
                            IntegrityState->IsHooked = TRUE;
                            procCtx->Flags |= SC_PROC_FLAG_NTDLL_MODIFIED;

                            RtlCopyMemory(
                                &procCtx->NtdllIntegrity,
                                IntegrityState,
                                sizeof(NTDLL_INTEGRITY_STATE)
                            );
                        }
                    } else {
                        //
                        // First call - establish baseline hash
                        //
                        RtlCopyMemory(
                            g_ScState.SystemNtdllHash,
                            currentHash,
                            32
                        );
                        IntegrityState->IsIntact = TRUE;
                    }
                }

                break;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);

    KeQuerySystemTimePrecise(
        (PLARGE_INTEGER)&IntegrityState->LastVerifyTime
    );

    ScMonitorReleaseProcessContext(procCtx);
    ScpReleaseReference();

    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ScMonitorGetNtdllHooks(
    _In_ UINT32 ProcessId,
    _Out_writes_to_(MaxFunctions, *FunctionCount) PHOOKED_FUNCTION_ENTRY HookedFunctions,
    _In_ UINT32 MaxFunctions,
    _Out_ PUINT32 FunctionCount
)
{
    NTSTATUS status;
    PSC_PROCESS_CONTEXT procCtx = NULL;
    PEPROCESS process = NULL;
    KAPC_STATE apcState;
    UINT32 hookCount = 0;

    PAGED_CODE();

    if (HookedFunctions == NULL || FunctionCount == NULL || MaxFunctions == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *FunctionCount = 0;
    RtlZeroMemory(
        HookedFunctions,
        MaxFunctions * sizeof(HOOKED_FUNCTION_ENTRY)
    );

    if (!g_ScState.Initialized || g_ScState.ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    ScpAcquireReference();

    status = ScMonitorGetProcessContext(ProcessId, &procCtx);
    if (!NT_SUCCESS(status)) {
        ScpReleaseReference();
        return status;
    }

    if (procCtx->NtdllBase == 0) {
        ScMonitorReleaseProcessContext(procCtx);
        ScpReleaseReference();
        return STATUS_NOT_FOUND;
    }

    status = ShadowStrikeGetProcessObject(
        ULongToHandle(ProcessId),
        &process
    );
    if (!NT_SUCCESS(status)) {
        ScMonitorReleaseProcessContext(procCtx);
        ScpReleaseReference();
        return status;
    }

    KeStackAttachProcess(process, &apcState);

    __try {
        PVOID ntdllBase = (PVOID)(ULONG_PTR)procCtx->NtdllBase;
        ULONG ntdllSize = (ULONG)procCtx->NtdllSize;
        PIMAGE_DOS_HEADER dosHeader;
        PIMAGE_NT_HEADERS ntHeaders;
        PIMAGE_EXPORT_DIRECTORY exportDir;
        PULONG functionRvas;
        PULONG nameRvas;
        PUSHORT ordinals;
        ULONG exportRva;
        ULONG exportSize;
        ULONG numFunctions;
        ULONG numNames;
        ULONG idx;

        ProbeForRead(ntdllBase, sizeof(IMAGE_DOS_HEADER), sizeof(USHORT));
        dosHeader = (PIMAGE_DOS_HEADER)ntdllBase;

        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            status = STATUS_INVALID_IMAGE_FORMAT;
            __leave;
        }

        //
        // Validate e_lfanew bounds before use
        //
        if (dosHeader->e_lfanew < (LONG)sizeof(IMAGE_DOS_HEADER) ||
            (ULONG)dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > ntdllSize) {
            status = STATUS_INVALID_IMAGE_FORMAT;
            __leave;
        }

        ntHeaders = (PIMAGE_NT_HEADERS)(
            (PUCHAR)ntdllBase + dosHeader->e_lfanew
        );
        ProbeForRead(ntHeaders, sizeof(IMAGE_NT_HEADERS), sizeof(ULONG));

        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            status = STATUS_INVALID_IMAGE_FORMAT;
            __leave;
        }

        exportRva = ntHeaders->OptionalHeader
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exportSize = ntHeaders->OptionalHeader
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

        if (exportRva == 0 || exportSize == 0) {
            status = STATUS_NOT_FOUND;
            __leave;
        }

        //
        // Validate export directory is within module bounds
        //
        if (exportRva + sizeof(IMAGE_EXPORT_DIRECTORY) > ntdllSize) {
            status = STATUS_INVALID_IMAGE_FORMAT;
            __leave;
        }

        exportDir = (PIMAGE_EXPORT_DIRECTORY)(
            (PUCHAR)ntdllBase + exportRva
        );
        ProbeForRead(exportDir, sizeof(IMAGE_EXPORT_DIRECTORY), sizeof(ULONG));

        numFunctions = exportDir->NumberOfFunctions;
        numNames = exportDir->NumberOfNames;

        if (numFunctions == 0 || numNames == 0 || numNames > 16384 ||
            numFunctions > 16384) {
            status = STATUS_NOT_FOUND;
            __leave;
        }

        //
        // Validate export table array RVAs are within module bounds
        //
        if (exportDir->AddressOfFunctions + numFunctions * sizeof(ULONG) > ntdllSize ||
            exportDir->AddressOfNames + numNames * sizeof(ULONG) > ntdllSize ||
            exportDir->AddressOfNameOrdinals + numNames * sizeof(USHORT) > ntdllSize) {
            status = STATUS_INVALID_IMAGE_FORMAT;
            __leave;
        }

        functionRvas = (PULONG)(
            (PUCHAR)ntdllBase + exportDir->AddressOfFunctions
        );
        nameRvas = (PULONG)(
            (PUCHAR)ntdllBase + exportDir->AddressOfNames
        );
        ordinals = (PUSHORT)(
            (PUCHAR)ntdllBase + exportDir->AddressOfNameOrdinals
        );

        ProbeForRead(
            functionRvas,
            numFunctions * sizeof(ULONG),
            sizeof(ULONG)
        );
        ProbeForRead(
            nameRvas,
            numNames * sizeof(ULONG),
            sizeof(ULONG)
        );
        ProbeForRead(
            ordinals,
            numNames * sizeof(USHORT),
            sizeof(USHORT)
        );

        for (idx = 0; idx < numNames && hookCount < MaxFunctions; idx++) {
            PCSTR funcName;
            ULONG funcRva;
            PVOID funcAddr;
            UCHAR prologue[16];
            BOOLEAN isHooked = FALSE;
            HOOK_TYPE hookType = HookType_None;

            funcName = (PCSTR)((PUCHAR)ntdllBase + nameRvas[idx]);

            //
            // Validate name RVA is within module bounds.
            // Probe enough bytes for typical Nt* function names (max ~64 chars).
            //
            if (nameRvas[idx] >= ntdllSize) {
                continue;
            }
            {
                ULONG maxNameProbe = min(SC_MAX_FUNCTION_NAME_LENGTH + 1,
                                         ntdllSize - nameRvas[idx]);
                ProbeForRead((PVOID)funcName, maxNameProbe, 1);
            }

            //
            // Only check Nt* and Zw* functions (syscall stubs)
            //
            if ((funcName[0] != 'N' || funcName[1] != 't') &&
                (funcName[0] != 'Z' || funcName[1] != 'w')) {
                continue;
            }

            if (ordinals[idx] >= numFunctions) {
                continue;
            }

            funcRva = functionRvas[ordinals[idx]];

            //
            // Validate function RVA is within module bounds
            //
            if (funcRva + sizeof(prologue) > ntdllSize) {
                continue;
            }

            funcAddr = (PUCHAR)ntdllBase + funcRva;

            ProbeForRead(funcAddr, sizeof(prologue), 1);
            RtlCopyMemory(prologue, funcAddr, sizeof(prologue));

            //
            // A clean ntdll syscall stub starts with:
            // mov r10, rcx  (4C 8B D1)  or
            // mov eax, imm32 (B8 xx xx xx xx)
            // Anything else at the entry point indicates a hook.
            //
            if (prologue[0] == 0xE9) {
                isHooked = TRUE;
                hookType = HookType_InlineJmp;
            } else if (prologue[0] == 0xE8) {
                isHooked = TRUE;
                hookType = HookType_InlineCall;
            } else if (prologue[0] == 0xFF && prologue[1] == 0x25) {
                isHooked = TRUE;
                hookType = HookType_Trampoline;
            } else if (prologue[0] == 0x68) {
                isHooked = TRUE;
                hookType = HookType_InlineJmp;
            } else if (prologue[0] != 0x4C && prologue[0] != 0xB8 &&
                       prologue[0] != 0x48 && prologue[0] != 0x90) {
                isHooked = TRUE;
                hookType = HookType_InlineJmp;
            }

            if (isHooked) {
                PHOOKED_FUNCTION_ENTRY entry = &HookedFunctions[hookCount];

                RtlStringCchCopyA(
                    entry->FunctionName,
                    sizeof(entry->FunctionName),
                    funcName
                );
                entry->OriginalAddress = (UINT64)(ULONG_PTR)funcAddr;
                entry->CurrentAddress = (UINT64)(ULONG_PTR)funcAddr;
                entry->HookType = hookType;

                if (hookType == HookType_InlineJmp && prologue[0] == 0xE9) {
                    LONG disp = *(PLONG)(&prologue[1]);
                    entry->HookDestination =
                        (UINT64)((ULONG_PTR)funcAddr + 5 + disp);
                }

                hookCount++;
            }
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);

    *FunctionCount = hookCount;

    ScMonitorReleaseProcessContext(procCtx);
    ScpReleaseReference();

    return NT_SUCCESS(status) ? STATUS_SUCCESS : status;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ScMonitorRestoreNtdllFunction(
    _In_ UINT32 ProcessId,
    _In_z_ PCSTR FunctionName
)
{
    NTSTATUS status;
    SIZE_T nameLen;

    PAGED_CODE();

    if (FunctionName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_ScState.Initialized || g_ScState.ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Validate function name length
    //
    status = RtlStringCchLengthA(
        FunctionName,
        SC_MAX_FUNCTION_NAME_LENGTH + 1,
        &nameLen
    );
    if (!NT_SUCCESS(status) || nameLen == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate against allowlist — only whitelisted Nt* functions may be restored
    //
    if (!ScpIsFunctionNameAllowed(FunctionName)) {
        return STATUS_ACCESS_DENIED;
    }

    //
    // Verify integrity state and emit telemetry.
    // The actual byte-level restore requires a verified clean ntdll copy
    // validated against SystemNtdllHash. The integrity check below detects
    // the hook and reports it; full byte restore is gated on having a
    // cryptographically-verified clean reference image.
    //
    {
        NTDLL_INTEGRITY_STATE integrity;

        status = ScMonitorVerifyNtdllIntegrity(ProcessId, &integrity);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (integrity.IsIntact) {
            return STATUS_SUCCESS;
        }

        ScpEmitEvasionEvent(
            ProcessId,
            BehaviorEvent_NtdllUnhooking,
            Evasion_NtdllUnhooking,
            70,
            integrity.TextSectionBase
        );
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - PROCESS CONTEXT
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ScMonitorGetProcessContext(
    _In_ UINT32 ProcessId,
    _Outptr_ PSC_PROCESS_CONTEXT* Context
)
{
    PSC_PROCESS_CONTEXT found = NULL;

    PAGED_CODE();

    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Context = NULL;

    if (!g_ScState.Initialized || g_ScState.ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Search under shared lock first (fast path)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_ScState.ProcessLock);

    found = ScpFindProcessContextLocked(ProcessId);
    if (found != NULL && !found->Removed) {
        InterlockedIncrement(&found->RefCount);
        *Context = found;
    }

    ExReleasePushLockShared(&g_ScState.ProcessLock);
    KeLeaveCriticalRegion();

    if (*Context != NULL) {
        return STATUS_SUCCESS;
    }

    //
    // Not found - create under exclusive lock
    //
    return ScpCreateProcessContext(ProcessId, Context);
}

_IRQL_requires_max_(APC_LEVEL)
VOID
ScMonitorReleaseProcessContext(
    _In_ PSC_PROCESS_CONTEXT Context
)
{
    LONG newRefCount;

    PAGED_CODE();

    if (Context == NULL) {
        return;
    }

    newRefCount = InterlockedDecrement(&Context->RefCount);

    if (newRefCount < 0) {
        //
        // Double-release detected - bug in caller. Repair the refcount.
        //
        InterlockedIncrement(&Context->RefCount);
        return;
    }

    if (newRefCount == 0 && Context->Removed) {
        //
        // Last reference on a removed context - perform deferred free
        //
        if (Context->ProcessObject != NULL) {
            ObDereferenceObject(Context->ProcessObject);
            Context->ProcessObject = NULL;
        }

        ScpFreeProcessContext(Context);
    }
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ScMonitorRemoveProcessContext(
    _In_ UINT32 ProcessId
)
{
    PSC_PROCESS_CONTEXT context = NULL;

    PAGED_CODE();

    if (!g_ScState.Initialized) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ScState.ProcessLock);

    context = ScpFindProcessContextLocked(ProcessId);
    if (context != NULL && !context->Removed) {
        RemoveEntryList(&context->ListEntry);
        InitializeListHead(&context->ListEntry);
        context->Removed = TRUE;
        InterlockedDecrement(&g_ScState.ProcessContextCount);
    }

    ExReleasePushLockExclusive(&g_ScState.ProcessLock);
    KeLeaveCriticalRegion();

    //
    // Release the creation reference. If no other holders exist,
    // this triggers the deferred free via ScMonitorReleaseProcessContext.
    //
    if (context != NULL && context->Removed) {
        ScMonitorReleaseProcessContext(context);
    }
}

// ============================================================================
// PUBLIC API - SYSCALL TABLE (DELEGATION)
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ScMonitorGetSyscallName(
    _In_ UINT32 SyscallNumber,
    _Out_writes_z_(NameSize) PSTR Name,
    _In_ UINT32 NameSize
)
{
    SST_ENTRY_INFO info;
    NTSTATUS status;

    PAGED_CODE();

    if (Name == NULL || NameSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    Name[0] = '\0';

    if (!g_ScState.Initialized || g_ScState.SyscallTableHandle == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    status = SstLookupByNumber(
        g_ScState.SyscallTableHandle,
        SyscallNumber,
        &info
    );
    if (!NT_SUCCESS(status)) {
        return STATUS_NOT_FOUND;
    }

    return RtlStringCchCopyA(Name, NameSize, info.Name);
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ScMonitorGetSyscallNumber(
    _In_z_ PCSTR Name,
    _Out_ PUINT32 SyscallNumber
)
{
    SST_ENTRY_INFO info;
    NTSTATUS status;

    PAGED_CODE();

    if (Name == NULL || SyscallNumber == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *SyscallNumber = 0;

    if (!g_ScState.Initialized || g_ScState.SyscallTableHandle == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    status = SstLookupByName(g_ScState.SyscallTableHandle, Name, &info);
    if (!NT_SUCCESS(status)) {
        return STATUS_NOT_FOUND;
    }

    *SyscallNumber = info.Number;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ScMonitorGetSyscallDefinition(
    _In_ UINT32 SyscallNumber,
    _Out_ PSYSCALL_DEFINITION Definition
)
{
    SST_ENTRY_INFO info;
    NTSTATUS status;

    PAGED_CODE();

    if (Definition == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Definition, sizeof(SYSCALL_DEFINITION));

    if (!g_ScState.Initialized || g_ScState.SyscallTableHandle == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    status = SstLookupByNumber(
        g_ScState.SyscallTableHandle,
        SyscallNumber,
        &info
    );
    if (!NT_SUCCESS(status)) {
        return STATUS_NOT_FOUND;
    }

    //
    // Map SST_ENTRY_INFO to SYSCALL_DEFINITION.
    // The new SyscallTable already provides category and risk data,
    // so we use it directly instead of heuristic name matching.
    //
    Definition->SyscallNumber = info.Number;
    RtlStringCchCopyA(
        Definition->SyscallName,
        sizeof(Definition->SyscallName),
        info.Name
    );
    Definition->ArgumentCount = info.ArgumentCount;

    //
    // Map SST_CATEGORY to SYSCALL_CATEGORY (enums are compatible)
    //
    switch (info.Category) {
    case SstCategory_Process:   Definition->Category = SyscallCategory_Process; break;
    case SstCategory_Thread:    Definition->Category = SyscallCategory_Thread; break;
    case SstCategory_Memory:    Definition->Category = SyscallCategory_Memory; break;
    case SstCategory_File:      Definition->Category = SyscallCategory_File; break;
    case SstCategory_Registry:  Definition->Category = SyscallCategory_Registry; break;
    case SstCategory_Object:    Definition->Category = SyscallCategory_Object; break;
    case SstCategory_Security:  Definition->Category = SyscallCategory_Security; break;
    case SstCategory_System:    Definition->Category = SyscallCategory_System; break;
    case SstCategory_Network:   Definition->Category = SyscallCategory_Network; break;
    default:                    Definition->Category = SyscallCategory_Unknown; break;
    }

    //
    // Map SST_RISK_LEVEL to SYSCALL_RISK_CATEGORY
    //
    switch (info.RiskLevel) {
    case SstRisk_Low:       Definition->RiskCategory = SyscallRisk_Low; break;
    case SstRisk_Medium:    Definition->RiskCategory = SyscallRisk_Medium; break;
    case SstRisk_High:      Definition->RiskCategory = SyscallRisk_High; break;
    case SstRisk_Critical:  Definition->RiskCategory = SyscallRisk_Critical; break;
    default:                Definition->RiskCategory = SyscallRisk_None; break;
    }

    //
    // Map SST_FLAG_* to SC_FLAG_* (compatible where applicable)
    //
    if (info.Flags & SST_FLAG_INJECTION_RISK) {
        Definition->Flags |= SC_FLAG_INJECTION_RISK;
    }
    if (info.Flags & SST_FLAG_CREDENTIAL_RISK) {
        Definition->Flags |= SC_FLAG_CREDENTIAL_RISK;
    }
    if (info.Flags & SST_FLAG_EVASION_RISK) {
        Definition->Flags |= SC_FLAG_EVASION_RISK;
    }
    if (info.Flags & SST_FLAG_CROSS_PROCESS) {
        Definition->Flags |= SC_FLAG_CROSS_PROCESS;
    }
    if (info.Flags & SST_FLAG_REQUIRES_ADMIN) {
        Definition->Flags |= SC_FLAG_REQUIRES_ELEVATION;
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - STATISTICS
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
ScMonitorGetStatistics(
    _Out_ PSYSCALL_MONITOR_STATISTICS Stats
)
{
    PAGED_CODE();

    if (Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Stats, sizeof(SYSCALL_MONITOR_STATISTICS));

    if (!g_ScState.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    Stats->Initialized = g_ScState.Initialized;
    Stats->Enabled = g_ScState.Enabled;
    Stats->ProcessContextCount = (UINT32)g_ScState.ProcessContextCount;
    Stats->KnownGoodCallerCount = (UINT32)g_ScState.KnownGoodCallerCount;
    Stats->TotalSyscallsMonitored = g_ScState.TotalSyscallsMonitored;
    Stats->TotalDirectSyscalls = g_ScState.TotalDirectSyscalls;
    Stats->TotalHeavensGate = g_ScState.TotalHeavensGate;
    Stats->TotalSuspiciousCalls = g_ScState.TotalSuspiciousCalls;
    Stats->TotalBlocked = g_ScState.TotalBlocked;

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ScMonitorGetProcessStats(
    _In_ UINT32 ProcessId,
    _Out_ PUINT64 TotalSyscalls,
    _Out_ PUINT64 DirectSyscalls,
    _Out_ PUINT64 SuspiciousSyscalls
)
{
    NTSTATUS status;
    PSC_PROCESS_CONTEXT procCtx = NULL;

    PAGED_CODE();

    if (TotalSyscalls == NULL || DirectSyscalls == NULL ||
        SuspiciousSyscalls == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *TotalSyscalls = 0;
    *DirectSyscalls = 0;
    *SuspiciousSyscalls = 0;

    if (!g_ScState.Initialized || g_ScState.ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    status = ScMonitorGetProcessContext(ProcessId, &procCtx);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *TotalSyscalls = (UINT64)procCtx->TotalSyscalls;
    *DirectSyscalls = (UINT64)procCtx->DirectSyscalls;
    *SuspiciousSyscalls = (UINT64)procCtx->SuspiciousSyscalls;

    ScMonitorReleaseProcessContext(procCtx);

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - REFERENCE COUNTING
// ============================================================================

static VOID
ScpAcquireReference(VOID)
{
    InterlockedIncrement(&g_ScState.ReferenceCount);
}

static VOID
ScpReleaseReference(VOID)
{
    LONG newCount = InterlockedDecrement(&g_ScState.ReferenceCount);

    if (newCount == 0 && g_ScState.ShuttingDown) {
        KeSetEvent(&g_ScState.ShutdownEvent, IO_NO_INCREMENT, FALSE);
    }
}

// ============================================================================
// PRIVATE IMPLEMENTATION - PROCESS CONTEXT MANAGEMENT
// ============================================================================

static PSC_PROCESS_CONTEXT
ScpAllocateProcessContext(VOID)
{
    PSC_PROCESS_CONTEXT context = NULL;

    if (g_ScState.ContextLookasideInitialized) {
        context = (PSC_PROCESS_CONTEXT)ExAllocateFromNPagedLookasideList(
            &g_ScState.ContextLookaside
        );
    }

    if (context == NULL) {
        context = (PSC_PROCESS_CONTEXT)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(SC_PROCESS_CONTEXT),
            SC_POOL_TAG_GENERAL
        );
    }

    if (context != NULL) {
        RtlZeroMemory(context, sizeof(SC_PROCESS_CONTEXT));
    }

    return context;
}

static VOID
ScpFreeProcessContext(
    _In_ PSC_PROCESS_CONTEXT Context
)
{
    if (Context == NULL) {
        return;
    }

    if (g_ScState.ContextLookasideInitialized) {
        ExFreeToNPagedLookasideList(&g_ScState.ContextLookaside, Context);
    } else {
        ShadowStrikeFreePoolWithTag(Context, SC_POOL_TAG_GENERAL);
    }
}

static PSC_PROCESS_CONTEXT
ScpFindProcessContextLocked(
    _In_ UINT32 ProcessId
)
{
    PLIST_ENTRY entry;
    PSC_PROCESS_CONTEXT context;

    for (entry = g_ScState.ProcessContextList.Flink;
         entry != &g_ScState.ProcessContextList;
         entry = entry->Flink) {

        context = CONTAINING_RECORD(entry, SC_PROCESS_CONTEXT, ListEntry);

        if (context->ProcessId == ProcessId) {
            return context;
        }
    }

    return NULL;
}

static NTSTATUS
ScpCreateProcessContext(
    _In_ UINT32 ProcessId,
    _Out_ PSC_PROCESS_CONTEXT* Context
)
{
    PSC_PROCESS_CONTEXT newContext = NULL;
    PSC_PROCESS_CONTEXT existing = NULL;
    PEPROCESS process = NULL;
    NTSTATUS status;

    *Context = NULL;

    //
    // Enforce maximum context count to prevent unbounded growth
    //
    if ((ULONG)g_ScState.ProcessContextCount >= SC_MAX_PROCESS_CONTEXTS) {
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Get EPROCESS (ObReferenceObject'd by ShadowStrikeGetProcessObject)
    //
    status = ShadowStrikeGetProcessObject(
        ULongToHandle(ProcessId),
        &process
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    newContext = ScpAllocateProcessContext();
    if (newContext == NULL) {
        ObDereferenceObject(process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize the context
    //
    InitializeListHead(&newContext->ListEntry);
    newContext->ProcessId = ProcessId;
    newContext->ProcessObject = process;  // Transfer ObReference to context
    newContext->IsWoW64 = ShadowStrikeIsProcessWow64(process);
    newContext->Removed = FALSE;
    newContext->RefCount = 2;  // 1 for list ownership, 1 for caller
    newContext->Flags = SC_PROC_FLAG_MONITORED;

    KeQuerySystemTimePrecise((PLARGE_INTEGER)&newContext->ProcessCreateTime);

    //
    // Populate NTDLL info
    //
    ScpPopulateNtdllInfo(newContext);

    //
    // Insert under exclusive lock, checking for race with another creator
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ScState.ProcessLock);

    existing = ScpFindProcessContextLocked(ProcessId);
    if (existing != NULL && !existing->Removed) {
        //
        // Another thread created it first - use the existing one
        //
        InterlockedIncrement(&existing->RefCount);
        *Context = existing;

        ExReleasePushLockExclusive(&g_ScState.ProcessLock);
        KeLeaveCriticalRegion();

        //
        // Free our redundant allocation
        //
        ObDereferenceObject(newContext->ProcessObject);
        newContext->ProcessObject = NULL;
        ScpFreeProcessContext(newContext);

        return STATUS_SUCCESS;
    }

    InsertTailList(&g_ScState.ProcessContextList, &newContext->ListEntry);
    InterlockedIncrement(&g_ScState.ProcessContextCount);
    *Context = newContext;

    ExReleasePushLockExclusive(&g_ScState.ProcessLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

static VOID
ScpAddSuspiciousCaller(
    _Inout_ PSC_PROCESS_CONTEXT Context,
    _In_ UINT64 CallerAddress
)
{
    UINT32 index;

    //
    // Atomically claim a slot; wraps automatically, no overflow.
    // Benign race on the array element write is acceptable —
    // worst case is a single overwritten address, which is fine
    // for a diagnostic circular buffer.
    //
    index = (UINT32)InterlockedIncrement((PLONG)&Context->SuspiciousCallerCount) - 1;
    Context->SuspiciousCallers[index % SC_MAX_SUSPICIOUS_CALLERS] = CallerAddress;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - ADDRESS HELPERS
// ============================================================================

static BOOLEAN
ScpIsAddressInRange(
    _In_ UINT64 Address,
    _In_ UINT64 Base,
    _In_ UINT64 Size
)
{
    if (Base == 0 || Size == 0) {
        return FALSE;
    }

    //
    // Overflow-safe range check: Address >= Base && (Address - Base) < Size
    //
    return (Address >= Base && (Address - Base) < Size);
}

static BOOLEAN
ScpValidateUserAddress(
    _In_ UINT64 Address
)
{
    if (Address == 0) {
        return FALSE;
    }

    if (Address < SC_MIN_USER_ADDRESS) {
        return FALSE;
    }

    if (Address > SC_USER_SPACE_LIMIT) {
        return FALSE;
    }

    return TRUE;
}

static NTSTATUS
ScpSafeReadUserMemory(
    _In_ PVOID SourceAddress,
    _Out_writes_bytes_(Length) PVOID Destination,
    _In_ SIZE_T Length
)
{
    NTSTATUS status = STATUS_SUCCESS;

    __try {
        ProbeForRead(SourceAddress, Length, 1);
        RtlCopyMemory(Destination, SourceAddress, Length);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    return status;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - SECURITY HELPERS
// ============================================================================

static BOOLEAN
ScpIsFunctionNameAllowed(
    _In_z_ PCSTR FunctionName
)
{
    ULONG idx;

    for (idx = 0; ScpAllowedRestoreFunctions[idx] != NULL; idx++) {
        if (strcmp(FunctionName, ScpAllowedRestoreFunctions[idx]) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

static VOID
ScpEmitEvasionEvent(
    _In_ UINT32 ProcessId,
    _In_ BEHAVIOR_EVENT_TYPE EventType,
    _In_ EVASION_TECHNIQUE Technique,
    _In_ UINT32 ThreatScore,
    _In_ UINT64 TargetAddress
)
{
    BEHAVIOR_EVASION_EVENT evasionEvent;
    BEHAVIOR_RESPONSE_ACTION response = BehaviorResponse_Allow;

    RtlZeroMemory(&evasionEvent, sizeof(evasionEvent));

    evasionEvent.Header.Size = sizeof(BEHAVIOR_EVASION_EVENT);
    evasionEvent.Header.Version = 1;
    evasionEvent.Header.EventType = EventType;
    evasionEvent.Header.Category = BehaviorCategory_DefenseEvasion;
    evasionEvent.Header.ThreatScore = ThreatScore;
    evasionEvent.Header.CorrelationId.ProcessId = ProcessId;
    KeQuerySystemTimePrecise(
        (PLARGE_INTEGER)&evasionEvent.Header.RawTimestamp
    );

    if (ThreatScore >= 80) {
        evasionEvent.Header.Severity = ThreatSeverity_High;
        evasionEvent.Header.Flags |= BEHAVIOR_FLAG_HIGH_CONFIDENCE;
    } else if (ThreatScore >= 50) {
        evasionEvent.Header.Severity = ThreatSeverity_Medium;
    } else {
        evasionEvent.Header.Severity = ThreatSeverity_Low;
    }

    evasionEvent.Process.ProcessId = ProcessId;
    evasionEvent.EvasionTechnique = (UINT32)Technique;
    evasionEvent.TargetAddress = TargetAddress;

    //
    // Non-blocking submission to avoid stalling the caller
    //
    BeEngineSubmitEvent(
        EventType,
        BehaviorCategory_DefenseEvasion,
        ProcessId,
        &evasionEvent,
        sizeof(evasionEvent),
        ThreatScore,
        FALSE,
        &response
    );
}

// ============================================================================
// PRIVATE IMPLEMENTATION - NTDLL INFO POPULATION
// ============================================================================

static NTSTATUS
ScpPopulateNtdllInfo(
    _Inout_ PSC_PROCESS_CONTEXT Context
)
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    KAPC_STATE apcState;
    PKM_PEB kmPeb = NULL;

    if (Context == NULL || Context->ProcessObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    process = Context->ProcessObject;

    kmPeb = (PKM_PEB)PsGetProcessPeb(process);
    if (kmPeb == NULL) {
        return STATUS_NOT_FOUND;
    }

    KeStackAttachProcess(process, &apcState);

    __try {
        PKM_PEB_LDR_DATA ldr;
        PLIST_ENTRY moduleList;
        PLIST_ENTRY entry;
        ULONG walkCount = 0;

        ProbeForRead(kmPeb, KM_PEB_PROBE_SIZE, sizeof(PVOID));
        ldr = kmPeb->Ldr;

        if (ldr == NULL) {
            status = STATUS_NOT_FOUND;
            __leave;
        }

        ProbeForRead(ldr, KM_PEB_LDR_PROBE_SIZE, sizeof(PVOID));
        moduleList = &ldr->InLoadOrderModuleList;

        //
        // Walk loaded module list looking for ntdll.dll.
        // Cap iterations to prevent infinite loops on corrupted lists.
        //
        for (entry = moduleList->Flink;
             entry != moduleList && walkCount < KM_MAX_MODULE_WALK_COUNT;
             entry = entry->Flink, walkCount++) {

            PKM_LDR_DATA_TABLE_ENTRY moduleEntry;
            UNICODE_STRING ntdllName;

            ProbeForRead(entry, sizeof(LIST_ENTRY), sizeof(PVOID));
            moduleEntry = CONTAINING_RECORD(
                entry,
                KM_LDR_DATA_TABLE_ENTRY,
                InLoadOrderLinks
            );
            ProbeForRead(moduleEntry, KM_LDR_ENTRY_PROBE_SIZE, sizeof(PVOID));

            if (moduleEntry->BaseDllName.Buffer == NULL ||
                moduleEntry->BaseDllName.Length == 0) {
                continue;
            }

            ProbeForRead(
                moduleEntry->BaseDllName.Buffer,
                moduleEntry->BaseDllName.Length,
                sizeof(WCHAR)
            );

            RtlInitUnicodeString(&ntdllName, L"ntdll.dll");

            if (RtlEqualUnicodeString(
                    &moduleEntry->BaseDllName,
                    &ntdllName,
                    TRUE)) {

                Context->NtdllBase =
                    (UINT64)(ULONG_PTR)moduleEntry->DllBase;
                Context->NtdllSize =
                    (UINT64)moduleEntry->SizeOfImage;
                break;
            }
        }

        //
        // For WoW64 processes, find the second ntdll instance (32-bit)
        //
        if (Context->IsWoW64 && Context->NtdllBase != 0) {
            walkCount = 0;
            for (entry = moduleList->Flink;
                 entry != moduleList && walkCount < KM_MAX_MODULE_WALK_COUNT;
                 entry = entry->Flink, walkCount++) {

                PKM_LDR_DATA_TABLE_ENTRY moduleEntry;
                UNICODE_STRING ntdllName;

                ProbeForRead(entry, sizeof(LIST_ENTRY), sizeof(PVOID));
                moduleEntry = CONTAINING_RECORD(
                    entry,
                    KM_LDR_DATA_TABLE_ENTRY,
                    InLoadOrderLinks
                );
                ProbeForRead(
                    moduleEntry,
                    KM_LDR_ENTRY_PROBE_SIZE,
                    sizeof(PVOID)
                );

                if (moduleEntry->BaseDllName.Buffer == NULL ||
                    moduleEntry->BaseDllName.Length == 0) {
                    continue;
                }

                ProbeForRead(
                    moduleEntry->BaseDllName.Buffer,
                    moduleEntry->BaseDllName.Length,
                    sizeof(WCHAR)
                );

                RtlInitUnicodeString(&ntdllName, L"ntdll.dll");

                if (RtlEqualUnicodeString(
                        &moduleEntry->BaseDllName,
                        &ntdllName,
                        TRUE)) {

                    UINT64 base =
                        (UINT64)(ULONG_PTR)moduleEntry->DllBase;

                    if (base != Context->NtdllBase) {
                        Context->Wow64NtdllBase = base;
                        Context->Wow64NtdllSize =
                            (UINT64)moduleEntry->SizeOfImage;
                        break;
                    }
                }
            }
        }

        status = STATUS_SUCCESS;

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    KeUnstackDetachProcess(&apcState);

    return status;
}