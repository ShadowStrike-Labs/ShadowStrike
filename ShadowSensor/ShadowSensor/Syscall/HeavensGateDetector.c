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
===============================================================================
ShadowStrike NGAV - HEAVEN'S GATE DETECTOR IMPLEMENTATION
===============================================================================

@file HeavensGateDetector.c
@brief Enterprise-grade Heaven's Gate (WoW64 abuse) detection for kernel EDR.

This module provides comprehensive detection of 32-to-64 bit transition abuse:
- Heaven's Gate detection (manual CS segment switching)
- Hell's Gate detection (dynamic SSN resolution from clean ntdll)
- Halo's Gate detection (neighbor syscall walking)
- Legitimate WoW64 transition validation
- Syscall origin verification
- Pattern-based shellcode detection

Implementation Features:
- Per-process WoW64 context tracking with reference counting
- Known good transition address caching
- Syscall number correlation with transition patterns
- IRQL-safe lock-free statistics
- Lookaside lists for high-frequency allocations
- Asynchronous notification callbacks at PASSIVE_LEVEL
- DPC-safe cleanup via work queue deferral
- Deep-copy transition records to prevent use-after-free

Detection Techniques Covered:
- T1106: Native API (direct syscall abuse)
- T1055: Process Injection (WoW64 abuse for injection)
- T1562: Impair Defenses (security product bypass)
- T1027: Obfuscated Files (encoded syscall stubs)

@author ShadowStrike Security Team
@version 2.1.0 (Enterprise Edition)
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#include "HeavensGateDetector.h"
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/ProcessUtils.h"
#include "../Sync/WorkQueue.h"
#include "../Tracing/WppConfig.h"
#include "../../Shared/KernelProcessTypes.h"
#include <ntstrsafe.h>

//
// TraceEvents is a WPP-generated macro. Until WPP preprocessing is enabled
// in the build system, provide a no-op fallback to allow compilation.
//
#ifndef TraceEvents
#define TraceEvents(Level, Flags, Msg, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, \
        "[ShadowStrike][HGD] " Msg "\n", ##__VA_ARGS__)
#endif

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, HgdInitialize)
#pragma alloc_text(PAGE, HgdShutdown)
#pragma alloc_text(PAGE, HgdRefreshWow64Addresses)
#pragma alloc_text(PAGE, HgdAnalyzeTransition)
#pragma alloc_text(PAGE, HgdIsLegitimateWow64)
#pragma alloc_text(PAGE, HgdDetectSyscallOrigin)
#pragma alloc_text(PAGE, HgdGetTransitions)
#pragma alloc_text(PAGE, HgdGetProcessFlags)
#pragma alloc_text(PAGE, HgdAddKnownGoodAddress)
#pragma alloc_text(PAGE, HgdRemoveProcessContext)
#pragma alloc_text(PAGE, HgdRegisterCallback)
#pragma alloc_text(PAGE, HgdUnregisterCallback)
#endif

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

#define HGD_SIGNATURE                   'DGHH'
#define HGD_MAX_TRANSITIONS             4096
#define HGD_MAX_PROCESS_CONTEXTS        1024
#define HGD_MAX_CALLBACKS               16
#define HGD_TRANSITION_TIMEOUT_MS       60000   // 1 minute retention
#define HGD_CLEANUP_INTERVAL_MS         30000   // 30 second cleanup

//
// x64 code segment selectors
//
#define HGD_CS_SEGMENT_32BIT            0x23    // WoW64 32-bit CS
#define HGD_CS_SEGMENT_64BIT            0x33    // Native 64-bit CS

//
// Heaven's Gate instruction patterns
//
#define HGD_PATTERN_JMP_FAR             0xEA    // JMP FAR ptr16:32
#define HGD_PATTERN_CALL_FAR            0x9A    // CALL FAR ptr16:32
#define HGD_PATTERN_RETF                0xCB    // RETF
#define HGD_PATTERN_IRETD               0xCF    // IRETD

//
// Suspicion score thresholds
//
#define HGD_SUSPICION_LOW               25
#define HGD_SUSPICION_MEDIUM            50
#define HGD_SUSPICION_HIGH              75
#define HGD_SUSPICION_CRITICAL          90

//
// Maximum code bytes to analyze for pattern detection
//
#define HGD_MAX_CODE_SCAN               64

//
// Pool tags
//
#define HGD_POOL_TAG_TRANSITION         'rTGH'
#define HGD_POOL_TAG_CONTEXT            'xCGH'
#define HGD_POOL_TAG_PATTERN            'tPGH'
#define HGD_POOL_TAG_RESULT             'sRGH'

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

//
// Callback registration entry
//
typedef struct _HGD_CALLBACK_ENTRY {
    HGD_DETECTION_CALLBACK Callback;
    PVOID Context;
    BOOLEAN Active;
    UCHAR Reserved[7];
} HGD_CALLBACK_ENTRY, *PHGD_CALLBACK_ENTRY;

//
// Known WoW64 transition pattern
//
typedef struct _HGD_WOW64_PATTERN {
    UCHAR Pattern[32];
    ULONG PatternSize;
    BOOLEAN IsLegitimate;
    CHAR Description[64];
    LIST_ENTRY ListEntry;
} HGD_WOW64_PATTERN, *PHGD_WOW64_PATTERN;

//
// Internal transition record (list-linked, detector-owned)
//
typedef struct _HGD_TRANSITION_INTERNAL {
    HGD_TRANSITION_INFO Info;
    volatile LONG RefCount;
    LIST_ENTRY ListEntry;
} HGD_TRANSITION_INTERNAL, *PHGD_TRANSITION_INTERNAL;

//
// Per-process WoW64 context
//
typedef struct _HGD_PROCESS_CONTEXT {
    HANDLE ProcessId;

    //
    // WoW64 state
    //
    BOOLEAN IsWow64Process;
    PVOID Wow64TransitionAddress;       // wow64cpu!KiFastSystemCall
    PVOID Wow64SyscallAddress;          // wow64!Wow64SystemServiceCall
    PVOID NtdllBase32;                  // 32-bit ntdll base
    PVOID NtdllBase64;                  // 64-bit ntdll base (wow64)
    SIZE_T NtdllSize32;
    SIZE_T NtdllSize64;
    PVOID Wow64CpuBase;                 // wow64cpu.dll base
    SIZE_T Wow64CpuSize;

    //
    // Transition tracking (atomic counters)
    //
    volatile LONG64 TotalTransitions;
    volatile LONG64 LegitimateTransitions;
    volatile LONG64 SuspiciousTransitions;
    volatile LONG64 BlockedTransitions;

    //
    // Known good addresses for this process
    //
    PVOID KnownGoodAddresses[16];
    ULONG KnownGoodCount;
    EX_PUSH_LOCK KnownGoodLock;

    //
    // Flags (modified atomically via InterlockedOr)
    //
    volatile LONG Flags;
    volatile LONG SuspicionScore;

    //
    // Reference counting
    //
    volatile LONG RefCount;

    //
    // Marked for removal (prevents new lookups from finding it)
    //
    volatile BOOLEAN MarkedForRemoval;

    //
    // List linkage
    //
    LIST_ENTRY ListEntry;

} HGD_PROCESS_CONTEXT, *PHGD_PROCESS_CONTEXT;

//
// Full detector structure (opaque to callers)
//
struct _HGD_DETECTOR {
    BOOLEAN Initialized;

    //
    // WoW64 system addresses
    //
    PVOID Wow64TransitionAddress;
    PVOID Wow64SystemServiceAddress;

    //
    // Transition list
    //
    LIST_ENTRY TransitionList;
    EX_PUSH_LOCK TransitionLock;
    volatile LONG TransitionCount;

    //
    // Atomic statistics
    //
    struct {
        volatile LONG64 TransitionsDetected;
        volatile LONG64 LegitimateTransitions;
        volatile LONG64 SuspiciousTransitions;
        LARGE_INTEGER StartTime;
    } Stats;

    //
    // Process contexts
    //
    LIST_ENTRY ProcessContextList;
    EX_PUSH_LOCK ProcessLock;
    volatile LONG ProcessContextCount;

    //
    // Known WoW64 patterns
    //
    LIST_ENTRY PatternList;
    EX_PUSH_LOCK PatternLock;
    ULONG PatternCount;

    //
    // Callback registrations (protected by push lock, not spinlock)
    //
    HGD_CALLBACK_ENTRY DetectionCallbacks[HGD_MAX_CALLBACKS];
    EX_PUSH_LOCK CallbackLock;
    volatile LONG CallbackCount;

    //
    // Lookaside lists
    //
    NPAGED_LOOKASIDE_LIST TransitionLookaside;
    NPAGED_LOOKASIDE_LIST ContextLookaside;
    BOOLEAN LookasideInitialized;

    //
    // System WoW64 addresses (resolved at init)
    //
    PVOID SystemWow64CpuBase;
    SIZE_T SystemWow64CpuSize;

    //
    // Cleanup timer
    //
    KTIMER CleanupTimer;
    KDPC CleanupDpc;
    BOOLEAN CleanupTimerActive;

    //
    // Shutdown synchronization
    //
    volatile BOOLEAN ShutdownRequested;
    KEVENT ShutdownComplete;
    volatile LONG PendingWorkItems;
};

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static PHGD_PROCESS_CONTEXT
HgdpAllocateProcessContext(
    _In_ PHGD_DETECTOR Detector,
    _In_ HANDLE ProcessId
    );

static VOID
HgdpFreeProcessContext(
    _In_ PHGD_DETECTOR Detector,
    _In_ PHGD_PROCESS_CONTEXT Context
    );

static PHGD_PROCESS_CONTEXT
HgdpLookupProcessContext(
    _In_ PHGD_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN CreateIfNotFound
    );

static VOID
HgdpReferenceProcessContext(
    _Inout_ PHGD_PROCESS_CONTEXT Context
    );

static VOID
HgdpDereferenceProcessContext(
    _In_ PHGD_DETECTOR Detector,
    _Inout_ PHGD_PROCESS_CONTEXT Context
    );

static PHGD_TRANSITION_INTERNAL
HgdpAllocateTransitionInternal(
    _In_ PHGD_DETECTOR Detector
    );

static VOID
HgdpFreeTransitionInternal(
    _In_ PHGD_DETECTOR Detector,
    _In_ PHGD_TRANSITION_INTERNAL Transition
    );

static NTSTATUS
HgdpInsertTransition(
    _In_ PHGD_DETECTOR Detector,
    _In_ PHGD_TRANSITION_INTERNAL Transition
    );

static PHGD_TRANSITION_INFO
HgdpDeepCopyTransition(
    _In_ PHGD_TRANSITION_INTERNAL Source
    );

static HGD_GATE_TYPE
HgdpAnalyzeTransitionAddress(
    _In_ PHGD_DETECTOR Detector,
    _In_ PHGD_PROCESS_CONTEXT ProcessContext,
    _In_ PVOID TransitionAddress,
    _In_reads_bytes_(CodeSize) PUCHAR CodeBuffer,
    _In_ ULONG CodeSize,
    _Out_ PULONG SuspicionScore
    );

static BOOLEAN
HgdpIsKnownWow64Address(
    _In_ PHGD_DETECTOR Detector,
    _In_ PHGD_PROCESS_CONTEXT ProcessContext,
    _In_ PVOID Address
    );

static BOOLEAN
HgdpDetectHeavensGatePattern(
    _In_reads_bytes_(Size) PUCHAR Buffer,
    _In_ ULONG Size,
    _Out_ PULONG PatternOffset
    );

static BOOLEAN
HgdpDetectHellsGatePattern(
    _In_reads_bytes_(Size) PUCHAR Buffer,
    _In_ ULONG Size
    );

static BOOLEAN
HgdpDetectHalosGatePattern(
    _In_reads_bytes_(Size) PUCHAR Buffer,
    _In_ ULONG Size
    );

static NTSTATUS
HgdpReadProcessMemory(
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size
    );

static NTSTATUS
HgdpResolveWow64Addresses(
    _In_ PHGD_DETECTOR Detector,
    _In_ PHGD_PROCESS_CONTEXT ProcessContext
    );

static NTSTATUS
HgdpFindModuleInProcess(
    _In_ HANDLE ProcessId,
    _In_ PCUNICODE_STRING ModuleName,
    _Out_ PVOID* ModuleBase,
    _Out_ PSIZE_T ModuleSize
    );

static VOID
HgdpInitializePatterns(
    _In_ PHGD_DETECTOR Detector
    );

static VOID
HgdpCleanupPatterns(
    _In_ PHGD_DETECTOR Detector
    );

static VOID
HgdpNotifyCallbacks(
    _In_ PHGD_DETECTOR Detector,
    _In_ PHGD_TRANSITION_INFO TransitionInfo
    );

static VOID
HgdpCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

static VOID
HgdpCleanupWorkRoutine(
    _In_opt_ PVOID Context
    );

static VOID
HgdpCleanupStaleTransitions(
    _In_ PHGD_DETECTOR Detector
    );

static VOID
HgdpCleanupStaleProcessContexts(
    _In_ PHGD_DETECTOR Detector
    );

static VOID
HgdpAddPattern(
    _In_ PHGD_DETECTOR Detector,
    _In_reads_bytes_(PatternSize) PUCHAR Pattern,
    _In_ ULONG PatternSize,
    _In_ BOOLEAN IsLegitimate,
    _In_ PCSTR Description
    );

// ============================================================================
// PUBLIC FUNCTION IMPLEMENTATIONS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
HgdInitialize(
    _Out_ PHGD_DETECTOR* Detector
    )
/*++
Routine Description:
    Initializes the Heaven's Gate detector subsystem.
    Must be called at PASSIVE_LEVEL after the work queue is initialized.

Arguments:
    Detector - Receives pointer to initialized detector.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PHGD_DETECTOR Internal = NULL;
    NTSTATUS Status;
    LARGE_INTEGER DueTime;

    PAGED_CODE();

    if (Detector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Detector = NULL;

    //
    // Allocate detector structure from non-paged pool
    //
    Internal = (PHGD_DETECTOR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(HGD_DETECTOR),
        HGD_POOL_TAG
        );

    if (Internal == NULL) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_FLAG_BEHAVIOR,
            "HgdInitialize: Failed to allocate detector structure (%Iu bytes)",
            sizeof(HGD_DETECTOR));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Internal, sizeof(HGD_DETECTOR));

    //
    // Initialize process context list
    //
    InitializeListHead(&Internal->ProcessContextList);
    ExInitializePushLock(&Internal->ProcessLock);

    //
    // Initialize transition list
    //
    InitializeListHead(&Internal->TransitionList);
    ExInitializePushLock(&Internal->TransitionLock);

    //
    // Initialize pattern list
    //
    InitializeListHead(&Internal->PatternList);
    ExInitializePushLock(&Internal->PatternLock);

    //
    // Initialize callback infrastructure (push lock, not spinlock)
    //
    ExInitializePushLock(&Internal->CallbackLock);

    //
    // Initialize shutdown synchronization
    //
    KeInitializeEvent(&Internal->ShutdownComplete, NotificationEvent, TRUE);

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &Internal->TransitionLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(HGD_TRANSITION_INTERNAL),
        HGD_POOL_TAG_TRANSITION,
        0
        );

    ExInitializeNPagedLookasideList(
        &Internal->ContextLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(HGD_PROCESS_CONTEXT),
        HGD_POOL_TAG_CONTEXT,
        0
        );

    Internal->LookasideInitialized = TRUE;

    //
    // Initialize known patterns
    //
    HgdpInitializePatterns(Internal);

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&Internal->Stats.StartTime);

    //
    // Initialize cleanup timer
    //
    KeInitializeTimer(&Internal->CleanupTimer);
    KeInitializeDpc(&Internal->CleanupDpc, HgdpCleanupTimerDpc, Internal);

    //
    // Start periodic cleanup timer
    //
    DueTime.QuadPart = -((LONGLONG)HGD_CLEANUP_INTERVAL_MS * 10000);
    KeSetTimerEx(
        &Internal->CleanupTimer,
        DueTime,
        HGD_CLEANUP_INTERVAL_MS,
        &Internal->CleanupDpc
        );
    Internal->CleanupTimerActive = TRUE;

    //
    // Try to resolve system WoW64 addresses (non-fatal if fails)
    //
    Status = HgdRefreshWow64Addresses(Internal);
    if (!NT_SUCCESS(Status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_FLAG_BEHAVIOR,
            "HgdInitialize: WoW64 address resolution deferred: %!STATUS!", Status);
    }

    //
    // Mark as initialized
    //
    Internal->Initialized = TRUE;
    *Detector = Internal;

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_FLAG_INIT,
        "HgdInitialize: Heaven's Gate detector initialized successfully");

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
HgdShutdown(
    _Inout_ PHGD_DETECTOR Detector
    )
/*++
Routine Description:
    Shuts down the Heaven's Gate detector subsystem.
    Blocks until all pending work items complete, then frees all resources.

Arguments:
    Detector - Detector instance to shutdown.
--*/
{
    PLIST_ENTRY Entry;
    PHGD_TRANSITION_INTERNAL Transition;
    PHGD_PROCESS_CONTEXT Context;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized) {
        return;
    }

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_FLAG_INIT,
        "HgdShutdown: Shutting down Heaven's Gate detector");

    //
    // Signal shutdown - prevents new work items from being queued
    //
    Detector->Initialized = FALSE;
    InterlockedExchange8((volatile CHAR*)&Detector->ShutdownRequested, TRUE);

    //
    // Cancel cleanup timer and flush any in-flight DPCs.
    // KeFlushQueuedDpcs must be called at PASSIVE_LEVEL.
    //
    if (Detector->CleanupTimerActive) {
        KeCancelTimer(&Detector->CleanupTimer);
        KeFlushQueuedDpcs();
        Detector->CleanupTimerActive = FALSE;
    }

    //
    // Wait for any in-flight work items to complete.
    // Clear the event BEFORE checking the count to avoid the race where
    // the last work item completes between our check and the wait.
    //
    KeClearEvent(&Detector->ShutdownComplete);
    if (InterlockedCompareExchange(&Detector->PendingWorkItems, 0, 0) > 0) {
        LARGE_INTEGER Timeout;
        Timeout.QuadPart = -10LL * 1000 * 1000 * 10;  // 10 seconds

        KeWaitForSingleObject(
            &Detector->ShutdownComplete,
            Executive,
            KernelMode,
            FALSE,
            &Timeout
            );
    }

    //
    // Free all transitions
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->TransitionLock);

    while (!IsListEmpty(&Detector->TransitionList)) {
        Entry = RemoveHeadList(&Detector->TransitionList);
        Transition = CONTAINING_RECORD(Entry, HGD_TRANSITION_INTERNAL, ListEntry);
        InterlockedDecrement(&Detector->TransitionCount);

        //
        // Free inline - we hold exclusive lock and are shutting down
        //
        ExFreeToNPagedLookasideList(&Detector->TransitionLookaside, Transition);
    }

    ExReleasePushLockExclusive(&Detector->TransitionLock);
    KeLeaveCriticalRegion();

    //
    // Free all process contexts
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->ProcessLock);

    while (!IsListEmpty(&Detector->ProcessContextList)) {
        Entry = RemoveHeadList(&Detector->ProcessContextList);
        Context = CONTAINING_RECORD(Entry, HGD_PROCESS_CONTEXT, ListEntry);
        InterlockedDecrement(&Detector->ProcessContextCount);
        ExFreeToNPagedLookasideList(&Detector->ContextLookaside, Context);
    }

    ExReleasePushLockExclusive(&Detector->ProcessLock);
    KeLeaveCriticalRegion();

    //
    // Cleanup patterns
    //
    HgdpCleanupPatterns(Detector);

    //
    // Delete lookaside lists
    //
    if (Detector->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&Detector->TransitionLookaside);
        ExDeleteNPagedLookasideList(&Detector->ContextLookaside);
    }

    //
    // Free detector structure
    //
    ShadowStrikeFreePoolWithTag(Detector, HGD_POOL_TAG);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_FLAG_INIT,
        "HgdShutdown: Heaven's Gate detector shutdown complete");
}


_Use_decl_annotations_
NTSTATUS
HgdAnalyzeTransition(
    _In_ PHGD_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ PVOID TransitionAddress,
    _In_reads_bytes_(CodeSnapshotSize) PUCHAR CodeSnapshot,
    _In_ ULONG CodeSnapshotSize,
    _Out_ PHGD_TRANSITION_INFO* Transition
    )
/*++
Routine Description:
    Analyzes a potential Heaven's Gate transition.
    Returns a deep-copied, caller-owned transition record.

    The caller provides a pre-read code snapshot to eliminate TOCTOU
    issues from double-reading process memory.

Arguments:
    Detector          - Detector instance.
    ProcessId         - Process ID where transition occurred.
    ThreadId          - Thread ID.
    TransitionAddress - Address of transition code.
    CodeSnapshot      - Pre-read code bytes at transition address.
    CodeSnapshotSize  - Size of code snapshot in bytes.
    Transition        - Receives caller-owned transition record.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PHGD_PROCESS_CONTEXT ProcessContext = NULL;
    PHGD_TRANSITION_INTERNAL InternalTransition = NULL;
    PHGD_TRANSITION_INFO Result = NULL;
    HGD_GATE_TYPE GateType;
    ULONG SuspicionScore = 0;
    ULONG ClampedCodeSize;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized || Transition == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (CodeSnapshot == NULL || CodeSnapshotSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *Transition = NULL;

    //
    // Clamp code snapshot size to our analysis maximum
    //
    ClampedCodeSize = min(CodeSnapshotSize, HGD_MAX_CODE_SCAN);

    //
    // Get or create process context
    //
    ProcessContext = HgdpLookupProcessContext(Detector, ProcessId, TRUE);
    if (ProcessContext == NULL) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_FLAG_BEHAVIOR,
            "HgdAnalyzeTransition: Failed to allocate process context for PID %Iu",
            (ULONG_PTR)ProcessId);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Skip non-WoW64 processes
    //
    if (!ProcessContext->IsWow64Process) {
        HgdpDereferenceProcessContext(Detector, ProcessContext);
        return STATUS_NOT_SUPPORTED;
    }

    //
    // Analyze transition type using the single code snapshot
    //
    GateType = HgdpAnalyzeTransitionAddress(
        Detector,
        ProcessContext,
        TransitionAddress,
        CodeSnapshot,
        ClampedCodeSize,
        &SuspicionScore
        );

    //
    // Allocate internal transition record
    //
    InternalTransition = HgdpAllocateTransitionInternal(Detector);
    if (InternalTransition == NULL) {
        HgdpDereferenceProcessContext(Detector, ProcessContext);
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_FLAG_BEHAVIOR,
            "HgdAnalyzeTransition: Failed to allocate transition record for PID %Iu",
            (ULONG_PTR)ProcessId);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Populate transition record
    //
    InternalTransition->Info.ProcessId = ProcessId;
    InternalTransition->Info.ThreadId = ThreadId;
    InternalTransition->Info.Type = GateType;
    InternalTransition->Info.SourceRIP = TransitionAddress;
    InternalTransition->Info.SourceCS = HGD_CS_SEGMENT_32BIT;
    InternalTransition->Info.TargetCS = HGD_CS_SEGMENT_64BIT;
    InternalTransition->Info.SuspicionScore = SuspicionScore;
    InternalTransition->Info.IsFromWow64 =
        HgdpIsKnownWow64Address(Detector, ProcessContext, TransitionAddress);
    KeQuerySystemTime(&InternalTransition->Info.Timestamp);

    //
    // Update statistics (lock-free atomic operations)
    //
    InterlockedIncrement64(&Detector->Stats.TransitionsDetected);
    InterlockedIncrement64(&ProcessContext->TotalTransitions);

    if (InternalTransition->Info.IsFromWow64 && GateType == HgdGate_WoW64Transition) {
        InterlockedIncrement64(&Detector->Stats.LegitimateTransitions);
        InterlockedIncrement64(&ProcessContext->LegitimateTransitions);
    } else {
        InterlockedIncrement64(&Detector->Stats.SuspiciousTransitions);
        InterlockedIncrement64(&ProcessContext->SuspiciousTransitions);

        //
        // Set high-risk flag atomically
        //
        if (SuspicionScore >= HGD_SUSPICION_HIGH) {
            InterlockedOr(&ProcessContext->Flags, HGD_PROC_FLAG_HIGH_RISK);

            if (GateType == HgdGate_HeavensGate) {
                InterlockedOr(&ProcessContext->Flags, HGD_PROC_FLAG_HEAVENS_GATE);
            } else if (GateType == HgdGate_HellsGate) {
                InterlockedOr(&ProcessContext->Flags, HGD_PROC_FLAG_HELLS_GATE);
            }

            TraceEvents(TRACE_LEVEL_WARNING, TRACE_FLAG_THREAT,
                "HgdAnalyzeTransition: High suspicion transition detected - "
                "PID %Iu, Type %d, Score %lu, Address %p",
                (ULONG_PTR)ProcessId, (int)GateType, SuspicionScore,
                TransitionAddress);
        }
    }

    //
    // Deep-copy transition record for the caller BEFORE inserting
    // into the internal list (caller gets independent ownership)
    //
    Result = HgdpDeepCopyTransition(InternalTransition);
    if (Result == NULL) {
        HgdpFreeTransitionInternal(Detector, InternalTransition);
        HgdpDereferenceProcessContext(Detector, ProcessContext);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Insert into tracking list
    //
    HgdpInsertTransition(Detector, InternalTransition);

    //
    // Notify callbacks for medium+ suspicion
    //
    if (SuspicionScore >= HGD_SUSPICION_MEDIUM) {
        HgdpNotifyCallbacks(Detector, &InternalTransition->Info);
    }

    HgdpDereferenceProcessContext(Detector, ProcessContext);

    *Transition = Result;

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
HgdIsLegitimateWow64(
    _In_ PHGD_DETECTOR Detector,
    _In_ PVOID Address,
    _Out_ PBOOLEAN IsLegitimate
    )
/*++
Routine Description:
    Checks if an address is a legitimate WoW64 transition point
    for the current process.

Arguments:
    Detector     - Detector instance.
    Address      - Address to check.
    IsLegitimate - Receives TRUE if legitimate.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    HANDLE CurrentProcessId;
    PHGD_PROCESS_CONTEXT ProcessContext;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized || IsLegitimate == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Default to suspicious for unmonitored processes.
    // This is the security-safe default: unknown = untrusted.
    //
    *IsLegitimate = FALSE;

    CurrentProcessId = PsGetCurrentProcessId();

    ProcessContext = HgdpLookupProcessContext(Detector, CurrentProcessId, FALSE);
    if (ProcessContext == NULL) {
        //
        // No context = not monitored. Return FALSE (suspicious)
        // to force the caller to create monitoring context.
        //
        return STATUS_SUCCESS;
    }

    *IsLegitimate = HgdpIsKnownWow64Address(Detector, ProcessContext, Address);

    HgdpDereferenceProcessContext(Detector, ProcessContext);

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
HgdGetTransitions(
    _In_ PHGD_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_writes_to_(Max, *Count) PHGD_TRANSITION_INFO* Transitions,
    _In_ ULONG Max,
    _Out_ PULONG Count
    )
/*++
Routine Description:
    Gets deep-copied transition records for a specific process.
    Each returned pointer is independently allocated and must be
    freed by the caller with HgdFreeTransition.

Arguments:
    Detector    - Detector instance.
    ProcessId   - Process ID to query.
    Transitions - Array to receive transition pointers.
    Max         - Maximum transitions to return.
    Count       - Receives number of transitions returned.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PLIST_ENTRY Entry;
    PHGD_TRANSITION_INTERNAL InternalTransition;
    PHGD_TRANSITION_INFO Copy;
    ULONG Found = 0;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized ||
        Transitions == NULL || Count == NULL || Max == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *Count = 0;
    RtlZeroMemory(Transitions, Max * sizeof(PHGD_TRANSITION_INFO));

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->TransitionLock);

    for (Entry = Detector->TransitionList.Flink;
         Entry != &Detector->TransitionList && Found < Max;
         Entry = Entry->Flink) {

        InternalTransition = CONTAINING_RECORD(
            Entry, HGD_TRANSITION_INTERNAL, ListEntry);

        if (InternalTransition->Info.ProcessId == ProcessId) {
            //
            // Deep-copy each record so the caller owns independent memory
            //
            Copy = HgdpDeepCopyTransition(InternalTransition);
            if (Copy != NULL) {
                Transitions[Found] = Copy;
                Found++;
            }
        }
    }

    ExReleasePushLockShared(&Detector->TransitionLock);
    KeLeaveCriticalRegion();

    *Count = Found;

    //
    // If any allocation failed mid-way, we still return what we got.
    // Caller is responsible for freeing the ones we returned.
    //

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
HgdFreeTransition(
    _In_opt_ PHGD_TRANSITION_INFO Transition
    )
/*++
Routine Description:
    Frees a caller-owned transition record (deep copy).
    Safe to call with NULL.

Arguments:
    Transition - Transition to free.
--*/
{
    if (Transition == NULL) {
        return;
    }

    ShadowStrikeFreePoolWithTag(Transition, HGD_POOL_TAG_RESULT);
}


_Use_decl_annotations_
NTSTATUS
HgdRefreshWow64Addresses(
    _In_ PHGD_DETECTOR Detector
    )
/*++
Routine Description:
    Refreshes system WoW64 module addresses by locating wow64cpu.dll
    in a WoW64 system process and extracting the transition address.

Arguments:
    Detector - Detector instance.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PAGED_CODE();

    if (Detector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // System-level wow64cpu.dll resolution is deferred to per-process
    // context creation (HgdpResolveWow64Addresses). Each WoW64 process
    // gets its addresses resolved when first observed.
    //
    // This function provides a hook point for future system-wide
    // resolution (e.g., on WoW64 subsystem load notification).
    //

    TraceEvents(TRACE_LEVEL_VERBOSE, TRACE_FLAG_BEHAVIOR,
        "HgdRefreshWow64Addresses: WoW64 resolution deferred to per-process");

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
HgdRegisterCallback(
    _In_ PHGD_DETECTOR Detector,
    _In_ HGD_DETECTION_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
/*++
Routine Description:
    Registers a detection callback.
    Callbacks are invoked at PASSIVE_LEVEL with no locks held.

Arguments:
    Detector - Detector instance.
    Callback - Callback function (see HGD_DETECTION_CALLBACK).
    Context  - Optional user context.

Return Value:
    STATUS_SUCCESS on success, STATUS_QUOTA_EXCEEDED if full.
--*/
{
    ULONG i;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->CallbackLock);

    for (i = 0; i < HGD_MAX_CALLBACKS; i++) {
        if (!Detector->DetectionCallbacks[i].Active) {
            Detector->DetectionCallbacks[i].Callback = Callback;
            Detector->DetectionCallbacks[i].Context = Context;
            Detector->DetectionCallbacks[i].Active = TRUE;
            InterlockedIncrement(&Detector->CallbackCount);

            ExReleasePushLockExclusive(&Detector->CallbackLock);
            KeLeaveCriticalRegion();

            TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_FLAG_BEHAVIOR,
                "HgdRegisterCallback: Registered callback %p, slot %lu",
                Callback, i);

            return STATUS_SUCCESS;
        }
    }

    ExReleasePushLockExclusive(&Detector->CallbackLock);
    KeLeaveCriticalRegion();

    TraceEvents(TRACE_LEVEL_WARNING, TRACE_FLAG_BEHAVIOR,
        "HgdRegisterCallback: All %d callback slots exhausted",
        HGD_MAX_CALLBACKS);

    return STATUS_QUOTA_EXCEEDED;
}


_Use_decl_annotations_
VOID
HgdUnregisterCallback(
    _In_ PHGD_DETECTOR Detector,
    _In_ HGD_DETECTION_CALLBACK Callback
    )
/*++
Routine Description:
    Unregisters a detection callback.

Arguments:
    Detector - Detector instance.
    Callback - Callback to unregister.
--*/
{
    ULONG i;

    PAGED_CODE();

    if (Detector == NULL || Callback == NULL) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->CallbackLock);

    for (i = 0; i < HGD_MAX_CALLBACKS; i++) {
        if (Detector->DetectionCallbacks[i].Active &&
            Detector->DetectionCallbacks[i].Callback == Callback) {
            Detector->DetectionCallbacks[i].Active = FALSE;
            Detector->DetectionCallbacks[i].Callback = NULL;
            Detector->DetectionCallbacks[i].Context = NULL;
            InterlockedDecrement(&Detector->CallbackCount);
            break;
        }
    }

    ExReleasePushLockExclusive(&Detector->CallbackLock);
    KeLeaveCriticalRegion();
}


_Use_decl_annotations_
NTSTATUS
HgdGetStatistics(
    _In_ PHGD_DETECTOR Detector,
    _Out_ PHGD_STATISTICS Statistics
    )
/*++
Routine Description:
    Gets detector statistics snapshot (lock-free, atomic reads).

Arguments:
    Detector   - Detector instance.
    Statistics - Receives statistics snapshot.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    if (Detector == NULL || Statistics == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Statistics->TransitionsDetected =
        InterlockedCompareExchange64(&Detector->Stats.TransitionsDetected, 0, 0);
    Statistics->LegitimateTransitions =
        InterlockedCompareExchange64(&Detector->Stats.LegitimateTransitions, 0, 0);
    Statistics->SuspiciousTransitions =
        InterlockedCompareExchange64(&Detector->Stats.SuspiciousTransitions, 0, 0);
    Statistics->StartTime = Detector->Stats.StartTime;

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
HgdDetectSyscallOrigin(
    _In_ PHGD_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ ULONG SyscallNumber,
    _In_ PVOID ReturnAddress,
    _Out_ PBOOLEAN IsSuspicious,
    _Out_opt_ HGD_GATE_TYPE* GateType
    )
/*++
Routine Description:
    Detects if a syscall originated from a suspicious location.
    Reads code at the return address and analyzes for gate patterns.

Arguments:
    Detector      - Detector instance.
    ProcessId     - Process ID.
    SyscallNumber - Syscall number being invoked.
    ReturnAddress - Return address of syscall.
    IsSuspicious  - Receives TRUE if suspicious.
    GateType      - Optional gate type detected.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PHGD_PROCESS_CONTEXT ProcessContext;
    UCHAR CodeBuffer[HGD_MAX_CODE_SCAN];
    ULONG SuspicionScore = 0;
    HGD_GATE_TYPE DetectedType;
    NTSTATUS Status;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(SyscallNumber);

    if (Detector == NULL || !Detector->Initialized ||
        IsSuspicious == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsSuspicious = FALSE;
    if (GateType != NULL) {
        *GateType = HgdGate_None;
    }

    ProcessContext = HgdpLookupProcessContext(Detector, ProcessId, FALSE);
    if (ProcessContext == NULL) {
        return STATUS_SUCCESS;
    }

    //
    // Read code at the return address
    //
    RtlZeroMemory(CodeBuffer, sizeof(CodeBuffer));
    Status = HgdpReadProcessMemory(
        ProcessId,
        ReturnAddress,
        CodeBuffer,
        sizeof(CodeBuffer)
        );

    if (!NT_SUCCESS(Status)) {
        //
        // Cannot read return address - suspicious
        //
        *IsSuspicious = TRUE;
        if (GateType != NULL) {
            *GateType = HgdGate_ManualTransition;
        }
        HgdpDereferenceProcessContext(Detector, ProcessContext);
        return STATUS_SUCCESS;
    }

    DetectedType = HgdpAnalyzeTransitionAddress(
        Detector,
        ProcessContext,
        ReturnAddress,
        CodeBuffer,
        sizeof(CodeBuffer),
        &SuspicionScore
        );

    HgdpDereferenceProcessContext(Detector, ProcessContext);

    *IsSuspicious = (SuspicionScore >= HGD_SUSPICION_MEDIUM);

    if (GateType != NULL) {
        *GateType = DetectedType;
    }

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
HgdAddKnownGoodAddress(
    _In_ PHGD_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ PVOID Address
    )
/*++
Routine Description:
    Adds an address to the known-good whitelist for a process.
    Returns STATUS_QUOTA_EXCEEDED if the whitelist is full.

Arguments:
    Detector  - Detector instance.
    ProcessId - Process ID.
    Address   - Address to whitelist.

Return Value:
    STATUS_SUCCESS on success, STATUS_QUOTA_EXCEEDED if full.
--*/
{
    PHGD_PROCESS_CONTEXT ProcessContext;
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    ProcessContext = HgdpLookupProcessContext(Detector, ProcessId, TRUE);
    if (ProcessContext == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&ProcessContext->KnownGoodLock);

    if (ProcessContext->KnownGoodCount < ARRAYSIZE(ProcessContext->KnownGoodAddresses)) {
        //
        // Check for duplicates first
        //
        BOOLEAN AlreadyPresent = FALSE;
        for (ULONG i = 0; i < ProcessContext->KnownGoodCount; i++) {
            if (ProcessContext->KnownGoodAddresses[i] == Address) {
                AlreadyPresent = TRUE;
                break;
            }
        }

        if (!AlreadyPresent) {
            ProcessContext->KnownGoodAddresses[ProcessContext->KnownGoodCount] = Address;
            ProcessContext->KnownGoodCount++;

            TraceEvents(TRACE_LEVEL_VERBOSE, TRACE_FLAG_BEHAVIOR,
                "HgdAddKnownGoodAddress: Added %p for PID %Iu (count: %lu)",
                Address, (ULONG_PTR)ProcessId, ProcessContext->KnownGoodCount);
        }
    } else {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_FLAG_BEHAVIOR,
            "HgdAddKnownGoodAddress: Known-good list full for PID %Iu (%lu/%lu)",
            (ULONG_PTR)ProcessId, ProcessContext->KnownGoodCount,
            (ULONG)ARRAYSIZE(ProcessContext->KnownGoodAddresses));
        Status = STATUS_QUOTA_EXCEEDED;
    }

    ExReleasePushLockExclusive(&ProcessContext->KnownGoodLock);
    KeLeaveCriticalRegion();

    HgdpDereferenceProcessContext(Detector, ProcessContext);

    return Status;
}


_Use_decl_annotations_
NTSTATUS
HgdGetProcessFlags(
    _In_ PHGD_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_ PULONG Flags,
    _Out_opt_ PULONG SuspicionScore
    )
/*++
Routine Description:
    Gets detection flags for a process.

Arguments:
    Detector       - Detector instance.
    ProcessId      - Process ID.
    Flags          - Receives process flags.
    SuspicionScore - Optional suspicion score.

Return Value:
    STATUS_SUCCESS on success, STATUS_NOT_FOUND if not tracked.
--*/
{
    PHGD_PROCESS_CONTEXT ProcessContext;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized || Flags == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Flags = 0;
    if (SuspicionScore != NULL) {
        *SuspicionScore = 0;
    }

    ProcessContext = HgdpLookupProcessContext(Detector, ProcessId, FALSE);
    if (ProcessContext == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Read atomically
    //
    *Flags = (ULONG)InterlockedCompareExchange(&ProcessContext->Flags, 0, 0);

    if (SuspicionScore != NULL) {
        *SuspicionScore = (ULONG)InterlockedCompareExchange(
            &ProcessContext->SuspicionScore, 0, 0);
    }

    HgdpDereferenceProcessContext(Detector, ProcessContext);

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
HgdRemoveProcessContext(
    _In_ PHGD_DETECTOR Detector,
    _In_ HANDLE ProcessId
    )
/*++
Routine Description:
    Removes process context when process exits.
    Marks the context for removal and decrements its reference count.
    The context is physically freed when the last reference drops.

Arguments:
    Detector  - Detector instance.
    ProcessId - Process ID.
--*/
{
    PLIST_ENTRY Entry;
    PHGD_PROCESS_CONTEXT Context = NULL;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->ProcessLock);

    for (Entry = Detector->ProcessContextList.Flink;
         Entry != &Detector->ProcessContextList;
         Entry = Entry->Flink) {

        Context = CONTAINING_RECORD(Entry, HGD_PROCESS_CONTEXT, ListEntry);

        if (Context->ProcessId == ProcessId) {
            //
            // Mark for removal so no new lookups find it
            //
            InterlockedExchange8(
                (volatile CHAR*)&Context->MarkedForRemoval, TRUE);

            //
            // Remove from list under the lock
            //
            RemoveEntryList(&Context->ListEntry);
            InitializeListHead(&Context->ListEntry);
            InterlockedDecrement(&Detector->ProcessContextCount);
            break;
        }
        Context = NULL;
    }

    ExReleasePushLockExclusive(&Detector->ProcessLock);
    KeLeaveCriticalRegion();

    if (Context != NULL) {
        TraceEvents(TRACE_LEVEL_VERBOSE, TRACE_FLAG_PROCESS,
            "HgdRemoveProcessContext: Removed context for PID %Iu (refs: %ld)",
            (ULONG_PTR)ProcessId, Context->RefCount);

        //
        // Drop the list's reference. If other users still hold references,
        // the context stays alive until they dereference.
        //
        HgdpDereferenceProcessContext(Detector, Context);
    }
}


// ============================================================================
// PRIVATE FUNCTION IMPLEMENTATIONS
// ============================================================================

static PHGD_PROCESS_CONTEXT
HgdpAllocateProcessContext(
    _In_ PHGD_DETECTOR Detector,
    _In_ HANDLE ProcessId
    )
{
    PHGD_PROCESS_CONTEXT Context;
    PEPROCESS Process = NULL;
    NTSTATUS Status;

    Context = (PHGD_PROCESS_CONTEXT)ExAllocateFromNPagedLookasideList(
        &Detector->ContextLookaside
        );

    if (Context == NULL) {
        return NULL;
    }

    RtlZeroMemory(Context, sizeof(HGD_PROCESS_CONTEXT));

    Context->ProcessId = ProcessId;
    //
    // RefCount = 1 for the list's ownership.
    // Callers who find it via lookup will add their own reference.
    //
    Context->RefCount = 1;
    ExInitializePushLock(&Context->KnownGoodLock);
    InitializeListHead(&Context->ListEntry);

    //
    // Get process object to determine WoW64 status
    //
    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (NT_SUCCESS(Status)) {
        //
        // Check if process is still alive before using it
        //
        if (!ShadowStrikeIsProcessTerminating(Process)) {
            Context->IsWow64Process = ShadowStrikeIsProcessWow64(Process);

            //
            // Resolve WoW64 addresses for this process
            //
            if (Context->IsWow64Process) {
                HgdpResolveWow64Addresses(Detector, Context);
                InterlockedOr(&Context->Flags, HGD_PROC_FLAG_MONITORED);
            }
        }

        //
        // Release the reference from PsLookupProcessByProcessId.
        // We do NOT store the PEPROCESS pointer - it becomes stale.
        //
        ObDereferenceObject(Process);
    }

    return Context;
}


static VOID
HgdpFreeProcessContext(
    _In_ PHGD_DETECTOR Detector,
    _In_ PHGD_PROCESS_CONTEXT Context
    )
{
    if (Context == NULL) {
        return;
    }

    ExFreeToNPagedLookasideList(&Detector->ContextLookaside, Context);
}


static PHGD_PROCESS_CONTEXT
HgdpLookupProcessContext(
    _In_ PHGD_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN CreateIfNotFound
    )
{
    PLIST_ENTRY Entry;
    PHGD_PROCESS_CONTEXT Context = NULL;
    PHGD_PROCESS_CONTEXT NewContext = NULL;

    //
    // Shared lookup first
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->ProcessLock);

    for (Entry = Detector->ProcessContextList.Flink;
         Entry != &Detector->ProcessContextList;
         Entry = Entry->Flink) {

        Context = CONTAINING_RECORD(Entry, HGD_PROCESS_CONTEXT, ListEntry);

        if (Context->ProcessId == ProcessId && !Context->MarkedForRemoval) {
            HgdpReferenceProcessContext(Context);
            ExReleasePushLockShared(&Detector->ProcessLock);
            KeLeaveCriticalRegion();
            return Context;
        }
    }

    ExReleasePushLockShared(&Detector->ProcessLock);
    KeLeaveCriticalRegion();

    if (!CreateIfNotFound) {
        return NULL;
    }

    //
    // Check process context count limit before allocating
    //
    if ((ULONG)InterlockedCompareExchange(
            &Detector->ProcessContextCount, 0, 0) >= HGD_MAX_PROCESS_CONTEXTS) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_FLAG_BEHAVIOR,
            "HgdpLookupProcessContext: Process context limit reached (%d)",
            HGD_MAX_PROCESS_CONTEXTS);
        return NULL;
    }

    //
    // Allocate outside the lock
    //
    NewContext = HgdpAllocateProcessContext(Detector, ProcessId);
    if (NewContext == NULL) {
        return NULL;
    }

    //
    // Insert with exclusive lock, checking for race
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->ProcessLock);

    for (Entry = Detector->ProcessContextList.Flink;
         Entry != &Detector->ProcessContextList;
         Entry = Entry->Flink) {

        PHGD_PROCESS_CONTEXT Existing =
            CONTAINING_RECORD(Entry, HGD_PROCESS_CONTEXT, ListEntry);

        if (Existing->ProcessId == ProcessId && !Existing->MarkedForRemoval) {
            //
            // Another thread created it - use theirs
            //
            HgdpReferenceProcessContext(Existing);
            ExReleasePushLockExclusive(&Detector->ProcessLock);
            KeLeaveCriticalRegion();

            HgdpFreeProcessContext(Detector, NewContext);
            return Existing;
        }
    }

    //
    // Insert our new context. RefCount is already 1 (list ownership).
    // Add another reference for the caller.
    //
    HgdpReferenceProcessContext(NewContext);
    InsertTailList(&Detector->ProcessContextList, &NewContext->ListEntry);
    InterlockedIncrement(&Detector->ProcessContextCount);

    ExReleasePushLockExclusive(&Detector->ProcessLock);
    KeLeaveCriticalRegion();

    return NewContext;
}


static VOID
HgdpReferenceProcessContext(
    _Inout_ PHGD_PROCESS_CONTEXT Context
    )
{
    LONG NewRef = InterlockedIncrement(&Context->RefCount);
    NT_ASSERT(NewRef > 1);
    UNREFERENCED_PARAMETER(NewRef);
}


static VOID
HgdpDereferenceProcessContext(
    _In_ PHGD_DETECTOR Detector,
    _Inout_ PHGD_PROCESS_CONTEXT Context
    )
{
    LONG NewRef = InterlockedDecrement(&Context->RefCount);
    NT_ASSERT(NewRef >= 0);

    if (NewRef == 0) {
        //
        // The context should already be removed from the list by
        // HgdRemoveProcessContext or HgdShutdown before reaching
        // refcount 0. We do not re-acquire the lock here to remove
        // from list since that creates a race condition.
        //
        HgdpFreeProcessContext(Detector, Context);
    }
}


static PHGD_TRANSITION_INTERNAL
HgdpAllocateTransitionInternal(
    _In_ PHGD_DETECTOR Detector
    )
{
    PHGD_TRANSITION_INTERNAL Transition;

    Transition = (PHGD_TRANSITION_INTERNAL)ExAllocateFromNPagedLookasideList(
        &Detector->TransitionLookaside
        );

    if (Transition != NULL) {
        RtlZeroMemory(Transition, sizeof(HGD_TRANSITION_INTERNAL));
        Transition->RefCount = 1;
        InitializeListHead(&Transition->ListEntry);
    }

    return Transition;
}


static VOID
HgdpFreeTransitionInternal(
    _In_ PHGD_DETECTOR Detector,
    _In_ PHGD_TRANSITION_INTERNAL Transition
    )
{
    ExFreeToNPagedLookasideList(&Detector->TransitionLookaside, Transition);
}


static PHGD_TRANSITION_INFO
HgdpDeepCopyTransition(
    _In_ PHGD_TRANSITION_INTERNAL Source
    )
/*++
Routine Description:
    Creates a deep copy of a transition record for caller ownership.
    The returned record has no list linkage and is independently freeable.
--*/
{
    PHGD_TRANSITION_INFO Copy;

    Copy = (PHGD_TRANSITION_INFO)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(HGD_TRANSITION_INFO),
        HGD_POOL_TAG_RESULT
        );

    if (Copy == NULL) {
        return NULL;
    }

    //
    // Shallow copy of value types is safe since HGD_TRANSITION_INFO
    // uses embedded buffers (WCHAR array), not pointers.
    //
    RtlCopyMemory(Copy, &Source->Info, sizeof(HGD_TRANSITION_INFO));

    return Copy;
}


static NTSTATUS
HgdpInsertTransition(
    _In_ PHGD_DETECTOR Detector,
    _In_ PHGD_TRANSITION_INTERNAL Transition
    )
{
    LIST_ENTRY EvictionList;

    InitializeListHead(&EvictionList);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->TransitionLock);

    //
    // If at capacity, collect entries to evict while holding the lock.
    // Free them after releasing the lock.
    //
    while ((ULONG)Detector->TransitionCount >= HGD_MAX_TRANSITIONS &&
           !IsListEmpty(&Detector->TransitionList)) {

        PLIST_ENTRY OldEntry = RemoveHeadList(&Detector->TransitionList);
        InterlockedDecrement(&Detector->TransitionCount);
        InsertTailList(&EvictionList, OldEntry);
    }

    InsertTailList(&Detector->TransitionList, &Transition->ListEntry);
    InterlockedIncrement(&Detector->TransitionCount);

    ExReleasePushLockExclusive(&Detector->TransitionLock);
    KeLeaveCriticalRegion();

    //
    // Free evicted entries outside the lock
    //
    while (!IsListEmpty(&EvictionList)) {
        PLIST_ENTRY Entry = RemoveHeadList(&EvictionList);
        PHGD_TRANSITION_INTERNAL OldTransition =
            CONTAINING_RECORD(Entry, HGD_TRANSITION_INTERNAL, ListEntry);
        HgdpFreeTransitionInternal(Detector, OldTransition);
    }

    return STATUS_SUCCESS;
}


static HGD_GATE_TYPE
HgdpAnalyzeTransitionAddress(
    _In_ PHGD_DETECTOR Detector,
    _In_ PHGD_PROCESS_CONTEXT ProcessContext,
    _In_ PVOID TransitionAddress,
    _In_reads_bytes_(CodeSize) PUCHAR CodeBuffer,
    _In_ ULONG CodeSize,
    _Out_ PULONG SuspicionScore
    )
/*++
Routine Description:
    Analyzes transition code to determine the gate type and suspicion level.
    Uses the caller-provided code buffer (single read, no TOCTOU).
--*/
{
    ULONG PatternOffset = 0;

    *SuspicionScore = 0;

    //
    // Check if this is a known legitimate WoW64 address
    //
    if (HgdpIsKnownWow64Address(Detector, ProcessContext, TransitionAddress)) {
        *SuspicionScore = 0;
        return HgdGate_WoW64Transition;
    }

    //
    // Check for Heaven's Gate pattern (manual CS segment switch)
    //
    if (HgdpDetectHeavensGatePattern(CodeBuffer, CodeSize, &PatternOffset)) {
        *SuspicionScore = HGD_SUSPICION_CRITICAL;
        return HgdGate_HeavensGate;
    }

    //
    // Check for Hell's Gate pattern (dynamic SSN resolution)
    //
    if (HgdpDetectHellsGatePattern(CodeBuffer, CodeSize)) {
        *SuspicionScore = HGD_SUSPICION_CRITICAL;
        return HgdGate_HellsGate;
    }

    //
    // Check for Halo's Gate pattern (neighbor walking)
    //
    if (HgdpDetectHalosGatePattern(CodeBuffer, CodeSize)) {
        *SuspicionScore = HGD_SUSPICION_HIGH;
        return HgdGate_HellsGate;
    }

    //
    // Check if address is in known modules (overflow-safe range check)
    //
    if (ProcessContext->NtdllBase32 != NULL && ProcessContext->NtdllSize32 != 0) {
        ULONG_PTR TransAddr = (ULONG_PTR)TransitionAddress;
        ULONG_PTR NtdllStart = (ULONG_PTR)ProcessContext->NtdllBase32;

        if (TransAddr >= NtdllStart &&
            (TransAddr - NtdllStart) < ProcessContext->NtdllSize32) {
            *SuspicionScore = HGD_SUSPICION_LOW;
            return HgdGate_WoW64Transition;
        }
    }

    //
    // Check if in wow64cpu.dll range (overflow-safe)
    //
    if (ProcessContext->Wow64CpuBase != NULL && ProcessContext->Wow64CpuSize != 0) {
        ULONG_PTR TransAddr = (ULONG_PTR)TransitionAddress;
        ULONG_PTR CpuStart = (ULONG_PTR)ProcessContext->Wow64CpuBase;

        if (TransAddr >= CpuStart &&
            (TransAddr - CpuStart) < ProcessContext->Wow64CpuSize) {
            *SuspicionScore = 0;
            return HgdGate_WoW64Transition;
        }
    }

    //
    // Unknown transition - medium suspicion
    //
    *SuspicionScore = HGD_SUSPICION_MEDIUM;
    return HgdGate_ManualTransition;
}


static BOOLEAN
HgdpIsKnownWow64Address(
    _In_ PHGD_DETECTOR Detector,
    _In_ PHGD_PROCESS_CONTEXT ProcessContext,
    _In_ PVOID Address
    )
{
    ULONG i;

    UNREFERENCED_PARAMETER(Detector);

    //
    // Check known transition addresses (no lock needed, these are
    // written once during context creation)
    //
    if (ProcessContext->Wow64TransitionAddress == Address ||
        ProcessContext->Wow64SyscallAddress == Address) {
        return TRUE;
    }

    //
    // Check per-process known good list under push lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&ProcessContext->KnownGoodLock);

    for (i = 0; i < ProcessContext->KnownGoodCount; i++) {
        if (ProcessContext->KnownGoodAddresses[i] == Address) {
            ExReleasePushLockShared(&ProcessContext->KnownGoodLock);
            KeLeaveCriticalRegion();
            return TRUE;
        }
    }

    ExReleasePushLockShared(&ProcessContext->KnownGoodLock);
    KeLeaveCriticalRegion();

    return FALSE;
}


static BOOLEAN
HgdpDetectHeavensGatePattern(
    _In_reads_bytes_(Size) PUCHAR Buffer,
    _In_ ULONG Size,
    _Out_ PULONG PatternOffset
    )
/*++
Routine Description:
    Detects Heaven's Gate (manual segment switching) patterns.

    Common patterns:
    1. PUSH 0x33; CALL $+5; ADD [ESP], 5; RETF
    2. JMP FAR PTR 0x33:address
    3. PUSH 0x33; PUSH address; RETF
--*/
{
    ULONG i;

    *PatternOffset = 0;

    if (Size < 6) {
        return FALSE;
    }

    //
    // Use explicit unsigned comparison to avoid underflow.
    // We need at least 7 bytes for the shortest meaningful pattern.
    //
    for (i = 0; i + 7 <= Size; i++) {
        //
        // Pattern 1: PUSH 0x33 (6A 33)
        //
        if (Buffer[i] == 0x6A && Buffer[i + 1] == 0x33) {
            //
            // Check for CALL $+5 (E8 00 00 00 00)
            //
            if (i + 12 <= Size &&
                Buffer[i + 2] == 0xE8 &&
                Buffer[i + 3] == 0x00 &&
                Buffer[i + 4] == 0x00 &&
                Buffer[i + 5] == 0x00 &&
                Buffer[i + 6] == 0x00) {
                //
                // ADD DWORD PTR [ESP], imm8 (83 04 24 xx) followed by RETF (CB)
                //
                if (i + 12 <= Size &&
                    Buffer[i + 7] == 0x83 &&
                    Buffer[i + 8] == 0x04 &&
                    Buffer[i + 9] == 0x24 &&
                    Buffer[i + 11] == 0xCB) {
                    *PatternOffset = i;
                    return TRUE;
                }
            }

            //
            // Pattern 3: PUSH 0x33; PUSH imm32; RETF
            // 6A 33 68 xx xx xx xx CB
            //
            if (i + 8 <= Size &&
                Buffer[i + 2] == 0x68 &&
                Buffer[i + 7] == 0xCB) {
                *PatternOffset = i;
                return TRUE;
            }
        }

        //
        // Pattern 2: JMP FAR (EA xx xx xx xx 33 00)
        //
        if (Buffer[i] == 0xEA && i + 7 <= Size) {
            if (Buffer[i + 5] == 0x33 && Buffer[i + 6] == 0x00) {
                *PatternOffset = i;
                return TRUE;
            }
        }

        //
        // Direct RETF preceded by PUSH 0x33
        //
        if (Buffer[i] == 0xCB && i >= 2) {
            if (Buffer[i - 2] == 0x6A && Buffer[i - 1] == 0x33) {
                *PatternOffset = i - 2;
                return TRUE;
            }
        }
    }

    return FALSE;
}


static BOOLEAN
HgdpDetectHellsGatePattern(
    _In_reads_bytes_(Size) PUCHAR Buffer,
    _In_ ULONG Size
    )
/*++
Routine Description:
    Detects Hell's Gate pattern (dynamic SSN resolution from clean ntdll).

    Pattern characteristics:
    1. Reading from PEB to find ntdll
    2. Parsing export table
    3. Finding Zw/Nt function
    4. Extracting syscall number from stub
--*/
{
    ULONG i;

    if (Size < 16) {
        return FALSE;
    }

    for (i = 0; i + 16 <= Size; i++) {
        //
        // Pattern: MOV EAX, [FS:0x30] (access PEB)
        // 64 A1 30 00 00 00 (x86)
        //
        if (Buffer[i] == 0x64 && Buffer[i + 1] == 0xA1 &&
            Buffer[i + 2] == 0x30 && Buffer[i + 3] == 0x00) {
            //
            // Look for subsequent module list traversal
            // MOV reg, [eax+0x0C] (PEB_LDR_DATA)
            //
            ULONG j;
            ULONG jEnd = min(i + 32, Size - 3);
            for (j = i + 4; j < jEnd; j++) {
                if ((Buffer[j] == 0x8B) &&
                    ((Buffer[j + 1] & 0xC7) == 0x40) &&
                    (Buffer[j + 2] == 0x0C || Buffer[j + 2] == 0x14)) {
                    return TRUE;
                }
            }
        }

        //
        // x64 pattern: MOV RAX, GS:[0x60] (access PEB)
        // 65 48 8B 04 25 60 00 00 00
        //
        if (i + 9 <= Size &&
            Buffer[i] == 0x65 && Buffer[i + 1] == 0x48 &&
            Buffer[i + 2] == 0x8B && Buffer[i + 3] == 0x04 &&
            Buffer[i + 4] == 0x25 && Buffer[i + 5] == 0x60) {
            return TRUE;
        }

        //
        // Pattern: Reading syscall number from ntdll stub
        // MOV EAX, DWORD PTR [reg+4] after function call
        //
        if (Buffer[i] == 0x8B && (Buffer[i + 1] & 0xC0) == 0x40 &&
            Buffer[i + 2] == 0x04) {
            if (i >= 5) {
                if ((Buffer[i - 2] == 0xFF && (Buffer[i - 1] & 0xF8) == 0xD0) ||
                    (Buffer[i - 2] == 0xFF && (Buffer[i - 1] & 0xF8) == 0x10)) {
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}


static BOOLEAN
HgdpDetectHalosGatePattern(
    _In_reads_bytes_(Size) PUCHAR Buffer,
    _In_ ULONG Size
    )
/*++
Routine Description:
    Detects Halo's Gate pattern (walking neighboring syscall stubs).

    Pattern characteristics:
    1. Finding a hooked function
    2. Walking up/down to find unhook neighbor
    3. Calculating SSN from neighbor offset
--*/
{
    ULONG i;

    if (Size < 24) {
        return FALSE;
    }

    for (i = 0; i + 24 <= Size; i++) {
        //
        // Pattern: Checking for JMP (hook detection)
        // CMP BYTE PTR [reg], 0xE9
        //
        if (Buffer[i] == 0x80 && (Buffer[i + 1] & 0xF8) == 0x38 &&
            Buffer[i + 2] == 0xE9) {
            //
            // Look for conditional jump (hook bypass logic)
            //
            ULONG j;
            ULONG jEnd = min(i + 16, Size - 2);
            for (j = i + 3; j < jEnd; j++) {
                if (Buffer[j] == 0x74 || Buffer[j] == 0x75 ||
                    Buffer[j] == 0x0F) {
                    //
                    // Look for ADD/SUB for neighbor walking
                    //
                    ULONG k;
                    ULONG kEnd = min(j + 16, Size - 3);
                    for (k = j; k < kEnd; k++) {
                        if ((Buffer[k] == 0x83 || Buffer[k] == 0x81) &&
                            ((Buffer[k + 1] & 0xC0) == 0xC0)) {
                            return TRUE;
                        }
                    }
                }
            }
        }

        //
        // Direct syscall stub structure check
        // MOV R10, RCX; MOV EAX, imm32; ... SYSCALL
        // 4C 8B D1 B8 xx xx xx xx ... 0F 05
        //
        if (i + 12 <= Size &&
            Buffer[i] == 0x4C && Buffer[i + 1] == 0x8B && Buffer[i + 2] == 0xD1 &&
            Buffer[i + 3] == 0xB8) {
            ULONG j;
            ULONG jEnd = min(i + 16, Size - 1);
            for (j = i + 8; j < jEnd; j++) {
                if (Buffer[j] == 0x0F && Buffer[j + 1] == 0x05) {
                    //
                    // Direct syscall stub found but need context to
                    // determine if it's from a legitimate location
                    //
                    return FALSE;
                }
            }
        }
    }

    return FALSE;
}


static NTSTATUS
HgdpReadProcessMemory(
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size
    )
/*++
Routine Description:
    Safely reads memory from a process's address space.
    Validates that the target process is alive before attaching.
--*/
{
    NTSTATUS Status;
    PEPROCESS Process = NULL;
    KAPC_STATE ApcState;
    BOOLEAN Attached = FALSE;
    SIZE_T BytesCopied = 0;

    if (Size == 0) {
        return STATUS_SUCCESS;
    }

    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Verify the process is not terminating before attaching.
    // Attaching to a dying process can hang or crash.
    //
    if (ShadowStrikeIsProcessTerminating(Process)) {
        ObDereferenceObject(Process);
        return STATUS_PROCESS_IS_TERMINATING;
    }

    __try {
        KeStackAttachProcess(Process, &ApcState);
        Attached = TRUE;

        ProbeForRead(Address, Size, 1);
        RtlCopyMemory(Buffer, Address, Size);
        BytesCopied = Size;

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    if (Attached) {
        KeUnstackDetachProcess(&ApcState);
    }

    ObDereferenceObject(Process);

    return (BytesCopied == Size) ? STATUS_SUCCESS : Status;
}


static NTSTATUS
HgdpResolveWow64Addresses(
    _In_ PHGD_DETECTOR Detector,
    _In_ PHGD_PROCESS_CONTEXT ProcessContext
    )
/*++
Routine Description:
    Resolves WoW64 module addresses for a specific process by walking
    the process's PEB module list. Locates:
    1. ntdll.dll (32-bit) base and size
    2. wow64cpu.dll base and size
    3. wow64.dll base and size (for Wow64SystemServiceCall)

    All addresses are stored in the process context for fast lookup.
--*/
{
    UNICODE_STRING Ntdll32Name;
    UNICODE_STRING Wow64CpuName;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(Detector);

    RtlInitUnicodeString(&Ntdll32Name, L"ntdll.dll");
    RtlInitUnicodeString(&Wow64CpuName, L"wow64cpu.dll");

    //
    // Resolve 32-bit ntdll
    //
    Status = HgdpFindModuleInProcess(
        ProcessContext->ProcessId,
        &Ntdll32Name,
        &ProcessContext->NtdllBase32,
        &ProcessContext->NtdllSize32
        );

    if (!NT_SUCCESS(Status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_FLAG_BEHAVIOR,
            "HgdpResolveWow64Addresses: Failed to find ntdll.dll in PID %Iu: %!STATUS!",
            (ULONG_PTR)ProcessContext->ProcessId, Status);
    }

    //
    // Resolve wow64cpu.dll
    //
    Status = HgdpFindModuleInProcess(
        ProcessContext->ProcessId,
        &Wow64CpuName,
        &ProcessContext->Wow64CpuBase,
        &ProcessContext->Wow64CpuSize
        );

    if (NT_SUCCESS(Status) && ProcessContext->Wow64CpuBase != NULL) {
        //
        // The transition address is typically at a fixed offset within
        // wow64cpu.dll. Store the base so we can do range checks.
        // The exact transition function will be validated when first seen.
        //
        TraceEvents(TRACE_LEVEL_VERBOSE, TRACE_FLAG_BEHAVIOR,
            "HgdpResolveWow64Addresses: PID %Iu - wow64cpu.dll at %p (size %Iu)",
            (ULONG_PTR)ProcessContext->ProcessId,
            ProcessContext->Wow64CpuBase,
            ProcessContext->Wow64CpuSize);
    } else {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_FLAG_BEHAVIOR,
            "HgdpResolveWow64Addresses: Failed to find wow64cpu.dll in PID %Iu: %!STATUS!",
            (ULONG_PTR)ProcessContext->ProcessId, Status);
    }

    return STATUS_SUCCESS;
}


static NTSTATUS
HgdpFindModuleInProcess(
    _In_ HANDLE ProcessId,
    _In_ PCUNICODE_STRING ModuleName,
    _Out_ PVOID* ModuleBase,
    _Out_ PSIZE_T ModuleSize
    )
/*++
Routine Description:
    Finds a loaded module in a process by walking PEB->Ldr.
    Uses the same proven pattern as NtdllIntegrity's NipGetProcessNtdll.
--*/
{
    NTSTATUS Status;
    PEPROCESS Process = NULL;
    PPEB Peb = NULL;
    PKM_PEB_LDR_DATA LdrData = NULL;
    PLIST_ENTRY ListHead;
    PLIST_ENTRY ListEntry;
    KAPC_STATE ApcState;
    BOOLEAN Found = FALSE;
    BOOLEAN Attached = FALSE;
    ULONG WalkCount = 0;

    *ModuleBase = NULL;
    *ModuleSize = 0;

    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    if (ShadowStrikeIsProcessTerminating(Process)) {
        ObDereferenceObject(Process);
        return STATUS_PROCESS_IS_TERMINATING;
    }

    Peb = PsGetProcessPeb(Process);
    if (Peb == NULL) {
        ObDereferenceObject(Process);
        return STATUS_NOT_FOUND;
    }

    __try {
        KeStackAttachProcess(Process, &ApcState);
        Attached = TRUE;

        ProbeForRead(Peb, KM_PEB_PROBE_SIZE, sizeof(PVOID));
        LdrData = (PKM_PEB_LDR_DATA)((PKM_PEB)Peb)->Ldr;

        if (LdrData == NULL) {
            Status = STATUS_NOT_FOUND;
            __leave;
        }

        ProbeForRead(LdrData, KM_PEB_LDR_PROBE_SIZE, sizeof(PVOID));

        ListHead = &LdrData->InMemoryOrderModuleList;
        ListEntry = ListHead->Flink;

        while (ListEntry != ListHead && WalkCount < KM_MAX_MODULE_WALK_COUNT) {
            PKM_LDR_DATA_TABLE_ENTRY LdrEntry;

            LdrEntry = CONTAINING_RECORD(
                ListEntry,
                KM_LDR_DATA_TABLE_ENTRY,
                InMemoryOrderLinks
                );

            ProbeForRead(LdrEntry, KM_LDR_ENTRY_PROBE_SIZE, sizeof(PVOID));

            if (LdrEntry->BaseDllName.Buffer != NULL &&
                LdrEntry->BaseDllName.Length > 0 &&
                LdrEntry->BaseDllName.Length <= 512) {

                ProbeForRead(
                    LdrEntry->BaseDllName.Buffer,
                    LdrEntry->BaseDllName.Length,
                    sizeof(WCHAR)
                    );

                if (RtlCompareUnicodeString(
                        &LdrEntry->BaseDllName, ModuleName, TRUE) == 0) {
                    *ModuleBase = LdrEntry->DllBase;
                    *ModuleSize = LdrEntry->SizeOfImage;
                    Found = TRUE;
                    break;
                }
            }

            ListEntry = ListEntry->Flink;
            WalkCount++;
        }

        if (!Found) {
            Status = STATUS_NOT_FOUND;
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    if (Attached) {
        KeUnstackDetachProcess(&ApcState);
    }

    ObDereferenceObject(Process);

    return Found ? STATUS_SUCCESS : Status;
}


static VOID
HgdpInitializePatterns(
    _In_ PHGD_DETECTOR Detector
    )
/*++
Routine Description:
    Initializes known legitimate WoW64 transition patterns.
    These are the standard instruction sequences used by wow64cpu.dll
    for legitimate 32-to-64 bit transitions.
--*/
{
    //
    // Standard wow64cpu.dll KiFastSystemCall pattern (Win10+):
    // EA xx xx xx xx 33 00 (JMP FAR 0x33:addr)
    //
    UCHAR Pattern1[] = { 0xEA, 0x00, 0x00, 0x00, 0x00, 0x33, 0x00 };
    HgdpAddPattern(Detector, Pattern1, 2, TRUE,
        "JMP FAR 0x33 (wow64cpu transition)");

    //
    // wow64cpu CpupReturnFromSimulatedCode pattern:
    // FF 25 xx xx xx xx (JMP QWORD PTR [rip+disp32]) in 64-bit
    //
    UCHAR Pattern2[] = { 0xFF, 0x25 };
    HgdpAddPattern(Detector, Pattern2, sizeof(Pattern2), TRUE,
        "JMP [rip+disp] (wow64cpu return)");

    //
    // Wow64SystemServiceCall entry pattern:
    // 41 FF D2 (CALL R10)
    //
    UCHAR Pattern3[] = { 0x41, 0xFF, 0xD2 };
    HgdpAddPattern(Detector, Pattern3, sizeof(Pattern3), TRUE,
        "CALL R10 (Wow64SystemServiceCall)");
}


static VOID
HgdpAddPattern(
    _In_ PHGD_DETECTOR Detector,
    _In_reads_bytes_(PatternSize) PUCHAR Pattern,
    _In_ ULONG PatternSize,
    _In_ BOOLEAN IsLegitimate,
    _In_ PCSTR Description
    )
{
    PHGD_WOW64_PATTERN PatternEntry;

    if (PatternSize > sizeof(PatternEntry->Pattern)) {
        return;
    }

    PatternEntry = (PHGD_WOW64_PATTERN)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(HGD_WOW64_PATTERN),
        HGD_POOL_TAG_PATTERN
        );

    if (PatternEntry == NULL) {
        return;
    }

    RtlZeroMemory(PatternEntry, sizeof(HGD_WOW64_PATTERN));
    RtlCopyMemory(PatternEntry->Pattern, Pattern, PatternSize);
    PatternEntry->PatternSize = PatternSize;
    PatternEntry->IsLegitimate = IsLegitimate;
    RtlStringCchCopyA(
        PatternEntry->Description,
        sizeof(PatternEntry->Description),
        Description
        );

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->PatternLock);

    InsertTailList(&Detector->PatternList, &PatternEntry->ListEntry);
    Detector->PatternCount++;

    ExReleasePushLockExclusive(&Detector->PatternLock);
    KeLeaveCriticalRegion();
}


static VOID
HgdpCleanupPatterns(
    _In_ PHGD_DETECTOR Detector
    )
{
    PLIST_ENTRY Entry;
    PHGD_WOW64_PATTERN Pattern;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->PatternLock);

    while (!IsListEmpty(&Detector->PatternList)) {
        Entry = RemoveHeadList(&Detector->PatternList);
        Pattern = CONTAINING_RECORD(Entry, HGD_WOW64_PATTERN, ListEntry);
        ShadowStrikeFreePoolWithTag(Pattern, HGD_POOL_TAG_PATTERN);
    }
    Detector->PatternCount = 0;

    ExReleasePushLockExclusive(&Detector->PatternLock);
    KeLeaveCriticalRegion();
}


static VOID
HgdpNotifyCallbacks(
    _In_ PHGD_DETECTOR Detector,
    _In_ PHGD_TRANSITION_INFO TransitionInfo
    )
/*++
Routine Description:
    Notifies registered detection callbacks.
    Takes a snapshot of the callback array under the lock, then
    invokes all callbacks outside the lock at the current IRQL
    (which should be <= APC_LEVEL for all callers).
--*/
{
    HGD_CALLBACK_ENTRY Snapshot[HGD_MAX_CALLBACKS];
    ULONG SnapshotCount = 0;
    ULONG i;

    //
    // Snapshot the callback array under the lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->CallbackLock);

    for (i = 0; i < HGD_MAX_CALLBACKS; i++) {
        if (Detector->DetectionCallbacks[i].Active &&
            Detector->DetectionCallbacks[i].Callback != NULL) {
            Snapshot[SnapshotCount] = Detector->DetectionCallbacks[i];
            SnapshotCount++;
        }
    }

    ExReleasePushLockShared(&Detector->CallbackLock);
    KeLeaveCriticalRegion();

    //
    // Invoke callbacks outside the lock
    //
    for (i = 0; i < SnapshotCount; i++) {
        __try {
            Snapshot[i].Callback(TransitionInfo, Snapshot[i].Context);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            TraceEvents(TRACE_LEVEL_ERROR, TRACE_FLAG_BEHAVIOR,
                "HgdpNotifyCallbacks: Callback %p raised exception 0x%08X",
                Snapshot[i].Callback, GetExceptionCode());
        }
    }
}


static VOID
HgdpCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
/*++
Routine Description:
    Timer DPC callback. Runs at DISPATCH_LEVEL.
    Queues a work item to perform actual cleanup at PASSIVE_LEVEL.
    Push locks and PEB walking cannot be done at DISPATCH_LEVEL.
--*/
{
    PHGD_DETECTOR Detector = (PHGD_DETECTOR)DeferredContext;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (Detector == NULL || Detector->ShutdownRequested) {
        return;
    }

    //
    // Queue a work item for cleanup at PASSIVE_LEVEL.
    // Track pending work items for shutdown synchronization.
    //
    InterlockedIncrement(&Detector->PendingWorkItems);
    KeClearEvent(&Detector->ShutdownComplete);

    Status = ShadowStrikeQueueWorkItem(HgdpCleanupWorkRoutine, Detector);
    if (!NT_SUCCESS(Status)) {
        //
        // Failed to queue - decrement counter and signal if zero
        //
        if (InterlockedDecrement(&Detector->PendingWorkItems) == 0) {
            KeSetEvent(&Detector->ShutdownComplete, IO_NO_INCREMENT, FALSE);
        }
    }
}


static VOID
HgdpCleanupWorkRoutine(
    _In_opt_ PVOID Context
    )
/*++
Routine Description:
    Work queue callback for periodic cleanup.
    Runs at PASSIVE_LEVEL. Safe to use push locks and PEB walking.
--*/
{
    PHGD_DETECTOR Detector = (PHGD_DETECTOR)Context;

    if (Detector == NULL || Detector->ShutdownRequested) {
        goto Done;
    }

    //
    // Clean up stale transitions (older than timeout)
    //
    HgdpCleanupStaleTransitions(Detector);

    //
    // Clean up process contexts for dead processes
    //
    HgdpCleanupStaleProcessContexts(Detector);

Done:
    if (Detector != NULL) {
        if (InterlockedDecrement(&Detector->PendingWorkItems) == 0) {
            KeSetEvent(&Detector->ShutdownComplete, IO_NO_INCREMENT, FALSE);
        }
    }
}


static VOID
HgdpCleanupStaleTransitions(
    _In_ PHGD_DETECTOR Detector
    )
{
    LARGE_INTEGER CurrentTime;
    LONGLONG TimeoutTicks;
    PLIST_ENTRY Entry, Next;
    PHGD_TRANSITION_INTERNAL Transition;
    LIST_ENTRY StaleList;

    InitializeListHead(&StaleList);

    KeQuerySystemTime(&CurrentTime);
    TimeoutTicks = (LONGLONG)HGD_TRANSITION_TIMEOUT_MS * 10000;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->TransitionLock);

    for (Entry = Detector->TransitionList.Flink;
         Entry != &Detector->TransitionList;
         Entry = Next) {

        Next = Entry->Flink;
        Transition = CONTAINING_RECORD(
            Entry, HGD_TRANSITION_INTERNAL, ListEntry);

        if ((CurrentTime.QuadPart - Transition->Info.Timestamp.QuadPart) >
            TimeoutTicks) {
            RemoveEntryList(&Transition->ListEntry);
            InterlockedDecrement(&Detector->TransitionCount);
            InsertTailList(&StaleList, &Transition->ListEntry);
        }
    }

    ExReleasePushLockExclusive(&Detector->TransitionLock);
    KeLeaveCriticalRegion();

    //
    // Free stale transitions outside lock
    //
    while (!IsListEmpty(&StaleList)) {
        Entry = RemoveHeadList(&StaleList);
        Transition = CONTAINING_RECORD(
            Entry, HGD_TRANSITION_INTERNAL, ListEntry);
        HgdpFreeTransitionInternal(Detector, Transition);
    }
}


static VOID
HgdpCleanupStaleProcessContexts(
    _In_ PHGD_DETECTOR Detector
    )
/*++
Routine Description:
    Removes process contexts for processes that have exited.
    This handles the case where HgdRemoveProcessContext was not
    called explicitly (e.g., missed process-exit notification).

    We avoid calling PsLookupProcessByProcessId while holding the
    push lock to prevent potential deadlock with kernel process locks.
    Instead: collect PIDs under lock, release, check liveness, then
    re-acquire to remove confirmed stale entries.
--*/
{
    HANDLE CandidatePids[32];
    ULONG CandidateCount = 0;
    PLIST_ENTRY Entry;
    PHGD_PROCESS_CONTEXT Context;
    LIST_ENTRY StaleList;
    HANDLE StalePids[32];
    ULONG StaleCount = 0;
    ULONG i;

    InitializeListHead(&StaleList);

    //
    // Phase 1: Collect candidate PIDs under shared lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->ProcessLock);

    for (Entry = Detector->ProcessContextList.Flink;
         Entry != &Detector->ProcessContextList && CandidateCount < ARRAYSIZE(CandidatePids);
         Entry = Entry->Flink) {

        Context = CONTAINING_RECORD(Entry, HGD_PROCESS_CONTEXT, ListEntry);

        if (!Context->MarkedForRemoval) {
            CandidatePids[CandidateCount] = Context->ProcessId;
            CandidateCount++;
        }
    }

    ExReleasePushLockShared(&Detector->ProcessLock);
    KeLeaveCriticalRegion();

    if (CandidateCount == 0) {
        return;
    }

    //
    // Phase 2: Check process liveness WITHOUT holding any lock
    //
    for (i = 0; i < CandidateCount; i++) {
        PEPROCESS Process = NULL;
        NTSTATUS Status;
        BOOLEAN IsStale = FALSE;

        Status = PsLookupProcessByProcessId(CandidatePids[i], &Process);
        if (!NT_SUCCESS(Status)) {
            IsStale = TRUE;
        } else {
            IsStale = ShadowStrikeIsProcessTerminating(Process);
            ObDereferenceObject(Process);
        }

        if (IsStale && StaleCount < ARRAYSIZE(StalePids)) {
            StalePids[StaleCount] = CandidatePids[i];
            StaleCount++;
        }
    }

    if (StaleCount == 0) {
        return;
    }

    //
    // Phase 3: Remove confirmed stale entries under exclusive lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->ProcessLock);

    for (i = 0; i < StaleCount; i++) {
        for (Entry = Detector->ProcessContextList.Flink;
             Entry != &Detector->ProcessContextList;
             Entry = Entry->Flink) {

            Context = CONTAINING_RECORD(Entry, HGD_PROCESS_CONTEXT, ListEntry);

            if (Context->ProcessId == StalePids[i] &&
                !Context->MarkedForRemoval) {

                InterlockedExchange8(
                    (volatile CHAR*)&Context->MarkedForRemoval, TRUE);
                RemoveEntryList(&Context->ListEntry);
                InitializeListHead(&Context->ListEntry);
                InterlockedDecrement(&Detector->ProcessContextCount);
                InsertTailList(&StaleList, &Context->ListEntry);
                break;
            }
        }
    }

    ExReleasePushLockExclusive(&Detector->ProcessLock);
    KeLeaveCriticalRegion();

    //
    // Phase 4: Dereference outside the lock (may free if refcount drops to 0)
    //
    while (!IsListEmpty(&StaleList)) {
        Entry = RemoveHeadList(&StaleList);
        Context = CONTAINING_RECORD(Entry, HGD_PROCESS_CONTEXT, ListEntry);
        InitializeListHead(&Context->ListEntry);
        HgdpDereferenceProcessContext(Detector, Context);
    }
}
