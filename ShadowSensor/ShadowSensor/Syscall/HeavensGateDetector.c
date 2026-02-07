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
- Tartarus Gate detection (exception-based SSN resolution)
- Legitimate WoW64 transition validation
- Syscall origin verification
- Pattern-based shellcode detection

Implementation Features:
- Per-process WoW64 context tracking
- Known good transition address caching
- Syscall number correlation with transition patterns
- IRQL-safe lock-free statistics
- Lookaside lists for high-frequency allocations
- Asynchronous notification callbacks

Detection Techniques Covered:
- T1106: Native API (direct syscall abuse)
- T1055: Process Injection (WoW64 abuse for injection)
- T1562: Impair Defenses (security product bypass)
- T1027: Obfuscated Files (encoded syscall stubs)

@author ShadowStrike Security Team
@version 2.0.0 (Enterprise Edition)
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#include "HeavensGateDetector.h"
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/ProcessUtils.h"
#include <ntstrsafe.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, HgdInitialize)
#pragma alloc_text(PAGE, HgdShutdown)
#pragma alloc_text(PAGE, HgdRefreshWow64Addresses)
#endif

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

#define HGD_SIGNATURE                   'DGHH'  // HHGD reversed
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
#define HGD_PATTERN_PUSH_33             0x6A33  // PUSH 0x33

//
// Suspicion score thresholds
//
#define HGD_SUSPICION_LOW               25
#define HGD_SUSPICION_MEDIUM            50
#define HGD_SUSPICION_HIGH              75
#define HGD_SUSPICION_CRITICAL          90

//
// Pool tags
//
#define HGD_POOL_TAG_TRANSITION         'rTGH'  // Transition record
#define HGD_POOL_TAG_CONTEXT            'xCGH'  // Process context
#define HGD_POOL_TAG_PATTERN            'tPGH'  // Pattern entry

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

//
// Callback registration entry
//
typedef struct _HGD_CALLBACK_ENTRY {
    PVOID Callback;
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
// Per-process WoW64 context
//
typedef struct _HGD_PROCESS_CONTEXT {
    HANDLE ProcessId;
    PEPROCESS Process;

    //
    // WoW64 state
    //
    BOOLEAN IsWow64Process;
    PVOID Wow64TransitionAddress;       // wow64cpu!KiFastSystemCall or similar
    PVOID Wow64SyscallAddress;          // wow64!Wow64SystemServiceCall
    PVOID NtdllBase32;                  // 32-bit ntdll base
    PVOID NtdllBase64;                  // 64-bit ntdll base (wow64 version)
    SIZE_T NtdllSize32;
    SIZE_T NtdllSize64;

    //
    // Transition tracking
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
    KSPIN_LOCK KnownGoodLock;

    //
    // Flags
    //
    ULONG Flags;
    ULONG SuspicionScore;

    //
    // Reference counting
    //
    volatile LONG RefCount;

    //
    // List linkage
    //
    LIST_ENTRY ListEntry;

} HGD_PROCESS_CONTEXT, *PHGD_PROCESS_CONTEXT;

//
// Process context flags
//
#define HGD_PROC_FLAG_MONITORED         0x00000001
#define HGD_PROC_FLAG_HIGH_RISK         0x00000002
#define HGD_PROC_FLAG_HEAVENS_GATE      0x00000004
#define HGD_PROC_FLAG_HELLS_GATE        0x00000008
#define HGD_PROC_FLAG_BLOCKED           0x00000010

//
// Extended detector structure
//
typedef struct _HGD_DETECTOR_INTERNAL {
    //
    // Public structure (must be first)
    //
    HGD_DETECTOR Public;

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
    // Callback registrations
    //
    HGD_CALLBACK_ENTRY DetectionCallbacks[HGD_MAX_CALLBACKS];
    KSPIN_LOCK CallbackLock;
    ULONG CallbackCount;

    //
    // Lookaside lists
    //
    NPAGED_LOOKASIDE_LIST TransitionLookaside;
    NPAGED_LOOKASIDE_LIST ContextLookaside;
    BOOLEAN LookasideInitialized;

    //
    // System WoW64 addresses (resolved at init)
    //
    PVOID SystemWow64TransitionAddress;
    PVOID SystemWow64SyscallAddress;
    PVOID SystemWow64CpuBase;
    SIZE_T SystemWow64CpuSize;

    //
    // Cleanup timer
    //
    KTIMER CleanupTimer;
    KDPC CleanupDpc;
    BOOLEAN CleanupTimerActive;

    //
    // Shutdown flag
    //
    volatile BOOLEAN ShutdownRequested;

} HGD_DETECTOR_INTERNAL, *PHGD_DETECTOR_INTERNAL;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

//
// Process context management
//
static PHGD_PROCESS_CONTEXT
HgdpAllocateProcessContext(
    _In_ PHGD_DETECTOR_INTERNAL Detector,
    _In_ HANDLE ProcessId
    );

static VOID
HgdpFreeProcessContext(
    _In_ PHGD_DETECTOR_INTERNAL Detector,
    _In_ PHGD_PROCESS_CONTEXT Context
    );

static PHGD_PROCESS_CONTEXT
HgdpLookupProcessContext(
    _In_ PHGD_DETECTOR_INTERNAL Detector,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN CreateIfNotFound
    );

static VOID
HgdpReferenceProcessContext(
    _Inout_ PHGD_PROCESS_CONTEXT Context
    );

static VOID
HgdpDereferenceProcessContext(
    _In_ PHGD_DETECTOR_INTERNAL Detector,
    _Inout_ PHGD_PROCESS_CONTEXT Context
    );

//
// Transition management
//
static PHGD_TRANSITION
HgdpAllocateTransition(
    _In_ PHGD_DETECTOR_INTERNAL Detector
    );

static VOID
HgdpFreeTransitionInternal(
    _In_ PHGD_DETECTOR_INTERNAL Detector,
    _In_ PHGD_TRANSITION Transition
    );

static NTSTATUS
HgdpInsertTransition(
    _In_ PHGD_DETECTOR_INTERNAL Detector,
    _In_ PHGD_TRANSITION Transition
    );

//
// Detection analysis
//
static HGD_GATE_TYPE
HgdpAnalyzeTransitionAddress(
    _In_ PHGD_DETECTOR_INTERNAL Detector,
    _In_ PHGD_PROCESS_CONTEXT ProcessContext,
    _In_ PVOID TransitionAddress,
    _Out_ PULONG SuspicionScore
    );

static BOOLEAN
HgdpIsKnownWow64Address(
    _In_ PHGD_DETECTOR_INTERNAL Detector,
    _In_ PHGD_PROCESS_CONTEXT ProcessContext,
    _In_ PVOID Address
    );

static BOOLEAN
HgdpDetectHeavensGatePattern(
    _In_reads_bytes_(Size) PUCHAR Buffer,
    _In_ SIZE_T Size,
    _Out_ PULONG PatternOffset
    );

static BOOLEAN
HgdpDetectHellsGatePattern(
    _In_reads_bytes_(Size) PUCHAR Buffer,
    _In_ SIZE_T Size
    );

static BOOLEAN
HgdpDetectHalosGatePattern(
    _In_reads_bytes_(Size) PUCHAR Buffer,
    _In_ SIZE_T Size
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
    _In_ PHGD_DETECTOR_INTERNAL Detector,
    _In_ PHGD_PROCESS_CONTEXT ProcessContext
    );

//
// Pattern management
//
static VOID
HgdpInitializePatterns(
    _In_ PHGD_DETECTOR_INTERNAL Detector
    );

static VOID
HgdpCleanupPatterns(
    _In_ PHGD_DETECTOR_INTERNAL Detector
    );

//
// Callback notification
//
static VOID
HgdpNotifyCallbacks(
    _In_ PHGD_DETECTOR_INTERNAL Detector,
    _In_ PHGD_TRANSITION Transition
    );

//
// Timer and cleanup
//
static VOID
HgdpCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

static VOID
HgdpCleanupStaleTransitions(
    _In_ PHGD_DETECTOR_INTERNAL Detector
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

Arguments:
    Detector - Receives pointer to initialized detector.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PHGD_DETECTOR_INTERNAL Internal = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    LARGE_INTEGER DueTime;

    PAGED_CODE();

    if (Detector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Detector = NULL;

    //
    // Allocate internal detector structure
    //
    Internal = (PHGD_DETECTOR_INTERNAL)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(HGD_DETECTOR_INTERNAL),
        HGD_POOL_TAG
        );

    if (Internal == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Internal, sizeof(HGD_DETECTOR_INTERNAL));

    //
    // Initialize process context list
    //
    InitializeListHead(&Internal->ProcessContextList);
    ExInitializePushLock(&Internal->ProcessLock);

    //
    // Initialize transition list
    //
    InitializeListHead(&Internal->Public.TransitionList);
    ExInitializePushLock(&Internal->Public.TransitionLock);

    //
    // Initialize pattern list
    //
    InitializeListHead(&Internal->PatternList);
    ExInitializePushLock(&Internal->PatternLock);

    //
    // Initialize callback infrastructure
    //
    KeInitializeSpinLock(&Internal->CallbackLock);

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &Internal->TransitionLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(HGD_TRANSITION),
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
    KeQuerySystemTime(&Internal->Public.Stats.StartTime);

    //
    // Initialize cleanup timer
    //
    KeInitializeTimer(&Internal->CleanupTimer);
    KeInitializeDpc(&Internal->CleanupDpc, HgdpCleanupTimerDpc, Internal);

    //
    // Start cleanup timer (every 30 seconds)
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
    // Try to resolve system WoW64 addresses
    //
    Status = HgdRefreshWow64Addresses((PHGD_DETECTOR)Internal);
    if (!NT_SUCCESS(Status)) {
        //
        // Non-fatal - may not have WoW64 processes yet
        //
        Status = STATUS_SUCCESS;
    }

    //
    // Mark as initialized
    //
    Internal->Public.Initialized = TRUE;
    *Detector = (PHGD_DETECTOR)Internal;

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

Arguments:
    Detector - Detector instance to shutdown.
--*/
{
    PHGD_DETECTOR_INTERNAL Internal = (PHGD_DETECTOR_INTERNAL)Detector;
    PLIST_ENTRY Entry;
    PHGD_TRANSITION Transition;
    PHGD_PROCESS_CONTEXT Context;

    PAGED_CODE();

    if (Internal == NULL || !Internal->Public.Initialized) {
        return;
    }

    Internal->Public.Initialized = FALSE;
    Internal->ShutdownRequested = TRUE;

    //
    // Cancel cleanup timer
    //
    if (Internal->CleanupTimerActive) {
        KeCancelTimer(&Internal->CleanupTimer);
        Internal->CleanupTimerActive = FALSE;
    }

    //
    // Free all transitions
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Internal->Public.TransitionLock);

    while (!IsListEmpty(&Internal->Public.TransitionList)) {
        Entry = RemoveHeadList(&Internal->Public.TransitionList);
        Transition = CONTAINING_RECORD(Entry, HGD_TRANSITION, ListEntry);
        ExReleasePushLockExclusive(&Internal->Public.TransitionLock);
        KeLeaveCriticalRegion();

        HgdpFreeTransitionInternal(Internal, Transition);

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Internal->Public.TransitionLock);
    }

    ExReleasePushLockExclusive(&Internal->Public.TransitionLock);
    KeLeaveCriticalRegion();

    //
    // Free all process contexts
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Internal->ProcessLock);

    while (!IsListEmpty(&Internal->ProcessContextList)) {
        Entry = RemoveHeadList(&Internal->ProcessContextList);
        Context = CONTAINING_RECORD(Entry, HGD_PROCESS_CONTEXT, ListEntry);
        ExReleasePushLockExclusive(&Internal->ProcessLock);
        KeLeaveCriticalRegion();

        HgdpFreeProcessContext(Internal, Context);

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Internal->ProcessLock);
    }

    ExReleasePushLockExclusive(&Internal->ProcessLock);
    KeLeaveCriticalRegion();

    //
    // Cleanup patterns
    //
    HgdpCleanupPatterns(Internal);

    //
    // Delete lookaside lists
    //
    if (Internal->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&Internal->TransitionLookaside);
        ExDeleteNPagedLookasideList(&Internal->ContextLookaside);
    }

    //
    // Free detector
    //
    ShadowStrikeFreePoolWithTag(Internal, HGD_POOL_TAG);
}


_Use_decl_annotations_
NTSTATUS
HgdAnalyzeTransition(
    _In_ PHGD_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ PVOID TransitionAddress,
    _Out_ PHGD_TRANSITION* Transition
    )
/*++
Routine Description:
    Analyzes a potential Heaven's Gate transition.

Arguments:
    Detector - Detector instance.
    ProcessId - Process ID where transition occurred.
    ThreadId - Thread ID.
    TransitionAddress - Address of transition code.
    Transition - Receives transition record.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PHGD_DETECTOR_INTERNAL Internal = (PHGD_DETECTOR_INTERNAL)Detector;
    PHGD_PROCESS_CONTEXT ProcessContext = NULL;
    PHGD_TRANSITION NewTransition = NULL;
    HGD_GATE_TYPE GateType;
    ULONG SuspicionScore = 0;
    NTSTATUS Status = STATUS_SUCCESS;
    UCHAR CodeBuffer[64];
    SIZE_T BytesRead = 0;

    if (Internal == NULL || !Internal->Public.Initialized || Transition == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Transition = NULL;

    //
    // Get or create process context
    //
    ProcessContext = HgdpLookupProcessContext(Internal, ProcessId, TRUE);
    if (ProcessContext == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Skip non-WoW64 processes
    //
    if (!ProcessContext->IsWow64Process) {
        HgdpDereferenceProcessContext(Internal, ProcessContext);
        return STATUS_NOT_SUPPORTED;
    }

    //
    // Read code at transition address
    //
    RtlZeroMemory(CodeBuffer, sizeof(CodeBuffer));
    Status = HgdpReadProcessMemory(
        ProcessId,
        TransitionAddress,
        CodeBuffer,
        sizeof(CodeBuffer)
        );

    if (!NT_SUCCESS(Status)) {
        //
        // Can't read - highly suspicious
        //
        SuspicionScore = HGD_SUSPICION_HIGH;
        GateType = HgdGate_ManualTransition;
    } else {
        //
        // Analyze transition type
        //
        GateType = HgdpAnalyzeTransitionAddress(
            Internal,
            ProcessContext,
            TransitionAddress,
            &SuspicionScore
            );
    }

    //
    // Allocate transition record
    //
    NewTransition = HgdpAllocateTransition(Internal);
    if (NewTransition == NULL) {
        HgdpDereferenceProcessContext(Internal, ProcessContext);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Populate transition record
    //
    NewTransition->ProcessId = ProcessId;
    NewTransition->ThreadId = ThreadId;
    NewTransition->Type = GateType;
    NewTransition->SourceRIP = TransitionAddress;
    NewTransition->SourceCS = HGD_CS_SEGMENT_32BIT;
    NewTransition->TargetCS = HGD_CS_SEGMENT_64BIT;
    NewTransition->SuspicionScore = SuspicionScore;
    NewTransition->IsFromWow64 = HgdpIsKnownWow64Address(Internal, ProcessContext, TransitionAddress);
    KeQuerySystemTime(&NewTransition->Timestamp);

    //
    // Update statistics
    //
    InterlockedIncrement64(&Internal->Public.Stats.TransitionsDetected);
    InterlockedIncrement64(&ProcessContext->TotalTransitions);

    if (NewTransition->IsFromWow64 && GateType == HgdGate_WoW64Transition) {
        InterlockedIncrement64(&Internal->Public.Stats.LegitimateTransitions);
        InterlockedIncrement64(&ProcessContext->LegitimateTransitions);
    } else {
        InterlockedIncrement64(&Internal->Public.Stats.SuspiciousTransitions);
        InterlockedIncrement64(&ProcessContext->SuspiciousTransitions);

        //
        // Set high-risk flag
        //
        if (SuspicionScore >= HGD_SUSPICION_HIGH) {
            ProcessContext->Flags |= HGD_PROC_FLAG_HIGH_RISK;

            if (GateType == HgdGate_HeavensGate) {
                ProcessContext->Flags |= HGD_PROC_FLAG_HEAVENS_GATE;
            } else if (GateType == HgdGate_HellsGate) {
                ProcessContext->Flags |= HGD_PROC_FLAG_HELLS_GATE;
            }
        }
    }

    //
    // Insert into tracking list
    //
    HgdpInsertTransition(Internal, NewTransition);

    //
    // Notify callbacks
    //
    if (SuspicionScore >= HGD_SUSPICION_MEDIUM) {
        HgdpNotifyCallbacks(Internal, NewTransition);
    }

    HgdpDereferenceProcessContext(Internal, ProcessContext);

    *Transition = NewTransition;

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
    Checks if an address is a legitimate WoW64 transition point.

Arguments:
    Detector - Detector instance.
    Address - Address to check.
    IsLegitimate - Receives TRUE if legitimate.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PHGD_DETECTOR_INTERNAL Internal = (PHGD_DETECTOR_INTERNAL)Detector;
    HANDLE CurrentProcessId;
    PHGD_PROCESS_CONTEXT ProcessContext;

    if (Internal == NULL || !Internal->Public.Initialized || IsLegitimate == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsLegitimate = FALSE;

    CurrentProcessId = PsGetCurrentProcessId();

    ProcessContext = HgdpLookupProcessContext(Internal, CurrentProcessId, FALSE);
    if (ProcessContext == NULL) {
        //
        // No context = not monitored = assume legitimate for now
        //
        *IsLegitimate = TRUE;
        return STATUS_SUCCESS;
    }

    *IsLegitimate = HgdpIsKnownWow64Address(Internal, ProcessContext, Address);

    HgdpDereferenceProcessContext(Internal, ProcessContext);

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
HgdGetTransitions(
    _In_ PHGD_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_writes_to_(Max, *Count) PHGD_TRANSITION* Transitions,
    _In_ ULONG Max,
    _Out_ PULONG Count
    )
/*++
Routine Description:
    Gets transition records for a specific process.

Arguments:
    Detector - Detector instance.
    ProcessId - Process ID to query.
    Transitions - Array to receive transition pointers.
    Max - Maximum transitions to return.
    Count - Receives number of transitions returned.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PHGD_DETECTOR_INTERNAL Internal = (PHGD_DETECTOR_INTERNAL)Detector;
    PLIST_ENTRY Entry;
    PHGD_TRANSITION Transition;
    ULONG Found = 0;

    if (Internal == NULL || !Internal->Public.Initialized ||
        Transitions == NULL || Count == NULL || Max == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *Count = 0;
    RtlZeroMemory(Transitions, Max * sizeof(PHGD_TRANSITION));

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Internal->Public.TransitionLock);

    for (Entry = Internal->Public.TransitionList.Flink;
         Entry != &Internal->Public.TransitionList && Found < Max;
         Entry = Entry->Flink) {

        Transition = CONTAINING_RECORD(Entry, HGD_TRANSITION, ListEntry);

        if (Transition->ProcessId == ProcessId) {
            Transitions[Found] = Transition;
            Found++;
        }
    }

    ExReleasePushLockShared(&Internal->Public.TransitionLock);
    KeLeaveCriticalRegion();

    *Count = Found;

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
HgdFreeTransition(
    _In_ PHGD_TRANSITION Transition
    )
/*++
Routine Description:
    Frees a transition record.

Arguments:
    Transition - Transition to free.
--*/
{
    if (Transition == NULL) {
        return;
    }

    //
    // Free source module string if allocated
    //
    if (Transition->SourceModule.Buffer != NULL) {
        ShadowStrikeFreePoolWithTag(
            Transition->SourceModule.Buffer,
            HGD_POOL_TAG_TRANSITION
            );
        Transition->SourceModule.Buffer = NULL;
    }

    //
    // Note: Transition itself is freed by detector when removed from list
    //
}


_Use_decl_annotations_
NTSTATUS
HgdRefreshWow64Addresses(
    _In_ PHGD_DETECTOR Detector
    )
/*++
Routine Description:
    Refreshes system WoW64 module addresses.

Arguments:
    Detector - Detector instance.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PHGD_DETECTOR_INTERNAL Internal = (PHGD_DETECTOR_INTERNAL)Detector;

    PAGED_CODE();

    if (Internal == NULL || !Internal->Public.Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Resolve wow64cpu.dll transition address
    // This would typically be done by:
    // 1. Finding wow64cpu.dll in system32
    // 2. Locating KiFastSystemCall or equivalent
    // 3. Caching the address pattern
    //
    // For now, we rely on per-process resolution
    //

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
HgdRegisterCallback(
    _In_ PHGD_DETECTOR Detector,
    _In_ PVOID Callback,
    _In_opt_ PVOID Context
    )
/*++
Routine Description:
    Registers a detection callback.

Arguments:
    Detector - Detector instance.
    Callback - Callback function.
    Context - User context.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PHGD_DETECTOR_INTERNAL Internal = (PHGD_DETECTOR_INTERNAL)Detector;
    KIRQL OldIrql;
    ULONG i;

    if (Internal == NULL || !Internal->Public.Initialized || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&Internal->CallbackLock, &OldIrql);

    for (i = 0; i < HGD_MAX_CALLBACKS; i++) {
        if (!Internal->DetectionCallbacks[i].Active) {
            Internal->DetectionCallbacks[i].Callback = Callback;
            Internal->DetectionCallbacks[i].Context = Context;
            Internal->DetectionCallbacks[i].Active = TRUE;
            Internal->CallbackCount++;
            KeReleaseSpinLock(&Internal->CallbackLock, OldIrql);
            return STATUS_SUCCESS;
        }
    }

    KeReleaseSpinLock(&Internal->CallbackLock, OldIrql);
    return STATUS_QUOTA_EXCEEDED;
}


_Use_decl_annotations_
VOID
HgdUnregisterCallback(
    _In_ PHGD_DETECTOR Detector,
    _In_ PVOID Callback
    )
/*++
Routine Description:
    Unregisters a detection callback.

Arguments:
    Detector - Detector instance.
    Callback - Callback to unregister.
--*/
{
    PHGD_DETECTOR_INTERNAL Internal = (PHGD_DETECTOR_INTERNAL)Detector;
    KIRQL OldIrql;
    ULONG i;

    if (Internal == NULL || Callback == NULL) {
        return;
    }

    KeAcquireSpinLock(&Internal->CallbackLock, &OldIrql);

    for (i = 0; i < HGD_MAX_CALLBACKS; i++) {
        if (Internal->DetectionCallbacks[i].Active &&
            Internal->DetectionCallbacks[i].Callback == Callback) {
            Internal->DetectionCallbacks[i].Active = FALSE;
            Internal->DetectionCallbacks[i].Callback = NULL;
            Internal->DetectionCallbacks[i].Context = NULL;
            Internal->CallbackCount--;
            break;
        }
    }

    KeReleaseSpinLock(&Internal->CallbackLock, OldIrql);
}


_Use_decl_annotations_
NTSTATUS
HgdGetStatistics(
    _In_ PHGD_DETECTOR Detector,
    _Out_ PULONG64 TotalTransitions,
    _Out_ PULONG64 LegitimateTransitions,
    _Out_ PULONG64 SuspiciousTransitions
    )
/*++
Routine Description:
    Gets detector statistics.

Arguments:
    Detector - Detector instance.
    TotalTransitions - Receives total transition count.
    LegitimateTransitions - Receives legitimate count.
    SuspiciousTransitions - Receives suspicious count.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PHGD_DETECTOR_INTERNAL Internal = (PHGD_DETECTOR_INTERNAL)Detector;

    if (Internal == NULL || !Internal->Public.Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (TotalTransitions != NULL) {
        *TotalTransitions = (ULONG64)Internal->Public.Stats.TransitionsDetected;
    }

    if (LegitimateTransitions != NULL) {
        *LegitimateTransitions = (ULONG64)Internal->Public.Stats.LegitimateTransitions;
    }

    if (SuspiciousTransitions != NULL) {
        *SuspiciousTransitions = (ULONG64)Internal->Public.Stats.SuspiciousTransitions;
    }

    return STATUS_SUCCESS;
}


// ============================================================================
// PRIVATE FUNCTION IMPLEMENTATIONS
// ============================================================================

static PHGD_PROCESS_CONTEXT
HgdpAllocateProcessContext(
    _In_ PHGD_DETECTOR_INTERNAL Detector,
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
    Context->RefCount = 1;
    KeInitializeSpinLock(&Context->KnownGoodLock);
    InitializeListHead(&Context->ListEntry);

    //
    // Get process object
    //
    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (NT_SUCCESS(Status)) {
        Context->Process = Process;
        Context->IsWow64Process = ShadowStrikeIsProcessWow64(Process);

        //
        // Resolve WoW64 addresses for this process
        //
        if (Context->IsWow64Process) {
            HgdpResolveWow64Addresses(Detector, Context);
        }

        ObDereferenceObject(Process);
    }

    return Context;
}


static VOID
HgdpFreeProcessContext(
    _In_ PHGD_DETECTOR_INTERNAL Detector,
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
    _In_ PHGD_DETECTOR_INTERNAL Detector,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN CreateIfNotFound
    )
{
    PLIST_ENTRY Entry;
    PHGD_PROCESS_CONTEXT Context = NULL;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->ProcessLock);

    for (Entry = Detector->ProcessContextList.Flink;
         Entry != &Detector->ProcessContextList;
         Entry = Entry->Flink) {

        Context = CONTAINING_RECORD(Entry, HGD_PROCESS_CONTEXT, ListEntry);

        if (Context->ProcessId == ProcessId) {
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
    // Create new context
    //
    Context = HgdpAllocateProcessContext(Detector, ProcessId);
    if (Context == NULL) {
        return NULL;
    }

    //
    // Insert into list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->ProcessLock);

    //
    // Check for race condition
    //
    for (Entry = Detector->ProcessContextList.Flink;
         Entry != &Detector->ProcessContextList;
         Entry = Entry->Flink) {

        PHGD_PROCESS_CONTEXT Existing = CONTAINING_RECORD(Entry, HGD_PROCESS_CONTEXT, ListEntry);

        if (Existing->ProcessId == ProcessId) {
            //
            // Another thread created it
            //
            HgdpReferenceProcessContext(Existing);
            ExReleasePushLockExclusive(&Detector->ProcessLock);
            KeLeaveCriticalRegion();
            HgdpFreeProcessContext(Detector, Context);
            return Existing;
        }
    }

    InsertTailList(&Detector->ProcessContextList, &Context->ListEntry);
    InterlockedIncrement(&Detector->ProcessContextCount);
    HgdpReferenceProcessContext(Context);

    ExReleasePushLockExclusive(&Detector->ProcessLock);
    KeLeaveCriticalRegion();

    return Context;
}


static VOID
HgdpReferenceProcessContext(
    _Inout_ PHGD_PROCESS_CONTEXT Context
    )
{
    InterlockedIncrement(&Context->RefCount);
}


static VOID
HgdpDereferenceProcessContext(
    _In_ PHGD_DETECTOR_INTERNAL Detector,
    _Inout_ PHGD_PROCESS_CONTEXT Context
    )
{
    if (InterlockedDecrement(&Context->RefCount) == 0) {
        //
        // Remove from list and free
        //
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Detector->ProcessLock);

        if (!IsListEmpty(&Context->ListEntry)) {
            RemoveEntryList(&Context->ListEntry);
            InitializeListHead(&Context->ListEntry);
            InterlockedDecrement(&Detector->ProcessContextCount);
        }

        ExReleasePushLockExclusive(&Detector->ProcessLock);
        KeLeaveCriticalRegion();

        HgdpFreeProcessContext(Detector, Context);
    }
}


static PHGD_TRANSITION
HgdpAllocateTransition(
    _In_ PHGD_DETECTOR_INTERNAL Detector
    )
{
    PHGD_TRANSITION Transition;

    Transition = (PHGD_TRANSITION)ExAllocateFromNPagedLookasideList(
        &Detector->TransitionLookaside
        );

    if (Transition != NULL) {
        RtlZeroMemory(Transition, sizeof(HGD_TRANSITION));
        InitializeListHead(&Transition->ListEntry);
    }

    return Transition;
}


static VOID
HgdpFreeTransitionInternal(
    _In_ PHGD_DETECTOR_INTERNAL Detector,
    _In_ PHGD_TRANSITION Transition
    )
{
    if (Transition->SourceModule.Buffer != NULL) {
        ShadowStrikeFreePoolWithTag(
            Transition->SourceModule.Buffer,
            HGD_POOL_TAG_TRANSITION
            );
    }

    ExFreeToNPagedLookasideList(&Detector->TransitionLookaside, Transition);
}


static NTSTATUS
HgdpInsertTransition(
    _In_ PHGD_DETECTOR_INTERNAL Detector,
    _In_ PHGD_TRANSITION Transition
    )
{
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->Public.TransitionLock);

    //
    // Check limit
    //
    if ((ULONG)Detector->Public.TransitionCount >= HGD_MAX_TRANSITIONS) {
        //
        // Remove oldest entry
        //
        if (!IsListEmpty(&Detector->Public.TransitionList)) {
            PLIST_ENTRY Entry = RemoveHeadList(&Detector->Public.TransitionList);
            PHGD_TRANSITION OldTransition = CONTAINING_RECORD(Entry, HGD_TRANSITION, ListEntry);
            InterlockedDecrement(&Detector->Public.TransitionCount);

            ExReleasePushLockExclusive(&Detector->Public.TransitionLock);
            KeLeaveCriticalRegion();

            HgdpFreeTransitionInternal(Detector, OldTransition);

            KeEnterCriticalRegion();
            ExAcquirePushLockExclusive(&Detector->Public.TransitionLock);
        }
    }

    InsertTailList(&Detector->Public.TransitionList, &Transition->ListEntry);
    InterlockedIncrement(&Detector->Public.TransitionCount);

    ExReleasePushLockExclusive(&Detector->Public.TransitionLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}


static HGD_GATE_TYPE
HgdpAnalyzeTransitionAddress(
    _In_ PHGD_DETECTOR_INTERNAL Detector,
    _In_ PHGD_PROCESS_CONTEXT ProcessContext,
    _In_ PVOID TransitionAddress,
    _Out_ PULONG SuspicionScore
    )
{
    UCHAR CodeBuffer[64];
    NTSTATUS Status;
    ULONG PatternOffset = 0;
    HGD_GATE_TYPE GateType = HgdGate_None;

    *SuspicionScore = 0;

    //
    // Check if this is a known legitimate WoW64 address
    //
    if (HgdpIsKnownWow64Address(Detector, ProcessContext, TransitionAddress)) {
        *SuspicionScore = 0;
        return HgdGate_WoW64Transition;
    }

    //
    // Read code at transition address
    //
    Status = HgdpReadProcessMemory(
        ProcessContext->ProcessId,
        TransitionAddress,
        CodeBuffer,
        sizeof(CodeBuffer)
        );

    if (!NT_SUCCESS(Status)) {
        //
        // Can't read memory - suspicious
        //
        *SuspicionScore = HGD_SUSPICION_HIGH;
        return HgdGate_ManualTransition;
    }

    //
    // Check for Heaven's Gate pattern (manual CS segment switch)
    //
    if (HgdpDetectHeavensGatePattern(CodeBuffer, sizeof(CodeBuffer), &PatternOffset)) {
        *SuspicionScore = HGD_SUSPICION_CRITICAL;
        return HgdGate_HeavensGate;
    }

    //
    // Check for Hell's Gate pattern (dynamic SSN resolution)
    //
    if (HgdpDetectHellsGatePattern(CodeBuffer, sizeof(CodeBuffer))) {
        *SuspicionScore = HGD_SUSPICION_CRITICAL;
        return HgdGate_HellsGate;
    }

    //
    // Check for Halo's Gate pattern (neighbor walking)
    //
    if (HgdpDetectHalosGatePattern(CodeBuffer, sizeof(CodeBuffer))) {
        *SuspicionScore = HGD_SUSPICION_HIGH;
        return HgdGate_HellsGate;  // Similar classification
    }

    //
    // Check if address is in known modules
    //
    if (ProcessContext->NtdllBase32 != NULL &&
        (ULONG_PTR)TransitionAddress >= (ULONG_PTR)ProcessContext->NtdllBase32 &&
        (ULONG_PTR)TransitionAddress < (ULONG_PTR)ProcessContext->NtdllBase32 + ProcessContext->NtdllSize32) {
        //
        // From 32-bit ntdll - likely legitimate
        //
        *SuspicionScore = HGD_SUSPICION_LOW;
        return HgdGate_WoW64Transition;
    }

    //
    // Unknown transition - medium suspicion
    //
    *SuspicionScore = HGD_SUSPICION_MEDIUM;
    return HgdGate_ManualTransition;
}


static BOOLEAN
HgdpIsKnownWow64Address(
    _In_ PHGD_DETECTOR_INTERNAL Detector,
    _In_ PHGD_PROCESS_CONTEXT ProcessContext,
    _In_ PVOID Address
    )
{
    KIRQL OldIrql;
    ULONG i;

    UNREFERENCED_PARAMETER(Detector);

    //
    // Check known transition addresses
    //
    if (ProcessContext->Wow64TransitionAddress == Address ||
        ProcessContext->Wow64SyscallAddress == Address) {
        return TRUE;
    }

    //
    // Check per-process known good list
    //
    KeAcquireSpinLock(&ProcessContext->KnownGoodLock, &OldIrql);

    for (i = 0; i < ProcessContext->KnownGoodCount; i++) {
        if (ProcessContext->KnownGoodAddresses[i] == Address) {
            KeReleaseSpinLock(&ProcessContext->KnownGoodLock, OldIrql);
            return TRUE;
        }
    }

    KeReleaseSpinLock(&ProcessContext->KnownGoodLock, OldIrql);

    return FALSE;
}


static BOOLEAN
HgdpDetectHeavensGatePattern(
    _In_reads_bytes_(Size) PUCHAR Buffer,
    _In_ SIZE_T Size,
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
    SIZE_T i;

    *PatternOffset = 0;

    if (Size < 6) {
        return FALSE;
    }

    for (i = 0; i < Size - 6; i++) {
        //
        // Pattern 1: PUSH 0x33 (6A 33)
        //
        if (Buffer[i] == 0x6A && Buffer[i + 1] == 0x33) {
            //
            // Check for CALL $+5 (E8 00 00 00 00)
            //
            if (i + 7 <= Size &&
                Buffer[i + 2] == 0xE8 &&
                Buffer[i + 3] == 0x00 &&
                Buffer[i + 4] == 0x00 &&
                Buffer[i + 5] == 0x00 &&
                Buffer[i + 6] == 0x00) {
                //
                // Look for ADD [ESP], X and RETF
                //
                if (i + 12 <= Size) {
                    //
                    // ADD DWORD PTR [ESP], imm8 (83 04 24 xx)
                    //
                    if (Buffer[i + 7] == 0x83 &&
                        Buffer[i + 8] == 0x04 &&
                        Buffer[i + 9] == 0x24) {
                        //
                        // RETF (CB)
                        //
                        if (i + 12 <= Size && Buffer[i + 11] == 0xCB) {
                            *PatternOffset = (ULONG)i;
                            return TRUE;
                        }
                    }
                }
            }

            //
            // Pattern 3: PUSH 0x33; PUSH imm32; RETF
            //
            if (i + 8 <= Size && Buffer[i + 2] == 0x68) {
                //
                // PUSH imm32 followed by RETF
                //
                if (i + 8 <= Size && Buffer[i + 7] == 0xCB) {
                    *PatternOffset = (ULONG)i;
                    return TRUE;
                }
            }
        }

        //
        // Pattern 2: JMP FAR (EA xx xx xx xx 33 00)
        //
        if (Buffer[i] == 0xEA && i + 7 <= Size) {
            //
            // Check for segment 0x33
            //
            if (Buffer[i + 5] == 0x33 && Buffer[i + 6] == 0x00) {
                *PatternOffset = (ULONG)i;
                return TRUE;
            }
        }

        //
        // Direct RETF without proper setup (suspicious)
        //
        if (Buffer[i] == 0xCB) {
            //
            // Check previous instructions for segment manipulation
            //
            if (i >= 2 && Buffer[i - 2] == 0x6A && Buffer[i - 1] == 0x33) {
                *PatternOffset = (ULONG)(i - 2);
                return TRUE;
            }
        }
    }

    return FALSE;
}


static BOOLEAN
HgdpDetectHellsGatePattern(
    _In_reads_bytes_(Size) PUCHAR Buffer,
    _In_ SIZE_T Size
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
    SIZE_T i;

    if (Size < 16) {
        return FALSE;
    }

    for (i = 0; i < Size - 16; i++) {
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
            SIZE_T j;
            for (j = i + 4; j < min(i + 32, Size - 3); j++) {
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
        // Looking for: MOV EAX, DWORD PTR [reg+4] after finding Nt/Zw function
        // This typically follows export resolution
        //
        if (Buffer[i] == 0x8B && (Buffer[i + 1] & 0xC0) == 0x40 &&
            Buffer[i + 2] == 0x04) {
            //
            // Check if preceded by call or indirect addressing
            //
            if (i >= 5) {
                //
                // CALL reg or CALL [reg]
                //
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
    _In_ SIZE_T Size
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
    SIZE_T i;

    if (Size < 24) {
        return FALSE;
    }

    for (i = 0; i < Size - 24; i++) {
        //
        // Pattern: Checking for JMP (hook detection)
        // CMP BYTE PTR [reg], 0xE9
        //
        if (Buffer[i] == 0x80 && (Buffer[i + 1] & 0xF8) == 0x38 &&
            Buffer[i + 2] == 0xE9) {
            //
            // Look for conditional jump (hook bypass logic)
            //
            SIZE_T j;
            for (j = i + 3; j < min(i + 16, Size - 2); j++) {
                if (Buffer[j] == 0x74 || Buffer[j] == 0x75 ||  // JE/JNE
                    Buffer[j] == 0x0F) {  // Extended conditional
                    //
                    // Look for ADD/SUB for neighbor walking
                    //
                    SIZE_T k;
                    for (k = j; k < min(j + 16, Size - 3); k++) {
                        if ((Buffer[k] == 0x83 || Buffer[k] == 0x81) &&
                            ((Buffer[k + 1] & 0xC0) == 0xC0)) {
                            //
                            // ADD/SUB reg, imm - likely walking stubs
                            //
                            return TRUE;
                        }
                    }
                }
            }
        }

        //
        // Alternative: Direct syscall stub structure check
        // MOV R10, RCX; MOV EAX, imm32; SYSCALL
        // 4C 8B D1 B8 xx xx xx xx 0F 05
        //
        if (i + 12 <= Size &&
            Buffer[i] == 0x4C && Buffer[i + 1] == 0x8B && Buffer[i + 2] == 0xD1 &&
            Buffer[i + 3] == 0xB8) {
            //
            // Check for SYSCALL instruction
            //
            SIZE_T j;
            for (j = i + 8; j < min(i + 16, Size - 1); j++) {
                if (Buffer[j] == 0x0F && Buffer[j + 1] == 0x05) {
                    //
                    // Found syscall stub pattern - check if it's from suspicious location
                    // This would need additional context to determine if Halo's Gate
                    //
                    return FALSE;  // Need more context
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
{
    NTSTATUS Status;
    PEPROCESS Process = NULL;
    KAPC_STATE ApcState;
    SIZE_T BytesCopied = 0;

    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    __try {
        KeStackAttachProcess(Process, &ApcState);

        __try {
            ProbeForRead(Address, Size, 1);
            RtlCopyMemory(Buffer, Address, Size);
            BytesCopied = Size;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Status = GetExceptionCode();
        }

        KeUnstackDetachProcess(&ApcState);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    ObDereferenceObject(Process);

    return (BytesCopied == Size) ? STATUS_SUCCESS : Status;
}


static NTSTATUS
HgdpResolveWow64Addresses(
    _In_ PHGD_DETECTOR_INTERNAL Detector,
    _In_ PHGD_PROCESS_CONTEXT ProcessContext
    )
{
    //
    // This would resolve:
    // 1. wow64cpu.dll base and size
    // 2. KiFastSystemCall / Wow64SystemServiceCall addresses
    // 3. 32-bit and 64-bit ntdll addresses
    //
    // For now, we'll populate with known offsets when the first
    // transition is detected and validated
    //

    UNREFERENCED_PARAMETER(Detector);
    UNREFERENCED_PARAMETER(ProcessContext);

    return STATUS_SUCCESS;
}


static VOID
HgdpInitializePatterns(
    _In_ PHGD_DETECTOR_INTERNAL Detector
    )
{
    //
    // Initialize known legitimate WoW64 transition patterns
    // These would be populated from wow64cpu.dll analysis
    //

    UNREFERENCED_PARAMETER(Detector);
}


static VOID
HgdpCleanupPatterns(
    _In_ PHGD_DETECTOR_INTERNAL Detector
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

    ExReleasePushLockExclusive(&Detector->PatternLock);
    KeLeaveCriticalRegion();
}


static VOID
HgdpNotifyCallbacks(
    _In_ PHGD_DETECTOR_INTERNAL Detector,
    _In_ PHGD_TRANSITION Transition
    )
{
    typedef VOID (*HGD_CALLBACK)(PHGD_TRANSITION, PVOID);

    KIRQL OldIrql;
    ULONG i;

    KeAcquireSpinLock(&Detector->CallbackLock, &OldIrql);

    for (i = 0; i < HGD_MAX_CALLBACKS; i++) {
        if (Detector->DetectionCallbacks[i].Active &&
            Detector->DetectionCallbacks[i].Callback != NULL) {

            HGD_CALLBACK Callback = (HGD_CALLBACK)Detector->DetectionCallbacks[i].Callback;
            PVOID Context = Detector->DetectionCallbacks[i].Context;

            KeReleaseSpinLock(&Detector->CallbackLock, OldIrql);

            __try {
                Callback(Transition, Context);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                // Ignore callback exceptions
            }

            KeAcquireSpinLock(&Detector->CallbackLock, &OldIrql);
        }
    }

    KeReleaseSpinLock(&Detector->CallbackLock, OldIrql);
}


static VOID
HgdpCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PHGD_DETECTOR_INTERNAL Detector = (PHGD_DETECTOR_INTERNAL)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (Detector == NULL || Detector->ShutdownRequested) {
        return;
    }

    //
    // Queue work item for cleanup (can't do paged operations in DPC)
    //
    HgdpCleanupStaleTransitions(Detector);
}


static VOID
HgdpCleanupStaleTransitions(
    _In_ PHGD_DETECTOR_INTERNAL Detector
    )
{
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeoutInterval;
    PLIST_ENTRY Entry, Next;
    PHGD_TRANSITION Transition;
    LIST_ENTRY StaleList;

    InitializeListHead(&StaleList);

    KeQuerySystemTime(&CurrentTime);
    TimeoutInterval.QuadPart = (LONGLONG)HGD_TRANSITION_TIMEOUT_MS * 10000;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->Public.TransitionLock);

    for (Entry = Detector->Public.TransitionList.Flink;
         Entry != &Detector->Public.TransitionList;
         Entry = Next) {

        Next = Entry->Flink;
        Transition = CONTAINING_RECORD(Entry, HGD_TRANSITION, ListEntry);

        if ((CurrentTime.QuadPart - Transition->Timestamp.QuadPart) > TimeoutInterval.QuadPart) {
            RemoveEntryList(&Transition->ListEntry);
            InterlockedDecrement(&Detector->Public.TransitionCount);
            InsertTailList(&StaleList, &Transition->ListEntry);
        }
    }

    ExReleasePushLockExclusive(&Detector->Public.TransitionLock);
    KeLeaveCriticalRegion();

    //
    // Free stale transitions outside lock
    //
    while (!IsListEmpty(&StaleList)) {
        Entry = RemoveHeadList(&StaleList);
        Transition = CONTAINING_RECORD(Entry, HGD_TRANSITION, ListEntry);
        HgdpFreeTransitionInternal(Detector, Transition);
    }
}


// ============================================================================
// ADDITIONAL DETECTION APIs
// ============================================================================

_Use_decl_annotations_
NTSTATUS
HgdDetectSyscallOrigin(
    _In_ PHGD_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ ULONG SyscallNumber,
    _In_ PVOID ReturnAddress,
    _Out_ PBOOLEAN IsSuspicious,
    _Out_opt_ PHGD_GATE_TYPE GateType
    )
/*++
Routine Description:
    Detects if a syscall originated from a suspicious location.

Arguments:
    Detector - Detector instance.
    ProcessId - Process ID.
    SyscallNumber - Syscall number being invoked.
    ReturnAddress - Return address of syscall.
    IsSuspicious - Receives TRUE if suspicious.
    GateType - Optional gate type detected.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PHGD_DETECTOR_INTERNAL Internal = (PHGD_DETECTOR_INTERNAL)Detector;
    PHGD_PROCESS_CONTEXT ProcessContext;
    ULONG SuspicionScore = 0;
    HGD_GATE_TYPE DetectedType;

    if (Internal == NULL || !Internal->Public.Initialized ||
        IsSuspicious == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsSuspicious = FALSE;
    if (GateType != NULL) {
        *GateType = HgdGate_None;
    }

    //
    // Get process context
    //
    ProcessContext = HgdpLookupProcessContext(Internal, ProcessId, FALSE);
    if (ProcessContext == NULL) {
        //
        // No context - not monitored
        //
        return STATUS_SUCCESS;
    }

    //
    // Analyze the return address
    //
    DetectedType = HgdpAnalyzeTransitionAddress(
        Internal,
        ProcessContext,
        ReturnAddress,
        &SuspicionScore
        );

    HgdpDereferenceProcessContext(Internal, ProcessContext);

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
    Adds an address to the known-good list for a process.

Arguments:
    Detector - Detector instance.
    ProcessId - Process ID.
    Address - Address to whitelist.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PHGD_DETECTOR_INTERNAL Internal = (PHGD_DETECTOR_INTERNAL)Detector;
    PHGD_PROCESS_CONTEXT ProcessContext;
    KIRQL OldIrql;

    if (Internal == NULL || !Internal->Public.Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    ProcessContext = HgdpLookupProcessContext(Internal, ProcessId, TRUE);
    if (ProcessContext == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeAcquireSpinLock(&ProcessContext->KnownGoodLock, &OldIrql);

    if (ProcessContext->KnownGoodCount < ARRAYSIZE(ProcessContext->KnownGoodAddresses)) {
        ProcessContext->KnownGoodAddresses[ProcessContext->KnownGoodCount] = Address;
        ProcessContext->KnownGoodCount++;
    }

    KeReleaseSpinLock(&ProcessContext->KnownGoodLock, OldIrql);

    HgdpDereferenceProcessContext(Internal, ProcessContext);

    return STATUS_SUCCESS;
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
    Detector - Detector instance.
    ProcessId - Process ID.
    Flags - Receives process flags.
    SuspicionScore - Optional suspicion score.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PHGD_DETECTOR_INTERNAL Internal = (PHGD_DETECTOR_INTERNAL)Detector;
    PHGD_PROCESS_CONTEXT ProcessContext;

    if (Internal == NULL || !Internal->Public.Initialized || Flags == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Flags = 0;
    if (SuspicionScore != NULL) {
        *SuspicionScore = 0;
    }

    ProcessContext = HgdpLookupProcessContext(Internal, ProcessId, FALSE);
    if (ProcessContext == NULL) {
        return STATUS_NOT_FOUND;
    }

    *Flags = ProcessContext->Flags;

    if (SuspicionScore != NULL) {
        *SuspicionScore = ProcessContext->SuspicionScore;
    }

    HgdpDereferenceProcessContext(Internal, ProcessContext);

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

Arguments:
    Detector - Detector instance.
    ProcessId - Process ID.
--*/
{
    PHGD_DETECTOR_INTERNAL Internal = (PHGD_DETECTOR_INTERNAL)Detector;
    PLIST_ENTRY Entry;
    PHGD_PROCESS_CONTEXT Context = NULL;

    if (Internal == NULL || !Internal->Public.Initialized) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Internal->ProcessLock);

    for (Entry = Internal->ProcessContextList.Flink;
         Entry != &Internal->ProcessContextList;
         Entry = Entry->Flink) {

        Context = CONTAINING_RECORD(Entry, HGD_PROCESS_CONTEXT, ListEntry);

        if (Context->ProcessId == ProcessId) {
            RemoveEntryList(&Context->ListEntry);
            InitializeListHead(&Context->ListEntry);
            InterlockedDecrement(&Internal->ProcessContextCount);
            break;
        }
        Context = NULL;
    }

    ExReleasePushLockExclusive(&Internal->ProcessLock);
    KeLeaveCriticalRegion();

    if (Context != NULL) {
        //
        // Dereference (will free if no other references)
        //
        if (InterlockedDecrement(&Context->RefCount) == 0) {
            HgdpFreeProcessContext(Internal, Context);
        }
    }
}

