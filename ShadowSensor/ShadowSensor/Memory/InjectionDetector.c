/*++
===============================================================================
ShadowStrike NGAV - INJECTION DETECTOR IMPLEMENTATION
===============================================================================

@file InjectionDetector.c
@brief Enterprise-grade code injection detection for comprehensive threat analysis.

This module provides real-time detection of process injection attacks through:
- Operation correlation and attack chain detection
- Cross-process memory operation monitoring
- Thread creation pattern analysis
- APC injection detection
- Process hollowing and doppelganging detection
- Atom bombing and callback-based injection detection

Implementation Features:
- Thread-safe operation tracking with hash tables
- Efficient chain detection using sliding window
- Per-process context with reference counting
- Lookaside lists for frequent allocations
- Asynchronous callback notification
- Comprehensive MITRE ATT&CK mapping

Detection Techniques Covered:
- T1055.001: Dynamic-link Library Injection
- T1055.002: Portable Executable Injection
- T1055.003: Thread Execution Hijacking
- T1055.004: Asynchronous Procedure Call
- T1055.005: Thread Local Storage
- T1055.011: Extra Window Memory Injection
- T1055.012: Process Hollowing
- T1055.013: Process Doppelganging
- T1055.014: VDSO Hijacking
- T1055.015: Listplanting

@author ShadowStrike Security Team
@version 2.0.0 (Enterprise Edition)
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#include "InjectionDetector.h"
#include "VadTracker.h"
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/ProcessUtils.h"
#include <ntstrsafe.h>

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define INJ_HASH_BUCKET_COUNT           512
#define INJ_HASH_BUCKET_MASK            (INJ_HASH_BUCKET_COUNT - 1)
#define INJ_MAX_CALLBACKS               16
#define INJ_CHAIN_CORRELATION_WINDOW_MS 5000
#define INJ_MAX_OPERATIONS_PER_CHAIN    32
#define INJ_SUSPICION_THRESHOLD_LOW     25
#define INJ_SUSPICION_THRESHOLD_MEDIUM  50
#define INJ_SUSPICION_THRESHOLD_HIGH    75
#define INJ_SUSPICION_THRESHOLD_CRITICAL 90

//
// Operation patterns for chain detection
//
#define INJ_PATTERN_ALLOCATE_WRITE      0x0001
#define INJ_PATTERN_WRITE_PROTECT       0x0002
#define INJ_PATTERN_PROTECT_EXECUTE     0x0004
#define INJ_PATTERN_CREATE_THREAD       0x0008
#define INJ_PATTERN_QUEUE_APC           0x0010
#define INJ_PATTERN_MAP_SECTION         0x0020
#define INJ_PATTERN_SET_CONTEXT         0x0040
#define INJ_PATTERN_SUSPEND_RESUME      0x0080

//
// Attack signatures
//
#define INJ_SIG_CLASSIC_INJECTION       (INJ_PATTERN_ALLOCATE_WRITE | INJ_PATTERN_CREATE_THREAD)
#define INJ_SIG_APC_INJECTION           (INJ_PATTERN_ALLOCATE_WRITE | INJ_PATTERN_QUEUE_APC)
#define INJ_SIG_PROCESS_HOLLOWING       (INJ_PATTERN_SUSPEND_RESUME | INJ_PATTERN_WRITE_PROTECT)
#define INJ_SIG_REFLECTIVE_DLL          (INJ_PATTERN_ALLOCATE_WRITE | INJ_PATTERN_PROTECT_EXECUTE)

// ============================================================================
// PRIVATE STRUCTURES
// ============================================================================

//
// Callback registration entry
//
typedef struct _INJ_CALLBACK_ENTRY {
    INJ_DETECTION_CALLBACK Callback;
    PVOID Context;
    BOOLEAN Active;
    UCHAR Reserved[7];
} INJ_CALLBACK_ENTRY, *PINJ_CALLBACK_ENTRY;

//
// Operation hash bucket
//
typedef struct _INJ_OPERATION_BUCKET {
    LIST_ENTRY OperationList;
    KSPIN_LOCK Lock;
    ULONG Count;
} INJ_OPERATION_BUCKET, *PINJ_OPERATION_BUCKET;

//
// Process hash bucket for context lookup
//
typedef struct _INJ_PROCESS_BUCKET {
    PINJ_PROCESS_CONTEXT Context;
    KSPIN_LOCK Lock;
} INJ_PROCESS_BUCKET, *PINJ_PROCESS_BUCKET;

//
// Extended detector with private data
//
typedef struct _INJ_DETECTOR_INTERNAL {
    //
    // Public structure (must be first)
    //
    INJ_DETECTOR Public;

    //
    // Callback registrations
    //
    INJ_CALLBACK_ENTRY DetectionCallbacks[INJ_MAX_CALLBACKS];
    INJ_CALLBACK_ENTRY BlockCallbacks[INJ_MAX_CALLBACKS];
    KSPIN_LOCK CallbackLock;
    ULONG DetectionCallbackCount;
    ULONG BlockCallbackCount;

    //
    // Operation hash table
    //
    INJ_OPERATION_BUCKET OperationBuckets[INJ_HASH_BUCKET_COUNT];
    volatile LONG TotalOperationCount;

    //
    // Process context hash table
    //
    INJ_PROCESS_BUCKET ProcessBuckets[INJ_HASH_BUCKET_COUNT];
    volatile LONG ProcessContextCount;

    //
    // Chain tracking
    //
    LIST_ENTRY ActiveChains;
    KSPIN_LOCK ChainLock;
    volatile LONG ActiveChainCount;

    //
    // Lookaside lists
    //
    NPAGED_LOOKASIDE_LIST OperationLookaside;
    NPAGED_LOOKASIDE_LIST ChainLookaside;
    NPAGED_LOOKASIDE_LIST ContextLookaside;
    NPAGED_LOOKASIDE_LIST ResultLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Worker thread for chain analysis
    //
    HANDLE WorkerThread;
    KEVENT ShutdownEvent;
    KEVENT AnalysisEvent;
    BOOLEAN ShutdownRequested;

    //
    // Timer for stale operation cleanup
    //
    KTIMER CleanupTimer;
    KDPC CleanupDpc;
    BOOLEAN CleanupTimerActive;

} INJ_DETECTOR_INTERNAL, *PINJ_DETECTOR_INTERNAL;

// ============================================================================
// PRIVATE FUNCTION PROTOTYPES
// ============================================================================

//
// Hash functions
//
static ULONG
InjpHashProcessId(
    _In_ HANDLE ProcessId
    );

static ULONG
InjpHashOperation(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ PVOID Address
    );

//
// Operation management
//
static PINJ_OPERATION
InjpAllocateOperation(
    _In_ PINJ_DETECTOR_INTERNAL Detector
    );

static VOID
InjpFreeOperation(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _In_ PINJ_OPERATION Operation
    );

static NTSTATUS
InjpInsertOperation(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _In_ PINJ_OPERATION Operation
    );

static PINJ_OPERATION
InjpFindOperation(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ PVOID Address,
    _In_ INJ_OPERATION_TYPE Type
    );

static VOID
InjpRemoveOperation(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _In_ PINJ_OPERATION Operation
    );

//
// Process context management
//
static PINJ_PROCESS_CONTEXT
InjpAllocateProcessContext(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _In_ HANDLE ProcessId
    );

static VOID
InjpFreeProcessContext(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _In_ PINJ_PROCESS_CONTEXT Context
    );

static PINJ_PROCESS_CONTEXT
InjpLookupProcessContext(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN CreateIfNotFound
    );

static VOID
InjpReferenceProcessContext(
    _Inout_ PINJ_PROCESS_CONTEXT Context
    );

static VOID
InjpDereferenceProcessContext(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _Inout_ PINJ_PROCESS_CONTEXT Context
    );

//
// Chain management
//
static PINJ_CHAIN
InjpAllocateChain(
    _In_ PINJ_DETECTOR_INTERNAL Detector
    );

static VOID
InjpFreeChain(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _In_ PINJ_CHAIN Chain
    );

static PINJ_CHAIN
InjpFindOrCreateChain(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId
    );

static NTSTATUS
InjpAddOperationToChain(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _In_ PINJ_CHAIN Chain,
    _In_ PINJ_OPERATION Operation
    );

//
// Detection analysis
//
static INJ_TECHNIQUE
InjpAnalyzeChain(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _In_ PINJ_CHAIN Chain,
    _Out_ PULONG ConfidenceScore
    );

static ULONG
InjpCalculateOperationPatterns(
    _In_ PINJ_CHAIN Chain
    );

static INJ_TECHNIQUE
InjpMatchPatternToTechnique(
    _In_ ULONG Patterns,
    _In_ PINJ_CHAIN Chain
    );

static VOID
InjpPopulateMitreMapping(
    _In_ INJ_TECHNIQUE Technique,
    _Out_ PINJ_DETECTION_RESULT Result
    );

static ULONG
InjpCalculateSuspicionScore(
    _In_ PINJ_CHAIN Chain,
    _In_ INJ_TECHNIQUE Technique
    );

//
// Result generation
//
static PINJ_DETECTION_RESULT
InjpAllocateResult(
    _In_ PINJ_DETECTOR_INTERNAL Detector
    );

static VOID
InjpFreeResult(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _In_ PINJ_DETECTION_RESULT Result
    );

static NTSTATUS
InjpGenerateDetectionResult(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _In_ PINJ_CHAIN Chain,
    _In_ INJ_TECHNIQUE Technique,
    _In_ ULONG ConfidenceScore,
    _Out_ PINJ_DETECTION_RESULT* Result
    );

//
// Callback notification
//
static VOID
InjpNotifyDetectionCallbacks(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _In_ PINJ_DETECTION_RESULT Result
    );

static BOOLEAN
InjpShouldBlockInjection(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _In_ PINJ_OPERATION Operation
    );

//
// Worker and timer routines
//
static VOID
InjpWorkerThread(
    _In_ PVOID StartContext
    );

static VOID
InjpCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

static VOID
InjpCleanupStaleOperations(
    _In_ PINJ_DETECTOR_INTERNAL Detector
    );

static VOID
InjpCleanupStaleChains(
    _In_ PINJ_DETECTOR_INTERNAL Detector
    );

//
// Utility functions
//
static BOOLEAN
InjpIsRemoteOperation(
    _In_ PINJ_OPERATION Operation
    );

static BOOLEAN
InjpIsSuspiciousProtection(
    _In_ ULONG Protection
    );

static BOOLEAN
InjpIsExecutableProtection(
    _In_ ULONG Protection
    );

static BOOLEAN
InjpIsWritableProtection(
    _In_ ULONG Protection
    );

// ============================================================================
// PUBLIC FUNCTION IMPLEMENTATIONS
// ============================================================================

NTSTATUS
InjInitialize(
    _In_opt_ PVAD_TRACKER VadTracker,
    _Out_ PINJ_DETECTOR* Detector
    )
/*++
Routine Description:
    Initializes the injection detector subsystem.

Arguments:
    VadTracker - Optional VAD tracker for memory region information.
    Detector - Receives pointer to initialized detector.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    NTSTATUS Status;
    PINJ_DETECTOR_INTERNAL Internal = NULL;
    HANDLE ThreadHandle = NULL;
    OBJECT_ATTRIBUTES ObjectAttributes;
    LARGE_INTEGER DueTime;
    ULONG i;

    if (Detector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Detector = NULL;

    //
    // Allocate internal detector structure
    //
    Internal = (PINJ_DETECTOR_INTERNAL)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(INJ_DETECTOR_INTERNAL),
        INJ_POOL_TAG
        );

    if (Internal == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Internal, sizeof(INJ_DETECTOR_INTERNAL));

    //
    // Store VAD tracker reference
    //
    Internal->Public.VadTracker = VadTracker;

    //
    // Initialize operation hash buckets
    //
    for (i = 0; i < INJ_HASH_BUCKET_COUNT; i++) {
        InitializeListHead(&Internal->OperationBuckets[i].OperationList);
        KeInitializeSpinLock(&Internal->OperationBuckets[i].Lock);
        Internal->OperationBuckets[i].Count = 0;

        Internal->ProcessBuckets[i].Context = NULL;
        KeInitializeSpinLock(&Internal->ProcessBuckets[i].Lock);
    }

    //
    // Initialize chain tracking
    //
    InitializeListHead(&Internal->ActiveChains);
    KeInitializeSpinLock(&Internal->ChainLock);

    //
    // Initialize callback infrastructure
    //
    KeInitializeSpinLock(&Internal->CallbackLock);

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &Internal->OperationLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(INJ_OPERATION),
        INJ_POOL_TAG_OP,
        0
        );

    ExInitializeNPagedLookasideList(
        &Internal->ChainLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(INJ_CHAIN),
        INJ_POOL_TAG_CHAIN,
        0
        );

    ExInitializeNPagedLookasideList(
        &Internal->ContextLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(INJ_PROCESS_CONTEXT),
        INJ_POOL_TAG_CTX,
        0
        );

    ExInitializeNPagedLookasideList(
        &Internal->ResultLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(INJ_DETECTION_RESULT),
        INJ_POOL_TAG,
        0
        );

    Internal->LookasideInitialized = TRUE;

    //
    // Initialize default configuration
    //
    Internal->Public.Config.EnableRealTimeDetection = TRUE;
    Internal->Public.Config.EnableChainCorrelation = TRUE;
    Internal->Public.Config.EnableAutoBlocking = FALSE;
    Internal->Public.Config.ChainTimeoutMs = INJ_CHAIN_CORRELATION_WINDOW_MS;
    Internal->Public.Config.MaxOperationsPerChain = INJ_MAX_OPERATIONS_PER_CHAIN;
    Internal->Public.Config.MinConfidenceToAlert = INJ_SUSPICION_THRESHOLD_MEDIUM;
    Internal->Public.Config.MinConfidenceToBlock = INJ_SUSPICION_THRESHOLD_CRITICAL;

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&Internal->Public.Stats.StartTime);

    //
    // Initialize worker thread synchronization
    //
    KeInitializeEvent(&Internal->ShutdownEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&Internal->AnalysisEvent, SynchronizationEvent, FALSE);

    //
    // Create worker thread for chain analysis
    //
    InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    Status = PsCreateSystemThread(
        &ThreadHandle,
        THREAD_ALL_ACCESS,
        &ObjectAttributes,
        NULL,
        NULL,
        InjpWorkerThread,
        Internal
        );

    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    Status = ObReferenceObjectByHandle(
        ThreadHandle,
        THREAD_ALL_ACCESS,
        *PsThreadType,
        KernelMode,
        (PVOID*)&Internal->WorkerThread,
        NULL
        );

    ZwClose(ThreadHandle);

    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    //
    // Initialize cleanup timer
    //
    KeInitializeTimer(&Internal->CleanupTimer);
    KeInitializeDpc(&Internal->CleanupDpc, InjpCleanupTimerDpc, Internal);

    //
    // Start cleanup timer (every 30 seconds)
    //
    DueTime.QuadPart = -((LONGLONG)30000 * 10000);
    KeSetTimerEx(
        &Internal->CleanupTimer,
        DueTime,
        30000,
        &Internal->CleanupDpc
        );
    Internal->CleanupTimerActive = TRUE;

    //
    // Mark as initialized
    //
    Internal->Public.Initialized = TRUE;
    *Detector = (PINJ_DETECTOR)Internal;

    return STATUS_SUCCESS;

Cleanup:
    if (Internal->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&Internal->OperationLookaside);
        ExDeleteNPagedLookasideList(&Internal->ChainLookaside);
        ExDeleteNPagedLookasideList(&Internal->ContextLookaside);
        ExDeleteNPagedLookasideList(&Internal->ResultLookaside);
    }

    ExFreePoolWithTag(Internal, INJ_POOL_TAG);
    return Status;
}

VOID
InjShutdown(
    _Inout_ PINJ_DETECTOR Detector
    )
/*++
Routine Description:
    Shuts down the injection detector subsystem.

Arguments:
    Detector - Detector instance to shutdown.
--*/
{
    PINJ_DETECTOR_INTERNAL Internal = (PINJ_DETECTOR_INTERNAL)Detector;
    PLIST_ENTRY Entry;
    PINJ_CHAIN Chain;
    PINJ_OPERATION Operation;
    KIRQL OldIrql;
    ULONG i;

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
    // Signal worker thread to exit
    //
    KeSetEvent(&Internal->ShutdownEvent, IO_NO_INCREMENT, FALSE);
    KeSetEvent(&Internal->AnalysisEvent, IO_NO_INCREMENT, FALSE);

    if (Internal->WorkerThread != NULL) {
        KeWaitForSingleObject(
            Internal->WorkerThread,
            Executive,
            KernelMode,
            FALSE,
            NULL
            );
        ObDereferenceObject(Internal->WorkerThread);
        Internal->WorkerThread = NULL;
    }

    //
    // Free all active chains
    //
    KeAcquireSpinLock(&Internal->ChainLock, &OldIrql);

    while (!IsListEmpty(&Internal->ActiveChains)) {
        Entry = RemoveHeadList(&Internal->ActiveChains);
        Chain = CONTAINING_RECORD(Entry, INJ_CHAIN, ListEntry);
        KeReleaseSpinLock(&Internal->ChainLock, OldIrql);

        InjpFreeChain(Internal, Chain);

        KeAcquireSpinLock(&Internal->ChainLock, &OldIrql);
    }

    KeReleaseSpinLock(&Internal->ChainLock, OldIrql);

    //
    // Free all operations
    //
    for (i = 0; i < INJ_HASH_BUCKET_COUNT; i++) {
        KeAcquireSpinLock(&Internal->OperationBuckets[i].Lock, &OldIrql);

        while (!IsListEmpty(&Internal->OperationBuckets[i].OperationList)) {
            Entry = RemoveHeadList(&Internal->OperationBuckets[i].OperationList);
            Operation = CONTAINING_RECORD(Entry, INJ_OPERATION, HashEntry);
            KeReleaseSpinLock(&Internal->OperationBuckets[i].Lock, OldIrql);

            InjpFreeOperation(Internal, Operation);

            KeAcquireSpinLock(&Internal->OperationBuckets[i].Lock, &OldIrql);
        }

        KeReleaseSpinLock(&Internal->OperationBuckets[i].Lock, OldIrql);
    }

    //
    // Free all process contexts
    //
    for (i = 0; i < INJ_HASH_BUCKET_COUNT; i++) {
        KeAcquireSpinLock(&Internal->ProcessBuckets[i].Lock, &OldIrql);

        if (Internal->ProcessBuckets[i].Context != NULL) {
            PINJ_PROCESS_CONTEXT Context = Internal->ProcessBuckets[i].Context;
            Internal->ProcessBuckets[i].Context = NULL;
            KeReleaseSpinLock(&Internal->ProcessBuckets[i].Lock, OldIrql);

            InjpFreeProcessContext(Internal, Context);
        } else {
            KeReleaseSpinLock(&Internal->ProcessBuckets[i].Lock, OldIrql);
        }
    }

    //
    // Delete lookaside lists
    //
    if (Internal->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&Internal->OperationLookaside);
        ExDeleteNPagedLookasideList(&Internal->ChainLookaside);
        ExDeleteNPagedLookasideList(&Internal->ContextLookaside);
        ExDeleteNPagedLookasideList(&Internal->ResultLookaside);
    }

    //
    // Free detector
    //
    ExFreePoolWithTag(Internal, INJ_POOL_TAG);
}

NTSTATUS
InjRecordOperation(
    _In_ PINJ_DETECTOR Detector,
    _In_ INJ_OPERATION_TYPE OperationType,
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_opt_ HANDLE SourceThreadId,
    _In_opt_ HANDLE TargetThreadId,
    _In_ PVOID TargetAddress,
    _In_ SIZE_T Size,
    _In_ ULONG Protection,
    _In_opt_ PVOID SourceAddress,
    _In_ ULONG Flags
    )
/*++
Routine Description:
    Records a memory operation for injection detection analysis.

Arguments:
    Detector - Detector instance.
    OperationType - Type of operation (allocate, write, protect, etc.).
    SourceProcessId - Process performing the operation.
    TargetProcessId - Process being operated on.
    SourceThreadId - Thread performing the operation.
    TargetThreadId - Target thread (for thread operations).
    TargetAddress - Target memory address.
    Size - Size of operation.
    Protection - Memory protection.
    SourceAddress - Source address for copy operations.
    Flags - Operation flags.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PINJ_DETECTOR_INTERNAL Internal = (PINJ_DETECTOR_INTERNAL)Detector;
    PINJ_OPERATION Operation = NULL;
    PINJ_CHAIN Chain = NULL;
    NTSTATUS Status;
    BOOLEAN IsRemote;

    if (Internal == NULL || !Internal->Public.Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Internal->Public.Config.EnableRealTimeDetection) {
        return STATUS_SUCCESS;
    }

    //
    // Check if this is a remote operation
    //
    IsRemote = (SourceProcessId != TargetProcessId);

    //
    // Only track remote operations or explicit cross-process flags
    //
    if (!IsRemote && !(Flags & INJ_FLAG_CROSS_PROCESS)) {
        return STATUS_SUCCESS;
    }

    //
    // Check if we've hit the operation limit
    //
    if ((ULONG)Internal->TotalOperationCount >= Internal->Public.Config.MaxOperationsPerChain * INJ_HASH_BUCKET_COUNT) {
        InterlockedIncrement64(&Internal->Public.Stats.DroppedOperations);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Allocate operation structure
    //
    Operation = InjpAllocateOperation(Internal);
    if (Operation == NULL) {
        InterlockedIncrement64(&Internal->Public.Stats.DroppedOperations);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Populate operation
    //
    Operation->Type = OperationType;
    Operation->SourceProcessId = SourceProcessId;
    Operation->TargetProcessId = TargetProcessId;
    Operation->SourceThreadId = SourceThreadId;
    Operation->TargetThreadId = TargetThreadId;
    Operation->TargetAddress = TargetAddress;
    Operation->Size = Size;
    Operation->Protection = Protection;
    Operation->SourceAddress = SourceAddress;
    Operation->Flags = Flags;
    KeQuerySystemTime(&Operation->Timestamp);

    //
    // Calculate initial suspicion score
    //
    Operation->SuspicionScore = 0;

    if (InjpIsRemoteOperation(Operation)) {
        Operation->SuspicionScore += 20;
    }

    if (InjpIsSuspiciousProtection(Protection)) {
        Operation->SuspicionScore += 30;
    }

    if (OperationType == InjOpCreateThread && IsRemote) {
        Operation->SuspicionScore += 40;
    }

    if (OperationType == InjOpQueueApc && IsRemote) {
        Operation->SuspicionScore += 35;
    }

    //
    // Insert into operation tracking
    //
    Status = InjpInsertOperation(Internal, Operation);
    if (!NT_SUCCESS(Status)) {
        InjpFreeOperation(Internal, Operation);
        return Status;
    }

    InterlockedIncrement64(&Internal->Public.Stats.TotalOperations);

    //
    // Find or create correlation chain
    //
    if (Internal->Public.Config.EnableChainCorrelation) {
        Chain = InjpFindOrCreateChain(Internal, SourceProcessId, TargetProcessId);
        if (Chain != NULL) {
            InjpAddOperationToChain(Internal, Chain, Operation);

            //
            // Signal worker thread for analysis
            //
            KeSetEvent(&Internal->AnalysisEvent, IO_NO_INCREMENT, FALSE);
        }
    }

    //
    // Check for immediate blocking conditions
    //
    if (Internal->Public.Config.EnableAutoBlocking) {
        if (InjpShouldBlockInjection(Internal, Operation)) {
            InterlockedIncrement64(&Internal->Public.Stats.BlockedInjections);
            return STATUS_ACCESS_DENIED;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
InjAnalyzeChain(
    _In_ PINJ_DETECTOR Detector,
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _Out_ PINJ_DETECTION_RESULT* Result
    )
/*++
Routine Description:
    Analyzes an operation chain for injection indicators.

Arguments:
    Detector - Detector instance.
    SourceProcessId - Source process.
    TargetProcessId - Target process.
    Result - Receives detection result.

Return Value:
    STATUS_SUCCESS if injection detected.
    STATUS_NOT_FOUND if no chain exists.
--*/
{
    PINJ_DETECTOR_INTERNAL Internal = (PINJ_DETECTOR_INTERNAL)Detector;
    PINJ_CHAIN Chain;
    INJ_TECHNIQUE Technique;
    ULONG ConfidenceScore;
    PLIST_ENTRY Entry;
    KIRQL OldIrql;
    NTSTATUS Status = STATUS_NOT_FOUND;

    if (Internal == NULL || !Internal->Public.Initialized || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Result = NULL;

    //
    // Find matching chain
    //
    KeAcquireSpinLock(&Internal->ChainLock, &OldIrql);

    for (Entry = Internal->ActiveChains.Flink;
         Entry != &Internal->ActiveChains;
         Entry = Entry->Flink) {

        Chain = CONTAINING_RECORD(Entry, INJ_CHAIN, ListEntry);

        if (Chain->SourceProcessId == SourceProcessId &&
            Chain->TargetProcessId == TargetProcessId) {

            //
            // Found matching chain - analyze it
            //
            Technique = InjpAnalyzeChain(Internal, Chain, &ConfidenceScore);

            if (Technique != InjTechNone &&
                ConfidenceScore >= Internal->Public.Config.MinConfidenceToAlert) {

                KeReleaseSpinLock(&Internal->ChainLock, OldIrql);

                Status = InjpGenerateDetectionResult(
                    Internal,
                    Chain,
                    Technique,
                    ConfidenceScore,
                    Result
                    );

                if (NT_SUCCESS(Status)) {
                    InterlockedIncrement64(&Internal->Public.Stats.DetectedInjections);
                    InjpNotifyDetectionCallbacks(Internal, *Result);
                }

                return Status;
            }

            KeReleaseSpinLock(&Internal->ChainLock, OldIrql);
            return STATUS_NOT_FOUND;
        }
    }

    KeReleaseSpinLock(&Internal->ChainLock, OldIrql);
    return STATUS_NOT_FOUND;
}

NTSTATUS
InjDetectInjection(
    _In_ PINJ_DETECTOR Detector,
    _In_ HANDLE TargetProcessId,
    _In_ PVOID TargetAddress,
    _In_ SIZE_T Size,
    _Out_ PINJ_DETECTION_RESULT* Result
    )
/*++
Routine Description:
    Performs on-demand injection detection for a memory region.

Arguments:
    Detector - Detector instance.
    TargetProcessId - Process to analyze.
    TargetAddress - Memory region start.
    Size - Region size.
    Result - Receives detection result.

Return Value:
    STATUS_SUCCESS if injection detected.
--*/
{
    PINJ_DETECTOR_INTERNAL Internal = (PINJ_DETECTOR_INTERNAL)Detector;
    PINJ_PROCESS_CONTEXT Context;
    PLIST_ENTRY Entry;
    PINJ_CHAIN Chain;
    INJ_TECHNIQUE BestTechnique = InjTechNone;
    ULONG BestConfidence = 0;
    PINJ_CHAIN BestChain = NULL;
    KIRQL OldIrql;
    NTSTATUS Status = STATUS_NOT_FOUND;

    if (Internal == NULL || !Internal->Public.Initialized || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Result = NULL;

    //
    // Get process context
    //
    Context = InjpLookupProcessContext(Internal, TargetProcessId, FALSE);
    if (Context == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Search all chains targeting this process
    //
    KeAcquireSpinLock(&Internal->ChainLock, &OldIrql);

    for (Entry = Internal->ActiveChains.Flink;
         Entry != &Internal->ActiveChains;
         Entry = Entry->Flink) {

        Chain = CONTAINING_RECORD(Entry, INJ_CHAIN, ListEntry);

        if (Chain->TargetProcessId == TargetProcessId) {
            //
            // Check if any operation in this chain targets our region
            //
            PLIST_ENTRY OpEntry;
            BOOLEAN RegionMatch = FALSE;

            for (OpEntry = Chain->OperationList.Flink;
                 OpEntry != &Chain->OperationList;
                 OpEntry = OpEntry->Flink) {

                PINJ_OPERATION Op = CONTAINING_RECORD(OpEntry, INJ_OPERATION, ChainEntry);

                if ((ULONG_PTR)Op->TargetAddress >= (ULONG_PTR)TargetAddress &&
                    (ULONG_PTR)Op->TargetAddress < (ULONG_PTR)TargetAddress + Size) {
                    RegionMatch = TRUE;
                    break;
                }
            }

            if (RegionMatch) {
                INJ_TECHNIQUE Technique;
                ULONG Confidence;

                Technique = InjpAnalyzeChain(Internal, Chain, &Confidence);

                if (Confidence > BestConfidence) {
                    BestTechnique = Technique;
                    BestConfidence = Confidence;
                    BestChain = Chain;
                }
            }
        }
    }

    KeReleaseSpinLock(&Internal->ChainLock, OldIrql);

    InjpDereferenceProcessContext(Internal, Context);

    //
    // Generate result if detection found
    //
    if (BestTechnique != InjTechNone &&
        BestConfidence >= Internal->Public.Config.MinConfidenceToAlert) {

        Status = InjpGenerateDetectionResult(
            Internal,
            BestChain,
            BestTechnique,
            BestConfidence,
            Result
            );

        if (NT_SUCCESS(Status)) {
            InterlockedIncrement64(&Internal->Public.Stats.DetectedInjections);
            InjpNotifyDetectionCallbacks(Internal, *Result);
        }
    }

    return Status;
}

NTSTATUS
InjGetChainInfo(
    _In_ PINJ_DETECTOR Detector,
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _Out_ PINJ_CHAIN ChainInfo
    )
/*++
Routine Description:
    Gets information about an operation chain.

Arguments:
    Detector - Detector instance.
    SourceProcessId - Source process.
    TargetProcessId - Target process.
    ChainInfo - Receives chain information.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PINJ_DETECTOR_INTERNAL Internal = (PINJ_DETECTOR_INTERNAL)Detector;
    PLIST_ENTRY Entry;
    PINJ_CHAIN Chain;
    KIRQL OldIrql;
    NTSTATUS Status = STATUS_NOT_FOUND;

    if (Internal == NULL || !Internal->Public.Initialized || ChainInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&Internal->ChainLock, &OldIrql);

    for (Entry = Internal->ActiveChains.Flink;
         Entry != &Internal->ActiveChains;
         Entry = Entry->Flink) {

        Chain = CONTAINING_RECORD(Entry, INJ_CHAIN, ListEntry);

        if (Chain->SourceProcessId == SourceProcessId &&
            Chain->TargetProcessId == TargetProcessId) {

            //
            // Copy chain info (without list entries)
            //
            ChainInfo->ChainId = Chain->ChainId;
            ChainInfo->SourceProcessId = Chain->SourceProcessId;
            ChainInfo->TargetProcessId = Chain->TargetProcessId;
            ChainInfo->OperationCount = Chain->OperationCount;
            ChainInfo->TotalSize = Chain->TotalSize;
            ChainInfo->FirstOperationTime = Chain->FirstOperationTime;
            ChainInfo->LastOperationTime = Chain->LastOperationTime;
            ChainInfo->Flags = Chain->Flags;
            ChainInfo->DetectedTechnique = Chain->DetectedTechnique;
            ChainInfo->ConfidenceScore = Chain->ConfidenceScore;

            Status = STATUS_SUCCESS;
            break;
        }
    }

    KeReleaseSpinLock(&Internal->ChainLock, OldIrql);

    return Status;
}

NTSTATUS
InjRegisterDetectionCallback(
    _In_ PINJ_DETECTOR Detector,
    _In_ INJ_DETECTION_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
/*++
Routine Description:
    Registers a callback for injection detection notifications.

Arguments:
    Detector - Detector instance.
    Callback - Callback function.
    Context - User context.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PINJ_DETECTOR_INTERNAL Internal = (PINJ_DETECTOR_INTERNAL)Detector;
    KIRQL OldIrql;
    ULONG i;

    if (Internal == NULL || !Internal->Public.Initialized || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&Internal->CallbackLock, &OldIrql);

    for (i = 0; i < INJ_MAX_CALLBACKS; i++) {
        if (!Internal->DetectionCallbacks[i].Active) {
            Internal->DetectionCallbacks[i].Callback = Callback;
            Internal->DetectionCallbacks[i].Context = Context;
            Internal->DetectionCallbacks[i].Active = TRUE;
            Internal->DetectionCallbackCount++;
            KeReleaseSpinLock(&Internal->CallbackLock, OldIrql);
            return STATUS_SUCCESS;
        }
    }

    KeReleaseSpinLock(&Internal->CallbackLock, OldIrql);
    return STATUS_QUOTA_EXCEEDED;
}

VOID
InjUnregisterDetectionCallback(
    _In_ PINJ_DETECTOR Detector,
    _In_ INJ_DETECTION_CALLBACK Callback
    )
/*++
Routine Description:
    Unregisters a detection callback.

Arguments:
    Detector - Detector instance.
    Callback - Callback to unregister.
--*/
{
    PINJ_DETECTOR_INTERNAL Internal = (PINJ_DETECTOR_INTERNAL)Detector;
    KIRQL OldIrql;
    ULONG i;

    if (Internal == NULL || Callback == NULL) {
        return;
    }

    KeAcquireSpinLock(&Internal->CallbackLock, &OldIrql);

    for (i = 0; i < INJ_MAX_CALLBACKS; i++) {
        if (Internal->DetectionCallbacks[i].Active &&
            Internal->DetectionCallbacks[i].Callback == Callback) {
            Internal->DetectionCallbacks[i].Active = FALSE;
            Internal->DetectionCallbacks[i].Callback = NULL;
            Internal->DetectionCallbacks[i].Context = NULL;
            Internal->DetectionCallbackCount--;
            break;
        }
    }

    KeReleaseSpinLock(&Internal->CallbackLock, OldIrql);
}

NTSTATUS
InjRegisterBlockCallback(
    _In_ PINJ_DETECTOR Detector,
    _In_ INJ_BLOCK_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
/*++
Routine Description:
    Registers a callback for injection blocking decisions.

Arguments:
    Detector - Detector instance.
    Callback - Callback function.
    Context - User context.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PINJ_DETECTOR_INTERNAL Internal = (PINJ_DETECTOR_INTERNAL)Detector;
    KIRQL OldIrql;
    ULONG i;

    if (Internal == NULL || !Internal->Public.Initialized || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&Internal->CallbackLock, &OldIrql);

    for (i = 0; i < INJ_MAX_CALLBACKS; i++) {
        if (!Internal->BlockCallbacks[i].Active) {
            Internal->BlockCallbacks[i].Callback = (INJ_DETECTION_CALLBACK)Callback;
            Internal->BlockCallbacks[i].Context = Context;
            Internal->BlockCallbacks[i].Active = TRUE;
            Internal->BlockCallbackCount++;
            KeReleaseSpinLock(&Internal->CallbackLock, OldIrql);
            return STATUS_SUCCESS;
        }
    }

    KeReleaseSpinLock(&Internal->CallbackLock, OldIrql);
    return STATUS_QUOTA_EXCEEDED;
}

VOID
InjUnregisterBlockCallback(
    _In_ PINJ_DETECTOR Detector,
    _In_ INJ_BLOCK_CALLBACK Callback
    )
/*++
Routine Description:
    Unregisters a block callback.

Arguments:
    Detector - Detector instance.
    Callback - Callback to unregister.
--*/
{
    PINJ_DETECTOR_INTERNAL Internal = (PINJ_DETECTOR_INTERNAL)Detector;
    KIRQL OldIrql;
    ULONG i;

    if (Internal == NULL || Callback == NULL) {
        return;
    }

    KeAcquireSpinLock(&Internal->CallbackLock, &OldIrql);

    for (i = 0; i < INJ_MAX_CALLBACKS; i++) {
        if (Internal->BlockCallbacks[i].Active &&
            Internal->BlockCallbacks[i].Callback == (INJ_DETECTION_CALLBACK)Callback) {
            Internal->BlockCallbacks[i].Active = FALSE;
            Internal->BlockCallbacks[i].Callback = NULL;
            Internal->BlockCallbacks[i].Context = NULL;
            Internal->BlockCallbackCount--;
            break;
        }
    }

    KeReleaseSpinLock(&Internal->CallbackLock, OldIrql);
}

NTSTATUS
InjGetStatistics(
    _In_ PINJ_DETECTOR Detector,
    _Out_ PINJ_STATISTICS Stats
    )
/*++
Routine Description:
    Gets detector statistics.

Arguments:
    Detector - Detector instance.
    Stats - Receives statistics.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PINJ_DETECTOR_INTERNAL Internal = (PINJ_DETECTOR_INTERNAL)Detector;
    LARGE_INTEGER CurrentTime;

    if (Internal == NULL || !Internal->Public.Initialized || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(Stats, &Internal->Public.Stats, sizeof(INJ_STATISTICS));

    //
    // Update current counts
    //
    Stats->ActiveOperations = (ULONG64)Internal->TotalOperationCount;
    Stats->ActiveChains = (ULONG64)Internal->ActiveChainCount;

    //
    // Calculate uptime
    //
    KeQuerySystemTime(&CurrentTime);
    Stats->UptimeSeconds = (ULONG)(
        (CurrentTime.QuadPart - Internal->Public.Stats.StartTime.QuadPart) / 10000000
        );

    return STATUS_SUCCESS;
}

NTSTATUS
InjClearChain(
    _In_ PINJ_DETECTOR Detector,
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId
    )
/*++
Routine Description:
    Clears a specific operation chain.

Arguments:
    Detector - Detector instance.
    SourceProcessId - Source process.
    TargetProcessId - Target process.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PINJ_DETECTOR_INTERNAL Internal = (PINJ_DETECTOR_INTERNAL)Detector;
    PLIST_ENTRY Entry;
    PINJ_CHAIN Chain;
    KIRQL OldIrql;
    NTSTATUS Status = STATUS_NOT_FOUND;

    if (Internal == NULL || !Internal->Public.Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&Internal->ChainLock, &OldIrql);

    for (Entry = Internal->ActiveChains.Flink;
         Entry != &Internal->ActiveChains;
         Entry = Entry->Flink) {

        Chain = CONTAINING_RECORD(Entry, INJ_CHAIN, ListEntry);

        if (Chain->SourceProcessId == SourceProcessId &&
            Chain->TargetProcessId == TargetProcessId) {

            RemoveEntryList(&Chain->ListEntry);
            InterlockedDecrement(&Internal->ActiveChainCount);
            KeReleaseSpinLock(&Internal->ChainLock, OldIrql);

            InjpFreeChain(Internal, Chain);
            return STATUS_SUCCESS;
        }
    }

    KeReleaseSpinLock(&Internal->ChainLock, OldIrql);
    return Status;
}

NTSTATUS
InjClearAllChains(
    _In_ PINJ_DETECTOR Detector
    )
/*++
Routine Description:
    Clears all operation chains.

Arguments:
    Detector - Detector instance.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PINJ_DETECTOR_INTERNAL Internal = (PINJ_DETECTOR_INTERNAL)Detector;
    PLIST_ENTRY Entry;
    PINJ_CHAIN Chain;
    KIRQL OldIrql;

    if (Internal == NULL || !Internal->Public.Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&Internal->ChainLock, &OldIrql);

    while (!IsListEmpty(&Internal->ActiveChains)) {
        Entry = RemoveHeadList(&Internal->ActiveChains);
        Chain = CONTAINING_RECORD(Entry, INJ_CHAIN, ListEntry);
        InterlockedDecrement(&Internal->ActiveChainCount);
        KeReleaseSpinLock(&Internal->ChainLock, OldIrql);

        InjpFreeChain(Internal, Chain);

        KeAcquireSpinLock(&Internal->ChainLock, &OldIrql);
    }

    KeReleaseSpinLock(&Internal->ChainLock, OldIrql);

    return STATUS_SUCCESS;
}

VOID
InjFreeDetectionResult(
    _In_ PINJ_DETECTOR Detector,
    _In_ PINJ_DETECTION_RESULT Result
    )
/*++
Routine Description:
    Frees a detection result.

Arguments:
    Detector - Detector instance.
    Result - Result to free.
--*/
{
    PINJ_DETECTOR_INTERNAL Internal = (PINJ_DETECTOR_INTERNAL)Detector;

    if (Internal == NULL || Result == NULL) {
        return;
    }

    InjpFreeResult(Internal, Result);
}

// ============================================================================
// PRIVATE FUNCTION IMPLEMENTATIONS
// ============================================================================

static ULONG
InjpHashProcessId(
    _In_ HANDLE ProcessId
    )
{
    ULONG_PTR Value = (ULONG_PTR)ProcessId;

    Value ^= (Value >> 16);
    Value *= 0x85ebca6b;
    Value ^= (Value >> 13);
    Value *= 0xc2b2ae35;
    Value ^= (Value >> 16);

    return (ULONG)(Value & INJ_HASH_BUCKET_MASK);
}

static ULONG
InjpHashOperation(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ PVOID Address
    )
{
    ULONG_PTR Value;

    Value = (ULONG_PTR)SourceProcessId ^ ((ULONG_PTR)TargetProcessId << 7);
    Value ^= ((ULONG_PTR)Address >> 12);
    Value *= 0x85ebca6b;
    Value ^= (Value >> 13);

    return (ULONG)(Value & INJ_HASH_BUCKET_MASK);
}

static PINJ_OPERATION
InjpAllocateOperation(
    _In_ PINJ_DETECTOR_INTERNAL Detector
    )
{
    PINJ_OPERATION Operation;

    Operation = (PINJ_OPERATION)ExAllocateFromNPagedLookasideList(
        &Detector->OperationLookaside
        );

    if (Operation != NULL) {
        RtlZeroMemory(Operation, sizeof(INJ_OPERATION));
        InitializeListHead(&Operation->HashEntry);
        InitializeListHead(&Operation->ChainEntry);
    }

    return Operation;
}

static VOID
InjpFreeOperation(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _In_ PINJ_OPERATION Operation
    )
{
    ExFreeToNPagedLookasideList(&Detector->OperationLookaside, Operation);
}

static NTSTATUS
InjpInsertOperation(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _In_ PINJ_OPERATION Operation
    )
{
    ULONG Hash;
    KIRQL OldIrql;

    Hash = InjpHashOperation(
        Operation->SourceProcessId,
        Operation->TargetProcessId,
        Operation->TargetAddress
        );

    KeAcquireSpinLock(&Detector->OperationBuckets[Hash].Lock, &OldIrql);

    InsertTailList(
        &Detector->OperationBuckets[Hash].OperationList,
        &Operation->HashEntry
        );
    Detector->OperationBuckets[Hash].Count++;

    KeReleaseSpinLock(&Detector->OperationBuckets[Hash].Lock, OldIrql);

    InterlockedIncrement(&Detector->TotalOperationCount);

    return STATUS_SUCCESS;
}

static PINJ_OPERATION
InjpFindOperation(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ PVOID Address,
    _In_ INJ_OPERATION_TYPE Type
    )
{
    ULONG Hash;
    PLIST_ENTRY Entry;
    PINJ_OPERATION Operation;
    KIRQL OldIrql;

    Hash = InjpHashOperation(SourceProcessId, TargetProcessId, Address);

    KeAcquireSpinLock(&Detector->OperationBuckets[Hash].Lock, &OldIrql);

    for (Entry = Detector->OperationBuckets[Hash].OperationList.Flink;
         Entry != &Detector->OperationBuckets[Hash].OperationList;
         Entry = Entry->Flink) {

        Operation = CONTAINING_RECORD(Entry, INJ_OPERATION, HashEntry);

        if (Operation->SourceProcessId == SourceProcessId &&
            Operation->TargetProcessId == TargetProcessId &&
            Operation->TargetAddress == Address &&
            Operation->Type == Type) {

            KeReleaseSpinLock(&Detector->OperationBuckets[Hash].Lock, OldIrql);
            return Operation;
        }
    }

    KeReleaseSpinLock(&Detector->OperationBuckets[Hash].Lock, OldIrql);
    return NULL;
}

static VOID
InjpRemoveOperation(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _In_ PINJ_OPERATION Operation
    )
{
    ULONG Hash;
    KIRQL OldIrql;

    Hash = InjpHashOperation(
        Operation->SourceProcessId,
        Operation->TargetProcessId,
        Operation->TargetAddress
        );

    KeAcquireSpinLock(&Detector->OperationBuckets[Hash].Lock, &OldIrql);

    if (!IsListEmpty(&Operation->HashEntry)) {
        RemoveEntryList(&Operation->HashEntry);
        InitializeListHead(&Operation->HashEntry);
        Detector->OperationBuckets[Hash].Count--;
        InterlockedDecrement(&Detector->TotalOperationCount);
    }

    KeReleaseSpinLock(&Detector->OperationBuckets[Hash].Lock, OldIrql);
}

static PINJ_PROCESS_CONTEXT
InjpAllocateProcessContext(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _In_ HANDLE ProcessId
    )
{
    PINJ_PROCESS_CONTEXT Context;

    Context = (PINJ_PROCESS_CONTEXT)ExAllocateFromNPagedLookasideList(
        &Detector->ContextLookaside
        );

    if (Context != NULL) {
        RtlZeroMemory(Context, sizeof(INJ_PROCESS_CONTEXT));
        Context->ProcessId = ProcessId;
        Context->RefCount = 1;
        InitializeListHead(&Context->IncomingChains);
        InitializeListHead(&Context->OutgoingChains);
        KeInitializeSpinLock(&Context->Lock);
        KeQuerySystemTime(&Context->FirstSeenTime);
    }

    return Context;
}

static VOID
InjpFreeProcessContext(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _In_ PINJ_PROCESS_CONTEXT Context
    )
{
    ExFreeToNPagedLookasideList(&Detector->ContextLookaside, Context);
}

static PINJ_PROCESS_CONTEXT
InjpLookupProcessContext(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN CreateIfNotFound
    )
{
    ULONG Hash;
    PINJ_PROCESS_CONTEXT Context;
    KIRQL OldIrql;

    Hash = InjpHashProcessId(ProcessId);

    KeAcquireSpinLock(&Detector->ProcessBuckets[Hash].Lock, &OldIrql);

    Context = Detector->ProcessBuckets[Hash].Context;

    //
    // Linear probe through collisions
    //
    while (Context != NULL && Context->ProcessId != ProcessId) {
        ULONG NextHash = (Hash + 1) & INJ_HASH_BUCKET_MASK;
        if (NextHash == Hash) {
            Context = NULL;
            break;
        }
        KeReleaseSpinLock(&Detector->ProcessBuckets[Hash].Lock, OldIrql);
        Hash = NextHash;
        KeAcquireSpinLock(&Detector->ProcessBuckets[Hash].Lock, &OldIrql);
        Context = Detector->ProcessBuckets[Hash].Context;
    }

    if (Context != NULL) {
        InjpReferenceProcessContext(Context);
        KeReleaseSpinLock(&Detector->ProcessBuckets[Hash].Lock, OldIrql);
        return Context;
    }

    KeReleaseSpinLock(&Detector->ProcessBuckets[Hash].Lock, OldIrql);

    if (!CreateIfNotFound) {
        return NULL;
    }

    //
    // Create new context
    //
    Context = InjpAllocateProcessContext(Detector, ProcessId);
    if (Context == NULL) {
        return NULL;
    }

    //
    // Insert into hash table
    //
    Hash = InjpHashProcessId(ProcessId);

    KeAcquireSpinLock(&Detector->ProcessBuckets[Hash].Lock, &OldIrql);

    //
    // Check for race condition
    //
    if (Detector->ProcessBuckets[Hash].Context == NULL) {
        Detector->ProcessBuckets[Hash].Context = Context;
        InterlockedIncrement(&Detector->ProcessContextCount);
        InjpReferenceProcessContext(Context);
        KeReleaseSpinLock(&Detector->ProcessBuckets[Hash].Lock, OldIrql);
        return Context;
    }

    //
    // Find empty slot with linear probing
    //
    while (Detector->ProcessBuckets[Hash].Context != NULL) {
        if (Detector->ProcessBuckets[Hash].Context->ProcessId == ProcessId) {
            //
            // Another thread created it
            //
            PINJ_PROCESS_CONTEXT Existing = Detector->ProcessBuckets[Hash].Context;
            InjpReferenceProcessContext(Existing);
            KeReleaseSpinLock(&Detector->ProcessBuckets[Hash].Lock, OldIrql);
            InjpFreeProcessContext(Detector, Context);
            return Existing;
        }

        KeReleaseSpinLock(&Detector->ProcessBuckets[Hash].Lock, OldIrql);
        Hash = (Hash + 1) & INJ_HASH_BUCKET_MASK;
        KeAcquireSpinLock(&Detector->ProcessBuckets[Hash].Lock, &OldIrql);
    }

    Detector->ProcessBuckets[Hash].Context = Context;
    InterlockedIncrement(&Detector->ProcessContextCount);
    InjpReferenceProcessContext(Context);
    KeReleaseSpinLock(&Detector->ProcessBuckets[Hash].Lock, OldIrql);

    return Context;
}

static VOID
InjpReferenceProcessContext(
    _Inout_ PINJ_PROCESS_CONTEXT Context
    )
{
    InterlockedIncrement(&Context->RefCount);
}

static VOID
InjpDereferenceProcessContext(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _Inout_ PINJ_PROCESS_CONTEXT Context
    )
{
    if (InterlockedDecrement(&Context->RefCount) == 0) {
        InjpFreeProcessContext(Detector, Context);
    }
}

static PINJ_CHAIN
InjpAllocateChain(
    _In_ PINJ_DETECTOR_INTERNAL Detector
    )
{
    PINJ_CHAIN Chain;
    static volatile LONG NextChainId = 0;

    Chain = (PINJ_CHAIN)ExAllocateFromNPagedLookasideList(
        &Detector->ChainLookaside
        );

    if (Chain != NULL) {
        RtlZeroMemory(Chain, sizeof(INJ_CHAIN));
        Chain->ChainId = (ULONG)InterlockedIncrement(&NextChainId);
        InitializeListHead(&Chain->ListEntry);
        InitializeListHead(&Chain->OperationList);
    }

    return Chain;
}

static VOID
InjpFreeChain(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _In_ PINJ_CHAIN Chain
    )
{
    PLIST_ENTRY Entry;
    PINJ_OPERATION Operation;

    //
    // Free all operations in the chain
    //
    while (!IsListEmpty(&Chain->OperationList)) {
        Entry = RemoveHeadList(&Chain->OperationList);
        Operation = CONTAINING_RECORD(Entry, INJ_OPERATION, ChainEntry);
        InitializeListHead(&Operation->ChainEntry);

        //
        // Remove from hash table and free
        //
        InjpRemoveOperation(Detector, Operation);
        InjpFreeOperation(Detector, Operation);
    }

    ExFreeToNPagedLookasideList(&Detector->ChainLookaside, Chain);
}

static PINJ_CHAIN
InjpFindOrCreateChain(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId
    )
{
    PLIST_ENTRY Entry;
    PINJ_CHAIN Chain;
    KIRQL OldIrql;
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeoutInterval;

    KeQuerySystemTime(&CurrentTime);
    TimeoutInterval.QuadPart = (LONGLONG)Detector->Public.Config.ChainTimeoutMs * 10000;

    KeAcquireSpinLock(&Detector->ChainLock, &OldIrql);

    //
    // Search for existing chain
    //
    for (Entry = Detector->ActiveChains.Flink;
         Entry != &Detector->ActiveChains;
         Entry = Entry->Flink) {

        Chain = CONTAINING_RECORD(Entry, INJ_CHAIN, ListEntry);

        if (Chain->SourceProcessId == SourceProcessId &&
            Chain->TargetProcessId == TargetProcessId) {

            //
            // Check if chain is still active (within timeout window)
            //
            if ((CurrentTime.QuadPart - Chain->LastOperationTime.QuadPart) <= TimeoutInterval.QuadPart) {
                KeReleaseSpinLock(&Detector->ChainLock, OldIrql);
                return Chain;
            }

            //
            // Chain has timed out - remove and create new one
            //
            RemoveEntryList(&Chain->ListEntry);
            InterlockedDecrement(&Detector->ActiveChainCount);
            KeReleaseSpinLock(&Detector->ChainLock, OldIrql);

            InjpFreeChain(Detector, Chain);

            KeAcquireSpinLock(&Detector->ChainLock, &OldIrql);
            break;
        }
    }

    //
    // Create new chain
    //
    Chain = InjpAllocateChain(Detector);
    if (Chain == NULL) {
        KeReleaseSpinLock(&Detector->ChainLock, OldIrql);
        return NULL;
    }

    Chain->SourceProcessId = SourceProcessId;
    Chain->TargetProcessId = TargetProcessId;
    Chain->FirstOperationTime = CurrentTime;
    Chain->LastOperationTime = CurrentTime;

    InsertTailList(&Detector->ActiveChains, &Chain->ListEntry);
    InterlockedIncrement(&Detector->ActiveChainCount);

    KeReleaseSpinLock(&Detector->ChainLock, OldIrql);

    InterlockedIncrement64(&Detector->Public.Stats.ChainsCreated);

    return Chain;
}

static NTSTATUS
InjpAddOperationToChain(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _In_ PINJ_CHAIN Chain,
    _In_ PINJ_OPERATION Operation
    )
{
    KIRQL OldIrql;

    if (Chain->OperationCount >= Detector->Public.Config.MaxOperationsPerChain) {
        return STATUS_QUOTA_EXCEEDED;
    }

    KeAcquireSpinLock(&Detector->ChainLock, &OldIrql);

    InsertTailList(&Chain->OperationList, &Operation->ChainEntry);
    Chain->OperationCount++;
    Chain->TotalSize += Operation->Size;
    Chain->LastOperationTime = Operation->Timestamp;

    //
    // Update chain flags based on operation
    //
    if (InjpIsExecutableProtection(Operation->Protection)) {
        Chain->Flags |= INJ_CHAIN_FLAG_HAS_EXECUTE;
    }

    if (InjpIsWritableProtection(Operation->Protection)) {
        Chain->Flags |= INJ_CHAIN_FLAG_HAS_WRITE;
    }

    if (Operation->Type == InjOpCreateThread) {
        Chain->Flags |= INJ_CHAIN_FLAG_HAS_THREAD;
    }

    if (Operation->Type == InjOpQueueApc) {
        Chain->Flags |= INJ_CHAIN_FLAG_HAS_APC;
    }

    KeReleaseSpinLock(&Detector->ChainLock, OldIrql);

    return STATUS_SUCCESS;
}

static INJ_TECHNIQUE
InjpAnalyzeChain(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _In_ PINJ_CHAIN Chain,
    _Out_ PULONG ConfidenceScore
    )
{
    ULONG Patterns;
    INJ_TECHNIQUE Technique;

    UNREFERENCED_PARAMETER(Detector);

    *ConfidenceScore = 0;

    if (Chain->OperationCount < 2) {
        return InjTechNone;
    }

    //
    // Calculate operation patterns
    //
    Patterns = InjpCalculateOperationPatterns(Chain);

    //
    // Match patterns to techniques
    //
    Technique = InjpMatchPatternToTechnique(Patterns, Chain);

    if (Technique != InjTechNone) {
        *ConfidenceScore = InjpCalculateSuspicionScore(Chain, Technique);
    }

    Chain->DetectedTechnique = Technique;
    Chain->ConfidenceScore = *ConfidenceScore;

    return Technique;
}

static ULONG
InjpCalculateOperationPatterns(
    _In_ PINJ_CHAIN Chain
    )
{
    ULONG Patterns = 0;
    PLIST_ENTRY Entry;
    PINJ_OPERATION Op;
    PINJ_OPERATION PrevOp = NULL;

    for (Entry = Chain->OperationList.Flink;
         Entry != &Chain->OperationList;
         Entry = Entry->Flink) {

        Op = CONTAINING_RECORD(Entry, INJ_OPERATION, ChainEntry);

        switch (Op->Type) {
        case InjOpAllocate:
            if (PrevOp == NULL || PrevOp->Type != InjOpAllocate) {
                Patterns |= INJ_PATTERN_ALLOCATE_WRITE;
            }
            break;

        case InjOpWrite:
            if (PrevOp != NULL && PrevOp->Type == InjOpAllocate) {
                Patterns |= INJ_PATTERN_ALLOCATE_WRITE;
            }
            break;

        case InjOpProtect:
            if (PrevOp != NULL && PrevOp->Type == InjOpWrite) {
                Patterns |= INJ_PATTERN_WRITE_PROTECT;
            }
            if (InjpIsExecutableProtection(Op->Protection)) {
                Patterns |= INJ_PATTERN_PROTECT_EXECUTE;
            }
            break;

        case InjOpCreateThread:
            Patterns |= INJ_PATTERN_CREATE_THREAD;
            break;

        case InjOpQueueApc:
            Patterns |= INJ_PATTERN_QUEUE_APC;
            break;

        case InjOpMapSection:
            Patterns |= INJ_PATTERN_MAP_SECTION;
            break;

        case InjOpSetContext:
            Patterns |= INJ_PATTERN_SET_CONTEXT;
            break;

        case InjOpSuspend:
        case InjOpResume:
            Patterns |= INJ_PATTERN_SUSPEND_RESUME;
            break;

        default:
            break;
        }

        PrevOp = Op;
    }

    return Patterns;
}

static INJ_TECHNIQUE
InjpMatchPatternToTechnique(
    _In_ ULONG Patterns,
    _In_ PINJ_CHAIN Chain
    )
{
    //
    // Process Hollowing: Suspend + Write + Set Context + Resume
    //
    if ((Patterns & INJ_PATTERN_SUSPEND_RESUME) &&
        (Patterns & INJ_PATTERN_SET_CONTEXT) &&
        (Patterns & INJ_PATTERN_ALLOCATE_WRITE)) {
        return InjTechProcessHollowing;
    }

    //
    // Process Doppelganging: Map Section with transacted file
    //
    if ((Patterns & INJ_PATTERN_MAP_SECTION) &&
        (Chain->Flags & INJ_CHAIN_FLAG_TRANSACTED)) {
        return InjTechProcessDoppelganging;
    }

    //
    // APC Injection: Allocate + Write + Queue APC
    //
    if ((Patterns & INJ_PATTERN_ALLOCATE_WRITE) &&
        (Patterns & INJ_PATTERN_QUEUE_APC)) {
        return InjTechApcInjection;
    }

    //
    // Classic DLL Injection: Allocate + Write + CreateRemoteThread
    //
    if ((Patterns & INJ_PATTERN_ALLOCATE_WRITE) &&
        (Patterns & INJ_PATTERN_CREATE_THREAD)) {
        return InjTechCreateRemoteThread;
    }

    //
    // Reflective DLL: Allocate + Write + Protect RX
    //
    if ((Patterns & INJ_PATTERN_ALLOCATE_WRITE) &&
        (Patterns & INJ_PATTERN_PROTECT_EXECUTE)) {
        return InjTechReflectiveDll;
    }

    //
    // Thread Hijacking: Suspend + Set Context + Resume
    //
    if ((Patterns & INJ_PATTERN_SUSPEND_RESUME) &&
        (Patterns & INJ_PATTERN_SET_CONTEXT)) {
        return InjTechThreadHijacking;
    }

    //
    // Section mapping without other patterns
    //
    if ((Patterns & INJ_PATTERN_MAP_SECTION) &&
        (Chain->Flags & INJ_CHAIN_FLAG_HAS_EXECUTE)) {
        return InjTechMapViewOfSection;
    }

    //
    // Generic PE injection patterns
    //
    if ((Patterns & INJ_PATTERN_ALLOCATE_WRITE) &&
        (Chain->Flags & INJ_CHAIN_FLAG_HAS_EXECUTE)) {
        return InjTechPeInjection;
    }

    return InjTechNone;
}

static VOID
InjpPopulateMitreMapping(
    _In_ INJ_TECHNIQUE Technique,
    _Out_ PINJ_DETECTION_RESULT Result
    )
{
    switch (Technique) {
    case InjTechCreateRemoteThread:
        RtlStringCchCopyA(Result->MitreTechnique, sizeof(Result->MitreTechnique), "T1055.001");
        RtlStringCchCopyA(Result->MitreSubTechnique, sizeof(Result->MitreSubTechnique), "DLL Injection");
        break;

    case InjTechPeInjection:
        RtlStringCchCopyA(Result->MitreTechnique, sizeof(Result->MitreTechnique), "T1055.002");
        RtlStringCchCopyA(Result->MitreSubTechnique, sizeof(Result->MitreSubTechnique), "PE Injection");
        break;

    case InjTechThreadHijacking:
        RtlStringCchCopyA(Result->MitreTechnique, sizeof(Result->MitreTechnique), "T1055.003");
        RtlStringCchCopyA(Result->MitreSubTechnique, sizeof(Result->MitreSubTechnique), "Thread Execution Hijacking");
        break;

    case InjTechApcInjection:
        RtlStringCchCopyA(Result->MitreTechnique, sizeof(Result->MitreTechnique), "T1055.004");
        RtlStringCchCopyA(Result->MitreSubTechnique, sizeof(Result->MitreSubTechnique), "Asynchronous Procedure Call");
        break;

    case InjTechTlsCallback:
        RtlStringCchCopyA(Result->MitreTechnique, sizeof(Result->MitreTechnique), "T1055.005");
        RtlStringCchCopyA(Result->MitreSubTechnique, sizeof(Result->MitreSubTechnique), "Thread Local Storage");
        break;

    case InjTechExtraWindowMemory:
        RtlStringCchCopyA(Result->MitreTechnique, sizeof(Result->MitreTechnique), "T1055.011");
        RtlStringCchCopyA(Result->MitreSubTechnique, sizeof(Result->MitreSubTechnique), "Extra Window Memory Injection");
        break;

    case InjTechProcessHollowing:
        RtlStringCchCopyA(Result->MitreTechnique, sizeof(Result->MitreTechnique), "T1055.012");
        RtlStringCchCopyA(Result->MitreSubTechnique, sizeof(Result->MitreSubTechnique), "Process Hollowing");
        break;

    case InjTechProcessDoppelganging:
        RtlStringCchCopyA(Result->MitreTechnique, sizeof(Result->MitreTechnique), "T1055.013");
        RtlStringCchCopyA(Result->MitreSubTechnique, sizeof(Result->MitreSubTechnique), "Process Doppelganging");
        break;

    case InjTechReflectiveDll:
        RtlStringCchCopyA(Result->MitreTechnique, sizeof(Result->MitreTechnique), "T1620");
        RtlStringCchCopyA(Result->MitreSubTechnique, sizeof(Result->MitreSubTechnique), "Reflective Code Loading");
        break;

    case InjTechAtomBombing:
        RtlStringCchCopyA(Result->MitreTechnique, sizeof(Result->MitreTechnique), "T1055");
        RtlStringCchCopyA(Result->MitreSubTechnique, sizeof(Result->MitreSubTechnique), "Atom Bombing");
        break;

    case InjTechMapViewOfSection:
        RtlStringCchCopyA(Result->MitreTechnique, sizeof(Result->MitreTechnique), "T1055");
        RtlStringCchCopyA(Result->MitreSubTechnique, sizeof(Result->MitreSubTechnique), "Section Mapping");
        break;

    default:
        RtlStringCchCopyA(Result->MitreTechnique, sizeof(Result->MitreTechnique), "T1055");
        RtlStringCchCopyA(Result->MitreSubTechnique, sizeof(Result->MitreSubTechnique), "Process Injection");
        break;
    }
}

static ULONG
InjpCalculateSuspicionScore(
    _In_ PINJ_CHAIN Chain,
    _In_ INJ_TECHNIQUE Technique
    )
{
    ULONG Score = 0;

    //
    // Base score by technique severity
    //
    switch (Technique) {
    case InjTechProcessHollowing:
    case InjTechProcessDoppelganging:
        Score = 95;
        break;

    case InjTechCreateRemoteThread:
    case InjTechApcInjection:
        Score = 85;
        break;

    case InjTechReflectiveDll:
    case InjTechThreadHijacking:
        Score = 80;
        break;

    case InjTechPeInjection:
    case InjTechMapViewOfSection:
        Score = 70;
        break;

    case InjTechAtomBombing:
    case InjTechCallbackInjection:
        Score = 75;
        break;

    default:
        Score = 50;
        break;
    }

    //
    // Adjust based on chain characteristics
    //
    if (Chain->Flags & INJ_CHAIN_FLAG_HAS_EXECUTE) {
        Score += 5;
    }

    if (Chain->Flags & INJ_CHAIN_FLAG_HAS_WRITE) {
        Score += 3;
    }

    if (Chain->OperationCount >= 5) {
        Score += 5;
    }

    if (Chain->TotalSize > 0x10000) {
        Score += 3;
    }

    //
    // Cap at 100
    //
    if (Score > 100) {
        Score = 100;
    }

    return Score;
}

static PINJ_DETECTION_RESULT
InjpAllocateResult(
    _In_ PINJ_DETECTOR_INTERNAL Detector
    )
{
    PINJ_DETECTION_RESULT Result;

    Result = (PINJ_DETECTION_RESULT)ExAllocateFromNPagedLookasideList(
        &Detector->ResultLookaside
        );

    if (Result != NULL) {
        RtlZeroMemory(Result, sizeof(INJ_DETECTION_RESULT));
    }

    return Result;
}

static VOID
InjpFreeResult(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _In_ PINJ_DETECTION_RESULT Result
    )
{
    ExFreeToNPagedLookasideList(&Detector->ResultLookaside, Result);
}

static NTSTATUS
InjpGenerateDetectionResult(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _In_ PINJ_CHAIN Chain,
    _In_ INJ_TECHNIQUE Technique,
    _In_ ULONG ConfidenceScore,
    _Out_ PINJ_DETECTION_RESULT* Result
    )
{
    PINJ_DETECTION_RESULT NewResult;
    PLIST_ENTRY Entry;
    PINJ_OPERATION FirstOp = NULL;

    NewResult = InjpAllocateResult(Detector);
    if (NewResult == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NewResult->Technique = Technique;
    NewResult->ConfidenceScore = ConfidenceScore;
    NewResult->SourceProcessId = Chain->SourceProcessId;
    NewResult->TargetProcessId = Chain->TargetProcessId;
    NewResult->ChainId = Chain->ChainId;
    KeQuerySystemTime(&NewResult->DetectionTime);

    //
    // Get first operation details
    //
    if (!IsListEmpty(&Chain->OperationList)) {
        Entry = Chain->OperationList.Flink;
        FirstOp = CONTAINING_RECORD(Entry, INJ_OPERATION, ChainEntry);

        NewResult->TargetAddress = FirstOp->TargetAddress;
        NewResult->Size = Chain->TotalSize;
    }

    //
    // Set severity based on confidence
    //
    if (ConfidenceScore >= INJ_SUSPICION_THRESHOLD_CRITICAL) {
        NewResult->Severity = 4; // Critical
    } else if (ConfidenceScore >= INJ_SUSPICION_THRESHOLD_HIGH) {
        NewResult->Severity = 3; // High
    } else if (ConfidenceScore >= INJ_SUSPICION_THRESHOLD_MEDIUM) {
        NewResult->Severity = 2; // Medium
    } else {
        NewResult->Severity = 1; // Low
    }

    //
    // Populate MITRE mapping
    //
    InjpPopulateMitreMapping(Technique, NewResult);

    //
    // Generate description
    //
    RtlStringCchPrintfA(
        NewResult->Description,
        sizeof(NewResult->Description),
        "Injection detected: %s (PID %u -> PID %u, Confidence: %u%%)",
        NewResult->MitreSubTechnique,
        (ULONG)(ULONG_PTR)Chain->SourceProcessId,
        (ULONG)(ULONG_PTR)Chain->TargetProcessId,
        ConfidenceScore
        );

    *Result = NewResult;

    return STATUS_SUCCESS;
}

static VOID
InjpNotifyDetectionCallbacks(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _In_ PINJ_DETECTION_RESULT Result
    )
{
    KIRQL OldIrql;
    ULONG i;

    KeAcquireSpinLock(&Detector->CallbackLock, &OldIrql);

    for (i = 0; i < INJ_MAX_CALLBACKS; i++) {
        if (Detector->DetectionCallbacks[i].Active &&
            Detector->DetectionCallbacks[i].Callback != NULL) {

            KeReleaseSpinLock(&Detector->CallbackLock, OldIrql);

            __try {
                Detector->DetectionCallbacks[i].Callback(
                    Result,
                    Detector->DetectionCallbacks[i].Context
                    );
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                // Ignore callback exceptions
            }

            KeAcquireSpinLock(&Detector->CallbackLock, &OldIrql);
        }
    }

    KeReleaseSpinLock(&Detector->CallbackLock, OldIrql);
}

static BOOLEAN
InjpShouldBlockInjection(
    _In_ PINJ_DETECTOR_INTERNAL Detector,
    _In_ PINJ_OPERATION Operation
    )
{
    KIRQL OldIrql;
    ULONG i;
    BOOLEAN ShouldBlock = FALSE;

    //
    // Check basic blocking conditions
    //
    if (Operation->SuspicionScore < (ULONG)Detector->Public.Config.MinConfidenceToBlock) {
        return FALSE;
    }

    //
    // Consult block callbacks
    //
    KeAcquireSpinLock(&Detector->CallbackLock, &OldIrql);

    for (i = 0; i < INJ_MAX_CALLBACKS; i++) {
        if (Detector->BlockCallbacks[i].Active &&
            Detector->BlockCallbacks[i].Callback != NULL) {

            KeReleaseSpinLock(&Detector->CallbackLock, OldIrql);

            __try {
                INJ_DETECTION_RESULT TempResult;
                RtlZeroMemory(&TempResult, sizeof(TempResult));
                TempResult.SourceProcessId = Operation->SourceProcessId;
                TempResult.TargetProcessId = Operation->TargetProcessId;
                TempResult.TargetAddress = Operation->TargetAddress;
                TempResult.ConfidenceScore = Operation->SuspicionScore;

                //
                // Block callback returns TRUE if we should block
                //
                ShouldBlock = ((INJ_BLOCK_CALLBACK)Detector->BlockCallbacks[i].Callback)(
                    Operation,
                    Detector->BlockCallbacks[i].Context
                    );
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                // Default to not blocking on exception
            }

            if (ShouldBlock) {
                return TRUE;
            }

            KeAcquireSpinLock(&Detector->CallbackLock, &OldIrql);
        }
    }

    KeReleaseSpinLock(&Detector->CallbackLock, OldIrql);

    return ShouldBlock;
}

static VOID
InjpWorkerThread(
    _In_ PVOID StartContext
    )
{
    PINJ_DETECTOR_INTERNAL Detector = (PINJ_DETECTOR_INTERNAL)StartContext;
    PVOID WaitObjects[2];
    NTSTATUS Status;
    PLIST_ENTRY Entry;
    PINJ_CHAIN Chain;
    KIRQL OldIrql;

    WaitObjects[0] = &Detector->ShutdownEvent;
    WaitObjects[1] = &Detector->AnalysisEvent;

    while (!Detector->ShutdownRequested) {
        Status = KeWaitForMultipleObjects(
            2,
            WaitObjects,
            WaitAny,
            Executive,
            KernelMode,
            FALSE,
            NULL,
            NULL
            );

        if (Status == STATUS_WAIT_0 || Detector->ShutdownRequested) {
            break;
        }

        if (Status == STATUS_WAIT_1) {
            //
            // Analyze all active chains
            //
            if (Detector->Public.Initialized && !Detector->ShutdownRequested) {
                KeAcquireSpinLock(&Detector->ChainLock, &OldIrql);

                for (Entry = Detector->ActiveChains.Flink;
                     Entry != &Detector->ActiveChains && !Detector->ShutdownRequested;
                     Entry = Entry->Flink) {

                    Chain = CONTAINING_RECORD(Entry, INJ_CHAIN, ListEntry);

                    if (Chain->OperationCount >= 2 &&
                        Chain->DetectedTechnique == InjTechNone) {

                        INJ_TECHNIQUE Technique;
                        ULONG Confidence;
                        PINJ_DETECTION_RESULT Result = NULL;

                        KeReleaseSpinLock(&Detector->ChainLock, OldIrql);

                        Technique = InjpAnalyzeChain(Detector, Chain, &Confidence);

                        if (Technique != InjTechNone &&
                            Confidence >= Detector->Public.Config.MinConfidenceToAlert) {

                            Status = InjpGenerateDetectionResult(
                                Detector,
                                Chain,
                                Technique,
                                Confidence,
                                &Result
                                );

                            if (NT_SUCCESS(Status) && Result != NULL) {
                                InterlockedIncrement64(&Detector->Public.Stats.DetectedInjections);
                                InjpNotifyDetectionCallbacks(Detector, Result);
                                InjpFreeResult(Detector, Result);
                            }
                        }

                        KeAcquireSpinLock(&Detector->ChainLock, &OldIrql);
                    }
                }

                KeReleaseSpinLock(&Detector->ChainLock, OldIrql);

                //
                // Cleanup stale data
                //
                InjpCleanupStaleChains(Detector);
                InjpCleanupStaleOperations(Detector);
            }
        }
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

static VOID
InjpCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PINJ_DETECTOR_INTERNAL Detector = (PINJ_DETECTOR_INTERNAL)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (Detector == NULL || Detector->ShutdownRequested) {
        return;
    }

    //
    // Signal worker thread for cleanup
    //
    KeSetEvent(&Detector->AnalysisEvent, IO_NO_INCREMENT, FALSE);
}

static VOID
InjpCleanupStaleOperations(
    _In_ PINJ_DETECTOR_INTERNAL Detector
    )
{
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeoutInterval;
    ULONG i;

    KeQuerySystemTime(&CurrentTime);
    TimeoutInterval.QuadPart = (LONGLONG)Detector->Public.Config.ChainTimeoutMs * 10000 * 2;

    for (i = 0; i < INJ_HASH_BUCKET_COUNT && !Detector->ShutdownRequested; i++) {
        KIRQL OldIrql;
        PLIST_ENTRY Entry, Next;
        PINJ_OPERATION Operation;

        KeAcquireSpinLock(&Detector->OperationBuckets[i].Lock, &OldIrql);

        for (Entry = Detector->OperationBuckets[i].OperationList.Flink;
             Entry != &Detector->OperationBuckets[i].OperationList;
             Entry = Next) {

            Next = Entry->Flink;
            Operation = CONTAINING_RECORD(Entry, INJ_OPERATION, HashEntry);

            if ((CurrentTime.QuadPart - Operation->Timestamp.QuadPart) > TimeoutInterval.QuadPart) {
                //
                // Operation is stale - remove it
                //
                RemoveEntryList(&Operation->HashEntry);
                InitializeListHead(&Operation->HashEntry);
                Detector->OperationBuckets[i].Count--;
                InterlockedDecrement(&Detector->TotalOperationCount);

                KeReleaseSpinLock(&Detector->OperationBuckets[i].Lock, OldIrql);
                InjpFreeOperation(Detector, Operation);
                KeAcquireSpinLock(&Detector->OperationBuckets[i].Lock, &OldIrql);
            }
        }

        KeReleaseSpinLock(&Detector->OperationBuckets[i].Lock, OldIrql);
    }
}

static VOID
InjpCleanupStaleChains(
    _In_ PINJ_DETECTOR_INTERNAL Detector
    )
{
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeoutInterval;
    PLIST_ENTRY Entry, Next;
    PINJ_CHAIN Chain;
    KIRQL OldIrql;

    KeQuerySystemTime(&CurrentTime);
    TimeoutInterval.QuadPart = (LONGLONG)Detector->Public.Config.ChainTimeoutMs * 10000;

    KeAcquireSpinLock(&Detector->ChainLock, &OldIrql);

    for (Entry = Detector->ActiveChains.Flink;
         Entry != &Detector->ActiveChains;
         Entry = Next) {

        Next = Entry->Flink;
        Chain = CONTAINING_RECORD(Entry, INJ_CHAIN, ListEntry);

        if ((CurrentTime.QuadPart - Chain->LastOperationTime.QuadPart) > TimeoutInterval.QuadPart) {
            //
            // Chain is stale - remove it
            //
            RemoveEntryList(&Chain->ListEntry);
            InterlockedDecrement(&Detector->ActiveChainCount);

            KeReleaseSpinLock(&Detector->ChainLock, OldIrql);
            InjpFreeChain(Detector, Chain);
            KeAcquireSpinLock(&Detector->ChainLock, &OldIrql);
        }
    }

    KeReleaseSpinLock(&Detector->ChainLock, OldIrql);
}

static BOOLEAN
InjpIsRemoteOperation(
    _In_ PINJ_OPERATION Operation
    )
{
    return (Operation->SourceProcessId != Operation->TargetProcessId);
}

static BOOLEAN
InjpIsSuspiciousProtection(
    _In_ ULONG Protection
    )
{
    //
    // RWX is highly suspicious
    //
    if ((Protection & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) {
        return TRUE;
    }

    if ((Protection & PAGE_EXECUTE_WRITECOPY) == PAGE_EXECUTE_WRITECOPY) {
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN
InjpIsExecutableProtection(
    _In_ ULONG Protection
    )
{
    return (Protection & PAGE_EXECUTE) ||
           (Protection & PAGE_EXECUTE_READ) ||
           (Protection & PAGE_EXECUTE_READWRITE) ||
           (Protection & PAGE_EXECUTE_WRITECOPY);
}

static BOOLEAN
InjpIsWritableProtection(
    _In_ ULONG Protection
    )
{
    return (Protection & PAGE_READWRITE) ||
           (Protection & PAGE_WRITECOPY) ||
           (Protection & PAGE_EXECUTE_READWRITE) ||
           (Protection & PAGE_EXECUTE_WRITECOPY);
}

