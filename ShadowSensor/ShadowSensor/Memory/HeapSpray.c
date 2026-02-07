/*++
    ShadowStrike Next-Generation Antivirus
    Module: HeapSpray.c

    Purpose: Enterprise-grade heap spray attack detection through pattern analysis,
             memory allocation monitoring, and behavioral heuristics.

    Architecture:
    - Per-process allocation tracking with sliding time windows
    - Pattern hash-based similarity detection using FNV-1a
    - NOP sled and shellcode pattern recognition
    - JIT spray detection via executable page tracking
    - Rate-based anomaly detection for allocation bursts
    - Memory-efficient allocation record pooling
    - Lock-free statistics for minimal overhead

    Detection Capabilities:
    - Classic NOP sled spray (0x90, 0x0C0C, etc.)
    - Heap feng shui patterns
    - JIT-compiled code spray (JavaScript engines)
    - TypedArray spray (WebAssembly/Browser exploits)
    - String-based sprays (BSTR, Unicode patterns)
    - Object spray (vtable pointer spray)

    MITRE ATT&CK Coverage:
    - T1203: Exploitation for Client Execution
    - T1189: Drive-by Compromise
    - T1499: Endpoint Denial of Service

    Copyright (c) ShadowStrike Team
--*/

#include "HeapSpray.h"
#include "../Utilities/MemoryUtils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, HsInitialize)
#pragma alloc_text(PAGE, HsShutdown)
#pragma alloc_text(PAGE, HsStartTracking)
#pragma alloc_text(PAGE, HsStopTracking)
#pragma alloc_text(PAGE, HsRegisterCallback)
#pragma alloc_text(PAGE, HsUnregisterCallback)
#endif

//=============================================================================
// Internal Constants
//=============================================================================

#define HS_SIGNATURE                    'YPSH'  // 'HSPY' reversed
#define HS_PROCESS_SIGNATURE            'CPSH'  // 'HSPC' reversed
#define HS_ALLOC_SIGNATURE              'AOSH'  // 'HSOA' reversed

#define HS_PATTERN_HASH_BUCKETS         256
#define HS_MAX_CALLBACKS                8
#define HS_ALLOCATION_POOL_SIZE         4096

#define HS_FNV_OFFSET_BASIS             0x811C9DC5
#define HS_FNV_PRIME                    0x01000193

#define HS_REPETITION_THRESHOLD         80      // 80% repetition = suspicious
#define HS_MIN_SCORE_FOR_SPRAY          500     // Score threshold for detection
#define HS_HIGH_ALLOC_RATE_THRESHOLD    50      // Allocations per second

//
// Known spray patterns
//
#define HS_NOP_X86                      0x90
#define HS_NOP_SLIDE_12                 0x0C0C0C0C
#define HS_NOP_SLIDE_0D                 0x0D0D0D0D
#define HS_NOP_SLIDE_0A                 0x0A0A0A0A
#define HS_HEAP_SPRAY_MAGIC_1           0x41414141  // AAAA
#define HS_HEAP_SPRAY_MAGIC_2           0x42424242  // BBBB
#define HS_JIT_XOR_PATTERN              0x3C909090  // XOR + NOPs

//=============================================================================
// Internal Structures
//=============================================================================

typedef struct _HS_CALLBACK_ENTRY {
    HS_SPRAY_CALLBACK Callback;
    PVOID Context;
    volatile BOOLEAN Active;
} HS_CALLBACK_ENTRY, *PHS_CALLBACK_ENTRY;

typedef struct _HS_DETECTOR_INTERNAL {
    ULONG Signature;
    HS_DETECTOR Detector;

    //
    // Callback management
    //
    HS_CALLBACK_ENTRY Callbacks[HS_MAX_CALLBACKS];
    EX_PUSH_LOCK CallbackLock;
    volatile LONG CallbackCount;

    //
    // Process context pool
    //
    NPAGED_LOOKASIDE_LIST ProcessContextLookaside;

    //
    // Shutdown flag
    //
    volatile BOOLEAN ShuttingDown;

} HS_DETECTOR_INTERNAL, *PHS_DETECTOR_INTERNAL;

//=============================================================================
// Forward Declarations
//=============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
static PHS_PROCESS_CONTEXT
HspFindProcessContext(
    _In_ PHS_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN CreateIfNotFound
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
HspReferenceProcessContext(
    _Inout_ PHS_PROCESS_CONTEXT Context
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
HspDereferenceProcessContext(
    _In_ PHS_DETECTOR_INTERNAL* DetectorInternal,
    _Inout_ PHS_PROCESS_CONTEXT Context
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
HspDestroyProcessContext(
    _In_ PHS_DETECTOR_INTERNAL* DetectorInternal,
    _Inout_ PHS_PROCESS_CONTEXT Context
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static PHS_ALLOCATION_RECORD
HspAllocateRecord(
    _In_ PHS_DETECTOR Detector
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
HspFreeRecord(
    _In_ PHS_DETECTOR Detector,
    _Inout_ PHS_ALLOCATION_RECORD Record
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
HspCalculatePatternHash(
    _In_reads_bytes_(Size) PUCHAR Data,
    _In_ ULONG Size
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
HspCalculateRepetitionScore(
    _In_reads_bytes_(Size) PUCHAR Data,
    _In_ ULONG Size
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static HS_SPRAY_TYPE
HspDetectSprayType(
    _In_ PHS_PROCESS_CONTEXT Context,
    _In_ PUCHAR PatternSample,
    _In_ ULONG SampleSize
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
HspCalculateSprayScore(
    _In_ PHS_PROCESS_CONTEXT Context,
    _In_ PHS_ALLOCATION_RECORD Record
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
HspPruneOldAllocations(
    _Inout_ PHS_PROCESS_CONTEXT Context,
    _In_ PLARGE_INTEGER CurrentTime,
    _In_ PHS_DETECTOR Detector
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
HspInvokeCallbacks(
    _In_ PHS_DETECTOR_INTERNAL DetectorInternal,
    _In_ PHS_SPRAY_RESULT Result
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
HspIsKnownSprayPattern(
    _In_reads_bytes_(Size) PUCHAR Data,
    _In_ ULONG Size
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
HspContainsNopSled(
    _In_reads_bytes_(Size) PUCHAR Data,
    _In_ ULONG Size
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
HspContainsShellcodeSignatures(
    _In_reads_bytes_(Size) PUCHAR Data,
    _In_ ULONG Size
    );

//=============================================================================
// Initialization / Shutdown
//=============================================================================

_Use_decl_annotations_
NTSTATUS
HsInitialize(
    _Out_ PHS_DETECTOR* Detector
    )
/*++

Routine Description:

    Initializes the heap spray detection subsystem. Allocates the detector
    structure, initializes allocation pools, and prepares tracking infrastructure.

Arguments:

    Detector - Receives pointer to initialized detector.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PHS_DETECTOR_INTERNAL detectorInternal = NULL;
    PHS_DETECTOR detector = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG i;

    PAGED_CODE();

    if (Detector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Detector = NULL;

    //
    // Allocate the internal detector structure
    //
    detectorInternal = (PHS_DETECTOR_INTERNAL)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(HS_DETECTOR_INTERNAL),
        HS_POOL_TAG_CONTEXT
        );

    if (detectorInternal == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(detectorInternal, sizeof(HS_DETECTOR_INTERNAL));

    detectorInternal->Signature = HS_SIGNATURE;
    detector = &detectorInternal->Detector;

    //
    // Initialize process list
    //
    InitializeListHead(&detector->ProcessList);
    FltInitializePushLock(&detector->ProcessListLock);
    detector->ProcessCount = 0;

    //
    // Initialize allocation record pool
    //
    detector->AllocationPool.PoolSize = HS_ALLOCATION_POOL_SIZE;
    detector->AllocationPool.PoolMemory = (PHS_ALLOCATION_RECORD)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(HS_ALLOCATION_RECORD) * HS_ALLOCATION_POOL_SIZE,
        HS_POOL_TAG_ALLOC
        );

    if (detector->AllocationPool.PoolMemory == NULL) {
        ShadowStrikeFreePoolWithTag(detectorInternal, HS_POOL_TAG_CONTEXT);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(
        detector->AllocationPool.PoolMemory,
        sizeof(HS_ALLOCATION_RECORD) * HS_ALLOCATION_POOL_SIZE
        );

    //
    // Build free list from pool
    //
    InitializeListHead(&detector->AllocationPool.FreeList);
    KeInitializeSpinLock(&detector->AllocationPool.Lock);

    for (i = 0; i < HS_ALLOCATION_POOL_SIZE; i++) {
        InsertTailList(
            &detector->AllocationPool.FreeList,
            &detector->AllocationPool.PoolMemory[i].ListEntry
            );
    }
    detector->AllocationPool.FreeCount = HS_ALLOCATION_POOL_SIZE;

    //
    // Initialize process context lookaside list
    //
    ExInitializeNPagedLookasideList(
        &detectorInternal->ProcessContextLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(HS_PROCESS_CONTEXT),
        HS_POOL_TAG_CONTEXT,
        0
        );

    //
    // Initialize callbacks
    //
    FltInitializePushLock(&detectorInternal->CallbackLock);
    detectorInternal->CallbackCount = 0;

    for (i = 0; i < HS_MAX_CALLBACKS; i++) {
        detectorInternal->Callbacks[i].Active = FALSE;
    }

    //
    // Set default configuration
    //
    detector->Config.MinSpraySizeBytes = HS_MIN_SPRAY_SIZE;
    detector->Config.MinAllocationCount = HS_MIN_SIMILAR_ALLOCATIONS;
    detector->Config.AllocationWindowMs = HS_ALLOCATION_WINDOW_MS;
    detector->Config.PatternSampleSize = HS_PATTERN_SAMPLE_SIZE;
    detector->Config.TrackAllProcesses = FALSE;

    //
    // Initialize statistics
    //
    KeQuerySystemTimePrecise(&detector->Stats.StartTime);
    detector->Stats.TotalAllocationsTracked = 0;
    detector->Stats.SpraysDetected = 0;
    detector->Stats.ProcessesMonitored = 0;

    detector->Initialized = TRUE;
    detectorInternal->ShuttingDown = FALSE;

    *Detector = detector;

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
HsShutdown(
    _Inout_ PHS_DETECTOR Detector
    )
/*++

Routine Description:

    Shuts down the heap spray detector. Stops all tracking, frees all
    resources, and releases the detector structure.

Arguments:

    Detector - Detector to shutdown.

--*/
{
    PHS_DETECTOR_INTERNAL detectorInternal;
    PHS_PROCESS_CONTEXT context;
    PLIST_ENTRY entry;
    LIST_ENTRY contextsToFree;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized) {
        return;
    }

    detectorInternal = CONTAINING_RECORD(Detector, HS_DETECTOR_INTERNAL, Detector);

    if (detectorInternal->Signature != HS_SIGNATURE) {
        return;
    }

    detectorInternal->ShuttingDown = TRUE;
    Detector->Initialized = FALSE;
    KeMemoryBarrier();

    //
    // Collect all process contexts for cleanup
    //
    InitializeListHead(&contextsToFree);

    FltAcquirePushLockExclusive(&Detector->ProcessListLock);

    while (!IsListEmpty(&Detector->ProcessList)) {
        entry = RemoveHeadList(&Detector->ProcessList);
        context = CONTAINING_RECORD(entry, HS_PROCESS_CONTEXT, ListEntry);
        InsertTailList(&contextsToFree, entry);
    }

    Detector->ProcessCount = 0;

    FltReleasePushLock(&Detector->ProcessListLock);

    //
    // Destroy all process contexts
    //
    while (!IsListEmpty(&contextsToFree)) {
        entry = RemoveHeadList(&contextsToFree);
        context = CONTAINING_RECORD(entry, HS_PROCESS_CONTEXT, ListEntry);
        HspDestroyProcessContext(detectorInternal, context);
    }

    //
    // Free allocation pool
    //
    if (Detector->AllocationPool.PoolMemory != NULL) {
        ShadowStrikeFreePoolWithTag(
            Detector->AllocationPool.PoolMemory,
            HS_POOL_TAG_ALLOC
            );
        Detector->AllocationPool.PoolMemory = NULL;
    }

    //
    // Delete lookaside list
    //
    ExDeleteNPagedLookasideList(&detectorInternal->ProcessContextLookaside);

    //
    // Clear signature and free
    //
    detectorInternal->Signature = 0;
    ShadowStrikeFreePoolWithTag(detectorInternal, HS_POOL_TAG_CONTEXT);
}


//=============================================================================
// Process Tracking
//=============================================================================

_Use_decl_annotations_
NTSTATUS
HsStartTracking(
    _In_ PHS_DETECTOR Detector,
    _In_ HANDLE ProcessId
    )
/*++

Routine Description:

    Starts tracking heap allocations for a specific process.

Arguments:

    Detector - Heap spray detector.
    ProcessId - Process to track.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PHS_PROCESS_CONTEXT context;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ProcessId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Create context if it doesn't exist
    //
    context = HspFindProcessContext(Detector, ProcessId, TRUE);
    if (context == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Release the reference from find
    //
    HspDereferenceProcessContext(
        CONTAINING_RECORD(Detector, HS_DETECTOR_INTERNAL, Detector),
        context
        );

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
HsStopTracking(
    _In_ PHS_DETECTOR Detector,
    _In_ HANDLE ProcessId
    )
/*++

Routine Description:

    Stops tracking heap allocations for a specific process.

Arguments:

    Detector - Heap spray detector.
    ProcessId - Process to stop tracking.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PHS_DETECTOR_INTERNAL detectorInternal;
    PHS_PROCESS_CONTEXT context;
    PLIST_ENTRY entry;
    BOOLEAN found = FALSE;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    detectorInternal = CONTAINING_RECORD(Detector, HS_DETECTOR_INTERNAL, Detector);

    //
    // Find and remove the process context
    //
    FltAcquirePushLockExclusive(&Detector->ProcessListLock);

    for (entry = Detector->ProcessList.Flink;
         entry != &Detector->ProcessList;
         entry = entry->Flink) {

        context = CONTAINING_RECORD(entry, HS_PROCESS_CONTEXT, ListEntry);

        if (context->ProcessId == ProcessId) {
            RemoveEntryList(&context->ListEntry);
            InterlockedDecrement(&Detector->ProcessCount);
            found = TRUE;
            break;
        }
    }

    FltReleasePushLock(&Detector->ProcessListLock);

    if (found) {
        HspDestroyProcessContext(detectorInternal, context);
    }

    return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}


//=============================================================================
// Allocation Monitoring
//=============================================================================

_Use_decl_annotations_
NTSTATUS
HsRecordAllocation(
    _In_ PHS_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _In_ SIZE_T Size,
    _In_ ULONG Protection,
    _In_opt_ PVOID ReturnAddress
    )
/*++

Routine Description:

    Records a heap allocation for spray detection analysis.

Arguments:

    Detector - Heap spray detector.
    ProcessId - Process that made the allocation.
    Address - Base address of allocation.
    Size - Size of allocation.
    Protection - Page protection flags.
    ReturnAddress - Optional return address of caller.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PHS_DETECTOR_INTERNAL detectorInternal;
    PHS_PROCESS_CONTEXT context;
    PHS_ALLOCATION_RECORD record = NULL;
    LARGE_INTEGER currentTime;
    ULONG bucketIndex;
    KIRQL oldIrql;
    ULONG sprayScore;
    BOOLEAN sprayDetected = FALSE;
    HS_SPRAY_RESULT sprayResult;

    if (Detector == NULL || !Detector->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Address == NULL || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    detectorInternal = CONTAINING_RECORD(Detector, HS_DETECTOR_INTERNAL, Detector);

    if (detectorInternal->ShuttingDown) {
        return STATUS_SHUTDOWN_IN_PROGRESS;
    }

    //
    // Find or create process context
    //
    context = HspFindProcessContext(Detector, ProcessId, TRUE);
    if (context == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeQuerySystemTimePrecise(&currentTime);

    //
    // Prune old allocations outside the window
    //
    HspPruneOldAllocations(context, &currentTime, Detector);

    //
    // Check if we've exceeded tracking limits
    //
    if ((ULONG)context->AllocationCount >= HS_MAX_TRACKED_ALLOCATIONS) {
        HspDereferenceProcessContext(detectorInternal, context);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Allocate a record from the pool
    //
    record = HspAllocateRecord(Detector);
    if (record == NULL) {
        HspDereferenceProcessContext(detectorInternal, context);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Fill in record details
    //
    record->Address = Address;
    record->Size = Size;
    record->Protection = Protection;
    record->Timestamp = currentTime;
    record->ReturnAddress = ReturnAddress;
    record->ThreadId = PsGetCurrentThreadId();

    //
    // Sample pattern from memory if accessible
    //
    RtlZeroMemory(record->PatternSample, HS_PATTERN_SAMPLE_SIZE);

    __try {
        SIZE_T sampleSize = min(Size, HS_PATTERN_SAMPLE_SIZE);

        if (MmIsAddressValid(Address)) {
            RtlCopyMemory(record->PatternSample, Address, sampleSize);
            record->PatternHash = HspCalculatePatternHash(record->PatternSample, (ULONG)sampleSize);
            record->RepetitionScore = HspCalculateRepetitionScore(record->PatternSample, (ULONG)sampleSize);
        } else {
            record->PatternHash = 0;
            record->RepetitionScore = 0;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        record->PatternHash = 0;
        record->RepetitionScore = 0;
    }

    //
    // Add to allocation list
    //
    KeAcquireSpinLock(&context->AllocationLock, &oldIrql);

    InsertTailList(&context->AllocationList, &record->ListEntry);
    InterlockedIncrement(&context->AllocationCount);
    context->TotalAllocatedSize += Size;
    context->AllocationsInWindow++;

    //
    // Add to pattern hash bucket
    //
    bucketIndex = record->PatternHash % HS_PATTERN_HASH_BUCKETS;
    InsertTailList(&context->PatternBuckets[bucketIndex], &record->HashEntry);

    KeReleaseSpinLock(&context->AllocationLock, oldIrql);

    //
    // Update statistics
    //
    InterlockedIncrement64(&Detector->Stats.TotalAllocationsTracked);

    //
    // Calculate spray score
    //
    sprayScore = HspCalculateSprayScore(context, record);
    context->SprayScore = sprayScore;

    //
    // Check if spray threshold exceeded
    //
    if (sprayScore >= HS_MIN_SCORE_FOR_SPRAY &&
        context->TotalAllocatedSize >= Detector->Config.MinSpraySizeBytes &&
        (ULONG)context->AllocationCount >= Detector->Config.MinAllocationCount) {

        sprayDetected = TRUE;
        context->SprayInProgress = TRUE;
        context->SuspectedType = HspDetectSprayType(
            context,
            record->PatternSample,
            HS_PATTERN_SAMPLE_SIZE
            );

        InterlockedIncrement64(&Detector->Stats.SpraysDetected);
    }

    //
    // If spray detected, build result and invoke callbacks
    //
    if (sprayDetected) {
        RtlZeroMemory(&sprayResult, sizeof(sprayResult));

        sprayResult.SprayDetected = TRUE;
        sprayResult.Type = context->SuspectedType;
        sprayResult.ConfidenceScore = min(sprayScore, 1000);
        sprayResult.ProcessId = ProcessId;
        sprayResult.AllocationCount = (ULONG)context->AllocationCount;
        sprayResult.TotalSize = context->TotalAllocatedSize;
        sprayResult.AverageSize = context->TotalAllocatedSize / max((ULONG)context->AllocationCount, 1);

        //
        // Set detection flags
        //
        if (context->AllocationsInWindow > HS_HIGH_ALLOC_RATE_THRESHOLD) {
            sprayResult.Flags |= HsFlag_HighAllocationRate;
        }
        if (record->RepetitionScore > HS_REPETITION_THRESHOLD) {
            sprayResult.Flags |= HsFlag_RepeatedPattern;
        }
        if (Protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                          PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
            sprayResult.Flags |= HsFlag_ExecutableAlloc;
        }
        if (((ULONG_PTR)Address & 0xFFFF) == 0) {
            sprayResult.Flags |= HsFlag_AlignedAddresses;
        }
        if (HspContainsShellcodeSignatures(record->PatternSample, HS_PATTERN_SAMPLE_SIZE)) {
            sprayResult.Flags |= HsFlag_ShellcodePattern;
        }

        //
        // Copy dominant pattern
        //
        RtlCopyMemory(
            sprayResult.DominantPattern,
            record->PatternSample,
            min(64, HS_PATTERN_SAMPLE_SIZE)
            );
        sprayResult.DominantPatternSize = min(64, HS_PATTERN_SAMPLE_SIZE);

        //
        // Timing information
        //
        sprayResult.FirstAllocation = context->WindowStartTime;
        sprayResult.LastAllocation = currentTime;
        sprayResult.DurationMs = (ULONG)((currentTime.QuadPart -
                                          context->WindowStartTime.QuadPart) / 10000);

        //
        // Invoke callbacks
        //
        HspInvokeCallbacks(detectorInternal, &sprayResult);
    }

    HspDereferenceProcessContext(detectorInternal, context);

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
HsRecordDeallocation(
    _In_ PHS_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ PVOID Address
    )
/*++

Routine Description:

    Records a heap deallocation.

Arguments:

    Detector - Heap spray detector.
    ProcessId - Process that freed the allocation.
    Address - Address being freed.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PHS_DETECTOR_INTERNAL detectorInternal;
    PHS_PROCESS_CONTEXT context;
    PHS_ALLOCATION_RECORD record = NULL;
    PLIST_ENTRY entry;
    KIRQL oldIrql;
    BOOLEAN found = FALSE;

    if (Detector == NULL || !Detector->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Address == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    detectorInternal = CONTAINING_RECORD(Detector, HS_DETECTOR_INTERNAL, Detector);

    if (detectorInternal->ShuttingDown) {
        return STATUS_SHUTDOWN_IN_PROGRESS;
    }

    //
    // Find process context
    //
    context = HspFindProcessContext(Detector, ProcessId, FALSE);
    if (context == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Find and remove the allocation record
    //
    KeAcquireSpinLock(&context->AllocationLock, &oldIrql);

    for (entry = context->AllocationList.Flink;
         entry != &context->AllocationList;
         entry = entry->Flink) {

        record = CONTAINING_RECORD(entry, HS_ALLOCATION_RECORD, ListEntry);

        if (record->Address == Address) {
            RemoveEntryList(&record->ListEntry);
            RemoveEntryList(&record->HashEntry);
            InterlockedDecrement(&context->AllocationCount);
            context->TotalAllocatedSize -= record->Size;
            found = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&context->AllocationLock, oldIrql);

    if (found && record != NULL) {
        HspFreeRecord(Detector, record);
    }

    HspDereferenceProcessContext(detectorInternal, context);

    return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}


//=============================================================================
// Detection
//=============================================================================

_Use_decl_annotations_
NTSTATUS
HsAnalyzeProcess(
    _In_ PHS_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_ PHS_SPRAY_RESULT* Result
    )
/*++

Routine Description:

    Performs comprehensive heap spray analysis for a process.

Arguments:

    Detector - Heap spray detector.
    ProcessId - Process to analyze.
    Result - Receives analysis result (must be freed with HsFreeResult).

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PHS_DETECTOR_INTERNAL detectorInternal;
    PHS_PROCESS_CONTEXT context;
    PHS_SPRAY_RESULT result = NULL;
    PHS_ALLOCATION_RECORD record;
    PLIST_ENTRY entry;
    KIRQL oldIrql;
    LARGE_INTEGER currentTime;
    ULONG patternCounts[HS_PATTERN_HASH_BUCKETS] = {0};
    ULONG maxPatternCount = 0;
    ULONG maxPatternBucket = 0;
    ULONG totalScore = 0;
    ULONG alignedCount = 0;
    PVOID lowestAddr = (PVOID)MAXULONG_PTR;
    PVOID highestAddr = NULL;
    SIZE_T totalSize = 0;
    ULONG allocCount = 0;

    if (Detector == NULL || !Detector->Initialized || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Result = NULL;

    detectorInternal = CONTAINING_RECORD(Detector, HS_DETECTOR_INTERNAL, Detector);

    //
    // Find process context
    //
    context = HspFindProcessContext(Detector, ProcessId, FALSE);
    if (context == NULL) {
        return STATUS_NOT_FOUND;
    }

    KeQuerySystemTimePrecise(&currentTime);

    //
    // Allocate result structure
    //
    result = (PHS_SPRAY_RESULT)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(HS_SPRAY_RESULT),
        HS_POOL_TAG_CONTEXT
        );

    if (result == NULL) {
        HspDereferenceProcessContext(detectorInternal, context);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(result, sizeof(HS_SPRAY_RESULT));

    result->ProcessId = ProcessId;

    //
    // Analyze all allocations
    //
    KeAcquireSpinLock(&context->AllocationLock, &oldIrql);

    for (entry = context->AllocationList.Flink;
         entry != &context->AllocationList;
         entry = entry->Flink) {

        record = CONTAINING_RECORD(entry, HS_ALLOCATION_RECORD, ListEntry);
        allocCount++;

        //
        // Track pattern frequency
        //
        ULONG bucket = record->PatternHash % HS_PATTERN_HASH_BUCKETS;
        patternCounts[bucket]++;
        if (patternCounts[bucket] > maxPatternCount) {
            maxPatternCount = patternCounts[bucket];
            maxPatternBucket = bucket;
        }

        //
        // Track address range
        //
        if ((ULONG_PTR)record->Address < (ULONG_PTR)lowestAddr) {
            lowestAddr = record->Address;
        }
        if ((ULONG_PTR)record->Address > (ULONG_PTR)highestAddr) {
            highestAddr = record->Address;
        }

        //
        // Count aligned allocations
        //
        if (((ULONG_PTR)record->Address & 0xFFFF) == 0) {
            alignedCount++;
        }

        totalSize += record->Size;
        totalScore += record->RepetitionScore;
    }

    result->AllocationCount = allocCount;
    result->TotalSize = totalSize;
    result->AverageSize = (allocCount > 0) ? totalSize / allocCount : 0;
    result->LowestAddress = lowestAddr;
    result->HighestAddress = highestAddr;
    result->AddressSpan = (SIZE_T)((ULONG_PTR)highestAddr - (ULONG_PTR)lowestAddr);
    result->AlignedCount = alignedCount;
    result->PatternRepetitions = maxPatternCount;

    //
    // Count unique patterns (buckets with > 0 entries)
    //
    for (ULONG i = 0; i < HS_PATTERN_HASH_BUCKETS; i++) {
        if (patternCounts[i] > 0) {
            result->UniquePatterns++;
        }
    }

    //
    // Get dominant pattern from first matching allocation
    //
    if (maxPatternCount > 0) {
        for (entry = context->AllocationList.Flink;
             entry != &context->AllocationList;
             entry = entry->Flink) {

            record = CONTAINING_RECORD(entry, HS_ALLOCATION_RECORD, ListEntry);
            if ((record->PatternHash % HS_PATTERN_HASH_BUCKETS) == maxPatternBucket) {
                RtlCopyMemory(result->DominantPattern, record->PatternSample, 64);
                result->DominantPatternSize = 64;
                break;
            }
        }
    }

    KeReleaseSpinLock(&context->AllocationLock, oldIrql);

    //
    // Calculate confidence score
    //
    ULONG confidenceScore = 0;

    //
    // High pattern repetition
    //
    if (maxPatternCount > 10 && allocCount > 0) {
        confidenceScore += (maxPatternCount * 100) / allocCount;
    }

    //
    // High allocation count
    //
    if (allocCount > HS_MIN_SIMILAR_ALLOCATIONS) {
        confidenceScore += 200;
    }

    //
    // Large total size
    //
    if (totalSize > HS_MIN_SPRAY_SIZE) {
        confidenceScore += 200;
    }

    //
    // Many aligned allocations
    //
    if (allocCount > 0 && (alignedCount * 100 / allocCount) > 50) {
        confidenceScore += 150;
    }

    //
    // Low pattern diversity
    //
    if (allocCount > 10 && result->UniquePatterns < 5) {
        confidenceScore += 200;
    }

    //
    // High repetition scores
    //
    if (allocCount > 0) {
        ULONG avgRepetition = totalScore / allocCount;
        if (avgRepetition > HS_REPETITION_THRESHOLD) {
            confidenceScore += 150;
        }
    }

    result->ConfidenceScore = min(confidenceScore, 1000);
    result->SprayDetected = (confidenceScore >= HS_MIN_SCORE_FOR_SPRAY);
    result->Type = context->SuspectedType;

    //
    // Set flags
    //
    if (context->AllocationsInWindow > HS_HIGH_ALLOC_RATE_THRESHOLD) {
        result->Flags |= HsFlag_HighAllocationRate;
    }
    if (maxPatternCount > allocCount / 2) {
        result->Flags |= HsFlag_RepeatedPattern;
    }
    if (alignedCount > allocCount / 2) {
        result->Flags |= HsFlag_AlignedAddresses;
    }
    if (totalSize > 10 * 1024 * 1024) {
        result->Flags |= HsFlag_LargeContiguous;
    }

    //
    // Timing
    //
    result->FirstAllocation = context->WindowStartTime;
    result->LastAllocation = currentTime;
    result->DurationMs = (ULONG)((currentTime.QuadPart -
                                  context->WindowStartTime.QuadPart) / 10000);

    //
    // Calculate allocations per second
    //
    if (result->DurationMs > 0) {
        result->AllocationsPerSecond = (allocCount * 1000) / result->DurationMs;
    }

    HspDereferenceProcessContext(detectorInternal, context);

    *Result = result;

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
HsCheckForSpray(
    _In_ PHS_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_ PBOOLEAN SprayDetected,
    _Out_opt_ PHS_SPRAY_TYPE Type,
    _Out_opt_ PULONG Score
    )
/*++

Routine Description:

    Quick check for heap spray without full analysis.

Arguments:

    Detector - Heap spray detector.
    ProcessId - Process to check.
    SprayDetected - Receives TRUE if spray detected.
    Type - Optional; receives spray type if detected.
    Score - Optional; receives confidence score.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PHS_DETECTOR_INTERNAL detectorInternal;
    PHS_PROCESS_CONTEXT context;

    if (Detector == NULL || !Detector->Initialized || SprayDetected == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *SprayDetected = FALSE;
    if (Type != NULL) *Type = HsSprayType_Unknown;
    if (Score != NULL) *Score = 0;

    detectorInternal = CONTAINING_RECORD(Detector, HS_DETECTOR_INTERNAL, Detector);

    //
    // Find process context
    //
    context = HspFindProcessContext(Detector, ProcessId, FALSE);
    if (context == NULL) {
        return STATUS_NOT_FOUND;
    }

    *SprayDetected = context->SprayInProgress;

    if (context->SprayInProgress) {
        if (Type != NULL) {
            *Type = context->SuspectedType;
        }
        if (Score != NULL) {
            *Score = context->SprayScore;
        }
    }

    HspDereferenceProcessContext(detectorInternal, context);

    return STATUS_SUCCESS;
}


//=============================================================================
// Callbacks
//=============================================================================

_Use_decl_annotations_
NTSTATUS
HsRegisterCallback(
    _In_ PHS_DETECTOR Detector,
    _In_ HS_SPRAY_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
{
    PHS_DETECTOR_INTERNAL detectorInternal;
    ULONG i;
    BOOLEAN registered = FALSE;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    detectorInternal = CONTAINING_RECORD(Detector, HS_DETECTOR_INTERNAL, Detector);

    FltAcquirePushLockExclusive(&detectorInternal->CallbackLock);

    for (i = 0; i < HS_MAX_CALLBACKS; i++) {
        if (!detectorInternal->Callbacks[i].Active) {
            detectorInternal->Callbacks[i].Callback = Callback;
            detectorInternal->Callbacks[i].Context = Context;
            detectorInternal->Callbacks[i].Active = TRUE;
            InterlockedIncrement(&detectorInternal->CallbackCount);
            registered = TRUE;
            break;
        }
    }

    FltReleasePushLock(&detectorInternal->CallbackLock);

    return registered ? STATUS_SUCCESS : STATUS_QUOTA_EXCEEDED;
}


_Use_decl_annotations_
VOID
HsUnregisterCallback(
    _In_ PHS_DETECTOR Detector,
    _In_ HS_SPRAY_CALLBACK Callback
    )
{
    PHS_DETECTOR_INTERNAL detectorInternal;
    ULONG i;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized || Callback == NULL) {
        return;
    }

    detectorInternal = CONTAINING_RECORD(Detector, HS_DETECTOR_INTERNAL, Detector);

    FltAcquirePushLockExclusive(&detectorInternal->CallbackLock);

    for (i = 0; i < HS_MAX_CALLBACKS; i++) {
        if (detectorInternal->Callbacks[i].Active &&
            detectorInternal->Callbacks[i].Callback == Callback) {
            detectorInternal->Callbacks[i].Active = FALSE;
            detectorInternal->Callbacks[i].Callback = NULL;
            detectorInternal->Callbacks[i].Context = NULL;
            InterlockedDecrement(&detectorInternal->CallbackCount);
            break;
        }
    }

    FltReleasePushLock(&detectorInternal->CallbackLock);
}


//=============================================================================
// Results
//=============================================================================

_Use_decl_annotations_
VOID
HsFreeResult(
    _In_ PHS_SPRAY_RESULT Result
    )
{
    if (Result != NULL) {
        ShadowStrikeFreePoolWithTag(Result, HS_POOL_TAG_CONTEXT);
    }
}


//=============================================================================
// Statistics
//=============================================================================

_Use_decl_annotations_
NTSTATUS
HsGetStatistics(
    _In_ PHS_DETECTOR Detector,
    _Out_ PHS_STATISTICS Stats
    )
{
    LARGE_INTEGER currentTime;

    if (Detector == NULL || !Detector->Initialized || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Stats, sizeof(HS_STATISTICS));

    Stats->TrackedProcesses = (ULONG)Detector->ProcessCount;
    Stats->TotalAllocations = Detector->Stats.TotalAllocationsTracked;
    Stats->SpraysDetected = Detector->Stats.SpraysDetected;

    KeQuerySystemTimePrecise(&currentTime);
    Stats->UpTime.QuadPart = currentTime.QuadPart - Detector->Stats.StartTime.QuadPart;

    return STATUS_SUCCESS;
}


//=============================================================================
// Internal Functions
//=============================================================================

static
_Use_decl_annotations_
PHS_PROCESS_CONTEXT
HspFindProcessContext(
    _In_ PHS_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN CreateIfNotFound
    )
/*++

Routine Description:

    Finds or creates a process context.

--*/
{
    PHS_DETECTOR_INTERNAL detectorInternal;
    PHS_PROCESS_CONTEXT context = NULL;
    PLIST_ENTRY entry;
    ULONG i;

    detectorInternal = CONTAINING_RECORD(Detector, HS_DETECTOR_INTERNAL, Detector);

    //
    // Search existing contexts
    //
    FltAcquirePushLockShared(&Detector->ProcessListLock);

    for (entry = Detector->ProcessList.Flink;
         entry != &Detector->ProcessList;
         entry = entry->Flink) {

        context = CONTAINING_RECORD(entry, HS_PROCESS_CONTEXT, ListEntry);

        if (context->ProcessId == ProcessId) {
            HspReferenceProcessContext(context);
            FltReleasePushLock(&Detector->ProcessListLock);
            return context;
        }
    }

    FltReleasePushLock(&Detector->ProcessListLock);

    //
    // Not found, create if requested
    //
    if (!CreateIfNotFound) {
        return NULL;
    }

    //
    // Allocate new context
    //
    context = (PHS_PROCESS_CONTEXT)ExAllocateFromNPagedLookasideList(
        &detectorInternal->ProcessContextLookaside
        );

    if (context == NULL) {
        return NULL;
    }

    RtlZeroMemory(context, sizeof(HS_PROCESS_CONTEXT));

    context->ProcessId = ProcessId;
    context->Process = NULL;  // Could be obtained if needed

    //
    // Try to get EPROCESS
    //
    PsLookupProcessByProcessId(ProcessId, &context->Process);

    //
    // Initialize allocation list
    //
    InitializeListHead(&context->AllocationList);
    KeInitializeSpinLock(&context->AllocationLock);
    context->AllocationCount = 0;

    //
    // Initialize pattern hash buckets
    //
    for (i = 0; i < HS_PATTERN_HASH_BUCKETS; i++) {
        InitializeListHead(&context->PatternBuckets[i]);
    }
    context->UniquePatterns = 0;

    //
    // Initialize metrics
    //
    context->TotalAllocatedSize = 0;
    context->AllocationsInWindow = 0;
    KeQuerySystemTimePrecise(&context->WindowStartTime);

    //
    // Initialize spray state
    //
    context->SprayInProgress = FALSE;
    context->SuspectedType = HsSprayType_Unknown;
    context->SprayScore = 0;

    //
    // Reference count: 1 for creation, will increment for caller
    //
    context->RefCount = 2;

    //
    // Add to list
    //
    FltAcquirePushLockExclusive(&Detector->ProcessListLock);
    InsertTailList(&Detector->ProcessList, &context->ListEntry);
    InterlockedIncrement(&Detector->ProcessCount);
    InterlockedIncrement64(&Detector->Stats.ProcessesMonitored);
    FltReleasePushLock(&Detector->ProcessListLock);

    return context;
}


static
_Use_decl_annotations_
VOID
HspReferenceProcessContext(
    _Inout_ PHS_PROCESS_CONTEXT Context
    )
{
    InterlockedIncrement(&Context->RefCount);
}


static
_Use_decl_annotations_
VOID
HspDereferenceProcessContext(
    _In_ PHS_DETECTOR_INTERNAL* DetectorInternal,
    _Inout_ PHS_PROCESS_CONTEXT Context
    )
{
    LONG newCount;

    newCount = InterlockedDecrement(&Context->RefCount);

    if (newCount == 0) {
        HspDestroyProcessContext(DetectorInternal, Context);
    }
}


static
_Use_decl_annotations_
VOID
HspDestroyProcessContext(
    _In_ PHS_DETECTOR_INTERNAL* DetectorInternal,
    _Inout_ PHS_PROCESS_CONTEXT Context
    )
/*++

Routine Description:

    Destroys a process context and frees all associated allocations.

--*/
{
    PHS_ALLOCATION_RECORD record;
    PLIST_ENTRY entry;
    KIRQL oldIrql;
    LIST_ENTRY recordsToFree;

    InitializeListHead(&recordsToFree);

    //
    // Collect all allocation records
    //
    KeAcquireSpinLock(&Context->AllocationLock, &oldIrql);

    while (!IsListEmpty(&Context->AllocationList)) {
        entry = RemoveHeadList(&Context->AllocationList);
        InsertTailList(&recordsToFree, entry);
    }

    Context->AllocationCount = 0;

    KeReleaseSpinLock(&Context->AllocationLock, oldIrql);

    //
    // Free all records
    //
    while (!IsListEmpty(&recordsToFree)) {
        entry = RemoveHeadList(&recordsToFree);
        record = CONTAINING_RECORD(entry, HS_ALLOCATION_RECORD, ListEntry);
        HspFreeRecord(&DetectorInternal->Detector, record);
    }

    //
    // Dereference EPROCESS if we have one
    //
    if (Context->Process != NULL) {
        ObDereferenceObject(Context->Process);
        Context->Process = NULL;
    }

    //
    // Return to lookaside list
    //
    ExFreeToNPagedLookasideList(&DetectorInternal->ProcessContextLookaside, Context);
}


static
_Use_decl_annotations_
PHS_ALLOCATION_RECORD
HspAllocateRecord(
    _In_ PHS_DETECTOR Detector
    )
{
    PHS_ALLOCATION_RECORD record = NULL;
    PLIST_ENTRY entry;
    KIRQL oldIrql;

    KeAcquireSpinLock(&Detector->AllocationPool.Lock, &oldIrql);

    if (!IsListEmpty(&Detector->AllocationPool.FreeList)) {
        entry = RemoveHeadList(&Detector->AllocationPool.FreeList);
        record = CONTAINING_RECORD(entry, HS_ALLOCATION_RECORD, ListEntry);
        InterlockedDecrement(&Detector->AllocationPool.FreeCount);
    }

    KeReleaseSpinLock(&Detector->AllocationPool.Lock, oldIrql);

    if (record != NULL) {
        RtlZeroMemory(record, sizeof(HS_ALLOCATION_RECORD));
        InitializeListHead(&record->ListEntry);
        InitializeListHead(&record->HashEntry);
    }

    return record;
}


static
_Use_decl_annotations_
VOID
HspFreeRecord(
    _In_ PHS_DETECTOR Detector,
    _Inout_ PHS_ALLOCATION_RECORD Record
    )
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&Detector->AllocationPool.Lock, &oldIrql);

    InsertTailList(&Detector->AllocationPool.FreeList, &Record->ListEntry);
    InterlockedIncrement(&Detector->AllocationPool.FreeCount);

    KeReleaseSpinLock(&Detector->AllocationPool.Lock, oldIrql);
}


static
_Use_decl_annotations_
ULONG
HspCalculatePatternHash(
    _In_reads_bytes_(Size) PUCHAR Data,
    _In_ ULONG Size
    )
/*++

Routine Description:

    Calculates FNV-1a hash of pattern data.

--*/
{
    ULONG hash = HS_FNV_OFFSET_BASIS;
    ULONG i;

    for (i = 0; i < Size; i++) {
        hash ^= Data[i];
        hash *= HS_FNV_PRIME;
    }

    return hash;
}


static
_Use_decl_annotations_
ULONG
HspCalculateRepetitionScore(
    _In_reads_bytes_(Size) PUCHAR Data,
    _In_ ULONG Size
    )
/*++

Routine Description:

    Calculates a repetition score (0-100) indicating how repetitive the data is.
    Higher scores indicate more repetition (suspicious for heap spray).

--*/
{
    ULONG byteCounts[256] = {0};
    ULONG maxCount = 0;
    ULONG runLength = 0;
    ULONG maxRunLength = 0;
    UCHAR lastByte = 0;
    ULONG i;
    ULONG score = 0;
    ULONG uniqueBytes = 0;

    if (Size == 0) {
        return 0;
    }

    //
    // Count byte frequencies and track runs
    //
    for (i = 0; i < Size; i++) {
        byteCounts[Data[i]]++;

        if (i == 0 || Data[i] == lastByte) {
            runLength++;
        } else {
            if (runLength > maxRunLength) {
                maxRunLength = runLength;
            }
            runLength = 1;
        }
        lastByte = Data[i];
    }

    if (runLength > maxRunLength) {
        maxRunLength = runLength;
    }

    //
    // Find max frequency and count unique bytes
    //
    for (i = 0; i < 256; i++) {
        if (byteCounts[i] > maxCount) {
            maxCount = byteCounts[i];
        }
        if (byteCounts[i] > 0) {
            uniqueBytes++;
        }
    }

    //
    // Score based on dominant byte frequency (0-40 points)
    //
    score += (maxCount * 40) / Size;

    //
    // Score based on max run length (0-30 points)
    //
    score += (maxRunLength * 30) / Size;

    //
    // Score based on low byte diversity (0-30 points)
    // Fewer unique bytes = higher score
    //
    if (uniqueBytes < 16) {
        score += 30 - (uniqueBytes * 2);
    }

    return min(score, 100);
}


static
_Use_decl_annotations_
HS_SPRAY_TYPE
HspDetectSprayType(
    _In_ PHS_PROCESS_CONTEXT Context,
    _In_ PUCHAR PatternSample,
    _In_ ULONG SampleSize
    )
/*++

Routine Description:

    Determines the type of heap spray based on pattern analysis.

--*/
{
    ULONG i;
    ULONG nopCount = 0;
    ULONG slide0CCount = 0;
    ULONG slide0DCount = 0;
    BOOLEAN hasJitPattern = FALSE;

    UNREFERENCED_PARAMETER(Context);

    if (SampleSize < 4) {
        return HsSprayType_Unknown;
    }

    //
    // Count various patterns
    //
    for (i = 0; i < SampleSize; i++) {
        if (PatternSample[i] == HS_NOP_X86) {
            nopCount++;
        }
        if (PatternSample[i] == 0x0C) {
            slide0CCount++;
        }
        if (PatternSample[i] == 0x0D) {
            slide0DCount++;
        }
    }

    //
    // Check for DWORD patterns
    //
    for (i = 0; i < SampleSize - 3; i += 4) {
        ULONG dword = *(PULONG)&PatternSample[i];

        if ((dword & 0x00FFFFFF) == (HS_JIT_XOR_PATTERN & 0x00FFFFFF)) {
            hasJitPattern = TRUE;
        }
    }

    //
    // Classify spray type
    //
    if (nopCount > SampleSize * 80 / 100) {
        return HsSprayType_NopSled;
    }

    if (slide0CCount > SampleSize * 80 / 100 ||
        slide0DCount > SampleSize * 80 / 100) {
        return HsSprayType_NopSled;
    }

    if (hasJitPattern) {
        return HsSprayType_JitSpray;
    }

    //
    // Check for string-like patterns (printable ASCII)
    //
    ULONG printableCount = 0;
    for (i = 0; i < SampleSize; i++) {
        if (PatternSample[i] >= 0x20 && PatternSample[i] < 0x7F) {
            printableCount++;
        }
    }

    if (printableCount > SampleSize * 90 / 100) {
        return HsSprayType_StringSpray;
    }

    //
    // Check for BSTR-like patterns (length prefixed)
    //
    if (SampleSize >= 4) {
        ULONG potentialLength = *(PULONG)PatternSample;
        if (potentialLength > 0 && potentialLength < 0x10000) {
            return HsSprayType_StringSpray;
        }
    }

    //
    // Check for object spray (vtable-like patterns)
    //
    ULONG ptrCount = 0;
    for (i = 0; i < SampleSize - sizeof(PVOID) + 1; i += sizeof(PVOID)) {
        ULONG_PTR ptr = *(PULONG_PTR)&PatternSample[i];
        //
        // Check if it looks like a valid user-mode pointer
        //
        if (ptr > 0x10000 && ptr < 0x7FFFFFFFFFFF) {
            ptrCount++;
        }
    }

    if (ptrCount > (SampleSize / sizeof(PVOID)) * 80 / 100) {
        return HsSprayType_ObjectSpray;
    }

    return HsSprayType_Unknown;
}


static
_Use_decl_annotations_
ULONG
HspCalculateSprayScore(
    _In_ PHS_PROCESS_CONTEXT Context,
    _In_ PHS_ALLOCATION_RECORD Record
    )
/*++

Routine Description:

    Calculates spray detection score based on allocation characteristics.

--*/
{
    ULONG score = 0;
    LARGE_INTEGER windowDuration;
    ULONG allocsPerSecond;

    //
    // Base score from repetition
    //
    score += Record->RepetitionScore * 3;

    //
    // Score from allocation count
    //
    if (Context->AllocationCount > HS_MIN_SIMILAR_ALLOCATIONS) {
        score += 100 + min((Context->AllocationCount - HS_MIN_SIMILAR_ALLOCATIONS) * 2, 200);
    }

    //
    // Score from total size
    //
    if (Context->TotalAllocatedSize > HS_MIN_SPRAY_SIZE) {
        score += 100;
        score += min((ULONG)(Context->TotalAllocatedSize / (1024 * 1024)), 100);
    }

    //
    // Score from allocation rate
    //
    windowDuration.QuadPart = Record->Timestamp.QuadPart - Context->WindowStartTime.QuadPart;
    if (windowDuration.QuadPart > 0) {
        allocsPerSecond = (ULONG)(((LONG64)Context->AllocationsInWindow * 10000000LL) /
                                  windowDuration.QuadPart);
        if (allocsPerSecond > HS_HIGH_ALLOC_RATE_THRESHOLD) {
            score += 150;
        }
    }

    //
    // Score from known patterns
    //
    if (HspIsKnownSprayPattern(Record->PatternSample, HS_PATTERN_SAMPLE_SIZE)) {
        score += 200;
    }

    //
    // Score from NOP sled detection
    //
    if (HspContainsNopSled(Record->PatternSample, HS_PATTERN_SAMPLE_SIZE)) {
        score += 250;
    }

    //
    // Score from shellcode signatures
    //
    if (HspContainsShellcodeSignatures(Record->PatternSample, HS_PATTERN_SAMPLE_SIZE)) {
        score += 300;
    }

    //
    // Score from executable protection
    //
    if (Record->Protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                              PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
        score += 100;
    }

    //
    // Score from aligned address (common in heap spray)
    //
    if (((ULONG_PTR)Record->Address & 0xFFFF) == 0) {
        score += 50;
    }

    return min(score, 1000);
}


static
_Use_decl_annotations_
VOID
HspPruneOldAllocations(
    _Inout_ PHS_PROCESS_CONTEXT Context,
    _In_ PLARGE_INTEGER CurrentTime,
    _In_ PHS_DETECTOR Detector
    )
/*++

Routine Description:

    Removes allocation records outside the tracking window.

--*/
{
    PHS_ALLOCATION_RECORD record;
    PLIST_ENTRY entry;
    PLIST_ENTRY next;
    KIRQL oldIrql;
    LARGE_INTEGER windowStart;
    LIST_ENTRY recordsToFree;

    InitializeListHead(&recordsToFree);

    //
    // Calculate window start time
    //
    windowStart.QuadPart = CurrentTime->QuadPart -
                           ((LONGLONG)Detector->Config.AllocationWindowMs * 10000LL);

    KeAcquireSpinLock(&Context->AllocationLock, &oldIrql);

    //
    // Find and remove old allocations
    //
    for (entry = Context->AllocationList.Flink;
         entry != &Context->AllocationList;
         entry = next) {

        next = entry->Flink;
        record = CONTAINING_RECORD(entry, HS_ALLOCATION_RECORD, ListEntry);

        if (record->Timestamp.QuadPart < windowStart.QuadPart) {
            RemoveEntryList(&record->ListEntry);
            RemoveEntryList(&record->HashEntry);
            InterlockedDecrement(&Context->AllocationCount);
            Context->TotalAllocatedSize -= record->Size;
            InsertTailList(&recordsToFree, &record->ListEntry);
        }
    }

    //
    // Reset window if empty
    //
    if (IsListEmpty(&Context->AllocationList)) {
        Context->WindowStartTime = *CurrentTime;
        Context->AllocationsInWindow = 0;
        Context->SprayInProgress = FALSE;
        Context->SprayScore = 0;
    }

    KeReleaseSpinLock(&Context->AllocationLock, oldIrql);

    //
    // Free collected records
    //
    while (!IsListEmpty(&recordsToFree)) {
        entry = RemoveHeadList(&recordsToFree);
        record = CONTAINING_RECORD(entry, HS_ALLOCATION_RECORD, ListEntry);
        HspFreeRecord(Detector, record);
    }
}


static
_Use_decl_annotations_
VOID
HspInvokeCallbacks(
    _In_ PHS_DETECTOR_INTERNAL DetectorInternal,
    _In_ PHS_SPRAY_RESULT Result
    )
{
    ULONG i;

    FltAcquirePushLockShared(&DetectorInternal->CallbackLock);

    for (i = 0; i < HS_MAX_CALLBACKS; i++) {
        if (DetectorInternal->Callbacks[i].Active &&
            DetectorInternal->Callbacks[i].Callback != NULL) {

            DetectorInternal->Callbacks[i].Callback(
                Result,
                DetectorInternal->Callbacks[i].Context
                );
        }
    }

    FltReleasePushLock(&DetectorInternal->CallbackLock);
}


static
_Use_decl_annotations_
BOOLEAN
HspIsKnownSprayPattern(
    _In_reads_bytes_(Size) PUCHAR Data,
    _In_ ULONG Size
    )
/*++

Routine Description:

    Checks for known heap spray patterns.

--*/
{
    ULONG i;

    if (Size < 4) {
        return FALSE;
    }

    //
    // Check for repeated DWORD patterns
    //
    for (i = 0; i < Size - 3; i += 4) {
        ULONG dword = *(PULONG)&Data[i];

        if (dword == HS_NOP_SLIDE_12 ||
            dword == HS_NOP_SLIDE_0D ||
            dword == HS_NOP_SLIDE_0A ||
            dword == HS_HEAP_SPRAY_MAGIC_1 ||
            dword == HS_HEAP_SPRAY_MAGIC_2 ||
            dword == 0x90909090) {
            return TRUE;
        }
    }

    return FALSE;
}


static
_Use_decl_annotations_
BOOLEAN
HspContainsNopSled(
    _In_reads_bytes_(Size) PUCHAR Data,
    _In_ ULONG Size
    )
/*++

Routine Description:

    Detects NOP sled patterns commonly used in heap spray.

--*/
{
    ULONG consecutiveNops = 0;
    ULONG i;

    for (i = 0; i < Size; i++) {
        //
        // Common NOP equivalents: 0x90, 0x0C0C, 0x0D0D, etc.
        //
        if (Data[i] == 0x90 ||
            Data[i] == 0x0C ||
            Data[i] == 0x0D ||
            Data[i] == 0x0A) {
            consecutiveNops++;
        } else {
            consecutiveNops = 0;
        }

        //
        // 16+ consecutive NOPs is suspicious
        //
        if (consecutiveNops >= 16) {
            return TRUE;
        }
    }

    return FALSE;
}


static
_Use_decl_annotations_
BOOLEAN
HspContainsShellcodeSignatures(
    _In_reads_bytes_(Size) PUCHAR Data,
    _In_ ULONG Size
    )
/*++

Routine Description:

    Detects common shellcode signatures that may indicate heap spray payload.

--*/
{
    ULONG i;

    if (Size < 4) {
        return FALSE;
    }

    for (i = 0; i < Size - 3; i++) {
        //
        // Common shellcode patterns
        //

        //
        // GetPC via call $+5 / pop
        // E8 00 00 00 00 (call $+5)
        //
        if (i + 4 < Size &&
            Data[i] == 0xE8 &&
            Data[i+1] == 0x00 &&
            Data[i+2] == 0x00 &&
            Data[i+3] == 0x00 &&
            Data[i+4] == 0x00) {
            return TRUE;
        }

        //
        // JMP ESP (FF E4)
        //
        if (Data[i] == 0xFF && Data[i+1] == 0xE4) {
            return TRUE;
        }

        //
        // CALL ESP (FF D4)
        //
        if (Data[i] == 0xFF && Data[i+1] == 0xD4) {
            return TRUE;
        }

        //
        // PUSH ESP; RET (54 C3)
        //
        if (Data[i] == 0x54 && Data[i+1] == 0xC3) {
            return TRUE;
        }

        //
        // XOR decoder stub pattern (common in encoded shellcode)
        // XOR reg, reg followed by LODS/STOS pattern
        //
        if ((Data[i] >= 0x30 && Data[i] <= 0x33) &&  // XOR opcodes
            (Data[i+1] & 0xC0) == 0xC0) {            // ModR/M for reg,reg
            //
            // Look for loop instruction nearby
            //
            for (ULONG j = i + 2; j < min(i + 20, Size - 1); j++) {
                if (Data[j] == 0xE2 ||      // LOOP
                    Data[j] == 0xEB ||      // JMP short
                    Data[j] == 0x75 ||      // JNZ short
                    Data[j] == 0x74) {      // JZ short
                    return TRUE;
                }
            }
        }

        //
        // FS:[0x30] access (PEB access common in shellcode)
        // 64 A1 30 00 00 00 (MOV EAX, FS:[0x30])
        //
        if (i + 5 < Size &&
            Data[i] == 0x64 &&
            Data[i+1] == 0xA1 &&
            Data[i+2] == 0x30 &&
            Data[i+3] == 0x00 &&
            Data[i+4] == 0x00 &&
            Data[i+5] == 0x00) {
            return TRUE;
        }

        //
        // GS:[0x60] access (64-bit PEB access)
        // 65 48 8B 04 25 60 00 00 00
        //
        if (i + 8 < Size &&
            Data[i] == 0x65 &&
            Data[i+1] == 0x48 &&
            Data[i+2] == 0x8B &&
            Data[i+3] == 0x04 &&
            Data[i+4] == 0x25 &&
            Data[i+5] == 0x60) {
            return TRUE;
        }
    }

    return FALSE;
}

