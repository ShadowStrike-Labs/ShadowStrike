/*++
    ShadowStrike Next-Generation Antivirus
    Module: BatchProcessing.c - Event batch processing engine

    Purpose: Implements high-throughput event batching with a DISPATCH_LEVEL-safe
             hot path (BpQueueEvent) and PASSIVE_LEVEL processing thread.

    Synchronization Strategy:
    - KSPIN_LOCK for BatchLock and QueueLock: minimal hold time, DISPATCH-safe.
    - EX_RUNDOWN_REF on all public APIs to prevent teardown during in-flight ops.
    - Processing thread holds its own rundown ref while alive.
    - InterlockedExchange for Running/Initialized flags.

    Safety Guarantees:
    - No paged code acquires spin locks (BpFlush is NOT in PAGE section).
    - BpStop flushes the current batch before stopping the thread.
    - BpStart atomically sets Running BEFORE the thread starts processing.
    - Thread holds rundown protection for its entire lifetime.
    - Queue depth limit uses InterlockedCompareExchange to be race-free.
    - CurrentBatch NULL recovery in BpQueueEvent.

    Copyright (c) ShadowStrike Team
--*/

#include "BatchProcessing.h"

// ============================================================================
// CONSTANTS
// ============================================================================

#define BP_LOOKASIDE_DEPTH 16

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

//
// Batch: holds an array of event pointers. Allocated from lookaside list.
// The Events array is BP_MAX_BATCH_SIZE entries. BP_MAX_BATCH_SIZE=1000
// gives 1000 * sizeof(PBP_EVENT) = 8000 bytes. Batches must NEVER be
// stack-allocated — always from pool/lookaside.
//
typedef struct _BP_BATCH {
    LIST_ENTRY ListEntry;
    LARGE_INTEGER OldestEventTime;
    ULONG EventCount;
    PBP_EVENT Events[BP_MAX_BATCH_SIZE];
} BP_BATCH, *PBP_BATCH;

//
// Full internal processor state. Opaque to consumers.
//
struct _BP_PROCESSOR {
    //
    // Lifecycle
    //
    volatile LONG Initialized;
    volatile LONG Running;
    EX_RUNDOWN_REF RundownRef;

    //
    // Configuration (written only at PASSIVE with Interlocked, read at any IRQL)
    //
    volatile LONG MaxBatchSize;
    volatile LONG MaxBatchAgeMs;

    //
    // Current active batch (written under BatchLock)
    //
    KSPIN_LOCK BatchLock;
    PBP_BATCH CurrentBatch;
    PBP_BATCH SpareBatch;

    //
    // Ready queue of full/aged batches (written under QueueLock)
    //
    KSPIN_LOCK QueueLock;
    LIST_ENTRY ReadyQueue;
    volatile LONG QueuedBatches;

    //
    // Processing thread
    //
    PETHREAD ProcessingThread;
    KEVENT StopEvent;
    KEVENT NewBatchEvent;

    //
    // Age timer fires DPC → moves aged batch to ready queue
    //
    KTIMER AgeTimer;
    KDPC AgeDpc;
    volatile LONG AgeTimerArmed;

    //
    // Callback
    //
    BP_BATCH_CALLBACK BatchCallback;
    PVOID CallbackContext;

    //
    // Lookaside for batches
    //
    NPAGED_LOOKASIDE_LIST BatchLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Statistics (Interlocked updates only)
    //
    struct {
        volatile LONG64 EventsQueued;
        volatile LONG64 BatchesProcessed;
        volatile LONG64 EventsProcessed;
        volatile LONG64 EventsDropped;
        LARGE_INTEGER StartTime;
    } Stats;
};

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static PBP_BATCH
BppAllocateBatch(
    _In_ PBP_PROCESSOR Processor
    );

static VOID
BppFreeBatch(
    _In_ PBP_PROCESSOR Processor,
    _In_ PBP_BATCH Batch,
    _In_ BOOLEAN FreeEvents
    );

__declspec(noinline)
static VOID
BppMoveBatchToReadyQueue(
    _In_ PBP_PROCESSOR Processor,
    _In_ PBP_BATCH Batch
    );

__declspec(noinline)
static VOID
BppDrainReadyQueue(
    _In_ PBP_PROCESSOR Processor,
    _In_ BOOLEAN InvokeCallback
    );

static VOID NTAPI
BppProcessingThread(
    _In_ PVOID StartContext
    );

static VOID
BppArmAgeTimer(
    _In_ PBP_PROCESSOR Processor
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
BppAgeDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

//
// Internal flush helper — NOT paged. Moves current batch to ready queue
// under spin lock. Can be called at any IRQL <= DISPATCH_LEVEL.
//
//
// __declspec(noinline) prevents the compiler from inlining this into
// PAGE-sectioned callers, which would place spin lock code in pageable
// memory and cause IRQL_NOT_LESS_OR_EQUAL BSOD.
//
__declspec(noinline)
static PBP_BATCH
BppRotateCurrentBatch(
    _In_ PBP_PROCESSOR Processor
    );

// ============================================================================
// PAGE SECTION — Only PASSIVE_LEVEL functions that do NOT acquire spin locks
// OR functions where spin lock acquisition is safe because they are always
// called at PASSIVE (BpFlush is intentionally NOT here).
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, BpInitialize)
#pragma alloc_text(PAGE, BpShutdown)
#pragma alloc_text(PAGE, BpSetBatchParameters)
#pragma alloc_text(PAGE, BpRegisterCallback)
#pragma alloc_text(PAGE, BpStart)
#pragma alloc_text(PAGE, BpStop)
#pragma alloc_text(PAGE, BpGetStatistics)
//
// NOTE: BpFlush is NOT in PAGE section because it acquires spin locks.
// If the code were paged out and a page fault occurred at DISPATCH_LEVEL,
// that would be IRQL_NOT_LESS_OR_EQUAL BSOD.
//
#endif

// ============================================================================
// INITIALIZATION / SHUTDOWN
// ============================================================================

_Use_decl_annotations_
NTSTATUS
BpInitialize(
    _Out_ PBP_PROCESSOR* Processor
    )
{
    PBP_PROCESSOR proc = NULL;

    PAGED_CODE();

    if (Processor == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Processor = NULL;

    proc = (PBP_PROCESSOR)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(BP_PROCESSOR),
        BP_POOL_TAG
    );

    if (proc == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ExInitializeRundownProtection(&proc->RundownRef);
    KeInitializeSpinLock(&proc->BatchLock);
    KeInitializeSpinLock(&proc->QueueLock);
    InitializeListHead(&proc->ReadyQueue);
    KeInitializeEvent(&proc->NewBatchEvent, SynchronizationEvent, FALSE);
    KeInitializeEvent(&proc->StopEvent, NotificationEvent, FALSE);

    ExInitializeNPagedLookasideList(
        &proc->BatchLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(BP_BATCH),
        BP_POOL_TAG_BATCH,
        BP_LOOKASIDE_DEPTH
    );
    proc->LookasideInitialized = TRUE;

    proc->MaxBatchSize = (LONG)BP_DEFAULT_BATCH_SIZE;
    proc->MaxBatchAgeMs = (LONG)BP_DEFAULT_MAX_AGE_MS;

    //
    // Allocate initial current batch and spare batch
    //
    proc->CurrentBatch = BppAllocateBatch(proc);
    if (proc->CurrentBatch == NULL) {
        ExDeleteNPagedLookasideList(&proc->BatchLookaside);
        ExFreePoolWithTag(proc, BP_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    proc->SpareBatch = BppAllocateBatch(proc);
    if (proc->SpareBatch == NULL) {
        BppFreeBatch(proc, proc->CurrentBatch, TRUE);
        ExDeleteNPagedLookasideList(&proc->BatchLookaside);
        ExFreePoolWithTag(proc, BP_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeTimer(&proc->AgeTimer);
    KeInitializeDpc(&proc->AgeDpc, BppAgeDpcRoutine, proc);
    KeQuerySystemTime(&proc->Stats.StartTime);

    InterlockedExchange(&proc->Initialized, TRUE);
    *Processor = proc;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
BpShutdown(
    _Inout_ PBP_PROCESSOR Processor
    )
{
    PAGED_CODE();

    if (Processor == NULL || !Processor->Initialized) {
        return;
    }

    //
    // Mark not initialized first. This prevents new callers from
    // entering any API. Existing in-flight callers already hold rundown.
    //
    InterlockedExchange(&Processor->Initialized, FALSE);

    //
    // Stop the processing thread if running. BpStop signals the thread,
    // waits for it to exit, and the thread releases its rundown ref
    // before terminating.
    //
    if (Processor->Running) {
        BpStop(Processor);
    }

    //
    // Wait for ALL in-flight operations to drain. After this returns,
    // no thread is inside any public API and no new threads can enter
    // (Initialized is FALSE, and rundown is completed).
    //
    ExWaitForRundownProtectionRelease(&Processor->RundownRef);

    //
    // Cancel age timer and flush any pending DPCs to ensure BppAgeDpcRoutine
    // has fully returned. The DPC checks Initialized/Running so it will
    // bail out, but we must wait for it to finish accessing the Processor.
    //
    KeCancelTimer(&Processor->AgeTimer);
    KeFlushQueuedDpcs();

    //
    // Free current batch (with events — they were not delivered)
    //
    if (Processor->CurrentBatch != NULL) {
        BppFreeBatch(Processor, Processor->CurrentBatch, TRUE);
        Processor->CurrentBatch = NULL;
    }

    //
    // Free spare batch
    //
    if (Processor->SpareBatch != NULL) {
        BppFreeBatch(Processor, Processor->SpareBatch, TRUE);
        Processor->SpareBatch = NULL;
    }

    //
    // Drain and free any remaining ready batches (no callback — shutting down)
    //
    BppDrainReadyQueue(Processor, FALSE);

    if (Processor->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&Processor->BatchLookaside);
        Processor->LookasideInitialized = FALSE;
    }

    ExFreePoolWithTag(Processor, BP_POOL_TAG);
}

// ============================================================================
// CONFIGURATION
// ============================================================================

_Use_decl_annotations_
NTSTATUS
BpSetBatchParameters(
    _In_ PBP_PROCESSOR Processor,
    _In_ ULONG MaxSize,
    _In_ ULONG MaxAgeMs
    )
{
    PAGED_CODE();

    if (Processor == NULL || !Processor->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (MaxSize == 0 || MaxSize > BP_MAX_BATCH_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (MaxAgeMs == 0 || MaxAgeMs > 60000) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Processor->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    //
    // Use Interlocked to guarantee atomic 32-bit writes visible to
    // BpQueueEvent and the DPC which read these at DISPATCH_LEVEL.
    //
    InterlockedExchange(&Processor->MaxBatchSize, (LONG)MaxSize);
    InterlockedExchange(&Processor->MaxBatchAgeMs, (LONG)MaxAgeMs);

    ExReleaseRundownProtection(&Processor->RundownRef);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
BpRegisterCallback(
    _In_ PBP_PROCESSOR Processor,
    _In_ BP_BATCH_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
{
    PAGED_CODE();

    if (Processor == NULL || !Processor->Initialized || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Processor->Running) {
        return STATUS_DEVICE_BUSY;
    }

    if (!ExAcquireRundownProtection(&Processor->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    Processor->BatchCallback = Callback;
    Processor->CallbackContext = Context;

    ExReleaseRundownProtection(&Processor->RundownRef);
    return STATUS_SUCCESS;
}

// ============================================================================
// EVENT QUEUING — HOT PATH (DISPATCH_LEVEL SAFE)
// ============================================================================

_Use_decl_annotations_
NTSTATUS
BpQueueEvent(
    _In_ PBP_PROCESSOR Processor,
    _In_ ULONG Type,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ SIZE_T DataSize
    )
{
    PBP_EVENT event = NULL;
    SIZE_T allocSize;
    KIRQL oldIrql;
    PBP_BATCH fullBatch = NULL;
    ULONG maxBatchSize;

    if (Processor == NULL || !Processor->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Data == NULL && DataSize > 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (DataSize > BP_MAX_EVENT_DATA_SIZE) {
        InterlockedIncrement64(&Processor->Stats.EventsDropped);
        return STATUS_BUFFER_OVERFLOW;
    }

    if (!ExAcquireRundownProtection(&Processor->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    //
    // Compute allocation size with overflow check.
    // FIELD_OFFSET(BP_EVENT, Data) is small (~16 bytes), DataSize <= 64KB,
    // so overflow is impossible in practice, but we check defensively.
    //
    allocSize = FIELD_OFFSET(BP_EVENT, Data) + DataSize;
    if (allocSize < DataSize) {
        // Overflow
        InterlockedIncrement64(&Processor->Stats.EventsDropped);
        ExReleaseRundownProtection(&Processor->RundownRef);
        return STATUS_INTEGER_OVERFLOW;
    }

    event = (PBP_EVENT)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        allocSize,
        BP_POOL_TAG_EVENT
    );

    if (event == NULL) {
        InterlockedIncrement64(&Processor->Stats.EventsDropped);
        ExReleaseRundownProtection(&Processor->RundownRef);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    event->Type = Type;
    event->DataSize = DataSize;
    if (DataSize > 0 && Data != NULL) {
        RtlCopyMemory(event->Data, Data, DataSize);
    }

    //
    // Read MaxBatchSize once (it's volatile LONG, atomic on x86/x64/ARM64).
    //
    maxBatchSize = (ULONG)Processor->MaxBatchSize;

    //
    // Insert into current batch under spin lock (minimal hold time).
    //
    KeAcquireSpinLock(&Processor->BatchLock, &oldIrql);

    //
    // Recovery: if CurrentBatch is NULL (allocation failed previously),
    // attempt to allocate one now. This prevents permanent event dropping.
    //
    if (Processor->CurrentBatch == NULL) {
        Processor->CurrentBatch = BppAllocateBatch(Processor);
        if (Processor->CurrentBatch == NULL) {
            KeReleaseSpinLock(&Processor->BatchLock, oldIrql);
            ExFreePoolWithTag(event, BP_POOL_TAG_EVENT);
            InterlockedIncrement64(&Processor->Stats.EventsDropped);
            ExReleaseRundownProtection(&Processor->RundownRef);
            return STATUS_DEVICE_NOT_READY;
        }
    }

    if (Processor->CurrentBatch->EventCount == 0) {
        KeQuerySystemTime(&Processor->CurrentBatch->OldestEventTime);
    }

    Processor->CurrentBatch->Events[Processor->CurrentBatch->EventCount] = event;
    Processor->CurrentBatch->EventCount++;

    InterlockedIncrement64(&Processor->Stats.EventsQueued);

    //
    // Check if batch is full
    //
    if (Processor->CurrentBatch->EventCount >= maxBatchSize) {
        fullBatch = Processor->CurrentBatch;

        if (Processor->SpareBatch != NULL) {
            Processor->CurrentBatch = Processor->SpareBatch;
            Processor->SpareBatch = NULL;
        } else {
            //
            // No spare available — allocate a new one. If this fails,
            // CurrentBatch becomes NULL and the next BpQueueEvent call
            // will attempt recovery above.
            //
            Processor->CurrentBatch = BppAllocateBatch(Processor);
        }
    }

    KeReleaseSpinLock(&Processor->BatchLock, oldIrql);

    if (fullBatch != NULL) {
        BppMoveBatchToReadyQueue(Processor, fullBatch);
    }

    ExReleaseRundownProtection(&Processor->RundownRef);
    return STATUS_SUCCESS;
}

// ============================================================================
// FLUSH — NOT in PAGE section (acquires spin lock)
// ============================================================================

_Use_decl_annotations_
NTSTATUS
BpFlush(
    _In_ PBP_PROCESSOR Processor
    )
{
    PBP_BATCH batch = NULL;

    //
    // NOTE: No PAGED_CODE() here — this function acquires spin locks
    // which raise to DISPATCH_LEVEL. It must NOT be in a paged section.
    //

    if (Processor == NULL || !Processor->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Processor->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    batch = BppRotateCurrentBatch(Processor);

    if (batch != NULL) {
        BppMoveBatchToReadyQueue(Processor, batch);
    }

    ExReleaseRundownProtection(&Processor->RundownRef);
    return STATUS_SUCCESS;
}

// ============================================================================
// START / STOP
// ============================================================================

_Use_decl_annotations_
NTSTATUS
BpStart(
    _In_ PBP_PROCESSOR Processor
    )
{
    NTSTATUS status;
    HANDLE threadHandle = NULL;

    PAGED_CODE();

    if (Processor == NULL || !Processor->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Processor->BatchCallback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Processor->Running) {
        return STATUS_ALREADY_INITIALIZED;
    }

    if (!ExAcquireRundownProtection(&Processor->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    //
    // Set Running=TRUE BEFORE creating the thread. This way the thread
    // (and the DPC, and BpStop) see a consistent state from the moment
    // they start. If thread creation fails, we revert.
    //
    InterlockedExchange(&Processor->Running, TRUE);

    KeClearEvent(&Processor->StopEvent);
    KeClearEvent(&Processor->NewBatchEvent);

    status = PsCreateSystemThread(
        &threadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        BppProcessingThread,
        Processor
    );

    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&Processor->Running, FALSE);
        ExReleaseRundownProtection(&Processor->RundownRef);
        return status;
    }

    status = ObReferenceObjectByHandle(
        threadHandle,
        THREAD_ALL_ACCESS,
        *PsThreadType,
        KernelMode,
        (PVOID*)&Processor->ProcessingThread,
        NULL
    );

    ZwClose(threadHandle);

    if (!NT_SUCCESS(status)) {
        //
        // Thread is running but we can't get a reference to wait on it.
        // Signal it to stop and wait via the handle we already closed...
        // Actually, we must stop it. Signal StopEvent — the thread checks
        // it and will terminate. We cannot wait on it (no reference), but
        // the thread will self-terminate shortly. This is an extremely
        // rare error path.
        //
        KeSetEvent(&Processor->StopEvent, IO_NO_INCREMENT, FALSE);
        InterlockedExchange(&Processor->Running, FALSE);
        //
        // Give thread a moment to notice StopEvent and terminate.
        // Not ideal, but ObReferenceObjectByHandle failure after
        // successful PsCreateSystemThread is essentially impossible.
        //
        {
            LARGE_INTEGER delay;
            delay.QuadPart = -10000 * 100; // 100ms
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }
        ExReleaseRundownProtection(&Processor->RundownRef);
        return status;
    }

    BppArmAgeTimer(Processor);

    ExReleaseRundownProtection(&Processor->RundownRef);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
BpStop(
    _In_ PBP_PROCESSOR Processor
    )
{
    PBP_BATCH batch = NULL;

    PAGED_CODE();

    if (Processor == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Processor->Running) {
        return STATUS_SUCCESS;
    }

    //
    // Cancel age timer first. KeFlushQueuedDpcs ensures the DPC has
    // finished executing and won't touch Processor after this point.
    //
    KeCancelTimer(&Processor->AgeTimer);
    KeFlushQueuedDpcs();
    InterlockedExchange(&Processor->AgeTimerArmed, FALSE);

    //
    // Flush the current batch so no events are silently lost.
    // We do this under spin lock (same as BpFlush) — this is NOT paged.
    //
    batch = BppRotateCurrentBatch(Processor);
    if (batch != NULL) {
        BppMoveBatchToReadyQueue(Processor, batch);
    }

    //
    // Signal the thread to stop and wake it to drain final batches.
    //
    KeSetEvent(&Processor->StopEvent, IO_NO_INCREMENT, FALSE);
    KeSetEvent(&Processor->NewBatchEvent, IO_NO_INCREMENT, FALSE);

    //
    // Wait for thread to exit (indefinite, PASSIVE_LEVEL).
    // The thread drains ready queue on exit before terminating.
    //
    if (Processor->ProcessingThread != NULL) {
        KeWaitForSingleObject(
            Processor->ProcessingThread,
            Executive,
            KernelMode,
            FALSE,
            NULL
        );

        ObDereferenceObject(Processor->ProcessingThread);
        Processor->ProcessingThread = NULL;
    }

    InterlockedExchange(&Processor->Running, FALSE);

    return STATUS_SUCCESS;
}

// ============================================================================
// STATISTICS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
BpGetStatistics(
    _In_ PBP_PROCESSOR Processor,
    _Out_ PBP_STATISTICS Stats
    )
{
    LARGE_INTEGER currentTime;

    PAGED_CODE();

    if (Processor == NULL || !Processor->Initialized || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Stats, sizeof(BP_STATISTICS));

    Stats->EventsQueued = Processor->Stats.EventsQueued;
    Stats->BatchesProcessed = Processor->Stats.BatchesProcessed;
    Stats->EventsProcessed = Processor->Stats.EventsProcessed;
    Stats->EventsDropped = Processor->Stats.EventsDropped;
    Stats->QueuedBatchCount = (ULONG)Processor->QueuedBatches;

    //
    // ActiveBatchCount: 1 if CurrentBatch has events, 0 otherwise.
    // We don't acquire the lock here — this is a best-effort snapshot.
    //
    if (Processor->CurrentBatch != NULL && Processor->CurrentBatch->EventCount > 0) {
        Stats->ActiveBatchCount = 1;
    }

    KeQuerySystemTime(&currentTime);
    Stats->UpTime.QuadPart = currentTime.QuadPart - Processor->Stats.StartTime.QuadPart;

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE — BATCH ROTATION HELPER
// ============================================================================

/**
 * @brief Atomically rotate the current batch out and replace with spare/new.
 *
 * Returns the old batch (with events) or NULL if current batch was empty.
 * The returned batch is detached from the processor and owned by the caller.
 * 
 * NOT paged — acquires spin lock.
 */
__declspec(noinline)
static PBP_BATCH
BppRotateCurrentBatch(
    _In_ PBP_PROCESSOR Processor
    )
{
    KIRQL oldIrql;
    PBP_BATCH batch = NULL;

    KeAcquireSpinLock(&Processor->BatchLock, &oldIrql);

    if (Processor->CurrentBatch != NULL && Processor->CurrentBatch->EventCount > 0) {
        batch = Processor->CurrentBatch;

        if (Processor->SpareBatch != NULL) {
            Processor->CurrentBatch = Processor->SpareBatch;
            Processor->SpareBatch = NULL;
        } else {
            Processor->CurrentBatch = BppAllocateBatch(Processor);
        }
    }

    KeReleaseSpinLock(&Processor->BatchLock, oldIrql);
    return batch;
}

// ============================================================================
// PRIVATE — BATCH ALLOCATION
// ============================================================================

static PBP_BATCH
BppAllocateBatch(
    _In_ PBP_PROCESSOR Processor
    )
{
    PBP_BATCH batch;

    batch = (PBP_BATCH)ExAllocateFromNPagedLookasideList(
        &Processor->BatchLookaside
    );

    if (batch != NULL) {
        RtlZeroMemory(batch, sizeof(BP_BATCH));
        InitializeListHead(&batch->ListEntry);
    }

    return batch;
}

static VOID
BppFreeBatch(
    _In_ PBP_PROCESSOR Processor,
    _In_ PBP_BATCH Batch,
    _In_ BOOLEAN FreeEvents
    )
{
    ULONG i;

    if (Batch == NULL) {
        return;
    }

    if (FreeEvents) {
        for (i = 0; i < Batch->EventCount; i++) {
            if (Batch->Events[i] != NULL) {
                ExFreePoolWithTag(Batch->Events[i], BP_POOL_TAG_EVENT);
                Batch->Events[i] = NULL;
            }
        }
    }

    ExFreeToNPagedLookasideList(&Processor->BatchLookaside, Batch);
}

// ============================================================================
// PRIVATE — READY QUEUE MANAGEMENT
// ============================================================================

__declspec(noinline)
static VOID
BppMoveBatchToReadyQueue(
    _In_ PBP_PROCESSOR Processor,
    _In_ PBP_BATCH Batch
    )
{
    KIRQL oldIrql;
    LONG currentCount;
    LONG newCount;

    //
    // Enforce queue depth limit using InterlockedCompareExchange to avoid
    // TOCTOU race. Two concurrent callers cannot both pass the limit.
    //
    for (;;) {
        currentCount = Processor->QueuedBatches;
        if (currentCount >= (LONG)BP_MAX_QUEUED_BATCHES) {
            //
            // Queue is full — drop the batch
            //
            InterlockedAdd64(
                &Processor->Stats.EventsDropped,
                (LONG64)Batch->EventCount
            );
            BppFreeBatch(Processor, Batch, TRUE);
            return;
        }

        newCount = currentCount + 1;
        if (InterlockedCompareExchange(
                &Processor->QueuedBatches,
                newCount,
                currentCount) == currentCount) {
            break;
        }
        //
        // CAS failed — another thread incremented. Retry.
        //
    }

    //
    // We've reserved our slot in QueuedBatches. Now insert under lock.
    //
    KeAcquireSpinLock(&Processor->QueueLock, &oldIrql);
    InsertTailList(&Processor->ReadyQueue, &Batch->ListEntry);
    KeReleaseSpinLock(&Processor->QueueLock, oldIrql);

    KeSetEvent(&Processor->NewBatchEvent, IO_NO_INCREMENT, FALSE);
}

/**
 * @brief Drain all batches from the ready queue.
 *
 * Moves the entire list under spin lock, then processes at PASSIVE_LEVEL.
 * If InvokeCallback is TRUE, calls the registered callback for each batch.
 *
 * NOT paged — acquires spin locks.
 */
__declspec(noinline)
static VOID
BppDrainReadyQueue(
    _In_ PBP_PROCESSOR Processor,
    _In_ BOOLEAN InvokeCallback
    )
{
    KIRQL oldIrql;
    LIST_ENTRY drainList;
    PLIST_ENTRY entry;
    PBP_BATCH batch;
    LONG drainCount = 0;

    InitializeListHead(&drainList);

    //
    // Snapshot entire queue under spin lock (very fast — just pointer swaps)
    //
    KeAcquireSpinLock(&Processor->QueueLock, &oldIrql);

    while (!IsListEmpty(&Processor->ReadyQueue)) {
        entry = RemoveHeadList(&Processor->ReadyQueue);
        InsertTailList(&drainList, entry);
        drainCount++;
    }

    KeReleaseSpinLock(&Processor->QueueLock, oldIrql);

    //
    // Decrement QueuedBatches by the number we removed.
    // We use InterlockedAdd because BppMoveBatchToReadyQueue uses
    // InterlockedCompareExchange on QueuedBatches.
    //
    if (drainCount > 0) {
        InterlockedAdd(&Processor->QueuedBatches, -drainCount);
    }

    //
    // Process batches outside lock (caller must be at PASSIVE_LEVEL
    // if InvokeCallback is TRUE, since callbacks run at PASSIVE).
    //
    while (!IsListEmpty(&drainList)) {
        entry = RemoveHeadList(&drainList);
        batch = CONTAINING_RECORD(entry, BP_BATCH, ListEntry);

        if (InvokeCallback && Processor->BatchCallback != NULL && batch->EventCount > 0) {
            Processor->BatchCallback(
                batch->Events,
                batch->EventCount,
                Processor->CallbackContext
            );

            InterlockedIncrement64(&Processor->Stats.BatchesProcessed);
            InterlockedAdd64(
                &Processor->Stats.EventsProcessed,
                (LONG64)batch->EventCount
            );
        }

        BppFreeBatch(Processor, batch, TRUE);
    }

    //
    // Replenish spare batch if consumed. We must acquire BatchLock because
    // SpareBatch is also accessed by BpQueueEvent and the DPC.
    //
    if (Processor->SpareBatch == NULL && Processor->LookasideInitialized) {
        KIRQL spareIrql;
        KeAcquireSpinLock(&Processor->BatchLock, &spareIrql);
        if (Processor->SpareBatch == NULL) {
            Processor->SpareBatch = BppAllocateBatch(Processor);
        }
        KeReleaseSpinLock(&Processor->BatchLock, spareIrql);
    }
}

// ============================================================================
// PRIVATE — PROCESSING THREAD
// ============================================================================

static VOID NTAPI
BppProcessingThread(
    _In_ PVOID StartContext
    )
{
    PBP_PROCESSOR proc = (PBP_PROCESSOR)StartContext;
    PVOID waitObjects[2];
    NTSTATUS waitStatus;

    //
    // Acquire rundown protection for the thread's entire lifetime.
    // This ensures BpShutdown's ExWaitForRundownProtectionRelease will
    // wait for this thread to release before tearing down the processor.
    //
    if (!ExAcquireRundownProtection(&proc->RundownRef)) {
        //
        // Processor is already being torn down — exit immediately.
        //
        PsTerminateSystemThread(STATUS_CANCELLED);
        return; // Unreachable, but silences warnings
    }

    waitObjects[0] = &proc->StopEvent;
    waitObjects[1] = &proc->NewBatchEvent;

    for (;;) {
        waitStatus = KeWaitForMultipleObjects(
            2,
            waitObjects,
            WaitAny,
            Executive,
            KernelMode,
            FALSE,
            NULL,
            NULL
        );

        if (waitStatus == STATUS_WAIT_0) {
            //
            // StopEvent signaled — drain remaining batches and exit.
            // BpStop already moved the current batch to ready queue
            // before signaling, so we drain everything here.
            //
            BppDrainReadyQueue(proc, TRUE);
            break;
        }

        //
        // NewBatchEvent signaled (or spurious) — process ready batches.
        // BppDrainReadyQueue drains ALL batches in the ready queue, so
        // even if multiple batches were queued before the thread woke,
        // they are all processed in this single drain cycle.
        //
        BppDrainReadyQueue(proc, TRUE);
    }

    ExReleaseRundownProtection(&proc->RundownRef);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

// ============================================================================
// PRIVATE — AGE TIMER
// ============================================================================

static VOID
BppArmAgeTimer(
    _In_ PBP_PROCESSOR Processor
    )
{
    LARGE_INTEGER dueTime;
    LONG ageMs;

    ageMs = Processor->MaxBatchAgeMs;
    if (ageMs == 0) {
        return;
    }

    dueTime.QuadPart = -((LONGLONG)ageMs * 10000);

    KeSetTimerEx(
        &Processor->AgeTimer,
        dueTime,
        (LONG)ageMs,
        &Processor->AgeDpc
    );

    InterlockedExchange(&Processor->AgeTimerArmed, TRUE);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
BppAgeDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PBP_PROCESSOR proc = (PBP_PROCESSOR)DeferredContext;
    KIRQL oldIrql;
    PBP_BATCH agedBatch = NULL;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (proc == NULL || !proc->Initialized || !proc->Running) {
        return;
    }

    KeAcquireSpinLock(&proc->BatchLock, &oldIrql);

    if (proc->CurrentBatch != NULL && proc->CurrentBatch->EventCount > 0) {
        LARGE_INTEGER now;
        LONGLONG ageMs;

        KeQuerySystemTime(&now);
        ageMs = (now.QuadPart - proc->CurrentBatch->OldestEventTime.QuadPart) / 10000;

        if (ageMs >= (LONGLONG)proc->MaxBatchAgeMs) {
            agedBatch = proc->CurrentBatch;

            if (proc->SpareBatch != NULL) {
                proc->CurrentBatch = proc->SpareBatch;
                proc->SpareBatch = NULL;
            } else {
                proc->CurrentBatch = BppAllocateBatch(proc);
            }
        }
    }

    KeReleaseSpinLock(&proc->BatchLock, oldIrql);

    if (agedBatch != NULL) {
        BppMoveBatchToReadyQueue(proc, agedBatch);
    }
}
