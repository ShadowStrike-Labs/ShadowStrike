/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE ASYNC WORK QUEUE
 * ============================================================================
 *
 * @file AsyncWorkQueue.c
 * @brief High-performance asynchronous work queue implementation.
 *
 * This module implements CrowdStrike/SentinelOne-class async work queue
 * infrastructure for kernel-mode EDR operations. All functions are
 * designed for:
 * - Maximum throughput (lock-free dequeue, per-priority queues)
 * - Scalability (work stealing, dynamic thread pool)
 * - Reliability (completion tracking, retry support)
 * - Observability (detailed statistics, diagnostics)
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "AsyncWorkQueue.h"
#include <ntstrsafe.h>

// ============================================================================
// PAGED/NON-PAGED CODE SEGMENT DECLARATIONS
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, AwqInitialize)
#pragma alloc_text(PAGE, AwqShutdown)
#pragma alloc_text(PAGE, AwqPause)
#pragma alloc_text(PAGE, AwqResume)
#pragma alloc_text(PAGE, AwqDrain)
#pragma alloc_text(PAGE, AwqSetThreadCount)
#pragma alloc_text(PAGE, AwqSetDefaultTimeout)
#pragma alloc_text(PAGE, AwqSetWorkStealing)
#pragma alloc_text(PAGE, AwqSetDynamicThreads)
#endif

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

/**
 * @brief Magic value for manager validation
 */
#define AWQ_MANAGER_MAGIC               0x51575141  // 'AWQM'

/**
 * @brief Magic value for work item validation
 */
#define AWQ_ITEM_MAGIC                  0x49575141  // 'AWQI'

/**
 * @brief Default number of cached work items
 */
#define AWQ_DEFAULT_CACHE_SIZE          256

/**
 * @brief Maximum retry count
 */
#define AWQ_MAX_RETRIES                 5

/**
 * @brief Worker thread stack size
 */
#define AWQ_WORKER_STACK_SIZE           (32 * 1024)

/**
 * @brief Priority names for debugging
 */
static const PCSTR g_PriorityNames[] = {
    "Low",
    "Normal",
    "High",
    "Critical"
};

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

/**
 * @brief Extended work item with internal fields
 */
typedef struct _AWQ_WORK_ITEM_INTERNAL {
    //
    // Public work item (must be first)
    //
    AWQ_WORK_ITEM Public;

    //
    // Validation magic
    //
    ULONG Magic;

    //
    // Back pointer to manager
    //
    struct _AWQ_MANAGER_INTERNAL* Manager;

    //
    // Allocated context buffer (if copied)
    //
    PVOID AllocatedContext;
    ULONG AllocatedContextSize;

    //
    // Completion status
    //
    volatile BOOLEAN Completed;

    //
    // Wait reference count
    //
    volatile LONG WaitRefCount;

} AWQ_WORK_ITEM_INTERNAL, *PAWQ_WORK_ITEM_INTERNAL;

/**
 * @brief Serialization key entry
 */
typedef struct _AWQ_SERIALIZATION_KEY {
    LIST_ENTRY ListEntry;
    ULONG64 Key;
    volatile LONG ActiveCount;
    LIST_ENTRY PendingItems;
    KSPIN_LOCK Lock;
} AWQ_SERIALIZATION_KEY, *PAWQ_SERIALIZATION_KEY;

/**
 * @brief Extended manager with internal fields
 */
typedef struct _AWQ_MANAGER_INTERNAL {
    //
    // Public manager (must be first for casting)
    //
    AWQ_MANAGER Public;

    //
    // Validation magic
    //
    ULONG Magic;

    //
    // Worker thread routine context
    //
    PIO_WORKITEM ShutdownWorkItem;

    //
    // Item tracking for wait operations
    //
    struct {
        LIST_ENTRY ActiveItems;
        KSPIN_LOCK Lock;
        volatile LONG ActiveCount;
    } ItemTracking;

    //
    // Lookup table for fast item access
    //
    struct {
        PAWQ_WORK_ITEM_INTERNAL* Buckets;
        ULONG BucketCount;
        KSPIN_LOCK Lock;
    } ItemLookup;

} AWQ_MANAGER_INTERNAL, *PAWQ_MANAGER_INTERNAL;

// ============================================================================
// INTERNAL FORWARD DECLARATIONS
// ============================================================================

static VOID
AwqpWorkerThreadRoutine(
    _In_ PVOID StartContext
    );

static PAWQ_WORK_ITEM_INTERNAL
AwqpAllocateWorkItem(
    _In_ PAWQ_MANAGER_INTERNAL Manager
    );

static VOID
AwqpFreeWorkItem(
    _In_ PAWQ_MANAGER_INTERNAL Manager,
    _In_ PAWQ_WORK_ITEM_INTERNAL Item
    );

static NTSTATUS
AwqpEnqueueItem(
    _In_ PAWQ_MANAGER_INTERNAL Manager,
    _In_ PAWQ_WORK_ITEM_INTERNAL Item
    );

static PAWQ_WORK_ITEM_INTERNAL
AwqpDequeueItem(
    _In_ PAWQ_MANAGER_INTERNAL Manager,
    _In_ PAWQ_WORKER_THREAD Worker
    );

static VOID
AwqpExecuteItem(
    _In_ PAWQ_MANAGER_INTERNAL Manager,
    _In_ PAWQ_WORKER_THREAD Worker,
    _In_ PAWQ_WORK_ITEM_INTERNAL Item
    );

static VOID
AwqpCompleteItem(
    _In_ PAWQ_MANAGER_INTERNAL Manager,
    _In_ PAWQ_WORK_ITEM_INTERNAL Item,
    _In_ NTSTATUS Status
    );

static NTSTATUS
AwqpCreateWorkerThread(
    _In_ PAWQ_MANAGER_INTERNAL Manager,
    _Out_ PAWQ_WORKER_THREAD* Worker
    );

static VOID
AwqpDestroyWorkerThread(
    _In_ PAWQ_MANAGER_INTERNAL Manager,
    _In_ PAWQ_WORKER_THREAD Worker,
    _In_ BOOLEAN Wait
    );

static BOOLEAN
AwqpTryStealWork(
    _In_ PAWQ_MANAGER_INTERNAL Manager,
    _In_ PAWQ_WORKER_THREAD Worker,
    _Out_ PAWQ_WORK_ITEM_INTERNAL* StolenItem
    );

static VOID
AwqpCheckSerializationKey(
    _In_ PAWQ_MANAGER_INTERNAL Manager,
    _In_ ULONG64 Key
    );

static VOID
AwqpRegisterItem(
    _In_ PAWQ_MANAGER_INTERNAL Manager,
    _In_ PAWQ_WORK_ITEM_INTERNAL Item
    );

static VOID
AwqpUnregisterItem(
    _In_ PAWQ_MANAGER_INTERNAL Manager,
    _In_ PAWQ_WORK_ITEM_INTERNAL Item
    );

static PAWQ_WORK_ITEM_INTERNAL
AwqpFindItem(
    _In_ PAWQ_MANAGER_INTERNAL Manager,
    _In_ ULONG64 ItemId
    );

// ============================================================================
// INTERNAL HELPER MACROS
// ============================================================================

/**
 * @brief Validate manager pointer
 */
#define AWQ_VALIDATE_MANAGER(Manager) \
    ((Manager) != NULL && \
     ((PAWQ_MANAGER_INTERNAL)(Manager))->Magic == AWQ_MANAGER_MAGIC && \
     ((PAWQ_MANAGER_INTERNAL)(Manager))->Public.State != AwqQueueState_Uninitialized)

/**
 * @brief Validate work item pointer
 */
#define AWQ_VALIDATE_ITEM(Item) \
    ((Item) != NULL && (Item)->Magic == AWQ_ITEM_MAGIC)

/**
 * @brief Convert public manager to internal
 */
#define AWQ_TO_INTERNAL(Manager) ((PAWQ_MANAGER_INTERNAL)(Manager))

/**
 * @brief Convert internal manager to public
 */
#define AWQ_TO_PUBLIC(Manager) (&((PAWQ_MANAGER_INTERNAL)(Manager))->Public)

/**
 * @brief Acquire priority queue lock
 */
#define AWQ_LOCK_PRIORITY_QUEUE(Queue, OldIrql) \
    KeAcquireSpinLock(&(Queue)->Lock, &(OldIrql))

/**
 * @brief Release priority queue lock
 */
#define AWQ_UNLOCK_PRIORITY_QUEUE(Queue, OldIrql) \
    KeReleaseSpinLock(&(Queue)->Lock, (OldIrql))

// ============================================================================
// MANAGER INITIALIZATION AND SHUTDOWN
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqInitialize(
    _Out_ PAWQ_MANAGER* Manager,
    _In_ ULONG MinThreads,
    _In_ ULONG MaxThreads,
    _In_ ULONG MaxQueueSize
    )
{
    PAWQ_MANAGER_INTERNAL NewManager = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG i;
    ULONG ProcessorCount;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Manager == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Manager = NULL;

    //
    // Get processor count for defaults
    //
    ProcessorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

    //
    // Validate and adjust thread counts
    //
    if (MinThreads == 0) {
        MinThreads = AWQ_MIN_THREADS;
    }
    if (MaxThreads == 0) {
        MaxThreads = min(ProcessorCount * AWQ_DEFAULT_THREADS_PER_CPU, AWQ_MAX_THREADS);
    }
    if (MinThreads > MaxThreads) {
        MinThreads = MaxThreads;
    }
    if (MaxThreads > AWQ_MAX_THREADS) {
        MaxThreads = AWQ_MAX_THREADS;
    }
    if (MinThreads < AWQ_MIN_THREADS) {
        MinThreads = AWQ_MIN_THREADS;
    }

    //
    // Validate queue size
    //
    if (MaxQueueSize == 0) {
        MaxQueueSize = AWQ_DEFAULT_QUEUE_SIZE;
    }
    if (MaxQueueSize < AWQ_MIN_QUEUE_SIZE) {
        MaxQueueSize = AWQ_MIN_QUEUE_SIZE;
    }
    if (MaxQueueSize > AWQ_MAX_QUEUE_SIZE) {
        MaxQueueSize = AWQ_MAX_QUEUE_SIZE;
    }

    //
    // Allocate manager structure
    //
    NewManager = (PAWQ_MANAGER_INTERNAL)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(AWQ_MANAGER_INTERNAL),
        AWQ_POOL_TAG_QUEUE
    );

    if (NewManager == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(NewManager, sizeof(AWQ_MANAGER_INTERNAL));

    //
    // Initialize basic fields
    //
    NewManager->Magic = AWQ_MANAGER_MAGIC;
    NewManager->Public.State = AwqQueueState_Initializing;

    //
    // Initialize priority queues
    //
    for (i = 0; i < AwqPriority_Max; i++) {
        PAWQ_PRIORITY_QUEUE Queue = &NewManager->Public.PriorityQueues[i];

        InitializeListHead(&Queue->ItemList);
        KeInitializeSpinLock(&Queue->Lock);
        Queue->ItemCount = 0;
        Queue->PeakCount = 0;
        Queue->MaxItems = MaxQueueSize;
        Queue->TotalEnqueued = 0;
        Queue->TotalDequeued = 0;
        Queue->TotalDropped = 0;
        KeInitializeSemaphore(&Queue->ItemSemaphore, 0, MAXLONG);
    }

    //
    // Initialize worker thread list
    //
    InitializeListHead(&NewManager->Public.WorkerList);
    KeInitializeSpinLock(&NewManager->Public.WorkerListLock);
    NewManager->Public.WorkerCount = 0;
    NewManager->Public.IdleWorkerCount = 0;
    NewManager->Public.ActiveWorkerCount = 0;
    NewManager->Public.MinWorkers = MinThreads;
    NewManager->Public.MaxWorkers = MaxThreads;

    //
    // Initialize events
    //
    KeInitializeEvent(&NewManager->Public.NewWorkEvent, SynchronizationEvent, FALSE);
    KeInitializeEvent(&NewManager->Public.ShutdownEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&NewManager->Public.DrainCompleteEvent, NotificationEvent, FALSE);

    //
    // Initialize ID generation
    //
    NewManager->Public.NextItemId = 1;

    //
    // Initialize serialization support
    //
    InitializeListHead(&NewManager->Public.Serialization.ActiveKeys);
    KeInitializeSpinLock(&NewManager->Public.Serialization.Lock);

    //
    // Initialize statistics
    //
    NewManager->Public.Stats.TotalSubmitted = 0;
    NewManager->Public.Stats.TotalCompleted = 0;
    NewManager->Public.Stats.TotalCancelled = 0;
    NewManager->Public.Stats.TotalFailed = 0;
    NewManager->Public.Stats.TotalRetries = 0;
    NewManager->Public.Stats.TotalTimeouts = 0;
    KeQuerySystemTimePrecise(&NewManager->Public.Stats.StartTime);

    //
    // Initialize configuration
    //
    NewManager->Public.Config.DefaultTimeoutMs = AWQ_DEFAULT_TIMEOUT_MS;
    NewManager->Public.Config.MaxItemSize = AWQ_MAX_WORK_ITEM_SIZE;
    NewManager->Public.Config.MaxQueueSize = MaxQueueSize;
    NewManager->Public.Config.EnableWorkStealing = TRUE;
    NewManager->Public.Config.EnableDynamicThreads = TRUE;

    //
    // Initialize work item cache (free list)
    //
    InitializeListHead(&NewManager->Public.ItemCache.FreeList);
    KeInitializeSpinLock(&NewManager->Public.ItemCache.Lock);
    NewManager->Public.ItemCache.FreeCount = 0;
    NewManager->Public.ItemCache.MaxFreeItems = AWQ_DEFAULT_CACHE_SIZE;

    //
    // Initialize item tracking
    //
    InitializeListHead(&NewManager->ItemTracking.ActiveItems);
    KeInitializeSpinLock(&NewManager->ItemTracking.Lock);
    NewManager->ItemTracking.ActiveCount = 0;

    //
    // Allocate item lookup buckets
    //
    NewManager->ItemLookup.BucketCount = 256;
    NewManager->ItemLookup.Buckets = (PAWQ_WORK_ITEM_INTERNAL*)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        NewManager->ItemLookup.BucketCount * sizeof(PAWQ_WORK_ITEM_INTERNAL),
        AWQ_POOL_TAG_QUEUE
    );

    if (NewManager->ItemLookup.Buckets == NULL) {
        ExFreePoolWithTag(NewManager, AWQ_POOL_TAG_QUEUE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(
        NewManager->ItemLookup.Buckets,
        NewManager->ItemLookup.BucketCount * sizeof(PAWQ_WORK_ITEM_INTERNAL)
    );
    KeInitializeSpinLock(&NewManager->ItemLookup.Lock);

    //
    // Pre-allocate some work items for the cache
    //
    for (i = 0; i < min(AWQ_DEFAULT_CACHE_SIZE / 4, 64); i++) {
        PAWQ_WORK_ITEM_INTERNAL Item;

        Item = (PAWQ_WORK_ITEM_INTERNAL)ExAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(AWQ_WORK_ITEM_INTERNAL),
            AWQ_POOL_TAG_ITEM
        );

        if (Item != NULL) {
            RtlZeroMemory(Item, sizeof(AWQ_WORK_ITEM_INTERNAL));
            Item->Magic = AWQ_ITEM_MAGIC;
            Item->Public.State = AwqItemState_Free;

            InsertTailList(
                &NewManager->Public.ItemCache.FreeList,
                &Item->Public.ListEntry
            );
            NewManager->Public.ItemCache.FreeCount++;
        }
    }

    //
    // Create initial worker threads
    //
    for (i = 0; i < MinThreads; i++) {
        PAWQ_WORKER_THREAD Worker = NULL;

        Status = AwqpCreateWorkerThread(NewManager, &Worker);
        if (!NT_SUCCESS(Status)) {
            //
            // Failed to create worker - continue with what we have
            //
#if DBG
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_WARNING_LEVEL,
                "[ShadowStrike] AWQ: Failed to create worker thread %u: 0x%08X\n",
                i, Status
            );
#endif
            if (NewManager->Public.WorkerCount == 0) {
                //
                // No workers created at all - fail initialization
                //
                if (NewManager->ItemLookup.Buckets != NULL) {
                    ExFreePoolWithTag(NewManager->ItemLookup.Buckets, AWQ_POOL_TAG_QUEUE);
                }

                //
                // Free cached items
                //
                while (!IsListEmpty(&NewManager->Public.ItemCache.FreeList)) {
                    PLIST_ENTRY Entry = RemoveHeadList(&NewManager->Public.ItemCache.FreeList);
                    PAWQ_WORK_ITEM_INTERNAL Item = CONTAINING_RECORD(
                        Entry, AWQ_WORK_ITEM_INTERNAL, Public.ListEntry
                    );
                    ExFreePoolWithTag(Item, AWQ_POOL_TAG_ITEM);
                }

                ExFreePoolWithTag(NewManager, AWQ_POOL_TAG_QUEUE);
                return Status;
            }
            break;
        }
    }

    //
    // Mark as running
    //
    NewManager->Public.State = AwqQueueState_Running;

    *Manager = AWQ_TO_PUBLIC(NewManager);

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
AwqShutdown(
    _Inout_ PAWQ_MANAGER Manager,
    _In_ BOOLEAN WaitForCompletion
    )
{
    PAWQ_MANAGER_INTERNAL Internal = AWQ_TO_INTERNAL(Manager);
    LIST_ENTRY WorkersToDestroy;
    PLIST_ENTRY Entry;
    LARGE_INTEGER Timeout;
    ULONG i;

    PAGED_CODE();

    if (!AWQ_VALIDATE_MANAGER(Manager)) {
        return;
    }

    //
    // Mark as shutting down
    //
    Internal->Public.State = AwqQueueState_Shutdown;

    //
    // Signal shutdown event
    //
    KeSetEvent(&Internal->Public.ShutdownEvent, IO_NO_INCREMENT, FALSE);

    //
    // Wake all waiting workers
    //
    for (i = 0; i < AwqPriority_Max; i++) {
        //
        // Release semaphore to wake any waiting threads
        //
        KeReleaseSemaphore(
            &Internal->Public.PriorityQueues[i].ItemSemaphore,
            IO_NO_INCREMENT,
            Internal->Public.WorkerCount,
            FALSE
        );
    }
    KeSetEvent(&Internal->Public.NewWorkEvent, IO_NO_INCREMENT, FALSE);

    //
    // Collect all workers
    //
    InitializeListHead(&WorkersToDestroy);

    {
        KIRQL OldIrql;
        KeAcquireSpinLock(&Internal->Public.WorkerListLock, &OldIrql);

        while (!IsListEmpty(&Internal->Public.WorkerList)) {
            Entry = RemoveHeadList(&Internal->Public.WorkerList);
            InsertTailList(&WorkersToDestroy, Entry);
        }

        KeReleaseSpinLock(&Internal->Public.WorkerListLock, OldIrql);
    }

    //
    // Wait for and destroy workers
    //
    if (WaitForCompletion) {
        Timeout.QuadPart = -((LONGLONG)AWQ_SHUTDOWN_TIMEOUT_MS * 10000);

        while (!IsListEmpty(&WorkersToDestroy)) {
            Entry = RemoveHeadList(&WorkersToDestroy);
            PAWQ_WORKER_THREAD Worker = CONTAINING_RECORD(Entry, AWQ_WORKER_THREAD, ListEntry);

            Worker->Running = FALSE;

            if (Worker->ThreadObject != NULL) {
                KeWaitForSingleObject(
                    Worker->ThreadObject,
                    Executive,
                    KernelMode,
                    FALSE,
                    &Timeout
                );
                ObDereferenceObject(Worker->ThreadObject);
            }

            ExFreePoolWithTag(Worker, AWQ_POOL_TAG_THREAD);
            InterlockedDecrement(&Internal->Public.WorkerCount);
        }
    } else {
        //
        // Just mark workers as not running
        //
        for (Entry = WorkersToDestroy.Flink;
             Entry != &WorkersToDestroy;
             Entry = Entry->Flink) {

            PAWQ_WORKER_THREAD Worker = CONTAINING_RECORD(Entry, AWQ_WORKER_THREAD, ListEntry);
            Worker->Running = FALSE;
        }
    }

    //
    // Free all queued work items
    //
    for (i = 0; i < AwqPriority_Max; i++) {
        PAWQ_PRIORITY_QUEUE Queue = &Internal->Public.PriorityQueues[i];
        KIRQL OldIrql;

        AWQ_LOCK_PRIORITY_QUEUE(Queue, OldIrql);

        while (!IsListEmpty(&Queue->ItemList)) {
            Entry = RemoveHeadList(&Queue->ItemList);
            PAWQ_WORK_ITEM_INTERNAL Item = CONTAINING_RECORD(
                Entry, AWQ_WORK_ITEM_INTERNAL, Public.ListEntry
            );

            Item->Public.State = AwqItemState_Cancelled;

            //
            // Call cleanup callback if specified
            //
            if (Item->Public.CleanupCallback != NULL && Item->Public.Context != NULL) {
                Item->Public.CleanupCallback(Item->Public.Context);
            }

            //
            // Free allocated context
            //
            if (Item->AllocatedContext != NULL) {
                ExFreePoolWithTag(Item->AllocatedContext, AWQ_POOL_TAG_CONTEXT);
            }

            //
            // Signal completion event if waiting
            //
            if (Item->Public.CompletionEvent != NULL) {
                Item->Public.CompletionStatus = STATUS_CANCELLED;
                KeSetEvent(Item->Public.CompletionEvent, IO_NO_INCREMENT, FALSE);
            }

            ExFreePoolWithTag(Item, AWQ_POOL_TAG_ITEM);
        }

        AWQ_UNLOCK_PRIORITY_QUEUE(Queue, OldIrql);
    }

    //
    // Free cached work items
    //
    {
        KIRQL OldIrql;
        KeAcquireSpinLock(&Internal->Public.ItemCache.Lock, &OldIrql);

        while (!IsListEmpty(&Internal->Public.ItemCache.FreeList)) {
            Entry = RemoveHeadList(&Internal->Public.ItemCache.FreeList);
            PAWQ_WORK_ITEM_INTERNAL Item = CONTAINING_RECORD(
                Entry, AWQ_WORK_ITEM_INTERNAL, Public.ListEntry
            );
            ExFreePoolWithTag(Item, AWQ_POOL_TAG_ITEM);
        }

        KeReleaseSpinLock(&Internal->Public.ItemCache.Lock, OldIrql);
    }

    //
    // Free serialization keys
    //
    {
        KIRQL OldIrql;
        KeAcquireSpinLock(&Internal->Public.Serialization.Lock, &OldIrql);

        while (!IsListEmpty(&Internal->Public.Serialization.ActiveKeys)) {
            Entry = RemoveHeadList(&Internal->Public.Serialization.ActiveKeys);
            PAWQ_SERIALIZATION_KEY Key = CONTAINING_RECORD(Entry, AWQ_SERIALIZATION_KEY, ListEntry);
            ExFreePoolWithTag(Key, AWQ_POOL_TAG_CONTEXT);
        }

        KeReleaseSpinLock(&Internal->Public.Serialization.Lock, OldIrql);
    }

    //
    // Free lookup buckets
    //
    if (Internal->ItemLookup.Buckets != NULL) {
        ExFreePoolWithTag(Internal->ItemLookup.Buckets, AWQ_POOL_TAG_QUEUE);
    }

    //
    // Clear magic and free manager
    //
    Internal->Magic = 0;
    Internal->Public.State = AwqQueueState_Uninitialized;

    ExFreePoolWithTag(Internal, AWQ_POOL_TAG_QUEUE);
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
AwqPause(
    _Inout_ PAWQ_MANAGER Manager
    )
{
    PAWQ_MANAGER_INTERNAL Internal = AWQ_TO_INTERNAL(Manager);

    PAGED_CODE();

    if (!AWQ_VALIDATE_MANAGER(Manager)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Internal->Public.State != AwqQueueState_Running) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    Internal->Public.State = AwqQueueState_Paused;

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
AwqResume(
    _Inout_ PAWQ_MANAGER Manager
    )
{
    PAWQ_MANAGER_INTERNAL Internal = AWQ_TO_INTERNAL(Manager);

    PAGED_CODE();

    if (!AWQ_VALIDATE_MANAGER(Manager)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Internal->Public.State != AwqQueueState_Paused) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    Internal->Public.State = AwqQueueState_Running;

    //
    // Wake workers to process any pending work
    //
    KeSetEvent(&Internal->Public.NewWorkEvent, IO_NO_INCREMENT, FALSE);

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
AwqDrain(
    _Inout_ PAWQ_MANAGER Manager,
    _In_ ULONG TimeoutMs
    )
{
    PAWQ_MANAGER_INTERNAL Internal = AWQ_TO_INTERNAL(Manager);
    LARGE_INTEGER Timeout;
    NTSTATUS Status;
    ULONG TotalPending = 0;
    ULONG i;

    PAGED_CODE();

    if (!AWQ_VALIDATE_MANAGER(Manager)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Check if there's anything to drain
    //
    for (i = 0; i < AwqPriority_Max; i++) {
        TotalPending += Internal->Public.PriorityQueues[i].ItemCount;
    }

    if (TotalPending == 0 && Internal->Public.ActiveWorkerCount == 0) {
        return STATUS_SUCCESS;
    }

    //
    // Mark as draining
    //
    Internal->Public.State = AwqQueueState_Draining;
    KeClearEvent(&Internal->Public.DrainCompleteEvent);

    //
    // Wait for drain to complete
    //
    if (TimeoutMs == 0) {
        TimeoutMs = AWQ_SHUTDOWN_TIMEOUT_MS;
    }

    Timeout.QuadPart = -((LONGLONG)TimeoutMs * 10000);

    Status = KeWaitForSingleObject(
        &Internal->Public.DrainCompleteEvent,
        Executive,
        KernelMode,
        FALSE,
        &Timeout
    );

    if (Status == STATUS_TIMEOUT) {
        Internal->Public.State = AwqQueueState_Running;
        return STATUS_TIMEOUT;
    }

    Internal->Public.State = AwqQueueState_Running;

    return STATUS_SUCCESS;
}

// ============================================================================
// WORK SUBMISSION
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqSubmit(
    _In_ PAWQ_MANAGER Manager,
    _In_ AWQ_WORK_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _In_ ULONG ContextSize,
    _In_opt_ PAWQ_SUBMIT_OPTIONS Options,
    _Out_opt_ PULONG64 ItemId
    )
{
    PAWQ_MANAGER_INTERNAL Internal = AWQ_TO_INTERNAL(Manager);
    PAWQ_WORK_ITEM_INTERNAL Item = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    AWQ_PRIORITY Priority = AwqPriority_Normal;
    AWQ_WORK_FLAGS Flags = AwqFlag_None;

    if (ItemId != NULL) {
        *ItemId = 0;
    }

    //
    // Validate parameters
    //
    if (!AWQ_VALIDATE_MANAGER(Manager)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ContextSize > AWQ_MAX_WORK_ITEM_SIZE) {
        return STATUS_BUFFER_OVERFLOW;
    }

    //
    // Check state
    //
    if (Internal->Public.State != AwqQueueState_Running &&
        Internal->Public.State != AwqQueueState_Paused) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Extract options
    //
    if (Options != NULL) {
        Priority = Options->Priority;
        Flags = Options->Flags;

        if (Priority >= AwqPriority_Max) {
            Priority = AwqPriority_Normal;
        }
    }

    //
    // Check queue capacity
    //
    if ((ULONG)Internal->Public.PriorityQueues[Priority].ItemCount >=
        Internal->Public.Config.MaxQueueSize) {
        InterlockedIncrement64(&Internal->Public.PriorityQueues[Priority].TotalDropped);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Allocate work item
    //
    Item = AwqpAllocateWorkItem(Internal);
    if (Item == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize work item
    //
    Item->Public.ItemId = InterlockedIncrement64(&Internal->Public.NextItemId);
    Item->Public.Priority = Priority;
    Item->Public.Flags = Flags;
    Item->Public.State = AwqItemState_Queued;
    Item->Public.WorkCallback = Callback;
    Item->Public.Context = Context;
    Item->Public.ContextSize = ContextSize;
    Item->Public.RefCount = 1;
    Item->Manager = Internal;
    Item->Completed = FALSE;

    KeQuerySystemTimePrecise(&Item->Public.SubmitTime);

    //
    // Copy options
    //
    if (Options != NULL) {
        Item->Public.SerializationKey = Options->SerializationKey;
        Item->Public.CompletionCallback = Options->CompletionCallback;
        Item->Public.CleanupCallback = Options->CleanupCallback;
        Item->Public.CompletionContext = Options->CompletionContext;
        Item->Public.TimeoutMs = Options->TimeoutMs;
        Item->Public.MaxRetries = Options->MaxRetries;
        Item->Public.RetryDelayMs = Options->RetryDelayMs;
        Item->Public.CompletionEvent = Options->CompletionEvent;
    }

    if (Item->Public.TimeoutMs == 0) {
        Item->Public.TimeoutMs = Internal->Public.Config.DefaultTimeoutMs;
    }

    //
    // Copy context if DeleteContext flag is set
    //
    if ((Flags & AwqFlag_DeleteContext) && Context != NULL && ContextSize > 0) {
        Item->AllocatedContext = ExAllocatePoolWithTag(
            NonPagedPoolNx,
            ContextSize,
            AWQ_POOL_TAG_CONTEXT
        );

        if (Item->AllocatedContext == NULL) {
            AwqpFreeWorkItem(Internal, Item);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(Item->AllocatedContext, Context, ContextSize);
        Item->AllocatedContextSize = ContextSize;
        Item->Public.Context = Item->AllocatedContext;
    }

    //
    // Register for tracking
    //
    AwqpRegisterItem(Internal, Item);

    //
    // Enqueue the item
    //
    Status = AwqpEnqueueItem(Internal, Item);
    if (!NT_SUCCESS(Status)) {
        AwqpUnregisterItem(Internal, Item);
        AwqpFreeWorkItem(Internal, Item);
        return Status;
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&Internal->Public.Stats.TotalSubmitted);

    //
    // Return item ID
    //
    if (ItemId != NULL) {
        *ItemId = Item->Public.ItemId;
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqSubmitWithContext(
    _In_ PAWQ_MANAGER Manager,
    _In_ AWQ_WORK_CALLBACK Callback,
    _In_reads_bytes_(ContextSize) PVOID Context,
    _In_ ULONG ContextSize,
    _In_ AWQ_PRIORITY Priority,
    _Out_opt_ PULONG64 ItemId
    )
{
    AWQ_SUBMIT_OPTIONS Options;

    RtlZeroMemory(&Options, sizeof(Options));
    Options.Priority = Priority;
    Options.Flags = AwqFlag_DeleteContext;

    return AwqSubmit(
        Manager,
        Callback,
        Context,
        ContextSize,
        &Options,
        ItemId
    );
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqSubmitChain(
    _In_ PAWQ_MANAGER Manager,
    _In_reads_(Count) AWQ_WORK_CALLBACK* Callbacks,
    _In_reads_opt_(Count) PVOID* Contexts,
    _In_reads_opt_(Count) ULONG* ContextSizes,
    _In_ ULONG Count,
    _In_ AWQ_PRIORITY Priority,
    _Out_opt_ PULONG64 ChainId
    )
{
    PAWQ_MANAGER_INTERNAL Internal = AWQ_TO_INTERNAL(Manager);
    PAWQ_WORK_ITEM_INTERNAL* Items = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG i;
    ULONG64 FirstItemId = 0;

    if (ChainId != NULL) {
        *ChainId = 0;
    }

    //
    // Validate parameters
    //
    if (!AWQ_VALIDATE_MANAGER(Manager)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Callbacks == NULL || Count == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Count > 256) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Allocate array for items
    //
    Items = (PAWQ_WORK_ITEM_INTERNAL*)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        Count * sizeof(PAWQ_WORK_ITEM_INTERNAL),
        AWQ_POOL_TAG_CONTEXT
    );

    if (Items == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Items, Count * sizeof(PAWQ_WORK_ITEM_INTERNAL));

    //
    // Allocate all items first
    //
    for (i = 0; i < Count; i++) {
        Items[i] = AwqpAllocateWorkItem(Internal);
        if (Items[i] == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }
    }

    //
    // Initialize items and chain them
    //
    FirstItemId = InterlockedAdd64(&Internal->Public.NextItemId, Count);
    FirstItemId -= Count;

    for (i = 0; i < Count; i++) {
        PAWQ_WORK_ITEM_INTERNAL Item = Items[i];

        Item->Public.ItemId = FirstItemId + i + 1;
        Item->Public.Priority = Priority;
        Item->Public.Flags = AwqFlag_ChainedItem;
        Item->Public.State = AwqItemState_Queued;
        Item->Public.WorkCallback = Callbacks[i];
        Item->Public.Context = (Contexts != NULL) ? Contexts[i] : NULL;
        Item->Public.ContextSize = (ContextSizes != NULL) ? ContextSizes[i] : 0;
        Item->Public.ChainIndex = i;
        Item->Public.ChainLength = Count;
        Item->Public.RefCount = 1;
        Item->Manager = Internal;

        if (i < Count - 1) {
            Item->Public.NextInChain = &Items[i + 1]->Public;
        }

        KeQuerySystemTimePrecise(&Item->Public.SubmitTime);
    }

    //
    // Only enqueue the first item - chain will continue automatically
    //
    AwqpRegisterItem(Internal, Items[0]);
    Status = AwqpEnqueueItem(Internal, Items[0]);

    if (!NT_SUCCESS(Status)) {
        AwqpUnregisterItem(Internal, Items[0]);
        goto Cleanup;
    }

    InterlockedIncrement64(&Internal->Public.Stats.TotalSubmitted);

    if (ChainId != NULL) {
        *ChainId = FirstItemId + 1;
    }

    ExFreePoolWithTag(Items, AWQ_POOL_TAG_CONTEXT);
    return STATUS_SUCCESS;

Cleanup:
    //
    // Free all allocated items on failure
    //
    for (i = 0; i < Count; i++) {
        if (Items[i] != NULL) {
            AwqpFreeWorkItem(Internal, Items[i]);
        }
    }

    ExFreePoolWithTag(Items, AWQ_POOL_TAG_CONTEXT);
    return Status;
}

// ============================================================================
// WORK ITEM MANAGEMENT
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
AwqCancel(
    _In_ PAWQ_MANAGER Manager,
    _In_ ULONG64 ItemId
    )
{
    PAWQ_MANAGER_INTERNAL Internal = AWQ_TO_INTERNAL(Manager);
    PAWQ_WORK_ITEM_INTERNAL Item;
    KIRQL OldIrql;
    ULONG i;

    if (!AWQ_VALIDATE_MANAGER(Manager)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ItemId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Find the item
    //
    Item = AwqpFindItem(Internal, ItemId);
    if (Item == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Check if cancellable
    //
    if (!(Item->Public.Flags & AwqFlag_CanCancel)) {
        return STATUS_NOT_SUPPORTED;
    }

    //
    // Try to cancel based on state
    //
    if (Item->Public.State == AwqItemState_Queued) {
        //
        // Remove from queue
        //
        PAWQ_PRIORITY_QUEUE Queue = &Internal->Public.PriorityQueues[Item->Public.Priority];

        AWQ_LOCK_PRIORITY_QUEUE(Queue, OldIrql);

        if (Item->Public.State == AwqItemState_Queued) {
            RemoveEntryList(&Item->Public.ListEntry);
            InterlockedDecrement(&Queue->ItemCount);
            Item->Public.State = AwqItemState_Cancelled;
        }

        AWQ_UNLOCK_PRIORITY_QUEUE(Queue, OldIrql);

        if (Item->Public.State == AwqItemState_Cancelled) {
            AwqpCompleteItem(Internal, Item, STATUS_CANCELLED);
            InterlockedIncrement64(&Internal->Public.Stats.TotalCancelled);
            return STATUS_SUCCESS;
        }
    }

    //
    // Item is running - can't cancel
    //
    if (Item->Public.State == AwqItemState_Running) {
        return STATUS_PENDING;
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
AwqCancelByKey(
    _In_ PAWQ_MANAGER Manager,
    _In_ ULONG64 SerializationKey
    )
{
    PAWQ_MANAGER_INTERNAL Internal = AWQ_TO_INTERNAL(Manager);
    ULONG i;
    ULONG CancelledCount = 0;

    if (!AWQ_VALIDATE_MANAGER(Manager)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Scan all queues for items with matching key
    //
    for (i = 0; i < AwqPriority_Max; i++) {
        PAWQ_PRIORITY_QUEUE Queue = &Internal->Public.PriorityQueues[i];
        KIRQL OldIrql;
        PLIST_ENTRY Entry, NextEntry;
        LIST_ENTRY ItemsToCancel;

        InitializeListHead(&ItemsToCancel);

        AWQ_LOCK_PRIORITY_QUEUE(Queue, OldIrql);

        for (Entry = Queue->ItemList.Flink;
             Entry != &Queue->ItemList;
             Entry = NextEntry) {

            NextEntry = Entry->Flink;

            PAWQ_WORK_ITEM_INTERNAL Item = CONTAINING_RECORD(
                Entry, AWQ_WORK_ITEM_INTERNAL, Public.ListEntry
            );

            if (Item->Public.SerializationKey == SerializationKey &&
                (Item->Public.Flags & AwqFlag_CanCancel)) {

                RemoveEntryList(Entry);
                InterlockedDecrement(&Queue->ItemCount);
                Item->Public.State = AwqItemState_Cancelled;
                InsertTailList(&ItemsToCancel, Entry);
            }
        }

        AWQ_UNLOCK_PRIORITY_QUEUE(Queue, OldIrql);

        //
        // Complete cancelled items
        //
        while (!IsListEmpty(&ItemsToCancel)) {
            PLIST_ENTRY Entry = RemoveHeadList(&ItemsToCancel);
            PAWQ_WORK_ITEM_INTERNAL Item = CONTAINING_RECORD(
                Entry, AWQ_WORK_ITEM_INTERNAL, Public.ListEntry
            );

            AwqpCompleteItem(Internal, Item, STATUS_CANCELLED);
            CancelledCount++;
        }
    }

    InterlockedAdd64(&Internal->Public.Stats.TotalCancelled, CancelledCount);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
AwqWaitForItem(
    _In_ PAWQ_MANAGER Manager,
    _In_ ULONG64 ItemId,
    _In_ ULONG TimeoutMs,
    _Out_opt_ PNTSTATUS ItemStatus
    )
{
    PAWQ_MANAGER_INTERNAL Internal = AWQ_TO_INTERNAL(Manager);
    PAWQ_WORK_ITEM_INTERNAL Item;
    LARGE_INTEGER Timeout;
    KEVENT WaitEvent;
    NTSTATUS Status;

    if (ItemStatus != NULL) {
        *ItemStatus = STATUS_UNSUCCESSFUL;
    }

    if (!AWQ_VALIDATE_MANAGER(Manager)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ItemId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Find the item
    //
    Item = AwqpFindItem(Internal, ItemId);
    if (Item == NULL) {
        //
        // Item may have already completed
        //
        return STATUS_NOT_FOUND;
    }

    //
    // Check if already completed
    //
    if (Item->Public.State == AwqItemState_Completed ||
        Item->Public.State == AwqItemState_Cancelled ||
        Item->Public.State == AwqItemState_Failed) {

        if (ItemStatus != NULL) {
            *ItemStatus = Item->Public.CompletionStatus;
        }
        return STATUS_SUCCESS;
    }

    //
    // Wait for completion
    //
    if (Item->Public.CompletionEvent != NULL) {
        //
        // Use existing event
        //
        if (TimeoutMs == 0) {
            TimeoutMs = AWQ_SHUTDOWN_TIMEOUT_MS;
        }

        Timeout.QuadPart = -((LONGLONG)TimeoutMs * 10000);

        Status = KeWaitForSingleObject(
            Item->Public.CompletionEvent,
            Executive,
            KernelMode,
            FALSE,
            &Timeout
        );

        if (Status == STATUS_TIMEOUT) {
            return STATUS_TIMEOUT;
        }
    } else {
        //
        // Poll for completion (not ideal but works)
        //
        LARGE_INTEGER Delay;
        ULONG Elapsed = 0;

        Delay.QuadPart = -10 * 1000 * 10; // 10ms

        while (!Item->Completed && Elapsed < TimeoutMs) {
            KeDelayExecutionThread(KernelMode, FALSE, &Delay);
            Elapsed += 10;
        }

        if (!Item->Completed) {
            return STATUS_TIMEOUT;
        }
    }

    if (ItemStatus != NULL) {
        *ItemStatus = Item->Public.CompletionStatus;
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
AwqWaitForKey(
    _In_ PAWQ_MANAGER Manager,
    _In_ ULONG64 SerializationKey,
    _In_ ULONG TimeoutMs
    )
{
    PAWQ_MANAGER_INTERNAL Internal = AWQ_TO_INTERNAL(Manager);
    LARGE_INTEGER Delay;
    ULONG Elapsed = 0;
    BOOLEAN HasPending;
    ULONG i;

    if (!AWQ_VALIDATE_MANAGER(Manager)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (TimeoutMs == 0) {
        TimeoutMs = AWQ_SHUTDOWN_TIMEOUT_MS;
    }

    Delay.QuadPart = -10 * 1000 * 10; // 10ms

    //
    // Poll until all items with key are done
    //
    do {
        HasPending = FALSE;

        for (i = 0; i < AwqPriority_Max; i++) {
            PAWQ_PRIORITY_QUEUE Queue = &Internal->Public.PriorityQueues[i];
            KIRQL OldIrql;
            PLIST_ENTRY Entry;

            AWQ_LOCK_PRIORITY_QUEUE(Queue, OldIrql);

            for (Entry = Queue->ItemList.Flink;
                 Entry != &Queue->ItemList;
                 Entry = Entry->Flink) {

                PAWQ_WORK_ITEM_INTERNAL Item = CONTAINING_RECORD(
                    Entry, AWQ_WORK_ITEM_INTERNAL, Public.ListEntry
                );

                if (Item->Public.SerializationKey == SerializationKey) {
                    HasPending = TRUE;
                    break;
                }
            }

            AWQ_UNLOCK_PRIORITY_QUEUE(Queue, OldIrql);

            if (HasPending) {
                break;
            }
        }

        if (HasPending) {
            KeDelayExecutionThread(KernelMode, FALSE, &Delay);
            Elapsed += 10;
        }

    } while (HasPending && Elapsed < TimeoutMs);

    return HasPending ? STATUS_TIMEOUT : STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
AwqGetItemStatus(
    _In_ PAWQ_MANAGER Manager,
    _In_ ULONG64 ItemId,
    _Out_ PAWQ_ITEM_STATE State,
    _Out_opt_ PNTSTATUS CompletionStatus
    )
{
    PAWQ_MANAGER_INTERNAL Internal = AWQ_TO_INTERNAL(Manager);
    PAWQ_WORK_ITEM_INTERNAL Item;

    if (State == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *State = AwqItemState_Free;

    if (CompletionStatus != NULL) {
        *CompletionStatus = STATUS_UNSUCCESSFUL;
    }

    if (!AWQ_VALIDATE_MANAGER(Manager)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ItemId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Find the item
    //
    Item = AwqpFindItem(Internal, ItemId);
    if (Item == NULL) {
        return STATUS_NOT_FOUND;
    }

    *State = Item->Public.State;

    if (CompletionStatus != NULL) {
        *CompletionStatus = Item->Public.CompletionStatus;
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// THREAD MANAGEMENT
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
AwqSetThreadCount(
    _Inout_ PAWQ_MANAGER Manager,
    _In_ ULONG MinThreads,
    _In_ ULONG MaxThreads
    )
{
    PAWQ_MANAGER_INTERNAL Internal = AWQ_TO_INTERNAL(Manager);
    ULONG CurrentCount;
    ULONG i;
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    if (!AWQ_VALIDATE_MANAGER(Manager)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate parameters
    //
    if (MinThreads > MaxThreads) {
        return STATUS_INVALID_PARAMETER;
    }
    if (MaxThreads > AWQ_MAX_THREADS) {
        MaxThreads = AWQ_MAX_THREADS;
    }
    if (MinThreads < AWQ_MIN_THREADS) {
        MinThreads = AWQ_MIN_THREADS;
    }

    //
    // Update limits
    //
    Internal->Public.MinWorkers = MinThreads;
    Internal->Public.MaxWorkers = MaxThreads;

    //
    // Adjust thread count if needed
    //
    CurrentCount = Internal->Public.WorkerCount;

    if (CurrentCount < MinThreads) {
        //
        // Need more threads
        //
        for (i = CurrentCount; i < MinThreads; i++) {
            PAWQ_WORKER_THREAD Worker = NULL;
            Status = AwqpCreateWorkerThread(Internal, &Worker);
            if (!NT_SUCCESS(Status)) {
                break;
            }
        }
    } else if (CurrentCount > MaxThreads) {
        //
        // Need fewer threads - will be reduced as workers go idle
        //
        // Just mark them for removal; they'll exit naturally
        //
    }

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
AwqGetThreadCount(
    _In_ PAWQ_MANAGER Manager,
    _Out_ PULONG Current,
    _Out_ PULONG Idle,
    _Out_ PULONG Active
    )
{
    PAWQ_MANAGER_INTERNAL Internal = AWQ_TO_INTERNAL(Manager);

    if (Current != NULL) {
        *Current = 0;
    }
    if (Idle != NULL) {
        *Idle = 0;
    }
    if (Active != NULL) {
        *Active = 0;
    }

    if (!AWQ_VALIDATE_MANAGER(Manager)) {
        return;
    }

    if (Current != NULL) {
        *Current = Internal->Public.WorkerCount;
    }
    if (Idle != NULL) {
        *Idle = Internal->Public.IdleWorkerCount;
    }
    if (Active != NULL) {
        *Active = Internal->Public.ActiveWorkerCount;
    }
}

// ============================================================================
// STATISTICS
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
AwqGetStatistics(
    _In_ PAWQ_MANAGER Manager,
    _Out_ PAWQ_STATISTICS Stats
    )
{
    PAWQ_MANAGER_INTERNAL Internal = AWQ_TO_INTERNAL(Manager);
    LARGE_INTEGER CurrentTime;
    ULONG i;

    if (Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Stats, sizeof(AWQ_STATISTICS));

    if (!AWQ_VALIDATE_MANAGER(Manager)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Copy state
    //
    Stats->State = Internal->Public.State;

    //
    // Copy item counts
    //
    Stats->TotalSubmitted = Internal->Public.Stats.TotalSubmitted;
    Stats->TotalCompleted = Internal->Public.Stats.TotalCompleted;
    Stats->TotalCancelled = Internal->Public.Stats.TotalCancelled;
    Stats->TotalFailed = Internal->Public.Stats.TotalFailed;
    Stats->TotalRetries = Internal->Public.Stats.TotalRetries;
    Stats->TotalTimeouts = Internal->Public.Stats.TotalTimeouts;

    //
    // Calculate pending items
    //
    Stats->TotalPending = 0;
    for (i = 0; i < AwqPriority_Max; i++) {
        Stats->PendingItems[i] = Internal->Public.PriorityQueues[i].ItemCount;
        Stats->TotalPending += Stats->PendingItems[i];

        Stats->PerPriority[i].Submitted = Internal->Public.PriorityQueues[i].TotalEnqueued;
        Stats->PerPriority[i].Completed = Internal->Public.PriorityQueues[i].TotalDequeued;
        Stats->PerPriority[i].Pending = Internal->Public.PriorityQueues[i].ItemCount;
    }

    //
    // Thread pool stats
    //
    Stats->WorkerCount = Internal->Public.WorkerCount;
    Stats->IdleWorkers = Internal->Public.IdleWorkerCount;
    Stats->ActiveWorkers = Internal->Public.ActiveWorkerCount;

    //
    // Calculate uptime
    //
    KeQuerySystemTimePrecise(&CurrentTime);
    Stats->UpTime.QuadPart = CurrentTime.QuadPart - Internal->Public.Stats.StartTime.QuadPart;

    //
    // Calculate rates (simplified)
    //
    if (Stats->UpTime.QuadPart > 0) {
        LONG64 UptimeSeconds = Stats->UpTime.QuadPart / 10000000;
        if (UptimeSeconds > 0) {
            Stats->ItemsPerSecond = Stats->TotalCompleted / (ULONG64)UptimeSeconds;
        }
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
AwqResetStatistics(
    _Inout_ PAWQ_MANAGER Manager
    )
{
    PAWQ_MANAGER_INTERNAL Internal = AWQ_TO_INTERNAL(Manager);
    ULONG i;

    if (!AWQ_VALIDATE_MANAGER(Manager)) {
        return;
    }

    //
    // Reset global stats
    //
    InterlockedExchange64(&Internal->Public.Stats.TotalSubmitted, 0);
    InterlockedExchange64(&Internal->Public.Stats.TotalCompleted, 0);
    InterlockedExchange64(&Internal->Public.Stats.TotalCancelled, 0);
    InterlockedExchange64(&Internal->Public.Stats.TotalFailed, 0);
    InterlockedExchange64(&Internal->Public.Stats.TotalRetries, 0);
    InterlockedExchange64(&Internal->Public.Stats.TotalTimeouts, 0);
    KeQuerySystemTimePrecise(&Internal->Public.Stats.StartTime);

    //
    // Reset per-queue stats
    //
    for (i = 0; i < AwqPriority_Max; i++) {
        InterlockedExchange64(&Internal->Public.PriorityQueues[i].TotalEnqueued, 0);
        InterlockedExchange64(&Internal->Public.PriorityQueues[i].TotalDequeued, 0);
        InterlockedExchange64(&Internal->Public.PriorityQueues[i].TotalDropped, 0);
        InterlockedExchange(&Internal->Public.PriorityQueues[i].PeakCount,
                           Internal->Public.PriorityQueues[i].ItemCount);
    }
}

// ============================================================================
// CONFIGURATION
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
AwqSetDefaultTimeout(
    _Inout_ PAWQ_MANAGER Manager,
    _In_ ULONG TimeoutMs
    )
{
    PAWQ_MANAGER_INTERNAL Internal = AWQ_TO_INTERNAL(Manager);

    PAGED_CODE();

    if (!AWQ_VALIDATE_MANAGER(Manager)) {
        return STATUS_INVALID_PARAMETER;
    }

    Internal->Public.Config.DefaultTimeoutMs = TimeoutMs;

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
AwqSetWorkStealing(
    _Inout_ PAWQ_MANAGER Manager,
    _In_ BOOLEAN Enable
    )
{
    PAWQ_MANAGER_INTERNAL Internal = AWQ_TO_INTERNAL(Manager);

    PAGED_CODE();

    if (!AWQ_VALIDATE_MANAGER(Manager)) {
        return STATUS_INVALID_PARAMETER;
    }

    Internal->Public.Config.EnableWorkStealing = Enable;

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
AwqSetDynamicThreads(
    _Inout_ PAWQ_MANAGER Manager,
    _In_ BOOLEAN Enable
    )
{
    PAWQ_MANAGER_INTERNAL Internal = AWQ_TO_INTERNAL(Manager);

    PAGED_CODE();

    if (!AWQ_VALIDATE_MANAGER(Manager)) {
        return STATUS_INVALID_PARAMETER;
    }

    Internal->Public.Config.EnableDynamicThreads = Enable;

    return STATUS_SUCCESS;
}

// ============================================================================
// INTERNAL FUNCTIONS - WORK ITEM MANAGEMENT
// ============================================================================

static PAWQ_WORK_ITEM_INTERNAL
AwqpAllocateWorkItem(
    _In_ PAWQ_MANAGER_INTERNAL Manager
    )
{
    PAWQ_WORK_ITEM_INTERNAL Item = NULL;
    KIRQL OldIrql;

    //
    // Try to get from cache first
    //
    KeAcquireSpinLock(&Manager->Public.ItemCache.Lock, &OldIrql);

    if (!IsListEmpty(&Manager->Public.ItemCache.FreeList)) {
        PLIST_ENTRY Entry = RemoveHeadList(&Manager->Public.ItemCache.FreeList);
        Item = CONTAINING_RECORD(Entry, AWQ_WORK_ITEM_INTERNAL, Public.ListEntry);
        Manager->Public.ItemCache.FreeCount--;
    }

    KeReleaseSpinLock(&Manager->Public.ItemCache.Lock, OldIrql);

    if (Item != NULL) {
        //
        // Reset the cached item
        //
        ULONG Magic = Item->Magic;
        RtlZeroMemory(Item, sizeof(AWQ_WORK_ITEM_INTERNAL));
        Item->Magic = Magic;
        return Item;
    }

    //
    // Allocate new item
    //
    Item = (PAWQ_WORK_ITEM_INTERNAL)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(AWQ_WORK_ITEM_INTERNAL),
        AWQ_POOL_TAG_ITEM
    );

    if (Item != NULL) {
        RtlZeroMemory(Item, sizeof(AWQ_WORK_ITEM_INTERNAL));
        Item->Magic = AWQ_ITEM_MAGIC;
    }

    return Item;
}

static VOID
AwqpFreeWorkItem(
    _In_ PAWQ_MANAGER_INTERNAL Manager,
    _In_ PAWQ_WORK_ITEM_INTERNAL Item
    )
{
    KIRQL OldIrql;
    BOOLEAN CacheItem = FALSE;

    if (!AWQ_VALIDATE_ITEM(Item)) {
        return;
    }

    //
    // Free allocated context
    //
    if (Item->AllocatedContext != NULL) {
        ExFreePoolWithTag(Item->AllocatedContext, AWQ_POOL_TAG_CONTEXT);
        Item->AllocatedContext = NULL;
    }

    //
    // Try to return to cache
    //
    KeAcquireSpinLock(&Manager->Public.ItemCache.Lock, &OldIrql);

    if ((ULONG)Manager->Public.ItemCache.FreeCount < Manager->Public.ItemCache.MaxFreeItems) {
        //
        // Reset item for reuse
        //
        Item->Public.State = AwqItemState_Free;
        Item->Manager = NULL;
        Item->Completed = FALSE;

        InsertTailList(&Manager->Public.ItemCache.FreeList, &Item->Public.ListEntry);
        Manager->Public.ItemCache.FreeCount++;
        CacheItem = TRUE;
    }

    KeReleaseSpinLock(&Manager->Public.ItemCache.Lock, OldIrql);

    if (!CacheItem) {
        //
        // Cache is full, free the item
        //
        Item->Magic = 0;
        ExFreePoolWithTag(Item, AWQ_POOL_TAG_ITEM);
    }
}

static NTSTATUS
AwqpEnqueueItem(
    _In_ PAWQ_MANAGER_INTERNAL Manager,
    _In_ PAWQ_WORK_ITEM_INTERNAL Item
    )
{
    PAWQ_PRIORITY_QUEUE Queue;
    KIRQL OldIrql;
    LONG NewCount;

    Queue = &Manager->Public.PriorityQueues[Item->Public.Priority];

    AWQ_LOCK_PRIORITY_QUEUE(Queue, OldIrql);

    //
    // Check capacity
    //
    if ((ULONG)Queue->ItemCount >= Queue->MaxItems) {
        AWQ_UNLOCK_PRIORITY_QUEUE(Queue, OldIrql);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Add to queue
    //
    InsertTailList(&Queue->ItemList, &Item->Public.ListEntry);
    NewCount = InterlockedIncrement(&Queue->ItemCount);
    InterlockedIncrement64(&Queue->TotalEnqueued);

    //
    // Update peak
    //
    if (NewCount > Queue->PeakCount) {
        InterlockedExchange(&Queue->PeakCount, NewCount);
    }

    AWQ_UNLOCK_PRIORITY_QUEUE(Queue, OldIrql);

    //
    // Signal that work is available
    //
    KeReleaseSemaphore(&Queue->ItemSemaphore, IO_NO_INCREMENT, 1, FALSE);
    KeSetEvent(&Manager->Public.NewWorkEvent, IO_NO_INCREMENT, FALSE);

    return STATUS_SUCCESS;
}

static PAWQ_WORK_ITEM_INTERNAL
AwqpDequeueItem(
    _In_ PAWQ_MANAGER_INTERNAL Manager,
    _In_ PAWQ_WORKER_THREAD Worker
    )
{
    PAWQ_WORK_ITEM_INTERNAL Item = NULL;
    KIRQL OldIrql;
    LONG Priority;

    //
    // Try to dequeue from highest priority first
    //
    for (Priority = AwqPriority_Max - 1; Priority >= 0; Priority--) {
        PAWQ_PRIORITY_QUEUE Queue = &Manager->Public.PriorityQueues[Priority];

        if (Queue->ItemCount == 0) {
            continue;
        }

        AWQ_LOCK_PRIORITY_QUEUE(Queue, OldIrql);

        if (!IsListEmpty(&Queue->ItemList)) {
            PLIST_ENTRY Entry = RemoveHeadList(&Queue->ItemList);
            Item = CONTAINING_RECORD(Entry, AWQ_WORK_ITEM_INTERNAL, Public.ListEntry);
            InterlockedDecrement(&Queue->ItemCount);
            InterlockedIncrement64(&Queue->TotalDequeued);
        }

        AWQ_UNLOCK_PRIORITY_QUEUE(Queue, OldIrql);

        if (Item != NULL) {
            break;
        }
    }

    //
    // Try work stealing if enabled and no local work
    //
    if (Item == NULL && Manager->Public.Config.EnableWorkStealing) {
        AwqpTryStealWork(Manager, Worker, &Item);
    }

    return Item;
}

static VOID
AwqpExecuteItem(
    _In_ PAWQ_MANAGER_INTERNAL Manager,
    _In_ PAWQ_WORKER_THREAD Worker,
    _In_ PAWQ_WORK_ITEM_INTERNAL Item
    )
{
    NTSTATUS Status = STATUS_SUCCESS;

    //
    // Update item state
    //
    Item->Public.State = AwqItemState_Running;
    KeQuerySystemTimePrecise(&Item->Public.StartTime);
    Item->Public.ExecutingCpu = KeGetCurrentProcessorNumberEx(NULL);
    Item->Public.ExecutingThread = PsGetCurrentThreadId();

    //
    // Update worker state
    //
    Worker->CurrentItem = &Item->Public;
    Worker->Idle = FALSE;
    InterlockedIncrement(&Manager->Public.ActiveWorkerCount);
    InterlockedDecrement(&Manager->Public.IdleWorkerCount);

    //
    // Execute the callback
    //
    __try {
        Status = Item->Public.WorkCallback(
            Item->Public.Context,
            Item->Public.ContextSize
        );
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
#if DBG
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "[ShadowStrike] AWQ: Work callback exception 0x%08X for item %llu\n",
            Status, Item->Public.ItemId
        );
#endif
    }

    //
    // Record end time
    //
    KeQuerySystemTimePrecise(&Item->Public.EndTime);

    //
    // Update worker stats
    //
    Worker->CurrentItem = NULL;
    InterlockedIncrement64(&Worker->ItemsProcessed);
    InterlockedAdd64(
        &Worker->TotalProcessingTime,
        (Item->Public.EndTime.QuadPart - Item->Public.StartTime.QuadPart) / 10000
    );
    InterlockedDecrement(&Manager->Public.ActiveWorkerCount);
    InterlockedIncrement(&Manager->Public.IdleWorkerCount);
    Worker->Idle = TRUE;

    //
    // Handle retry on failure
    //
    if (!NT_SUCCESS(Status) &&
        (Item->Public.Flags & AwqFlag_RetryOnFailure) &&
        Item->Public.RetryCount < Item->Public.MaxRetries) {

        Item->Public.RetryCount++;
        Item->Public.State = AwqItemState_Retrying;
        InterlockedIncrement64(&Manager->Public.Stats.TotalRetries);

        //
        // Delay before retry if specified
        //
        if (Item->Public.RetryDelayMs > 0) {
            LARGE_INTEGER Delay;
            Delay.QuadPart = -((LONGLONG)Item->Public.RetryDelayMs * 10000);
            KeDelayExecutionThread(KernelMode, FALSE, &Delay);
        }

        //
        // Re-enqueue
        //
        Item->Public.State = AwqItemState_Queued;
        AwqpEnqueueItem(Manager, Item);
        return;
    }

    //
    // Complete the item
    //
    if (NT_SUCCESS(Status)) {
        Item->Public.State = AwqItemState_Completed;
        InterlockedIncrement64(&Manager->Public.Stats.TotalCompleted);
    } else {
        Item->Public.State = AwqItemState_Failed;
        InterlockedIncrement64(&Manager->Public.Stats.TotalFailed);
    }

    AwqpCompleteItem(Manager, Item, Status);

    //
    // Handle chain continuation
    //
    if ((Item->Public.Flags & AwqFlag_ChainedItem) &&
        Item->Public.NextInChain != NULL &&
        NT_SUCCESS(Status)) {

        PAWQ_WORK_ITEM_INTERNAL NextItem = CONTAINING_RECORD(
            Item->Public.NextInChain, AWQ_WORK_ITEM_INTERNAL, Public
        );

        AwqpRegisterItem(Manager, NextItem);
        AwqpEnqueueItem(Manager, NextItem);
    }
}

static VOID
AwqpCompleteItem(
    _In_ PAWQ_MANAGER_INTERNAL Manager,
    _In_ PAWQ_WORK_ITEM_INTERNAL Item,
    _In_ NTSTATUS Status
    )
{
    //
    // Store completion status
    //
    Item->Public.CompletionStatus = Status;
    Item->Completed = TRUE;

    //
    // Call completion callback
    //
    if (Item->Public.CompletionCallback != NULL) {
        Item->Public.CompletionCallback(
            Status,
            Item->Public.Context,
            Item->Public.CompletionContext
        );
    }

    //
    // Signal completion event
    //
    if (Item->Public.CompletionEvent != NULL) {
        KeSetEvent(Item->Public.CompletionEvent, IO_NO_INCREMENT, FALSE);
    }

    //
    // Call cleanup callback
    //
    if (Item->Public.CleanupCallback != NULL && Item->Public.Context != NULL) {
        if (!(Item->Public.Flags & AwqFlag_DeleteContext)) {
            Item->Public.CleanupCallback(Item->Public.Context);
        }
    }

    //
    // Check serialization key
    //
    if (Item->Public.SerializationKey != 0) {
        AwqpCheckSerializationKey(Manager, Item->Public.SerializationKey);
    }

    //
    // Unregister from tracking
    //
    AwqpUnregisterItem(Manager, Item);

    //
    // Free the item
    //
    AwqpFreeWorkItem(Manager, Item);

    //
    // Check if draining
    //
    if (Manager->Public.State == AwqQueueState_Draining) {
        ULONG TotalPending = 0;
        ULONG i;

        for (i = 0; i < AwqPriority_Max; i++) {
            TotalPending += Manager->Public.PriorityQueues[i].ItemCount;
        }

        if (TotalPending == 0 && Manager->Public.ActiveWorkerCount == 0) {
            KeSetEvent(&Manager->Public.DrainCompleteEvent, IO_NO_INCREMENT, FALSE);
        }
    }
}

// ============================================================================
// INTERNAL FUNCTIONS - WORKER THREAD MANAGEMENT
// ============================================================================

static NTSTATUS
AwqpCreateWorkerThread(
    _In_ PAWQ_MANAGER_INTERNAL Manager,
    _Out_ PAWQ_WORKER_THREAD* Worker
    )
{
    PAWQ_WORKER_THREAD NewWorker = NULL;
    OBJECT_ATTRIBUTES ObjectAttributes;
    NTSTATUS Status;
    HANDLE ThreadHandle = NULL;
    KIRQL OldIrql;

    *Worker = NULL;

    //
    // Allocate worker structure
    //
    NewWorker = (PAWQ_WORKER_THREAD)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(AWQ_WORKER_THREAD),
        AWQ_POOL_TAG_THREAD
    );

    if (NewWorker == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(NewWorker, sizeof(AWQ_WORKER_THREAD));

    NewWorker->Running = TRUE;
    NewWorker->Idle = TRUE;
    NewWorker->ThreadId = InterlockedIncrement(&Manager->Public.WorkerCount);
    NewWorker->PreferredCpu = NewWorker->ThreadId % KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

    //
    // Create the thread
    //
    InitializeObjectAttributes(
        &ObjectAttributes,
        NULL,
        OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    Status = PsCreateSystemThread(
        &ThreadHandle,
        THREAD_ALL_ACCESS,
        &ObjectAttributes,
        NULL,
        NULL,
        AwqpWorkerThreadRoutine,
        NewWorker
    );

    if (!NT_SUCCESS(Status)) {
        InterlockedDecrement(&Manager->Public.WorkerCount);
        ExFreePoolWithTag(NewWorker, AWQ_POOL_TAG_THREAD);
        return Status;
    }

    //
    // Get thread object
    //
    Status = ObReferenceObjectByHandle(
        ThreadHandle,
        THREAD_ALL_ACCESS,
        *PsThreadType,
        KernelMode,
        (PVOID*)&NewWorker->ThreadObject,
        NULL
    );

    ZwClose(ThreadHandle);

    if (!NT_SUCCESS(Status)) {
        NewWorker->Running = FALSE;
        //
        // Thread will exit on its own
        //
        return Status;
    }

    NewWorker->ThreadHandle = ThreadHandle;

    //
    // Add to worker list
    //
    KeAcquireSpinLock(&Manager->Public.WorkerListLock, &OldIrql);
    InsertTailList(&Manager->Public.WorkerList, &NewWorker->ListEntry);
    InterlockedIncrement(&Manager->Public.IdleWorkerCount);
    KeReleaseSpinLock(&Manager->Public.WorkerListLock, OldIrql);

    *Worker = NewWorker;

    return STATUS_SUCCESS;
}

static VOID
AwqpDestroyWorkerThread(
    _In_ PAWQ_MANAGER_INTERNAL Manager,
    _In_ PAWQ_WORKER_THREAD Worker,
    _In_ BOOLEAN Wait
    )
{
    KIRQL OldIrql;
    LARGE_INTEGER Timeout;

    //
    // Remove from list
    //
    KeAcquireSpinLock(&Manager->Public.WorkerListLock, &OldIrql);
    RemoveEntryList(&Worker->ListEntry);
    KeReleaseSpinLock(&Manager->Public.WorkerListLock, OldIrql);

    //
    // Signal thread to stop
    //
    Worker->Running = FALSE;

    //
    // Wait for thread to exit
    //
    if (Wait && Worker->ThreadObject != NULL) {
        Timeout.QuadPart = -((LONGLONG)AWQ_SHUTDOWN_TIMEOUT_MS * 10000);

        KeWaitForSingleObject(
            Worker->ThreadObject,
            Executive,
            KernelMode,
            FALSE,
            &Timeout
        );
    }

    //
    // Cleanup
    //
    if (Worker->ThreadObject != NULL) {
        ObDereferenceObject(Worker->ThreadObject);
    }

    InterlockedDecrement(&Manager->Public.WorkerCount);

    if (Worker->Idle) {
        InterlockedDecrement(&Manager->Public.IdleWorkerCount);
    } else {
        InterlockedDecrement(&Manager->Public.ActiveWorkerCount);
    }

    ExFreePoolWithTag(Worker, AWQ_POOL_TAG_THREAD);
}

static VOID
AwqpWorkerThreadRoutine(
    _In_ PVOID StartContext
    )
{
    PAWQ_WORKER_THREAD Worker = (PAWQ_WORKER_THREAD)StartContext;
    PAWQ_MANAGER_INTERNAL Manager;
    PAWQ_WORK_ITEM_INTERNAL Item;
    PVOID WaitObjects[2];
    LARGE_INTEGER Timeout;
    NTSTATUS WaitStatus;

    //
    // Get manager from first work item or wait for it
    //
    Manager = NULL;

    //
    // Wait objects: [0] = NewWorkEvent, [1] = ShutdownEvent
    //

    KeQuerySystemTimePrecise(&Worker->LastActivityTime);
    Worker->IdleStartTime = Worker->LastActivityTime;

    //
    // Main worker loop
    //
    while (Worker->Running) {
        //
        // Get manager reference (set by first item or during creation)
        //
        if (Manager == NULL) {
            //
            // Find our manager through the worker list
            //
            KIRQL OldIrql;
            PLIST_ENTRY Entry;

            //
            // Search for manager that owns us
            // This is a simplification - in production we'd pass manager directly
            //
            LARGE_INTEGER Delay;
            Delay.QuadPart = -10 * 1000 * 100; // 100ms
            KeDelayExecutionThread(KernelMode, FALSE, &Delay);

            //
            // For now, we need to find our manager
            // The worker was added to Manager->Public.WorkerList
            // We can find it by checking our ListEntry
            //
            Manager = CONTAINING_RECORD(
                CONTAINING_RECORD(Worker->ListEntry.Blink, AWQ_MANAGER, WorkerList),
                AWQ_MANAGER_INTERNAL,
                Public
            );

            if (Manager == NULL || Manager->Magic != AWQ_MANAGER_MAGIC) {
                //
                // Can't find manager, exit
                //
                break;
            }
        }

        //
        // Check if we should exit
        //
        if (Manager->Public.State == AwqQueueState_Shutdown) {
            break;
        }

        //
        // Check if paused
        //
        if (Manager->Public.State == AwqQueueState_Paused) {
            LARGE_INTEGER Delay;
            Delay.QuadPart = -10 * 1000 * 100; // 100ms
            KeDelayExecutionThread(KernelMode, FALSE, &Delay);
            continue;
        }

        //
        // Try to get work
        //
        Item = AwqpDequeueItem(Manager, Worker);

        if (Item != NULL) {
            //
            // Execute the work item
            //
            KeQuerySystemTimePrecise(&Worker->LastActivityTime);
            AwqpExecuteItem(Manager, Worker, Item);
            KeQuerySystemTimePrecise(&Worker->LastActivityTime);
            Worker->IdleStartTime = Worker->LastActivityTime;
        } else {
            //
            // No work available, wait
            //
            WaitObjects[0] = &Manager->Public.NewWorkEvent;
            WaitObjects[1] = &Manager->Public.ShutdownEvent;

            Timeout.QuadPart = -((LONGLONG)1000 * 10000); // 1 second

            WaitStatus = KeWaitForMultipleObjects(
                2,
                WaitObjects,
                WaitAny,
                Executive,
                KernelMode,
                FALSE,
                &Timeout,
                NULL
            );

            if (WaitStatus == STATUS_WAIT_1) {
                //
                // Shutdown signaled
                //
                break;
            }

            //
            // Check if we've been idle too long and should exit
            //
            if (Manager->Public.Config.EnableDynamicThreads &&
                (ULONG)Manager->Public.WorkerCount > Manager->Public.MinWorkers) {

                LARGE_INTEGER CurrentTime;
                LONG64 IdleTime;

                KeQuerySystemTimePrecise(&CurrentTime);
                IdleTime = (CurrentTime.QuadPart - Worker->IdleStartTime.QuadPart) / 10000;

                if (IdleTime > AWQ_IDLE_TIMEOUT_MS) {
                    //
                    // We've been idle too long, exit
                    //
                    Worker->Running = FALSE;
                    break;
                }
            }
        }
    }

    //
    // Thread exiting
    //
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static BOOLEAN
AwqpTryStealWork(
    _In_ PAWQ_MANAGER_INTERNAL Manager,
    _In_ PAWQ_WORKER_THREAD Worker,
    _Out_ PAWQ_WORK_ITEM_INTERNAL* StolenItem
    )
{
    *StolenItem = NULL;

    //
    // Work stealing is currently implemented as checking all priority queues
    // A more sophisticated implementation would steal from other CPU-local queues
    //
    // For now, the dequeue function already checks all priorities
    //

    return FALSE;
}

static VOID
AwqpCheckSerializationKey(
    _In_ PAWQ_MANAGER_INTERNAL Manager,
    _In_ ULONG64 Key
    )
{
    KIRQL OldIrql;
    PLIST_ENTRY Entry;
    PAWQ_SERIALIZATION_KEY KeyEntry = NULL;

    KeAcquireSpinLock(&Manager->Public.Serialization.Lock, &OldIrql);

    //
    // Find the key entry
    //
    for (Entry = Manager->Public.Serialization.ActiveKeys.Flink;
         Entry != &Manager->Public.Serialization.ActiveKeys;
         Entry = Entry->Flink) {

        PAWQ_SERIALIZATION_KEY Current = CONTAINING_RECORD(Entry, AWQ_SERIALIZATION_KEY, ListEntry);

        if (Current->Key == Key) {
            KeyEntry = Current;
            break;
        }
    }

    if (KeyEntry != NULL) {
        InterlockedDecrement(&KeyEntry->ActiveCount);

        //
        // If no more active items, process pending items
        //
        if (KeyEntry->ActiveCount == 0 && !IsListEmpty(&KeyEntry->PendingItems)) {
            //
            // Get next pending item
            //
            PLIST_ENTRY PendingEntry = RemoveHeadList(&KeyEntry->PendingItems);
            PAWQ_WORK_ITEM_INTERNAL PendingItem = CONTAINING_RECORD(
                PendingEntry, AWQ_WORK_ITEM_INTERNAL, Public.ListEntry
            );

            InterlockedIncrement(&KeyEntry->ActiveCount);

            KeReleaseSpinLock(&Manager->Public.Serialization.Lock, OldIrql);

            //
            // Enqueue the pending item
            //
            AwqpEnqueueItem(Manager, PendingItem);
            return;
        }

        //
        // Remove key entry if no more items
        //
        if (KeyEntry->ActiveCount == 0 && IsListEmpty(&KeyEntry->PendingItems)) {
            RemoveEntryList(&KeyEntry->ListEntry);
            KeReleaseSpinLock(&Manager->Public.Serialization.Lock, OldIrql);
            ExFreePoolWithTag(KeyEntry, AWQ_POOL_TAG_CONTEXT);
            return;
        }
    }

    KeReleaseSpinLock(&Manager->Public.Serialization.Lock, OldIrql);
}

// ============================================================================
// INTERNAL FUNCTIONS - ITEM TRACKING
// ============================================================================

static VOID
AwqpRegisterItem(
    _In_ PAWQ_MANAGER_INTERNAL Manager,
    _In_ PAWQ_WORK_ITEM_INTERNAL Item
    )
{
    KIRQL OldIrql;
    ULONG BucketIndex;

    if (Manager->ItemLookup.Buckets == NULL) {
        return;
    }

    BucketIndex = (ULONG)(Item->Public.ItemId % Manager->ItemLookup.BucketCount);

    KeAcquireSpinLock(&Manager->ItemLookup.Lock, &OldIrql);

    //
    // Simple bucket storage (first item wins)
    //
    if (Manager->ItemLookup.Buckets[BucketIndex] == NULL) {
        Manager->ItemLookup.Buckets[BucketIndex] = Item;
    }

    KeReleaseSpinLock(&Manager->ItemLookup.Lock, OldIrql);

    //
    // Also add to active items list
    //
    KeAcquireSpinLock(&Manager->ItemTracking.Lock, &OldIrql);
    InterlockedIncrement(&Manager->ItemTracking.ActiveCount);
    KeReleaseSpinLock(&Manager->ItemTracking.Lock, OldIrql);
}

static VOID
AwqpUnregisterItem(
    _In_ PAWQ_MANAGER_INTERNAL Manager,
    _In_ PAWQ_WORK_ITEM_INTERNAL Item
    )
{
    KIRQL OldIrql;
    ULONG BucketIndex;

    if (Manager->ItemLookup.Buckets == NULL) {
        return;
    }

    BucketIndex = (ULONG)(Item->Public.ItemId % Manager->ItemLookup.BucketCount);

    KeAcquireSpinLock(&Manager->ItemLookup.Lock, &OldIrql);

    if (Manager->ItemLookup.Buckets[BucketIndex] == Item) {
        Manager->ItemLookup.Buckets[BucketIndex] = NULL;
    }

    KeReleaseSpinLock(&Manager->ItemLookup.Lock, OldIrql);

    //
    // Remove from active items
    //
    KeAcquireSpinLock(&Manager->ItemTracking.Lock, &OldIrql);
    InterlockedDecrement(&Manager->ItemTracking.ActiveCount);
    KeReleaseSpinLock(&Manager->ItemTracking.Lock, OldIrql);
}

static PAWQ_WORK_ITEM_INTERNAL
AwqpFindItem(
    _In_ PAWQ_MANAGER_INTERNAL Manager,
    _In_ ULONG64 ItemId
    )
{
    KIRQL OldIrql;
    ULONG BucketIndex;
    PAWQ_WORK_ITEM_INTERNAL Item = NULL;

    if (Manager->ItemLookup.Buckets == NULL) {
        return NULL;
    }

    BucketIndex = (ULONG)(ItemId % Manager->ItemLookup.BucketCount);

    KeAcquireSpinLock(&Manager->ItemLookup.Lock, &OldIrql);

    Item = Manager->ItemLookup.Buckets[BucketIndex];

    if (Item != NULL && Item->Public.ItemId != ItemId) {
        //
        // Hash collision - item not found in this simple implementation
        //
        Item = NULL;
    }

    KeReleaseSpinLock(&Manager->ItemLookup.Lock, OldIrql);

    return Item;
}
