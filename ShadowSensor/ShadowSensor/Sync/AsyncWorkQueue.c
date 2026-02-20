/**
 * ============================================================================
 * ShadowStrike NGAV — Async Work Queue Implementation
 * ============================================================================
 *
 * @file AsyncWorkQueue.c
 *
 * Enterprise-grade asynchronous work queue for kernel-mode EDR operations.
 *
 * Architecture:
 *   - Four priority queues (Critical > High > Normal > Low)
 *   - Worker thread pool with dynamic idle-timeout scaling
 *   - EX_PUSH_LOCK for all synchronization (IRQL <= APC_LEVEL)
 *   - EX_RUNDOWN_REF for safe concurrent shutdown
 *   - Reference-counted items for safe lookup/wait/cancel
 *   - Chained hash table for O(1) item lookup by ID
 *   - All callbacks invoked at PASSIVE_LEVEL outside any lock
 *   - Serialized execution enforced at enqueue time
 *
 * @copyright (c) ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "AsyncWorkQueue.h"
#include <ntstrsafe.h>

// ============================================================================
// PAGE segment declarations (NOT INIT — callable after DriverEntry)
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, AwqInitialize)
#pragma alloc_text(PAGE, AwqShutdown)
#pragma alloc_text(PAGE, AwqPause)
#pragma alloc_text(PAGE, AwqResume)
#pragma alloc_text(PAGE, AwqDrain)
#pragma alloc_text(PAGE, AwqSetThreadCount)
#pragma alloc_text(PAGE, AwqSetDefaultTimeout)
#pragma alloc_text(PAGE, AwqSetDynamicThreads)
#pragma alloc_text(PAGE, AwqWaitForItem)
#endif

// ============================================================================
// Internal constants
// ============================================================================

#define AWQ_MANAGER_MAGIC   0x4D515741  /* 'AWQM' */
#define AWQ_ITEM_MAGIC      0x49515741  /* 'AWQI' */

// ============================================================================
// Internal: hash bucket entry (chained)
// ============================================================================

typedef struct _AWQ_HASH_ENTRY {
    LIST_ENTRY              HashLink;
    struct _AWQ_WORK_ITEM_I *Item;
} AWQ_HASH_ENTRY, *PAWQ_HASH_ENTRY;

// ============================================================================
// Internal work item
// ============================================================================

typedef struct _AWQ_WORK_ITEM_I {
    LIST_ENTRY              QueueLink;      // on priority queue
    LIST_ENTRY              TrackLink;      // on active-items list

    ULONG                   Magic;
    volatile LONG           RefCount;       // ref-counted for safe access

    ULONG64                 ItemId;
    AWQ_PRIORITY            Priority;
    AWQ_WORK_FLAGS          Flags;
    volatile LONG           State;          // AWQ_ITEM_STATE via interlocked

    PAWQ_WORK_CALLBACK      WorkCallback;
    PAWQ_COMPLETION_CALLBACK CompletionCallback;
    PAWQ_CLEANUP_CALLBACK   CleanupCallback;
    PVOID                   CompletionContext;

    PVOID                   Context;
    ULONG                   ContextSize;
    PVOID                   AllocatedContext;   // non-NULL if we own the copy

    ULONG                   TimeoutMs;
    ULONG                   RetryCount;
    ULONG                   MaxRetries;
    ULONG                   RetryDelayMs;
    ULONG64                 SerializationKey;

    KEVENT                  CompletionEvent;    // embedded, always valid
    NTSTATUS                CompletionStatus;

    // Chain support
    struct _AWQ_WORK_ITEM_I *NextInChain;
    ULONG                   ChainIndex;
    ULONG                   ChainLength;

    // Hash entry (embedded, one per item)
    AWQ_HASH_ENTRY          HashEntry;

    // Back-pointer (set at allocation)
    struct _AWQ_MANAGER_I   *Manager;

    LARGE_INTEGER           SubmitTime;

} AWQ_WORK_ITEM_I, *PAWQ_WORK_ITEM_I;

// ============================================================================
// Internal per-priority queue
// ============================================================================

typedef struct _AWQ_PQUEUE {
    LIST_ENTRY              ItemList;
    EX_PUSH_LOCK            Lock;
    volatile LONG           ItemCount;
    ULONG                   MaxItems;

    volatile LONG64         TotalEnqueued;
    volatile LONG64         TotalDequeued;
    volatile LONG64         TotalDropped;
} AWQ_PQUEUE, *PAWQ_PQUEUE;

// ============================================================================
// Internal worker thread
// ============================================================================

typedef struct _AWQ_WORKER_I {
    LIST_ENTRY              ListEntry;
    PKTHREAD                ThreadObject;   // referenced
    ULONG                   ThreadId;
    volatile LONG           Running;        // 1=running, 0=stop requested
    volatile LONG           Idle;           // 1=idle, 0=active
    LARGE_INTEGER           IdleStartTime;
    LARGE_INTEGER           LastActivityTime;
    volatile LONG64         ItemsProcessed;
    struct _AWQ_MANAGER_I   *Manager;       // direct pointer, no CONTAINING_RECORD hack
} AWQ_WORKER_I, *PAWQ_WORKER_I;

// ============================================================================
// Internal serialization key tracker
// ============================================================================

typedef struct _AWQ_SKEY {
    LIST_ENTRY              ListEntry;
    ULONG64                 Key;
    volatile LONG           ActiveCount;    // items currently executing
    LIST_ENTRY              PendingItems;   // items waiting for execution
} AWQ_SKEY, *PAWQ_SKEY;

// ============================================================================
// Internal manager
// ============================================================================

typedef struct _AWQ_MANAGER_I {
    ULONG                   Magic;
    volatile LONG           Initialized;
    volatile LONG           State;          // AWQ_QUEUE_STATE via interlocked

    EX_RUNDOWN_REF          RundownRef;

    // Priority queues
    AWQ_PQUEUE              Queues[AwqPriority_Count];

    // Worker threads
    LIST_ENTRY              WorkerList;
    EX_PUSH_LOCK            WorkerLock;
    volatile LONG           WorkerCount;
    volatile LONG           IdleWorkerCount;
    volatile LONG           ActiveWorkerCount;
    ULONG                   MinWorkers;
    ULONG                   MaxWorkers;

    // Thread signaling
    KEVENT                  NewWorkEvent;       // auto-reset
    KEVENT                  ShutdownEvent;       // manual-reset
    KEVENT                  DrainCompleteEvent;  // manual-reset

    // Item ID generation
    volatile LONG64         NextItemId;

    // Chained hash table for item lookup
    struct {
        LIST_ENTRY          *Buckets;       // array of list heads
        EX_PUSH_LOCK        Lock;
        ULONG               BucketCount;
    } Hash;

    // Active item tracking
    struct {
        LIST_ENTRY          List;
        EX_PUSH_LOCK        Lock;
        volatile LONG       Count;
    } ActiveItems;

    // Serialization
    struct {
        LIST_ENTRY          KeyList;
        EX_PUSH_LOCK        Lock;
    } Serialization;

    // Work item cache (lookaside-like free list)
    struct {
        LIST_ENTRY          FreeList;
        EX_PUSH_LOCK        Lock;
        volatile LONG       FreeCount;
        ULONG               MaxFree;
    } Cache;

    // Configuration
    struct {
        ULONG               DefaultTimeoutMs;
        ULONG               MaxQueueSize;
        volatile LONG       EnableDynamicThreads;
    } Config;

    // Statistics
    struct {
        volatile LONG64     TotalSubmitted;
        volatile LONG64     TotalCompleted;
        volatile LONG64     TotalCancelled;
        volatile LONG64     TotalFailed;
        volatile LONG64     TotalRetries;
        LARGE_INTEGER       StartTime;
    } Stats;

} AWQ_MANAGER_I, *PAWQ_MANAGER_I;

// ============================================================================
// Forward declarations
// ============================================================================

static VOID AwqpWorkerThread(_In_ PVOID Ctx);

static PAWQ_WORK_ITEM_I AwqpAllocItem(_In_ PAWQ_MANAGER_I Mgr);
static VOID AwqpFreeItem(_In_ PAWQ_MANAGER_I Mgr, _In_ PAWQ_WORK_ITEM_I Item);

static VOID AwqpRefItem(_In_ PAWQ_WORK_ITEM_I Item);
static VOID AwqpDerefItem(_In_ PAWQ_MANAGER_I Mgr, _In_ PAWQ_WORK_ITEM_I Item);

static NTSTATUS AwqpEnqueue(_In_ PAWQ_MANAGER_I Mgr, _In_ PAWQ_WORK_ITEM_I Item);
static PAWQ_WORK_ITEM_I AwqpDequeue(_In_ PAWQ_MANAGER_I Mgr);

static VOID AwqpRegisterItem(_In_ PAWQ_MANAGER_I Mgr, _In_ PAWQ_WORK_ITEM_I Item);
static VOID AwqpUnregisterItem(_In_ PAWQ_MANAGER_I Mgr, _In_ PAWQ_WORK_ITEM_I Item);
static PAWQ_WORK_ITEM_I AwqpFindItem(_In_ PAWQ_MANAGER_I Mgr, _In_ ULONG64 Id);

static VOID AwqpCompleteItem(_In_ PAWQ_MANAGER_I Mgr,
                             _In_ PAWQ_WORK_ITEM_I Item,
                             _In_ NTSTATUS Status);
static VOID AwqpExecuteItem(_In_ PAWQ_MANAGER_I Mgr,
                            _In_ PAWQ_WORKER_I Worker,
                            _In_ PAWQ_WORK_ITEM_I Item);

static NTSTATUS AwqpCreateWorker(_In_ PAWQ_MANAGER_I Mgr, _Out_ PAWQ_WORKER_I *Out);

static NTSTATUS AwqpSerializationCheck(_In_ PAWQ_MANAGER_I Mgr, _In_ PAWQ_WORK_ITEM_I Item);
static VOID AwqpSerializationRelease(_In_ PAWQ_MANAGER_I Mgr, _In_ ULONG64 Key);

static VOID AwqpCheckDrainComplete(_In_ PAWQ_MANAGER_I Mgr);

// ============================================================================
// Helper: safe acquire/release for push lock with critical region
// ============================================================================

#define AWQ_LOCK_EXCLUSIVE(pLock)    \
    do { KeEnterCriticalRegion(); ExAcquirePushLockExclusive(pLock); } while(0)

#define AWQ_UNLOCK_EXCLUSIVE(pLock)  \
    do { ExReleasePushLockExclusive(pLock); KeLeaveCriticalRegion(); } while(0)

#define AWQ_LOCK_SHARED(pLock)      \
    do { KeEnterCriticalRegion(); ExAcquirePushLockShared(pLock); } while(0)

#define AWQ_UNLOCK_SHARED(pLock)    \
    do { ExReleasePushLockShared(pLock); KeLeaveCriticalRegion(); } while(0)

// ============================================================================
// Validate handle → internal pointer
// ============================================================================

static __forceinline PAWQ_MANAGER_I
AwqpFromHandle(
    _In_ HAWQ_MANAGER Handle
    )
{
    PAWQ_MANAGER_I Mgr = (PAWQ_MANAGER_I)(ULONG_PTR)Handle;
    if (Mgr == NULL) return NULL;
    if (Mgr->Magic != AWQ_MANAGER_MAGIC) return NULL;
    if (Mgr->Initialized == 0) return NULL;
    return Mgr;
}

// ============================================================================
//  AwqInitialize
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqInitialize(
    _Out_ HAWQ_MANAGER *Handle,
    _In_ ULONG MinThreads,
    _In_ ULONG MaxThreads,
    _In_ ULONG MaxQueueSize
    )
{
    PAWQ_MANAGER_I Mgr = NULL;
    NTSTATUS Status;
    ULONG i;
    ULONG ProcessorCount;

    PAGED_CODE();

    if (Handle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *Handle = NULL;

    ProcessorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

    //
    // Clamp parameters
    //
    if (MinThreads == 0) MinThreads = AWQ_MIN_THREADS;
    if (MaxThreads == 0) MaxThreads = min(ProcessorCount * AWQ_DEFAULT_THREADS_PER_CPU, AWQ_MAX_THREADS);
    if (MinThreads > MaxThreads) MinThreads = MaxThreads;
    if (MaxThreads > AWQ_MAX_THREADS) MaxThreads = AWQ_MAX_THREADS;
    if (MinThreads < AWQ_MIN_THREADS) MinThreads = AWQ_MIN_THREADS;
    if (MaxQueueSize == 0) MaxQueueSize = AWQ_DEFAULT_QUEUE_SIZE;
    if (MaxQueueSize < AWQ_MIN_QUEUE_SIZE) MaxQueueSize = AWQ_MIN_QUEUE_SIZE;
    if (MaxQueueSize > AWQ_MAX_QUEUE_SIZE) MaxQueueSize = AWQ_MAX_QUEUE_SIZE;

    //
    // Allocate manager (ExAllocatePool2 zero-inits)
    //
    Mgr = (PAWQ_MANAGER_I)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(AWQ_MANAGER_I), AWQ_POOL_TAG_MGR);
    if (Mgr == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Mgr->Magic = AWQ_MANAGER_MAGIC;
    InterlockedExchange(&Mgr->State, (LONG)AwqQueueState_Running);

    ExInitializeRundownProtection(&Mgr->RundownRef);

    //
    // Priority queues
    //
    for (i = 0; i < AwqPriority_Count; i++) {
        InitializeListHead(&Mgr->Queues[i].ItemList);
        ExInitializePushLock(&Mgr->Queues[i].Lock);
        Mgr->Queues[i].MaxItems = MaxQueueSize;
    }

    //
    // Worker thread list
    //
    InitializeListHead(&Mgr->WorkerList);
    ExInitializePushLock(&Mgr->WorkerLock);
    Mgr->MinWorkers = MinThreads;
    Mgr->MaxWorkers = MaxThreads;

    //
    // Events
    //
    KeInitializeEvent(&Mgr->NewWorkEvent, SynchronizationEvent, FALSE);
    KeInitializeEvent(&Mgr->ShutdownEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&Mgr->DrainCompleteEvent, NotificationEvent, FALSE);

    //
    // ID generator (start at 1)
    //
    Mgr->NextItemId = 1;

    //
    // Hash table (chained)
    //
    Mgr->Hash.BucketCount = AWQ_HASH_BUCKET_COUNT;
    Mgr->Hash.Buckets = (LIST_ENTRY *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        Mgr->Hash.BucketCount * sizeof(LIST_ENTRY),
        AWQ_POOL_TAG_HASH);
    if (Mgr->Hash.Buckets == NULL) {
        ExFreePoolWithTag(Mgr, AWQ_POOL_TAG_MGR);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    for (i = 0; i < Mgr->Hash.BucketCount; i++) {
        InitializeListHead(&Mgr->Hash.Buckets[i]);
    }
    ExInitializePushLock(&Mgr->Hash.Lock);

    //
    // Active item tracking
    //
    InitializeListHead(&Mgr->ActiveItems.List);
    ExInitializePushLock(&Mgr->ActiveItems.Lock);

    //
    // Serialization
    //
    InitializeListHead(&Mgr->Serialization.KeyList);
    ExInitializePushLock(&Mgr->Serialization.Lock);

    //
    // Item cache
    //
    InitializeListHead(&Mgr->Cache.FreeList);
    ExInitializePushLock(&Mgr->Cache.Lock);
    Mgr->Cache.MaxFree = AWQ_ITEM_CACHE_SIZE;

    //
    // Pre-populate cache
    //
    for (i = 0; i < min(AWQ_ITEM_CACHE_SIZE / 4, 32); i++) {
        PAWQ_WORK_ITEM_I Item = (PAWQ_WORK_ITEM_I)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(AWQ_WORK_ITEM_I), AWQ_POOL_TAG_ITEM);
        if (Item != NULL) {
            Item->Magic = AWQ_ITEM_MAGIC;
            InsertTailList(&Mgr->Cache.FreeList, &Item->QueueLink);
            Mgr->Cache.FreeCount++;
        }
    }

    //
    // Configuration
    //
    Mgr->Config.DefaultTimeoutMs = AWQ_DEFAULT_TIMEOUT_MS;
    Mgr->Config.MaxQueueSize = MaxQueueSize;
    InterlockedExchange(&Mgr->Config.EnableDynamicThreads, 1);

    //
    // Statistics
    //
    KeQuerySystemTimePrecise(&Mgr->Stats.StartTime);

    //
    // Create initial workers
    //
    for (i = 0; i < MinThreads; i++) {
        PAWQ_WORKER_I W = NULL;
        Status = AwqpCreateWorker(Mgr, &W);
        if (!NT_SUCCESS(Status)) {
            if (Mgr->WorkerCount == 0) {
                //
                // No workers at all — tear down and fail
                //
                while (!IsListEmpty(&Mgr->Cache.FreeList)) {
                    PLIST_ENTRY E = RemoveHeadList(&Mgr->Cache.FreeList);
                    PAWQ_WORK_ITEM_I It = CONTAINING_RECORD(E, AWQ_WORK_ITEM_I, QueueLink);
                    ExFreePoolWithTag(It, AWQ_POOL_TAG_ITEM);
                }
                ExFreePoolWithTag(Mgr->Hash.Buckets, AWQ_POOL_TAG_HASH);
                ExFreePoolWithTag(Mgr, AWQ_POOL_TAG_MGR);
                return Status;
            }
            break;  // partial success is acceptable
        }
    }

    InterlockedExchange(&Mgr->Initialized, 1);
    *Handle = (HAWQ_MANAGER)(ULONG_PTR)Mgr;

    return STATUS_SUCCESS;
}

// ============================================================================
//  AwqShutdown
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
VOID
AwqShutdown(
    _In_ HAWQ_MANAGER Handle
    )
{
    PAWQ_MANAGER_I Mgr;
    LIST_ENTRY WorkersToDestroy;
    PLIST_ENTRY Entry;
    ULONG i;
    LARGE_INTEGER Timeout;

    PAGED_CODE();

    Mgr = AwqpFromHandle(Handle);
    if (Mgr == NULL) return;

    //
    // Idempotent: only one caller wins
    //
    if (InterlockedCompareExchange(&Mgr->Initialized, 0, 1) != 1) {
        return;
    }

    InterlockedExchange(&Mgr->State, (LONG)AwqQueueState_ShuttingDown);

    //
    // Signal shutdown, wake all workers
    //
    KeSetEvent(&Mgr->ShutdownEvent, IO_NO_INCREMENT, FALSE);
    KeSetEvent(&Mgr->NewWorkEvent, IO_NO_INCREMENT, FALSE);

    //
    // Wait for all in-flight API calls to drain
    //
    ExWaitForRundownProtectionRelease(&Mgr->RundownRef);

    //
    // Collect all workers under lock
    //
    InitializeListHead(&WorkersToDestroy);

    AWQ_LOCK_EXCLUSIVE(&Mgr->WorkerLock);
    while (!IsListEmpty(&Mgr->WorkerList)) {
        Entry = RemoveHeadList(&Mgr->WorkerList);
        InsertTailList(&WorkersToDestroy, Entry);
    }
    AWQ_UNLOCK_EXCLUSIVE(&Mgr->WorkerLock);

    //
    // Signal each worker to stop and wait for thread exit
    //
    Timeout.QuadPart = -((LONGLONG)AWQ_SHUTDOWN_TIMEOUT_MS * 10000);

    while (!IsListEmpty(&WorkersToDestroy)) {
        Entry = RemoveHeadList(&WorkersToDestroy);
        PAWQ_WORKER_I W = CONTAINING_RECORD(Entry, AWQ_WORKER_I, ListEntry);

        InterlockedExchange(&W->Running, 0);

        if (W->ThreadObject != NULL) {
            KeWaitForSingleObject(W->ThreadObject, Executive, KernelMode, FALSE, &Timeout);
            ObDereferenceObject(W->ThreadObject);
        }
        ExFreePoolWithTag(W, AWQ_POOL_TAG_THREAD);
    }

    //
    // Cancel and free all remaining queued items.
    // Callbacks are called outside the lock (free-outside-lock pattern).
    //
    for (i = 0; i < AwqPriority_Count; i++) {
        LIST_ENTRY FreeList;
        InitializeListHead(&FreeList);

        AWQ_LOCK_EXCLUSIVE(&Mgr->Queues[i].Lock);
        while (!IsListEmpty(&Mgr->Queues[i].ItemList)) {
            Entry = RemoveHeadList(&Mgr->Queues[i].ItemList);
            InsertTailList(&FreeList, Entry);
            InterlockedDecrement(&Mgr->Queues[i].ItemCount);
        }
        AWQ_UNLOCK_EXCLUSIVE(&Mgr->Queues[i].Lock);

        while (!IsListEmpty(&FreeList)) {
            Entry = RemoveHeadList(&FreeList);
            PAWQ_WORK_ITEM_I Item = CONTAINING_RECORD(Entry, AWQ_WORK_ITEM_I, QueueLink);

            // Cancel any chained successors before completing this item
            {
                PAWQ_WORK_ITEM_I Chain = Item->NextInChain;
                Item->NextInChain = NULL;
                while (Chain != NULL) {
                    PAWQ_WORK_ITEM_I Next = Chain->NextInChain;
                    Chain->NextInChain = NULL;
                    InterlockedExchange(&Chain->State, (LONG)AwqItemState_Cancelled);
                    AwqpCompleteItem(Mgr, Chain, STATUS_CANCELLED);
                    Chain = Next;
                }
            }

            InterlockedExchange(&Item->State, (LONG)AwqItemState_Cancelled);
            AwqpCompleteItem(Mgr, Item, STATUS_CANCELLED);
        }
    }

    //
    // Free cached items
    //
    AWQ_LOCK_EXCLUSIVE(&Mgr->Cache.Lock);
    while (!IsListEmpty(&Mgr->Cache.FreeList)) {
        Entry = RemoveHeadList(&Mgr->Cache.FreeList);
        PAWQ_WORK_ITEM_I Item = CONTAINING_RECORD(Entry, AWQ_WORK_ITEM_I, QueueLink);
        ExFreePoolWithTag(Item, AWQ_POOL_TAG_ITEM);
    }
    AWQ_UNLOCK_EXCLUSIVE(&Mgr->Cache.Lock);

    //
    // Free serialization keys
    //
    AWQ_LOCK_EXCLUSIVE(&Mgr->Serialization.Lock);
    while (!IsListEmpty(&Mgr->Serialization.KeyList)) {
        Entry = RemoveHeadList(&Mgr->Serialization.KeyList);
        PAWQ_SKEY SK = CONTAINING_RECORD(Entry, AWQ_SKEY, ListEntry);

        // Complete pending items properly — they are registered in the hash
        // table and active items list. Raw ExFreePoolWithTag would leave
        // dangling entries → use-after-free during hash cleanup.
        while (!IsListEmpty(&SK->PendingItems)) {
            PLIST_ENTRY PE = RemoveHeadList(&SK->PendingItems);
            PAWQ_WORK_ITEM_I PI = CONTAINING_RECORD(PE, AWQ_WORK_ITEM_I, QueueLink);
            InterlockedExchange(&PI->State, (LONG)AwqItemState_Cancelled);
            AwqpCompleteItem(Mgr, PI, STATUS_CANCELLED);
        }
        ExFreePoolWithTag(SK, AWQ_POOL_TAG_SKEY);
    }
    AWQ_UNLOCK_EXCLUSIVE(&Mgr->Serialization.Lock);

    //
    // Free hash table
    //
    if (Mgr->Hash.Buckets != NULL) {
        //
        // Free any remaining hash entries
        //
        for (i = 0; i < Mgr->Hash.BucketCount; i++) {
            while (!IsListEmpty(&Mgr->Hash.Buckets[i])) {
                Entry = RemoveHeadList(&Mgr->Hash.Buckets[i]);
                // Hash entries are embedded in items, no separate free needed
            }
        }
        ExFreePoolWithTag(Mgr->Hash.Buckets, AWQ_POOL_TAG_HASH);
    }

    //
    // Clear magic and free manager
    //
    Mgr->Magic = 0;
    ExFreePoolWithTag(Mgr, AWQ_POOL_TAG_MGR);
}

// ============================================================================
//  AwqPause / AwqResume
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqPause(
    _In_ HAWQ_MANAGER Handle
    )
{
    PAWQ_MANAGER_I Mgr;

    PAGED_CODE();

    Mgr = AwqpFromHandle(Handle);
    if (Mgr == NULL) return STATUS_INVALID_PARAMETER;
    if (!ExAcquireRundownProtection(&Mgr->RundownRef)) return STATUS_DELETE_PENDING;

    if (InterlockedCompareExchange(&Mgr->State,
            (LONG)AwqQueueState_Paused,
            (LONG)AwqQueueState_Running) != (LONG)AwqQueueState_Running) {
        ExReleaseRundownProtection(&Mgr->RundownRef);
        return STATUS_INVALID_DEVICE_STATE;
    }

    ExReleaseRundownProtection(&Mgr->RundownRef);
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqResume(
    _In_ HAWQ_MANAGER Handle
    )
{
    PAWQ_MANAGER_I Mgr;

    PAGED_CODE();

    Mgr = AwqpFromHandle(Handle);
    if (Mgr == NULL) return STATUS_INVALID_PARAMETER;
    if (!ExAcquireRundownProtection(&Mgr->RundownRef)) return STATUS_DELETE_PENDING;

    if (InterlockedCompareExchange(&Mgr->State,
            (LONG)AwqQueueState_Running,
            (LONG)AwqQueueState_Paused) != (LONG)AwqQueueState_Paused) {
        ExReleaseRundownProtection(&Mgr->RundownRef);
        return STATUS_INVALID_DEVICE_STATE;
    }

    KeSetEvent(&Mgr->NewWorkEvent, IO_NO_INCREMENT, FALSE);

    ExReleaseRundownProtection(&Mgr->RundownRef);
    return STATUS_SUCCESS;
}

// ============================================================================
//  AwqDrain
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqDrain(
    _In_ HAWQ_MANAGER Handle,
    _In_ ULONG TimeoutMs
    )
{
    PAWQ_MANAGER_I Mgr;
    NTSTATUS Status;
    LARGE_INTEGER Timeout;
    ULONG TotalPending = 0;
    ULONG i;

    PAGED_CODE();

    Mgr = AwqpFromHandle(Handle);
    if (Mgr == NULL) return STATUS_INVALID_PARAMETER;
    if (!ExAcquireRundownProtection(&Mgr->RundownRef)) return STATUS_DELETE_PENDING;

    //
    // Check if already empty
    //
    for (i = 0; i < AwqPriority_Count; i++) {
        TotalPending += (ULONG)Mgr->Queues[i].ItemCount;
    }
    if (TotalPending == 0 && Mgr->ActiveWorkerCount == 0) {
        ExReleaseRundownProtection(&Mgr->RundownRef);
        return STATUS_SUCCESS;
    }

    //
    // Set draining state (block new submissions).
    // CRITICAL: Clear the drain event BEFORE setting state to Draining.
    // If we set Draining first, a worker completing the last item could
    // signal DrainCompleteEvent between our state-set and event-clear,
    // and KeClearEvent would lose that signal → drain hangs until timeout.
    //
    KeClearEvent(&Mgr->DrainCompleteEvent);
    MemoryBarrier();
    InterlockedExchange(&Mgr->State, (LONG)AwqQueueState_Draining);

    //
    // Re-check: items may have completed between initial check and state change
    //
    {
        ULONG PostCheckPending = 0;
        for (i = 0; i < AwqPriority_Count; i++) {
            PostCheckPending += (ULONG)Mgr->Queues[i].ItemCount;
        }
        if (PostCheckPending == 0 && Mgr->ActiveWorkerCount == 0) {
            InterlockedExchange(&Mgr->State, (LONG)AwqQueueState_Running);
            ExReleaseRundownProtection(&Mgr->RundownRef);
            return STATUS_SUCCESS;
        }
    }

    if (TimeoutMs == 0) TimeoutMs = AWQ_SHUTDOWN_TIMEOUT_MS;
    Timeout.QuadPart = -((LONGLONG)TimeoutMs * 10000);

    Status = KeWaitForSingleObject(
        &Mgr->DrainCompleteEvent, Executive, KernelMode, FALSE, &Timeout);

    //
    // Restore running state regardless of outcome
    //
    InterlockedExchange(&Mgr->State, (LONG)AwqQueueState_Running);

    ExReleaseRundownProtection(&Mgr->RundownRef);
    return (Status == STATUS_TIMEOUT) ? STATUS_TIMEOUT : STATUS_SUCCESS;
}

// ============================================================================
//  AwqSubmit
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqSubmit(
    _In_ HAWQ_MANAGER Handle,
    _In_ PAWQ_WORK_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _In_ ULONG ContextSize,
    _In_opt_ PAWQ_SUBMIT_OPTIONS Options,
    _Out_opt_ PULONG64 ItemId
    )
{
    PAWQ_MANAGER_I Mgr;
    PAWQ_WORK_ITEM_I Item = NULL;
    NTSTATUS Status;
    AWQ_PRIORITY Priority = AwqPriority_Normal;
    AWQ_WORK_FLAGS Flags = AwqFlag_None;

    if (ItemId != NULL) *ItemId = 0;

    Mgr = AwqpFromHandle(Handle);
    if (Mgr == NULL) return STATUS_INVALID_PARAMETER;
    if (Callback == NULL) return STATUS_INVALID_PARAMETER;
    if (ContextSize > AWQ_MAX_CONTEXT_SIZE) return STATUS_BUFFER_OVERFLOW;

    if (!ExAcquireRundownProtection(&Mgr->RundownRef)) return STATUS_DELETE_PENDING;

    //
    // Only accept work in Running state
    //
    {
        LONG CurState = Mgr->State;
        if (CurState != (LONG)AwqQueueState_Running) {
            ExReleaseRundownProtection(&Mgr->RundownRef);
            return STATUS_DEVICE_NOT_READY;
        }
    }

    if (Options != NULL) {
        Priority = Options->Priority;
        Flags = Options->Flags;
        if ((ULONG)Priority >= AwqPriority_Count) Priority = AwqPriority_Normal;
    }

    //
    // Capacity check
    //
    if ((ULONG)Mgr->Queues[Priority].ItemCount >= Mgr->Config.MaxQueueSize) {
        InterlockedIncrement64(&Mgr->Queues[Priority].TotalDropped);
        ExReleaseRundownProtection(&Mgr->RundownRef);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Allocate item
    //
    Item = AwqpAllocItem(Mgr);
    if (Item == NULL) {
        ExReleaseRundownProtection(&Mgr->RundownRef);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize
    //
    Item->ItemId = InterlockedIncrement64(&Mgr->NextItemId);
    Item->Priority = Priority;
    Item->Flags = Flags;
    InterlockedExchange(&Item->State, (LONG)AwqItemState_Queued);
    Item->WorkCallback = Callback;
    Item->Context = Context;
    Item->ContextSize = ContextSize;
    Item->Manager = Mgr;
    KeInitializeEvent(&Item->CompletionEvent, NotificationEvent, FALSE);
    KeQuerySystemTimePrecise(&Item->SubmitTime);

    if (Options != NULL) {
        Item->SerializationKey = Options->SerializationKey;
        Item->CompletionCallback = Options->CompletionCallback;
        Item->CleanupCallback = Options->CleanupCallback;
        Item->CompletionContext = Options->CompletionContext;
        Item->TimeoutMs = Options->TimeoutMs;
        Item->MaxRetries = min(Options->MaxRetries, AWQ_MAX_RETRIES);
        Item->RetryDelayMs = Options->RetryDelayMs;
    }
    if (Item->TimeoutMs == 0) {
        Item->TimeoutMs = Mgr->Config.DefaultTimeoutMs;
    }

    //
    // Copy context if DeleteContext flag is set
    //
    if ((Flags & AwqFlag_DeleteContext) && Context != NULL && ContextSize > 0) {
        Item->AllocatedContext = ExAllocatePool2(
            POOL_FLAG_NON_PAGED, ContextSize, AWQ_POOL_TAG_CTX);
        if (Item->AllocatedContext == NULL) {
            AwqpFreeItem(Mgr, Item);
            ExReleaseRundownProtection(&Mgr->RundownRef);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlCopyMemory(Item->AllocatedContext, Context, ContextSize);
        Item->Context = Item->AllocatedContext;
    }

    //
    // Register in hash + active list
    //
    AwqpRegisterItem(Mgr, Item);

    //
    // Serialization check: if serialized and key is busy, defer
    //
    if ((Flags & AwqFlag_Serialized) && Item->SerializationKey != 0) {
        Status = AwqpSerializationCheck(Mgr, Item);
        if (Status == STATUS_PENDING) {
            // Item was deferred into the serialization pending list
            InterlockedIncrement64(&Mgr->Stats.TotalSubmitted);
            if (ItemId != NULL) *ItemId = Item->ItemId;
            ExReleaseRundownProtection(&Mgr->RundownRef);
            return STATUS_SUCCESS;
        }
        if (!NT_SUCCESS(Status)) {
            // Serialization key allocation failed
            AwqpUnregisterItem(Mgr, Item);
            AwqpFreeItem(Mgr, Item);
            ExReleaseRundownProtection(&Mgr->RundownRef);
            return Status;
        }
        // STATUS_SUCCESS means we're clear to enqueue
    }

    //
    // Enqueue
    //
    Status = AwqpEnqueue(Mgr, Item);
    if (!NT_SUCCESS(Status)) {
        AwqpUnregisterItem(Mgr, Item);
        AwqpFreeItem(Mgr, Item);
        ExReleaseRundownProtection(&Mgr->RundownRef);
        return Status;
    }

    InterlockedIncrement64(&Mgr->Stats.TotalSubmitted);

    if (ItemId != NULL) *ItemId = Item->ItemId;

    ExReleaseRundownProtection(&Mgr->RundownRef);
    return STATUS_SUCCESS;
}

// ============================================================================
//  AwqSubmitWithContext
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqSubmitWithContext(
    _In_ HAWQ_MANAGER Handle,
    _In_ PAWQ_WORK_CALLBACK Callback,
    _In_reads_bytes_(ContextSize) PVOID Context,
    _In_ ULONG ContextSize,
    _In_ AWQ_PRIORITY Priority,
    _Out_opt_ PULONG64 ItemId
    )
{
    AWQ_SUBMIT_OPTIONS Opts;
    RtlZeroMemory(&Opts, sizeof(Opts));
    Opts.Priority = Priority;
    Opts.Flags = AwqFlag_DeleteContext;
    return AwqSubmit(Handle, Callback, Context, ContextSize, &Opts, ItemId);
}

// ============================================================================
//  AwqSubmitChain
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqSubmitChain(
    _In_ HAWQ_MANAGER Handle,
    _In_reads_(Count) PAWQ_WORK_CALLBACK *Callbacks,
    _In_reads_opt_(Count) PVOID *Contexts,
    _In_reads_opt_(Count) ULONG *ContextSizes,
    _In_ ULONG Count,
    _In_ AWQ_PRIORITY Priority,
    _Out_opt_ PULONG64 ChainId
    )
{
    PAWQ_MANAGER_I Mgr;
    PAWQ_WORK_ITEM_I *Items = NULL;
    NTSTATUS Status;
    ULONG i;
    ULONG64 BaseId;

    if (ChainId != NULL) *ChainId = 0;

    Mgr = AwqpFromHandle(Handle);
    if (Mgr == NULL) return STATUS_INVALID_PARAMETER;
    if (Callbacks == NULL || Count == 0) return STATUS_INVALID_PARAMETER;
    if (Count > AWQ_MAX_CHAIN_LENGTH) return STATUS_INVALID_PARAMETER;
    if ((ULONG)Priority >= AwqPriority_Count) return STATUS_INVALID_PARAMETER;

    if (!ExAcquireRundownProtection(&Mgr->RundownRef)) return STATUS_DELETE_PENDING;

    if (Mgr->State != (LONG)AwqQueueState_Running) {
        ExReleaseRundownProtection(&Mgr->RundownRef);
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Allocate pointer array
    //
    Items = (PAWQ_WORK_ITEM_I *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        Count * sizeof(PAWQ_WORK_ITEM_I),
        AWQ_POOL_TAG_CTX);
    if (Items == NULL) {
        ExReleaseRundownProtection(&Mgr->RundownRef);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Allocate all items upfront
    //
    for (i = 0; i < Count; i++) {
        Items[i] = AwqpAllocItem(Mgr);
        if (Items[i] == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto ChainCleanup;
        }
    }

    //
    // Reserve IDs atomically
    //
    BaseId = InterlockedAdd64(&Mgr->NextItemId, (LONG64)Count);
    BaseId -= Count;

    //
    // Initialize and chain items
    //
    for (i = 0; i < Count; i++) {
        PAWQ_WORK_ITEM_I It = Items[i];

        It->ItemId = BaseId + i + 1;
        It->Priority = Priority;
        It->Flags = AwqFlag_CanCancel;  // chains are cancellable
        InterlockedExchange(&It->State, (LONG)AwqItemState_Queued);
        It->WorkCallback = Callbacks[i];
        It->Context = (Contexts != NULL) ? Contexts[i] : NULL;
        It->ContextSize = (ContextSizes != NULL) ? ContextSizes[i] : 0;
        It->ChainIndex = i;
        It->ChainLength = Count;
        It->Manager = Mgr;
        KeInitializeEvent(&It->CompletionEvent, NotificationEvent, FALSE);
        KeQuerySystemTimePrecise(&It->SubmitTime);

        if (i < Count - 1) {
            It->NextInChain = Items[i + 1];
        }
    }

    //
    // Register ALL chain items in hash table (so they're all findable)
    //
    for (i = 0; i < Count; i++) {
        AwqpRegisterItem(Mgr, Items[i]);
    }

    //
    // Enqueue only the first item
    //
    Status = AwqpEnqueue(Mgr, Items[0]);
    if (!NT_SUCCESS(Status)) {
        for (i = 0; i < Count; i++) {
            AwqpUnregisterItem(Mgr, Items[i]);
            AwqpFreeItem(Mgr, Items[i]);
        }
        ExFreePoolWithTag(Items, AWQ_POOL_TAG_CTX);
        ExReleaseRundownProtection(&Mgr->RundownRef);
        return Status;
    }

    InterlockedIncrement64(&Mgr->Stats.TotalSubmitted);

    if (ChainId != NULL) *ChainId = Items[0]->ItemId;

    ExFreePoolWithTag(Items, AWQ_POOL_TAG_CTX);
    ExReleaseRundownProtection(&Mgr->RundownRef);
    return STATUS_SUCCESS;

ChainCleanup:
    for (i = 0; i < Count; i++) {
        if (Items[i] != NULL) {
            AwqpFreeItem(Mgr, Items[i]);
        }
    }
    ExFreePoolWithTag(Items, AWQ_POOL_TAG_CTX);
    ExReleaseRundownProtection(&Mgr->RundownRef);
    return Status;
}

// ============================================================================
//  AwqCancel
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqCancel(
    _In_ HAWQ_MANAGER Handle,
    _In_ ULONG64 ItemId
    )
{
    PAWQ_MANAGER_I Mgr;
    PAWQ_WORK_ITEM_I Item;
    BOOLEAN Removed = FALSE;

    Mgr = AwqpFromHandle(Handle);
    if (Mgr == NULL) return STATUS_INVALID_PARAMETER;
    if (ItemId == 0) return STATUS_INVALID_PARAMETER;
    if (!ExAcquireRundownProtection(&Mgr->RundownRef)) return STATUS_DELETE_PENDING;

    //
    // Find item (acquires a reference)
    //
    Item = AwqpFindItem(Mgr, ItemId);
    if (Item == NULL) {
        ExReleaseRundownProtection(&Mgr->RundownRef);
        return STATUS_NOT_FOUND;
    }

    if (!(Item->Flags & AwqFlag_CanCancel)) {
        AwqpDerefItem(Mgr, Item);
        ExReleaseRundownProtection(&Mgr->RundownRef);
        return STATUS_NOT_SUPPORTED;
    }

    //
    // Try to cancel: CAS must be done UNDER the queue lock to prevent
    // a race with AwqpDequeue. Without the lock, Dequeue could remove
    // the item from the list between our CAS and RemoveEntryList,
    // causing double-remove list corruption.
    //
    {
        PAWQ_PQUEUE Q = &Mgr->Queues[Item->Priority];
        AWQ_LOCK_EXCLUSIVE(&Q->Lock);
        if (InterlockedCompareExchange(&Item->State,
                (LONG)AwqItemState_Cancelled,
                (LONG)AwqItemState_Queued) == (LONG)AwqItemState_Queued) {
            RemoveEntryList(&Item->QueueLink);
            InitializeListHead(&Item->QueueLink);
            InterlockedDecrement(&Q->ItemCount);
            Removed = TRUE;
        }
        AWQ_UNLOCK_EXCLUSIVE(&Q->Lock);
    }

    if (Removed) {
        AwqpCompleteItem(Mgr, Item, STATUS_CANCELLED);
        InterlockedIncrement64(&Mgr->Stats.TotalCancelled);
        // CompleteItem releases existence + tracking refs; release FindItem ref
        AwqpDerefItem(Mgr, Item);
        ExReleaseRundownProtection(&Mgr->RundownRef);
        return STATUS_SUCCESS;
    }

    //
    // Item is Running or already completed
    //
    LONG CurState = Item->State;
    AwqpDerefItem(Mgr, Item);
    ExReleaseRundownProtection(&Mgr->RundownRef);

    return (CurState == (LONG)AwqItemState_Running) ? STATUS_PENDING : STATUS_SUCCESS;
}

// ============================================================================
//  AwqCancelByKey
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqCancelByKey(
    _In_ HAWQ_MANAGER Handle,
    _In_ ULONG64 SerializationKey
    )
{
    PAWQ_MANAGER_I Mgr;
    ULONG i;
    ULONG CancelledCount = 0;

    Mgr = AwqpFromHandle(Handle);
    if (Mgr == NULL) return STATUS_INVALID_PARAMETER;
    if (!ExAcquireRundownProtection(&Mgr->RundownRef)) return STATUS_DELETE_PENDING;

    for (i = 0; i < AwqPriority_Count; i++) {
        PAWQ_PQUEUE Q = &Mgr->Queues[i];
        LIST_ENTRY ToCancel;
        PLIST_ENTRY Entry, Next;

        InitializeListHead(&ToCancel);

        AWQ_LOCK_EXCLUSIVE(&Q->Lock);
        for (Entry = Q->ItemList.Flink; Entry != &Q->ItemList; Entry = Next) {
            Next = Entry->Flink;
            PAWQ_WORK_ITEM_I Item = CONTAINING_RECORD(Entry, AWQ_WORK_ITEM_I, QueueLink);

            if (Item->SerializationKey == SerializationKey &&
                (Item->Flags & AwqFlag_CanCancel)) {

                if (InterlockedCompareExchange(&Item->State,
                        (LONG)AwqItemState_Cancelled,
                        (LONG)AwqItemState_Queued) == (LONG)AwqItemState_Queued) {
                    RemoveEntryList(Entry);
                    InterlockedDecrement(&Q->ItemCount);
                    InsertTailList(&ToCancel, Entry);
                }
            }
        }
        AWQ_UNLOCK_EXCLUSIVE(&Q->Lock);

        //
        // Complete cancelled items outside the lock
        //
        while (!IsListEmpty(&ToCancel)) {
            Entry = RemoveHeadList(&ToCancel);
            PAWQ_WORK_ITEM_I Item = CONTAINING_RECORD(Entry, AWQ_WORK_ITEM_I, QueueLink);
            AwqpCompleteItem(Mgr, Item, STATUS_CANCELLED);
            CancelledCount++;
        }
    }

    InterlockedAdd64(&Mgr->Stats.TotalCancelled, CancelledCount);
    ExReleaseRundownProtection(&Mgr->RundownRef);
    return STATUS_SUCCESS;
}

// ============================================================================
//  AwqWaitForItem
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqWaitForItem(
    _In_ HAWQ_MANAGER Handle,
    _In_ ULONG64 ItemId,
    _In_ ULONG TimeoutMs,
    _Out_opt_ PNTSTATUS ItemStatus
    )
{
    PAWQ_MANAGER_I Mgr;
    PAWQ_WORK_ITEM_I Item;
    LARGE_INTEGER Timeout;
    NTSTATUS WaitResult;

    PAGED_CODE();

    if (ItemStatus != NULL) *ItemStatus = STATUS_UNSUCCESSFUL;

    Mgr = AwqpFromHandle(Handle);
    if (Mgr == NULL) return STATUS_INVALID_PARAMETER;
    if (ItemId == 0) return STATUS_INVALID_PARAMETER;
    if (!ExAcquireRundownProtection(&Mgr->RundownRef)) return STATUS_DELETE_PENDING;

    //
    // Find item (ref-counted — safe even if item completes concurrently)
    //
    Item = AwqpFindItem(Mgr, ItemId);
    if (Item == NULL) {
        ExReleaseRundownProtection(&Mgr->RundownRef);
        return STATUS_NOT_FOUND;
    }

    //
    // Check if already done
    //
    {
        LONG S = Item->State;
        if (S == (LONG)AwqItemState_Completed ||
            S == (LONG)AwqItemState_Cancelled ||
            S == (LONG)AwqItemState_Failed) {

            if (ItemStatus != NULL) *ItemStatus = Item->CompletionStatus;
            AwqpDerefItem(Mgr, Item);
            ExReleaseRundownProtection(&Mgr->RundownRef);
            return STATUS_SUCCESS;
        }
    }

    //
    // Wait on the embedded completion event
    //
    if (TimeoutMs == 0) TimeoutMs = AWQ_SHUTDOWN_TIMEOUT_MS;
    Timeout.QuadPart = -((LONGLONG)TimeoutMs * 10000);

    WaitResult = KeWaitForSingleObject(
        &Item->CompletionEvent, Executive, KernelMode, FALSE, &Timeout);

    if (WaitResult == STATUS_TIMEOUT) {
        AwqpDerefItem(Mgr, Item);
        ExReleaseRundownProtection(&Mgr->RundownRef);
        return STATUS_TIMEOUT;
    }

    if (ItemStatus != NULL) *ItemStatus = Item->CompletionStatus;

    AwqpDerefItem(Mgr, Item);
    ExReleaseRundownProtection(&Mgr->RundownRef);
    return STATUS_SUCCESS;
}

// ============================================================================
//  AwqGetItemStatus
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqGetItemStatus(
    _In_ HAWQ_MANAGER Handle,
    _In_ ULONG64 ItemId,
    _Out_ AWQ_ITEM_STATE *State,
    _Out_opt_ PNTSTATUS CompletionStatus
    )
{
    PAWQ_MANAGER_I Mgr;
    PAWQ_WORK_ITEM_I Item;

    if (State == NULL) return STATUS_INVALID_PARAMETER;
    *State = AwqItemState_Unknown;
    if (CompletionStatus != NULL) *CompletionStatus = STATUS_UNSUCCESSFUL;

    Mgr = AwqpFromHandle(Handle);
    if (Mgr == NULL) return STATUS_INVALID_PARAMETER;
    if (ItemId == 0) return STATUS_INVALID_PARAMETER;
    if (!ExAcquireRundownProtection(&Mgr->RundownRef)) return STATUS_DELETE_PENDING;

    Item = AwqpFindItem(Mgr, ItemId);
    if (Item == NULL) {
        ExReleaseRundownProtection(&Mgr->RundownRef);
        return STATUS_NOT_FOUND;
    }

    *State = (AWQ_ITEM_STATE)Item->State;
    if (CompletionStatus != NULL) *CompletionStatus = Item->CompletionStatus;

    AwqpDerefItem(Mgr, Item);
    ExReleaseRundownProtection(&Mgr->RundownRef);
    return STATUS_SUCCESS;
}

// ============================================================================
//  AwqSetThreadCount
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqSetThreadCount(
    _In_ HAWQ_MANAGER Handle,
    _In_ ULONG MinThreads,
    _In_ ULONG MaxThreads
    )
{
    PAWQ_MANAGER_I Mgr;
    ULONG i;
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    Mgr = AwqpFromHandle(Handle);
    if (Mgr == NULL) return STATUS_INVALID_PARAMETER;
    if (MinThreads > MaxThreads) return STATUS_INVALID_PARAMETER;
    if (!ExAcquireRundownProtection(&Mgr->RundownRef)) return STATUS_DELETE_PENDING;

    if (MaxThreads > AWQ_MAX_THREADS) MaxThreads = AWQ_MAX_THREADS;
    if (MinThreads < AWQ_MIN_THREADS) MinThreads = AWQ_MIN_THREADS;

    Mgr->MinWorkers = MinThreads;
    Mgr->MaxWorkers = MaxThreads;

    //
    // Scale up if needed
    //
    for (i = (ULONG)Mgr->WorkerCount; i < MinThreads; i++) {
        PAWQ_WORKER_I W = NULL;
        Status = AwqpCreateWorker(Mgr, &W);
        if (!NT_SUCCESS(Status)) break;
    }

    ExReleaseRundownProtection(&Mgr->RundownRef);
    return Status;
}

// ============================================================================
//  AwqGetStatistics
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqGetStatistics(
    _In_ HAWQ_MANAGER Handle,
    _Out_ PAWQ_STATISTICS Stats
    )
{
    PAWQ_MANAGER_I Mgr;
    LARGE_INTEGER Now;
    ULONG i;

    if (Stats == NULL) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Stats, sizeof(AWQ_STATISTICS));

    Mgr = AwqpFromHandle(Handle);
    if (Mgr == NULL) return STATUS_INVALID_PARAMETER;
    if (!ExAcquireRundownProtection(&Mgr->RundownRef)) return STATUS_DELETE_PENDING;

    Stats->State = (AWQ_QUEUE_STATE)Mgr->State;
    Stats->TotalSubmitted = (ULONG64)Mgr->Stats.TotalSubmitted;
    Stats->TotalCompleted = (ULONG64)Mgr->Stats.TotalCompleted;
    Stats->TotalCancelled = (ULONG64)Mgr->Stats.TotalCancelled;
    Stats->TotalFailed = (ULONG64)Mgr->Stats.TotalFailed;
    Stats->TotalRetries = (ULONG64)Mgr->Stats.TotalRetries;

    Stats->TotalPending = 0;
    for (i = 0; i < AwqPriority_Count; i++) {
        Stats->PendingItems[i] = (ULONG)Mgr->Queues[i].ItemCount;
        Stats->TotalPending += Stats->PendingItems[i];

        Stats->PerPriority[i].Enqueued = (ULONG64)Mgr->Queues[i].TotalEnqueued;
        Stats->PerPriority[i].Dequeued = (ULONG64)Mgr->Queues[i].TotalDequeued;
        Stats->PerPriority[i].Dropped = (ULONG64)Mgr->Queues[i].TotalDropped;
        Stats->PerPriority[i].Pending = (ULONG)Mgr->Queues[i].ItemCount;
    }

    Stats->WorkerCount = (ULONG)Mgr->WorkerCount;
    Stats->IdleWorkers = (ULONG)Mgr->IdleWorkerCount;
    Stats->ActiveWorkers = (ULONG)Mgr->ActiveWorkerCount;

    KeQuerySystemTimePrecise(&Now);
    Stats->UpTime.QuadPart = Now.QuadPart - Mgr->Stats.StartTime.QuadPart;
    {
        LONG64 Sec = Stats->UpTime.QuadPart / 10000000;
        if (Sec > 0) {
            Stats->ItemsPerSecond = Stats->TotalCompleted / (ULONG64)Sec;
        }
    }

    ExReleaseRundownProtection(&Mgr->RundownRef);
    return STATUS_SUCCESS;
}

// ============================================================================
//  AwqResetStatistics
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
VOID
AwqResetStatistics(
    _In_ HAWQ_MANAGER Handle
    )
{
    PAWQ_MANAGER_I Mgr;
    ULONG i;

    Mgr = AwqpFromHandle(Handle);
    if (Mgr == NULL) return;
    if (!ExAcquireRundownProtection(&Mgr->RundownRef)) return;

    InterlockedExchange64(&Mgr->Stats.TotalSubmitted, 0);
    InterlockedExchange64(&Mgr->Stats.TotalCompleted, 0);
    InterlockedExchange64(&Mgr->Stats.TotalCancelled, 0);
    InterlockedExchange64(&Mgr->Stats.TotalFailed, 0);
    InterlockedExchange64(&Mgr->Stats.TotalRetries, 0);
    KeQuerySystemTimePrecise(&Mgr->Stats.StartTime);

    for (i = 0; i < AwqPriority_Count; i++) {
        InterlockedExchange64(&Mgr->Queues[i].TotalEnqueued, 0);
        InterlockedExchange64(&Mgr->Queues[i].TotalDequeued, 0);
        InterlockedExchange64(&Mgr->Queues[i].TotalDropped, 0);
    }

    ExReleaseRundownProtection(&Mgr->RundownRef);
}

// ============================================================================
//  AwqSetDefaultTimeout
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqSetDefaultTimeout(
    _In_ HAWQ_MANAGER Handle,
    _In_ ULONG TimeoutMs
    )
{
    PAWQ_MANAGER_I Mgr;

    PAGED_CODE();

    Mgr = AwqpFromHandle(Handle);
    if (Mgr == NULL) return STATUS_INVALID_PARAMETER;
    if (!ExAcquireRundownProtection(&Mgr->RundownRef)) return STATUS_DELETE_PENDING;

    Mgr->Config.DefaultTimeoutMs = TimeoutMs;

    ExReleaseRundownProtection(&Mgr->RundownRef);
    return STATUS_SUCCESS;
}

// ============================================================================
//  AwqSetDynamicThreads
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqSetDynamicThreads(
    _In_ HAWQ_MANAGER Handle,
    _In_ BOOLEAN Enable
    )
{
    PAWQ_MANAGER_I Mgr;

    PAGED_CODE();

    Mgr = AwqpFromHandle(Handle);
    if (Mgr == NULL) return STATUS_INVALID_PARAMETER;
    if (!ExAcquireRundownProtection(&Mgr->RundownRef)) return STATUS_DELETE_PENDING;

    InterlockedExchange(&Mgr->Config.EnableDynamicThreads, Enable ? 1 : 0);

    ExReleaseRundownProtection(&Mgr->RundownRef);
    return STATUS_SUCCESS;
}

// ============================================================================
// Internal: Item allocation / cache
// ============================================================================

static PAWQ_WORK_ITEM_I
AwqpAllocItem(
    _In_ PAWQ_MANAGER_I Mgr
    )
{
    PAWQ_WORK_ITEM_I Item = NULL;

    //
    // Try cache first
    //
    AWQ_LOCK_EXCLUSIVE(&Mgr->Cache.Lock);
    if (!IsListEmpty(&Mgr->Cache.FreeList)) {
        PLIST_ENTRY E = RemoveHeadList(&Mgr->Cache.FreeList);
        Item = CONTAINING_RECORD(E, AWQ_WORK_ITEM_I, QueueLink);
        InterlockedDecrement(&Mgr->Cache.FreeCount);
    }
    AWQ_UNLOCK_EXCLUSIVE(&Mgr->Cache.Lock);

    if (Item != NULL) {
        ULONG SavedMagic = Item->Magic;
        RtlZeroMemory(Item, sizeof(AWQ_WORK_ITEM_I));
        Item->Magic = SavedMagic;
        Item->RefCount = 1;
        return Item;
    }

    //
    // Fresh allocation
    //
    Item = (PAWQ_WORK_ITEM_I)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(AWQ_WORK_ITEM_I), AWQ_POOL_TAG_ITEM);
    if (Item != NULL) {
        Item->Magic = AWQ_ITEM_MAGIC;
        Item->RefCount = 1;
    }
    return Item;
}

static VOID
AwqpFreeItem(
    _In_ PAWQ_MANAGER_I Mgr,
    _In_ PAWQ_WORK_ITEM_I Item
    )
{
    BOOLEAN Cached = FALSE;

    if (Item == NULL || Item->Magic != AWQ_ITEM_MAGIC) return;

    //
    // Free allocated context
    //
    if (Item->AllocatedContext != NULL) {
        ExFreePoolWithTag(Item->AllocatedContext, AWQ_POOL_TAG_CTX);
        Item->AllocatedContext = NULL;
    }

    //
    // Try to return to cache
    //
    AWQ_LOCK_EXCLUSIVE(&Mgr->Cache.Lock);
    if ((ULONG)Mgr->Cache.FreeCount < Mgr->Cache.MaxFree) {
        RtlZeroMemory(Item, sizeof(AWQ_WORK_ITEM_I));
        Item->Magic = AWQ_ITEM_MAGIC;
        InsertTailList(&Mgr->Cache.FreeList, &Item->QueueLink);
        InterlockedIncrement(&Mgr->Cache.FreeCount);
        Cached = TRUE;
    }
    AWQ_UNLOCK_EXCLUSIVE(&Mgr->Cache.Lock);

    if (!Cached) {
        Item->Magic = 0;
        ExFreePoolWithTag(Item, AWQ_POOL_TAG_ITEM);
    }
}

// ============================================================================
// Internal: Reference counting
// ============================================================================

static VOID
AwqpRefItem(
    _In_ PAWQ_WORK_ITEM_I Item
    )
{
    InterlockedIncrement(&Item->RefCount);
}

static VOID
AwqpDerefItem(
    _In_ PAWQ_MANAGER_I Mgr,
    _In_ PAWQ_WORK_ITEM_I Item
    )
{
    if (InterlockedDecrement(&Item->RefCount) == 0) {
        AwqpFreeItem(Mgr, Item);
    }
}

// ============================================================================
// Internal: Hash table (chained, for O(1) item lookup by ID)
// ============================================================================

static __forceinline ULONG
AwqpHashId(
    _In_ ULONG64 Id,
    _In_ ULONG BucketCount
    )
{
    // Mix bits for better distribution
    ULONG64 h = Id;
    h ^= (h >> 16);
    h *= 0x45d9f3b;
    h ^= (h >> 16);
    return (ULONG)(h % BucketCount);
}

static VOID
AwqpRegisterItem(
    _In_ PAWQ_MANAGER_I Mgr,
    _In_ PAWQ_WORK_ITEM_I Item
    )
{
    ULONG Bucket;

    //
    // Add to hash table
    //
    Item->HashEntry.Item = Item;
    Bucket = AwqpHashId(Item->ItemId, Mgr->Hash.BucketCount);

    AWQ_LOCK_EXCLUSIVE(&Mgr->Hash.Lock);
    InsertTailList(&Mgr->Hash.Buckets[Bucket], &Item->HashEntry.HashLink);
    AWQ_UNLOCK_EXCLUSIVE(&Mgr->Hash.Lock);

    //
    // Add to active items list (take an extra ref for tracking)
    //
    AwqpRefItem(Item);

    AWQ_LOCK_EXCLUSIVE(&Mgr->ActiveItems.Lock);
    InsertTailList(&Mgr->ActiveItems.List, &Item->TrackLink);
    InterlockedIncrement(&Mgr->ActiveItems.Count);
    AWQ_UNLOCK_EXCLUSIVE(&Mgr->ActiveItems.Lock);
}

static VOID
AwqpUnregisterItem(
    _In_ PAWQ_MANAGER_I Mgr,
    _In_ PAWQ_WORK_ITEM_I Item
    )
{
    ULONG Bucket;

    //
    // Remove from hash table
    //
    Bucket = AwqpHashId(Item->ItemId, Mgr->Hash.BucketCount);

    AWQ_LOCK_EXCLUSIVE(&Mgr->Hash.Lock);
    RemoveEntryList(&Item->HashEntry.HashLink);
    InitializeListHead(&Item->HashEntry.HashLink);  // make safe to re-remove
    AWQ_UNLOCK_EXCLUSIVE(&Mgr->Hash.Lock);

    //
    // Remove from active list
    //
    AWQ_LOCK_EXCLUSIVE(&Mgr->ActiveItems.Lock);
    RemoveEntryList(&Item->TrackLink);
    InitializeListHead(&Item->TrackLink);
    InterlockedDecrement(&Mgr->ActiveItems.Count);
    AWQ_UNLOCK_EXCLUSIVE(&Mgr->ActiveItems.Lock);

    //
    // Release tracking ref
    //
    AwqpDerefItem(Mgr, Item);
}

//
// FindItem: returns item with an ADDED reference. Caller must DerefItem.
//
static PAWQ_WORK_ITEM_I
AwqpFindItem(
    _In_ PAWQ_MANAGER_I Mgr,
    _In_ ULONG64 Id
    )
{
    ULONG Bucket;
    PLIST_ENTRY Entry;
    PAWQ_WORK_ITEM_I Found = NULL;

    Bucket = AwqpHashId(Id, Mgr->Hash.BucketCount);

    AWQ_LOCK_SHARED(&Mgr->Hash.Lock);
    for (Entry = Mgr->Hash.Buckets[Bucket].Flink;
         Entry != &Mgr->Hash.Buckets[Bucket];
         Entry = Entry->Flink) {

        PAWQ_HASH_ENTRY HE = CONTAINING_RECORD(Entry, AWQ_HASH_ENTRY, HashLink);
        if (HE->Item != NULL && HE->Item->ItemId == Id) {
            Found = HE->Item;
            AwqpRefItem(Found);
            break;
        }
    }
    AWQ_UNLOCK_SHARED(&Mgr->Hash.Lock);

    return Found;
}

// ============================================================================
// Internal: Enqueue / Dequeue
// ============================================================================

static NTSTATUS
AwqpEnqueue(
    _In_ PAWQ_MANAGER_I Mgr,
    _In_ PAWQ_WORK_ITEM_I Item
    )
{
    PAWQ_PQUEUE Q = &Mgr->Queues[Item->Priority];

    AWQ_LOCK_EXCLUSIVE(&Q->Lock);

    if ((ULONG)Q->ItemCount >= Q->MaxItems) {
        AWQ_UNLOCK_EXCLUSIVE(&Q->Lock);
        return STATUS_QUOTA_EXCEEDED;
    }

    InsertTailList(&Q->ItemList, &Item->QueueLink);
    InterlockedIncrement(&Q->ItemCount);
    InterlockedIncrement64(&Q->TotalEnqueued);

    AWQ_UNLOCK_EXCLUSIVE(&Q->Lock);

    //
    // Wake a worker
    //
    KeSetEvent(&Mgr->NewWorkEvent, IO_NO_INCREMENT, FALSE);

    return STATUS_SUCCESS;
}

static PAWQ_WORK_ITEM_I
AwqpDequeue(
    _In_ PAWQ_MANAGER_I Mgr
    )
{
    LONG p;

    //
    // Highest priority first.
    // We CAS item state from Queued→Running UNDER the queue lock
    // to prevent a race with AwqCancel. If Cancel won the CAS first
    // (state is Cancelled), we skip the item — Cancel will remove it.
    //
    for (p = AwqPriority_Count - 1; p >= 0; p--) {
        PAWQ_PQUEUE Q = &Mgr->Queues[p];
        PLIST_ENTRY Entry, Next;

        if (Q->ItemCount == 0) continue;

        AWQ_LOCK_EXCLUSIVE(&Q->Lock);
        for (Entry = Q->ItemList.Flink; Entry != &Q->ItemList; Entry = Next) {
            PAWQ_WORK_ITEM_I Item = CONTAINING_RECORD(Entry, AWQ_WORK_ITEM_I, QueueLink);
            Next = Entry->Flink;

            if (InterlockedCompareExchange(&Item->State,
                    (LONG)AwqItemState_Running,
                    (LONG)AwqItemState_Queued) == (LONG)AwqItemState_Queued) {
                RemoveEntryList(Entry);
                InitializeListHead(&Item->QueueLink);
                InterlockedDecrement(&Q->ItemCount);
                InterlockedIncrement64(&Q->TotalDequeued);
                AWQ_UNLOCK_EXCLUSIVE(&Q->Lock);
                return Item;
            }
            // Item was concurrently cancelled — skip, Cancel will clean it up
        }
        AWQ_UNLOCK_EXCLUSIVE(&Q->Lock);
    }

    return NULL;
}

// ============================================================================
// Internal: Serialization
//
// If an item has AwqFlag_Serialized and SerializationKey != 0:
//   - On submit: check if key has active items. If yes, defer to pending list.
//   - On completion: release key, enqueue next pending item if any.
// ============================================================================

static NTSTATUS
AwqpSerializationCheck(
    _In_ PAWQ_MANAGER_I Mgr,
    _In_ PAWQ_WORK_ITEM_I Item
    )
{
    PLIST_ENTRY Entry;
    PAWQ_SKEY SK = NULL;
    BOOLEAN Found = FALSE;

    AWQ_LOCK_EXCLUSIVE(&Mgr->Serialization.Lock);

    //
    // Find or create key entry
    //
    for (Entry = Mgr->Serialization.KeyList.Flink;
         Entry != &Mgr->Serialization.KeyList;
         Entry = Entry->Flink) {
        PAWQ_SKEY Cur = CONTAINING_RECORD(Entry, AWQ_SKEY, ListEntry);
        if (Cur->Key == Item->SerializationKey) {
            SK = Cur;
            Found = TRUE;
            break;
        }
    }

    if (!Found) {
        //
        // First item for this key — create entry and allow execution
        //
        SK = (PAWQ_SKEY)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(AWQ_SKEY), AWQ_POOL_TAG_SKEY);
        if (SK == NULL) {
            AWQ_UNLOCK_EXCLUSIVE(&Mgr->Serialization.Lock);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        SK->Key = Item->SerializationKey;
        SK->ActiveCount = 1;
        InitializeListHead(&SK->PendingItems);
        InsertTailList(&Mgr->Serialization.KeyList, &SK->ListEntry);
        AWQ_UNLOCK_EXCLUSIVE(&Mgr->Serialization.Lock);
        return STATUS_SUCCESS;   // proceed to enqueue
    }

    if (SK->ActiveCount == 0) {
        //
        // Key exists but no active items — allow
        //
        InterlockedIncrement(&SK->ActiveCount);
        AWQ_UNLOCK_EXCLUSIVE(&Mgr->Serialization.Lock);
        return STATUS_SUCCESS;
    }

    //
    // Key is busy — defer item to pending list
    //
    InsertTailList(&SK->PendingItems, &Item->QueueLink);
    AWQ_UNLOCK_EXCLUSIVE(&Mgr->Serialization.Lock);

    return STATUS_PENDING;  // caller should NOT enqueue
}

static VOID
AwqpSerializationRelease(
    _In_ PAWQ_MANAGER_I Mgr,
    _In_ ULONG64 Key
    )
{
    PLIST_ENTRY Entry;
    PAWQ_SKEY SK = NULL;
    PAWQ_WORK_ITEM_I NextItem = NULL;

    AWQ_LOCK_EXCLUSIVE(&Mgr->Serialization.Lock);

    for (Entry = Mgr->Serialization.KeyList.Flink;
         Entry != &Mgr->Serialization.KeyList;
         Entry = Entry->Flink) {
        PAWQ_SKEY Cur = CONTAINING_RECORD(Entry, AWQ_SKEY, ListEntry);
        if (Cur->Key == Key) {
            SK = Cur;
            break;
        }
    }

    if (SK == NULL) {
        AWQ_UNLOCK_EXCLUSIVE(&Mgr->Serialization.Lock);
        return;
    }

    InterlockedDecrement(&SK->ActiveCount);

    if (SK->ActiveCount == 0 && !IsListEmpty(&SK->PendingItems)) {
        //
        // Dequeue next pending item for this key
        //
        PLIST_ENTRY PE = RemoveHeadList(&SK->PendingItems);
        NextItem = CONTAINING_RECORD(PE, AWQ_WORK_ITEM_I, QueueLink);
        InterlockedIncrement(&SK->ActiveCount);
    } else if (SK->ActiveCount == 0 && IsListEmpty(&SK->PendingItems)) {
        //
        // No more items — remove key entry
        //
        RemoveEntryList(&SK->ListEntry);
        AWQ_UNLOCK_EXCLUSIVE(&Mgr->Serialization.Lock);
        ExFreePoolWithTag(SK, AWQ_POOL_TAG_SKEY);

        // No next item to enqueue
        return;
    }

    AWQ_UNLOCK_EXCLUSIVE(&Mgr->Serialization.Lock);

    if (NextItem != NULL) {
        AwqpEnqueue(Mgr, NextItem);
    }
}

// ============================================================================
// Internal: Execute item
// ============================================================================

static VOID
AwqpExecuteItem(
    _In_ PAWQ_MANAGER_I Mgr,
    _In_ PAWQ_WORKER_I Worker,
    _In_ PAWQ_WORK_ITEM_I Item
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    PAWQ_WORK_ITEM_I NextChainItem = NULL;

    InterlockedExchange(&Item->State, (LONG)AwqItemState_Running);

    //
    // Track worker activity
    //
    InterlockedExchange(&Worker->Idle, 0);
    InterlockedIncrement(&Mgr->ActiveWorkerCount);
    InterlockedDecrement(&Mgr->IdleWorkerCount);

    //
    // Execute callback (SEH-protected)
    //
    __try {
        Status = Item->WorkCallback(Item->Context, Item->ContextSize);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
#if DBG
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[ShadowStrike] AWQ: Callback exception 0x%08X for item %llu\n",
            Status, Item->ItemId);
#endif
    }

    //
    // Restore worker state
    //
    InterlockedDecrement(&Mgr->ActiveWorkerCount);
    InterlockedIncrement(&Mgr->IdleWorkerCount);
    InterlockedExchange(&Worker->Idle, 1);
    InterlockedIncrement64(&Worker->ItemsProcessed);

    //
    // Handle retry
    //
    if (!NT_SUCCESS(Status) &&
        (Item->Flags & AwqFlag_RetryOnFailure) &&
        Item->RetryCount < Item->MaxRetries) {

        Item->RetryCount++;
        InterlockedExchange(&Item->State, (LONG)AwqItemState_Queued);
        InterlockedIncrement64(&Mgr->Stats.TotalRetries);

        //
        // Re-enqueue (no blocking delay — just re-submit)
        //
        AwqpEnqueue(Mgr, Item);
        return;
    }

    //
    // Save chain info BEFORE completing (which may free the item)
    //
    if (Item->NextInChain != NULL && NT_SUCCESS(Status)) {
        NextChainItem = Item->NextInChain;
    }

    //
    // Final state
    //
    if (NT_SUCCESS(Status)) {
        InterlockedExchange(&Item->State, (LONG)AwqItemState_Completed);
        InterlockedIncrement64(&Mgr->Stats.TotalCompleted);
    } else {
        InterlockedExchange(&Item->State, (LONG)AwqItemState_Failed);
        InterlockedIncrement64(&Mgr->Stats.TotalFailed);
    }

    //
    // Release serialization key (before complete, so next serialized item
    // can be enqueued while our callbacks run)
    //
    if ((Item->Flags & AwqFlag_Serialized) && Item->SerializationKey != 0) {
        AwqpSerializationRelease(Mgr, Item->SerializationKey);
    }

    //
    // Complete (calls callbacks, signals event, unrefs)
    //
    AwqpCompleteItem(Mgr, Item, Status);

    //
    // Chain continuation: enqueue next item
    //
    if (NextChainItem != NULL) {
        AwqpEnqueue(Mgr, NextChainItem);
    }

    //
    // Check if drain is complete
    //
    AwqpCheckDrainComplete(Mgr);
}

// ============================================================================
// Internal: Complete item
//
// All callbacks are called at PASSIVE_LEVEL outside any lock.
// This function releases one reference on the item.
// ============================================================================

static VOID
AwqpCompleteItem(
    _In_ PAWQ_MANAGER_I Mgr,
    _In_ PAWQ_WORK_ITEM_I Item,
    _In_ NTSTATUS Status
    )
{
    Item->CompletionStatus = Status;

    //
    // Completion callback
    //
    if (Item->CompletionCallback != NULL) {
        Item->CompletionCallback(Status, Item->Context, Item->CompletionContext);
    }

    //
    // Cleanup callback (always called if set, before context is freed)
    //
    if (Item->CleanupCallback != NULL) {
        Item->CleanupCallback(Item->Context);
    }

    //
    // Signal completion event (waiters can see CompletionStatus)
    //
    KeSetEvent(&Item->CompletionEvent, IO_NO_INCREMENT, FALSE);

    //
    // Unregister from hash + active list
    //
    AwqpUnregisterItem(Mgr, Item);

    //
    // Release the "existence" reference.
    // If nobody else holds a ref (from FindItem), this frees the item.
    // If a waiter holds a ref, the item lives until they DerefItem.
    //
    AwqpDerefItem(Mgr, Item);
}

// ============================================================================
// Internal: Check drain completion
// ============================================================================

static VOID
AwqpCheckDrainComplete(
    _In_ PAWQ_MANAGER_I Mgr
    )
{
    if (Mgr->State != (LONG)AwqQueueState_Draining) return;

    ULONG TotalPending = 0;
    ULONG i;
    for (i = 0; i < AwqPriority_Count; i++) {
        TotalPending += (ULONG)Mgr->Queues[i].ItemCount;
    }

    if (TotalPending == 0 && Mgr->ActiveWorkerCount == 0) {
        KeSetEvent(&Mgr->DrainCompleteEvent, IO_NO_INCREMENT, FALSE);
    }
}

// ============================================================================
// Internal: Worker thread creation
// ============================================================================

static NTSTATUS
AwqpCreateWorker(
    _In_ PAWQ_MANAGER_I Mgr,
    _Out_ PAWQ_WORKER_I *Out
    )
{
    PAWQ_WORKER_I W = NULL;
    OBJECT_ATTRIBUTES ObjAttr;
    HANDLE ThreadHandle = NULL;
    NTSTATUS Status;

    *Out = NULL;

    W = (PAWQ_WORKER_I)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(AWQ_WORKER_I), AWQ_POOL_TAG_THREAD);
    if (W == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    W->Manager = Mgr;  // direct pointer — no CONTAINING_RECORD hack
    InterlockedExchange(&W->Running, 1);
    InterlockedExchange(&W->Idle, 1);
    W->ThreadId = (ULONG)InterlockedIncrement(&Mgr->WorkerCount);

    InitializeObjectAttributes(&ObjAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    Status = PsCreateSystemThread(
        &ThreadHandle,
        THREAD_ALL_ACCESS,
        &ObjAttr,
        NULL, NULL,
        AwqpWorkerThread,
        W);

    if (!NT_SUCCESS(Status)) {
        InterlockedDecrement(&Mgr->WorkerCount);
        ExFreePoolWithTag(W, AWQ_POOL_TAG_THREAD);
        return Status;
    }

    //
    // Get thread object (referenced), then close handle
    //
    Status = ObReferenceObjectByHandle(
        ThreadHandle,
        THREAD_ALL_ACCESS,
        *PsThreadType,
        KernelMode,
        (PVOID *)&W->ThreadObject,
        NULL);

    ZwClose(ThreadHandle);
    // Do NOT store the now-invalid handle

    if (!NT_SUCCESS(Status)) {
        //
        // Thread was created but we can't reference it.
        // Signal it to stop; it will exit and free itself.
        // ThreadObject remains NULL → worker self-frees on exit.
        //
        InterlockedExchange(&W->Running, 0);
        return Status;
    }

    //
    // Add to worker list
    //
    AWQ_LOCK_EXCLUSIVE(&Mgr->WorkerLock);
    InsertTailList(&Mgr->WorkerList, &W->ListEntry);
    InterlockedIncrement(&Mgr->IdleWorkerCount);
    AWQ_UNLOCK_EXCLUSIVE(&Mgr->WorkerLock);

    *Out = W;
    return STATUS_SUCCESS;
}

// ============================================================================
// Internal: Worker thread routine
// ============================================================================

static VOID
AwqpWorkerThread(
    _In_ PVOID Ctx
    )
{
    PAWQ_WORKER_I Worker = (PAWQ_WORKER_I)Ctx;
    PAWQ_MANAGER_I Mgr = Worker->Manager;
    PVOID WaitObjects[2];
    LARGE_INTEGER Timeout;
    NTSTATUS WaitStatus;

    KeQuerySystemTimePrecise(&Worker->LastActivityTime);
    Worker->IdleStartTime = Worker->LastActivityTime;

    WaitObjects[0] = &Mgr->NewWorkEvent;
    WaitObjects[1] = &Mgr->ShutdownEvent;

    while (Worker->Running != 0) {
        PAWQ_WORK_ITEM_I Item;

        //
        // Check shutdown
        //
        if (Mgr->State == (LONG)AwqQueueState_ShuttingDown) {
            break;
        }

        //
        // Paused — wait for resume
        //
        if (Mgr->State == (LONG)AwqQueueState_Paused) {
            LARGE_INTEGER PauseDelay;
            PauseDelay.QuadPart = -10 * 1000 * 100; // 100ms
            KeDelayExecutionThread(KernelMode, FALSE, &PauseDelay);
            continue;
        }

        //
        // Try to dequeue work
        //
        Item = AwqpDequeue(Mgr);

        if (Item != NULL) {
            KeQuerySystemTimePrecise(&Worker->LastActivityTime);
            AwqpExecuteItem(Mgr, Worker, Item);
            KeQuerySystemTimePrecise(&Worker->LastActivityTime);
            Worker->IdleStartTime = Worker->LastActivityTime;
        } else {
            //
            // No work — wait for signal or timeout
            //
            Timeout.QuadPart = -((LONGLONG)1000 * 10000); // 1 second

            WaitStatus = KeWaitForMultipleObjects(
                2, WaitObjects, WaitAny,
                Executive, KernelMode, FALSE,
                &Timeout, NULL);

            if (WaitStatus == STATUS_WAIT_1) {
                // Shutdown signaled
                break;
            }

            //
            // Dynamic scaling: exit if idle too long and above minimum
            //
            if (Mgr->Config.EnableDynamicThreads &&
                (ULONG)Mgr->WorkerCount > Mgr->MinWorkers) {

                LARGE_INTEGER Now;
                KeQuerySystemTimePrecise(&Now);
                LONG64 IdleMs = (Now.QuadPart - Worker->IdleStartTime.QuadPart) / 10000;

                if (IdleMs > AWQ_IDLE_TIMEOUT_MS) {
                    //
                    // Remove ourselves from the worker list and exit
                    //
                    AWQ_LOCK_EXCLUSIVE(&Mgr->WorkerLock);
                    RemoveEntryList(&Worker->ListEntry);
                    AWQ_UNLOCK_EXCLUSIVE(&Mgr->WorkerLock);

                    InterlockedDecrement(&Mgr->WorkerCount);
                    InterlockedDecrement(&Mgr->IdleWorkerCount);

                    if (Worker->ThreadObject != NULL) {
                        ObDereferenceObject(Worker->ThreadObject);
                    }
                    ExFreePoolWithTag(Worker, AWQ_POOL_TAG_THREAD);

                    PsTerminateSystemThread(STATUS_SUCCESS);
                    // No return
                }
            }
        }
    }

    //
    // If this worker was never added to WorkerList (ObRef failed
    // during creation), free ourselves before exiting to avoid leak.
    // Workers on the list are freed by shutdown or dynamic scaling.
    //
    if (Worker->ThreadObject == NULL) {
        ExFreePoolWithTag(Worker, AWQ_POOL_TAG_THREAD);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}
