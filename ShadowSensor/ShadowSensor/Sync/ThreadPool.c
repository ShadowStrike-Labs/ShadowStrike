/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE KERNEL THREAD POOL ENGINE
 * ============================================================================
 *
 * @file ThreadPool.c
 * @brief Enterprise-grade managed thread pool for kernel-mode EDR operations.
 *
 * IRQL Safety Architecture:
 * - Scale timer fires DPC at DISPATCH_LEVEL.
 *   DPC queues IoWorkItem to defer ALL scaling work to PASSIVE_LEVEL.
 *   PsCreateSystemThread and thread cleanup ONLY happen at PASSIVE_LEVEL.
 * - Worker threads run at PASSIVE_LEVEL. They apply their own affinity
 *   and priority at startup (not from creating thread).
 * - All pool configuration changes require PASSIVE_LEVEL.
 * - Counters (ThreadCount, IdleThreadCount, RunningThreadCount) are
 *   volatile LONGs, updated with Interlocked* ops — safe at any IRQL.
 *
 * Synchronization:
 * - ThreadListLock (KSPIN_LOCK): protects ThreadList add/remove.
 *   Acquired briefly at <= DISPATCH_LEVEL.
 * - ExecutorLock (EX_PUSH_LOCK): protects WorkExecutor pointer swap.
 *   Acquired shared in worker threads, exclusive in TpSetWorkExecutor.
 * - ConfigLock (EX_PUSH_LOCK): protects MinThreads/MaxThreads/thresholds.
 * - ScaleInProgress (InterlockedCAS): prevents concurrent scale operations.
 *
 * Thread Lifecycle:
 * - TppCreateThread: alloc info → PsCreateSystemThread → ObReferenceObjectByHandle
 *   → add to list → signal StartEvent. PASSIVE_LEVEL only.
 * - TppDestroyThread: signal StopEvent → wait → ObDereference → ZwClose
 *   → cleanup callback → free. PASSIVE_LEVEL only.
 * - Worker thread exit: save pre-exit state → decrement correct counter
 *   → remove self from list under spinlock → decrement ThreadCount.
 *
 * Memory:
 * - All allocations use ShadowStrikeAllocatePoolWithTag / ShadowStrikeFreePoolWithTag.
 *   No lookaside list (avoids alloc/free mismatch bugs).
 *
 * @version 3.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "ThreadPool.h"
#include "../Utilities/MemoryUtils.h"
#include "../Core/Globals.h"

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define TP_POOL_MAGIC                   0x50545048  // 'PTPH'
#define TP_THREAD_INFO_MAGIC            0x54495450  // 'TITP'
#define TP_THREAD_STACK_SIZE            0           // Default kernel stack
#define TP_THREAD_TERMINATE_TIMEOUT_MS  10000
#define TP_SCALE_COOLDOWN_MS            5000
#define TP_WORK_WAIT_TIMEOUT_MS         100

// ============================================================================
// INTERNAL STRUCTURES (private to this .c file)
// ============================================================================

//
// TP_THREAD_INFO: Full per-thread state. Opaque to callers.
//
struct _TP_THREAD_INFO {
    ULONG Magic;

    // Thread identity
    HANDLE ThreadHandle;
    PKTHREAD ThreadObject;
    ULONG ThreadIndex;

    // Thread state
    volatile TP_THREAD_STATE State;
    volatile BOOLEAN ShutdownRequested;

    // Idle tracking
    LARGE_INTEGER LastActivityTime;
    LARGE_INTEGER IdleStartTime;
    LARGE_INTEGER WorkStartTime;

    // Statistics (per-thread, updated with Interlocked)
    volatile LONG64 WorkItemsCompleted;
    volatile LONG64 TotalWorkTimeMs;
    volatile LONG64 TotalIdleTimeMs;

    // Thread control events
    KEVENT StartEvent;          // Signaled to let worker start
    KEVENT StopEvent;           // Signaled to request worker exit
    volatile LONG StopRequested;

    // Work execution state
    volatile LONG IsExecuting;

    // Lifecycle flags
    volatile LONG Registered;       // TRUE if added to pool's ThreadList and counters
    volatile LONG OwnerWillDestroy; // TRUE if TppDestroyThread will handle cleanup

    // Owner pool (back-pointer, protected by pool lifetime)
    struct _TP_THREAD_POOL* Pool;

    // List linkage (protected by Pool->ThreadListLock)
    LIST_ENTRY ListEntry;
};

//
// TP_THREAD_POOL: Full pool state. Opaque to callers.
//
struct _TP_THREAD_POOL {
    ULONG Magic;
    volatile BOOLEAN Initialized;
    volatile BOOLEAN ShuttingDown;

    // Thread list (protected by ThreadListLock)
    LIST_ENTRY ThreadList;
    KSPIN_LOCK ThreadListLock;
    volatile LONG ThreadCount;
    volatile LONG IdleThreadCount;
    volatile LONG RunningThreadCount;

    // Thread limits (protected by ConfigLock)
    ULONG MinThreads;
    ULONG MaxThreads;

    // Events
    KSEMAPHORE WorkAvailableSemaphore;  // Semaphore (wakes one thread per signal)
    KEVENT ShutdownEvent;               // Manual-reset (broadcast)
    KEVENT AllThreadsStoppedEvent;      // Manual-reset

    // Scaling
    KTIMER ScaleTimer;
    KDPC ScaleDpc;
    volatile BOOLEAN ScalingEnabled;
    ULONG ScaleUpThreshold;
    ULONG ScaleDownThreshold;
    ULONG ScaleIntervalMs;
    ULONG IdleTimeoutMs;
    LARGE_INTEGER LastScaleTime;
    volatile LONG ScaleInProgress;

    // DPC → work item deferral for scaling
    PIO_WORKITEM ScaleWorkItem;
    PDEVICE_OBJECT DeviceObject;
    volatile LONG ScaleWorkItemQueued;
    KEVENT ScaleWorkItemComplete;

    // Work executor (protected by ExecutorLock)
    TP_WORK_EXECUTOR WorkExecutor;
    PVOID ExecutorContext;
    EX_PUSH_LOCK ExecutorLock;

    // Configuration lock
    EX_PUSH_LOCK ConfigLock;

    // Callbacks
    TP_THREAD_INIT_CALLBACK InitCallback;
    TP_THREAD_CLEANUP_CALLBACK CleanupCallback;
    PVOID CallbackContext;

    // Priority / affinity
    TP_THREAD_PRIORITY DefaultPriority;
    KAFFINITY AffinityMask;

    // Reference counting (prevents free while threads still reference pool)
    volatile LONG ReferenceCount;

    // Thread ID assignment
    volatile LONG NextThreadIndex;

    // Statistics
    struct {
        volatile LONG64 TotalWorkItems;
        volatile LONG64 ThreadsCreated;
        volatile LONG64 ThreadsDestroyed;
        volatile LONG64 ScaleUpCount;
        volatile LONG64 ScaleDownCount;
        LARGE_INTEGER StartTime;
    } Stats;
};

// ============================================================================
// PRIVATE FUNCTION PROTOTYPES
// ============================================================================

static KSTART_ROUTINE TppWorkerThreadRoutine;
static KDEFERRED_ROUTINE TppScaleDpcRoutine;

_Function_class_(IO_WORKITEM_ROUTINE)
static VOID NTAPI
TppScaleWorkItemRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    );

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
TppCreateThread(
    _Inout_ PTP_THREAD_POOL Pool,
    _Out_ PTP_THREAD_INFO* ThreadInfo
    );

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
TppDestroyThread(
    _Inout_ PTP_THREAD_INFO ThreadInfo,
    _In_ BOOLEAN Wait
    );

static VOID
TppSignalThreadStop(
    _Inout_ PTP_THREAD_INFO ThreadInfo
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
TppIsValidPool(
    _In_opt_ PTP_THREAD_POOL Pool
    );

static VOID
TppAcquirePoolReference(
    _Inout_ PTP_THREAD_POOL Pool
    );

static VOID
TppReleasePoolReference(
    _Inout_ PTP_THREAD_POOL Pool
    );

static VOID
TppSetThreadPriority(
    _In_ PKTHREAD Thread,
    _In_ TP_THREAD_PRIORITY Priority
    );

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
TppEvaluateScaling(
    _Inout_ PTP_THREAD_POOL Pool
    );

static VOID
TppDefaultWorkExecutor(
    _In_ PTP_THREAD_INFO ThreadInfo,
    _In_ PKEVENT WorkEvent,
    _In_ PKEVENT ShutdownEvent,
    _In_opt_ PVOID ExecutorContext
    );

// ============================================================================
// INITIALIZATION AND CLEANUP
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
TpCreate(
    _Out_ PTP_THREAD_POOL* Pool,
    _In_ const TP_CONFIG* Config
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PTP_THREAD_POOL pool = NULL;
    TP_CONFIG localConfig;
    ULONG i;
    LARGE_INTEGER dueTime;
    BOOLEAN timerStarted = FALSE;

    PAGED_CODE();

    if (Pool == NULL || Config == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Pool = NULL;

    //
    // Make a local copy of config so we don't modify caller's _In_ struct
    //
    RtlCopyMemory(&localConfig, Config, sizeof(TP_CONFIG));

    //
    // Validate and clamp configuration
    //
    if (localConfig.MinThreads < TP_MIN_THREADS) {
        localConfig.MinThreads = TP_MIN_THREADS;
    }
    if (localConfig.MaxThreads > TP_MAX_THREADS) {
        localConfig.MaxThreads = TP_MAX_THREADS;
    }
    if (localConfig.MaxThreads < localConfig.MinThreads) {
        return STATUS_INVALID_PARAMETER;
    }
    if (localConfig.ScaleUpThreshold == 0) {
        localConfig.ScaleUpThreshold = TP_SCALE_UP_THRESHOLD;
    }
    if (localConfig.ScaleDownThreshold == 0) {
        localConfig.ScaleDownThreshold = TP_SCALE_DOWN_THRESHOLD;
    }
    if (localConfig.ScaleIntervalMs == 0) {
        localConfig.ScaleIntervalMs = TP_SCALE_INTERVAL_MS;
    }
    if (localConfig.IdleTimeoutMs == 0) {
        localConfig.IdleTimeoutMs = TP_IDLE_TIMEOUT_MS;
    }

    //
    // Allocate pool structure
    //
    pool = (PTP_THREAD_POOL)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(TP_THREAD_POOL),
        TP_POOL_TAG_CONTEXT
    );
    if (pool == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(pool, sizeof(TP_THREAD_POOL));

    pool->Magic = TP_POOL_MAGIC;
    pool->ReferenceCount = 1;

    //
    // Initialize synchronization
    //
    InitializeListHead(&pool->ThreadList);
    KeInitializeSpinLock(&pool->ThreadListLock);
    ExInitializePushLock(&pool->ExecutorLock);
    ExInitializePushLock(&pool->ConfigLock);

    //
    // Store configuration
    //
    pool->MinThreads = localConfig.MinThreads;
    pool->MaxThreads = localConfig.MaxThreads;
    pool->ScaleUpThreshold = localConfig.ScaleUpThreshold;
    pool->ScaleDownThreshold = localConfig.ScaleDownThreshold;
    pool->ScaleIntervalMs = localConfig.ScaleIntervalMs;
    pool->IdleTimeoutMs = localConfig.IdleTimeoutMs;
    pool->DefaultPriority = localConfig.DefaultPriority;
    pool->AffinityMask = localConfig.AffinityMask != 0 ?
        localConfig.AffinityMask : KeQueryActiveProcessors();
    pool->DeviceObject = localConfig.DeviceObject;

    //
    // Initialize events/semaphore
    //
    KeInitializeSemaphore(&pool->WorkAvailableSemaphore, 0, MAXLONG);
    KeInitializeEvent(&pool->ShutdownEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&pool->AllThreadsStoppedEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&pool->ScaleWorkItemComplete, NotificationEvent, TRUE);

    //
    // Initialize scaling timer/DPC
    //
    KeInitializeTimer(&pool->ScaleTimer);
    KeInitializeDpc(&pool->ScaleDpc, TppScaleDpcRoutine, pool);

    //
    // Allocate scale work item (for DPC → PASSIVE deferral)
    //
    if (pool->DeviceObject != NULL) {
        pool->ScaleWorkItem = IoAllocateWorkItem(pool->DeviceObject);
        if (pool->ScaleWorkItem == NULL) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike:TP] WARNING: No DeviceObject for scale work item. "
                       "Scaling will be disabled.\n");
        }
    }

    //
    // Set callbacks
    //
    pool->InitCallback = localConfig.InitCallback;
    pool->CleanupCallback = localConfig.CleanupCallback;
    pool->CallbackContext = localConfig.CallbackContext;

    //
    // Set default work executor (logs warning that no real executor is set)
    //
    pool->WorkExecutor = TppDefaultWorkExecutor;
    pool->ExecutorContext = NULL;

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&pool->Stats.StartTime);

    //
    // Mark initialized BEFORE creating threads so TpDestroy works on partial cleanup
    //
    pool->Initialized = TRUE;

    //
    // Create initial threads
    //
    for (i = 0; i < localConfig.MinThreads; i++) {
        PTP_THREAD_INFO threadInfo;

        status = TppCreateThread(pool, &threadInfo);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike:TP] Failed to create initial thread %u: 0x%08X\n",
                       i, status);
            //
            // Cleanup already-created threads.
            // Initialized=TRUE so TpDestroy will work properly.
            //
            TpDestroy(&pool, TRUE);
            return status;
        }
    }

    //
    // Enable scaling if requested and work item is available
    //
    if (localConfig.EnableScaling && pool->ScaleWorkItem != NULL) {
        pool->ScalingEnabled = TRUE;
        KeQuerySystemTime(&pool->LastScaleTime);

        dueTime.QuadPart = -((LONGLONG)pool->ScaleIntervalMs * 10000);
        KeSetTimerEx(
            &pool->ScaleTimer,
            dueTime,
            pool->ScaleIntervalMs,
            &pool->ScaleDpc
        );
        timerStarted = TRUE;
    }

    *Pool = pool;
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
TpCreateDefault(
    _Out_ PTP_THREAD_POOL* Pool,
    _In_ ULONG MinThreads,
    _In_ ULONG MaxThreads,
    _In_opt_ PDEVICE_OBJECT DeviceObject
)
{
    TP_CONFIG config;

    PAGED_CODE();

    RtlZeroMemory(&config, sizeof(config));
    config.MinThreads = MinThreads > 0 ? MinThreads : TP_DEFAULT_MIN_THREADS;
    config.MaxThreads = MaxThreads > 0 ? MaxThreads : TP_DEFAULT_MAX_THREADS;
    config.DefaultPriority = TpPriority_Normal;
    config.AffinityMask = 0;
    config.EnableScaling = TRUE;
    config.ScaleUpThreshold = TP_SCALE_UP_THRESHOLD;
    config.ScaleDownThreshold = TP_SCALE_DOWN_THRESHOLD;
    config.ScaleIntervalMs = TP_SCALE_INTERVAL_MS;
    config.IdleTimeoutMs = TP_IDLE_TIMEOUT_MS;
    config.DeviceObject = DeviceObject;

    return TpCreate(Pool, &config);
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
TpDestroy(
    _Inout_ PTP_THREAD_POOL* PoolPtr,
    _In_ BOOLEAN WaitForCompletion
)
{
    PTP_THREAD_POOL pool;
    PLIST_ENTRY entry;
    PTP_THREAD_INFO threadInfo;
    LARGE_INTEGER timeout;
    KIRQL oldIrql;
    LIST_ENTRY threadsToDestroy;

    PAGED_CODE();

    if (PoolPtr == NULL || *PoolPtr == NULL) {
        return;
    }

    pool = *PoolPtr;
    *PoolPtr = NULL;

    if (!TppIsValidPool(pool)) {
        return;
    }

    //
    // Step 1: Set shutdown flag and signal shutdown event.
    // This causes all worker threads to exit their main loops.
    //
    pool->ShuttingDown = TRUE;
    KeSetEvent(&pool->ShutdownEvent, IO_NO_INCREMENT, FALSE);

    //
    // Step 2: Cancel scaling timer and flush DPCs.
    // After KeFlushQueuedDpcs, no DPC can be running.
    //
    if (pool->ScalingEnabled) {
        KeCancelTimer(&pool->ScaleTimer);
        KeFlushQueuedDpcs();
        pool->ScalingEnabled = FALSE;
    }

    //
    // Step 3: Wait for any in-flight scale work item to complete.
    //
    if (pool->ScaleWorkItem != NULL) {
        timeout.QuadPart = -((LONGLONG)TP_THREAD_TERMINATE_TIMEOUT_MS * 10000);
        KeWaitForSingleObject(
            &pool->ScaleWorkItemComplete,
            Executive,
            KernelMode,
            FALSE,
            &timeout
        );
    }

    //
    // Step 4: Wake all sleeping threads so they exit.
    // Release a large count on the semaphore to ensure all threads wake.
    //
    KeReleaseSemaphore(&pool->WorkAvailableSemaphore, IO_NO_INCREMENT,
                       TP_MAX_THREADS, FALSE);

    //
    // Step 5: Collect all threads from list under spinlock.
    //
    InitializeListHead(&threadsToDestroy);

    KeAcquireSpinLock(&pool->ThreadListLock, &oldIrql);
    while (!IsListEmpty(&pool->ThreadList)) {
        entry = RemoveHeadList(&pool->ThreadList);
        threadInfo = CONTAINING_RECORD(entry, TP_THREAD_INFO, ListEntry);
        InsertTailList(&threadsToDestroy, &threadInfo->ListEntry);
    }
    KeReleaseSpinLock(&pool->ThreadListLock, oldIrql);

    //
    // Step 6: Destroy each thread (signal stop + wait + cleanup).
    //
    while (!IsListEmpty(&threadsToDestroy)) {
        entry = RemoveHeadList(&threadsToDestroy);
        threadInfo = CONTAINING_RECORD(entry, TP_THREAD_INFO, ListEntry);
        TppDestroyThread(threadInfo, WaitForCompletion);
    }

    //
    // Step 7: Wait for any threads that exited on their own.
    //
    if (WaitForCompletion && pool->ThreadCount > 0) {
        timeout.QuadPart = -((LONGLONG)TP_THREAD_TERMINATE_TIMEOUT_MS * 10000);
        KeWaitForSingleObject(
            &pool->AllThreadsStoppedEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout
        );
    }

    //
    // Step 8: Free scale work item.
    //
    if (pool->ScaleWorkItem != NULL) {
        IoFreeWorkItem(pool->ScaleWorkItem);
        pool->ScaleWorkItem = NULL;
    }

    //
    // Step 9: Invalidate and release pool.
    //
    pool->Magic = 0;
    pool->Initialized = FALSE;

    TppReleasePoolReference(pool);
}

// ============================================================================
// THREAD MANAGEMENT
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
TpAddThreads(
    _Inout_ PTP_THREAD_POOL Pool,
    _In_ ULONG Count
)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG i;
    ULONG created = 0;
    ULONG currentCount;
    ULONG maxThreads;
    ULONG allowedCount;

    PAGED_CODE();

    if (!TppIsValidPool(Pool) || Count == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Pool->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Read limits under ConfigLock to avoid TOCTOU
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Pool->ConfigLock);
    maxThreads = Pool->MaxThreads;
    ExReleasePushLockShared(&Pool->ConfigLock);
    KeLeaveCriticalRegion();

    currentCount = (ULONG)InterlockedCompareExchange(&Pool->ThreadCount, 0, 0);
    if (currentCount >= maxThreads) {
        return STATUS_QUOTA_EXCEEDED;
    }

    allowedCount = maxThreads - currentCount;
    if (Count > allowedCount) {
        Count = allowedCount;
    }

    for (i = 0; i < Count; i++) {
        PTP_THREAD_INFO threadInfo;

        //
        // Re-check limit before each creation (other threads may be adding too)
        //
        currentCount = (ULONG)InterlockedCompareExchange(&Pool->ThreadCount, 0, 0);
        if (currentCount >= maxThreads) {
            break;
        }

        status = TppCreateThread(Pool, &threadInfo);
        if (!NT_SUCCESS(status)) {
            break;
        }
        created++;
    }

    if (created > 0) {
        InterlockedAdd64(&Pool->Stats.ThreadsCreated, created);
    }

    return created > 0 ? STATUS_SUCCESS : status;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
TpRemoveThreads(
    _Inout_ PTP_THREAD_POOL Pool,
    _In_ ULONG Count,
    _In_ BOOLEAN WaitForCompletion
)
{
    PLIST_ENTRY entry;
    PTP_THREAD_INFO threadInfo;
    KIRQL oldIrql;
    ULONG removed = 0;
    ULONG minThreads;
    ULONG currentCount;
    LIST_ENTRY threadsToRemove;

    PAGED_CODE();

    if (!TppIsValidPool(Pool) || Count == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Read limits under ConfigLock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Pool->ConfigLock);
    minThreads = Pool->MinThreads;
    ExReleasePushLockShared(&Pool->ConfigLock);
    KeLeaveCriticalRegion();

    currentCount = (ULONG)InterlockedCompareExchange(&Pool->ThreadCount, 0, 0);
    if (currentCount <= minThreads) {
        return STATUS_SUCCESS;
    }

    //
    // Clamp count to not go below minimum
    //
    if (currentCount - Count < minThreads) {
        Count = currentCount - minThreads;
    }
    if (Count == 0) {
        return STATUS_SUCCESS;
    }

    //
    // Prefer removing idle threads first
    //
    InitializeListHead(&threadsToRemove);

    KeAcquireSpinLock(&Pool->ThreadListLock, &oldIrql);

    // Pass 1: remove idle threads
    for (entry = Pool->ThreadList.Flink;
         entry != &Pool->ThreadList && removed < Count;
         /* advance in loop */) {

        PLIST_ENTRY next = entry->Flink;
        threadInfo = CONTAINING_RECORD(entry, TP_THREAD_INFO, ListEntry);

        if (threadInfo->State == TpThreadState_Idle) {
            RemoveEntryList(entry);
            InitializeListHead(entry);
            InsertTailList(&threadsToRemove, entry);
            removed++;
        }

        entry = next;
    }

    // Pass 2: if still need more, take running threads
    for (entry = Pool->ThreadList.Flink;
         entry != &Pool->ThreadList && removed < Count;
         /* advance in loop */) {

        PLIST_ENTRY next = entry->Flink;
        threadInfo = CONTAINING_RECORD(entry, TP_THREAD_INFO, ListEntry);

        if (threadInfo->State == TpThreadState_Running ||
            threadInfo->State == TpThreadState_Starting) {
            RemoveEntryList(entry);
            InitializeListHead(entry);
            InsertTailList(&threadsToRemove, entry);
            removed++;
        }

        entry = next;
    }

    KeReleaseSpinLock(&Pool->ThreadListLock, oldIrql);

    //
    // Destroy removed threads outside spinlock
    //
    while (!IsListEmpty(&threadsToRemove)) {
        entry = RemoveHeadList(&threadsToRemove);
        threadInfo = CONTAINING_RECORD(entry, TP_THREAD_INFO, ListEntry);
        TppDestroyThread(threadInfo, WaitForCompletion);
    }

    if (removed > 0) {
        InterlockedAdd64(&Pool->Stats.ThreadsDestroyed, removed);
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
TpSetThreadCount(
    _Inout_ PTP_THREAD_POOL Pool,
    _In_ ULONG MinThreads,
    _In_ ULONG MaxThreads
)
{
    PAGED_CODE();

    if (!TppIsValidPool(Pool)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (MinThreads < TP_MIN_THREADS) {
        MinThreads = TP_MIN_THREADS;
    }
    if (MaxThreads > TP_MAX_THREADS) {
        MaxThreads = TP_MAX_THREADS;
    }
    if (MinThreads > MaxThreads) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Update under exclusive ConfigLock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Pool->ConfigLock);
    Pool->MinThreads = MinThreads;
    Pool->MaxThreads = MaxThreads;
    ExReleasePushLockExclusive(&Pool->ConfigLock);
    KeLeaveCriticalRegion();

    //
    // Trigger scaling to adjust thread count to new limits
    //
    TpTriggerScale(Pool);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TpGetThreadCount(
    _In_ PTP_THREAD_POOL Pool,
    _Out_opt_ PULONG Total,
    _Out_opt_ PULONG Idle,
    _Out_opt_ PULONG Running
)
{
    if (!TppIsValidPool(Pool)) {
        if (Total) *Total = 0;
        if (Idle) *Idle = 0;
        if (Running) *Running = 0;
        return;
    }

    if (Total) *Total = (ULONG)InterlockedCompareExchange(&Pool->ThreadCount, 0, 0);
    if (Idle) *Idle = (ULONG)InterlockedCompareExchange(&Pool->IdleThreadCount, 0, 0);
    if (Running) *Running = (ULONG)InterlockedCompareExchange(&Pool->RunningThreadCount, 0, 0);
}

// ============================================================================
// SCALING CONTROL
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
TpSetScaling(
    _Inout_ PTP_THREAD_POOL Pool,
    _In_ BOOLEAN Enable,
    _In_ ULONG ScaleUpThreshold,
    _In_ ULONG ScaleDownThreshold
)
{
    LARGE_INTEGER dueTime;

    PAGED_CODE();

    if (!TppIsValidPool(Pool)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ScaleUpThreshold > 100 || ScaleDownThreshold > 100) {
        return STATUS_INVALID_PARAMETER;
    }
    if (ScaleDownThreshold >= ScaleUpThreshold) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Pool->ConfigLock);
    Pool->ScaleUpThreshold = ScaleUpThreshold;
    Pool->ScaleDownThreshold = ScaleDownThreshold;
    ExReleasePushLockExclusive(&Pool->ConfigLock);
    KeLeaveCriticalRegion();

    if (Enable && !Pool->ScalingEnabled) {
        if (Pool->ScaleWorkItem == NULL) {
            return STATUS_DEVICE_NOT_READY;
        }

        Pool->ScalingEnabled = TRUE;
        KeQuerySystemTime(&Pool->LastScaleTime);

        dueTime.QuadPart = -((LONGLONG)Pool->ScaleIntervalMs * 10000);
        KeSetTimerEx(
            &Pool->ScaleTimer,
            dueTime,
            Pool->ScaleIntervalMs,
            &Pool->ScaleDpc
        );
    } else if (!Enable && Pool->ScalingEnabled) {
        Pool->ScalingEnabled = FALSE;
        KeCancelTimer(&Pool->ScaleTimer);
        //
        // Flush DPCs to ensure no DPC is in-flight after disable
        //
        KeFlushQueuedDpcs();
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TpTriggerScale(
    _In_ PTP_THREAD_POOL Pool
)
{
    if (!TppIsValidPool(Pool)) {
        return;
    }

    //
    // Queue DPC which will defer to work item at PASSIVE_LEVEL
    //
    KeInsertQueueDpc(&Pool->ScaleDpc, NULL, NULL);
}

// ============================================================================
// THREAD PRIORITY AND AFFINITY
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
TpSetPriority(
    _Inout_ PTP_THREAD_POOL Pool,
    _In_ TP_THREAD_PRIORITY Priority
)
{
    PLIST_ENTRY entry;
    PTP_THREAD_INFO threadInfo;
    KIRQL oldIrql;

    PAGED_CODE();

    if (!TppIsValidPool(Pool)) {
        return STATUS_INVALID_PARAMETER;
    }

    Pool->DefaultPriority = Priority;

    //
    // Update all existing threads
    //
    KeAcquireSpinLock(&Pool->ThreadListLock, &oldIrql);

    for (entry = Pool->ThreadList.Flink;
         entry != &Pool->ThreadList;
         entry = entry->Flink) {

        threadInfo = CONTAINING_RECORD(entry, TP_THREAD_INFO, ListEntry);
        if (threadInfo->ThreadObject != NULL) {
            TppSetThreadPriority(threadInfo->ThreadObject, Priority);
        }
    }

    KeReleaseSpinLock(&Pool->ThreadListLock, oldIrql);

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
TpSetAffinity(
    _Inout_ PTP_THREAD_POOL Pool,
    _In_ KAFFINITY AffinityMask
)
{
    KAFFINITY systemAffinity;
    PLIST_ENTRY entry;
    PTP_THREAD_INFO threadInfo;
    KIRQL oldIrql;
    ULONG successCount = 0;
    ULONG failCount = 0;

    PAGED_CODE();

    if (!TppIsValidPool(Pool)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Get system-supported affinity for validation
    //
    systemAffinity = KeQueryActiveProcessors();

    if (AffinityMask == 0) {
        AffinityMask = systemAffinity;
    }

    //
    // Validate: mask must specify at least one active processor.
    // Mask bits for non-existent processors are stripped to prevent BSOD.
    //
    AffinityMask &= systemAffinity;
    if (AffinityMask == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Store new mask — new threads will use this at startup
    //
    Pool->AffinityMask = AffinityMask;

    //
    // Apply immediately to all existing threads via ZwSetInformationThread.
    // KeSetSystemAffinityThread only affects the CALLING thread, so it cannot
    // be used here. ZwSetInformationThread with ThreadAffinityMask properly
    // sets the affinity of any thread given its handle.
    //
    KeAcquireSpinLock(&Pool->ThreadListLock, &oldIrql);

    for (entry = Pool->ThreadList.Flink;
         entry != &Pool->ThreadList;
         entry = entry->Flink) {

        threadInfo = CONTAINING_RECORD(entry, TP_THREAD_INFO, ListEntry);

        if (threadInfo->ThreadHandle != NULL &&
            threadInfo->State != TpThreadState_Stopping &&
            threadInfo->State != TpThreadState_Stopped) {

            //
            // ZwSetInformationThread requires PASSIVE_LEVEL and cannot be
            // called under a spinlock. Collect info and apply outside.
            // But we need the handle to stay valid. Since we hold the list
            // lock, the thread can't be destroyed, and the handle is valid.
            // Use a two-pass approach: mark threads, then apply.
            //
            // Actually, we can't call Zw* under spinlock. Break approach:
            // We'll iterate, ref the thread object, release lock, apply, re-lock.
            // Simpler: since shutdown is checked and pool ref protects pool,
            // collect handles in a local array and apply after releasing the lock.
            //
            // For simplicity and IRQL-safety, defer to signaling approach.
            //
            break;
        }
    }

    KeReleaseSpinLock(&Pool->ThreadListLock, oldIrql);

    //
    // Apply affinity to each thread outside the spinlock.
    // We iterate the list, reference each thread's handle, and call
    // ZwSetInformationThread at PASSIVE_LEVEL.
    //
    {
        HANDLE threadHandles[TP_MAX_THREADS];
        ULONG handleCount = 0;
        ULONG i;

        KeAcquireSpinLock(&Pool->ThreadListLock, &oldIrql);
        for (entry = Pool->ThreadList.Flink;
             entry != &Pool->ThreadList && handleCount < TP_MAX_THREADS;
             entry = entry->Flink) {

            threadInfo = CONTAINING_RECORD(entry, TP_THREAD_INFO, ListEntry);
            if (threadInfo->ThreadHandle != NULL &&
                threadInfo->State != TpThreadState_Stopping &&
                threadInfo->State != TpThreadState_Stopped) {
                threadHandles[handleCount++] = threadInfo->ThreadHandle;
            }
        }
        KeReleaseSpinLock(&Pool->ThreadListLock, oldIrql);

        //
        // Apply at PASSIVE_LEVEL. Handles remain valid because:
        // - Pool is not shutting down (checked by TppIsValidPool)
        // - Threads don't close their own handles unless stop-requested AND
        //   pool is not shutting down (self-cleanup path)
        // - We're at PASSIVE_LEVEL, so no concurrent TpDestroy can proceed
        //   past the thread list collection phase
        //
        for (i = 0; i < handleCount; i++) {
            NTSTATUS status = ZwSetInformationThread(
                threadHandles[i],
                ThreadAffinityMask,
                &AffinityMask,
                sizeof(KAFFINITY)
            );
            if (NT_SUCCESS(status)) {
                successCount++;
            } else {
                failCount++;
#if DBG
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "[ShadowStrike:TP] TpSetAffinity: ZwSetInformationThread "
                    "failed for handle %p: 0x%08X\n",
                    threadHandles[i], status);
#endif
            }
        }
    }

    return (failCount > 0 && successCount == 0) ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}

// ============================================================================
// SIGNALING
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TpSignalWorkAvailable(
    _In_ PTP_THREAD_POOL Pool
)
{
    if (!TppIsValidPool(Pool)) {
        return;
    }

    //
    // Release one count on the semaphore to wake one idle thread
    //
    KeReleaseSemaphore(&Pool->WorkAvailableSemaphore, IO_NO_INCREMENT, 1, FALSE);
}

// ============================================================================
// WORK EXECUTOR
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
TpSetWorkExecutor(
    _Inout_ PTP_THREAD_POOL Pool,
    _In_ TP_WORK_EXECUTOR Executor,
    _In_opt_ PVOID Context
)
{
    PAGED_CODE();

    if (!TppIsValidPool(Pool) || Executor == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Pool->ExecutorLock);
    Pool->WorkExecutor = Executor;
    Pool->ExecutorContext = Context;
    ExReleasePushLockExclusive(&Pool->ExecutorLock);
    KeLeaveCriticalRegion();

    //
    // Wake all threads to use new executor
    //
    KeReleaseSemaphore(&Pool->WorkAvailableSemaphore, IO_NO_INCREMENT,
                       TP_MAX_THREADS, FALSE);

    return STATUS_SUCCESS;
}

// ============================================================================
// STATISTICS
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TpGetStatistics(
    _In_ PTP_THREAD_POOL Pool,
    _Out_ PTP_STATISTICS Stats
)
{
    PLIST_ENTRY entry;
    PTP_THREAD_INFO threadInfo;
    KIRQL oldIrql;
    LARGE_INTEGER currentTime;
    LONG64 totalWorkTime = 0;
    LONG64 totalIdleTime = 0;
    ULONG threadCount = 0;
    LONG64 totalWorkItems;

    if (Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Stats, sizeof(TP_STATISTICS));

    if (!TppIsValidPool(Pool)) {
        return STATUS_INVALID_PARAMETER;
    }

    KeQuerySystemTime(&currentTime);

    //
    // Read counters atomically
    //
    Stats->TotalThreads = (ULONG)InterlockedCompareExchange(&Pool->ThreadCount, 0, 0);
    Stats->IdleThreads = (ULONG)InterlockedCompareExchange(&Pool->IdleThreadCount, 0, 0);
    Stats->RunningThreads = (ULONG)InterlockedCompareExchange(&Pool->RunningThreadCount, 0, 0);

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Pool->ConfigLock);
    Stats->MinThreads = Pool->MinThreads;
    Stats->MaxThreads = Pool->MaxThreads;
    ExReleasePushLockShared(&Pool->ConfigLock);
    KeLeaveCriticalRegion();

    totalWorkItems = InterlockedCompareExchange64(&Pool->Stats.TotalWorkItems, 0, 0);
    Stats->TotalWorkItems = (ULONG64)totalWorkItems;
    Stats->ThreadsCreated = (ULONG64)InterlockedCompareExchange64(&Pool->Stats.ThreadsCreated, 0, 0);
    Stats->ThreadsDestroyed = (ULONG64)InterlockedCompareExchange64(&Pool->Stats.ThreadsDestroyed, 0, 0);
    Stats->ScaleUpCount = (ULONG64)InterlockedCompareExchange64(&Pool->Stats.ScaleUpCount, 0, 0);
    Stats->ScaleDownCount = (ULONG64)InterlockedCompareExchange64(&Pool->Stats.ScaleDownCount, 0, 0);
    Stats->ScalingEnabled = Pool->ScalingEnabled;

    Stats->UpTime.QuadPart = currentTime.QuadPart - Pool->Stats.StartTime.QuadPart;

    //
    // Aggregate per-thread statistics under spinlock
    //
    KeAcquireSpinLock(&Pool->ThreadListLock, &oldIrql);
    for (entry = Pool->ThreadList.Flink;
         entry != &Pool->ThreadList;
         entry = entry->Flink) {
        threadInfo = CONTAINING_RECORD(entry, TP_THREAD_INFO, ListEntry);
        totalWorkTime += InterlockedCompareExchange64(&threadInfo->TotalWorkTimeMs, 0, 0);
        totalIdleTime += InterlockedCompareExchange64(&threadInfo->TotalIdleTimeMs, 0, 0);
        threadCount++;
    }
    KeReleaseSpinLock(&Pool->ThreadListLock, oldIrql);

    if (threadCount > 0 && totalWorkItems > 0) {
        Stats->AverageWorkTimeMs = (ULONG)(totalWorkTime / totalWorkItems);
    }
    if (threadCount > 0) {
        Stats->AverageIdleTimeMs = (ULONG)(totalIdleTime / threadCount);
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TpResetStatistics(
    _Inout_ PTP_THREAD_POOL Pool
)
{
    PLIST_ENTRY entry;
    PTP_THREAD_INFO threadInfo;
    KIRQL oldIrql;

    if (!TppIsValidPool(Pool)) {
        return;
    }

    InterlockedExchange64(&Pool->Stats.TotalWorkItems, 0);
    InterlockedExchange64(&Pool->Stats.ThreadsCreated, 0);
    InterlockedExchange64(&Pool->Stats.ThreadsDestroyed, 0);
    InterlockedExchange64(&Pool->Stats.ScaleUpCount, 0);
    InterlockedExchange64(&Pool->Stats.ScaleDownCount, 0);
    KeQuerySystemTime(&Pool->Stats.StartTime);

    KeAcquireSpinLock(&Pool->ThreadListLock, &oldIrql);
    for (entry = Pool->ThreadList.Flink;
         entry != &Pool->ThreadList;
         entry = entry->Flink) {
        threadInfo = CONTAINING_RECORD(entry, TP_THREAD_INFO, ListEntry);
        InterlockedExchange64(&threadInfo->WorkItemsCompleted, 0);
        InterlockedExchange64(&threadInfo->TotalWorkTimeMs, 0);
        InterlockedExchange64(&threadInfo->TotalIdleTimeMs, 0);
    }
    KeReleaseSpinLock(&Pool->ThreadListLock, oldIrql);
}

// ============================================================================
// PUBLIC HELPER
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
TpGetThreadIndex(
    _In_ PTP_THREAD_INFO ThreadInfo
)
{
    if (ThreadInfo == NULL || ThreadInfo->Magic != TP_THREAD_INFO_MAGIC) {
        return (ULONG)-1;
    }
    return ThreadInfo->ThreadIndex;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - THREAD CREATION / DESTRUCTION
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
TppCreateThread(
    _Inout_ PTP_THREAD_POOL Pool,
    _Out_ PTP_THREAD_INFO* ThreadInfo
)
{
    NTSTATUS status;
    PTP_THREAD_INFO info = NULL;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE threadHandle = NULL;
    KIRQL oldIrql;

    PAGED_CODE();

    *ThreadInfo = NULL;

    //
    // Allocate thread info — always use the same allocator
    //
    info = (PTP_THREAD_INFO)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(TP_THREAD_INFO),
        TP_POOL_TAG_THREAD
    );
    if (info == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(info, sizeof(TP_THREAD_INFO));

    info->Magic = TP_THREAD_INFO_MAGIC;
    info->Pool = Pool;
    info->ThreadIndex = (ULONG)InterlockedIncrement(&Pool->NextThreadIndex) - 1;
    info->State = TpThreadState_Starting;

    InitializeListHead(&info->ListEntry);
    KeInitializeEvent(&info->StartEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&info->StopEvent, NotificationEvent, FALSE);

    KeQuerySystemTime(&info->LastActivityTime);
    KeQuerySystemTime(&info->IdleStartTime);

    //
    // Acquire pool reference BEFORE creating thread (thread will use pool)
    //
    TppAcquirePoolReference(Pool);

    //
    // Create system thread
    //
    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    status = PsCreateSystemThread(
        &threadHandle,
        THREAD_ALL_ACCESS,
        &objAttr,
        NULL,
        NULL,
        TppWorkerThreadRoutine,
        info
    );
    if (!NT_SUCCESS(status)) {
        TppReleasePoolReference(Pool);
        ShadowStrikeFreePoolWithTag(info, TP_POOL_TAG_THREAD);
        return status;
    }

    //
    // Get thread object reference
    //
    status = ObReferenceObjectByHandle(
        threadHandle,
        THREAD_ALL_ACCESS,
        *PsThreadType,
        KernelMode,
        (PVOID*)&info->ThreadObject,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        //
        // Thread is already created but we can't get the object.
        // Signal it to stop immediately and close the handle.
        // DO NOT release pool ref here — the thread owns it and will release on exit.
        //
        info->StopRequested = 1;
        KeSetEvent(&info->StartEvent, IO_NO_INCREMENT, FALSE);
        ZwClose(threadHandle);
        return status;
    }

    info->ThreadHandle = threadHandle;

    //
    // Add to thread list BEFORE signaling start
    //
    KeAcquireSpinLock(&Pool->ThreadListLock, &oldIrql);
    InsertTailList(&Pool->ThreadList, &info->ListEntry);
    InterlockedExchange(&info->Registered, 1);
    InterlockedIncrement(&Pool->ThreadCount);
    InterlockedIncrement(&Pool->IdleThreadCount);
    KeReleaseSpinLock(&Pool->ThreadListLock, oldIrql);

    //
    // Signal thread to begin
    //
    KeSetEvent(&info->StartEvent, IO_NO_INCREMENT, FALSE);

    *ThreadInfo = info;
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
TppDestroyThread(
    _Inout_ PTP_THREAD_INFO ThreadInfo,
    _In_ BOOLEAN Wait
)
{
    LARGE_INTEGER timeout;

    PAGED_CODE();

    if (ThreadInfo == NULL || ThreadInfo->Magic != TP_THREAD_INFO_MAGIC) {
        return;
    }

    //
    // Mark that this thread's cleanup is owned by TppDestroyThread,
    // NOT by the thread's self-cleanup path. Prevents double-free
    // when TpRemoveThreads calls TppDestroyThread concurrently with
    // the thread's own exit path.
    //
    InterlockedExchange(&ThreadInfo->OwnerWillDestroy, 1);

    //
    // Signal the thread to stop
    //
    TppSignalThreadStop(ThreadInfo);

    //
    // Wait for thread to terminate
    //
    if (Wait && ThreadInfo->ThreadObject != NULL) {
        timeout.QuadPart = -((LONGLONG)TP_THREAD_TERMINATE_TIMEOUT_MS * 10000);
        KeWaitForSingleObject(
            ThreadInfo->ThreadObject,
            Executive,
            KernelMode,
            FALSE,
            &timeout
        );
    }

    //
    // Release thread object reference
    //
    if (ThreadInfo->ThreadObject != NULL) {
        ObDereferenceObject(ThreadInfo->ThreadObject);
        ThreadInfo->ThreadObject = NULL;
    }

    //
    // Close thread handle
    //
    if (ThreadInfo->ThreadHandle != NULL) {
        ZwClose(ThreadInfo->ThreadHandle);
        ThreadInfo->ThreadHandle = NULL;
    }

    //
    // Call cleanup callback at PASSIVE_LEVEL
    //
    if (ThreadInfo->Pool != NULL && ThreadInfo->Pool->CleanupCallback != NULL) {
        ThreadInfo->Pool->CleanupCallback(
            ThreadInfo->ThreadIndex,
            ThreadInfo->Pool->CallbackContext
        );
    }

    //
    // Invalidate and free
    //
    ThreadInfo->Magic = 0;

    //
    // Release pool reference (may free pool if last reference)
    //
    if (ThreadInfo->Pool != NULL) {
        TppReleasePoolReference(ThreadInfo->Pool);
    }

    ShadowStrikeFreePoolWithTag(ThreadInfo, TP_POOL_TAG_THREAD);
}

static VOID
TppSignalThreadStop(
    _Inout_ PTP_THREAD_INFO ThreadInfo
)
{
    InterlockedExchange(&ThreadInfo->StopRequested, 1);
    ThreadInfo->ShutdownRequested = TRUE;
    KeSetEvent(&ThreadInfo->StopEvent, IO_NO_INCREMENT, FALSE);
}

// ============================================================================
// PRIVATE IMPLEMENTATION - WORKER THREAD
// ============================================================================

_Function_class_(KSTART_ROUTINE)
static VOID
TppWorkerThreadRoutine(
    _In_ PVOID StartContext
)
{
    PTP_THREAD_INFO threadInfo = (PTP_THREAD_INFO)StartContext;
    PTP_THREAD_POOL pool;
    PVOID waitObjects[3];
    NTSTATUS waitStatus;
    LARGE_INTEGER timeout;
    LARGE_INTEGER currentTime;
    TP_WORK_EXECUTOR executor;
    PVOID executorContext;
    TP_THREAD_STATE preExitState;
    KAFFINITY affinityMask;
    ULONG processorCount;
    ULONG idealProc;
    KIRQL oldIrql;

    if (threadInfo == NULL || threadInfo->Magic != TP_THREAD_INFO_MAGIC) {
        PsTerminateSystemThread(STATUS_INVALID_PARAMETER);
        return;
    }

    pool = threadInfo->Pool;

    //
    // Wait for start signal from creating thread
    //
    KeWaitForSingleObject(
        &threadInfo->StartEvent,
        Executive,
        KernelMode,
        FALSE,
        NULL
    );

    //
    // Check if we should exit immediately (ObReferenceObjectByHandle failed)
    //
    if (threadInfo->StopRequested) {
        goto ExitCleanup;
    }

    //
    // Apply CPU affinity from within THIS thread context (CRITICAL-05 fix).
    // KeSetSystemAffinityThread affects the CALLING thread, so it must be
    // called from the thread itself.
    //
    affinityMask = pool->AffinityMask;
    if (affinityMask != 0) {
        KeSetSystemAffinityThread(affinityMask);
    }

    //
    // Set ideal processor for cache locality
    //
    processorCount = KeQueryActiveProcessorCount(NULL);
    if (processorCount > 0) {
        idealProc = threadInfo->ThreadIndex % processorCount;
        KeSetIdealProcessorThread(KeGetCurrentThread(), (CCHAR)idealProc);
    }

    //
    // Apply thread priority
    //
    TppSetThreadPriority(KeGetCurrentThread(), pool->DefaultPriority);

    //
    // Call initialization callback
    //
    if (pool->InitCallback != NULL) {
        pool->InitCallback(
            threadInfo->ThreadIndex,
            pool->CallbackContext
        );
    }

    //
    // Mark as idle
    //
    threadInfo->State = TpThreadState_Idle;
    KeQuerySystemTime(&threadInfo->IdleStartTime);

    //
    // Set up wait objects:
    //   [0] = WorkAvailableSemaphore (auto-decremented on wake)
    //   [1] = StopEvent (thread-specific stop)
    //   [2] = ShutdownEvent (pool-wide shutdown)
    //
    waitObjects[0] = &pool->WorkAvailableSemaphore;
    waitObjects[1] = &threadInfo->StopEvent;
    waitObjects[2] = &pool->ShutdownEvent;

    //
    // Main work loop
    //
    while (!threadInfo->StopRequested && !pool->ShuttingDown) {

        timeout.QuadPart = -((LONGLONG)TP_WORK_WAIT_TIMEOUT_MS * 10000);

        waitStatus = KeWaitForMultipleObjects(
            3,
            waitObjects,
            WaitAny,
            Executive,
            KernelMode,
            FALSE,
            &timeout,
            NULL
        );

        //
        // Check exit conditions
        //
        if (threadInfo->StopRequested || pool->ShuttingDown) {
            break;
        }

        //
        // If signaled by StopEvent or ShutdownEvent → exit
        //
        if (waitStatus == STATUS_WAIT_1 || waitStatus == STATUS_WAIT_2) {
            break;
        }

        //
        // If work semaphore was signaled → execute work
        //
        if (waitStatus == STATUS_WAIT_0) {
            //
            // Get current executor under shared lock
            //
            KeEnterCriticalRegion();
            ExAcquirePushLockShared(&pool->ExecutorLock);
            executor = pool->WorkExecutor;
            executorContext = pool->ExecutorContext;
            ExReleasePushLockShared(&pool->ExecutorLock);
            KeLeaveCriticalRegion();

            if (executor != NULL) {
                //
                // Transition: Idle → Running
                //
                threadInfo->State = TpThreadState_Running;
                InterlockedDecrement(&pool->IdleThreadCount);
                InterlockedIncrement(&pool->RunningThreadCount);
                KeQuerySystemTime(&threadInfo->WorkStartTime);
                InterlockedExchange(&threadInfo->IsExecuting, 1);

                //
                // Track idle time
                //
                KeQuerySystemTime(&currentTime);
                InterlockedAdd64(
                    &threadInfo->TotalIdleTimeMs,
                    (currentTime.QuadPart - threadInfo->IdleStartTime.QuadPart) / 10000
                );

                //
                // Execute work.
                // The executor is called with the semaphore (as PKEVENT-compatible)
                // and shutdown event so it can implement its own wait loop.
                //
                executor(
                    threadInfo,
                    (PKEVENT)&pool->WorkAvailableSemaphore,
                    &pool->ShutdownEvent,
                    executorContext
                );

                //
                // Track work time
                //
                KeQuerySystemTime(&currentTime);
                InterlockedAdd64(
                    &threadInfo->TotalWorkTimeMs,
                    (currentTime.QuadPart - threadInfo->WorkStartTime.QuadPart) / 10000
                );
                InterlockedIncrement64(&threadInfo->WorkItemsCompleted);
                InterlockedIncrement64(&pool->Stats.TotalWorkItems);

                //
                // Transition: Running → Idle
                //
                InterlockedExchange(&threadInfo->IsExecuting, 0);
                InterlockedDecrement(&pool->RunningThreadCount);
                InterlockedIncrement(&pool->IdleThreadCount);
                threadInfo->State = TpThreadState_Idle;
                KeQuerySystemTime(&threadInfo->IdleStartTime);
                KeQuerySystemTime(&threadInfo->LastActivityTime);
            }
        }

        // STATUS_TIMEOUT: just loop and check conditions again
    }

ExitCleanup:
    //
    // Only decrement pool counters if this thread was registered in the pool.
    // Threads that failed ObReferenceObjectByHandle during creation were never
    // added to the pool list or counted — decrementing would corrupt counters.
    //
    if (threadInfo->Registered) {
        //
        // Save state BEFORE setting Stopping,
        // then decrement the correct counter based on saved state.
        //
        preExitState = threadInfo->State;
        threadInfo->State = TpThreadState_Stopping;

        if (preExitState == TpThreadState_Idle ||
            preExitState == TpThreadState_Starting) {
            InterlockedDecrement(&pool->IdleThreadCount);
        } else if (preExitState == TpThreadState_Running) {
            InterlockedDecrement(&pool->RunningThreadCount);
        }

        //
        // Remove ourselves from the thread list under spinlock.
        // TppDestroyThread may have already removed us (TpRemoveThreads path),
        // so check IsListEmpty first.
        //
        KeAcquireSpinLock(&pool->ThreadListLock, &oldIrql);
        if (!IsListEmpty(&threadInfo->ListEntry)) {
            RemoveEntryList(&threadInfo->ListEntry);
            InitializeListHead(&threadInfo->ListEntry);
        }
        KeReleaseSpinLock(&pool->ThreadListLock, oldIrql);

        InterlockedDecrement(&pool->ThreadCount);

        //
        // Signal if last thread
        //
        if (InterlockedCompareExchange(&pool->ThreadCount, 0, 0) == 0) {
            KeSetEvent(&pool->AllThreadsStoppedEvent, IO_NO_INCREMENT, FALSE);
        }
    } else {
        threadInfo->State = TpThreadState_Stopping;
    }

    threadInfo->State = TpThreadState_Stopped;

    //
    // Self-cleanup: only if NOT owned by TppDestroyThread.
    // This covers: (1) scale-down, (2) unregistered threads (ObRef failure),
    // (3) threads that self-remove during shutdown before TpDestroy collects them.
    // OwnerWillDestroy is the sole discriminator — set by TppDestroyThread
    // before signaling stop.
    //
    if (!threadInfo->OwnerWillDestroy) {
        //
        // Close our own handle and dereference ourselves
        //
        if (threadInfo->ThreadHandle != NULL) {
            ZwClose(threadInfo->ThreadHandle);
            threadInfo->ThreadHandle = NULL;
        }
        if (threadInfo->ThreadObject != NULL) {
            ObDereferenceObject(threadInfo->ThreadObject);
            threadInfo->ThreadObject = NULL;
        }

        //
        // Cleanup callback
        //
        if (pool->CleanupCallback != NULL) {
            pool->CleanupCallback(
                threadInfo->ThreadIndex,
                pool->CallbackContext
            );
        }

        threadInfo->Magic = 0;
        TppReleasePoolReference(pool);
        ShadowStrikeFreePoolWithTag(threadInfo, TP_POOL_TAG_THREAD);
        InterlockedIncrement64(&pool->Stats.ThreadsDestroyed);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

// ============================================================================
// PRIVATE IMPLEMENTATION - SCALING (DPC → WORK ITEM → PASSIVE_LEVEL)
// ============================================================================

/**
 * @brief DPC routine fired by the scale timer.
 *
 * Runs at DISPATCH_LEVEL. MUST NOT call PsCreateSystemThread, ZwClose,
 * KeWaitForSingleObject, or any PASSIVE_LEVEL API.
 * Defers ALL scaling work to TppScaleWorkItemRoutine via IoQueueWorkItem.
 */
_Function_class_(KDEFERRED_ROUTINE)
static VOID
TppScaleDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
)
{
    PTP_THREAD_POOL pool = (PTP_THREAD_POOL)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (pool == NULL || pool->Magic != TP_POOL_MAGIC) {
        return;
    }

    if (pool->ShuttingDown) {
        return;
    }

    //
    // Guard against double-queuing the work item (IoQueueWorkItem contract)
    //
    if (pool->ScaleWorkItem != NULL) {
        if (InterlockedCompareExchange(&pool->ScaleWorkItemQueued, 1, 0) == 0) {
            KeClearEvent(&pool->ScaleWorkItemComplete);
            IoQueueWorkItem(
                pool->ScaleWorkItem,
                TppScaleWorkItemRoutine,
                DelayedWorkQueue,
                pool
            );
        }
    }
}

/**
 * @brief Work item routine for scaling. Runs at PASSIVE_LEVEL.
 *
 * Safe to call PsCreateSystemThread, ZwClose, KeWaitForSingleObject, etc.
 */
_Function_class_(IO_WORKITEM_ROUTINE)
static VOID NTAPI
TppScaleWorkItemRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
)
{
    PTP_THREAD_POOL pool = (PTP_THREAD_POOL)Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (pool == NULL || pool->Magic != TP_POOL_MAGIC || pool->ShuttingDown) {
        if (pool != NULL) {
            InterlockedExchange(&pool->ScaleWorkItemQueued, 0);
            KeSetEvent(&pool->ScaleWorkItemComplete, IO_NO_INCREMENT, FALSE);
        }
        return;
    }

    TppEvaluateScaling(pool);

    //
    // Allow next DPC to queue another work item
    //
    InterlockedExchange(&pool->ScaleWorkItemQueued, 0);
    KeSetEvent(&pool->ScaleWorkItemComplete, IO_NO_INCREMENT, FALSE);
}

/**
 * @brief Evaluate current thread utilization and scale up/down.
 *
 * IRQL: PASSIVE_LEVEL (called from work item routine).
 * This function may create or signal threads.
 */
_IRQL_requires_(PASSIVE_LEVEL)
static VOID
TppEvaluateScaling(
    _Inout_ PTP_THREAD_POOL Pool
)
{
    LARGE_INTEGER currentTime;
    LONG64 timeSinceLastScale;
    ULONG totalThreads;
    ULONG idleThreads;
    ULONG runningThreads;
    ULONG utilization;
    ULONG minThreads;
    ULONG maxThreads;
    ULONG scaleUp;
    ULONG scaleDown;
    BOOLEAN shouldScaleUp = FALSE;
    BOOLEAN shouldScaleDown = FALSE;

    PAGED_CODE();

    //
    // Cooldown check
    //
    KeQuerySystemTime(&currentTime);
    timeSinceLastScale = (currentTime.QuadPart - Pool->LastScaleTime.QuadPart) / 10000;

    if (timeSinceLastScale < TP_SCALE_COOLDOWN_MS) {
        return;
    }

    //
    // Prevent concurrent scaling
    //
    if (InterlockedCompareExchange(&Pool->ScaleInProgress, 1, 0) != 0) {
        return;
    }

    //
    // Read configuration under lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Pool->ConfigLock);
    minThreads = Pool->MinThreads;
    maxThreads = Pool->MaxThreads;
    scaleUp = Pool->ScaleUpThreshold;
    scaleDown = Pool->ScaleDownThreshold;
    ExReleasePushLockShared(&Pool->ConfigLock);
    KeLeaveCriticalRegion();

    //
    // Read current state
    //
    totalThreads = (ULONG)InterlockedCompareExchange(&Pool->ThreadCount, 0, 0);
    idleThreads = (ULONG)InterlockedCompareExchange(&Pool->IdleThreadCount, 0, 0);
    runningThreads = (ULONG)InterlockedCompareExchange(&Pool->RunningThreadCount, 0, 0);

    if (totalThreads == 0) {
        InterlockedExchange(&Pool->ScaleInProgress, 0);
        return;
    }

    utilization = (runningThreads * 100) / totalThreads;

    if (utilization >= scaleUp && totalThreads < maxThreads) {
        shouldScaleUp = TRUE;
    } else if (utilization <= scaleDown && totalThreads > minThreads) {
        shouldScaleDown = TRUE;
    }

    if (shouldScaleUp) {
        //
        // CRITICAL-01 fix: PsCreateSystemThread now runs at PASSIVE_LEVEL
        // (this function is called from a work item routine).
        //
        PTP_THREAD_INFO newThread;
        NTSTATUS status = TppCreateThread(Pool, &newThread);
        if (NT_SUCCESS(status)) {
            InterlockedIncrement64(&Pool->Stats.ScaleUpCount);
            InterlockedIncrement64(&Pool->Stats.ThreadsCreated);
        }
    } else if (shouldScaleDown) {
        //
        // CRITICAL-02 fix: Find idle thread with timeout exceeded.
        // Remove from list under spinlock. Signal stop.
        // The worker thread handles its own cleanup (self-destruct pattern).
        //
        PLIST_ENTRY entry;
        PTP_THREAD_INFO threadToRemove = NULL;
        KIRQL oldIrql;

        KeAcquireSpinLock(&Pool->ThreadListLock, &oldIrql);

        for (entry = Pool->ThreadList.Flink;
             entry != &Pool->ThreadList;
             entry = entry->Flink) {

            PTP_THREAD_INFO ti = CONTAINING_RECORD(entry, TP_THREAD_INFO, ListEntry);

            if (ti->State == TpThreadState_Idle) {
                LARGE_INTEGER idleTime;
                idleTime.QuadPart = currentTime.QuadPart - ti->IdleStartTime.QuadPart;

                if (idleTime.QuadPart / 10000 >= (LONGLONG)Pool->IdleTimeoutMs) {
                    //
                    // DON'T remove from list here — the thread will self-remove on exit
                    //
                    threadToRemove = ti;
                    break;
                }
            }
        }

        KeReleaseSpinLock(&Pool->ThreadListLock, oldIrql);

        if (threadToRemove != NULL) {
            //
            // Signal the thread to stop. It will self-cleanup.
            //
            TppSignalThreadStop(threadToRemove);
            InterlockedIncrement64(&Pool->Stats.ScaleDownCount);
        }
    }

    Pool->LastScaleTime = currentTime;
    InterlockedExchange(&Pool->ScaleInProgress, 0);
}

// ============================================================================
// PRIVATE IMPLEMENTATION - UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Default work executor — logs a warning and returns.
 *
 * If no executor is set, work signals are consumed with a warning.
 * In production, callers MUST set a real executor via TpSetWorkExecutor
 * before signaling work.
 */
static VOID
TppDefaultWorkExecutor(
    _In_ PTP_THREAD_INFO ThreadInfo,
    _In_ PKEVENT WorkEvent,
    _In_ PKEVENT ShutdownEvent,
    _In_opt_ PVOID ExecutorContext
)
{
    UNREFERENCED_PARAMETER(ThreadInfo);
    UNREFERENCED_PARAMETER(WorkEvent);
    UNREFERENCED_PARAMETER(ShutdownEvent);
    UNREFERENCED_PARAMETER(ExecutorContext);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
               "[ShadowStrike:TP] WARNING: Default work executor invoked. "
               "No work executor set. Call TpSetWorkExecutor() before signaling work.\n");
}

/**
 * @brief Validate pool pointer (safe at any IRQL).
 *
 * Only checks Magic and Initialized flag. No dereference of untrusted pointers.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
TppIsValidPool(
    _In_opt_ PTP_THREAD_POOL Pool
)
{
    if (Pool == NULL) {
        return FALSE;
    }

    //
    // __try is NOT available in kernel code at DISPATCH_LEVEL for structured
    // exception handling on arbitrary pointers. We trust that callers pass
    // valid pool pointers that were returned from TpCreate.
    //
    return (Pool->Magic == TP_POOL_MAGIC && Pool->Initialized);
}

/**
 * @brief Acquire a reference on the pool.
 */
static VOID
TppAcquirePoolReference(
    _Inout_ PTP_THREAD_POOL Pool
)
{
    InterlockedIncrement(&Pool->ReferenceCount);
}

/**
 * @brief Release a reference on the pool. Frees on last release.
 */
static VOID
TppReleasePoolReference(
    _Inout_ PTP_THREAD_POOL Pool
)
{
    LONG ref = InterlockedDecrement(&Pool->ReferenceCount);

    if (ref == 0) {
        ShadowStrikeFreePoolWithTag(Pool, TP_POOL_TAG_CONTEXT);
    }
}

/**
 * @brief Set kernel thread priority.
 *
 * Uses KeSetPriorityThread (absolute priority), NOT KeSetBasePriorityThread
 * (which takes a priority INCREMENT, not an absolute value — HIGH-06 fix).
 *
 * KeSetPriorityThread is safe at any IRQL.
 */
static VOID
TppSetThreadPriority(
    _In_ PKTHREAD Thread,
    _In_ TP_THREAD_PRIORITY Priority
)
{
    KPRIORITY absolutePriority;

    switch (Priority) {
        case TpPriority_Lowest:
            absolutePriority = LOW_PRIORITY + 1;
            break;
        case TpPriority_BelowNormal:
            absolutePriority = LOW_REALTIME_PRIORITY - 2;
            break;
        case TpPriority_Normal:
            absolutePriority = LOW_REALTIME_PRIORITY;
            break;
        case TpPriority_AboveNormal:
            absolutePriority = LOW_REALTIME_PRIORITY + 2;
            break;
        case TpPriority_Highest:
            absolutePriority = HIGH_PRIORITY;
            break;
        case TpPriority_TimeCritical:
            absolutePriority = HIGH_PRIORITY + 1;
            break;
        default:
            absolutePriority = LOW_REALTIME_PRIORITY;
            break;
    }

    //
    // HIGH-06 fix: KeSetPriorityThread takes absolute priority.
    // KeSetBasePriorityThread takes an INCREMENT — wrong API for absolute values.
    //
    KeSetPriorityThread(Thread, absolutePriority);
}
