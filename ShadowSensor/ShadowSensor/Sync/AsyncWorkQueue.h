/*++
    ShadowStrike Next-Generation Antivirus
    Module: AsyncWorkQueue.h

    Purpose: Asynchronous work queue for deferred processing of
             kernel events without blocking critical paths.

    Architecture:
    - Four priority levels (Critical, High, Normal, Low)
    - Bounded queues with back-pressure (STATUS_QUOTA_EXCEEDED)
    - Dynamic thread pool with idle-timeout scaling
    - Serialized execution by key (mutual exclusion per key)
    - Work item chaining (sequential pipeline execution)
    - Reference-counted items for safe concurrent access
    - EX_RUNDOWN_REF lifecycle: every public API acquires rundown
      protection; shutdown waits for all outstanding calls to drain
    - EX_PUSH_LOCK synchronization (IRQL <= APC_LEVEL for all ops)
    - All callbacks execute at PASSIVE_LEVEL outside any lock

    Thread safety:
    - All public APIs are safe to call concurrently.
    - AwqInitialize must be called once before any other API.
    - AwqShutdown always waits for all workers and pending items.
    - After AwqShutdown returns, the handle is invalid.

    Callback lifetime contract:
    - WorkCallback: called at PASSIVE_LEVEL on a worker thread.
      The Context pointer is valid for the duration of the call.
    - CompletionCallback: called at PASSIVE_LEVEL after the work
      callback returns. Called even on failure or cancellation.
    - CleanupCallback: called at PASSIVE_LEVEL after completion
      callback. Always called if set, regardless of DeleteContext.
      Called before the context is freed.

    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

// ============================================================================
// Pool Tags (one per allocation type for leak tracking)
// ============================================================================

#define AWQ_POOL_TAG_MGR        'mWQA'  // Manager structure
#define AWQ_POOL_TAG_ITEM       'iWQA'  // Work items
#define AWQ_POOL_TAG_THREAD     'tWQA'  // Worker thread structs
#define AWQ_POOL_TAG_CTX        'cWQA'  // Copied context buffers
#define AWQ_POOL_TAG_HASH       'hWQA'  // Hash table buckets/chains
#define AWQ_POOL_TAG_SKEY       'sWQA'  // Serialization key entries

// ============================================================================
// Configuration Constants
// ============================================================================

#define AWQ_MIN_THREADS                 1
#define AWQ_MAX_THREADS                 64
#define AWQ_DEFAULT_THREADS_PER_CPU     1

#define AWQ_MIN_QUEUE_SIZE              64
#define AWQ_MAX_QUEUE_SIZE              (256 * 1024)
#define AWQ_DEFAULT_QUEUE_SIZE          4096

#define AWQ_DEFAULT_TIMEOUT_MS          5000
#define AWQ_SHUTDOWN_TIMEOUT_MS         30000
#define AWQ_IDLE_TIMEOUT_MS             60000

#define AWQ_MAX_CONTEXT_SIZE            (64 * 1024)
#define AWQ_MAX_CHAIN_LENGTH            64
#define AWQ_MAX_RETRIES                 5
#define AWQ_ITEM_CACHE_SIZE             128
#define AWQ_HASH_BUCKET_COUNT           1024

// ============================================================================
// Priority Levels
// ============================================================================

typedef enum _AWQ_PRIORITY {
    AwqPriority_Low      = 0,
    AwqPriority_Normal   = 1,
    AwqPriority_High     = 2,
    AwqPriority_Critical = 3,
    AwqPriority_Count    = 4
} AWQ_PRIORITY;

// ============================================================================
// Work Item Flags
// ============================================================================

typedef enum _AWQ_WORK_FLAGS {
    AwqFlag_None             = 0x00000000,
    AwqFlag_CanCancel        = 0x00000001,
    AwqFlag_DeleteContext    = 0x00000002,  // Queue copies context; frees on completion
    AwqFlag_RetryOnFailure   = 0x00000004,
    AwqFlag_Serialized       = 0x00000008,  // Mutually exclusive by SerializationKey
} AWQ_WORK_FLAGS;

// ============================================================================
// Work Item State (value type returned to callers)
// ============================================================================

typedef enum _AWQ_ITEM_STATE {
    AwqItemState_Unknown    = 0,
    AwqItemState_Queued,
    AwqItemState_Running,
    AwqItemState_Completed,
    AwqItemState_Cancelled,
    AwqItemState_Failed,
} AWQ_ITEM_STATE;

// ============================================================================
// Queue State
// ============================================================================

typedef enum _AWQ_QUEUE_STATE {
    AwqQueueState_Uninitialized = 0,
    AwqQueueState_Running,
    AwqQueueState_Paused,
    AwqQueueState_Draining,
    AwqQueueState_ShuttingDown,
} AWQ_QUEUE_STATE;

// ============================================================================
// Callback Signatures
//
// All callbacks are invoked at PASSIVE_LEVEL outside any lock.
// The callee MUST NOT call back into the AWQ module from within
// a callback (no submit, cancel, wait, etc.) to avoid deadlock.
// ============================================================================

typedef NTSTATUS
(AWQ_WORK_CALLBACK)(
    _In_opt_ PVOID Context,
    _In_ ULONG ContextSize
    );
typedef AWQ_WORK_CALLBACK *PAWQ_WORK_CALLBACK;

typedef VOID
(AWQ_COMPLETION_CALLBACK)(
    _In_ NTSTATUS CompletionStatus,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID CompletionContext
    );
typedef AWQ_COMPLETION_CALLBACK *PAWQ_COMPLETION_CALLBACK;

typedef VOID
(AWQ_CLEANUP_CALLBACK)(
    _In_opt_ PVOID Context
    );
typedef AWQ_CLEANUP_CALLBACK *PAWQ_CLEANUP_CALLBACK;

// ============================================================================
// Opaque Handle
//
// Callers receive and pass HAWQ_MANAGER. Internal structures are
// hidden in the .c file. No internal fields are exposed.
// ============================================================================

DECLARE_HANDLE(HAWQ_MANAGER);

// ============================================================================
// Submission Options (caller fills before AwqSubmit)
// ============================================================================

typedef struct _AWQ_SUBMIT_OPTIONS {
    AWQ_PRIORITY            Priority;
    AWQ_WORK_FLAGS          Flags;
    ULONG                   TimeoutMs;          // 0 = use default
    ULONG64                 SerializationKey;   // Non-zero enables serialization
    PAWQ_COMPLETION_CALLBACK CompletionCallback;
    PAWQ_CLEANUP_CALLBACK   CleanupCallback;
    PVOID                   CompletionContext;
    ULONG                   MaxRetries;         // Capped at AWQ_MAX_RETRIES
    ULONG                   RetryDelayMs;
} AWQ_SUBMIT_OPTIONS, *PAWQ_SUBMIT_OPTIONS;

// ============================================================================
// Statistics (value-type snapshot, safe to read without lock)
// ============================================================================

typedef struct _AWQ_STATISTICS {
    AWQ_QUEUE_STATE State;

    ULONG64 TotalSubmitted;
    ULONG64 TotalCompleted;
    ULONG64 TotalCancelled;
    ULONG64 TotalFailed;
    ULONG64 TotalRetries;

    ULONG   PendingItems[AwqPriority_Count];
    ULONG   TotalPending;

    ULONG   WorkerCount;
    ULONG   IdleWorkers;
    ULONG   ActiveWorkers;

    LARGE_INTEGER UpTime;
    ULONG64 ItemsPerSecond;

    struct {
        ULONG64 Enqueued;
        ULONG64 Dequeued;
        ULONG64 Dropped;
        ULONG   Pending;
    } PerPriority[AwqPriority_Count];

} AWQ_STATISTICS, *PAWQ_STATISTICS;

// ============================================================================
// Public API — Lifecycle
// ============================================================================

//
// Initialize the work queue. Must be called at PASSIVE_LEVEL.
// On success, *Handle is valid until AwqShutdown is called.
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqInitialize(
    _Out_ HAWQ_MANAGER *Handle,
    _In_ ULONG MinThreads,
    _In_ ULONG MaxThreads,
    _In_ ULONG MaxQueueSize
    );

//
// Shut down the work queue. Cancels pending items, waits for all
// running items and workers to finish, then frees all resources.
// After return, Handle is invalid. Idempotent.
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
AwqShutdown(
    _In_ HAWQ_MANAGER Handle
    );

// ============================================================================
// Public API — Queue Control
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqPause(
    _In_ HAWQ_MANAGER Handle
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqResume(
    _In_ HAWQ_MANAGER Handle
    );

//
// Drain: stop accepting new work and wait for all pending/running
// items to complete. Returns STATUS_TIMEOUT if TimeoutMs expires.
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqDrain(
    _In_ HAWQ_MANAGER Handle,
    _In_ ULONG TimeoutMs
    );

// ============================================================================
// Public API — Work Submission
// ============================================================================

//
// Submit a single work item. If Options is NULL, uses Normal
// priority with default timeout. If AwqFlag_DeleteContext is set,
// the queue copies Context and frees the copy after callbacks.
//
// Returns STATUS_QUOTA_EXCEEDED if the target queue is full.
// Returns STATUS_DEVICE_NOT_READY if the queue is not running.
//
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
    );

//
// Convenience: submit with copied context at given priority.
//
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
    );

//
// Submit a chain of items. Each item executes sequentially — the
// next item is enqueued only when the previous one succeeds. On
// failure, remaining chain items are cleaned up. Returns the ID
// of the first item in ChainId.
//
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
    );

// ============================================================================
// Public API — Item Management
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqCancel(
    _In_ HAWQ_MANAGER Handle,
    _In_ ULONG64 ItemId
    );

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqCancelByKey(
    _In_ HAWQ_MANAGER Handle,
    _In_ ULONG64 SerializationKey
    );

//
// Wait for a specific item to complete. The item's completion
// status is returned in *ItemStatus. Returns STATUS_NOT_FOUND
// if the item has already been completed and reclaimed.
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqWaitForItem(
    _In_ HAWQ_MANAGER Handle,
    _In_ ULONG64 ItemId,
    _In_ ULONG TimeoutMs,
    _Out_opt_ PNTSTATUS ItemStatus
    );

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqGetItemStatus(
    _In_ HAWQ_MANAGER Handle,
    _In_ ULONG64 ItemId,
    _Out_ AWQ_ITEM_STATE *State,
    _Out_opt_ PNTSTATUS CompletionStatus
    );

// ============================================================================
// Public API — Thread Pool
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqSetThreadCount(
    _In_ HAWQ_MANAGER Handle,
    _In_ ULONG MinThreads,
    _In_ ULONG MaxThreads
    );

// ============================================================================
// Public API — Statistics & Configuration
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqGetStatistics(
    _In_ HAWQ_MANAGER Handle,
    _Out_ PAWQ_STATISTICS Stats
    );

_IRQL_requires_max_(APC_LEVEL)
VOID
AwqResetStatistics(
    _In_ HAWQ_MANAGER Handle
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqSetDefaultTimeout(
    _In_ HAWQ_MANAGER Handle,
    _In_ ULONG TimeoutMs
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
AwqSetDynamicThreads(
    _In_ HAWQ_MANAGER Handle,
    _In_ BOOLEAN Enable
    );

// ============================================================================
// Convenience Macros
// ============================================================================

#define AwqSubmitNormal(h, cb, ctx, sz) \
    AwqSubmitWithContext((h), (cb), (ctx), (sz), AwqPriority_Normal, NULL)

#define AwqSubmitHigh(h, cb, ctx, sz) \
    AwqSubmitWithContext((h), (cb), (ctx), (sz), AwqPriority_High, NULL)

#define AwqSubmitCritical(h, cb, ctx, sz) \
    AwqSubmitWithContext((h), (cb), (ctx), (sz), AwqPriority_Critical, NULL)

#ifdef __cplusplus
}
#endif
