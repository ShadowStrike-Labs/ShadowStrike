/*++
    ShadowStrike Next-Generation Antivirus
    Module: AsyncWorkQueue.h
    
    Purpose: Asynchronous work queue for deferred processing of
             kernel events without blocking critical paths.
             
    Architecture:
    - Multiple priority levels (Critical, High, Normal, Low)
    - Work stealing between threads for load balancing
    - Bounded queue with back-pressure support
    - Per-CPU local queues for reduced contention
    
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

//=============================================================================
// Pool Tags
//=============================================================================

#define AWQ_POOL_TAG_QUEUE      'QWQA'  // Async Work Queue - Queue
#define AWQ_POOL_TAG_ITEM       'IWQA'  // Async Work Queue - Item
#define AWQ_POOL_TAG_THREAD     'TWQA'  // Async Work Queue - Thread
#define AWQ_POOL_TAG_CONTEXT    'CWQA'  // Async Work Queue - Context

//=============================================================================
// Configuration Constants
//=============================================================================

// Queue sizes
#define AWQ_DEFAULT_QUEUE_SIZE          16384       // Items per queue
#define AWQ_MIN_QUEUE_SIZE              256
#define AWQ_MAX_QUEUE_SIZE              (1024 * 1024)

// Thread pool
#define AWQ_MIN_THREADS                 2
#define AWQ_MAX_THREADS                 64
#define AWQ_DEFAULT_THREADS_PER_CPU     2
#define AWQ_MAX_IDLE_THREADS            8

// Timeouts
#define AWQ_DEFAULT_TIMEOUT_MS          5000        // 5 seconds
#define AWQ_SHUTDOWN_TIMEOUT_MS         30000       // 30 seconds
#define AWQ_IDLE_TIMEOUT_MS             60000       // 1 minute

// Work item limits
#define AWQ_MAX_WORK_ITEM_SIZE          (64 * 1024) // 64 KB context
#define AWQ_MAX_PENDING_ITEMS           (1024 * 1024)

//=============================================================================
// Priority Levels
//=============================================================================

typedef enum _AWQ_PRIORITY {
    AwqPriority_Low = 0,                // Background tasks
    AwqPriority_Normal = 1,             // Default priority
    AwqPriority_High = 2,               // Important tasks
    AwqPriority_Critical = 3,           // Must execute ASAP
    AwqPriority_Max = 4
} AWQ_PRIORITY;

//=============================================================================
// Work Item Flags
//=============================================================================

typedef enum _AWQ_WORK_FLAGS {
    AwqFlag_None                = 0x00000000,
    AwqFlag_LongRunning         = 0x00000001,   // May take a long time
    AwqFlag_CanCancel           = 0x00000002,   // Can be cancelled
    AwqFlag_Serialized          = 0x00000004,   // Execute serially (by key)
    AwqFlag_DeleteContext       = 0x00000008,   // Free context on completion
    AwqFlag_NotifyCompletion    = 0x00000010,   // Signal event on completion
    AwqFlag_RetryOnFailure      = 0x00000020,   // Retry if callback fails
    AwqFlag_ChainedItem         = 0x00000040,   // Part of a chain
    AwqFlag_NonPagedContext     = 0x00000080,   // Context in non-paged pool
    AwqFlag_AffineToSubmitter   = 0x00000100,   // Execute on submitting CPU
} AWQ_WORK_FLAGS;

//=============================================================================
// Work Item State
//=============================================================================

typedef enum _AWQ_ITEM_STATE {
    AwqItemState_Free = 0,
    AwqItemState_Queued,
    AwqItemState_Running,
    AwqItemState_Completed,
    AwqItemState_Cancelled,
    AwqItemState_Failed,
    AwqItemState_Retrying
} AWQ_ITEM_STATE;

//=============================================================================
// Queue State
//=============================================================================

typedef enum _AWQ_QUEUE_STATE {
    AwqQueueState_Uninitialized = 0,
    AwqQueueState_Initializing,
    AwqQueueState_Running,
    AwqQueueState_Paused,
    AwqQueueState_Draining,
    AwqQueueState_Shutdown
} AWQ_QUEUE_STATE;

//=============================================================================
// Callback Types
//=============================================================================

//
// Work callback - executed for each work item
//
typedef NTSTATUS (*AWQ_WORK_CALLBACK)(
    _In_opt_ PVOID Context,
    _In_ ULONG ContextSize
    );

//
// Completion callback - called when work item completes
//
typedef VOID (*AWQ_COMPLETION_CALLBACK)(
    _In_ NTSTATUS Status,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID CompletionContext
    );

//
// Cleanup callback - called to free context
//
typedef VOID (*AWQ_CLEANUP_CALLBACK)(
    _In_opt_ PVOID Context
    );

//=============================================================================
// Work Item
//=============================================================================

typedef struct _AWQ_WORK_ITEM {
    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
    
    //
    // Item identification
    //
    ULONG64 ItemId;
    ULONG64 SerializationKey;           // For serialized execution
    AWQ_PRIORITY Priority;
    AWQ_WORK_FLAGS Flags;
    volatile AWQ_ITEM_STATE State;
    
    //
    // Callbacks
    //
    AWQ_WORK_CALLBACK WorkCallback;
    AWQ_COMPLETION_CALLBACK CompletionCallback;
    AWQ_CLEANUP_CALLBACK CleanupCallback;
    PVOID CompletionContext;
    
    //
    // Work context
    //
    PVOID Context;
    ULONG ContextSize;
    
    //
    // Timing
    //
    LARGE_INTEGER SubmitTime;
    LARGE_INTEGER StartTime;
    LARGE_INTEGER EndTime;
    ULONG TimeoutMs;
    
    //
    // Retry support
    //
    ULONG RetryCount;
    ULONG MaxRetries;
    ULONG RetryDelayMs;
    
    //
    // Completion signaling
    //
    PKEVENT CompletionEvent;
    NTSTATUS CompletionStatus;
    
    //
    // Chaining support
    //
    struct _AWQ_WORK_ITEM* NextInChain;
    ULONG ChainIndex;
    ULONG ChainLength;
    
    //
    // Execution tracking
    //
    ULONG ExecutingCpu;
    HANDLE ExecutingThread;
    
    //
    // Reference counting
    //
    volatile LONG RefCount;
    
} AWQ_WORK_ITEM, *PAWQ_WORK_ITEM;

//=============================================================================
// Per-Priority Queue
//=============================================================================

typedef struct _AWQ_PRIORITY_QUEUE {
    //
    // Queue storage (lock-free MPMC)
    //
    LIST_ENTRY ItemList;
    KSPIN_LOCK Lock;
    
    //
    // Queue state
    //
    volatile LONG ItemCount;
    volatile LONG PeakCount;
    ULONG MaxItems;
    
    //
    // Statistics
    //
    volatile LONG64 TotalEnqueued;
    volatile LONG64 TotalDequeued;
    volatile LONG64 TotalDropped;
    
    //
    // Semaphore for waiting threads
    //
    KSEMAPHORE ItemSemaphore;
    
} AWQ_PRIORITY_QUEUE, *PAWQ_PRIORITY_QUEUE;

//=============================================================================
// Worker Thread
//=============================================================================

typedef struct _AWQ_WORKER_THREAD {
    //
    // Thread handle
    //
    HANDLE ThreadHandle;
    PKTHREAD ThreadObject;
    ULONG ThreadId;
    
    //
    // Thread state
    //
    volatile BOOLEAN Running;
    volatile BOOLEAN Idle;
    LARGE_INTEGER IdleStartTime;
    
    //
    // Current work
    //
    PAWQ_WORK_ITEM CurrentItem;
    
    //
    // Statistics
    //
    volatile LONG64 ItemsProcessed;
    volatile LONG64 TotalProcessingTime;
    
    //
    // Affinity
    //
    ULONG PreferredCpu;
    BOOLEAN AffinitySet;
    
    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
    
} AWQ_WORKER_THREAD, *PAWQ_WORKER_THREAD;

//=============================================================================
// Work Queue Manager
//=============================================================================

typedef struct _AWQ_MANAGER {
    //
    // Queue state
    //
    volatile AWQ_QUEUE_STATE State;
    
    //
    // Priority queues
    //
    AWQ_PRIORITY_QUEUE PriorityQueues[AwqPriority_Max];
    
    //
    // Worker threads
    //
    LIST_ENTRY WorkerList;
    KSPIN_LOCK WorkerListLock;
    volatile LONG WorkerCount;
    volatile LONG IdleWorkerCount;
    volatile LONG ActiveWorkerCount;
    ULONG MinWorkers;
    ULONG MaxWorkers;
    
    //
    // Thread management
    //
    KEVENT NewWorkEvent;                // Signal when work available
    KEVENT ShutdownEvent;               // Signal for shutdown
    KEVENT DrainCompleteEvent;          // Signal when drained
    
    //
    // Work item ID generation
    //
    volatile LONG64 NextItemId;
    
    //
    // Serialization support
    //
    struct {
        LIST_ENTRY ActiveKeys;          // Keys with running items
        KSPIN_LOCK Lock;
    } Serialization;
    
    //
    // Statistics
    //
    struct {
        volatile LONG64 TotalSubmitted;
        volatile LONG64 TotalCompleted;
        volatile LONG64 TotalCancelled;
        volatile LONG64 TotalFailed;
        volatile LONG64 TotalRetries;
        volatile LONG64 TotalTimeouts;
        LARGE_INTEGER StartTime;
    } Stats;
    
    //
    // Configuration
    //
    struct {
        ULONG DefaultTimeoutMs;
        ULONG MaxItemSize;
        ULONG MaxQueueSize;
        BOOLEAN EnableWorkStealing;
        BOOLEAN EnableDynamicThreads;
    } Config;
    
    //
    // Free list for work items
    //
    struct {
        LIST_ENTRY FreeList;
        KSPIN_LOCK Lock;
        volatile LONG FreeCount;
        ULONG MaxFreeItems;
    } ItemCache;
    
} AWQ_MANAGER, *PAWQ_MANAGER;

//=============================================================================
// Work Item Options
//=============================================================================

typedef struct _AWQ_SUBMIT_OPTIONS {
    AWQ_PRIORITY Priority;
    AWQ_WORK_FLAGS Flags;
    ULONG TimeoutMs;
    ULONG64 SerializationKey;
    AWQ_COMPLETION_CALLBACK CompletionCallback;
    AWQ_CLEANUP_CALLBACK CleanupCallback;
    PVOID CompletionContext;
    ULONG MaxRetries;
    ULONG RetryDelayMs;
    PKEVENT CompletionEvent;
} AWQ_SUBMIT_OPTIONS, *PAWQ_SUBMIT_OPTIONS;

//=============================================================================
// Public API - Initialization
//=============================================================================

//
// Initialize the work queue manager
//
NTSTATUS
AwqInitialize(
    _Out_ PAWQ_MANAGER* Manager,
    _In_ ULONG MinThreads,
    _In_ ULONG MaxThreads,
    _In_ ULONG MaxQueueSize
    );

//
// Shutdown the work queue manager
//
VOID
AwqShutdown(
    _Inout_ PAWQ_MANAGER Manager,
    _In_ BOOLEAN WaitForCompletion
    );

//
// Pause/Resume processing
//
NTSTATUS
AwqPause(
    _Inout_ PAWQ_MANAGER Manager
    );

NTSTATUS
AwqResume(
    _Inout_ PAWQ_MANAGER Manager
    );

//
// Drain all pending work
//
NTSTATUS
AwqDrain(
    _Inout_ PAWQ_MANAGER Manager,
    _In_ ULONG TimeoutMs
    );

//=============================================================================
// Public API - Work Submission
//=============================================================================

//
// Submit a work item
//
NTSTATUS
AwqSubmit(
    _In_ PAWQ_MANAGER Manager,
    _In_ AWQ_WORK_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _In_ ULONG ContextSize,
    _In_opt_ PAWQ_SUBMIT_OPTIONS Options,
    _Out_opt_ PULONG64 ItemId
    );

//
// Submit with inline context (allocates and copies)
//
NTSTATUS
AwqSubmitWithContext(
    _In_ PAWQ_MANAGER Manager,
    _In_ AWQ_WORK_CALLBACK Callback,
    _In_reads_bytes_(ContextSize) PVOID Context,
    _In_ ULONG ContextSize,
    _In_ AWQ_PRIORITY Priority,
    _Out_opt_ PULONG64 ItemId
    );

//
// Submit a chain of work items
//
NTSTATUS
AwqSubmitChain(
    _In_ PAWQ_MANAGER Manager,
    _In_reads_(Count) AWQ_WORK_CALLBACK* Callbacks,
    _In_reads_opt_(Count) PVOID* Contexts,
    _In_reads_opt_(Count) ULONG* ContextSizes,
    _In_ ULONG Count,
    _In_ AWQ_PRIORITY Priority,
    _Out_opt_ PULONG64 ChainId
    );

//=============================================================================
// Public API - Work Item Management
//=============================================================================

//
// Cancel a work item by ID
//
NTSTATUS
AwqCancel(
    _In_ PAWQ_MANAGER Manager,
    _In_ ULONG64 ItemId
    );

//
// Cancel all items with serialization key
//
NTSTATUS
AwqCancelByKey(
    _In_ PAWQ_MANAGER Manager,
    _In_ ULONG64 SerializationKey
    );

//
// Wait for a specific item to complete
//
NTSTATUS
AwqWaitForItem(
    _In_ PAWQ_MANAGER Manager,
    _In_ ULONG64 ItemId,
    _In_ ULONG TimeoutMs,
    _Out_opt_ PNTSTATUS ItemStatus
    );

//
// Wait for all items with key to complete
//
NTSTATUS
AwqWaitForKey(
    _In_ PAWQ_MANAGER Manager,
    _In_ ULONG64 SerializationKey,
    _In_ ULONG TimeoutMs
    );

//
// Get item status
//
NTSTATUS
AwqGetItemStatus(
    _In_ PAWQ_MANAGER Manager,
    _In_ ULONG64 ItemId,
    _Out_ PAWQ_ITEM_STATE State,
    _Out_opt_ PNTSTATUS CompletionStatus
    );

//=============================================================================
// Public API - Thread Management
//=============================================================================

//
// Adjust thread pool size
//
NTSTATUS
AwqSetThreadCount(
    _Inout_ PAWQ_MANAGER Manager,
    _In_ ULONG MinThreads,
    _In_ ULONG MaxThreads
    );

//
// Get current thread count
//
VOID
AwqGetThreadCount(
    _In_ PAWQ_MANAGER Manager,
    _Out_ PULONG Current,
    _Out_ PULONG Idle,
    _Out_ PULONG Active
    );

//=============================================================================
// Public API - Statistics
//=============================================================================

typedef struct _AWQ_STATISTICS {
    //
    // Queue state
    //
    AWQ_QUEUE_STATE State;
    
    //
    // Item counts
    //
    ULONG64 TotalSubmitted;
    ULONG64 TotalCompleted;
    ULONG64 TotalCancelled;
    ULONG64 TotalFailed;
    ULONG64 TotalRetries;
    ULONG64 TotalTimeouts;
    
    //
    // Queue depths
    //
    ULONG PendingItems[AwqPriority_Max];
    ULONG TotalPending;
    ULONG PeakPending;
    
    //
    // Thread pool
    //
    ULONG WorkerCount;
    ULONG IdleWorkers;
    ULONG ActiveWorkers;
    
    //
    // Timing
    //
    LARGE_INTEGER UpTime;
    ULONG64 AverageWaitTimeUs;
    ULONG64 AverageProcessTimeUs;
    ULONG64 ItemsPerSecond;
    
    //
    // Per-priority breakdown
    //
    struct {
        ULONG64 Submitted;
        ULONG64 Completed;
        ULONG Pending;
    } PerPriority[AwqPriority_Max];
    
} AWQ_STATISTICS, *PAWQ_STATISTICS;

NTSTATUS
AwqGetStatistics(
    _In_ PAWQ_MANAGER Manager,
    _Out_ PAWQ_STATISTICS Stats
    );

VOID
AwqResetStatistics(
    _Inout_ PAWQ_MANAGER Manager
    );

//=============================================================================
// Public API - Configuration
//=============================================================================

//
// Set default timeout
//
NTSTATUS
AwqSetDefaultTimeout(
    _Inout_ PAWQ_MANAGER Manager,
    _In_ ULONG TimeoutMs
    );

//
// Enable/disable work stealing
//
NTSTATUS
AwqSetWorkStealing(
    _Inout_ PAWQ_MANAGER Manager,
    _In_ BOOLEAN Enable
    );

//
// Enable/disable dynamic thread scaling
//
NTSTATUS
AwqSetDynamicThreads(
    _Inout_ PAWQ_MANAGER Manager,
    _In_ BOOLEAN Enable
    );

//=============================================================================
// Helper Macros
//=============================================================================

//
// Quick submit for common cases
//
#define AwqSubmitNormal(Manager, Callback, Context, Size) \
    AwqSubmitWithContext(Manager, Callback, Context, Size, AwqPriority_Normal, NULL)

#define AwqSubmitHigh(Manager, Callback, Context, Size) \
    AwqSubmitWithContext(Manager, Callback, Context, Size, AwqPriority_High, NULL)

#define AwqSubmitCritical(Manager, Callback, Context, Size) \
    AwqSubmitWithContext(Manager, Callback, Context, Size, AwqPriority_Critical, NULL)

#ifdef __cplusplus
}
#endif
