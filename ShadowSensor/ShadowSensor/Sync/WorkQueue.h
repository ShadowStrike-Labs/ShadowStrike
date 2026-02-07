/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE KERNEL WORK QUEUE
 * ============================================================================
 *
 * @file WorkQueue.h
 * @brief Enterprise-grade work queue for kernel-mode EDR deferred processing.
 *
 * Provides CrowdStrike Falcon-level work queue capabilities with:
 * - System work queue integration (IoQueueWorkItem/ExQueueWorkItem)
 * - Filter manager work queue support (FltQueueGenericWorkItem)
 * - Priority-based work scheduling (Critical, High, Normal, Low, Background)
 * - Bounded queue with configurable backpressure
 * - Work item cancellation with cleanup callbacks
 * - Rundown protection for safe driver unload
 * - Per-CPU work distribution for cache locality
 * - Work item batching for efficiency
 * - Comprehensive statistics and monitoring
 * - IRQL-aware operation selection
 *
 * Architecture:
 * - Uses IoWorkItem for device-associated work (preferred for unload safety)
 * - Falls back to ExWorkItem for lightweight operations
 * - Integrates with FltQueueGenericWorkItem when filter instance available
 * - Reference-counted work items prevent use-after-free
 * - Rundown protection ensures clean driver unload
 *
 * Security Guarantees:
 * - Work items are validated before execution
 * - Context memory is properly managed (copy or reference)
 * - Cancellation is atomic and safe
 * - All operations are thread-safe
 * - Resource limits prevent DoS via queue flooding
 *
 * Performance Optimizations:
 * - Lookaside list for work item allocations
 * - Lock-free submission path where possible
 * - Batched notifications to reduce overhead
 * - Per-priority queues for fairness
 *
 * MITRE ATT&CK Coverage:
 * - T1055: Process Injection (deferred async processing)
 * - T1106: Native API (safe work deferral)
 * - T1562: Impair Defenses (reliable async execution)
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_WORK_QUEUE_H_
#define _SHADOWSTRIKE_WORK_QUEUE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <fltKernel.h>
#include <ntddk.h>
#include <wdm.h>

// ============================================================================
// POOL TAGS
// ============================================================================

/**
 * @brief Pool tag for work queue manager: 'qWSs'
 */
#define SHADOW_WQ_TAG               'qWSs'

/**
 * @brief Pool tag for work items: 'iWSs'
 */
#define SHADOW_WQ_ITEM_TAG          'iWSs'

/**
 * @brief Pool tag for work context: 'cWSs'
 */
#define SHADOW_WQ_CONTEXT_TAG       'cWSs'

/**
 * @brief Pool tag for batch allocations: 'bWSs'
 */
#define SHADOW_WQ_BATCH_TAG         'bWSs'

// ============================================================================
// CONFIGURATION CONSTANTS
// ============================================================================

/**
 * @brief Default maximum pending work items
 */
#define WQ_DEFAULT_MAX_PENDING          65536

/**
 * @brief Minimum allowed pending work items
 */
#define WQ_MIN_MAX_PENDING              256

/**
 * @brief Maximum allowed pending work items
 */
#define WQ_MAX_MAX_PENDING              (1024 * 1024)

/**
 * @brief Maximum inline context size (larger contexts are heap-allocated)
 */
#define WQ_MAX_INLINE_CONTEXT_SIZE      128

/**
 * @brief Maximum external context size (safety limit)
 */
#define WQ_MAX_CONTEXT_SIZE             (64 * 1024)

/**
 * @brief Default work item timeout (0 = no timeout)
 */
#define WQ_DEFAULT_TIMEOUT_MS           0

/**
 * @brief Shutdown timeout for pending work items
 */
#define WQ_SHUTDOWN_TIMEOUT_MS          30000

/**
 * @brief Lookaside list depth for work items
 */
#define WQ_LOOKASIDE_DEPTH              512

/**
 * @brief Maximum batch size for batched submissions
 */
#define WQ_MAX_BATCH_SIZE               64

/**
 * @brief Work queue version for compatibility
 */
#define WQ_VERSION_MAJOR                2
#define WQ_VERSION_MINOR                0

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Work item priority levels
 */
typedef enum _SHADOWSTRIKE_WQ_PRIORITY {
    /// Background priority - lowest, runs when system is idle
    ShadowWqPriorityBackground = 0,

    /// Low priority - below normal operations
    ShadowWqPriorityLow,

    /// Normal priority - default for most work items
    ShadowWqPriorityNormal,

    /// High priority - time-sensitive operations
    ShadowWqPriorityHigh,

    /// Critical priority - must execute ASAP
    ShadowWqPriorityCritical,

    /// Number of priority levels
    ShadowWqPriorityCount

} SHADOWSTRIKE_WQ_PRIORITY;

/**
 * @brief Work queue type
 */
typedef enum _SHADOWSTRIKE_WQ_TYPE {
    /// System work queue (IoQueueWorkItem)
    ShadowWqTypeSystem = 0,

    /// Filter manager work queue (FltQueueGenericWorkItem)
    ShadowWqTypeFilter,

    /// Executive work queue (ExQueueWorkItem)
    ShadowWqTypeExecutive,

    /// Delayed work queue (timer-based)
    ShadowWqTypeDelayed

} SHADOWSTRIKE_WQ_TYPE;

/**
 * @brief Work item state
 */
typedef enum _SHADOWSTRIKE_WQ_ITEM_STATE {
    /// Item is free/unallocated
    ShadowWqItemStateFree = 0,

    /// Item is allocated but not queued
    ShadowWqItemStateAllocated,

    /// Item is queued waiting for execution
    ShadowWqItemStateQueued,

    /// Item is currently executing
    ShadowWqItemStateRunning,

    /// Item completed successfully
    ShadowWqItemStateCompleted,

    /// Item was cancelled
    ShadowWqItemStateCancelled,

    /// Item failed during execution
    ShadowWqItemStateFailed

} SHADOWSTRIKE_WQ_ITEM_STATE;

/**
 * @brief Work queue state
 */
typedef enum _SHADOWSTRIKE_WQ_STATE {
    /// Queue is not initialized
    ShadowWqStateUninitialized = 0,

    /// Queue is initializing
    ShadowWqStateInitializing,

    /// Queue is running and accepting work
    ShadowWqStateRunning,

    /// Queue is paused (not accepting new work)
    ShadowWqStatePaused,

    /// Queue is draining (processing remaining, not accepting new)
    ShadowWqStateDraining,

    /// Queue is shutting down
    ShadowWqStateShutdown

} SHADOWSTRIKE_WQ_STATE;

/**
 * @brief Work item flags
 */
typedef enum _SHADOWSTRIKE_WQ_FLAGS {
    /// No special flags
    ShadowWqFlagNone                = 0x00000000,

    /// Copy context data (don't reference caller's buffer)
    ShadowWqFlagCopyContext         = 0x00000001,

    /// Work item can be cancelled
    ShadowWqFlagCancellable         = 0x00000002,

    /// Delete context on completion (if copied)
    ShadowWqFlagDeleteContext       = 0x00000004,

    /// Signal completion event when done
    ShadowWqFlagSignalCompletion    = 0x00000008,

    /// Long-running operation (use different queue)
    ShadowWqFlagLongRunning         = 0x00000010,

    /// Execute on specific processor
    ShadowWqFlagProcessorAffinity   = 0x00000020,

    /// Execute serially with same key
    ShadowWqFlagSerialized          = 0x00000040,

    /// Retry on failure
    ShadowWqFlagRetryOnFailure      = 0x00000080,

    /// Use non-paged pool for context
    ShadowWqFlagNonPagedContext     = 0x00000100,

    /// Part of a batch submission
    ShadowWqFlagBatched             = 0x00000200,

    /// High importance (front of queue)
    ShadowWqFlagHighImportance      = 0x00000400,

    /// Secure wipe context on completion
    ShadowWqFlagSecureContext       = 0x00000800

} SHADOWSTRIKE_WQ_FLAGS;

// ============================================================================
// CALLBACK TYPES
// ============================================================================

/**
 * @brief Work routine callback type
 *
 * @param Context       User-provided context
 * @param ContextSize   Size of context in bytes
 *
 * @return NTSTATUS indicating success or failure
 *
 * @note Runs at PASSIVE_LEVEL
 */
typedef NTSTATUS
(*PFN_SHADOWSTRIKE_WORK_ROUTINE)(
    _In_opt_ PVOID Context,
    _In_ ULONG ContextSize
    );

/**
 * @brief Legacy work routine (no return value)
 */
typedef VOID
(*PFN_SHADOWSTRIKE_WORK_ROUTINE_LEGACY)(
    _In_opt_ PVOID Context
    );

/**
 * @brief Completion callback type
 *
 * @param Status        Completion status
 * @param Context       Original work context
 * @param CompletionCtx Completion-specific context
 */
typedef VOID
(*PFN_SHADOWSTRIKE_WQ_COMPLETION)(
    _In_ NTSTATUS Status,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID CompletionContext
    );

/**
 * @brief Cleanup callback for context
 *
 * @param Context       Context to clean up
 * @param ContextSize   Size of context
 */
typedef VOID
(*PFN_SHADOWSTRIKE_WQ_CLEANUP)(
    _In_opt_ PVOID Context,
    _In_ ULONG ContextSize
    );

/**
 * @brief Cancel callback type
 *
 * @param Context       Work context being cancelled
 * @param ContextSize   Size of context
 *
 * @note Called when work item is cancelled before execution
 */
typedef VOID
(*PFN_SHADOWSTRIKE_WQ_CANCEL)(
    _In_opt_ PVOID Context,
    _In_ ULONG ContextSize
    );

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Work item options for submission
 */
typedef struct _SHADOWSTRIKE_WQ_OPTIONS {
    /// Work item priority
    SHADOWSTRIKE_WQ_PRIORITY Priority;

    /// Work item flags
    ULONG Flags;

    /// Timeout in milliseconds (0 = no timeout)
    ULONG TimeoutMs;

    /// Serialization key (for ordered execution)
    ULONG64 SerializationKey;

    /// Completion callback (optional)
    PFN_SHADOWSTRIKE_WQ_COMPLETION CompletionCallback;

    /// Completion context (optional)
    PVOID CompletionContext;

    /// Cleanup callback for context (optional)
    PFN_SHADOWSTRIKE_WQ_CLEANUP CleanupCallback;

    /// Cancel callback (optional)
    PFN_SHADOWSTRIKE_WQ_CANCEL CancelCallback;

    /// Completion event to signal (optional)
    PKEVENT CompletionEvent;

    /// Target processor for affinity (if flag set)
    ULONG TargetProcessor;

    /// Maximum retry count (if retry flag set)
    ULONG MaxRetries;

    /// Retry delay in milliseconds
    ULONG RetryDelayMs;

    /// Reserved for future use
    ULONG Reserved[2];

} SHADOWSTRIKE_WQ_OPTIONS, *PSHADOWSTRIKE_WQ_OPTIONS;

/**
 * @brief Work item structure
 */
typedef struct _SHADOWSTRIKE_WORK_ITEM {
    /// List entry for queue linkage
    LIST_ENTRY ListEntry;

    /// Work item ID (unique identifier)
    ULONG64 ItemId;

    /// Work routine to execute
    PFN_SHADOWSTRIKE_WORK_ROUTINE Routine;

    /// User context
    PVOID Context;

    /// Context size
    ULONG ContextSize;

    /// Inline context storage (for small contexts)
    UCHAR InlineContext[WQ_MAX_INLINE_CONTEXT_SIZE];

    /// TRUE if using inline context
    BOOLEAN UsingInlineContext;

    /// Work item state
    volatile SHADOWSTRIKE_WQ_ITEM_STATE State;

    /// Work item priority
    SHADOWSTRIKE_WQ_PRIORITY Priority;

    /// Work item flags
    ULONG Flags;

    /// Options snapshot
    SHADOWSTRIKE_WQ_OPTIONS Options;

    /// Submission timestamp
    LARGE_INTEGER SubmitTime;

    /// Start execution timestamp
    LARGE_INTEGER StartTime;

    /// Completion timestamp
    LARGE_INTEGER EndTime;

    /// Completion status
    NTSTATUS CompletionStatus;

    /// Retry count
    ULONG RetryCount;

    /// Reference count
    volatile LONG RefCount;

    /// Cancellation flag
    volatile BOOLEAN CancelRequested;

    /// Work item type indicator
    SHADOWSTRIKE_WQ_TYPE Type;

    /// IO work item (for system queue type)
    PIO_WORKITEM IoWorkItem;

    /// Filter work item (for filter queue type)
    PFLT_GENERIC_WORKITEM FltWorkItem;

    /// Timer for delayed execution
    KTIMER DelayTimer;

    /// DPC for timer
    KDPC DelayDpc;

    /// Back-reference to manager
    struct _SHADOWSTRIKE_WQ_MANAGER* Manager;

    /// SLIST entry for free list
    SLIST_ENTRY FreeListEntry;

    /// Padding for cache alignment
    UCHAR Padding[8];

} SHADOWSTRIKE_WORK_ITEM, *PSHADOWSTRIKE_WORK_ITEM;

/**
 * @brief Per-priority queue structure
 */
typedef struct _SHADOWSTRIKE_WQ_PRIORITY_QUEUE {
    /// Queue head
    LIST_ENTRY Head;

    /// Queue lock
    KSPIN_LOCK Lock;

    /// Current item count
    volatile LONG Count;

    /// Peak item count
    volatile LONG PeakCount;

    /// Maximum allowed items
    ULONG MaxItems;

    /// Total items enqueued
    volatile LONG64 TotalEnqueued;

    /// Total items dequeued
    volatile LONG64 TotalDequeued;

    /// Total items dropped (queue full)
    volatile LONG64 TotalDropped;

} SHADOWSTRIKE_WQ_PRIORITY_QUEUE, *PSHADOWSTRIKE_WQ_PRIORITY_QUEUE;

/**
 * @brief Work queue statistics
 */
typedef struct _SHADOWSTRIKE_WQ_STATISTICS {
    /// Current queue state
    SHADOWSTRIKE_WQ_STATE State;

    /// Total items submitted
    volatile LONG64 TotalSubmitted;

    /// Total items completed successfully
    volatile LONG64 TotalCompleted;

    /// Total items failed
    volatile LONG64 TotalFailed;

    /// Total items cancelled
    volatile LONG64 TotalCancelled;

    /// Total items timed out
    volatile LONG64 TotalTimedOut;

    /// Total retries
    volatile LONG64 TotalRetries;

    /// Current pending items
    volatile LONG CurrentPending;

    /// Peak pending items
    volatile LONG PeakPending;

    /// Current executing items
    volatile LONG CurrentExecuting;

    /// Peak executing items
    volatile LONG PeakExecuting;

    /// Items dropped due to queue full
    volatile LONG64 TotalDropped;

    /// Queue full events
    volatile LONG64 QueueFullEvents;

    /// Average wait time (microseconds)
    ULONG64 AverageWaitTimeUs;

    /// Average execution time (microseconds)
    ULONG64 AverageExecTimeUs;

    /// Per-priority statistics
    struct {
        ULONG64 Submitted;
        ULONG64 Completed;
        ULONG Pending;
        ULONG Peak;
    } PerPriority[ShadowWqPriorityCount];

    /// Uptime
    LARGE_INTEGER Uptime;

    /// Start time
    LARGE_INTEGER StartTime;

} SHADOWSTRIKE_WQ_STATISTICS, *PSHADOWSTRIKE_WQ_STATISTICS;

/**
 * @brief Work queue configuration
 */
typedef struct _SHADOWSTRIKE_WQ_CONFIG {
    /// Maximum pending items per priority
    ULONG MaxPendingPerPriority;

    /// Total maximum pending items
    ULONG MaxPendingTotal;

    /// Default timeout for items (0 = none)
    ULONG DefaultTimeoutMs;

    /// Lookaside list depth
    USHORT LookasideDepth;

    /// Enable statistics collection
    BOOLEAN EnableStatistics;

    /// Enable detailed timing
    BOOLEAN EnableDetailedTiming;

    /// Device object for IoWorkItem (optional)
    PDEVICE_OBJECT DeviceObject;

    /// Filter handle for FltWorkItem (optional)
    PFLT_FILTER FilterHandle;

    /// Reserved
    ULONG Reserved[4];

} SHADOWSTRIKE_WQ_CONFIG, *PSHADOWSTRIKE_WQ_CONFIG;

/**
 * @brief Work queue manager
 */
typedef struct _SHADOWSTRIKE_WQ_MANAGER {
    /// Manager state
    volatile SHADOWSTRIKE_WQ_STATE State;

    /// Initialization lock
    EX_PUSH_LOCK InitLock;

    /// Reference count for initialization
    volatile LONG InitCount;

    /// Priority queues
    SHADOWSTRIKE_WQ_PRIORITY_QUEUE Queues[ShadowWqPriorityCount];

    /// Free list for work items (lock-free SLIST)
    SLIST_HEADER FreeList;
    volatile LONG FreeCount;

    /// Active work items list
    LIST_ENTRY ActiveList;
    KSPIN_LOCK ActiveListLock;
    volatile LONG ActiveCount;

    /// Work item ID generator
    volatile LONG64 NextItemId;

    /// Configuration
    SHADOWSTRIKE_WQ_CONFIG Config;

    /// Statistics
    SHADOWSTRIKE_WQ_STATISTICS Stats;

    /// Device object for IoWorkItem
    PDEVICE_OBJECT DeviceObject;

    /// Filter handle for FltWorkItem
    PFLT_FILTER FilterHandle;

    /// Rundown protection
    EX_RUNDOWN_REF RundownProtection;

    /// Shutdown event
    KEVENT ShutdownEvent;

    /// Drain complete event
    KEVENT DrainCompleteEvent;

    /// Lookaside list for work items
    NPAGED_LOOKASIDE_LIST WorkItemLookaside;
    BOOLEAN LookasideInitialized;

    /// Serialization support
    struct {
        LIST_ENTRY ActiveKeys;
        KSPIN_LOCK Lock;
    } Serialization;

    /// Timing statistics
    struct {
        volatile LONG64 TotalWaitTime;
        volatile LONG64 TotalExecTime;
        volatile LONG64 SampleCount;
    } Timing;

} SHADOWSTRIKE_WQ_MANAGER, *PSHADOWSTRIKE_WQ_MANAGER;

// ============================================================================
// SUBSYSTEM INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the work queue subsystem.
 *
 * Must be called during driver initialization before any work queue operations.
 * Thread-safe with reference counting.
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeWorkQueueInitialize(
    VOID
    );

/**
 * @brief Initialize work queue with configuration.
 *
 * @param Config        Configuration options
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeWorkQueueInitializeEx(
    _In_ PSHADOWSTRIKE_WQ_CONFIG Config
    );

/**
 * @brief Shutdown the work queue subsystem.
 *
 * Waits for pending work items to complete or times out.
 *
 * @param WaitForCompletion     TRUE to wait for pending items
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeWorkQueueShutdown(
    _In_ BOOLEAN WaitForCompletion
    );

/**
 * @brief Check if work queue is initialized.
 *
 * @return TRUE if initialized and ready
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeWorkQueueIsInitialized(
    VOID
    );

/**
 * @brief Get current work queue state.
 *
 * @return Current state
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
SHADOWSTRIKE_WQ_STATE
ShadowStrikeWorkQueueGetState(
    VOID
    );

// ============================================================================
// WORK ITEM SUBMISSION - SIMPLE API
// ============================================================================

/**
 * @brief Queue a work item (simple API).
 *
 * Legacy-compatible simple interface for queuing work.
 *
 * @param Routine       Work routine to execute
 * @param Context       User context (referenced, not copied)
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeQueueWorkItem(
    _In_ PFN_SHADOWSTRIKE_WORK_ROUTINE_LEGACY Routine,
    _In_opt_ PVOID Context
    );

/**
 * @brief Queue a work item with priority.
 *
 * @param Routine       Work routine to execute
 * @param Context       User context
 * @param Priority      Work item priority
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeQueueWorkItemWithPriority(
    _In_ PFN_SHADOWSTRIKE_WORK_ROUTINE_LEGACY Routine,
    _In_opt_ PVOID Context,
    _In_ SHADOWSTRIKE_WQ_PRIORITY Priority
    );

/**
 * @brief Queue a work item with copied context.
 *
 * Context is copied to internal storage - caller's buffer can be freed.
 *
 * @param Routine       Work routine to execute
 * @param Context       Context to copy
 * @param ContextSize   Size of context
 * @param Priority      Work item priority
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeQueueWorkItemWithContext(
    _In_ PFN_SHADOWSTRIKE_WORK_ROUTINE Routine,
    _In_reads_bytes_opt_(ContextSize) PVOID Context,
    _In_ ULONG ContextSize,
    _In_ SHADOWSTRIKE_WQ_PRIORITY Priority
    );

// ============================================================================
// WORK ITEM SUBMISSION - ADVANCED API
// ============================================================================

/**
 * @brief Queue a work item with full options.
 *
 * @param Routine       Work routine to execute
 * @param Context       User context
 * @param ContextSize   Size of context (0 if just pointer)
 * @param Options       Work item options (NULL for defaults)
 * @param ItemId        Receives work item ID (optional)
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeQueueWorkItemEx(
    _In_ PFN_SHADOWSTRIKE_WORK_ROUTINE Routine,
    _In_reads_bytes_opt_(ContextSize) PVOID Context,
    _In_ ULONG ContextSize,
    _In_opt_ PSHADOWSTRIKE_WQ_OPTIONS Options,
    _Out_opt_ PULONG64 ItemId
    );

/**
 * @brief Queue a delayed work item.
 *
 * Work item will be queued after specified delay.
 *
 * @param Routine       Work routine to execute
 * @param Context       User context
 * @param ContextSize   Size of context
 * @param DelayMs       Delay in milliseconds
 * @param Options       Work item options (optional)
 * @param ItemId        Receives work item ID (optional)
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeQueueDelayedWorkItem(
    _In_ PFN_SHADOWSTRIKE_WORK_ROUTINE Routine,
    _In_reads_bytes_opt_(ContextSize) PVOID Context,
    _In_ ULONG ContextSize,
    _In_ ULONG DelayMs,
    _In_opt_ PSHADOWSTRIKE_WQ_OPTIONS Options,
    _Out_opt_ PULONG64 ItemId
    );

/**
 * @brief Queue work item using filter manager.
 *
 * Uses FltQueueGenericWorkItem for filter driver work.
 *
 * @param Instance      Filter instance
 * @param Routine       Work routine
 * @param Context       User context
 * @param ContextSize   Size of context
 * @param Options       Work item options
 * @param ItemId        Receives work item ID
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeQueueFilterWorkItem(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFN_SHADOWSTRIKE_WORK_ROUTINE Routine,
    _In_reads_bytes_opt_(ContextSize) PVOID Context,
    _In_ ULONG ContextSize,
    _In_opt_ PSHADOWSTRIKE_WQ_OPTIONS Options,
    _Out_opt_ PULONG64 ItemId
    );

// ============================================================================
// WORK ITEM MANAGEMENT
// ============================================================================

/**
 * @brief Cancel a work item by ID.
 *
 * @param ItemId        Work item ID to cancel
 *
 * @return STATUS_SUCCESS if cancelled
 *         STATUS_NOT_FOUND if item not found
 *         STATUS_UNSUCCESSFUL if already executing
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeCancelWorkItem(
    _In_ ULONG64 ItemId
    );

/**
 * @brief Cancel all work items with serialization key.
 *
 * @param SerializationKey  Key to match
 *
 * @return Number of items cancelled
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
ShadowStrikeCancelWorkItemsByKey(
    _In_ ULONG64 SerializationKey
    );

/**
 * @brief Wait for a work item to complete.
 *
 * @param ItemId        Work item ID
 * @param TimeoutMs     Timeout in milliseconds (0 = infinite)
 * @param Status        Receives completion status
 *
 * @return STATUS_SUCCESS if completed
 *         STATUS_TIMEOUT if timed out
 *         STATUS_NOT_FOUND if item not found
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeWaitForWorkItem(
    _In_ ULONG64 ItemId,
    _In_ ULONG TimeoutMs,
    _Out_opt_ PNTSTATUS Status
    );

/**
 * @brief Get work item state.
 *
 * @param ItemId        Work item ID
 * @param State         Receives current state
 *
 * @return STATUS_SUCCESS if found
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeGetWorkItemState(
    _In_ ULONG64 ItemId,
    _Out_ PSHADOWSTRIKE_WQ_ITEM_STATE State
    );

// ============================================================================
// QUEUE CONTROL
// ============================================================================

/**
 * @brief Pause work queue (stop accepting new items).
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeWorkQueuePause(
    VOID
    );

/**
 * @brief Resume work queue.
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeWorkQueueResume(
    VOID
    );

/**
 * @brief Drain work queue (wait for all pending items).
 *
 * @param TimeoutMs     Timeout in milliseconds
 *
 * @return STATUS_SUCCESS if drained
 *         STATUS_TIMEOUT if timed out
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeWorkQueueDrain(
    _In_ ULONG TimeoutMs
    );

/**
 * @brief Flush work queue (cancel all pending items).
 *
 * @return Number of items cancelled
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
ShadowStrikeWorkQueueFlush(
    VOID
    );

// ============================================================================
// STATISTICS
// ============================================================================

/**
 * @brief Get work queue statistics.
 *
 * @param Statistics    Receives current statistics
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeGetWorkQueueStatistics(
    _Out_ PSHADOWSTRIKE_WQ_STATISTICS Statistics
    );

/**
 * @brief Reset work queue statistics.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeResetWorkQueueStatistics(
    VOID
    );

/**
 * @brief Get pending work item count.
 *
 * @return Number of pending items
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
LONG
ShadowStrikeGetPendingWorkItemCount(
    VOID
    );

/**
 * @brief Get pending count by priority.
 *
 * @param Priority      Priority level
 *
 * @return Number of pending items at priority
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
LONG
ShadowStrikeGetPendingWorkItemCountByPriority(
    _In_ SHADOWSTRIKE_WQ_PRIORITY Priority
    );

// ============================================================================
// CONFIGURATION
// ============================================================================

/**
 * @brief Set device object for IoWorkItem.
 *
 * @param DeviceObject  Device object to use
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeWorkQueueSetDeviceObject(
    _In_ PDEVICE_OBJECT DeviceObject
    );

/**
 * @brief Set filter handle for FltWorkItem.
 *
 * @param FilterHandle  Filter handle
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeWorkQueueSetFilterHandle(
    _In_ PFLT_FILTER FilterHandle
    );

/**
 * @brief Initialize default options structure.
 *
 * @param Options       Options to initialize
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeInitWorkQueueOptions(
    _Out_ PSHADOWSTRIKE_WQ_OPTIONS Options
    );

/**
 * @brief Initialize default configuration.
 *
 * @param Config        Configuration to initialize
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeInitWorkQueueConfig(
    _Out_ PSHADOWSTRIKE_WQ_CONFIG Config
    );

// ============================================================================
// INLINE UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Check if priority is valid.
 */
FORCEINLINE
BOOLEAN
ShadowStrikeIsValidWqPriority(
    _In_ SHADOWSTRIKE_WQ_PRIORITY Priority
    )
{
    return (Priority >= ShadowWqPriorityBackground &&
            Priority < ShadowWqPriorityCount);
}

/**
 * @brief Map Windows work queue type to our priority.
 */
FORCEINLINE
WORK_QUEUE_TYPE
ShadowStrikeWqPriorityToWorkQueueType(
    _In_ SHADOWSTRIKE_WQ_PRIORITY Priority
    )
{
    switch (Priority) {
        case ShadowWqPriorityCritical:
            return CriticalWorkQueue;
        case ShadowWqPriorityHigh:
            return CriticalWorkQueue;
        case ShadowWqPriorityNormal:
            return DelayedWorkQueue;
        case ShadowWqPriorityLow:
            return DelayedWorkQueue;
        case ShadowWqPriorityBackground:
            return DelayedWorkQueue;
        default:
            return DelayedWorkQueue;
    }
}

/**
 * @brief Get current timestamp in 100ns units.
 */
FORCEINLINE
LARGE_INTEGER
ShadowStrikeWqGetTimestamp(
    VOID
    )
{
    LARGE_INTEGER Time;
    KeQuerySystemTimePrecise(&Time);
    return Time;
}

/**
 * @brief Calculate elapsed time in microseconds.
 */
FORCEINLINE
ULONG64
ShadowStrikeWqGetElapsedUs(
    _In_ PLARGE_INTEGER StartTime,
    _In_ PLARGE_INTEGER EndTime
    )
{
    return (ULONG64)((EndTime->QuadPart - StartTime->QuadPart) / 10);
}

#ifdef __cplusplus
}
#endif

#endif // _SHADOWSTRIKE_WORK_QUEUE_H_
