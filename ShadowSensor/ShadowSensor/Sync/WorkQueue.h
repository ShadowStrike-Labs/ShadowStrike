/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE KERNEL WORK QUEUE
 * ============================================================================
 *
 * @file WorkQueue.h
 * @brief Enterprise-grade work queue for kernel-mode EDR deferred processing.
 *
 * Provides:
 * - IoWorkItem integration for safe driver unload
 * - FltQueueGenericWorkItem for filter manager operations
 * - Priority-based dispatch (Critical, High, Normal, Low, Background)
 * - Bounded queue with backpressure
 * - Work item cancellation with cleanup callbacks
 * - Rundown protection for safe driver unload
 * - Delayed (timer-based) work items
 * - Reference-counted work items prevent use-after-free
 *
 * v2.1.0 Changes (Enterprise Hardened):
 * ======================================
 * - KeEnterCriticalRegion around all push lock acquisitions
 * - Removed INIT segment pragmas (was BSOD on re-init)
 * - DPC never executes work directly; always defers to IoWorkItem
 * - Proper SLIST item freeing during shutdown
 * - Fixed rundown protection balance on retry path
 * - Separate ListEntry for ActiveList vs priority queue (was corruption)
 * - Legacy callback wrapper instead of UB function pointer cast
 * - All per-priority stats use interlocked operations
 * - Context copies always use NonPaged pool (callable from DISPATCH)
 * - Wait polling uses KeQueryPerformanceCounter for accurate timing
 * - Shutdown cancels timers and calls KeFlushQueuedDpcs
 * - Removed unimplemented features (serialization, affinity, batching, timeout)
 *
 * @author ShadowStrike Security Team
 * @version 2.1.0 (Enterprise Edition - Hardened)
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

#define SHADOW_WQ_TAG               'qWSs'
#define SHADOW_WQ_ITEM_TAG          'iWSs'
#define SHADOW_WQ_CONTEXT_TAG       'cWSs'

// ============================================================================
// CONFIGURATION CONSTANTS
// ============================================================================

#define WQ_DEFAULT_MAX_PENDING          65536
#define WQ_MIN_MAX_PENDING              256
#define WQ_MAX_MAX_PENDING              (1024 * 1024)

/// Contexts <= this size use inline storage in the work item
#define WQ_MAX_INLINE_CONTEXT_SIZE      128

/// Safety limit for external context allocations
#define WQ_MAX_CONTEXT_SIZE             (64 * 1024)

/// Shutdown timeout waiting for in-flight items
#define WQ_SHUTDOWN_TIMEOUT_MS          30000

/// Lookaside list depth for work item recycling
#define WQ_LOOKASIDE_DEPTH              512

// ============================================================================
// ENUMERATIONS
// ============================================================================

typedef enum _SHADOWSTRIKE_WQ_PRIORITY {
    ShadowWqPriorityBackground = 0,
    ShadowWqPriorityLow,
    ShadowWqPriorityNormal,
    ShadowWqPriorityHigh,
    ShadowWqPriorityCritical,
    ShadowWqPriorityCount
} SHADOWSTRIKE_WQ_PRIORITY;

typedef enum _SHADOWSTRIKE_WQ_TYPE {
    ShadowWqTypeSystem = 0,     // IoQueueWorkItem
    ShadowWqTypeFilter,         // FltQueueGenericWorkItem
    ShadowWqTypeDelayed         // Timer -> IoQueueWorkItem
} SHADOWSTRIKE_WQ_TYPE;

typedef enum _SHADOWSTRIKE_WQ_ITEM_STATE {
    ShadowWqItemStateFree = 0,
    ShadowWqItemStateAllocated,
    ShadowWqItemStateQueued,
    ShadowWqItemStateRunning,
    ShadowWqItemStateCompleted,
    ShadowWqItemStateCancelled,
    ShadowWqItemStateFailed
} SHADOWSTRIKE_WQ_ITEM_STATE;

typedef enum _SHADOWSTRIKE_WQ_STATE {
    ShadowWqStateUninitialized = 0,
    ShadowWqStateInitializing,
    ShadowWqStateRunning,
    ShadowWqStatePaused,
    ShadowWqStateDraining,
    ShadowWqStateShutdown
} SHADOWSTRIKE_WQ_STATE;

/**
 * @brief Work item flags (only implemented features)
 */
typedef enum _SHADOWSTRIKE_WQ_FLAGS {
    ShadowWqFlagNone                = 0x00000000,
    ShadowWqFlagCopyContext         = 0x00000001,
    ShadowWqFlagCancellable         = 0x00000002,
    ShadowWqFlagDeleteContext       = 0x00000004,
    ShadowWqFlagSignalCompletion    = 0x00000008,
    ShadowWqFlagLongRunning         = 0x00000010,
    ShadowWqFlagRetryOnFailure      = 0x00000080,
    ShadowWqFlagSecureContext       = 0x00000800
} SHADOWSTRIKE_WQ_FLAGS;

// ============================================================================
// CALLBACK TYPES
// ============================================================================

/// Work routine: returns NTSTATUS, receives context + size
typedef NTSTATUS
(*PFN_SHADOWSTRIKE_WORK_ROUTINE)(
    _In_opt_ PVOID Context,
    _In_ ULONG ContextSize
    );

/// Legacy work routine: void return, context only
typedef VOID
(*PFN_SHADOWSTRIKE_WORK_ROUTINE_LEGACY)(
    _In_opt_ PVOID Context
    );

/// Completion callback
typedef VOID
(*PFN_SHADOWSTRIKE_WQ_COMPLETION)(
    _In_ NTSTATUS Status,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID CompletionContext
    );

/// Cleanup callback for owned context
typedef VOID
(*PFN_SHADOWSTRIKE_WQ_CLEANUP)(
    _In_opt_ PVOID Context,
    _In_ ULONG ContextSize
    );

/// Cancel callback
typedef VOID
(*PFN_SHADOWSTRIKE_WQ_CANCEL)(
    _In_opt_ PVOID Context,
    _In_ ULONG ContextSize
    );

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Options for advanced work item submission
 */
typedef struct _SHADOWSTRIKE_WQ_OPTIONS {
    SHADOWSTRIKE_WQ_PRIORITY Priority;
    ULONG Flags;

    /// Completion callback (optional)
    PFN_SHADOWSTRIKE_WQ_COMPLETION CompletionCallback;
    PVOID CompletionContext;

    /// Cleanup callback for context (optional)
    PFN_SHADOWSTRIKE_WQ_CLEANUP CleanupCallback;

    /// Cancel callback (optional)
    PFN_SHADOWSTRIKE_WQ_CANCEL CancelCallback;

    /// Completion event to signal (optional, must be NonPaged)
    PKEVENT CompletionEvent;

    /// Maximum retry count (if ShadowWqFlagRetryOnFailure set)
    ULONG MaxRetries;

    /// Retry delay in milliseconds
    ULONG RetryDelayMs;

} SHADOWSTRIKE_WQ_OPTIONS, *PSHADOWSTRIKE_WQ_OPTIONS;

/**
 * @brief Work item structure (internal, exposed for inline helpers only)
 *
 * Users should NOT access fields directly.
 */
typedef struct _SHADOWSTRIKE_WORK_ITEM {
    /// List entry for ActiveList tracking
    LIST_ENTRY ActiveListEntry;

    /// Work item ID
    ULONG64 ItemId;

    /// Work routine
    PFN_SHADOWSTRIKE_WORK_ROUTINE Routine;

    /// User context pointer
    PVOID Context;

    /// Context size in bytes
    ULONG ContextSize;

    /// Inline context (for small contexts, avoids separate allocation)
    UCHAR InlineContext[WQ_MAX_INLINE_CONTEXT_SIZE];

    /// TRUE if Context points to InlineContext
    BOOLEAN UsingInlineContext;

    /// Current state (atomic)
    volatile LONG State;

    /// Priority level
    SHADOWSTRIKE_WQ_PRIORITY Priority;

    /// Flags
    ULONG Flags;

    /// Snapshot of submission options
    SHADOWSTRIKE_WQ_OPTIONS Options;

    /// Timestamps
    LARGE_INTEGER SubmitTime;
    LARGE_INTEGER StartTime;
    LARGE_INTEGER EndTime;

    /// Completion status
    NTSTATUS CompletionStatus;

    /// Retry count
    ULONG RetryCount;

    /// Reference count (atomic)
    volatile LONG RefCount;

    /// Cancellation requested (atomic)
    volatile LONG CancelRequested;

    /// Work queue type
    SHADOWSTRIKE_WQ_TYPE Type;

    /// IoWorkItem handle (for system + delayed types)
    PIO_WORKITEM IoWorkItem;

    /// Filter work item handle
    PFLT_GENERIC_WORKITEM FltWorkItem;

    /// Timer + DPC for delayed execution
    KTIMER DelayTimer;
    KDPC DelayDpc;

    /// Back-reference to manager
    struct _SHADOWSTRIKE_WQ_MANAGER* Manager;

    /// SLIST entry for free list (must be MEMORY_ALLOCATION_ALIGNMENT aligned)
    SLIST_ENTRY FreeListEntry;

    /// Legacy wrapper: original void-return callback
    PFN_SHADOWSTRIKE_WORK_ROUTINE_LEGACY LegacyRoutine;

} SHADOWSTRIKE_WORK_ITEM, *PSHADOWSTRIKE_WORK_ITEM;

/**
 * @brief Work queue statistics
 */
typedef struct _SHADOWSTRIKE_WQ_STATISTICS {
    volatile LONG State;

    volatile LONG64 TotalSubmitted;
    volatile LONG64 TotalCompleted;
    volatile LONG64 TotalFailed;
    volatile LONG64 TotalCancelled;
    volatile LONG64 TotalRetries;
    volatile LONG64 TotalDropped;

    volatile LONG CurrentPending;
    volatile LONG PeakPending;
    volatile LONG CurrentExecuting;
    volatile LONG PeakExecuting;

    /// Timing (microseconds, accumulated)
    volatile LONG64 TotalWaitTimeUs;
    volatile LONG64 TotalExecTimeUs;
    volatile LONG64 TimingSampleCount;

    LARGE_INTEGER StartTime;

} SHADOWSTRIKE_WQ_STATISTICS, *PSHADOWSTRIKE_WQ_STATISTICS;

/**
 * @brief Work queue configuration
 */
typedef struct _SHADOWSTRIKE_WQ_CONFIG {
    /// Total maximum pending items
    ULONG MaxPendingTotal;

    /// Lookaside list depth
    USHORT LookasideDepth;

    /// Enable detailed timing
    BOOLEAN EnableDetailedTiming;

    /// Device object for IoWorkItem (required for system queue)
    PDEVICE_OBJECT DeviceObject;

    /// Filter handle for FltWorkItem (optional)
    PFLT_FILTER FilterHandle;

} SHADOWSTRIKE_WQ_CONFIG, *PSHADOWSTRIKE_WQ_CONFIG;

/**
 * @brief Work queue manager
 */
typedef struct _SHADOWSTRIKE_WQ_MANAGER {
    /// Manager state (atomic)
    volatile LONG State;

    /// Initialization lock
    EX_PUSH_LOCK InitLock;

    /// Reference count for init/shutdown balancing
    volatile LONG InitCount;

    /// Active work items (tracked via ActiveListEntry)
    LIST_ENTRY ActiveList;
    KSPIN_LOCK ActiveListLock;
    volatile LONG ActiveCount;

    /// Free list (lock-free SLIST for recycling)
    SLIST_HEADER FreeList;
    volatile LONG FreeCount;

    /// Work item ID generator
    volatile LONG64 NextItemId;

    /// Configuration
    SHADOWSTRIKE_WQ_CONFIG Config;

    /// Statistics
    SHADOWSTRIKE_WQ_STATISTICS Stats;

    /// Device/filter handles (read with InterlockedCompareExchangePointer)
    PDEVICE_OBJECT DeviceObject;
    PFLT_FILTER FilterHandle;

    /// Rundown protection for safe shutdown
    EX_RUNDOWN_REF RundownProtection;

    /// Shutdown + drain events
    KEVENT ShutdownEvent;
    KEVENT DrainCompleteEvent;

    /// Lookaside for work items
    NPAGED_LOOKASIDE_LIST WorkItemLookaside;
    BOOLEAN LookasideInitialized;

    /// Current pending count (separate from stats for precise tracking)
    volatile LONG PendingCount;

    /// Maximum pending (from config, cached for fast check)
    LONG MaxPending;

} SHADOWSTRIKE_WQ_MANAGER, *PSHADOWSTRIKE_WQ_MANAGER;

// ============================================================================
// PUBLIC API
// ============================================================================

/// Initialize with default config
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeWorkQueueInitialize(
    VOID
    );

/// Initialize with explicit config
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeWorkQueueInitializeEx(
    _In_ PSHADOWSTRIKE_WQ_CONFIG Config
    );

/// Shutdown. Waits for in-flight items if WaitForCompletion is TRUE.
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeWorkQueueShutdown(
    _In_ BOOLEAN WaitForCompletion
    );

/// Check if initialized and running
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeWorkQueueIsInitialized(
    VOID
    );

/// Get current state
_IRQL_requires_max_(DISPATCH_LEVEL)
SHADOWSTRIKE_WQ_STATE
ShadowStrikeWorkQueueGetState(
    VOID
    );

// ----- Simple submission API -----

/// Queue work (legacy void-return callback, normal priority)
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeQueueWorkItem(
    _In_ PFN_SHADOWSTRIKE_WORK_ROUTINE_LEGACY Routine,
    _In_opt_ PVOID Context
    );

/// Queue work with priority (legacy callback)
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeQueueWorkItemWithPriority(
    _In_ PFN_SHADOWSTRIKE_WORK_ROUTINE_LEGACY Routine,
    _In_opt_ PVOID Context,
    _In_ SHADOWSTRIKE_WQ_PRIORITY Priority
    );

/// Queue work with copied context
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeQueueWorkItemWithContext(
    _In_ PFN_SHADOWSTRIKE_WORK_ROUTINE Routine,
    _In_reads_bytes_opt_(ContextSize) PVOID Context,
    _In_ ULONG ContextSize,
    _In_ SHADOWSTRIKE_WQ_PRIORITY Priority
    );

// ----- Advanced submission API -----

/// Queue work with full options
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeQueueWorkItemEx(
    _In_ PFN_SHADOWSTRIKE_WORK_ROUTINE Routine,
    _In_reads_bytes_opt_(ContextSize) PVOID Context,
    _In_ ULONG ContextSize,
    _In_opt_ PSHADOWSTRIKE_WQ_OPTIONS Options,
    _Out_opt_ PULONG64 ItemId
    );

/// Queue delayed work item (fires after DelayMs)
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

/// Queue work via filter manager
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

// ----- Work item management -----

/// Cancel a work item by ID
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeCancelWorkItem(
    _In_ ULONG64 ItemId
    );

/// Wait for a work item to complete
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeWaitForWorkItem(
    _In_ ULONG64 ItemId,
    _In_ ULONG TimeoutMs,
    _Out_opt_ PNTSTATUS CompletionStatus
    );

/// Get work item state
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeGetWorkItemState(
    _In_ ULONG64 ItemId,
    _Out_ PSHADOWSTRIKE_WQ_ITEM_STATE State
    );

// ----- Queue control -----

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS ShadowStrikeWorkQueuePause(VOID);

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS ShadowStrikeWorkQueueResume(VOID);

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS ShadowStrikeWorkQueueDrain(_In_ ULONG TimeoutMs);

_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG ShadowStrikeWorkQueueFlush(VOID);

// ----- Statistics -----

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID ShadowStrikeGetWorkQueueStatistics(
    _Out_ PSHADOWSTRIKE_WQ_STATISTICS Statistics);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID ShadowStrikeResetWorkQueueStatistics(VOID);

_IRQL_requires_max_(DISPATCH_LEVEL)
LONG ShadowStrikeGetPendingWorkItemCount(VOID);

// ----- Configuration -----

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS ShadowStrikeWorkQueueSetDeviceObject(
    _In_ PDEVICE_OBJECT DeviceObject);

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS ShadowStrikeWorkQueueSetFilterHandle(
    _In_ PFLT_FILTER FilterHandle);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID ShadowStrikeInitWorkQueueOptions(
    _Out_ PSHADOWSTRIKE_WQ_OPTIONS Options);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID ShadowStrikeInitWorkQueueConfig(
    _Out_ PSHADOWSTRIKE_WQ_CONFIG Config);

// ============================================================================
// INLINE UTILITIES
// ============================================================================

FORCEINLINE BOOLEAN
ShadowStrikeIsValidWqPriority(
    _In_ SHADOWSTRIKE_WQ_PRIORITY Priority)
{
    return (Priority >= ShadowWqPriorityBackground &&
            Priority < ShadowWqPriorityCount);
}

FORCEINLINE WORK_QUEUE_TYPE
ShadowStrikeWqPriorityToWorkQueueType(
    _In_ SHADOWSTRIKE_WQ_PRIORITY Priority)
{
    switch (Priority) {
        case ShadowWqPriorityCritical:
        case ShadowWqPriorityHigh:
            return CriticalWorkQueue;
        default:
            return DelayedWorkQueue;
    }
}

FORCEINLINE LARGE_INTEGER
ShadowStrikeWqGetTimestamp(VOID)
{
    LARGE_INTEGER Time;
    KeQuerySystemTimePrecise(&Time);
    return Time;
}

FORCEINLINE ULONG64
ShadowStrikeWqGetElapsedUs(
    _In_ PLARGE_INTEGER Start,
    _In_ PLARGE_INTEGER End)
{
    if (End->QuadPart <= Start->QuadPart) return 0;
    return (ULONG64)((End->QuadPart - Start->QuadPart) / 10);
}

#ifdef __cplusplus
}
#endif

#endif // _SHADOWSTRIKE_WORK_QUEUE_H_
