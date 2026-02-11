/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE RESOURCE THROTTLING ENGINE
 * ============================================================================
 *
 * @file ResourceThrottling.h
 * @brief Enterprise-grade resource throttling for kernel-mode EDR operations.
 *
 * Provides resource management with:
 * - Multi-dimensional resource tracking (CPU, Memory, I/O, Network, Callbacks)
 * - Adaptive throttling with configurable soft/hard limits
 * - Per-process and global resource quotas with per-process limit enforcement
 * - Real-time usage monitoring with DPC-based sampling
 * - Exponential backoff for sustained overload conditions
 * - Priority-based operation scheduling during throttling
 * - Work queue management for deferred operations
 * - Burst allowance with token bucket algorithm
 * - Automatic recovery when resources normalize
 *
 * Safety Guarantees:
 * - Prevents resource exhaustion attacks (DoS mitigation)
 * - Protects system stability under heavy load
 * - Atomic operations for all counter updates
 * - Safe cleanup with EX_RUNDOWN_REF lifecycle management
 * - No deadlocks through lock ordering discipline
 * - KSPIN_LOCK for all DPC-accessible state
 *
 * Performance:
 * - Lock-free Interlocked* counters for hot-path usage reporting
 * - Tiered throttling to minimize impact on normal operations
 * - Lazy evaluation of expensive metrics (rate calc only in DPC)
 *
 * Memory Budget:
 * - RT_THROTTLER is allocated from NonPagedPoolNx (~25KB base)
 * - Per-process quota entries allocated individually from NonPagedPoolNx
 *   (each ~310 bytes, up to RT_MAX_TRACKED_PROCESSES=256 = ~80KB max)
 * - Deferred work items allocated individually (~64 bytes each)
 *
 * MITRE ATT&CK Coverage:
 * - T1499: Endpoint Denial of Service (resource exhaustion prevention)
 * - T1496: Resource Hijacking (CPU/memory abuse detection)
 * - T1498: Network Denial of Service (bandwidth throttling)
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_RESOURCE_THROTTLING_H_
#define _SHADOWSTRIKE_RESOURCE_THROTTLING_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

// ============================================================================
// POOL TAGS
// ============================================================================

/** @brief Primary pool tag: 'SsRt' = ShadowStrike Resource Throttling */
#define RT_POOL_TAG                     'tRsS'

/** @brief Pool tag for per-process quota entries: 'SsRp' */
#define RT_PROCESS_TAG                  'pRsS'

/** @brief Pool tag for deferred queue entries: 'SsRq' */
#define RT_QUEUE_TAG                    'qRsS'

// ============================================================================
// CONSTANTS
// ============================================================================

#define RT_MAX_RESOURCE_TYPES           16
#define RT_MAX_TRACKED_PROCESSES        256
#define RT_DEFAULT_MONITOR_INTERVAL_MS  100
#define RT_MIN_MONITOR_INTERVAL_MS      10
#define RT_MAX_MONITOR_INTERVAL_MS      10000
#define RT_DEFAULT_BURST_CAPACITY       100
#define RT_TOKEN_REFILL_RATE            10
#define RT_MAX_DELAY_MS                 1000
#define RT_MIN_DELAY_MS                 1
#define RT_BACKOFF_MULTIPLIER           150
#define RT_BACKOFF_DIVISOR              100
#define RT_MAX_DEFERRED_QUEUE_DEPTH     1024
#define RT_RATE_HISTORY_SIZE            64
#define RT_HYSTERESIS_PERCENT           10
#define RT_PROCESS_HASH_BUCKETS         64

/** @brief Sentinel for action enum validation */
#define RT_ACTION_MAX_VALID             (RtActionEscalate)

/** @brief Sentinel for state enum validation */
#define RT_STATE_MAX_VALID              (RtStateRecovery)

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Resource types that can be throttled.
 */
typedef enum _RT_RESOURCE_TYPE {
    RtResourceCpu = 0,
    RtResourceMemoryNonPaged,
    RtResourceMemoryPaged,
    RtResourceDiskIops,
    RtResourceDiskBandwidth,
    RtResourceNetworkIops,
    RtResourceNetworkBandwidth,
    RtResourceCallbackRate,
    RtResourceEventQueue,
    RtResourceFsOps,
    RtResourceRegOps,
    RtResourceProcessCreation,
    RtResourceHandleOps,
    RtResourceMemoryMaps,
    RtResourceCustom1,
    RtResourceCustom2,
    RtResourceMax
} RT_RESOURCE_TYPE;

/**
 * @brief Throttle actions when limits are exceeded.
 */
typedef enum _RT_THROTTLE_ACTION {
    RtActionNone = 0,
    RtActionDelay,
    RtActionSkipLowPriority,
    RtActionQueue,
    RtActionSample,
    RtActionAbort,
    RtActionNotify,
    RtActionEscalate
} RT_THROTTLE_ACTION;

/**
 * @brief Throttle state for a resource.
 */
typedef enum _RT_THROTTLE_STATE {
    RtStateNormal = 0,
    RtStateWarning,
    RtStateThrottled,
    RtStateCritical,
    RtStateRecovery
} RT_THROTTLE_STATE;

/**
 * @brief Priority levels for operations.
 *
 * ORDERING: Lower numeric value = higher importance.
 * RtPriorityCritical (0) is never throttled.
 * Comparisons use >= to mean "this priority or less important".
 * Example: (Priority >= RtPriorityLow) matches Low and Background.
 */
typedef enum _RT_PRIORITY {
    RtPriorityCritical = 0,     ///< Never throttled
    RtPriorityHigh,             ///< Throttled only at critical state
    RtPriorityNormal,           ///< Throttled at hard limit and above
    RtPriorityLow,              ///< Throttled at warning and above
    RtPriorityBackground        ///< Always throttled when any limit exceeded
} RT_PRIORITY;

typedef enum _RT_ALERT_SEVERITY {
    RtAlertInfo = 0,
    RtAlertWarning,
    RtAlertError,
    RtAlertCritical
} RT_ALERT_SEVERITY;

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Configuration for a single resource limit.
 */
typedef struct _RT_RESOURCE_CONFIG {
    RT_RESOURCE_TYPE Type;
    BOOLEAN Enabled;
    UCHAR Reserved[3];
    ULONG64 SoftLimit;
    ULONG64 HardLimit;
    ULONG64 CriticalLimit;
    RT_THROTTLE_ACTION SoftAction;
    RT_THROTTLE_ACTION HardAction;
    RT_THROTTLE_ACTION CriticalAction;
    ULONG DelayMs;
    ULONG SampleRate;
    ULONG RateWindowMs;
    ULONG BurstCapacity;
} RT_RESOURCE_CONFIG, *PRT_RESOURCE_CONFIG;

/**
 * @brief Current state of a resource.
 *
 * All fields protected by ResourceLock (KSPIN_LOCK) except
 * CurrentUsage and PeakUsage which use Interlocked* access.
 */
typedef struct _RT_RESOURCE_STATE {
    RT_RESOURCE_TYPE Type;
    RT_THROTTLE_STATE State;
    RT_THROTTLE_STATE PreviousState;

    /// Current usage value (Interlocked* access only)
    volatile LONG64 CurrentUsage;

    /// Peak usage in current window (Interlocked* access only)
    volatile LONG64 PeakUsage;

    /// Usage at last sample (protected by ResourceLock)
    LONG64 LastSampleUsage;

    /// Current rate (Interlocked* for reads, ResourceLock for writes)
    volatile LONG64 CurrentRate;

    /// Available burst tokens (Interlocked* CAS access)
    volatile LONG BurstTokens;

    ULONG OverLimitCount;
    ULONG UnderLimitCount;
    ULONG CurrentDelayMs;

    LARGE_INTEGER StateEnterTime;
    LARGE_INTEGER LastRateCalcTime;

    /// Separate timestamp for token refill (not shared with rate calc)
    LARGE_INTEGER LastTokenRefillTime;

    LONG64 RateHistory[RT_RATE_HISTORY_SIZE];
    ULONG RateHistoryIndex;
    ULONG RateHistorySamples;

    /// Per-resource spin lock — safe at DISPATCH_LEVEL (DPC)
    KSPIN_LOCK ResourceLock;

} RT_RESOURCE_STATE, *PRT_RESOURCE_STATE;

/**
 * @brief Per-process resource tracking.
 *
 * Allocated individually from NonPagedPoolNx.
 * Protected by ProcessQuotas.Lock (KSPIN_LOCK).
 */
typedef struct _RT_PROCESS_QUOTA {
    HANDLE ProcessId;
    BOOLEAN InUse;
    BOOLEAN Exempt;
    UCHAR Reserved[6];
    volatile LONG64 ResourceUsage[RT_MAX_RESOURCE_TYPES];
    volatile LONG64 ResourceRates[RT_MAX_RESOURCE_TYPES];
    volatile LONG64 ThrottleHits;
    LARGE_INTEGER LastActivity;
    LIST_ENTRY HashLink;

    /// Per-process soft limits (0 = use global)
    ULONG64 ProcessSoftLimit[RT_MAX_RESOURCE_TYPES];
} RT_PROCESS_QUOTA, *PRT_PROCESS_QUOTA;

/**
 * @brief Deferred work item for queued operations.
 */
typedef struct _RT_DEFERRED_WORK {
    LIST_ENTRY ListEntry;
    RT_RESOURCE_TYPE ResourceType;
    RT_PRIORITY Priority;
    PVOID Callback;
    PVOID Context;
    LARGE_INTEGER QueueTime;
    LARGE_INTEGER ExpirationTime;
} RT_DEFERRED_WORK, *PRT_DEFERRED_WORK;

/**
 * @brief Throttle event for callback notification.
 */
typedef struct _RT_THROTTLE_EVENT {
    RT_RESOURCE_TYPE Resource;
    RT_THROTTLE_ACTION Action;
    RT_THROTTLE_STATE NewState;
    RT_THROTTLE_STATE OldState;
    ULONG64 CurrentUsage;
    ULONG64 LimitValue;
    ULONG64 CurrentRate;
    HANDLE ProcessId;
    LARGE_INTEGER Timestamp;
} RT_THROTTLE_EVENT, *PRT_THROTTLE_EVENT;

/**
 * @brief Statistics for the throttling subsystem.
 *
 * Read via RtGetStatistics under StatsLock for consistent snapshot.
 */
typedef struct _RT_STATISTICS {
    volatile LONG64 TotalOperations;
    volatile LONG64 ThrottledOperations;
    volatile LONG64 DelayedOperations;
    volatile LONG64 QueuedOperations;
    volatile LONG64 SkippedOperations;
    volatile LONG64 AbortedOperations;
    volatile LONG64 TotalDelayMs;
    volatile LONG64 StateTransitions;
    volatile LONG64 AlertsSent;
    volatile LONG64 DeferredWorkProcessed;
    volatile LONG64 DeferredWorkExpired;
    LARGE_INTEGER StartTime;
    struct {
        volatile LONG64 Checks;
        volatile LONG64 Throttles;
        volatile LONG64 PeakUsage;
    } PerResource[RT_MAX_RESOURCE_TYPES];
} RT_STATISTICS, *PRT_STATISTICS;

/**
 * @brief Callback type for throttle notifications.
 *
 * Called at DISPATCH_LEVEL from DPC context.
 */
typedef VOID (*PRT_THROTTLE_CALLBACK)(
    _In_ PRT_THROTTLE_EVENT Event,
    _In_opt_ PVOID Context
);

/**
 * @brief Callback type for deferred work execution.
 *
 * Called at PASSIVE_LEVEL from system worker thread.
 */
typedef NTSTATUS (*PRT_DEFERRED_CALLBACK)(
    _In_opt_ PVOID Context
);

/**
 * @brief Main throttler structure.
 *
 * Allocated from NonPagedPoolNx (accessed from DPC context).
 * Lifecycle managed by EX_RUNDOWN_REF (RundownRef).
 */
typedef struct _RT_THROTTLER {
    BOOLEAN Initialized;
    BOOLEAN Enabled;
    BOOLEAN MonitoringActive;
    UCHAR Reserved;
    ULONG Magic;

    /// Set to 1 before ExWaitForRundownProtectionRelease — safe to read at any IRQL
    volatile LONG ShutdownFlag;

    /// Resource configurations (protected by per-resource ResourceLock)
    RT_RESOURCE_CONFIG Configs[RT_MAX_RESOURCE_TYPES];

    /// Resource states (protected by per-resource ResourceLock)
    RT_RESOURCE_STATE States[RT_MAX_RESOURCE_TYPES];

    /// Number of configured resources (Interlocked* access)
    volatile LONG ConfiguredResourceCount;

    /// Callback — protected by CallbackSpinLock
    PRT_THROTTLE_CALLBACK ThrottleCallback;
    PVOID CallbackContext;
    KSPIN_LOCK CallbackSpinLock;

    /// Callback rundown — prevents unregister during invocation
    volatile LONG CallbackActiveCount;

    /// Per-process quota tracking (protected by ProcessQuotas.Lock KSPIN_LOCK)
    struct {
        LIST_ENTRY HashBuckets[RT_PROCESS_HASH_BUCKETS];
        KSPIN_LOCK Lock;
        volatile LONG ActiveCount;
    } ProcessQuotas;

    /// Deferred work queue
    struct {
        LIST_ENTRY Queue;
        KSPIN_LOCK Lock;
        volatile LONG Depth;
        LONG MaxDepth;
        KTIMER ProcessTimer;
        KDPC ProcessDpc;
        BOOLEAN ProcessingEnabled;
    } DeferredWork;

    /// Monitoring timer and DPC
    KTIMER MonitorTimer;
    KDPC MonitorDpc;
    ULONG MonitorIntervalMs;

    /// System worker thread for PASSIVE_LEVEL deferred work
    HANDLE WorkerThreadHandle;
    PETHREAD WorkerThread;
    KEVENT WorkerWakeEvent;
    volatile LONG WorkerShouldExit;

    /// Lifecycle management via rundown protection
    EX_RUNDOWN_REF RundownRef;

    /// Spin lock protecting Stats snapshot
    KSPIN_LOCK StatsLock;

    /// Statistics
    RT_STATISTICS Stats;

    /// Creation timestamp
    LARGE_INTEGER CreateTime;

} RT_THROTTLER, *PRT_THROTTLER;

#define RT_THROTTLER_MAGIC  0x54485254  // 'THRT'

// ============================================================================
// INITIALIZATION AND CLEANUP
// ============================================================================

/**
 * @brief Initialize the resource throttling subsystem.
 *
 * @param Throttler     Receives pointer to initialized throttler
 * @return STATUS_SUCCESS or STATUS_INSUFFICIENT_RESOURCES
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
RtInitialize(
    _Outptr_ PRT_THROTTLER* Throttler
);

/**
 * @brief Shutdown and cleanup the throttling subsystem.
 *
 * Stops monitoring, drains deferred work, waits for active operations,
 * then frees all resources. Sets caller's pointer to NULL.
 *
 * @param Throttler     Pointer to throttler pointer (NULLed on return)
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
RtShutdown(
    _Inout_ PRT_THROTTLER* Throttler
);

// ============================================================================
// CONFIGURATION (all <= APC_LEVEL)
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
RtSetLimits(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource,
    _In_ ULONG64 SoftLimit,
    _In_ ULONG64 HardLimit,
    _In_ ULONG64 CriticalLimit
);

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
RtSetActions(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource,
    _In_ RT_THROTTLE_ACTION SoftAction,
    _In_ RT_THROTTLE_ACTION HardAction,
    _In_ RT_THROTTLE_ACTION CriticalAction,
    _In_ ULONG DelayMs
);

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
RtSetRateConfig(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource,
    _In_ ULONG RateWindowMs,
    _In_ ULONG BurstCapacity
);

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
RtEnableResource(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource,
    _In_ BOOLEAN Enable
);

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
RtRegisterCallback(
    _In_ PRT_THROTTLER Throttler,
    _In_ PRT_THROTTLE_CALLBACK Callback,
    _In_opt_ PVOID Context
);

/**
 * @brief Unregister throttle callback.
 *
 * Waits for any in-flight callback invocations to complete
 * before clearing the callback pointer.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
RtUnregisterCallback(
    _In_ PRT_THROTTLER Throttler
);

// ============================================================================
// MONITORING CONTROL
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
RtStartMonitoring(
    _In_ PRT_THROTTLER Throttler,
    _In_ ULONG IntervalMs
);

_IRQL_requires_max_(APC_LEVEL)
VOID
RtStopMonitoring(
    _In_ PRT_THROTTLER Throttler
);

// ============================================================================
// USAGE REPORTING AND THROTTLE CHECKING
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
RtReportUsage(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource,
    _In_ LONG64 Delta
);

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
RtSetUsage(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource,
    _In_ ULONG64 Value
);

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
RtCheckThrottle(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource,
    _In_ RT_PRIORITY Priority,
    _Out_ PRT_THROTTLE_ACTION Action
);

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
RtShouldProceed(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource,
    _In_ RT_PRIORITY Priority
);

_When_(Action == RtActionDelay, _IRQL_requires_(PASSIVE_LEVEL))
_When_(Action != RtActionDelay, _IRQL_requires_max_(DISPATCH_LEVEL))
NTSTATUS
RtApplyThrottle(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource,
    _In_ RT_THROTTLE_ACTION Action
);

// ============================================================================
// PER-PROCESS THROTTLING
// ============================================================================

/**
 * @brief Report per-process resource usage.
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
RtReportProcessUsage(
    _In_ PRT_THROTTLER Throttler,
    _In_ HANDLE ProcessId,
    _In_ RT_RESOURCE_TYPE Resource,
    _In_ LONG64 Delta
);

/**
 * @brief Check per-process throttle status.
 *
 * Checks per-process limits first; falls back to global if no
 * per-process limit is set.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
RtCheckProcessThrottle(
    _In_ PRT_THROTTLER Throttler,
    _In_ HANDLE ProcessId,
    _In_ RT_RESOURCE_TYPE Resource,
    _Out_ PRT_THROTTLE_ACTION Action
);

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
RtSetProcessExemption(
    _In_ PRT_THROTTLER Throttler,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Exempt
);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RtRemoveProcess(
    _In_ PRT_THROTTLER Throttler,
    _In_ HANDLE ProcessId
);

// ============================================================================
// DEFERRED WORK QUEUE
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
RtQueueDeferredWork(
    _In_ PRT_THROTTLER Throttler,
    _In_ PRT_DEFERRED_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _In_ RT_PRIORITY Priority,
    _In_ ULONG TimeoutMs
);

_IRQL_requires_max_(DISPATCH_LEVEL)
LONG
RtGetDeferredQueueDepth(
    _In_ PRT_THROTTLER Throttler
);

// ============================================================================
// STATE AND STATISTICS
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
RtGetResourceState(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource,
    _Out_ PRT_THROTTLE_STATE State,
    _Out_opt_ PULONG64 Usage,
    _Out_opt_ PULONG64 Rate
);

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
RtGetStatistics(
    _In_ PRT_THROTTLER Throttler,
    _Out_ PRT_STATISTICS Stats
);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RtResetStatistics(
    _In_ PRT_THROTTLER Throttler
);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RtResetResource(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource
);

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

PCWSTR RtGetResourceName(_In_ RT_RESOURCE_TYPE Resource);
PCWSTR RtGetActionName(_In_ RT_THROTTLE_ACTION Action);
PCWSTR RtGetStateName(_In_ RT_THROTTLE_STATE State);

// ============================================================================
// INLINE UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Check if throttler pointer is valid.
 *
 * Safe to call with NULL (returns FALSE).
 * NOTE: Does NOT protect against use-after-free on its own —
 * callers must ensure the pointer is still owned (not freed).
 */
FORCEINLINE
BOOLEAN
RtIsValidThrottler(
    _In_opt_ PRT_THROTTLER Throttler
)
{
    return (Throttler != NULL &&
            Throttler->Magic == RT_THROTTLER_MAGIC &&
            Throttler->Initialized);
}

/**
 * @brief Check if shutdown is in progress.
 */
FORCEINLINE
BOOLEAN
RtIsShuttingDown(
    _In_ PRT_THROTTLER Throttler
)
{
    return (InterlockedCompareExchange(&Throttler->ShutdownFlag, 0, 0) != 0);
}

#ifdef __cplusplus
}
#endif

#endif // _SHADOWSTRIKE_RESOURCE_THROTTLING_H_
