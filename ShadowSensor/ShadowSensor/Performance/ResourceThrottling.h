/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE RESOURCE THROTTLING ENGINE
 * ============================================================================
 *
 * @file ResourceThrottling.h
 * @brief Enterprise-grade resource throttling for kernel-mode EDR operations.
 *
 * Provides CrowdStrike Falcon-class resource management with:
 * - Multi-dimensional resource tracking (CPU, Memory, I/O, Network, Callbacks)
 * - Adaptive throttling with configurable soft/hard limits
 * - Per-process and global resource quotas
 * - Real-time usage monitoring with DPC-based sampling
 * - Exponential backoff for sustained overload conditions
 * - Priority-based operation scheduling during throttling
 * - Integration with PerformanceMonitor for telemetry
 * - Work queue management for deferred operations
 * - Burst allowance with token bucket algorithm
 * - Automatic recovery when resources normalize
 *
 * Security Guarantees:
 * - Prevents resource exhaustion attacks (DoS mitigation)
 * - Protects system stability under heavy load
 * - Atomic operations for all counter updates
 * - Safe cleanup with reference counting
 * - No deadlocks through lock ordering discipline
 *
 * Performance Optimizations:
 * - Lock-free counters for hot paths
 * - Per-CPU sampling to reduce contention
 * - Tiered throttling to minimize impact
 * - Lazy evaluation of expensive metrics
 * - Cache-line aligned structures
 *
 * MITRE ATT&CK Coverage:
 * - T1499: Endpoint Denial of Service (resource exhaustion prevention)
 * - T1496: Resource Hijacking (CPU/memory abuse detection)
 * - T1498: Network Denial of Service (bandwidth throttling)
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
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

/**
 * @brief Primary pool tag: 'RtTh' = Resource Throttling
 */
#define RT_POOL_TAG                     'hTtR'

/**
 * @brief Pool tag for work items
 */
#define RT_WORKITEM_TAG                 'iWtR'

/**
 * @brief Pool tag for per-process tracking
 */
#define RT_PROCESS_TAG                  'rPtR'

/**
 * @brief Pool tag for deferred queue entries
 */
#define RT_QUEUE_TAG                    'uQtR'

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * @brief Maximum number of resource types
 */
#define RT_MAX_RESOURCE_TYPES           16

/**
 * @brief Maximum tracked processes for per-process throttling
 */
#define RT_MAX_TRACKED_PROCESSES        256

/**
 * @brief Default monitoring interval in milliseconds
 */
#define RT_DEFAULT_MONITOR_INTERVAL_MS  100

/**
 * @brief Minimum monitoring interval
 */
#define RT_MIN_MONITOR_INTERVAL_MS      10

/**
 * @brief Maximum monitoring interval
 */
#define RT_MAX_MONITOR_INTERVAL_MS      10000

/**
 * @brief Default burst allowance (token bucket capacity)
 */
#define RT_DEFAULT_BURST_CAPACITY       100

/**
 * @brief Token refill rate per second
 */
#define RT_TOKEN_REFILL_RATE            10

/**
 * @brief Maximum delay for throttled operations (ms)
 */
#define RT_MAX_DELAY_MS                 1000

/**
 * @brief Minimum delay for throttled operations (ms)
 */
#define RT_MIN_DELAY_MS                 1

/**
 * @brief Exponential backoff multiplier (fixed point: 1.5 = 150)
 */
#define RT_BACKOFF_MULTIPLIER           150

/**
 * @brief Backoff divisor for fixed point math
 */
#define RT_BACKOFF_DIVISOR              100

/**
 * @brief Maximum deferred queue depth
 */
#define RT_MAX_DEFERRED_QUEUE_DEPTH     1024

/**
 * @brief History window for rate calculations (samples)
 */
#define RT_RATE_HISTORY_SIZE            64

/**
 * @brief Hysteresis percentage for state transitions
 */
#define RT_HYSTERESIS_PERCENT           10

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Resource types that can be throttled
 */
typedef enum _RT_RESOURCE_TYPE {
    /// CPU time consumption
    RtResourceCpu = 0,

    /// Non-paged pool memory
    RtResourceMemoryNonPaged,

    /// Paged pool memory
    RtResourceMemoryPaged,

    /// Disk I/O operations per second
    RtResourceDiskIops,

    /// Disk I/O bandwidth (bytes/sec)
    RtResourceDiskBandwidth,

    /// Network I/O operations per second
    RtResourceNetworkIops,

    /// Network I/O bandwidth (bytes/sec)
    RtResourceNetworkBandwidth,

    /// Callback invocations per second
    RtResourceCallbackRate,

    /// Event queue depth
    RtResourceEventQueue,

    /// File system operations per second
    RtResourceFsOps,

    /// Registry operations per second
    RtResourceRegOps,

    /// Process/thread creation rate
    RtResourceProcessCreation,

    /// Handle operations per second
    RtResourceHandleOps,

    /// Memory mapping operations
    RtResourceMemoryMaps,

    /// Custom resource type 1
    RtResourceCustom1,

    /// Custom resource type 2
    RtResourceCustom2,

    /// Sentinel value
    RtResourceMax

} RT_RESOURCE_TYPE;

/**
 * @brief Throttle actions when limits are exceeded
 */
typedef enum _RT_THROTTLE_ACTION {
    /// No action - allow operation
    RtActionNone = 0,

    /// Add configurable delay to operation
    RtActionDelay,

    /// Skip low-priority operations
    RtActionSkipLowPriority,

    /// Queue operation for later processing
    RtActionQueue,

    /// Sample operations (process 1 in N)
    RtActionSample,

    /// Abort operation with status
    RtActionAbort,

    /// Notify only (log but allow)
    RtActionNotify,

    /// Escalate to higher severity response
    RtActionEscalate

} RT_THROTTLE_ACTION;

/**
 * @brief Throttle state for a resource
 */
typedef enum _RT_THROTTLE_STATE {
    /// Normal operation - no throttling
    RtStateNormal = 0,

    /// Warning level - soft limit exceeded
    RtStateWarning,

    /// Throttled - hard limit exceeded
    RtStateThrottled,

    /// Critical - emergency throttling active
    RtStateCritical,

    /// Recovery - transitioning back to normal
    RtStateRecovery

} RT_THROTTLE_STATE;

/**
 * @brief Priority levels for operations
 */
typedef enum _RT_PRIORITY {
    /// Critical - never throttled
    RtPriorityCritical = 0,

    /// High - throttled only at critical state
    RtPriorityHigh,

    /// Normal - throttled at warning and above
    RtPriorityNormal,

    /// Low - throttled first
    RtPriorityLow,

    /// Background - always throttled when any limit exceeded
    RtPriorityBackground

} RT_PRIORITY;

/**
 * @brief Alert severity levels
 */
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
 * @brief Configuration for a single resource limit
 */
typedef struct _RT_RESOURCE_CONFIG {
    /// Resource type this config applies to
    RT_RESOURCE_TYPE Type;

    /// Is this resource being monitored
    BOOLEAN Enabled;

    /// Padding
    UCHAR Reserved[3];

    /// Soft limit - triggers warning state
    ULONG64 SoftLimit;

    /// Hard limit - triggers throttling
    ULONG64 HardLimit;

    /// Critical limit - triggers emergency response
    ULONG64 CriticalLimit;

    /// Action to take at soft limit
    RT_THROTTLE_ACTION SoftAction;

    /// Action to take at hard limit
    RT_THROTTLE_ACTION HardAction;

    /// Action to take at critical limit
    RT_THROTTLE_ACTION CriticalAction;

    /// Delay in milliseconds for RtActionDelay
    ULONG DelayMs;

    /// Sample rate for RtActionSample (1 in N)
    ULONG SampleRate;

    /// Time window for rate-based limits (ms)
    ULONG RateWindowMs;

    /// Burst allowance tokens
    ULONG BurstCapacity;

} RT_RESOURCE_CONFIG, *PRT_RESOURCE_CONFIG;

/**
 * @brief Current state of a resource
 */
typedef struct _RT_RESOURCE_STATE {
    /// Resource type
    RT_RESOURCE_TYPE Type;

    /// Current throttle state
    RT_THROTTLE_STATE State;

    /// Previous state (for hysteresis)
    RT_THROTTLE_STATE PreviousState;

    /// Padding
    UCHAR Reserved;

    /// Current usage value (atomic)
    volatile LONG64 CurrentUsage;

    /// Peak usage in current window
    volatile LONG64 PeakUsage;

    /// Usage at last sample
    LONG64 LastSampleUsage;

    /// Current rate (operations/second)
    volatile LONG64 CurrentRate;

    /// Available burst tokens
    volatile LONG BurstTokens;

    /// Consecutive samples over limit
    ULONG OverLimitCount;

    /// Consecutive samples under limit
    ULONG UnderLimitCount;

    /// Current delay (for exponential backoff)
    ULONG CurrentDelayMs;

    /// Time entered current state
    LARGE_INTEGER StateEnterTime;

    /// Last rate calculation time
    LARGE_INTEGER LastRateCalcTime;

    /// Rate history for averaging
    LONG64 RateHistory[RT_RATE_HISTORY_SIZE];
    ULONG RateHistoryIndex;
    ULONG RateHistorySamples;

    /// Lock for state updates (push lock for efficiency)
    EX_PUSH_LOCK StateLock;

} RT_RESOURCE_STATE, *PRT_RESOURCE_STATE;

/**
 * @brief Per-process resource tracking
 */
typedef struct _RT_PROCESS_QUOTA {
    /// Process ID
    HANDLE ProcessId;

    /// Is this entry in use
    BOOLEAN InUse;

    /// Is this process exempt from throttling
    BOOLEAN Exempt;

    /// Padding
    UCHAR Reserved[6];

    /// Per-resource usage counters
    volatile LONG64 ResourceUsage[RT_MAX_RESOURCE_TYPES];

    /// Per-resource rate counters
    volatile LONG64 ResourceRates[RT_MAX_RESOURCE_TYPES];

    /// Throttle hit count
    volatile LONG64 ThrottleHits;

    /// Last activity time
    LARGE_INTEGER LastActivity;

    /// Hash chain link
    LIST_ENTRY HashLink;

} RT_PROCESS_QUOTA, *PRT_PROCESS_QUOTA;

/**
 * @brief Deferred work item for queued operations
 */
typedef struct _RT_DEFERRED_WORK {
    /// List entry for queue
    LIST_ENTRY ListEntry;

    /// Resource type that triggered queueing
    RT_RESOURCE_TYPE ResourceType;

    /// Priority of this work item
    RT_PRIORITY Priority;

    /// Callback to execute
    PVOID Callback;

    /// Context for callback
    PVOID Context;

    /// Queue time for aging
    LARGE_INTEGER QueueTime;

    /// Expiration time (0 = no expiration)
    LARGE_INTEGER ExpirationTime;

    /// Reference count
    volatile LONG RefCount;

} RT_DEFERRED_WORK, *PRT_DEFERRED_WORK;

/**
 * @brief Throttle event for callback notification
 */
typedef struct _RT_THROTTLE_EVENT {
    /// Resource that triggered the event
    RT_RESOURCE_TYPE Resource;

    /// Action being taken
    RT_THROTTLE_ACTION Action;

    /// New state
    RT_THROTTLE_STATE NewState;

    /// Previous state
    RT_THROTTLE_STATE OldState;

    /// Current usage value
    ULONG64 CurrentUsage;

    /// Limit that was exceeded
    ULONG64 LimitValue;

    /// Current rate (if rate-based)
    ULONG64 CurrentRate;

    /// Process ID (if per-process throttling)
    HANDLE ProcessId;

    /// Timestamp
    LARGE_INTEGER Timestamp;

} RT_THROTTLE_EVENT, *PRT_THROTTLE_EVENT;

/**
 * @brief Statistics for the throttling subsystem
 */
typedef struct _RT_STATISTICS {
    /// Total operations checked
    volatile LONG64 TotalOperations;

    /// Operations that were throttled
    volatile LONG64 ThrottledOperations;

    /// Operations that were delayed
    volatile LONG64 DelayedOperations;

    /// Operations that were queued
    volatile LONG64 QueuedOperations;

    /// Operations that were skipped
    volatile LONG64 SkippedOperations;

    /// Operations that were aborted
    volatile LONG64 AbortedOperations;

    /// Total delay time imposed (ms)
    volatile LONG64 TotalDelayMs;

    /// State transitions
    volatile LONG64 StateTransitions;

    /// Alert notifications sent
    volatile LONG64 AlertsSent;

    /// Deferred work items processed
    volatile LONG64 DeferredWorkProcessed;

    /// Deferred work items expired
    volatile LONG64 DeferredWorkExpired;

    /// Start time of statistics collection
    LARGE_INTEGER StartTime;

    /// Per-resource statistics
    struct {
        volatile LONG64 Checks;
        volatile LONG64 Throttles;
        volatile LONG64 PeakUsage;
    } PerResource[RT_MAX_RESOURCE_TYPES];

} RT_STATISTICS, *PRT_STATISTICS;

/**
 * @brief Callback type for throttle notifications
 */
typedef VOID (*PRT_THROTTLE_CALLBACK)(
    _In_ PRT_THROTTLE_EVENT Event,
    _In_opt_ PVOID Context
);

/**
 * @brief Callback type for deferred work execution
 */
typedef NTSTATUS (*PRT_DEFERRED_CALLBACK)(
    _In_opt_ PVOID Context
);

/**
 * @brief Main throttler structure
 */
typedef struct _RT_THROTTLER {
    /// Initialization flag
    BOOLEAN Initialized;

    /// Is throttling globally enabled
    BOOLEAN Enabled;

    /// Is monitoring active
    BOOLEAN MonitoringActive;

    /// Padding
    UCHAR Reserved;

    /// Magic value for validation
    ULONG Magic;

    /// Resource configurations
    RT_RESOURCE_CONFIG Configs[RT_MAX_RESOURCE_TYPES];

    /// Resource states
    RT_RESOURCE_STATE States[RT_MAX_RESOURCE_TYPES];

    /// Number of configured resources
    ULONG ConfiguredResourceCount;

    /// Global throttle callback
    PRT_THROTTLE_CALLBACK ThrottleCallback;
    PVOID CallbackContext;
    EX_PUSH_LOCK CallbackLock;

    /// Per-process quota tracking
    struct {
        RT_PROCESS_QUOTA Entries[RT_MAX_TRACKED_PROCESSES];
        LIST_ENTRY HashBuckets[64];
        EX_PUSH_LOCK Lock;
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
        KEVENT ShutdownEvent;
        BOOLEAN ProcessingEnabled;
    } DeferredWork;

    /// Monitoring timer and DPC
    KTIMER MonitorTimer;
    KDPC MonitorDpc;
    ULONG MonitorIntervalMs;

    /// Work item for PASSIVE_LEVEL processing
    PIO_WORKITEM PassiveWorkItem;
    volatile LONG PassiveWorkPending;

    /// Shutdown synchronization
    KEVENT ShutdownEvent;
    volatile LONG ShutdownInProgress;
    volatile LONG ActiveOperations;

    /// Reference count for safe cleanup
    volatile LONG ReferenceCount;

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
 * Creates and initializes a throttler instance with default configuration.
 * Must be called at PASSIVE_LEVEL during driver initialization.
 *
 * @param Throttler     Receives pointer to initialized throttler
 *
 * @return STATUS_SUCCESS on success
 * @return STATUS_INSUFFICIENT_RESOURCES if allocation fails
 *
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
 * Stops monitoring, drains deferred work queue, and releases all resources.
 * Waits for all active operations to complete.
 *
 * @param Throttler     Throttler to shutdown (set to NULL on return)
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
RtShutdown(
    _Inout_ PRT_THROTTLER Throttler
);

// ============================================================================
// CONFIGURATION
// ============================================================================

/**
 * @brief Configure limits for a resource type.
 *
 * @param Throttler     Throttler instance
 * @param Resource      Resource type to configure
 * @param SoftLimit     Soft limit (warning threshold)
 * @param HardLimit     Hard limit (throttling threshold)
 * @param CriticalLimit Critical limit (emergency threshold)
 *
 * @return STATUS_SUCCESS on success
 * @return STATUS_INVALID_PARAMETER if limits are invalid
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
RtSetLimits(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource,
    _In_ ULONG64 SoftLimit,
    _In_ ULONG64 HardLimit,
    _In_ ULONG64 CriticalLimit
);

/**
 * @brief Configure actions for a resource type.
 *
 * @param Throttler     Throttler instance
 * @param Resource      Resource type to configure
 * @param SoftAction    Action at soft limit
 * @param HardAction    Action at hard limit
 * @param CriticalAction Action at critical limit
 * @param DelayMs       Delay for RtActionDelay (1-1000ms)
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= APC_LEVEL
 */
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

/**
 * @brief Configure rate-based limiting for a resource.
 *
 * @param Throttler     Throttler instance
 * @param Resource      Resource type to configure
 * @param RateWindowMs  Time window for rate calculation (ms)
 * @param BurstCapacity Maximum burst tokens
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
RtSetRateConfig(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource,
    _In_ ULONG RateWindowMs,
    _In_ ULONG BurstCapacity
);

/**
 * @brief Enable or disable a resource for throttling.
 *
 * @param Throttler     Throttler instance
 * @param Resource      Resource type
 * @param Enable        TRUE to enable, FALSE to disable
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
RtEnableResource(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource,
    _In_ BOOLEAN Enable
);

/**
 * @brief Register callback for throttle events.
 *
 * @param Throttler     Throttler instance
 * @param Callback      Callback function
 * @param Context       Context passed to callback
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= APC_LEVEL
 */
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
 * @param Throttler     Throttler instance
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

/**
 * @brief Start resource monitoring.
 *
 * @param Throttler     Throttler instance
 * @param IntervalMs    Monitoring interval in milliseconds
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
RtStartMonitoring(
    _In_ PRT_THROTTLER Throttler,
    _In_ ULONG IntervalMs
);

/**
 * @brief Stop resource monitoring.
 *
 * @param Throttler     Throttler instance
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
RtStopMonitoring(
    _In_ PRT_THROTTLER Throttler
);

// ============================================================================
// USAGE REPORTING AND THROTTLE CHECKING
// ============================================================================

/**
 * @brief Report resource usage increment.
 *
 * Atomically adds delta to current usage counter.
 *
 * @param Throttler     Throttler instance
 * @param Resource      Resource type
 * @param Delta         Usage increment
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
RtReportUsage(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource,
    _In_ LONG64 Delta
);

/**
 * @brief Report absolute resource usage.
 *
 * Sets the current usage to an absolute value.
 *
 * @param Throttler     Throttler instance
 * @param Resource      Resource type
 * @param Value         Absolute usage value
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
RtSetUsage(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource,
    _In_ ULONG64 Value
);

/**
 * @brief Check if operation should be throttled.
 *
 * Main throttle decision function. Returns recommended action.
 *
 * @param Throttler     Throttler instance
 * @param Resource      Resource type to check
 * @param Priority      Operation priority
 * @param Action        Receives recommended action
 *
 * @return STATUS_SUCCESS if operation should proceed
 * @return STATUS_DEVICE_BUSY if operation should be delayed/queued
 * @return STATUS_QUOTA_EXCEEDED if operation should be aborted
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
RtCheckThrottle(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource,
    _In_ RT_PRIORITY Priority,
    _Out_ PRT_THROTTLE_ACTION Action
);

/**
 * @brief Simplified throttle check returning boolean.
 *
 * @param Throttler     Throttler instance
 * @param Resource      Resource type to check
 * @param Priority      Operation priority
 *
 * @return TRUE if operation should proceed, FALSE if throttled
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
RtShouldProceed(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource,
    _In_ RT_PRIORITY Priority
);

/**
 * @brief Apply throttle action (delay if needed).
 *
 * Executes the throttle action, including delays.
 * For RtActionDelay, blocks for the configured delay period.
 *
 * @param Throttler     Throttler instance
 * @param Resource      Resource type
 * @param Action        Action to apply
 *
 * @return STATUS_SUCCESS if operation should continue
 * @return STATUS_CANCELLED if operation should abort
 *
 * @irql PASSIVE_LEVEL (for delay actions)
 * @irql <= DISPATCH_LEVEL (for non-delay actions)
 */
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
 *
 * @param Throttler     Throttler instance
 * @param ProcessId     Process ID
 * @param Resource      Resource type
 * @param Delta         Usage increment
 *
 * @return STATUS_SUCCESS on success
 *
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
 * @param Throttler     Throttler instance
 * @param ProcessId     Process ID
 * @param Resource      Resource type
 * @param Action        Receives recommended action
 *
 * @return STATUS_SUCCESS or throttle status
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

/**
 * @brief Exempt a process from throttling.
 *
 * @param Throttler     Throttler instance
 * @param ProcessId     Process ID to exempt
 * @param Exempt        TRUE to exempt, FALSE to remove exemption
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
RtSetProcessExemption(
    _In_ PRT_THROTTLER Throttler,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Exempt
);

/**
 * @brief Remove process from tracking.
 *
 * Call when process terminates to free tracking resources.
 *
 * @param Throttler     Throttler instance
 * @param ProcessId     Process ID to remove
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RtRemoveProcess(
    _In_ PRT_THROTTLER Throttler,
    _In_ HANDLE ProcessId
);

// ============================================================================
// DEFERRED WORK QUEUE
// ============================================================================

/**
 * @brief Queue work for deferred execution.
 *
 * @param Throttler     Throttler instance
 * @param Callback      Work callback function
 * @param Context       Context for callback
 * @param Priority      Work priority
 * @param TimeoutMs     Timeout in ms (0 = no timeout)
 *
 * @return STATUS_SUCCESS if queued
 * @return STATUS_QUOTA_EXCEEDED if queue is full
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
RtQueueDeferredWork(
    _In_ PRT_THROTTLER Throttler,
    _In_ PRT_DEFERRED_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _In_ RT_PRIORITY Priority,
    _In_ ULONG TimeoutMs
);

/**
 * @brief Get deferred work queue depth.
 *
 * @param Throttler     Throttler instance
 *
 * @return Current queue depth
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
LONG
RtGetDeferredQueueDepth(
    _In_ PRT_THROTTLER Throttler
);

// ============================================================================
// STATE AND STATISTICS
// ============================================================================

/**
 * @brief Get current state of a resource.
 *
 * @param Throttler     Throttler instance
 * @param Resource      Resource type
 * @param State         Receives current state
 * @param Usage         Receives current usage
 * @param Rate          Receives current rate
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
RtGetResourceState(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource,
    _Out_ PRT_THROTTLE_STATE State,
    _Out_opt_ PULONG64 Usage,
    _Out_opt_ PULONG64 Rate
);

/**
 * @brief Get throttling statistics.
 *
 * @param Throttler     Throttler instance
 * @param Stats         Receives statistics snapshot
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
RtGetStatistics(
    _In_ PRT_THROTTLER Throttler,
    _Out_ PRT_STATISTICS Stats
);

/**
 * @brief Reset throttling statistics.
 *
 * @param Throttler     Throttler instance
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RtResetStatistics(
    _In_ PRT_THROTTLER Throttler
);

/**
 * @brief Reset a resource to normal state.
 *
 * Clears usage counters and resets state to normal.
 *
 * @param Throttler     Throttler instance
 * @param Resource      Resource type to reset
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RtResetResource(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource
);

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get resource type name string.
 *
 * @param Resource      Resource type
 *
 * @return Static string name of resource type
 *
 * @irql Any
 */
PCWSTR
RtGetResourceName(
    _In_ RT_RESOURCE_TYPE Resource
);

/**
 * @brief Get action name string.
 *
 * @param Action        Throttle action
 *
 * @return Static string name of action
 *
 * @irql Any
 */
PCWSTR
RtGetActionName(
    _In_ RT_THROTTLE_ACTION Action
);

/**
 * @brief Get state name string.
 *
 * @param State         Throttle state
 *
 * @return Static string name of state
 *
 * @irql Any
 */
PCWSTR
RtGetStateName(
    _In_ RT_THROTTLE_STATE State
);

// ============================================================================
// INLINE UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Check if throttler is valid.
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
 * @brief Acquire throttler reference.
 */
FORCEINLINE
LONG
RtAcquireReference(
    _In_ PRT_THROTTLER Throttler
)
{
    return InterlockedIncrement(&Throttler->ReferenceCount);
}

/**
 * @brief Release throttler reference.
 */
FORCEINLINE
LONG
RtReleaseReference(
    _In_ PRT_THROTTLER Throttler
)
{
    return InterlockedDecrement(&Throttler->ReferenceCount);
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
    return (Throttler->ShutdownInProgress != 0);
}

#ifdef __cplusplus
}
#endif

#endif // _SHADOWSTRIKE_RESOURCE_THROTTLING_H_
