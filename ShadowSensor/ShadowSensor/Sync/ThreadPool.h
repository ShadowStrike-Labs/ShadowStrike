/*++
    ShadowStrike Next-Generation Antivirus
    Module: ThreadPool.h
    
    Purpose: Enterprise-grade managed thread pool for kernel-mode EDR operations.
    
    Architecture:
    - Pre-allocated worker threads with dynamic scaling
    - CPU affinity and ideal processor support for cache locality
    - Priority-based thread scheduling via KeSetPriorityThread
    - Graceful shutdown with work completion guarantees
    - Per-thread statistics and performance monitoring
    - DPC-safe scaling via IoQueueWorkItem (deferred to PASSIVE_LEVEL)
    - Opaque internal structures — public API only
    
    IRQL Contract:
    - TpCreate / TpCreateDefault / TpDestroy: PASSIVE_LEVEL only
    - TpAddThreads / TpRemoveThreads / TpSetWorkExecutor / TpSetScaling: PASSIVE_LEVEL only
    - TpGetThreadCount / TpSignalWorkAvailable / TpGetWorkAvailableEvent: <= DISPATCH_LEVEL
    - TpSetPriority / TpSetAffinity / TpSetThreadCount: PASSIVE_LEVEL only
    - TpGetStatistics / TpResetStatistics: <= DISPATCH_LEVEL
    - TpTriggerScale: <= DISPATCH_LEVEL (queues DPC, which defers to work item)
    
    Thread Safety:
    - All public APIs are thread-safe
    - Work executor callback runs at PASSIVE_LEVEL
    - Init/cleanup callbacks run at PASSIVE_LEVEL
    
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntifs.h>

//=============================================================================
// Pool Tags
//=============================================================================

#define TP_POOL_TAG_CONTEXT     'CTPT'  // Thread Pool - Context
#define TP_POOL_TAG_THREAD      'HTPT'  // Thread Pool - Thread
#define TP_POOL_TAG_WORK        'KWPT'  // Thread Pool - Work

//=============================================================================
// Configuration Constants (Public)
//=============================================================================

#define TP_MIN_THREADS              1
#define TP_MAX_THREADS              128
#define TP_DEFAULT_MIN_THREADS      2
#define TP_DEFAULT_MAX_THREADS      32
#define TP_SCALE_UP_THRESHOLD       80      // % utilization to trigger scale-up
#define TP_SCALE_DOWN_THRESHOLD     20      // % utilization to trigger scale-down
#define TP_SCALE_INTERVAL_MS        1000    // Scaling check interval (ms)
#define TP_IDLE_TIMEOUT_MS          60000   // Idle thread timeout (ms)

//=============================================================================
// Thread State (Public — read-only for callers)
//=============================================================================

typedef enum _TP_THREAD_STATE {
    TpThreadState_Uninitialized = 0,
    TpThreadState_Starting,
    TpThreadState_Idle,
    TpThreadState_Running,
    TpThreadState_Stopping,
    TpThreadState_Stopped
} TP_THREAD_STATE;

//=============================================================================
// Thread Priority (Public)
//=============================================================================

typedef enum _TP_THREAD_PRIORITY {
    TpPriority_Lowest       = -2,
    TpPriority_BelowNormal  = -1,
    TpPriority_Normal       = 0,
    TpPriority_AboveNormal  = 1,
    TpPriority_Highest      = 2,
    TpPriority_TimeCritical = 15
} TP_THREAD_PRIORITY;

//=============================================================================
// Opaque Types — Internal structures defined only in ThreadPool.c
//=============================================================================

//
// TP_THREAD_POOL: Opaque thread pool handle.
// Callers receive PTP_THREAD_POOL from TpCreate and pass it to all APIs.
// Internal layout is NEVER exposed to consumers.
//
typedef struct _TP_THREAD_POOL TP_THREAD_POOL, *PTP_THREAD_POOL;

//
// TP_THREAD_INFO: Opaque per-thread handle.
// Only passed to work executor callbacks.
//
typedef struct _TP_THREAD_INFO TP_THREAD_INFO, *PTP_THREAD_INFO;

//=============================================================================
// Callback Types
//=============================================================================

//
// TP_WORK_EXECUTOR: Main work execution function called by each worker thread.
// IRQL: Called at PASSIVE_LEVEL.
// Contract: Must return within a reasonable time (check ShutdownEvent periodically).
//
// Parameters:
//   ThreadInfo      - Opaque per-thread info (for TpGetThreadIndex)
//   WorkEvent       - Signals when work is available (auto-reset)
//   ShutdownEvent   - Signals when pool is shutting down (manual-reset)
//   ExecutorContext  - Caller-supplied context from TpSetWorkExecutor
//
typedef VOID (*TP_WORK_EXECUTOR)(
    _In_ PTP_THREAD_INFO ThreadInfo,
    _In_ PKEVENT WorkEvent,
    _In_ PKEVENT ShutdownEvent,
    _In_opt_ PVOID ExecutorContext
    );

//
// TP_THREAD_INIT_CALLBACK: Called when a worker thread starts.
// IRQL: PASSIVE_LEVEL.
//
typedef VOID (*TP_THREAD_INIT_CALLBACK)(
    _In_ ULONG ThreadIndex,
    _In_opt_ PVOID Context
    );

//
// TP_THREAD_CLEANUP_CALLBACK: Called before a worker thread is destroyed.
// IRQL: PASSIVE_LEVEL.
// Contract: Must NOT block indefinitely.
//
typedef VOID (*TP_THREAD_CLEANUP_CALLBACK)(
    _In_ ULONG ThreadIndex,
    _In_opt_ PVOID Context
    );

//=============================================================================
// Thread Pool Configuration
//=============================================================================

typedef struct _TP_CONFIG {
    ULONG MinThreads;
    ULONG MaxThreads;
    TP_THREAD_PRIORITY DefaultPriority;
    KAFFINITY AffinityMask;
    BOOLEAN EnableScaling;
    ULONG ScaleUpThreshold;         // 0-100, default TP_SCALE_UP_THRESHOLD
    ULONG ScaleDownThreshold;       // 0-100, default TP_SCALE_DOWN_THRESHOLD
    ULONG ScaleIntervalMs;          // 0 = default TP_SCALE_INTERVAL_MS
    ULONG IdleTimeoutMs;            // 0 = default TP_IDLE_TIMEOUT_MS
    TP_THREAD_INIT_CALLBACK InitCallback;
    TP_THREAD_CLEANUP_CALLBACK CleanupCallback;
    PVOID CallbackContext;
    PDEVICE_OBJECT DeviceObject;    // Required for DPC→work item deferral
} TP_CONFIG, *PTP_CONFIG;

//=============================================================================
// Statistics (Public — returned by TpGetStatistics, no internal pointers)
//=============================================================================

typedef struct _TP_STATISTICS {
    ULONG TotalThreads;
    ULONG IdleThreads;
    ULONG RunningThreads;
    ULONG MinThreads;
    ULONG MaxThreads;
    ULONG64 TotalWorkItems;
    ULONG64 ThreadsCreated;
    ULONG64 ThreadsDestroyed;
    ULONG64 ScaleUpCount;
    ULONG64 ScaleDownCount;
    LARGE_INTEGER UpTime;
    ULONG AverageWorkTimeMs;
    ULONG AverageIdleTimeMs;
    BOOLEAN ScalingEnabled;
} TP_STATISTICS, *PTP_STATISTICS;

//=============================================================================
// Public API - Initialization
//=============================================================================

//
// Create a thread pool with full configuration.
// IRQL: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TpCreate(
    _Out_ PTP_THREAD_POOL* Pool,
    _In_ const TP_CONFIG* Config
    );

//
// Create a thread pool with defaults (scaling enabled, normal priority).
// IRQL: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TpCreateDefault(
    _Out_ PTP_THREAD_POOL* Pool,
    _In_ ULONG MinThreads,
    _In_ ULONG MaxThreads,
    _In_opt_ PDEVICE_OBJECT DeviceObject
    );

//
// Destroy a thread pool. Signals all threads to stop, optionally waits.
// IRQL: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
TpDestroy(
    _Inout_ PTP_THREAD_POOL* Pool,
    _In_ BOOLEAN WaitForCompletion
    );

//=============================================================================
// Public API - Thread Management
//=============================================================================

//
// Add threads to the pool (up to MaxThreads).
// IRQL: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TpAddThreads(
    _Inout_ PTP_THREAD_POOL Pool,
    _In_ ULONG Count
    );

//
// Remove threads from the pool (down to MinThreads).
// IRQL: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TpRemoveThreads(
    _Inout_ PTP_THREAD_POOL Pool,
    _In_ ULONG Count,
    _In_ BOOLEAN WaitForCompletion
    );

//
// Set min/max thread limits. Triggers scale check.
// IRQL: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TpSetThreadCount(
    _Inout_ PTP_THREAD_POOL Pool,
    _In_ ULONG MinThreads,
    _In_ ULONG MaxThreads
    );

//
// Get current thread counts (lock-free reads of volatile counters).
// IRQL: <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TpGetThreadCount(
    _In_ PTP_THREAD_POOL Pool,
    _Out_opt_ PULONG Total,
    _Out_opt_ PULONG Idle,
    _Out_opt_ PULONG Running
    );

//=============================================================================
// Public API - Scaling Control
//=============================================================================

//
// Enable/disable automatic scaling.
// IRQL: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TpSetScaling(
    _Inout_ PTP_THREAD_POOL Pool,
    _In_ BOOLEAN Enable,
    _In_ ULONG ScaleUpThreshold,
    _In_ ULONG ScaleDownThreshold
    );

//
// Trigger an immediate scale evaluation (queues DPC → work item).
// IRQL: <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TpTriggerScale(
    _In_ PTP_THREAD_POOL Pool
    );

//=============================================================================
// Public API - Thread Priority/Affinity
//=============================================================================

//
// Set default priority for all pool threads.
// IRQL: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TpSetPriority(
    _Inout_ PTP_THREAD_POOL Pool,
    _In_ TP_THREAD_PRIORITY Priority
    );

//
// Set CPU affinity mask for all pool threads.
// IRQL: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TpSetAffinity(
    _Inout_ PTP_THREAD_POOL Pool,
    _In_ KAFFINITY AffinityMask
    );

//=============================================================================
// Public API - Signaling
//=============================================================================

//
// Signal that work is available (wakes one idle thread via semaphore).
// IRQL: <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TpSignalWorkAvailable(
    _In_ PTP_THREAD_POOL Pool
    );

//=============================================================================
// Public API - Work Executor
//=============================================================================

//
// Set the work execution function for all worker threads.
// Must be called before work is submitted, or during initialization.
// IRQL: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TpSetWorkExecutor(
    _Inout_ PTP_THREAD_POOL Pool,
    _In_ TP_WORK_EXECUTOR Executor,
    _In_opt_ PVOID Context
    );

//=============================================================================
// Public API - Statistics
//=============================================================================

//
// Get current pool statistics (copies data, no internal pointers).
// IRQL: <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
TpGetStatistics(
    _In_ PTP_THREAD_POOL Pool,
    _Out_ PTP_STATISTICS Stats
    );

//
// Reset all pool and per-thread statistics counters.
// IRQL: <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TpResetStatistics(
    _Inout_ PTP_THREAD_POOL Pool
    );

//=============================================================================
// Public API - Thread Info Helpers (for use inside work executor callbacks)
//=============================================================================

//
// Get the thread index from an opaque thread info handle.
// IRQL: Any
//
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
TpGetThreadIndex(
    _In_ PTP_THREAD_INFO ThreadInfo
    );

#ifdef __cplusplus
}
#endif
