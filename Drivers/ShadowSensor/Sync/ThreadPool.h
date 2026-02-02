/*++
    ShadowStrike Next-Generation Antivirus
    Module: ThreadPool.h
    
    Purpose: Managed thread pool for executing async work with
             automatic scaling based on workload.
             
    Architecture:
    - Pre-allocated worker threads
    - Dynamic scaling based on queue depth
    - CPU affinity support for cache locality
    - Priority-based thread scheduling
    
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

#define TP_POOL_TAG_CONTEXT     'CTPT'  // Thread Pool - Context
#define TP_POOL_TAG_THREAD      'HTPT'  // Thread Pool - Thread
#define TP_POOL_TAG_WORK        'KWPT'  // Thread Pool - Work

//=============================================================================
// Configuration Constants
//=============================================================================

#define TP_MIN_THREADS              1
#define TP_MAX_THREADS              128
#define TP_DEFAULT_MIN_THREADS      2
#define TP_DEFAULT_MAX_THREADS      32
#define TP_SCALE_UP_THRESHOLD       80      // % queue utilization
#define TP_SCALE_DOWN_THRESHOLD     20      // % queue utilization
#define TP_SCALE_INTERVAL_MS        1000    // Check every second
#define TP_IDLE_TIMEOUT_MS          60000   // Kill idle thread after 1 min

//=============================================================================
// Thread State
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
// Thread Priority
//=============================================================================

typedef enum _TP_THREAD_PRIORITY {
    TpPriority_Lowest = -2,
    TpPriority_BelowNormal = -1,
    TpPriority_Normal = 0,
    TpPriority_AboveNormal = 1,
    TpPriority_Highest = 2,
    TpPriority_TimeCritical = 15
} TP_THREAD_PRIORITY;

//=============================================================================
// Callback Types
//=============================================================================

typedef VOID (*TP_WORK_CALLBACK)(
    _In_opt_ PVOID Context
    );

typedef VOID (*TP_THREAD_INIT_CALLBACK)(
    _In_ ULONG ThreadIndex,
    _In_opt_ PVOID Context
    );

typedef VOID (*TP_THREAD_CLEANUP_CALLBACK)(
    _In_ ULONG ThreadIndex,
    _In_opt_ PVOID Context
    );

//=============================================================================
// Thread Info
//=============================================================================

typedef struct _TP_THREAD_INFO {
    //
    // Thread identity
    //
    HANDLE ThreadHandle;
    PKTHREAD ThreadObject;
    ULONG ThreadIndex;
    ULONG ProcessorNumber;
    
    //
    // Thread state
    //
    volatile TP_THREAD_STATE State;
    volatile BOOLEAN ShutdownRequested;
    
    //
    // Current execution
    //
    TP_WORK_CALLBACK CurrentCallback;
    PVOID CurrentContext;
    LARGE_INTEGER WorkStartTime;
    
    //
    // Idle tracking
    //
    LARGE_INTEGER LastActivityTime;
    LARGE_INTEGER IdleStartTime;
    
    //
    // Statistics
    //
    volatile LONG64 WorkItemsCompleted;
    volatile LONG64 TotalWorkTimeMs;
    volatile LONG64 TotalIdleTimeMs;
    
    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
    
} TP_THREAD_INFO, *PTP_THREAD_INFO;

//=============================================================================
// Thread Pool
//=============================================================================

typedef struct _TP_THREAD_POOL {
    //
    // Pool state
    //
    volatile BOOLEAN Initialized;
    volatile BOOLEAN ShuttingDown;
    
    //
    // Thread list
    //
    LIST_ENTRY ThreadList;
    KSPIN_LOCK ThreadListLock;
    volatile LONG ThreadCount;
    volatile LONG IdleThreadCount;
    volatile LONG RunningThreadCount;
    
    //
    // Thread limits
    //
    ULONG MinThreads;
    ULONG MaxThreads;
    
    //
    // Events
    //
    KEVENT WorkAvailableEvent;
    KEVENT ShutdownEvent;
    KEVENT AllThreadsStoppedEvent;
    
    //
    // Scaling
    //
    KTIMER ScaleTimer;
    KDPC ScaleDpc;
    volatile BOOLEAN ScalingEnabled;
    ULONG ScaleUpThreshold;
    ULONG ScaleDownThreshold;
    
    //
    // Thread callbacks
    //
    TP_THREAD_INIT_CALLBACK InitCallback;
    TP_THREAD_CLEANUP_CALLBACK CleanupCallback;
    PVOID CallbackContext;
    
    //
    // Priority settings
    //
    TP_THREAD_PRIORITY DefaultPriority;
    KAFFINITY AffinityMask;
    BOOLEAN UseIdealProcessor;
    
    //
    // Statistics
    //
    struct {
        volatile LONG64 TotalWorkItems;
        volatile LONG64 ThreadsCreated;
        volatile LONG64 ThreadsDestroyed;
        volatile LONG64 ScaleUpCount;
        volatile LONG64 ScaleDownCount;
        LARGE_INTEGER StartTime;
    } Stats;
    
} TP_THREAD_POOL, *PTP_THREAD_POOL;

//=============================================================================
// Thread Pool Configuration
//=============================================================================

typedef struct _TP_CONFIG {
    ULONG MinThreads;
    ULONG MaxThreads;
    TP_THREAD_PRIORITY DefaultPriority;
    KAFFINITY AffinityMask;
    BOOLEAN EnableScaling;
    ULONG ScaleUpThreshold;
    ULONG ScaleDownThreshold;
    ULONG ScaleIntervalMs;
    ULONG IdleTimeoutMs;
    TP_THREAD_INIT_CALLBACK InitCallback;
    TP_THREAD_CLEANUP_CALLBACK CleanupCallback;
    PVOID CallbackContext;
} TP_CONFIG, *PTP_CONFIG;

//=============================================================================
// Public API - Initialization
//=============================================================================

//
// Create a thread pool
//
NTSTATUS
TpCreate(
    _Out_ PTP_THREAD_POOL* Pool,
    _In_ PTP_CONFIG Config
    );

//
// Create with defaults
//
NTSTATUS
TpCreateDefault(
    _Out_ PTP_THREAD_POOL* Pool,
    _In_ ULONG MinThreads,
    _In_ ULONG MaxThreads
    );

//
// Destroy a thread pool
//
VOID
TpDestroy(
    _Inout_ PTP_THREAD_POOL Pool,
    _In_ BOOLEAN WaitForCompletion
    );

//=============================================================================
// Public API - Thread Management
//=============================================================================

//
// Add threads to the pool
//
NTSTATUS
TpAddThreads(
    _Inout_ PTP_THREAD_POOL Pool,
    _In_ ULONG Count
    );

//
// Remove threads from the pool
//
NTSTATUS
TpRemoveThreads(
    _Inout_ PTP_THREAD_POOL Pool,
    _In_ ULONG Count,
    _In_ BOOLEAN WaitForCompletion
    );

//
// Set thread count
//
NTSTATUS
TpSetThreadCount(
    _Inout_ PTP_THREAD_POOL Pool,
    _In_ ULONG MinThreads,
    _In_ ULONG MaxThreads
    );

//
// Get thread count
//
VOID
TpGetThreadCount(
    _In_ PTP_THREAD_POOL Pool,
    _Out_ PULONG Total,
    _Out_ PULONG Idle,
    _Out_ PULONG Running
    );

//=============================================================================
// Public API - Scaling Control
//=============================================================================

//
// Enable/disable automatic scaling
//
NTSTATUS
TpSetScaling(
    _Inout_ PTP_THREAD_POOL Pool,
    _In_ BOOLEAN Enable,
    _In_ ULONG ScaleUpThreshold,
    _In_ ULONG ScaleDownThreshold
    );

//
// Trigger immediate scale check
//
VOID
TpTriggerScale(
    _In_ PTP_THREAD_POOL Pool
    );

//=============================================================================
// Public API - Thread Priority/Affinity
//=============================================================================

//
// Set default thread priority
//
NTSTATUS
TpSetPriority(
    _Inout_ PTP_THREAD_POOL Pool,
    _In_ TP_THREAD_PRIORITY Priority
    );

//
// Set affinity mask
//
NTSTATUS
TpSetAffinity(
    _Inout_ PTP_THREAD_POOL Pool,
    _In_ KAFFINITY AffinityMask
    );

//=============================================================================
// Public API - Signaling
//=============================================================================

//
// Signal that work is available (wake idle thread)
//
VOID
TpSignalWorkAvailable(
    _In_ PTP_THREAD_POOL Pool
    );

//
// Get event to wait on
//
PKEVENT
TpGetWorkAvailableEvent(
    _In_ PTP_THREAD_POOL Pool
    );

//=============================================================================
// Public API - Statistics
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

NTSTATUS
TpGetStatistics(
    _In_ PTP_THREAD_POOL Pool,
    _Out_ PTP_STATISTICS Stats
    );

VOID
TpResetStatistics(
    _Inout_ PTP_THREAD_POOL Pool
    );

//=============================================================================
// Internal - Thread Entry Point (for work queue integration)
//=============================================================================

//
// Set the work execution function for threads
//
typedef VOID (*TP_WORK_EXECUTOR)(
    _In_ PTP_THREAD_INFO ThreadInfo,
    _In_ PKEVENT WorkEvent,
    _In_ PKEVENT ShutdownEvent,
    _In_opt_ PVOID ExecutorContext
    );

NTSTATUS
TpSetWorkExecutor(
    _Inout_ PTP_THREAD_POOL Pool,
    _In_ TP_WORK_EXECUTOR Executor,
    _In_opt_ PVOID Context
    );

#ifdef __cplusplus
}
#endif
