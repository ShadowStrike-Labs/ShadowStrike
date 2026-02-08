/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE THREAD NOTIFICATION ENGINE
 * ============================================================================
 *
 * @file ThreadNotify.h
 * @brief Enterprise-grade thread creation/termination monitoring and injection detection.
 *
 * Provides CrowdStrike Falcon-class thread monitoring with:
 * - Remote thread injection detection (T1055.003)
 * - Thread hijacking detection
 * - APC injection monitoring
 * - Thread context manipulation detection
 * - Suspicious thread start address analysis
 * - Cross-process thread creation tracking
 * - Thread call stack validation
 * - Per-process thread statistics
 * - Cross-session threat detection
 * - Rapid thread creation pattern detection
 *
 * Detection Capabilities:
 * - CreateRemoteThread / CreateRemoteThreadEx
 * - NtCreateThreadEx with remote process handles
 * - RtlCreateUserThread injection
 * - Thread execution hijacking via SetThreadContext
 * - QueueUserAPC-based injection
 * - Atom bombing and similar techniques
 * - Shellcode injection via unbacked memory
 *
 * MITRE ATT&CK Coverage:
 * - T1055.001: Dynamic-link Library Injection
 * - T1055.002: Portable Executable Injection
 * - T1055.003: Thread Execution Hijacking
 * - T1055.004: Asynchronous Procedure Call
 * - T1055.012: Process Hollowing
 * - T1106: Native API
 *
 * @author ShadowStrike Security Team
 * @version 2.1.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#pragma once

#ifndef _SHADOWSTRIKE_THREAD_NOTIFY_H_
#define _SHADOWSTRIKE_THREAD_NOTIFY_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

// ============================================================================
// POOL TAGS
// ============================================================================

#define TN_POOL_TAG                 'nTsS'  // SsTn - Thread Notify
#define TN_POOL_TAG_CONTEXT         'cTsS'  // SsTc - Thread Context
#define TN_POOL_TAG_EVENT           'eTsS'  // SsTe - Thread Event
#define TN_POOL_TAG_SYSPROCESS      'pTsS'  // SsTp - System Process Cache

// ============================================================================
// CONSTANTS
// ============================================================================

#define TN_MAX_TRACKED_PROCESSES    4096
#define TN_MAX_THREADS_PER_PROCESS  4096
#define TN_THREAD_HISTORY_SIZE      256
#define TN_INJECTION_SCORE_THRESHOLD 500
#define TN_SUSPICIOUS_THREAD_WINDOW_MS 5000
#define TN_MAX_MODULE_WALK_ITERATIONS 2048
#define TN_RAPID_THREAD_THRESHOLD   10
#define TN_RAPID_THREAD_WINDOW_100NS (1000LL * 10000LL)  // 1 second in 100ns units

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Thread event types
 */
typedef enum _TN_EVENT_TYPE {
    TnEventCreate = 0,
    TnEventTerminate,
    TnEventSuspend,
    TnEventResume,
    TnEventContextChange,
    TnEventApcQueue,
    TnEventMax
} TN_EVENT_TYPE;

/**
 * @brief Thread injection indicators (bitmask)
 */
typedef enum _TN_INJECTION_INDICATOR {
    TnIndicator_None                = 0x00000000,
    TnIndicator_RemoteThread        = 0x00000001,   // Thread created by different process
    TnIndicator_SuspendedStart      = 0x00000002,   // Thread created suspended
    TnIndicator_UnbackedStartAddr   = 0x00000004,   // Start address not in any module
    TnIndicator_RWXStartAddr        = 0x00000008,   // Start address in RWX memory
    TnIndicator_SystemProcess       = 0x00000010,   // Target is a system process
    TnIndicator_ProtectedProcess    = 0x00000020,   // Target is a protected process
    TnIndicator_UnusualEntryPoint   = 0x00000040,   // Entry point is suspicious
    TnIndicator_CrossSession        = 0x00000080,   // Cross-session thread creation
    TnIndicator_ElevatedSource      = 0x00000100,   // Source process is elevated
    TnIndicator_KnownInjector       = 0x00000200,   // Source matches known injector patterns
    TnIndicator_RapidCreation       = 0x00000400,   // Many threads created quickly
    TnIndicator_HiddenThread        = 0x00000800,   // Thread attempts to hide itself
    TnIndicator_ApcInjection        = 0x00001000,   // APC-based injection detected
    TnIndicator_ContextHijack       = 0x00002000,   // Thread context was modified
    TnIndicator_ShellcodePattern    = 0x00004000,   // Start address contains shellcode patterns
} TN_INJECTION_INDICATOR;

/**
 * @brief Thread risk level
 */
typedef enum _TN_RISK_LEVEL {
    TnRiskNone = 0,
    TnRiskLow = 1,
    TnRiskMedium = 2,
    TnRiskHigh = 3,
    TnRiskCritical = 4
} TN_RISK_LEVEL;

/**
 * @brief Thread action
 */
typedef enum _TN_ACTION {
    TnActionAllow = 0,
    TnActionMonitor = 1,
    TnActionAlert = 2,
    TnActionBlock = 3
} TN_ACTION;

/**
 * @brief Monitor initialization state
 */
typedef enum _TN_INIT_STATE {
    TnStateUninitialized = 0,
    TnStateInitializing = 1,
    TnStateInitialized = 2,
    TnStateShuttingDown = 3,
    TnStateShutdown = 4
} TN_INIT_STATE;

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Thread creation event details
 */
typedef struct _TN_THREAD_EVENT {
    //
    // Identification
    //
    HANDLE TargetProcessId;
    HANDLE TargetThreadId;
    HANDLE CreatorProcessId;
    HANDLE CreatorThreadId;

    //
    // Event details
    //
    TN_EVENT_TYPE EventType;
    LARGE_INTEGER Timestamp;

    //
    // Thread information
    //
    PVOID StartAddress;
    PVOID Win32StartAddress;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID Teb;

    //
    // Analysis results
    //
    BOOLEAN IsRemote;
    BOOLEAN IsSuspended;
    BOOLEAN IsStartAddressBacked;
    TN_INJECTION_INDICATOR Indicators;
    TN_RISK_LEVEL RiskLevel;
    ULONG InjectionScore;

    //
    // Module information (if start address is in a module)
    //
    WCHAR ModuleName[260];
    ULONG_PTR ModuleBase;
    SIZE_T ModuleSize;

    //
    // Creator process information
    //
    WCHAR CreatorImageName[260];
    ULONG CreatorSessionId;

    //
    // Target process information
    //
    WCHAR TargetImageName[260];
    ULONG TargetSessionId;

    //
    // List management
    //
    LIST_ENTRY ListEntry;

} TN_THREAD_EVENT, *PTN_THREAD_EVENT;

/**
 * @brief Per-process thread tracking context
 */
typedef struct _TN_PROCESS_CONTEXT {
    //
    // Signature for validation
    //
    ULONG Signature;

    //
    // Process identification
    //
    HANDLE ProcessId;
    PEPROCESS Process;

    //
    // Session information
    //
    ULONG SessionId;

    //
    // Thread counts (atomic)
    //
    volatile LONG ThreadCount;
    volatile LONG RemoteThreadCount;
    volatile LONG SuspiciousThreadCount;

    //
    // Recent thread events
    //
    LIST_ENTRY RecentEvents;
    KSPIN_LOCK EventLock;
    ULONG EventCount;

    //
    // Timing for rapid creation detection
    //
    LARGE_INTEGER WindowStart;
    LARGE_INTEGER LastRemoteThread;
    volatile LONG RemoteThreadsInWindow;

    //
    // Risk assessment
    //
    TN_RISK_LEVEL OverallRisk;
    volatile ULONG CumulativeScore;
    TN_INJECTION_INDICATOR CumulativeIndicators;

    //
    // Reference counting (atomic)
    //
    volatile LONG RefCount;

    //
    // Flags
    //
    volatile LONG Destroying;

    //
    // List entry for global list
    //
    LIST_ENTRY ListEntry;

} TN_PROCESS_CONTEXT, *PTN_PROCESS_CONTEXT;

#define TN_PROCESS_CONTEXT_SIGNATURE 'CTHT'

/**
 * @brief Thread notification callback function
 */
typedef VOID
(*TN_CALLBACK_ROUTINE)(
    _In_ PTN_THREAD_EVENT Event,
    _In_opt_ PVOID Context
    );

/**
 * @brief Callback registration entry
 */
typedef struct _TN_CALLBACK_ENTRY {
    TN_CALLBACK_ROUTINE Callback;
    PVOID Context;
    volatile LONG RefCount;
} TN_CALLBACK_ENTRY, *PTN_CALLBACK_ENTRY;

/**
 * @brief Thread notify monitor state
 */
typedef struct _TN_MONITOR {
    //
    // Initialization state (atomic)
    //
    volatile LONG InitState;
    BOOLEAN CallbackRegistered;

    //
    // Process tracking
    //
    LIST_ENTRY ProcessList;
    EX_PUSH_LOCK ProcessLock;
    volatile LONG ProcessCount;

    //
    // Lookaside lists
    //
    NPAGED_LOOKASIDE_LIST EventLookaside;
    NPAGED_LOOKASIDE_LIST ContextLookaside;

    //
    // User callback (protected by lock)
    //
    EX_PUSH_LOCK CallbackLock;
    PTN_CALLBACK_ENTRY CallbackEntry;

    //
    // Configuration
    //
    struct {
        BOOLEAN MonitorRemoteThreads;
        BOOLEAN MonitorSuspendedThreads;
        BOOLEAN ValidateStartAddresses;
        BOOLEAN TrackThreadHistory;
        BOOLEAN DetectCrossSession;
        BOOLEAN DetectRapidCreation;
        ULONG InjectionScoreThreshold;
        TN_ACTION DefaultAction;
    } Config;

    //
    // Statistics (atomic)
    //
    struct {
        volatile LONG64 TotalThreadsCreated;
        volatile LONG64 TotalThreadsTerminated;
        volatile LONG64 RemoteThreadsDetected;
        volatile LONG64 SuspiciousThreadsDetected;
        volatile LONG64 InjectionAttempts;
        volatile LONG64 BlockedThreads;
        volatile LONG64 AlertsGenerated;
        volatile LONG64 CrossSessionDetected;
        volatile LONG64 RapidCreationDetected;
        LARGE_INTEGER StartTime;
    } Stats;

} TN_MONITOR, *PTN_MONITOR;

// ============================================================================
// INITIALIZATION AND CLEANUP
// ============================================================================

/**
 * @brief Registers the thread creation notification callback.
 *
 * Initializes the thread monitoring subsystem and registers with
 * PsSetCreateThreadNotifyRoutine for comprehensive thread tracking.
 *
 * @return STATUS_SUCCESS if successful, otherwise an NTSTATUS error code.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
RegisterThreadNotify(
    VOID
    );

/**
 * @brief Unregisters the thread creation notification callback.
 *
 * Cleans up all tracking structures and unregisters the callback.
 *
 * @return STATUS_SUCCESS if successful, otherwise an NTSTATUS error code.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
UnregisterThreadNotify(
    VOID
    );

// ============================================================================
// MONITORING API
// ============================================================================

/**
 * @brief Get thread monitor instance.
 *
 * @return Pointer to global thread monitor, or NULL if not initialized.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
PTN_MONITOR
TnGetMonitor(
    VOID
    );

/**
 * @brief Check if thread monitor is ready.
 *
 * @return TRUE if monitor is initialized and ready.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
TnIsReady(
    VOID
    );

/**
 * @brief Register a user callback for thread events.
 *
 * @param Callback  Callback routine to invoke on thread events.
 * @param Context   Optional context passed to callback.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TnRegisterCallback(
    _In_ TN_CALLBACK_ROUTINE Callback,
    _In_opt_ PVOID Context
    );

/**
 * @brief Unregister user callback.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
TnUnregisterCallback(
    VOID
    );

// ============================================================================
// PROCESS CLEANUP INTEGRATION
// ============================================================================

/**
 * @brief Notify thread monitor of process termination.
 *
 * Called by process notify callback to clean up thread tracking state
 * for a terminating process. This must be called to prevent memory leaks
 * and stale EPROCESS references.
 *
 * @param ProcessId   ID of the terminating process.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
TnNotifyProcessTermination(
    _In_ HANDLE ProcessId
    );

// ============================================================================
// QUERY API
// ============================================================================

/**
 * @brief Get process thread context.
 *
 * @param ProcessId     Target process ID.
 * @param Context       Receives process context (must be released when done).
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
TnGetProcessContext(
    _In_ HANDLE ProcessId,
    _Outptr_ PTN_PROCESS_CONTEXT* Context
    );

/**
 * @brief Release reference to process context.
 *
 * @param Context   Context to dereference.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TnReleaseProcessContext(
    _In_ PTN_PROCESS_CONTEXT Context
    );

/**
 * @brief Check if a thread is a remote injection.
 *
 * @param TargetProcessId   Process containing the thread.
 * @param ThreadId          Thread to check.
 * @param IsRemote          Receives TRUE if remote thread.
 * @param Indicators        Optional; receives injection indicators.
 * @param Score             Optional; receives injection score.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TnIsRemoteThread(
    _In_ HANDLE TargetProcessId,
    _In_ HANDLE ThreadId,
    _Out_ PBOOLEAN IsRemote,
    _Out_opt_ TN_INJECTION_INDICATOR* Indicators,
    _Out_opt_ PULONG Score
    );

/**
 * @brief Analyze thread start address for suspicious patterns.
 *
 * @param ProcessId     Process containing the thread.
 * @param StartAddress  Thread start address to analyze.
 * @param Indicators    Receives detected indicators.
 * @param RiskLevel     Receives risk assessment.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TnAnalyzeStartAddress(
    _In_ HANDLE ProcessId,
    _In_ PVOID StartAddress,
    _Out_ TN_INJECTION_INDICATOR* Indicators,
    _Out_ TN_RISK_LEVEL* RiskLevel
    );

// ============================================================================
// STATISTICS
// ============================================================================

/**
 * @brief Get thread monitor statistics.
 *
 * @param TotalCreated          Receives total threads created.
 * @param TotalTerminated       Receives total threads terminated.
 * @param RemoteDetected        Receives remote threads detected.
 * @param SuspiciousDetected    Receives suspicious threads detected.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TnGetStatistics(
    _Out_opt_ PULONG64 TotalCreated,
    _Out_opt_ PULONG64 TotalTerminated,
    _Out_opt_ PULONG64 RemoteDetected,
    _Out_opt_ PULONG64 SuspiciousDetected
    );

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get risk level name string.
 *
 * @param Level     Risk level value.
 *
 * @return Static string name.
 *
 * @irql Any
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
PCWSTR
TnGetRiskLevelName(
    _In_ TN_RISK_LEVEL Level
    );

/**
 * @brief Get indicator description.
 *
 * @param Indicator     Indicator flag.
 *
 * @return Static string description.
 *
 * @irql Any
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
PCWSTR
TnGetIndicatorName(
    _In_ TN_INJECTION_INDICATOR Indicator
    );

#ifdef __cplusplus
}
#endif

#endif // _SHADOWSTRIKE_THREAD_NOTIFY_H_
