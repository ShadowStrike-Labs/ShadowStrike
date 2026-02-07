/**
 * ============================================================================
 * ShadowStrike NGAV - PROCESS PROTECTION MONITOR (Enterprise Edition)
 * ============================================================================
 *
 * @file AlpcMonitor.h
 * @brief Enterprise-grade LSASS protection and credential theft detection.
 *
 * Provides CrowdStrike Falcon-level protection against:
 * - LSASS credential dumping (Mimikatz, LaZagne, ProcDump, etc.)
 * - Process injection via remote thread creation
 * - Token manipulation and privilege escalation
 * - Handle duplication attacks
 * - Cross-session process access
 *
 * Architecture (PRODUCTION-GRADE APPROACH):
 * ==========================================
 * 1. ObRegisterCallbacks for *PsProcessType* (documented API)
 *    -> Monitor PROCESS_VM_READ on LSASS (credential theft)
 *    -> Monitor PROCESS_CREATE_THREAD (injection)
 *    -> Monitor PROCESS_DUP_HANDLE (privilege escalation)
 *
 * 2. Process Notify Routine (PsSetCreateProcessNotifyRoutineEx)
 *    -> Track process lifetime and parent chains
 *    -> Cleanup connections on process exit
 *    -> Detect suspicious process creation patterns
 *
 * 3. Thread-safe connection tracking with LRU cache
 *    -> Atomic initialization (no race conditions)
 *    -> Reference counting (no use-after-free)
 *    -> Proper lock hierarchy (no deadlocks)
 *    -> IRQL-safe operations throughout
 *
 * 4. Rate limiting and behavioral analytics
 *    -> Time-windowed access tracking
 *    -> Adaptive threat scoring
 *    -> Anomaly detection
 *
 * 5. User-mode communication (filter communication port)
 *    -> Real-time threat alerts
 *    -> Telemetry streaming
 *    -> Policy updates
 *
 * Security Guarantees:
 * ====================
 * - BSOD-safe: Atomic initialization, proper cleanup, exception handling
 * - Thread-safe: All operations protected by appropriate locks
 * - IRQL-safe: NonPagedPool for callback contexts, proper lock usage
 * - DoS-resistant: Rate limiting, bounded memory usage
 * - Bypass-resistant: Multiple detection layers, behavioral analytics
 *
 * Lock Hierarchy (MUST BE FOLLOWED):
 * ==================================
 * 1. state->Lock (EX_PUSH_LOCK) - Outer lock, acquired at PASSIVE/APC
 * 2. state->AlertLock (KSPIN_LOCK) - Inner lock, raises to DISPATCH
 * NEVER acquire Lock while holding AlertLock!
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1003.001: OS Credential Dumping - LSASS Memory (PRIMARY)
 * - T1055.001: Process Injection - Dynamic-link Library Injection
 * - T1055.002: Process Injection - Portable Executable Injection
 * - T1055.003: Process Injection - Thread Execution Hijacking
 * - T1134.001: Access Token Manipulation - Token Impersonation/Theft
 * - T1134.002: Access Token Manipulation - Create Process with Token
 * - T1134.003: Access Token Manipulation - Make and Impersonate Token
 * - T1106: Native API (direct LSASS access)
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition - Production Ready)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_ALPC_MONITOR_H
#define SHADOWSTRIKE_ALPC_MONITOR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include <ntifs.h>
#include <wdm.h>
#include <ntstrsafe.h>

// ============================================================================
// POOL TAGS
// ============================================================================

/**
 * @brief Pool tag for ALPC monitor allocations: 'aSSx' = ShadowStrike ALPC
 */
#define SHADOW_ALPC_TAG 'aSSx'

/**
 * @brief Pool tag for process tracking entries
 */
#define SHADOW_ALPC_PROCESS_TAG 'pSSa'

/**
 * @brief Pool tag for ALPC port name strings (NonPaged for callback safety)
 */
#define SHADOW_ALPC_STRING_TAG 'sSSa'

/**
 * @brief Pool tag for alert queue entries
 */
#define SHADOW_ALPC_ALERT_TAG 'lSSa'

/**
 * @brief Pool tag for cached process names
 */
#define SHADOW_ALPC_CACHE_TAG 'cSSa'

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * @brief Maximum tracked process access records (LRU cache)
 */
#define SHADOW_MAX_PROCESS_TRACKING 2048

/**
 * @brief Maximum process image name length (characters)
 */
#define SHADOW_MAX_PROCESS_NAME 260

/**
 * @brief Maximum base name length for exact matching
 */
#define SHADOW_MAX_BASE_NAME 64

/**
 * @brief Rate limit window (milliseconds)
 */
#define SHADOW_RATE_LIMIT_WINDOW_MS 1000

/**
 * @brief Maximum process opens per second (rate limit)
 */
#define SHADOW_MAX_OPENS_PER_SECOND 10

/**
 * @brief Threat score threshold for blocking
 */
#define SHADOW_ALPC_THREAT_THRESHOLD 75

/**
 * @brief Alert queue maximum size
 */
#define SHADOW_MAX_ALERT_QUEUE 512

/**
 * @brief Process name cache size
 */
#define SHADOW_PROCESS_NAME_CACHE_SIZE 256

/**
 * @brief Process name cache entry TTL (100ns units = 30 seconds)
 */
#define SHADOW_PROCESS_NAME_CACHE_TTL (30LL * 10000000LL)

/**
 * @brief Initialization states
 */
#define ALPC_STATE_UNINITIALIZED 0
#define ALPC_STATE_INITIALIZING  1
#define ALPC_STATE_INITIALIZED   2

// ============================================================================
// SUSPICIOUS ACCESS RIGHTS (Credential Theft & Injection Patterns)
// ============================================================================

/**
 * @brief Access rights that indicate credential dumping attempts
 */
#define SUSPICIOUS_CREDENTIAL_ACCESS ( \
    PROCESS_VM_READ |                  \
    PROCESS_QUERY_INFORMATION |        \
    PROCESS_QUERY_LIMITED_INFORMATION  \
)

/**
 * @brief Access rights that indicate process injection attempts
 */
#define SUSPICIOUS_INJECTION_ACCESS (  \
    PROCESS_CREATE_THREAD |            \
    PROCESS_VM_WRITE |                 \
    PROCESS_VM_OPERATION               \
)

/**
 * @brief Access rights for handle duplication attacks
 */
#define SUSPICIOUS_HANDLE_ACCESS (     \
    PROCESS_DUP_HANDLE                 \
)

// ============================================================================
// THREAT LEVELS
// ============================================================================

/**
 * @brief Process access threat severity levels.
 */
typedef enum _SHADOW_THREAT_LEVEL {
    ThreatNone = 0,           ///< Benign access
    ThreatLow = 25,           ///< Suspicious but likely safe
    ThreatMedium = 50,        ///< Potentially malicious
    ThreatHigh = 75,          ///< Likely malicious
    ThreatCritical = 100      ///< Confirmed malicious (block)
} SHADOW_THREAT_LEVEL;

/**
 * @brief Process operation types.
 */
typedef enum _SHADOW_PROCESS_OPERATION {
    ProcessOperationOpen = 1,      ///< Process handle open
    ProcessOperationDuplicate = 2, ///< Handle duplication
    ProcessOperationCreate = 3,    ///< Process creation
    ProcessOperationTerminate = 4  ///< Process termination
} SHADOW_PROCESS_OPERATION;

/**
 * @brief Alert types for user-mode notification.
 */
typedef enum _SHADOW_ALERT_TYPE {
    AlertCredentialTheft = 1,      ///< LSASS credential dumping
    AlertProcessInjection = 2,     ///< Thread injection attack
    AlertTokenManipulation = 3,    ///< Token theft/impersonation
    AlertHandleDuplication = 4,    ///< Handle duplication attack
    AlertCrossSessionAccess = 5,   ///< Cross-session suspicious access
    AlertRateLimitViolation = 6,   ///< Rate limit exceeded
    AlertSuspiciousParent = 7      ///< Suspicious parent process
} SHADOW_ALERT_TYPE;

// ============================================================================
// STATISTICS STRUCTURE
// ============================================================================

/**
 * @brief ALPC monitoring statistics.
 *
 * All counters are atomic (updated via InterlockedIncrement/Add).
 */
typedef struct _SHADOW_ALPC_STATISTICS {

    /// @brief Total process access attempts observed
    volatile LONG64 TotalProcessAccess;

    /// @brief Process opens to protected processes
    volatile LONG64 ProtectedProcessAccess;

    /// @brief LSASS access attempts (credential theft detection)
    volatile LONG64 LsassAccessAttempts;

    /// @brief Suspicious VM_READ operations
    volatile LONG64 SuspiciousVmRead;

    /// @brief Process injection attempts (CREATE_THREAD)
    volatile LONG64 InjectionAttempts;

    /// @brief Token manipulation attempts
    volatile LONG64 TokenManipulationAttempts;

    /// @brief Handle duplication attempts
    volatile LONG64 HandleDuplicationAttempts;

    /// @brief Cross-session access attempts
    volatile LONG64 CrossSessionAccess;

    /// @brief Blocked operations (high threat score)
    volatile LONG64 BlockedOperations;

    /// @brief Total threat alerts generated
    volatile LONG64 ThreatAlerts;

    /// @brief Rate limit violations
    volatile LONG64 RateLimitViolations;

    /// @brief Cache hits (process lookup)
    volatile LONG64 CacheHits;

    /// @brief Cache misses (process lookup)
    volatile LONG64 CacheMisses;

    /// @brief Process creations tracked
    volatile LONG64 ProcessCreations;

    /// @brief Process exits tracked
    volatile LONG64 ProcessExits;

    /// @brief Process name cache hits
    volatile LONG64 NameCacheHits;

    /// @brief Process name cache misses
    volatile LONG64 NameCacheMisses;

} SHADOW_ALPC_STATISTICS, *PSHADOW_ALPC_STATISTICS;

// ============================================================================
// PROCESS NAME CACHE ENTRY (IRQL-SAFE)
// ============================================================================

/**
 * @brief Cached process name entry for IRQL-safe lookups.
 *
 * This cache allows process name lookups from DISPATCH_LEVEL callbacks
 * without allocating paged memory.
 */
typedef struct _SHADOW_PROCESS_NAME_CACHE_ENTRY {

    /// @brief Process ID
    HANDLE ProcessId;

    /// @brief Base name (null-terminated, lowercase)
    WCHAR BaseName[SHADOW_MAX_BASE_NAME];

    /// @brief Full path (null-terminated, lowercase)
    WCHAR FullPath[SHADOW_MAX_PROCESS_NAME];

    /// @brief Cache entry timestamp
    LARGE_INTEGER Timestamp;

    /// @brief Is this entry valid?
    BOOLEAN Valid;

    /// @brief Is this a protected process?
    BOOLEAN IsProtected;

    /// @brief Session ID
    ULONG SessionId;

    /// @brief Parent process ID (cached at creation time)
    HANDLE ParentProcessId;

} SHADOW_PROCESS_NAME_CACHE_ENTRY, *PSHADOW_PROCESS_NAME_CACHE_ENTRY;

// ============================================================================
// PROCESS TRACKING ENTRY
// ============================================================================

/**
 * @brief Process access tracking entry.
 *
 * Tracks per-process access patterns for behavioral analysis.
 * All fields are safe for access at DISPATCH_LEVEL.
 */
typedef struct _SHADOW_PROCESS_TRACKING {

    /// @brief List entry for LRU cache
    LIST_ENTRY ListEntry;

    /// @brief Source process ID (accessor)
    HANDLE SourceProcessId;

    /// @brief Target process ID (accessed)
    HANDLE TargetProcessId;

    /// @brief Source process base name (from cache, IRQL-safe)
    WCHAR SourceProcessName[SHADOW_MAX_BASE_NAME];

    /// @brief Target process base name (from cache, IRQL-safe)
    WCHAR TargetProcessName[SHADOW_MAX_BASE_NAME];

    /// @brief Parent process ID of source
    HANDLE ParentProcessId;

    /// @brief First access timestamp
    LARGE_INTEGER FirstAccessTime;

    /// @brief Last access timestamp
    LARGE_INTEGER LastAccessTime;

    /// @brief Access count (for rate limiting)
    volatile LONG AccessCount;

    /// @brief Cumulative threat score (0-100)
    volatile LONG ThreatScore;

    /// @brief Access rights requested (bitfield)
    ACCESS_MASK RequestedAccess;

    /// @brief Is target a protected process?
    BOOLEAN IsProtectedTarget;

    /// @brief Is this cross-session access?
    BOOLEAN IsCrossSession;

    /// @brief Has credential access rights?
    BOOLEAN HasCredentialAccess;

    /// @brief Has injection access rights?
    BOOLEAN HasInjectionAccess;

    /// @brief Is this access blocked?
    BOOLEAN IsBlocked;

    /// @brief Reference count for safe cleanup
    volatile LONG ReferenceCount;

    /// @brief Entry has been removed from list (pending free)
    volatile LONG RemovedFromList;

    /// @brief Padding for alignment
    UCHAR Reserved[4];

} SHADOW_PROCESS_TRACKING, *PSHADOW_PROCESS_TRACKING;

// ============================================================================
// ALERT STRUCTURE
// ============================================================================

/**
 * @brief Threat alert for user-mode notification.
 */
typedef struct _SHADOW_THREAT_ALERT {

    /// @brief List entry for alert queue
    LIST_ENTRY ListEntry;

    /// @brief Alert type
    SHADOW_ALERT_TYPE AlertType;

    /// @brief Threat score (0-100)
    ULONG ThreatScore;

    /// @brief Source process ID
    HANDLE SourceProcessId;

    /// @brief Target process ID
    HANDLE TargetProcessId;

    /// @brief Source process name (base name only)
    WCHAR SourceProcessName[SHADOW_MAX_BASE_NAME];

    /// @brief Target process name (base name only)
    WCHAR TargetProcessName[SHADOW_MAX_BASE_NAME];

    /// @brief Alert timestamp
    LARGE_INTEGER AlertTime;

    /// @brief Access rights requested
    ACCESS_MASK RequestedAccess;

    /// @brief Was this access blocked?
    BOOLEAN WasBlocked;

    /// @brief Padding
    UCHAR Reserved[3];

} SHADOW_THREAT_ALERT, *PSHADOW_THREAT_ALERT;

// ============================================================================
// GLOBAL STATE STRUCTURE
// ============================================================================

/**
 * @brief Process monitor global state.
 *
 * Lock Hierarchy (MUST follow this order):
 * 1. Lock (EX_PUSH_LOCK) - for TrackingList, acquired at PASSIVE/APC
 * 2. NameCacheLock (KSPIN_LOCK) - for ProcessNameCache, raises to DISPATCH
 * 3. AlertLock (KSPIN_LOCK) - for AlertQueue, raises to DISPATCH
 *
 * NEVER acquire a higher-numbered lock while holding a lower-numbered lock
 * when the lower lock is a spinlock (would cause IRQL issues).
 */
typedef struct _SHADOW_ALPC_MONITOR_STATE {

    //
    // Synchronization
    //

    /// @brief Lock protecting TrackingList (PASSIVE/APC level only)
    EX_PUSH_LOCK Lock;

    /// @brief TRUE if Lock was initialized
    BOOLEAN LockInitialized;

    /// @brief Lock protecting ProcessNameCache (can be acquired at DISPATCH)
    KSPIN_LOCK NameCacheLock;

    /// @brief Lock protecting AlertQueue (can be acquired at DISPATCH)
    KSPIN_LOCK AlertLock;

    /// @brief Atomic initialization state (0/1/2)
    volatile LONG InitializationState;

    //
    // Object Callback Registration
    //

    /// @brief Object callback handle (from ObRegisterCallbacks)
    PVOID ObjectCallbackHandle;

    /// @brief TRUE if callbacks are registered
    BOOLEAN CallbacksRegistered;

    //
    // Process Notify Registration
    //

    /// @brief TRUE if process notify routine is registered
    BOOLEAN ProcessNotifyRegistered;

    //
    // Process Name Cache (IRQL-safe)
    //

    /// @brief Process name cache (preallocated NonPagedPool)
    PSHADOW_PROCESS_NAME_CACHE_ENTRY ProcessNameCache;

    /// @brief Process name cache size
    ULONG ProcessNameCacheSize;

    //
    // Process Tracking
    //

    /// @brief LRU list of tracked process access records
    LIST_ENTRY TrackingList;

    /// @brief Current tracking entry count
    volatile LONG TrackingCount;

    /// @brief Maximum tracking entries
    ULONG MaxTrackingEntries;

    //
    // Alert Queue
    //

    /// @brief Alert queue list
    LIST_ENTRY AlertQueue;

    /// @brief Alert queue count
    volatile LONG AlertCount;

    /// @brief Maximum alerts in queue
    ULONG MaxAlerts;

    //
    // Configuration
    //

    /// @brief Enable process monitoring
    BOOLEAN MonitoringEnabled;

    /// @brief Block high-threat operations
    BOOLEAN BlockingEnabled;

    /// @brief Protect LSASS process
    BOOLEAN ProtectLsass;

    /// @brief Enable rate limiting
    BOOLEAN RateLimitingEnabled;

    /// @brief Threat score threshold for blocking
    ULONG ThreatThreshold;

    /// @brief Rate limit: max accesses per second
    ULONG MaxAccessesPerSecond;

    /// @brief Rate limit window (100ns units)
    LARGE_INTEGER RateLimitWindow;

    //
    // Statistics
    //

    /// @brief Monitoring statistics
    SHADOW_ALPC_STATISTICS Stats;

    //
    // State Tracking
    //

    /// @brief TRUE if initialized
    BOOLEAN Initialized;

    /// @brief TRUE if shutting down
    volatile LONG ShuttingDown;

    /// @brief Initialization timestamp
    LARGE_INTEGER InitTime;

    //
    // User-mode Communication
    //

    /// @brief Filter communication server port
    PFLT_PORT ServerPort;

    /// @brief Client connection port
    PFLT_PORT ClientPort;

    /// @brief TRUE if communication port is open
    BOOLEAN CommunicationPortOpen;

} SHADOW_ALPC_MONITOR_STATE, *PSHADOW_ALPC_MONITOR_STATE;

// ============================================================================
// GLOBAL STATE
// ============================================================================

/**
 * @brief Global process monitor state.
 *
 * Defined in AlpcMonitor.c.
 */
extern SHADOW_ALPC_MONITOR_STATE g_AlpcMonitorState;

// ============================================================================
// PUBLIC FUNCTION PROTOTYPES
// ============================================================================

/**
 * @brief Initialize process monitoring subsystem.
 *
 * Registers object callbacks for process access, process notify routine,
 * and initializes tracking infrastructure.
 *
 * Must be called during driver initialization at PASSIVE_LEVEL.
 *
 * @param FilterHandle  Filter handle for communication port
 *
 * @return STATUS_SUCCESS on success
 *         STATUS_INSUFFICIENT_RESOURCES if allocation fails
 *         STATUS_UNSUCCESSFUL if callback registration fails
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowInitializeAlpcMonitor(
    _In_opt_ PFLT_FILTER FilterHandle
    );

/**
 * @brief Cleanup process monitoring subsystem.
 *
 * Unregisters callbacks, frees all tracked entries, and cleans up
 * resources. BSOD-safe - handles partial initialization.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowCleanupAlpcMonitor(
    VOID
    );

/**
 * @brief Register process object callbacks.
 *
 * Registers ObRegisterCallbacks for PsProcessType to intercept
 * process handle operations.
 *
 * @return STATUS_SUCCESS on success
 *         STATUS_ACCESS_DENIED if callback registration fails
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowRegisterProcessCallbacks(
    VOID
    );

/**
 * @brief Unregister process object callbacks.
 *
 * Safely unregisters callbacks. BSOD-safe.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowUnregisterProcessCallbacks(
    VOID
    );

/**
 * @brief Register process creation notification.
 *
 * Registers PsSetCreateProcessNotifyRoutineEx for process lifetime tracking.
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowRegisterProcessNotify(
    VOID
    );

/**
 * @brief Unregister process creation notification.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowUnregisterProcessNotify(
    VOID
    );

/**
 * @brief Track process access operation (IRQL-safe version).
 *
 * Creates tracking entry for process access with threat scoring.
 * Uses cached process names for IRQL safety.
 *
 * @param SourcePid         Source process ID
 * @param TargetPid         Target process ID
 * @param RequestedAccess   Access rights requested
 * @param Tracking          [out] Receives tracking object (caller must release)
 *
 * @return STATUS_SUCCESS on success
 *
 * @note Caller must call ShadowReleaseProcessTracking when done
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowTrackProcessAccess(
    _In_ HANDLE SourcePid,
    _In_ HANDLE TargetPid,
    _In_ ACCESS_MASK RequestedAccess,
    _Outptr_ PSHADOW_PROCESS_TRACKING* Tracking
    );

/**
 * @brief Find existing process tracking entry.
 *
 * Looks up tracking entry in LRU cache.
 *
 * @param SourcePid     Source process ID
 * @param TargetPid     Target process ID
 * @param Tracking      [out] Receives tracking if found (caller must release)
 *
 * @return STATUS_SUCCESS if found, STATUS_NOT_FOUND otherwise
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowFindProcessTracking(
    _In_ HANDLE SourcePid,
    _In_ HANDLE TargetPid,
    _Outptr_ PSHADOW_PROCESS_TRACKING* Tracking
    );

/**
 * @brief Release process tracking reference.
 *
 * Decrements reference count. When count reaches zero, entry is freed.
 *
 * @param Tracking      Tracking entry to release
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowReleaseProcessTracking(
    _In_opt_ PSHADOW_PROCESS_TRACKING Tracking
    );

/**
 * @brief Calculate threat score for process access.
 *
 * Analyzes process access and calculates threat score based on:
 * - Target process (LSASS, csrss.exe, etc.)
 * - Access rights (VM_READ, CREATE_THREAD, etc.)
 * - Cross-session access
 * - Parent process chain
 * - Rate limiting violations
 * - Behavioral patterns
 *
 * @param Tracking      Process tracking entry with cached data
 * @param ThreatScore   [out] Receives threat score (0-100)
 *
 * @return STATUS_SUCCESS
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowCalculateThreatScoreFromTracking(
    _In_ PSHADOW_PROCESS_TRACKING Tracking,
    _Out_ PULONG ThreatScore
    );

/**
 * @brief Check if process is protected (IRQL-safe).
 *
 * Uses cached process names for IRQL safety.
 *
 * @param ProcessId     Process ID to check
 *
 * @return TRUE if protected, FALSE otherwise
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowIsProtectedProcessCached(
    _In_ HANDLE ProcessId
    );

/**
 * @brief Check if access rights are suspicious.
 *
 * Analyzes access rights for credential theft or injection patterns.
 *
 * @param RequestedAccess   Access rights to check
 * @param IsCredentialAccess [out] TRUE if credential access detected
 * @param IsInjectionAccess  [out] TRUE if injection access detected
 *
 * @return TRUE if suspicious, FALSE otherwise
 *
 * @irql Any
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowIsSuspiciousAccess(
    _In_ ACCESS_MASK RequestedAccess,
    _Out_ PBOOLEAN IsCredentialAccess,
    _Out_ PBOOLEAN IsInjectionAccess
    );

/**
 * @brief Check if rate limit is violated.
 *
 * Checks if process access rate exceeds configured threshold.
 *
 * @param Tracking      Process tracking entry
 *
 * @return TRUE if rate limit exceeded, FALSE otherwise
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowCheckRateLimit(
    _In_ PSHADOW_PROCESS_TRACKING Tracking
    );

/**
 * @brief Get monitoring statistics.
 *
 * Thread-safe retrieval of current statistics.
 *
 * @param Stats     [out] Receives statistics snapshot
 *
 * @irql Any
 */
VOID
ShadowGetAlpcStatistics(
    _Out_ PSHADOW_ALPC_STATISTICS Stats
    );

/**
 * @brief Queue threat alert for user-mode notification.
 *
 * Adds alert to queue for delivery to user-mode service.
 * Uses cached process names for IRQL safety.
 *
 * @param AlertType         Alert type
 * @param Tracking          Process tracking entry
 * @param WasBlocked        Was operation blocked?
 *
 * @return STATUS_SUCCESS or STATUS_INSUFFICIENT_RESOURCES
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowQueueThreatAlertFromTracking(
    _In_ SHADOW_ALERT_TYPE AlertType,
    _In_ PSHADOW_PROCESS_TRACKING Tracking,
    _In_ BOOLEAN WasBlocked
    );

// ============================================================================
// PROCESS NAME CACHE FUNCTIONS (IRQL-SAFE)
// ============================================================================

/**
 * @brief Initialize process name cache.
 *
 * Allocates NonPagedPool cache for IRQL-safe process name lookups.
 *
 * @return STATUS_SUCCESS or STATUS_INSUFFICIENT_RESOURCES
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowInitializeProcessNameCache(
    VOID
    );

/**
 * @brief Cleanup process name cache.
 *
 * Frees the process name cache.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowCleanupProcessNameCache(
    VOID
    );

/**
 * @brief Add process to name cache.
 *
 * Called from process notify routine at PASSIVE_LEVEL when process is created.
 *
 * @param ProcessId         Process ID
 * @param ImageFileName     Process image file name (from CreateInfo)
 * @param ParentProcessId   Parent process ID
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowCacheProcessName(
    _In_ HANDLE ProcessId,
    _In_opt_ PUNICODE_STRING ImageFileName,
    _In_ HANDLE ParentProcessId
    );

/**
 * @brief Remove process from name cache.
 *
 * Called from process notify routine when process exits.
 *
 * @param ProcessId     Process ID to remove
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowRemoveProcessFromCache(
    _In_ HANDLE ProcessId
    );

/**
 * @brief Lookup process in name cache.
 *
 * Fast, IRQL-safe lookup of cached process information.
 *
 * @param ProcessId     Process ID to lookup
 * @param BaseName      [out] Receives base name (optional, SHADOW_MAX_BASE_NAME)
 * @param IsProtected   [out] Receives protected status (optional)
 * @param SessionId     [out] Receives session ID (optional)
 * @param ParentPid     [out] Receives parent PID (optional)
 *
 * @return TRUE if found in cache, FALSE otherwise
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowLookupProcessInCache(
    _In_ HANDLE ProcessId,
    _Out_writes_opt_(SHADOW_MAX_BASE_NAME) PWCHAR BaseName,
    _Out_opt_ PBOOLEAN IsProtected,
    _Out_opt_ PULONG SessionId,
    _Out_opt_ PHANDLE ParentPid
    );

// ============================================================================
// PRIVATE HELPER PROTOTYPES (Internal use only)
// ============================================================================

/**
 * @brief Pre-operation callback for process access.
 *
 * Called before process handle is opened or duplicated.
 * Implements threat detection and access control.
 *
 * @irql <= APC_LEVEL (per ObRegisterCallbacks documentation)
 */
OB_PREOP_CALLBACK_STATUS
ShadowProcessPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    );

/**
 * @brief Post-operation callback for process access.
 *
 * Called after process handle operation completes.
 * Used for telemetry and tracking.
 *
 * @irql <= APC_LEVEL
 */
VOID
ShadowProcessPostOperationCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_POST_OPERATION_INFORMATION OperationInformation
    );

/**
 * @brief Process creation/exit notification callback.
 *
 * Called when process is created or destroyed.
 * Populates process name cache and cleans up tracking entries.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowProcessNotifyRoutine(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    );

/**
 * @brief Evict least recently used tracking entry from cache.
 *
 * Called when tracking cache is full. Lock must be held by caller.
 *
 * @irql <= DISPATCH_LEVEL (caller holds lock)
 */
VOID
ShadowEvictLruTracking(
    VOID
    );

/**
 * @brief Cleanup all tracking entries.
 *
 * Frees all tracked entries. Called during shutdown.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowCleanupTrackingEntries(
    VOID
    );

/**
 * @brief Cleanup alert queue.
 *
 * Frees all pending alerts.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowCleanupAlertQueue(
    VOID
    );

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_ALPC_MONITOR_H
