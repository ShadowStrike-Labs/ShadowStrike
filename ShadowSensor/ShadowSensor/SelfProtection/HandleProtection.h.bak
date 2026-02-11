/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE HANDLE PROTECTION HEADER
 * ============================================================================
 *
 * @file HandleProtection.h
 * @brief Enterprise-grade handle protection and forensics definitions.
 *
 * This module provides advanced handle protection capabilities beyond
 * ObRegisterCallbacks, including:
 * - Handle table enumeration and analysis
 * - Cross-process handle detection and stripping
 * - Suspicious handle pattern detection
 * - Handle duplication monitoring
 * - Protected object handle tracking
 * - Handle leak detection for security analysis
 * - Real-time handle abuse alerting
 *
 * Detection Capabilities (MITRE ATT&CK):
 * - T1055: Process Injection (via handle abuse)
 * - T1134: Access Token Manipulation
 * - T1003: OS Credential Dumping (LSASS handle detection)
 * - T1543: Create or Modify System Process
 * - T1489: Service Stop (via handle to service process)
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// CONSTANTS
// ============================================================================

#define HP_POOL_TAG                             'pHsS'
#define HP_VERSION                              0x0200

/**
 * @brief Maximum handles to track per process.
 */
#define HP_MAX_HANDLES_PER_PROCESS              4096

/**
 * @brief Maximum processes to track.
 */
#define HP_MAX_TRACKED_PROCESSES                1024

/**
 * @brief Maximum sensitive objects to monitor.
 */
#define HP_MAX_SENSITIVE_OBJECTS                256

/**
 * @brief Maximum handle events in history.
 */
#define HP_MAX_HANDLE_HISTORY                   10000

/**
 * @brief Hash table bucket count.
 */
#define HP_HASH_BUCKET_COUNT                    512

/**
 * @brief Handle analysis interval in milliseconds.
 */
#define HP_ANALYSIS_INTERVAL_MS                 5000

/**
 * @brief Stale entry timeout in milliseconds.
 */
#define HP_STALE_ENTRY_TIMEOUT_MS               300000  // 5 minutes

// ============================================================================
// DANGEROUS ACCESS MASKS
// ============================================================================

/**
 * @brief Process access rights that enable termination.
 */
#define HP_DANGEROUS_PROCESS_TERMINATE          \
    (PROCESS_TERMINATE)

/**
 * @brief Process access rights that enable code injection.
 */
#define HP_DANGEROUS_PROCESS_INJECT             \
    (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD)

/**
 * @brief Process access rights that enable memory reading (credential theft).
 */
#define HP_DANGEROUS_PROCESS_READ               \
    (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)

/**
 * @brief Thread access rights that enable manipulation.
 */
#define HP_DANGEROUS_THREAD_ACCESS              \
    (THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | \
     THREAD_GET_CONTEXT | THREAD_SET_INFORMATION)

/**
 * @brief Token access rights that enable privilege escalation.
 */
#define HP_DANGEROUS_TOKEN_ACCESS               \
    (TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_ASSIGN_PRIMARY | \
     TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS)

/**
 * @brief All dangerous process access combined.
 */
#define HP_DANGEROUS_PROCESS_ALL                \
    (HP_DANGEROUS_PROCESS_TERMINATE | HP_DANGEROUS_PROCESS_INJECT | \
     HP_DANGEROUS_PROCESS_READ)

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Handle object types we track.
 */
typedef enum _HP_OBJECT_TYPE {
    HpObjectType_Unknown        = 0,
    HpObjectType_Process        = 1,
    HpObjectType_Thread         = 2,
    HpObjectType_Token          = 3,
    HpObjectType_File           = 4,
    HpObjectType_Key            = 5,
    HpObjectType_Section        = 6,
    HpObjectType_Event          = 7,
    HpObjectType_Mutant         = 8,
    HpObjectType_Semaphore      = 9,
    HpObjectType_Timer          = 10,
    HpObjectType_Port           = 11,
    HpObjectType_Device         = 12,
    HpObjectType_Driver         = 13,
    HpObjectType_Desktop        = 14,
    HpObjectType_WindowStation  = 15,
    HpObjectType_Job            = 16,
    HpObjectType_Max
} HP_OBJECT_TYPE;

/**
 * @brief Handle suspicion indicators.
 */
typedef enum _HP_SUSPICION_FLAGS {
    HpSuspicion_None                    = 0x00000000,

    // Cross-process indicators
    HpSuspicion_CrossProcess            = 0x00000001,
    HpSuspicion_CrossSession            = 0x00000002,
    HpSuspicion_CrossIntegrity          = 0x00000004,

    // Privilege indicators
    HpSuspicion_HighPrivilegeAccess     = 0x00000008,
    HpSuspicion_TerminateAccess         = 0x00000010,
    HpSuspicion_InjectAccess            = 0x00000020,
    HpSuspicion_ReadMemoryAccess        = 0x00000040,

    // Target indicators
    HpSuspicion_TargetProtected         = 0x00000080,
    HpSuspicion_TargetLSASS             = 0x00000100,
    HpSuspicion_TargetCSRSS             = 0x00000200,
    HpSuspicion_TargetSMSS              = 0x00000400,
    HpSuspicion_TargetServices          = 0x00000800,
    HpSuspicion_TargetAntivirus         = 0x00001000,
    HpSuspicion_TargetSystem            = 0x00002000,

    // Operation indicators
    HpSuspicion_DuplicatedHandle        = 0x00004000,
    HpSuspicion_InheritedHandle         = 0x00008000,
    HpSuspicion_KernelHandle            = 0x00010000,

    // Pattern indicators
    HpSuspicion_RapidEnumeration        = 0x00020000,
    HpSuspicion_BulkHandleOpen          = 0x00040000,
    HpSuspicion_HandleSpray             = 0x00080000,

    // Token indicators
    HpSuspicion_TokenDuplicate          = 0x00100000,
    HpSuspicion_TokenImpersonate        = 0x00200000,
    HpSuspicion_PrivilegeEscalation     = 0x00400000,

    // Critical
    HpSuspicion_CredentialAccess        = 0x00800000,
    HpSuspicion_ServiceManipulation     = 0x01000000,

} HP_SUSPICION_FLAGS;

/**
 * @brief Handle event types for history tracking.
 */
typedef enum _HP_EVENT_TYPE {
    HpEvent_HandleCreate        = 0,
    HpEvent_HandleDuplicate     = 1,
    HpEvent_HandleClose         = 2,
    HpEvent_HandleInherit       = 3,
    HpEvent_AccessStripped      = 4,
    HpEvent_AccessBlocked       = 5,
    HpEvent_SuspiciousDetected  = 6,
    HpEvent_AlertRaised         = 7,
} HP_EVENT_TYPE;

/**
 * @brief Sensitivity level for objects.
 */
typedef enum _HP_SENSITIVITY_LEVEL {
    HpSensitivity_None          = 0,
    HpSensitivity_Low           = 1,
    HpSensitivity_Medium        = 2,
    HpSensitivity_High          = 3,
    HpSensitivity_Critical      = 4,
} HP_SENSITIVITY_LEVEL;

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Tracked handle entry.
 */
typedef struct _HP_HANDLE_ENTRY {
    LIST_ENTRY ListEntry;               // List linkage
    LIST_ENTRY HashEntry;               // Hash table linkage

    //
    // Handle identification
    //
    HANDLE Handle;                      // Handle value
    HP_OBJECT_TYPE ObjectType;          // Type of object
    ACCESS_MASK GrantedAccess;          // Granted access rights
    ACCESS_MASK OriginalAccess;         // Original requested access

    //
    // Object information
    //
    PVOID ObjectPointer;                // Kernel object pointer
    HANDLE TargetProcessId;             // For process/thread handles
    HANDLE TargetThreadId;              // For thread handles

    //
    // Source information
    //
    HANDLE OwnerProcessId;              // Process owning this handle
    HANDLE CreatorProcessId;            // Process that created handle
    HANDLE CreatorThreadId;             // Thread that created handle

    //
    // Duplication tracking
    //
    BOOLEAN IsDuplicated;               // Was this handle duplicated
    HANDLE DuplicatedFromProcess;       // Source process for duplication
    HANDLE OriginalHandle;              // Original handle value

    //
    // Analysis
    //
    HP_SUSPICION_FLAGS SuspicionFlags;  // Suspicion indicators
    ULONG SuspicionScore;               // Calculated suspicion score
    HP_SENSITIVITY_LEVEL Sensitivity;   // Target sensitivity level

    //
    // Timing
    //
    LARGE_INTEGER CreateTime;           // When handle was created
    LARGE_INTEGER LastAccessTime;       // Last access time

    //
    // Reference counting
    //
    volatile LONG RefCount;

} HP_HANDLE_ENTRY, *PHP_HANDLE_ENTRY;

/**
 * @brief Per-process handle tracking context.
 */
typedef struct _HP_PROCESS_CONTEXT {
    LIST_ENTRY ListEntry;               // Global list linkage
    LIST_ENTRY HashEntry;               // Hash table linkage

    //
    // Process identification
    //
    HANDLE ProcessId;                   // Process ID
    PEPROCESS Process;                  // EPROCESS pointer (referenced)
    ULONG SessionId;                    // Session ID
    ULONG IntegrityLevel;               // Process integrity level
    BOOLEAN IsProtected;                // Is this a protected process
    BOOLEAN IsSystem;                   // Is this a system process
    BOOLEAN IsSensitive;                // Is this a sensitive process (LSASS, etc.)
    UINT8 Reserved1;

    //
    // Handle tracking
    //
    LIST_ENTRY HandleList;              // List of tracked handles
    KSPIN_LOCK HandleListLock;          // Lock for handle list
    volatile LONG HandleCount;          // Number of tracked handles
    volatile LONG CrossProcessHandles;  // Handles to other processes

    //
    // Statistics
    //
    volatile LONG64 TotalHandlesOpened; // Total handles opened
    volatile LONG64 HandlesStripped;    // Handles with access stripped
    volatile LONG64 SuspiciousHandles;  // Suspicious handle count

    //
    // Suspicion aggregation
    //
    HP_SUSPICION_FLAGS AggregatedFlags; // Combined suspicion flags
    ULONG HighestSuspicionScore;        // Highest individual score
    ULONG TotalSuspicionScore;          // Aggregated score

    //
    // Activity tracking
    //
    LARGE_INTEGER FirstActivity;        // First handle activity
    LARGE_INTEGER LastActivity;         // Last handle activity
    volatile LONG RecentHandleCount;    // Handles in recent window
    LARGE_INTEGER WindowStart;          // Activity window start

    //
    // Reference counting
    //
    volatile LONG RefCount;

} HP_PROCESS_CONTEXT, *PHP_PROCESS_CONTEXT;

/**
 * @brief Sensitive object registration.
 */
typedef struct _HP_SENSITIVE_OBJECT {
    LIST_ENTRY ListEntry;

    HANDLE ProcessId;                   // For process objects
    PWSTR ProcessName;                  // Process name pattern
    HP_OBJECT_TYPE ObjectType;          // Type of object
    HP_SENSITIVITY_LEVEL Sensitivity;   // Sensitivity level
    HP_SUSPICION_FLAGS RequiredFlags;   // Flags to apply when accessed
    ULONG BaseScore;                    // Base suspicion score
    BOOLEAN InUse;
    UINT8 Reserved[3];

} HP_SENSITIVE_OBJECT, *PHP_SENSITIVE_OBJECT;

/**
 * @brief Handle event for history tracking.
 */
typedef struct _HP_HANDLE_EVENT {
    LIST_ENTRY ListEntry;

    HP_EVENT_TYPE EventType;            // Type of event
    LARGE_INTEGER Timestamp;            // Event time

    HANDLE OwnerProcessId;              // Process owning handle
    HANDLE TargetProcessId;             // Target process (if applicable)
    HANDLE Handle;                      // Handle value
    HP_OBJECT_TYPE ObjectType;          // Object type
    ACCESS_MASK AccessMask;             // Access mask
    HP_SUSPICION_FLAGS Flags;           // Suspicion flags
    ULONG Score;                        // Suspicion score

} HP_HANDLE_EVENT, *PHP_HANDLE_EVENT;

/**
 * @brief Handle protection statistics.
 */
typedef struct _HP_STATISTICS {
    volatile LONG64 TotalHandlesTracked;        // Total handles tracked
    volatile LONG64 CrossProcessHandles;        // Cross-process handles detected
    volatile LONG64 SuspiciousHandles;          // Suspicious handles detected
    volatile LONG64 AccessStripped;             // Access rights stripped
    volatile LONG64 HandlesDenied;              // Handles completely denied
    volatile LONG64 DuplicationsTracked;        // Handle duplications tracked
    volatile LONG64 LSASSAccessBlocked;         // LSASS access attempts blocked
    volatile LONG64 ProtectedAccessBlocked;     // Protected process access blocked
    volatile LONG64 TokenManipulations;         // Token manipulation attempts
    volatile LONG64 AlertsRaised;               // Alerts raised
    volatile LONG TrackedProcesses;             // Currently tracked processes
    volatile LONG ActiveHandles;                // Currently active handles
    LARGE_INTEGER StartTime;                    // Subsystem start time
} HP_STATISTICS, *PHP_STATISTICS;

/**
 * @brief Handle protection configuration.
 */
typedef struct _HP_CONFIG {
    BOOLEAN Enabled;                    // Handle protection enabled
    BOOLEAN TrackAllHandles;            // Track all handles (expensive)
    BOOLEAN TrackCrossProcess;          // Track cross-process handles
    BOOLEAN BlockLSASSAccess;           // Block direct LSASS access
    BOOLEAN StripDangerousAccess;       // Strip dangerous access rights
    BOOLEAN AlertOnSuspicious;          // Raise alerts for suspicious handles
    UINT8 Reserved[2];

    ULONG SuspicionThreshold;           // Threshold for alerts
    ULONG MaxHandlesPerProcess;         // Max handles to track per process
    ULONG AnalysisIntervalMs;           // Analysis interval
    ULONG HistoryRetentionMs;           // Event history retention

} HP_CONFIG, *PHP_CONFIG;

/**
 * @brief Main handle protection engine state.
 */
typedef struct _HP_PROTECTION_ENGINE {
    BOOLEAN Initialized;
    UINT8 Reserved1[7];

    //
    // Configuration
    //
    HP_CONFIG Config;
    EX_PUSH_LOCK ConfigLock;

    //
    // Process tracking
    //
    LIST_ENTRY ProcessList;
    EX_PUSH_LOCK ProcessListLock;
    struct {
        LIST_ENTRY* Buckets;
        ULONG BucketCount;
        EX_PUSH_LOCK Lock;
    } ProcessHash;

    //
    // Sensitive objects
    //
    HP_SENSITIVE_OBJECT SensitiveObjects[HP_MAX_SENSITIVE_OBJECTS];
    EX_PUSH_LOCK SensitiveObjectLock;
    LONG SensitiveObjectCount;

    //
    // Event history
    //
    LIST_ENTRY EventHistory;
    KSPIN_LOCK EventHistoryLock;
    volatile LONG EventCount;

    //
    // Lookaside lists
    //
    NPAGED_LOOKASIDE_LIST HandleEntryLookaside;
    NPAGED_LOOKASIDE_LIST ProcessContextLookaside;
    NPAGED_LOOKASIDE_LIST EventLookaside;
    BOOLEAN LookasideInitialized;
    UINT8 Reserved2[7];

    //
    // Timer for periodic analysis
    //
    KTIMER AnalysisTimer;
    KDPC AnalysisDpc;
    volatile LONG AnalysisInProgress;

    //
    // Statistics
    //
    HP_STATISTICS Stats;

    //
    // Known sensitive process IDs (cached)
    //
    HANDLE LsassProcessId;
    HANDLE CsrssProcessId;
    HANDLE SmssProcessId;
    HANDLE ServicesProcessId;
    HANDLE WinlogonProcessId;

    //
    // Callbacks
    //
    PVOID DetectionCallback;
    PVOID DetectionCallbackContext;

} HP_PROTECTION_ENGINE, *PHP_PROTECTION_ENGINE;

/**
 * @brief Handle detection result.
 */
typedef struct _HP_DETECTION_RESULT {
    BOOLEAN SuspiciousDetected;
    BOOLEAN AccessModified;
    BOOLEAN AccessBlocked;
    UINT8 Reserved;

    HP_SUSPICION_FLAGS Flags;
    ULONG SuspicionScore;
    HP_SENSITIVITY_LEVEL TargetSensitivity;

    HANDLE OwnerProcessId;
    HANDLE TargetProcessId;
    HP_OBJECT_TYPE ObjectType;
    ACCESS_MASK OriginalAccess;
    ACCESS_MASK ModifiedAccess;

    LARGE_INTEGER DetectionTime;

} HP_DETECTION_RESULT, *PHP_DETECTION_RESULT;

/**
 * @brief Detection callback type.
 */
typedef VOID (*HP_DETECTION_CALLBACK)(
    _In_ PHP_DETECTION_RESULT Result,
    _In_opt_ PVOID Context
    );

// ============================================================================
// FUNCTION PROTOTYPES - INITIALIZATION
// ============================================================================

/**
 * @brief Initialize handle protection engine.
 * @param Engine Pointer to receive engine pointer.
 * @return STATUS_SUCCESS or error code.
 */
NTSTATUS
HpInitialize(
    _Out_ PHP_PROTECTION_ENGINE* Engine
    );

/**
 * @brief Shutdown handle protection engine.
 * @param Engine Engine to shutdown.
 */
VOID
HpShutdown(
    _Inout_ PHP_PROTECTION_ENGINE Engine
    );

// ============================================================================
// FUNCTION PROTOTYPES - CONFIGURATION
// ============================================================================

/**
 * @brief Update engine configuration.
 * @param Engine Engine instance.
 * @param Config New configuration.
 * @return STATUS_SUCCESS or error code.
 */
NTSTATUS
HpSetConfiguration(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ PHP_CONFIG Config
    );

/**
 * @brief Get current configuration.
 * @param Engine Engine instance.
 * @param Config Buffer to receive configuration.
 * @return STATUS_SUCCESS or error code.
 */
NTSTATUS
HpGetConfiguration(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _Out_ PHP_CONFIG Config
    );

// ============================================================================
// FUNCTION PROTOTYPES - HANDLE OPERATIONS
// ============================================================================

/**
 * @brief Analyze a handle operation before it completes.
 *
 * Called from ObRegisterCallbacks pre-operation to analyze and potentially
 * modify the requested access rights.
 *
 * @param Engine Engine instance.
 * @param OperationInfo Operation information from object manager.
 * @param Result Buffer to receive detection result.
 * @return STATUS_SUCCESS or error code.
 */
NTSTATUS
HpAnalyzeHandleOperation(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ POB_PRE_OPERATION_INFORMATION OperationInfo,
    _Out_ PHP_DETECTION_RESULT Result
    );

/**
 * @brief Record a successful handle creation.
 * @param Engine Engine instance.
 * @param OwnerProcessId Process that owns the handle.
 * @param Handle Handle value.
 * @param ObjectType Type of object.
 * @param Object Kernel object pointer.
 * @param GrantedAccess Granted access rights.
 * @return STATUS_SUCCESS or error code.
 */
NTSTATUS
HpRecordHandle(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HANDLE OwnerProcessId,
    _In_ HANDLE Handle,
    _In_ HP_OBJECT_TYPE ObjectType,
    _In_ PVOID Object,
    _In_ ACCESS_MASK GrantedAccess
    );

/**
 * @brief Record a handle duplication.
 * @param Engine Engine instance.
 * @param SourceProcess Source process.
 * @param TargetProcess Target process.
 * @param SourceHandle Original handle.
 * @param TargetHandle New handle.
 * @param GrantedAccess Granted access rights.
 * @return STATUS_SUCCESS or error code.
 */
NTSTATUS
HpRecordDuplication(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HANDLE SourceProcess,
    _In_ HANDLE TargetProcess,
    _In_ HANDLE SourceHandle,
    _In_ HANDLE TargetHandle,
    _In_ ACCESS_MASK GrantedAccess
    );

/**
 * @brief Record a handle close.
 * @param Engine Engine instance.
 * @param ProcessId Process closing the handle.
 * @param Handle Handle being closed.
 */
VOID
HpRecordHandleClose(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _In_ HANDLE Handle
    );

// ============================================================================
// FUNCTION PROTOTYPES - SENSITIVE OBJECTS
// ============================================================================

/**
 * @brief Register a sensitive process for enhanced protection.
 * @param Engine Engine instance.
 * @param ProcessId Process ID to protect.
 * @param Sensitivity Sensitivity level.
 * @return STATUS_SUCCESS or error code.
 */
NTSTATUS
HpRegisterSensitiveProcess(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _In_ HP_SENSITIVITY_LEVEL Sensitivity
    );

/**
 * @brief Unregister a sensitive process.
 * @param Engine Engine instance.
 * @param ProcessId Process ID to unregister.
 */
VOID
HpUnregisterSensitiveProcess(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HANDLE ProcessId
    );

/**
 * @brief Check if a process is sensitive.
 * @param Engine Engine instance.
 * @param ProcessId Process ID to check.
 * @param OutSensitivity Optional pointer to receive sensitivity level.
 * @return TRUE if sensitive.
 */
BOOLEAN
HpIsSensitiveProcess(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _Out_opt_ PHP_SENSITIVITY_LEVEL OutSensitivity
    );

// ============================================================================
// FUNCTION PROTOTYPES - ANALYSIS
// ============================================================================

/**
 * @brief Analyze all handles held by a process.
 * @param Engine Engine instance.
 * @param ProcessId Process to analyze.
 * @param OutFlags Combined suspicion flags.
 * @param OutScore Total suspicion score.
 * @return STATUS_SUCCESS or error code.
 */
NTSTATUS
HpAnalyzeProcessHandles(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _Out_ PHP_SUSPICION_FLAGS OutFlags,
    _Out_ PULONG OutScore
    );

/**
 * @brief Find all cross-process handles targeting a specific process.
 * @param Engine Engine instance.
 * @param TargetProcessId Target process.
 * @param Handles Buffer to receive handle entries.
 * @param MaxHandles Maximum handles to return.
 * @param ReturnedCount Actual count returned.
 * @return STATUS_SUCCESS or error code.
 */
NTSTATUS
HpFindHandlesToProcess(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HANDLE TargetProcessId,
    _Out_writes_to_(MaxHandles, *ReturnedCount) PHP_HANDLE_ENTRY* Handles,
    _In_ ULONG MaxHandles,
    _Out_ PULONG ReturnedCount
    );

/**
 * @brief Enumerate handles from the system handle table.
 * @param Engine Engine instance.
 * @param ProcessId Process to enumerate (NULL for all).
 * @return STATUS_SUCCESS or error code.
 */
NTSTATUS
HpEnumerateSystemHandles(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_opt_ HANDLE ProcessId
    );

// ============================================================================
// FUNCTION PROTOTYPES - CALLBACKS
// ============================================================================

/**
 * @brief Register a detection callback.
 * @param Engine Engine instance.
 * @param Callback Callback function.
 * @param Context Callback context.
 * @return STATUS_SUCCESS or error code.
 */
NTSTATUS
HpRegisterCallback(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HP_DETECTION_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

/**
 * @brief Unregister detection callback.
 * @param Engine Engine instance.
 */
VOID
HpUnregisterCallback(
    _In_ PHP_PROTECTION_ENGINE Engine
    );

// ============================================================================
// FUNCTION PROTOTYPES - STATISTICS
// ============================================================================

/**
 * @brief Get engine statistics.
 * @param Engine Engine instance.
 * @param Stats Buffer to receive statistics.
 * @return STATUS_SUCCESS or error code.
 */
NTSTATUS
HpGetStatistics(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _Out_ PHP_STATISTICS Stats
    );

/**
 * @brief Get recent handle events.
 * @param Engine Engine instance.
 * @param Events Buffer to receive events.
 * @param MaxEvents Maximum events to return.
 * @param ReturnedCount Actual count returned.
 * @return STATUS_SUCCESS or error code.
 */
NTSTATUS
HpGetRecentEvents(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _Out_writes_to_(MaxEvents, *ReturnedCount) PHP_HANDLE_EVENT* Events,
    _In_ ULONG MaxEvents,
    _Out_ PULONG ReturnedCount
    );

// ============================================================================
// FUNCTION PROTOTYPES - CLEANUP
// ============================================================================

/**
 * @brief Clean up tracking for a terminated process.
 * @param Engine Engine instance.
 * @param ProcessId Process that terminated.
 */
VOID
HpProcessTerminated(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HANDLE ProcessId
    );

/**
 * @brief Flush all tracking data.
 * @param Engine Engine instance.
 */
VOID
HpFlushAllTracking(
    _In_ PHP_PROTECTION_ENGINE Engine
    );

#ifdef __cplusplus
}
#endif
