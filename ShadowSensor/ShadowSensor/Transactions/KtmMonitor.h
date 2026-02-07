/**
 * ============================================================================
 * ShadowStrike NGAV - KTM TRANSACTION MONITOR
 * ============================================================================
 *
 * @file KtmMonitor.h
 * @brief Enterprise-grade Kernel Transaction Manager monitoring for ransomware detection.
 *
 * Provides CrowdStrike Falcon-level protection against:
 * - Ransomware using atomic file encryption (LockBit, BlackCat, REvil)
 * - Transacted registry manipulation (persistence attacks)
 * - Volume shadow copy deletion via transactions
 * - Database tampering (SQL injection via transacted operations)
 * - Suspicious transaction rollback patterns
 * - High-velocity transaction abuse
 *
 * Architecture (PRODUCTION-GRADE):
 * ================================
 * 1. ObRegisterCallbacks for TmTransactionManager and Transaction objects
 *    → Monitor transaction handle creation and duplication
 *    → Track transaction commit/rollback patterns
 *
 * 2. Minifilter Pre/Post Operation Callbacks
 *    → Monitor IRP_MJ_CREATE with FILE_OPEN_FOR_BACKUP_INTENT + Transacted
 *    → Track transacted file write operations
 *    → Detect mass encryption patterns
 *
 * 3. Transaction Tracking with Behavioral Analytics
 *    → Track transaction lifetime and operation counts
 *    → Detect high-velocity file modifications (ransomware signature)
 *    → Monitor entropy changes in transacted writes
 *    → Rate limiting per process
 *
 * 4. User-mode Communication
 *    → Real-time ransomware alerts
 *    → Telemetry streaming
 *    → Policy-based blocking
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1486: Data Encrypted for Impact (PRIMARY)
 * - T1490: Inhibit System Recovery (VSS deletion)
 * - T1070.001: Indicator Removal - Clear Windows Event Logs (via transactions)
 * - T1547.001: Boot or Logon Autostart Execution - Registry Run Keys (transacted)
 * - T1059: Command and Scripting Interpreter (transacted script execution)
 *
 * Ransomware Families Detected:
 * =============================
 * - LockBit 2.0/3.0 (uses TxF for atomic encryption)
 * - BlackCat/ALPHV (transacted file operations)
 * - REvil/Sodinokibi (TxF-based encryption)
 * - Conti (transacted registry persistence)
 * - DarkSide (atomic file manipulation)
 * - Hive (transacted VSS deletion)
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition - Falcon-Grade)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_KTM_MONITOR_H
#define SHADOWSTRIKE_KTM_MONITOR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include <ntifs.h>
#include <wdm.h>
#include <ntstrsafe.h>
#include <fltKernel.h>

// ============================================================================
// POOL TAGS
// ============================================================================

/**
 * @brief Pool tag for KTM monitor allocations: 'kSSx' = ShadowStrike KTM
 */
#define SHADOW_KTM_TAG 'kSSx'

/**
 * @brief Pool tag for transaction tracking entries
 */
#define SHADOW_KTM_TRANSACTION_TAG 'tSSk'

/**
 * @brief Pool tag for KTM string buffers
 */
#define SHADOW_KTM_STRING_TAG 'sSSk'

/**
 * @brief Pool tag for KTM alert queue
 */
#define SHADOW_KTM_ALERT_TAG 'aSSk'

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * @brief Maximum tracked transactions (LRU cache)
 */
#define SHADOW_MAX_TRANSACTIONS 1024

/**
 * @brief Maximum process image name length
 */
#define SHADOW_MAX_PROCESS_NAME 256

/**
 * @brief Maximum file path length for tracking
 */
#define SHADOW_MAX_FILE_PATH 512

/**
 * @brief Ransomware detection threshold (files per second)
 */
#define SHADOW_RANSOMWARE_THRESHOLD_FILES_PER_SEC 50

/**
 * @brief Ransomware detection window (milliseconds)
 */
#define SHADOW_RANSOMWARE_DETECTION_WINDOW_MS 1000

/**
 * @brief Threat score threshold for blocking
 */
#define SHADOW_KTM_THREAT_THRESHOLD 80

/**
 * @brief Alert queue maximum size
 */
#define SHADOW_MAX_KTM_ALERT_QUEUE 512

/**
 * @brief Initialization states
 */
#define KTM_STATE_UNINITIALIZED 0
#define KTM_STATE_INITIALIZING  1
#define KTM_STATE_INITIALIZED   2

// ============================================================================
// SUSPICIOUS TRANSACTION PATTERNS
// ============================================================================

/**
 * @brief Transaction access rights indicating suspicious activity
 */
#define SUSPICIOUS_TRANSACTION_ACCESS (  \
    TRANSACTION_COMMIT |                 \
    TRANSACTION_ROLLBACK |               \
    TRANSACTION_ENLIST                   \
)

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Transaction operation types.
 */
typedef enum _SHADOW_KTM_OPERATION {
    KtmOperationCreate = 1,       ///< Transaction creation
    KtmOperationCommit = 2,       ///< Transaction commit
    KtmOperationRollback = 3,     ///< Transaction rollback
    KtmOperationEnlist = 4,       ///< Resource enlistment
    KtmOperationFileWrite = 5,    ///< Transacted file write
    KtmOperationRegistrySet = 6   ///< Transacted registry set
} SHADOW_KTM_OPERATION;

/**
 * @brief Threat levels for transaction operations.
 */
typedef enum _SHADOW_KTM_THREAT_LEVEL {
    KtmThreatNone = 0,            ///< Benign transaction
    KtmThreatLow = 25,            ///< Suspicious but likely safe
    KtmThreatMedium = 50,         ///< Potentially malicious
    KtmThreatHigh = 75,           ///< Likely ransomware
    KtmThreatCritical = 100       ///< Confirmed ransomware (block)
} SHADOW_KTM_THREAT_LEVEL;

/**
 * @brief Alert types for KTM monitoring.
 */
typedef enum _SHADOW_KTM_ALERT_TYPE {
    KtmAlertRansomware = 1,       ///< Mass file encryption detected
    KtmAlertVSSDelete = 2,        ///< Volume shadow copy deletion
    KtmAlertMassCommit = 3,       ///< High-velocity commits (ransomware)
    KtmAlertSuspiciousRollback = 4, ///< Unusual rollback pattern
    KtmAlertRegistryPersistence = 5, ///< Transacted registry persistence
    KtmAlertRateLimitViolation = 6  ///< Rate limit exceeded
} SHADOW_KTM_ALERT_TYPE;

// ============================================================================
// STATISTICS STRUCTURE
// ============================================================================

/**
 * @brief KTM monitoring statistics.
 *
 * All counters are atomic (updated via InterlockedIncrement/Add).
 */
typedef struct _SHADOW_KTM_STATISTICS {

    /// @brief Total transaction creations observed
    volatile LONG64 TotalTransactions;

    /// @brief Total transaction commits
    volatile LONG64 TotalCommits;

    /// @brief Total transaction rollbacks
    volatile LONG64 TotalRollbacks;

    /// @brief Transacted file operations
    volatile LONG64 TransactedFileOperations;

    /// @brief Transacted registry operations
    volatile LONG64 TransactedRegistryOperations;

    /// @brief Suspicious transaction patterns detected
    volatile LONG64 SuspiciousTransactions;

    /// @brief Ransomware activity detected
    volatile LONG64 RansomwareDetections;

    /// @brief Volume shadow copy deletion attempts
    volatile LONG64 VSSDeleteAttempts;

    /// @brief Mass commit operations (high velocity)
    volatile LONG64 MassCommitOperations;

    /// @brief Blocked transactions (high threat score)
    volatile LONG64 BlockedTransactions;

    /// @brief Total threat alerts generated
    volatile LONG64 ThreatAlerts;

    /// @brief Rate limit violations
    volatile LONG64 RateLimitViolations;

    /// @brief Cache hits (transaction lookup)
    volatile LONG64 CacheHits;

    /// @brief Cache misses (transaction lookup)
    volatile LONG64 CacheMisses;

    /// @brief Files encrypted (estimated)
    volatile LONG64 FilesEncrypted;

} SHADOW_KTM_STATISTICS, *PSHADOW_KTM_STATISTICS;

// ============================================================================
// TRANSACTION TRACKING ENTRY
// ============================================================================

/**
 * @brief Transaction tracking entry.
 *
 * Tracks individual transactions for behavioral ransomware detection.
 */
typedef struct _SHADOW_KTM_TRANSACTION {

    /// @brief List entry for LRU cache
    LIST_ENTRY ListEntry;

    /// @brief Transaction GUID
    GUID TransactionGuid;

    /// @brief Process ID that created transaction
    HANDLE ProcessId;

    /// @brief Process name
    WCHAR ProcessName[SHADOW_MAX_PROCESS_NAME];

    /// @brief Transaction creation time
    LARGE_INTEGER CreateTime;

    /// @brief Last activity time
    LARGE_INTEGER LastActivityTime;

    /// @brief Commit time (if committed)
    LARGE_INTEGER CommitTime;

    /// @brief Number of transacted file operations
    volatile LONG FileOperationCount;

    /// @brief Number of transacted registry operations
    volatile LONG RegistryOperationCount;

    /// @brief Cumulative threat score (0-100)
    volatile LONG ThreatScore;

    /// @brief Is this transaction committed?
    BOOLEAN IsCommitted;

    /// @brief Is this transaction rolled back?
    BOOLEAN IsRolledBack;

    /// @brief Is this transaction blocked?
    BOOLEAN IsBlocked;

    /// @brief Has ransomware pattern been detected?
    BOOLEAN HasRansomwarePattern;

    /// @brief Files modified in this transaction
    volatile LONG FilesModified;

    /// @brief Time window for rate calculation (100ns units)
    LARGE_INTEGER RateWindowStart;

    /// @brief Reference count for safe cleanup
    volatile LONG ReferenceCount;

    /// @brief Padding for alignment
    UCHAR Reserved[3];

} SHADOW_KTM_TRANSACTION, *PSHADOW_KTM_TRANSACTION;

// ============================================================================
// ALERT STRUCTURE
// ============================================================================

/**
 * @brief KTM threat alert for user-mode notification.
 */
typedef struct _SHADOW_KTM_ALERT {

    /// @brief List entry for alert queue
    LIST_ENTRY ListEntry;

    /// @brief Alert type
    SHADOW_KTM_ALERT_TYPE AlertType;

    /// @brief Threat score (0-100)
    ULONG ThreatScore;

    /// @brief Process ID
    HANDLE ProcessId;

    /// @brief Process name
    WCHAR ProcessName[SHADOW_MAX_PROCESS_NAME];

    /// @brief Transaction GUID
    GUID TransactionGuid;

    /// @brief Alert timestamp
    LARGE_INTEGER AlertTime;

    /// @brief Number of files affected
    ULONG FilesAffected;

    /// @brief Was this transaction blocked?
    BOOLEAN WasBlocked;

} SHADOW_KTM_ALERT, *PSHADOW_KTM_ALERT;

// ============================================================================
// GLOBAL STATE STRUCTURE
// ============================================================================

/**
 * @brief KTM monitor global state.
 */
typedef struct _SHADOW_KTM_MONITOR_STATE {

    //
    // Synchronization
    //

    /// @brief Lock protecting this structure
    EX_PUSH_LOCK Lock;

    /// @brief TRUE if lock was initialized
    BOOLEAN LockInitialized;

    /// @brief Atomic initialization state (0/1/2)
    volatile LONG InitializationState;

    //
    // Object Callback Registration
    //

    /// @brief Transaction object callback handle
    PVOID TransactionCallbackHandle;

    /// @brief TRUE if callbacks are registered
    BOOLEAN CallbacksRegistered;

    //
    // Transaction Tracking
    //

    /// @brief LRU list of tracked transactions
    LIST_ENTRY TransactionList;

    /// @brief Current transaction count
    volatile LONG TransactionCount;

    /// @brief Maximum transactions tracked
    ULONG MaxTransactions;

    //
    // Alert Queue
    //

    /// @brief Lock for alert queue
    KSPIN_LOCK AlertLock;

    /// @brief Alert queue list
    LIST_ENTRY AlertQueue;

    /// @brief Alert queue count
    volatile LONG AlertCount;

    /// @brief Maximum alerts in queue
    ULONG MaxAlerts;

    //
    // Configuration
    //

    /// @brief Enable KTM monitoring
    BOOLEAN MonitoringEnabled;

    /// @brief Block high-threat transactions
    BOOLEAN BlockingEnabled;

    /// @brief Enable ransomware detection
    BOOLEAN RansomwareDetectionEnabled;

    /// @brief Enable rate limiting
    BOOLEAN RateLimitingEnabled;

    /// @brief Threat score threshold for blocking
    ULONG ThreatThreshold;

    /// @brief Ransomware detection threshold (files/sec)
    ULONG RansomwareThreshold;

    /// @brief Rate limit window (100ns units)
    LARGE_INTEGER RateLimitWindow;

    //
    // Statistics
    //

    /// @brief KTM monitoring statistics
    SHADOW_KTM_STATISTICS Stats;

    //
    // State Tracking
    //

    /// @brief TRUE if initialized
    BOOLEAN Initialized;

    /// @brief TRUE if shutting down
    BOOLEAN ShuttingDown;

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

} SHADOW_KTM_MONITOR_STATE, *PSHADOW_KTM_MONITOR_STATE;

// ============================================================================
// GLOBAL STATE
// ============================================================================

/**
 * @brief Global KTM monitor state.
 *
 * Defined in KtmMonitor.c.
 */
extern SHADOW_KTM_MONITOR_STATE g_KtmMonitorState;

// ============================================================================
// PUBLIC FUNCTION PROTOTYPES
// ============================================================================

/**
 * @brief Initialize KTM monitoring subsystem.
 *
 * Registers object callbacks for transaction objects and initializes
 * tracking infrastructure.
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
NTSTATUS
ShadowInitializeKtmMonitor(
    _In_ PFLT_FILTER FilterHandle
    );

/**
 * @brief Cleanup KTM monitoring subsystem.
 *
 * Unregisters callbacks, frees all tracked transactions, and cleans up
 * resources. BSOD-safe - handles partial initialization.
 *
 * @irql PASSIVE_LEVEL
 */
VOID
ShadowCleanupKtmMonitor(
    VOID
    );

/**
 * @brief Register transaction object callbacks.
 *
 * Registers ObRegisterCallbacks for transaction objects to intercept
 * transaction handle operations.
 *
 * @return STATUS_SUCCESS on success
 *         STATUS_ACCESS_DENIED if callback registration fails
 *         STATUS_NOT_SUPPORTED if TmTx/TmTm types not available
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowRegisterTransactionCallbacks(
    VOID
    );

/**
 * @brief Unregister transaction object callbacks.
 *
 * Safely unregisters callbacks. BSOD-safe.
 *
 * @irql PASSIVE_LEVEL
 */
VOID
ShadowUnregisterTransactionCallbacks(
    VOID
    );

/**
 * @brief Track new transaction.
 *
 * Creates tracking entry for transaction with ransomware detection.
 *
 * @param TransactionGuid   Transaction GUID
 * @param ProcessId         Process ID
 * @param Transaction       [out] Receives transaction object (caller must release)
 *
 * @return STATUS_SUCCESS on success
 *
 * @note Caller must call ShadowReleaseKtmTransaction when done
 */
NTSTATUS
ShadowTrackTransaction(
    _In_ GUID TransactionGuid,
    _In_ HANDLE ProcessId,
    _Outptr_ PSHADOW_KTM_TRANSACTION* Transaction
    );

/**
 * @brief Find existing transaction.
 *
 * Looks up transaction in LRU cache by GUID.
 *
 * @param TransactionGuid   Transaction GUID
 * @param Transaction       [out] Receives transaction if found (caller must release)
 *
 * @return STATUS_SUCCESS if found, STATUS_NOT_FOUND otherwise
 */
NTSTATUS
ShadowFindKtmTransaction(
    _In_ GUID TransactionGuid,
    _Outptr_ PSHADOW_KTM_TRANSACTION* Transaction
    );

/**
 * @brief Release transaction reference.
 *
 * Decrements reference count. When count reaches zero, transaction is freed.
 *
 * @param Transaction   Transaction to release
 */
VOID
ShadowReleaseKtmTransaction(
    _In_ PSHADOW_KTM_TRANSACTION Transaction
    );

/**
 * @brief Calculate threat score for transaction.
 *
 * Analyzes transaction and calculates threat score based on:
 * - File operation velocity (ransomware signature)
 * - Transaction commit patterns
 * - Process reputation
 * - File extension targeting
 * - Rate limiting violations
 *
 * @param Transaction       Transaction to analyze
 * @param Operation         Operation type
 * @param ThreatScore       [out] Receives threat score (0-100)
 *
 * @return STATUS_SUCCESS
 */
NTSTATUS
ShadowCalculateKtmThreatScore(
    _In_ PSHADOW_KTM_TRANSACTION Transaction,
    _In_ SHADOW_KTM_OPERATION Operation,
    _Out_ PULONG ThreatScore
    );

/**
 * @brief Check if file extension is ransomware target.
 *
 * Checks if file extension matches common ransomware targets.
 *
 * @param FilePath      File path to check
 *
 * @return TRUE if targeted extension, FALSE otherwise
 */
BOOLEAN
ShadowIsRansomwareTargetFile(
    _In_ PUNICODE_STRING FilePath
    );

/**
 * @brief Check for ransomware pattern (high-velocity file operations).
 *
 * Detects mass file encryption patterns.
 *
 * @param Transaction   Transaction to check
 *
 * @return TRUE if ransomware pattern detected, FALSE otherwise
 */
BOOLEAN
ShadowDetectRansomwarePattern(
    _In_ PSHADOW_KTM_TRANSACTION Transaction
    );

/**
 * @brief Record transacted file operation.
 *
 * Updates transaction tracking with new file operation.
 *
 * @param Transaction   Transaction object
 * @param FilePath      File path
 *
 * @return STATUS_SUCCESS
 */
NTSTATUS
ShadowRecordTransactedFileOperation(
    _In_ PSHADOW_KTM_TRANSACTION Transaction,
    _In_ PUNICODE_STRING FilePath
    );

/**
 * @brief Mark transaction as committed.
 *
 * Records transaction commit and checks for ransomware.
 *
 * @param Transaction   Transaction to mark
 *
 * @return STATUS_SUCCESS
 */
NTSTATUS
ShadowMarkTransactionCommitted(
    _In_ PSHADOW_KTM_TRANSACTION Transaction
    );

/**
 * @brief Get KTM monitoring statistics.
 *
 * Thread-safe retrieval of current statistics.
 *
 * @param Stats     [out] Receives statistics snapshot
 */
VOID
ShadowGetKtmStatistics(
    _Out_ PSHADOW_KTM_STATISTICS Stats
    );

/**
 * @brief Queue KTM threat alert for user-mode notification.
 *
 * Adds alert to queue for delivery to user-mode service.
 *
 * @param AlertType         Alert type
 * @param ProcessId         Process ID
 * @param TransactionGuid   Transaction GUID
 * @param FilesAffected     Number of files affected
 * @param ThreatScore       Threat score
 * @param WasBlocked        Was transaction blocked?
 *
 * @return STATUS_SUCCESS or STATUS_INSUFFICIENT_RESOURCES
 */
NTSTATUS
ShadowQueueKtmAlert(
    _In_ SHADOW_KTM_ALERT_TYPE AlertType,
    _In_ HANDLE ProcessId,
    _In_ GUID TransactionGuid,
    _In_ ULONG FilesAffected,
    _In_ ULONG ThreatScore,
    _In_ BOOLEAN WasBlocked
    );

/**
 * @brief Minifilter transaction notification callback.
 *
 * Called by Filter Manager when transaction operations occur.
 * Legacy callback for compatibility.
 *
 * @param FltObjects        Filter objects
 * @param TransactionContext Transaction context
 * @param NotificationMask  Notification type
 *
 * @return STATUS_SUCCESS
 */
NTSTATUS
ShadowKtmNotificationCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_CONTEXT TransactionContext,
    _In_ ULONG NotificationMask
    );

// ============================================================================
// PRIVATE HELPER PROTOTYPES (Internal use only)
// ============================================================================

/**
 * @brief Pre-operation callback for transaction access.
 *
 * Called before transaction handle is opened or duplicated.
 * Implements ransomware detection and access control.
 */
OB_PREOP_CALLBACK_STATUS
ShadowTransactionPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    );

/**
 * @brief Post-operation callback for transaction access.
 *
 * Called after transaction handle operation completes.
 * Used for telemetry and tracking.
 */
VOID
ShadowTransactionPostOperationCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_POST_OPERATION_INFORMATION OperationInformation
    );

/**
 * @brief Evict least recently used transaction from cache.
 *
 * Called when transaction cache is full.
 */
VOID
ShadowEvictLruTransaction(
    VOID
    );

/**
 * @brief Cleanup all transaction tracking entries.
 *
 * Frees all tracked transactions. Called during shutdown.
 */
VOID
ShadowCleanupTransactionEntries(
    VOID
    );

/**
 * @brief Cleanup KTM alert queue.
 *
 * Frees all pending alerts.
 */
VOID
ShadowCleanupKtmAlertQueue(
    VOID
    );

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_KTM_MONITOR_H
