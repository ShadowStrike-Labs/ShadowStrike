/**
 * ============================================================================
 * ShadowStrike NGAV - KTM TRANSACTION MONITOR
 * ============================================================================
 *
 * @file KtmMonitor.h
 * @brief Enterprise-grade Kernel Transaction Manager monitoring for ransomware detection.
 *
 * Provides protection against:
 * - Ransomware using atomic file encryption (LockBit, BlackCat, REvil)
 * - Transacted registry manipulation (persistence attacks)
 * - Volume shadow copy deletion via transactions
 * - Suspicious transaction rollback patterns
 * - High-velocity transaction abuse
 *
 * Architecture:
 * =============
 * 1. ObRegisterCallbacks for TmTransactionManager and Transaction objects
 * 2. Minifilter Pre/Post Operation Callbacks for transacted file operations
 * 3. Transaction Tracking with Behavioral Analytics (LRU cache)
 * 4. User-mode Communication via filter communication port
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1486: Data Encrypted for Impact (PRIMARY)
 * - T1490: Inhibit System Recovery (VSS deletion)
 * - T1547.001: Boot or Logon Autostart Execution - Registry Run Keys (transacted)
 *
 * @author ShadowStrike Security Team
 * @version 3.1.0 (Enterprise Edition)
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

#define SHADOW_KTM_TAG              'kSSx'
#define SHADOW_KTM_TRANSACTION_TAG  'tSSk'
#define SHADOW_KTM_STRING_TAG       'sSSk'
#define SHADOW_KTM_ALERT_TAG        'aSSk'

// ============================================================================
// CONSTANTS
// ============================================================================

#define SHADOW_MAX_TRANSACTIONS                  1024
#define SHADOW_MAX_PROCESS_NAME                  256
#define SHADOW_MAX_FILE_PATH                     512
#define SHADOW_RANSOMWARE_THRESHOLD_FILES_PER_SEC 50
#define SHADOW_RANSOMWARE_DETECTION_WINDOW_MS    1000
#define SHADOW_KTM_THREAT_THRESHOLD              80
#define SHADOW_MAX_KTM_ALERT_QUEUE               512

/**
 * @brief Initialization states (atomic transitions only)
 */
#define KTM_STATE_UNINITIALIZED 0
#define KTM_STATE_INITIALIZING  1
#define KTM_STATE_INITIALIZED   2
#define KTM_STATE_SHUTTING_DOWN 3

/**
 * @brief Reference count drain parameters
 */
#define SHADOW_REFCOUNT_DRAIN_INTERVAL_MS    100
#define SHADOW_REFCOUNT_DRAIN_MAX_ITERATIONS 50

/**
 * @brief Magic value for transaction structure validation
 */
#define SHADOW_KTM_TRANSACTION_MAGIC 0x4B544D58  // 'KTMX'

/**
 * @brief Sentinel value indicating transaction destruction in progress.
 *        Set via InterlockedExchange before final free.
 */
#define SHADOW_KTM_REFCOUNT_DESTROYING (-1)

// ============================================================================
// SUSPICIOUS TRANSACTION PATTERNS
// ============================================================================

#define SUSPICIOUS_TRANSACTION_ACCESS (  \
    TRANSACTION_COMMIT |                 \
    TRANSACTION_ROLLBACK |               \
    TRANSACTION_ENLIST                   \
)

// ============================================================================
// ENUMERATIONS
// ============================================================================

typedef enum _SHADOW_KTM_OPERATION {
    KtmOperationCreate = 1,
    KtmOperationCommit = 2,
    KtmOperationRollback = 3,
    KtmOperationEnlist = 4,
    KtmOperationFileWrite = 5,
    KtmOperationRegistrySet = 6
} SHADOW_KTM_OPERATION;

typedef enum _SHADOW_KTM_THREAT_LEVEL {
    KtmThreatNone = 0,
    KtmThreatLow = 25,
    KtmThreatMedium = 50,
    KtmThreatHigh = 75,
    KtmThreatCritical = 100
} SHADOW_KTM_THREAT_LEVEL;

typedef enum _SHADOW_KTM_ALERT_TYPE {
    KtmAlertRansomware = 1,
    KtmAlertVSSDelete = 2,
    KtmAlertMassCommit = 3,
    KtmAlertSuspiciousRollback = 4,
    KtmAlertRegistryPersistence = 5,
    KtmAlertRateLimitViolation = 6
} SHADOW_KTM_ALERT_TYPE;

// ============================================================================
// STATISTICS STRUCTURE
// ============================================================================

/**
 * @brief KTM monitoring statistics.
 *
 * All counters are atomic (updated via InterlockedIncrement64).
 * Snapshot copies are taken under a spinlock for consistency.
 */
typedef struct _SHADOW_KTM_STATISTICS {

    volatile LONG64 TotalTransactions;
    volatile LONG64 TotalCommits;
    volatile LONG64 TotalRollbacks;
    volatile LONG64 TransactedFileOperations;
    volatile LONG64 TransactedRegistryOperations;
    volatile LONG64 SuspiciousTransactions;
    volatile LONG64 RansomwareDetections;
    volatile LONG64 VSSDeleteAttempts;
    volatile LONG64 MassCommitOperations;
    volatile LONG64 BlockedTransactions;
    volatile LONG64 ThreatAlerts;
    volatile LONG64 RateLimitViolations;
    volatile LONG64 CacheHits;
    volatile LONG64 CacheMisses;
    volatile LONG64 FilesEncrypted;
    volatile LONG64 RefCountRaces;
    volatile LONG64 TransactionsLeaked;

} SHADOW_KTM_STATISTICS, *PSHADOW_KTM_STATISTICS;

// ============================================================================
// TRANSACTION TRACKING ENTRY
// ============================================================================

/**
 * @brief Transaction tracking entry.
 *
 * Tracks individual transactions for behavioral ransomware detection.
 * Reference counting uses atomic CAS loop via ShadowReferenceKtmTransaction.
 * Magic field is validated on every access via ShadowValidateKtmTransaction.
 */
typedef struct _SHADOW_KTM_TRANSACTION {

    LIST_ENTRY ListEntry;

    /// @brief Magic value for corruption detection (SHADOW_KTM_TRANSACTION_MAGIC)
    ULONG Magic;

    GUID TransactionGuid;
    HANDLE ProcessId;

    /// @brief Process name captured at creation time (safe for any IRQL)
    WCHAR ProcessName[SHADOW_MAX_PROCESS_NAME];

    LARGE_INTEGER CreateTime;
    LARGE_INTEGER LastActivityTime;
    LARGE_INTEGER CommitTime;

    volatile LONG FileOperationCount;
    volatile LONG RegistryOperationCount;
    volatile LONG ThreatScore;

    BOOLEAN IsCommitted;
    BOOLEAN IsRolledBack;
    BOOLEAN IsBlocked;
    BOOLEAN HasRansomwarePattern;

    volatile LONG FilesModified;
    LARGE_INTEGER RateWindowStart;

    /// @brief Reference count managed exclusively by CAS operations.
    ///        Set to SHADOW_KTM_REFCOUNT_DESTROYING before final free.
    volatile LONG ReferenceCount;

    /// @brief Set to TRUE when removed from the global list.
    volatile LONG RemovedFromList;

} SHADOW_KTM_TRANSACTION, *PSHADOW_KTM_TRANSACTION;

// ============================================================================
// ALERT STRUCTURE
// ============================================================================

typedef struct _SHADOW_KTM_ALERT {

    LIST_ENTRY ListEntry;
    SHADOW_KTM_ALERT_TYPE AlertType;
    ULONG ThreatScore;
    HANDLE ProcessId;
    WCHAR ProcessName[SHADOW_MAX_PROCESS_NAME];
    GUID TransactionGuid;
    LARGE_INTEGER AlertTime;
    ULONG FilesAffected;
    BOOLEAN WasBlocked;

} SHADOW_KTM_ALERT, *PSHADOW_KTM_ALERT;

// ============================================================================
// GLOBAL STATE STRUCTURE
// ============================================================================

typedef struct _SHADOW_KTM_MONITOR_STATE {

    //
    // Synchronization
    //

    /// @brief Push lock protecting transaction list (shared/exclusive semantics)
    EX_PUSH_LOCK Lock;

    /// @brief TRUE after FsRtlInitializePushLock(&Lock) completes
    BOOLEAN LockInitialized;

    /// @brief Atomic initialization state (KTM_STATE_*)
    volatile LONG InitializationState;

    //
    // Object Callback Registration
    //

    PVOID TransactionCallbackHandle;
    BOOLEAN CallbacksRegistered;

    //
    // Transaction Tracking
    //

    LIST_ENTRY TransactionList;
    volatile LONG TransactionCount;
    ULONG MaxTransactions;

    //
    // Alert Queue
    //

    KSPIN_LOCK AlertLock;
    LIST_ENTRY AlertQueue;
    volatile LONG AlertCount;
    ULONG MaxAlerts;

    //
    // Lookaside Lists
    //

    NPAGED_LOOKASIDE_LIST TransactionLookaside;
    BOOLEAN TransactionLookasideInitialized;

    NPAGED_LOOKASIDE_LIST AlertLookaside;
    BOOLEAN AlertLookasideInitialized;

    //
    // Statistics snapshot lock (protects Stats copies only)
    //

    KSPIN_LOCK StatsLock;

    //
    // Configuration
    //

    BOOLEAN MonitoringEnabled;
    BOOLEAN BlockingEnabled;
    BOOLEAN RansomwareDetectionEnabled;
    BOOLEAN RateLimitingEnabled;
    ULONG ThreatThreshold;
    ULONG RansomwareThreshold;
    LARGE_INTEGER RateLimitWindow;

    //
    // Statistics
    //

    SHADOW_KTM_STATISTICS Stats;

    //
    // State Tracking
    //

    BOOLEAN Initialized;
    volatile LONG ShuttingDown;
    LARGE_INTEGER InitTime;

    //
    // User-mode Communication
    //

    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort;
    BOOLEAN CommunicationPortOpen;
    PFLT_FILTER FilterHandle;

} SHADOW_KTM_MONITOR_STATE, *PSHADOW_KTM_MONITOR_STATE;

// ============================================================================
// GLOBAL STATE
// ============================================================================

extern SHADOW_KTM_MONITOR_STATE g_KtmMonitorState;

// ============================================================================
// PUBLIC FUNCTION PROTOTYPES
// ============================================================================

/**
 * @brief Initialize KTM monitoring subsystem.
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowInitializeKtmMonitor(
    _In_ PFLT_FILTER FilterHandle
    );

/**
 * @brief Cleanup KTM monitoring subsystem.
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowCleanupKtmMonitor(
    VOID
    );

/**
 * @brief Register transaction object callbacks (ObRegisterCallbacks).
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowRegisterTransactionCallbacks(
    VOID
    );

/**
 * @brief Unregister transaction object callbacks.
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowUnregisterTransactionCallbacks(
    VOID
    );

/**
 * @brief Track new transaction. Caller must release via ShadowReleaseKtmTransaction.
 * @irql PASSIVE_LEVEL (calls PsLookupProcessByProcessId)
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowTrackTransaction(
    _In_ GUID TransactionGuid,
    _In_ HANDLE ProcessId,
    _Outptr_ PSHADOW_KTM_TRANSACTION* Transaction
    );

/**
 * @brief Find existing transaction by GUID. Caller must release.
 * @irql <= APC_LEVEL (acquires push lock)
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
ShadowFindKtmTransaction(
    _In_ GUID TransactionGuid,
    _Outptr_ PSHADOW_KTM_TRANSACTION* Transaction
    );

/**
 * @brief Acquire additional reference via atomic CAS loop.
 * @return TRUE if reference acquired, FALSE if transaction is being destroyed.
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowReferenceKtmTransaction(
    _In_ PSHADOW_KTM_TRANSACTION Transaction
    );

/**
 * @brief Release transaction reference. Frees when count reaches zero.
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowReleaseKtmTransaction(
    _In_ PSHADOW_KTM_TRANSACTION Transaction
    );

/**
 * @brief Validate transaction structure integrity (magic + bounds).
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowValidateKtmTransaction(
    _In_ PSHADOW_KTM_TRANSACTION Transaction
    );

/**
 * @brief Calculate threat score for transaction (uses cached process name).
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowCalculateKtmThreatScore(
    _In_ PSHADOW_KTM_TRANSACTION Transaction,
    _In_ SHADOW_KTM_OPERATION Operation,
    _Out_ PULONG ThreatScore
    );

/**
 * @brief Check if file extension is a ransomware target.
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowIsRansomwareTargetFile(
    _In_ PUNICODE_STRING FilePath
    );

/**
 * @brief Check for ransomware pattern (high-velocity file operations).
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowDetectRansomwarePattern(
    _In_ PSHADOW_KTM_TRANSACTION Transaction
    );

/**
 * @brief Record transacted file operation against a transaction.
 * @irql PASSIVE_LEVEL (may queue alert which captures process name)
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowRecordTransactedFileOperation(
    _In_ PSHADOW_KTM_TRANSACTION Transaction,
    _In_ PUNICODE_STRING FilePath
    );

/**
 * @brief Mark transaction as committed and evaluate threat.
 * @irql PASSIVE_LEVEL (may queue alert which captures process name)
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowMarkTransactionCommitted(
    _In_ PSHADOW_KTM_TRANSACTION Transaction
    );

/**
 * @brief Get atomic snapshot of KTM monitoring statistics.
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowGetKtmStatistics(
    _Out_ PSHADOW_KTM_STATISTICS Stats
    );

/**
 * @brief Queue KTM threat alert. Process name is captured from the
 *        transaction's cached ProcessName field (IRQL-safe).
 *
 * @param AlertType         Alert type
 * @param ProcessId         Process ID
 * @param ProcessName       Pre-captured process name (may be NULL)
 * @param TransactionGuid   Transaction GUID
 * @param FilesAffected     Number of files affected
 * @param ThreatScore       Threat score (0-100)
 * @param WasBlocked        Was this transaction blocked?
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowQueueKtmAlert(
    _In_ SHADOW_KTM_ALERT_TYPE AlertType,
    _In_ HANDLE ProcessId,
    _In_opt_ PCWSTR ProcessName,
    _In_ GUID TransactionGuid,
    _In_ ULONG FilesAffected,
    _In_ ULONG ThreatScore,
    _In_ BOOLEAN WasBlocked
    );

/**
 * @brief Minifilter transaction notification callback.
 */
NTSTATUS
ShadowKtmNotificationCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_CONTEXT TransactionContext,
    _In_ ULONG NotificationMask
    );

// ============================================================================
// INTERNAL PROTOTYPES (used across compilation units within Transactions/)
// ============================================================================

OB_PREOP_CALLBACK_STATUS
ShadowTransactionPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    );

VOID
ShadowTransactionPostOperationCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_POST_OPERATION_INFORMATION OperationInformation
    );

_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowEvictLruTransaction(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowCleanupTransactionEntries(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowCleanupKtmAlertQueue(
    VOID
    );

/**
 * @brief Get process image name. Allocates from NonPagedPool.
 *        Caller frees ImageName->Buffer with SHADOW_KTM_STRING_TAG.
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowGetProcessImageName(
    _In_ HANDLE ProcessId,
    _Out_ PUNICODE_STRING ImageName
    );

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_KTM_MONITOR_H
