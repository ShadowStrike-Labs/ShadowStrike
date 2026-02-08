/*++
    ShadowStrike Next-Generation Antivirus
    Module: TokenAnalyzer.h - Enterprise Token Manipulation Detection Engine
    Copyright (c) ShadowStrike Team

    SECURITY HARDENED v3.0.0:
    - Full reference counting with proper lifecycle management
    - Thread-safe cache operations with proper synchronization
    - Process termination notification integration
    - Comprehensive IRQL annotations
    - Enterprise logging integration
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

// ============================================================================
// POOL TAGS
// ============================================================================

#define TA_POOL_TAG                     'ANOT'
#define TA_TOKEN_INFO_TAG               'ITOT'
#define TA_BASELINE_TAG                 'BSLT'
#define TA_SID_TAG                      'SITA'
#define TA_PRIVILEGE_TAG                'PRTA'
#define TA_GROUPS_TAG                   'GRTA'

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * @brief Maximum cached token entries
 */
#define TA_MAX_CACHE_ENTRIES            4096

/**
 * @brief Maximum baseline entries
 */
#define TA_MAX_BASELINE_ENTRIES         8192

/**
 * @brief Maximum privileges to track per token
 */
#define TA_MAX_PRIVILEGES               64

/**
 * @brief Maximum groups to track per token
 */
#define TA_MAX_GROUPS                   128

/**
 * @brief Cache entry expiry time (5 minutes in 100ns units)
 */
#define TA_CACHE_EXPIRY_TIME            (5LL * 60LL * 10000000LL)

/**
 * @brief Shutdown wait timeout (10 seconds)
 */
#define TA_SHUTDOWN_TIMEOUT             (-10LL * 1000LL * 10000LL)

// ============================================================================
// INTEGRITY LEVEL RIDS
// ============================================================================

#define TA_INTEGRITY_UNTRUSTED          0x00000000UL
#define TA_INTEGRITY_LOW                0x00001000UL
#define TA_INTEGRITY_MEDIUM             0x00002000UL
#define TA_INTEGRITY_MEDIUM_PLUS        0x00002100UL
#define TA_INTEGRITY_HIGH               0x00003000UL
#define TA_INTEGRITY_SYSTEM             0x00004000UL
#define TA_INTEGRITY_PROTECTED          0x00005000UL

// ============================================================================
// ATTACK TYPES
// ============================================================================

typedef enum _TA_TOKEN_ATTACK {
    TaAttack_None = 0,
    TaAttack_Impersonation,
    TaAttack_TokenStealing,
    TaAttack_PrivilegeEscalation,
    TaAttack_SIDInjection,
    TaAttack_IntegrityDowngrade,
    TaAttack_GroupModification,
    TaAttack_PrimaryTokenReplace,
    TaAttack_MaxValue
} TA_TOKEN_ATTACK;

// ============================================================================
// PUBLIC STRUCTURES
// ============================================================================

/**
 * @brief Token information structure returned to callers.
 *        Callers MUST call TaReleaseTokenInfo when done.
 */
typedef struct _TA_TOKEN_INFO {
    //
    // Process identification
    //
    HANDLE ProcessId;

    //
    // Token properties
    //
    LUID AuthenticationId;
    TOKEN_TYPE TokenType;
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
    ULONG IntegrityLevel;

    //
    // Privilege summary
    //
    ULONG EnabledPrivileges;
    ULONG PrivilegeCount;
    BOOLEAN HasDebugPrivilege;
    BOOLEAN HasImpersonatePrivilege;
    BOOLEAN HasAssignPrimaryPrivilege;
    BOOLEAN HasTcbPrivilege;
    BOOLEAN HasLoadDriverPrivilege;
    BOOLEAN HasBackupPrivilege;
    BOOLEAN HasRestorePrivilege;

    //
    // Group summary
    //
    ULONG GroupCount;
    BOOLEAN IsAdmin;
    BOOLEAN IsSystem;
    BOOLEAN IsService;
    BOOLEAN IsNetworkService;
    BOOLEAN IsLocalService;

    //
    // Token attributes
    //
    BOOLEAN IsRestricted;
    BOOLEAN IsFiltered;
    BOOLEAN IsVirtualized;
    BOOLEAN IsSandboxed;
    BOOLEAN IsAppContainer;
    BOOLEAN IsElevated;

    //
    // Session information
    //
    ULONG SessionId;

    //
    // Detection results
    //
    TA_TOKEN_ATTACK DetectedAttack;
    ULONG SuspicionScore;

} TA_TOKEN_INFO, *PTA_TOKEN_INFO;

/**
 * @brief Opaque analyzer handle
 */
typedef struct _TA_ANALYZER *PTA_ANALYZER;

/**
 * @brief Statistics structure
 */
typedef struct _TA_STATISTICS {
    volatile LONG64 TokensAnalyzed;
    volatile LONG64 AttacksDetected;
    volatile LONG64 CacheHits;
    volatile LONG64 CacheMisses;
    volatile LONG64 BaselinesCreated;
    volatile LONG64 BaselinesEvicted;
    LARGE_INTEGER StartTime;
} TA_STATISTICS, *PTA_STATISTICS;

/**
 * @brief Baseline snapshot for comparison (copied data, safe to use without locks)
 */
typedef struct _TA_BASELINE_SNAPSHOT {
    BOOLEAN Valid;
    HANDLE ProcessId;
    LUID AuthenticationId;
    LUID TokenId;
    ULONG IntegrityLevel;
    ULONG EnabledPrivileges;
    ULONG GroupCount;
    BOOLEAN IsAdmin;
    BOOLEAN IsSystem;
    TOKEN_TYPE TokenType;
    LARGE_INTEGER RecordTime;
} TA_BASELINE_SNAPSHOT, *PTA_BASELINE_SNAPSHOT;

// ============================================================================
// INITIALIZATION / SHUTDOWN
// ============================================================================

/**
 * @brief Initialize the token analyzer engine.
 *
 * @param[out] Analyzer - Receives the analyzer handle
 * @return STATUS_SUCCESS or error code
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TaInitialize(
    _Out_ PTA_ANALYZER* Analyzer
);

/**
 * @brief Shutdown the token analyzer and free all resources.
 *        Waits for all outstanding references to drain.
 *
 * @param[in,out] Analyzer - Analyzer handle to shutdown
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
TaShutdown(
    _Inout_ PTA_ANALYZER Analyzer
);

// ============================================================================
// TOKEN ANALYSIS
// ============================================================================

/**
 * @brief Analyze a process token and return detailed information.
 *        Caller MUST call TaReleaseTokenInfo when done with the returned info.
 *
 * @param[in] Analyzer - Analyzer handle
 * @param[in] ProcessId - Target process ID
 * @param[out] Info - Receives token information (caller must release)
 * @return STATUS_SUCCESS or error code
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TaAnalyzeToken(
    _In_ PTA_ANALYZER Analyzer,
    _In_ HANDLE ProcessId,
    _Outptr_ PTA_TOKEN_INFO* Info
);

/**
 * @brief Detect token manipulation by comparing to baseline.
 *
 * @param[in] Analyzer - Analyzer handle
 * @param[in] ProcessId - Target process ID
 * @param[out] Attack - Detected attack type
 * @param[out] Score - Suspicion score (0-100)
 * @return STATUS_SUCCESS or error code
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TaDetectTokenManipulation(
    _In_ PTA_ANALYZER Analyzer,
    _In_ HANDLE ProcessId,
    _Out_ TA_TOKEN_ATTACK* Attack,
    _Out_ PULONG Score
);

/**
 * @brief Compare two token info structures for changes.
 *
 * @param[in] Analyzer - Analyzer handle
 * @param[in] Original - Original token info
 * @param[in] Current - Current token info
 * @param[out] Changed - TRUE if tokens differ
 * @return STATUS_SUCCESS or error code
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TaCompareTokens(
    _In_ PTA_ANALYZER Analyzer,
    _In_ PTA_TOKEN_INFO Original,
    _In_ PTA_TOKEN_INFO Current,
    _Out_ PBOOLEAN Changed
);

// ============================================================================
// REFERENCE MANAGEMENT
// ============================================================================

/**
 * @brief Add a reference to token info.
 *        Use when storing token info pointer for later use.
 *
 * @param[in] Info - Token info to reference
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TaReferenceTokenInfo(
    _In_ PTA_TOKEN_INFO Info
);

/**
 * @brief Release a reference to token info.
 *        MUST be called for every TaAnalyzeToken result and TaReferenceTokenInfo call.
 *
 * @param[in] Info - Token info to release
 *
 * @irql <= DISPATCH_LEVEL (actual free deferred if > PASSIVE)
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TaReleaseTokenInfo(
    _In_ PTA_TOKEN_INFO Info
);

// ============================================================================
// BASELINE MANAGEMENT
// ============================================================================

/**
 * @brief Get a snapshot of the baseline for a process.
 *        Returns a COPY of the baseline data, safe to use without locks.
 *
 * @param[in] Analyzer - Analyzer handle
 * @param[in] ProcessId - Target process ID
 * @param[out] Snapshot - Receives baseline snapshot
 * @return STATUS_SUCCESS, STATUS_NOT_FOUND, or error code
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TaGetBaselineSnapshot(
    _In_ PTA_ANALYZER Analyzer,
    _In_ HANDLE ProcessId,
    _Out_ PTA_BASELINE_SNAPSHOT Snapshot
);

/**
 * @brief Invalidate baseline for a terminated process.
 *        Called from process notification callback.
 *
 * @param[in] Analyzer - Analyzer handle
 * @param[in] ProcessId - Terminated process ID
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
TaOnProcessTerminated(
    _In_ PTA_ANALYZER Analyzer,
    _In_ HANDLE ProcessId
);

// ============================================================================
// STATISTICS
// ============================================================================

/**
 * @brief Get analyzer statistics.
 *
 * @param[in] Analyzer - Analyzer handle
 * @param[out] Stats - Receives statistics
 * @return STATUS_SUCCESS or error code
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
TaGetStatistics(
    _In_ PTA_ANALYZER Analyzer,
    _Out_ PTA_STATISTICS Stats
);

// ============================================================================
// UTILITY
// ============================================================================

/**
 * @brief Convert attack type to string for logging.
 *
 * @param[in] Attack - Attack type
 * @return Static string describing the attack
 *
 * @irql Any
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
PCWSTR
TaAttackTypeToString(
    _In_ TA_TOKEN_ATTACK Attack
);

/**
 * @brief Convert integrity level to string for logging.
 *
 * @param[in] IntegrityLevel - Integrity level RID
 * @return Static string describing the integrity level
 *
 * @irql Any
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
PCWSTR
TaIntegrityLevelToString(
    _In_ ULONG IntegrityLevel
);

#ifdef __cplusplus
}
#endif
