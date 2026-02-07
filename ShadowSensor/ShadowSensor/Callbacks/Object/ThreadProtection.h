/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE THREAD PROTECTION HEADER
 * ============================================================================
 *
 * @file ThreadProtection.h
 * @brief Enterprise-grade thread handle protection for kernel-mode EDR.
 *
 * This module provides comprehensive thread handle monitoring and protection:
 * - Handle access rights stripping for threads in protected processes
 * - Thread injection detection (SET_CONTEXT, SUSPEND_RESUME)
 * - APC injection attack detection and prevention
 * - Remote thread context manipulation monitoring
 * - Cross-process thread access control
 * - Thread hijacking detection (context modification attacks)
 * - Anti-debugging protection at thread level
 * - Thread pool and fiber abuse detection
 *
 * Detection Techniques Covered (MITRE ATT&CK):
 * - T1055.003: Thread Execution Hijacking
 * - T1055.004: Asynchronous Procedure Call (APC) Injection
 * - T1055.005: Thread Local Storage (TLS) Callback Injection
 * - T1106: Native API (NtSetContextThread, NtSuspendThread)
 * - T1562: Impair Defenses (EDR thread protection)
 * - T1622: Debugger Evasion (anti-debug at thread level)
 *
 * Integration Points:
 * - ObRegisterCallbacks (PsThreadType pre-operation)
 * - SelfProtection module for protected process list
 * - ETW telemetry for suspicious thread operations
 * - ProcessProtection module for coordinated defense
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_THREAD_PROTECTION_H_
#define _SHADOWSTRIKE_THREAD_PROTECTION_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <ntifs.h>
#include <wdm.h>

// ============================================================================
// POOL TAGS
// ============================================================================

#define TP_POOL_TAG                     'TPPS'  // Thread Protection
#define TP_CONTEXT_TAG                  'xCTP'  // Context allocations
#define TP_TRACKER_TAG                  'kTTP'  // Tracker allocations

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * @brief Maximum protected threads tracked in fast-path cache
 */
#define TP_MAX_CACHED_THREADS           256

/**
 * @brief Maximum thread operations to log per second (rate limiting)
 */
#define TP_MAX_LOG_RATE_PER_SEC         100

/**
 * @brief Threshold for suspicious thread activity (per source process)
 */
#define TP_SUSPICIOUS_ACTIVITY_THRESHOLD 30

/**
 * @brief Time window for thread activity tracking (100ns units = 5 seconds)
 */
#define TP_ACTIVITY_WINDOW_100NS        (5LL * 10000000LL)

/**
 * @brief Maximum threads to track per source process
 */
#define TP_MAX_TRACKED_THREADS_PER_SOURCE 64

/**
 * @brief High suspicion score threshold
 */
#define TP_HIGH_SUSPICION_THRESHOLD     80

/**
 * @brief Medium suspicion score threshold
 */
#define TP_MEDIUM_SUSPICION_THRESHOLD   50

// ============================================================================
// ACCESS MASKS FOR PROTECTION
// ============================================================================

/**
 * @brief Dangerous thread access rights that enable termination
 */
#define TP_DANGEROUS_TERMINATE_ACCESS   \
    (THREAD_TERMINATE)

/**
 * @brief Dangerous thread access rights that enable injection/hijacking
 */
#define TP_DANGEROUS_INJECT_ACCESS      \
    (THREAD_SET_CONTEXT |               \
     THREAD_GET_CONTEXT |               \
     THREAD_SET_INFORMATION)

/**
 * @brief Dangerous thread access rights that enable control
 */
#define TP_DANGEROUS_CONTROL_ACCESS     \
    (THREAD_SUSPEND_RESUME |            \
     THREAD_IMPERSONATE |               \
     THREAD_DIRECT_IMPERSONATION)

/**
 * @brief Access rights for APC injection
 */
#define TP_APC_INJECT_ACCESS            \
    (THREAD_SET_CONTEXT |               \
     THREAD_SUSPEND_RESUME)

/**
 * @brief Access rights for thread hijacking
 */
#define TP_HIJACK_ACCESS                \
    (THREAD_GET_CONTEXT |               \
     THREAD_SET_CONTEXT |               \
     THREAD_SUSPEND_RESUME)

/**
 * @brief Full dangerous access mask (all of the above)
 */
#define TP_FULL_DANGEROUS_ACCESS        \
    (TP_DANGEROUS_TERMINATE_ACCESS |    \
     TP_DANGEROUS_INJECT_ACCESS |       \
     TP_DANGEROUS_CONTROL_ACCESS)

/**
 * @brief Safe read-only access mask
 */
#define TP_SAFE_READ_ACCESS             \
    (THREAD_QUERY_LIMITED_INFORMATION | \
     SYNCHRONIZE)

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Thread protection level
 */
typedef enum _TP_PROTECTION_LEVEL {
    TpProtectionNone            = 0,    ///< No protection
    TpProtectionLight           = 1,    ///< Block terminate only
    TpProtectionMedium          = 2,    ///< Block terminate + suspend
    TpProtectionStrict          = 3,    ///< Block all dangerous access
    TpProtectionCritical        = 4,    ///< Critical system thread
    TpProtectionAntimalware     = 5     ///< Full EDR thread protection
} TP_PROTECTION_LEVEL;

/**
 * @brief Thread operation type for classification
 */
typedef enum _TP_OPERATION_TYPE {
    TpOperationUnknown          = 0,
    TpOperationCreate           = 1,    ///< NtOpenThread
    TpOperationDuplicate        = 2,    ///< NtDuplicateObject
    TpOperationInherit          = 3     ///< Handle inheritance
} TP_OPERATION_TYPE;

/**
 * @brief Thread operation verdict
 */
typedef enum _TP_VERDICT {
    TpVerdictAllow              = 0,    ///< Allow with original access
    TpVerdictStrip              = 1,    ///< Allow with stripped access
    TpVerdictMonitor            = 2,    ///< Allow but log/alert
    TpVerdictBlock              = 3     ///< Block entirely (set access to 0)
} TP_VERDICT;

/**
 * @brief Suspicious thread activity indicators
 */
typedef enum _TP_SUSPICIOUS_FLAGS {
    TpSuspiciousNone                = 0x00000000,
    TpSuspiciousContextAccess       = 0x00000001,  ///< GET/SET_CONTEXT access
    TpSuspiciousSuspendAccess       = 0x00000002,  ///< SUSPEND_RESUME access
    TpSuspiciousTerminateAttempt    = 0x00000004,  ///< Terminate protected thread
    TpSuspiciousCrossProcess        = 0x00000008,  ///< Cross-process thread access
    TpSuspiciousRapidEnumeration    = 0x00000010,  ///< Fast thread enumeration
    TpSuspiciousAPCPattern          = 0x00000020,  ///< APC injection pattern
    TpSuspiciousHijackPattern       = 0x00000040,  ///< Thread hijacking pattern
    TpSuspiciousImpersonation       = 0x00000080,  ///< Thread impersonation access
    TpSuspiciousDebugAccess         = 0x00000100,  ///< Debug-related access
    TpSuspiciousMultiThread         = 0x00000200,  ///< Multiple threads targeted
    TpSuspiciousRemoteThread        = 0x00000400,  ///< Remote thread creation follow-up
    TpSuspiciousSelfProtectBypass   = 0x00000800   ///< Self-protection bypass attempt
} TP_SUSPICIOUS_FLAGS;

/**
 * @brief Thread attack type classification
 */
typedef enum _TP_ATTACK_TYPE {
    TpAttackNone                = 0,
    TpAttackContextHijack       = 1,    ///< Thread context hijacking
    TpAttackAPCInjection        = 2,    ///< APC injection
    TpAttackSuspendInject       = 3,    ///< Suspend-Inject-Resume pattern
    TpAttackTermination         = 4,    ///< Thread termination attack
    TpAttackImpersonation       = 5,    ///< Thread impersonation abuse
    TpAttackDebugManipulation   = 6,    ///< Debug register manipulation
    TpAttackTLSCallback         = 7,    ///< TLS callback abuse
    TpAttackUnknown             = 0xFF
} TP_ATTACK_TYPE;

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Thread handle operation context for analysis
 */
typedef struct _TP_OPERATION_CONTEXT {
    //
    // Operation details
    //
    TP_OPERATION_TYPE OperationType;
    BOOLEAN IsKernelHandle;

    //
    // Source process
    //
    HANDLE SourceProcessId;
    HANDLE SourceThreadId;
    PEPROCESS SourceProcess;
    ULONG SourceSessionId;
    BOOLEAN SourceIsElevated;
    BOOLEAN SourceIsProtected;

    //
    // Target thread
    //
    HANDLE TargetThreadId;
    HANDLE TargetProcessId;
    PETHREAD TargetThread;
    PEPROCESS TargetProcess;
    ULONG TargetSessionId;
    BOOLEAN TargetIsMainThread;
    BOOLEAN TargetIsSystemThread;
    TP_PROTECTION_LEVEL TargetProtectionLevel;

    //
    // Access details
    //
    ACCESS_MASK OriginalDesiredAccess;
    ACCESS_MASK ModifiedDesiredAccess;
    ACCESS_MASK StrippedAccess;

    //
    // Analysis results
    //
    TP_SUSPICIOUS_FLAGS SuspiciousFlags;
    TP_ATTACK_TYPE DetectedAttack;
    ULONG SuspicionScore;
    TP_VERDICT Verdict;

    //
    // Timing
    //
    LARGE_INTEGER Timestamp;

} TP_OPERATION_CONTEXT, *PTP_OPERATION_CONTEXT;

/**
 * @brief Thread activity tracker (per source process)
 */
typedef struct _TP_ACTIVITY_TRACKER {
    LIST_ENTRY ListEntry;
    LIST_ENTRY HashEntry;

    HANDLE SourceProcessId;
    LARGE_INTEGER FirstActivity;
    LARGE_INTEGER LastActivity;

    volatile LONG TotalOperationCount;
    volatile LONG SuspiciousOperationCount;
    volatile LONG StrippedOperationCount;
    volatile LONG ContextAccessCount;
    volatile LONG SuspendAccessCount;

    //
    // Target tracking
    //
    ULONG UniqueThreadCount;
    ULONG UniqueProcessCount;
    HANDLE RecentTargetThreads[16];
    HANDLE RecentTargetProcesses[8];

    //
    // Attack pattern detection
    //
    BOOLEAN HasSuspendPattern;
    BOOLEAN HasContextPattern;
    BOOLEAN HasAPCPattern;
    BOOLEAN HasEnumerationPattern;

    //
    // Flags
    //
    BOOLEAN IsRateLimited;
    BOOLEAN IsBlacklisted;

} TP_ACTIVITY_TRACKER, *PTP_ACTIVITY_TRACKER;

/**
 * @brief Thread protection state
 */
typedef struct _TP_PROTECTION_STATE {
    //
    // Initialization
    //
    BOOLEAN Initialized;
    ULONG Magic;

    //
    // Reference counting
    //
    volatile LONG ReferenceCount;
    volatile LONG ShuttingDown;
    KEVENT ShutdownEvent;

    //
    // Activity tracking
    //
    LIST_ENTRY ActivityList;
    EX_PUSH_LOCK ActivityLock;
    volatile LONG ActiveTrackers;

    //
    // Hash table for fast activity lookup (by source PID)
    //
    LIST_ENTRY ActivityHashTable[64];

    //
    // Rate limiting
    //
    volatile LONG CurrentSecondLogs;
    LARGE_INTEGER CurrentSecondStart;

    //
    // Statistics
    //
    struct {
        volatile LONG64 TotalOperations;
        volatile LONG64 ProtectedTargetOperations;
        volatile LONG64 AccessStripped;
        volatile LONG64 OperationsBlocked;
        volatile LONG64 TerminateAttempts;
        volatile LONG64 ContextAccessAttempts;
        volatile LONG64 SuspendAttempts;
        volatile LONG64 ImpersonationAttempts;
        volatile LONG64 APCInjectionPatterns;
        volatile LONG64 HijackPatterns;
        volatile LONG64 CrossProcessAccess;
        volatile LONG64 SuspiciousOperations;
        volatile LONG64 RateLimitedOperations;
        LARGE_INTEGER StartTime;
    } Stats;

    //
    // Configuration
    //
    struct {
        BOOLEAN EnableTerminationProtection;    ///< Block THREAD_TERMINATE
        BOOLEAN EnableContextProtection;        ///< Block SET_CONTEXT
        BOOLEAN EnableSuspendProtection;        ///< Block SUSPEND_RESUME
        BOOLEAN EnableImpersonationProtection;  ///< Block IMPERSONATE
        BOOLEAN EnableActivityTracking;         ///< Per-process activity
        BOOLEAN EnablePatternDetection;         ///< Attack pattern detection
        BOOLEAN EnableRateLimiting;             ///< Log rate limiting
        BOOLEAN LogStrippedAccess;              ///< Log when access is stripped
        BOOLEAN NotifyUserMode;                 ///< Send notifications
        ULONG SuspicionScoreThreshold;          ///< Score to trigger alert
    } Config;

    //
    // Lookaside list for trackers
    //
    NPAGED_LOOKASIDE_LIST TrackerLookaside;
    BOOLEAN LookasideInitialized;

} TP_PROTECTION_STATE, *PTP_PROTECTION_STATE;

// ============================================================================
// FUNCTION PROTOTYPES - INITIALIZATION
// ============================================================================

/**
 * @brief Initialize thread protection subsystem.
 *
 * Must be called before registering object callbacks.
 * Initializes trackers and detection state.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
TpInitializeThreadProtection(
    VOID
    );

/**
 * @brief Shutdown thread protection subsystem.
 *
 * Frees all resources. Must be called after unregistering object callbacks.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
TpShutdownThreadProtection(
    VOID
    );

// ============================================================================
// FUNCTION PROTOTYPES - CALLBACK
// ============================================================================

/**
 * @brief Thread handle pre-operation callback.
 *
 * Core callback registered via ObRegisterCallbacks.
 * Analyzes thread handle operations and strips dangerous access rights.
 *
 * @param RegistrationContext   Registration context (unused).
 * @param OperationInformation  Handle operation details.
 *
 * @return OB_PREOP_SUCCESS always (we strip access, not block).
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
OB_PREOP_CALLBACK_STATUS
TpThreadHandlePreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    );

/**
 * @brief Thread handle post-operation callback (optional).
 *
 * Can be used for additional logging after handle is created.
 *
 * @param RegistrationContext   Registration context.
 * @param OperationInformation  Handle operation details.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
TpThreadHandlePostCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_POST_OPERATION_INFORMATION OperationInformation
    );

// ============================================================================
// FUNCTION PROTOTYPES - ANALYSIS
// ============================================================================

/**
 * @brief Analyze a thread handle operation for suspicious activity.
 *
 * @param Context   Operation context to analyze (updated in place).
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TpAnalyzeOperation(
    _Inout_ PTP_OPERATION_CONTEXT Context
    );

/**
 * @brief Determine verdict for a thread handle operation.
 *
 * @param Context   Analyzed operation context.
 *
 * @return Verdict (allow, strip, monitor, or block).
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
TP_VERDICT
TpDetermineVerdict(
    _In_ PTP_OPERATION_CONTEXT Context
    );

/**
 * @brief Calculate access mask to strip based on protection level.
 *
 * @param OriginalAccess    Requested access mask.
 * @param ProtectionLevel   Target's protection level.
 * @param Flags             Suspicious flags detected.
 *
 * @return Access mask with dangerous rights removed.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
ACCESS_MASK
TpCalculateAllowedAccess(
    _In_ ACCESS_MASK OriginalAccess,
    _In_ TP_PROTECTION_LEVEL ProtectionLevel,
    _In_ TP_SUSPICIOUS_FLAGS Flags
    );

/**
 * @brief Detect attack pattern from operation context.
 *
 * @param Context   Operation context.
 *
 * @return Detected attack type.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
TP_ATTACK_TYPE
TpDetectAttackPattern(
    _In_ PTP_OPERATION_CONTEXT Context
    );

// ============================================================================
// FUNCTION PROTOTYPES - ACTIVITY TRACKING
// ============================================================================

/**
 * @brief Track thread handle activity from a source process.
 *
 * @param SourceProcessId   Source process ID.
 * @param TargetThreadId    Target thread ID.
 * @param TargetProcessId   Target process ID.
 * @param AccessMask        Requested access mask.
 * @param IsSuspicious      Whether this operation is suspicious.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TpTrackActivity(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetThreadId,
    _In_ HANDLE TargetProcessId,
    _In_ ACCESS_MASK AccessMask,
    _In_ BOOLEAN IsSuspicious
    );

/**
 * @brief Get activity tracker for a source process.
 *
 * @param SourceProcessId   Source process ID.
 * @param OutTracker        Receives tracker pointer (if found).
 *
 * @return TRUE if tracker exists.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
TpGetActivityTracker(
    _In_ HANDLE SourceProcessId,
    _Out_ PTP_ACTIVITY_TRACKER* OutTracker
    );

/**
 * @brief Check if a source process should be rate limited.
 *
 * @param SourceProcessId   Source process ID.
 *
 * @return TRUE if rate limited.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
TpIsSourceRateLimited(
    _In_ HANDLE SourceProcessId
    );

/**
 * @brief Cleanup expired activity trackers.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
TpCleanupExpiredTrackers(
    VOID
    );

// ============================================================================
// FUNCTION PROTOTYPES - PROTECTION QUERIES
// ============================================================================

/**
 * @brief Check if a thread belongs to a protected process.
 *
 * @param Thread                Target thread.
 * @param OutProtectionLevel    Receives protection level if protected.
 *
 * @return TRUE if thread is in a protected process.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
TpIsThreadProtected(
    _In_ PETHREAD Thread,
    _Out_opt_ TP_PROTECTION_LEVEL* OutProtectionLevel
    );

/**
 * @brief Get protection level for a thread's process.
 *
 * @param ProcessId     Process ID to check.
 *
 * @return Protection level (TpProtectionNone if not protected).
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
TP_PROTECTION_LEVEL
TpGetProcessProtectionLevel(
    _In_ HANDLE ProcessId
    );

// ============================================================================
// FUNCTION PROTOTYPES - STATISTICS
// ============================================================================

/**
 * @brief Get thread protection statistics.
 *
 * @param TotalOperations       Receives total operations.
 * @param AccessStripped        Receives stripped count.
 * @param ContextAttempts       Receives context access attempts.
 * @param SuspendAttempts       Receives suspend attempts.
 * @param APCPatterns           Receives APC injection patterns.
 * @param HijackPatterns        Receives hijack patterns.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TpGetStatistics(
    _Out_opt_ PULONG64 TotalOperations,
    _Out_opt_ PULONG64 AccessStripped,
    _Out_opt_ PULONG64 ContextAttempts,
    _Out_opt_ PULONG64 SuspendAttempts,
    _Out_opt_ PULONG64 APCPatterns,
    _Out_opt_ PULONG64 HijackPatterns
    );

// ============================================================================
// INLINE HELPERS
// ============================================================================

/**
 * @brief Check if access mask allows thread context manipulation.
 */
FORCEINLINE
BOOLEAN
TpAccessAllowsContextManipulation(
    _In_ ACCESS_MASK Access
    )
{
    return (Access & (THREAD_SET_CONTEXT | THREAD_GET_CONTEXT)) != 0;
}

/**
 * @brief Check if access mask allows thread suspension.
 */
FORCEINLINE
BOOLEAN
TpAccessAllowsSuspension(
    _In_ ACCESS_MASK Access
    )
{
    return (Access & THREAD_SUSPEND_RESUME) != 0;
}

/**
 * @brief Check if access mask allows thread termination.
 */
FORCEINLINE
BOOLEAN
TpAccessAllowsTermination(
    _In_ ACCESS_MASK Access
    )
{
    return (Access & THREAD_TERMINATE) != 0;
}

/**
 * @brief Check if access mask matches APC injection pattern.
 */
FORCEINLINE
BOOLEAN
TpAccessMatchesAPCPattern(
    _In_ ACCESS_MASK Access
    )
{
    //
    // APC injection typically requires SUSPEND + SET_CONTEXT
    //
    return ((Access & TP_APC_INJECT_ACCESS) == TP_APC_INJECT_ACCESS);
}

/**
 * @brief Check if access mask matches thread hijacking pattern.
 */
FORCEINLINE
BOOLEAN
TpAccessMatchesHijackPattern(
    _In_ ACCESS_MASK Access
    )
{
    //
    // Thread hijacking requires GET_CONTEXT + SET_CONTEXT + SUSPEND
    //
    return ((Access & TP_HIJACK_ACCESS) == TP_HIJACK_ACCESS);
}

/**
 * @brief Check if access is safe read-only.
 */
FORCEINLINE
BOOLEAN
TpAccessIsSafeReadOnly(
    _In_ ACCESS_MASK Access
    )
{
    return ((Access & TP_FULL_DANGEROUS_ACCESS) == 0) &&
           ((Access & ~TP_SAFE_READ_ACCESS) == 0);
}

/**
 * @brief Calculate hash for source process ID.
 */
FORCEINLINE
ULONG
TpHashProcessId(
    _In_ HANDLE ProcessId
    )
{
    return ((ULONG)(ULONG_PTR)ProcessId >> 2) & 0x3F;
}

#ifdef __cplusplus
}
#endif

#endif // _SHADOWSTRIKE_THREAD_PROTECTION_H_
