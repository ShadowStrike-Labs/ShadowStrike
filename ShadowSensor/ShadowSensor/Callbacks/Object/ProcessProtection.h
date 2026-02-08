/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE PROCESS PROTECTION HEADER
 * ============================================================================
 *
 * @file ProcessProtection.h
 * @brief Enterprise-grade process handle protection for kernel-mode EDR.
 *
 * This module provides comprehensive process handle monitoring and protection:
 * - Handle access rights stripping for protected processes
 * - Malicious handle operation detection (credential theft, injection)
 * - Per-process access policy enforcement
 * - Handle duplication monitoring across process boundaries
 * - LSASS, CSRSS, and critical system process protection
 * - Anti-debugging protection for EDR processes
 * - Handle table enumeration defense
 * - Cross-session handle access monitoring
 *
 * Detection Techniques Covered (MITRE ATT&CK):
 * - T1003: OS Credential Dumping (LSASS protection)
 * - T1055: Process Injection (VM_WRITE/CREATE_THREAD blocking)
 * - T1489: Service Stop (service process protection)
 * - T1562: Impair Defenses (EDR self-protection)
 * - T1106: Native API (handle duplication monitoring)
 * - T1134: Access Token Manipulation (token access monitoring)
 *
 * Integration Points:
 * - ObRegisterCallbacks (PsProcessType pre-operation)
 * - SelfProtection module for protected process list
 * - ETW telemetry for suspicious handle operations
 * - User-mode notification for critical events
 *
 * Thread Safety:
 * - All public functions are thread-safe
 * - Uses EX_RUNDOWN_REF for safe shutdown
 * - Lock ordering: RundownRef -> CacheLock -> PolicyLock -> ActivityLock
 *
 * @author ShadowStrike Security Team
 * @version 2.1.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_PROCESS_PROTECTION_H_
#define _SHADOWSTRIKE_PROCESS_PROTECTION_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <ntifs.h>
#include <wdm.h>

// ============================================================================
// POOL TAGS
// ============================================================================

#define PP_POOL_TAG                     'PPPS'  // Process Protection
#define PP_CONTEXT_TAG                  'xCPP'  // Context allocations
#define PP_POLICY_TAG                   'lPPP'  // Policy allocations
#define PP_TRACKER_TAG                  'tTPP'  // Activity tracker allocations
#define PP_STRING_TAG                   'rSPP'  // String allocations

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * @brief Maximum protected processes tracked in fast-path cache
 */
#define PP_MAX_CACHED_PROTECTED         64

/**
 * @brief Maximum process-specific access policies
 */
#define PP_MAX_ACCESS_POLICIES          32

/**
 * @brief Maximum handle operations to log per second (rate limiting)
 */
#define PP_MAX_LOG_RATE_PER_SEC         100

/**
 * @brief Threshold for suspicious handle activity (per source process)
 */
#define PP_SUSPICIOUS_HANDLE_THRESHOLD  50

/**
 * @brief Time window for handle activity tracking (100ns units = 10 seconds)
 */
#define PP_ACTIVITY_WINDOW_100NS        (10LL * 10000000LL)

/**
 * @brief Maximum CSRSS instances to track (one per session typically)
 */
#define PP_MAX_CSRSS_INSTANCES          16

/**
 * @brief Activity hash table size (must be power of 2)
 */
#define PP_ACTIVITY_HASH_SIZE           64

/**
 * @brief Maximum unique targets to track per source
 */
#define PP_MAX_TRACKED_TARGETS          16

// ============================================================================
// ACCESS MASKS FOR PROTECTION
// ============================================================================

/**
 * @brief Dangerous process access rights that enable termination
 */
#define PP_DANGEROUS_TERMINATE_ACCESS   \
    (PROCESS_TERMINATE)

/**
 * @brief Dangerous process access rights that enable code injection
 */
#define PP_DANGEROUS_INJECT_ACCESS      \
    (PROCESS_VM_WRITE |                 \
     PROCESS_VM_OPERATION |             \
     PROCESS_CREATE_THREAD)

/**
 * @brief Dangerous process access rights that enable control
 */
#define PP_DANGEROUS_CONTROL_ACCESS     \
    (PROCESS_SUSPEND_RESUME |           \
     PROCESS_SET_INFORMATION |          \
     PROCESS_SET_QUOTA)

/**
 * @brief Access rights commonly used for credential dumping
 */
#define PP_CREDENTIAL_DUMP_ACCESS       \
    (PROCESS_VM_READ |                  \
     PROCESS_QUERY_INFORMATION)

/**
 * @brief Access rights for debugging (anti-debug protection)
 */
#define PP_DEBUG_ACCESS                 \
    (PROCESS_ALL_ACCESS)

/**
 * @brief Full dangerous access mask (all of the above)
 */
#define PP_FULL_DANGEROUS_ACCESS        \
    (PP_DANGEROUS_TERMINATE_ACCESS |    \
     PP_DANGEROUS_INJECT_ACCESS |       \
     PP_DANGEROUS_CONTROL_ACCESS)

/**
 * @brief Safe read-only access mask
 */
#define PP_SAFE_READ_ACCESS             \
    (PROCESS_QUERY_LIMITED_INFORMATION |\
     SYNCHRONIZE)

/**
 * @brief LSASS-specific blocked access (credential protection)
 */
#define PP_LSASS_BLOCKED_ACCESS         \
    (PROCESS_VM_READ |                  \
     PROCESS_VM_WRITE |                 \
     PROCESS_VM_OPERATION |             \
     PROCESS_DUP_HANDLE |               \
     PROCESS_CREATE_THREAD |            \
     PROCESS_TERMINATE)

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Process protection level
 */
typedef enum _PP_PROTECTION_LEVEL {
    PpProtectionNone            = 0,    ///< No protection
    PpProtectionLight           = 1,    ///< Block terminate only
    PpProtectionMedium          = 2,    ///< Block terminate + inject
    PpProtectionStrict          = 3,    ///< Block all dangerous access
    PpProtectionCritical        = 4,    ///< Critical system process (CSRSS, LSASS)
    PpProtectionAntimalware     = 5     ///< Full EDR self-protection
} PP_PROTECTION_LEVEL;

/**
 * @brief Handle operation type for classification
 */
typedef enum _PP_OPERATION_TYPE {
    PpOperationUnknown          = 0,
    PpOperationCreate           = 1,    ///< NtOpenProcess
    PpOperationDuplicate        = 2,    ///< NtDuplicateObject
    PpOperationInherit          = 3     ///< Handle inheritance
} PP_OPERATION_TYPE;

/**
 * @brief Handle operation verdict
 */
typedef enum _PP_VERDICT {
    PpVerdictAllow              = 0,    ///< Allow with original access
    PpVerdictStrip              = 1,    ///< Allow with stripped access
    PpVerdictMonitor            = 2,    ///< Allow but log/alert
    PpVerdictBlock              = 3     ///< Block entirely (set access to 0)
} PP_VERDICT;

/**
 * @brief Suspicious activity indicators
 */
typedef enum _PP_SUSPICIOUS_FLAGS {
    PpSuspiciousNone                = 0x00000000,
    PpSuspiciousCredentialAccess    = 0x00000001,  ///< LSASS/SAM access pattern
    PpSuspiciousInjectionAttempt    = 0x00000002,  ///< VM_WRITE + CREATE_THREAD
    PpSuspiciousTerminationAttempt  = 0x00000004,  ///< Terminate protected process
    PpSuspiciousCrossSectionAccess  = 0x00000008,  ///< Cross-session handle access
    PpSuspiciousRapidEnumeration    = 0x00000010,  ///< Fast handle enumeration
    PpSuspiciousElevatedAccess      = 0x00000020,  ///< Non-admin accessing admin process
    PpSuspiciousDebugAttempt        = 0x00000040,  ///< Debug access to protected
    PpSuspiciousDuplicationChain    = 0x00000080,  ///< Handle duplication chain
    PpSuspiciousUnknownSource       = 0x00000100,  ///< Unknown/untrusted source process
    PpSuspiciousSelfProtectBypass   = 0x00000200   ///< Attempt to bypass self-protection
} PP_SUSPICIOUS_FLAGS;

/**
 * @brief Protected process category
 */
typedef enum _PP_PROCESS_CATEGORY {
    PpCategoryUnknown           = 0,
    PpCategorySystem            = 1,    ///< System, smss, csrss, etc.
    PpCategoryLsass             = 2,    ///< LSASS (credential protection)
    PpCategoryServices          = 3,    ///< services.exe, svchost.exe
    PpCategoryAntimalware       = 4,    ///< EDR/AV processes
    PpCategoryUserDefined       = 5     ///< Custom protected processes
} PP_PROCESS_CATEGORY;

/**
 * @brief Tracker reference state
 */
typedef enum _PP_TRACKER_STATE {
    PpTrackerStateActive        = 0,    ///< Tracker is active and in use
    PpTrackerStateRemoving      = 1,    ///< Tracker is being removed
    PpTrackerStateFreed         = 2     ///< Tracker has been freed
} PP_TRACKER_STATE;

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Per-process access policy
 */
typedef struct _PP_ACCESS_POLICY {
    LIST_ENTRY ListEntry;

    //
    // Target specification
    //
    HANDLE TargetProcessId;             ///< Specific PID or 0 for category
    PP_PROCESS_CATEGORY Category;       ///< Process category
    UNICODE_STRING ImageName;           ///< Image name pattern (optional)

    //
    // Policy settings
    //
    PP_PROTECTION_LEVEL ProtectionLevel;
    ACCESS_MASK DeniedAccess;           ///< Access rights to strip
    ACCESS_MASK AllowedAccess;          ///< Access rights to allow (whitelist)
    BOOLEAN BlockKernelHandles;         ///< Also filter kernel-mode handles
    BOOLEAN LogOnly;                    ///< Log but don't enforce

    //
    // Exemptions
    //
    HANDLE ExemptProcessIds[8];         ///< Processes exempt from this policy
    ULONG ExemptCount;

    //
    // Signature requirement for exemption
    //
    BOOLEAN RequireSignedExemption;     ///< Exempt process must be signed

    //
    // Statistics
    //
    volatile LONG64 TimesApplied;
    volatile LONG64 AccessStripped;

} PP_ACCESS_POLICY, *PPP_ACCESS_POLICY;

/**
 * @brief Handle operation context for analysis
 */
typedef struct _PP_OPERATION_CONTEXT {
    //
    // Operation details
    //
    PP_OPERATION_TYPE OperationType;
    BOOLEAN IsKernelHandle;

    //
    // Source process
    //
    HANDLE SourceProcessId;
    PEPROCESS SourceProcess;
    ULONG SourceSessionId;
    BOOLEAN SourceIsElevated;
    BOOLEAN SourceIsProtected;
    BOOLEAN SourceIsSigned;

    //
    // Target process
    //
    HANDLE TargetProcessId;
    PEPROCESS TargetProcess;
    ULONG TargetSessionId;
    PP_PROCESS_CATEGORY TargetCategory;
    PP_PROTECTION_LEVEL TargetProtectionLevel;

    //
    // Access details
    //
    ACCESS_MASK OriginalDesiredAccess;
    ACCESS_MASK ModifiedDesiredAccess;
    ACCESS_MASK StrippedAccess;

    //
    // Analysis results
    //
    PP_SUSPICIOUS_FLAGS SuspiciousFlags;
    ULONG SuspicionScore;
    PP_VERDICT Verdict;

    //
    // Timing
    //
    LARGE_INTEGER Timestamp;

} PP_OPERATION_CONTEXT, *PPP_OPERATION_CONTEXT;

/**
 * @brief Handle activity tracker (per source process)
 *
 * Uses reference counting for safe concurrent access.
 */
typedef struct _PP_ACTIVITY_TRACKER {
    LIST_ENTRY ListEntry;
    LIST_ENTRY HashEntry;

    //
    // Reference counting for safe access
    //
    volatile LONG ReferenceCount;
    volatile LONG State;                ///< PP_TRACKER_STATE

    HANDLE SourceProcessId;
    LARGE_INTEGER FirstActivity;
    LARGE_INTEGER LastActivity;

    volatile LONG HandleOperationCount;
    volatile LONG SuspiciousOperationCount;
    volatile LONG StrippedOperationCount;

    //
    // Target tracking (protected by dedicated spinlock)
    //
    KSPIN_LOCK TargetLock;
    ULONG UniqueTargetCount;
    HANDLE RecentTargets[PP_MAX_TRACKED_TARGETS];

    //
    // Flags (atomic access)
    //
    volatile LONG IsRateLimited;
    volatile LONG IsBlacklisted;

} PP_ACTIVITY_TRACKER, *PPP_ACTIVITY_TRACKER;

/**
 * @brief Critical process cache entry for fast lookup
 */
typedef struct _PP_CRITICAL_PROCESS_ENTRY {
    HANDLE ProcessId;
    PP_PROCESS_CATEGORY Category;
    PP_PROTECTION_LEVEL ProtectionLevel;
    ULONG Flags;
    LARGE_INTEGER CacheTime;            ///< When this entry was cached
} PP_CRITICAL_PROCESS_ENTRY, *PPP_CRITICAL_PROCESS_ENTRY;

/**
 * @brief Rate limiter state (lock-free)
 */
typedef struct _PP_RATE_LIMITER {
    volatile LONG64 CurrentSecondStart; ///< Aligned for atomic access
    volatile LONG CurrentSecondLogs;
} PP_RATE_LIMITER, *PPP_RATE_LIMITER;

/**
 * @brief Process protection state
 */
typedef struct _PP_PROTECTION_STATE {
    //
    // Initialization and shutdown
    //
    BOOLEAN Initialized;
    EX_RUNDOWN_REF RundownRef;          ///< For safe shutdown

    //
    // Critical process cache (fast path)
    //
    PP_CRITICAL_PROCESS_ENTRY CriticalProcessCache[PP_MAX_CACHED_PROTECTED];
    volatile LONG CriticalProcessCount;
    EX_PUSH_LOCK CacheLock;

    //
    // Access policies
    //
    LIST_ENTRY PolicyList;
    EX_PUSH_LOCK PolicyLock;
    volatile LONG PolicyCount;

    //
    // Activity tracking
    //
    LIST_ENTRY ActivityList;
    EX_PUSH_LOCK ActivityLock;
    volatile LONG ActiveTrackers;

    //
    // Hash table for activity lookup
    //
    LIST_ENTRY ActivityHashTable[PP_ACTIVITY_HASH_SIZE];

    //
    // Rate limiting (lock-free)
    //
    PP_RATE_LIMITER RateLimiter;

    //
    // Well-known PIDs (cached at init, validated on use)
    //
    HANDLE SystemPid;
    HANDLE LsassPid;
    HANDLE CsrssPids[PP_MAX_CSRSS_INSTANCES];
    volatile LONG CsrssCount;
    HANDLE ServicesPid;
    HANDLE WinlogonPid;

    //
    // Process notify callback handle
    //
    BOOLEAN ProcessNotifyRegistered;

    //
    // Statistics
    //
    struct {
        volatile LONG64 TotalOperations;
        volatile LONG64 ProtectedTargetOperations;
        volatile LONG64 AccessStripped;
        volatile LONG64 OperationsBlocked;
        volatile LONG64 CredentialAccessAttempts;
        volatile LONG64 InjectionAttempts;
        volatile LONG64 TerminationAttempts;
        volatile LONG64 DebugAttempts;
        volatile LONG64 CrossSessionAccess;
        volatile LONG64 SuspiciousOperations;
        volatile LONG64 RateLimitedOperations;
        volatile LONG64 PolicyMatches;
        volatile LONG64 NotificationsSent;
        LARGE_INTEGER StartTime;
    } Stats;

    //
    // Configuration
    //
    struct {
        BOOLEAN EnableCredentialProtection;     ///< LSASS protection
        BOOLEAN EnableInjectionProtection;      ///< VM_WRITE blocking
        BOOLEAN EnableTerminationProtection;    ///< Terminate blocking
        BOOLEAN EnableCrossSessionMonitoring;   ///< Cross-session detection
        BOOLEAN EnableActivityTracking;         ///< Per-process activity
        BOOLEAN EnableRateLimiting;             ///< Log rate limiting
        BOOLEAN EnableKernelHandleFiltering;    ///< Filter kernel handles too
        BOOLEAN EnablePolicyEnforcement;        ///< Use policy list
        BOOLEAN LogStrippedAccess;              ///< Log when access is stripped
        BOOLEAN NotifyUserMode;                 ///< Send notifications to user-mode
        BOOLEAN StrictLsassProtection;          ///< Block VM_READ on LSASS
        ULONG SuspicionScoreThreshold;          ///< Score to trigger alert
    } Config;

} PP_PROTECTION_STATE, *PPP_PROTECTION_STATE;

// ============================================================================
// FUNCTION PROTOTYPES - INITIALIZATION
// ============================================================================

/**
 * @brief Initialize process protection subsystem.
 *
 * Must be called before registering object callbacks.
 * Initializes caches, policies, and detects critical system processes.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
PpInitializeProcessProtection(
    VOID
    );

/**
 * @brief Shutdown process protection subsystem.
 *
 * Waits for all in-flight operations to complete.
 * Frees all resources. Must be called after unregistering object callbacks.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
PpShutdownProcessProtection(
    VOID
    );

// ============================================================================
// FUNCTION PROTOTYPES - CALLBACK
// ============================================================================

/**
 * @brief Process handle pre-operation callback.
 *
 * Core callback registered via ObRegisterCallbacks.
 * Analyzes handle operations and strips dangerous access rights.
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
PpProcessHandlePreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    );

// ============================================================================
// FUNCTION PROTOTYPES - PROTECTION MANAGEMENT
// ============================================================================

/**
 * @brief Add a process to the protection cache.
 *
 * @param ProcessId         Process ID to protect.
 * @param Category          Process category.
 * @param ProtectionLevel   Protection level to apply.
 *
 * @return STATUS_SUCCESS or STATUS_INSUFFICIENT_RESOURCES.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
PpAddProtectedProcess(
    _In_ HANDLE ProcessId,
    _In_ PP_PROCESS_CATEGORY Category,
    _In_ PP_PROTECTION_LEVEL ProtectionLevel
    );

/**
 * @brief Remove a process from the protection cache.
 *
 * @param ProcessId     Process ID to remove.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
PpRemoveProtectedProcess(
    _In_ HANDLE ProcessId
    );

/**
 * @brief Check if a process is in the protection cache.
 *
 * @param ProcessId         Process ID to check.
 * @param OutCategory       Receives category if protected.
 * @param OutProtectionLevel Receives protection level if protected.
 *
 * @return TRUE if protected.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
PpIsProcessProtected(
    _In_ HANDLE ProcessId,
    _Out_opt_ PP_PROCESS_CATEGORY* OutCategory,
    _Out_opt_ PP_PROTECTION_LEVEL* OutProtectionLevel
    );

/**
 * @brief Validate that a cached critical PID is still valid.
 *
 * @param ProcessId     Process ID to validate.
 * @param ExpectedName  Expected image name (e.g., L"lsass.exe").
 *
 * @return TRUE if the PID is still valid for the expected process.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
PpValidateCachedProcess(
    _In_ HANDLE ProcessId,
    _In_ PCWSTR ExpectedName
    );

// ============================================================================
// FUNCTION PROTOTYPES - POLICY MANAGEMENT
// ============================================================================

/**
 * @brief Add an access policy.
 *
 * @param Policy    Policy to add (will be copied).
 *
 * @return STATUS_SUCCESS or error.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
PpAddAccessPolicy(
    _In_ PPP_ACCESS_POLICY Policy
    );

/**
 * @brief Remove all policies for a process category.
 *
 * @param Category  Category to remove policies for.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
PpRemovePoliciesForCategory(
    _In_ PP_PROCESS_CATEGORY Category
    );

/**
 * @brief Find matching policy for an operation.
 *
 * @param Context   Operation context.
 * @param OutPolicy Receives matching policy (if found).
 *
 * @return TRUE if a matching policy was found.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
PpFindMatchingPolicy(
    _In_ PPP_OPERATION_CONTEXT Context,
    _Out_ PPP_ACCESS_POLICY OutPolicy
    );

// ============================================================================
// FUNCTION PROTOTYPES - CRITICAL PROCESS DETECTION
// ============================================================================

/**
 * @brief Detect and cache well-known critical system processes.
 *
 * Finds LSASS, CSRSS, services.exe, etc. and adds them to protection.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
PpDetectCriticalProcesses(
    VOID
    );

/**
 * @brief Classify a process by its image name.
 *
 * @param Process           EPROCESS pointer.
 * @param OutCategory       Receives process category.
 * @param OutProtectionLevel Receives recommended protection level.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
PpClassifyProcess(
    _In_ PEPROCESS Process,
    _Out_ PP_PROCESS_CATEGORY* OutCategory,
    _Out_ PP_PROTECTION_LEVEL* OutProtectionLevel
    );

// ============================================================================
// FUNCTION PROTOTYPES - ANALYSIS
// ============================================================================

/**
 * @brief Analyze a handle operation for suspicious activity.
 *
 * @param Context   Operation context to analyze (updated in place).
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
PpAnalyzeOperation(
    _Inout_ PPP_OPERATION_CONTEXT Context
    );

/**
 * @brief Determine verdict for a handle operation.
 *
 * @param Context   Analyzed operation context.
 *
 * @return Verdict (allow, strip, or block).
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
PP_VERDICT
PpDetermineVerdict(
    _In_ PPP_OPERATION_CONTEXT Context
    );

/**
 * @brief Calculate access mask to strip based on protection level.
 *
 * @param OriginalAccess    Requested access mask.
 * @param ProtectionLevel   Target's protection level.
 * @param Category          Target's category.
 *
 * @return Access mask with dangerous rights removed.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
ACCESS_MASK
PpCalculateAllowedAccess(
    _In_ ACCESS_MASK OriginalAccess,
    _In_ PP_PROTECTION_LEVEL ProtectionLevel,
    _In_ PP_PROCESS_CATEGORY Category
    );

// ============================================================================
// FUNCTION PROTOTYPES - ACTIVITY TRACKING
// ============================================================================

/**
 * @brief Track handle activity from a source process.
 *
 * @param SourceProcessId   Source process ID.
 * @param TargetProcessId   Target process ID.
 * @param IsSuspicious      Whether this operation is suspicious.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
PpTrackActivity(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ BOOLEAN IsSuspicious
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
PpIsSourceRateLimited(
    _In_ HANDLE SourceProcessId
    );

/**
 * @brief Clean up activity tracker for a terminated process.
 *
 * Called from process notify callback.
 *
 * @param ProcessId     Process ID that terminated.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
PpCleanupActivityTrackerForProcess(
    _In_ HANDLE ProcessId
    );

// ============================================================================
// FUNCTION PROTOTYPES - STATISTICS
// ============================================================================

/**
 * @brief Get process protection statistics.
 *
 * @param TotalOperations           Receives total operations.
 * @param AccessStripped            Receives stripped count.
 * @param CredentialAccessAttempts  Receives credential dump attempts.
 * @param InjectionAttempts         Receives injection attempts.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
PpGetStatistics(
    _Out_opt_ PULONG64 TotalOperations,
    _Out_opt_ PULONG64 AccessStripped,
    _Out_opt_ PULONG64 CredentialAccessAttempts,
    _Out_opt_ PULONG64 InjectionAttempts
    );

// ============================================================================
// INLINE HELPERS
// ============================================================================

/**
 * @brief Check if access mask contains dangerous injection rights.
 */
FORCEINLINE
BOOLEAN
PpAccessAllowsInjection(
    _In_ ACCESS_MASK Access
    )
{
    return (Access & PP_DANGEROUS_INJECT_ACCESS) != 0;
}

/**
 * @brief Check if access mask contains terminate right.
 */
FORCEINLINE
BOOLEAN
PpAccessAllowsTermination(
    _In_ ACCESS_MASK Access
    )
{
    return (Access & PROCESS_TERMINATE) != 0;
}

/**
 * @brief Check if access mask is typical for credential dumping.
 */
FORCEINLINE
BOOLEAN
PpAccessMatchesCredentialDump(
    _In_ ACCESS_MASK Access
    )
{
    //
    // Credential dumping typically requires VM_READ and QUERY_INFORMATION
    //
    return ((Access & PP_CREDENTIAL_DUMP_ACCESS) == PP_CREDENTIAL_DUMP_ACCESS);
}

/**
 * @brief Check if access is safe read-only.
 */
FORCEINLINE
BOOLEAN
PpAccessIsSafeReadOnly(
    _In_ ACCESS_MASK Access
    )
{
    //
    // Safe if no dangerous rights and only safe read rights
    //
    return ((Access & PP_FULL_DANGEROUS_ACCESS) == 0) &&
           ((Access & ~PP_SAFE_READ_ACCESS) == 0);
}

/**
 * @brief Safe string comparison for UNICODE_STRING (length-aware).
 *
 * Unlike wcsicmp, this respects the Length field and does not rely
 * on NULL termination.
 */
FORCEINLINE
BOOLEAN
PpSafeStringEndsWith(
    _In_ PCUNICODE_STRING String,
    _In_ PCUNICODE_STRING Suffix,
    _In_ BOOLEAN CaseInsensitive
    )
{
    UNICODE_STRING EndPart;

    if (String == NULL || Suffix == NULL ||
        String->Buffer == NULL || Suffix->Buffer == NULL) {
        return FALSE;
    }

    if (String->Length < Suffix->Length) {
        return FALSE;
    }

    EndPart.Length = Suffix->Length;
    EndPart.MaximumLength = Suffix->Length;
    EndPart.Buffer = (PWCH)((PUCHAR)String->Buffer +
                            (String->Length - Suffix->Length));

    return RtlEqualUnicodeString(&EndPart, Suffix, CaseInsensitive);
}

#ifdef __cplusplus
}
#endif

#endif // _SHADOWSTRIKE_PROCESS_PROTECTION_H_
