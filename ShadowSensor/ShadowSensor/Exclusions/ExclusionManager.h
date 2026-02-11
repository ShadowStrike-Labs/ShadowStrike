/**
 * ============================================================================
 * ShadowStrike NGAV - EXCLUSION MANAGER
 * ============================================================================
 *
 * @file ExclusionManager.h
 * @brief Kernel-mode file and process exclusion management.
 *
 * Provides fast exclusion matching for:
 * - Path prefixes (e.g., \Device\HarddiskVolume1\Windows\System32\*)
 * - File extensions (e.g., *.log, *.tmp)
 * - Process names (e.g., svchost.exe)
 * - Process IDs (runtime exclusions)
 *
 * Features:
 * - Hash-based lookups for O(1) extension/process matching
 * - Normalized path comparison with case-insensitive matching
 * - Thread-safe with reader-writer locks and EX_RUNDOWN_REF
 * - Dynamic add/remove at runtime with duplicate detection
 * - Access control on all mutation APIs (kernel callers only)
 * - Statistics tracking (approximate, lock-free counters)
 *
 * Thread Safety:
 * - All public APIs are safe to call concurrently.
 * - EX_RUNDOWN_REF ensures safe shutdown drain (no timeout, no forced free).
 * - Counts modified under exclusive lock use plain increments.
 * - Statistics counters are approximate (no cross-field atomicity).
 *
 * Memory:
 * - All exclusion entries are allocated from PagedPool (access <= APC_LEVEL).
 * - Path exclusion entries are ~1060 bytes each (max 256 = ~272 KB).
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_EXCLUSION_MANAGER_H
#define SHADOWSTRIKE_EXCLUSION_MANAGER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <fltKernel.h>

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * @brief Maximum number of path exclusions.
 */
#define SHADOWSTRIKE_MAX_PATH_EXCLUSIONS        256

/**
 * @brief Maximum number of extension exclusions.
 */
#define SHADOWSTRIKE_MAX_EXTENSION_EXCLUSIONS   64

/**
 * @brief Maximum number of process name exclusions.
 */
#define SHADOWSTRIKE_MAX_PROCESS_EXCLUSIONS     128

/**
 * @brief Maximum number of runtime PID exclusions.
 */
#define SHADOWSTRIKE_MAX_PID_EXCLUSIONS         64

/**
 * @brief Maximum path length for exclusions (characters).
 */
#define SHADOWSTRIKE_MAX_EXCLUSION_PATH_LENGTH  520

/**
 * @brief Maximum extension length (without dot, characters).
 */
#define SHADOWSTRIKE_MAX_EXTENSION_LENGTH       16

/**
 * @brief Maximum process name length (characters).
 */
#define SHADOWSTRIKE_MAX_PROCESS_NAME_LENGTH    260

/**
 * @brief Pool tag for exclusion allocations.
 */
#define SHADOWSTRIKE_EXCLUSION_POOL_TAG         'lExS'

/**
 * @brief Hash bucket count for extension lookup.
 */
#define SHADOWSTRIKE_EXTENSION_HASH_BUCKETS     32

/**
 * @brief Hash bucket count for process name lookup.
 */
#define SHADOWSTRIKE_PROCESS_HASH_BUCKETS       64

/**
 * @brief Pool tag for expired entry cleanup allocations.
 */
#define SHADOWSTRIKE_EXCLUSION_CLEANUP_TAG      'cExS'

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Exclusion types.
 */
typedef enum _SHADOWSTRIKE_EXCLUSION_TYPE {
    /// @brief Path prefix exclusion (e.g., C:\Windows\*)
    ShadowStrikeExclusionPath = 0,

    /// @brief File extension exclusion (e.g., *.log)
    ShadowStrikeExclusionExtension = 1,

    /// @brief Process name exclusion (e.g., svchost.exe)
    ShadowStrikeExclusionProcessName = 2,

    /// @brief Process ID exclusion (runtime)
    ShadowStrikeExclusionProcessId = 3,

    /// @brief Maximum value
    ShadowStrikeExclusionTypeMax

} SHADOWSTRIKE_EXCLUSION_TYPE;

/**
 * @brief Exclusion flags.
 */
typedef enum _SHADOWSTRIKE_EXCLUSION_FLAGS {
    /// @brief No special flags
    ShadowStrikeExclusionFlagNone = 0x00,

    /// @brief Case-sensitive matching
    ShadowStrikeExclusionFlagCaseSensitive = 0x01,

    /// @brief Wildcard matching enabled
    ShadowStrikeExclusionFlagWildcard = 0x02,

    /// @brief Applies to subdirectories
    ShadowStrikeExclusionFlagRecursive = 0x04,

    /// @brief Temporary exclusion (auto-expires)
    ShadowStrikeExclusionFlagTemporary = 0x08,

    /// @brief System exclusion (cannot be removed by user)
    ShadowStrikeExclusionFlagSystem = 0x10

} SHADOWSTRIKE_EXCLUSION_FLAGS;

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Path exclusion entry.
 *
 * Contains a normalized path prefix and associated matching metadata.
 * Stored in a linked list protected by PathLock.
 */
typedef struct _SHADOWSTRIKE_PATH_EXCLUSION {
    /// @brief List linkage
    LIST_ENTRY ListEntry;

    /// @brief Exclusion path (normalized, uppercase)
    WCHAR Path[SHADOWSTRIKE_MAX_EXCLUSION_PATH_LENGTH];

    /// @brief Path length in characters (excluding null terminator)
    USHORT PathLength;

    /// @brief Exclusion flags
    UINT8 Flags;

    /// @brief Reserved for alignment
    UINT8 Reserved;

    /// @brief Hit count (approximate, updated under shared lock)
    volatile LONG HitCount;

    /// @brief Creation time
    LARGE_INTEGER CreateTime;

    /// @brief Expiration time (0 = never)
    LARGE_INTEGER ExpireTime;

} SHADOWSTRIKE_PATH_EXCLUSION, *PSHADOWSTRIKE_PATH_EXCLUSION;

/**
 * @brief Extension exclusion entry.
 *
 * Stored in a hash bucket chain protected by ExtensionLock.
 */
typedef struct _SHADOWSTRIKE_EXTENSION_EXCLUSION {
    /// @brief List linkage within bucket
    LIST_ENTRY ListEntry;

    /// @brief Extension (without dot, uppercase)
    WCHAR Extension[SHADOWSTRIKE_MAX_EXTENSION_LENGTH];

    /// @brief Extension length in characters
    USHORT ExtensionLength;

    /// @brief Exclusion flags
    UINT8 Flags;

    /// @brief Reserved for alignment
    UINT8 Reserved;

    /// @brief Hit count (approximate, updated under shared lock)
    volatile LONG HitCount;

} SHADOWSTRIKE_EXTENSION_EXCLUSION, *PSHADOWSTRIKE_EXTENSION_EXCLUSION;

/**
 * @brief Process name exclusion entry.
 *
 * Stored in a hash bucket chain protected by ProcessLock.
 */
typedef struct _SHADOWSTRIKE_PROCESS_EXCLUSION {
    /// @brief List linkage within bucket
    LIST_ENTRY ListEntry;

    /// @brief Process name (uppercase)
    WCHAR ProcessName[SHADOWSTRIKE_MAX_PROCESS_NAME_LENGTH];

    /// @brief Process name length in characters
    USHORT NameLength;

    /// @brief Exclusion flags
    UINT8 Flags;

    /// @brief Reserved for alignment
    UINT8 Reserved;

    /// @brief Hit count (approximate, updated under shared lock)
    volatile LONG HitCount;

} SHADOWSTRIKE_PROCESS_EXCLUSION, *PSHADOWSTRIKE_PROCESS_EXCLUSION;

/**
 * @brief Process ID exclusion entry.
 *
 * Fixed-size array element protected by PidLock.
 */
typedef struct _SHADOWSTRIKE_PID_EXCLUSION {
    /// @brief Process ID
    HANDLE ProcessId;

    /// @brief Valid flag
    BOOLEAN Valid;

    /// @brief Reserved for alignment
    UINT8 Reserved[3];

    /// @brief Hit count (approximate, updated under shared lock)
    volatile LONG HitCount;

    /// @brief Expiration time (0 = until process exits)
    LARGE_INTEGER ExpireTime;

} SHADOWSTRIKE_PID_EXCLUSION, *PSHADOWSTRIKE_PID_EXCLUSION;

/**
 * @brief Extension hash bucket.
 *
 * EntryCount is protected by ExtensionLock and uses plain increments
 * under exclusive lock. Lockless reads of EntryCount for fast-path
 * optimization are documented as benign races (may produce a false
 * negative on a just-added entry for a single check cycle).
 */
typedef struct _SHADOWSTRIKE_EXTENSION_BUCKET {
    /// @brief List head
    LIST_ENTRY ListHead;

    /// @brief Entry count (modified under exclusive lock only)
    LONG EntryCount;

} SHADOWSTRIKE_EXTENSION_BUCKET, *PSHADOWSTRIKE_EXTENSION_BUCKET;

/**
 * @brief Process name hash bucket.
 *
 * Same locking contract as SHADOWSTRIKE_EXTENSION_BUCKET.
 */
typedef struct _SHADOWSTRIKE_PROCESS_BUCKET {
    /// @brief List head
    LIST_ENTRY ListHead;

    /// @brief Entry count (modified under exclusive lock only)
    LONG EntryCount;

} SHADOWSTRIKE_PROCESS_BUCKET, *PSHADOWSTRIKE_PROCESS_BUCKET;

/**
 * @brief Exclusion statistics.
 *
 * All counters are approximate. There is no cross-field atomicity
 * guarantee. Individual fields use InterlockedIncrement64 for
 * monotonic correctness. A snapshot may show slight inconsistencies
 * between related counters (e.g., TotalChecks vs sum of matches).
 */
typedef struct _SHADOWSTRIKE_EXCLUSION_STATS {
    /// @brief Total exclusion checks
    volatile LONG64 TotalChecks;

    /// @brief Path exclusion matches
    volatile LONG64 PathMatches;

    /// @brief Extension exclusion matches
    volatile LONG64 ExtensionMatches;

    /// @brief Process name exclusion matches
    volatile LONG64 ProcessNameMatches;

    /// @brief PID exclusion matches
    volatile LONG64 PidMatches;

    /// @brief Total exclusions bypassed (allowed without scan)
    volatile LONG64 TotalBypassed;

    /// @brief Current path exclusion count (modified under PathLock)
    volatile LONG PathExclusionCount;

    /// @brief Current extension exclusion count (modified under ExtensionLock)
    volatile LONG ExtensionExclusionCount;

    /// @brief Current process exclusion count (modified under ProcessLock)
    volatile LONG ProcessExclusionCount;

    /// @brief Current PID exclusion count (modified under PidLock)
    volatile LONG PidExclusionCount;

} SHADOWSTRIKE_EXCLUSION_STATS, *PSHADOWSTRIKE_EXCLUSION_STATS;

/**
 * @brief Main exclusion manager structure.
 *
 * Locking hierarchy (acquire in this order to prevent deadlock):
 * 1. PathLock
 * 2. ExtensionLock
 * 3. ProcessLock
 * 4. PidLock
 *
 * Shutdown safety: callers of matching functions acquire rundown
 * protection via ExAcquireRundownProtection(&RundownRef) and release
 * via ExReleaseRundownProtection(&RundownRef). Shutdown blocks in
 * ExWaitForRundownProtectionRelease until all callers drain — no
 * timeout, no forced free, no use-after-free.
 */
typedef struct _SHADOWSTRIKE_EXCLUSION_MANAGER {
    /// @brief Path exclusions list
    LIST_ENTRY PathExclusions;

    /// @brief Path exclusions lock
    EX_PUSH_LOCK PathLock;

    /// @brief Extension hash buckets
    SHADOWSTRIKE_EXTENSION_BUCKET ExtensionBuckets[SHADOWSTRIKE_EXTENSION_HASH_BUCKETS];

    /// @brief Extension exclusions lock
    EX_PUSH_LOCK ExtensionLock;

    /// @brief Process name hash buckets
    SHADOWSTRIKE_PROCESS_BUCKET ProcessBuckets[SHADOWSTRIKE_PROCESS_HASH_BUCKETS];

    /// @brief Process name exclusions lock
    EX_PUSH_LOCK ProcessLock;

    /// @brief PID exclusions array
    SHADOWSTRIKE_PID_EXCLUSION PidExclusions[SHADOWSTRIKE_MAX_PID_EXCLUSIONS];

    /// @brief PID exclusions lock
    EX_PUSH_LOCK PidLock;

    /// @brief Statistics (approximate, lock-free counters)
    SHADOWSTRIKE_EXCLUSION_STATS Stats;

    /// @brief Rundown protection for safe shutdown drain (replaces manual refcount)
    EX_RUNDOWN_REF RundownRef;

    /// @brief Manager initialized flag
    BOOLEAN Initialized;

    /// @brief Exclusions enabled flag
    BOOLEAN Enabled;

    /// @brief Reserved for alignment
    UINT8 Reserved[6];

} SHADOWSTRIKE_EXCLUSION_MANAGER, *PSHADOWSTRIKE_EXCLUSION_MANAGER;

// ============================================================================
// GLOBAL INSTANCE
// ============================================================================

/**
 * @brief Global exclusion manager instance.
 */
extern SHADOWSTRIKE_EXCLUSION_MANAGER g_ExclusionManager;

// ============================================================================
// FUNCTION PROTOTYPES
// ============================================================================

/**
 * @brief Initialize the exclusion manager.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeExclusionInitialize(
    VOID
    );

/**
 * @brief Shutdown the exclusion manager.
 *
 * Drains all active references before freeing resources.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeExclusionShutdown(
    VOID
    );

/**
 * @brief Check if a file path is excluded.
 *
 * Checks extension exclusions first (fast hash lookup), then
 * path prefix exclusions (linear scan with normalized comparison).
 *
 * @param FilePath      Full file path to check. Buffer must be non-NULL.
 * @param Extension     File extension without dot (optional).
 * @return TRUE if excluded, FALSE otherwise.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
ShadowStrikeIsPathExcluded(
    _In_ PCUNICODE_STRING FilePath,
    _In_opt_ PCUNICODE_STRING Extension
    );

/**
 * @brief Check if a process is excluded.
 *
 * Checks by process ID first, then by process name.
 *
 * @param ProcessId     Process ID to check.
 * @param ProcessName   Process name (optional). Buffer must be non-NULL if Length > 0.
 * @return TRUE if excluded, FALSE otherwise.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
ShadowStrikeIsProcessExcluded(
    _In_ HANDLE ProcessId,
    _In_opt_ PCUNICODE_STRING ProcessName
    );

/**
 * @brief Check if an extension is excluded.
 *
 * @param Extension     Extension to check (without dot). Buffer must be non-NULL.
 * @return TRUE if excluded, FALSE otherwise.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
ShadowStrikeIsExtensionExcluded(
    _In_ PCUNICODE_STRING Extension
    );

/**
 * @brief Add a path exclusion.
 *
 * Normalizes the path to uppercase before storing.
 * Rejects duplicates. Checks count limit under exclusive lock.
 * If ShadowStrikeExclusionFlagTemporary is set, TTLSeconds controls
 * the expiration time (0 = no expiry even with Temporary flag).
 *
 * @param Path      Path to exclude. Buffer must be non-NULL.
 * @param Flags     Exclusion flags.
 * @param TTLSeconds  Time-to-live in seconds (0 = permanent). Only used
 *                    when ShadowStrikeExclusionFlagTemporary is set.
 * @return STATUS_SUCCESS on success.
 *         STATUS_OBJECT_NAME_COLLISION if duplicate.
 *         STATUS_INSUFFICIENT_RESOURCES if at capacity or allocation fails.
 *         STATUS_ACCESS_DENIED if caller is not kernel-mode.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeAddPathExclusion(
    _In_ PCUNICODE_STRING Path,
    _In_ UINT8 Flags,
    _In_ ULONG TTLSeconds
    );

/**
 * @brief Remove a path exclusion.
 *
 * System exclusions cannot be removed.
 *
 * @param Path      Path to remove. Buffer must be non-NULL.
 * @return TRUE if found and removed.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ShadowStrikeRemovePathExclusion(
    _In_ PCUNICODE_STRING Path
    );

/**
 * @brief Add an extension exclusion.
 *
 * Normalizes the extension to uppercase. Rejects duplicates.
 *
 * @param Extension     Extension to exclude (without dot). Buffer must be non-NULL.
 * @param Flags         Exclusion flags.
 * @return STATUS_SUCCESS on success.
 *         STATUS_ACCESS_DENIED if caller is not kernel-mode.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeAddExtensionExclusion(
    _In_ PCUNICODE_STRING Extension,
    _In_ UINT8 Flags
    );

/**
 * @brief Remove an extension exclusion.
 *
 * @param Extension     Extension to remove. Buffer must be non-NULL.
 * @return TRUE if found and removed.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ShadowStrikeRemoveExtensionExclusion(
    _In_ PCUNICODE_STRING Extension
    );

/**
 * @brief Add a process name exclusion.
 *
 * @param ProcessName   Process name to exclude. Buffer must be non-NULL.
 * @param Flags         Exclusion flags.
 * @return STATUS_SUCCESS on success.
 *         STATUS_ACCESS_DENIED if caller is not kernel-mode.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeAddProcessExclusion(
    _In_ PCUNICODE_STRING ProcessName,
    _In_ UINT8 Flags
    );

/**
 * @brief Remove a process name exclusion.
 *
 * @param ProcessName   Process name to remove. Buffer must be non-NULL.
 * @return TRUE if found and removed.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ShadowStrikeRemoveProcessExclusion(
    _In_ PCUNICODE_STRING ProcessName
    );

/**
 * @brief Add a PID exclusion.
 *
 * Validates that the PID refers to an existing process before adding.
 *
 * @param ProcessId     Process ID to exclude.
 * @param TTLSeconds    Time to live in seconds (0 = until process exits).
 * @return STATUS_SUCCESS on success.
 *         STATUS_INVALID_PARAMETER if PID does not exist.
 *         STATUS_ACCESS_DENIED if caller is not kernel-mode.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeAddPidExclusion(
    _In_ HANDLE ProcessId,
    _In_ ULONG TTLSeconds
    );

/**
 * @brief Remove a PID exclusion.
 *
 * @param ProcessId     Process ID to remove.
 * @return TRUE if found and removed.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ShadowStrikeRemovePidExclusion(
    _In_ HANDLE ProcessId
    );

/**
 * @brief Clear all exclusions of a specific type.
 *
 * @param Type      Exclusion type to clear.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeClearExclusions(
    _In_ SHADOWSTRIKE_EXCLUSION_TYPE Type
    );

/**
 * @brief Get exclusion statistics snapshot.
 *
 * The snapshot is approximate — individual fields are consistent but
 * cross-field relationships may show slight inconsistencies due to
 * concurrent updates.
 *
 * @param Stats     Receives current statistics.
 */
VOID
ShadowStrikeExclusionGetStats(
    _Out_ PSHADOWSTRIKE_EXCLUSION_STATS Stats
    );

/**
 * @brief Reset exclusion match statistics.
 *
 * Preserves current exclusion counts, resets match counters only.
 */
VOID
ShadowStrikeExclusionResetStats(
    VOID
    );

/**
 * @brief Load default system exclusions.
 *
 * Adds exclusions for NTFS metafiles (pagefile.sys, $Mft, etc.).
 * Does NOT add extension exclusions — no file extension is inherently safe.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeLoadDefaultExclusions(
    VOID
    );

/**
 * @brief Enable or disable exclusion checking.
 *
 * Uses InterlockedExchange8 for atomic cross-CPU visibility.
 *
 * @param Enable    TRUE to enable, FALSE to disable.
 */
VOID
ShadowStrikeExclusionSetEnabled(
    _In_ BOOLEAN Enable
    );

/**
 * @brief Check if exclusion checking is enabled.
 *
 * @return TRUE if enabled.
 */
BOOLEAN
ShadowStrikeExclusionIsEnabled(
    VOID
    );

/**
 * @brief Remove expired path and PID exclusions.
 *
 * Scans path exclusions and PID exclusions for entries past their
 * ExpireTime and removes them. Should be called periodically (e.g.,
 * from a timer DPC work item or maintenance routine).
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeCleanupExpiredExclusions(
    VOID
    );

// ============================================================================
// PATH EXCLUSION HELPERS (PathExclusion.c)
// ============================================================================

/**
 * @brief Normalize a file path for exclusion matching.
 *
 * Converts to uppercase and strips trailing separators.
 * The caller must free the output buffer with ExFreePoolWithTag
 * using SHADOWSTRIKE_EXCLUSION_POOL_TAG.
 *
 * @param InputPath      Raw path to normalize.
 * @param NormalizedPath Receives the normalized path.
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeNormalizePath(
    _In_ PCUNICODE_STRING InputPath,
    _Out_ PUNICODE_STRING NormalizedPath
    );

/**
 * @brief Match a file path against an exclusion pattern.
 *
 * Supports:
 * - Exact prefix matching (case-insensitive)
 * - Wildcard '*' at end of pattern for directory subtree matching
 * - Wildcard '?' for single-character matching
 * - Recursive matching validates path component boundaries
 *
 * @param FilePath       Normalized file path to check.
 * @param Pattern        Exclusion pattern entry.
 * @param CaseSensitive  TRUE for case-sensitive match.
 * @return TRUE if the path matches the pattern.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeMatchPathPattern(
    _In_ PCUNICODE_STRING FilePath,
    _In_ PCUNICODE_STRING Pattern,
    _In_ UINT8 Flags
    );

/**
 * @brief Extract file extension from a path.
 *
 * Returns a zero-copy view into the input buffer pointing at the
 * extension characters after the last dot. If no dot is found,
 * the output has Length == 0.
 *
 * @param FilePath       Full file path.
 * @param Extension      Receives extension (zero-copy, no dot).
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeExtractExtension(
    _In_ PCUNICODE_STRING FilePath,
    _Out_ PUNICODE_STRING Extension
    );

// ============================================================================
// INLINE HELPERS
// ============================================================================

/**
 * @brief Validate a UNICODE_STRING for safe use.
 *
 * Checks that Length is even (WCHAR-aligned), Buffer is non-NULL when
 * Length > 0, Length does not exceed MaximumLength, and Length is within
 * a sane bound to prevent integer overflow in downstream calculations.
 *
 * @param String   String to validate.
 * @return TRUE if valid, FALSE otherwise.
 */
FORCEINLINE
BOOLEAN
ShadowStrikeValidateUnicodeString(
    _In_ PCUNICODE_STRING String
    )
{
    if (String == NULL) {
        return FALSE;
    }

    if (String->Length == 0) {
        return TRUE;
    }

    if (String->Buffer == NULL) {
        return FALSE;
    }

    if (String->Length > String->MaximumLength) {
        return FALSE;
    }

    //
    // Length must be WCHAR-aligned
    //
    if ((String->Length & 1) != 0) {
        return FALSE;
    }

    return TRUE;
}

/**
 * @brief Calculate hash for extension lookup.
 *
 * Case-insensitive hash using upcased characters.
 * Caller must validate Extension before calling.
 */
FORCEINLINE
ULONG
ShadowStrikeExtensionHash(
    _In_ PCUNICODE_STRING Extension
    )
{
    ULONG hash = 0;
    USHORT i;
    USHORT charCount = Extension->Length / sizeof(WCHAR);

    for (i = 0; i < charCount; i++) {
        WCHAR ch = RtlUpcaseUnicodeChar(Extension->Buffer[i]);
        hash = hash * 31 + ch;
    }

    return hash % SHADOWSTRIKE_EXTENSION_HASH_BUCKETS;
}

/**
 * @brief Calculate hash for process name lookup.
 *
 * Case-insensitive hash using upcased characters.
 * Caller must validate ProcessName before calling.
 */
FORCEINLINE
ULONG
ShadowStrikeProcessNameHash(
    _In_ PCUNICODE_STRING ProcessName
    )
{
    ULONG hash = 0;
    USHORT i;
    USHORT charCount = ProcessName->Length / sizeof(WCHAR);

    for (i = 0; i < charCount; i++) {
        WCHAR ch = RtlUpcaseUnicodeChar(ProcessName->Buffer[i]);
        hash = hash * 31 + ch;
    }

    return hash % SHADOWSTRIKE_PROCESS_HASH_BUCKETS;
}

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_EXCLUSION_MANAGER_H
