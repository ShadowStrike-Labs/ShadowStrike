/**
 * ============================================================================
 * ShadowStrike NGAV - EXCLUSION MANAGER
 * ============================================================================
 *
 * @file ExclusionManager.h
 * @brief Kernel-mode file and process exclusion management.
 *
 * Provides fast exclusion matching for:
 * - Path prefixes (e.g., C:\Windows\System32\*)
 * - File extensions (e.g., *.log, *.tmp)
 * - Process names (e.g., svchost.exe)
 * - Process IDs (runtime exclusions)
 *
 * Features:
 * - Hash-based lookups for O(1) extension/process matching
 * - Prefix tree for efficient path matching
 * - Thread-safe with reader-writer locks
 * - Dynamic add/remove at runtime
 * - Statistics tracking
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
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
 * @brief Maximum path length for exclusions.
 */
#define SHADOWSTRIKE_MAX_EXCLUSION_PATH_LENGTH  520

/**
 * @brief Maximum extension length (without dot).
 */
#define SHADOWSTRIKE_MAX_EXTENSION_LENGTH       16

/**
 * @brief Maximum process name length.
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
 */
typedef struct _SHADOWSTRIKE_PATH_EXCLUSION {
    /// @brief List linkage
    LIST_ENTRY ListEntry;

    /// @brief Exclusion path (normalized, uppercase)
    WCHAR Path[SHADOWSTRIKE_MAX_EXCLUSION_PATH_LENGTH];

    /// @brief Path length in characters
    USHORT PathLength;

    /// @brief Exclusion flags
    UINT8 Flags;

    /// @brief Reserved
    UINT8 Reserved;

    /// @brief Hit count
    volatile LONG HitCount;

    /// @brief Creation time
    LARGE_INTEGER CreateTime;

    /// @brief Expiration time (0 = never)
    LARGE_INTEGER ExpireTime;

} SHADOWSTRIKE_PATH_EXCLUSION, *PSHADOWSTRIKE_PATH_EXCLUSION;

/**
 * @brief Extension exclusion entry.
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

    /// @brief Reserved
    UINT8 Reserved;

    /// @brief Hit count
    volatile LONG HitCount;

} SHADOWSTRIKE_EXTENSION_EXCLUSION, *PSHADOWSTRIKE_EXTENSION_EXCLUSION;

/**
 * @brief Process name exclusion entry.
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

    /// @brief Reserved
    UINT8 Reserved;

    /// @brief Hit count
    volatile LONG HitCount;

} SHADOWSTRIKE_PROCESS_EXCLUSION, *PSHADOWSTRIKE_PROCESS_EXCLUSION;

/**
 * @brief Process ID exclusion entry.
 */
typedef struct _SHADOWSTRIKE_PID_EXCLUSION {
    /// @brief Process ID
    HANDLE ProcessId;

    /// @brief Valid flag
    BOOLEAN Valid;

    /// @brief Reserved
    UINT8 Reserved[3];

    /// @brief Hit count
    volatile LONG HitCount;

    /// @brief Expiration time (0 = until process exits)
    LARGE_INTEGER ExpireTime;

} SHADOWSTRIKE_PID_EXCLUSION, *PSHADOWSTRIKE_PID_EXCLUSION;

/**
 * @brief Extension hash bucket.
 */
typedef struct _SHADOWSTRIKE_EXTENSION_BUCKET {
    /// @brief List head
    LIST_ENTRY ListHead;

    /// @brief Entry count
    volatile LONG EntryCount;

} SHADOWSTRIKE_EXTENSION_BUCKET, *PSHADOWSTRIKE_EXTENSION_BUCKET;

/**
 * @brief Process name hash bucket.
 */
typedef struct _SHADOWSTRIKE_PROCESS_BUCKET {
    /// @brief List head
    LIST_ENTRY ListHead;

    /// @brief Entry count
    volatile LONG EntryCount;

} SHADOWSTRIKE_PROCESS_BUCKET, *PSHADOWSTRIKE_PROCESS_BUCKET;

/**
 * @brief Exclusion statistics.
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

    /// @brief Current path exclusion count
    volatile LONG PathExclusionCount;

    /// @brief Current extension exclusion count
    volatile LONG ExtensionExclusionCount;

    /// @brief Current process exclusion count
    volatile LONG ProcessExclusionCount;

    /// @brief Current PID exclusion count
    volatile LONG PidExclusionCount;

} SHADOWSTRIKE_EXCLUSION_STATS, *PSHADOWSTRIKE_EXCLUSION_STATS;

/**
 * @brief Main exclusion manager structure.
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

    /// @brief Statistics
    SHADOWSTRIKE_EXCLUSION_STATS Stats;

    /// @brief Manager initialized
    BOOLEAN Initialized;

    /// @brief Exclusions enabled
    BOOLEAN Enabled;

    /// @brief Reserved
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
 */
NTSTATUS
ShadowStrikeExclusionInitialize(
    VOID
    );

/**
 * @brief Shutdown the exclusion manager.
 */
VOID
ShadowStrikeExclusionShutdown(
    VOID
    );

/**
 * @brief Check if a file path is excluded.
 *
 * Checks path prefix and extension exclusions.
 *
 * @param FilePath      Full file path to check.
 * @param Extension     File extension (optional, extracted if NULL).
 * @return TRUE if excluded, FALSE otherwise.
 */
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
 * @param ProcessName   Process name (optional).
 * @return TRUE if excluded, FALSE otherwise.
 */
BOOLEAN
ShadowStrikeIsProcessExcluded(
    _In_ HANDLE ProcessId,
    _In_opt_ PCUNICODE_STRING ProcessName
    );

/**
 * @brief Check if an extension is excluded.
 *
 * @param Extension     Extension to check (without dot).
 * @return TRUE if excluded, FALSE otherwise.
 */
BOOLEAN
ShadowStrikeIsExtensionExcluded(
    _In_ PCUNICODE_STRING Extension
    );

/**
 * @brief Add a path exclusion.
 *
 * @param Path      Path to exclude (can end with * for prefix).
 * @param Flags     Exclusion flags.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ShadowStrikeAddPathExclusion(
    _In_ PCUNICODE_STRING Path,
    _In_ UINT8 Flags
    );

/**
 * @brief Remove a path exclusion.
 *
 * @param Path      Path to remove.
 * @return TRUE if found and removed.
 */
BOOLEAN
ShadowStrikeRemovePathExclusion(
    _In_ PCUNICODE_STRING Path
    );

/**
 * @brief Add an extension exclusion.
 *
 * @param Extension     Extension to exclude (without dot).
 * @param Flags         Exclusion flags.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ShadowStrikeAddExtensionExclusion(
    _In_ PCUNICODE_STRING Extension,
    _In_ UINT8 Flags
    );

/**
 * @brief Remove an extension exclusion.
 *
 * @param Extension     Extension to remove.
 * @return TRUE if found and removed.
 */
BOOLEAN
ShadowStrikeRemoveExtensionExclusion(
    _In_ PCUNICODE_STRING Extension
    );

/**
 * @brief Add a process name exclusion.
 *
 * @param ProcessName   Process name to exclude.
 * @param Flags         Exclusion flags.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ShadowStrikeAddProcessExclusion(
    _In_ PCUNICODE_STRING ProcessName,
    _In_ UINT8 Flags
    );

/**
 * @brief Remove a process name exclusion.
 *
 * @param ProcessName   Process name to remove.
 * @return TRUE if found and removed.
 */
BOOLEAN
ShadowStrikeRemoveProcessExclusion(
    _In_ PCUNICODE_STRING ProcessName
    );

/**
 * @brief Add a PID exclusion.
 *
 * @param ProcessId     Process ID to exclude.
 * @param TTLSeconds    Time to live (0 = until process exits).
 * @return STATUS_SUCCESS on success.
 */
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
 */
BOOLEAN
ShadowStrikeRemovePidExclusion(
    _In_ HANDLE ProcessId
    );

/**
 * @brief Clear all exclusions of a specific type.
 *
 * @param Type      Exclusion type to clear.
 */
VOID
ShadowStrikeClearExclusions(
    _In_ SHADOWSTRIKE_EXCLUSION_TYPE Type
    );

/**
 * @brief Get exclusion statistics.
 *
 * @param Stats     Receives current statistics.
 */
VOID
ShadowStrikeExclusionGetStats(
    _Out_ PSHADOWSTRIKE_EXCLUSION_STATS Stats
    );

/**
 * @brief Reset exclusion statistics.
 */
VOID
ShadowStrikeExclusionResetStats(
    VOID
    );

/**
 * @brief Load default system exclusions.
 *
 * Adds exclusions for Windows system directories, etc.
 */
VOID
ShadowStrikeLoadDefaultExclusions(
    VOID
    );

/**
 * @brief Enable or disable exclusion checking.
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

// ============================================================================
// INLINE HELPERS
// ============================================================================

/**
 * @brief Calculate hash for extension lookup.
 */
FORCEINLINE
ULONG
ShadowStrikeExtensionHash(
    _In_ PCUNICODE_STRING Extension
    )
{
    ULONG hash = 0;
    USHORT i;

    for (i = 0; i < Extension->Length / sizeof(WCHAR); i++) {
        WCHAR ch = RtlUpcaseUnicodeChar(Extension->Buffer[i]);
        hash = hash * 31 + ch;
    }

    return hash % SHADOWSTRIKE_EXTENSION_HASH_BUCKETS;
}

/**
 * @brief Calculate hash for process name lookup.
 */
FORCEINLINE
ULONG
ShadowStrikeProcessNameHash(
    _In_ PCUNICODE_STRING ProcessName
    )
{
    ULONG hash = 0;
    USHORT i;

    for (i = 0; i < ProcessName->Length / sizeof(WCHAR); i++) {
        WCHAR ch = RtlUpcaseUnicodeChar(ProcessName->Buffer[i]);
        hash = hash * 31 + ch;
    }

    return hash % SHADOWSTRIKE_PROCESS_HASH_BUCKETS;
}

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_EXCLUSION_MANAGER_H
