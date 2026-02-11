/**
 * ============================================================================
 * ShadowStrike NGAV - SELF-PROTECTION HEADER
 * ============================================================================
 *
 * @file SelfProtect.h
 * @brief Self-protection definitions and structures.
 *
 * Without ELAM (Early Launch Anti-Malware) certificate, we rely on:
 * 1. ObRegisterCallbacks - Strip dangerous access rights from handles
 * 2. File system protection - Block writes to AV binaries
 * 3. Registry protection - Block changes to AV service keys
 *
 * IRQL SAFETY:
 * - ObCallbacks fire at IRQL <= DISPATCH_LEVEL.
 * - All lookups use EX_SPIN_LOCK (reader/writer safe at DISPATCH_LEVEL).
 * - Push locks are NOT used anywhere in this module.
 * - Paged functions (Init/Shutdown/Protect/Unprotect/Add*) run at PASSIVE_LEVEL.
 *
 * LIFECYCLE:
 * - volatile LONG Initialized / ShuttingDown / ActiveOperations
 * - Drain mechanism (KEVENT DrainEvent) ensures no in-flight callbacks
 *   access freed data during shutdown.
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SELFPROTECT_H
#define SELFPROTECT_H

#include <ntifs.h>
#include <fltKernel.h>
#include <ntstrsafe.h>

// ============================================================================
// POOL TAGS
// ============================================================================

#define SSSP_POOL_TAG_PROCESS   'pPsS'  // SsP process entries
#define SSSP_POOL_TAG_GENERAL   'gPsS'  // SsP general allocations

// ============================================================================
// CONSTANTS
// ============================================================================

#define SHADOWSTRIKE_MAX_PROTECTED_PROCESSES    16
#define SHADOWSTRIKE_MAX_PROTECTED_PATH_LENGTH  512
#define SHADOWSTRIKE_MAX_PROTECTED_PATHS        32
#define SHADOWSTRIKE_MAX_PROTECTED_REGKEYS      16

/**
 * @brief Maximum length for PCWSTR parameters (characters, not bytes).
 * Used with RtlStringCchLengthW to prevent unbounded wcslen.
 */
#define SSSP_MAX_INPUT_CCH      2048

/**
 * @brief Dangerous process access rights to strip.
 */
#define SHADOWSTRIKE_DANGEROUS_PROCESS_ACCESS   \
    (PROCESS_TERMINATE |                        \
     PROCESS_VM_WRITE |                         \
     PROCESS_VM_OPERATION |                     \
     PROCESS_CREATE_THREAD |                    \
     PROCESS_SUSPEND_RESUME)

/**
 * @brief Dangerous thread access rights to strip.
 */
#define SHADOWSTRIKE_DANGEROUS_THREAD_ACCESS    \
    (THREAD_TERMINATE |                         \
     THREAD_SUSPEND_RESUME |                    \
     THREAD_SET_CONTEXT |                       \
     THREAD_SET_INFORMATION)

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Entry in the protected process list.
 *
 * Allocated from NonPagedPoolNx. Contains a referenced PEPROCESS.
 * CreateTime is stored alongside ProcessId to prevent PID-reuse attacks.
 */
typedef struct _SHADOWSTRIKE_PROTECTED_PROCESS_ENTRY {
    LIST_ENTRY ListEntry;
    HANDLE ProcessId;
    PEPROCESS Process;              // Referenced via ObReferenceObject
    LARGE_INTEGER CreateTime;       // PID-reuse guard
    LARGE_INTEGER RegistrationTime;
    ULONG Flags;
    WCHAR ImagePath[260];
} SHADOWSTRIKE_PROTECTED_PROCESS_ENTRY, *PSHADOWSTRIKE_PROTECTED_PROCESS_ENTRY;

/**
 * @brief Protection flags for protected processes.
 */
typedef enum _SHADOWSTRIKE_PROTECTION_FLAGS {
    ProtectionFlagNone              = 0x00000000,
    ProtectionFlagBlockTerminate    = 0x00000001,
    ProtectionFlagBlockVMWrite      = 0x00000002,
    ProtectionFlagBlockInject       = 0x00000004,
    ProtectionFlagBlockSuspend      = 0x00000008,
    ProtectionFlagIsPrimaryService  = 0x00000010,
    ProtectionFlagIsDriverLoader    = 0x00000020,
    ProtectionFlagFull              = 0x0000000F
} SHADOWSTRIKE_PROTECTION_FLAGS;

/**
 * @brief Protected file path entry.
 * Flags and InUse are grouped as ULONGs to eliminate padding holes.
 */
typedef struct _SHADOWSTRIKE_PROTECTED_PATH {
    ULONG InUse;
    ULONG Flags;
    USHORT PathLength;      // Character count (not bytes)
    WCHAR Path[SHADOWSTRIKE_MAX_PROTECTED_PATH_LENGTH];
} SHADOWSTRIKE_PROTECTED_PATH, *PSHADOWSTRIKE_PROTECTED_PATH;

/**
 * @brief Protected registry key entry.
 */
typedef struct _SHADOWSTRIKE_PROTECTED_REGKEY {
    ULONG InUse;
    ULONG Flags;
    USHORT KeyPathLength;   // Character count (not bytes)
    WCHAR KeyPath[SHADOWSTRIKE_MAX_PROTECTED_PATH_LENGTH];
} SHADOWSTRIKE_PROTECTED_REGKEY, *PSHADOWSTRIKE_PROTECTED_REGKEY;

/**
 * @brief Self-protection statistics. All fields updated via InterlockedIncrement64.
 */
typedef struct _SHADOWSTRIKE_SELFPROTECT_STATS {
    volatile LONG64 HandleStrips;
    volatile LONG64 ProcessTerminateBlocks;
    volatile LONG64 VMWriteBlocks;
    volatile LONG64 ThreadInjectBlocks;
    volatile LONG64 FileWriteBlocks;
    volatile LONG64 FileDeleteBlocks;
    volatile LONG64 RegistryBlocks;
} SHADOWSTRIKE_SELFPROTECT_STATS, *PSHADOWSTRIKE_SELFPROTECT_STATS;

// ============================================================================
// FUNCTION PROTOTYPES
// ============================================================================

/**
 * @brief Initialize self-protection subsystem.
 * Must be called at PASSIVE_LEVEL before any other SelfProtect function.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeInitializeSelfProtection(
    VOID
    );

/**
 * @brief Shutdown self-protection subsystem.
 * Drains all in-flight callbacks, frees all resources.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeShutdownSelfProtection(
    VOID
    );

/**
 * @brief Register a process for protection.
 * @param ProcessId Process ID to protect.
 * @param Flags Protection flags (SHADOWSTRIKE_PROTECTION_FLAGS).
 * @param ImagePath Optional NUL-terminated image path for logging.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeProtectProcess(
    _In_ HANDLE ProcessId,
    _In_ ULONG Flags,
    _In_opt_ PCWSTR ImagePath
    );

/**
 * @brief Unregister a process from protection.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeUnprotectProcess(
    _In_ HANDLE ProcessId
    );

/**
 * @brief Check if a process is protected.
 * Safe to call at any IRQL <= DISPATCH_LEVEL.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsProcessProtected(
    _In_ HANDLE ProcessId,
    _Out_opt_ PULONG OutFlags
    );

/**
 * @brief Add a protected file path prefix.
 * @param Path NUL-terminated path prefix.
 * @param Flags Protection flags.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeAddProtectedPath(
    _In_ PCWSTR Path,
    _In_ ULONG Flags
    );

/**
 * @brief Remove a protected file path prefix.
 * @param Path NUL-terminated path prefix to remove.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeRemoveProtectedPath(
    _In_ PCWSTR Path
    );

/**
 * @brief Check if a file path is protected.
 * Safe at any IRQL <= DISPATCH_LEVEL.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsPathProtected(
    _In_ PCUNICODE_STRING Path
    );

/**
 * @brief Add a protected registry key path.
 * @param KeyPath NUL-terminated registry key path.
 * @param Flags Protection flags.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeAddProtectedRegistryKey(
    _In_ PCWSTR KeyPath,
    _In_ ULONG Flags
    );

/**
 * @brief Remove a protected registry key path.
 * @param KeyPath NUL-terminated registry key path to remove.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeRemoveProtectedRegistryKey(
    _In_ PCWSTR KeyPath
    );

/**
 * @brief Check if a registry key is protected.
 * Safe at any IRQL <= DISPATCH_LEVEL.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsRegistryKeyProtected(
    _In_ PCUNICODE_STRING KeyPath
    );

/**
 * @brief Get snapshot of self-protection statistics.
 * Atomically copies all stat fields under a spin lock.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeGetSelfProtectStats(
    _Out_ PSHADOWSTRIKE_SELFPROTECT_STATS Stats
    );

/**
 * @brief Object pre-operation callback for handle protection.
 *
 * Registered via ObRegisterCallbacks. Runs at IRQL <= DISPATCH_LEVEL.
 * Strips dangerous access rights from handles to protected processes/threads.
 * Never blocks, never allocates, never acquires paged resources.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
OB_PREOP_CALLBACK_STATUS
ShadowStrikeObjectPreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    );

/**
 * @brief Check file access for self-protection.
 * Called from minifilter PreCreate/PreSetInformation.
 * @return TRUE to block, FALSE to allow.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeShouldBlockFileAccess(
    _In_ PCUNICODE_STRING FilePath,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ HANDLE RequestorPid,
    _In_ BOOLEAN IsDelete
    );

/**
 * @brief Check registry access for self-protection.
 * Called from registry callback.
 * @return TRUE to block, FALSE to allow.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeShouldBlockRegistryAccess(
    _In_ PCUNICODE_STRING KeyPath,
    _In_ REG_NOTIFY_CLASS Operation,
    _In_ HANDLE RequestorPid
    );

#endif /* SELFPROTECT_H */
