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
 * CRITICAL: This is our primary defense against malware terminating us.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#pragma once

#include <ntifs.h>
#include <fltKernel.h>

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * @brief Maximum number of protected processes we track.
 */
#define SHADOWSTRIKE_MAX_PROTECTED_PROCESSES    16

/**
 * @brief Maximum length for protected path prefixes.
 */
#define SHADOWSTRIKE_MAX_PROTECTED_PATH_LENGTH  512

/**
 * @brief Maximum number of protected file paths.
 */
#define SHADOWSTRIKE_MAX_PROTECTED_PATHS        32

/**
 * @brief Maximum number of protected registry keys.
 */
#define SHADOWSTRIKE_MAX_PROTECTED_REGKEYS      16

/**
 * @brief Access rights that allow process termination.
 * We strip these from handles opened to protected processes.
 */
#define SHADOWSTRIKE_DANGEROUS_PROCESS_ACCESS   \
    (PROCESS_TERMINATE |                        \
     PROCESS_VM_WRITE |                         \
     PROCESS_VM_OPERATION |                     \
     PROCESS_CREATE_THREAD |                    \
     PROCESS_SUSPEND_RESUME)

/**
 * @brief Access rights that allow thread manipulation.
 * We strip these from handles opened to threads in protected processes.
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
 */
typedef struct _SHADOWSTRIKE_PROTECTED_PROCESS_ENTRY {
    LIST_ENTRY ListEntry;           // List linkage
    HANDLE ProcessId;               // Protected process ID
    PEPROCESS Process;              // EPROCESS pointer (referenced)
    LARGE_INTEGER RegistrationTime; // When protection was registered
    ULONG Flags;                    // Protection flags
    WCHAR ImagePath[260];           // Image path for logging
} SHADOWSTRIKE_PROTECTED_PROCESS_ENTRY, *PSHADOWSTRIKE_PROTECTED_PROCESS_ENTRY;

/**
 * @brief Protection flags for protected processes.
 */
typedef enum _SHADOWSTRIKE_PROTECTION_FLAGS {
    ProtectionFlagNone              = 0x00000000,
    ProtectionFlagBlockTerminate    = 0x00000001,  // Block PROCESS_TERMINATE
    ProtectionFlagBlockVMWrite      = 0x00000002,  // Block PROCESS_VM_WRITE
    ProtectionFlagBlockInject       = 0x00000004,  // Block thread injection
    ProtectionFlagBlockSuspend      = 0x00000008,  // Block suspend/resume
    ProtectionFlagIsPrimaryService  = 0x00000010,  // This is the main AV service
    ProtectionFlagIsDriverLoader    = 0x00000020,  // This loads our driver
    ProtectionFlagFull              = 0x0000000F   // All protection enabled
} SHADOWSTRIKE_PROTECTION_FLAGS;

/**
 * @brief Protected file path entry.
 */
typedef struct _SHADOWSTRIKE_PROTECTED_PATH {
    BOOLEAN InUse;
    WCHAR Path[SHADOWSTRIKE_MAX_PROTECTED_PATH_LENGTH];
    USHORT PathLength;
    ULONG Flags;
} SHADOWSTRIKE_PROTECTED_PATH, *PSHADOWSTRIKE_PROTECTED_PATH;

/**
 * @brief Protected registry key entry.
 */
typedef struct _SHADOWSTRIKE_PROTECTED_REGKEY {
    BOOLEAN InUse;
    WCHAR KeyPath[SHADOWSTRIKE_MAX_PROTECTED_PATH_LENGTH];
    USHORT KeyPathLength;
    ULONG Flags;
} SHADOWSTRIKE_PROTECTED_REGKEY, *PSHADOWSTRIKE_PROTECTED_REGKEY;

/**
 * @brief Self-protection statistics.
 */
typedef struct _SHADOWSTRIKE_SELFPROTECT_STATS {
    volatile LONG64 HandleStrips;           // Handles where access was stripped
    volatile LONG64 ProcessTerminateBlocks; // Blocked termination attempts
    volatile LONG64 VMWriteBlocks;          // Blocked VM write attempts
    volatile LONG64 ThreadInjectBlocks;     // Blocked thread injection
    volatile LONG64 FileWriteBlocks;        // Blocked file writes to AV
    volatile LONG64 FileDeleteBlocks;       // Blocked file deletes
    volatile LONG64 RegistryBlocks;         // Blocked registry changes
} SHADOWSTRIKE_SELFPROTECT_STATS, *PSHADOWSTRIKE_SELFPROTECT_STATS;

// ============================================================================
// FUNCTION PROTOTYPES
// ============================================================================

/**
 * @brief Initialize self-protection subsystem.
 * @return STATUS_SUCCESS or error code.
 */
NTSTATUS
ShadowStrikeInitializeSelfProtection(
    VOID
    );

/**
 * @brief Shutdown self-protection subsystem.
 */
VOID
ShadowStrikeShutdownSelfProtection(
    VOID
    );

/**
 * @brief Register a process for protection.
 * @param ProcessId Process ID to protect.
 * @param Flags Protection flags.
 * @param ImagePath Optional image path for logging.
 * @return STATUS_SUCCESS or error code.
 */
NTSTATUS
ShadowStrikeProtectProcess(
    _In_ HANDLE ProcessId,
    _In_ ULONG Flags,
    _In_opt_ PCWSTR ImagePath
    );

/**
 * @brief Unregister a process from protection.
 * @param ProcessId Process ID to unprotect.
 */
VOID
ShadowStrikeUnprotectProcess(
    _In_ HANDLE ProcessId
    );

/**
 * @brief Check if a process is protected.
 * @param ProcessId Process ID to check.
 * @param OutFlags Optional pointer to receive protection flags.
 * @return TRUE if protected, FALSE otherwise.
 */
BOOLEAN
ShadowStrikeIsProcessProtected(
    _In_ HANDLE ProcessId,
    _Out_opt_ PULONG OutFlags
    );

/**
 * @brief Add a protected file path.
 * @param Path Path prefix to protect (e.g., L"\\Device\\HarddiskVolume1\\Program Files\\ShadowStrike\\").
 * @param Flags Protection flags.
 * @return STATUS_SUCCESS or error code.
 */
NTSTATUS
ShadowStrikeAddProtectedPath(
    _In_ PCWSTR Path,
    _In_ ULONG Flags
    );

/**
 * @brief Check if a file path is protected.
 * @param Path Path to check.
 * @return TRUE if protected, FALSE otherwise.
 */
BOOLEAN
ShadowStrikeIsPathProtected(
    _In_ PCUNICODE_STRING Path
    );

/**
 * @brief Add a protected registry key.
 * @param KeyPath Key path to protect.
 * @param Flags Protection flags.
 * @return STATUS_SUCCESS or error code.
 */
NTSTATUS
ShadowStrikeAddProtectedRegistryKey(
    _In_ PCWSTR KeyPath,
    _In_ ULONG Flags
    );

/**
 * @brief Check if a registry key is protected.
 * @param KeyPath Key path to check.
 * @return TRUE if protected, FALSE otherwise.
 */
BOOLEAN
ShadowStrikeIsRegistryKeyProtected(
    _In_ PCUNICODE_STRING KeyPath
    );

/**
 * @brief Get self-protection statistics.
 * @param Stats Pointer to receive statistics.
 */
VOID
ShadowStrikeGetSelfProtectStats(
    _Out_ PSHADOWSTRIKE_SELFPROTECT_STATS Stats
    );

/**
 * @brief Object pre-operation callback for handle protection.
 *
 * This is the core of our self-protection. Called by ObRegisterCallbacks
 * before any handle is opened to a process or thread.
 *
 * @param RegistrationContext Our registration context.
 * @param OperationInformation Information about the handle operation.
 * @return OB_PREOP_SUCCESS (we never block, only strip access rights).
 */
OB_PREOP_CALLBACK_STATUS
ShadowStrikeObjectPreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    );

/**
 * @brief Check file access for self-protection.
 *
 * Called from PreCreate/PreSetInformation to block writes/deletes
 * to protected files.
 *
 * @param FilePath Path being accessed.
 * @param DesiredAccess Requested access rights.
 * @param RequestorPid PID making the request.
 * @param IsDelete TRUE if this is a delete operation.
 * @return TRUE to block, FALSE to allow.
 */
BOOLEAN
ShadowStrikeShouldBlockFileAccess(
    _In_ PCUNICODE_STRING FilePath,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ HANDLE RequestorPid,
    _In_ BOOLEAN IsDelete
    );

/**
 * @brief Check registry access for self-protection.
 *
 * Called from registry callback to block changes to protected keys.
 *
 * @param KeyPath Key being accessed.
 * @param Operation Registry operation type.
 * @param RequestorPid PID making the request.
 * @return TRUE to block, FALSE to allow.
 */
BOOLEAN
ShadowStrikeShouldBlockRegistryAccess(
    _In_ PCUNICODE_STRING KeyPath,
    _In_ REG_NOTIFY_CLASS Operation,
    _In_ HANDLE RequestorPid
    );

#endif // SELFPROTECT_H
