/**
 * ============================================================================
 * ShadowStrike NGAV - PROCESS UTILITIES
 * ============================================================================
 *
 * @file ProcessUtils.h
 * @brief Enterprise-grade process analysis for kernel-mode EDR operations.
 *
 * Provides CrowdStrike Falcon-level process introspection with:
 * - Process information retrieval (image path, command line, PEB)
 * - Parent/child relationship tracking
 * - Token and privilege analysis
 * - Process integrity level detection
 * - Session and user context extraction
 * - Thread enumeration and analysis
 * - Memory region inspection
 * - Loaded module enumeration
 * - Process state and flag detection
 * - Secure process validation (PPL, Protected)
 *
 * Security Guarantees:
 * - All functions validate input parameters
 * - Safe handle management with proper cleanup
 * - IRQL-aware implementations
 * - Exception handling for invalid processes
 * - Reference counting for EPROCESS objects
 *
 * MITRE ATT&CK Coverage:
 * - T1055: Process Injection (parent/child analysis)
 * - T1134: Access Token Manipulation (token analysis)
 * - T1548: Abuse Elevation Control (privilege detection)
 * - T1036: Masquerading (process validation)
 * - T1059: Command and Scripting Interpreter (command line parsing)
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_PROCESS_UTILS_H_
#define _SHADOWSTRIKE_PROCESS_UTILS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <fltKernel.h>
#include <ntifs.h>

// ============================================================================
// POOL TAGS
// ============================================================================

/**
 * @brief Pool tag for process utility allocations: 'pSSx'
 */
#define SHADOW_PROCESS_TAG 'pSSx'

/**
 * @brief Pool tag for process info allocations
 */
#define SHADOW_PROCINFO_TAG 'iSSp'

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * @brief Maximum process image path length
 */
#define SHADOW_MAX_PROCESS_PATH 520

/**
 * @brief Maximum command line length
 */
#define SHADOW_MAX_CMDLINE_LENGTH 32767

/**
 * @brief Maximum number of threads to enumerate
 */
#define SHADOW_MAX_THREADS 4096

/**
 * @brief Maximum number of modules to enumerate
 */
#define SHADOW_MAX_MODULES 1024

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Process integrity levels
 */
typedef enum _SHADOW_INTEGRITY_LEVEL {
    ShadowIntegrityUntrusted = 0,
    ShadowIntegrityLow = 1,
    ShadowIntegrityMedium = 2,
    ShadowIntegrityMediumPlus = 3,
    ShadowIntegrityHigh = 4,
    ShadowIntegritySystem = 5,
    ShadowIntegrityProtected = 6,
    ShadowIntegrityUnknown = 0xFF
} SHADOW_INTEGRITY_LEVEL;

/**
 * @brief Process protection level (PPL)
 */
typedef enum _SHADOW_PROTECTION_LEVEL {
    ShadowProtectionNone = 0,
    ShadowProtectionLight = 1,          // PsProtectedSignerAntimalware
    ShadowProtectionFull = 2,           // PsProtectedSignerWindows
    ShadowProtectionSecure = 3          // Secure process (trustlet)
} SHADOW_PROTECTION_LEVEL;

/**
 * @brief Process type classification
 */
typedef enum _SHADOW_PROCESS_TYPE {
    ShadowProcessUnknown = 0,
    ShadowProcessNative,                // Native process (csrss, smss)
    ShadowProcessSystem,                // System process
    ShadowProcessService,               // Windows service
    ShadowProcessUser,                  // User application
    ShadowProcessUWP,                   // UWP/Store app
    ShadowProcessWow64,                 // 32-bit on 64-bit
    ShadowProcessProtected              // Protected process
} SHADOW_PROCESS_TYPE;

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Comprehensive process information structure
 */
typedef struct _SHADOW_PROCESS_INFO {
    //
    // Basic identification
    //
    HANDLE ProcessId;
    HANDLE ParentProcessId;
    HANDLE CreatingProcessId;
    HANDLE CreatingThreadId;

    //
    // Image information
    //
    UNICODE_STRING ImagePath;
    UNICODE_STRING ImageFileName;
    UNICODE_STRING CommandLine;

    //
    // Session and user context
    //
    ULONG SessionId;
    LUID AuthenticationId;
    TOKEN_USER* TokenUser;
    ULONG TokenUserSize;

    //
    // Security attributes
    //
    SHADOW_INTEGRITY_LEVEL IntegrityLevel;
    SHADOW_PROTECTION_LEVEL ProtectionLevel;
    SHADOW_PROCESS_TYPE ProcessType;

    //
    // Flags
    //
    BOOLEAN IsWow64;
    BOOLEAN IsElevated;
    BOOLEAN IsProtectedProcess;
    BOOLEAN IsSecureProcess;
    BOOLEAN IsSubsystemProcess;
    BOOLEAN IsTerminating;
    BOOLEAN IsDebugged;

    //
    // Timestamps
    //
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER ExitTime;

    //
    // Statistics
    //
    ULONG ThreadCount;
    ULONG HandleCount;
    SIZE_T VirtualSize;
    SIZE_T WorkingSetSize;

} SHADOW_PROCESS_INFO, *PSHADOW_PROCESS_INFO;

/**
 * @brief Thread information structure
 */
typedef struct _SHADOW_THREAD_INFO {
    HANDLE ThreadId;
    HANDLE ProcessId;
    PVOID StartAddress;
    PVOID Win32StartAddress;
    ULONG State;
    ULONG Priority;
    ULONG BasePriority;
    BOOLEAN IsTerminating;
    BOOLEAN IsSystemThread;
    LARGE_INTEGER CreateTime;
} SHADOW_THREAD_INFO, *PSHADOW_THREAD_INFO;

/**
 * @brief Module information structure
 */
typedef struct _SHADOW_MODULE_INFO {
    PVOID BaseAddress;
    SIZE_T Size;
    UNICODE_STRING FullPath;
    UNICODE_STRING BaseName;
    ULONG Flags;
    USHORT LoadCount;
    BOOLEAN IsMainModule;
} SHADOW_MODULE_INFO, *PSHADOW_MODULE_INFO;

// ============================================================================
// INITIALIZATION
// ============================================================================

/**
 * @brief Initialize process utilities subsystem.
 *
 * Resolves required system routine addresses.
 * Must be called during driver initialization.
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowProcessUtilsInitialize(
    VOID
    );

/**
 * @brief Cleanup process utilities subsystem.
 *
 * @irql PASSIVE_LEVEL
 */
VOID
ShadowProcessUtilsCleanup(
    VOID
    );

// ============================================================================
// PROCESS INFORMATION RETRIEVAL
// ============================================================================

/**
 * @brief Get process image path by process ID.
 *
 * Retrieves the full NT path of the process executable.
 *
 * @param ProcessId     Process ID
 * @param ImagePath     Receives image path (caller must free with ShadowFreeProcessString)
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeGetProcessImagePath(
    _In_ HANDLE ProcessId,
    _Out_ PUNICODE_STRING ImagePath
    );

/**
 * @brief Get process image name (filename only) by process ID.
 *
 * @param ProcessId     Process ID
 * @param ImageName     Receives image name (caller must free)
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeGetProcessImageName(
    _In_ HANDLE ProcessId,
    _Out_ PUNICODE_STRING ImageName
    );

/**
 * @brief Get process command line by process ID.
 *
 * Reads command line from process PEB.
 *
 * @param ProcessId     Process ID
 * @param CommandLine   Receives command line (caller must free)
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeGetProcessCommandLine(
    _In_ HANDLE ProcessId,
    _Out_ PUNICODE_STRING CommandLine
    );

/**
 * @brief Get comprehensive process information.
 *
 * Retrieves all available process metadata.
 *
 * @param ProcessId     Process ID
 * @param ProcessInfo   Receives process information
 *
 * @return STATUS_SUCCESS or error
 *
 * @note Caller must free with ShadowFreeProcessInfo
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeGetProcessInfo(
    _In_ HANDLE ProcessId,
    _Out_ PSHADOW_PROCESS_INFO ProcessInfo
    );

/**
 * @brief Free process information structure.
 *
 * @param ProcessInfo   Structure to free
 *
 * @irql PASSIVE_LEVEL
 */
VOID
ShadowFreeProcessInfo(
    _Inout_ PSHADOW_PROCESS_INFO ProcessInfo
    );

/**
 * @brief Free process string allocated by process utils.
 *
 * @param String    String to free
 *
 * @irql PASSIVE_LEVEL
 */
VOID
ShadowFreeProcessString(
    _Inout_ PUNICODE_STRING String
    );

// ============================================================================
// PARENT/CHILD RELATIONSHIPS
// ============================================================================

/**
 * @brief Get parent process ID.
 *
 * @param ProcessId         Process ID
 * @param ParentProcessId   Receives parent process ID
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeGetParentProcessId(
    _In_ HANDLE ProcessId,
    _Out_ PHANDLE ParentProcessId
    );

/**
 * @brief Get creating process ID (real parent, not inherited).
 *
 * @param Process               EPROCESS pointer
 * @param CreatingProcessId     Receives creating process ID
 * @param CreatingThreadId      Receives creating thread ID (optional)
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql <= APC_LEVEL
 */
NTSTATUS
ShadowStrikeGetCreatingProcess(
    _In_ PEPROCESS Process,
    _Out_ PHANDLE CreatingProcessId,
    _Out_opt_ PHANDLE CreatingThreadId
    );

/**
 * @brief Validate parent-child relationship.
 *
 * Checks if ParentId is the actual parent of ChildId.
 * Detects parent PID spoofing attacks.
 *
 * @param ChildId       Child process ID
 * @param ClaimedParentId   Claimed parent process ID
 * @param IsValid       Receives validation result
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeValidateParentChild(
    _In_ HANDLE ChildId,
    _In_ HANDLE ClaimedParentId,
    _Out_ PBOOLEAN IsValid
    );

// ============================================================================
// PROCESS STATE AND FLAGS
// ============================================================================

/**
 * @brief Check if process is terminating.
 *
 * @param Process   EPROCESS pointer
 *
 * @return TRUE if process is terminating
 *
 * @irql <= DISPATCH_LEVEL
 */
BOOLEAN
ShadowStrikeIsProcessTerminating(
    _In_ PEPROCESS Process
    );

/**
 * @brief Check if process is a WOW64 process.
 *
 * @param Process   EPROCESS pointer
 *
 * @return TRUE if 32-bit process on 64-bit OS
 *
 * @irql <= DISPATCH_LEVEL
 */
BOOLEAN
ShadowStrikeIsProcessWow64(
    _In_ PEPROCESS Process
    );

/**
 * @brief Check if process is protected (PPL).
 *
 * @param Process   EPROCESS pointer
 *
 * @return TRUE if protected process
 *
 * @irql <= DISPATCH_LEVEL
 */
BOOLEAN
ShadowStrikeIsProcessProtected(
    _In_ PEPROCESS Process
    );

/**
 * @brief Check if process is being debugged.
 *
 * @param Process   EPROCESS pointer
 *
 * @return TRUE if process has debugger attached
 *
 * @irql <= DISPATCH_LEVEL
 */
BOOLEAN
ShadowStrikeIsProcessDebugged(
    _In_ PEPROCESS Process
    );

/**
 * @brief Check if process is a system process.
 *
 * @param ProcessId     Process ID
 *
 * @return TRUE if system process (SYSTEM token)
 *
 * @irql PASSIVE_LEVEL
 */
BOOLEAN
ShadowStrikeIsSystemProcess(
    _In_ HANDLE ProcessId
    );

/**
 * @brief Check if process is elevated.
 *
 * @param ProcessId     Process ID
 * @param IsElevated    Receives elevation status
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeIsProcessElevated(
    _In_ HANDLE ProcessId,
    _Out_ PBOOLEAN IsElevated
    );

// ============================================================================
// TOKEN AND PRIVILEGE ANALYSIS
// ============================================================================

/**
 * @brief Get process integrity level.
 *
 * @param ProcessId         Process ID
 * @param IntegrityLevel    Receives integrity level
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeGetProcessIntegrityLevel(
    _In_ HANDLE ProcessId,
    _Out_ PSHADOW_INTEGRITY_LEVEL IntegrityLevel
    );

/**
 * @brief Get process session ID.
 *
 * @param ProcessId     Process ID
 * @param SessionId     Receives session ID
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeGetProcessSessionId(
    _In_ HANDLE ProcessId,
    _Out_ PULONG SessionId
    );

/**
 * @brief Check if process has specific privilege.
 *
 * @param ProcessId         Process ID
 * @param PrivilegeLuid     Privilege LUID to check
 * @param HasPrivilege      Receives result
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeProcessHasPrivilege(
    _In_ HANDLE ProcessId,
    _In_ LUID PrivilegeLuid,
    _Out_ PBOOLEAN HasPrivilege
    );

/**
 * @brief Get process user SID.
 *
 * @param ProcessId     Process ID
 * @param UserSid       Receives user SID (caller must free)
 * @param SidSize       Receives SID size
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeGetProcessUserSid(
    _In_ HANDLE ProcessId,
    _Out_ PSID* UserSid,
    _Out_ PULONG SidSize
    );

// ============================================================================
// HANDLE OPERATIONS
// ============================================================================

/**
 * @brief Get process ID from handle.
 *
 * @param ProcessHandle     Process handle
 * @param ProcessId         Receives process ID
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeGetProcessIdFromHandle(
    _In_ HANDLE ProcessHandle,
    _Out_ PHANDLE ProcessId
    );

/**
 * @brief Get EPROCESS from process ID.
 *
 * @param ProcessId     Process ID
 * @param Process       Receives EPROCESS pointer (caller must dereference)
 *
 * @return STATUS_SUCCESS or error
 *
 * @note Caller must call ObDereferenceObject when done
 *
 * @irql <= APC_LEVEL
 */
NTSTATUS
ShadowStrikeGetProcessObject(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS* Process
    );

/**
 * @brief Open handle to process.
 *
 * @param ProcessId         Process ID
 * @param DesiredAccess     Access mask
 * @param ProcessHandle     Receives handle
 *
 * @return STATUS_SUCCESS or error
 *
 * @note Caller must close handle with ZwClose
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeOpenProcess(
    _In_ HANDLE ProcessId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ProcessHandle
    );

// ============================================================================
// THREAD OPERATIONS
// ============================================================================

/**
 * @brief Get thread information.
 *
 * @param ThreadId      Thread ID
 * @param ThreadInfo    Receives thread information
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeGetThreadInfo(
    _In_ HANDLE ThreadId,
    _Out_ PSHADOW_THREAD_INFO ThreadInfo
    );

/**
 * @brief Check if thread is terminating.
 *
 * @param Thread    ETHREAD pointer
 *
 * @return TRUE if thread is terminating
 *
 * @irql <= DISPATCH_LEVEL
 */
BOOLEAN
ShadowStrikeIsThreadTerminating(
    _In_ PETHREAD Thread
    );

/**
 * @brief Get thread start address.
 *
 * @param ThreadId          Thread ID
 * @param StartAddress      Receives start address
 * @param Win32StartAddress Receives Win32 start address (optional)
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeGetThreadStartAddress(
    _In_ HANDLE ThreadId,
    _Out_ PVOID* StartAddress,
    _Out_opt_ PVOID* Win32StartAddress
    );

// ============================================================================
// PROCESS VALIDATION
// ============================================================================

/**
 * @brief Validate process image signature.
 *
 * Checks if process image is properly signed.
 *
 * @param ProcessId         Process ID
 * @param IsSigned          Receives signature status
 * @param SignerType        Receives signer type (optional)
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeValidateProcessSignature(
    _In_ HANDLE ProcessId,
    _Out_ PBOOLEAN IsSigned,
    _Out_opt_ PULONG SignerType
    );

/**
 * @brief Check if process is a known Windows process.
 *
 * Validates process path against known Windows directories.
 *
 * @param ProcessId         Process ID
 * @param IsWindowsProcess  Receives result
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeIsWindowsProcess(
    _In_ HANDLE ProcessId,
    _Out_ PBOOLEAN IsWindowsProcess
    );

/**
 * @brief Classify process type.
 *
 * Determines if process is service, user app, UWP, etc.
 *
 * @param ProcessId     Process ID
 * @param ProcessType   Receives process type
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeClassifyProcess(
    _In_ HANDLE ProcessId,
    _Out_ PSHADOW_PROCESS_TYPE ProcessType
    );

// ============================================================================
// INLINE UTILITIES
// ============================================================================

/**
 * @brief Check if process ID is valid (non-zero and not system idle).
 */
FORCEINLINE
BOOLEAN
ShadowStrikeIsValidProcessId(
    _In_ HANDLE ProcessId
    )
{
    return (ProcessId != NULL && ProcessId != (HANDLE)4);
}

/**
 * @brief Get current process ID.
 */
FORCEINLINE
HANDLE
ShadowStrikeGetCurrentProcessId(
    VOID
    )
{
    return PsGetCurrentProcessId();
}

/**
 * @brief Get current thread ID.
 */
FORCEINLINE
HANDLE
ShadowStrikeGetCurrentThreadId(
    VOID
    )
{
    return PsGetCurrentThreadId();
}

/**
 * @brief Check if running in system process context.
 */
FORCEINLINE
BOOLEAN
ShadowStrikeIsSystemContext(
    VOID
    )
{
    return (PsGetCurrentProcessId() == (HANDLE)4);
}

#ifdef __cplusplus
}
#endif

#endif // _SHADOWSTRIKE_PROCESS_UTILS_H_
