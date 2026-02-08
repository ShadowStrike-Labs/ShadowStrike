/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE OBJECT CALLBACK HEADER
 * ============================================================================
 *
 * @file ObjectCallback.h
 * @brief Object manager callback definitions for self-protection.
 *
 * Handles ObRegisterCallbacks logic to strip dangerous access rights
 * from handles opened to our protected processes and threads.
 *
 * Security Capabilities:
 * - T1003: OS Credential Dumping (LSASS protection)
 * - T1055: Process Injection (VM_WRITE/CREATE_THREAD blocking)
 * - T1489: Service Stop (service process protection)
 * - T1562: Impair Defenses (EDR self-protection)
 * - T1106: Native API abuse detection
 * - T1134: Access Token Manipulation
 *
 * @author ShadowStrike Security Team
 * @version 2.1.0 (Enterprise Edition - Security Hardened)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#pragma once

#ifndef _SHADOWSTRIKE_OBJECT_CALLBACK_H_
#define _SHADOWSTRIKE_OBJECT_CALLBACK_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <ntifs.h>
#include <wdm.h>

// ============================================================================
// POOL TAGS
// ============================================================================

#define OB_POOL_TAG                         'bOSS'
#define OB_PROTECTED_ENTRY_TAG              'eOSS'
#define OB_TELEMETRY_TAG                    'tOSS'
#define OB_NAME_CACHE_TAG                   'nOSS'

// ============================================================================
// CONSTANTS
// ============================================================================

#define OB_CALLBACK_VERSION                 0x100
#define OB_MAX_CALLBACK_CONTEXTS            16
#define OB_TELEMETRY_RATE_LIMIT             100
#define OB_SUSPICIOUS_SCORE_THRESHOLD       50
#define OB_MAX_PROTECTED_PROCESSES          256
#define OB_MAX_IMAGE_NAME_CCH               260
#define OB_NAME_CACHE_SIZE                  64

//
// Thread access masks for protection
//
#define OB_DANGEROUS_THREAD_ACCESS          \
    (THREAD_TERMINATE |                     \
     THREAD_SUSPEND_RESUME |                \
     THREAD_SET_CONTEXT |                   \
     THREAD_SET_INFORMATION |               \
     THREAD_SET_THREAD_TOKEN |              \
     THREAD_IMPERSONATE |                   \
     THREAD_DIRECT_IMPERSONATION)

#define OB_INJECTION_THREAD_ACCESS          \
    (THREAD_SET_CONTEXT |                   \
     THREAD_GET_CONTEXT |                   \
     THREAD_SUSPEND_RESUME)

#define OB_SAFE_THREAD_ACCESS               \
    (THREAD_QUERY_LIMITED_INFORMATION |     \
     SYNCHRONIZE)

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Protected process list entry for self-protection
 */
typedef struct _OB_PROTECTED_PROCESS_ENTRY {
    //
    // List linkage
    //
    LIST_ENTRY ListEntry;

    //
    // Process identification
    //
    HANDLE ProcessId;

    //
    // Classification from ProcessProtection.h
    //
    ULONG Category;         // PP_PROCESS_CATEGORY
    ULONG ProtectionLevel;  // PP_PROTECTION_LEVEL

    //
    // Image path hash for validation (FNV-1a)
    //
    ULONG64 ImagePathHash;

    //
    // Cached short name for fast matching (15 chars like PsGetProcessImageFileName)
    //
    CHAR ImageFileName[16];

    //
    // Flags
    //
    BOOLEAN IsValidated;
    BOOLEAN IsShadowStrike;
    BOOLEAN IsCriticalSystem;
    UCHAR Reserved;

    //
    // Reference count for safe removal
    //
    volatile LONG ReferenceCount;

    //
    // Statistics
    //
    volatile LONG64 AccessStrippedCount;
    volatile LONG64 TerminationBlockedCount;

} OB_PROTECTED_PROCESS_ENTRY, *POB_PROTECTED_PROCESS_ENTRY;

/**
 * @brief Name cache entry for IRQL-safe lookups
 */
typedef struct _OB_NAME_CACHE_ENTRY {
    HANDLE ProcessId;
    CHAR ImageFileName[16];
    LARGE_INTEGER CacheTime;
    volatile LONG Valid;
} OB_NAME_CACHE_ENTRY, *POB_NAME_CACHE_ENTRY;

/**
 * @brief Telemetry event for suspicious operations
 */
typedef struct _OB_TELEMETRY_EVENT {
    //
    // Event identification
    //
    LARGE_INTEGER Timestamp;
    ULONG64 EventId;

    //
    // Source process
    //
    HANDLE SourceProcessId;
    CHAR SourceImageName[16];

    //
    // Target process
    //
    HANDLE TargetProcessId;
    CHAR TargetImageName[16];
    ULONG TargetCategory;

    //
    // Operation details
    //
    BOOLEAN IsProcessHandle;
    BOOLEAN IsDuplicate;
    BOOLEAN IsKernelHandle;
    BOOLEAN IsCrossSession;

    //
    // Access details
    //
    ACCESS_MASK OriginalAccess;
    ACCESS_MASK AllowedAccess;
    ACCESS_MASK StrippedAccess;

    //
    // Analysis
    //
    ULONG SuspicionScore;
    ULONG SuspiciousFlags;

} OB_TELEMETRY_EVENT, *POB_TELEMETRY_EVENT;

/**
 * @brief Extended callback context for telemetry and state
 */
typedef struct _OB_CALLBACK_CONTEXT {
    //
    // Initialization state (must be first for atomic check)
    //
    volatile LONG InitState;        // 0=uninit, 1=initializing, 2=initialized
    LARGE_INTEGER StartTime;

    //
    // Statistics (all volatile for lock-free access)
    //
    volatile LONG64 TotalProcessOperations;
    volatile LONG64 TotalThreadOperations;
    volatile LONG64 ProcessAccessStripped;
    volatile LONG64 ThreadAccessStripped;
    volatile LONG64 CredentialAccessBlocked;
    volatile LONG64 InjectionBlocked;
    volatile LONG64 TerminationBlocked;
    volatile LONG64 SuspiciousOperations;

    //
    // Rate limiting - uses spin lock for DISPATCH_LEVEL safety
    //
    KSPIN_LOCK RateLimitSpinLock;
    volatile LONG CurrentSecondEvents;
    volatile LONG64 CurrentSecondStart100ns;

    //
    // Cached well-known PIDs
    //
    volatile LONG64 LsassPid;
    volatile LONG64 CsrssPid;
    volatile LONG64 ServicesPid;
    volatile LONG64 WinlogonPid;
    volatile LONG64 SmsssPid;
    volatile LONG WellKnownPidsInitialized;

    //
    // Name cache for IRQL-safe lookups
    //
    OB_NAME_CACHE_ENTRY NameCache[OB_NAME_CACHE_SIZE];
    volatile LONG NameCacheIndex;

    //
    // Configuration (volatile for dynamic updates)
    //
    volatile BOOLEAN EnableCredentialProtection;
    volatile BOOLEAN EnableInjectionProtection;
    volatile BOOLEAN EnableTerminationProtection;
    volatile BOOLEAN EnableSelfProtection;
    volatile BOOLEAN EnableCrossSessionMonitoring;
    volatile BOOLEAN LogStrippedAccess;
    volatile BOOLEAN EnablePathValidation;
    volatile BOOLEAN EnableTelemetry;

} OB_CALLBACK_CONTEXT, *POB_CALLBACK_CONTEXT;

// ============================================================================
// FUNCTION PROTOTYPES - REGISTRATION
// ============================================================================

/**
 * @brief Register object manager callbacks.
 *
 * Registers callbacks for PsProcessType and PsThreadType to protect
 * critical services from termination and injection.
 *
 * @return STATUS_SUCCESS or error code.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeRegisterObjectCallbacks(
    VOID
    );

/**
 * @brief Unregister object manager callbacks.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeUnregisterObjectCallbacks(
    VOID
    );

// ============================================================================
// FUNCTION PROTOTYPES - CALLBACKS
// ============================================================================

/**
 * @brief Pre-operation callback for process handles.
 *
 * Called before a handle to a process is created or duplicated.
 * Checks if the target is a protected process and strips dangerous rights.
 *
 * @param RegistrationContext Context passed during registration.
 * @param OperationInformation Operation details.
 * @return OB_PREOP_SUCCESS.
 *
 * @irql <= APC_LEVEL (per ObRegisterCallbacks documentation)
 */
_IRQL_requires_max_(APC_LEVEL)
OB_PREOP_CALLBACK_STATUS
ShadowStrikeProcessPreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    );

/**
 * @brief Pre-operation callback for thread handles.
 *
 * Called before a handle to a thread is created or duplicated.
 * Checks if the target thread belongs to a protected process.
 *
 * @param RegistrationContext Context passed during registration.
 * @param OperationInformation Operation details.
 * @return OB_PREOP_SUCCESS.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
OB_PREOP_CALLBACK_STATUS
ShadowStrikeThreadPreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    );

// ============================================================================
// FUNCTION PROTOTYPES - PROTECTED PROCESS MANAGEMENT
// ============================================================================

/**
 * @brief Add a process to the protected process list.
 *
 * @param ProcessId         Process ID to protect.
 * @param Category          Process category (PP_PROCESS_CATEGORY).
 * @param ProtectionLevel   Protection level (PP_PROTECTION_LEVEL).
 * @param ImagePath         Optional image path for validation.
 *
 * @return STATUS_SUCCESS or error code.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
ObAddProtectedProcess(
    _In_ HANDLE ProcessId,
    _In_ ULONG Category,
    _In_ ULONG ProtectionLevel,
    _In_opt_ PCUNICODE_STRING ImagePath
    );

/**
 * @brief Remove a process from the protected process list.
 *
 * @param ProcessId Process ID to remove.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
ObRemoveProtectedProcess(
    _In_ HANDLE ProcessId
    );

/**
 * @brief Check if a process is in our protected process list.
 *
 * @param ProcessId         Process ID to check.
 * @param OutEntry          Optional - receives entry if found.
 *
 * @return TRUE if protected.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ObIsInProtectedList(
    _In_ HANDLE ProcessId,
    _Out_opt_ POB_PROTECTED_PROCESS_ENTRY* OutEntry
    );

// ============================================================================
// FUNCTION PROTOTYPES - TELEMETRY
// ============================================================================

/**
 * @brief Queue telemetry event for delivery to user-mode.
 *
 * @param Event Telemetry event to queue.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ObQueueTelemetryEvent(
    _In_ POB_TELEMETRY_EVENT Event
    );

/**
 * @brief Get callback statistics.
 *
 * @param ProcessOps        Receives total process operations.
 * @param ThreadOps         Receives total thread operations.
 * @param AccessStripped    Receives total access stripped count.
 * @param Suspicious        Receives suspicious operation count.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ObGetCallbackStatistics(
    _Out_opt_ PLONG64 ProcessOps,
    _Out_opt_ PLONG64 ThreadOps,
    _Out_opt_ PLONG64 AccessStripped,
    _Out_opt_ PLONG64 Suspicious
    );

#ifdef __cplusplus
}
#endif

#endif // _SHADOWSTRIKE_OBJECT_CALLBACK_H_
