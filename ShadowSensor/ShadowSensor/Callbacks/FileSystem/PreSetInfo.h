/**
 * ============================================================================
 * ShadowStrike NGAV - PRE-SET-INFORMATION CALLBACK HEADER
 * ============================================================================
 *
 * @file PreSetInfo.h
 * @brief Public declarations for IRP_MJ_SET_INFORMATION pre-operation callback.
 *
 * This module provides enterprise-grade file set information monitoring with:
 * - Self-protection for AV files (delete/rename blocking)
 * - Ransomware detection via mass rename/delete patterns
 * - Data destruction prevention (mass deletion detection)
 * - Credential access detection (hard links to SAM/SECURITY)
 * - File attribute manipulation monitoring
 *
 * @author ShadowStrike Security Team
 * @version 2.1.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#pragma once

#ifndef _SHADOWSTRIKE_PRESETINFO_H_
#define _SHADOWSTRIKE_PRESETINFO_H_

#include <fltKernel.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// PUBLIC CONSTANTS
// ============================================================================

/**
 * @brief Behavior flags for process context (bitmask)
 */
#define PSI_BEHAVIOR_MASS_RENAME            0x00000001
#define PSI_BEHAVIOR_MASS_DELETE            0x00000002
#define PSI_BEHAVIOR_EXTENSION_CHANGE       0x00000004
#define PSI_BEHAVIOR_MASS_TRUNCATION        0x00000008
#define PSI_BEHAVIOR_CREDENTIAL_ACCESS      0x00000010
#define PSI_BEHAVIOR_SYSTEM_FILE_ACCESS     0x00000020
#define PSI_BEHAVIOR_AV_TAMPERING           0x00000040
#define PSI_BEHAVIOR_BOOT_TAMPERING         0x00000080
#define PSI_BEHAVIOR_TIMESTAMP_STOMP        0x00000100
#define PSI_BEHAVIOR_HIDDEN_ATTRIBUTE       0x00000200

// ============================================================================
// INITIALIZATION AND CLEANUP
// ============================================================================

/**
 * @brief Initialize the PreSetInfo subsystem.
 *
 * Must be called once during driver initialization at PASSIVE_LEVEL.
 * Allocates lookaside lists, initializes synchronization primitives,
 * and sets default configuration values.
 *
 * @return STATUS_SUCCESS on success.
 * @return STATUS_ALREADY_REGISTERED if already initialized.
 * @return STATUS_INSUFFICIENT_RESOURCES on allocation failure.
 *
 * @irql PASSIVE_LEVEL
 * @threadsafety Thread-safe. Multiple calls are serialized.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeInitializePreSetInfo(
    VOID
    );

/**
 * @brief Cleanup the PreSetInfo subsystem.
 *
 * Must be called during driver unload at PASSIVE_LEVEL.
 * Waits for all outstanding operations to complete before
 * freeing resources. Safe to call if not initialized.
 *
 * @irql PASSIVE_LEVEL
 * @threadsafety Thread-safe. Blocks until cleanup is complete.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeCleanupPreSetInfo(
    VOID
    );

// ============================================================================
// MINIFILTER CALLBACK
// ============================================================================

/**
 * @brief Pre-operation callback for IRP_MJ_SET_INFORMATION.
 *
 * Enterprise-grade handler for file set information operations including:
 * - Self-protection (delete/rename of AV files)
 * - Ransomware detection (mass rename/delete patterns)
 * - Data destruction prevention
 * - Credential access detection (hard links to SAM/SECURITY)
 * - File attribute manipulation monitoring
 *
 * @param Data              Callback data from filter manager.
 * @param FltObjects        Filter objects (volume, instance, file).
 * @param CompletionContext Not used (no post-op callback required).
 *
 * @return FLT_PREOP_SUCCESS_NO_CALLBACK on allow.
 * @return FLT_PREOP_COMPLETE on block (status set to STATUS_ACCESS_DENIED).
 *
 * @irql PASSIVE_LEVEL to APC_LEVEL
 * @threadsafety Thread-safe. Lock-free statistics, synchronized contexts.
 */
_IRQL_requires_max_(APC_LEVEL)
FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

// ============================================================================
// STATISTICS API
// ============================================================================

/**
 * @brief Get PreSetInfo operation statistics.
 *
 * Retrieves current counters for monitoring and diagnostics.
 * All parameters are optional; pass NULL to skip.
 *
 * @param TotalCalls        Receives total callback invocations.
 * @param DeleteOperations  Receives delete operation count.
 * @param RenameOperations  Receives rename operation count.
 * @param BlockedOperations Receives total blocked operation count.
 *
 * @return STATUS_SUCCESS on success.
 * @return STATUS_NOT_FOUND if subsystem not initialized.
 *
 * @irql <= DISPATCH_LEVEL
 * @threadsafety Thread-safe. Uses lock-free reads.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeGetPreSetInfoStats(
    _Out_opt_ PULONG64 TotalCalls,
    _Out_opt_ PULONG64 DeleteOperations,
    _Out_opt_ PULONG64 RenameOperations,
    _Out_opt_ PULONG64 BlockedOperations
    );

// ============================================================================
// PROCESS CONTEXT QUERY API
// ============================================================================

/**
 * @brief Query behavioral context for a specific process.
 *
 * Retrieves the current behavioral analysis state for a process.
 * Useful for external components making policy decisions.
 * All output parameters are optional; pass NULL to skip.
 *
 * @param ProcessId             Process ID to query.
 * @param IsRansomwareSuspect   Receives TRUE if ransomware behavior detected.
 * @param IsDestructionSuspect  Receives TRUE if data destruction detected.
 * @param SuspicionScore        Receives current suspicion score (0-100+).
 * @param BehaviorFlags         Receives PSI_BEHAVIOR_* flags bitmask.
 *
 * @return STATUS_SUCCESS on success.
 * @return STATUS_NOT_FOUND if subsystem not initialized or process not tracked.
 *
 * @irql <= APC_LEVEL
 * @threadsafety Thread-safe.
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeQueryPreSetInfoProcessContext(
    _In_ HANDLE ProcessId,
    _Out_opt_ PBOOLEAN IsRansomwareSuspect,
    _Out_opt_ PBOOLEAN IsDestructionSuspect,
    _Out_opt_ PULONG SuspicionScore,
    _Out_opt_ PULONG BehaviorFlags
    );

// ============================================================================
// CONFIGURATION API
// ============================================================================

/**
 * @brief Configure PreSetInfo behavioral detection thresholds.
 *
 * Allows runtime adjustment of detection sensitivity.
 * Pass 0 for any threshold to leave unchanged.
 *
 * @param RansomwareRenameThreshold  Renames per second to trigger detection.
 * @param RansomwareDeleteThreshold  Deletes per second to trigger detection.
 * @param DestructionDeleteThreshold Total deletes to trigger destruction alert.
 *
 * @return STATUS_SUCCESS on success.
 * @return STATUS_NOT_FOUND if subsystem not initialized.
 *
 * @irql <= DISPATCH_LEVEL
 * @threadsafety Thread-safe.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeConfigurePreSetInfoThresholds(
    _In_ ULONG RansomwareRenameThreshold,
    _In_ ULONG RansomwareDeleteThreshold,
    _In_ ULONG DestructionDeleteThreshold
    );

/**
 * @brief Enable or disable specific protection features.
 *
 * @param BlockRansomware      Enable ransomware behavior blocking.
 * @param BlockDestruction     Enable data destruction blocking.
 * @param BlockCredentialAccess Enable credential access blocking.
 * @param MonitorAttributes    Enable attribute change monitoring.
 *
 * @return STATUS_SUCCESS on success.
 * @return STATUS_NOT_FOUND if subsystem not initialized.
 *
 * @irql <= DISPATCH_LEVEL
 * @threadsafety Thread-safe.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeConfigurePreSetInfoProtection(
    _In_ BOOLEAN BlockRansomware,
    _In_ BOOLEAN BlockDestruction,
    _In_ BOOLEAN BlockCredentialAccess,
    _In_ BOOLEAN MonitorAttributes
    );

/**
 * @brief Clear behavioral tracking for a specific process.
 *
 * Resets all counters and flags for a process. Useful when
 * a process is determined to be benign after initial suspicion.
 *
 * @param ProcessId Process ID to clear.
 *
 * @return STATUS_SUCCESS on success.
 * @return STATUS_NOT_FOUND if process not tracked.
 *
 * @irql <= APC_LEVEL
 * @threadsafety Thread-safe.
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeClearPreSetInfoProcessContext(
    _In_ HANDLE ProcessId
    );

#ifdef __cplusplus
}
#endif

#endif // _SHADOWSTRIKE_PRESETINFO_H_
