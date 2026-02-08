/**
 * ============================================================================
 * ShadowStrike NGAV - PROCESS NOTIFICATIONS
 * ============================================================================
 *
 * @file ProcessNotify.h
 * @brief Process creation and termination callback definitions.
 *
 * Handles the interception of process creation (PsSetCreateProcessNotifyRoutineEx)
 * and forwards events to user-mode for analysis and verdict rendering.
 *
 * Features:
 * - Full process context capture (token, privileges, parent chain, command line)
 * - PPID spoofing detection
 * - Command line analysis for suspicious patterns
 * - Rate limiting and pool limits for DoS protection
 * - Configurable timeout for user-mode communication
 * - Enterprise-grade lock ordering and IRQL safety
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition - Security Hardened)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_PROCESS_NOTIFY_H
#define SHADOWSTRIKE_PROCESS_NOTIFY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include "../../../Shared/SharedDefs.h"

// ============================================================================
// PUBLIC CALLBACKS
// ============================================================================

/**
 * @brief Process creation/termination callback.
 *
 * Registered via PsSetCreateProcessNotifyRoutineEx.
 *
 * This callback performs comprehensive process analysis including:
 * - PPID spoofing detection
 * - Token/privilege analysis
 * - Command line pattern matching
 * - LOLBin detection
 * - Suspicion scoring
 *
 * IRQL: PASSIVE_LEVEL (guaranteed by system)
 *
 * @param Process     Pointer to the process object.
 * @param ProcessId   ID of the process.
 * @param CreateInfo  Creation info (NULL for termination).
 */
VOID
ShadowStrikeProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    );

// ============================================================================
// INITIALIZATION AND CLEANUP
// ============================================================================

/**
 * @brief Initialize process monitoring resources.
 *
 * Must be called before registering the process notify callback.
 * Allocates lookaside lists, initializes locks, and starts cleanup timer.
 *
 * IRQL: PASSIVE_LEVEL
 *
 * @return STATUS_SUCCESS on success.
 * @return STATUS_ALREADY_REGISTERED if already initialized.
 * @return STATUS_INSUFFICIENT_RESOURCES on allocation failure.
 * @return STATUS_INVALID_DEVICE_STATE if driver device object not available.
 */
NTSTATUS
ShadowStrikeInitializeProcessMonitoring(
    VOID
    );

/**
 * @brief Cleanup process monitoring resources.
 *
 * Must be called after unregistering the process notify callback.
 * Waits for pending DPCs and work items, frees all contexts.
 *
 * IRQL: PASSIVE_LEVEL
 */
VOID
ShadowStrikeCleanupProcessMonitoring(
    VOID
    );

// ============================================================================
// STATISTICS AND DIAGNOSTICS
// ============================================================================

/**
 * @brief Get basic process monitor statistics.
 *
 * Thread-safe, lock-free statistics retrieval.
 *
 * @param ProcessCreations      Output for total process creations seen.
 * @param ProcessesBlocked      Output for total processes blocked.
 * @param PpidSpoofingDetected  Output for PPID spoofing detections.
 * @param SuspiciousProcesses   Output for suspicious process count.
 *
 * @return STATUS_SUCCESS on success.
 * @return STATUS_NOT_FOUND if not initialized.
 */
NTSTATUS
ShadowStrikeGetProcessMonitorStats(
    _Out_opt_ PULONG64 ProcessCreations,
    _Out_opt_ PULONG64 ProcessesBlocked,
    _Out_opt_ PULONG64 PpidSpoofingDetected,
    _Out_opt_ PULONG64 SuspiciousProcesses
    );

/**
 * @brief Get extended process monitor statistics.
 *
 * Includes rate limiting, pool usage, and timeout statistics.
 *
 * @param RateLimitDrops    Output for notifications dropped due to rate limit.
 * @param PoolLimitDrops    Output for notifications dropped due to pool limit.
 * @param UserModeTimeouts  Output for user-mode communication timeouts.
 * @param CurrentPoolUsage  Output for current pool memory usage in bytes.
 * @param PeakPoolUsage     Output for peak pool memory usage in bytes.
 *
 * @return STATUS_SUCCESS on success.
 * @return STATUS_NOT_FOUND if not initialized.
 */
NTSTATUS
ShadowStrikeGetProcessMonitorExtendedStats(
    _Out_opt_ PULONG64 RateLimitDrops,
    _Out_opt_ PULONG64 PoolLimitDrops,
    _Out_opt_ PULONG64 UserModeTimeouts,
    _Out_opt_ PULONG64 CurrentPoolUsage,
    _Out_opt_ PULONG64 PeakPoolUsage
    );

/**
 * @brief Query context for a specific process.
 *
 * Returns the flags and suspicion score for a tracked process.
 *
 * @param ProcessId      The process ID to query.
 * @param Flags          Output for process flags.
 * @param SuspicionScore Output for suspicion score (0-100).
 *
 * @return STATUS_SUCCESS on success.
 * @return STATUS_NOT_FOUND if process not tracked or not initialized.
 */
NTSTATUS
ShadowStrikeQueryProcessContext(
    _In_ HANDLE ProcessId,
    _Out_opt_ PULONG Flags,
    _Out_opt_ PULONG SuspicionScore
    );

// ============================================================================
// PROCESS FLAG DEFINITIONS (for external use)
// ============================================================================

#define SHADOWSTRIKE_PROC_FLAG_ANALYZED           0x00000001
#define SHADOWSTRIKE_PROC_FLAG_SUSPICIOUS         0x00000002
#define SHADOWSTRIKE_PROC_FLAG_PPID_SPOOFED       0x00000004
#define SHADOWSTRIKE_PROC_FLAG_ELEVATED           0x00000008
#define SHADOWSTRIKE_PROC_FLAG_SYSTEM             0x00000010
#define SHADOWSTRIKE_PROC_FLAG_SERVICE            0x00000020
#define SHADOWSTRIKE_PROC_FLAG_LOLBIN             0x00000040
#define SHADOWSTRIKE_PROC_FLAG_ENCODED_CMD        0x00000080
#define SHADOWSTRIKE_PROC_FLAG_CROSS_SESSION      0x00000100
#define SHADOWSTRIKE_PROC_FLAG_UNSIGNED           0x00000200
#define SHADOWSTRIKE_PROC_FLAG_BLOCKED            0x00000400
#define SHADOWSTRIKE_PROC_FLAG_TRUSTED            0x00000800
#define SHADOWSTRIKE_PROC_FLAG_HAS_DEBUG_PRIV     0x00002000
#define SHADOWSTRIKE_PROC_FLAG_HAS_IMPERSONATE    0x00004000
#define SHADOWSTRIKE_PROC_FLAG_HAS_TCB            0x00008000
#define SHADOWSTRIKE_PROC_FLAG_SIGNATURE_VALID    0x00020000

// ============================================================================
// SUSPICION SCORE THRESHOLDS (for external use)
// ============================================================================

#define SHADOWSTRIKE_SUSPICION_LOW                15
#define SHADOWSTRIKE_SUSPICION_MEDIUM             35
#define SHADOWSTRIKE_SUSPICION_HIGH               60
#define SHADOWSTRIKE_SUSPICION_CRITICAL           85

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_PROCESS_NOTIFY_H
