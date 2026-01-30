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
 * @author ShadowStrike Security Team
 * @version 1.0.0
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
// HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Initialize process monitoring resources.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ShadowStrikeInitializeProcessMonitoring(
    VOID
    );

/**
 * @brief Cleanup process monitoring resources.
 */
VOID
ShadowStrikeCleanupProcessMonitoring(
    VOID
    );

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_PROCESS_NOTIFY_H
