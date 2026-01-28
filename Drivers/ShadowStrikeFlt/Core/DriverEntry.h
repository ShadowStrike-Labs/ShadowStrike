/**
 * ============================================================================
 * ShadowStrike NGAV - DRIVER ENTRY HEADER
 * ============================================================================
 *
 * @file DriverEntry.h
 * @brief Driver entry point and unload function declarations.
 *
 * Contains the main driver lifecycle function prototypes and initialization
 * helper declarations.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_DRIVER_ENTRY_H
#define SHADOWSTRIKE_DRIVER_ENTRY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <fltKernel.h>
#include <ntddk.h>
#include "Globals.h"

// ============================================================================
// DRIVER LIFECYCLE FUNCTIONS
// ============================================================================

/**
 * @brief Main driver entry point.
 *
 * Called by the system when the driver is loaded. Performs all initialization
 * including filter registration, callback setup, and communication port creation.
 *
 * @param DriverObject  Pointer to the driver object.
 * @param RegistryPath  Path to the driver's registry key.
 * @return STATUS_SUCCESS on success, appropriate error code otherwise.
 */
DRIVER_INITIALIZE DriverEntry;

/**
 * @brief Driver unload callback.
 *
 * Called by the Filter Manager when the driver is being unloaded.
 * Performs cleanup of all resources in reverse order of allocation.
 *
 * @param Flags  Flags indicating the reason for unload.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ShadowStrikeUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

// ============================================================================
// INITIALIZATION FUNCTIONS
// ============================================================================

/**
 * @brief Initialize all lookaside lists.
 *
 * Creates non-paged lookaside lists for common allocations to prevent
 * pool fragmentation and improve performance.
 *
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ShadowStrikeInitializeLookasideLists(
    VOID
    );

/**
 * @brief Cleanup all lookaside lists.
 */
VOID
ShadowStrikeCleanupLookasideLists(
    VOID
    );

/**
 * @brief Register process and thread notification callbacks.
 *
 * Registers:
 * - PsSetCreateProcessNotifyRoutineEx2
 * - PsSetCreateThreadNotifyRoutine
 * - PsSetLoadImageNotifyRoutine
 *
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ShadowStrikeRegisterProcessCallbacks(
    VOID
    );

/**
 * @brief Unregister process and thread notification callbacks.
 */
VOID
ShadowStrikeUnregisterProcessCallbacks(
    VOID
    );

/**
 * @brief Register registry callback.
 *
 * Uses CmRegisterCallbackEx for registry operation monitoring.
 *
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ShadowStrikeRegisterRegistryCallback(
    VOID
    );

/**
 * @brief Unregister registry callback.
 */
VOID
ShadowStrikeUnregisterRegistryCallback(
    VOID
    );

/**
 * @brief Register object callbacks for self-protection.
 *
 * Uses ObRegisterCallbacks to protect AV processes from termination
 * and handle manipulation.
 *
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ShadowStrikeRegisterObjectCallbacks(
    VOID
    );

/**
 * @brief Unregister object callbacks.
 */
VOID
ShadowStrikeUnregisterObjectCallbacks(
    VOID
    );

/**
 * @brief Initialize protected process list.
 */
VOID
ShadowStrikeInitializeProtectedProcessList(
    VOID
    );

/**
 * @brief Cleanup protected process list.
 */
VOID
ShadowStrikeCleanupProtectedProcessList(
    VOID
    );

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Wait for all outstanding operations to complete.
 *
 * Called during unload to ensure no operations are in progress
 * before freeing resources.
 *
 * @param TimeoutMs  Maximum time to wait in milliseconds.
 * @return STATUS_SUCCESS if all operations completed, STATUS_TIMEOUT otherwise.
 */
NTSTATUS
ShadowStrikeWaitForOutstandingOperations(
    _In_ ULONG TimeoutMs
    );

/**
 * @brief Log driver initialization status.
 *
 * @param Component  Name of the component being initialized.
 * @param Status     Initialization status.
 */
VOID
ShadowStrikeLogInitStatus(
    _In_ PCSTR Component,
    _In_ NTSTATUS Status
    );

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_DRIVER_ENTRY_H
