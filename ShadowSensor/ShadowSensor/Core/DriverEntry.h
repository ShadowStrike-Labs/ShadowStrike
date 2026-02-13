/**
 * ============================================================================
 * ShadowStrike NGAV - DRIVER ENTRY HEADER
 * ============================================================================
 *
 * @file DriverEntry.h
 * @brief Driver entry point and unload function declarations.
 *
 * Contains the main driver lifecycle function prototypes and initialization
 * helper declarations. This is the primary entry point for the enterprise
 * kernel sensor.
 *
 * CRITICAL DESIGN DECISIONS:
 * 1. Uses EX_RUNDOWN_REF for safe callback synchronization during unload
 * 2. All security callbacks are MANDATORY - failure to register is FATAL
 * 3. Memory barriers used for all shared state access
 * 4. IRQL-correct implementations throughout
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0
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
#include <wdm.h>
#include "Globals.h"

// ============================================================================
// VERSION REQUIREMENTS
// ============================================================================

/**
 * @brief Minimum Windows version required.
 * Windows 10 RS1 (1607) = 14393 for PsSetCreateProcessNotifyRoutineEx2
 */
#define SHADOWSTRIKE_MIN_BUILD_NUMBER   14393

/**
 * @brief Windows version for enhanced features.
 * Windows 10 RS3 (1709) = 16299 for additional APIs
 */
#define SHADOWSTRIKE_ENHANCED_BUILD     16299

// ============================================================================
// INITIALIZATION STATE FLAGS
// ============================================================================

/**
 * @brief Bit flags tracking which subsystems were successfully initialized.
 * Used for precise cleanup on failure and for degraded mode detection.
 */
typedef enum _SHADOWSTRIKE_INIT_FLAGS {
    InitFlag_None                   = 0x00000000,
    InitFlag_LookasideLists         = 0x00000001,
    InitFlag_FilterRegistered       = 0x00000002,
    InitFlag_CommPortCreated        = 0x00000004,
    InitFlag_ScanCacheInitialized   = 0x00000008,
    InitFlag_ExclusionsInitialized  = 0x00000010,
    InitFlag_HashUtilsInitialized   = 0x00000020,
    InitFlag_ProcessCallbackReg     = 0x00000040,
    InitFlag_ThreadCallbackReg      = 0x00000080,
    InitFlag_ImageCallbackReg       = 0x00000100,
    InitFlag_RegistryCallbackReg    = 0x00000200,
    InitFlag_ObjectCallbackReg      = 0x00000400,
    InitFlag_FilteringStarted       = 0x00000800,
    InitFlag_RundownInitialized     = 0x00001000,
    InitFlag_SelfProtectInitialized = 0x00002000,
    InitFlag_NamedPipeMonInitialized = 0x00004000,
    InitFlag_AmsiBypassDetInitialized = 0x00008000,
    InitFlag_FileBackupEngineInitialized = 0x00010000,
    InitFlag_USBDeviceControlInitialized = 0x00020000,
    InitFlag_WslMonitorInitialized     = 0x00040000,
    InitFlag_AppControlInitialized     = 0x00080000,
    InitFlag_FirmwareIntegrityInitialized = 0x00100000,
    InitFlag_ClipboardMonitorInitialized  = 0x00200000,

    // Combined flags for critical security components
    InitFlag_AllSecurityCallbacks   = (InitFlag_ProcessCallbackReg |
                                       InitFlag_ObjectCallbackReg),
    InitFlag_AllCritical            = (InitFlag_LookasideLists |
                                       InitFlag_FilterRegistered |
                                       InitFlag_CommPortCreated |
                                       InitFlag_RundownInitialized)
} SHADOWSTRIKE_INIT_FLAGS;

// ============================================================================
// DRIVER LIFECYCLE FUNCTIONS
// ============================================================================

/**
 * @brief Main driver entry point.
 *
 * Called by the system when the driver is loaded. Performs all initialization
 * including filter registration, callback setup, and communication port creation.
 *
 * INITIALIZATION ORDER (critical for correctness):
 * 1. Version check
 * 2. Initialize global state and rundown protection
 * 3. Create lookaside lists
 * 4. Register minifilter
 * 5. Create communication port
 * 6. Initialize scan cache
 * 7. Initialize exclusion manager
 * 8. Initialize hash utilities
 * 9. Register process/thread/image callbacks
 * 10. Register registry callback
 * 11. Register object callbacks (self-protection)
 * 12. Start filtering
 *
 * On any CRITICAL failure, cleanup is performed in reverse order.
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
 * CRITICAL: Uses EX_RUNDOWN_REF to wait for all outstanding callbacks
 * to complete before freeing any resources. This prevents BSOD.
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
 * @brief Check Windows version compatibility.
 *
 * Verifies the running Windows version meets minimum requirements
 * for all APIs used by this driver.
 *
 * @param OutBuildNumber  Optional pointer to receive actual build number.
 * @return STATUS_SUCCESS if compatible, STATUS_NOT_SUPPORTED otherwise.
 */
NTSTATUS
ShadowStrikeCheckVersionCompatibility(
    _Out_opt_ PULONG OutBuildNumber
    );

/**
 * @brief Load configuration from registry.
 *
 * Reads driver configuration from the registry path provided in DriverEntry.
 * Falls back to defaults if registry values are missing or invalid.
 *
 * @param RegistryPath  Registry path from DriverEntry.
 * @param Config        Configuration structure to populate.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ShadowStrikeLoadConfiguration(
    _In_ PUNICODE_STRING RegistryPath,
    _Out_ PSHADOWSTRIKE_CONFIG Config
    );

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
 * - PsSetCreateProcessNotifyRoutineEx (process creation/termination)
 * - PsSetCreateThreadNotifyRoutine (thread creation/termination)
 * - PsSetLoadImageNotifyRoutine (image/DLL loading)
 *
 * IMPORTANT: Process callback registration is MANDATORY for security.
 * Thread and image callbacks are optional enhancements.
 *
 * @param OutFlags  Receives flags indicating which callbacks registered.
 * @return STATUS_SUCCESS if process callback registered successfully.
 */
NTSTATUS
ShadowStrikeRegisterProcessCallbacks(
    _Out_ PULONG OutFlags
    );

/**
 * @brief Unregister process and thread notification callbacks.
 *
 * @param Flags  Flags from registration indicating which to unregister.
 */
VOID
ShadowStrikeUnregisterProcessCallbacks(
    _In_ ULONG Flags
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
 * and handle manipulation. This is CRITICAL for self-protection.
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
 *
 * Properly frees all entries, dereferencing EPROCESS objects.
 */
VOID
ShadowStrikeCleanupProtectedProcessList(
    VOID
    );

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Wait for rundown protection to drain.
 *
 * Called during unload to ensure no callbacks are in progress
 * before freeing resources. Uses EX_RUNDOWN_REF.
 */
VOID
ShadowStrikeWaitForRundownComplete(
    VOID
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

/**
 * @brief Perform cleanup based on initialization flags.
 *
 * @param InitFlags  Flags indicating which components to clean up.
 */
VOID
ShadowStrikeCleanupByFlags(
    _In_ ULONG InitFlags
    );

// ============================================================================
// CALLBACK DECLARATIONS
// ============================================================================

/**
 * @brief Process creation/termination notification callback.
 *
 * Called by the kernel for every process creation and termination.
 * Implements threat detection, logging, and optional blocking.
 */
VOID
ShadowStrikeProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    );

/**
 * @brief Thread creation/termination notification callback.
 *
 * Called by the kernel for every thread creation and termination.
 * Used for detecting suspicious thread injection patterns.
 */
VOID
ShadowStrikeThreadNotifyCallback(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
    );

/**
 * @brief Image load notification callback.
 *
 * Called by the kernel for every image (EXE/DLL) load.
 * Used for detecting malicious DLL injection and suspicious modules.
 */
VOID
ShadowStrikeImageNotifyCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
    );

/**
 * @brief Registry operation callback.
 *
 * Called by the configuration manager for registry operations.
 * Used for detecting registry-based persistence and tampering.
 */
NTSTATUS
ShadowStrikeRegistryCallbackRoutine(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
    );

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_DRIVER_ENTRY_H
