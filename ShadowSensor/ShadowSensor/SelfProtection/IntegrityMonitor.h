/*++
    ShadowStrike Next-Generation Antivirus
    Module: IntegrityMonitor.h - Self-integrity monitoring

    v2.1.0 Changes (Enterprise Hardened):
    ======================================
    - EX_RUNDOWN_REF replaces BOOLEAN Initialized for safe shutdown
    - IoWorkItem for DPC -> PASSIVE_LEVEL deferral (BCrypt safety)
    - ImShutdown takes PIM_MONITOR* to NULL caller's pointer
    - ImFreeCheckResult added for proper result lifetime
    - IRQL SAL annotations on all public APIs
    - New IM_MODIFICATION values: ImMod_ImportHook, ImMod_ExportHook, ImMod_HeaderTamper
    - Callback list instead of single callback pointer
    - volatile fields for cross-thread visibility
    - PDEVICE_OBJECT required for work item allocation

    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define IM_POOL_TAG 'NOIM'

// ============================================================================
// ENUMERATIONS
// ============================================================================

typedef enum _IM_COMPONENT {
    ImComp_CodeSections = 0,    // Non-writable executable sections
    ImComp_DataSections,        // Non-writable data sections
    ImComp_DriverImage,         // PE header integrity
    ImComp_Callbacks,           // Callback registration status
    ImComp_Handles,             // Object callback handle status
    ImComp_Configuration,       // Driver configuration state
    ImComp_MaxValue             // Sentinel (must be last)
} IM_COMPONENT;

typedef enum _IM_MODIFICATION {
    ImMod_None = 0,
    ImMod_CodePatch,            // Code section bytes changed
    ImMod_DataCorruption,       // Read-only data section changed
    ImMod_ImportHook,           // Import table tampered
    ImMod_ExportHook,           // Export table tampered
    ImMod_HeaderTamper,         // PE header modified
    ImMod_CallbackRemoval,      // Kernel callback unregistered
    ImMod_ConfigChanged,        // Driver configuration state changed
} IM_MODIFICATION;

// ============================================================================
// CHECK RESULT STRUCTURE
// ============================================================================

typedef struct _IM_CHECK_RESULT {
    IM_COMPONENT    Component;
    BOOLEAN         IsIntact;
    IM_MODIFICATION ModificationType;
    CHAR            Details[128];
} IM_CHECK_RESULT, *PIM_CHECK_RESULT;

// ============================================================================
// CALLBACK TYPE
// ============================================================================

/// Tamper detection callback. Called at PASSIVE_LEVEL.
typedef VOID (*PIM_TAMPER_CALLBACK)(
    _In_ PIM_CHECK_RESULT Result,
    _In_opt_ PVOID Context
);

// ============================================================================
// MONITOR STRUCTURE (Public portion — internal extends this)
// ============================================================================

typedef struct _IM_MONITOR {
    /// Rundown protection for safe shutdown
    EX_RUNDOWN_REF  RundownProtection;

    /// Manager state: 0=uninit, 1=active, 2=shutting down
    volatile LONG   State;

    /// Periodic check interval (ms)
    ULONG           CheckIntervalMs;

    /// Periodic check enabled (atomic)
    volatile LONG   PeriodicEnabled;

    /// Work item pending flag (atomic)
    volatile LONG   WorkItemPending;

    /// Statistics
    LARGE_INTEGER   LastCheckTime;
    ULONG           TotalChecks;
} IM_MONITOR, *PIM_MONITOR;

// ============================================================================
// PUBLIC API
// ============================================================================

/**
 * @brief Initialize the integrity monitoring subsystem.
 * @param Monitor       Receives pointer to initialized monitor
 * @param DriverBase    Base address of the driver image in memory
 * @param DriverSize    Size of the driver image
 * @param DeviceObject  Device object for work item allocation
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ImInitialize(
    _Out_    PIM_MONITOR *Monitor,
    _In_     PVOID DriverBase,
    _In_     SIZE_T DriverSize,
    _In_     PDEVICE_OBJECT DeviceObject
);

/**
 * @brief Shutdown the integrity monitoring subsystem.
 * Sets *Monitor to NULL on return. Waits for rundown.
 * @param Monitor  Pointer to monitor pointer (set to NULL)
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ImShutdown(
    _Inout_ PIM_MONITOR *Monitor
);

/**
 * @brief Register a tamper detection callback.
 * Multiple callbacks may be registered.
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ImRegisterCallback(
    _In_     PIM_MONITOR Monitor,
    _In_     PIM_TAMPER_CALLBACK Callback,
    _In_opt_ PVOID Context
);

/**
 * @brief Enable periodic integrity checking.
 * @param IntervalMs  Check interval in ms (clamped to 5s-300s range)
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ImEnablePeriodicCheck(
    _In_ PIM_MONITOR Monitor,
    _In_ ULONG IntervalMs
);

/**
 * @brief Disable periodic integrity checking.
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ImDisablePeriodicCheck(
    _In_ PIM_MONITOR Monitor
);

/**
 * @brief Check integrity of a specific component (on-demand).
 * @param Result  Caller-provided result buffer (stack or pool)
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ImCheckIntegrity(
    _In_  PIM_MONITOR Monitor,
    _In_  IM_COMPONENT Component,
    _Out_ PIM_CHECK_RESULT Result
);

/**
 * @brief Check integrity of all components.
 * Caller must free *Results via ImFreeCheckResult.
 * @param Results     Receives allocated array of results
 * @param ResultCount Receives number of results
 * @param AllIntact   Receives TRUE if all components intact
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ImCheckAll(
    _In_  PIM_MONITOR Monitor,
    _Out_ PIM_CHECK_RESULT *Results,
    _Out_ PULONG ResultCount,
    _Out_ PBOOLEAN AllIntact
);

/**
 * @brief Free results array allocated by ImCheckAll.
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ImFreeCheckResult(
    _In_ PIM_CHECK_RESULT Results
);

#ifdef __cplusplus
}
#endif
