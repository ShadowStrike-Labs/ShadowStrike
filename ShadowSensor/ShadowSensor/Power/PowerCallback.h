/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE POWER MANAGEMENT HEADER
 * ============================================================================
 *
 * @file PowerCallback.h
 * @brief Enterprise-grade power state management for kernel EDR.
 *
 * Implements comprehensive power transition handling:
 * - System sleep/hibernate/resume detection
 * - Connected standby (Modern Standby) support
 * - AC/DC power source monitoring
 * - Display state change tracking
 * - Lid open/close detection
 * - Battery level monitoring
 *
 * Security Implications:
 * - Malware may attempt attacks during power transitions
 * - Resume from sleep requires re-validation of system state
 * - Hibernate can expose memory contents on disk
 * - Power events can be used for timing-based evasion
 *
 * IRQL Safety:
 * - System state callback may fire at DISPATCH_LEVEL
 * - All callback work is deferred to PASSIVE_LEVEL via work items
 * - State query functions use atomic reads or spin locks
 * - No push locks acquired above APC_LEVEL
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_POWER_CALLBACK_H
#define SHADOWSTRIKE_POWER_CALLBACK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include <wdm.h>

// ============================================================================
// POOL TAGS
// ============================================================================

#define PWR_POOL_TAG                    'rwPS'
#define PWR_POOL_TAG_EVENT              'vEwP'
#define PWR_POOL_TAG_CALLBACK           'bCwP'

// ============================================================================
// CONSTANTS
// ============================================================================

#define PWR_MAX_EVENT_HISTORY           64
#define PWR_MAX_CALLBACKS               8
#define PWR_RESUME_VALIDATION_TIMEOUT_MS    5000
#define PWR_SLEEP_WAIT_TIMEOUT_MS       10000

// ============================================================================
// POWER STATE ENUMERATIONS
// ============================================================================

typedef enum _SHADOW_POWER_STATE {
    ShadowPowerState_Unknown = 0,
    ShadowPowerState_Working,           // S0
    ShadowPowerState_Standby,           // S1-S3
    ShadowPowerState_Hibernate,         // S4
    ShadowPowerState_Shutdown,          // S5
    ShadowPowerState_ConnectedStandby,  // S0ix
    ShadowPowerState_HybridSleep,
    ShadowPowerState_FastStartup,
    ShadowPowerState_Max
} SHADOW_POWER_STATE;

typedef enum _SHADOW_POWER_SOURCE {
    ShadowPowerSource_Unknown = 0,
    ShadowPowerSource_AC,
    ShadowPowerSource_DC,
    ShadowPowerSource_UPS,
    ShadowPowerSource_Max
} SHADOW_POWER_SOURCE;

typedef enum _SHADOW_POWER_EVENT_TYPE {
    ShadowPowerEvent_None = 0,

    // System state transitions (bits 1-7)
    ShadowPowerEvent_EnteringSleep,
    ShadowPowerEvent_ResumingFromSleep,
    ShadowPowerEvent_EnteringHibernate,
    ShadowPowerEvent_ResumingFromHibernate,
    ShadowPowerEvent_EnteringConnectedStandby,
    ShadowPowerEvent_ExitingConnectedStandby,
    ShadowPowerEvent_Shutdown,

    // Power source changes (bits 8-11)
    ShadowPowerEvent_ACPowerConnected,
    ShadowPowerEvent_ACPowerDisconnected,
    ShadowPowerEvent_BatteryLow,
    ShadowPowerEvent_BatteryCritical,

    // Display changes (bits 12-14)
    ShadowPowerEvent_DisplayOn,
    ShadowPowerEvent_DisplayOff,
    ShadowPowerEvent_DisplayDimmed,

    // User presence (bits 15-18)
    ShadowPowerEvent_UserPresent,
    ShadowPowerEvent_UserAway,
    ShadowPowerEvent_LidOpen,
    ShadowPowerEvent_LidClosed,

    // Thermal/throttling (bits 19-22)
    ShadowPowerEvent_ThermalThrottling,
    ShadowPowerEvent_ThermalNormal,
    ShadowPowerEvent_PowerThrottling,
    ShadowPowerEvent_PowerNormal,

    // Session changes (bits 23-26)
    ShadowPowerEvent_SessionLock,
    ShadowPowerEvent_SessionUnlock,
    ShadowPowerEvent_SessionLogoff,
    ShadowPowerEvent_SessionLogon,

    ShadowPowerEvent_Max    // Must be < 64 for ULONGLONG event mask
} SHADOW_POWER_EVENT_TYPE;

//
// Compile-time assertion: event type must fit in 64-bit event mask
//
C_ASSERT(ShadowPowerEvent_Max <= 64);

typedef enum _SHADOW_POWER_CALLBACK_PRIORITY {
    ShadowPowerPriority_Critical = 0,
    ShadowPowerPriority_High,
    ShadowPowerPriority_Normal,
    ShadowPowerPriority_Low,
    ShadowPowerPriority_Max
} SHADOW_POWER_CALLBACK_PRIORITY;

// ============================================================================
// PUBLIC STRUCTURES (no internal pointers exposed)
// ============================================================================

/**
 * @brief Public power event information (safe to copy/expose).
 *        Internal list linkage is NOT included.
 */
typedef struct _SHADOW_POWER_EVENT_INFO {
    SHADOW_POWER_EVENT_TYPE EventType;
    SHADOW_POWER_STATE PreviousState;
    SHADOW_POWER_STATE NewState;
    LARGE_INTEGER Timestamp;
    UINT64 EventSequence;

    union {
        struct {
            ULONG BatteryPercentage;
            ULONG EstimatedTimeRemaining;
        } Battery;

        struct {
            BOOLEAN IsACOnline;
            BOOLEAN IsBatteryPresent;
        } PowerSource;

        struct {
            ULONG ThermalLevel;
            ULONG ThrottlePercent;
        } Thermal;

        struct {
            ULONG SessionId;
        } Session;
    } Data;

} SHADOW_POWER_EVENT_INFO, *PSHADOW_POWER_EVENT_INFO;

/**
 * @brief Power state snapshot (read-only, no internal pointers).
 */
typedef struct _SHADOW_POWER_STATE_INFO {
    SHADOW_POWER_STATE CurrentState;
    SHADOW_POWER_STATE PreviousState;
    SHADOW_POWER_SOURCE PowerSource;

    LARGE_INTEGER LastStateChangeTime;
    LARGE_INTEGER LastResumeTime;
    LARGE_INTEGER LastSleepTime;

    BOOLEAN BatteryPresent;
    ULONG BatteryPercentage;
    ULONG BatteryEstimatedTime;
    BOOLEAN BatteryCharging;

    BOOLEAN DisplayOn;
    BOOLEAN DisplayDimmed;

    BOOLEAN LidOpen;
    BOOLEAN UserPresent;
    BOOLEAN SessionLocked;

    BOOLEAN ThermalThrottling;
    ULONG ThermalLevel;

    BOOLEAN InConnectedStandby;
    ULONG ConnectedStandbyExitCount;

} SHADOW_POWER_STATE_INFO, *PSHADOW_POWER_STATE_INFO;

/**
 * @brief Power management statistics (all fields are snapshot copies).
 */
typedef struct _SHADOW_POWER_STATISTICS {
    LONG64 TotalPowerEvents;
    LONG64 SleepTransitions;
    LONG64 ResumeTransitions;
    LONG64 HibernateTransitions;
    LONG64 ConnectedStandbyTransitions;
    LONG64 ACDCTransitions;
    LONG64 DisplayStateChanges;
    LONG64 LidStateChanges;
    LONG64 SessionChanges;
    LONG64 ThermalEvents;
    LONG64 CallbacksInvoked;
    LONG64 CallbackErrors;
    LONG64 ValidationsPassed;
    LONG64 ValidationsFailed;

    LARGE_INTEGER TotalSleepDuration;
    LARGE_INTEGER LongestSleepDuration;
    LARGE_INTEGER LastSleepDuration;

} SHADOW_POWER_STATISTICS, *PSHADOW_POWER_STATISTICS;

/**
 * @brief Power callback function type.
 *
 * Called at PASSIVE_LEVEL with shared lock held on callback list.
 * Must not block for extended periods.
 */
typedef VOID
(*PSHADOW_POWER_CALLBACK)(
    _In_ SHADOW_POWER_EVENT_TYPE EventType,
    _In_ PSHADOW_POWER_EVENT_INFO Event,
    _In_opt_ PVOID Context
    );

// ============================================================================
// OPAQUE HANDLE — internal state is private to PowerCallback.c
// ============================================================================

//
// No SHADOW_POWER_GLOBALS exposed in the header.
// All state is file-static in PowerCallback.c.
//

// ============================================================================
// FUNCTION PROTOTYPES - INITIALIZATION
// ============================================================================

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
ShadowRegisterPowerCallbacks(
    _In_opt_ PDEVICE_OBJECT DeviceObject
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
ShadowUnregisterPowerCallbacks(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
ShadowPowerSetEnabled(
    _In_ BOOLEAN Enable
    );

// ============================================================================
// FUNCTION PROTOTYPES - STATE QUERY
// ============================================================================

/**
 * @brief Get current power state. Safe at any IRQL <= APC_LEVEL.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
ShadowPowerGetState(
    _Out_ PSHADOW_POWER_STATE_INFO StateInfo
    );

/**
 * @brief Lock-free check if in low-power state (relaxed read).
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowPowerIsLowPowerState(
    VOID
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowPowerIsResuming(
    VOID
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowPowerIsOnBattery(
    VOID
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
ShadowPowerGetBatteryPercentage(
    VOID
    );

// ============================================================================
// FUNCTION PROTOTYPES - CALLBACK REGISTRATION
// ============================================================================

/**
 * @brief Register a power event callback.
 *
 * @param EventMask 64-bit bitmask of events to receive (0 = all).
 *                  Bit N corresponds to SHADOW_POWER_EVENT_TYPE value N.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
ShadowPowerRegisterCallback(
    _In_ PSHADOW_POWER_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _In_ SHADOW_POWER_CALLBACK_PRIORITY Priority,
    _In_ ULONGLONG EventMask,
    _Out_ PVOID* Handle
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
ShadowPowerUnregisterCallback(
    _In_ PVOID Handle
    );

// ============================================================================
// FUNCTION PROTOTYPES - EVENT MANAGEMENT
// ============================================================================

/**
 * @brief Get recent power event history (public event structs, no pointers).
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
ShadowPowerGetEventHistory(
    _Out_writes_to_(MaxEvents, *EventCount) PSHADOW_POWER_EVENT_INFO Events,
    _In_ ULONG MaxEvents,
    _Out_ PULONG EventCount
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
ShadowPowerWaitForPendingOperations(
    _In_ ULONG TimeoutMs
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowPowerEnterOperation(
    VOID
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowPowerLeaveOperation(
    VOID
    );

// ============================================================================
// FUNCTION PROTOTYPES - RESUME VALIDATION
// ============================================================================

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
ShadowPowerValidateResume(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
ShadowPowerWaitForResumeValidation(
    _In_ ULONG TimeoutMs
    );

// ============================================================================
// FUNCTION PROTOTYPES - STATISTICS
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
ShadowPowerGetStatistics(
    _Out_ PSHADOW_POWER_STATISTICS Stats
    );

_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowPowerResetStatistics(
    VOID
    );

// ============================================================================
// FUNCTION PROTOTYPES - UTILITY
// ============================================================================

PCSTR
ShadowPowerStateToString(
    _In_ SHADOW_POWER_STATE State
    );

PCSTR
ShadowPowerEventToString(
    _In_ SHADOW_POWER_EVENT_TYPE EventType
    );

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_POWER_CALLBACK_H
