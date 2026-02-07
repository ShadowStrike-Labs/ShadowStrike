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
 * - Power throttling state awareness
 * - Thermal state monitoring
 *
 * Security Implications:
 * - Malware may attempt attacks during power transitions
 * - Resume from sleep requires re-validation of system state
 * - Hibernate can expose memory contents on disk
 * - Power events can be used for timing-based evasion
 *
 * BSOD PREVENTION:
 * - All callbacks are non-blocking
 * - Proper IRQL handling throughout
 * - Safe state transitions with atomic operations
 * - Graceful handling of rapid power state changes
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
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

/**
 * @brief Maximum power event history entries
 */
#define PWR_MAX_EVENT_HISTORY           64

/**
 * @brief Maximum registered power callbacks
 */
#define PWR_MAX_CALLBACKS               8

/**
 * @brief Power event notification delay (ms) before processing
 */
#define PWR_EVENT_DEBOUNCE_MS           100

/**
 * @brief Resume validation timeout (ms)
 */
#define PWR_RESUME_VALIDATION_TIMEOUT_MS    5000

/**
 * @brief Maximum time to wait for pending operations on sleep (ms)
 */
#define PWR_SLEEP_WAIT_TIMEOUT_MS       10000

// ============================================================================
// POWER STATE ENUMERATIONS
// ============================================================================

/**
 * @brief System power state enumeration
 */
typedef enum _SHADOW_POWER_STATE {
    ShadowPowerState_Unknown = 0,
    ShadowPowerState_Working,           // S0 - System fully operational
    ShadowPowerState_Standby,           // S1-S3 - Various sleep states
    ShadowPowerState_Hibernate,         // S4 - Hibernate to disk
    ShadowPowerState_Shutdown,          // S5 - System shutdown
    ShadowPowerState_ConnectedStandby,  // Modern Standby (S0ix)
    ShadowPowerState_HybridSleep,       // Hybrid sleep (S3 + hibernate file)
    ShadowPowerState_FastStartup,       // Fast startup transition
    ShadowPowerState_Max
} SHADOW_POWER_STATE, *PSHADOW_POWER_STATE;

/**
 * @brief Power source enumeration
 */
typedef enum _SHADOW_POWER_SOURCE {
    ShadowPowerSource_Unknown = 0,
    ShadowPowerSource_AC,               // Connected to AC power
    ShadowPowerSource_DC,               // Running on battery
    ShadowPowerSource_UPS,              // Uninterruptible power supply
    ShadowPowerSource_Max
} SHADOW_POWER_SOURCE, *PSHADOW_POWER_SOURCE;

/**
 * @brief Power event type enumeration
 */
typedef enum _SHADOW_POWER_EVENT_TYPE {
    ShadowPowerEvent_None = 0,

    // System state transitions
    ShadowPowerEvent_EnteringSleep,
    ShadowPowerEvent_ResumingFromSleep,
    ShadowPowerEvent_EnteringHibernate,
    ShadowPowerEvent_ResumingFromHibernate,
    ShadowPowerEvent_EnteringConnectedStandby,
    ShadowPowerEvent_ExitingConnectedStandby,
    ShadowPowerEvent_Shutdown,

    // Power source changes
    ShadowPowerEvent_ACPowerConnected,
    ShadowPowerEvent_ACPowerDisconnected,
    ShadowPowerEvent_BatteryLow,
    ShadowPowerEvent_BatteryCritical,

    // Display changes
    ShadowPowerEvent_DisplayOn,
    ShadowPowerEvent_DisplayOff,
    ShadowPowerEvent_DisplayDimmed,

    // User presence
    ShadowPowerEvent_UserPresent,
    ShadowPowerEvent_UserAway,
    ShadowPowerEvent_LidOpen,
    ShadowPowerEvent_LidClosed,

    // Thermal/throttling
    ShadowPowerEvent_ThermalThrottling,
    ShadowPowerEvent_ThermalNormal,
    ShadowPowerEvent_PowerThrottling,
    ShadowPowerEvent_PowerNormal,

    // Session changes
    ShadowPowerEvent_SessionLock,
    ShadowPowerEvent_SessionUnlock,
    ShadowPowerEvent_SessionLogoff,
    ShadowPowerEvent_SessionLogon,

    ShadowPowerEvent_Max
} SHADOW_POWER_EVENT_TYPE, *PSHADOW_POWER_EVENT_TYPE;

/**
 * @brief Power callback priority
 */
typedef enum _SHADOW_POWER_CALLBACK_PRIORITY {
    ShadowPowerPriority_Critical = 0,   // Must complete before transition
    ShadowPowerPriority_High,           // Important but not critical
    ShadowPowerPriority_Normal,         // Standard priority
    ShadowPowerPriority_Low,            // Can be deferred
    ShadowPowerPriority_Max
} SHADOW_POWER_CALLBACK_PRIORITY, *PSHADOW_POWER_CALLBACK_PRIORITY;

// ============================================================================
// POWER EVENT STRUCTURES
// ============================================================================

/**
 * @brief Power event information
 */
typedef struct _SHADOW_POWER_EVENT {
    LIST_ENTRY ListEntry;

    SHADOW_POWER_EVENT_TYPE EventType;
    SHADOW_POWER_STATE PreviousState;
    SHADOW_POWER_STATE NewState;

    LARGE_INTEGER Timestamp;
    UINT64 EventSequence;

    // Additional event data
    union {
        struct {
            ULONG BatteryPercentage;
            ULONG EstimatedTimeRemaining;   // Seconds
        } Battery;

        struct {
            BOOLEAN IsACOnline;
            BOOLEAN IsBatteryPresent;
        } PowerSource;

        struct {
            ULONG ThermalLevel;             // 0-100
            ULONG ThrottlePercent;
        } Thermal;

        struct {
            ULONG SessionId;
            HANDLE UserToken;
        } Session;
    } Data;

    // Processing state
    BOOLEAN Processed;
    BOOLEAN Notified;
    NTSTATUS ProcessingStatus;

} SHADOW_POWER_EVENT, *PSHADOW_POWER_EVENT;

/**
 * @brief Power state snapshot
 */
typedef struct _SHADOW_POWER_STATE_INFO {
    SHADOW_POWER_STATE CurrentState;
    SHADOW_POWER_STATE PreviousState;
    SHADOW_POWER_SOURCE PowerSource;

    LARGE_INTEGER LastStateChangeTime;
    LARGE_INTEGER LastResumeTime;
    LARGE_INTEGER LastSleepTime;

    // Battery information
    BOOLEAN BatteryPresent;
    ULONG BatteryPercentage;
    ULONG BatteryEstimatedTime;         // Seconds remaining
    BOOLEAN BatteryCharging;

    // Display state
    BOOLEAN DisplayOn;
    BOOLEAN DisplayDimmed;

    // User presence
    BOOLEAN LidOpen;
    BOOLEAN UserPresent;
    BOOLEAN SessionLocked;

    // Thermal state
    BOOLEAN ThermalThrottling;
    ULONG ThermalLevel;

    // Connected standby
    BOOLEAN InConnectedStandby;
    ULONG ConnectedStandbyExitCount;

} SHADOW_POWER_STATE_INFO, *PSHADOW_POWER_STATE_INFO;

/**
 * @brief Power callback registration
 */
typedef VOID
(*PSHADOW_POWER_CALLBACK)(
    _In_ SHADOW_POWER_EVENT_TYPE EventType,
    _In_ PSHADOW_POWER_EVENT Event,
    _In_opt_ PVOID Context
    );

typedef struct _SHADOW_POWER_CALLBACK_ENTRY {
    LIST_ENTRY ListEntry;

    PSHADOW_POWER_CALLBACK Callback;
    PVOID Context;
    SHADOW_POWER_CALLBACK_PRIORITY Priority;
    ULONG EventMask;                    // Bitmask of events to receive

    BOOLEAN Enabled;
    volatile LONG CallCount;
    LARGE_INTEGER LastCallTime;

} SHADOW_POWER_CALLBACK_ENTRY, *PSHADOW_POWER_CALLBACK_ENTRY;

/**
 * @brief Power management statistics
 */
typedef struct _SHADOW_POWER_STATISTICS {
    volatile LONG64 TotalPowerEvents;
    volatile LONG64 SleepTransitions;
    volatile LONG64 ResumeTransitions;
    volatile LONG64 HibernateTransitions;
    volatile LONG64 ConnectedStandbyTransitions;
    volatile LONG64 ACDCTransitions;
    volatile LONG64 DisplayStateChanges;
    volatile LONG64 LidStateChanges;
    volatile LONG64 SessionChanges;
    volatile LONG64 ThermalEvents;
    volatile LONG64 CallbacksInvoked;
    volatile LONG64 CallbackErrors;
    volatile LONG64 ValidationsPassed;
    volatile LONG64 ValidationsFailed;

    LARGE_INTEGER TotalSleepDuration;   // Cumulative time in sleep
    LARGE_INTEGER LongestSleepDuration;
    LARGE_INTEGER LastSleepDuration;

} SHADOW_POWER_STATISTICS, *PSHADOW_POWER_STATISTICS;

/**
 * @brief Power management global state
 */
typedef struct _SHADOW_POWER_GLOBALS {
    BOOLEAN Initialized;
    BOOLEAN Enabled;
    BOOLEAN ShuttingDown;

    // Current state
    SHADOW_POWER_STATE_INFO StateInfo;
    EX_PUSH_LOCK StateLock;

    // Power setting callback handles
    PVOID PowerSettingCallbackHandle;
    PVOID ConsoleDisplayStateHandle;
    PVOID MonitorPowerOnHandle;
    PVOID AcDcPowerSourceHandle;
    PVOID LidSwitchStateHandle;
    PVOID BatteryPercentageHandle;
    PVOID PowerSchemeHandle;
    PVOID IdleResiliencyHandle;
    PVOID UserPresenceHandle;

    // System state callback
    PCALLBACK_OBJECT SystemStateCallback;
    PVOID SystemStateRegistration;

    // Event history
    LIST_ENTRY EventHistory;
    EX_PUSH_LOCK EventHistoryLock;
    volatile LONG EventCount;
    volatile LONG64 EventSequence;

    // Registered callbacks
    LIST_ENTRY CallbackList;
    EX_PUSH_LOCK CallbackLock;
    volatile LONG CallbackCount;

    // Resume validation
    KEVENT ResumeValidationComplete;
    BOOLEAN ResumeValidationRequired;
    BOOLEAN ResumeValidationPassed;

    // Pending operation tracking
    volatile LONG PendingOperations;
    KEVENT NoPendingOperationsEvent;

    // Work item for deferred processing
    PIO_WORKITEM DeferredWorkItem;
    PDEVICE_OBJECT DeviceObject;

    // Statistics
    SHADOW_POWER_STATISTICS Stats;

} SHADOW_POWER_GLOBALS, *PSHADOW_POWER_GLOBALS;

// ============================================================================
// FUNCTION PROTOTYPES - INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the power management subsystem.
 *
 * Registers for all power-related notifications:
 * - System power state callback
 * - Power setting callbacks (display, AC/DC, lid, battery)
 * - Session notification callbacks
 *
 * @param DeviceObject Device object for work item allocation.
 * @return STATUS_SUCCESS on success, error status otherwise.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
ShadowRegisterPowerCallbacks(
    _In_opt_ PDEVICE_OBJECT DeviceObject
    );

/**
 * @brief Shutdown the power management subsystem.
 *
 * Unregisters all callbacks and frees resources.
 * Waits for any pending operations to complete.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
ShadowUnregisterPowerCallbacks(
    VOID
    );

/**
 * @brief Enable or disable power management.
 *
 * @param Enable TRUE to enable, FALSE to disable.
 * @return STATUS_SUCCESS on success.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
ShadowPowerSetEnabled(
    _In_ BOOLEAN Enable
    );

// ============================================================================
// FUNCTION PROTOTYPES - STATE QUERY
// ============================================================================

/**
 * @brief Get current power state information.
 *
 * @param StateInfo Pointer to receive state information.
 * @return STATUS_SUCCESS on success.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowPowerGetState(
    _Out_ PSHADOW_POWER_STATE_INFO StateInfo
    );

/**
 * @brief Check if system is in low-power state.
 *
 * @return TRUE if in sleep/hibernate/connected standby.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowPowerIsLowPowerState(
    VOID
    );

/**
 * @brief Check if system is resuming from sleep.
 *
 * @return TRUE if recently resumed and validation pending.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowPowerIsResuming(
    VOID
    );

/**
 * @brief Check if running on battery power.
 *
 * @return TRUE if on battery, FALSE if on AC or unknown.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowPowerIsOnBattery(
    VOID
    );

/**
 * @brief Get battery percentage.
 *
 * @return Battery percentage (0-100), or 0 if unknown/no battery.
 */
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
 * @param Callback Function to call on power events.
 * @param Context Context passed to callback.
 * @param Priority Callback priority.
 * @param EventMask Bitmask of events to receive (0 = all events).
 * @param Handle Receives callback handle for unregistration.
 * @return STATUS_SUCCESS on success.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
ShadowPowerRegisterCallback(
    _In_ PSHADOW_POWER_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _In_ SHADOW_POWER_CALLBACK_PRIORITY Priority,
    _In_ ULONG EventMask,
    _Out_ PVOID* Handle
    );

/**
 * @brief Unregister a power event callback.
 *
 * @param Handle Callback handle from registration.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
ShadowPowerUnregisterCallback(
    _In_ PVOID Handle
    );

// ============================================================================
// FUNCTION PROTOTYPES - EVENT MANAGEMENT
// ============================================================================

/**
 * @brief Get recent power event history.
 *
 * @param Events Array to receive events.
 * @param MaxEvents Maximum events to return.
 * @param EventCount Receives actual event count.
 * @return STATUS_SUCCESS on success.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
ShadowPowerGetEventHistory(
    _Out_writes_to_(MaxEvents, *EventCount) PSHADOW_POWER_EVENT Events,
    _In_ ULONG MaxEvents,
    _Out_ PULONG EventCount
    );

/**
 * @brief Wait for pending operations before sleep.
 *
 * Called internally before entering sleep state.
 * Waits for outstanding operations to complete.
 *
 * @param TimeoutMs Maximum time to wait.
 * @return STATUS_SUCCESS if all operations completed.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
ShadowPowerWaitForPendingOperations(
    _In_ ULONG TimeoutMs
    );

/**
 * @brief Signal that a power-sensitive operation is starting.
 *
 * Call before starting operations that should block sleep.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowPowerEnterOperation(
    VOID
    );

/**
 * @brief Signal that a power-sensitive operation has completed.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowPowerLeaveOperation(
    VOID
    );

// ============================================================================
// FUNCTION PROTOTYPES - RESUME VALIDATION
// ============================================================================

/**
 * @brief Perform security validation after resume.
 *
 * Called after system resumes from sleep/hibernate.
 * Validates critical system state hasn't been tampered.
 *
 * @return STATUS_SUCCESS if validation passes.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
ShadowPowerValidateResume(
    VOID
    );

/**
 * @brief Wait for resume validation to complete.
 *
 * @param TimeoutMs Maximum time to wait.
 * @return TRUE if validation completed successfully.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
ShadowPowerWaitForResumeValidation(
    _In_ ULONG TimeoutMs
    );

// ============================================================================
// FUNCTION PROTOTYPES - STATISTICS
// ============================================================================

/**
 * @brief Get power management statistics.
 *
 * @param Stats Pointer to receive statistics.
 * @return STATUS_SUCCESS on success.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowPowerGetStatistics(
    _Out_ PSHADOW_POWER_STATISTICS Stats
    );

/**
 * @brief Reset power management statistics.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowPowerResetStatistics(
    VOID
    );

// ============================================================================
// FUNCTION PROTOTYPES - UTILITY
// ============================================================================

/**
 * @brief Get string name for power state.
 *
 * @param State Power state value.
 * @return Static string name.
 */
PCSTR
ShadowPowerStateToString(
    _In_ SHADOW_POWER_STATE State
    );

/**
 * @brief Get string name for power event type.
 *
 * @param EventType Event type value.
 * @return Static string name.
 */
PCSTR
ShadowPowerEventToString(
    _In_ SHADOW_POWER_EVENT_TYPE EventType
    );

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_POWER_CALLBACK_H
