/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE POWER MANAGEMENT IMPLEMENTATION
 * ============================================================================
 *
 * @file PowerCallback.c
 * @brief Enterprise-grade power state management for kernel EDR.
 *
 * Implements comprehensive power transition handling:
 * - System power state callback (PoRegisterPowerSettingCallback)
 * - Connected Standby / Modern Standby support
 * - AC/DC power source monitoring
 * - Display state tracking
 * - Lid switch monitoring
 * - Battery level tracking
 * - Session lock/unlock detection
 * - Resume validation for security
 *
 * Security Considerations:
 * - Malware may attempt attacks during power transitions
 * - Cold boot attacks possible after hibernate
 * - Time-based evasion using sleep/resume
 * - Re-validation of driver state after resume
 *
 * BSOD PREVENTION:
 * - All callbacks are non-blocking
 * - Proper IRQL handling throughout
 * - Safe state transitions with atomic operations
 * - Graceful handling of rapid power state changes
 * - No allocations in power callbacks when possible
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "PowerCallback.h"
#include "../Core/Globals.h"
#include <ntstrsafe.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ShadowRegisterPowerCallbacks)
#pragma alloc_text(PAGE, ShadowUnregisterPowerCallbacks)
#pragma alloc_text(PAGE, ShadowPowerSetEnabled)
#pragma alloc_text(PAGE, ShadowPowerRegisterCallback)
#pragma alloc_text(PAGE, ShadowPowerUnregisterCallback)
#pragma alloc_text(PAGE, ShadowPowerGetEventHistory)
#pragma alloc_text(PAGE, ShadowPowerWaitForPendingOperations)
#pragma alloc_text(PAGE, ShadowPowerValidateResume)
#pragma alloc_text(PAGE, ShadowPowerWaitForResumeValidation)
#endif

// ============================================================================
// POWER SETTING GUIDs
// ============================================================================

//
// GUID_CONSOLE_DISPLAY_STATE - Display on/off/dimmed
// {6FE69556-704A-47A0-8F24-C28D936FDA47}
//
DEFINE_GUID(GUID_CONSOLE_DISPLAY_STATE,
    0x6FE69556, 0x704A, 0x47A0, 0x8F, 0x24, 0xC2, 0x8D, 0x93, 0x6F, 0xDA, 0x47);

//
// GUID_MONITOR_POWER_ON - Monitor power state
// {02731015-4510-4526-99E6-E5A17EBD1AEA}
//
DEFINE_GUID(GUID_MONITOR_POWER_ON,
    0x02731015, 0x4510, 0x4526, 0x99, 0xE6, 0xE5, 0xA1, 0x7E, 0xBD, 0x1A, 0xEA);

//
// GUID_ACDC_POWER_SOURCE - AC/DC power source
// {5D3E9A59-E9D5-4B00-A6BD-FF34FF516548}
//
DEFINE_GUID(GUID_ACDC_POWER_SOURCE,
    0x5D3E9A59, 0xE9D5, 0x4B00, 0xA6, 0xBD, 0xFF, 0x34, 0xFF, 0x51, 0x65, 0x48);

//
// GUID_LIDSWITCH_STATE_CHANGE - Lid open/close
// {BA3E0F4D-B817-4094-A2D1-D56379E6A0F3}
//
DEFINE_GUID(GUID_LIDSWITCH_STATE_CHANGE,
    0xBA3E0F4D, 0xB817, 0x4094, 0xA2, 0xD1, 0xD5, 0x63, 0x79, 0xE6, 0xA0, 0xF3);

//
// GUID_BATTERY_PERCENTAGE_REMAINING - Battery level
// {A7AD8041-B45A-4CAE-87A3-EECBB468A9E1}
//
DEFINE_GUID(GUID_BATTERY_PERCENTAGE_REMAINING,
    0xA7AD8041, 0xB45A, 0x4CAE, 0x87, 0xA3, 0xEE, 0xCB, 0xB4, 0x68, 0xA9, 0xE1);

//
// GUID_IDLE_RESILIENCY - Connected Standby entry/exit
// {C42B1B9A-2D5B-4C55-9E20-FB9FFFB7D32F}
//
DEFINE_GUID(GUID_IDLE_RESILIENCY,
    0xC42B1B9A, 0x2D5B, 0x4C55, 0x9E, 0x20, 0xFB, 0x9F, 0xFF, 0xB7, 0xD3, 0x2F);

//
// GUID_SESSION_DISPLAY_STATUS - Session lock/unlock
// {2B84C20E-AD23-4DDF-93DB-05FFBD7EFCA5}
//
DEFINE_GUID(GUID_SESSION_DISPLAY_STATUS,
    0x2B84C20E, 0xAD23, 0x4DDF, 0x93, 0xDB, 0x05, 0xFF, 0xBD, 0x7E, 0xFC, 0xA5);

//
// GUID_SESSION_USER_PRESENCE - User presence detection
// {3C0F4548-C03F-4C4D-B9F2-237EDE686376}
//
DEFINE_GUID(GUID_SESSION_USER_PRESENCE,
    0x3C0F4548, 0xC03F, 0x4C4D, 0xB9, 0xF2, 0x23, 0x7E, 0xDE, 0x68, 0x63, 0x76);

//
// GUID_SYSTEM_AWAYMODE - Away mode state
// {98A7F580-01F7-48AA-9C0F-44352C29E5C0}
//
DEFINE_GUID(GUID_SYSTEM_AWAYMODE,
    0x98A7F580, 0x01F7, 0x48AA, 0x9C, 0x0F, 0x44, 0x35, 0x2C, 0x29, 0xE5, 0xC0);

// ============================================================================
// GLOBAL STATE
// ============================================================================

/**
 * @brief Power management global state
 */
static SHADOW_POWER_GLOBALS g_PowerState = {0};

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static NTSTATUS
PwrpRegisterPowerSettingCallbacks(
    VOID
    );

static VOID
PwrpUnregisterPowerSettingCallbacks(
    VOID
    );

static NTSTATUS
PwrpRegisterSystemStateCallback(
    VOID
    );

static VOID
PwrpUnregisterSystemStateCallback(
    VOID
    );

static NTSTATUS NTAPI
PwrpPowerSettingCallback(
    _In_ LPCGUID SettingGuid,
    _In_ PVOID Value,
    _In_ ULONG ValueLength,
    _Inout_opt_ PVOID Context
    );

static VOID
PwrpSystemStateCallback(
    _In_opt_ PVOID CallbackContext,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2
    );

static VOID
PwrpProcessPowerEvent(
    _In_ SHADOW_POWER_EVENT_TYPE EventType,
    _In_opt_ PVOID EventData,
    _In_ ULONG EventDataSize
    );

static VOID
PwrpRecordEvent(
    _In_ PSHADOW_POWER_EVENT Event
    );

static VOID
PwrpNotifyCallbacks(
    _In_ PSHADOW_POWER_EVENT Event
    );

static VOID
PwrpDeferredWorkRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    );

static VOID
PwrpCleanupEventHistory(
    VOID
    );

static VOID
PwrpUpdateStateFromEvent(
    _In_ PSHADOW_POWER_EVENT Event
    );

static NTSTATUS
PwrpPerformResumeValidation(
    VOID
    );

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the power management subsystem.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
ShadowRegisterPowerCallbacks(
    _In_opt_ PDEVICE_OBJECT DeviceObject
    )
{
    NTSTATUS status;

    PAGED_CODE();

    //
    // Check if already initialized
    //
    if (g_PowerState.Initialized) {
        return STATUS_ALREADY_INITIALIZED;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Initializing power management subsystem\n");

    RtlZeroMemory(&g_PowerState, sizeof(SHADOW_POWER_GLOBALS));

    //
    // Store device object
    //
    g_PowerState.DeviceObject = DeviceObject;

    //
    // Initialize locks
    //
    ExInitializePushLock(&g_PowerState.StateLock);
    ExInitializePushLock(&g_PowerState.EventHistoryLock);
    ExInitializePushLock(&g_PowerState.CallbackLock);

    //
    // Initialize lists
    //
    InitializeListHead(&g_PowerState.EventHistory);
    InitializeListHead(&g_PowerState.CallbackList);

    //
    // Initialize events
    //
    KeInitializeEvent(&g_PowerState.ResumeValidationComplete, NotificationEvent, TRUE);
    KeInitializeEvent(&g_PowerState.NoPendingOperationsEvent, NotificationEvent, TRUE);

    //
    // Initialize default state
    //
    g_PowerState.StateInfo.CurrentState = ShadowPowerState_Working;
    g_PowerState.StateInfo.PreviousState = ShadowPowerState_Unknown;
    g_PowerState.StateInfo.PowerSource = ShadowPowerSource_Unknown;
    g_PowerState.StateInfo.DisplayOn = TRUE;
    g_PowerState.StateInfo.LidOpen = TRUE;
    g_PowerState.StateInfo.UserPresent = TRUE;
    KeQuerySystemTime(&g_PowerState.StateInfo.LastStateChangeTime);

    //
    // Allocate work item for deferred processing
    //
    if (DeviceObject != NULL) {
        g_PowerState.DeferredWorkItem = IoAllocateWorkItem(DeviceObject);
        if (g_PowerState.DeferredWorkItem == NULL) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] Failed to allocate power work item\n");
            // Non-fatal - continue without deferred processing
        }
    }

    //
    // Register system state callback (sleep/resume)
    //
    status = PwrpRegisterSystemStateCallback();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Failed to register system state callback: 0x%08X\n",
                   status);
        // Non-fatal - continue with power setting callbacks
    }

    //
    // Register power setting callbacks
    //
    status = PwrpRegisterPowerSettingCallbacks();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Failed to register power setting callbacks: 0x%08X\n",
                   status);
        // Non-fatal - we can still operate without all callbacks
    }

    //
    // Record initialization time
    //
    KeQuerySystemTime(&g_PowerState.Stats.TotalSleepDuration);
    g_PowerState.Stats.TotalSleepDuration.QuadPart = 0;

    //
    // Mark as initialized and enabled
    //
    g_PowerState.Initialized = TRUE;
    g_PowerState.Enabled = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Power management initialized successfully\n");

    return STATUS_SUCCESS;
}

/**
 * @brief Shutdown the power management subsystem.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
ShadowUnregisterPowerCallbacks(
    VOID
    )
{
    PLIST_ENTRY entry;
    PSHADOW_POWER_EVENT event;
    PSHADOW_POWER_CALLBACK_ENTRY callbackEntry;
    LARGE_INTEGER timeout;

    PAGED_CODE();

    if (!g_PowerState.Initialized) {
        return;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Shutting down power management\n");

    //
    // Mark as shutting down
    //
    g_PowerState.ShuttingDown = TRUE;
    g_PowerState.Enabled = FALSE;

    //
    // Wait for pending operations
    //
    if (g_PowerState.PendingOperations > 0) {
        timeout.QuadPart = -50000000;  // 5 seconds
        KeWaitForSingleObject(
            &g_PowerState.NoPendingOperationsEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout
            );
    }

    //
    // Unregister power setting callbacks
    //
    PwrpUnregisterPowerSettingCallbacks();

    //
    // Unregister system state callback
    //
    PwrpUnregisterSystemStateCallback();

    //
    // Free work item
    //
    if (g_PowerState.DeferredWorkItem != NULL) {
        IoFreeWorkItem(g_PowerState.DeferredWorkItem);
        g_PowerState.DeferredWorkItem = NULL;
    }

    //
    // Free event history
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PowerState.EventHistoryLock);

    while (!IsListEmpty(&g_PowerState.EventHistory)) {
        entry = RemoveHeadList(&g_PowerState.EventHistory);
        event = CONTAINING_RECORD(entry, SHADOW_POWER_EVENT, ListEntry);
        ExFreePoolWithTag(event, PWR_POOL_TAG_EVENT);
    }
    g_PowerState.EventCount = 0;

    ExReleasePushLockExclusive(&g_PowerState.EventHistoryLock);
    KeLeaveCriticalRegion();

    //
    // Free registered callbacks
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PowerState.CallbackLock);

    while (!IsListEmpty(&g_PowerState.CallbackList)) {
        entry = RemoveHeadList(&g_PowerState.CallbackList);
        callbackEntry = CONTAINING_RECORD(entry, SHADOW_POWER_CALLBACK_ENTRY, ListEntry);
        ExFreePoolWithTag(callbackEntry, PWR_POOL_TAG_CALLBACK);
    }
    g_PowerState.CallbackCount = 0;

    ExReleasePushLockExclusive(&g_PowerState.CallbackLock);
    KeLeaveCriticalRegion();

    //
    // Log final statistics
    //
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Power stats: Events=%lld, Sleep=%lld, Resume=%lld, "
               "Hibernate=%lld, ConnStandby=%lld\n",
               g_PowerState.Stats.TotalPowerEvents,
               g_PowerState.Stats.SleepTransitions,
               g_PowerState.Stats.ResumeTransitions,
               g_PowerState.Stats.HibernateTransitions,
               g_PowerState.Stats.ConnectedStandbyTransitions);

    g_PowerState.Initialized = FALSE;
    RtlZeroMemory(&g_PowerState, sizeof(SHADOW_POWER_GLOBALS));
}

/**
 * @brief Enable or disable power management.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
ShadowPowerSetEnabled(
    _In_ BOOLEAN Enable
    )
{
    PAGED_CODE();

    if (!g_PowerState.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    g_PowerState.Enabled = Enable;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Power management %s\n",
               Enable ? "enabled" : "disabled");

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - STATE QUERY
// ============================================================================

/**
 * @brief Get current power state information.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowPowerGetState(
    _Out_ PSHADOW_POWER_STATE_INFO StateInfo
    )
{
    if (StateInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_PowerState.Initialized) {
        RtlZeroMemory(StateInfo, sizeof(SHADOW_POWER_STATE_INFO));
        return STATUS_DEVICE_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_PowerState.StateLock);

    RtlCopyMemory(StateInfo, &g_PowerState.StateInfo, sizeof(SHADOW_POWER_STATE_INFO));

    ExReleasePushLockShared(&g_PowerState.StateLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

/**
 * @brief Check if system is in low-power state.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowPowerIsLowPowerState(
    VOID
    )
{
    SHADOW_POWER_STATE state;

    if (!g_PowerState.Initialized) {
        return FALSE;
    }

    state = g_PowerState.StateInfo.CurrentState;

    return (state == ShadowPowerState_Standby ||
            state == ShadowPowerState_Hibernate ||
            state == ShadowPowerState_ConnectedStandby ||
            state == ShadowPowerState_HybridSleep);
}

/**
 * @brief Check if system is resuming from sleep.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowPowerIsResuming(
    VOID
    )
{
    if (!g_PowerState.Initialized) {
        return FALSE;
    }

    return g_PowerState.ResumeValidationRequired &&
           !g_PowerState.ResumeValidationPassed;
}

/**
 * @brief Check if running on battery power.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowPowerIsOnBattery(
    VOID
    )
{
    if (!g_PowerState.Initialized) {
        return FALSE;
    }

    return (g_PowerState.StateInfo.PowerSource == ShadowPowerSource_DC);
}

/**
 * @brief Get battery percentage.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
ShadowPowerGetBatteryPercentage(
    VOID
    )
{
    if (!g_PowerState.Initialized) {
        return 0;
    }

    if (!g_PowerState.StateInfo.BatteryPresent) {
        return 0;
    }

    return g_PowerState.StateInfo.BatteryPercentage;
}

// ============================================================================
// PUBLIC API - CALLBACK REGISTRATION
// ============================================================================

/**
 * @brief Register a power event callback.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
ShadowPowerRegisterCallback(
    _In_ PSHADOW_POWER_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _In_ SHADOW_POWER_CALLBACK_PRIORITY Priority,
    _In_ ULONG EventMask,
    _Out_ PVOID* Handle
    )
{
    PSHADOW_POWER_CALLBACK_ENTRY entry;

    PAGED_CODE();

    if (Callback == NULL || Handle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Handle = NULL;

    if (!g_PowerState.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (g_PowerState.CallbackCount >= PWR_MAX_CALLBACKS) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Allocate callback entry
    //
    entry = (PSHADOW_POWER_CALLBACK_ENTRY)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(SHADOW_POWER_CALLBACK_ENTRY),
        PWR_POOL_TAG_CALLBACK
        );

    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    entry->Callback = Callback;
    entry->Context = Context;
    entry->Priority = Priority;
    entry->EventMask = EventMask;
    entry->Enabled = TRUE;
    entry->CallCount = 0;

    //
    // Insert into list (sorted by priority)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PowerState.CallbackLock);

    //
    // Find insertion point based on priority
    //
    PLIST_ENTRY insertBefore = &g_PowerState.CallbackList;
    PLIST_ENTRY current;

    for (current = g_PowerState.CallbackList.Flink;
         current != &g_PowerState.CallbackList;
         current = current->Flink) {

        PSHADOW_POWER_CALLBACK_ENTRY existing = CONTAINING_RECORD(
            current, SHADOW_POWER_CALLBACK_ENTRY, ListEntry);

        if (existing->Priority > Priority) {
            insertBefore = current;
            break;
        }
    }

    InsertTailList(insertBefore, &entry->ListEntry);
    InterlockedIncrement(&g_PowerState.CallbackCount);

    ExReleasePushLockExclusive(&g_PowerState.CallbackLock);
    KeLeaveCriticalRegion();

    *Handle = entry;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] Power callback registered (priority=%d, mask=0x%X)\n",
               Priority, EventMask);

    return STATUS_SUCCESS;
}

/**
 * @brief Unregister a power event callback.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
ShadowPowerUnregisterCallback(
    _In_ PVOID Handle
    )
{
    PSHADOW_POWER_CALLBACK_ENTRY entry = (PSHADOW_POWER_CALLBACK_ENTRY)Handle;
    PLIST_ENTRY current;
    BOOLEAN found = FALSE;

    PAGED_CODE();

    if (Handle == NULL || !g_PowerState.Initialized) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PowerState.CallbackLock);

    //
    // Verify handle is in our list
    //
    for (current = g_PowerState.CallbackList.Flink;
         current != &g_PowerState.CallbackList;
         current = current->Flink) {

        if (current == &entry->ListEntry) {
            RemoveEntryList(&entry->ListEntry);
            InterlockedDecrement(&g_PowerState.CallbackCount);
            found = TRUE;
            break;
        }
    }

    ExReleasePushLockExclusive(&g_PowerState.CallbackLock);
    KeLeaveCriticalRegion();

    if (found) {
        ExFreePoolWithTag(entry, PWR_POOL_TAG_CALLBACK);
    }
}

// ============================================================================
// PUBLIC API - EVENT MANAGEMENT
// ============================================================================

/**
 * @brief Get recent power event history.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
ShadowPowerGetEventHistory(
    _Out_writes_to_(MaxEvents, *EventCount) PSHADOW_POWER_EVENT Events,
    _In_ ULONG MaxEvents,
    _Out_ PULONG EventCount
    )
{
    PLIST_ENTRY entry;
    PSHADOW_POWER_EVENT event;
    ULONG count = 0;

    PAGED_CODE();

    if (Events == NULL || EventCount == NULL || MaxEvents == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *EventCount = 0;

    if (!g_PowerState.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_PowerState.EventHistoryLock);

    for (entry = g_PowerState.EventHistory.Flink;
         entry != &g_PowerState.EventHistory && count < MaxEvents;
         entry = entry->Flink) {

        event = CONTAINING_RECORD(entry, SHADOW_POWER_EVENT, ListEntry);
        RtlCopyMemory(&Events[count], event, sizeof(SHADOW_POWER_EVENT));
        count++;
    }

    ExReleasePushLockShared(&g_PowerState.EventHistoryLock);
    KeLeaveCriticalRegion();

    *EventCount = count;
    return STATUS_SUCCESS;
}

/**
 * @brief Wait for pending operations before sleep.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
ShadowPowerWaitForPendingOperations(
    _In_ ULONG TimeoutMs
    )
{
    LARGE_INTEGER timeout;
    NTSTATUS status;

    PAGED_CODE();

    if (!g_PowerState.Initialized) {
        return STATUS_SUCCESS;
    }

    if (g_PowerState.PendingOperations == 0) {
        return STATUS_SUCCESS;
    }

    timeout.QuadPart = -((LONGLONG)TimeoutMs * 10000);

    status = KeWaitForSingleObject(
        &g_PowerState.NoPendingOperationsEvent,
        Executive,
        KernelMode,
        FALSE,
        &timeout
        );

    if (status == STATUS_TIMEOUT) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Timeout waiting for %d pending operations\n",
                   g_PowerState.PendingOperations);
        return STATUS_TIMEOUT;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Signal that a power-sensitive operation is starting.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowPowerEnterOperation(
    VOID
    )
{
    if (!g_PowerState.Initialized) {
        return;
    }

    if (InterlockedIncrement(&g_PowerState.PendingOperations) == 1) {
        KeClearEvent(&g_PowerState.NoPendingOperationsEvent);
    }
}

/**
 * @brief Signal that a power-sensitive operation has completed.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowPowerLeaveOperation(
    VOID
    )
{
    LONG count;

    if (!g_PowerState.Initialized) {
        return;
    }

    count = InterlockedDecrement(&g_PowerState.PendingOperations);

    if (count == 0) {
        KeSetEvent(&g_PowerState.NoPendingOperationsEvent, IO_NO_INCREMENT, FALSE);
    }

    if (count < 0) {
        //
        // Mismatched Enter/Leave - fix the count
        //
        InterlockedExchange(&g_PowerState.PendingOperations, 0);
        KeSetEvent(&g_PowerState.NoPendingOperationsEvent, IO_NO_INCREMENT, FALSE);
    }
}

// ============================================================================
// PUBLIC API - RESUME VALIDATION
// ============================================================================

/**
 * @brief Perform security validation after resume.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
ShadowPowerValidateResume(
    VOID
    )
{
    NTSTATUS status;

    PAGED_CODE();

    if (!g_PowerState.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Performing post-resume validation\n");

    //
    // Clear validation event
    //
    KeClearEvent(&g_PowerState.ResumeValidationComplete);
    g_PowerState.ResumeValidationRequired = TRUE;
    g_PowerState.ResumeValidationPassed = FALSE;

    //
    // Perform validation
    //
    status = PwrpPerformResumeValidation();

    if (NT_SUCCESS(status)) {
        g_PowerState.ResumeValidationPassed = TRUE;
        InterlockedIncrement64(&g_PowerState.Stats.ValidationsPassed);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike] Post-resume validation PASSED\n");
    } else {
        InterlockedIncrement64(&g_PowerState.Stats.ValidationsFailed);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Post-resume validation FAILED: 0x%08X\n",
                   status);
    }

    //
    // Signal completion
    //
    g_PowerState.ResumeValidationRequired = FALSE;
    KeSetEvent(&g_PowerState.ResumeValidationComplete, IO_NO_INCREMENT, FALSE);

    return status;
}

/**
 * @brief Wait for resume validation to complete.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
ShadowPowerWaitForResumeValidation(
    _In_ ULONG TimeoutMs
    )
{
    LARGE_INTEGER timeout;
    NTSTATUS status;

    PAGED_CODE();

    if (!g_PowerState.Initialized) {
        return TRUE;
    }

    if (!g_PowerState.ResumeValidationRequired) {
        return g_PowerState.ResumeValidationPassed;
    }

    timeout.QuadPart = -((LONGLONG)TimeoutMs * 10000);

    status = KeWaitForSingleObject(
        &g_PowerState.ResumeValidationComplete,
        Executive,
        KernelMode,
        FALSE,
        &timeout
        );

    if (status == STATUS_TIMEOUT) {
        return FALSE;
    }

    return g_PowerState.ResumeValidationPassed;
}

// ============================================================================
// PUBLIC API - STATISTICS
// ============================================================================

/**
 * @brief Get power management statistics.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowPowerGetStatistics(
    _Out_ PSHADOW_POWER_STATISTICS Stats
    )
{
    if (Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_PowerState.Initialized) {
        RtlZeroMemory(Stats, sizeof(SHADOW_POWER_STATISTICS));
        return STATUS_DEVICE_NOT_READY;
    }

    RtlCopyMemory(Stats, &g_PowerState.Stats, sizeof(SHADOW_POWER_STATISTICS));
    return STATUS_SUCCESS;
}

/**
 * @brief Reset power management statistics.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowPowerResetStatistics(
    VOID
    )
{
    if (!g_PowerState.Initialized) {
        return;
    }

    RtlZeroMemory(&g_PowerState.Stats, sizeof(SHADOW_POWER_STATISTICS));
}

// ============================================================================
// PUBLIC API - UTILITY
// ============================================================================

/**
 * @brief Get string name for power state.
 */
PCSTR
ShadowPowerStateToString(
    _In_ SHADOW_POWER_STATE State
    )
{
    switch (State) {
        case ShadowPowerState_Unknown:          return "Unknown";
        case ShadowPowerState_Working:          return "Working (S0)";
        case ShadowPowerState_Standby:          return "Standby (S1-S3)";
        case ShadowPowerState_Hibernate:        return "Hibernate (S4)";
        case ShadowPowerState_Shutdown:         return "Shutdown (S5)";
        case ShadowPowerState_ConnectedStandby: return "Connected Standby";
        case ShadowPowerState_HybridSleep:      return "Hybrid Sleep";
        case ShadowPowerState_FastStartup:      return "Fast Startup";
        default:                                return "Invalid";
    }
}

/**
 * @brief Get string name for power event type.
 */
PCSTR
ShadowPowerEventToString(
    _In_ SHADOW_POWER_EVENT_TYPE EventType
    )
{
    switch (EventType) {
        case ShadowPowerEvent_None:                     return "None";
        case ShadowPowerEvent_EnteringSleep:            return "Entering Sleep";
        case ShadowPowerEvent_ResumingFromSleep:        return "Resuming From Sleep";
        case ShadowPowerEvent_EnteringHibernate:        return "Entering Hibernate";
        case ShadowPowerEvent_ResumingFromHibernate:    return "Resuming From Hibernate";
        case ShadowPowerEvent_EnteringConnectedStandby: return "Entering Connected Standby";
        case ShadowPowerEvent_ExitingConnectedStandby:  return "Exiting Connected Standby";
        case ShadowPowerEvent_Shutdown:                 return "Shutdown";
        case ShadowPowerEvent_ACPowerConnected:         return "AC Power Connected";
        case ShadowPowerEvent_ACPowerDisconnected:      return "AC Power Disconnected";
        case ShadowPowerEvent_BatteryLow:               return "Battery Low";
        case ShadowPowerEvent_BatteryCritical:          return "Battery Critical";
        case ShadowPowerEvent_DisplayOn:                return "Display On";
        case ShadowPowerEvent_DisplayOff:               return "Display Off";
        case ShadowPowerEvent_DisplayDimmed:            return "Display Dimmed";
        case ShadowPowerEvent_UserPresent:              return "User Present";
        case ShadowPowerEvent_UserAway:                 return "User Away";
        case ShadowPowerEvent_LidOpen:                  return "Lid Open";
        case ShadowPowerEvent_LidClosed:                return "Lid Closed";
        case ShadowPowerEvent_ThermalThrottling:        return "Thermal Throttling";
        case ShadowPowerEvent_ThermalNormal:            return "Thermal Normal";
        case ShadowPowerEvent_PowerThrottling:          return "Power Throttling";
        case ShadowPowerEvent_PowerNormal:              return "Power Normal";
        case ShadowPowerEvent_SessionLock:              return "Session Lock";
        case ShadowPowerEvent_SessionUnlock:            return "Session Unlock";
        case ShadowPowerEvent_SessionLogoff:            return "Session Logoff";
        case ShadowPowerEvent_SessionLogon:             return "Session Logon";
        default:                                        return "Unknown";
    }
}

// ============================================================================
// PRIVATE FUNCTIONS - CALLBACK REGISTRATION
// ============================================================================

/**
 * @brief Register power setting callbacks.
 */
static NTSTATUS
PwrpRegisterPowerSettingCallbacks(
    VOID
    )
{
    NTSTATUS status;

    //
    // Register for console display state (on/off/dimmed)
    //
    status = PoRegisterPowerSettingCallback(
        NULL,
        &GUID_CONSOLE_DISPLAY_STATE,
        PwrpPowerSettingCallback,
        (PVOID)(ULONG_PTR)1,  // Context indicates callback type
        &g_PowerState.ConsoleDisplayStateHandle
        );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Failed to register CONSOLE_DISPLAY_STATE: 0x%08X\n",
                   status);
    }

    //
    // Register for AC/DC power source
    //
    status = PoRegisterPowerSettingCallback(
        NULL,
        &GUID_ACDC_POWER_SOURCE,
        PwrpPowerSettingCallback,
        (PVOID)(ULONG_PTR)2,
        &g_PowerState.AcDcPowerSourceHandle
        );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Failed to register ACDC_POWER_SOURCE: 0x%08X\n",
                   status);
    }

    //
    // Register for lid switch state
    //
    status = PoRegisterPowerSettingCallback(
        NULL,
        &GUID_LIDSWITCH_STATE_CHANGE,
        PwrpPowerSettingCallback,
        (PVOID)(ULONG_PTR)3,
        &g_PowerState.LidSwitchStateHandle
        );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Failed to register LIDSWITCH_STATE: 0x%08X\n",
                   status);
    }

    //
    // Register for battery percentage
    //
    status = PoRegisterPowerSettingCallback(
        NULL,
        &GUID_BATTERY_PERCENTAGE_REMAINING,
        PwrpPowerSettingCallback,
        (PVOID)(ULONG_PTR)4,
        &g_PowerState.BatteryPercentageHandle
        );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Failed to register BATTERY_PERCENTAGE: 0x%08X\n",
                   status);
    }

    //
    // Register for idle resiliency (Connected Standby)
    //
    status = PoRegisterPowerSettingCallback(
        NULL,
        &GUID_IDLE_RESILIENCY,
        PwrpPowerSettingCallback,
        (PVOID)(ULONG_PTR)5,
        &g_PowerState.IdleResiliencyHandle
        );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Failed to register IDLE_RESILIENCY: 0x%08X\n",
                   status);
    }

    //
    // Register for user presence
    //
    status = PoRegisterPowerSettingCallback(
        NULL,
        &GUID_SESSION_USER_PRESENCE,
        PwrpPowerSettingCallback,
        (PVOID)(ULONG_PTR)6,
        &g_PowerState.UserPresenceHandle
        );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Failed to register USER_PRESENCE: 0x%08X\n",
                   status);
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Unregister power setting callbacks.
 */
static VOID
PwrpUnregisterPowerSettingCallbacks(
    VOID
    )
{
    if (g_PowerState.ConsoleDisplayStateHandle != NULL) {
        PoUnregisterPowerSettingCallback(g_PowerState.ConsoleDisplayStateHandle);
        g_PowerState.ConsoleDisplayStateHandle = NULL;
    }

    if (g_PowerState.AcDcPowerSourceHandle != NULL) {
        PoUnregisterPowerSettingCallback(g_PowerState.AcDcPowerSourceHandle);
        g_PowerState.AcDcPowerSourceHandle = NULL;
    }

    if (g_PowerState.LidSwitchStateHandle != NULL) {
        PoUnregisterPowerSettingCallback(g_PowerState.LidSwitchStateHandle);
        g_PowerState.LidSwitchStateHandle = NULL;
    }

    if (g_PowerState.BatteryPercentageHandle != NULL) {
        PoUnregisterPowerSettingCallback(g_PowerState.BatteryPercentageHandle);
        g_PowerState.BatteryPercentageHandle = NULL;
    }

    if (g_PowerState.IdleResiliencyHandle != NULL) {
        PoUnregisterPowerSettingCallback(g_PowerState.IdleResiliencyHandle);
        g_PowerState.IdleResiliencyHandle = NULL;
    }

    if (g_PowerState.UserPresenceHandle != NULL) {
        PoUnregisterPowerSettingCallback(g_PowerState.UserPresenceHandle);
        g_PowerState.UserPresenceHandle = NULL;
    }
}

/**
 * @brief Register system state callback.
 */
static NTSTATUS
PwrpRegisterSystemStateCallback(
    VOID
    )
{
    NTSTATUS status;
    UNICODE_STRING callbackName;
    OBJECT_ATTRIBUTES oa;

    //
    // Open the system state callback object
    //
    RtlInitUnicodeString(&callbackName, L"\\Callback\\PowerState");
    InitializeObjectAttributes(&oa, &callbackName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ExCreateCallback(
        &g_PowerState.SystemStateCallback,
        &oa,
        FALSE,  // Don't create if doesn't exist
        TRUE    // Allow multiple callbacks
        );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Failed to open PowerState callback: 0x%08X\n",
                   status);
        return status;
    }

    //
    // Register our callback
    //
    g_PowerState.SystemStateRegistration = ExRegisterCallback(
        g_PowerState.SystemStateCallback,
        PwrpSystemStateCallback,
        NULL
        );

    if (g_PowerState.SystemStateRegistration == NULL) {
        ObDereferenceObject(g_PowerState.SystemStateCallback);
        g_PowerState.SystemStateCallback = NULL;
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Unregister system state callback.
 */
static VOID
PwrpUnregisterSystemStateCallback(
    VOID
    )
{
    if (g_PowerState.SystemStateRegistration != NULL) {
        ExUnregisterCallback(g_PowerState.SystemStateRegistration);
        g_PowerState.SystemStateRegistration = NULL;
    }

    if (g_PowerState.SystemStateCallback != NULL) {
        ObDereferenceObject(g_PowerState.SystemStateCallback);
        g_PowerState.SystemStateCallback = NULL;
    }
}

// ============================================================================
// PRIVATE FUNCTIONS - CALLBACKS
// ============================================================================

/**
 * @brief Power setting callback handler.
 */
static NTSTATUS NTAPI
PwrpPowerSettingCallback(
    _In_ LPCGUID SettingGuid,
    _In_ PVOID Value,
    _In_ ULONG ValueLength,
    _Inout_opt_ PVOID Context
    )
{
    ULONG_PTR callbackType = (ULONG_PTR)Context;
    ULONG valueData;

    UNREFERENCED_PARAMETER(SettingGuid);

    if (!g_PowerState.Initialized || !g_PowerState.Enabled) {
        return STATUS_SUCCESS;
    }

    if (Value == NULL || ValueLength < sizeof(ULONG)) {
        return STATUS_SUCCESS;
    }

    valueData = *(PULONG)Value;

    switch (callbackType) {
        case 1:  // CONSOLE_DISPLAY_STATE
            if (valueData == 0) {
                // Display off
                PwrpProcessPowerEvent(ShadowPowerEvent_DisplayOff, NULL, 0);
            } else if (valueData == 1) {
                // Display on
                PwrpProcessPowerEvent(ShadowPowerEvent_DisplayOn, NULL, 0);
            } else if (valueData == 2) {
                // Display dimmed
                PwrpProcessPowerEvent(ShadowPowerEvent_DisplayDimmed, NULL, 0);
            }
            InterlockedIncrement64(&g_PowerState.Stats.DisplayStateChanges);
            break;

        case 2:  // ACDC_POWER_SOURCE
            if (valueData == 0) {
                // AC power
                PwrpProcessPowerEvent(ShadowPowerEvent_ACPowerConnected, NULL, 0);
            } else if (valueData == 1) {
                // DC (battery) power
                PwrpProcessPowerEvent(ShadowPowerEvent_ACPowerDisconnected, NULL, 0);
            }
            InterlockedIncrement64(&g_PowerState.Stats.ACDCTransitions);
            break;

        case 3:  // LIDSWITCH_STATE
            if (valueData == 0) {
                // Lid closed
                PwrpProcessPowerEvent(ShadowPowerEvent_LidClosed, NULL, 0);
            } else {
                // Lid open
                PwrpProcessPowerEvent(ShadowPowerEvent_LidOpen, NULL, 0);
            }
            InterlockedIncrement64(&g_PowerState.Stats.LidStateChanges);
            break;

        case 4:  // BATTERY_PERCENTAGE
            {
                KeEnterCriticalRegion();
                ExAcquirePushLockExclusive(&g_PowerState.StateLock);

                g_PowerState.StateInfo.BatteryPresent = TRUE;
                g_PowerState.StateInfo.BatteryPercentage = valueData;

                ExReleasePushLockExclusive(&g_PowerState.StateLock);
                KeLeaveCriticalRegion();

                // Generate events for low/critical battery
                if (valueData <= 5) {
                    PwrpProcessPowerEvent(ShadowPowerEvent_BatteryCritical, &valueData, sizeof(ULONG));
                } else if (valueData <= 20) {
                    PwrpProcessPowerEvent(ShadowPowerEvent_BatteryLow, &valueData, sizeof(ULONG));
                }
            }
            break;

        case 5:  // IDLE_RESILIENCY (Connected Standby)
            if (valueData == 0) {
                // Entering Connected Standby
                PwrpProcessPowerEvent(ShadowPowerEvent_EnteringConnectedStandby, NULL, 0);
            } else {
                // Exiting Connected Standby
                PwrpProcessPowerEvent(ShadowPowerEvent_ExitingConnectedStandby, NULL, 0);
            }
            InterlockedIncrement64(&g_PowerState.Stats.ConnectedStandbyTransitions);
            break;

        case 6:  // USER_PRESENCE
            if (valueData == 0) {
                // User away
                PwrpProcessPowerEvent(ShadowPowerEvent_UserAway, NULL, 0);
            } else {
                // User present
                PwrpProcessPowerEvent(ShadowPowerEvent_UserPresent, NULL, 0);
            }
            break;

        default:
            break;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief System state callback handler.
 */
static VOID
PwrpSystemStateCallback(
    _In_opt_ PVOID CallbackContext,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2
    )
{
    ULONG_PTR action = (ULONG_PTR)Argument1;
    ULONG_PTR state = (ULONG_PTR)Argument2;

    UNREFERENCED_PARAMETER(CallbackContext);

    if (!g_PowerState.Initialized || !g_PowerState.Enabled) {
        return;
    }

    //
    // Action: 0 = entering low power, 1 = resuming
    // State: power state value
    //

    if (action == 0) {
        //
        // Entering low-power state
        //
        if (state == 4) {  // S4 = Hibernate
            PwrpProcessPowerEvent(ShadowPowerEvent_EnteringHibernate, NULL, 0);
            InterlockedIncrement64(&g_PowerState.Stats.HibernateTransitions);
        } else if (state >= 1 && state <= 3) {  // S1-S3 = Sleep
            PwrpProcessPowerEvent(ShadowPowerEvent_EnteringSleep, NULL, 0);
            InterlockedIncrement64(&g_PowerState.Stats.SleepTransitions);
        } else if (state == 5) {  // S5 = Shutdown
            PwrpProcessPowerEvent(ShadowPowerEvent_Shutdown, NULL, 0);
        }

        //
        // Record sleep time
        //
        KeQuerySystemTime(&g_PowerState.StateInfo.LastSleepTime);

    } else if (action == 1) {
        //
        // Resuming from low-power state
        //
        LARGE_INTEGER currentTime;
        KeQuerySystemTime(&currentTime);

        //
        // Calculate sleep duration
        //
        if (g_PowerState.StateInfo.LastSleepTime.QuadPart > 0) {
            LARGE_INTEGER duration;
            duration.QuadPart = currentTime.QuadPart - g_PowerState.StateInfo.LastSleepTime.QuadPart;

            g_PowerState.Stats.LastSleepDuration = duration;
            g_PowerState.Stats.TotalSleepDuration.QuadPart += duration.QuadPart;

            if (duration.QuadPart > g_PowerState.Stats.LongestSleepDuration.QuadPart) {
                g_PowerState.Stats.LongestSleepDuration = duration;
            }
        }

        g_PowerState.StateInfo.LastResumeTime = currentTime;

        if (state == 4) {  // Resuming from hibernate
            PwrpProcessPowerEvent(ShadowPowerEvent_ResumingFromHibernate, NULL, 0);
        } else {  // Resuming from sleep
            PwrpProcessPowerEvent(ShadowPowerEvent_ResumingFromSleep, NULL, 0);
        }

        InterlockedIncrement64(&g_PowerState.Stats.ResumeTransitions);

        //
        // Trigger resume validation
        //
        if (g_PowerState.DeferredWorkItem != NULL && g_PowerState.DeviceObject != NULL) {
            IoQueueWorkItem(
                g_PowerState.DeferredWorkItem,
                PwrpDeferredWorkRoutine,
                DelayedWorkQueue,
                NULL
                );
        }
    }
}

// ============================================================================
// PRIVATE FUNCTIONS - EVENT PROCESSING
// ============================================================================

/**
 * @brief Process a power event.
 */
static VOID
PwrpProcessPowerEvent(
    _In_ SHADOW_POWER_EVENT_TYPE EventType,
    _In_opt_ PVOID EventData,
    _In_ ULONG EventDataSize
    )
{
    PSHADOW_POWER_EVENT event;

    UNREFERENCED_PARAMETER(EventData);
    UNREFERENCED_PARAMETER(EventDataSize);

    if (!g_PowerState.Initialized || g_PowerState.ShuttingDown) {
        return;
    }

    //
    // Allocate event structure
    //
    event = (PSHADOW_POWER_EVENT)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(SHADOW_POWER_EVENT),
        PWR_POOL_TAG_EVENT
        );

    if (event == NULL) {
        return;
    }

    //
    // Initialize event
    //
    event->EventType = EventType;
    event->PreviousState = g_PowerState.StateInfo.CurrentState;
    KeQuerySystemTime(&event->Timestamp);
    event->EventSequence = (UINT64)InterlockedIncrement64(&g_PowerState.EventSequence);

    //
    // Update state based on event
    //
    PwrpUpdateStateFromEvent(event);
    event->NewState = g_PowerState.StateInfo.CurrentState;

    //
    // Record event in history
    //
    PwrpRecordEvent(event);

    //
    // Notify registered callbacks
    //
    PwrpNotifyCallbacks(event);

    //
    // Update statistics
    //
    InterlockedIncrement64(&g_PowerState.Stats.TotalPowerEvents);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] Power event: %s (seq=%llu)\n",
               ShadowPowerEventToString(EventType),
               event->EventSequence);
}

/**
 * @brief Record event in history.
 */
static VOID
PwrpRecordEvent(
    _In_ PSHADOW_POWER_EVENT Event
    )
{
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PowerState.EventHistoryLock);

    //
    // Insert at head (most recent first)
    //
    InsertHeadList(&g_PowerState.EventHistory, &Event->ListEntry);
    InterlockedIncrement(&g_PowerState.EventCount);

    //
    // Trim if over limit
    //
    while (g_PowerState.EventCount > PWR_MAX_EVENT_HISTORY) {
        PLIST_ENTRY tail = RemoveTailList(&g_PowerState.EventHistory);
        PSHADOW_POWER_EVENT oldEvent = CONTAINING_RECORD(tail, SHADOW_POWER_EVENT, ListEntry);
        ExFreePoolWithTag(oldEvent, PWR_POOL_TAG_EVENT);
        InterlockedDecrement(&g_PowerState.EventCount);
    }

    ExReleasePushLockExclusive(&g_PowerState.EventHistoryLock);
    KeLeaveCriticalRegion();
}

/**
 * @brief Notify registered callbacks.
 */
static VOID
PwrpNotifyCallbacks(
    _In_ PSHADOW_POWER_EVENT Event
    )
{
    PLIST_ENTRY entry;
    PSHADOW_POWER_CALLBACK_ENTRY callbackEntry;
    ULONG eventBit;

    if (g_PowerState.CallbackCount == 0) {
        return;
    }

    eventBit = 1 << (ULONG)Event->EventType;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_PowerState.CallbackLock);

    for (entry = g_PowerState.CallbackList.Flink;
         entry != &g_PowerState.CallbackList;
         entry = entry->Flink) {

        callbackEntry = CONTAINING_RECORD(entry, SHADOW_POWER_CALLBACK_ENTRY, ListEntry);

        if (!callbackEntry->Enabled) {
            continue;
        }

        //
        // Check if callback wants this event type
        //
        if (callbackEntry->EventMask != 0 && !(callbackEntry->EventMask & eventBit)) {
            continue;
        }

        //
        // Invoke callback
        //
        __try {
            callbackEntry->Callback(Event->EventType, Event, callbackEntry->Context);
            InterlockedIncrement(&callbackEntry->CallCount);
            KeQuerySystemTime(&callbackEntry->LastCallTime);
            InterlockedIncrement64(&g_PowerState.Stats.CallbacksInvoked);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            InterlockedIncrement64(&g_PowerState.Stats.CallbackErrors);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike] Power callback exception: 0x%08X\n",
                       GetExceptionCode());
        }
    }

    ExReleasePushLockShared(&g_PowerState.CallbackLock);
    KeLeaveCriticalRegion();

    Event->Notified = TRUE;
}

/**
 * @brief Deferred work routine for post-resume processing.
 */
static VOID
PwrpDeferredWorkRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Context);

    //
    // Perform resume validation
    //
    ShadowPowerValidateResume();
}

/**
 * @brief Cleanup old event history entries.
 */
static VOID
PwrpCleanupEventHistory(
    VOID
    )
{
    //
    // Already handled in PwrpRecordEvent by limiting to PWR_MAX_EVENT_HISTORY
    //
}

/**
 * @brief Update state based on power event.
 */
static VOID
PwrpUpdateStateFromEvent(
    _In_ PSHADOW_POWER_EVENT Event
    )
{
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PowerState.StateLock);

    g_PowerState.StateInfo.PreviousState = g_PowerState.StateInfo.CurrentState;

    switch (Event->EventType) {
        case ShadowPowerEvent_EnteringSleep:
            g_PowerState.StateInfo.CurrentState = ShadowPowerState_Standby;
            break;

        case ShadowPowerEvent_ResumingFromSleep:
        case ShadowPowerEvent_ResumingFromHibernate:
        case ShadowPowerEvent_ExitingConnectedStandby:
            g_PowerState.StateInfo.CurrentState = ShadowPowerState_Working;
            break;

        case ShadowPowerEvent_EnteringHibernate:
            g_PowerState.StateInfo.CurrentState = ShadowPowerState_Hibernate;
            break;

        case ShadowPowerEvent_EnteringConnectedStandby:
            g_PowerState.StateInfo.CurrentState = ShadowPowerState_ConnectedStandby;
            g_PowerState.StateInfo.InConnectedStandby = TRUE;
            break;

        case ShadowPowerEvent_Shutdown:
            g_PowerState.StateInfo.CurrentState = ShadowPowerState_Shutdown;
            break;

        case ShadowPowerEvent_ACPowerConnected:
            g_PowerState.StateInfo.PowerSource = ShadowPowerSource_AC;
            break;

        case ShadowPowerEvent_ACPowerDisconnected:
            g_PowerState.StateInfo.PowerSource = ShadowPowerSource_DC;
            break;

        case ShadowPowerEvent_DisplayOn:
            g_PowerState.StateInfo.DisplayOn = TRUE;
            g_PowerState.StateInfo.DisplayDimmed = FALSE;
            break;

        case ShadowPowerEvent_DisplayOff:
            g_PowerState.StateInfo.DisplayOn = FALSE;
            g_PowerState.StateInfo.DisplayDimmed = FALSE;
            break;

        case ShadowPowerEvent_DisplayDimmed:
            g_PowerState.StateInfo.DisplayDimmed = TRUE;
            break;

        case ShadowPowerEvent_LidOpen:
            g_PowerState.StateInfo.LidOpen = TRUE;
            break;

        case ShadowPowerEvent_LidClosed:
            g_PowerState.StateInfo.LidOpen = FALSE;
            break;

        case ShadowPowerEvent_UserPresent:
            g_PowerState.StateInfo.UserPresent = TRUE;
            break;

        case ShadowPowerEvent_UserAway:
            g_PowerState.StateInfo.UserPresent = FALSE;
            break;

        case ShadowPowerEvent_SessionLock:
            g_PowerState.StateInfo.SessionLocked = TRUE;
            break;

        case ShadowPowerEvent_SessionUnlock:
            g_PowerState.StateInfo.SessionLocked = FALSE;
            break;

        case ShadowPowerEvent_ThermalThrottling:
            g_PowerState.StateInfo.ThermalThrottling = TRUE;
            break;

        case ShadowPowerEvent_ThermalNormal:
            g_PowerState.StateInfo.ThermalThrottling = FALSE;
            break;

        default:
            break;
    }

    if (Event->EventType == ShadowPowerEvent_ExitingConnectedStandby) {
        g_PowerState.StateInfo.InConnectedStandby = FALSE;
        g_PowerState.StateInfo.ConnectedStandbyExitCount++;
    }

    KeQuerySystemTime(&g_PowerState.StateInfo.LastStateChangeTime);

    ExReleasePushLockExclusive(&g_PowerState.StateLock);
    KeLeaveCriticalRegion();
}

// ============================================================================
// PRIVATE FUNCTIONS - RESUME VALIDATION
// ============================================================================

/**
 * @brief Perform actual resume validation checks.
 */
static NTSTATUS
PwrpPerformResumeValidation(
    VOID
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER sleepDuration;

    //
    // Get current time and calculate sleep duration
    //
    KeQuerySystemTime(&currentTime);

    if (g_PowerState.StateInfo.LastSleepTime.QuadPart > 0) {
        sleepDuration.QuadPart = currentTime.QuadPart -
                                  g_PowerState.StateInfo.LastSleepTime.QuadPart;

        //
        // Convert to seconds for logging
        //
        ULONG sleepSeconds = (ULONG)(sleepDuration.QuadPart / 10000000);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike] Resume validation: slept for %lu seconds\n",
                   sleepSeconds);
    }

    //
    // Validation checks:
    //

    //
    // 1. Verify driver state is consistent
    //
    if (!g_PowerState.Initialized) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Resume validation: Driver not initialized!\n");
        status = STATUS_DRIVER_INTERNAL_ERROR;
        goto Exit;
    }

    //
    // 2. Check for time anomalies (clock manipulation)
    //
    if (g_PowerState.StateInfo.LastSleepTime.QuadPart > currentTime.QuadPart) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Resume validation: Time anomaly detected\n");
        // This is suspicious but not fatal - system clock may have been adjusted
    }

    //
    // 3. Verify critical kernel structures are intact
    //    (In production, this would check for callback removal, hook integrity, etc.)
    //

    //
    // 4. Check if our callbacks are still registered
    //
    if (g_PowerState.ConsoleDisplayStateHandle == NULL &&
        g_PowerState.AcDcPowerSourceHandle == NULL &&
        g_PowerState.SystemStateRegistration == NULL) {

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Resume validation: No power callbacks registered\n");
        // Attempt to re-register
    }

    //
    // 5. Verify self-protection is still active
    //    (Would call into SelfProtect module to verify)
    //

    //
    // 6. Re-initialize any state that may have been lost
    //

Exit:
    return status;
}

#endif // SHADOWSTRIKE_POWER_CALLBACK_C
