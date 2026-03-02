/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE POWER MANAGEMENT IMPLEMENTATION
 * ============================================================================
 *
 * @file PowerCallback.c
 * @brief Enterprise-grade power state management for kernel EDR.
 *
 * IRQL Safety Model:
 * - PwrpSystemStateCallback may fire at DISPATCH_LEVEL.
 *   It MUST NOT acquire push locks or allocate paged pool.
 *   All heavy work is deferred to PwrpDeferredEventWorkRoutine
 *   via IoQueueWorkItem (runs at PASSIVE_LEVEL).
 * - PwrpPowerSettingCallback runs at PASSIVE_LEVEL per MSDN.
 *   It may safely use push locks and allocate memory.
 * - State query functions that use push locks are annotated APC_LEVEL max.
 *   Lock-free query functions use volatile reads and are DISPATCH_LEVEL safe.
 *
 * Lock Ordering (to prevent deadlocks):
 *   StateLock → EventHistoryLock → CallbackLock
 *   (Never acquire in reverse order)
 *
 * Work Item Safety:
 *   - WorkItemQueued flag prevents double-queuing (IoQueueWorkItem contract).
 *   - WorkItemComplete event ensures shutdown waits for in-flight work items.
 *   - IoFreeWorkItem is only called after the work item has finished.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition)
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
#pragma alloc_text(PAGE, ShadowPowerGetState)
#pragma alloc_text(PAGE, ShadowPowerGetStatistics)
#pragma alloc_text(PAGE, ShadowPowerResetStatistics)
#endif

// ============================================================================
// POWER SETTING GUIDs
// ============================================================================

DEFINE_GUID(GUID_CONSOLE_DISPLAY_STATE,
    0x6FE69556, 0x704A, 0x47A0, 0x8F, 0x24, 0xC2, 0x8D, 0x93, 0x6F, 0xDA, 0x47);

DEFINE_GUID(GUID_ACDC_POWER_SOURCE,
    0x5D3E9A59, 0xE9D5, 0x4B00, 0xA6, 0xBD, 0xFF, 0x34, 0xFF, 0x51, 0x65, 0x48);

DEFINE_GUID(GUID_LIDSWITCH_STATE_CHANGE,
    0xBA3E0F4D, 0xB817, 0x4094, 0xA2, 0xD1, 0xD5, 0x63, 0x79, 0xE6, 0xA0, 0xF3);

DEFINE_GUID(GUID_BATTERY_PERCENTAGE_REMAINING,
    0xA7AD8041, 0xB45A, 0x4CAE, 0x87, 0xA3, 0xEE, 0xCB, 0xB4, 0x68, 0xA9, 0xE1);

DEFINE_GUID(GUID_IDLE_RESILIENCY,
    0xC42B1B9A, 0x2D5B, 0x4C55, 0x9E, 0x20, 0xFB, 0x9F, 0xFF, 0xB7, 0xD3, 0x2F);

DEFINE_GUID(GUID_SESSION_USER_PRESENCE,
    0x3C0F4548, 0xC03F, 0x4C4D, 0xB9, 0xF2, 0x23, 0x7E, 0xDE, 0x68, 0x63, 0x76);

DEFINE_GUID(GUID_SESSION_DISPLAY_STATUS,
    0x2B84C20E, 0xAD23, 0x4DDF, 0x93, 0xDB, 0x05, 0xFF, 0xBD, 0x7E, 0xFC, 0xA5);

// ============================================================================
// INTERNAL STRUCTURES (private to this file)
// ============================================================================

/**
 * @brief Internal power event with list linkage.
 *        The public SHADOW_POWER_EVENT_INFO is a subset of this.
 */
typedef struct _SHADOW_POWER_EVENT_INTERNAL {
    LIST_ENTRY ListEntry;

    SHADOW_POWER_EVENT_INFO Info;

    BOOLEAN Processed;
    BOOLEAN Notified;
    NTSTATUS ProcessingStatus;

} SHADOW_POWER_EVENT_INTERNAL, *PSHADOW_POWER_EVENT_INTERNAL;

/**
 * @brief Internal callback registration entry.
 */
typedef struct _SHADOW_POWER_CALLBACK_ENTRY {
    LIST_ENTRY ListEntry;

    PSHADOW_POWER_CALLBACK Callback;
    PVOID Context;
    SHADOW_POWER_CALLBACK_PRIORITY Priority;
    ULONGLONG EventMask;

    BOOLEAN Enabled;
    volatile LONG CallCount;
    LARGE_INTEGER LastCallTime;

} SHADOW_POWER_CALLBACK_ENTRY, *PSHADOW_POWER_CALLBACK_ENTRY;

/**
 * @brief Deferred event work item context.
 *        Passed through the work item to process events at PASSIVE_LEVEL.
 */
#define PWR_DEFERRED_EVENT_MAX  8

typedef struct _PWR_DEFERRED_EVENT_CONTEXT {
    SHADOW_POWER_EVENT_TYPE Events[PWR_DEFERRED_EVENT_MAX];
    ULONG EventCount;
} PWR_DEFERRED_EVENT_CONTEXT;

/**
 * @brief Power management global state (file-static, NEVER exposed in header).
 */
typedef struct _SHADOW_POWER_GLOBALS {
    volatile LONG Initialized;
    volatile LONG Enabled;
    volatile LONG ShuttingDown;

    // Current state — protected by StateLock (EX_PUSH_LOCK, max APC_LEVEL)
    SHADOW_POWER_STATE_INFO StateInfo;
    EX_PUSH_LOCK StateLock;

    //
    // Volatile copies for lock-free DISPATCH_LEVEL readers.
    // Updated under StateLock, read with volatile semantics.
    //
    volatile LONG CurrentPowerState;    // SHADOW_POWER_STATE
    volatile LONG CurrentPowerSource;   // SHADOW_POWER_SOURCE
    volatile LONG ResumeValidationRequired;
    volatile LONG ResumeValidationPassed;

    // Power setting callback handles
    PVOID ConsoleDisplayStateHandle;
    PVOID AcDcPowerSourceHandle;
    PVOID LidSwitchStateHandle;
    PVOID BatteryPercentageHandle;
    PVOID IdleResiliencyHandle;
    PVOID UserPresenceHandle;
    PVOID SessionDisplayStatusHandle;

    // System state callback
    PCALLBACK_OBJECT SystemStateCallback;
    PVOID SystemStateRegistration;

    // Event history — protected by EventHistoryLock (push lock, max APC_LEVEL)
    LIST_ENTRY EventHistory;
    EX_PUSH_LOCK EventHistoryLock;
    volatile LONG EventCount;
    volatile LONG64 EventSequence;

    // Registered callbacks — protected by CallbackLock (push lock, max APC_LEVEL)
    LIST_ENTRY CallbackList;
    EX_PUSH_LOCK CallbackLock;
    volatile LONG CallbackCount;

    // Resume validation
    KEVENT ResumeValidationComplete;

    // Pending operation tracking
    volatile LONG PendingOperations;
    KEVENT NoPendingOperationsEvent;

    // Work item for deferred processing from DISPATCH_LEVEL callbacks
    PIO_WORKITEM DeferredWorkItem;
    PDEVICE_OBJECT DeviceObject;
    volatile LONG WorkItemQueued;
    KEVENT WorkItemComplete;

    // Deferred events from system state callback (lock-free ring)
    PWR_DEFERRED_EVENT_CONTEXT DeferredCtx;
    KSPIN_LOCK DeferredCtxLock;

    // Statistics — protected by StatsLock (push lock)
    // All volatile counters updated via Interlocked*, but durations need lock
    struct {
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

        volatile LONG64 TotalSleepDuration100ns;
        volatile LONG64 LongestSleepDuration100ns;
        volatile LONG64 LastSleepDuration100ns;
    } Stats;

    LARGE_INTEGER LastSleepStartTime;

} SHADOW_POWER_GLOBALS;

// ============================================================================
// GLOBAL STATE (file-static)
// ============================================================================

static SHADOW_POWER_GLOBALS g_PowerState;

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

_Function_class_(POWER_SETTING_CALLBACK)
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
    _In_ PSHADOW_POWER_EVENT_INTERNAL Event
    );

static VOID
PwrpNotifyCallbacks(
    _In_ PSHADOW_POWER_EVENT_INTERNAL Event
    );

_Function_class_(IO_WORKITEM_ROUTINE)
static VOID NTAPI
PwrpDeferredEventWorkRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    );

static VOID
PwrpUpdateStateFromEvent(
    _In_ PSHADOW_POWER_EVENT_INTERNAL Event
    );

static VOID
PwrpUpdateVolatileState(
    VOID
    );

static NTSTATUS
PwrpPerformResumeValidation(
    VOID
    );

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
ShadowRegisterPowerCallbacks(
    _In_opt_ PDEVICE_OBJECT DeviceObject
    )
{
    NTSTATUS status;

    PAGED_CODE();

    if (InterlockedCompareExchange(&g_PowerState.Initialized, 0, 0) != 0) {
        return STATUS_ALREADY_INITIALIZED;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Initializing power management subsystem\n");

    RtlZeroMemory(&g_PowerState, sizeof(SHADOW_POWER_GLOBALS));

    g_PowerState.DeviceObject = DeviceObject;

    //
    // Initialize synchronization primitives
    //
    ExInitializePushLock(&g_PowerState.StateLock);
    ExInitializePushLock(&g_PowerState.EventHistoryLock);
    ExInitializePushLock(&g_PowerState.CallbackLock);
    KeInitializeSpinLock(&g_PowerState.DeferredCtxLock);

    InitializeListHead(&g_PowerState.EventHistory);
    InitializeListHead(&g_PowerState.CallbackList);

    KeInitializeEvent(&g_PowerState.ResumeValidationComplete, NotificationEvent, TRUE);
    KeInitializeEvent(&g_PowerState.NoPendingOperationsEvent, NotificationEvent, TRUE);
    KeInitializeEvent(&g_PowerState.WorkItemComplete, NotificationEvent, TRUE);

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
    // Set volatile copies
    //
    InterlockedExchange(&g_PowerState.CurrentPowerState, (LONG)ShadowPowerState_Working);
    InterlockedExchange(&g_PowerState.CurrentPowerSource, (LONG)ShadowPowerSource_Unknown);

    //
    // Allocate work item for deferred processing
    //
    if (DeviceObject != NULL) {
        g_PowerState.DeferredWorkItem = IoAllocateWorkItem(DeviceObject);
        if (g_PowerState.DeferredWorkItem == NULL) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] Failed to allocate power work item\n");
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
    }

    //
    // Register power setting callbacks
    //
    status = PwrpRegisterPowerSettingCallbacks();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Failed to register power setting callbacks: 0x%08X\n",
                   status);
    }

    //
    // Mark as initialized and enabled
    //
    InterlockedExchange(&g_PowerState.Enabled, TRUE);
    InterlockedExchange(&g_PowerState.Initialized, TRUE);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Power management initialized successfully\n");

    return STATUS_SUCCESS;
}

/**
 * @brief Shutdown the power management subsystem.
 *
 * Order of operations:
 * 1. Set ShuttingDown flag (prevents new events/work)
 * 2. Wait for pending operations
 * 3. Unregister all OS callbacks (no new callbacks will fire)
 * 4. Wait for any in-flight work item to complete
 * 5. Free work item
 * 6. Free event history and callback list under their locks
 * 7. Clear Initialized flag
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
ShadowUnregisterPowerCallbacks(
    VOID
    )
{
    PLIST_ENTRY entry;
    PSHADOW_POWER_EVENT_INTERNAL event;
    PSHADOW_POWER_CALLBACK_ENTRY callbackEntry;
    LARGE_INTEGER timeout;

    PAGED_CODE();

    if (InterlockedCompareExchange(&g_PowerState.Initialized, 0, 0) == 0) {
        return;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Shutting down power management\n");

    //
    // Step 1: Mark as shutting down — no new events will be processed
    //
    InterlockedExchange(&g_PowerState.ShuttingDown, TRUE);
    InterlockedExchange(&g_PowerState.Enabled, FALSE);

    //
    // Step 2: Wait for pending operations (ShadowPowerEnterOperation/LeaveOperation)
    //
    if (g_PowerState.PendingOperations > 0) {
        timeout.QuadPart = -50000000LL;  // 5 seconds
        KeWaitForSingleObject(
            &g_PowerState.NoPendingOperationsEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout
            );
    }

    //
    // Step 3: Unregister all OS callbacks.
    // After this, no new PwrpSystemStateCallback or PwrpPowerSettingCallback
    // invocations will start.
    //
    PwrpUnregisterPowerSettingCallbacks();
    PwrpUnregisterSystemStateCallback();

    //
    // Step 4: Wait for any in-flight work item to complete.
    // The work item sets WorkItemComplete when it finishes.
    //
    if (InterlockedCompareExchange(&g_PowerState.WorkItemQueued, 0, 0) != 0) {
        timeout.QuadPart = -100000000LL;  // 10 seconds
        KeWaitForSingleObject(
            &g_PowerState.WorkItemComplete,
            Executive,
            KernelMode,
            FALSE,
            &timeout
            );
    }

    //
    // Step 5: Free work item (safe — work item is guaranteed not running)
    //
    if (g_PowerState.DeferredWorkItem != NULL) {
        IoFreeWorkItem(g_PowerState.DeferredWorkItem);
        g_PowerState.DeferredWorkItem = NULL;
    }

    //
    // Step 6: Free event history
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PowerState.EventHistoryLock);

    while (!IsListEmpty(&g_PowerState.EventHistory)) {
        entry = RemoveHeadList(&g_PowerState.EventHistory);
        event = CONTAINING_RECORD(entry, SHADOW_POWER_EVENT_INTERNAL, ListEntry);
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

    //
    // Step 7: Mark as uninitialized.
    // Do NOT RtlZeroMemory the struct — that would destroy lock state
    // that late readers might still touch momentarily.
    //
    InterlockedExchange(&g_PowerState.Initialized, FALSE);
}

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

    InterlockedExchange(&g_PowerState.Enabled, (LONG)Enable);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Power management %s\n",
               Enable ? "enabled" : "disabled");

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - STATE QUERY
// ============================================================================

/**
 * @brief Get full power state snapshot under shared lock.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
ShadowPowerGetState(
    _Out_ PSHADOW_POWER_STATE_INFO StateInfo
    )
{
    PAGED_CODE();

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
 * @brief Lock-free low-power check (volatile read of single enum value).
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowPowerIsLowPowerState(
    VOID
    )
{
    LONG state;

    if (!g_PowerState.Initialized) {
        return FALSE;
    }

    state = ReadNoFence(&g_PowerState.CurrentPowerState);

    return (state == (LONG)ShadowPowerState_Standby ||
            state == (LONG)ShadowPowerState_Hibernate ||
            state == (LONG)ShadowPowerState_ConnectedStandby ||
            state == (LONG)ShadowPowerState_HybridSleep);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowPowerIsResuming(
    VOID
    )
{
    if (!g_PowerState.Initialized) {
        return FALSE;
    }

    return (ReadNoFence(&g_PowerState.ResumeValidationRequired) != 0) &&
           (ReadNoFence(&g_PowerState.ResumeValidationPassed) == 0);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowPowerIsOnBattery(
    VOID
    )
{
    if (!g_PowerState.Initialized) {
        return FALSE;
    }

    return (ReadNoFence(&g_PowerState.CurrentPowerSource) == (LONG)ShadowPowerSource_DC);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
ShadowPowerGetBatteryPercentage(
    VOID
    )
{
    if (!g_PowerState.Initialized) {
        return 0;
    }

    //
    // BatteryPercentage is a single ULONG — naturally atomic on all
    // supported architectures. Read without lock.
    //
    if (!g_PowerState.StateInfo.BatteryPresent) {
        return 0;
    }

    return g_PowerState.StateInfo.BatteryPercentage;
}

// ============================================================================
// PUBLIC API - CALLBACK REGISTRATION
// ============================================================================

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
ShadowPowerRegisterCallback(
    _In_ PSHADOW_POWER_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _In_ SHADOW_POWER_CALLBACK_PRIORITY Priority,
    _In_ ULONGLONG EventMask,
    _Out_ PVOID* Handle
    )
{
    PSHADOW_POWER_CALLBACK_ENTRY entry;

    PAGED_CODE();

    if (Callback == NULL || Handle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Priority >= ShadowPowerPriority_Max) {
        return STATUS_INVALID_PARAMETER;
    }

    *Handle = NULL;

    if (!g_PowerState.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (g_PowerState.CallbackCount >= PWR_MAX_CALLBACKS) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    entry = (PSHADOW_POWER_CALLBACK_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
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
    // Insert into list sorted by priority (lower value = higher priority)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PowerState.CallbackLock);

    //
    // Re-check count under lock
    //
    if (g_PowerState.CallbackCount >= PWR_MAX_CALLBACKS) {
        ExReleasePushLockExclusive(&g_PowerState.CallbackLock);
        KeLeaveCriticalRegion();
        ExFreePoolWithTag(entry, PWR_POOL_TAG_CALLBACK);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    {
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
    }

    InterlockedIncrement(&g_PowerState.CallbackCount);

    ExReleasePushLockExclusive(&g_PowerState.CallbackLock);
    KeLeaveCriticalRegion();

    *Handle = entry;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] Power callback registered (priority=%d, mask=0x%llX)\n",
               Priority, EventMask);

    return STATUS_SUCCESS;
}

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
 * @brief Get event history. Copies public SHADOW_POWER_EVENT_INFO only
 *        (no ListEntry, no internal fields).
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
ShadowPowerGetEventHistory(
    _Out_writes_to_(MaxEvents, *EventCount) PSHADOW_POWER_EVENT_INFO Events,
    _In_ ULONG MaxEvents,
    _Out_ PULONG EventCount
    )
{
    PLIST_ENTRY entry;
    PSHADOW_POWER_EVENT_INTERNAL internalEvent;
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

        internalEvent = CONTAINING_RECORD(entry, SHADOW_POWER_EVENT_INTERNAL, ListEntry);

        //
        // Copy only the public info — no ListEntry, no internal flags
        //
        RtlCopyMemory(&Events[count], &internalEvent->Info, sizeof(SHADOW_POWER_EVENT_INFO));
        count++;
    }

    ExReleasePushLockShared(&g_PowerState.EventHistoryLock);
    KeLeaveCriticalRegion();

    *EventCount = count;
    return STATUS_SUCCESS;
}

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
        InterlockedExchange(&g_PowerState.PendingOperations, 0);
        KeSetEvent(&g_PowerState.NoPendingOperationsEvent, IO_NO_INCREMENT, FALSE);
    }
}

// ============================================================================
// PUBLIC API - RESUME VALIDATION
// ============================================================================

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

    KeClearEvent(&g_PowerState.ResumeValidationComplete);
    InterlockedExchange(&g_PowerState.ResumeValidationRequired, TRUE);
    InterlockedExchange(&g_PowerState.ResumeValidationPassed, FALSE);

    status = PwrpPerformResumeValidation();

    if (NT_SUCCESS(status)) {
        InterlockedExchange(&g_PowerState.ResumeValidationPassed, TRUE);
        InterlockedIncrement64(&g_PowerState.Stats.ValidationsPassed);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike] Post-resume validation PASSED\n");
    } else {
        InterlockedIncrement64(&g_PowerState.Stats.ValidationsFailed);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Post-resume validation FAILED: 0x%08X\n",
                   status);
    }

    InterlockedExchange(&g_PowerState.ResumeValidationRequired, FALSE);
    KeSetEvent(&g_PowerState.ResumeValidationComplete, IO_NO_INCREMENT, FALSE);

    return status;
}

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
        return (BOOLEAN)(g_PowerState.ResumeValidationPassed != 0);
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

    return (BOOLEAN)(g_PowerState.ResumeValidationPassed != 0);
}

// ============================================================================
// PUBLIC API - STATISTICS
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
ShadowPowerGetStatistics(
    _Out_ PSHADOW_POWER_STATISTICS Stats
    )
{
    PAGED_CODE();

    if (Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_PowerState.Initialized) {
        RtlZeroMemory(Stats, sizeof(SHADOW_POWER_STATISTICS));
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Snapshot all counters. Each individual read is atomic (Interlocked values).
    //
    Stats->TotalPowerEvents = g_PowerState.Stats.TotalPowerEvents;
    Stats->SleepTransitions = g_PowerState.Stats.SleepTransitions;
    Stats->ResumeTransitions = g_PowerState.Stats.ResumeTransitions;
    Stats->HibernateTransitions = g_PowerState.Stats.HibernateTransitions;
    Stats->ConnectedStandbyTransitions = g_PowerState.Stats.ConnectedStandbyTransitions;
    Stats->ACDCTransitions = g_PowerState.Stats.ACDCTransitions;
    Stats->DisplayStateChanges = g_PowerState.Stats.DisplayStateChanges;
    Stats->LidStateChanges = g_PowerState.Stats.LidStateChanges;
    Stats->SessionChanges = g_PowerState.Stats.SessionChanges;
    Stats->ThermalEvents = g_PowerState.Stats.ThermalEvents;
    Stats->CallbacksInvoked = g_PowerState.Stats.CallbacksInvoked;
    Stats->CallbackErrors = g_PowerState.Stats.CallbackErrors;
    Stats->ValidationsPassed = g_PowerState.Stats.ValidationsPassed;
    Stats->ValidationsFailed = g_PowerState.Stats.ValidationsFailed;

    Stats->TotalSleepDuration.QuadPart = g_PowerState.Stats.TotalSleepDuration100ns;
    Stats->LongestSleepDuration.QuadPart = g_PowerState.Stats.LongestSleepDuration100ns;
    Stats->LastSleepDuration.QuadPart = g_PowerState.Stats.LastSleepDuration100ns;

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowPowerResetStatistics(
    VOID
    )
{
    PAGED_CODE();

    if (!g_PowerState.Initialized) {
        return;
    }

    //
    // Reset each counter atomically. Not a point-in-time snapshot,
    // but individual fields are consistent.
    //
    InterlockedExchange64(&g_PowerState.Stats.TotalPowerEvents, 0);
    InterlockedExchange64(&g_PowerState.Stats.SleepTransitions, 0);
    InterlockedExchange64(&g_PowerState.Stats.ResumeTransitions, 0);
    InterlockedExchange64(&g_PowerState.Stats.HibernateTransitions, 0);
    InterlockedExchange64(&g_PowerState.Stats.ConnectedStandbyTransitions, 0);
    InterlockedExchange64(&g_PowerState.Stats.ACDCTransitions, 0);
    InterlockedExchange64(&g_PowerState.Stats.DisplayStateChanges, 0);
    InterlockedExchange64(&g_PowerState.Stats.LidStateChanges, 0);
    InterlockedExchange64(&g_PowerState.Stats.SessionChanges, 0);
    InterlockedExchange64(&g_PowerState.Stats.ThermalEvents, 0);
    InterlockedExchange64(&g_PowerState.Stats.CallbacksInvoked, 0);
    InterlockedExchange64(&g_PowerState.Stats.CallbackErrors, 0);
    InterlockedExchange64(&g_PowerState.Stats.ValidationsPassed, 0);
    InterlockedExchange64(&g_PowerState.Stats.ValidationsFailed, 0);
    InterlockedExchange64(&g_PowerState.Stats.TotalSleepDuration100ns, 0);
    InterlockedExchange64(&g_PowerState.Stats.LongestSleepDuration100ns, 0);
    InterlockedExchange64(&g_PowerState.Stats.LastSleepDuration100ns, 0);
}

// ============================================================================
// PUBLIC API - UTILITY
// ============================================================================

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

static NTSTATUS
PwrpRegisterPowerSettingCallbacks(
    VOID
    )
{
    NTSTATUS status;

    //
    // Console display state (on/off/dimmed)
    //
    status = PoRegisterPowerSettingCallback(
        NULL,
        &GUID_CONSOLE_DISPLAY_STATE,
        PwrpPowerSettingCallback,
        (PVOID)(ULONG_PTR)1,
        &g_PowerState.ConsoleDisplayStateHandle
        );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Failed to register CONSOLE_DISPLAY_STATE: 0x%08X\n",
                   status);
    }

    //
    // AC/DC power source
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
    // Lid switch state
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
    // Battery percentage
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
    // Idle resiliency (Connected Standby)
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
    // User presence
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

    //
    // Session display status (session lock/unlock)
    //
    status = PoRegisterPowerSettingCallback(
        NULL,
        &GUID_SESSION_DISPLAY_STATUS,
        PwrpPowerSettingCallback,
        (PVOID)(ULONG_PTR)7,
        &g_PowerState.SessionDisplayStatusHandle
        );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Failed to register SESSION_DISPLAY_STATUS: 0x%08X\n",
                   status);
    }

    return STATUS_SUCCESS;
}

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

    if (g_PowerState.SessionDisplayStatusHandle != NULL) {
        PoUnregisterPowerSettingCallback(g_PowerState.SessionDisplayStatusHandle);
        g_PowerState.SessionDisplayStatusHandle = NULL;
    }
}

static NTSTATUS
PwrpRegisterSystemStateCallback(
    VOID
    )
{
    NTSTATUS status;
    UNICODE_STRING callbackName;
    OBJECT_ATTRIBUTES oa;

    RtlInitUnicodeString(&callbackName, L"\\Callback\\PowerState");
    InitializeObjectAttributes(&oa, &callbackName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ExCreateCallback(
        &g_PowerState.SystemStateCallback,
        &oa,
        FALSE,
        TRUE
        );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Failed to open PowerState callback: 0x%08X\n",
                   status);
        return status;
    }

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
// PRIVATE FUNCTIONS - OS CALLBACKS
// ============================================================================

/**
 * @brief Power setting callback handler.
 *
 * IRQL: PASSIVE_LEVEL (guaranteed by PoRegisterPowerSettingCallback).
 * Safe to use push locks and allocate memory.
 */
_Function_class_(POWER_SETTING_CALLBACK)
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
                PwrpProcessPowerEvent(ShadowPowerEvent_DisplayOff, NULL, 0);
            } else if (valueData == 1) {
                PwrpProcessPowerEvent(ShadowPowerEvent_DisplayOn, NULL, 0);
            } else if (valueData == 2) {
                PwrpProcessPowerEvent(ShadowPowerEvent_DisplayDimmed, NULL, 0);
            }
            InterlockedIncrement64(&g_PowerState.Stats.DisplayStateChanges);
            break;

        case 2:  // ACDC_POWER_SOURCE
            if (valueData == 0) {
                PwrpProcessPowerEvent(ShadowPowerEvent_ACPowerConnected, NULL, 0);
            } else if (valueData == 1) {
                PwrpProcessPowerEvent(ShadowPowerEvent_ACPowerDisconnected, NULL, 0);
            }
            InterlockedIncrement64(&g_PowerState.Stats.ACDCTransitions);
            break;

        case 3:  // LIDSWITCH_STATE
            if (valueData == 0) {
                PwrpProcessPowerEvent(ShadowPowerEvent_LidClosed, NULL, 0);
            } else {
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

                if (valueData <= 5) {
                    PwrpProcessPowerEvent(ShadowPowerEvent_BatteryCritical, &valueData, sizeof(ULONG));
                } else if (valueData <= 20) {
                    PwrpProcessPowerEvent(ShadowPowerEvent_BatteryLow, &valueData, sizeof(ULONG));
                }
            }
            break;

        case 5:  // IDLE_RESILIENCY (Connected Standby)
            if (valueData == 0) {
                PwrpProcessPowerEvent(ShadowPowerEvent_EnteringConnectedStandby, NULL, 0);
            } else {
                PwrpProcessPowerEvent(ShadowPowerEvent_ExitingConnectedStandby, NULL, 0);
            }
            InterlockedIncrement64(&g_PowerState.Stats.ConnectedStandbyTransitions);
            break;

        case 6:  // USER_PRESENCE
            if (valueData == 0) {
                PwrpProcessPowerEvent(ShadowPowerEvent_UserAway, NULL, 0);
            } else {
                PwrpProcessPowerEvent(ShadowPowerEvent_UserPresent, NULL, 0);
            }
            break;

        case 7:  // SESSION_DISPLAY_STATUS (session lock/unlock)
            //
            // Value: 1 = session unlock, 0 = session lock
            //
            if (valueData == 0) {
                PwrpProcessPowerEvent(ShadowPowerEvent_SessionLock, NULL, 0);
            } else {
                PwrpProcessPowerEvent(ShadowPowerEvent_SessionUnlock, NULL, 0);
            }
            InterlockedIncrement64(&g_PowerState.Stats.SessionChanges);
            break;

        default:
            break;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief System state callback handler.
 *
 * CRITICAL: This callback can fire at DISPATCH_LEVEL.
 * MUST NOT:
 *   - Acquire push locks
 *   - Wait on events
 *   - Allocate paged pool
 *   - Call any PASSIVE_LEVEL function
 *
 * Instead, we:
 *   1. Record the event type into a lock-free deferred context (spin lock)
 *   2. Update statistics atomically
 *   3. Queue a work item to do heavy processing at PASSIVE_LEVEL
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
    SHADOW_POWER_EVENT_TYPE eventType = ShadowPowerEvent_None;
    KIRQL oldIrql;

    UNREFERENCED_PARAMETER(CallbackContext);

    if (!g_PowerState.Initialized || !g_PowerState.Enabled) {
        return;
    }

    if (g_PowerState.ShuttingDown) {
        return;
    }

    //
    // Determine event type
    //
    if (action == 0) {
        // Entering low-power state
        if (state == 4) {
            eventType = ShadowPowerEvent_EnteringHibernate;
            InterlockedIncrement64(&g_PowerState.Stats.HibernateTransitions);
        } else if (state >= 1 && state <= 3) {
            eventType = ShadowPowerEvent_EnteringSleep;
            InterlockedIncrement64(&g_PowerState.Stats.SleepTransitions);
        } else if (state == 5) {
            eventType = ShadowPowerEvent_Shutdown;
        }

        // Record sleep start time atomically
        {
            LARGE_INTEGER now;
            KeQuerySystemTime(&now);
            //
            // QuadPart is 64-bit; on x64 this is atomic.
            // On x86 we accept the tiny torn-write risk for a timestamp.
            //
            g_PowerState.LastSleepStartTime = now;
        }
    } else if (action == 1) {
        // Resuming from low-power state
        LARGE_INTEGER currentTime;
        KeQuerySystemTime(&currentTime);

        //
        // Calculate sleep duration with Interlocked updates
        //
        if (g_PowerState.LastSleepStartTime.QuadPart > 0) {
            LONGLONG duration = currentTime.QuadPart - g_PowerState.LastSleepStartTime.QuadPart;

            if (duration > 0) {
                InterlockedExchange64(&g_PowerState.Stats.LastSleepDuration100ns, duration);

                //
                // Atomic add for total
                //
                InterlockedAdd64(&g_PowerState.Stats.TotalSleepDuration100ns, duration);

                //
                // Atomic compare-exchange loop for longest
                //
                {
                    LONGLONG currentLongest;
                    do {
                        currentLongest = g_PowerState.Stats.LongestSleepDuration100ns;
                        if (duration <= currentLongest) {
                            break;
                        }
                    } while (InterlockedCompareExchange64(
                                 &g_PowerState.Stats.LongestSleepDuration100ns,
                                 duration,
                                 currentLongest) != currentLongest);
                }
            }
        }

        if (state == 4) {
            eventType = ShadowPowerEvent_ResumingFromHibernate;
        } else {
            eventType = ShadowPowerEvent_ResumingFromSleep;
        }

        InterlockedIncrement64(&g_PowerState.Stats.ResumeTransitions);
    }

    if (eventType == ShadowPowerEvent_None) {
        return;
    }

    //
    // Store event in deferred context (protected by spin lock — DISPATCH_LEVEL safe)
    //
    KeAcquireSpinLock(&g_PowerState.DeferredCtxLock, &oldIrql);

    if (g_PowerState.DeferredCtx.EventCount < PWR_DEFERRED_EVENT_MAX) {
        g_PowerState.DeferredCtx.Events[g_PowerState.DeferredCtx.EventCount] = eventType;
        g_PowerState.DeferredCtx.EventCount++;
    }

    KeReleaseSpinLock(&g_PowerState.DeferredCtxLock, oldIrql);

    //
    // Queue work item to process at PASSIVE_LEVEL (only if not already queued)
    //
    if (g_PowerState.DeferredWorkItem != NULL &&
        g_PowerState.DeviceObject != NULL) {

        if (InterlockedCompareExchange(&g_PowerState.WorkItemQueued, 1, 0) == 0) {
            //
            // We won the race — queue the work item.
            // Clear the completion event so shutdown can wait on it.
            //
            KeClearEvent(&g_PowerState.WorkItemComplete);

            IoQueueWorkItem(
                g_PowerState.DeferredWorkItem,
                PwrpDeferredEventWorkRoutine,
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
 * @brief Process a power event at PASSIVE_LEVEL.
 *
 * Allocates memory, acquires push locks, notifies callbacks.
 * Only called from PASSIVE_LEVEL code paths.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
PwrpProcessPowerEvent(
    _In_ SHADOW_POWER_EVENT_TYPE EventType,
    _In_opt_ PVOID EventData,
    _In_ ULONG EventDataSize
    )
{
    PSHADOW_POWER_EVENT_INTERNAL event;

    if (!g_PowerState.Initialized || g_PowerState.ShuttingDown) {
        return;
    }

    event = (PSHADOW_POWER_EVENT_INTERNAL)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(SHADOW_POWER_EVENT_INTERNAL),
        PWR_POOL_TAG_EVENT
        );

    if (event == NULL) {
        return;
    }

    event->Info.EventType = EventType;
    event->Info.PreviousState = g_PowerState.StateInfo.CurrentState;
    KeQuerySystemTime(&event->Info.Timestamp);
    event->Info.EventSequence = (UINT64)InterlockedIncrement64(&g_PowerState.EventSequence);

    //
    // Populate event-specific data
    //
    if (EventData != NULL && EventDataSize >= sizeof(ULONG)) {
        ULONG val = *(PULONG)EventData;

        if (EventType == ShadowPowerEvent_BatteryLow ||
            EventType == ShadowPowerEvent_BatteryCritical) {
            event->Info.Data.Battery.BatteryPercentage = val;
        }
    }

    //
    // Update state based on event
    //
    PwrpUpdateStateFromEvent(event);
    event->Info.NewState = g_PowerState.StateInfo.CurrentState;

    //
    // Record in history
    //
    PwrpRecordEvent(event);

    //
    // Notify registered callbacks
    //
    PwrpNotifyCallbacks(event);

    InterlockedIncrement64(&g_PowerState.Stats.TotalPowerEvents);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] Power event: %s (seq=%llu)\n",
               ShadowPowerEventToString(EventType),
               event->Info.EventSequence);
}

/**
 * @brief Record event in bounded history list.
 *        Trims oldest events when over PWR_MAX_EVENT_HISTORY.
 */
static VOID
PwrpRecordEvent(
    _In_ PSHADOW_POWER_EVENT_INTERNAL Event
    )
{
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PowerState.EventHistoryLock);

    InsertHeadList(&g_PowerState.EventHistory, &Event->ListEntry);
    InterlockedIncrement(&g_PowerState.EventCount);

    while (g_PowerState.EventCount > PWR_MAX_EVENT_HISTORY) {
        PLIST_ENTRY tail = RemoveTailList(&g_PowerState.EventHistory);
        PSHADOW_POWER_EVENT_INTERNAL oldEvent =
            CONTAINING_RECORD(tail, SHADOW_POWER_EVENT_INTERNAL, ListEntry);
        ExFreePoolWithTag(oldEvent, PWR_POOL_TAG_EVENT);
        InterlockedDecrement(&g_PowerState.EventCount);
    }

    ExReleasePushLockExclusive(&g_PowerState.EventHistoryLock);
    KeLeaveCriticalRegion();
}

/**
 * @brief Notify registered callbacks with proper event mask filtering.
 *        Uses ULONGLONG mask for safe shifting up to 63 bits.
 */
static VOID
PwrpNotifyCallbacks(
    _In_ PSHADOW_POWER_EVENT_INTERNAL Event
    )
{
    PLIST_ENTRY entry;
    PSHADOW_POWER_CALLBACK_ENTRY callbackEntry;
    ULONGLONG eventBit;

    if (g_PowerState.CallbackCount == 0) {
        return;
    }

    //
    // Safe: EventType is validated < 64 by C_ASSERT(ShadowPowerEvent_Max <= 64)
    //
    if ((ULONG)Event->Info.EventType >= 64) {
        return;
    }
    eventBit = 1ULL << (ULONG)Event->Info.EventType;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_PowerState.CallbackLock);

    for (entry = g_PowerState.CallbackList.Flink;
         entry != &g_PowerState.CallbackList;
         entry = entry->Flink) {

        callbackEntry = CONTAINING_RECORD(entry, SHADOW_POWER_CALLBACK_ENTRY, ListEntry);

        if (!callbackEntry->Enabled) {
            continue;
        }

        if (callbackEntry->EventMask != 0 && !(callbackEntry->EventMask & eventBit)) {
            continue;
        }

        __try {
            callbackEntry->Callback(Event->Info.EventType, &Event->Info, callbackEntry->Context);
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
 * @brief Deferred work routine — processes events queued from DISPATCH_LEVEL.
 *
 * Runs at PASSIVE_LEVEL. Drains the deferred event queue and
 * processes each event with full locking/allocation capabilities.
 * Also triggers resume validation when a resume event is present.
 */
_Function_class_(IO_WORKITEM_ROUTINE)
static VOID NTAPI
PwrpDeferredEventWorkRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    )
{
    PWR_DEFERRED_EVENT_CONTEXT localCtx;
    ULONG i;
    BOOLEAN needsResumeValidation = FALSE;
    KIRQL oldIrql;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Context);

    //
    // Drain the deferred events under spin lock (quick copy)
    //
    KeAcquireSpinLock(&g_PowerState.DeferredCtxLock, &oldIrql);

    RtlCopyMemory(&localCtx, &g_PowerState.DeferredCtx, sizeof(PWR_DEFERRED_EVENT_CONTEXT));
    g_PowerState.DeferredCtx.EventCount = 0;

    KeReleaseSpinLock(&g_PowerState.DeferredCtxLock, oldIrql);

    //
    // Process each deferred event at PASSIVE_LEVEL
    //
    for (i = 0; i < localCtx.EventCount; i++) {
        SHADOW_POWER_EVENT_TYPE eventType = localCtx.Events[i];

        PwrpProcessPowerEvent(eventType, NULL, 0);

        if (eventType == ShadowPowerEvent_ResumingFromSleep ||
            eventType == ShadowPowerEvent_ResumingFromHibernate) {
            needsResumeValidation = TRUE;
        }
    }

    //
    // Perform resume validation if needed
    //
    if (needsResumeValidation && !g_PowerState.ShuttingDown) {
        ShadowPowerValidateResume();
    }

    //
    // Mark work item as no longer queued, then signal completion
    //
    InterlockedExchange(&g_PowerState.WorkItemQueued, 0);
    KeSetEvent(&g_PowerState.WorkItemComplete, IO_NO_INCREMENT, FALSE);
}

/**
 * @brief Update state based on power event.
 *        Acquires StateLock exclusively and also updates volatile copies.
 */
static VOID
PwrpUpdateStateFromEvent(
    _In_ PSHADOW_POWER_EVENT_INTERNAL Event
    )
{
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PowerState.StateLock);

    g_PowerState.StateInfo.PreviousState = g_PowerState.StateInfo.CurrentState;

    switch (Event->Info.EventType) {
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

    if (Event->Info.EventType == ShadowPowerEvent_ExitingConnectedStandby) {
        g_PowerState.StateInfo.InConnectedStandby = FALSE;
        g_PowerState.StateInfo.ConnectedStandbyExitCount++;
    }

    KeQuerySystemTime(&g_PowerState.StateInfo.LastStateChangeTime);

    //
    // Update volatile copies for lock-free DISPATCH_LEVEL readers
    //
    PwrpUpdateVolatileState();

    ExReleasePushLockExclusive(&g_PowerState.StateLock);
    KeLeaveCriticalRegion();
}

/**
 * @brief Update volatile copies of state for lock-free readers.
 *        Must be called under StateLock exclusive.
 */
static VOID
PwrpUpdateVolatileState(
    VOID
    )
{
    InterlockedExchange(&g_PowerState.CurrentPowerState,
                        (LONG)g_PowerState.StateInfo.CurrentState);
    InterlockedExchange(&g_PowerState.CurrentPowerSource,
                        (LONG)g_PowerState.StateInfo.PowerSource);
}

// ============================================================================
// PRIVATE FUNCTIONS - RESUME VALIDATION
// ============================================================================

/**
 * @brief Perform actual resume validation checks.
 *
 * Validates driver integrity after resume from sleep/hibernate.
 * Each check is independent — failure of one doesn't prevent others.
 */
static NTSTATUS
PwrpPerformResumeValidation(
    VOID
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS checkStatus;
    LARGE_INTEGER currentTime;

    KeQuerySystemTime(&currentTime);

    //
    // Check 1: Verify driver state is consistent
    //
    if (!g_PowerState.Initialized) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Resume validation: Driver not initialized\n");
        return STATUS_DRIVER_INTERNAL_ERROR;
    }

    //
    // Check 2: Detect time anomalies
    //
    if (g_PowerState.LastSleepStartTime.QuadPart > 0) {
        if (g_PowerState.LastSleepStartTime.QuadPart > currentTime.QuadPart) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] Resume validation: Time anomaly detected "
                       "(sleep start > current time)\n");
            //
            // Log but don't fail — clock can be adjusted legitimately
            //
        } else {
            LONGLONG sleepDuration = currentTime.QuadPart - g_PowerState.LastSleepStartTime.QuadPart;
            ULONG sleepSeconds = (ULONG)(sleepDuration / 10000000);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[ShadowStrike] Resume validation: slept for %lu seconds\n",
                       sleepSeconds);
        }
    }

    //
    // Check 3: Verify our power setting callbacks are still registered
    //
    {
        ULONG registeredCount = 0;
        if (g_PowerState.ConsoleDisplayStateHandle != NULL) registeredCount++;
        if (g_PowerState.AcDcPowerSourceHandle != NULL) registeredCount++;
        if (g_PowerState.LidSwitchStateHandle != NULL) registeredCount++;
        if (g_PowerState.BatteryPercentageHandle != NULL) registeredCount++;
        if (g_PowerState.IdleResiliencyHandle != NULL) registeredCount++;
        if (g_PowerState.UserPresenceHandle != NULL) registeredCount++;
        if (g_PowerState.SessionDisplayStatusHandle != NULL) registeredCount++;

        if (registeredCount == 0) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] Resume validation: No power callbacks registered, "
                       "attempting re-registration\n");

            checkStatus = PwrpRegisterPowerSettingCallbacks();
            if (!NT_SUCCESS(checkStatus)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                           "[ShadowStrike] Resume validation: Re-registration failed: 0x%08X\n",
                           checkStatus);
                status = STATUS_DRIVER_INTERNAL_ERROR;
            }
        } else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                       "[ShadowStrike] Resume validation: %lu power callbacks active\n",
                       registeredCount);
        }
    }

    //
    // Check 4: Verify system state callback registration
    //
    if (g_PowerState.SystemStateRegistration == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Resume validation: System state callback not registered, "
                   "attempting re-registration\n");

        checkStatus = PwrpRegisterSystemStateCallback();
        if (!NT_SUCCESS(checkStatus)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike] Resume validation: System state re-registration failed: 0x%08X\n",
                       checkStatus);
            status = STATUS_DRIVER_INTERNAL_ERROR;
        }
    }

    //
    // Check 5: Record resume time under lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PowerState.StateLock);
    g_PowerState.StateInfo.LastResumeTime = currentTime;
    ExReleasePushLockExclusive(&g_PowerState.StateLock);
    KeLeaveCriticalRegion();

    return status;
}
