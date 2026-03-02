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
 * ShadowStrike NGAV - ENTERPRISE ETW TELEMETRY ENGINE IMPLEMENTATION
 * ============================================================================
 *
 * @file TelemetryEvents.c
 * @brief Enterprise-grade ETW telemetry implementation for kernel-mode EDR.
 *
 * This module implements high-performance telemetry streaming with:
 * - Lookaside-based event allocation (prevents kernel stack overflow)
 * - Synchronous ETW writes with atomic state management
 * - Adaptive rate limiting and throttling with interlocked operations
 * - Bounded string operations (wcsnlen/strnlen) for safety
 * - Kernel-safe string formatting via ntstrsafe.h
 * - Proper DPC draining on shutdown (KeFlushQueuedDpcs)
 * - Atomic state machine for init/shutdown/pause/resume
 * - RW spinlock-protected configuration for DISPATCH_LEVEL safety
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "TelemetryEvents.h"
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/StringUtils.h"
#include "../Sync/SpinLock.h"
#include <ntstrsafe.h>

//
// MmGetSessionId is exported by ntoskrnl.exe since Windows Vista but
// not always declared in WDK headers depending on NTDDI_VERSION settings.
//
#ifndef MmGetSessionId
NTKERNELAPI ULONG MmGetSessionId(_In_ PEPROCESS Process);
#endif

#include <initguid.h>

// ============================================================================
// ETW PROVIDER GUID DEFINITION
// ============================================================================

// {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
DEFINE_GUID(SHADOWSTRIKE_TELEMETRY_PROVIDER_GUID,
    0xA1B2C3D4, 0xE5F6, 0x7890, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90);

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define TE_VERSION                      2
#define TE_CORRELATION_SEED             0x5348414457535452ULL  // "SHADOWSTR"
#define TE_MAX_ETW_DATA_DESCRIPTORS     16
#define TE_FLUSH_WORK_ITEM_DELAY_MS     10
#define TE_SHUTDOWN_TIMEOUT_MS          5000

// ============================================================================
// GLOBAL STATE
// ============================================================================

static TE_PROVIDER g_TeProvider = { 0 };

static volatile LONG64 g_CorrelationCounter = 0;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static VOID
TepEnableCallback(
    _In_ LPCGUID SourceId,
    _In_ ULONG IsEnabled,
    _In_ UCHAR Level,
    _In_ ULONGLONG MatchAnyKeyword,
    _In_ ULONGLONG MatchAllKeyword,
    _In_opt_ PEVENT_FILTER_DESCRIPTOR FilterData,
    _Inout_opt_ PVOID CallbackContext
    );

static VOID
TepFlushDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

static VOID
TepFlushWorkItemRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    );

static VOID
TepHeartbeatDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

static NTSTATUS
TepWriteEventInternal(
    _In_ PTE_EVENT_HEADER Header,
    _In_ PVOID EventData,
    _In_ ULONG EventSize
    );

static VOID
TepInitializeEventHeader(
    _Out_ PTE_EVENT_HEADER Header,
    _In_ TE_EVENT_ID EventId,
    _In_ TE_EVENT_LEVEL Level,
    _In_ UINT64 Keywords,
    _In_ UINT32 EventSize
    );

static BOOLEAN
TepShouldThrottle(
    _In_ TE_EVENT_LEVEL Level,
    _In_ TE_PRIORITY Priority
    );

static VOID
TepUpdateRateStatistics(
    VOID
    );

static VOID
TepAcquireReference(
    VOID
    );

static BOOLEAN
TepTryAcquireReference(
    VOID
    );

static VOID
TepReleaseReference(
    VOID
    );

static VOID
TepIncrementLevelStats(
    _In_ TE_EVENT_LEVEL Level
    );

static PVOID
TepAllocateEvent(
    VOID
    );

static VOID
TepFreeEvent(
    _In_ PVOID EventBuffer
    );

static VOID
TepCopyUnicodeStringSafe(
    _Out_writes_(MaxChars) PWCHAR Dest,
    _In_ SIZE_T MaxChars,
    _In_opt_ PCUNICODE_STRING Source
    );

static VOID
TepCopyPcwstrSafe(
    _Out_writes_(MaxChars) PWCHAR Dest,
    _In_ SIZE_T MaxChars,
    _In_opt_ PCWSTR Source
    );

static VOID
TepCopyAnsiStringSafe(
    _Out_writes_(MaxBytes) PCHAR Dest,
    _In_ SIZE_T MaxBytes,
    _In_opt_ PCSTR Source
    );

// ============================================================================
// SAFE STRING COPY HELPERS
// ============================================================================

static VOID
TepCopyUnicodeStringSafe(
    _Out_writes_(MaxChars) PWCHAR Dest,
    _In_ SIZE_T MaxChars,
    _In_opt_ PCUNICODE_STRING Source
    )
{
    SIZE_T copyChars;

    if (MaxChars == 0) {
        return;
    }

    Dest[0] = L'\0';

    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0) {
        return;
    }

    copyChars = Source->Length / sizeof(WCHAR);
    if (copyChars >= MaxChars) {
        copyChars = MaxChars - 1;
    }

    RtlCopyMemory(Dest, Source->Buffer, copyChars * sizeof(WCHAR));
    Dest[copyChars] = L'\0';
}

static VOID
TepCopyPcwstrSafe(
    _Out_writes_(MaxChars) PWCHAR Dest,
    _In_ SIZE_T MaxChars,
    _In_opt_ PCWSTR Source
    )
{
    SIZE_T copyChars;

    if (MaxChars == 0) {
        return;
    }

    Dest[0] = L'\0';

    if (Source == NULL) {
        return;
    }

    copyChars = wcsnlen(Source, MaxChars);
    if (copyChars >= MaxChars) {
        copyChars = MaxChars - 1;
    }

    RtlCopyMemory(Dest, Source, copyChars * sizeof(WCHAR));
    Dest[copyChars] = L'\0';
}

static VOID
TepCopyAnsiStringSafe(
    _Out_writes_(MaxBytes) PCHAR Dest,
    _In_ SIZE_T MaxBytes,
    _In_opt_ PCSTR Source
    )
{
    SIZE_T copyBytes;

    if (MaxBytes == 0) {
        return;
    }

    Dest[0] = '\0';

    if (Source == NULL) {
        return;
    }

    copyBytes = strnlen(Source, MaxBytes);
    if (copyBytes >= MaxBytes) {
        copyBytes = MaxBytes - 1;
    }

    RtlCopyMemory(Dest, Source, copyBytes);
    Dest[copyBytes] = '\0';
}

// ============================================================================
// LOOKASIDE EVENT ALLOCATION
// ============================================================================

static PVOID
TepAllocateEvent(
    VOID
    )
{
    PVOID buffer;

    buffer = ShadowStrikeLookasideAllocate(&g_TeProvider.EventLookaside);
    if (buffer == NULL) {
        InterlockedIncrement64(&g_TeProvider.Stats.AllocationFailures);
        return NULL;
    }

    return buffer;
}

static VOID
TepFreeEvent(
    _In_ PVOID EventBuffer
    )
{
    if (EventBuffer != NULL) {
        ShadowStrikeLookasideFree(&g_TeProvider.EventLookaside, EventBuffer);
    }
}

// ============================================================================
// LEVEL STATS WITH BOUNDS CHECK
// ============================================================================

static VOID
TepIncrementLevelStats(
    _In_ TE_EVENT_LEVEL Level
    )
{
    if ((ULONG)Level < TE_MAX_EVENT_LEVELS) {
        InterlockedIncrement64(&g_TeProvider.Stats.EventsByLevel[Level]);
    }
}

// ============================================================================
// INITIALIZATION AND SHUTDOWN
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
TeInitialize(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PTE_CONFIG Config
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    LARGE_INTEGER dueTime;
    BOOLEAN lookasideInitialized = FALSE;
    BOOLEAN etwRegistered = FALSE;
    BOOLEAN workItemAllocated = FALSE;

    PAGED_CODE();

    if (DeviceObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Atomic transition from Uninitialized to Initializing.
    // Prevents double-initialization race.
    //
    if (InterlockedCompareExchange(
            &g_TeProvider.State,
            (LONG)TeState_Initializing,
            (LONG)TeState_Uninitialized) != (LONG)TeState_Uninitialized) {
        return STATUS_ALREADY_INITIALIZED;
    }

    //
    // Initialize synchronization
    //
    ShadowStrikeInitializeRWSpinLock(&g_TeProvider.ConfigLock);
    ShadowStrikeInitializeRWSpinLock(&g_TeProvider.StatsLock);

    //
    // Initialize shutdown event and reference count
    //
    KeInitializeEvent(&g_TeProvider.ShutdownEvent, NotificationEvent, FALSE);
    g_TeProvider.ReferenceCount = 1;
    g_TeProvider.HeartbeatRunning = 0;

    g_TeProvider.DeviceObject = DeviceObject;

    //
    // Apply configuration
    //
    if (Config != NULL) {
        RtlCopyMemory(&g_TeProvider.Config, Config, sizeof(TE_CONFIG));
    } else {
        g_TeProvider.Config.Enabled = TRUE;
        g_TeProvider.Config.EnableBatching = FALSE;
        g_TeProvider.Config.EnableThrottling = TRUE;
        g_TeProvider.Config.EnableSampling = TRUE;
        g_TeProvider.Config.EnableCorrelation = TRUE;
        g_TeProvider.Config.EnableCompression = FALSE;
        g_TeProvider.Config.MaxVerbosity = TeLevel_Informational;
        g_TeProvider.Config.EnabledKeywords = TeKeyword_All;
        g_TeProvider.Config.MaxEventsPerSecond = TE_MAX_EVENTS_PER_SECOND;
        g_TeProvider.Config.SamplingRate = 10;
        g_TeProvider.Config.MaxBatchSize = TE_MAX_BATCH_SIZE;
        g_TeProvider.Config.MaxBatchAgeMs = TE_MAX_BATCH_AGE_MS;
        g_TeProvider.Config.ThrottleThreshold = TE_MAX_EVENTS_PER_SECOND / 2;
        g_TeProvider.Config.ThrottleRecoveryMs = 1000;
        g_TeProvider.Config.HeartbeatIntervalMs = TE_HEARTBEAT_INTERVAL_MS;
        g_TeProvider.Config.StatsIntervalMs = TE_STATS_INTERVAL_MS;
    }

    //
    // Validate and clamp critical config values
    //
    if (g_TeProvider.Config.SamplingRate == 0) {
        g_TeProvider.Config.SamplingRate = 1;
    }
    if (g_TeProvider.Config.MaxEventsPerSecond == 0) {
        g_TeProvider.Config.MaxEventsPerSecond = TE_MAX_EVENTS_PER_SECOND;
    }
    if (g_TeProvider.Config.ThrottleThreshold == 0) {
        g_TeProvider.Config.ThrottleThreshold = g_TeProvider.Config.MaxEventsPerSecond / 2;
    }

    //
    // Populate cached config for lock-free hot-path reads.
    //
    InterlockedExchange(&g_TeProvider.CachedEnableThrottling,
                        (LONG)g_TeProvider.Config.EnableThrottling);
    InterlockedExchange(&g_TeProvider.CachedSamplingRate,
                        (LONG)g_TeProvider.Config.SamplingRate);
    InterlockedExchange(&g_TeProvider.CachedThrottleThreshold,
                        (LONG)g_TeProvider.Config.ThrottleThreshold);
    InterlockedExchange(&g_TeProvider.CachedThrottleRecoveryMs,
                        (LONG)g_TeProvider.Config.ThrottleRecoveryMs);

    //
    // Initialize lookaside list for event buffers.
    // TE_MAX_EVENT_DATA_SIZE (16KB) is large enough for any event struct.
    //
    status = ShadowStrikeLookasideInit(
        &g_TeProvider.EventLookaside,
        TE_MAX_EVENT_DATA_SIZE,
        TE_EVENT_TAG,
        TE_LOOKASIDE_DEPTH,
        FALSE
    );

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    lookasideInitialized = TRUE;

    //
    // Register ETW provider
    //
    status = EtwRegister(
        &SHADOWSTRIKE_TELEMETRY_PROVIDER_GUID,
        TepEnableCallback,
        &g_TeProvider,
        &g_TeProvider.RegistrationHandle
    );

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    etwRegistered = TRUE;

    //
    // Allocate flush work item
    //
    g_TeProvider.FlushWorkItem = IoAllocateWorkItem(DeviceObject);
    if (g_TeProvider.FlushWorkItem == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }
    workItemAllocated = TRUE;

    //
    // Initialize timers and DPCs
    //
    KeInitializeTimer(&g_TeProvider.FlushTimer);
    KeInitializeDpc(&g_TeProvider.FlushDpc, TepFlushDpcRoutine, &g_TeProvider);

    KeInitializeTimer(&g_TeProvider.HeartbeatTimer);
    KeInitializeDpc(&g_TeProvider.HeartbeatDpc, TepHeartbeatDpcRoutine, &g_TeProvider);

    //
    // Record start time
    //
    {
        LARGE_INTEGER startTime;
        KeQuerySystemTime(&startTime);
        InterlockedExchange64(&g_TeProvider.Stats.StartTime, startTime.QuadPart);
        InterlockedExchange64(
            &g_TeProvider.Stats.CurrentSecondStart,
            startTime.QuadPart
        );
    }

    //
    // Start flush timer
    //
    dueTime.QuadPart = -((LONGLONG)g_TeProvider.Config.MaxBatchAgeMs * 10000);
    KeSetTimerEx(
        &g_TeProvider.FlushTimer,
        dueTime,
        g_TeProvider.Config.MaxBatchAgeMs,
        &g_TeProvider.FlushDpc
    );

    //
    // Start heartbeat timer
    //
    if (g_TeProvider.Config.HeartbeatIntervalMs > 0) {
        dueTime.QuadPart = -((LONGLONG)g_TeProvider.Config.HeartbeatIntervalMs * 10000);
        KeSetTimerEx(
            &g_TeProvider.HeartbeatTimer,
            dueTime,
            g_TeProvider.Config.HeartbeatIntervalMs,
            &g_TeProvider.HeartbeatDpc
        );
        InterlockedExchange(&g_TeProvider.HeartbeatRunning, 1);
    }

    //
    // Atomically transition to Running
    //
    InterlockedExchange(&g_TeProvider.State, (LONG)TeState_Running);

    TeLogOperational(
        TeEvent_DriverLoaded,
        TeLevel_Informational,
        Component_Telemetry,
        L"Telemetry subsystem initialized successfully",
        0
    );

    return STATUS_SUCCESS;

Cleanup:
    if (etwRegistered) {
        EtwUnregister(g_TeProvider.RegistrationHandle);
        g_TeProvider.RegistrationHandle = 0;
    }

    if (workItemAllocated) {
        IoFreeWorkItem(g_TeProvider.FlushWorkItem);
        g_TeProvider.FlushWorkItem = NULL;
    }

    if (lookasideInitialized) {
        ShadowStrikeLookasideCleanup(&g_TeProvider.EventLookaside);
    }

    InterlockedExchange(&g_TeProvider.State, (LONG)TeState_Error);

    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
TeShutdown(
    VOID
    )
{
    LARGE_INTEGER timeout;

    PAGED_CODE();

    //
    // Atomic transition to ShuttingDown. Only proceed from Running or Paused.
    //
    if (InterlockedCompareExchange(
            &g_TeProvider.State,
            (LONG)TeState_ShuttingDown,
            (LONG)TeState_Running) != (LONG)TeState_Running) {

        if (InterlockedCompareExchange(
                &g_TeProvider.State,
                (LONG)TeState_ShuttingDown,
                (LONG)TeState_Paused) != (LONG)TeState_Paused) {
            return;
        }
    }

    TeLogOperational(
        TeEvent_DriverUnloading,
        TeLevel_Informational,
        Component_Telemetry,
        L"Telemetry subsystem shutting down",
        0
    );

    //
    // Cancel timers
    //
    KeCancelTimer(&g_TeProvider.FlushTimer);
    KeCancelTimer(&g_TeProvider.HeartbeatTimer);
    InterlockedExchange(&g_TeProvider.HeartbeatRunning, 0);

    //
    // CRITICAL: Wait for any queued DPCs to complete before freeing resources.
    // Without this, a DPC could fire and access freed work items/state.
    //
    KeFlushQueuedDpcs();

    //
    // Flush remaining events (synchronous write, updates timestamp)
    //
    TeFlush();

    //
    // Release init reference and wait for active operations to drain
    //
    TepReleaseReference();
    timeout.QuadPart = -((LONGLONG)TE_SHUTDOWN_TIMEOUT_MS * 10000);
    KeWaitForSingleObject(
        &g_TeProvider.ShutdownEvent,
        Executive,
        KernelMode,
        FALSE,
        &timeout
    );

    //
    // Free work item (safe now — DPCs are drained)
    //
    if (g_TeProvider.FlushWorkItem != NULL) {
        IoFreeWorkItem(g_TeProvider.FlushWorkItem);
        g_TeProvider.FlushWorkItem = NULL;
    }

    //
    // Unregister ETW provider
    //
    if (g_TeProvider.RegistrationHandle != 0) {
        EtwUnregister(g_TeProvider.RegistrationHandle);
        g_TeProvider.RegistrationHandle = 0;
    }

    //
    // Cleanup lookaside list
    //
    ShadowStrikeLookasideCleanup(&g_TeProvider.EventLookaside);

    InterlockedExchange(&g_TeProvider.State, (LONG)TeState_Shutdown);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
TeIsEnabled(
    VOID
    )
{
    LONG state = g_TeProvider.State;

    return (state == (LONG)TeState_Running && g_TeProvider.Config.Enabled);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
TeIsEventEnabled(
    _In_ TE_EVENT_LEVEL Level,
    _In_ UINT64 Keywords
    )
{
    UCHAR enableLevel;
    ULONGLONG enableFlags;
    TE_CONFIG config;
    KIRQL oldIrql;

    if (!TeIsEnabled()) {
        return FALSE;
    }

    //
    // Check ETW consumer filter (set by TepEnableCallback, volatile reads)
    //
    enableLevel = g_TeProvider.EnableLevel;
    enableFlags = g_TeProvider.EnableFlags;

    if (enableLevel != 0 && (UCHAR)Level > enableLevel) {
        return FALSE;
    }

    if (enableFlags != 0 && (Keywords & enableFlags) == 0) {
        return FALSE;
    }

    //
    // Check config filter (protected by spinlock for consistency)
    //
    ShadowStrikeAcquireRWSpinLockShared(&g_TeProvider.ConfigLock, &oldIrql);
    config = g_TeProvider.Config;
    ShadowStrikeReleaseRWSpinLockShared(&g_TeProvider.ConfigLock, oldIrql);

    if ((UCHAR)Level > (UCHAR)config.MaxVerbosity) {
        return FALSE;
    }

    if ((Keywords & config.EnabledKeywords) == 0) {
        return FALSE;
    }

    return TRUE;
}

// ============================================================================
// CONFIGURATION
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeSetConfig(
    _In_ PTE_CONFIG Config
    )
{
    KIRQL oldIrql;
    TE_CONFIG validated;

    if (Config == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_TeProvider.State != (LONG)TeState_Running &&
        g_TeProvider.State != (LONG)TeState_Paused) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Copy and validate — never apply unvalidated config to global state.
    //
    RtlCopyMemory(&validated, Config, sizeof(TE_CONFIG));

    if (validated.SamplingRate == 0) {
        validated.SamplingRate = 1;
    }
    if (validated.MaxEventsPerSecond == 0) {
        validated.MaxEventsPerSecond = TE_MAX_EVENTS_PER_SECOND;
    }
    if (validated.ThrottleThreshold == 0) {
        validated.ThrottleThreshold = validated.MaxEventsPerSecond / 2;
    }
    if (validated.ThrottleRecoveryMs == 0) {
        validated.ThrottleRecoveryMs = 1000;
    }
    if ((UCHAR)validated.MaxVerbosity < (UCHAR)TeLevel_Critical ||
        (UCHAR)validated.MaxVerbosity > (UCHAR)TeLevel_Verbose) {
        validated.MaxVerbosity = TeLevel_Informational;
    }

    ShadowStrikeAcquireRWSpinLockExclusive(&g_TeProvider.ConfigLock, &oldIrql);
    RtlCopyMemory(&g_TeProvider.Config, &validated, sizeof(TE_CONFIG));
    ShadowStrikeReleaseRWSpinLockExclusive(&g_TeProvider.ConfigLock, oldIrql);

    //
    // Update cached config atomically for lock-free hot-path reads.
    //
    InterlockedExchange(&g_TeProvider.CachedEnableThrottling,
                        (LONG)validated.EnableThrottling);
    InterlockedExchange(&g_TeProvider.CachedSamplingRate,
                        (LONG)validated.SamplingRate);
    InterlockedExchange(&g_TeProvider.CachedThrottleThreshold,
                        (LONG)validated.ThrottleThreshold);
    InterlockedExchange(&g_TeProvider.CachedThrottleRecoveryMs,
                        (LONG)validated.ThrottleRecoveryMs);

    TeLogOperational(
        TeEvent_ConfigChange,
        TeLevel_Informational,
        Component_Telemetry,
        L"Telemetry configuration updated",
        0
    );

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeGetConfig(
    _Out_ PTE_CONFIG Config
    )
{
    KIRQL oldIrql;

    if (Config == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_TeProvider.State == (LONG)TeState_Uninitialized ||
        g_TeProvider.State == (LONG)TeState_Shutdown) {
        return STATUS_DEVICE_NOT_READY;
    }

    ShadowStrikeAcquireRWSpinLockShared(&g_TeProvider.ConfigLock, &oldIrql);
    RtlCopyMemory(Config, &g_TeProvider.Config, sizeof(TE_CONFIG));
    ShadowStrikeReleaseRWSpinLockShared(&g_TeProvider.ConfigLock, oldIrql);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TePause(
    VOID
    )
{
    if (InterlockedCompareExchange(
            &g_TeProvider.State,
            (LONG)TeState_Paused,
            (LONG)TeState_Running) == (LONG)TeState_Running) {
        //
        // Cancel heartbeat timer to avoid wasted DPC firings while paused.
        //
        KeCancelTimer(&g_TeProvider.HeartbeatTimer);
        InterlockedExchange(&g_TeProvider.HeartbeatRunning, 0);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TeResume(
    VOID
    )
{
    LARGE_INTEGER dueTime;

    if (InterlockedCompareExchange(
            &g_TeProvider.State,
            (LONG)TeState_Running,
            (LONG)TeState_Paused) == (LONG)TeState_Paused) {
        //
        // Restart heartbeat timer if configured.
        //
        if (g_TeProvider.Config.HeartbeatIntervalMs > 0 &&
            InterlockedCompareExchange(&g_TeProvider.HeartbeatRunning, 1, 0) == 0) {
            dueTime.QuadPart = -((LONGLONG)g_TeProvider.Config.HeartbeatIntervalMs * 10000);
            KeSetTimerEx(
                &g_TeProvider.HeartbeatTimer,
                dueTime,
                g_TeProvider.Config.HeartbeatIntervalMs,
                &g_TeProvider.HeartbeatDpc
            );
        }
    }
}

// ============================================================================
// ETW CALLBACK
// ============================================================================

static VOID
TepEnableCallback(
    _In_ LPCGUID SourceId,
    _In_ ULONG IsEnabled,
    _In_ UCHAR Level,
    _In_ ULONGLONG MatchAnyKeyword,
    _In_ ULONGLONG MatchAllKeyword,
    _In_opt_ PEVENT_FILTER_DESCRIPTOR FilterData,
    _Inout_opt_ PVOID CallbackContext
    )
{
    UNREFERENCED_PARAMETER(SourceId);
    UNREFERENCED_PARAMETER(MatchAllKeyword);
    UNREFERENCED_PARAMETER(FilterData);
    UNREFERENCED_PARAMETER(CallbackContext);

    //
    // IsEnabled values: EVENT_CONTROL_CODE_ENABLE_PROVIDER (1),
    // EVENT_CONTROL_CODE_DISABLE_PROVIDER (0),
    // EVENT_CONTROL_CODE_CAPTURE_STATE (2).
    // Only track enable/disable — capture state must not alter consumer count.
    //
    if (IsEnabled == EVENT_CONTROL_CODE_ENABLE_PROVIDER) {
        g_TeProvider.EnableLevel = Level;
        InterlockedExchange64(
            (volatile LONG64*)&g_TeProvider.EnableFlags,
            (LONG64)MatchAnyKeyword
        );
        InterlockedIncrement(&g_TeProvider.ConsumerCount);
        InterlockedExchange(&g_TeProvider.EtwEnabled, 1);
    } else if (IsEnabled == EVENT_CONTROL_CODE_DISABLE_PROVIDER) {
        if (InterlockedDecrement(&g_TeProvider.ConsumerCount) <= 0) {
            //
            // Clamp to zero — guard against orphaned disables
            //
            InterlockedExchange(&g_TeProvider.ConsumerCount, 0);
            InterlockedExchange(&g_TeProvider.EtwEnabled, 0);
        }
    }
    // EVENT_CONTROL_CODE_CAPTURE_STATE: update level/keywords but not consumer count
    else if (IsEnabled == EVENT_CONTROL_CODE_CAPTURE_STATE) {
        g_TeProvider.EnableLevel = Level;
        InterlockedExchange64(
            (volatile LONG64*)&g_TeProvider.EnableFlags,
            (LONG64)MatchAnyKeyword
        );
    }
}

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

static VOID
TepInitializeEventHeader(
    _Out_ PTE_EVENT_HEADER Header,
    _In_ TE_EVENT_ID EventId,
    _In_ TE_EVENT_LEVEL Level,
    _In_ UINT64 Keywords,
    _In_ UINT32 EventSize
    )
{
    LARGE_INTEGER timestamp;
    LARGE_INTEGER perfCounter;
    UINT64 counter;

    Header->Size = EventSize;
    Header->Version = TE_VERSION;
    Header->Flags = 0;
    Header->EventId = (UINT32)EventId;
    Header->Level = (UINT32)Level;
    Header->Keywords = Keywords;

    KeQuerySystemTime(&timestamp);
    Header->Timestamp = timestamp.QuadPart;

    Header->SequenceNumber = (UINT64)InterlockedIncrement64(&g_TeProvider.SequenceNumber);

    Header->ProcessId = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
    Header->ThreadId = (UINT32)(ULONG_PTR)PsGetCurrentThreadId();

    //
    // Session ID: MmGetSessionId reads the session from the current
    // EPROCESS. Safe at APC_LEVEL and below. At higher IRQL levels,
    // we set session ID to 0 (unknown) to avoid potential issues.
    //
    if (KeGetCurrentIrql() <= APC_LEVEL) {
        Header->SessionId = (UINT32)MmGetSessionId(PsGetCurrentProcess());
    } else {
        Header->SessionId = 0;
    }

    Header->ProcessorNumber = KeGetCurrentProcessorNumberEx(NULL);

    //
    // Generate correlation ID: mix of monotonic counter, timestamp, perf counter, and PID.
    // Not cryptographic — provides uniqueness, not unpredictability.
    //
    perfCounter = KeQueryPerformanceCounter(NULL);
    counter = (UINT64)InterlockedIncrement64(&g_CorrelationCounter);
    Header->CorrelationId = (TE_CORRELATION_SEED ^ perfCounter.QuadPart ^ timestamp.QuadPart) + counter;
    Header->ActivityId = Header->SequenceNumber;
}

static BOOLEAN
TepShouldThrottle(
    _In_ TE_EVENT_LEVEL Level,
    _In_ TE_PRIORITY Priority
    )
{
    LONG action;
    LONG samplingRate;

    //
    // Read cached config atomically — no lock needed on hot path.
    //
    if (!g_TeProvider.CachedEnableThrottling) {
        return FALSE;
    }

    action = g_TeProvider.ThrottleAction;

    if (Priority == TePriority_Critical || Level == TeLevel_Critical) {
        return FALSE;
    }

    switch (action) {
        case TeThrottle_None:
            return FALSE;

        case TeThrottle_Sample:
            samplingRate = g_TeProvider.CachedSamplingRate;
            if (samplingRate > 0) {
                LONG counter = InterlockedIncrement(&g_TeProvider.ThrottleSampleCounter);
                return (counter % samplingRate) != 0;
            }
            return FALSE;

        case TeThrottle_DropLow:
            return (Priority <= TePriority_Low);

        case TeThrottle_DropNormal:
            return (Priority <= TePriority_Normal);

        case TeThrottle_DropAll:
            return TRUE;

        default:
            return FALSE;
    }
}

static VOID
TepUpdateRateStatistics(
    VOID
    )
{
    LARGE_INTEGER currentTime;
    LONG64 currentSecondTicks;
    LONG64 storedSecondTicks;
    LONG eventsThisSecond;
    LONG oldPeak;
    LONG throttleThreshold;
    LONG throttleRecoveryMs;

    KeQuerySystemTime(&currentTime);
    currentSecondTicks = currentTime.QuadPart / 10000000;

    storedSecondTicks = InterlockedCompareExchange64(
        &g_TeProvider.Stats.CurrentSecondStart,
        0, 0
    ) / 10000000;

    if (currentSecondTicks != storedSecondTicks) {
        //
        // Attempt to atomically claim the second-boundary update.
        // Only one CPU should perform throttle state transitions.
        //
        LONG64 oldStart = InterlockedCompareExchange64(
            &g_TeProvider.Stats.CurrentSecondStart,
            currentTime.QuadPart,
            storedSecondTicks * 10000000
        );

        if (oldStart / 10000000 == storedSecondTicks) {
            //
            // We won the race. Perform second-boundary work.
            //
            eventsThisSecond = InterlockedExchange(
                &g_TeProvider.Stats.EventsThisSecond, 0
            );

            //
            // Update peak with proper CAS loop to avoid lost updates.
            //
            do {
                oldPeak = g_TeProvider.Stats.PeakEventsPerSecond;
                if (eventsThisSecond <= oldPeak) {
                    break;
                }
            } while (InterlockedCompareExchange(
                         &g_TeProvider.Stats.PeakEventsPerSecond,
                         eventsThisSecond,
                         oldPeak) != oldPeak);

            //
            // Throttle decision — read cached config (lock-free).
            //
            throttleThreshold = g_TeProvider.CachedThrottleThreshold;
            throttleRecoveryMs = g_TeProvider.CachedThrottleRecoveryMs;

            if (eventsThisSecond > throttleThreshold) {
                if (InterlockedCompareExchange(
                        &g_TeProvider.ThrottleAction,
                        (LONG)TeThrottle_Sample,
                        (LONG)TeThrottle_None) == (LONG)TeThrottle_None) {
                    InterlockedExchange64(
                        &g_TeProvider.ThrottleStartTime,
                        currentTime.QuadPart
                    );
                    InterlockedIncrement64(&g_TeProvider.Stats.ThrottleActivations);
                }
            } else if (g_TeProvider.ThrottleAction != (LONG)TeThrottle_None) {
                LONG64 throttleStart = InterlockedCompareExchange64(
                    &g_TeProvider.ThrottleStartTime, 0, 0
                );
                UINT64 throttleDuration = (UINT64)(currentTime.QuadPart - throttleStart);
                if (throttleDuration > (UINT64)throttleRecoveryMs * 10000) {
                    InterlockedExchange(&g_TeProvider.ThrottleAction, (LONG)TeThrottle_None);
                }
            }
        }
    }

    InterlockedIncrement(&g_TeProvider.Stats.EventsThisSecond);
}

static NTSTATUS
TepWriteEventInternal(
    _In_ PTE_EVENT_HEADER Header,
    _In_ PVOID EventData,
    _In_ ULONG EventSize
    )
{
    NTSTATUS status;
    EVENT_DESCRIPTOR eventDescriptor;
    EVENT_DATA_DESCRIPTOR dataDescriptor;

    RtlZeroMemory(&eventDescriptor, sizeof(EVENT_DESCRIPTOR));
    eventDescriptor.Id = (USHORT)Header->EventId;
    eventDescriptor.Version = (UCHAR)Header->Version;
    eventDescriptor.Channel = 0;
    eventDescriptor.Level = (UCHAR)Header->Level;
    eventDescriptor.Opcode = 0;
    eventDescriptor.Task = 0;
    eventDescriptor.Keyword = Header->Keywords;

    EventDataDescCreate(&dataDescriptor, EventData, EventSize);

    status = EtwWrite(
        g_TeProvider.RegistrationHandle,
        &eventDescriptor,
        NULL,
        1,
        &dataDescriptor
    );

    if (NT_SUCCESS(status)) {
        InterlockedIncrement64(&g_TeProvider.Stats.EventsWritten);
        InterlockedAdd64(&g_TeProvider.Stats.BytesWritten, EventSize);
    } else {
        InterlockedIncrement64(&g_TeProvider.Stats.EtwWriteErrors);
    }

    return status;
}

static VOID
TepAcquireReference(
    VOID
    )
{
    InterlockedIncrement(&g_TeProvider.ReferenceCount);
    InterlockedIncrement(&g_TeProvider.ActiveOperations);
}

/**
 * @brief Try to acquire a reference for an event operation.
 *
 * Acquires reference FIRST, then checks state. If state is not Running,
 * releases the reference immediately. This prevents the race where
 * shutdown can drain references between state check and acquire.
 *
 * @return TRUE if reference acquired and state is Running.
 */
static BOOLEAN
TepTryAcquireReference(
    VOID
    )
{
    TepAcquireReference();

    if (g_TeProvider.State != (LONG)TeState_Running) {
        TepReleaseReference();
        return FALSE;
    }

    return TRUE;
}

static VOID
TepReleaseReference(
    VOID
    )
{
    InterlockedDecrement(&g_TeProvider.ActiveOperations);

    if (InterlockedDecrement(&g_TeProvider.ReferenceCount) == 0) {
        KeSetEvent(&g_TeProvider.ShutdownEvent, IO_NO_INCREMENT, FALSE);
    }
}

// ============================================================================
// TIMER AND WORK ITEM ROUTINES
// ============================================================================

static VOID
TepFlushDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (g_TeProvider.FlushWorkItem != NULL &&
        g_TeProvider.State == (LONG)TeState_Running &&
        InterlockedCompareExchange(&g_TeProvider.FlushPending, 1, 0) == 0) {

        IoQueueWorkItem(
            g_TeProvider.FlushWorkItem,
            TepFlushWorkItemRoutine,
            DelayedWorkQueue,
            NULL
        );
    }
}

static VOID
TepFlushWorkItemRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Context);

    TeFlush();
    InterlockedExchange(&g_TeProvider.FlushPending, 0);
    {
        LARGE_INTEGER flushTime;
        KeQuerySystemTime(&flushTime);
        InterlockedExchange64(&g_TeProvider.Stats.LastFlushTime, flushTime.QuadPart);
    }
    InterlockedIncrement64(&g_TeProvider.Stats.BatchFlushes);
}

static VOID
TepHeartbeatDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (g_TeProvider.State == (LONG)TeState_Running) {
        TeLogOperational(
            TeEvent_Heartbeat,
            TeLevel_Verbose,
            Component_Telemetry,
            L"Heartbeat",
            0
        );
    }
}

// ============================================================================
// EVENT LOGGING - PROCESS
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogProcessCreate(
    _In_ UINT32 ProcessId,
    _In_ UINT32 ParentProcessId,
    _In_ PCUNICODE_STRING ImagePath,
    _In_opt_ PCUNICODE_STRING CommandLine,
    _In_ UINT32 ThreatScore,
    _In_ UINT32 Flags
    )
{
    NTSTATUS status;
    PTE_PROCESS_EVENT event;

    if (!TeIsEventEnabled(TeLevel_Informational, TeKeyword_Process)) {
        return STATUS_SUCCESS;
    }

    if (TepShouldThrottle(TeLevel_Informational, TePriority_Normal)) {
        InterlockedIncrement64(&g_TeProvider.Stats.EventsThrottled);
        return STATUS_SUCCESS;
    }

    event = (PTE_PROCESS_EVENT)TepAllocateEvent();
    if (event == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!TepTryAcquireReference()) {
        TepFreeEvent(event);
        return STATUS_DEVICE_NOT_READY;
    }

    TepUpdateRateStatistics();

    RtlZeroMemory(event, sizeof(TE_PROCESS_EVENT));
    TepInitializeEventHeader(
        &event->Header,
        TeEvent_ProcessCreate,
        TeLevel_Informational,
        TeKeyword_Process,
        sizeof(TE_PROCESS_EVENT)
    );

    event->ParentProcessId = ParentProcessId;
    event->CreatingProcessId = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
    event->CreatingThreadId = (UINT32)(ULONG_PTR)PsGetCurrentThreadId();
    event->ThreatScore = ThreatScore;
    event->Flags = Flags;

    //
    // Override the header's auto-filled ProcessId with the new process ID.
    // The header auto-fills with PsGetCurrentProcessId() (the creator),
    // but for process-create events the target PID is more relevant.
    //
    event->Header.ProcessId = ProcessId;

    TepCopyUnicodeStringSafe(event->ImagePath, MAX_FILE_PATH_LENGTH, ImagePath);
    TepCopyUnicodeStringSafe(event->CommandLine, TE_MAX_COMMAND_LINE_CHARS, CommandLine);

    status = TepWriteEventInternal(&event->Header, event, sizeof(TE_PROCESS_EVENT));

    InterlockedIncrement64(&g_TeProvider.Stats.EventsGenerated);
    TepIncrementLevelStats(TeLevel_Informational);

    TepReleaseReference();
    TepFreeEvent(event);

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogProcessTerminate(
    _In_ UINT32 ProcessId,
    _In_ UINT32 ExitCode
    )
{
    NTSTATUS status;
    PTE_PROCESS_EVENT event;

    if (!TeIsEventEnabled(TeLevel_Informational, TeKeyword_Process)) {
        return STATUS_SUCCESS;
    }

    if (TepShouldThrottle(TeLevel_Informational, TePriority_Low)) {
        InterlockedIncrement64(&g_TeProvider.Stats.EventsThrottled);
        return STATUS_SUCCESS;
    }

    event = (PTE_PROCESS_EVENT)TepAllocateEvent();
    if (event == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!TepTryAcquireReference()) {
        TepFreeEvent(event);
        return STATUS_DEVICE_NOT_READY;
    }

    TepUpdateRateStatistics();

    RtlZeroMemory(event, sizeof(TE_PROCESS_EVENT));
    TepInitializeEventHeader(
        &event->Header,
        TeEvent_ProcessTerminate,
        TeLevel_Informational,
        TeKeyword_Process,
        sizeof(TE_PROCESS_EVENT)
    );

    event->Header.ProcessId = ProcessId;
    event->ExitCode = ExitCode;

    status = TepWriteEventInternal(&event->Header, event, sizeof(TE_PROCESS_EVENT));

    InterlockedIncrement64(&g_TeProvider.Stats.EventsGenerated);

    TepReleaseReference();
    TepFreeEvent(event);

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogProcessBlocked(
    _In_ UINT32 ProcessId,
    _In_ UINT32 ParentProcessId,
    _In_ PCUNICODE_STRING ImagePath,
    _In_ UINT32 ThreatScore,
    _In_opt_ PCWSTR Reason
    )
{
    NTSTATUS status;
    PTE_PROCESS_EVENT event;

    if (!TeIsEnabled()) {
        return STATUS_SUCCESS;
    }

    event = (PTE_PROCESS_EVENT)TepAllocateEvent();
    if (event == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!TepTryAcquireReference()) {
        TepFreeEvent(event);
        return STATUS_DEVICE_NOT_READY;
    }

    TepUpdateRateStatistics();

    RtlZeroMemory(event, sizeof(TE_PROCESS_EVENT));
    TepInitializeEventHeader(
        &event->Header,
        TeEvent_ProcessBlocked,
        TeLevel_Warning,
        TeKeyword_Process | TeKeyword_Threat,
        sizeof(TE_PROCESS_EVENT)
    );

    event->Header.ProcessId = ProcessId;
    event->Header.Flags |= TE_FLAG_BLOCKING;
    event->ParentProcessId = ParentProcessId;
    event->ThreatScore = ThreatScore;
    event->Flags = TE_PROCESS_FLAG_BLOCKED;

    TepCopyUnicodeStringSafe(event->ImagePath, MAX_FILE_PATH_LENGTH, ImagePath);

    //
    // Store block reason in dedicated field — not repurposed from CommandLine.
    //
    if (Reason != NULL) {
        TepCopyPcwstrSafe(event->BlockReason, ARRAYSIZE(event->BlockReason), Reason);
    }

    status = TepWriteEventInternal(&event->Header, event, sizeof(TE_PROCESS_EVENT));

    InterlockedIncrement64(&g_TeProvider.Stats.EventsGenerated);
    TepIncrementLevelStats(TeLevel_Warning);

    TepReleaseReference();
    TepFreeEvent(event);

    return status;
}

// ============================================================================
// EVENT LOGGING - THREAD
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogThreadCreate(
    _In_ UINT32 ProcessId,
    _In_ UINT32 ThreadId,
    _In_ UINT64 StartAddress
    )
{
    NTSTATUS status;
    PTE_THREAD_EVENT event;

    if (!TeIsEventEnabled(TeLevel_Verbose, TeKeyword_Thread)) {
        return STATUS_SUCCESS;
    }

    if (TepShouldThrottle(TeLevel_Verbose, TePriority_Low)) {
        InterlockedIncrement64(&g_TeProvider.Stats.EventsThrottled);
        return STATUS_SUCCESS;
    }

    event = (PTE_THREAD_EVENT)TepAllocateEvent();
    if (event == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!TepTryAcquireReference()) {
        TepFreeEvent(event);
        return STATUS_DEVICE_NOT_READY;
    }

    TepUpdateRateStatistics();

    RtlZeroMemory(event, sizeof(TE_THREAD_EVENT));
    TepInitializeEventHeader(
        &event->Header,
        TeEvent_ThreadCreate,
        TeLevel_Verbose,
        TeKeyword_Thread,
        sizeof(TE_THREAD_EVENT)
    );

    event->Header.ProcessId = ProcessId;
    event->Header.ThreadId = ThreadId;
    event->TargetProcessId = ProcessId;
    event->TargetThreadId = ThreadId;
    event->StartAddress = StartAddress;

    status = TepWriteEventInternal(&event->Header, event, sizeof(TE_THREAD_EVENT));

    InterlockedIncrement64(&g_TeProvider.Stats.EventsGenerated);

    TepReleaseReference();
    TepFreeEvent(event);

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogRemoteThread(
    _In_ UINT32 SourceProcessId,
    _In_ UINT32 TargetProcessId,
    _In_ UINT32 ThreadId,
    _In_ UINT64 StartAddress,
    _In_ UINT32 ThreatScore
    )
{
    NTSTATUS status;
    PTE_THREAD_EVENT event;

    if (!TeIsEventEnabled(TeLevel_Warning, TeKeyword_Thread | TeKeyword_Injection)) {
        return STATUS_SUCCESS;
    }

    event = (PTE_THREAD_EVENT)TepAllocateEvent();
    if (event == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!TepTryAcquireReference()) {
        TepFreeEvent(event);
        return STATUS_DEVICE_NOT_READY;
    }

    TepUpdateRateStatistics();

    RtlZeroMemory(event, sizeof(TE_THREAD_EVENT));
    TepInitializeEventHeader(
        &event->Header,
        TeEvent_RemoteThreadCreate,
        TeLevel_Warning,
        TeKeyword_Thread | TeKeyword_Injection,
        sizeof(TE_THREAD_EVENT)
    );

    event->Header.ProcessId = SourceProcessId;
    event->TargetProcessId = TargetProcessId;
    event->TargetThreadId = ThreadId;
    event->StartAddress = StartAddress;
    event->ThreatScore = ThreatScore;
    event->Flags = TE_THREAD_FLAG_REMOTE;

    status = TepWriteEventInternal(&event->Header, event, sizeof(TE_THREAD_EVENT));

    InterlockedIncrement64(&g_TeProvider.Stats.EventsGenerated);
    TepIncrementLevelStats(TeLevel_Warning);

    TepReleaseReference();
    TepFreeEvent(event);

    return status;
}

// ============================================================================
// EVENT LOGGING - FILE
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogFileEvent(
    _In_ TE_EVENT_ID EventId,
    _In_ UINT32 ProcessId,
    _In_ PCUNICODE_STRING FilePath,
    _In_ UINT32 Operation,
    _In_ UINT64 FileSize,
    _In_ UINT32 Verdict,
    _In_opt_ PCWSTR ThreatName,
    _In_ UINT32 ThreatScore
    )
{
    NTSTATUS status;
    PTE_FILE_EVENT event;

    if (!TE_IS_FILE_EVENT(EventId)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!TeIsEventEnabled(TeLevel_Informational, TeKeyword_File)) {
        return STATUS_SUCCESS;
    }

    if (TepShouldThrottle(TeLevel_Informational, TePriority_Normal)) {
        InterlockedIncrement64(&g_TeProvider.Stats.EventsThrottled);
        return STATUS_SUCCESS;
    }

    event = (PTE_FILE_EVENT)TepAllocateEvent();
    if (event == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!TepTryAcquireReference()) {
        TepFreeEvent(event);
        return STATUS_DEVICE_NOT_READY;
    }

    TepUpdateRateStatistics();

    RtlZeroMemory(event, sizeof(TE_FILE_EVENT));
    TepInitializeEventHeader(
        &event->Header,
        EventId,
        TeLevel_Informational,
        TeKeyword_File,
        sizeof(TE_FILE_EVENT)
    );

    event->Header.ProcessId = ProcessId;
    event->Operation = Operation;
    event->FileSize = FileSize;
    event->Verdict = Verdict;
    event->ThreatScore = ThreatScore;

    TepCopyUnicodeStringSafe(event->FilePath, MAX_FILE_PATH_LENGTH, FilePath);
    TepCopyPcwstrSafe(event->ThreatName, MAX_THREAT_NAME_LENGTH, ThreatName);

    status = TepWriteEventInternal(&event->Header, event, sizeof(TE_FILE_EVENT));

    InterlockedIncrement64(&g_TeProvider.Stats.EventsGenerated);

    TepReleaseReference();
    TepFreeEvent(event);

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogFileBlocked(
    _In_ UINT32 ProcessId,
    _In_ PCUNICODE_STRING FilePath,
    _In_ PCWSTR ThreatName,
    _In_ UINT32 ThreatScore,
    _In_ BOOLEAN Quarantined
    )
{
    TE_EVENT_ID eventId = Quarantined ? TeEvent_FileQuarantined : TeEvent_FileBlocked;

    return TeLogFileEvent(
        eventId,
        ProcessId,
        FilePath,
        0,
        0,
        1,
        ThreatName,
        ThreatScore
    );
}

// ============================================================================
// EVENT LOGGING - REGISTRY
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogRegistryEvent(
    _In_ TE_EVENT_ID EventId,
    _In_ UINT32 ProcessId,
    _In_ PCUNICODE_STRING KeyPath,
    _In_opt_ PCUNICODE_STRING ValueName,
    _In_ UINT32 ValueType,
    _In_reads_bytes_opt_(DataSize) PVOID ValueData,
    _In_ UINT32 DataSize,
    _In_ UINT32 ThreatScore
    )
{
    NTSTATUS status;
    PTE_REGISTRY_EVENT event;
    SIZE_T copyLen;

    if (!TE_IS_REGISTRY_EVENT(EventId)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!TeIsEventEnabled(TeLevel_Informational, TeKeyword_Registry)) {
        return STATUS_SUCCESS;
    }

    if (TepShouldThrottle(TeLevel_Informational, TePriority_Normal)) {
        InterlockedIncrement64(&g_TeProvider.Stats.EventsThrottled);
        return STATUS_SUCCESS;
    }

    event = (PTE_REGISTRY_EVENT)TepAllocateEvent();
    if (event == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!TepTryAcquireReference()) {
        TepFreeEvent(event);
        return STATUS_DEVICE_NOT_READY;
    }

    TepUpdateRateStatistics();

    RtlZeroMemory(event, sizeof(TE_REGISTRY_EVENT));
    TepInitializeEventHeader(
        &event->Header,
        EventId,
        TeLevel_Informational,
        TeKeyword_Registry,
        sizeof(TE_REGISTRY_EVENT)
    );

    event->Header.ProcessId = ProcessId;
    event->Operation = EventId;
    event->ValueType = ValueType;
    event->DataSize = DataSize;
    event->ThreatScore = ThreatScore;

    TepCopyUnicodeStringSafe(event->KeyPath, MAX_REGISTRY_KEY_LENGTH, KeyPath);
    TepCopyUnicodeStringSafe(event->ValueName, MAX_REGISTRY_VALUE_LENGTH, ValueName);

    if (ValueData != NULL && DataSize > 0) {
        copyLen = DataSize;
        if (copyLen > sizeof(event->ValueData)) {
            copyLen = sizeof(event->ValueData);
        }
        RtlCopyMemory(event->ValueData, ValueData, copyLen);
    }

    status = TepWriteEventInternal(&event->Header, event, sizeof(TE_REGISTRY_EVENT));

    InterlockedIncrement64(&g_TeProvider.Stats.EventsGenerated);

    TepReleaseReference();
    TepFreeEvent(event);

    return status;
}

// ============================================================================
// EVENT LOGGING - NETWORK
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogNetworkEvent(
    _In_ TE_EVENT_ID EventId,
    _In_ PTE_NETWORK_EVENT Event
    )
{
    NTSTATUS status;
    PTE_NETWORK_EVENT localEvent;

    if (Event == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!TE_IS_NETWORK_EVENT(EventId)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!TeIsEventEnabled(TeLevel_Informational, TeKeyword_Network)) {
        return STATUS_SUCCESS;
    }

    if (TepShouldThrottle(TeLevel_Informational, TePriority_Normal)) {
        InterlockedIncrement64(&g_TeProvider.Stats.EventsThrottled);
        return STATUS_SUCCESS;
    }

    //
    // Copy caller's event to a local buffer so we don't mutate
    // the caller's data when initializing the header.
    //
    localEvent = (PTE_NETWORK_EVENT)TepAllocateEvent();
    if (localEvent == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!TepTryAcquireReference()) {
        TepFreeEvent(localEvent);
        return STATUS_DEVICE_NOT_READY;
    }

    TepUpdateRateStatistics();

    //
    // Copy caller's event safely — guard against partially valid buffers.
    //
    __try {
        RtlCopyMemory(localEvent, Event, sizeof(TE_NETWORK_EVENT));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        TepReleaseReference();
        TepFreeEvent(localEvent);
        return GetExceptionCode();
    }

    TepInitializeEventHeader(
        &localEvent->Header,
        EventId,
        TeLevel_Informational,
        TeKeyword_Network,
        sizeof(TE_NETWORK_EVENT)
    );

    status = TepWriteEventInternal(&localEvent->Header, localEvent, sizeof(TE_NETWORK_EVENT));

    InterlockedIncrement64(&g_TeProvider.Stats.EventsGenerated);

    TepReleaseReference();
    TepFreeEvent(localEvent);

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogDnsQuery(
    _In_ UINT32 ProcessId,
    _In_ PCWSTR QueryName,
    _In_ UINT16 QueryType,
    _In_ BOOLEAN Blocked,
    _In_ UINT32 ThreatScore
    )
{
    NTSTATUS status;
    PTE_NETWORK_EVENT event;

    if (!TeIsEventEnabled(TeLevel_Informational, TeKeyword_Network)) {
        return STATUS_SUCCESS;
    }

    event = (PTE_NETWORK_EVENT)TepAllocateEvent();
    if (event == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!TepTryAcquireReference()) {
        TepFreeEvent(event);
        return STATUS_DEVICE_NOT_READY;
    }

    TepUpdateRateStatistics();

    RtlZeroMemory(event, sizeof(TE_NETWORK_EVENT));
    TepInitializeEventHeader(
        &event->Header,
        Blocked ? TeEvent_DnsBlocked : TeEvent_DnsQuery,
        Blocked ? TeLevel_Warning : TeLevel_Informational,
        TeKeyword_Network,
        sizeof(TE_NETWORK_EVENT)
    );

    event->Header.ProcessId = ProcessId;
    event->ThreatScore = ThreatScore;
    event->Flags = Blocked ? TE_NET_FLAG_BLOCKED : 0;
    event->DnsQueryType = QueryType;

    TepCopyPcwstrSafe(event->RemoteHostname, ARRAYSIZE(event->RemoteHostname), QueryName);

    status = TepWriteEventInternal(&event->Header, event, sizeof(TE_NETWORK_EVENT));

    InterlockedIncrement64(&g_TeProvider.Stats.EventsGenerated);

    TepReleaseReference();
    TepFreeEvent(event);

    return status;
}

// ============================================================================
// EVENT LOGGING - MEMORY
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogMemoryEvent(
    _In_ TE_EVENT_ID EventId,
    _In_ UINT32 SourceProcessId,
    _In_ UINT32 TargetProcessId,
    _In_ UINT64 BaseAddress,
    _In_ UINT64 RegionSize,
    _In_ UINT32 Protection,
    _In_ UINT32 ThreatScore,
    _In_ UINT32 Flags
    )
{
    NTSTATUS status;
    PTE_MEMORY_EVENT event;

    if (!TE_IS_MEMORY_EVENT(EventId)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!TeIsEventEnabled(TeLevel_Informational, TeKeyword_Memory)) {
        return STATUS_SUCCESS;
    }

    if (TepShouldThrottle(TeLevel_Informational, TePriority_Normal)) {
        InterlockedIncrement64(&g_TeProvider.Stats.EventsThrottled);
        return STATUS_SUCCESS;
    }

    event = (PTE_MEMORY_EVENT)TepAllocateEvent();
    if (event == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!TepTryAcquireReference()) {
        TepFreeEvent(event);
        return STATUS_DEVICE_NOT_READY;
    }

    TepUpdateRateStatistics();

    RtlZeroMemory(event, sizeof(TE_MEMORY_EVENT));
    TepInitializeEventHeader(
        &event->Header,
        EventId,
        TeLevel_Informational,
        TeKeyword_Memory,
        sizeof(TE_MEMORY_EVENT)
    );

    event->Header.ProcessId = SourceProcessId;
    event->TargetProcessId = TargetProcessId;
    event->BaseAddress = BaseAddress;
    event->RegionSize = RegionSize;
    event->NewProtection = Protection;
    event->ThreatScore = ThreatScore;
    event->Flags = Flags;

    if (SourceProcessId != TargetProcessId) {
        event->Flags |= TE_MEM_FLAG_CROSS_PROCESS;
    }

    status = TepWriteEventInternal(&event->Header, event, sizeof(TE_MEMORY_EVENT));

    InterlockedIncrement64(&g_TeProvider.Stats.EventsGenerated);

    TepReleaseReference();
    TepFreeEvent(event);

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogInjection(
    _In_ UINT32 SourceProcessId,
    _In_ UINT32 TargetProcessId,
    _In_ UINT32 InjectionMethod,
    _In_ UINT64 TargetAddress,
    _In_ UINT64 Size,
    _In_ UINT32 ThreatScore
    )
{
    NTSTATUS status;
    PTE_MEMORY_EVENT event;

    if (!TeIsEnabled()) {
        return STATUS_SUCCESS;
    }

    event = (PTE_MEMORY_EVENT)TepAllocateEvent();
    if (event == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!TepTryAcquireReference()) {
        TepFreeEvent(event);
        return STATUS_DEVICE_NOT_READY;
    }

    TepUpdateRateStatistics();

    RtlZeroMemory(event, sizeof(TE_MEMORY_EVENT));
    TepInitializeEventHeader(
        &event->Header,
        TeEvent_InjectionDetected,
        TeLevel_Warning,
        TeKeyword_Memory | TeKeyword_Injection | TeKeyword_Threat,
        sizeof(TE_MEMORY_EVENT)
    );

    event->Header.ProcessId = SourceProcessId;
    event->Header.Flags |= TE_FLAG_HIGH_CONFIDENCE;
    event->TargetProcessId = TargetProcessId;
    event->BaseAddress = TargetAddress;
    event->RegionSize = Size;
    event->InjectionMethod = InjectionMethod;
    event->ThreatScore = ThreatScore;
    event->Flags = TE_MEM_FLAG_INJECTION | TE_MEM_FLAG_CROSS_PROCESS;

    status = TepWriteEventInternal(&event->Header, event, sizeof(TE_MEMORY_EVENT));

    InterlockedIncrement64(&g_TeProvider.Stats.EventsGenerated);
    TepIncrementLevelStats(TeLevel_Warning);

    TepReleaseReference();
    TepFreeEvent(event);

    return status;
}

// ============================================================================
// EVENT LOGGING - DETECTION
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogThreatDetection(
    _In_ UINT32 ProcessId,
    _In_ PCWSTR ThreatName,
    _In_ UINT32 ThreatScore,
    _In_ THREAT_SEVERITY Severity,
    _In_ UINT32 MitreTechnique,
    _In_opt_ PCWSTR Description,
    _In_ UINT32 ResponseAction
    )
{
    NTSTATUS status;
    PTE_DETECTION_EVENT event;
    TE_EVENT_LEVEL level;

    switch (Severity) {
        case ThreatSeverity_Critical: level = TeLevel_Critical; break;
        case ThreatSeverity_High:     level = TeLevel_Error;    break;
        case ThreatSeverity_Medium:   level = TeLevel_Warning;  break;
        default:                      level = TeLevel_Informational; break;
    }

    if (!TeIsEventEnabled(level, TeKeyword_Threat | TeKeyword_Detection)) {
        return STATUS_SUCCESS;
    }

    event = (PTE_DETECTION_EVENT)TepAllocateEvent();
    if (event == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!TepTryAcquireReference()) {
        TepFreeEvent(event);
        return STATUS_DEVICE_NOT_READY;
    }

    TepUpdateRateStatistics();

    RtlZeroMemory(event, sizeof(TE_DETECTION_EVENT));
    TepInitializeEventHeader(
        &event->Header,
        TeEvent_ThreatDetected,
        level,
        TeKeyword_Threat | TeKeyword_Detection,
        sizeof(TE_DETECTION_EVENT)
    );

    event->Header.ProcessId = ProcessId;
    event->Header.Flags |= TE_FLAG_HIGH_CONFIDENCE;
    event->ThreatScore = ThreatScore;
    event->Severity = Severity;
    event->MitreTechnique = MitreTechnique;
    event->ResponseAction = ResponseAction;

    TepCopyPcwstrSafe(event->ThreatName, MAX_THREAT_NAME_LENGTH, ThreatName);
    TepCopyPcwstrSafe(event->Description, ARRAYSIZE(event->Description), Description);

    status = TepWriteEventInternal(&event->Header, event, sizeof(TE_DETECTION_EVENT));

    InterlockedIncrement64(&g_TeProvider.Stats.EventsGenerated);
    TepIncrementLevelStats(level);

    TepReleaseReference();
    TepFreeEvent(event);

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogBehaviorAlert(
    _In_ UINT32 ProcessId,
    _In_ BEHAVIOR_EVENT_TYPE BehaviorType,
    _In_ BEHAVIOR_EVENT_CATEGORY Category,
    _In_ UINT32 ThreatScore,
    _In_ UINT64 ChainId,
    _In_opt_ PCWSTR Description
    )
{
    NTSTATUS status;
    PTE_DETECTION_EVENT event;

    if (!TeIsEventEnabled(TeLevel_Warning, TeKeyword_Behavioral | TeKeyword_Detection)) {
        return STATUS_SUCCESS;
    }

    event = (PTE_DETECTION_EVENT)TepAllocateEvent();
    if (event == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!TepTryAcquireReference()) {
        TepFreeEvent(event);
        return STATUS_DEVICE_NOT_READY;
    }

    TepUpdateRateStatistics();

    RtlZeroMemory(event, sizeof(TE_DETECTION_EVENT));
    TepInitializeEventHeader(
        &event->Header,
        TeEvent_BehaviorAlert,
        TeLevel_Warning,
        TeKeyword_Behavioral | TeKeyword_Detection,
        sizeof(TE_DETECTION_EVENT)
    );

    event->Header.ProcessId = ProcessId;
    event->DetectionType = BehaviorType;
    event->DetectionSource = Category;
    event->ThreatScore = ThreatScore;
    event->ChainId = ChainId;

    if (ChainId != 0) {
        event->Header.Flags |= TE_FLAG_CHAIN_MEMBER;
    }

    TepCopyPcwstrSafe(event->Description, ARRAYSIZE(event->Description), Description);

    status = TepWriteEventInternal(&event->Header, event, sizeof(TE_DETECTION_EVENT));

    InterlockedIncrement64(&g_TeProvider.Stats.EventsGenerated);
    TepIncrementLevelStats(TeLevel_Warning);

    TepReleaseReference();
    TepFreeEvent(event);

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogAttackChain(
    _In_ UINT64 ChainId,
    _In_ ATTACK_CHAIN_STAGE Stage,
    _In_ UINT32 ProcessId,
    _In_ BEHAVIOR_EVENT_TYPE EventType,
    _In_ UINT32 ThreatScore,
    _In_ UINT32 MitreTechnique
    )
{
    NTSTATUS status;
    PTE_DETECTION_EVENT event;
    TE_EVENT_ID eventId;

    if (!TeIsEventEnabled(TeLevel_Warning, TeKeyword_Attack | TeKeyword_Detection)) {
        return STATUS_SUCCESS;
    }

    if (Stage == AttackStage_Reconnaissance) {
        eventId = TeEvent_AttackChainStart;
    } else if (Stage == AttackStage_Actions) {
        eventId = TeEvent_AttackChainComplete;
    } else {
        eventId = TeEvent_AttackChainUpdate;
    }

    event = (PTE_DETECTION_EVENT)TepAllocateEvent();
    if (event == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!TepTryAcquireReference()) {
        TepFreeEvent(event);
        return STATUS_DEVICE_NOT_READY;
    }

    TepUpdateRateStatistics();

    RtlZeroMemory(event, sizeof(TE_DETECTION_EVENT));
    TepInitializeEventHeader(
        &event->Header,
        eventId,
        TeLevel_Warning,
        TeKeyword_Attack | TeKeyword_Detection,
        sizeof(TE_DETECTION_EVENT)
    );

    event->Header.ProcessId = ProcessId;
    event->Header.Flags |= TE_FLAG_CHAIN_MEMBER;
    event->Header.CorrelationId = ChainId;
    event->DetectionType = EventType;
    event->ThreatScore = ThreatScore;
    event->ChainId = ChainId;
    event->MitreTechnique = MitreTechnique;

    status = TepWriteEventInternal(&event->Header, event, sizeof(TE_DETECTION_EVENT));

    InterlockedIncrement64(&g_TeProvider.Stats.EventsGenerated);

    TepReleaseReference();
    TepFreeEvent(event);

    return status;
}

// ============================================================================
// EVENT LOGGING - SECURITY
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogTamperAttempt(
    _In_ TAMPER_ATTEMPT_TYPE TamperType,
    _In_ UINT32 ProcessId,
    _In_ DRIVER_COMPONENT_ID TargetComponent,
    _In_ UINT64 TargetAddress,
    _In_ BOOLEAN Blocked,
    _In_opt_ PCWSTR Description
    )
{
    NTSTATUS status;
    PTE_SECURITY_EVENT event;

    if (!TeIsEnabled()) {
        return STATUS_SUCCESS;
    }

    event = (PTE_SECURITY_EVENT)TepAllocateEvent();
    if (event == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!TepTryAcquireReference()) {
        TepFreeEvent(event);
        return STATUS_DEVICE_NOT_READY;
    }

    TepUpdateRateStatistics();

    RtlZeroMemory(event, sizeof(TE_SECURITY_EVENT));
    TepInitializeEventHeader(
        &event->Header,
        TeEvent_TamperAttempt,
        TeLevel_Critical,
        TeKeyword_Security | TeKeyword_SelfProtect,
        sizeof(TE_SECURITY_EVENT)
    );

    event->Header.ProcessId = ProcessId;
    event->Header.Flags |= TE_FLAG_URGENT | TE_FLAG_HIGH_CONFIDENCE;
    event->AlertType = TamperType;
    event->TargetComponent = TargetComponent;
    event->TargetAddress = TargetAddress;
    event->ThreatScore = 1000;
    event->ResponseAction = Blocked ? 1 : 0;

    TepCopyPcwstrSafe(event->Description, ARRAYSIZE(event->Description), Description);

    status = TepWriteEventInternal(&event->Header, event, sizeof(TE_SECURITY_EVENT));

    InterlockedIncrement64(&g_TeProvider.Stats.EventsGenerated);
    TepIncrementLevelStats(TeLevel_Critical);

    TepReleaseReference();
    TepFreeEvent(event);

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogEvasionAttempt(
    _In_ EVASION_TECHNIQUE EvasionType,
    _In_ UINT32 ProcessId,
    _In_opt_ PCWSTR TargetModule,
    _In_opt_ PCSTR TargetFunction,
    _In_ UINT32 ThreatScore
    )
{
    NTSTATUS status;
    PTE_SECURITY_EVENT event;

    if (!TeIsEventEnabled(TeLevel_Warning, TeKeyword_Security | TeKeyword_Evasion)) {
        return STATUS_SUCCESS;
    }

    event = (PTE_SECURITY_EVENT)TepAllocateEvent();
    if (event == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!TepTryAcquireReference()) {
        TepFreeEvent(event);
        return STATUS_DEVICE_NOT_READY;
    }

    TepUpdateRateStatistics();

    RtlZeroMemory(event, sizeof(TE_SECURITY_EVENT));
    TepInitializeEventHeader(
        &event->Header,
        TeEvent_EvasionAttempt,
        TeLevel_Warning,
        TeKeyword_Security | TeKeyword_Evasion,
        sizeof(TE_SECURITY_EVENT)
    );

    event->Header.ProcessId = ProcessId;
    event->AlertType = EvasionType;
    event->ThreatScore = ThreatScore;

    //
    // Include target module and function in the description.
    // These are critical forensic fields for incident response.
    //
    if (TargetModule != NULL && TargetFunction != NULL) {
        RtlStringCchPrintfW(
            event->Description,
            ARRAYSIZE(event->Description),
            L"Evasion technique %u: %ws!%S",
            (UINT32)EvasionType,
            TargetModule,
            TargetFunction
        );
    } else if (TargetModule != NULL) {
        RtlStringCchPrintfW(
            event->Description,
            ARRAYSIZE(event->Description),
            L"Evasion technique %u targeting %ws",
            (UINT32)EvasionType,
            TargetModule
        );
    } else {
        RtlStringCchPrintfW(
            event->Description,
            ARRAYSIZE(event->Description),
            L"Evasion technique %u detected",
            (UINT32)EvasionType
        );
    }

    //
    // Store target module path in AttackerProcess field for structured access
    //
    TepCopyPcwstrSafe(event->AttackerProcess, MAX_FILE_PATH_LENGTH, TargetModule);

    status = TepWriteEventInternal(&event->Header, event, sizeof(TE_SECURITY_EVENT));

    InterlockedIncrement64(&g_TeProvider.Stats.EventsGenerated);
    TepIncrementLevelStats(TeLevel_Warning);

    TepReleaseReference();
    TepFreeEvent(event);

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogCredentialAccess(
    _In_ UINT32 ProcessId,
    _In_ UINT32 TargetProcessId,
    _In_ CREDENTIAL_ACCESS_TYPE AccessType,
    _In_ UINT64 AccessMask,
    _In_ UINT32 ThreatScore,
    _In_ BOOLEAN Blocked
    )
{
    NTSTATUS status;
    PTE_SECURITY_EVENT event;

    if (!TeIsEventEnabled(TeLevel_Warning, TeKeyword_Security | TeKeyword_Credential)) {
        return STATUS_SUCCESS;
    }

    event = (PTE_SECURITY_EVENT)TepAllocateEvent();
    if (event == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!TepTryAcquireReference()) {
        TepFreeEvent(event);
        return STATUS_DEVICE_NOT_READY;
    }

    TepUpdateRateStatistics();

    RtlZeroMemory(event, sizeof(TE_SECURITY_EVENT));
    TepInitializeEventHeader(
        &event->Header,
        TeEvent_CredentialAccess,
        TeLevel_Warning,
        TeKeyword_Security | TeKeyword_Credential,
        sizeof(TE_SECURITY_EVENT)
    );

    event->Header.ProcessId = ProcessId;
    event->Header.Flags |= TE_FLAG_HIGH_CONFIDENCE;
    event->AlertType = AccessType;
    event->TargetProcessId = TargetProcessId;
    event->OriginalValue = AccessMask;
    event->ThreatScore = ThreatScore;
    event->ResponseAction = Blocked ? 1 : 0;

    RtlStringCchPrintfW(
        event->Description,
        ARRAYSIZE(event->Description),
        L"Credential access type %u to process %u, mask 0x%llX",
        (UINT32)AccessType,
        TargetProcessId,
        AccessMask
    );

    status = TepWriteEventInternal(&event->Header, event, sizeof(TE_SECURITY_EVENT));

    InterlockedIncrement64(&g_TeProvider.Stats.EventsGenerated);
    TepIncrementLevelStats(TeLevel_Warning);

    TepReleaseReference();
    TepFreeEvent(event);

    return status;
}

// ============================================================================
// EVENT LOGGING - OPERATIONAL
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogOperational(
    _In_ TE_EVENT_ID EventId,
    _In_ TE_EVENT_LEVEL Level,
    _In_ DRIVER_COMPONENT_ID ComponentId,
    _In_ PCWSTR Message,
    _In_ UINT32 ErrorCode
    )
{
    NTSTATUS status;
    PTE_OPERATIONAL_EVENT event;

    if (!TeIsEventEnabled(Level, TeKeyword_Diagnostic)) {
        return STATUS_SUCCESS;
    }

    if (TepShouldThrottle(Level, TePriority_Low)) {
        InterlockedIncrement64(&g_TeProvider.Stats.EventsThrottled);
        return STATUS_SUCCESS;
    }

    event = (PTE_OPERATIONAL_EVENT)TepAllocateEvent();
    if (event == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!TepTryAcquireReference()) {
        TepFreeEvent(event);
        return STATUS_DEVICE_NOT_READY;
    }

    TepUpdateRateStatistics();

    RtlZeroMemory(event, sizeof(TE_OPERATIONAL_EVENT));
    TepInitializeEventHeader(
        &event->Header,
        EventId,
        Level,
        TeKeyword_Diagnostic,
        sizeof(TE_OPERATIONAL_EVENT)
    );

    event->ComponentId = ComponentId;
    event->ErrorCode = ErrorCode;

    TepCopyPcwstrSafe(event->Message, MAX_ERROR_MESSAGE_LENGTH, Message);

    status = TepWriteEventInternal(&event->Header, event, sizeof(TE_OPERATIONAL_EVENT));

    InterlockedIncrement64(&g_TeProvider.Stats.EventsGenerated);
    TepIncrementLevelStats(Level);

    TepReleaseReference();
    TepFreeEvent(event);

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogError(
    _In_ DRIVER_COMPONENT_ID ComponentId,
    _In_ NTSTATUS ErrorCode,
    _In_ TELEMETRY_ERROR_SEVERITY Severity,
    _In_ PCSTR FileName,
    _In_ PCSTR FunctionName,
    _In_ UINT32 LineNumber,
    _In_ PCWSTR Message
    )
{
    NTSTATUS status;
    PTE_OPERATIONAL_EVENT event;
    TE_EVENT_LEVEL level;

    switch (Severity) {
        case ErrorSeverity_Fatal:
        case ErrorSeverity_Critical:
            level = TeLevel_Critical;
            break;
        case ErrorSeverity_Error:
            level = TeLevel_Error;
            break;
        case ErrorSeverity_Warning:
            level = TeLevel_Warning;
            break;
        default:
            level = TeLevel_Informational;
            break;
    }

    if (!TeIsEventEnabled(level, TeKeyword_Diagnostic)) {
        return STATUS_SUCCESS;
    }

    event = (PTE_OPERATIONAL_EVENT)TepAllocateEvent();
    if (event == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!TepTryAcquireReference()) {
        TepFreeEvent(event);
        return STATUS_DEVICE_NOT_READY;
    }

    TepUpdateRateStatistics();

    RtlZeroMemory(event, sizeof(TE_OPERATIONAL_EVENT));
    TepInitializeEventHeader(
        &event->Header,
        TeEvent_Error,
        level,
        TeKeyword_Diagnostic,
        sizeof(TE_OPERATIONAL_EVENT)
    );

    event->ComponentId = ComponentId;
    event->ErrorSeverity = Severity;
    event->ErrorCode = ErrorCode;
    event->LineNumber = LineNumber;

    TepCopyAnsiStringSafe(event->FileName, sizeof(event->FileName), FileName);
    TepCopyAnsiStringSafe(event->FunctionName, sizeof(event->FunctionName), FunctionName);
    TepCopyPcwstrSafe(event->Message, MAX_ERROR_MESSAGE_LENGTH, Message);

    status = TepWriteEventInternal(&event->Header, event, sizeof(TE_OPERATIONAL_EVENT));

    InterlockedIncrement64(&g_TeProvider.Stats.EventsGenerated);
    TepIncrementLevelStats(level);

    TepReleaseReference();
    TepFreeEvent(event);

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogComponentHealth(
    _In_ DRIVER_COMPONENT_ID ComponentId,
    _In_ COMPONENT_HEALTH_STATUS NewStatus,
    _In_ COMPONENT_HEALTH_STATUS OldStatus,
    _In_ UINT32 ErrorCode,
    _In_opt_ PCWSTR Message
    )
{
    NTSTATUS status;
    PTE_OPERATIONAL_EVENT event;
    TE_EVENT_LEVEL level;

    switch (NewStatus) {
        case Health_Failed:   level = TeLevel_Critical; break;
        case Health_Degraded: level = TeLevel_Warning;  break;
        default:              level = TeLevel_Informational; break;
    }

    if (!TeIsEventEnabled(level, TeKeyword_Health)) {
        return STATUS_SUCCESS;
    }

    event = (PTE_OPERATIONAL_EVENT)TepAllocateEvent();
    if (event == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!TepTryAcquireReference()) {
        TepFreeEvent(event);
        return STATUS_DEVICE_NOT_READY;
    }

    TepUpdateRateStatistics();

    RtlZeroMemory(event, sizeof(TE_OPERATIONAL_EVENT));
    TepInitializeEventHeader(
        &event->Header,
        TeEvent_ComponentHealth,
        level,
        TeKeyword_Health,
        sizeof(TE_OPERATIONAL_EVENT)
    );

    event->ComponentId = ComponentId;
    event->HealthStatus = NewStatus;
    event->ErrorCode = ErrorCode;
    event->ContextValue1 = OldStatus;
    event->ContextValue2 = NewStatus;

    TepCopyPcwstrSafe(event->Message, MAX_ERROR_MESSAGE_LENGTH, Message);

    status = TepWriteEventInternal(&event->Header, event, sizeof(TE_OPERATIONAL_EVENT));

    InterlockedIncrement64(&g_TeProvider.Stats.EventsGenerated);
    TepIncrementLevelStats(level);

    TepReleaseReference();
    TepFreeEvent(event);

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogPerformanceStats(
    _In_ PTELEMETRY_PERFORMANCE Stats
    )
{
    NTSTATUS status;
    PTE_OPERATIONAL_EVENT event;

    if (Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!TeIsEventEnabled(TeLevel_Informational, TeKeyword_Performance)) {
        return STATUS_SUCCESS;
    }

    event = (PTE_OPERATIONAL_EVENT)TepAllocateEvent();
    if (event == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!TepTryAcquireReference()) {
        TepFreeEvent(event);
        return STATUS_DEVICE_NOT_READY;
    }

    TepUpdateRateStatistics();

    RtlZeroMemory(event, sizeof(TE_OPERATIONAL_EVENT));
    TepInitializeEventHeader(
        &event->Header,
        TeEvent_PerformanceStats,
        TeLevel_Informational,
        TeKeyword_Performance,
        sizeof(TE_OPERATIONAL_EVENT)
    );

    event->ComponentId = Component_Telemetry;

    //
    // Encode key performance metrics into the context values for structured access.
    // ContextValue1: filesystem latency (avg microseconds)
    // ContextValue2: process monitor latency (avg microseconds)
    // ContextValue3: total events processed
    //
    event->ContextValue1 = Stats->FileSystem.AverageLatencyUs;
    event->ContextValue2 = Stats->Process.AverageLatencyUs;
    event->ContextValue3 = Stats->Process.TotalEventsProcessed;

    RtlStringCchPrintfW(
        event->Message,
        MAX_ERROR_MESSAGE_LENGTH,
        L"PerfStats: FS_lat=%lluus Proc_lat=%lluus Events=%llu",
        Stats->FileSystem.AverageLatencyUs,
        Stats->Process.AverageLatencyUs,
        Stats->Process.TotalEventsProcessed
    );

    status = TepWriteEventInternal(&event->Header, event, sizeof(TE_OPERATIONAL_EVENT));

    InterlockedIncrement64(&g_TeProvider.Stats.EventsGenerated);
    TepIncrementLevelStats(TeLevel_Informational);

    TepReleaseReference();
    TepFreeEvent(event);

    return status;
}

// ============================================================================
// STATISTICS
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeGetStatistics(
    _Out_ PTE_STATISTICS Stats
    )
{
    KIRQL oldIrql;

    if (Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_TeProvider.State == (LONG)TeState_Uninitialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Snapshot under shared lock for consistent read across all fields.
    // Individual fields are still updated via interlocked ops, so this
    // provides a point-in-time snapshot rather than per-field atomicity.
    //
    ShadowStrikeAcquireRWSpinLockShared(&g_TeProvider.StatsLock, &oldIrql);
    RtlCopyMemory(Stats, &g_TeProvider.Stats, sizeof(TE_STATISTICS));
    ShadowStrikeReleaseRWSpinLockShared(&g_TeProvider.StatsLock, oldIrql);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TeResetStatistics(
    VOID
    )
{
    ULONG i;
    LARGE_INTEGER now;

    if (g_TeProvider.State == (LONG)TeState_Uninitialized) {
        return;
    }

    // Event counters
    InterlockedExchange64(&g_TeProvider.Stats.EventsGenerated, 0);
    InterlockedExchange64(&g_TeProvider.Stats.EventsWritten, 0);
    InterlockedExchange64(&g_TeProvider.Stats.EventsDropped, 0);
    InterlockedExchange64(&g_TeProvider.Stats.EventsThrottled, 0);
    InterlockedExchange64(&g_TeProvider.Stats.EventsSampled, 0);
    InterlockedExchange64(&g_TeProvider.Stats.EventsFailed, 0);

    // Bytes counters
    InterlockedExchange64(&g_TeProvider.Stats.BytesGenerated, 0);
    InterlockedExchange64(&g_TeProvider.Stats.BytesWritten, 0);

    // Rate tracking
    InterlockedExchange(&g_TeProvider.Stats.EventsThisSecond, 0);
    InterlockedExchange(&g_TeProvider.Stats.PeakEventsPerSecond, 0);

    // Batch statistics
    InterlockedExchange64(&g_TeProvider.Stats.BatchesWritten, 0);
    InterlockedExchange64(&g_TeProvider.Stats.BatchFlushes, 0);
    InterlockedExchange(&g_TeProvider.Stats.CurrentBatchSize, 0);
    InterlockedExchange(&g_TeProvider.Stats.MaxBatchSize, 0);

    // Throttling statistics
    InterlockedExchange64(&g_TeProvider.Stats.ThrottleActivations, 0);
    InterlockedExchange(&g_TeProvider.Stats.ThrottleCurrentLevel, 0);
    InterlockedExchange64(&g_TeProvider.Stats.LastThrottleTime, 0);

    // Error tracking
    InterlockedExchange64(&g_TeProvider.Stats.EtwWriteErrors, 0);
    InterlockedExchange64(&g_TeProvider.Stats.AllocationFailures, 0);
    InterlockedExchange64(&g_TeProvider.Stats.SequenceGaps, 0);

    // Timing
    KeQuerySystemTime(&now);
    InterlockedExchange64(&g_TeProvider.Stats.StartTime, now.QuadPart);
    InterlockedExchange64(&g_TeProvider.Stats.LastEventTime, 0);
    InterlockedExchange64(&g_TeProvider.Stats.LastFlushTime, 0);
    InterlockedExchange64(&g_TeProvider.Stats.CurrentSecondStart, now.QuadPart);

    // Per-level counters
    for (i = 0; i < TE_MAX_EVENT_LEVELS; i++) {
        InterlockedExchange64(&g_TeProvider.Stats.EventsByLevel[i], 0);
    }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TeFlush(
    VOID
    )
{
    LARGE_INTEGER flushTime;

    //
    // Events are written synchronously via TepWriteEventInternal.
    // This function updates the last flush timestamp for monitoring.
    //
    KeQuerySystemTime(&flushTime);
    InterlockedExchange64(&g_TeProvider.Stats.LastFlushTime, flushTime.QuadPart);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
UINT64
TeGenerateCorrelationId(
    VOID
    )
{
    LARGE_INTEGER perfCounter;
    LARGE_INTEGER timestamp;
    UINT64 counter;

    KeQuerySystemTime(&timestamp);
    perfCounter = KeQueryPerformanceCounter(NULL);
    counter = (UINT64)InterlockedIncrement64(&g_CorrelationCounter);

    return (TE_CORRELATION_SEED ^ timestamp.QuadPart ^ perfCounter.QuadPart) + counter;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
UINT64
TeGetSequenceNumber(
    VOID
    )
{
    return (UINT64)InterlockedCompareExchange64(&g_TeProvider.SequenceNumber, 0, 0);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
TE_STATE
TeGetState(
    VOID
    )
{
    return (TE_STATE)g_TeProvider.State;
}
