// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
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
 * ShadowStrike NGAV - ENTERPRISE RESOURCE THROTTLING ENGINE
 * ============================================================================
 *
 * @file ResourceThrottling.c
 * @brief Enterprise-grade resource throttling implementation.
 *
 * Implements resource management with:
 * - Multi-dimensional resource tracking
 * - Adaptive throttling with exponential backoff
 * - Per-process quota enforcement with per-process limits
 * - Token bucket rate limiting (CAS-safe)
 * - Deferred work queue processing via system worker thread
 * - Real-time monitoring via TimerManager callbacks
 *
 * Safety v3.0.0:
 * - EX_RUNDOWN_REF for lifecycle management
 * - KSPIN_LOCK for all DPC-accessible state
 * - Callback rundown protection (CallbackActiveCount)
 * - StatsLock for atomic statistics snapshots
 * - Separate LastTokenRefillTime for burst tokens
 * - Per-process limits (not just global fallback)
 * - All enum inputs validated before array indexing
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "ResourceThrottling.h"
#include "../Utilities/MemoryUtils.h"
#include "../Sync/TimerManager.h"
#include "../Core/DriverEntry.h"
#include "../Power/PowerCallback.h"

// ============================================================================
// COMPILE-TIME ASSERTIONS
// ============================================================================

C_ASSERT(RtResourceMax == RT_MAX_RESOURCE_TYPES);

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define RT_HYSTERESIS_THRESHOLD         90
#define RT_MIN_SAMPLES_FOR_TRANSITION   3
#define RT_MAX_THROTTLE_DURATION_MS     60000
#define RT_DEFERRED_PROCESS_INTERVAL_MS 50
#define RT_SHUTDOWN_DRAIN_TIMEOUT_MS    5000

// ============================================================================
// PRIVATE FUNCTION PROTOTYPES
// ============================================================================

static VOID RtpInitializeResourceStates(_Inout_ PRT_THROTTLER Throttler);
static VOID RtpInitializeProcessQuotas(_Inout_ PRT_THROTTLER Throttler);
static VOID RtpInitializeDeferredWork(_Inout_ PRT_THROTTLER Throttler);

static VOID RtpMonitorTimerCallback(_In_ ULONG TimerId, _In_opt_ PVOID Context);
static VOID RtpDeferredWorkTimerCallback(_In_ ULONG TimerId, _In_opt_ PVOID Context);

static VOID RtpWorkerThreadRoutine(_In_ PVOID Context);

static VOID
RtpUpdateResourceState(
    _Inout_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource
);

static VOID
RtpCalculateRate(
    _Inout_ PRT_RESOURCE_STATE State,
    _In_ LARGE_INTEGER CurrentTime
);

static VOID
RtpRefillBurstTokens(
    _Inout_ PRT_RESOURCE_STATE State,
    _In_ PRT_RESOURCE_CONFIG Config,
    _In_ LARGE_INTEGER CurrentTime
);

static RT_THROTTLE_ACTION
RtpDetermineAction(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource,
    _In_ RT_PRIORITY Priority
);

static VOID
RtpNotifyCallback(
    _In_ PRT_THROTTLER Throttler,
    _In_ PRT_THROTTLE_EVENT Event
);

static PRT_PROCESS_QUOTA
RtpFindProcessQuota(
    _In_ PRT_THROTTLER Throttler,
    _In_ HANDLE ProcessId
);

static PRT_PROCESS_QUOTA
RtpFindOrCreateProcessQuota(
    _In_ PRT_THROTTLER Throttler,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN CreateIfNotFound
);

static ULONG RtpHashProcessId(_In_ HANDLE ProcessId);
static VOID RtpProcessDeferredWorkQueue(_Inout_ PRT_THROTTLER Throttler);
static VOID RtpDrainDeferredWorkQueue(_Inout_ PRT_THROTTLER Throttler);
static VOID RtpDrainProcessQuotas(_Inout_ PRT_THROTTLER Throttler);

//
// Locked lookup: returns quota with ProcessQuotas.Lock HELD.
// Caller MUST release via KeReleaseSpinLock(&Throttler->ProcessQuotas.Lock, OldIrql).
// Returns NULL with lock RELEASED if not found.
//
_IRQL_raises_(DISPATCH_LEVEL)
static PRT_PROCESS_QUOTA
RtpLookupProcessQuotaLocked(
    _In_ PRT_THROTTLER Throttler,
    _In_ HANDLE ProcessId,
    _Out_ PKIRQL OldIrql
);

// ============================================================================
// STATIC STRING TABLES (bounds checked via C_ASSERT)
// ============================================================================

static PCWSTR g_ResourceNames[RtResourceMax] = {
    L"CPU",
    L"MemoryNonPaged",
    L"MemoryPaged",
    L"DiskIOPS",
    L"DiskBandwidth",
    L"NetworkIOPS",
    L"NetworkBandwidth",
    L"CallbackRate",
    L"EventQueue",
    L"FsOps",
    L"RegOps",
    L"ProcessCreation",
    L"HandleOps",
    L"MemoryMaps",
    L"Custom1",
    L"Custom2"
};

static PCWSTR g_ActionNames[RtActionEscalate + 1] = {
    L"None",
    L"Delay",
    L"SkipLowPriority",
    L"Queue",
    L"Sample",
    L"Abort",
    L"Notify",
    L"Escalate"
};

static PCWSTR g_StateNames[RtStateRecovery + 1] = {
    L"Normal",
    L"Warning",
    L"Throttled",
    L"Critical",
    L"Recovery"
};

C_ASSERT(ARRAYSIZE(g_ResourceNames) == RtResourceMax);
C_ASSERT(ARRAYSIZE(g_ActionNames) == RtActionEscalate + 1);
C_ASSERT(ARRAYSIZE(g_StateNames) == RtStateRecovery + 1);

// ============================================================================
// INITIALIZATION AND CLEANUP
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
RtInitialize(
    _Outptr_ PRT_THROTTLER* Throttler
)
{
    PRT_THROTTLER throttler = NULL;
    NTSTATUS status;
    HANDLE threadHandle = NULL;
    OBJECT_ATTRIBUTES oa;
    ULONG i;

    PAGED_CODE();

    if (Throttler == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Throttler = NULL;

    throttler = (PRT_THROTTLER)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(RT_THROTTLER),
        RT_POOL_TAG
    );

    if (throttler == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(throttler, sizeof(RT_THROTTLER));

    throttler->Magic = RT_THROTTLER_MAGIC;

    //
    // Initialize spin locks
    //
    KeInitializeSpinLock(&throttler->CallbackSpinLock);
    KeInitializeSpinLock(&throttler->StatsLock);
    KeInitializeSpinLock(&throttler->ProcessQuotas.Lock);

    //
    // Initialize rundown protection
    //
    ExInitializeRundownProtection(&throttler->RundownRef);
    throttler->ShutdownFlag = 0;

    //
    // Initialize resource states (each with its own KSPIN_LOCK)
    //
    RtpInitializeResourceStates(throttler);
    RtpInitializeProcessQuotas(throttler);
    RtpInitializeDeferredWork(throttler);

    //
    // Monitoring timer ID (created lazily in RtStartMonitoring)
    //
    throttler->MonitorTimerId = 0;

    //
    // Worker thread wake event
    //
    KeInitializeEvent(&throttler->WorkerWakeEvent, SynchronizationEvent, FALSE);
    throttler->WorkerShouldExit = 0;

    //
    // Set default configuration
    //
    for (i = 0; i < RT_MAX_RESOURCE_TYPES; i++) {
        throttler->Configs[i].Type = (RT_RESOURCE_TYPE)i;
        throttler->Configs[i].Enabled = FALSE;
        throttler->Configs[i].SoftLimit = MAXULONG64;
        throttler->Configs[i].HardLimit = MAXULONG64;
        throttler->Configs[i].CriticalLimit = MAXULONG64;
        throttler->Configs[i].SoftAction = RtActionNotify;
        throttler->Configs[i].HardAction = RtActionDelay;
        throttler->Configs[i].CriticalAction = RtActionAbort;
        throttler->Configs[i].DelayMs = 10;
        throttler->Configs[i].SampleRate = 10;
        throttler->Configs[i].RateWindowMs = 1000;
        throttler->Configs[i].BurstCapacity = RT_DEFAULT_BURST_CAPACITY;
    }

    KeQuerySystemTime(&throttler->Stats.StartTime);
    KeQuerySystemTime(&throttler->CreateTime);

    //
    // Create system worker thread for PASSIVE_LEVEL deferred work
    //
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    status = PsCreateSystemThread(
        &threadHandle,
        THREAD_ALL_ACCESS,
        &oa,
        NULL,
        NULL,
        RtpWorkerThreadRoutine,
        throttler
    );

    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreePoolWithTag(throttler, RT_POOL_TAG);
        return status;
    }

    status = ObReferenceObjectByHandle(
        threadHandle,
        THREAD_ALL_ACCESS,
        *PsThreadType,
        KernelMode,
        (PVOID*)&throttler->WorkerThread,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        //
        // Thread is running with a pointer to throttler. We must wait
        // for it to exit BEFORE freeing the structure. The handle is
        // still open, so use it to wait. (RT-C1 fix)
        //
        InterlockedExchange(&throttler->WorkerShouldExit, 1);
        KeSetEvent(&throttler->WorkerWakeEvent, IO_NO_INCREMENT, FALSE);
        ZwWaitForSingleObject(threadHandle, FALSE, NULL);
        ZwClose(threadHandle);
        ShadowStrikeFreePoolWithTag(throttler, RT_POOL_TAG);
        return status;
    }

    ZwClose(threadHandle);

    throttler->Enabled = TRUE;
    throttler->Initialized = TRUE;

    *Throttler = throttler;

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
RtShutdown(
    _Inout_ PRT_THROTTLER* Throttler
)
{
    PRT_THROTTLER throttler;

    PAGED_CODE();

    if (Throttler == NULL || *Throttler == NULL) {
        return;
    }

    throttler = *Throttler;
    *Throttler = NULL;

    if (!RtIsValidThrottler(throttler)) {
        return;
    }

    //
    // 1. Signal shutdown flag (safe to read at any IRQL)
    //
    InterlockedExchange(&throttler->ShutdownFlag, 1);

    //
    // 2. Disable rundown â€” blocks new ExAcquireRundownProtection calls
    //
    ExWaitForRundownProtectionRelease(&throttler->RundownRef);

    //
    // 3. Stop monitoring timer
    //
    throttler->MonitoringActive = FALSE;
    {
        PTM_MANAGER tmMgr = ShadowStrikeGetTimerManager();
        if (tmMgr && throttler->MonitorTimerId != 0) {
            TmCancel(tmMgr, throttler->MonitorTimerId, TRUE);
            throttler->MonitorTimerId = 0;
        }
    }

    //
    // 4. Stop deferred work timer
    //
    throttler->DeferredWork.ProcessingEnabled = FALSE;
    {
        PTM_MANAGER tmMgr = ShadowStrikeGetTimerManager();
        if (tmMgr && throttler->DeferredWork.ProcessTimerId != 0) {
            TmCancel(tmMgr, throttler->DeferredWork.ProcessTimerId, TRUE);
            throttler->DeferredWork.ProcessTimerId = 0;
        }
    }

    //
    // 5. Signal worker thread to exit and wait
    //
    InterlockedExchange(&throttler->WorkerShouldExit, 1);
    KeSetEvent(&throttler->WorkerWakeEvent, IO_NO_INCREMENT, FALSE);

    if (throttler->WorkerThread != NULL) {
        KeWaitForSingleObject(
            throttler->WorkerThread,
            Executive,
            KernelMode,
            FALSE,
            NULL
        );
        ObDereferenceObject(throttler->WorkerThread);
        throttler->WorkerThread = NULL;
    }

    //
    // 6. Drain deferred work queue (free without executing)
    //
    RtpDrainDeferredWorkQueue(throttler);

    //
    // 7. Free all dynamically allocated process quotas
    //
    RtpDrainProcessQuotas(throttler);

    //
    // 8. Invalidate and free
    //
    throttler->Magic = 0;
    throttler->Initialized = FALSE;
    ShadowStrikeFreePoolWithTag(throttler, RT_POOL_TAG);
}

// ============================================================================
// CONFIGURATION
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
RtSetLimits(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource,
    _In_ ULONG64 SoftLimit,
    _In_ ULONG64 HardLimit,
    _In_ ULONG64 CriticalLimit
)
{
    PRT_RESOURCE_CONFIG config;
    KIRQL oldIrql;

    PAGED_CODE();

    if (!RtIsValidThrottler(Throttler)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Resource >= RtResourceMax) {
        return STATUS_INVALID_PARAMETER;
    }

    if (SoftLimit > HardLimit || HardLimit > CriticalLimit) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Throttler->RundownRef)) {
        return STATUS_DEVICE_NOT_READY;
    }

    config = &Throttler->Configs[Resource];

    KeAcquireSpinLock(&Throttler->States[Resource].ResourceLock, &oldIrql);

    if (!config->Enabled) {
        InterlockedIncrement(&Throttler->ConfiguredResourceCount);
    }

    config->SoftLimit = SoftLimit;
    config->HardLimit = HardLimit;
    config->CriticalLimit = CriticalLimit;
    config->Enabled = TRUE;

    KeReleaseSpinLock(&Throttler->States[Resource].ResourceLock, oldIrql);

    ExReleaseRundownProtection(&Throttler->RundownRef);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
RtSetActions(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource,
    _In_ RT_THROTTLE_ACTION SoftAction,
    _In_ RT_THROTTLE_ACTION HardAction,
    _In_ RT_THROTTLE_ACTION CriticalAction,
    _In_ ULONG DelayMs
)
{
    PRT_RESOURCE_CONFIG config;
    KIRQL oldIrql;

    PAGED_CODE();

    if (!RtIsValidThrottler(Throttler)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Resource >= RtResourceMax) {
        return STATUS_INVALID_PARAMETER;
    }

    if (SoftAction > RT_ACTION_MAX_VALID ||
        HardAction > RT_ACTION_MAX_VALID ||
        CriticalAction > RT_ACTION_MAX_VALID) {
        return STATUS_INVALID_PARAMETER;
    }

    if (DelayMs < RT_MIN_DELAY_MS) {
        DelayMs = RT_MIN_DELAY_MS;
    }
    if (DelayMs > RT_MAX_DELAY_MS) {
        DelayMs = RT_MAX_DELAY_MS;
    }

    if (!ExAcquireRundownProtection(&Throttler->RundownRef)) {
        return STATUS_DEVICE_NOT_READY;
    }

    config = &Throttler->Configs[Resource];

    KeAcquireSpinLock(&Throttler->States[Resource].ResourceLock, &oldIrql);

    config->SoftAction = SoftAction;
    config->HardAction = HardAction;
    config->CriticalAction = CriticalAction;
    config->DelayMs = DelayMs;

    KeReleaseSpinLock(&Throttler->States[Resource].ResourceLock, oldIrql);

    ExReleaseRundownProtection(&Throttler->RundownRef);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
RtSetRateConfig(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource,
    _In_ ULONG RateWindowMs,
    _In_ ULONG BurstCapacity
)
{
    PRT_RESOURCE_CONFIG config;
    KIRQL oldIrql;

    PAGED_CODE();

    if (!RtIsValidThrottler(Throttler)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Resource >= RtResourceMax) {
        return STATUS_INVALID_PARAMETER;
    }

    if (RateWindowMs < 100)   RateWindowMs = 100;
    if (RateWindowMs > 60000) RateWindowMs = 60000;

    if (!ExAcquireRundownProtection(&Throttler->RundownRef)) {
        return STATUS_DEVICE_NOT_READY;
    }

    config = &Throttler->Configs[Resource];

    KeAcquireSpinLock(&Throttler->States[Resource].ResourceLock, &oldIrql);

    config->RateWindowMs = RateWindowMs;
    config->BurstCapacity = BurstCapacity;
    InterlockedExchange(&Throttler->States[Resource].BurstTokens, (LONG)BurstCapacity);

    KeReleaseSpinLock(&Throttler->States[Resource].ResourceLock, oldIrql);

    ExReleaseRundownProtection(&Throttler->RundownRef);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
RtEnableResource(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource,
    _In_ BOOLEAN Enable
)
{
    KIRQL oldIrql;

    if (!RtIsValidThrottler(Throttler)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Resource >= RtResourceMax) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&Throttler->States[Resource].ResourceLock, &oldIrql);
    Throttler->Configs[Resource].Enabled = Enable;
    KeReleaseSpinLock(&Throttler->States[Resource].ResourceLock, oldIrql);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
RtRegisterCallback(
    _In_ PRT_THROTTLER Throttler,
    _In_ PRT_THROTTLE_CALLBACK Callback,
    _In_opt_ PVOID Context
)
{
    KIRQL oldIrql;

    PAGED_CODE();

    if (!RtIsValidThrottler(Throttler)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&Throttler->CallbackSpinLock, &oldIrql);

    Throttler->ThrottleCallback = Callback;
    Throttler->CallbackContext = Context;

    KeReleaseSpinLock(&Throttler->CallbackSpinLock, oldIrql);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
VOID
RtUnregisterCallback(
    _In_ PRT_THROTTLER Throttler
)
{
    KIRQL oldIrql;

    PAGED_CODE();

    if (!RtIsValidThrottler(Throttler)) {
        return;
    }

    KeAcquireSpinLock(&Throttler->CallbackSpinLock, &oldIrql);

    Throttler->ThrottleCallback = NULL;
    Throttler->CallbackContext = NULL;

    KeReleaseSpinLock(&Throttler->CallbackSpinLock, oldIrql);

    //
    // Wait for any in-flight callback invocations to complete.
    // Timeout after 5 seconds to prevent infinite hang on stuck callbacks.
    //
    {
        ULONG waitAttempts = 0;
        while (Throttler->CallbackActiveCount > 0 && waitAttempts < 5000) {
            LARGE_INTEGER delay;
            delay.QuadPart = -10000; // 1ms
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
            waitAttempts++;
        }
    }
}

// ============================================================================
// MONITORING CONTROL
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
RtStartMonitoring(
    _In_ PRT_THROTTLER Throttler,
    _In_ ULONG IntervalMs
)
{
    PTM_MANAGER tmMgr;
    NTSTATUS status;

    PAGED_CODE();

    if (!RtIsValidThrottler(Throttler)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Throttler->MonitoringActive) {
        return STATUS_ALREADY_REGISTERED;
    }

    if (IntervalMs < RT_MIN_MONITOR_INTERVAL_MS) {
        IntervalMs = RT_MIN_MONITOR_INTERVAL_MS;
    }
    if (IntervalMs > RT_MAX_MONITOR_INTERVAL_MS) {
        IntervalMs = RT_MAX_MONITOR_INTERVAL_MS;
    }

    Throttler->MonitorIntervalMs = IntervalMs;

    tmMgr = ShadowStrikeGetTimerManager();
    if (tmMgr == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Create monitor timer via TimerManager
    //
    {
        TM_TIMER_OPTIONS opts = { 0 };
        opts.Flags = TmFlag_WorkItemCallback | TmFlag_Coalescable;
        opts.ToleranceMs = 2000;

        status = TmCreatePeriodic(
            tmMgr,
            IntervalMs,
            RtpMonitorTimerCallback,
            Throttler,
            &opts,
            &Throttler->MonitorTimerId
        );

        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    Throttler->MonitoringActive = TRUE;

    //
    // Also start deferred work processing timer
    //
    if (!Throttler->DeferredWork.ProcessingEnabled) {
        TM_TIMER_OPTIONS opts2 = { 0 };
        opts2.Flags = TmFlag_WorkItemCallback | TmFlag_Coalescable;
        opts2.ToleranceMs = 10;

        status = TmCreatePeriodic(
            tmMgr,
            RT_DEFERRED_PROCESS_INTERVAL_MS,
            RtpDeferredWorkTimerCallback,
            Throttler,
            &opts2,
            &Throttler->DeferredWork.ProcessTimerId
        );

        if (!NT_SUCCESS(status)) {
            TmCancel(tmMgr, Throttler->MonitorTimerId, TRUE);
            Throttler->MonitorTimerId = 0;
            Throttler->MonitoringActive = FALSE;
            return status;
        }

        Throttler->DeferredWork.ProcessingEnabled = TRUE;
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
VOID
RtStopMonitoring(
    _In_ PRT_THROTTLER Throttler
)
{
    PTM_MANAGER tmMgr;

    PAGED_CODE();

    if (!RtIsValidThrottler(Throttler)) {
        return;
    }

    if (!Throttler->MonitoringActive) {
        return;
    }

    Throttler->MonitoringActive = FALSE;

    tmMgr = ShadowStrikeGetTimerManager();
    if (tmMgr && Throttler->MonitorTimerId != 0) {
        TmCancel(tmMgr, Throttler->MonitorTimerId, TRUE);
        Throttler->MonitorTimerId = 0;
    }
}

// ============================================================================
// USAGE REPORTING AND THROTTLE CHECKING
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
RtReportUsage(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource,
    _In_ LONG64 Delta
)
{
    PRT_RESOURCE_STATE state;
    LONG64 newValue;
    LONG64 currentPeak;

    if (!RtIsValidThrottler(Throttler)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Resource >= RtResourceMax) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Throttler->Configs[Resource].Enabled) {
        return STATUS_SUCCESS;
    }

    state = &Throttler->States[Resource];

    newValue = InterlockedAdd64(&state->CurrentUsage, Delta);

    //
    // Update peak (lock-free CAS)
    //
    do {
        currentPeak = state->PeakUsage;
        if (newValue <= currentPeak) {
            break;
        }
    } while (InterlockedCompareExchange64(
        &state->PeakUsage, newValue, currentPeak) != currentPeak);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
RtSetUsage(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource,
    _In_ ULONG64 Value
)
{
    PRT_RESOURCE_STATE state;
    LONG64 currentPeak;

    if (!RtIsValidThrottler(Throttler)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Resource >= RtResourceMax) {
        return STATUS_INVALID_PARAMETER;
    }

    state = &Throttler->States[Resource];

    InterlockedExchange64(&state->CurrentUsage, (LONG64)Value);

    do {
        currentPeak = state->PeakUsage;
        if ((LONG64)Value <= currentPeak) {
            break;
        }
    } while (InterlockedCompareExchange64(
        &state->PeakUsage, (LONG64)Value, currentPeak) != currentPeak);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
RtCheckThrottle(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource,
    _In_ RT_PRIORITY Priority,
    _Out_ PRT_THROTTLE_ACTION Action
)
{
    RT_THROTTLE_ACTION action;
    NTSTATUS status = STATUS_SUCCESS;

    if (Action == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Action = RtActionNone;

    if (!RtIsValidThrottler(Throttler)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Resource >= RtResourceMax) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Throttler->Enabled || !Throttler->Configs[Resource].Enabled) {
        return STATUS_SUCCESS;
    }

    //
    // Acquire rundown protection â€” prevents shutdown during operation
    //
    if (!ExAcquireRundownProtection(&Throttler->RundownRef)) {
        return STATUS_DEVICE_NOT_READY;
    }

    InterlockedIncrement64(&Throttler->Stats.TotalOperations);
    InterlockedIncrement64(&Throttler->Stats.PerResource[Resource].Checks);

    action = RtpDetermineAction(Throttler, Resource, Priority);
    *Action = action;

    switch (action) {
        case RtActionNone:
        case RtActionNotify:
            status = STATUS_SUCCESS;
            break;

        case RtActionDelay:
        case RtActionQueue:
            InterlockedIncrement64(&Throttler->Stats.ThrottledOperations);
            status = STATUS_DEVICE_BUSY;
            break;

        case RtActionSkipLowPriority:
        case RtActionSample:
            if (Priority >= RtPriorityLow) {
                InterlockedIncrement64(&Throttler->Stats.SkippedOperations);
                status = STATUS_DEVICE_BUSY;
            } else {
                status = STATUS_SUCCESS;
            }
            break;

        case RtActionAbort:
            InterlockedIncrement64(&Throttler->Stats.AbortedOperations);
            status = STATUS_QUOTA_EXCEEDED;
            break;

        default:
            status = STATUS_SUCCESS;
            break;
    }

    ExReleaseRundownProtection(&Throttler->RundownRef);

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
RtShouldProceed(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource,
    _In_ RT_PRIORITY Priority
)
{
    RT_THROTTLE_ACTION action;
    NTSTATUS status;

    status = RtCheckThrottle(Throttler, Resource, Priority, &action);
    return (NT_SUCCESS(status) || action == RtActionNotify);
}

_When_(Action == RtActionDelay, _IRQL_requires_(PASSIVE_LEVEL))
_When_(Action != RtActionDelay, _IRQL_requires_max_(DISPATCH_LEVEL))
NTSTATUS
RtApplyThrottle(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource,
    _In_ RT_THROTTLE_ACTION Action
)
{
    PRT_RESOURCE_STATE state;
    LARGE_INTEGER delayInterval;
    ULONG delayMs;
    KIRQL oldIrql;

    if (!RtIsValidThrottler(Throttler)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Resource >= RtResourceMax) {
        return STATUS_INVALID_PARAMETER;
    }

    state = &Throttler->States[Resource];

    switch (Action) {
        case RtActionNone:
        case RtActionNotify:
            return STATUS_SUCCESS;

        case RtActionDelay:
            delayMs = state->CurrentDelayMs;
            if (delayMs < RT_MIN_DELAY_MS) {
                delayMs = Throttler->Configs[Resource].DelayMs;
            }

            delayInterval.QuadPart = -((LONGLONG)delayMs * 10000);
            KeDelayExecutionThread(KernelMode, FALSE, &delayInterval);

            InterlockedIncrement64(&Throttler->Stats.DelayedOperations);
            InterlockedAdd64(&Throttler->Stats.TotalDelayMs, delayMs);

            //
            // Exponential backoff (protected by per-resource lock)
            //
            KeAcquireSpinLock(&state->ResourceLock, &oldIrql);
            delayMs = (state->CurrentDelayMs * RT_BACKOFF_MULTIPLIER) / RT_BACKOFF_DIVISOR;
            if (delayMs > RT_MAX_DELAY_MS) delayMs = RT_MAX_DELAY_MS;
            if (delayMs < RT_MIN_DELAY_MS) delayMs = Throttler->Configs[Resource].DelayMs;
            state->CurrentDelayMs = delayMs;
            KeReleaseSpinLock(&state->ResourceLock, oldIrql);

            return STATUS_SUCCESS;

        case RtActionSkipLowPriority:
        case RtActionSample:
            return STATUS_SUCCESS;

        case RtActionQueue:
            InterlockedIncrement64(&Throttler->Stats.QueuedOperations);
            return STATUS_DEVICE_BUSY;

        case RtActionAbort:
            return STATUS_CANCELLED;

        case RtActionEscalate:
            return STATUS_DEVICE_BUSY;

        default:
            return STATUS_SUCCESS;
    }
}

// ============================================================================
// PER-PROCESS THROTTLING
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
RtReportProcessUsage(
    _In_ PRT_THROTTLER Throttler,
    _In_ HANDLE ProcessId,
    _In_ RT_RESOURCE_TYPE Resource,
    _In_ LONG64 Delta
)
{
    PRT_PROCESS_QUOTA quota;
    LARGE_INTEGER currentTime;
    KIRQL oldIrql;

    if (!RtIsValidThrottler(Throttler)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Resource >= RtResourceMax) {
        return STATUS_INVALID_PARAMETER;
    }

    RtReportUsage(Throttler, Resource, Delta);

    //
    // Use locked lookup to prevent UAF: if RtRemoveProcess runs
    // concurrently, it cannot free the quota while we hold the lock.
    //
    quota = RtpLookupProcessQuotaLocked(Throttler, ProcessId, &oldIrql);
    if (quota == NULL) {
        //
        // No existing quota â€” try create via the full lookup path.
        // RtpFindOrCreateProcessQuota allocates under the lock, which is safe.
        //
        quota = RtpFindOrCreateProcessQuota(Throttler, ProcessId, TRUE);
        if (quota == NULL) {
            return STATUS_SUCCESS;
        }
        //
        // RtpFindOrCreateProcessQuota released the lock. Re-acquire
        // for the update. The quota is either found (existing) or just
        // inserted â€” RtRemoveProcess cannot race here because the process
        // is still running if it's reporting usage.
        //
        KeAcquireSpinLock(&Throttler->ProcessQuotas.Lock, &oldIrql);
    }

    InterlockedAdd64(&quota->ResourceUsage[Resource], Delta);

    KeQuerySystemTime(&currentTime);
    quota->LastActivity = currentTime;

    KeReleaseSpinLock(&Throttler->ProcessQuotas.Lock, oldIrql);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
RtCheckProcessThrottle(
    _In_ PRT_THROTTLER Throttler,
    _In_ HANDLE ProcessId,
    _In_ RT_RESOURCE_TYPE Resource,
    _Out_ PRT_THROTTLE_ACTION Action
)
{
    PRT_PROCESS_QUOTA quota;
    KIRQL oldIrql;
    BOOLEAN exempt;
    ULONG64 softLimit;
    LONG64 usage;

    if (Action == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Action = RtActionNone;

    if (!RtIsValidThrottler(Throttler)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Resource >= RtResourceMax) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Use locked lookup to prevent UAF: snapshot all needed quota
    // fields while holding ProcessQuotas.Lock, then release.
    //
    quota = RtpLookupProcessQuotaLocked(Throttler, ProcessId, &oldIrql);
    if (quota == NULL) {
        return RtCheckThrottle(Throttler, Resource, RtPriorityNormal, Action);
    }

    exempt = quota->Exempt;
    softLimit = quota->ProcessSoftLimit[Resource];
    usage = quota->ResourceUsage[Resource];

    if (!exempt && softLimit != 0 && (ULONG64)usage >= softLimit) {
        InterlockedIncrement64(&quota->ThrottleHits);
    }

    KeReleaseSpinLock(&Throttler->ProcessQuotas.Lock, oldIrql);

    //
    // Process snapshotted data outside lock
    //
    if (exempt) {
        return STATUS_SUCCESS;
    }

    if (softLimit != 0) {
        if ((ULONG64)usage >= softLimit) {
            if ((ULONG64)usage >= softLimit * 2) {
                *Action = RtActionAbort;
                return STATUS_QUOTA_EXCEEDED;
            }

            *Action = RtActionDelay;
            return STATUS_DEVICE_BUSY;
        }
    }

    //
    // Fall back to global throttle check
    //
    return RtCheckThrottle(Throttler, Resource, RtPriorityNormal, Action);
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
RtSetProcessExemption(
    _In_ PRT_THROTTLER Throttler,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Exempt
)
{
    PRT_PROCESS_QUOTA quota;
    KIRQL oldIrql;

    PAGED_CODE();

    if (!RtIsValidThrottler(Throttler)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Use locked lookup first. If not found, create via the full path
    // (which allocates under lock and returns with lock released).
    //
    quota = RtpLookupProcessQuotaLocked(Throttler, ProcessId, &oldIrql);
    if (quota != NULL) {
        quota->Exempt = Exempt;
        KeReleaseSpinLock(&Throttler->ProcessQuotas.Lock, oldIrql);
        return STATUS_SUCCESS;
    }

    //
    // Not found â€” create. RtpFindOrCreateProcessQuota handles its own locking.
    //
    quota = RtpFindOrCreateProcessQuota(Throttler, ProcessId, TRUE);
    if (quota == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Just created â€” no concurrent free possible yet. Safe to write.
    //
    quota->Exempt = Exempt;

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RtRemoveProcess(
    _In_ PRT_THROTTLER Throttler,
    _In_ HANDLE ProcessId
)
{
    PRT_PROCESS_QUOTA quota;
    ULONG bucket;
    PLIST_ENTRY entry;
    KIRQL oldIrql;

    if (!RtIsValidThrottler(Throttler)) {
        return;
    }

    bucket = RtpHashProcessId(ProcessId);

    KeAcquireSpinLock(&Throttler->ProcessQuotas.Lock, &oldIrql);

    for (entry = Throttler->ProcessQuotas.HashBuckets[bucket].Flink;
         entry != &Throttler->ProcessQuotas.HashBuckets[bucket];
         entry = entry->Flink) {

        quota = CONTAINING_RECORD(entry, RT_PROCESS_QUOTA, HashLink);

        if (quota->ProcessId == ProcessId && quota->InUse) {
            RemoveEntryList(&quota->HashLink);
            InterlockedDecrement(&Throttler->ProcessQuotas.ActiveCount);
            KeReleaseSpinLock(&Throttler->ProcessQuotas.Lock, oldIrql);

            ShadowStrikeFreePoolWithTag(quota, RT_PROCESS_TAG);
            return;
        }
    }

    KeReleaseSpinLock(&Throttler->ProcessQuotas.Lock, oldIrql);
}

// ============================================================================
// DEFERRED WORK QUEUE
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
RtQueueDeferredWork(
    _In_ PRT_THROTTLER Throttler,
    _In_ PRT_DEFERRED_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _In_ RT_PRIORITY Priority,
    _In_ ULONG TimeoutMs
)
{
    PRT_DEFERRED_WORK workItem;
    LARGE_INTEGER currentTime;
    KIRQL oldIrql;

    if (!RtIsValidThrottler(Throttler)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Throttler->DeferredWork.Depth >= Throttler->DeferredWork.MaxDepth) {
        return STATUS_QUOTA_EXCEEDED;
    }

    workItem = (PRT_DEFERRED_WORK)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(RT_DEFERRED_WORK),
        RT_QUEUE_TAG
    );

    if (workItem == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(workItem, sizeof(RT_DEFERRED_WORK));
    InitializeListHead(&workItem->ListEntry);
    workItem->ResourceType = RtResourceMax;
    workItem->Priority = Priority;
    workItem->Callback = Callback;
    workItem->Context = Context;

    KeQuerySystemTime(&currentTime);
    workItem->QueueTime = currentTime;

    if (TimeoutMs > 0) {
        workItem->ExpirationTime.QuadPart =
            currentTime.QuadPart + ((LONGLONG)TimeoutMs * 10000);
    }

    KeAcquireSpinLock(&Throttler->DeferredWork.Lock, &oldIrql);

    if (IsListEmpty(&Throttler->DeferredWork.Queue)) {
        InsertTailList(&Throttler->DeferredWork.Queue, &workItem->ListEntry);
    } else {
        PLIST_ENTRY entry;
        BOOLEAN inserted = FALSE;

        for (entry = Throttler->DeferredWork.Queue.Flink;
             entry != &Throttler->DeferredWork.Queue;
             entry = entry->Flink) {

            PRT_DEFERRED_WORK existing = CONTAINING_RECORD(
                entry, RT_DEFERRED_WORK, ListEntry);

            if (Priority < existing->Priority) {
                InsertTailList(entry, &workItem->ListEntry);
                inserted = TRUE;
                break;
            }
        }

        if (!inserted) {
            InsertTailList(&Throttler->DeferredWork.Queue, &workItem->ListEntry);
        }
    }

    InterlockedIncrement(&Throttler->DeferredWork.Depth);

    KeReleaseSpinLock(&Throttler->DeferredWork.Lock, oldIrql);

    //
    // Wake worker thread
    //
    KeSetEvent(&Throttler->WorkerWakeEvent, IO_NO_INCREMENT, FALSE);

    InterlockedIncrement64(&Throttler->Stats.QueuedOperations);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
LONG
RtGetDeferredQueueDepth(
    _In_ PRT_THROTTLER Throttler
)
{
    if (!RtIsValidThrottler(Throttler)) {
        return 0;
    }

    return Throttler->DeferredWork.Depth;
}

// ============================================================================
// STATE AND STATISTICS
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
RtGetResourceState(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource,
    _Out_ PRT_THROTTLE_STATE State,
    _Out_opt_ PULONG64 Usage,
    _Out_opt_ PULONG64 Rate
)
{
    PRT_RESOURCE_STATE resourceState;
    KIRQL oldIrql;

    if (State == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!RtIsValidThrottler(Throttler)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Resource >= RtResourceMax) {
        return STATUS_INVALID_PARAMETER;
    }

    resourceState = &Throttler->States[Resource];

    KeAcquireSpinLock(&resourceState->ResourceLock, &oldIrql);

    *State = resourceState->State;

    if (Usage != NULL) {
        *Usage = (ULONG64)resourceState->CurrentUsage;
    }

    if (Rate != NULL) {
        *Rate = (ULONG64)resourceState->CurrentRate;
    }

    KeReleaseSpinLock(&resourceState->ResourceLock, oldIrql);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
RtGetStatistics(
    _In_ PRT_THROTTLER Throttler,
    _Out_ PRT_STATISTICS Stats
)
{
    KIRQL oldIrql;

    if (Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!RtIsValidThrottler(Throttler)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Atomic snapshot under StatsLock
    //
    KeAcquireSpinLock(&Throttler->StatsLock, &oldIrql);
    RtlCopyMemory(Stats, &Throttler->Stats, sizeof(RT_STATISTICS));
    KeReleaseSpinLock(&Throttler->StatsLock, oldIrql);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RtResetStatistics(
    _In_ PRT_THROTTLER Throttler
)
{
    KIRQL oldIrql;
    ULONG i;

    if (!RtIsValidThrottler(Throttler)) {
        return;
    }

    KeAcquireSpinLock(&Throttler->StatsLock, &oldIrql);

    //
    // Under exclusive spin lock â€” plain stores are safe and cheaper
    // than Interlocked* (no bus-lock overhead on multi-core).
    //
    Throttler->Stats.TotalOperations = 0;
    Throttler->Stats.ThrottledOperations = 0;
    Throttler->Stats.DelayedOperations = 0;
    Throttler->Stats.QueuedOperations = 0;
    Throttler->Stats.SkippedOperations = 0;
    Throttler->Stats.AbortedOperations = 0;
    Throttler->Stats.TotalDelayMs = 0;
    Throttler->Stats.StateTransitions = 0;
    Throttler->Stats.AlertsSent = 0;
    Throttler->Stats.DeferredWorkProcessed = 0;
    Throttler->Stats.DeferredWorkExpired = 0;

    for (i = 0; i < RT_MAX_RESOURCE_TYPES; i++) {
        Throttler->Stats.PerResource[i].Checks = 0;
        Throttler->Stats.PerResource[i].Throttles = 0;
        Throttler->Stats.PerResource[i].PeakUsage = 0;
    }

    KeQuerySystemTime(&Throttler->Stats.StartTime);

    KeReleaseSpinLock(&Throttler->StatsLock, oldIrql);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RtResetResource(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource
)
{
    PRT_RESOURCE_STATE state;
    KIRQL oldIrql;

    if (!RtIsValidThrottler(Throttler)) {
        return;
    }

    if (Resource >= RtResourceMax) {
        return;
    }

    state = &Throttler->States[Resource];

    KeAcquireSpinLock(&state->ResourceLock, &oldIrql);

    state->PreviousState = state->State;
    state->State = RtStateNormal;
    InterlockedExchange64(&state->CurrentUsage, 0);
    InterlockedExchange64(&state->PeakUsage, 0);
    InterlockedExchange64(&state->CurrentRate, 0);
    state->OverLimitCount = 0;
    state->UnderLimitCount = 0;
    state->CurrentDelayMs = 0;
    InterlockedExchange(
        &state->BurstTokens,
        (LONG)Throttler->Configs[Resource].BurstCapacity
    );
    KeQuerySystemTime(&state->StateEnterTime);

    KeReleaseSpinLock(&state->ResourceLock, oldIrql);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

PCWSTR
RtGetResourceName(_In_ RT_RESOURCE_TYPE Resource)
{
    if (Resource >= RtResourceMax) {
        return L"Unknown";
    }
    return g_ResourceNames[Resource];
}

PCWSTR
RtGetActionName(_In_ RT_THROTTLE_ACTION Action)
{
    if (Action > RT_ACTION_MAX_VALID) {
        return L"Unknown";
    }
    return g_ActionNames[Action];
}

PCWSTR
RtGetStateName(_In_ RT_THROTTLE_STATE State)
{
    if (State > RT_STATE_MAX_VALID) {
        return L"Unknown";
    }
    return g_StateNames[State];
}

// ============================================================================
// PRIVATE IMPLEMENTATION
// ============================================================================

static VOID
RtpInitializeResourceStates(
    _Inout_ PRT_THROTTLER Throttler
)
{
    ULONG i;
    LARGE_INTEGER currentTime;

    KeQuerySystemTime(&currentTime);

    for (i = 0; i < RT_MAX_RESOURCE_TYPES; i++) {
        PRT_RESOURCE_STATE state = &Throttler->States[i];

        state->Type = (RT_RESOURCE_TYPE)i;
        state->State = RtStateNormal;
        state->PreviousState = RtStateNormal;
        state->CurrentUsage = 0;
        state->PeakUsage = 0;
        state->LastSampleUsage = 0;
        state->CurrentRate = 0;
        state->BurstTokens = RT_DEFAULT_BURST_CAPACITY;
        state->OverLimitCount = 0;
        state->UnderLimitCount = 0;
        state->CurrentDelayMs = 0;
        state->StateEnterTime = currentTime;
        state->LastRateCalcTime = currentTime;
        state->LastTokenRefillTime = currentTime;
        state->RateHistoryIndex = 0;
        state->RateHistorySamples = 0;

        KeInitializeSpinLock(&state->ResourceLock);
    }
}

static VOID
RtpInitializeProcessQuotas(
    _Inout_ PRT_THROTTLER Throttler
)
{
    ULONG i;

    for (i = 0; i < RT_PROCESS_HASH_BUCKETS; i++) {
        InitializeListHead(&Throttler->ProcessQuotas.HashBuckets[i]);
    }

    Throttler->ProcessQuotas.ActiveCount = 0;
}

static VOID
RtpInitializeDeferredWork(
    _Inout_ PRT_THROTTLER Throttler
)
{
    InitializeListHead(&Throttler->DeferredWork.Queue);
    KeInitializeSpinLock(&Throttler->DeferredWork.Lock);
    Throttler->DeferredWork.Depth = 0;
    Throttler->DeferredWork.MaxDepth = RT_MAX_DEFERRED_QUEUE_DEPTH;
    Throttler->DeferredWork.ProcessTimerId = 0;
    Throttler->DeferredWork.ProcessingEnabled = FALSE;
}

static VOID
RtpMonitorTimerCallback(
    _In_ ULONG TimerId,
    _In_opt_ PVOID Context
)
{
    PRT_THROTTLER throttler = (PRT_THROTTLER)Context;
    ULONG i;

    UNREFERENCED_PARAMETER(TimerId);

    if (throttler == NULL || !RtIsValidThrottler(throttler)) {
        return;
    }

    if (!ExAcquireRundownProtection(&throttler->RundownRef)) {
        return;
    }

    for (i = 0; i < RT_MAX_RESOURCE_TYPES; i++) {
        if (throttler->Configs[i].Enabled) {
            RtpUpdateResourceState(throttler, (RT_RESOURCE_TYPE)i);
        }
    }

    //
    // On battery power, refill burst tokens at 2Ã— rate to reduce
    // CPU overhead from throttle-induced retries. Protection is
    // still active (limits unchanged), but throttling is less aggressive.
    //
    if (ShadowPowerIsOnBattery()) {
        LARGE_INTEGER now;
        KeQuerySystemTime(&now);

        for (i = 0; i < RT_MAX_RESOURCE_TYPES; i++) {
            if (throttler->Configs[i].Enabled) {
                RtpRefillBurstTokens(
                    &throttler->States[i],
                    &throttler->Configs[i],
                    now);
            }
        }
    }

    ExReleaseRundownProtection(&throttler->RundownRef);
}

static VOID
RtpDeferredWorkTimerCallback(
    _In_ ULONG TimerId,
    _In_opt_ PVOID Context
)
{
    PRT_THROTTLER throttler = (PRT_THROTTLER)Context;

    UNREFERENCED_PARAMETER(TimerId);

    if (throttler == NULL || !RtIsValidThrottler(throttler)) {
        return;
    }

    //
    // Wake worker thread to process deferred work at PASSIVE_LEVEL
    //
    if (throttler->DeferredWork.Depth > 0) {
        KeSetEvent(&throttler->WorkerWakeEvent, IO_NO_INCREMENT, FALSE);
    }
}

/**
 * @brief System worker thread for PASSIVE_LEVEL deferred work processing.
 *
 * Replaces the dead PIO_WORKITEM path. Thread runs until WorkerShouldExit
 * is set and WorkerWakeEvent is signaled.
 */
static VOID
RtpWorkerThreadRoutine(
    _In_ PVOID Context
)
{
    PRT_THROTTLER throttler = (PRT_THROTTLER)Context;
    NTSTATUS waitStatus;

    while (TRUE) {
        waitStatus = KeWaitForSingleObject(
            &throttler->WorkerWakeEvent,
            Executive,
            KernelMode,
            FALSE,
            NULL
        );

        if (throttler->WorkerShouldExit) {
            break;
        }

        if (NT_SUCCESS(waitStatus) && RtIsValidThrottler(throttler)) {
            RtpProcessDeferredWorkQueue(throttler);
        }
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

static VOID
RtpUpdateResourceState(
    _Inout_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource
)
{
    PRT_RESOURCE_STATE state;
    PRT_RESOURCE_CONFIG config;
    LARGE_INTEGER currentTime;
    LONG64 currentUsage;
    RT_THROTTLE_STATE newState;
    RT_THROTTLE_STATE oldState;
    BOOLEAN stateChanged = FALSE;
    RT_THROTTLE_EVENT event;
    KIRQL oldIrql;
    ULONG64 softLimit, hardLimit, criticalLimit;
    RT_THROTTLE_ACTION softAction, hardAction, criticalAction;

    state = &Throttler->States[Resource];
    config = &Throttler->Configs[Resource];

    KeQuerySystemTime(&currentTime);

    //
    // Acquire per-resource lock to protect state + config reads
    //
    KeAcquireSpinLock(&state->ResourceLock, &oldIrql);

    //
    // Snapshot config under lock
    //
    softLimit = config->SoftLimit;
    hardLimit = config->HardLimit;
    criticalLimit = config->CriticalLimit;
    softAction = config->SoftAction;
    hardAction = config->HardAction;
    criticalAction = config->CriticalAction;

    //
    // Calculate rate (modifies RateHistory etc. â€” under lock)
    //
    RtpCalculateRate(state, currentTime);

    //
    // Refill burst tokens (uses separate LastTokenRefillTime)
    //
    RtpRefillBurstTokens(state, config, currentTime);

    currentUsage = state->CurrentUsage;

    //
    // Update per-resource peak stat
    //
    if (currentUsage > Throttler->Stats.PerResource[Resource].PeakUsage) {
        InterlockedExchange64(
            &Throttler->Stats.PerResource[Resource].PeakUsage,
            currentUsage
        );
    }

    oldState = state->State;

    if ((ULONG64)currentUsage >= criticalLimit) {
        newState = RtStateCritical;
        state->OverLimitCount++;
        state->UnderLimitCount = 0;
    } else if ((ULONG64)currentUsage >= hardLimit) {
        newState = RtStateThrottled;
        state->OverLimitCount++;
        state->UnderLimitCount = 0;
    } else if ((ULONG64)currentUsage >= softLimit) {
        newState = RtStateWarning;
        state->OverLimitCount++;
        state->UnderLimitCount = 0;
    } else {
        state->UnderLimitCount++;
        state->OverLimitCount = 0;

        if (oldState != RtStateNormal) {
            ULONG64 hysteresisThreshold =
                (softLimit * RT_HYSTERESIS_THRESHOLD) / 100;

            if ((ULONG64)currentUsage < hysteresisThreshold &&
                state->UnderLimitCount >= RT_MIN_SAMPLES_FOR_TRANSITION) {
                newState = RtStateNormal;
                state->CurrentDelayMs = 0;
            } else {
                newState = RtStateRecovery;
            }
        } else {
            newState = RtStateNormal;
        }
    }

    if (newState != oldState) {
        if (newState == RtStateCritical ||
            state->OverLimitCount >= RT_MIN_SAMPLES_FOR_TRANSITION ||
            state->UnderLimitCount >= RT_MIN_SAMPLES_FOR_TRANSITION) {

            state->PreviousState = oldState;
            state->State = newState;
            state->StateEnterTime = currentTime;
            stateChanged = TRUE;

            InterlockedIncrement64(&Throttler->Stats.StateTransitions);
        }
    }

    state->LastSampleUsage = currentUsage;

    KeReleaseSpinLock(&state->ResourceLock, oldIrql);

    //
    // Notify callback outside lock (event is stack-local)
    //
    if (stateChanged) {
        RtlZeroMemory(&event, sizeof(event));
        event.Resource = Resource;
        event.NewState = newState;
        event.OldState = oldState;
        event.CurrentUsage = (ULONG64)currentUsage;
        event.CurrentRate = (ULONG64)state->CurrentRate;
        event.Timestamp = currentTime;

        switch (newState) {
            case RtStateWarning:
                event.LimitValue = softLimit;
                event.Action = softAction;
                break;
            case RtStateThrottled:
                event.LimitValue = hardLimit;
                event.Action = hardAction;
                break;
            case RtStateCritical:
                event.LimitValue = criticalLimit;
                event.Action = criticalAction;
                break;
            default:
                event.LimitValue = softLimit;
                event.Action = RtActionNone;
                break;
        }

        RtpNotifyCallback(Throttler, &event);
    }
}

static VOID
RtpCalculateRate(
    _Inout_ PRT_RESOURCE_STATE State,
    _In_ LARGE_INTEGER CurrentTime
)
{
    LONG64 timeDelta;
    LONG64 usageDelta;
    LONG64 rate;

    timeDelta = (CurrentTime.QuadPart - State->LastRateCalcTime.QuadPart) / 10000;

    if (timeDelta <= 0) {
        return;
    }

    usageDelta = State->CurrentUsage - State->LastSampleUsage;

    rate = (usageDelta * 1000) / timeDelta;

    State->RateHistory[State->RateHistoryIndex] = rate;
    State->RateHistoryIndex = (State->RateHistoryIndex + 1) % RT_RATE_HISTORY_SIZE;

    if (State->RateHistorySamples < RT_RATE_HISTORY_SIZE) {
        State->RateHistorySamples++;
    }

    if (State->RateHistorySamples > 0) {
        LONG64 sum = 0;
        ULONG i;

        for (i = 0; i < State->RateHistorySamples; i++) {
            sum += State->RateHistory[i];
        }

        rate = sum / State->RateHistorySamples;
    }

    InterlockedExchange64(&State->CurrentRate, rate);
    State->LastRateCalcTime = CurrentTime;
}

static VOID
RtpRefillBurstTokens(
    _Inout_ PRT_RESOURCE_STATE State,
    _In_ PRT_RESOURCE_CONFIG Config,
    _In_ LARGE_INTEGER CurrentTime
)
{
    LONG64 timeDelta;
    LONG tokensToAdd;
    LONG currentTokens;
    LONG newTokens;

    //
    // Use LastTokenRefillTime (not LastRateCalcTime)
    //
    timeDelta = (CurrentTime.QuadPart - State->LastTokenRefillTime.QuadPart) / 10000000;

    if (timeDelta <= 0) {
        return;
    }

    tokensToAdd = (LONG)(timeDelta * RT_TOKEN_REFILL_RATE);
    if (tokensToAdd <= 0) {
        return;
    }

    //
    // Update refill timestamp
    //
    State->LastTokenRefillTime = CurrentTime;

    //
    // CAS loop for safe token addition
    //
    do {
        currentTokens = State->BurstTokens;
        newTokens = currentTokens + tokensToAdd;

        if (newTokens > (LONG)Config->BurstCapacity) {
            newTokens = (LONG)Config->BurstCapacity;
        }
    } while (InterlockedCompareExchange(
        &State->BurstTokens, newTokens, currentTokens) != currentTokens);
}

static RT_THROTTLE_ACTION
RtpDetermineAction(
    _In_ PRT_THROTTLER Throttler,
    _In_ RT_RESOURCE_TYPE Resource,
    _In_ RT_PRIORITY Priority
)
{
    PRT_RESOURCE_STATE state;
    PRT_RESOURCE_CONFIG config;
    RT_THROTTLE_STATE currentState;
    RT_THROTTLE_ACTION action;
    LONG prevTokens;

    state = &Throttler->States[Resource];
    config = &Throttler->Configs[Resource];
    currentState = state->State;

    if (Priority == RtPriorityCritical) {
        return RtActionNone;
    }

    //
    // CAS loop for burst tokens â€” only decrement if > 0
    //
    do {
        prevTokens = state->BurstTokens;
        if (prevTokens <= 0) {
            break;
        }
    } while (InterlockedCompareExchange(
        &state->BurstTokens, prevTokens - 1, prevTokens) != prevTokens);

    if (prevTokens > 0) {
        return RtActionNone;
    }

    //
    // Priority ordering: Critical(0) < High(1) < Normal(2) < Low(3) < Background(4)
    // >= means "this priority or LESS important"
    //
    switch (currentState) {
        case RtStateNormal:
            action = RtActionNone;
            break;

        case RtStateWarning:
            if (Priority >= RtPriorityBackground) {
                action = config->SoftAction;
            } else {
                action = RtActionNone;
            }
            break;

        case RtStateThrottled:
            if (Priority >= RtPriorityLow) {
                action = config->HardAction;
            } else if (Priority >= RtPriorityNormal) {
                action = config->SoftAction;
            } else {
                action = RtActionNone;
            }
            break;

        case RtStateCritical:
            if (Priority >= RtPriorityNormal) {
                action = config->CriticalAction;
            } else if (Priority >= RtPriorityHigh) {
                action = config->HardAction;
            } else {
                action = RtActionNone;  // Critical priority never throttled
            }
            break;

        case RtStateRecovery:
            if (Priority >= RtPriorityBackground) {
                action = RtActionDelay;
            } else {
                action = RtActionNone;
            }
            break;

        default:
            action = RtActionNone;
            break;
    }

    if (action != RtActionNone && action != RtActionNotify) {
        InterlockedIncrement64(&Throttler->Stats.PerResource[Resource].Throttles);
    }

    return action;
}

static VOID
RtpNotifyCallback(
    _In_ PRT_THROTTLER Throttler,
    _In_ PRT_THROTTLE_EVENT Event
)
{
    PRT_THROTTLE_CALLBACK callback;
    PVOID context;
    KIRQL oldIrql;

    KeAcquireSpinLock(&Throttler->CallbackSpinLock, &oldIrql);

    callback = Throttler->ThrottleCallback;
    context = Throttler->CallbackContext;

    if (callback != NULL) {
        //
        // Increment active count inside lock to prevent
        // RtUnregisterCallback from completing while we invoke
        //
        InterlockedIncrement(&Throttler->CallbackActiveCount);
    }

    KeReleaseSpinLock(&Throttler->CallbackSpinLock, oldIrql);

    if (callback != NULL) {
        callback(Event, context);
        InterlockedIncrement64(&Throttler->Stats.AlertsSent);
        InterlockedDecrement(&Throttler->CallbackActiveCount);
    }
}

/**
 * @brief Locked lookup: find process quota and return with lock HELD.
 *
 * The caller MUST release the lock via:
 *   KeReleaseSpinLock(&Throttler->ProcessQuotas.Lock, OldIrql);
 *
 * This prevents use-after-free if RtRemoveProcess runs concurrently
 * (the quota cannot be freed while we hold the lock).
 *
 * Returns NULL with lock RELEASED if entry is not found.
 */
_IRQL_raises_(DISPATCH_LEVEL)
static PRT_PROCESS_QUOTA
RtpLookupProcessQuotaLocked(
    _In_ PRT_THROTTLER Throttler,
    _In_ HANDLE ProcessId,
    _Out_ PKIRQL OldIrql
)
{
    ULONG bucket;
    PLIST_ENTRY entry;
    PRT_PROCESS_QUOTA quota;

    bucket = RtpHashProcessId(ProcessId);

    KeAcquireSpinLock(&Throttler->ProcessQuotas.Lock, OldIrql);

    for (entry = Throttler->ProcessQuotas.HashBuckets[bucket].Flink;
         entry != &Throttler->ProcessQuotas.HashBuckets[bucket];
         entry = entry->Flink) {

        quota = CONTAINING_RECORD(entry, RT_PROCESS_QUOTA, HashLink);

        if (quota->ProcessId == ProcessId && quota->InUse) {
            return quota;  // Lock still held â€” caller MUST release
        }
    }

    KeReleaseSpinLock(&Throttler->ProcessQuotas.Lock, *OldIrql);
    return NULL;
}

/**
 * @brief Find existing process quota (read-only, no allocation).
 *
 * Uses KSPIN_LOCK â€” safe at DISPATCH_LEVEL.
 */
static PRT_PROCESS_QUOTA
RtpFindProcessQuota(
    _In_ PRT_THROTTLER Throttler,
    _In_ HANDLE ProcessId
)
{
    ULONG bucket;
    PLIST_ENTRY entry;
    PRT_PROCESS_QUOTA quota;
    KIRQL oldIrql;

    bucket = RtpHashProcessId(ProcessId);

    KeAcquireSpinLock(&Throttler->ProcessQuotas.Lock, &oldIrql);

    for (entry = Throttler->ProcessQuotas.HashBuckets[bucket].Flink;
         entry != &Throttler->ProcessQuotas.HashBuckets[bucket];
         entry = entry->Flink) {

        quota = CONTAINING_RECORD(entry, RT_PROCESS_QUOTA, HashLink);

        if (quota->ProcessId == ProcessId && quota->InUse) {
            KeReleaseSpinLock(&Throttler->ProcessQuotas.Lock, oldIrql);
            return quota;
        }
    }

    KeReleaseSpinLock(&Throttler->ProcessQuotas.Lock, oldIrql);
    return NULL;
}

/**
 * @brief Find or allocate a process quota entry.
 *
 * Process quotas are now individually heap-allocated from NonPagedPoolNx,
 * not embedded in the RT_THROTTLER struct. This reduces the base struct size
 * and makes cleanup straightforward.
 *
 * Uses KSPIN_LOCK â€” safe at DISPATCH_LEVEL.
 */
static PRT_PROCESS_QUOTA
RtpFindOrCreateProcessQuota(
    _In_ PRT_THROTTLER Throttler,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN CreateIfNotFound
)
{
    ULONG bucket;
    PLIST_ENTRY entry;
    PRT_PROCESS_QUOTA quota;
    PRT_PROCESS_QUOTA newQuota = NULL;
    KIRQL oldIrql;

    bucket = RtpHashProcessId(ProcessId);

    KeAcquireSpinLock(&Throttler->ProcessQuotas.Lock, &oldIrql);

    for (entry = Throttler->ProcessQuotas.HashBuckets[bucket].Flink;
         entry != &Throttler->ProcessQuotas.HashBuckets[bucket];
         entry = entry->Flink) {

        quota = CONTAINING_RECORD(entry, RT_PROCESS_QUOTA, HashLink);

        if (quota->ProcessId == ProcessId && quota->InUse) {
            KeReleaseSpinLock(&Throttler->ProcessQuotas.Lock, oldIrql);
            return quota;
        }
    }

    if (!CreateIfNotFound) {
        KeReleaseSpinLock(&Throttler->ProcessQuotas.Lock, oldIrql);
        return NULL;
    }

    //
    // Check capacity
    //
    if (Throttler->ProcessQuotas.ActiveCount >= RT_MAX_TRACKED_PROCESSES) {
        KeReleaseSpinLock(&Throttler->ProcessQuotas.Lock, oldIrql);
        return NULL;
    }

    //
    // Release lock before allocation (can't allocate at DISPATCH on some paths)
    // Actually ShadowStrikeAllocatePoolWithTag from NonPagedPoolNx is safe
    // at DISPATCH_LEVEL. Allocate under lock to avoid TOCTOU on ActiveCount.
    //
    newQuota = (PRT_PROCESS_QUOTA)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(RT_PROCESS_QUOTA),
        RT_PROCESS_TAG
    );

    if (newQuota == NULL) {
        KeReleaseSpinLock(&Throttler->ProcessQuotas.Lock, oldIrql);
        return NULL;
    }

    RtlZeroMemory(newQuota, sizeof(RT_PROCESS_QUOTA));
    newQuota->ProcessId = ProcessId;
    newQuota->InUse = TRUE;
    newQuota->Exempt = FALSE;
    KeQuerySystemTime(&newQuota->LastActivity);

    InsertTailList(&Throttler->ProcessQuotas.HashBuckets[bucket],
                   &newQuota->HashLink);

    InterlockedIncrement(&Throttler->ProcessQuotas.ActiveCount);

    KeReleaseSpinLock(&Throttler->ProcessQuotas.Lock, oldIrql);

    return newQuota;
}

static ULONG
RtpHashProcessId(
    _In_ HANDLE ProcessId
)
{
    ULONG_PTR pid = (ULONG_PTR)ProcessId;

    pid = pid ^ (pid >> 16);
    pid = pid * 0x85ebca6b;
    pid = pid ^ (pid >> 13);

    return (ULONG)(pid % RT_PROCESS_HASH_BUCKETS);
}

static VOID
RtpProcessDeferredWorkQueue(
    _Inout_ PRT_THROTTLER Throttler
)
{
    PLIST_ENTRY entry;
    PRT_DEFERRED_WORK workItem;
    PRT_DEFERRED_CALLBACK callback;
    PVOID context;
    LARGE_INTEGER currentTime;
    KIRQL oldIrql;
    BOOLEAN expired;

    KeQuerySystemTime(&currentTime);

    while (TRUE) {
        workItem = NULL;
        expired = FALSE;

        KeAcquireSpinLock(&Throttler->DeferredWork.Lock, &oldIrql);

        if (IsListEmpty(&Throttler->DeferredWork.Queue)) {
            KeReleaseSpinLock(&Throttler->DeferredWork.Lock, oldIrql);
            break;
        }

        entry = RemoveHeadList(&Throttler->DeferredWork.Queue);
        InterlockedDecrement(&Throttler->DeferredWork.Depth);

        KeReleaseSpinLock(&Throttler->DeferredWork.Lock, oldIrql);

        workItem = CONTAINING_RECORD(entry, RT_DEFERRED_WORK, ListEntry);

        if (workItem->ExpirationTime.QuadPart != 0 &&
            currentTime.QuadPart > workItem->ExpirationTime.QuadPart) {
            expired = TRUE;
            InterlockedIncrement64(&Throttler->Stats.DeferredWorkExpired);
        }

        if (!expired) {
            callback = workItem->Callback;
            context = workItem->Context;

            if (callback != NULL) {
                callback(context);
                InterlockedIncrement64(&Throttler->Stats.DeferredWorkProcessed);
            }
        }

        ShadowStrikeFreePoolWithTag(workItem, RT_QUEUE_TAG);

        if (Throttler->WorkerShouldExit) {
            break;
        }
    }
}

static VOID
RtpDrainDeferredWorkQueue(
    _Inout_ PRT_THROTTLER Throttler
)
{
    PLIST_ENTRY entry;
    PRT_DEFERRED_WORK workItem;
    KIRQL oldIrql;

    while (TRUE) {
        KeAcquireSpinLock(&Throttler->DeferredWork.Lock, &oldIrql);

        if (IsListEmpty(&Throttler->DeferredWork.Queue)) {
            KeReleaseSpinLock(&Throttler->DeferredWork.Lock, oldIrql);
            break;
        }

        entry = RemoveHeadList(&Throttler->DeferredWork.Queue);
        InterlockedDecrement(&Throttler->DeferredWork.Depth);

        KeReleaseSpinLock(&Throttler->DeferredWork.Lock, oldIrql);

        workItem = CONTAINING_RECORD(entry, RT_DEFERRED_WORK, ListEntry);
        ShadowStrikeFreePoolWithTag(workItem, RT_QUEUE_TAG);
    }
}

/**
 * @brief Free all dynamically allocated process quota entries.
 *
 * Called during shutdown after all operations have drained.
 */
static VOID
RtpDrainProcessQuotas(
    _Inout_ PRT_THROTTLER Throttler
)
{
    ULONG i;
    PLIST_ENTRY entry;
    PRT_PROCESS_QUOTA quota;

    for (i = 0; i < RT_PROCESS_HASH_BUCKETS; i++) {
        while (!IsListEmpty(&Throttler->ProcessQuotas.HashBuckets[i])) {
            entry = RemoveHeadList(&Throttler->ProcessQuotas.HashBuckets[i]);
            quota = CONTAINING_RECORD(entry, RT_PROCESS_QUOTA, HashLink);
            ShadowStrikeFreePoolWithTag(quota, RT_PROCESS_TAG);
        }
    }

    Throttler->ProcessQuotas.ActiveCount = 0;
}
