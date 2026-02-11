/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE ETW CONSUMER IMPLEMENTATION
 * ============================================================================
 *
 * @file ETWConsumer.c
 * @brief Enterprise-grade kernel event processing engine for EDR operations.
 *
 * Implements a high-performance event processing pipeline fed by kernel
 * callbacks (process, file, registry, network notify routines) via the
 * EcIngestEvent() API. Events are filtered through subscriptions, queued
 * by priority, and dispatched to registered callbacks on processing threads.
 *
 * All issues from the v2.0 security review have been resolved:
 * - Proper reference counting for subscription lifetime
 * - Correct KTIMER-based health monitoring
 * - Safe shutdown with deadlock prevention
 * - Modern ExAllocatePool2 API usage
 * - Rate limiting and event source determination wired in
 * - Round-robin thread signaling for true multi-threading
 * - Overflow-safe arithmetic throughout
 * - Structured logging via TelemetryEvents
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "ETWConsumer.h"
#include "TelemetryEvents.h"

// ============================================================================
// PRAGMA DIRECTIVES
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, EcInitialize)
#pragma alloc_text(PAGE, EcShutdown)
#pragma alloc_text(PAGE, EcStart)
#pragma alloc_text(PAGE, EcStop)
#pragma alloc_text(PAGE, EcPause)
#pragma alloc_text(PAGE, EcResume)
#pragma alloc_text(PAGE, EcSubscribe)
#pragma alloc_text(PAGE, EcSubscribeByGuid)
#pragma alloc_text(PAGE, EcUnsubscribe)
#pragma alloc_text(PAGE, EcResetStatistics)
#pragma alloc_text(PAGE, EcSubscribeKernelProcess)
#pragma alloc_text(PAGE, EcSubscribeKernelFile)
#pragma alloc_text(PAGE, EcSubscribeKernelNetwork)
#pragma alloc_text(PAGE, EcSubscribeKernelRegistry)
#pragma alloc_text(PAGE, EcSubscribeSecurityAuditing)
#pragma alloc_text(PAGE, EcSubscribeThreatIntelligence)
#endif

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

#define EC_SESSION_NAME_PREFIX      L"ShadowStrike-ETW-Consumer-"
#define EC_SESSION_BUFFER_SIZE_KB   64
#define EC_SESSION_MIN_BUFFERS      4
#define EC_SESSION_MAX_BUFFERS      64
#define EC_SESSION_FLUSH_TIMER      1
#define EC_MAX_CONSECUTIVE_ERRORS   10
#define EC_THREAD_WAIT_TIMEOUT_MS   1000

/**
 * @brief Health check timer period in 100-nanosecond units (negative = relative).
 *        EC_HEALTH_CHECK_INTERVAL_SEC seconds.
 */
#define EC_HEALTH_TIMER_PERIOD_100NS  (-(LONGLONG)EC_HEALTH_CHECK_INTERVAL_SEC * 10LL * 1000 * 1000)

// ============================================================================
// INTERNAL HELPER FUNCTIONS - FORWARD DECLARATIONS
// ============================================================================

static VOID EcpInitializeDefaultConfig(_Out_ PEC_CONSUMER_CONFIG Config);
static VOID EcpInitializeLookasideLists(_Inout_ PEC_CONSUMER Consumer);
static VOID EcpCleanupLookasideLists(_Inout_ PEC_CONSUMER Consumer);
static NTSTATUS EcpStartProcessingThreads(_Inout_ PEC_CONSUMER Consumer);
static VOID EcpStopProcessingThreads(_Inout_ PEC_CONSUMER Consumer);
static VOID EcpProcessingThreadRoutine(_In_ PVOID Context);
static NTSTATUS EcpProcessEventBatch(_In_ PEC_CONSUMER Consumer, _In_ ULONG ThreadIndex);
static PEC_EVENT_RECORD EcpDequeueEvent(_In_ PEC_CONSUMER Consumer);
static VOID EcpEnqueueEvent(_In_ PEC_CONSUMER Consumer, _Inout_ PEC_EVENT_RECORD Record);
static VOID EcpDrainEventQueues(_Inout_ PEC_CONSUMER Consumer);
static VOID EcpFreeAllSubscriptions(_Inout_ PEC_CONSUMER Consumer);
static VOID EcpMarkSubscriptionRegistered(_Inout_ PEC_SUBSCRIPTION Subscription);
static VOID EcpMarkSubscriptionUnregistered(_Inout_ PEC_SUBSCRIPTION Subscription);
static VOID EcpUpdateSubscriptionState(_Inout_ PEC_SUBSCRIPTION Subscription, _In_ EC_SUBSCRIPTION_STATE NewState);
static BOOLEAN EcpCheckRateLimit(_Inout_ PEC_CONSUMER Consumer);
static VOID EcpUpdateFlowControl(_Inout_ PEC_CONSUMER Consumer);
static VOID EcpHealthCheckDpcRoutine(_In_ PKDPC Dpc, _In_opt_ PVOID Context, _In_opt_ PVOID Arg1, _In_opt_ PVOID Arg2);
static EC_EVENT_SOURCE EcpDetermineEventSource(_In_ LPCGUID ProviderId);
static VOID EcpFreeExtendedData(_In_ PEC_CONSUMER Consumer, _Inout_ PEC_EVENT_RECORD Record);
static VOID EcpReferenceSubscription(_Inout_ PEC_SUBSCRIPTION Subscription);
static VOID EcpDereferenceSubscription(_Inout_ PEC_SUBSCRIPTION Subscription);
static VOID EcpSignalProcessingThread(_In_ PEC_CONSUMER Consumer);
static BOOLEAN EcpValidateCallbackAddress(_In_ PVOID Address);

// ============================================================================
// SUBSCRIPTION REFERENCE COUNTING
// ============================================================================

/**
 * @brief Increment subscription reference count.
 */
static
VOID
EcpReferenceSubscription(
    _Inout_ PEC_SUBSCRIPTION Subscription
    )
{
    LONG OldRef;

    NT_ASSERT(Subscription != NULL);

    OldRef = InterlockedIncrement(&Subscription->RefCount);
    NT_ASSERT(OldRef > 1);  // Must not reference a zero-refcount object
    UNREFERENCED_PARAMETER(OldRef);
}

/**
 * @brief Decrement subscription reference count.
 *
 * When the reference count reaches zero and UnsubscribePending is set,
 * the subscription is freed. This ensures no use-after-free when events
 * hold references to subscriptions that have been unsubscribed.
 */
static
VOID
EcpDereferenceSubscription(
    _Inout_ PEC_SUBSCRIPTION Subscription
    )
{
    LONG NewRef;

    NT_ASSERT(Subscription != NULL);
    NT_ASSERT(Subscription->RefCount > 0);

    NewRef = InterlockedDecrement(&Subscription->RefCount);
    NT_ASSERT(NewRef >= 0);

    if (NewRef == 0) {
        //
        // Only free if unsubscribe has been requested.
        // The InterlockedDecrement provides a full memory barrier,
        // so the read of UnsubscribePending is ordered after the
        // decrement.
        //
        if (InterlockedCompareExchange(&Subscription->UnsubscribePending, 0, 0)) {
            ExFreePoolWithTag(Subscription, EC_SUBSCRIPTION_TAG);
        }
    }
}

/**
 * @brief Signal a processing thread using round-robin distribution.
 *
 * NextThreadSignal is a monotonically incrementing counter. It will
 * overflow from LONG_MAX to LONG_MIN after ~2 billion calls. This is
 * safe because we cast to ULONG before the modulo operation, which
 * makes the wrap-around produce valid indices continuously.
 */
static
VOID
EcpSignalProcessingThread(
    _In_ PEC_CONSUMER Consumer
    )
{
    ULONG ThreadCount;
    LONG Index;

    ThreadCount = Consumer->ActiveThreadCount;
    if (ThreadCount == 0) {
        return;
    }

    Index = InterlockedIncrement(&Consumer->NextThreadSignal);
    //
    // Modulo to distribute across threads. Use unsigned to avoid negative modulo.
    //
    Index = (LONG)((ULONG)Index % ThreadCount);

    KeSetEvent(
        &Consumer->ProcessingThreads[Index].WorkEvent,
        IO_NO_INCREMENT,
        FALSE
    );
}

// ============================================================================
// INITIALIZATION AND LIFECYCLE
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EcInitialize(
    _In_opt_ PEC_CONSUMER_CONFIG Config,
    _Out_ PEC_CONSUMER* Consumer
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    PEC_CONSUMER NewConsumer = NULL;
    EC_CONSUMER_CONFIG DefaultConfig;
    ULONG i;

    PAGED_CODE();

    if (Consumer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Consumer = NULL;

    //
    // Allocate consumer structure (ExAllocatePool2 returns zeroed memory)
    //
    NewConsumer = (PEC_CONSUMER)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(EC_CONSUMER),
        EC_POOL_TAG
    );

    if (NewConsumer == NULL) {
        TE_LOG_ERROR(Component_ETWProvider, STATUS_INSUFFICIENT_RESOURCES,
                     ErrorSeverity_Critical, L"Failed to allocate ETW consumer structure");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize configuration
    //
    if (Config != NULL) {
        RtlCopyMemory(&NewConsumer->Config, Config, sizeof(EC_CONSUMER_CONFIG));
    } else {
        EcpInitializeDefaultConfig(&DefaultConfig);
        RtlCopyMemory(&NewConsumer->Config, &DefaultConfig, sizeof(EC_CONSUMER_CONFIG));
    }

    //
    // Validate and clamp configuration
    //
    if (NewConsumer->Config.MaxBufferedEvents == 0) {
        NewConsumer->Config.MaxBufferedEvents = EC_MAX_BUFFERED_EVENTS;
    }
    if (NewConsumer->Config.BufferThreshold == 0) {
        NewConsumer->Config.BufferThreshold = EC_DEFAULT_BUFFER_THRESHOLD;
    }
    if (NewConsumer->Config.ProcessingThreadCount == 0) {
        NewConsumer->Config.ProcessingThreadCount = EC_DEFAULT_THREAD_COUNT;
    }
    if (NewConsumer->Config.ProcessingThreadCount > EC_MAX_THREAD_COUNT) {
        NewConsumer->Config.ProcessingThreadCount = EC_MAX_THREAD_COUNT;
    }

    //
    // Initialize subscription list
    //
    InitializeListHead(&NewConsumer->SubscriptionList);
    KeInitializeSpinLock(&NewConsumer->SubscriptionLock);
    NewConsumer->SubscriptionCount = 0;
    NewConsumer->NextSubscriptionId = 1;

    //
    // Initialize event queues (one per priority level)
    //
    for (i = 0; i < EC_PRIORITY_QUEUE_COUNT; i++) {
        InitializeListHead(&NewConsumer->EventQueues[i]);
    }
    KeInitializeSpinLock(&NewConsumer->EventQueueLock);
    NewConsumer->BufferedEventCount = 0;

    //
    // Initialize synchronization events
    //
    KeInitializeEvent(&NewConsumer->StopEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&NewConsumer->FlowResumeEvent, NotificationEvent, TRUE);

    //
    // Initialize rate limiting
    //
    KeInitializeSpinLock(&NewConsumer->RateLimitLock);
    NewConsumer->EventsThisSecond = 0;
    KeQuerySystemTimePrecise(&NewConsumer->CurrentSecondStart);

    //
    // Initialize lookaside lists (cannot fail — ExInitializeNPagedLookasideList is void)
    //
    EcpInitializeLookasideLists(NewConsumer);

    //
    // Initialize health check timer and DPC (proper KTIMER, not HANDLE)
    //
    KeInitializeTimer(&NewConsumer->HealthCheckTimer);
    KeInitializeDpc(&NewConsumer->HealthCheckDpc, EcpHealthCheckDpcRoutine, NewConsumer);
    NewConsumer->HealthTimerActive = FALSE;

    //
    // Initialize round-robin thread signal counter
    //
    NewConsumer->NextThreadSignal = -1;

    //
    // Initialize statistics
    //
    KeQuerySystemTimePrecise(&NewConsumer->Stats.StartTime);
    NewConsumer->Stats.IsHealthy = TRUE;

    //
    // Set initial state
    //
    InterlockedExchange(&NewConsumer->State, (LONG)EcState_Initialized);
    InterlockedExchange(&NewConsumer->CurrentFlowState, (LONG)EcFlow_Normal);
    NewConsumer->Initialized = TRUE;

    *Consumer = NewConsumer;

    TE_LOG_INFO(Component_ETWProvider, L"ETW consumer initialized successfully");

    //
    // Auto-start if configured
    //
    if (NewConsumer->Config.AutoStart) {
        Status = EcStart(NewConsumer);
        if (!NT_SUCCESS(Status)) {
            TE_LOG_ERROR(Component_ETWProvider, Status,
                         ErrorSeverity_Error, L"Auto-start failed, shutting down consumer");
            EcShutdown(&NewConsumer);
            *Consumer = NULL;
            return Status;
        }
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
EcShutdown(
    _Inout_ PEC_CONSUMER* Consumer
    )
{
    PEC_CONSUMER Ctx;
    LONG State;

    PAGED_CODE();

    if (Consumer == NULL || *Consumer == NULL) {
        return;
    }

    Ctx = *Consumer;

    if (!Ctx->Initialized) {
        *Consumer = NULL;
        return;
    }

    //
    // Stop if running (this stops threads and waits for them to exit)
    //
    State = InterlockedCompareExchange(&Ctx->State, 0, 0);
    if (State == (LONG)EcState_Running ||
        State == (LONG)EcState_Paused) {
        EcStop(Ctx);
    }

    InterlockedExchange(&Ctx->State, (LONG)EcState_Stopping);

    //
    // Cancel health check timer and flush any pending DPC
    //
    if (Ctx->HealthTimerActive) {
        KeCancelTimer(&Ctx->HealthCheckTimer);
        KeFlushQueuedDpcs();
        Ctx->HealthTimerActive = FALSE;
    }

    //
    // CRITICAL: Drain event queues FIRST. Each queued event holds a reference
    // to a subscription. We must release all those references before
    // freeing subscriptions, or we get use-after-free.
    //
    EcpDrainEventQueues(Ctx);

    //
    // Now safe to release all subscriptions (no more event references)
    //
    EcpFreeAllSubscriptions(Ctx);

    //
    // Cleanup lookaside lists
    //
    EcpCleanupLookasideLists(Ctx);

    //
    // Mark as stopped
    //
    InterlockedExchange(&Ctx->State, (LONG)EcState_Stopped);
    Ctx->Initialized = FALSE;

    TE_LOG_INFO(Component_ETWProvider, L"ETW consumer shut down");

    //
    // Free consumer structure and NULL the caller's pointer
    //
    ExFreePoolWithTag(Ctx, EC_POOL_TAG);
    *Consumer = NULL;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EcStart(
    _Inout_ PEC_CONSUMER Consumer
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    PLIST_ENTRY Entry;
    PEC_SUBSCRIPTION Subscription;
    LARGE_INTEGER DueTime;
    KIRQL OldIrql;
    LONG State;

    PAGED_CODE();

    if (Consumer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Consumer->Initialized) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    State = InterlockedCompareExchange(&Consumer->State, 0, 0);

    if (State == (LONG)EcState_Running) {
        return STATUS_SUCCESS;
    }

    if (State != (LONG)EcState_Initialized &&
        State != (LONG)EcState_Stopped) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    InterlockedExchange(&Consumer->State, (LONG)EcState_Starting);

    //
    // Reset stop event
    //
    KeClearEvent(&Consumer->StopEvent);

    //
    // Reset statistics (use interlocked for volatile fields)
    //
    KeQuerySystemTimePrecise(&Consumer->Stats.StartTime);
    InterlockedExchange64(&Consumer->Stats.TotalEventsReceived, 0);
    InterlockedExchange64(&Consumer->Stats.TotalEventsProcessed, 0);
    InterlockedExchange64(&Consumer->Stats.TotalEventsDropped, 0);
    InterlockedExchange(&Consumer->Stats.CurrentBufferedEvents, 0);
    InterlockedExchange64(&Consumer->Stats.TotalErrors, 0);
    InterlockedExchange(&Consumer->ConsecutiveErrors, 0);

    //
    // Start processing threads
    //
    Status = EcpStartProcessingThreads(Consumer);
    if (!NT_SUCCESS(Status)) {
        TE_LOG_ERROR(Component_ETWProvider, Status,
                     ErrorSeverity_Error, L"Failed to start processing threads");
        InterlockedExchange(&Consumer->State, (LONG)EcState_Error);
        Consumer->LastError = Status;
        return Status;
    }

    //
    // Activate all auto-start subscriptions under EXCLUSIVE spin lock
    // (we are WRITING subscription state)
    //
    KeAcquireSpinLock(&Consumer->SubscriptionLock, &OldIrql);

    Entry = Consumer->SubscriptionList.Flink;
    while (Entry != &Consumer->SubscriptionList) {
        Subscription = CONTAINING_RECORD(Entry, EC_SUBSCRIPTION, ListEntry);
        Entry = Entry->Flink;

        if (Subscription->Config.AutoStart &&
            InterlockedCompareExchange(&Subscription->State, 0, 0) == (LONG)EcSubState_Inactive) {
            InterlockedExchange(&Subscription->State, (LONG)EcSubState_Active);
        }
    }

    KeReleaseSpinLock(&Consumer->SubscriptionLock, OldIrql);

    //
    // Start health check timer (periodic, using KTIMER)
    //
    DueTime.QuadPart = EC_HEALTH_TIMER_PERIOD_100NS;
    KeSetTimerEx(
        &Consumer->HealthCheckTimer,
        DueTime,
        EC_HEALTH_CHECK_INTERVAL_SEC * 1000,  // Period in ms
        &Consumer->HealthCheckDpc
    );
    Consumer->HealthTimerActive = TRUE;

    InterlockedExchange(&Consumer->State, (LONG)EcState_Running);
    Consumer->Stats.IsHealthy = TRUE;

    TE_LOG_INFO(Component_ETWProvider, L"ETW consumer started");

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
EcStop(
    _Inout_ PEC_CONSUMER Consumer
    )
{
    PLIST_ENTRY Entry;
    PEC_SUBSCRIPTION Subscription;
    KIRQL OldIrql;
    LONG State;

    PAGED_CODE();

    if (Consumer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    State = InterlockedCompareExchange(&Consumer->State, 0, 0);
    if (State != (LONG)EcState_Running &&
        State != (LONG)EcState_Paused) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    InterlockedExchange(&Consumer->State, (LONG)EcState_Stopping);

    //
    // Cancel health check timer and flush any pending DPC before thread teardown
    //
    if (Consumer->HealthTimerActive) {
        KeCancelTimer(&Consumer->HealthCheckTimer);
        KeFlushQueuedDpcs();
        Consumer->HealthTimerActive = FALSE;
    }

    //
    // Signal stop event
    //
    KeSetEvent(&Consumer->StopEvent, IO_NO_INCREMENT, FALSE);

    //
    // Signal FlowResumeEvent to unblock any threads waiting on pause.
    // This prevents the deadlock where stop is called while paused.
    //
    KeSetEvent(&Consumer->FlowResumeEvent, IO_NO_INCREMENT, FALSE);

    //
    // Stop all processing threads (waits indefinitely for exit)
    //
    EcpStopProcessingThreads(Consumer);

    //
    // Deactivate all subscriptions under spin lock (writing state)
    //
    KeAcquireSpinLock(&Consumer->SubscriptionLock, &OldIrql);

    Entry = Consumer->SubscriptionList.Flink;
    while (Entry != &Consumer->SubscriptionList) {
        Subscription = CONTAINING_RECORD(Entry, EC_SUBSCRIPTION, ListEntry);
        Entry = Entry->Flink;

        if (InterlockedCompareExchange(&Subscription->State, 0, 0) == (LONG)EcSubState_Active) {
            InterlockedExchange(&Subscription->State, (LONG)EcSubState_Inactive);
        }
    }

    KeReleaseSpinLock(&Consumer->SubscriptionLock, OldIrql);

    InterlockedExchange(&Consumer->State, (LONG)EcState_Stopped);

    TE_LOG_INFO(Component_ETWProvider, L"ETW consumer stopped");

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
EcPause(
    _Inout_ PEC_CONSUMER Consumer
    )
{
    LONG OldState;

    PAGED_CODE();

    if (Consumer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Atomically transition Running → Paused.
    // Clear the resume event BEFORE setting state to prevent the race
    // where a thread sees Paused but the event is still signaled.
    //
    OldState = InterlockedCompareExchange(
        &Consumer->State,
        (LONG)EcState_Paused,
        (LONG)EcState_Running
    );

    if (OldState != (LONG)EcState_Running) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    KeClearEvent(&Consumer->FlowResumeEvent);

    TE_LOG_INFO(Component_ETWProvider, L"ETW consumer paused");

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
EcResume(
    _Inout_ PEC_CONSUMER Consumer
    )
{
    LONG OldState;
    ULONG i;

    PAGED_CODE();

    if (Consumer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Atomically transition Paused → Running.
    // Set the resume event AFTER state transition so threads see
    // Running when they wake.
    //
    OldState = InterlockedCompareExchange(
        &Consumer->State,
        (LONG)EcState_Running,
        (LONG)EcState_Paused
    );

    if (OldState != (LONG)EcState_Paused) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    KeSetEvent(&Consumer->FlowResumeEvent, IO_NO_INCREMENT, FALSE);

    //
    // Signal work events to resume processing
    //
    for (i = 0; i < Consumer->ActiveThreadCount; i++) {
        KeSetEvent(&Consumer->ProcessingThreads[i].WorkEvent, IO_NO_INCREMENT, FALSE);
    }

    TE_LOG_INFO(Component_ETWProvider, L"ETW consumer resumed");

    return STATUS_SUCCESS;
}

// ============================================================================
// EVENT INGESTION
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
EcIngestEvent(
    _Inout_ PEC_CONSUMER Consumer,
    _Inout_ PEC_EVENT_RECORD Record
    )
{
    PLIST_ENTRY Entry;
    PEC_SUBSCRIPTION Sub;
    PEC_SUBSCRIPTION MatchedSub = NULL;
    BOOLEAN Filtered;
    KIRQL OldIrql;

    if (Consumer == NULL || Record == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(&Consumer->State, 0, 0) != (LONG)EcState_Running) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    //
    // Rate limiting check
    //
    if (!EcpCheckRateLimit(Consumer)) {
        InterlockedIncrement64(&Consumer->Stats.TotalEventsDropped);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Determine event source from provider GUID
    //
    Record->Source = EcpDetermineEventSource(&Record->Header.ProviderId);

    //
    // Stamp receive time
    //
    KeQuerySystemTimePrecise(&Record->ReceiveTime);

    //
    // Find matching subscription under spin lock (DISPATCH_LEVEL safe).
    // Note: Filter callbacks are invoked under the spin lock. They MUST
    // be fast and non-blocking. This is documented in the callback contract.
    //
    KeAcquireSpinLock(&Consumer->SubscriptionLock, &OldIrql);

    Entry = Consumer->SubscriptionList.Flink;
    while (Entry != &Consumer->SubscriptionList) {
        Sub = CONTAINING_RECORD(Entry, EC_SUBSCRIPTION, ListEntry);
        Entry = Entry->Flink;

        if (InterlockedCompareExchange(&Sub->State, 0, 0) != (LONG)EcSubState_Active) {
            continue;
        }

        //
        // Match by provider GUID
        //
        if (!EcIsEqualGuid(&Sub->Config.ProviderFilter.ProviderId,
                           &Record->Header.ProviderId)) {
            continue;
        }

        //
        // Check keyword filters
        //
        if (Sub->Config.ProviderFilter.MatchAnyKeyword != 0 &&
            (Record->Header.Keywords & Sub->Config.ProviderFilter.MatchAnyKeyword) == 0) {
            continue;
        }

        if (Sub->Config.ProviderFilter.MatchAllKeyword != 0 &&
            (Record->Header.Keywords & Sub->Config.ProviderFilter.MatchAllKeyword)
             != Sub->Config.ProviderFilter.MatchAllKeyword) {
            continue;
        }

        //
        // Check level filter
        //
        if (Sub->Config.ProviderFilter.MaxLevel != 0 &&
            Record->Header.Level > Sub->Config.ProviderFilter.MaxLevel) {
            continue;
        }

        //
        // Apply pre-filter callback if configured.
        // Callbacks run at DISPATCH_LEVEL and must be non-blocking.
        //
        if (Sub->Config.FilterCallback != NULL) {
            Filtered = FALSE;
            __try {
                Filtered = !Sub->Config.FilterCallback(
                    &Record->Header.ProviderId,
                    Record->Header.EventId,
                    Record->Header.Level,
                    Record->Header.Keywords,
                    Sub->Config.FilterCallbackContext
                );
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {
                InterlockedIncrement64(&Sub->Stats.FilterErrors);
                Filtered = FALSE;
            }

            if (Filtered) {
                InterlockedIncrement64(&Sub->Stats.EventsFiltered);
                continue;
            }
        }

        //
        // Found a match — reference the subscription while holding lock
        // to prevent it from being freed between match and reference.
        //
        EcpReferenceSubscription(Sub);
        MatchedSub = Sub;
        break;
    }

    KeReleaseSpinLock(&Consumer->SubscriptionLock, OldIrql);

    if (MatchedSub == NULL) {
        //
        // No matching subscription — caller retains ownership
        //
        return STATUS_NOT_FOUND;
    }

    //
    // Assign subscription and priority to record
    //
    Record->Subscription = MatchedSub;
    Record->Priority = MatchedSub->Config.Priority;
    Record->SequenceNumber = (ULONG)InterlockedIncrement64(&MatchedSub->SequenceNumber);

    InterlockedIncrement64(&Consumer->Stats.TotalEventsReceived);
    InterlockedIncrement64(&MatchedSub->Stats.EventsReceived);
    KeQuerySystemTimePrecise(&MatchedSub->Stats.LastEventTime);

    //
    // Enqueue the event (ownership transfers here)
    //
    EcpEnqueueEvent(Consumer, Record);

    return STATUS_SUCCESS;
}

// ============================================================================
// SUBSCRIPTION MANAGEMENT
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EcSubscribe(
    _Inout_ PEC_CONSUMER Consumer,
    _In_ PEC_SUBSCRIPTION_CONFIG Config,
    _Out_ PEC_SUBSCRIPTION* Subscription
    )
{
    PEC_SUBSCRIPTION NewSub = NULL;
    KIRQL OldIrql;

    PAGED_CODE();

    if (Consumer == NULL || Config == NULL || Subscription == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Config->EventCallback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate callback addresses are in kernel address space
    //
    if (!EcpValidateCallbackAddress((PVOID)Config->EventCallback)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Config->FilterCallback != NULL &&
        !EcpValidateCallbackAddress((PVOID)Config->FilterCallback)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Config->StatusCallback != NULL &&
        !EcpValidateCallbackAddress((PVOID)Config->StatusCallback)) {
        return STATUS_INVALID_PARAMETER;
    }

    *Subscription = NULL;

    //
    // Allocate subscription (ExAllocatePool2 returns zeroed memory)
    //
    NewSub = (PEC_SUBSCRIPTION)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(EC_SUBSCRIPTION),
        EC_SUBSCRIPTION_TAG
    );

    if (NewSub == NULL) {
        TE_LOG_ERROR(Component_ETWProvider, STATUS_INSUFFICIENT_RESOURCES,
                     ErrorSeverity_Error, L"Failed to allocate subscription");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize subscription
    //
    NewSub->SubscriptionId = (ULONG)InterlockedIncrement(&Consumer->NextSubscriptionId);
    NewSub->Consumer = Consumer;
    NewSub->RefCount = 1;
    InterlockedExchange(&NewSub->UnsubscribePending, FALSE);
    InterlockedExchange(&NewSub->IsInList, FALSE);

    //
    // Copy configuration
    //
    RtlCopyMemory(&NewSub->Config, Config, sizeof(EC_SUBSCRIPTION_CONFIG));

    //
    // Set initial state
    //
    InterlockedExchange(&NewSub->State, (LONG)EcSubState_Inactive);

    //
    // Add to subscription list under spin lock FIRST, then mark registered.
    // This ensures the subscription is always in the list when registered,
    // preventing the TOCTOU where registration succeeds but list-add fails.
    //
    KeAcquireSpinLock(&Consumer->SubscriptionLock, &OldIrql);

    if ((ULONG)Consumer->SubscriptionCount >= EC_MAX_SUBSCRIPTIONS) {
        KeReleaseSpinLock(&Consumer->SubscriptionLock, OldIrql);
        ExFreePoolWithTag(NewSub, EC_SUBSCRIPTION_TAG);
        TE_LOG_WARNING(Component_ETWProvider, L"Subscription limit reached");
        return STATUS_QUOTA_EXCEEDED;
    }

    InsertTailList(&Consumer->SubscriptionList, &NewSub->ListEntry);
    InterlockedExchange(&NewSub->IsInList, TRUE);
    InterlockedIncrement(&Consumer->SubscriptionCount);

    KeReleaseSpinLock(&Consumer->SubscriptionLock, OldIrql);

    //
    // Mark registered and activate if appropriate
    //
    if (InterlockedCompareExchange(&Consumer->State, 0, 0) == (LONG)EcState_Running &&
        Config->AutoStart) {
        EcpMarkSubscriptionRegistered(NewSub);
        InterlockedExchange(&NewSub->State, (LONG)EcSubState_Active);
    }

    *Subscription = NewSub;

    TE_LOG_INFO(Component_ETWProvider, L"Subscription registered successfully");

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EcSubscribeByGuid(
    _Inout_ PEC_CONSUMER Consumer,
    _In_ LPCGUID ProviderId,
    _In_ ULONGLONG Keywords,
    _In_ UCHAR Level,
    _In_ EC_EVENT_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ PEC_SUBSCRIPTION* Subscription
    )
{
    EC_SUBSCRIPTION_CONFIG Config;

    PAGED_CODE();

    if (Consumer == NULL || ProviderId == NULL ||
        Callback == NULL || Subscription == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&Config, sizeof(Config));

    RtlCopyMemory(&Config.ProviderFilter.ProviderId, ProviderId, sizeof(GUID));
    Config.ProviderFilter.MatchAnyKeyword = Keywords;
    Config.ProviderFilter.MatchAllKeyword = 0;
    Config.ProviderFilter.MaxLevel = Level;

    Config.EventCallback = Callback;
    Config.EventCallbackContext = Context;
    Config.Priority = EcPriority_Normal;
    Config.AutoStart = TRUE;

    return EcSubscribe(Consumer, &Config, Subscription);
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
EcUnsubscribe(
    _Inout_ PEC_CONSUMER Consumer,
    _Inout_ PEC_SUBSCRIPTION Subscription
    )
{
    KIRQL OldIrql;

    PAGED_CODE();

    if (Consumer == NULL || Subscription == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Subscription->Consumer != Consumer) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Mark as unregistered
    //
    if (Subscription->IsRegistered) {
        EcpMarkSubscriptionUnregistered(Subscription);
    }

    //
    // Deactivate the subscription so no new events match it
    //
    InterlockedExchange(&Subscription->State, (LONG)EcSubState_Inactive);

    //
    // Remove from list under spin lock with double-remove protection
    //
    KeAcquireSpinLock(&Consumer->SubscriptionLock, &OldIrql);

    if (InterlockedCompareExchange(&Subscription->IsInList, FALSE, TRUE)) {
        RemoveEntryList(&Subscription->ListEntry);
        InitializeListHead(&Subscription->ListEntry);
        InterlockedDecrement(&Consumer->SubscriptionCount);
    }

    KeReleaseSpinLock(&Consumer->SubscriptionLock, OldIrql);

    //
    // Mark unsubscribe pending and release our creation reference.
    // If refcount reaches 0, the subscription is freed immediately.
    // If outstanding event records still hold references, the
    // subscription will be freed when the last reference is released.
    //
    InterlockedExchange(&Subscription->UnsubscribePending, TRUE);
    EcpDereferenceSubscription(Subscription);

    TE_LOG_INFO(Component_ETWProvider, L"Subscription unregistered");

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
EcActivateSubscription(
    _Inout_ PEC_SUBSCRIPTION Subscription
    )
{
    if (Subscription == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(&Subscription->State, 0, 0) == (LONG)EcSubState_Active) {
        return STATUS_SUCCESS;
    }

    EcpUpdateSubscriptionState(Subscription, EcSubState_Active);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
EcSuspendSubscription(
    _Inout_ PEC_SUBSCRIPTION Subscription
    )
{
    if (Subscription == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(&Subscription->State, 0, 0) == (LONG)EcSubState_Suspended) {
        return STATUS_SUCCESS;
    }

    EcpUpdateSubscriptionState(Subscription, EcSubState_Suspended);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
EcFindSubscription(
    _In_ PEC_CONSUMER Consumer,
    _In_ LPCGUID ProviderId,
    _Out_ PEC_SUBSCRIPTION* Subscription
    )
{
    PLIST_ENTRY Entry;
    PEC_SUBSCRIPTION Sub;
    KIRQL OldIrql;

    if (Consumer == NULL || ProviderId == NULL || Subscription == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Subscription = NULL;

    KeAcquireSpinLock(&Consumer->SubscriptionLock, &OldIrql);

    Entry = Consumer->SubscriptionList.Flink;
    while (Entry != &Consumer->SubscriptionList) {
        Sub = CONTAINING_RECORD(Entry, EC_SUBSCRIPTION, ListEntry);

        if (EcIsEqualGuid(&Sub->Config.ProviderFilter.ProviderId, ProviderId)) {
            //
            // Increment refcount while holding lock to prevent races
            //
            EcpReferenceSubscription(Sub);
            *Subscription = Sub;
            KeReleaseSpinLock(&Consumer->SubscriptionLock, OldIrql);
            return STATUS_SUCCESS;
        }

        Entry = Entry->Flink;
    }

    KeReleaseSpinLock(&Consumer->SubscriptionLock, OldIrql);

    return STATUS_NOT_FOUND;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EcReleaseSubscription(
    _In_ PEC_SUBSCRIPTION Subscription
    )
{
    if (Subscription != NULL) {
        EcpDereferenceSubscription(Subscription);
    }
}

// ============================================================================
// EVENT RECORD MANAGEMENT
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
PEC_EVENT_RECORD
EcAllocateEventRecord(
    _In_ PEC_CONSUMER Consumer
    )
{
    PEC_EVENT_RECORD Record;

    if (Consumer == NULL || !Consumer->LookasideInitialized) {
        return NULL;
    }

    Record = (PEC_EVENT_RECORD)ExAllocateFromNPagedLookasideList(
        &Consumer->EventRecordLookaside
    );

    if (Record != NULL) {
        RtlZeroMemory(Record, sizeof(EC_EVENT_RECORD));
        InitializeListHead(&Record->ExtendedDataList);
        Record->IsAllocated = TRUE;
        Record->IsPooled = TRUE;
    }

    return Record;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EcFreeEventRecord(
    _In_ PEC_CONSUMER Consumer,
    _Inout_ PEC_EVENT_RECORD Record
    )
{
    if (Consumer == NULL || Record == NULL) {
        return;
    }

    //
    // Release subscription reference if held
    //
    if (Record->Subscription != NULL) {
        EcpDereferenceSubscription(Record->Subscription);
        Record->Subscription = NULL;
    }

    //
    // Free extended data (pass Consumer for lookaside access)
    //
    EcpFreeExtendedData(Consumer, Record);

    //
    // Free user data if allocated
    //
    if (Record->UserData != NULL && Record->IsAllocated) {
        ExFreePoolWithTag(Record->UserData, EC_BUFFER_TAG);
        Record->UserData = NULL;
    }

    //
    // Return to lookaside or free
    //
    if (Record->IsPooled && Consumer->LookasideInitialized) {
        ExFreeToNPagedLookasideList(&Consumer->EventRecordLookaside, Record);
    } else {
        ExFreePoolWithTag(Record, EC_EVENT_TAG);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
EcCloneEventRecord(
    _In_ PEC_CONSUMER Consumer,
    _In_ PEC_EVENT_RECORD Source,
    _Out_ PEC_EVENT_RECORD* Clone
    )
{
    PEC_EVENT_RECORD NewRecord;
    PLIST_ENTRY Entry;
    PEC_EXTENDED_DATA SrcExt;
    PEC_EXTENDED_DATA NewExt;

    if (Consumer == NULL || Source == NULL || Clone == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Clone = NULL;

    NewRecord = EcAllocateEventRecord(Consumer);
    if (NewRecord == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Copy header and metadata
    //
    RtlCopyMemory(&NewRecord->Header, &Source->Header, sizeof(EC_EVENT_HEADER));
    NewRecord->Priority = Source->Priority;
    NewRecord->Source = Source->Source;
    NewRecord->SequenceNumber = Source->SequenceNumber;
    NewRecord->CorrelationId = Source->CorrelationId;
    NewRecord->IsCorrelated = Source->IsCorrelated;

    //
    // Reference the subscription for the clone
    //
    if (Source->Subscription != NULL) {
        EcpReferenceSubscription(Source->Subscription);
        NewRecord->Subscription = Source->Subscription;
    }

    //
    // Clone user data if present
    //
    if (Source->UserData != NULL && Source->UserDataLength > 0) {
        if (Source->UserDataLength > EC_MAX_EVENT_DATA_SIZE) {
            EcFreeEventRecord(Consumer, NewRecord);
            return STATUS_BUFFER_OVERFLOW;
        }

        NewRecord->UserData = ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            Source->UserDataLength,
            EC_BUFFER_TAG
        );

        if (NewRecord->UserData == NULL) {
            EcFreeEventRecord(Consumer, NewRecord);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(NewRecord->UserData, Source->UserData, Source->UserDataLength);
        NewRecord->UserDataLength = Source->UserDataLength;
        NewRecord->IsAllocated = TRUE;
    }

    //
    // Clone extended data items
    //
    Entry = Source->ExtendedDataList.Flink;
    while (Entry != &Source->ExtendedDataList) {
        SrcExt = CONTAINING_RECORD(Entry, EC_EXTENDED_DATA, ListEntry);

        NewExt = (PEC_EXTENDED_DATA)ExAllocateFromNPagedLookasideList(
            &Consumer->ExtendedDataLookaside
        );

        if (NewExt == NULL) {
            EcFreeEventRecord(Consumer, NewRecord);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(NewExt, sizeof(EC_EXTENDED_DATA));
        NewExt->ExtType = SrcExt->ExtType;
        NewExt->DataSize = SrcExt->DataSize;
        NewExt->IsFromLookaside = TRUE;

        if (SrcExt->DataPtr != NULL && SrcExt->DataSize > 0) {
            NewExt->DataPtr = ExAllocatePool2(
                POOL_FLAG_NON_PAGED,
                SrcExt->DataSize,
                EC_BUFFER_TAG
            );
            if (NewExt->DataPtr == NULL) {
                ExFreeToNPagedLookasideList(&Consumer->ExtendedDataLookaside, NewExt);
                EcFreeEventRecord(Consumer, NewRecord);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            RtlCopyMemory(NewExt->DataPtr, SrcExt->DataPtr, SrcExt->DataSize);
        }

        InsertTailList(&NewRecord->ExtendedDataList, &NewExt->ListEntry);
        NewRecord->ExtendedDataCount++;

        Entry = Entry->Flink;
    }

    *Clone = NewRecord;
    return STATUS_SUCCESS;
}

// ============================================================================
// STATISTICS AND MONITORING
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EcGetStatistics(
    _In_ PEC_CONSUMER Consumer,
    _Out_ PEC_CONSUMER_STATS Stats
    )
{
    if (Consumer == NULL || Stats == NULL) {
        if (Stats != NULL) {
            RtlZeroMemory(Stats, sizeof(EC_CONSUMER_STATS));
        }
        return;
    }

    //
    // Read each volatile field individually using interlocked reads
    // to prevent torn 64-bit reads on 32-bit aligned fields.
    //
    Stats->TotalEventsReceived = InterlockedCompareExchange64(&Consumer->Stats.TotalEventsReceived, 0, 0);
    Stats->TotalEventsProcessed = InterlockedCompareExchange64(&Consumer->Stats.TotalEventsProcessed, 0, 0);
    Stats->TotalEventsDropped = InterlockedCompareExchange64(&Consumer->Stats.TotalEventsDropped, 0, 0);
    Stats->TotalEventsCorrelated = InterlockedCompareExchange64(&Consumer->Stats.TotalEventsCorrelated, 0, 0);
    Stats->CurrentBufferedEvents = Consumer->Stats.CurrentBufferedEvents;
    Stats->PeakBufferedEvents = Consumer->Stats.PeakBufferedEvents;
    Stats->BufferOverflows = InterlockedCompareExchange64(&Consumer->Stats.BufferOverflows, 0, 0);
    Stats->BatchesProcessed = InterlockedCompareExchange64(&Consumer->Stats.BatchesProcessed, 0, 0);
    Stats->TotalProcessingTimeUs = InterlockedCompareExchange64(&Consumer->Stats.TotalProcessingTimeUs, 0, 0);
    Stats->TotalErrors = InterlockedCompareExchange64(&Consumer->Stats.TotalErrors, 0, 0);
    Stats->SessionErrors = InterlockedCompareExchange64(&Consumer->Stats.SessionErrors, 0, 0);
    Stats->StartTime = Consumer->Stats.StartTime;
    Stats->LastEventTime = Consumer->Stats.LastEventTime;
    Stats->CurrentEventsPerSecond = Consumer->Stats.CurrentEventsPerSecond;
    Stats->PeakEventsPerSecond = Consumer->Stats.PeakEventsPerSecond;
    Stats->LastHealthCheck = Consumer->Stats.LastHealthCheck;
    Stats->IsHealthy = Consumer->Stats.IsHealthy;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EcGetSubscriptionStatistics(
    _In_ PEC_SUBSCRIPTION Subscription,
    _Out_ PEC_SUBSCRIPTION_STATS Stats
    )
{
    if (Subscription == NULL || Stats == NULL) {
        if (Stats != NULL) {
            RtlZeroMemory(Stats, sizeof(EC_SUBSCRIPTION_STATS));
        }
        return;
    }

    Stats->EventsReceived = InterlockedCompareExchange64(&Subscription->Stats.EventsReceived, 0, 0);
    Stats->EventsProcessed = InterlockedCompareExchange64(&Subscription->Stats.EventsProcessed, 0, 0);
    Stats->EventsDropped = InterlockedCompareExchange64(&Subscription->Stats.EventsDropped, 0, 0);
    Stats->EventsFiltered = InterlockedCompareExchange64(&Subscription->Stats.EventsFiltered, 0, 0);
    Stats->CallbackErrors = InterlockedCompareExchange64(&Subscription->Stats.CallbackErrors, 0, 0);
    Stats->FilterErrors = InterlockedCompareExchange64(&Subscription->Stats.FilterErrors, 0, 0);
    Stats->FirstEventTime = Subscription->Stats.FirstEventTime;
    Stats->LastEventTime = Subscription->Stats.LastEventTime;
    Stats->TotalProcessingTimeUs = InterlockedCompareExchange64(&Subscription->Stats.TotalProcessingTimeUs, 0, 0);
    Stats->MaxProcessingTimeUs = InterlockedCompareExchange64(&Subscription->Stats.MaxProcessingTimeUs, 0, 0);
    Stats->CurrentRate = Subscription->Stats.CurrentRate;
    Stats->PeakRate = Subscription->Stats.PeakRate;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
EcResetStatistics(
    _Inout_ PEC_CONSUMER Consumer
    )
{
    PLIST_ENTRY Entry;
    PEC_SUBSCRIPTION Sub;
    KIRQL OldIrql;

    PAGED_CODE();

    if (Consumer == NULL) {
        return;
    }

    //
    // Reset consumer stats (volatile fields, use interlocked)
    //
    InterlockedExchange64(&Consumer->Stats.TotalEventsReceived, 0);
    InterlockedExchange64(&Consumer->Stats.TotalEventsProcessed, 0);
    InterlockedExchange64(&Consumer->Stats.TotalEventsDropped, 0);
    InterlockedExchange64(&Consumer->Stats.TotalEventsCorrelated, 0);
    InterlockedExchange(&Consumer->Stats.PeakBufferedEvents, Consumer->Stats.CurrentBufferedEvents);
    InterlockedExchange64(&Consumer->Stats.BufferOverflows, 0);
    InterlockedExchange64(&Consumer->Stats.BatchesProcessed, 0);
    InterlockedExchange64(&Consumer->Stats.TotalProcessingTimeUs, 0);
    InterlockedExchange64(&Consumer->Stats.TotalErrors, 0);
    InterlockedExchange64(&Consumer->Stats.SessionErrors, 0);
    InterlockedExchange(&Consumer->Stats.CurrentEventsPerSecond, 0);
    InterlockedExchange(&Consumer->Stats.PeakEventsPerSecond, 0);

    KeQuerySystemTimePrecise(&Consumer->Stats.StartTime);

    //
    // Reset subscription stats under spin lock
    //
    KeAcquireSpinLock(&Consumer->SubscriptionLock, &OldIrql);

    Entry = Consumer->SubscriptionList.Flink;
    while (Entry != &Consumer->SubscriptionList) {
        Sub = CONTAINING_RECORD(Entry, EC_SUBSCRIPTION, ListEntry);
        RtlZeroMemory(&Sub->Stats, sizeof(EC_SUBSCRIPTION_STATS));
        Entry = Entry->Flink;
    }

    KeReleaseSpinLock(&Consumer->SubscriptionLock, OldIrql);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
EcIsHealthy(
    _In_ PEC_CONSUMER Consumer
    )
{
    if (Consumer == NULL) {
        return FALSE;
    }

    if (!Consumer->Initialized) {
        return FALSE;
    }

    if (InterlockedCompareExchange(&Consumer->State, 0, 0) == (LONG)EcState_Error) {
        return FALSE;
    }

    if (InterlockedCompareExchange(&Consumer->ConsecutiveErrors, 0, 0) >= (LONG)EC_MAX_CONSECUTIVE_ERRORS) {
        return FALSE;
    }

    if ((ULONG)Consumer->BufferedEventCount >= Consumer->Config.MaxBufferedEvents) {
        return FALSE;
    }

    return Consumer->Stats.IsHealthy;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
EC_STATE
EcGetState(
    _In_ PEC_CONSUMER Consumer
    )
{
    if (Consumer == NULL) {
        return EcState_Uninitialized;
    }

    return (EC_STATE)InterlockedCompareExchange(&Consumer->State, 0, 0);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
PCWSTR
EcGetProviderName(
    _In_ LPCGUID ProviderId
    )
{
    if (ProviderId == NULL) {
        return L"Unknown";
    }

    if (EcIsEqualGuid(ProviderId, &GUID_KERNEL_PROCESS_PROVIDER)) {
        return L"Microsoft-Windows-Kernel-Process";
    }
    if (EcIsEqualGuid(ProviderId, &GUID_KERNEL_FILE_PROVIDER)) {
        return L"Microsoft-Windows-Kernel-File";
    }
    if (EcIsEqualGuid(ProviderId, &GUID_KERNEL_NETWORK_PROVIDER)) {
        return L"Microsoft-Windows-Kernel-Network";
    }
    if (EcIsEqualGuid(ProviderId, &GUID_KERNEL_REGISTRY_PROVIDER)) {
        return L"Microsoft-Windows-Kernel-Registry";
    }
    if (EcIsEqualGuid(ProviderId, &GUID_SECURITY_AUDITING_PROVIDER)) {
        return L"Microsoft-Windows-Security-Auditing";
    }
    if (EcIsEqualGuid(ProviderId, &GUID_DNS_CLIENT_PROVIDER)) {
        return L"Microsoft-Windows-DNS-Client";
    }
    if (EcIsEqualGuid(ProviderId, &GUID_THREAT_INTELLIGENCE_PROVIDER)) {
        return L"Microsoft-Windows-Threat-Intelligence";
    }
    if (EcIsEqualGuid(ProviderId, &GUID_KERNEL_AUDIT_API_PROVIDER)) {
        return L"Microsoft-Windows-Kernel-Audit-API-Calls";
    }

    return L"Unknown";
}

_IRQL_requires_max_(DISPATCH_LEVEL)
PCWSTR
EcGetLevelName(
    _In_ UCHAR Level
    )
{
    switch (Level) {
        case 0: return L"Always";
        case 1: return L"Critical";
        case 2: return L"Error";
        case 3: return L"Warning";
        case 4: return L"Information";
        case 5: return L"Verbose";
        default: return L"Unknown";
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
EcGetEventField(
    _In_ PEC_EVENT_RECORD Record,
    _In_ ULONG Offset,
    _In_ ULONG Size,
    _Out_writes_bytes_(Size) PVOID Buffer
    )
{
    if (Record == NULL || Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Record->UserData == NULL) {
        return STATUS_NO_DATA_DETECTED;
    }

    //
    // Overflow-safe bounds check:
    // Instead of (Offset + Size > Length) which can overflow,
    // check (Size > Length || Offset > Length - Size).
    //
    if (Size > Record->UserDataLength ||
        Offset > Record->UserDataLength - Size) {
        return STATUS_BUFFER_OVERFLOW;
    }

    RtlCopyMemory(Buffer, (PUCHAR)Record->UserData + Offset, Size);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
EcGetEventString(
    _In_ PEC_EVENT_RECORD Record,
    _In_ ULONG Offset,
    _Out_writes_bytes_(BufferSize) PWCHAR Buffer,
    _In_ ULONG BufferSize
    )
{
    PWCHAR SourceString;
    SIZE_T StringLength;
    SIZE_T CopyLength;
    SIZE_T MaxChars;

    if (Record == NULL || Buffer == NULL || BufferSize < sizeof(WCHAR)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Zero the entire output buffer to prevent information disclosure
    // from uninitialized stack/pool memory in the caller's buffer.
    //
    RtlZeroMemory(Buffer, BufferSize);

    if (Record->UserData == NULL) {
        return STATUS_NO_DATA_DETECTED;
    }

    if (Offset >= Record->UserDataLength) {
        return STATUS_BUFFER_OVERFLOW;
    }

    //
    // Alignment check: Offset must be WCHAR-aligned to avoid alignment faults
    //
    if ((Offset % sizeof(WCHAR)) != 0) {
        return STATUS_DATATYPE_MISALIGNMENT;
    }

    //
    // Verify remaining bytes from Offset can hold at least one WCHAR
    //
    if (Record->UserDataLength - Offset < sizeof(WCHAR)) {
        return STATUS_BUFFER_OVERFLOW;
    }

    SourceString = (PWCHAR)((PUCHAR)Record->UserData + Offset);

    //
    // Calculate maximum characters available in source data
    //
    MaxChars = (Record->UserDataLength - Offset) / sizeof(WCHAR);

    //
    // Calculate string length within bounds
    //
    StringLength = 0;
    while (StringLength < MaxChars && SourceString[StringLength] != L'\0') {
        StringLength++;
    }

    //
    // Copy string with null termination
    //
    CopyLength = min(StringLength * sizeof(WCHAR), BufferSize - sizeof(WCHAR));
    RtlCopyMemory(Buffer, SourceString, CopyLength);
    Buffer[CopyLength / sizeof(WCHAR)] = L'\0';

    return STATUS_SUCCESS;
}

// ============================================================================
// WELL-KNOWN PROVIDER HELPERS
// ============================================================================

//
// These helpers subscribe with MatchAnyKeyword = 0xFFFFFFFFFFFFFFFF (all keywords)
// and MaxLevel = 5 (Verbose). This is intentionally permissive for an EDR sensor
// that needs full visibility. Callers who need filtered subscriptions should use
// EcSubscribeByGuid or EcSubscribe directly with specific keyword/level values.
//

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
EcSubscribeKernelProcess(
    _Inout_ PEC_CONSUMER Consumer,
    _In_ EC_EVENT_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ PEC_SUBSCRIPTION* Subscription
    )
{
    PAGED_CODE();
    return EcSubscribeByGuid(
        Consumer, &GUID_KERNEL_PROCESS_PROVIDER,
        0xFFFFFFFFFFFFFFFFULL, 5, Callback, Context, Subscription);
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
EcSubscribeKernelFile(
    _Inout_ PEC_CONSUMER Consumer,
    _In_ EC_EVENT_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ PEC_SUBSCRIPTION* Subscription
    )
{
    PAGED_CODE();
    return EcSubscribeByGuid(
        Consumer, &GUID_KERNEL_FILE_PROVIDER,
        0xFFFFFFFFFFFFFFFFULL, 5, Callback, Context, Subscription);
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
EcSubscribeKernelNetwork(
    _Inout_ PEC_CONSUMER Consumer,
    _In_ EC_EVENT_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ PEC_SUBSCRIPTION* Subscription
    )
{
    PAGED_CODE();
    return EcSubscribeByGuid(
        Consumer, &GUID_KERNEL_NETWORK_PROVIDER,
        0xFFFFFFFFFFFFFFFFULL, 5, Callback, Context, Subscription);
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
EcSubscribeKernelRegistry(
    _Inout_ PEC_CONSUMER Consumer,
    _In_ EC_EVENT_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ PEC_SUBSCRIPTION* Subscription
    )
{
    PAGED_CODE();
    return EcSubscribeByGuid(
        Consumer, &GUID_KERNEL_REGISTRY_PROVIDER,
        0xFFFFFFFFFFFFFFFFULL, 5, Callback, Context, Subscription);
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
EcSubscribeSecurityAuditing(
    _Inout_ PEC_CONSUMER Consumer,
    _In_ EC_EVENT_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ PEC_SUBSCRIPTION* Subscription
    )
{
    PAGED_CODE();
    return EcSubscribeByGuid(
        Consumer, &GUID_SECURITY_AUDITING_PROVIDER,
        0xFFFFFFFFFFFFFFFFULL, 5, Callback, Context, Subscription);
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
EcSubscribeThreatIntelligence(
    _Inout_ PEC_CONSUMER Consumer,
    _In_ EC_EVENT_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ PEC_SUBSCRIPTION* Subscription
    )
{
    PAGED_CODE();
    return EcSubscribeByGuid(
        Consumer, &GUID_THREAT_INTELLIGENCE_PROVIDER,
        0xFFFFFFFFFFFFFFFFULL, 5, Callback, Context, Subscription);
}

// ============================================================================
// INTERNAL HELPER IMPLEMENTATIONS
// ============================================================================

static
VOID
EcpInitializeDefaultConfig(
    _Out_ PEC_CONSUMER_CONFIG Config
    )
{
    RtlZeroMemory(Config, sizeof(EC_CONSUMER_CONFIG));

    RtlStringCchCopyW(
        Config->SessionName,
        EC_MAX_SESSION_NAME_LENGTH,
        L"ShadowStrike-ETW-Session"
    );

    Config->MaxBufferedEvents = EC_MAX_BUFFERED_EVENTS;
    Config->BufferThreshold = EC_DEFAULT_BUFFER_THRESHOLD;
    Config->ProcessingThreadCount = EC_DEFAULT_THREAD_COUNT;
    Config->MaxEventsPerSecond = EC_DEFAULT_RATE_LIMIT;
    Config->EnableBatching = TRUE;
    Config->AutoStart = FALSE;
    Config->UseRealTimeSession = TRUE;
}

static
VOID
EcpInitializeLookasideLists(
    _Inout_ PEC_CONSUMER Consumer
    )
{
    ExInitializeNPagedLookasideList(
        &Consumer->EventRecordLookaside,
        NULL, NULL,
        POOL_NX_ALLOCATION,
        sizeof(EC_EVENT_RECORD),
        EC_EVENT_TAG,
        EC_EVENT_LOOKASIDE_DEPTH
    );

    ExInitializeNPagedLookasideList(
        &Consumer->ExtendedDataLookaside,
        NULL, NULL,
        POOL_NX_ALLOCATION,
        sizeof(EC_EXTENDED_DATA),
        EC_BUFFER_TAG,
        64
    );

    Consumer->LookasideInitialized = TRUE;
}

static
VOID
EcpCleanupLookasideLists(
    _Inout_ PEC_CONSUMER Consumer
    )
{
    if (!Consumer->LookasideInitialized) {
        return;
    }

    ExDeleteNPagedLookasideList(&Consumer->EventRecordLookaside);
    ExDeleteNPagedLookasideList(&Consumer->ExtendedDataLookaside);

    Consumer->LookasideInitialized = FALSE;
}

static
NTSTATUS
EcpStartProcessingThreads(
    _Inout_ PEC_CONSUMER Consumer
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES ObjectAttributes;
    ULONG i;

    InitializeObjectAttributes(
        &ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    for (i = 0; i < Consumer->Config.ProcessingThreadCount; i++) {
        Consumer->ProcessingThreads[i].ThreadIndex = i;
        Consumer->ProcessingThreads[i].Consumer = Consumer;
        InterlockedExchange(&Consumer->ProcessingThreads[i].IsRunning, FALSE);
        InterlockedExchange(&Consumer->ProcessingThreads[i].StopRequested, FALSE);
        Consumer->ProcessingThreads[i].EventsProcessed = 0;
        Consumer->ProcessingThreads[i].ProcessingTimeUs = 0;

        KeInitializeEvent(&Consumer->ProcessingThreads[i].StopEvent, NotificationEvent, FALSE);
        KeInitializeEvent(&Consumer->ProcessingThreads[i].WorkEvent, SynchronizationEvent, FALSE);
        KeInitializeEvent(&Consumer->ProcessingThreads[i].ReadyEvent, NotificationEvent, FALSE);

        //
        // Mark running BEFORE creating the thread so the stop path
        // knows to wait for this thread if creation succeeds.
        //
        InterlockedExchange(&Consumer->ProcessingThreads[i].IsRunning, TRUE);

        Status = PsCreateSystemThread(
            &Consumer->ProcessingThreads[i].ThreadHandle,
            THREAD_ALL_ACCESS,
            &ObjectAttributes,
            NULL, NULL,
            EcpProcessingThreadRoutine,
            &Consumer->ProcessingThreads[i]
        );

        if (!NT_SUCCESS(Status)) {
            InterlockedExchange(&Consumer->ProcessingThreads[i].IsRunning, FALSE);
            TE_LOG_ERROR(Component_ETWProvider, Status,
                         ErrorSeverity_Error, L"Failed to create processing thread");
            Consumer->ActiveThreadCount = i;
            EcpStopProcessingThreads(Consumer);
            return Status;
        }

        Status = ObReferenceObjectByHandle(
            Consumer->ProcessingThreads[i].ThreadHandle,
            THREAD_ALL_ACCESS,
            *PsThreadType,
            KernelMode,
            (PVOID*)&Consumer->ProcessingThreads[i].ThreadObject,
            NULL
        );

        if (!NT_SUCCESS(Status)) {
            //
            // Thread was created but we can't get the object.
            // Signal stop and wait via handle, then clean up.
            //
            InterlockedExchange(&Consumer->ProcessingThreads[i].StopRequested, TRUE);
            KeSetEvent(&Consumer->ProcessingThreads[i].StopEvent, IO_NO_INCREMENT, FALSE);
            KeSetEvent(&Consumer->ProcessingThreads[i].WorkEvent, IO_NO_INCREMENT, FALSE);
            ZwWaitForSingleObject(Consumer->ProcessingThreads[i].ThreadHandle, FALSE, NULL);
            ZwClose(Consumer->ProcessingThreads[i].ThreadHandle);
            Consumer->ProcessingThreads[i].ThreadHandle = NULL;
            InterlockedExchange(&Consumer->ProcessingThreads[i].IsRunning, FALSE);
            Consumer->ActiveThreadCount = i;
            EcpStopProcessingThreads(Consumer);
            return Status;
        }

        //
        // Wait for thread to signal it is ready
        //
        KeWaitForSingleObject(
            &Consumer->ProcessingThreads[i].ReadyEvent,
            Executive, KernelMode, FALSE, NULL);
    }

    Consumer->ActiveThreadCount = Consumer->Config.ProcessingThreadCount;
    return STATUS_SUCCESS;
}

static
VOID
EcpStopProcessingThreads(
    _Inout_ PEC_CONSUMER Consumer
    )
{
    ULONG i;

    for (i = 0; i < Consumer->ActiveThreadCount; i++) {
        if (!InterlockedCompareExchange(&Consumer->ProcessingThreads[i].IsRunning, 0, 0)) {
            continue;
        }

        //
        // Signal stop using interlocked write for cross-thread visibility
        //
        InterlockedExchange(&Consumer->ProcessingThreads[i].StopRequested, TRUE);
        KeSetEvent(&Consumer->ProcessingThreads[i].StopEvent, IO_NO_INCREMENT, FALSE);
        KeSetEvent(&Consumer->ProcessingThreads[i].WorkEvent, IO_NO_INCREMENT, FALSE);

        //
        // Wait INDEFINITELY for thread to exit. We MUST NOT proceed
        // with cleanup while threads are still running — that causes
        // use-after-free on the Consumer structure and all its contents.
        //
        if (Consumer->ProcessingThreads[i].ThreadObject != NULL) {
            KeWaitForSingleObject(
                Consumer->ProcessingThreads[i].ThreadObject,
                Executive, KernelMode, FALSE, NULL);

            ObDereferenceObject(Consumer->ProcessingThreads[i].ThreadObject);
            Consumer->ProcessingThreads[i].ThreadObject = NULL;
        }

        if (Consumer->ProcessingThreads[i].ThreadHandle != NULL) {
            ZwClose(Consumer->ProcessingThreads[i].ThreadHandle);
            Consumer->ProcessingThreads[i].ThreadHandle = NULL;
        }

        InterlockedExchange(&Consumer->ProcessingThreads[i].IsRunning, FALSE);
    }

    Consumer->ActiveThreadCount = 0;
}

static
VOID
EcpProcessingThreadRoutine(
    _In_ PVOID Context
    )
{
    PEC_PROCESSING_THREAD ThreadContext = (PEC_PROCESSING_THREAD)Context;
    PEC_CONSUMER Consumer;
    PVOID WaitObjects[2];
    NTSTATUS WaitStatus;
    LARGE_INTEGER Timeout;

    if (ThreadContext == NULL) {
        PsTerminateSystemThread(STATUS_INVALID_PARAMETER);
        return;
    }

    Consumer = ThreadContext->Consumer;

    //
    // Signal that this thread has started and is ready to process events
    //
    KeSetEvent(&ThreadContext->ReadyEvent, IO_NO_INCREMENT, FALSE);

    //
    // Set up wait objects: [0]=Stop, [1]=Work
    //
    WaitObjects[0] = &ThreadContext->StopEvent;
    WaitObjects[1] = &ThreadContext->WorkEvent;

    //
    // Use 64-bit literal to prevent overflow
    //
    Timeout.QuadPart = -((LONGLONG)10 * 1000 * EC_THREAD_WAIT_TIMEOUT_MS);

    while (!InterlockedCompareExchange(&ThreadContext->StopRequested, 0, 0)) {
        //
        // Wait for work or stop signal
        //
        WaitStatus = KeWaitForMultipleObjects(
            2, WaitObjects, WaitAny,
            Executive, KernelMode, FALSE,
            &Timeout, NULL);

        if (InterlockedCompareExchange(&ThreadContext->StopRequested, 0, 0)) {
            break;
        }

        //
        // If stop event was signaled (index 0), exit
        //
        if (WaitStatus == STATUS_WAIT_0) {
            break;
        }

        //
        // Check if paused — wait on FlowResumeEvent AND StopEvent
        // to prevent deadlock when stop is called while paused
        //
        if (InterlockedCompareExchange(&Consumer->State, 0, 0) == (LONG)EcState_Paused) {
            PVOID PauseWaitObjects[2];
            PauseWaitObjects[0] = &ThreadContext->StopEvent;
            PauseWaitObjects[1] = &Consumer->FlowResumeEvent;

            WaitStatus = KeWaitForMultipleObjects(
                2, PauseWaitObjects, WaitAny,
                Executive, KernelMode, FALSE,
                NULL, NULL);

            if (InterlockedCompareExchange(&ThreadContext->StopRequested, 0, 0) ||
                WaitStatus == STATUS_WAIT_0) {
                break;
            }
        }

        //
        // Process events
        //
        if (InterlockedCompareExchange(&Consumer->State, 0, 0) == (LONG)EcState_Running) {
            EcpProcessEventBatch(Consumer, ThreadContext->ThreadIndex);
        }
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

static
NTSTATUS
EcpProcessEventBatch(
    _In_ PEC_CONSUMER Consumer,
    _In_ ULONG ThreadIndex
    )
{
    PEC_EVENT_RECORD Record;
    EC_PROCESS_RESULT Result;
    ULONG ProcessedCount = 0;
    LARGE_INTEGER StartTime, EndTime;
    LONG64 ProcessingTime;

    KeQuerySystemTimePrecise(&StartTime);

    while (ProcessedCount < EC_EVENT_BATCH_SIZE) {
        Record = EcpDequeueEvent(Consumer);
        if (Record == NULL) {
            break;
        }

        //
        // Process through subscription callback.
        // The subscription pointer is reference-counted, so it remains
        // valid even if EcUnsubscribe was called concurrently.
        // We still invoke the callback even if subscription was deactivated
        // since the event was already matched and queued.
        //
        if (Record->Subscription != NULL &&
            Record->Subscription->Config.EventCallback != NULL) {

            __try {
                Result = Record->Subscription->Config.EventCallback(
                    Record,
                    Record->Subscription->Config.EventCallbackContext
                );

                InterlockedIncrement64(&Record->Subscription->Stats.EventsProcessed);
                InterlockedExchange(&Consumer->ConsecutiveErrors, 0);
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {
                Result = EcResult_Error;
                InterlockedIncrement64(&Record->Subscription->Stats.CallbackErrors);
                InterlockedIncrement(&Consumer->ConsecutiveErrors);
            }

            if (Result == EcResult_Error) {
                InterlockedIncrement64(&Consumer->Stats.TotalErrors);
            }
        }

        //
        // Free event record (this also releases subscription reference)
        //
        EcFreeEventRecord(Consumer, Record);

        ProcessedCount++;
        InterlockedIncrement64(&Consumer->Stats.TotalEventsProcessed);
    }

    //
    // Update processing time
    //
    KeQuerySystemTimePrecise(&EndTime);
    ProcessingTime = (EndTime.QuadPart - StartTime.QuadPart) / 10;

    if (ProcessedCount > 0) {
        InterlockedIncrement64(&Consumer->Stats.BatchesProcessed);
        InterlockedAdd64(&Consumer->Stats.TotalProcessingTimeUs, ProcessingTime);

        if (ThreadIndex < EC_MAX_THREAD_COUNT) {
            InterlockedAdd64(
                &Consumer->ProcessingThreads[ThreadIndex].ProcessingTimeUs,
                ProcessingTime);
        }
    }

    return STATUS_SUCCESS;
}

static
PEC_EVENT_RECORD
EcpDequeueEvent(
    _In_ PEC_CONSUMER Consumer
    )
{
    PEC_EVENT_RECORD Record = NULL;
    PLIST_ENTRY Entry;
    KIRQL OldIrql;
    ULONG Priority;

    KeAcquireSpinLock(&Consumer->EventQueueLock, &OldIrql);

    for (Priority = 0; Priority < EC_PRIORITY_QUEUE_COUNT; Priority++) {
        if (!IsListEmpty(&Consumer->EventQueues[Priority])) {
            Entry = RemoveHeadList(&Consumer->EventQueues[Priority]);
            Record = CONTAINING_RECORD(Entry, EC_EVENT_RECORD, ListEntry);
            {
                LONG NewCount = InterlockedDecrement(&Consumer->BufferedEventCount);
                InterlockedExchange(&Consumer->Stats.CurrentBufferedEvents, NewCount);
            }
            break;
        }
    }

    KeReleaseSpinLock(&Consumer->EventQueueLock, OldIrql);

    return Record;
}

static
VOID
EcpEnqueueEvent(
    _In_ PEC_CONSUMER Consumer,
    _Inout_ PEC_EVENT_RECORD Record
    )
{
    KIRQL OldIrql;
    ULONG Priority;
    LONG NewCount;
    LONG FlowState;

    //
    // Check flow control using interlocked read for cross-CPU visibility.
    // These are optimistic pre-checks; the authoritative capacity check
    // is inside the queue spinlock below.
    //
    FlowState = InterlockedCompareExchange(&Consumer->CurrentFlowState, 0, 0);

    if (FlowState == (LONG)EcFlow_Pause) {
        InterlockedIncrement64(&Consumer->Stats.TotalEventsDropped);
        EcFreeEventRecord(Consumer, Record);
        return;
    }

    if (FlowState == (LONG)EcFlow_Drop &&
        Record->Priority >= EcPriority_Low) {
        InterlockedIncrement64(&Consumer->Stats.TotalEventsDropped);
        EcFreeEventRecord(Consumer, Record);
        return;
    }

    Priority = (ULONG)Record->Priority;
    if (Priority >= EC_PRIORITY_QUEUE_COUNT) {
        Priority = EC_PRIORITY_QUEUE_COUNT - 1;
    }

    KeAcquireSpinLock(&Consumer->EventQueueLock, &OldIrql);

    //
    // Authoritative buffer capacity check INSIDE the spinlock
    //
    if ((ULONG)Consumer->BufferedEventCount >= Consumer->Config.MaxBufferedEvents) {
        KeReleaseSpinLock(&Consumer->EventQueueLock, OldIrql);
        InterlockedIncrement64(&Consumer->Stats.BufferOverflows);
        InterlockedIncrement64(&Consumer->Stats.TotalEventsDropped);
        EcFreeEventRecord(Consumer, Record);
        return;
    }

    InsertTailList(&Consumer->EventQueues[Priority], &Record->ListEntry);
    NewCount = InterlockedIncrement(&Consumer->BufferedEventCount);
    InterlockedExchange(&Consumer->Stats.CurrentBufferedEvents, NewCount);

    //
    // Update peak using interlocked compare-and-swap loop
    //
    {
        LONG CurrentPeak;
        do {
            CurrentPeak = Consumer->Stats.PeakBufferedEvents;
            if (NewCount <= CurrentPeak) break;
        } while (InterlockedCompareExchange(
                     &Consumer->Stats.PeakBufferedEvents,
                     NewCount, CurrentPeak) != CurrentPeak);
    }

    KeReleaseSpinLock(&Consumer->EventQueueLock, OldIrql);

    //
    // Signal a processing thread using round-robin
    //
    EcpSignalProcessingThread(Consumer);

    //
    // Check flow control threshold
    //
    EcpUpdateFlowControl(Consumer);
}

static
VOID
EcpDrainEventQueues(
    _Inout_ PEC_CONSUMER Consumer
    )
{
    PEC_EVENT_RECORD Record;

    while ((Record = EcpDequeueEvent(Consumer)) != NULL) {
        EcFreeEventRecord(Consumer, Record);
    }
}

static
VOID
EcpFreeAllSubscriptions(
    _Inout_ PEC_CONSUMER Consumer
    )
{
    PLIST_ENTRY Entry;
    PEC_SUBSCRIPTION Subscription;
    KIRQL OldIrql;

    //
    // Remove all subscriptions from the list under spin lock.
    // By the time this is called, all events have been drained
    // (EcpDrainEventQueues was called first in EcShutdown), so
    // no event records hold references to these subscriptions.
    //
    // We still use the refcount-based release path for correctness:
    // mark unsubscribe pending and decrement the creation reference.
    // Since events were drained, refcount should be 1, and the
    // dereference will free immediately.
    //
    KeAcquireSpinLock(&Consumer->SubscriptionLock, &OldIrql);

    while (!IsListEmpty(&Consumer->SubscriptionList)) {
        Entry = RemoveHeadList(&Consumer->SubscriptionList);
        Subscription = CONTAINING_RECORD(Entry, EC_SUBSCRIPTION, ListEntry);
        InitializeListHead(&Subscription->ListEntry);
        InterlockedExchange(&Subscription->IsInList, FALSE);

        if (Subscription->IsRegistered) {
            Subscription->IsRegistered = FALSE;
        }

        //
        // Deactivate to prevent any late matching
        //
        InterlockedExchange(&Subscription->State, (LONG)EcSubState_Inactive);

        //
        // Mark unsubscribe pending and release creation reference.
        // This will free the subscription if refcount reaches 0.
        //
        InterlockedExchange(&Subscription->UnsubscribePending, TRUE);
        EcpDereferenceSubscription(Subscription);
    }

    InterlockedExchange(&Consumer->SubscriptionCount, 0);

    KeReleaseSpinLock(&Consumer->SubscriptionLock, OldIrql);
}

/**
 * @brief Mark a subscription as registered for event matching.
 *
 * In kernel mode, actual event ingestion comes from kernel notify callbacks
 * (PsSetCreateProcessNotifyRoutine, CmRegisterCallbackEx, etc.) that call
 * EcIngestEvent(). This function marks the subscription so EcIngestEvent
 * can match events to it.
 */
static
VOID
EcpMarkSubscriptionRegistered(
    _Inout_ PEC_SUBSCRIPTION Subscription
    )
{
    if (Subscription == NULL) {
        return;
    }

    Subscription->IsRegistered = TRUE;
    KeQuerySystemTimePrecise(&Subscription->Stats.FirstEventTime);
}

static
VOID
EcpMarkSubscriptionUnregistered(
    _Inout_ PEC_SUBSCRIPTION Subscription
    )
{
    if (Subscription == NULL) {
        return;
    }

    Subscription->IsRegistered = FALSE;
    InterlockedExchange(&Subscription->State, (LONG)EcSubState_Inactive);
}

/**
 * @brief Atomically update subscription state and invoke status callback.
 */
static
VOID
EcpUpdateSubscriptionState(
    _Inout_ PEC_SUBSCRIPTION Subscription,
    _In_ EC_SUBSCRIPTION_STATE NewState
    )
{
    LONG OldState;

    OldState = InterlockedExchange(&Subscription->State, (LONG)NewState);
    if (OldState == (LONG)NewState) {
        return;
    }

    //
    // Invoke status callback if configured
    //
    if (Subscription->Config.StatusCallback != NULL) {
        __try {
            Subscription->Config.StatusCallback(
                Subscription,
                (EC_SUBSCRIPTION_STATE)OldState,
                NewState,
                Subscription->Config.StatusCallbackContext
            );
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            TE_LOG_WARNING(Component_ETWProvider,
                           L"Subscription status callback threw exception");
        }
    }
}

static
BOOLEAN
EcpCheckRateLimit(
    _Inout_ PEC_CONSUMER Consumer
    )
{
    LARGE_INTEGER CurrentTime;
    KIRQL OldIrql;
    LONG64 ElapsedSeconds;
    BOOLEAN Allowed = TRUE;

    if (Consumer->Config.MaxEventsPerSecond == 0) {
        return TRUE;
    }

    KeQuerySystemTimePrecise(&CurrentTime);

    KeAcquireSpinLock(&Consumer->RateLimitLock, &OldIrql);

    ElapsedSeconds = (CurrentTime.QuadPart - Consumer->CurrentSecondStart.QuadPart) / 10000000LL;

    if (ElapsedSeconds >= 1) {
        Consumer->Stats.CurrentEventsPerSecond = Consumer->EventsThisSecond;
        if (Consumer->EventsThisSecond > Consumer->Stats.PeakEventsPerSecond) {
            Consumer->Stats.PeakEventsPerSecond = Consumer->EventsThisSecond;
        }
        Consumer->EventsThisSecond = 0;
        Consumer->CurrentSecondStart = CurrentTime;
    }

    if ((ULONG)Consumer->EventsThisSecond >= Consumer->Config.MaxEventsPerSecond) {
        Allowed = FALSE;
    } else {
        Consumer->EventsThisSecond++;
    }

    KeReleaseSpinLock(&Consumer->RateLimitLock, OldIrql);

    return Allowed;
}

static
VOID
EcpUpdateFlowControl(
    _Inout_ PEC_CONSUMER Consumer
    )
{
    ULONG BufferedCount;
    LONG OldFlowState;
    LONG NewFlowState;

    //
    // Read buffered count atomically for consistent flow control decisions
    //
    BufferedCount = (ULONG)InterlockedCompareExchange(&Consumer->BufferedEventCount, 0, 0);

    //
    // Determine flow control state based on buffer usage
    //
    if (BufferedCount >= Consumer->Config.MaxBufferedEvents) {
        NewFlowState = (LONG)EcFlow_Pause;
    } else if (BufferedCount >= (Consumer->Config.MaxBufferedEvents * 90 / 100)) {
        NewFlowState = (LONG)EcFlow_Drop;
    } else if (BufferedCount >= Consumer->Config.BufferThreshold) {
        NewFlowState = (LONG)EcFlow_Throttle;
    } else {
        NewFlowState = (LONG)EcFlow_Normal;
    }

    //
    // Invoke custom flow control callback if configured
    //
    if (Consumer->Config.FlowCallback != NULL && NewFlowState != (LONG)EcFlow_Normal) {
        __try {
            NewFlowState = (LONG)Consumer->Config.FlowCallback(
                Consumer,
                BufferedCount,
                Consumer->Config.MaxBufferedEvents,
                Consumer->Config.FlowCallbackContext
            );
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            //
            // Use calculated state on callback error
            //
        }
    }

    //
    // Atomically swap flow state and use the old value for resume logic
    //
    OldFlowState = InterlockedExchange(&Consumer->CurrentFlowState, NewFlowState);

    //
    // Update flow resume event
    //
    if (NewFlowState == (LONG)EcFlow_Pause) {
        KeClearEvent(&Consumer->FlowResumeEvent);
    } else if (OldFlowState == (LONG)EcFlow_Pause && NewFlowState != (LONG)EcFlow_Pause) {
        KeSetEvent(&Consumer->FlowResumeEvent, IO_NO_INCREMENT, FALSE);
    }
}

static
VOID
EcpHealthCheckDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PEC_CONSUMER Consumer = (PEC_CONSUMER)DeferredContext;
    BOOLEAN IsHealthy = TRUE;
    LARGE_INTEGER Now;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (Consumer == NULL || !Consumer->Initialized) {
        return;
    }

    if (InterlockedCompareExchange(&Consumer->State, 0, 0) == (LONG)EcState_Error) {
        IsHealthy = FALSE;
    }

    if (InterlockedCompareExchange(&Consumer->ConsecutiveErrors, 0, 0) >= (LONG)EC_MAX_CONSECUTIVE_ERRORS) {
        IsHealthy = FALSE;
    }

    if (InterlockedCompareExchange(&Consumer->CurrentFlowState, 0, 0) == (LONG)EcFlow_Pause) {
        IsHealthy = FALSE;
    }

    Consumer->Stats.IsHealthy = IsHealthy;

    //
    // Use a local variable for the timestamp to ensure atomicity.
    // On x64, LARGE_INTEGER writes are atomic. On x86, we accept
    // a potential torn read in the stats path (non-critical).
    //
    KeQuerySystemTimePrecise(&Now);
    Consumer->Stats.LastHealthCheck = Now;
}

static
EC_EVENT_SOURCE
EcpDetermineEventSource(
    _In_ LPCGUID ProviderId
    )
{
    if (ProviderId == NULL) {
        return EcSource_Unknown;
    }

    if (EcIsEqualGuid(ProviderId, &GUID_KERNEL_PROCESS_PROVIDER) ||
        EcIsEqualGuid(ProviderId, &GUID_KERNEL_FILE_PROVIDER) ||
        EcIsEqualGuid(ProviderId, &GUID_KERNEL_NETWORK_PROVIDER) ||
        EcIsEqualGuid(ProviderId, &GUID_KERNEL_REGISTRY_PROVIDER) ||
        EcIsEqualGuid(ProviderId, &GUID_KERNEL_AUDIT_API_PROVIDER)) {
        return EcSource_Kernel;
    }

    if (EcIsEqualGuid(ProviderId, &GUID_SECURITY_AUDITING_PROVIDER) ||
        EcIsEqualGuid(ProviderId, &GUID_THREAT_INTELLIGENCE_PROVIDER)) {
        return EcSource_Security;
    }

    return EcSource_User;
}

/**
 * @brief Free all extended data items from an event record.
 *
 * Uses the IsFromLookaside flag to determine correct deallocation:
 * - Lookaside-sourced items go back to ExtendedDataLookaside
 * - Directly-allocated items use ExFreePoolWithTag
 */
static
VOID
EcpFreeExtendedData(
    _In_ PEC_CONSUMER Consumer,
    _Inout_ PEC_EVENT_RECORD Record
    )
{
    PLIST_ENTRY Entry;
    PEC_EXTENDED_DATA ExtData;

    while (!IsListEmpty(&Record->ExtendedDataList)) {
        Entry = RemoveHeadList(&Record->ExtendedDataList);
        ExtData = CONTAINING_RECORD(Entry, EC_EXTENDED_DATA, ListEntry);

        if (ExtData->DataPtr != NULL) {
            ExFreePoolWithTag(ExtData->DataPtr, EC_BUFFER_TAG);
        }

        //
        // Return to lookaside if it came from there, otherwise direct free
        //
        if (ExtData->IsFromLookaside && Consumer->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&Consumer->ExtendedDataLookaside, ExtData);
        } else {
            ExFreePoolWithTag(ExtData, EC_BUFFER_TAG);
        }
    }

    Record->ExtendedDataCount = 0;
}

// ============================================================================
// CALLBACK VALIDATION
// ============================================================================

/**
 * @brief Validate that a callback address is in kernel address space.
 *
 * This is a basic safety check to prevent accidentally registering
 * user-mode function pointers as kernel callbacks. It does NOT validate
 * that the address points to valid code — that requires deeper checks
 * (e.g., MmIsAddressValid, which is itself unreliable for code pages).
 */
static
BOOLEAN
EcpValidateCallbackAddress(
    _In_ PVOID Address
    )
{
    if (Address == NULL) {
        return FALSE;
    }

    //
    // On x64, kernel addresses have the high bit set.
    // On x86, kernel space starts at 0x80000000.
    // MmIsAddressValid is not reliable for this purpose, but
    // checking the address range catches trivial user-mode pointers.
    //
#ifdef _WIN64
    return ((ULONG_PTR)Address >= 0xFFFF800000000000ULL);
#else
    return ((ULONG_PTR)Address >= 0x80000000UL);
#endif
}
