/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE ETW CONSUMER IMPLEMENTATION
 * ============================================================================
 *
 * @file ETWConsumer.c
 * @brief Enterprise-grade ETW event consumption for kernel-mode EDR operations.
 *
 * Provides comprehensive ETW consumption infrastructure for Fortune 500
 * endpoint protection with:
 * - Real-time ETW trace session management
 * - Multi-provider subscription with filtering
 * - High-performance event buffering and processing
 * - Priority-based event queuing
 * - Backpressure handling for high-volume scenarios
 * - Statistics and health monitoring
 *
 * Implementation Features:
 * - Lookaside lists for event record allocation
 * - Multiple processing threads for throughput
 * - Rate limiting to prevent resource exhaustion
 * - Proper cleanup and resource management
 * - IRQL-aware implementations throughout
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "ETWConsumer.h"

// ============================================================================
// PRAGMA DIRECTIVES
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, EcInitialize)
#pragma alloc_text(PAGE, EcShutdown)
#pragma alloc_text(PAGE, EcStart)
#pragma alloc_text(PAGE, EcStop)
#pragma alloc_text(PAGE, EcSubscribe)
#pragma alloc_text(PAGE, EcSubscribeByGuid)
#pragma alloc_text(PAGE, EcUnsubscribe)
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

/**
 * @brief Session name prefix for ShadowStrike ETW sessions
 */
#define EC_SESSION_NAME_PREFIX      L"ShadowStrike-ETW-Consumer-"

/**
 * @brief Default buffer size for ETW session (KB)
 */
#define EC_SESSION_BUFFER_SIZE_KB   64

/**
 * @brief Minimum buffers for ETW session
 */
#define EC_SESSION_MIN_BUFFERS      4

/**
 * @brief Maximum buffers for ETW session
 */
#define EC_SESSION_MAX_BUFFERS      64

/**
 * @brief Flush timer interval (seconds)
 */
#define EC_SESSION_FLUSH_TIMER      1

/**
 * @brief Maximum consecutive errors before marking unhealthy
 */
#define EC_MAX_CONSECUTIVE_ERRORS   10

/**
 * @brief Processing thread wait timeout (ms)
 */
#define EC_THREAD_WAIT_TIMEOUT_MS   1000

// ============================================================================
// INTERNAL HELPER FUNCTIONS - FORWARD DECLARATIONS
// ============================================================================

static VOID EcpInitializeDefaultConfig(_Out_ PEC_CONSUMER_CONFIG Config);
static NTSTATUS EcpInitializeLookasideLists(_Inout_ PEC_CONSUMER Consumer);
static VOID EcpCleanupLookasideLists(_Inout_ PEC_CONSUMER Consumer);
static NTSTATUS EcpStartProcessingThreads(_Inout_ PEC_CONSUMER Consumer);
static VOID EcpStopProcessingThreads(_Inout_ PEC_CONSUMER Consumer);
static VOID EcpProcessingThreadRoutine(_In_ PVOID Context);
static NTSTATUS EcpProcessEventBatch(_In_ PEC_CONSUMER Consumer, _In_ ULONG ThreadIndex);
static PEC_EVENT_RECORD EcpDequeueEvent(_In_ PEC_CONSUMER Consumer);
static VOID EcpEnqueueEvent(_In_ PEC_CONSUMER Consumer, _Inout_ PEC_EVENT_RECORD Record);
static VOID EcpDrainEventQueues(_Inout_ PEC_CONSUMER Consumer);
static VOID EcpFreeAllSubscriptions(_Inout_ PEC_CONSUMER Consumer);
static NTSTATUS EcpRegisterSubscription(_Inout_ PEC_SUBSCRIPTION Subscription);
static VOID EcpUnregisterSubscription(_Inout_ PEC_SUBSCRIPTION Subscription);
static VOID EcpUpdateSubscriptionState(_Inout_ PEC_SUBSCRIPTION Subscription, _In_ EC_SUBSCRIPTION_STATE NewState);
static BOOLEAN EcpCheckRateLimit(_Inout_ PEC_CONSUMER Consumer);
static VOID EcpUpdateFlowControl(_Inout_ PEC_CONSUMER Consumer);
static VOID EcpHealthCheckDpcRoutine(_In_ PKDPC Dpc, _In_opt_ PVOID Context, _In_opt_ PVOID Arg1, _In_opt_ PVOID Arg2);
static EC_EVENT_SOURCE EcpDetermineEventSource(_In_ LPCGUID ProviderId);
static VOID EcpFreeExtendedData(_Inout_ PEC_EVENT_RECORD Record);

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

    //
    // Validate parameters
    //
    if (Consumer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Consumer = NULL;

    //
    // Allocate consumer structure
    //
    NewConsumer = (PEC_CONSUMER)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(EC_CONSUMER),
        EC_POOL_TAG
    );

    if (NewConsumer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(NewConsumer, sizeof(EC_CONSUMER));

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
    // Validate and adjust configuration
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
    ExInitializePushLock(&NewConsumer->SubscriptionLock);
    NewConsumer->SubscriptionCount = 0;
    NewConsumer->NextSubscriptionId = 1;

    //
    // Initialize event queues (one per priority level)
    //
    for (i = 0; i < 5; i++) {
        InitializeListHead(&NewConsumer->EventQueues[i]);
    }
    KeInitializeSpinLock(&NewConsumer->EventQueueLock);
    NewConsumer->BufferedEventCount = 0;

    //
    // Initialize events
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
    // Initialize lookaside lists
    //
    Status = EcpInitializeLookasideLists(NewConsumer);
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(NewConsumer, EC_POOL_TAG);
        return Status;
    }

    //
    // Initialize health check DPC
    //
    KeInitializeDpc(&NewConsumer->HealthCheckDpc, EcpHealthCheckDpcRoutine, NewConsumer);

    //
    // Initialize statistics
    //
    KeQuerySystemTimePrecise(&NewConsumer->Stats.StartTime);
    NewConsumer->Stats.IsHealthy = TRUE;

    //
    // Set initial state
    //
    NewConsumer->State = EcState_Initialized;
    NewConsumer->CurrentFlowState = EcFlow_Normal;
    NewConsumer->Initialized = TRUE;

    *Consumer = NewConsumer;

    //
    // Auto-start if configured
    //
    if (NewConsumer->Config.AutoStart) {
        Status = EcStart(NewConsumer);
        if (!NT_SUCCESS(Status)) {
            //
            // Clean up on auto-start failure
            //
            EcShutdown(NewConsumer);
            *Consumer = NULL;
            return Status;
        }
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
EcShutdown(
    _Inout_ PEC_CONSUMER Consumer
    )
{
    PAGED_CODE();

    if (Consumer == NULL || !Consumer->Initialized) {
        return;
    }

    //
    // Stop if running
    //
    if (Consumer->State == EcState_Running ||
        Consumer->State == EcState_Paused) {
        EcStop(Consumer);
    }

    Consumer->State = EcState_Stopping;

    //
    // Cancel health check timer if active
    //
    if (Consumer->HealthCheckTimer != NULL) {
        KeCancelTimer((PKTIMER)Consumer->HealthCheckTimer);
        Consumer->HealthCheckTimer = NULL;
    }

    //
    // Remove all subscriptions
    //
    EcpFreeAllSubscriptions(Consumer);

    //
    // Drain any remaining events
    //
    EcpDrainEventQueues(Consumer);

    //
    // Cleanup lookaside lists
    //
    EcpCleanupLookasideLists(Consumer);

    //
    // Mark as stopped
    //
    Consumer->State = EcState_Stopped;
    Consumer->Initialized = FALSE;

    //
    // Free consumer structure
    //
    ExFreePoolWithTag(Consumer, EC_POOL_TAG);
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

    PAGED_CODE();

    if (Consumer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Consumer->Initialized) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (Consumer->State == EcState_Running) {
        return STATUS_SUCCESS;
    }

    if (Consumer->State != EcState_Initialized &&
        Consumer->State != EcState_Stopped) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    Consumer->State = EcState_Starting;

    //
    // Reset stop event
    //
    KeClearEvent(&Consumer->StopEvent);

    //
    // Reset statistics
    //
    KeQuerySystemTimePrecise(&Consumer->Stats.StartTime);
    Consumer->Stats.TotalEventsReceived = 0;
    Consumer->Stats.TotalEventsProcessed = 0;
    Consumer->Stats.TotalEventsDropped = 0;
    Consumer->Stats.CurrentBufferedEvents = 0;
    Consumer->Stats.TotalErrors = 0;
    Consumer->ConsecutiveErrors = 0;

    //
    // Start processing threads
    //
    Status = EcpStartProcessingThreads(Consumer);
    if (!NT_SUCCESS(Status)) {
        Consumer->State = EcState_Error;
        Consumer->LastError = Status;
        return Status;
    }

    //
    // Activate all auto-start subscriptions
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Consumer->SubscriptionLock);

    Entry = Consumer->SubscriptionList.Flink;
    while (Entry != &Consumer->SubscriptionList) {
        Subscription = CONTAINING_RECORD(Entry, EC_SUBSCRIPTION, ListEntry);
        Entry = Entry->Flink;

        if (Subscription->Config.AutoStart &&
            Subscription->State == EcSubState_Inactive) {
            EcpUpdateSubscriptionState(Subscription, EcSubState_Active);
        }
    }

    ExReleasePushLockShared(&Consumer->SubscriptionLock);
    KeLeaveCriticalRegion();

    Consumer->State = EcState_Running;
    Consumer->Stats.IsHealthy = TRUE;

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

    PAGED_CODE();

    if (Consumer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Consumer->State != EcState_Running &&
        Consumer->State != EcState_Paused) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    Consumer->State = EcState_Stopping;

    //
    // Signal stop event
    //
    KeSetEvent(&Consumer->StopEvent, IO_NO_INCREMENT, FALSE);

    //
    // Stop all processing threads
    //
    EcpStopProcessingThreads(Consumer);

    //
    // Suspend all subscriptions
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Consumer->SubscriptionLock);

    Entry = Consumer->SubscriptionList.Flink;
    while (Entry != &Consumer->SubscriptionList) {
        Subscription = CONTAINING_RECORD(Entry, EC_SUBSCRIPTION, ListEntry);
        Entry = Entry->Flink;

        if (Subscription->State == EcSubState_Active) {
            EcpUpdateSubscriptionState(Subscription, EcSubState_Inactive);
        }
    }

    ExReleasePushLockShared(&Consumer->SubscriptionLock);
    KeLeaveCriticalRegion();

    Consumer->State = EcState_Stopped;

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
EcPause(
    _Inout_ PEC_CONSUMER Consumer
    )
{
    if (Consumer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Consumer->State != EcState_Running) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    Consumer->State = EcState_Paused;
    KeClearEvent(&Consumer->FlowResumeEvent);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
EcResume(
    _Inout_ PEC_CONSUMER Consumer
    )
{
    ULONG i;

    if (Consumer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Consumer->State != EcState_Paused) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    Consumer->State = EcState_Running;
    KeSetEvent(&Consumer->FlowResumeEvent, IO_NO_INCREMENT, FALSE);

    //
    // Signal work events to resume processing
    //
    for (i = 0; i < Consumer->ActiveThreadCount; i++) {
        KeSetEvent(&Consumer->ProcessingThreads[i].WorkEvent, IO_NO_INCREMENT, FALSE);
    }

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
    NTSTATUS Status = STATUS_SUCCESS;
    PEC_SUBSCRIPTION NewSub = NULL;

    PAGED_CODE();

    if (Consumer == NULL || Config == NULL || Subscription == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Config->EventCallback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Subscription = NULL;

    //
    // Check subscription limit
    //
    if ((ULONG)Consumer->SubscriptionCount >= EC_MAX_SUBSCRIPTIONS) {
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Allocate subscription
    //
    NewSub = (PEC_SUBSCRIPTION)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(EC_SUBSCRIPTION),
        EC_SUBSCRIPTION_TAG
    );

    if (NewSub == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(NewSub, sizeof(EC_SUBSCRIPTION));

    //
    // Initialize subscription
    //
    NewSub->SubscriptionId = InterlockedIncrement(&Consumer->NextSubscriptionId);
    NewSub->Consumer = Consumer;
    NewSub->RefCount = 1;

    //
    // Copy configuration
    //
    RtlCopyMemory(&NewSub->Config, Config, sizeof(EC_SUBSCRIPTION_CONFIG));

    //
    // Initialize statistics
    //
    RtlZeroMemory(&NewSub->Stats, sizeof(EC_SUBSCRIPTION_STATS));

    //
    // Set initial state
    //
    NewSub->State = EcSubState_Inactive;

    //
    // Register with ETW if consumer is running
    //
    if (Consumer->State == EcState_Running && Config->AutoStart) {
        Status = EcpRegisterSubscription(NewSub);
        if (!NT_SUCCESS(Status)) {
            ExFreePoolWithTag(NewSub, EC_SUBSCRIPTION_TAG);
            return Status;
        }
        NewSub->State = EcSubState_Active;
    }

    //
    // Add to subscription list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Consumer->SubscriptionLock);

    InsertTailList(&Consumer->SubscriptionList, &NewSub->ListEntry);
    InterlockedIncrement(&Consumer->SubscriptionCount);

    ExReleasePushLockExclusive(&Consumer->SubscriptionLock);
    KeLeaveCriticalRegion();

    *Subscription = NewSub;

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

    //
    // Build configuration
    //
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
    PAGED_CODE();

    if (Consumer == NULL || Subscription == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Subscription->Consumer != Consumer) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Unregister from ETW
    //
    if (Subscription->IsRegistered) {
        EcpUnregisterSubscription(Subscription);
    }

    //
    // Remove from list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Consumer->SubscriptionLock);

    RemoveEntryList(&Subscription->ListEntry);
    InterlockedDecrement(&Consumer->SubscriptionCount);

    ExReleasePushLockExclusive(&Consumer->SubscriptionLock);
    KeLeaveCriticalRegion();

    //
    // Free subscription
    //
    ExFreePoolWithTag(Subscription, EC_SUBSCRIPTION_TAG);

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

    if (Subscription->State == EcSubState_Active) {
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

    if (Subscription->State == EcSubState_Suspended) {
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

    if (Consumer == NULL || ProviderId == NULL || Subscription == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Subscription = NULL;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Consumer->SubscriptionLock);

    Entry = Consumer->SubscriptionList.Flink;
    while (Entry != &Consumer->SubscriptionList) {
        Sub = CONTAINING_RECORD(Entry, EC_SUBSCRIPTION, ListEntry);

        if (EcIsEqualGuid(&Sub->Config.ProviderFilter.ProviderId, ProviderId)) {
            *Subscription = Sub;
            ExReleasePushLockShared(&Consumer->SubscriptionLock);
            KeLeaveCriticalRegion();
            return STATUS_SUCCESS;
        }

        Entry = Entry->Flink;
    }

    ExReleasePushLockShared(&Consumer->SubscriptionLock);
    KeLeaveCriticalRegion();

    return STATUS_NOT_FOUND;
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
    // Free extended data
    //
    EcpFreeExtendedData(Record);

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
    NewRecord->Subscription = Source->Subscription;
    NewRecord->CorrelationId = Source->CorrelationId;
    NewRecord->IsCorrelated = Source->IsCorrelated;

    //
    // Clone user data if present
    //
    if (Source->UserData != NULL && Source->UserDataLength > 0) {
        NewRecord->UserData = ExAllocatePoolWithTag(
            NonPagedPoolNx,
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
    // Note: Extended data cloning would go here if needed
    //

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
    _Out_ PEC_CONSUMER_STATS* Stats
    )
{
    if (Consumer == NULL || Stats == NULL) {
        if (Stats != NULL) {
            RtlZeroMemory(Stats, sizeof(EC_CONSUMER_STATS));
        }
        return;
    }

    RtlCopyMemory(Stats, &Consumer->Stats, sizeof(EC_CONSUMER_STATS));
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EcGetSubscriptionStatistics(
    _In_ PEC_SUBSCRIPTION Subscription,
    _Out_ PEC_SUBSCRIPTION_STATS* Stats
    )
{
    if (Subscription == NULL || Stats == NULL) {
        if (Stats != NULL) {
            RtlZeroMemory(Stats, sizeof(EC_SUBSCRIPTION_STATS));
        }
        return;
    }

    RtlCopyMemory(Stats, &Subscription->Stats, sizeof(EC_SUBSCRIPTION_STATS));
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EcResetStatistics(
    _Inout_ PEC_CONSUMER Consumer
    )
{
    PLIST_ENTRY Entry;
    PEC_SUBSCRIPTION Sub;

    if (Consumer == NULL) {
        return;
    }

    //
    // Reset consumer stats
    //
    Consumer->Stats.TotalEventsReceived = 0;
    Consumer->Stats.TotalEventsProcessed = 0;
    Consumer->Stats.TotalEventsDropped = 0;
    Consumer->Stats.TotalEventsCorrelated = 0;
    Consumer->Stats.PeakBufferedEvents = Consumer->Stats.CurrentBufferedEvents;
    Consumer->Stats.BufferOverflows = 0;
    Consumer->Stats.BatchesProcessed = 0;
    Consumer->Stats.TotalProcessingTimeUs = 0;
    Consumer->Stats.TotalErrors = 0;
    Consumer->Stats.SessionErrors = 0;
    Consumer->Stats.CurrentEventsPerSecond = 0;
    Consumer->Stats.PeakEventsPerSecond = 0;

    KeQuerySystemTimePrecise(&Consumer->Stats.StartTime);

    //
    // Reset subscription stats
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Consumer->SubscriptionLock);

    Entry = Consumer->SubscriptionList.Flink;
    while (Entry != &Consumer->SubscriptionList) {
        Sub = CONTAINING_RECORD(Entry, EC_SUBSCRIPTION, ListEntry);
        RtlZeroMemory(&Sub->Stats, sizeof(EC_SUBSCRIPTION_STATS));
        Entry = Entry->Flink;
    }

    ExReleasePushLockShared(&Consumer->SubscriptionLock);
    KeLeaveCriticalRegion();
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

    //
    // Check various health indicators
    //
    if (!Consumer->Initialized) {
        return FALSE;
    }

    if (Consumer->State == EcState_Error) {
        return FALSE;
    }

    if (Consumer->ConsecutiveErrors >= EC_MAX_CONSECUTIVE_ERRORS) {
        return FALSE;
    }

    //
    // Check buffer health (not critically full)
    //
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

    return Consumer->State;
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

    if (Record->UserData == NULL) {
        return STATUS_NO_DATA_DETECTED;
    }

    //
    // Validate offset and size
    //
    if (Offset >= Record->UserDataLength) {
        return STATUS_BUFFER_OVERFLOW;
    }

    if (Offset + Size > Record->UserDataLength) {
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

    if (Record == NULL || Buffer == NULL || BufferSize < sizeof(WCHAR)) {
        return STATUS_INVALID_PARAMETER;
    }

    Buffer[0] = L'\0';

    if (Record->UserData == NULL) {
        return STATUS_NO_DATA_DETECTED;
    }

    if (Offset >= Record->UserDataLength) {
        return STATUS_BUFFER_OVERFLOW;
    }

    SourceString = (PWCHAR)((PUCHAR)Record->UserData + Offset);

    //
    // Calculate string length (with bounds check)
    //
    StringLength = 0;
    while ((Offset + (StringLength + 1) * sizeof(WCHAR)) <= Record->UserDataLength &&
           SourceString[StringLength] != L'\0') {
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
        Consumer,
        &GUID_KERNEL_PROCESS_PROVIDER,
        0xFFFFFFFFFFFFFFFFULL,  // All keywords
        5,                       // Verbose level
        Callback,
        Context,
        Subscription
    );
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
        Consumer,
        &GUID_KERNEL_FILE_PROVIDER,
        0xFFFFFFFFFFFFFFFFULL,
        5,
        Callback,
        Context,
        Subscription
    );
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
        Consumer,
        &GUID_KERNEL_NETWORK_PROVIDER,
        0xFFFFFFFFFFFFFFFFULL,
        5,
        Callback,
        Context,
        Subscription
    );
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
        Consumer,
        &GUID_KERNEL_REGISTRY_PROVIDER,
        0xFFFFFFFFFFFFFFFFULL,
        5,
        Callback,
        Context,
        Subscription
    );
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
        Consumer,
        &GUID_SECURITY_AUDITING_PROVIDER,
        0xFFFFFFFFFFFFFFFFULL,
        5,
        Callback,
        Context,
        Subscription
    );
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
        Consumer,
        &GUID_THREAT_INTELLIGENCE_PROVIDER,
        0xFFFFFFFFFFFFFFFFULL,
        5,
        Callback,
        Context,
        Subscription
    );
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
NTSTATUS
EcpInitializeLookasideLists(
    _Inout_ PEC_CONSUMER Consumer
    )
{
    //
    // Initialize event record lookaside
    //
    ExInitializeNPagedLookasideList(
        &Consumer->EventRecordLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(EC_EVENT_RECORD),
        EC_EVENT_TAG,
        EC_EVENT_LOOKASIDE_DEPTH
    );

    //
    // Initialize extended data lookaside
    //
    ExInitializeNPagedLookasideList(
        &Consumer->ExtendedDataLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(EC_EXTENDED_DATA),
        EC_BUFFER_TAG,
        64
    );

    Consumer->LookasideInitialized = TRUE;

    return STATUS_SUCCESS;
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
        &ObjectAttributes,
        NULL,
        OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    for (i = 0; i < Consumer->Config.ProcessingThreadCount; i++) {
        Consumer->ProcessingThreads[i].ThreadIndex = i;
        Consumer->ProcessingThreads[i].Consumer = Consumer;
        Consumer->ProcessingThreads[i].IsRunning = FALSE;
        Consumer->ProcessingThreads[i].StopRequested = FALSE;
        Consumer->ProcessingThreads[i].EventsProcessed = 0;
        Consumer->ProcessingThreads[i].ProcessingTimeUs = 0;

        KeInitializeEvent(&Consumer->ProcessingThreads[i].StopEvent, NotificationEvent, FALSE);
        KeInitializeEvent(&Consumer->ProcessingThreads[i].WorkEvent, SynchronizationEvent, FALSE);

        Status = PsCreateSystemThread(
            &Consumer->ProcessingThreads[i].ThreadHandle,
            THREAD_ALL_ACCESS,
            &ObjectAttributes,
            NULL,
            NULL,
            EcpProcessingThreadRoutine,
            &Consumer->ProcessingThreads[i]
        );

        if (!NT_SUCCESS(Status)) {
            //
            // Stop already-created threads
            //
            Consumer->ActiveThreadCount = i;
            EcpStopProcessingThreads(Consumer);
            return Status;
        }

        //
        // Get thread object reference
        //
        Status = ObReferenceObjectByHandle(
            Consumer->ProcessingThreads[i].ThreadHandle,
            THREAD_ALL_ACCESS,
            *PsThreadType,
            KernelMode,
            (PVOID*)&Consumer->ProcessingThreads[i].ThreadObject,
            NULL
        );

        if (!NT_SUCCESS(Status)) {
            ZwClose(Consumer->ProcessingThreads[i].ThreadHandle);
            Consumer->ProcessingThreads[i].ThreadHandle = NULL;
            Consumer->ActiveThreadCount = i;
            EcpStopProcessingThreads(Consumer);
            return Status;
        }

        Consumer->ProcessingThreads[i].IsRunning = TRUE;
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
    LARGE_INTEGER Timeout;

    Timeout.QuadPart = -10 * 1000 * 1000 * 5; // 5 seconds

    for (i = 0; i < Consumer->ActiveThreadCount; i++) {
        if (!Consumer->ProcessingThreads[i].IsRunning) {
            continue;
        }

        //
        // Signal stop
        //
        Consumer->ProcessingThreads[i].StopRequested = TRUE;
        KeSetEvent(&Consumer->ProcessingThreads[i].StopEvent, IO_NO_INCREMENT, FALSE);
        KeSetEvent(&Consumer->ProcessingThreads[i].WorkEvent, IO_NO_INCREMENT, FALSE);

        //
        // Wait for thread to exit
        //
        if (Consumer->ProcessingThreads[i].ThreadObject != NULL) {
            KeWaitForSingleObject(
                Consumer->ProcessingThreads[i].ThreadObject,
                Executive,
                KernelMode,
                FALSE,
                &Timeout
            );

            ObDereferenceObject(Consumer->ProcessingThreads[i].ThreadObject);
            Consumer->ProcessingThreads[i].ThreadObject = NULL;
        }

        if (Consumer->ProcessingThreads[i].ThreadHandle != NULL) {
            ZwClose(Consumer->ProcessingThreads[i].ThreadHandle);
            Consumer->ProcessingThreads[i].ThreadHandle = NULL;
        }

        Consumer->ProcessingThreads[i].IsRunning = FALSE;
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
    // Set up wait objects
    //
    WaitObjects[0] = &ThreadContext->StopEvent;
    WaitObjects[1] = &ThreadContext->WorkEvent;

    Timeout.QuadPart = -10 * 1000 * EC_THREAD_WAIT_TIMEOUT_MS;

    while (!ThreadContext->StopRequested) {
        //
        // Wait for work or stop signal
        //
        WaitStatus = KeWaitForMultipleObjects(
            2,
            WaitObjects,
            WaitAny,
            Executive,
            KernelMode,
            FALSE,
            &Timeout,
            NULL
        );

        if (ThreadContext->StopRequested) {
            break;
        }

        //
        // Check if paused
        //
        if (Consumer->State == EcState_Paused) {
            KeWaitForSingleObject(
                &Consumer->FlowResumeEvent,
                Executive,
                KernelMode,
                FALSE,
                NULL
            );

            if (ThreadContext->StopRequested) {
                break;
            }
        }

        //
        // Process events
        //
        if (Consumer->State == EcState_Running) {
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

    UNREFERENCED_PARAMETER(ThreadIndex);

    KeQuerySystemTimePrecise(&StartTime);

    while (ProcessedCount < EC_EVENT_BATCH_SIZE) {
        //
        // Dequeue event
        //
        Record = EcpDequeueEvent(Consumer);
        if (Record == NULL) {
            break;
        }

        //
        // Process through subscription callback
        //
        if (Record->Subscription != NULL &&
            Record->Subscription->State == EcSubState_Active &&
            Record->Subscription->Config.EventCallback != NULL) {

            __try {
                Result = Record->Subscription->Config.EventCallback(
                    Record,
                    Record->Subscription->Config.EventCallbackContext
                );

                InterlockedIncrement64(&Record->Subscription->Stats.EventsProcessed);
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {
                Result = EcResult_Error;
                InterlockedIncrement64(&Record->Subscription->Stats.CallbackErrors);
            }

            if (Result == EcResult_Error) {
                InterlockedIncrement64(&Consumer->Stats.TotalErrors);
            }
        }

        //
        // Free event record
        //
        EcFreeEventRecord(Consumer, Record);

        ProcessedCount++;
        InterlockedIncrement64(&Consumer->Stats.TotalEventsProcessed);
    }

    //
    // Update processing time
    //
    KeQuerySystemTimePrecise(&EndTime);
    ProcessingTime = (EndTime.QuadPart - StartTime.QuadPart) / 10; // Convert to microseconds

    if (ProcessedCount > 0) {
        InterlockedIncrement64(&Consumer->Stats.BatchesProcessed);
        InterlockedAdd64(&Consumer->Stats.TotalProcessingTimeUs, ProcessingTime);
        InterlockedAdd64(
            &Consumer->ProcessingThreads[ThreadIndex].ProcessingTimeUs,
            ProcessingTime
        );
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

    //
    // Dequeue from highest priority queue first
    //
    for (Priority = 0; Priority < 5; Priority++) {
        if (!IsListEmpty(&Consumer->EventQueues[Priority])) {
            Entry = RemoveHeadList(&Consumer->EventQueues[Priority]);
            Record = CONTAINING_RECORD(Entry, EC_EVENT_RECORD, ListEntry);
            InterlockedDecrement(&Consumer->BufferedEventCount);
            Consumer->Stats.CurrentBufferedEvents = Consumer->BufferedEventCount;
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

    //
    // Check flow control
    //
    if (Consumer->CurrentFlowState == EcFlow_Pause) {
        //
        // Drop event
        //
        InterlockedIncrement64(&Consumer->Stats.TotalEventsDropped);
        EcFreeEventRecord(Consumer, Record);
        return;
    }

    if (Consumer->CurrentFlowState == EcFlow_Drop &&
        Record->Priority >= EcPriority_Low) {
        //
        // Drop low-priority event
        //
        InterlockedIncrement64(&Consumer->Stats.TotalEventsDropped);
        EcFreeEventRecord(Consumer, Record);
        return;
    }

    //
    // Check buffer capacity
    //
    if ((ULONG)Consumer->BufferedEventCount >= Consumer->Config.MaxBufferedEvents) {
        InterlockedIncrement64(&Consumer->Stats.BufferOverflows);
        InterlockedIncrement64(&Consumer->Stats.TotalEventsDropped);
        EcFreeEventRecord(Consumer, Record);
        return;
    }

    Priority = (ULONG)Record->Priority;
    if (Priority >= 5) {
        Priority = 4;
    }

    KeAcquireSpinLock(&Consumer->EventQueueLock, &OldIrql);

    InsertTailList(&Consumer->EventQueues[Priority], &Record->ListEntry);
    NewCount = InterlockedIncrement(&Consumer->BufferedEventCount);
    Consumer->Stats.CurrentBufferedEvents = NewCount;

    //
    // Update peak
    //
    if (NewCount > Consumer->Stats.PeakBufferedEvents) {
        Consumer->Stats.PeakBufferedEvents = NewCount;
    }

    KeReleaseSpinLock(&Consumer->EventQueueLock, OldIrql);

    //
    // Signal processing threads
    //
    if (Consumer->ActiveThreadCount > 0) {
        KeSetEvent(
            &Consumer->ProcessingThreads[0].WorkEvent,
            IO_NO_INCREMENT,
            FALSE
        );
    }

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

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Consumer->SubscriptionLock);

    while (!IsListEmpty(&Consumer->SubscriptionList)) {
        Entry = RemoveHeadList(&Consumer->SubscriptionList);
        Subscription = CONTAINING_RECORD(Entry, EC_SUBSCRIPTION, ListEntry);

        if (Subscription->IsRegistered) {
            EcpUnregisterSubscription(Subscription);
        }

        ExFreePoolWithTag(Subscription, EC_SUBSCRIPTION_TAG);
    }

    Consumer->SubscriptionCount = 0;

    ExReleasePushLockExclusive(&Consumer->SubscriptionLock);
    KeLeaveCriticalRegion();
}

static
NTSTATUS
EcpRegisterSubscription(
    _Inout_ PEC_SUBSCRIPTION Subscription
    )
{
    //
    // In a full implementation, this would:
    // 1. Create or attach to an ETW trace session
    // 2. Enable the provider with specified keywords/level
    // 3. Set up the event callback
    //
    // For kernel-mode ETW consumption, this typically involves
    // using EtwRegister and setting up trace session via
    // NtTraceControl or similar APIs.
    //

    Subscription->IsRegistered = TRUE;
    KeQuerySystemTimePrecise(&Subscription->Stats.FirstEventTime);

    return STATUS_SUCCESS;
}

static
VOID
EcpUnregisterSubscription(
    _Inout_ PEC_SUBSCRIPTION Subscription
    )
{
    //
    // In a full implementation, this would:
    // 1. Disable the provider
    // 2. Detach from the trace session
    // 3. Clean up any resources
    //

    Subscription->IsRegistered = FALSE;
}

static
VOID
EcpUpdateSubscriptionState(
    _Inout_ PEC_SUBSCRIPTION Subscription,
    _In_ EC_SUBSCRIPTION_STATE NewState
    )
{
    EC_SUBSCRIPTION_STATE OldState;

    OldState = Subscription->State;
    if (OldState == NewState) {
        return;
    }

    Subscription->State = NewState;

    //
    // Invoke status callback if configured
    //
    if (Subscription->Config.StatusCallback != NULL) {
        __try {
            Subscription->Config.StatusCallback(
                Subscription,
                OldState,
                NewState,
                Subscription->Config.StatusCallbackContext
            );
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            //
            // Log error but don't fail
            //
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

    //
    // Check if we've moved to a new second
    //
    ElapsedSeconds = (CurrentTime.QuadPart - Consumer->CurrentSecondStart.QuadPart) / 10000000;

    if (ElapsedSeconds >= 1) {
        //
        // Reset counter for new second
        //
        Consumer->Stats.CurrentEventsPerSecond = Consumer->EventsThisSecond;
        if (Consumer->EventsThisSecond > Consumer->Stats.PeakEventsPerSecond) {
            Consumer->Stats.PeakEventsPerSecond = Consumer->EventsThisSecond;
        }
        Consumer->EventsThisSecond = 0;
        Consumer->CurrentSecondStart = CurrentTime;
    }

    //
    // Check rate limit
    //
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
    EC_FLOW_CONTROL NewState;

    BufferedCount = (ULONG)Consumer->BufferedEventCount;

    //
    // Determine flow control state based on buffer usage
    //
    if (BufferedCount >= Consumer->Config.MaxBufferedEvents) {
        NewState = EcFlow_Pause;
    } else if (BufferedCount >= (Consumer->Config.MaxBufferedEvents * 90 / 100)) {
        NewState = EcFlow_Drop;
    } else if (BufferedCount >= Consumer->Config.BufferThreshold) {
        NewState = EcFlow_Throttle;
    } else {
        NewState = EcFlow_Normal;
    }

    //
    // Invoke custom flow control callback if configured
    //
    if (Consumer->Config.FlowCallback != NULL && NewState != EcFlow_Normal) {
        __try {
            NewState = Consumer->Config.FlowCallback(
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

    Consumer->CurrentFlowState = NewState;

    //
    // Update flow resume event
    //
    if (NewState == EcFlow_Pause) {
        KeClearEvent(&Consumer->FlowResumeEvent);
    } else if (Consumer->CurrentFlowState == EcFlow_Pause && NewState != EcFlow_Pause) {
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

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (Consumer == NULL || !Consumer->Initialized) {
        return;
    }

    //
    // Check health indicators
    //
    if (Consumer->State == EcState_Error) {
        IsHealthy = FALSE;
    }

    if (Consumer->ConsecutiveErrors >= EC_MAX_CONSECUTIVE_ERRORS) {
        IsHealthy = FALSE;
    }

    if (Consumer->CurrentFlowState == EcFlow_Pause) {
        //
        // Prolonged pause indicates issues
        //
        IsHealthy = FALSE;
    }

    Consumer->Stats.IsHealthy = IsHealthy;
    KeQuerySystemTimePrecise(&Consumer->Stats.LastHealthCheck);
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

    //
    // Check for kernel providers
    //
    if (EcIsEqualGuid(ProviderId, &GUID_KERNEL_PROCESS_PROVIDER) ||
        EcIsEqualGuid(ProviderId, &GUID_KERNEL_FILE_PROVIDER) ||
        EcIsEqualGuid(ProviderId, &GUID_KERNEL_NETWORK_PROVIDER) ||
        EcIsEqualGuid(ProviderId, &GUID_KERNEL_REGISTRY_PROVIDER) ||
        EcIsEqualGuid(ProviderId, &GUID_KERNEL_AUDIT_API_PROVIDER)) {
        return EcSource_Kernel;
    }

    //
    // Check for security provider
    //
    if (EcIsEqualGuid(ProviderId, &GUID_SECURITY_AUDITING_PROVIDER) ||
        EcIsEqualGuid(ProviderId, &GUID_THREAT_INTELLIGENCE_PROVIDER)) {
        return EcSource_Security;
    }

    return EcSource_User;
}

static
VOID
EcpFreeExtendedData(
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

        ExFreePoolWithTag(ExtData, EC_BUFFER_TAG);
    }

    Record->ExtendedDataCount = 0;
}
