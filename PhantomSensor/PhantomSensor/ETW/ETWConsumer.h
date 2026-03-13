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
 * ShadowStrike NGAV - ENTERPRISE ETW CONSUMER
 * ============================================================================
 *
 * @file ETWConsumer.h
 * @brief Enterprise-grade kernel event processing engine for EDR operations.
 *
 * This module provides a high-performance event processing pipeline that
 * receives events from kernel callbacks (process, file, registry, network
 * notify routines) and processes them through subscription-based filtering
 * and callback dispatch.
 *
 * Architecture:
 * In Windows kernel mode, drivers are ETW *providers* (via EtwRegister),
 * not consumers. Actual event ingestion comes from kernel notify callbacks
 * (PsSetCreateProcessNotifyRoutine, CmRegisterCallbackEx, etc.). This
 * module provides the *processing pipeline* that those callbacks feed into.
 *
 * The public EcIngestEvent() API is the entry point for kernel callbacks
 * to submit events into the priority-queued processing pipeline.
 *
 * Features:
 * - Priority-based event queuing (5 levels)
 * - Multi-threaded batch processing
 * - Subscription-based event filtering and dispatch
 * - Reference-counted subscription lifetime management
 * - Backpressure / flow control with configurable thresholds
 * - Rate limiting to prevent resource exhaustion
 * - Health monitoring via periodic timer
 * - Integration with ShadowStrike TelemetryEvents and ThreatScoring
 * - IRQL-aware implementations throughout
 *
 * Supported Event Sources:
 * - Kernel process/thread/image callbacks
 * - Registry callbacks (CmRegisterCallbackEx)
 * - File system minifilter callbacks
 * - Network (WFP) callouts
 * - Custom ShadowStrike internal events
 *
 * Security Guarantees:
 * - All event data validated before processing
 * - Buffer overflow protection on all operations
 * - Rate limiting to prevent resource exhaustion
 * - Secure cleanup of sensitive event data
 * - Reference counting prevents use-after-free
 * - IRQL-correct implementations
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_ETW_CONSUMER_H_
#define _SHADOWSTRIKE_ETW_CONSUMER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>

// ============================================================================
// POOL TAGS
// ============================================================================

/** @brief Pool tag for ETW consumer general allocations: 'EcSs' */
#define EC_POOL_TAG             'sCcE'

/** @brief Pool tag for ETW event records: 'ErSs' */
#define EC_EVENT_TAG            'rEcE'

/** @brief Pool tag for ETW subscription allocations: 'EsSs' */
#define EC_SUBSCRIPTION_TAG     'sScE'

/** @brief Pool tag for ETW buffer allocations: 'EbSs' */
#define EC_BUFFER_TAG           'bBcE'

/** @brief Pool tag for ETW session allocations: 'EtSs' */
#define EC_SESSION_TAG          'tScE'

// ============================================================================
// CONFIGURATION CONSTANTS
// ============================================================================

/** @brief Maximum number of concurrent subscriptions */
#define EC_MAX_SUBSCRIPTIONS            64

/** @brief Maximum buffered events before flow control */
#define EC_MAX_BUFFERED_EVENTS          10000

/** @brief Default buffered event threshold for backpressure */
#define EC_DEFAULT_BUFFER_THRESHOLD     5000

/** @brief Maximum event user data size (256 KB) */
#define EC_MAX_EVENT_DATA_SIZE          (256 * 1024)

/** @brief Maximum provider name length */
#define EC_MAX_PROVIDER_NAME_LENGTH     256

/** @brief Maximum session name length */
#define EC_MAX_SESSION_NAME_LENGTH      256

/** @brief Default processing thread count */
#define EC_DEFAULT_THREAD_COUNT         2

/** @brief Maximum processing thread count */
#define EC_MAX_THREAD_COUNT             8

/** @brief Event batch size for processing */
#define EC_EVENT_BATCH_SIZE             32

/** @brief Rate limit: max events per second (0 = unlimited) */
#define EC_DEFAULT_RATE_LIMIT           0

/** @brief Lookaside list depth for event records */
#define EC_EVENT_LOOKASIDE_DEPTH        256

/** @brief Timeout for event processing (ms) */
#define EC_PROCESSING_TIMEOUT_MS        5000

/** @brief Health check interval (seconds) */
#define EC_HEALTH_CHECK_INTERVAL_SEC    30

/** @brief Number of priority queue levels */
#define EC_PRIORITY_QUEUE_COUNT         5

// ============================================================================
// WELL-KNOWN ETW PROVIDER GUIDs
// ============================================================================

// {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
DEFINE_GUID(GUID_KERNEL_PROCESS_PROVIDER,
    0x22fb2cd6, 0x0e7b, 0x422b, 0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16);

// {EDD08927-9CC4-4E65-B970-C2560FB5C289}
DEFINE_GUID(GUID_KERNEL_FILE_PROVIDER,
    0xedd08927, 0x9cc4, 0x4e65, 0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x89);

// {7DD42A49-5329-4832-8DFD-43D979153A88}
DEFINE_GUID(GUID_KERNEL_NETWORK_PROVIDER,
    0x7dd42a49, 0x5329, 0x4832, 0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88);

// {70EB4F03-C1DE-4F73-A051-33D13D5413BD}
DEFINE_GUID(GUID_KERNEL_REGISTRY_PROVIDER,
    0x70eb4f03, 0xc1de, 0x4f73, 0xa0, 0x51, 0x33, 0xd1, 0x3d, 0x54, 0x13, 0xbd);

// {54849625-5478-4994-A5BA-3E3B0328C30D}
DEFINE_GUID(GUID_SECURITY_AUDITING_PROVIDER,
    0x54849625, 0x5478, 0x4994, 0xa5, 0xba, 0x3e, 0x3b, 0x03, 0x28, 0xc3, 0x0d);

// {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}
DEFINE_GUID(GUID_DNS_CLIENT_PROVIDER,
    0x1c95126e, 0x7eea, 0x49a9, 0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d);

// {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}
DEFINE_GUID(GUID_THREAT_INTELLIGENCE_PROVIDER,
    0xf4e1897c, 0xbb5d, 0x5668, 0xf1, 0xd8, 0x04, 0x0f, 0x4d, 0x8d, 0xd3, 0x44);

// {E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23}
DEFINE_GUID(GUID_KERNEL_AUDIT_API_PROVIDER,
    0xe02a841c, 0x75a3, 0x4fa7, 0xaf, 0xc8, 0xae, 0x09, 0xcf, 0x9b, 0x7f, 0x23);

// ============================================================================
// ENUMERATIONS
// ============================================================================

/** @brief ETW consumer state */
typedef enum _EC_STATE {
    EcState_Uninitialized = 0,
    EcState_Initialized,
    EcState_Starting,
    EcState_Running,
    EcState_Paused,
    EcState_Stopping,
    EcState_Stopped,
    EcState_Error
} EC_STATE;

/** @brief Subscription state */
typedef enum _EC_SUBSCRIPTION_STATE {
    EcSubState_Inactive = 0,
    EcSubState_Active,
    EcSubState_Suspended,
    EcSubState_Error
} EC_SUBSCRIPTION_STATE;

/** @brief Event priority for processing order */
typedef enum _EC_EVENT_PRIORITY {
    EcPriority_Critical = 0,
    EcPriority_High,
    EcPriority_Normal,
    EcPriority_Low,
    EcPriority_Background
} EC_EVENT_PRIORITY;

/** @brief Event processing result */
typedef enum _EC_PROCESS_RESULT {
    EcResult_Continue = 0,
    EcResult_Skip,
    EcResult_Block,
    EcResult_Escalate,
    EcResult_Error
} EC_PROCESS_RESULT;

/** @brief Event source type */
typedef enum _EC_EVENT_SOURCE {
    EcSource_Unknown = 0,
    EcSource_Kernel,
    EcSource_User,
    EcSource_Security,
    EcSource_Custom
} EC_EVENT_SOURCE;

/** @brief Flow control action */
typedef enum _EC_FLOW_CONTROL {
    EcFlow_Normal = 0,
    EcFlow_Throttle,
    EcFlow_Drop,
    EcFlow_Pause
} EC_FLOW_CONTROL;

// ============================================================================
// FORWARD DECLARATIONS & CALLBACK TYPES
// ============================================================================

typedef struct _EC_EVENT_RECORD EC_EVENT_RECORD, *PEC_EVENT_RECORD;
typedef struct _EC_SUBSCRIPTION EC_SUBSCRIPTION, *PEC_SUBSCRIPTION;
typedef struct _EC_CONSUMER EC_CONSUMER, *PEC_CONSUMER;

/**
 * @brief Event callback function type.
 * @irql <= DISPATCH_LEVEL
 */
typedef EC_PROCESS_RESULT
(NTAPI *EC_EVENT_CALLBACK)(
    _In_ PEC_EVENT_RECORD Record,
    _In_opt_ PVOID Context
    );

/**
 * @brief Subscription status callback.
 * @irql PASSIVE_LEVEL
 */
typedef VOID
(NTAPI *EC_STATUS_CALLBACK)(
    _In_ PEC_SUBSCRIPTION Subscription,
    _In_ EC_SUBSCRIPTION_STATE OldState,
    _In_ EC_SUBSCRIPTION_STATE NewState,
    _In_opt_ PVOID Context
    );

/**
 * @brief Event filter callback (high-performance pre-filter).
 * @irql <= DISPATCH_LEVEL
 */
typedef BOOLEAN
(NTAPI *EC_FILTER_CALLBACK)(
    _In_ LPCGUID ProviderId,
    _In_ USHORT EventId,
    _In_ UCHAR Level,
    _In_ ULONGLONG Keywords,
    _In_opt_ PVOID Context
    );

/**
 * @brief Flow control callback.
 * @irql <= DISPATCH_LEVEL
 */
typedef EC_FLOW_CONTROL
(NTAPI *EC_FLOW_CALLBACK)(
    _In_ PEC_CONSUMER Consumer,
    _In_ ULONG BufferedCount,
    _In_ ULONG MaxCount,
    _In_opt_ PVOID Context
    );

// ============================================================================
// STRUCTURES
// ============================================================================

/** @brief ETW event header (subset of EVENT_HEADER) */
typedef struct _EC_EVENT_HEADER {
    USHORT EventId;
    UCHAR Version;
    UCHAR Channel;
    UCHAR Level;
    UCHAR Opcode;
    USHORT Task;
    ULONGLONG Keywords;
    LARGE_INTEGER Timestamp;
    GUID ActivityId;
    GUID RelatedActivityId;
    ULONG ProcessId;
    ULONG ThreadId;
    GUID ProviderId;
} EC_EVENT_HEADER, *PEC_EVENT_HEADER;

/** @brief Extended event data item */
typedef struct _EC_EXTENDED_DATA {
    USHORT ExtType;
    USHORT DataSize;
    PVOID DataPtr;
    LIST_ENTRY ListEntry;
    BOOLEAN IsFromLookaside;  // Track allocation source for correct deallocation
    UCHAR Reserved[3];
} EC_EXTENDED_DATA, *PEC_EXTENDED_DATA;

/** @brief ETW event record with full context */
typedef struct _EC_EVENT_RECORD {
    EC_EVENT_HEADER Header;

    PVOID UserData;
    ULONG UserDataLength;

    LIST_ENTRY ExtendedDataList;
    ULONG ExtendedDataCount;

    EC_EVENT_PRIORITY Priority;
    EC_EVENT_SOURCE Source;
    ULONG SequenceNumber;

    LARGE_INTEGER ReceiveTime;
    LARGE_INTEGER ProcessTime;

    /**
     * @brief Reference to subscription that matched.
     * This pointer is reference-counted: the subscription's RefCount
     * is incremented when this field is set, and decremented when
     * this record is freed.
     */
    PEC_SUBSCRIPTION Subscription;

    ULONGLONG CorrelationId;
    BOOLEAN IsCorrelated;

    BOOLEAN IsAllocated;    // TRUE if UserData was separately allocated
    BOOLEAN IsPooled;       // TRUE if record came from lookaside
    UCHAR Reserved;

    LIST_ENTRY ListEntry;
} EC_EVENT_RECORD, *PEC_EVENT_RECORD;

/** @brief Provider filter specification */
typedef struct _EC_PROVIDER_FILTER {
    GUID ProviderId;
    WCHAR ProviderName[EC_MAX_PROVIDER_NAME_LENGTH];
    ULONGLONG MatchAnyKeyword;
    ULONGLONG MatchAllKeyword;
    UCHAR MaxLevel;
    BOOLEAN EnableStackCapture;
    BOOLEAN EnableProcessCapture;
    UCHAR Reserved;
    PUSHORT EventIdFilter;
    ULONG EventIdFilterCount;
} EC_PROVIDER_FILTER, *PEC_PROVIDER_FILTER;

/** @brief Subscription configuration */
typedef struct _EC_SUBSCRIPTION_CONFIG {
    EC_PROVIDER_FILTER ProviderFilter;
    EC_EVENT_CALLBACK EventCallback;
    PVOID EventCallbackContext;
    EC_FILTER_CALLBACK FilterCallback;
    PVOID FilterCallbackContext;
    EC_STATUS_CALLBACK StatusCallback;
    PVOID StatusCallbackContext;
    EC_EVENT_PRIORITY Priority;
    BOOLEAN AutoStart;
    BOOLEAN EnableCorrelation;
    UCHAR Reserved[2];
} EC_SUBSCRIPTION_CONFIG, *PEC_SUBSCRIPTION_CONFIG;

/** @brief Subscription statistics */
typedef struct _EC_SUBSCRIPTION_STATS {
    volatile LONG64 EventsReceived;
    volatile LONG64 EventsProcessed;
    volatile LONG64 EventsDropped;
    volatile LONG64 EventsFiltered;
    volatile LONG64 CallbackErrors;
    volatile LONG64 FilterErrors;
    LARGE_INTEGER FirstEventTime;
    LARGE_INTEGER LastEventTime;
    volatile LONG64 TotalProcessingTimeUs;
    volatile LONG64 MaxProcessingTimeUs;
    volatile LONG CurrentRate;
    volatile LONG PeakRate;
} EC_SUBSCRIPTION_STATS, *PEC_SUBSCRIPTION_STATS;

/** @brief ETW subscription instance */
typedef struct _EC_SUBSCRIPTION {
    ULONG SubscriptionId;
    volatile LONG State;  // EC_SUBSCRIPTION_STATE, interlocked for thread safety
    EC_SUBSCRIPTION_CONFIG Config;
    EC_SUBSCRIPTION_STATS Stats;
    PEC_CONSUMER Consumer;
    TRACEHANDLE SessionHandle;
    volatile LONG64 SequenceNumber;
    NTSTATUS LastError;
    volatile LONG ConsecutiveErrors;
    LIST_ENTRY ListEntry;

    /**
     * @brief Reference count for lifetime management.
     * Starts at 1 (creation). Incremented when:
     *   - An event record references this subscription
     *   - EcFindSubscription returns this subscription
     * Decremented when:
     *   - An event record referencing this is freed
     *   - Caller releases a find result via EcReleaseSubscription
     * When refcount reaches 0, subscription is freed.
     */
    volatile LONG RefCount;

    /** @brief Set when unsubscribe is pending (waiting for refcount drain) */
    volatile LONG UnsubscribePending;
    BOOLEAN IsRegistered;

    /** @brief TRUE when this subscription is linked into Consumer->SubscriptionList */
    volatile LONG IsInList;

    BOOLEAN UsesSharedSession;
    UCHAR Reserved[3];
} EC_SUBSCRIPTION, *PEC_SUBSCRIPTION;

/** @brief Consumer configuration */
typedef struct _EC_CONSUMER_CONFIG {
    WCHAR SessionName[EC_MAX_SESSION_NAME_LENGTH];
    ULONG MaxBufferedEvents;
    ULONG BufferThreshold;
    ULONG ProcessingThreadCount;
    ULONG MaxEventsPerSecond;
    EC_FLOW_CALLBACK FlowCallback;
    PVOID FlowCallbackContext;
    BOOLEAN EnableBatching;
    BOOLEAN AutoStart;
    BOOLEAN UseRealTimeSession;
    UCHAR Reserved;
} EC_CONSUMER_CONFIG, *PEC_CONSUMER_CONFIG;

/** @brief Consumer statistics */
typedef struct _EC_CONSUMER_STATS {
    volatile LONG64 TotalEventsReceived;
    volatile LONG64 TotalEventsProcessed;
    volatile LONG64 TotalEventsDropped;
    volatile LONG64 TotalEventsCorrelated;
    volatile LONG CurrentBufferedEvents;
    volatile LONG PeakBufferedEvents;
    volatile LONG64 BufferOverflows;
    volatile LONG64 BatchesProcessed;
    volatile LONG64 TotalProcessingTimeUs;
    volatile LONG64 TotalErrors;
    volatile LONG64 SessionErrors;
    LARGE_INTEGER StartTime;
    LARGE_INTEGER LastEventTime;
    volatile LONG CurrentEventsPerSecond;
    volatile LONG PeakEventsPerSecond;
    LARGE_INTEGER LastHealthCheck;
    BOOLEAN IsHealthy;
    UCHAR Reserved[3];
} EC_CONSUMER_STATS, *PEC_CONSUMER_STATS;

/** @brief Processing thread context */
typedef struct _EC_PROCESSING_THREAD {
    HANDLE ThreadHandle;
    PKTHREAD ThreadObject;
    ULONG ThreadIndex;
    KEVENT StopEvent;
    KEVENT WorkEvent;
    KEVENT ReadyEvent;      // Signaled by thread when it has started
    PEC_CONSUMER Consumer;
    volatile LONG64 EventsProcessed;
    volatile LONG64 ProcessingTimeUs;
    volatile LONG IsRunning;    // Interlocked for cross-thread visibility
    volatile LONG StopRequested;// Interlocked for cross-thread visibility
    UCHAR Reserved[4];
} EC_PROCESSING_THREAD, *PEC_PROCESSING_THREAD;

/** @brief ETW Consumer instance */
typedef struct _EC_CONSUMER {
    volatile LONG State;  // EC_STATE, interlocked for thread safety
    EC_CONSUMER_CONFIG Config;
    EC_CONSUMER_STATS Stats;

    // Subscriptions — KSPIN_LOCK for DISPATCH_LEVEL compatibility
    LIST_ENTRY SubscriptionList;
    KSPIN_LOCK SubscriptionLock;
    volatile LONG SubscriptionCount;
    volatile LONG NextSubscriptionId;

    // Event buffer (priority queues)
    LIST_ENTRY EventQueues[EC_PRIORITY_QUEUE_COUNT];
    KSPIN_LOCK EventQueueLock;
    volatile LONG BufferedEventCount;

    // Processing threads
    EC_PROCESSING_THREAD ProcessingThreads[EC_MAX_THREAD_COUNT];
    ULONG ActiveThreadCount;

    // Global stop event
    KEVENT StopEvent;

    // Trace session (for potential future ETW provider registration)
    TRACEHANDLE TraceSessionHandle;
    TRACEHANDLE ConsumerHandle;
    BOOLEAN SessionActive;

    // Memory pools
    NPAGED_LOOKASIDE_LIST EventRecordLookaside;
    NPAGED_LOOKASIDE_LIST ExtendedDataLookaside;
    BOOLEAN LookasideInitialized;

    // Flow control
    volatile LONG CurrentFlowState;  // EC_FLOW_CONTROL, interlocked
    KEVENT FlowResumeEvent;

    // Rate limiting
    volatile LONG EventsThisSecond;
    LARGE_INTEGER CurrentSecondStart;
    KSPIN_LOCK RateLimitLock;

    // Correlation engine reference
    PVOID CorrelationEngine;

    // Health monitoring - proper KTIMER (not HANDLE)
    KTIMER HealthCheckTimer;
    KDPC HealthCheckDpc;
    BOOLEAN HealthTimerActive;

    // Round-robin thread signaling index — overflow-safe by unsigned modulo
    volatile LONG NextThreadSignal;

    // Error tracking
    NTSTATUS LastError;
    volatile LONG ConsecutiveErrors;

    // Initialization flag
    BOOLEAN Initialized;
    UCHAR Reserved[3];
} EC_CONSUMER, *PEC_CONSUMER;

// ============================================================================
// INITIALIZATION AND LIFECYCLE
// ============================================================================

/**
 * @brief Initialize an ETW consumer instance.
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EcInitialize(
    _In_opt_ PEC_CONSUMER_CONFIG Config,
    _Out_ PEC_CONSUMER* Consumer
    );

/**
 * @brief Shutdown an ETW consumer instance.
 *
 * Stops all processing, unsubscribes from all providers, and releases
 * all resources. Sets *Consumer to NULL after freeing.
 *
 * @param Consumer      Pointer to consumer pointer. Set to NULL on return.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
EcShutdown(
    _Inout_ PEC_CONSUMER* Consumer
    );

/**
 * @brief Start the ETW consumer.
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EcStart(
    _Inout_ PEC_CONSUMER Consumer
    );

/**
 * @brief Stop the ETW consumer.
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
EcStop(
    _Inout_ PEC_CONSUMER Consumer
    );

/**
 * @brief Pause event processing.
 * @irql PASSIVE_LEVEL (requires synchronization with processing threads)
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
EcPause(
    _Inout_ PEC_CONSUMER Consumer
    );

/**
 * @brief Resume event processing.
 * @irql PASSIVE_LEVEL (requires synchronization with processing threads)
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
EcResume(
    _Inout_ PEC_CONSUMER Consumer
    );

// ============================================================================
// EVENT INGESTION (DESIGN-01: Proper kernel-mode event intake)
// ============================================================================

/**
 * @brief Ingest an event into the processing pipeline.
 *
 * This is the primary entry point for kernel callbacks to submit events.
 * The event record is enqueued into the appropriate priority queue and
 * a processing thread is signaled.
 *
 * Callers must allocate the record via EcAllocateEventRecord and populate
 * it before calling this function. Ownership of the record transfers to
 * the consumer on success.
 *
 * @param Consumer      Consumer instance
 * @param Record        Event record (ownership transferred on success)
 *
 * @return STATUS_SUCCESS or error status. On error, caller retains ownership.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
EcIngestEvent(
    _Inout_ PEC_CONSUMER Consumer,
    _Inout_ PEC_EVENT_RECORD Record
    );

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
    );

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
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
EcUnsubscribe(
    _Inout_ PEC_CONSUMER Consumer,
    _Inout_ PEC_SUBSCRIPTION Subscription
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
EcActivateSubscription(
    _Inout_ PEC_SUBSCRIPTION Subscription
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
EcSuspendSubscription(
    _Inout_ PEC_SUBSCRIPTION Subscription
    );

/**
 * @brief Get subscription by provider GUID.
 *
 * On success, the returned subscription has its reference count
 * incremented. Caller MUST call EcReleaseSubscription when done.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
EcFindSubscription(
    _In_ PEC_CONSUMER Consumer,
    _In_ LPCGUID ProviderId,
    _Out_ PEC_SUBSCRIPTION* Subscription
    );

/**
 * @brief Release a subscription reference obtained via EcFindSubscription.
 *
 * @param Subscription  Subscription to release
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EcReleaseSubscription(
    _In_ PEC_SUBSCRIPTION Subscription
    );

// ============================================================================
// EVENT RECORD MANAGEMENT
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
PEC_EVENT_RECORD
EcAllocateEventRecord(
    _In_ PEC_CONSUMER Consumer
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EcFreeEventRecord(
    _In_ PEC_CONSUMER Consumer,
    _Inout_ PEC_EVENT_RECORD Record
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
EcCloneEventRecord(
    _In_ PEC_CONSUMER Consumer,
    _In_ PEC_EVENT_RECORD Source,
    _Out_ PEC_EVENT_RECORD* Clone
    );

// ============================================================================
// STATISTICS AND MONITORING
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EcGetStatistics(
    _In_ PEC_CONSUMER Consumer,
    _Out_ PEC_CONSUMER_STATS Stats
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EcGetSubscriptionStatistics(
    _In_ PEC_SUBSCRIPTION Subscription,
    _Out_ PEC_SUBSCRIPTION_STATS Stats
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
EcResetStatistics(
    _Inout_ PEC_CONSUMER Consumer
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
EcIsHealthy(
    _In_ PEC_CONSUMER Consumer
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
EC_STATE
EcGetState(
    _In_ PEC_CONSUMER Consumer
    );

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
PCWSTR
EcGetProviderName(
    _In_ LPCGUID ProviderId
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
PCWSTR
EcGetLevelName(
    _In_ UCHAR Level
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
EcGetEventField(
    _In_ PEC_EVENT_RECORD Record,
    _In_ ULONG Offset,
    _In_ ULONG Size,
    _Out_writes_bytes_(Size) PVOID Buffer
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
EcGetEventString(
    _In_ PEC_EVENT_RECORD Record,
    _In_ ULONG Offset,
    _Out_writes_bytes_(BufferSize) PWCHAR Buffer,
    _In_ ULONG BufferSize
    );

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
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
EcSubscribeKernelFile(
    _Inout_ PEC_CONSUMER Consumer,
    _In_ EC_EVENT_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ PEC_SUBSCRIPTION* Subscription
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
EcSubscribeKernelNetwork(
    _Inout_ PEC_CONSUMER Consumer,
    _In_ EC_EVENT_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ PEC_SUBSCRIPTION* Subscription
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
EcSubscribeKernelRegistry(
    _Inout_ PEC_CONSUMER Consumer,
    _In_ EC_EVENT_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ PEC_SUBSCRIPTION* Subscription
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
EcSubscribeSecurityAuditing(
    _Inout_ PEC_CONSUMER Consumer,
    _In_ EC_EVENT_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ PEC_SUBSCRIPTION* Subscription
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
EcSubscribeThreatIntelligence(
    _Inout_ PEC_CONSUMER Consumer,
    _In_ EC_EVENT_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ PEC_SUBSCRIPTION* Subscription
    );

// ============================================================================
// INLINE UTILITIES
// ============================================================================

FORCEINLINE
BOOLEAN
EcIsRunning(
    _In_ PEC_CONSUMER Consumer
    )
{
    return (Consumer != NULL &&
            InterlockedCompareExchange(&Consumer->State, 0, 0) == (LONG)EcState_Running);
}

FORCEINLINE
BOOLEAN
EcIsSubscriptionActive(
    _In_ PEC_SUBSCRIPTION Subscription
    )
{
    return (Subscription != NULL &&
            InterlockedCompareExchange(&Subscription->State, 0, 0) == (LONG)EcSubState_Active);
}

FORCEINLINE
LONG
EcGetBufferedEventCount(
    _In_ PEC_CONSUMER Consumer
    )
{
    return (Consumer != NULL) ? Consumer->BufferedEventCount : 0;
}

FORCEINLINE
BOOLEAN
EcIsBufferFull(
    _In_ PEC_CONSUMER Consumer
    )
{
    if (Consumer == NULL) return TRUE;
    return ((ULONG)Consumer->BufferedEventCount >= Consumer->Config.MaxBufferedEvents);
}

FORCEINLINE
BOOLEAN
EcIsEqualGuid(
    _In_ LPCGUID Guid1,
    _In_ LPCGUID Guid2
    )
{
    return RtlEqualMemory(Guid1, Guid2, sizeof(GUID));
}

#ifdef __cplusplus
}
#endif

#endif // _SHADOWSTRIKE_ETW_CONSUMER_H_
