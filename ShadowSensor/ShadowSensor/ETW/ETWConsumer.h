/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE ETW CONSUMER
 * ============================================================================
 *
 * @file ETWConsumer.h
 * @brief Enterprise-grade ETW event consumption for kernel-mode EDR operations.
 *
 * Provides CrowdStrike Falcon-level ETW consumption capabilities with:
 * - Real-time ETW trace session management
 * - Multi-provider subscription with filtering
 * - High-performance event buffering and processing
 * - Kernel-mode ETW consumer infrastructure
 * - Event correlation and chaining support
 * - Automatic provider discovery and attachment
 * - Backpressure handling for high-volume scenarios
 * - Statistics and health monitoring
 *
 * Supported ETW Providers:
 * - Microsoft-Windows-Kernel-Process
 * - Microsoft-Windows-Kernel-File
 * - Microsoft-Windows-Kernel-Network
 * - Microsoft-Windows-Kernel-Registry
 * - Microsoft-Windows-Security-Auditing
 * - Microsoft-Windows-DNS-Client
 * - Microsoft-Windows-Threat-Intelligence
 * - Custom ShadowStrike providers
 *
 * Security Guarantees:
 * - All event data is validated before processing
 * - Buffer overflow protection on all operations
 * - Rate limiting to prevent resource exhaustion
 * - Secure cleanup of sensitive event data
 * - IRQL-aware implementations
 *
 * Performance Optimizations:
 * - Lookaside lists for event record allocation
 * - Lock-free event queuing where possible
 * - Batch processing for high-throughput scenarios
 * - Configurable buffer depths and thresholds
 *
 * MITRE ATT&CK Coverage:
 * - T1055: Process Injection (via process/thread events)
 * - T1059: Command and Scripting Interpreter (via process events)
 * - T1071: Application Layer Protocol (via network events)
 * - T1547: Boot or Logon Autostart Execution (via registry events)
 * - T1562: Impair Defenses (via security events)
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_ETW_CONSUMER_H_
#define _SHADOWSTRIKE_ETW_CONSUMER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include <wdm.h>
#include <evntrace.h>
#include <evntcons.h>

// ============================================================================
// POOL TAGS
// ============================================================================

/**
 * @brief Pool tag for ETW consumer general allocations: 'EcSs'
 */
#define EC_POOL_TAG             'sCcE'

/**
 * @brief Pool tag for ETW event records: 'ErSs'
 */
#define EC_EVENT_TAG            'rEcE'

/**
 * @brief Pool tag for ETW subscription allocations: 'EsSs'
 */
#define EC_SUBSCRIPTION_TAG     'sScE'

/**
 * @brief Pool tag for ETW buffer allocations: 'EbSs'
 */
#define EC_BUFFER_TAG           'bBcE'

/**
 * @brief Pool tag for ETW session allocations: 'EtSs'
 */
#define EC_SESSION_TAG          'tScE'

// ============================================================================
// CONFIGURATION CONSTANTS
// ============================================================================

/**
 * @brief Maximum number of concurrent subscriptions
 */
#define EC_MAX_SUBSCRIPTIONS            64

/**
 * @brief Maximum buffered events before flow control
 */
#define EC_MAX_BUFFERED_EVENTS          10000

/**
 * @brief Default buffered event threshold for backpressure
 */
#define EC_DEFAULT_BUFFER_THRESHOLD     5000

/**
 * @brief Maximum event user data size (256 KB)
 */
#define EC_MAX_EVENT_DATA_SIZE          (256 * 1024)

/**
 * @brief Maximum provider name length
 */
#define EC_MAX_PROVIDER_NAME_LENGTH     256

/**
 * @brief Maximum session name length
 */
#define EC_MAX_SESSION_NAME_LENGTH      256

/**
 * @brief Default processing thread count
 */
#define EC_DEFAULT_THREAD_COUNT         2

/**
 * @brief Maximum processing thread count
 */
#define EC_MAX_THREAD_COUNT             8

/**
 * @brief Event batch size for processing
 */
#define EC_EVENT_BATCH_SIZE             32

/**
 * @brief Rate limit: max events per second (0 = unlimited)
 */
#define EC_DEFAULT_RATE_LIMIT           0

/**
 * @brief Lookaside list depth for event records
 */
#define EC_EVENT_LOOKASIDE_DEPTH        256

/**
 * @brief Timeout for event processing (ms)
 */
#define EC_PROCESSING_TIMEOUT_MS        5000

/**
 * @brief Health check interval (seconds)
 */
#define EC_HEALTH_CHECK_INTERVAL_SEC    30

// ============================================================================
// WELL-KNOWN ETW PROVIDER GUIDs
// ============================================================================

/**
 * @brief Microsoft-Windows-Kernel-Process provider GUID
 */
// {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
DEFINE_GUID(GUID_KERNEL_PROCESS_PROVIDER,
    0x22fb2cd6, 0x0e7b, 0x422b, 0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16);

/**
 * @brief Microsoft-Windows-Kernel-File provider GUID
 */
// {EDD08927-9CC4-4E65-B970-C2560FB5C289}
DEFINE_GUID(GUID_KERNEL_FILE_PROVIDER,
    0xedd08927, 0x9cc4, 0x4e65, 0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x89);

/**
 * @brief Microsoft-Windows-Kernel-Network provider GUID
 */
// {7DD42A49-5329-4832-8DFD-43D979153A88}
DEFINE_GUID(GUID_KERNEL_NETWORK_PROVIDER,
    0x7dd42a49, 0x5329, 0x4832, 0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88);

/**
 * @brief Microsoft-Windows-Kernel-Registry provider GUID
 */
// {70EB4F03-C1DE-4F73-A051-33D13D5413BD}
DEFINE_GUID(GUID_KERNEL_REGISTRY_PROVIDER,
    0x70eb4f03, 0xc1de, 0x4f73, 0xa0, 0x51, 0x33, 0xd1, 0x3d, 0x54, 0x13, 0xbd);

/**
 * @brief Microsoft-Windows-Security-Auditing provider GUID
 */
// {54849625-5478-4994-A5BA-3E3B0328C30D}
DEFINE_GUID(GUID_SECURITY_AUDITING_PROVIDER,
    0x54849625, 0x5478, 0x4994, 0xa5, 0xba, 0x3e, 0x3b, 0x03, 0x28, 0xc3, 0x0d);

/**
 * @brief Microsoft-Windows-DNS-Client provider GUID
 */
// {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}
DEFINE_GUID(GUID_DNS_CLIENT_PROVIDER,
    0x1c95126e, 0x7eea, 0x49a9, 0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d);

/**
 * @brief Microsoft-Windows-Threat-Intelligence provider GUID
 */
// {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}
DEFINE_GUID(GUID_THREAT_INTELLIGENCE_PROVIDER,
    0xf4e1897c, 0xbb5d, 0x5668, 0xf1, 0xd8, 0x04, 0x0f, 0x4d, 0x8d, 0xd3, 0x44);

/**
 * @brief Microsoft-Windows-Kernel-Audit-API-Calls provider GUID
 */
// {E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23}
DEFINE_GUID(GUID_KERNEL_AUDIT_API_PROVIDER,
    0xe02a841c, 0x75a3, 0x4fa7, 0xaf, 0xc8, 0xae, 0x09, 0xcf, 0x9b, 0x7f, 0x23);

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief ETW consumer state
 */
typedef enum _EC_STATE {
    EcState_Uninitialized = 0,      ///< Not initialized
    EcState_Initialized,            ///< Initialized but not started
    EcState_Starting,               ///< Starting up
    EcState_Running,                ///< Running and processing events
    EcState_Paused,                 ///< Paused (not processing)
    EcState_Stopping,               ///< Shutting down
    EcState_Stopped,                ///< Fully stopped
    EcState_Error                   ///< Error state
} EC_STATE;

/**
 * @brief Subscription state
 */
typedef enum _EC_SUBSCRIPTION_STATE {
    EcSubState_Inactive = 0,        ///< Not active
    EcSubState_Active,              ///< Active and receiving events
    EcSubState_Suspended,           ///< Temporarily suspended
    EcSubState_Error                ///< Error state
} EC_SUBSCRIPTION_STATE;

/**
 * @brief Event priority for processing order
 */
typedef enum _EC_EVENT_PRIORITY {
    EcPriority_Critical = 0,        ///< Highest priority (security events)
    EcPriority_High,                ///< High priority (threat events)
    EcPriority_Normal,              ///< Normal priority (telemetry)
    EcPriority_Low,                 ///< Low priority (diagnostic)
    EcPriority_Background           ///< Background processing
} EC_EVENT_PRIORITY;

/**
 * @brief Event processing result
 */
typedef enum _EC_PROCESS_RESULT {
    EcResult_Continue = 0,          ///< Continue processing normally
    EcResult_Skip,                  ///< Skip this event
    EcResult_Block,                 ///< Block/suppress this event
    EcResult_Escalate,              ///< Escalate to higher priority
    EcResult_Error                  ///< Processing error occurred
} EC_PROCESS_RESULT;

/**
 * @brief Event source type
 */
typedef enum _EC_EVENT_SOURCE {
    EcSource_Unknown = 0,           ///< Unknown source
    EcSource_Kernel,                ///< Kernel provider
    EcSource_User,                  ///< User-mode provider
    EcSource_Security,              ///< Security provider
    EcSource_Custom                 ///< Custom provider
} EC_EVENT_SOURCE;

/**
 * @brief Flow control action
 */
typedef enum _EC_FLOW_CONTROL {
    EcFlow_Normal = 0,              ///< Normal flow
    EcFlow_Throttle,                ///< Throttle (reduce rate)
    EcFlow_Drop,                    ///< Drop low-priority events
    EcFlow_Pause                    ///< Pause all intake
} EC_FLOW_CONTROL;

// ============================================================================
// CALLBACK TYPES
// ============================================================================

/**
 * @brief Forward declarations
 */
typedef struct _EC_EVENT_RECORD EC_EVENT_RECORD, *PEC_EVENT_RECORD;
typedef struct _EC_SUBSCRIPTION EC_SUBSCRIPTION, *PEC_SUBSCRIPTION;
typedef struct _EC_CONSUMER EC_CONSUMER, *PEC_CONSUMER;

/**
 * @brief Event callback function type.
 *
 * Called for each matching event. Must complete quickly to avoid
 * blocking the processing pipeline.
 *
 * @param Record        Event record being processed
 * @param Context       User-provided callback context
 *
 * @return Processing result indicating how to proceed
 *
 * @irql <= DISPATCH_LEVEL
 */
typedef EC_PROCESS_RESULT
(NTAPI *EC_EVENT_CALLBACK)(
    _In_ PEC_EVENT_RECORD Record,
    _In_opt_ PVOID Context
    );

/**
 * @brief Subscription status callback.
 *
 * Called when subscription state changes (active, suspended, error).
 *
 * @param Subscription  Subscription that changed
 * @param OldState      Previous state
 * @param NewState      New state
 * @param Context       User-provided callback context
 *
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
 * @brief Event filter callback.
 *
 * Called before event processing to determine if event should be processed.
 * Used for high-performance filtering before full callback invocation.
 *
 * @param ProviderId    Event provider GUID
 * @param EventId       Event ID
 * @param Level         Event level
 * @param Keywords      Event keywords
 * @param Context       User-provided callback context
 *
 * @return TRUE to process event, FALSE to skip
 *
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
 *
 * Called when buffer thresholds are reached to allow custom flow control.
 *
 * @param Consumer          Consumer instance
 * @param BufferedCount     Current buffered event count
 * @param MaxCount          Maximum buffer capacity
 * @param Context           User-provided callback context
 *
 * @return Flow control action to take
 *
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

/**
 * @brief ETW event header (subset of EVENT_HEADER)
 */
typedef struct _EC_EVENT_HEADER {
    /// Event descriptor
    USHORT EventId;
    UCHAR Version;
    UCHAR Channel;
    UCHAR Level;
    UCHAR Opcode;
    USHORT Task;
    ULONGLONG Keywords;

    /// Timing
    LARGE_INTEGER Timestamp;

    /// Activity
    GUID ActivityId;
    GUID RelatedActivityId;

    /// Process context
    ULONG ProcessId;
    ULONG ThreadId;

    /// Provider
    GUID ProviderId;

} EC_EVENT_HEADER, *PEC_EVENT_HEADER;

/**
 * @brief Extended event data item
 */
typedef struct _EC_EXTENDED_DATA {
    /// Data type (EVENT_HEADER_EXT_TYPE_*)
    USHORT ExtType;

    /// Data size
    USHORT DataSize;

    /// Data pointer
    PVOID DataPtr;

    /// List linkage for multiple extended items
    LIST_ENTRY ListEntry;

} EC_EXTENDED_DATA, *PEC_EXTENDED_DATA;

/**
 * @brief ETW event record with full context
 */
typedef struct _EC_EVENT_RECORD {
    /// Event header
    EC_EVENT_HEADER Header;

    /// User data
    PVOID UserData;
    ULONG UserDataLength;

    /// Extended data items
    LIST_ENTRY ExtendedDataList;
    ULONG ExtendedDataCount;

    /// Processing metadata
    EC_EVENT_PRIORITY Priority;
    EC_EVENT_SOURCE Source;
    ULONG SequenceNumber;

    /// Timing
    LARGE_INTEGER ReceiveTime;
    LARGE_INTEGER ProcessTime;

    /// Reference to subscription that matched
    PEC_SUBSCRIPTION Subscription;

    /// Correlation
    ULONGLONG CorrelationId;
    BOOLEAN IsCorrelated;

    /// Internal flags
    BOOLEAN IsAllocated;
    BOOLEAN IsPooled;
    UCHAR Reserved;

    /// Buffer linkage
    LIST_ENTRY ListEntry;

} EC_EVENT_RECORD, *PEC_EVENT_RECORD;

/**
 * @brief Provider filter specification
 */
typedef struct _EC_PROVIDER_FILTER {
    /// Provider GUID to subscribe to
    GUID ProviderId;

    /// Friendly name (for debugging)
    WCHAR ProviderName[EC_MAX_PROVIDER_NAME_LENGTH];

    /// Keyword mask (events must match any)
    ULONGLONG MatchAnyKeyword;

    /// Keyword mask (events must match all)
    ULONGLONG MatchAllKeyword;

    /// Maximum event level (0-5, 0=all)
    UCHAR MaxLevel;

    /// Enable stack capture (performance impact)
    BOOLEAN EnableStackCapture;

    /// Enable process context capture
    BOOLEAN EnableProcessCapture;

    /// Reserved
    UCHAR Reserved;

    /// Event ID filters (NULL = all events)
    PUSHORT EventIdFilter;
    ULONG EventIdFilterCount;

} EC_PROVIDER_FILTER, *PEC_PROVIDER_FILTER;

/**
 * @brief Subscription configuration
 */
typedef struct _EC_SUBSCRIPTION_CONFIG {
    /// Provider filter
    EC_PROVIDER_FILTER ProviderFilter;

    /// Event callback
    EC_EVENT_CALLBACK EventCallback;
    PVOID EventCallbackContext;

    /// Optional filter callback (high-performance pre-filter)
    EC_FILTER_CALLBACK FilterCallback;
    PVOID FilterCallbackContext;

    /// Optional status callback
    EC_STATUS_CALLBACK StatusCallback;
    PVOID StatusCallbackContext;

    /// Event priority for this subscription
    EC_EVENT_PRIORITY Priority;

    /// Auto-start subscription
    BOOLEAN AutoStart;

    /// Enable event correlation for this subscription
    BOOLEAN EnableCorrelation;

    /// Reserved
    UCHAR Reserved[2];

} EC_SUBSCRIPTION_CONFIG, *PEC_SUBSCRIPTION_CONFIG;

/**
 * @brief Subscription statistics
 */
typedef struct _EC_SUBSCRIPTION_STATS {
    /// Event counts
    volatile LONG64 EventsReceived;
    volatile LONG64 EventsProcessed;
    volatile LONG64 EventsDropped;
    volatile LONG64 EventsFiltered;

    /// Error counts
    volatile LONG64 CallbackErrors;
    volatile LONG64 FilterErrors;

    /// Timing
    LARGE_INTEGER FirstEventTime;
    LARGE_INTEGER LastEventTime;
    volatile LONG64 TotalProcessingTimeUs;
    volatile LONG64 MaxProcessingTimeUs;

    /// Rate (events per second, updated periodically)
    volatile LONG CurrentRate;
    volatile LONG PeakRate;

} EC_SUBSCRIPTION_STATS, *PEC_SUBSCRIPTION_STATS;

/**
 * @brief ETW subscription instance
 */
typedef struct _EC_SUBSCRIPTION {
    /// Subscription ID (unique within consumer)
    ULONG SubscriptionId;

    /// Current state
    volatile EC_SUBSCRIPTION_STATE State;

    /// Configuration
    EC_SUBSCRIPTION_CONFIG Config;

    /// Statistics
    EC_SUBSCRIPTION_STATS Stats;

    /// Parent consumer
    PEC_CONSUMER Consumer;

    /// Session handle (if per-subscription session)
    TRACEHANDLE SessionHandle;

    /// Internal sequence counter
    volatile LONG64 SequenceNumber;

    /// Error tracking
    NTSTATUS LastError;
    ULONG ConsecutiveErrors;

    /// List linkage
    LIST_ENTRY ListEntry;

    /// Reference count
    volatile LONG RefCount;

    /// Flags
    BOOLEAN IsRegistered;
    BOOLEAN UsesSharedSession;
    UCHAR Reserved[2];

} EC_SUBSCRIPTION, *PEC_SUBSCRIPTION;

/**
 * @brief Consumer configuration
 */
typedef struct _EC_CONSUMER_CONFIG {
    /// Session name (for real-time session)
    WCHAR SessionName[EC_MAX_SESSION_NAME_LENGTH];

    /// Buffer configuration
    ULONG MaxBufferedEvents;
    ULONG BufferThreshold;

    /// Processing threads
    ULONG ProcessingThreadCount;

    /// Rate limiting (0 = unlimited)
    ULONG MaxEventsPerSecond;

    /// Flow control callback
    EC_FLOW_CALLBACK FlowCallback;
    PVOID FlowCallbackContext;

    /// Enable event batching for efficiency
    BOOLEAN EnableBatching;

    /// Auto-start consumer after initialization
    BOOLEAN AutoStart;

    /// Use real-time session (vs. file-based)
    BOOLEAN UseRealTimeSession;

    /// Reserved
    UCHAR Reserved;

} EC_CONSUMER_CONFIG, *PEC_CONSUMER_CONFIG;

/**
 * @brief Consumer statistics
 */
typedef struct _EC_CONSUMER_STATS {
    /// Event counts (aggregate)
    volatile LONG64 TotalEventsReceived;
    volatile LONG64 TotalEventsProcessed;
    volatile LONG64 TotalEventsDropped;
    volatile LONG64 TotalEventsCorrelated;

    /// Buffer stats
    volatile LONG CurrentBufferedEvents;
    volatile LONG PeakBufferedEvents;
    volatile LONG64 BufferOverflows;

    /// Processing stats
    volatile LONG64 BatchesProcessed;
    volatile LONG64 TotalProcessingTimeUs;

    /// Error tracking
    volatile LONG64 TotalErrors;
    volatile LONG64 SessionErrors;

    /// Uptime
    LARGE_INTEGER StartTime;
    LARGE_INTEGER LastEventTime;

    /// Rate metrics (updated periodically)
    volatile LONG CurrentEventsPerSecond;
    volatile LONG PeakEventsPerSecond;

    /// Health
    LARGE_INTEGER LastHealthCheck;
    BOOLEAN IsHealthy;
    UCHAR Reserved[3];

} EC_CONSUMER_STATS, *PEC_CONSUMER_STATS;

/**
 * @brief Processing thread context
 */
typedef struct _EC_PROCESSING_THREAD {
    /// Thread handle
    HANDLE ThreadHandle;
    PKTHREAD ThreadObject;

    /// Thread index
    ULONG ThreadIndex;

    /// Stop event
    KEVENT StopEvent;

    /// Work event (signaled when events available)
    KEVENT WorkEvent;

    /// Parent consumer
    PEC_CONSUMER Consumer;

    /// Thread-local stats
    volatile LONG64 EventsProcessed;
    volatile LONG64 ProcessingTimeUs;

    /// State
    BOOLEAN IsRunning;
    BOOLEAN StopRequested;
    UCHAR Reserved[2];

} EC_PROCESSING_THREAD, *PEC_PROCESSING_THREAD;

/**
 * @brief ETW Consumer instance
 */
typedef struct _EC_CONSUMER {
    /// Consumer state
    volatile EC_STATE State;

    /// Configuration
    EC_CONSUMER_CONFIG Config;

    /// Statistics
    EC_CONSUMER_STATS Stats;

    /// Subscriptions
    LIST_ENTRY SubscriptionList;
    EX_PUSH_LOCK SubscriptionLock;
    volatile LONG SubscriptionCount;
    volatile LONG NextSubscriptionId;

    /// Event buffer (priority queues)
    LIST_ENTRY EventQueues[5];          ///< One per EC_EVENT_PRIORITY
    KSPIN_LOCK EventQueueLock;
    volatile LONG BufferedEventCount;

    /// Processing threads
    EC_PROCESSING_THREAD ProcessingThreads[EC_MAX_THREAD_COUNT];
    ULONG ActiveThreadCount;

    /// Global stop event
    KEVENT StopEvent;

    /// Trace session
    TRACEHANDLE TraceSessionHandle;
    TRACEHANDLE ConsumerHandle;
    BOOLEAN SessionActive;

    /// Memory pools
    NPAGED_LOOKASIDE_LIST EventRecordLookaside;
    NPAGED_LOOKASIDE_LIST ExtendedDataLookaside;
    BOOLEAN LookasideInitialized;

    /// Flow control
    volatile EC_FLOW_CONTROL CurrentFlowState;
    KEVENT FlowResumeEvent;

    /// Rate limiting
    volatile LONG EventsThisSecond;
    LARGE_INTEGER CurrentSecondStart;
    KSPIN_LOCK RateLimitLock;

    /// Correlation engine reference (if enabled)
    PVOID CorrelationEngine;

    /// Health monitoring
    HANDLE HealthCheckTimer;
    KDPC HealthCheckDpc;

    /// Error tracking
    NTSTATUS LastError;
    ULONG ConsecutiveErrors;

    /// Initialization flag
    BOOLEAN Initialized;
    UCHAR Reserved[3];

} EC_CONSUMER, *PEC_CONSUMER;

// ============================================================================
// INITIALIZATION AND LIFECYCLE
// ============================================================================

/**
 * @brief Initialize an ETW consumer instance.
 *
 * Creates a new ETW consumer with the specified configuration.
 * Must be called at PASSIVE_LEVEL during driver initialization.
 *
 * @param Config        Consumer configuration (NULL for defaults)
 * @param Consumer      Receives initialized consumer instance
 *
 * @return STATUS_SUCCESS or error status
 *
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
 * all resources. Consumer pointer is invalidated after this call.
 *
 * @param Consumer      Consumer instance to shutdown
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
EcShutdown(
    _Inout_ PEC_CONSUMER Consumer
    );

/**
 * @brief Start the ETW consumer.
 *
 * Begins event processing. All active subscriptions will start receiving events.
 *
 * @param Consumer      Consumer instance
 *
 * @return STATUS_SUCCESS or error status
 *
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
 *
 * Stops event processing. Subscriptions remain configured but inactive.
 *
 * @param Consumer      Consumer instance
 *
 * @return STATUS_SUCCESS or error status
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
EcStop(
    _Inout_ PEC_CONSUMER Consumer
    );

/**
 * @brief Pause event processing.
 *
 * Temporarily pauses processing without stopping the trace session.
 * Events continue to buffer up to the maximum threshold.
 *
 * @param Consumer      Consumer instance
 *
 * @return STATUS_SUCCESS or error status
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
EcPause(
    _Inout_ PEC_CONSUMER Consumer
    );

/**
 * @brief Resume event processing.
 *
 * Resumes processing after a pause.
 *
 * @param Consumer      Consumer instance
 *
 * @return STATUS_SUCCESS or error status
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
EcResume(
    _Inout_ PEC_CONSUMER Consumer
    );

// ============================================================================
// SUBSCRIPTION MANAGEMENT
// ============================================================================

/**
 * @brief Subscribe to an ETW provider.
 *
 * Creates a new subscription with the specified configuration.
 * Subscription starts immediately if AutoStart is set and consumer is running.
 *
 * @param Consumer      Consumer instance
 * @param Config        Subscription configuration
 * @param Subscription  Receives subscription handle
 *
 * @return STATUS_SUCCESS or error status
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EcSubscribe(
    _Inout_ PEC_CONSUMER Consumer,
    _In_ PEC_SUBSCRIPTION_CONFIG Config,
    _Out_ PEC_SUBSCRIPTION* Subscription
    );

/**
 * @brief Subscribe to a provider by GUID (simplified).
 *
 * Convenience function for common subscription scenarios.
 *
 * @param Consumer          Consumer instance
 * @param ProviderId        Provider GUID
 * @param Keywords          Keyword filter (0 = all)
 * @param Level             Maximum level (0 = all)
 * @param Callback          Event callback
 * @param Context           Callback context
 * @param Subscription      Receives subscription handle
 *
 * @return STATUS_SUCCESS or error status
 *
 * @irql PASSIVE_LEVEL
 */
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

/**
 * @brief Unsubscribe from a provider.
 *
 * Removes subscription and stops receiving events.
 *
 * @param Consumer      Consumer instance
 * @param Subscription  Subscription to remove
 *
 * @return STATUS_SUCCESS or error status
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
EcUnsubscribe(
    _Inout_ PEC_CONSUMER Consumer,
    _Inout_ PEC_SUBSCRIPTION Subscription
    );

/**
 * @brief Activate a subscription.
 *
 * Starts receiving events for a previously suspended subscription.
 *
 * @param Subscription  Subscription to activate
 *
 * @return STATUS_SUCCESS or error status
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
EcActivateSubscription(
    _Inout_ PEC_SUBSCRIPTION Subscription
    );

/**
 * @brief Suspend a subscription.
 *
 * Temporarily stops receiving events without removing subscription.
 *
 * @param Subscription  Subscription to suspend
 *
 * @return STATUS_SUCCESS or error status
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
EcSuspendSubscription(
    _Inout_ PEC_SUBSCRIPTION Subscription
    );

/**
 * @brief Get subscription by provider GUID.
 *
 * @param Consumer      Consumer instance
 * @param ProviderId    Provider GUID to find
 * @param Subscription  Receives subscription (if found)
 *
 * @return STATUS_SUCCESS or STATUS_NOT_FOUND
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

// ============================================================================
// EVENT RECORD MANAGEMENT
// ============================================================================

/**
 * @brief Allocate an event record.
 *
 * Allocates from lookaside list for efficiency.
 *
 * @param Consumer      Consumer instance
 *
 * @return Event record or NULL on failure
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
PEC_EVENT_RECORD
EcAllocateEventRecord(
    _In_ PEC_CONSUMER Consumer
    );

/**
 * @brief Free an event record.
 *
 * Returns to lookaside list. Frees any associated extended data.
 *
 * @param Consumer      Consumer instance
 * @param Record        Event record to free
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EcFreeEventRecord(
    _In_ PEC_CONSUMER Consumer,
    _Inout_ PEC_EVENT_RECORD Record
    );

/**
 * @brief Clone an event record.
 *
 * Creates a deep copy of an event record including user data.
 *
 * @param Consumer      Consumer instance
 * @param Source        Source record
 * @param Clone         Receives cloned record
 *
 * @return STATUS_SUCCESS or error status
 *
 * @irql <= DISPATCH_LEVEL
 */
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

/**
 * @brief Get consumer statistics.
 *
 * @param Consumer      Consumer instance
 * @param Stats         Receives statistics snapshot
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EcGetStatistics(
    _In_ PEC_CONSUMER Consumer,
    _Out_ PEC_CONSUMER_STATS* Stats
    );

/**
 * @brief Get subscription statistics.
 *
 * @param Subscription  Subscription instance
 * @param Stats         Receives statistics snapshot
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EcGetSubscriptionStatistics(
    _In_ PEC_SUBSCRIPTION Subscription,
    _Out_ PEC_SUBSCRIPTION_STATS* Stats
    );

/**
 * @brief Reset consumer statistics.
 *
 * @param Consumer      Consumer instance
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EcResetStatistics(
    _Inout_ PEC_CONSUMER Consumer
    );

/**
 * @brief Check consumer health.
 *
 * @param Consumer      Consumer instance
 *
 * @return TRUE if healthy, FALSE if issues detected
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
EcIsHealthy(
    _In_ PEC_CONSUMER Consumer
    );

/**
 * @brief Get current consumer state.
 *
 * @param Consumer      Consumer instance
 *
 * @return Current state
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
EC_STATE
EcGetState(
    _In_ PEC_CONSUMER Consumer
    );

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get provider name from GUID.
 *
 * Returns friendly name for well-known providers.
 *
 * @param ProviderId    Provider GUID
 *
 * @return Provider name or "Unknown"
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
PCWSTR
EcGetProviderName(
    _In_ LPCGUID ProviderId
    );

/**
 * @brief Get event level name.
 *
 * @param Level         Event level
 *
 * @return Level name string
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
PCWSTR
EcGetLevelName(
    _In_ UCHAR Level
    );

/**
 * @brief Parse event user data.
 *
 * Helper to safely extract typed fields from event user data.
 *
 * @param Record        Event record
 * @param Offset        Field offset in user data
 * @param Size          Field size
 * @param Buffer        Output buffer
 *
 * @return STATUS_SUCCESS or error status
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
EcGetEventField(
    _In_ PEC_EVENT_RECORD Record,
    _In_ ULONG Offset,
    _In_ ULONG Size,
    _Out_writes_bytes_(Size) PVOID Buffer
    );

/**
 * @brief Get string field from event.
 *
 * Extracts null-terminated Unicode string from event user data.
 *
 * @param Record        Event record
 * @param Offset        String offset in user data
 * @param Buffer        Output buffer
 * @param BufferSize    Buffer size in bytes
 *
 * @return STATUS_SUCCESS or error status
 *
 * @irql <= DISPATCH_LEVEL
 */
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

/**
 * @brief Subscribe to kernel process events.
 *
 * Convenience function for Microsoft-Windows-Kernel-Process.
 *
 * @param Consumer      Consumer instance
 * @param Callback      Event callback
 * @param Context       Callback context
 * @param Subscription  Receives subscription
 *
 * @return STATUS_SUCCESS or error status
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
EcSubscribeKernelProcess(
    _Inout_ PEC_CONSUMER Consumer,
    _In_ EC_EVENT_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ PEC_SUBSCRIPTION* Subscription
    );

/**
 * @brief Subscribe to kernel file events.
 *
 * Convenience function for Microsoft-Windows-Kernel-File.
 *
 * @param Consumer      Consumer instance
 * @param Callback      Event callback
 * @param Context       Callback context
 * @param Subscription  Receives subscription
 *
 * @return STATUS_SUCCESS or error status
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
EcSubscribeKernelFile(
    _Inout_ PEC_CONSUMER Consumer,
    _In_ EC_EVENT_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ PEC_SUBSCRIPTION* Subscription
    );

/**
 * @brief Subscribe to kernel network events.
 *
 * Convenience function for Microsoft-Windows-Kernel-Network.
 *
 * @param Consumer      Consumer instance
 * @param Callback      Event callback
 * @param Context       Callback context
 * @param Subscription  Receives subscription
 *
 * @return STATUS_SUCCESS or error status
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
EcSubscribeKernelNetwork(
    _Inout_ PEC_CONSUMER Consumer,
    _In_ EC_EVENT_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ PEC_SUBSCRIPTION* Subscription
    );

/**
 * @brief Subscribe to kernel registry events.
 *
 * Convenience function for Microsoft-Windows-Kernel-Registry.
 *
 * @param Consumer      Consumer instance
 * @param Callback      Event callback
 * @param Context       Callback context
 * @param Subscription  Receives subscription
 *
 * @return STATUS_SUCCESS or error status
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
EcSubscribeKernelRegistry(
    _Inout_ PEC_CONSUMER Consumer,
    _In_ EC_EVENT_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ PEC_SUBSCRIPTION* Subscription
    );

/**
 * @brief Subscribe to security auditing events.
 *
 * Convenience function for Microsoft-Windows-Security-Auditing.
 *
 * @param Consumer      Consumer instance
 * @param Callback      Event callback
 * @param Context       Callback context
 * @param Subscription  Receives subscription
 *
 * @return STATUS_SUCCESS or error status
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
EcSubscribeSecurityAuditing(
    _Inout_ PEC_CONSUMER Consumer,
    _In_ EC_EVENT_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ PEC_SUBSCRIPTION* Subscription
    );

/**
 * @brief Subscribe to threat intelligence provider.
 *
 * Convenience function for Microsoft-Windows-Threat-Intelligence.
 *
 * @param Consumer      Consumer instance
 * @param Callback      Event callback
 * @param Context       Callback context
 * @param Subscription  Receives subscription
 *
 * @return STATUS_SUCCESS or error status
 *
 * @irql PASSIVE_LEVEL
 */
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

/**
 * @brief Check if consumer is running.
 */
FORCEINLINE
BOOLEAN
EcIsRunning(
    _In_ PEC_CONSUMER Consumer
    )
{
    return (Consumer != NULL && Consumer->State == EcState_Running);
}

/**
 * @brief Check if subscription is active.
 */
FORCEINLINE
BOOLEAN
EcIsSubscriptionActive(
    _In_ PEC_SUBSCRIPTION Subscription
    )
{
    return (Subscription != NULL && Subscription->State == EcSubState_Active);
}

/**
 * @brief Get current buffered event count.
 */
FORCEINLINE
LONG
EcGetBufferedEventCount(
    _In_ PEC_CONSUMER Consumer
    )
{
    return (Consumer != NULL) ? Consumer->BufferedEventCount : 0;
}

/**
 * @brief Check if buffer is at capacity.
 */
FORCEINLINE
BOOLEAN
EcIsBufferFull(
    _In_ PEC_CONSUMER Consumer
    )
{
    if (Consumer == NULL) return TRUE;
    return ((ULONG)Consumer->BufferedEventCount >= Consumer->Config.MaxBufferedEvents);
}

/**
 * @brief Compare two GUIDs.
 */
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
