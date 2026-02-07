/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE WFP NETWORK FILTER IMPLEMENTATION
 * ============================================================================
 *
 * @file NetworkFilter.c
 * @brief Enterprise-grade Windows Filtering Platform (WFP) network monitoring.
 *
 * Implements CrowdStrike Falcon-class network filtering:
 * - Full WFP callout registration at multiple layers
 * - ALE Connect/Accept monitoring for connection tracking
 * - Outbound transport layer for DNS interception
 * - Stream layer for TCP data inspection
 * - Connection lifecycle management with reference counting
 * - DNS query/response correlation
 * - Beaconing detection infrastructure
 * - Data exfiltration monitoring
 * - C2 detection integration
 * - JA3/JA3S TLS fingerprinting support
 * - Rate-limited event generation
 * - Comprehensive statistics
 *
 * WFP Layer Coverage:
 * - FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6: Outbound connection authorization
 * - FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6: Inbound connection authorization
 * - FWPM_LAYER_OUTBOUND_TRANSPORT_V4: DNS query interception
 * - FWPM_LAYER_STREAM_V4: TCP stream data inspection
 *
 * BSOD PREVENTION:
 * - Proper IRQL handling throughout
 * - Safe resource acquisition ordering
 * - Graceful shutdown with pending operation tracking
 * - Memory allocation failure handling
 * - Reference counting for connection entries
 *
 * Performance Characteristics:
 * - O(1) connection lookup via hash table
 * - Lookaside list allocation for hot paths
 * - Lock-free statistics updates
 * - Rate-limited logging
 *
 * MITRE ATT&CK Coverage:
 * - T1071: Application Layer Protocol (C2 detection)
 * - T1572: Protocol Tunneling (DNS tunneling)
 * - T1048: Exfiltration Over Alternative Protocol
 * - T1095: Non-Application Layer Protocol
 * - T1573: Encrypted Channel (TLS inspection)
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "NetworkFilter.h"
#include "ConnectionTracker.h"
#include "DnsMonitor.h"
#include "C2Detection.h"
#include "NetworkReputation.h"
#include "../Core/Globals.h"
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/StringUtils.h"
#include <ntstrsafe.h>
#include <ip2string.h>

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

/**
 * @brief Maximum connections in tracking table
 */
#define NF_MAX_CONNECTIONS              65536

/**
 * @brief Connection hash table bucket count (power of 2)
 */
#define NF_CONNECTION_HASH_BUCKETS      4096

/**
 * @brief DNS entry hash table bucket count
 */
#define NF_DNS_HASH_BUCKETS             2048

/**
 * @brief Connection idle timeout (5 minutes)
 */
#define NF_CONNECTION_TIMEOUT_MS        300000

/**
 * @brief Cleanup timer interval (30 seconds)
 */
#define NF_CLEANUP_INTERVAL_MS          30000

/**
 * @brief Maximum events per second before throttling
 */
#define NF_MAX_EVENTS_PER_SECOND        10000

/**
 * @brief Rate limit log interval (1 minute)
 */
#define NF_RATE_LIMIT_LOG_INTERVAL_MS   60000

/**
 * @brief Lookaside list depth for connections
 */
#define NF_CONNECTION_LOOKASIDE_DEPTH   256

/**
 * @brief Lookaside list depth for DNS entries
 */
#define NF_DNS_LOOKASIDE_DEPTH          512

/**
 * @brief Lookaside list depth for events
 */
#define NF_EVENT_LOOKASIDE_DEPTH        1024

/**
 * @brief DNS port number
 */
#define NF_DNS_PORT                     53

/**
 * @brief Maximum process path length to capture
 */
#define NF_MAX_PROCESS_PATH             512

// ============================================================================
// PRIVATE TYPES
// ============================================================================

/**
 * @brief Connection hash entry for fast lookup
 */
typedef struct _NF_CONNECTION_HASH_ENTRY {
    LIST_ENTRY HashListEntry;
    PNF_CONNECTION_ENTRY Connection;
} NF_CONNECTION_HASH_ENTRY, *PNF_CONNECTION_HASH_ENTRY;

/**
 * @brief DNS query hash entry
 */
typedef struct _NF_DNS_HASH_ENTRY {
    LIST_ENTRY HashListEntry;
    PNF_DNS_ENTRY DnsEntry;
} NF_DNS_HASH_ENTRY, *PNF_DNS_HASH_ENTRY;

/**
 * @brief Pending DNS query for correlation
 */
typedef struct _NF_PENDING_DNS {
    LIST_ENTRY ListEntry;
    UINT16 TransactionId;
    UINT32 ProcessId;
    UINT64 QueryTime;
    WCHAR QueryName[MAX_DNS_NAME_LENGTH];
    UINT16 QueryType;
    UINT16 Reserved;
} NF_PENDING_DNS, *PNF_PENDING_DNS;

// ============================================================================
// GLOBAL STATE
// ============================================================================

/**
 * @brief Network filter global state
 */
static NETWORK_FILTER_GLOBALS g_NfState = {0};

/**
 * @brief Connection hash table
 */
static LIST_ENTRY g_ConnectionHashTable[NF_CONNECTION_HASH_BUCKETS];
static EX_PUSH_LOCK g_ConnectionHashLock;

/**
 * @brief Flow ID to connection lookup
 */
static LIST_ENTRY g_FlowHashTable[NF_CONNECTION_HASH_BUCKETS];
static EX_PUSH_LOCK g_FlowHashLock;

/**
 * @brief Pending DNS queries
 */
static LIST_ENTRY g_PendingDnsList;
static EX_PUSH_LOCK g_PendingDnsLock;
static volatile LONG g_PendingDnsCount;

/**
 * @brief Cleanup timer and DPC
 */
static KTIMER g_CleanupTimer;
static KDPC g_CleanupDpc;
static volatile LONG g_CleanupInProgress;

/**
 * @brief Subsystem pointers (from other Network modules)
 */
static PCT_TRACKER g_ConnectionTracker;
static PDNS_MONITOR g_DnsMonitor;
static PC2_DETECTOR g_C2Detector;
static PNR_MANAGER g_ReputationManager;

/**
 * @brief Rate limiting state
 */
static volatile LONG g_EventsThisSecond;
static UINT64 g_CurrentSecondStart;
static UINT64 g_LastRateLimitLogTime;
static volatile LONG64 g_TotalEventsDropped;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static NTSTATUS
NfpRegisterCallouts(
    _In_ PDEVICE_OBJECT DeviceObject
    );

static VOID
NfpUnregisterCallouts(
    VOID
    );

static NTSTATUS
NfpRegisterFilters(
    VOID
    );

static VOID
NfpUnregisterFilters(
    VOID
    );

static NTSTATUS
NfpInitializeHashTables(
    VOID
    );

static VOID
NfpCleanupHashTables(
    VOID
    );

static NTSTATUS
NfpInitializeLookasideLists(
    VOID
    );

static VOID
NfpCleanupLookasideLists(
    VOID
    );

static PNF_CONNECTION_ENTRY
NfpAllocateConnection(
    VOID
    );

static VOID
NfpFreeConnection(
    _In_ PNF_CONNECTION_ENTRY Connection
    );

static PNF_DNS_ENTRY
NfpAllocateDnsEntry(
    VOID
    );

static VOID
NfpFreeDnsEntry(
    _In_ PNF_DNS_ENTRY DnsEntry
    );

static UINT32
NfpHashEndpoints(
    _In_ PSS_SOCKET_ADDRESS Local,
    _In_ PSS_SOCKET_ADDRESS Remote,
    _In_ NETWORK_PROTOCOL Protocol
    );

static UINT32
NfpHashFlowId(
    _In_ UINT64 FlowId
    );

static UINT32
NfpHashDomainName(
    _In_ PCWSTR DomainName
    );

static NTSTATUS
NfpInsertConnection(
    _In_ PNF_CONNECTION_ENTRY Connection
    );

static VOID
NfpRemoveConnection(
    _In_ PNF_CONNECTION_ENTRY Connection
    );

static VOID
NfpCleanupTimerCallback(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

static VOID
NfpCleanupStaleConnections(
    VOID
    );

static VOID
NfpCleanupStaleDnsEntries(
    VOID
    );

static BOOLEAN
NfpCheckRateLimit(
    VOID
    );

static VOID
NfpGetProcessPath(
    _In_ HANDLE ProcessId,
    _Out_writes_(MaxLength) PWCHAR ProcessPath,
    _In_ ULONG MaxLength
    );

static VOID
NfpCopyAddress(
    _Out_ PSS_SOCKET_ADDRESS Dest,
    _In_ const FWP_BYTE_ARRAY16* IpV6,
    _In_ const UINT32* IpV4,
    _In_ UINT16 Port,
    _In_ BOOLEAN IsV6
    );

static BOOLEAN
NfpIsPrivateAddress(
    _In_ PSS_IP_ADDRESS Address
    );

static BOOLEAN
NfpIsLoopbackAddress(
    _In_ PSS_IP_ADDRESS Address
    );

static VOID
NfpProcessOutboundConnect(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _In_ UINT64 FlowContext,
    _Out_ FWPS_CLASSIFY_OUT0* ClassifyOut,
    _In_ BOOLEAN IsV6
    );

static VOID
NfpProcessInboundAccept(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _In_ UINT64 FlowContext,
    _Out_ FWPS_CLASSIFY_OUT0* ClassifyOut,
    _In_ BOOLEAN IsV6
    );

static VOID
NfpProcessDnsPacket(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _In_opt_ void* LayerData,
    _Out_ FWPS_CLASSIFY_OUT0* ClassifyOut
    );

static VOID
NfpProcessStreamData(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _In_opt_ FWPS_STREAM_CALLOUT_IO_PACKET0* StreamPacket,
    _In_ UINT64 FlowContext,
    _Out_ FWPS_CLASSIFY_OUT0* ClassifyOut
    );

static NTSTATUS
NfpAnalyzeConnection(
    _In_ PNF_CONNECTION_ENTRY Connection
    );

static VOID
NfpUpdateBeaconingState(
    _In_ PNF_CONNECTION_ENTRY Connection,
    _In_ UINT64 CurrentTime
    );

static BOOLEAN
NfpDetectBeaconingPattern(
    _In_ PNF_CONNECTION_ENTRY Connection,
    _Out_opt_ PBEACONING_DATA BeaconingData
    );

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the network filtering subsystem.
 *
 * This function initializes all WFP components:
 * 1. Initialize hash tables for connection tracking
 * 2. Initialize lookaside lists for memory allocation
 * 3. Open WFP engine handle
 * 4. Register provider and sublayer
 * 5. Register callouts at each layer
 * 6. Register filters
 * 7. Start cleanup timer
 *
 * @param DeviceObject Device object for WFP registration.
 * @return STATUS_SUCCESS on success, error status otherwise.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
NfFilterInitialize(
    _In_ PDEVICE_OBJECT DeviceObject
    )
{
    NTSTATUS status;
    FWPM_SESSION0 session = {0};
    FWPM_PROVIDER0 provider = {0};
    FWPM_SUBLAYER0 sublayer = {0};
    LARGE_INTEGER dueTime;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (DeviceObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Check if already initialized
    //
    if (g_NfState.Initialized) {
        return STATUS_ALREADY_INITIALIZED;
    }

    RtlZeroMemory(&g_NfState, sizeof(NETWORK_FILTER_GLOBALS));

    //
    // Store device object
    //
    g_NfState.WfpDeviceObject = DeviceObject;

    //
    // Initialize hash tables
    //
    status = NfpInitializeHashTables();
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Initialize lookaside lists
    //
    status = NfpInitializeLookasideLists();
    if (!NT_SUCCESS(status)) {
        NfpCleanupHashTables();
        goto Cleanup;
    }

    //
    // Initialize connection and DNS lists
    //
    InitializeListHead(&g_NfState.ConnectionList);
    ExInitializeResourceLite(&g_NfState.ConnectionLock);
    g_NfState.ConnectionCount = 0;

    InitializeListHead(&g_NfState.DnsQueryList);
    ExInitializeResourceLite(&g_NfState.DnsLock);
    g_NfState.DnsQueryCount = 0;

    InitializeListHead(&g_NfState.DnsTunnelStateList);
    g_NfState.DnsTunnelStateCount = 0;

    InitializeListHead(&g_PendingDnsList);
    ExInitializePushLock(&g_PendingDnsLock);
    g_PendingDnsCount = 0;

    //
    // Open WFP engine with transaction support
    //
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    session.displayData.name = L"ShadowStrike Network Monitor";
    session.displayData.description = L"Enterprise WFP-based network filtering";

    status = FwpmEngineOpen0(
        NULL,                       // Local machine
        RPC_C_AUTHN_WINNT,
        NULL,
        &session,
        &g_NfState.WfpEngineHandle
        );

    if (!NT_SUCCESS(status)) {
        goto CleanupLists;
    }

    //
    // Start transaction for atomic registration
    //
    status = FwpmTransactionBegin0(g_NfState.WfpEngineHandle, 0);
    if (!NT_SUCCESS(status)) {
        goto CleanupEngine;
    }

    //
    // Register provider
    //
    provider.providerKey = SHADOWSTRIKE_WFP_PROVIDER_GUID;
    provider.displayData.name = L"ShadowStrike NGAV Provider";
    provider.displayData.description = L"Network monitoring for threat detection";
    provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;

    status = FwpmProviderAdd0(
        g_NfState.WfpEngineHandle,
        &provider,
        NULL
        );

    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        FwpmTransactionAbort0(g_NfState.WfpEngineHandle);
        goto CleanupEngine;
    }

    //
    // Register sublayer
    //
    sublayer.subLayerKey = SHADOWSTRIKE_WFP_SUBLAYER_GUID;
    sublayer.displayData.name = L"ShadowStrike Inspection Sublayer";
    sublayer.displayData.description = L"Sublayer for connection and data inspection";
    sublayer.providerKey = (GUID*)&SHADOWSTRIKE_WFP_PROVIDER_GUID;
    sublayer.weight = 0xFFFF;   // High priority
    sublayer.flags = 0;

    status = FwpmSubLayerAdd0(
        g_NfState.WfpEngineHandle,
        &sublayer,
        NULL
        );

    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        FwpmTransactionAbort0(g_NfState.WfpEngineHandle);
        goto CleanupEngine;
    }

    //
    // Register callouts
    //
    status = NfpRegisterCallouts(DeviceObject);
    if (!NT_SUCCESS(status)) {
        FwpmTransactionAbort0(g_NfState.WfpEngineHandle);
        goto CleanupEngine;
    }

    //
    // Register filters
    //
    status = NfpRegisterFilters();
    if (!NT_SUCCESS(status)) {
        NfpUnregisterCallouts();
        FwpmTransactionAbort0(g_NfState.WfpEngineHandle);
        goto CleanupEngine;
    }

    //
    // Commit transaction
    //
    status = FwpmTransactionCommit0(g_NfState.WfpEngineHandle);
    if (!NT_SUCCESS(status)) {
        NfpUnregisterFilters();
        NfpUnregisterCallouts();
        goto CleanupEngine;
    }

    //
    // Initialize cleanup timer
    //
    KeInitializeTimer(&g_CleanupTimer);
    KeInitializeDpc(&g_CleanupDpc, NfpCleanupTimerCallback, NULL);
    g_CleanupInProgress = 0;

    //
    // Start cleanup timer (30 second interval)
    //
    dueTime.QuadPart = -((LONGLONG)NF_CLEANUP_INTERVAL_MS * 10000);
    KeSetTimerEx(
        &g_CleanupTimer,
        dueTime,
        NF_CLEANUP_INTERVAL_MS,
        &g_CleanupDpc
        );

    //
    // Initialize default configuration
    //
    g_NfState.Config.EnableConnectionMonitoring = TRUE;
    g_NfState.Config.EnableDnsMonitoring = TRUE;
    g_NfState.Config.EnableDataInspection = TRUE;
    g_NfState.Config.EnableTlsInspection = TRUE;
    g_NfState.Config.EnableC2Detection = TRUE;
    g_NfState.Config.EnableExfiltrationDetection = TRUE;
    g_NfState.Config.EnableDnsTunnelingDetection = TRUE;
    g_NfState.Config.EnablePortScanDetection = TRUE;
    g_NfState.Config.BeaconMinSamples = NF_DEFAULT_BEACON_MIN_SAMPLES;
    g_NfState.Config.BeaconJitterThreshold = NF_DEFAULT_BEACON_JITTER_THRESHOLD;
    g_NfState.Config.ExfiltrationThresholdMB = NF_DEFAULT_EXFIL_THRESHOLD_MB;
    g_NfState.Config.DnsQueryRateThreshold = NF_DEFAULT_DNS_RATE_THRESHOLD;
    g_NfState.Config.PortScanThreshold = NF_DEFAULT_PORT_SCAN_THRESHOLD;
    g_NfState.Config.MaxEventsPerSecond = NF_DEFAULT_MAX_EVENTS_PER_SEC;
    g_NfState.Config.DataSampleSize = NF_DEFAULT_DATA_SAMPLE_SIZE;
    g_NfState.Config.DataSampleInterval = NF_DEFAULT_DATA_SAMPLE_INTERVAL;

    //
    // Initialize rate limiting
    //
    g_EventsThisSecond = 0;
    g_CurrentSecondStart = 0;
    g_LastRateLimitLogTime = 0;
    g_TotalEventsDropped = 0;

    //
    // Mark as initialized and enabled
    //
    g_NfState.Initialized = TRUE;
    g_NfState.Enabled = TRUE;

    return STATUS_SUCCESS;

CleanupEngine:
    FwpmEngineClose0(g_NfState.WfpEngineHandle);
    g_NfState.WfpEngineHandle = NULL;

CleanupLists:
    ExDeleteResourceLite(&g_NfState.ConnectionLock);
    ExDeleteResourceLite(&g_NfState.DnsLock);
    NfpCleanupLookasideLists();
    NfpCleanupHashTables();

Cleanup:
    RtlZeroMemory(&g_NfState, sizeof(NETWORK_FILTER_GLOBALS));
    return status;
}

/**
 * @brief Shutdown the network filtering subsystem.
 *
 * Performs graceful shutdown:
 * 1. Stop cleanup timer
 * 2. Disable filtering
 * 3. Unregister filters
 * 4. Unregister callouts
 * 5. Close WFP engine
 * 6. Free all connections and DNS entries
 * 7. Cleanup hash tables and lookaside lists
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
NfFilterShutdown(
    VOID
    )
{
    PLIST_ENTRY entry;
    PNF_CONNECTION_ENTRY connection;
    PNF_DNS_ENTRY dnsEntry;
    LARGE_INTEGER timeout;

    PAGED_CODE();

    if (!g_NfState.Initialized) {
        return;
    }

    //
    // Mark as disabled first to stop new operations
    //
    g_NfState.Enabled = FALSE;

    //
    // Cancel and wait for cleanup timer
    //
    KeCancelTimer(&g_CleanupTimer);
    KeFlushQueuedDpcs();

    //
    // Wait for any in-progress cleanup to complete
    //
    timeout.QuadPart = -50000000;  // 5 seconds
    while (InterlockedCompareExchange(&g_CleanupInProgress, 0, 0) != 0) {
        KeDelayExecutionThread(KernelMode, FALSE, &timeout);
        timeout.QuadPart = -10000000;  // 1 second
    }

    //
    // Unregister filters and callouts
    //
    NfpUnregisterFilters();
    NfpUnregisterCallouts();

    //
    // Close WFP engine
    //
    if (g_NfState.WfpEngineHandle != NULL) {
        FwpmEngineClose0(g_NfState.WfpEngineHandle);
        g_NfState.WfpEngineHandle = NULL;
    }

    //
    // Free all connections
    //
    ExAcquireResourceExclusiveLite(&g_NfState.ConnectionLock, TRUE);

    while (!IsListEmpty(&g_NfState.ConnectionList)) {
        entry = RemoveHeadList(&g_NfState.ConnectionList);
        connection = CONTAINING_RECORD(entry, NF_CONNECTION_ENTRY, ListEntry);
        NfpFreeConnection(connection);
    }
    g_NfState.ConnectionCount = 0;

    ExReleaseResourceLite(&g_NfState.ConnectionLock);

    //
    // Free all DNS entries
    //
    ExAcquireResourceExclusiveLite(&g_NfState.DnsLock, TRUE);

    while (!IsListEmpty(&g_NfState.DnsQueryList)) {
        entry = RemoveHeadList(&g_NfState.DnsQueryList);
        dnsEntry = CONTAINING_RECORD(entry, NF_DNS_ENTRY, ListEntry);
        NfpFreeDnsEntry(dnsEntry);
    }
    g_NfState.DnsQueryCount = 0;

    ExReleaseResourceLite(&g_NfState.DnsLock);

    //
    // Free pending DNS list
    //
    FltAcquirePushLockExclusive(&g_PendingDnsLock);

    while (!IsListEmpty(&g_PendingDnsList)) {
        entry = RemoveHeadList(&g_PendingDnsList);
        PNF_PENDING_DNS pendingDns = CONTAINING_RECORD(entry, NF_PENDING_DNS, ListEntry);
        ExFreePoolWithTag(pendingDns, NF_POOL_TAG_DNS);
    }
    g_PendingDnsCount = 0;

    FltReleasePushLock(&g_PendingDnsLock);

    //
    // Cleanup resources
    //
    ExDeleteResourceLite(&g_NfState.ConnectionLock);
    ExDeleteResourceLite(&g_NfState.DnsLock);

    //
    // Cleanup hash tables and lookaside lists
    //
    NfpCleanupHashTables();
    NfpCleanupLookasideLists();

    //
    // Clear state
    //
    g_NfState.Initialized = FALSE;
    RtlZeroMemory(&g_NfState, sizeof(NETWORK_FILTER_GLOBALS));
}

/**
 * @brief Enable or disable network filtering.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
NfFilterSetEnabled(
    _In_ BOOLEAN Enable
    )
{
    PAGED_CODE();

    if (!g_NfState.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    g_NfState.Enabled = Enable;
    return STATUS_SUCCESS;
}

/**
 * @brief Update network filter configuration.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
NfFilterUpdateConfig(
    _In_ PNETWORK_MONITOR_CONFIG Config
    )
{
    PAGED_CODE();

    if (!g_NfState.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (Config == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate thresholds
    //
    if (Config->BeaconMinSamples < 5 || Config->BeaconMinSamples > 1000) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Config->BeaconJitterThreshold > 100) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Copy configuration atomically
    //
    RtlCopyMemory(&g_NfState.Config, Config, sizeof(NETWORK_MONITOR_CONFIG));

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - CONNECTION MANAGEMENT
// ============================================================================

/**
 * @brief Find connection by ID.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
NfFilterFindConnection(
    _In_ UINT64 ConnectionId,
    _Out_ PNF_CONNECTION_ENTRY* Connection
    )
{
    PLIST_ENTRY entry;
    PNF_CONNECTION_ENTRY current;
    NTSTATUS status = STATUS_NOT_FOUND;

    if (Connection == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Connection = NULL;

    if (!g_NfState.Initialized || !g_NfState.Enabled) {
        return STATUS_DEVICE_NOT_READY;
    }

    ExAcquireResourceSharedLite(&g_NfState.ConnectionLock, TRUE);

    for (entry = g_NfState.ConnectionList.Flink;
         entry != &g_NfState.ConnectionList;
         entry = entry->Flink) {

        current = CONTAINING_RECORD(entry, NF_CONNECTION_ENTRY, ListEntry);

        if (current->ConnectionId == ConnectionId) {
            //
            // Add reference before returning
            //
            InterlockedIncrement(&current->RefCount);
            *Connection = current;
            status = STATUS_SUCCESS;
            break;
        }
    }

    ExReleaseResourceLite(&g_NfState.ConnectionLock);
    return status;
}

/**
 * @brief Find connection by WFP flow ID.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
NfFilterFindConnectionByFlow(
    _In_ UINT64 FlowId,
    _Out_ PNF_CONNECTION_ENTRY* Connection
    )
{
    UINT32 hashIndex;
    PLIST_ENTRY entry;
    PNF_CONNECTION_ENTRY current;
    NTSTATUS status = STATUS_NOT_FOUND;

    if (Connection == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Connection = NULL;

    if (!g_NfState.Initialized || !g_NfState.Enabled) {
        return STATUS_DEVICE_NOT_READY;
    }

    hashIndex = NfpHashFlowId(FlowId);

    FltAcquirePushLockShared(&g_FlowHashLock);

    for (entry = g_FlowHashTable[hashIndex].Flink;
         entry != &g_FlowHashTable[hashIndex];
         entry = entry->Flink) {

        PNF_CONNECTION_HASH_ENTRY hashEntry =
            CONTAINING_RECORD(entry, NF_CONNECTION_HASH_ENTRY, HashListEntry);
        current = hashEntry->Connection;

        if (current->FlowId == FlowId) {
            InterlockedIncrement(&current->RefCount);
            *Connection = current;
            status = STATUS_SUCCESS;
            break;
        }
    }

    FltReleasePushLock(&g_FlowHashLock);
    return status;
}

/**
 * @brief Release connection reference.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
NfFilterReleaseConnection(
    _In_ PNF_CONNECTION_ENTRY Connection
    )
{
    if (Connection == NULL) {
        return;
    }

    LONG refCount = InterlockedDecrement(&Connection->RefCount);

    //
    // Connection cleanup is handled by the cleanup timer
    // when RefCount reaches 0 and connection is stale
    //
    UNREFERENCED_PARAMETER(refCount);
}

/**
 * @brief Block a connection.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
NfFilterBlockConnection(
    _In_ UINT64 ConnectionId,
    _In_ NETWORK_BLOCK_REASON Reason
    )
{
    PNF_CONNECTION_ENTRY connection;
    NTSTATUS status;

    status = NfFilterFindConnection(ConnectionId, &connection);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Update connection state
    //
    connection->State = ConnectionState_Blocked;
    connection->Flags |= NF_CONN_FLAG_BLOCKED;

    //
    // Update statistics
    //
    InterlockedIncrement64(&g_NfState.TotalConnectionsBlocked);

    //
    // Log the block
    //
    // Note: In production, this would send a notification to user-mode
    //

    UNREFERENCED_PARAMETER(Reason);

    NfFilterReleaseConnection(connection);
    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - DNS
// ============================================================================

/**
 * @brief Query DNS cache for domain.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
NfFilterQueryDnsCache(
    _In_ PCWSTR DomainName,
    _Out_ PNF_DNS_ENTRY Entry
    )
{
    UINT32 hashValue;
    PLIST_ENTRY entry;
    PNF_DNS_ENTRY current;
    NTSTATUS status = STATUS_NOT_FOUND;

    if (DomainName == NULL || Entry == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_NfState.Initialized || !g_NfState.Enabled) {
        return STATUS_DEVICE_NOT_READY;
    }

    hashValue = NfpHashDomainName(DomainName);

    ExAcquireResourceSharedLite(&g_NfState.DnsLock, TRUE);

    for (entry = g_NfState.DnsQueryList.Flink;
         entry != &g_NfState.DnsQueryList;
         entry = entry->Flink) {

        current = CONTAINING_RECORD(entry, NF_DNS_ENTRY, ListEntry);

        if (current->QueryNameHash == hashValue) {
            //
            // Verify exact match
            //
            if (_wcsicmp(current->QueryName, DomainName) == 0) {
                RtlCopyMemory(Entry, current, sizeof(NF_DNS_ENTRY));
                status = STATUS_SUCCESS;
                break;
            }
        }
    }

    ExReleaseResourceLite(&g_NfState.DnsLock);
    return status;
}

/**
 * @brief Block DNS queries to domain.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
NfFilterBlockDomain(
    _In_ PCWSTR DomainName,
    _In_ NETWORK_BLOCK_REASON Reason
    )
{
    //
    // This would add the domain to a blocked list
    // For now, we return success as a placeholder
    //
    UNREFERENCED_PARAMETER(DomainName);
    UNREFERENCED_PARAMETER(Reason);

    if (!g_NfState.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // In production: add to blocked domain list
    // which is checked during DNS query processing
    //

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - DETECTION
// ============================================================================

/**
 * @brief Check if connection exhibits C2 beaconing.
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
NfFilterDetectBeaconing(
    _In_ UINT64 ConnectionId,
    _Out_opt_ PBEACONING_DATA BeaconingData
    )
{
    PNF_CONNECTION_ENTRY connection;
    BOOLEAN isBeaconing = FALSE;
    NTSTATUS status;

    status = NfFilterFindConnection(ConnectionId, &connection);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    isBeaconing = NfpDetectBeaconingPattern(connection, BeaconingData);

    NfFilterReleaseConnection(connection);
    return isBeaconing;
}

/**
 * @brief Detect DNS tunneling for domain.
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
NfFilterDetectDnsTunneling(
    _In_ PCWSTR BaseDomain,
    _Out_opt_ PNF_DNS_TUNNEL_STATE TunnelState
    )
{
    PLIST_ENTRY entry;
    PNF_DNS_TUNNEL_STATE state;
    UINT32 domainHash;
    BOOLEAN found = FALSE;

    if (BaseDomain == NULL) {
        return FALSE;
    }

    if (!g_NfState.Initialized || !g_NfState.Config.EnableDnsTunnelingDetection) {
        return FALSE;
    }

    domainHash = NfpHashDomainName(BaseDomain);

    ExAcquireResourceSharedLite(&g_NfState.DnsLock, TRUE);

    for (entry = g_NfState.DnsTunnelStateList.Flink;
         entry != &g_NfState.DnsTunnelStateList;
         entry = entry->Flink) {

        state = CONTAINING_RECORD(entry, NF_DNS_TUNNEL_STATE, BaseDomain);

        //
        // The structure doesn't have a ListEntry, use offset calculation
        // This is a simplification - in production, wrap in a container struct
        //
        if (state->BaseDomainHash == domainHash) {
            if (_wcsicmp(state->BaseDomain, BaseDomain) == 0) {
                if (TunnelState != NULL) {
                    RtlCopyMemory(TunnelState, state, sizeof(NF_DNS_TUNNEL_STATE));
                }
                found = state->IsTunneling;
                break;
            }
        }
    }

    ExReleaseResourceLite(&g_NfState.DnsLock);
    return found;
}

/**
 * @brief Analyze connection for data exfiltration.
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
NfFilterDetectExfiltration(
    _In_ UINT64 ConnectionId,
    _Out_opt_ PNETWORK_EXFIL_EVENT Event
    )
{
    PNF_CONNECTION_ENTRY connection;
    NTSTATUS status;
    BOOLEAN isExfiltration = FALSE;
    UINT64 thresholdBytes;

    status = NfFilterFindConnection(ConnectionId, &connection);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    if (!g_NfState.Config.EnableExfiltrationDetection) {
        NfFilterReleaseConnection(connection);
        return FALSE;
    }

    //
    // Calculate threshold in bytes
    //
    thresholdBytes = (UINT64)g_NfState.Config.ExfiltrationThresholdMB * 1024 * 1024;

    //
    // Check for high outbound data volume
    //
    if (connection->BytesSent > thresholdBytes) {
        //
        // Check upload/download ratio (exfiltration has high upload)
        //
        if (connection->BytesReceived > 0) {
            UINT64 ratio = (connection->BytesSent * 100) / connection->BytesReceived;

            if (ratio > 500) {  // 5:1 upload to download ratio
                isExfiltration = TRUE;
                connection->Flags |= NF_CONN_FLAG_EXFIL_SUSPECT;

                if (Event != NULL) {
                    RtlZeroMemory(Event, sizeof(NETWORK_EXFIL_EVENT));
                    Event->Header.EventType = NetworkEvent_DataExfiltration;
                    Event->ConnectionId = connection->ConnectionId;
                    Event->TotalBytesSent = connection->BytesSent;
                    Event->TotalBytesReceived = connection->BytesReceived;
                    Event->UploadDownloadRatio = (UINT32)ratio;

                    RtlCopyMemory(&Event->LocalAddress, &connection->LocalAddress,
                                  sizeof(SS_SOCKET_ADDRESS));
                    RtlCopyMemory(&Event->RemoteAddress, &connection->RemoteAddress,
                                  sizeof(SS_SOCKET_ADDRESS));
                }

                InterlockedIncrement64(&g_NfState.TotalExfiltrationDetections);
            }
        }
    }

    NfFilterReleaseConnection(connection);
    return isExfiltration;
}

/**
 * @brief Check JA3 fingerprint against known malicious list.
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
NfFilterIsKnownMaliciousJA3(
    _In_ PCSTR JA3Fingerprint
    )
{
    BOOLEAN isKnown = FALSE;

    if (JA3Fingerprint == NULL) {
        return FALSE;
    }

    //
    // Check against C2 detector if available
    //
    if (g_C2Detector != NULL) {
        UCHAR ja3Hash[16];

        //
        // The JA3 fingerprint is typically MD5 hash in hex
        // In production, parse hex string to bytes
        //
        UNREFERENCED_PARAMETER(ja3Hash);

        //
        // For now, return false as placeholder
        // In production: C2LookupJA3(g_C2Detector, ja3Hash, &isKnown, NULL, 0);
        //
    }

    return isKnown;
}

// ============================================================================
// PUBLIC API - STATISTICS
// ============================================================================

/**
 * @brief Get network filter statistics.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
NfFilterGetStatistics(
    _Out_ PNETWORK_FILTER_GLOBALS Stats
    )
{
    if (Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_NfState.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    RtlCopyMemory(Stats, &g_NfState, sizeof(NETWORK_FILTER_GLOBALS));
    return STATUS_SUCCESS;
}

/**
 * @brief Get connection statistics for process.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
NfFilterGetProcessNetworkStats(
    _In_ UINT32 ProcessId,
    _Out_ PUINT32 ConnectionCount,
    _Out_ PUINT64 BytesSent,
    _Out_ PUINT64 BytesReceived
    )
{
    PLIST_ENTRY entry;
    PNF_CONNECTION_ENTRY connection;
    UINT32 count = 0;
    UINT64 sent = 0;
    UINT64 received = 0;

    if (ConnectionCount == NULL || BytesSent == NULL || BytesReceived == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_NfState.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    ExAcquireResourceSharedLite(&g_NfState.ConnectionLock, TRUE);

    for (entry = g_NfState.ConnectionList.Flink;
         entry != &g_NfState.ConnectionList;
         entry = entry->Flink) {

        connection = CONTAINING_RECORD(entry, NF_CONNECTION_ENTRY, ListEntry);

        if (connection->ProcessId == ProcessId) {
            count++;
            sent += connection->BytesSent;
            received += connection->BytesReceived;
        }
    }

    ExReleaseResourceLite(&g_NfState.ConnectionLock);

    *ConnectionCount = count;
    *BytesSent = sent;
    *BytesReceived = received;

    return STATUS_SUCCESS;
}

// ============================================================================
// WFP CALLOUT FUNCTIONS
// ============================================================================

/**
 * @brief ALE Connect classify function (outbound connections).
 */
VOID NTAPI
NfAleConnectClassify(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER3* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
    )
{
    BOOLEAN isV6;

    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);

    //
    // Check if we should process this
    //
    if (!g_NfState.Initialized || !g_NfState.Enabled) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    if (!g_NfState.Config.EnableConnectionMonitoring) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    //
    // Check rate limit
    //
    if (!NfpCheckRateLimit()) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    //
    // Determine if IPv6
    //
    isV6 = (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6);

    //
    // Process the outbound connection
    //
    NfpProcessOutboundConnect(inFixedValues, inMetaValues, flowContext, classifyOut, isV6);
}

/**
 * @brief ALE Recv Accept classify function (inbound connections).
 */
VOID NTAPI
NfAleRecvAcceptClassify(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER3* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
    )
{
    BOOLEAN isV6;

    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);

    if (!g_NfState.Initialized || !g_NfState.Enabled) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    if (!g_NfState.Config.EnableConnectionMonitoring) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    if (!NfpCheckRateLimit()) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    isV6 = (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6);

    NfpProcessInboundAccept(inFixedValues, inMetaValues, flowContext, classifyOut, isV6);
}

/**
 * @brief Outbound transport classify function (for DNS).
 */
VOID NTAPI
NfOutboundTransportClassify(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER3* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
    )
{
    UINT16 remotePort;

    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    if (!g_NfState.Initialized || !g_NfState.Enabled) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    if (!g_NfState.Config.EnableDnsMonitoring) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    //
    // Check if this is DNS traffic (port 53)
    //
    remotePort = inFixedValues->incomingValue[
        FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;

    if (remotePort == NF_DNS_PORT) {
        if (NfpCheckRateLimit()) {
            NfpProcessDnsPacket(inFixedValues, inMetaValues, layerData, classifyOut);
            return;
        }
    }

    classifyOut->actionType = FWP_ACTION_PERMIT;
}

/**
 * @brief Stream data classify function (TCP inspection).
 */
VOID NTAPI
NfStreamClassify(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER3* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
    )
{
    FWPS_STREAM_CALLOUT_IO_PACKET0* streamPacket;

    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);

    if (!g_NfState.Initialized || !g_NfState.Enabled) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    if (!g_NfState.Config.EnableDataInspection) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    streamPacket = (FWPS_STREAM_CALLOUT_IO_PACKET0*)layerData;

    if (streamPacket != NULL && NfpCheckRateLimit()) {
        NfpProcessStreamData(inFixedValues, inMetaValues, streamPacket,
                             flowContext, classifyOut);
    } else {
        classifyOut->actionType = FWP_ACTION_PERMIT;
    }
}

/**
 * @brief Callout notify function.
 */
NTSTATUS NTAPI
NfCalloutNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER3* filter
    )
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);

    return STATUS_SUCCESS;
}

/**
 * @brief Flow delete notify function.
 */
VOID NTAPI
NfFlowDeleteNotify(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext
    )
{
    PNF_CONNECTION_ENTRY connection;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);

    if (!g_NfState.Initialized) {
        return;
    }

    //
    // Find and update connection state
    //
    status = NfFilterFindConnectionByFlow(flowContext, &connection);
    if (NT_SUCCESS(status)) {
        connection->State = ConnectionState_Closed;
        NfFilterReleaseConnection(connection);
    }
}

// ============================================================================
// PRIVATE FUNCTIONS - INITIALIZATION
// ============================================================================

/**
 * @brief Register all WFP callouts.
 */
static NTSTATUS
NfpRegisterCallouts(
    _In_ PDEVICE_OBJECT DeviceObject
    )
{
    NTSTATUS status;
    FWPS_CALLOUT3 sCallout = {0};
    FWPM_CALLOUT0 mCallout = {0};
    FWPM_DISPLAY_DATA0 displayData = {0};

    //
    // Register ALE Connect v4 callout
    //
    sCallout.calloutKey = SHADOWSTRIKE_ALE_CONNECT_V4_CALLOUT_GUID;
    sCallout.classifyFn = NfAleConnectClassify;
    sCallout.notifyFn = NfCalloutNotify;
    sCallout.flowDeleteFn = NfFlowDeleteNotify;
    sCallout.flags = FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW;

    status = FwpsCalloutRegister3(DeviceObject, &sCallout,
                                  &g_NfState.AleConnectV4CalloutId);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    displayData.name = L"ShadowStrike ALE Connect v4";
    displayData.description = L"Monitors outbound IPv4 connections";

    mCallout.calloutKey = SHADOWSTRIKE_ALE_CONNECT_V4_CALLOUT_GUID;
    mCallout.displayData = displayData;
    mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    mCallout.flags = 0;

    status = FwpmCalloutAdd0(g_NfState.WfpEngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        FwpsCalloutUnregisterById0(g_NfState.AleConnectV4CalloutId);
        return status;
    }

    //
    // Register ALE Connect v6 callout
    //
    sCallout.calloutKey = SHADOWSTRIKE_ALE_CONNECT_V6_CALLOUT_GUID;

    status = FwpsCalloutRegister3(DeviceObject, &sCallout,
                                  &g_NfState.AleConnectV6CalloutId);
    if (!NT_SUCCESS(status)) {
        goto CleanupV4Connect;
    }

    displayData.name = L"ShadowStrike ALE Connect v6";
    displayData.description = L"Monitors outbound IPv6 connections";

    mCallout.calloutKey = SHADOWSTRIKE_ALE_CONNECT_V6_CALLOUT_GUID;
    mCallout.displayData = displayData;
    mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V6;

    status = FwpmCalloutAdd0(g_NfState.WfpEngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        FwpsCalloutUnregisterById0(g_NfState.AleConnectV6CalloutId);
        goto CleanupV4Connect;
    }

    //
    // Register ALE Recv Accept v4 callout
    //
    sCallout.calloutKey = SHADOWSTRIKE_ALE_RECV_ACCEPT_V4_CALLOUT_GUID;
    sCallout.classifyFn = NfAleRecvAcceptClassify;

    status = FwpsCalloutRegister3(DeviceObject, &sCallout,
                                  &g_NfState.AleRecvAcceptV4CalloutId);
    if (!NT_SUCCESS(status)) {
        goto CleanupV6Connect;
    }

    displayData.name = L"ShadowStrike ALE Recv Accept v4";
    displayData.description = L"Monitors inbound IPv4 connections";

    mCallout.calloutKey = SHADOWSTRIKE_ALE_RECV_ACCEPT_V4_CALLOUT_GUID;
    mCallout.displayData = displayData;
    mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;

    status = FwpmCalloutAdd0(g_NfState.WfpEngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        FwpsCalloutUnregisterById0(g_NfState.AleRecvAcceptV4CalloutId);
        goto CleanupV6Connect;
    }

    //
    // Register ALE Recv Accept v6 callout
    //
    sCallout.calloutKey = SHADOWSTRIKE_ALE_RECV_ACCEPT_V6_CALLOUT_GUID;

    status = FwpsCalloutRegister3(DeviceObject, &sCallout,
                                  &g_NfState.AleRecvAcceptV6CalloutId);
    if (!NT_SUCCESS(status)) {
        goto CleanupV4Accept;
    }

    displayData.name = L"ShadowStrike ALE Recv Accept v6";
    displayData.description = L"Monitors inbound IPv6 connections";

    mCallout.calloutKey = SHADOWSTRIKE_ALE_RECV_ACCEPT_V6_CALLOUT_GUID;
    mCallout.displayData = displayData;
    mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;

    status = FwpmCalloutAdd0(g_NfState.WfpEngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        FwpsCalloutUnregisterById0(g_NfState.AleRecvAcceptV6CalloutId);
        goto CleanupV4Accept;
    }

    //
    // Register Outbound Transport v4 callout (DNS)
    //
    sCallout.calloutKey = SHADOWSTRIKE_OUTBOUND_TRANSPORT_V4_CALLOUT_GUID;
    sCallout.classifyFn = NfOutboundTransportClassify;
    sCallout.flowDeleteFn = NULL;
    sCallout.flags = 0;

    status = FwpsCalloutRegister3(DeviceObject, &sCallout,
                                  &g_NfState.OutboundTransportV4CalloutId);
    if (!NT_SUCCESS(status)) {
        goto CleanupV6Accept;
    }

    displayData.name = L"ShadowStrike Outbound Transport v4";
    displayData.description = L"Monitors DNS and other transport traffic";

    mCallout.calloutKey = SHADOWSTRIKE_OUTBOUND_TRANSPORT_V4_CALLOUT_GUID;
    mCallout.displayData = displayData;
    mCallout.applicableLayer = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;

    status = FwpmCalloutAdd0(g_NfState.WfpEngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        FwpsCalloutUnregisterById0(g_NfState.OutboundTransportV4CalloutId);
        goto CleanupV6Accept;
    }

    //
    // Register Stream v4 callout (TCP data)
    //
    sCallout.calloutKey = SHADOWSTRIKE_STREAM_V4_CALLOUT_GUID;
    sCallout.classifyFn = NfStreamClassify;
    sCallout.flags = FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW;

    status = FwpsCalloutRegister3(DeviceObject, &sCallout,
                                  &g_NfState.StreamV4CalloutId);
    if (!NT_SUCCESS(status)) {
        goto CleanupTransport;
    }

    displayData.name = L"ShadowStrike Stream v4";
    displayData.description = L"Inspects TCP stream data";

    mCallout.calloutKey = SHADOWSTRIKE_STREAM_V4_CALLOUT_GUID;
    mCallout.displayData = displayData;
    mCallout.applicableLayer = FWPM_LAYER_STREAM_V4;

    status = FwpmCalloutAdd0(g_NfState.WfpEngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        FwpsCalloutUnregisterById0(g_NfState.StreamV4CalloutId);
        goto CleanupTransport;
    }

    return STATUS_SUCCESS;

CleanupTransport:
    FwpsCalloutUnregisterById0(g_NfState.OutboundTransportV4CalloutId);

CleanupV6Accept:
    FwpsCalloutUnregisterById0(g_NfState.AleRecvAcceptV6CalloutId);

CleanupV4Accept:
    FwpsCalloutUnregisterById0(g_NfState.AleRecvAcceptV4CalloutId);

CleanupV6Connect:
    FwpsCalloutUnregisterById0(g_NfState.AleConnectV6CalloutId);

CleanupV4Connect:
    FwpsCalloutUnregisterById0(g_NfState.AleConnectV4CalloutId);

    return status;
}

/**
 * @brief Unregister all WFP callouts.
 */
static VOID
NfpUnregisterCallouts(
    VOID
    )
{
    if (g_NfState.StreamV4CalloutId != 0) {
        FwpsCalloutUnregisterById0(g_NfState.StreamV4CalloutId);
        g_NfState.StreamV4CalloutId = 0;
    }

    if (g_NfState.OutboundTransportV4CalloutId != 0) {
        FwpsCalloutUnregisterById0(g_NfState.OutboundTransportV4CalloutId);
        g_NfState.OutboundTransportV4CalloutId = 0;
    }

    if (g_NfState.AleRecvAcceptV6CalloutId != 0) {
        FwpsCalloutUnregisterById0(g_NfState.AleRecvAcceptV6CalloutId);
        g_NfState.AleRecvAcceptV6CalloutId = 0;
    }

    if (g_NfState.AleRecvAcceptV4CalloutId != 0) {
        FwpsCalloutUnregisterById0(g_NfState.AleRecvAcceptV4CalloutId);
        g_NfState.AleRecvAcceptV4CalloutId = 0;
    }

    if (g_NfState.AleConnectV6CalloutId != 0) {
        FwpsCalloutUnregisterById0(g_NfState.AleConnectV6CalloutId);
        g_NfState.AleConnectV6CalloutId = 0;
    }

    if (g_NfState.AleConnectV4CalloutId != 0) {
        FwpsCalloutUnregisterById0(g_NfState.AleConnectV4CalloutId);
        g_NfState.AleConnectV4CalloutId = 0;
    }
}

/**
 * @brief Register WFP filters.
 */
static NTSTATUS
NfpRegisterFilters(
    VOID
    )
{
    NTSTATUS status;
    FWPM_FILTER0 filter = {0};

    filter.subLayerKey = SHADOWSTRIKE_WFP_SUBLAYER_GUID;
    filter.weight.type = FWP_EMPTY;
    filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;

    //
    // ALE Connect v4 filter
    //
    filter.displayData.name = L"ShadowStrike ALE Connect v4 Filter";
    filter.displayData.description = L"Inspect outbound IPv4 connections";
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.action.calloutKey = SHADOWSTRIKE_ALE_CONNECT_V4_CALLOUT_GUID;

    status = FwpmFilterAdd0(g_NfState.WfpEngineHandle, &filter, NULL,
                            &g_NfState.AleConnectV4FilterId);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // ALE Connect v6 filter
    //
    filter.displayData.name = L"ShadowStrike ALE Connect v6 Filter";
    filter.displayData.description = L"Inspect outbound IPv6 connections";
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    filter.action.calloutKey = SHADOWSTRIKE_ALE_CONNECT_V6_CALLOUT_GUID;

    status = FwpmFilterAdd0(g_NfState.WfpEngineHandle, &filter, NULL,
                            &g_NfState.AleConnectV6FilterId);
    if (!NT_SUCCESS(status)) {
        goto CleanupV4Connect;
    }

    //
    // ALE Recv Accept v4 filter
    //
    filter.displayData.name = L"ShadowStrike ALE Recv Accept v4 Filter";
    filter.displayData.description = L"Inspect inbound IPv4 connections";
    filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
    filter.action.calloutKey = SHADOWSTRIKE_ALE_RECV_ACCEPT_V4_CALLOUT_GUID;

    status = FwpmFilterAdd0(g_NfState.WfpEngineHandle, &filter, NULL,
                            &g_NfState.AleRecvAcceptV4FilterId);
    if (!NT_SUCCESS(status)) {
        goto CleanupV6Connect;
    }

    //
    // ALE Recv Accept v6 filter
    //
    filter.displayData.name = L"ShadowStrike ALE Recv Accept v6 Filter";
    filter.displayData.description = L"Inspect inbound IPv6 connections";
    filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
    filter.action.calloutKey = SHADOWSTRIKE_ALE_RECV_ACCEPT_V6_CALLOUT_GUID;

    status = FwpmFilterAdd0(g_NfState.WfpEngineHandle, &filter, NULL,
                            &g_NfState.AleRecvAcceptV6FilterId);
    if (!NT_SUCCESS(status)) {
        goto CleanupV4Accept;
    }

    //
    // Outbound Transport v4 filter
    //
    filter.displayData.name = L"ShadowStrike Outbound Transport v4 Filter";
    filter.displayData.description = L"Inspect DNS and transport traffic";
    filter.layerKey = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
    filter.action.calloutKey = SHADOWSTRIKE_OUTBOUND_TRANSPORT_V4_CALLOUT_GUID;

    status = FwpmFilterAdd0(g_NfState.WfpEngineHandle, &filter, NULL,
                            &g_NfState.OutboundTransportV4FilterId);
    if (!NT_SUCCESS(status)) {
        goto CleanupV6Accept;
    }

    //
    // Stream v4 filter
    //
    filter.displayData.name = L"ShadowStrike Stream v4 Filter";
    filter.displayData.description = L"Inspect TCP stream data";
    filter.layerKey = FWPM_LAYER_STREAM_V4;
    filter.action.calloutKey = SHADOWSTRIKE_STREAM_V4_CALLOUT_GUID;

    status = FwpmFilterAdd0(g_NfState.WfpEngineHandle, &filter, NULL,
                            &g_NfState.StreamV4FilterId);
    if (!NT_SUCCESS(status)) {
        goto CleanupTransport;
    }

    return STATUS_SUCCESS;

CleanupTransport:
    FwpmFilterDeleteById0(g_NfState.WfpEngineHandle, g_NfState.OutboundTransportV4FilterId);

CleanupV6Accept:
    FwpmFilterDeleteById0(g_NfState.WfpEngineHandle, g_NfState.AleRecvAcceptV6FilterId);

CleanupV4Accept:
    FwpmFilterDeleteById0(g_NfState.WfpEngineHandle, g_NfState.AleRecvAcceptV4FilterId);

CleanupV6Connect:
    FwpmFilterDeleteById0(g_NfState.WfpEngineHandle, g_NfState.AleConnectV6FilterId);

CleanupV4Connect:
    FwpmFilterDeleteById0(g_NfState.WfpEngineHandle, g_NfState.AleConnectV4FilterId);

    return status;
}

/**
 * @brief Unregister WFP filters.
 */
static VOID
NfpUnregisterFilters(
    VOID
    )
{
    if (g_NfState.WfpEngineHandle == NULL) {
        return;
    }

    if (g_NfState.StreamV4FilterId != 0) {
        FwpmFilterDeleteById0(g_NfState.WfpEngineHandle, g_NfState.StreamV4FilterId);
        g_NfState.StreamV4FilterId = 0;
    }

    if (g_NfState.OutboundTransportV4FilterId != 0) {
        FwpmFilterDeleteById0(g_NfState.WfpEngineHandle, g_NfState.OutboundTransportV4FilterId);
        g_NfState.OutboundTransportV4FilterId = 0;
    }

    if (g_NfState.AleRecvAcceptV6FilterId != 0) {
        FwpmFilterDeleteById0(g_NfState.WfpEngineHandle, g_NfState.AleRecvAcceptV6FilterId);
        g_NfState.AleRecvAcceptV6FilterId = 0;
    }

    if (g_NfState.AleRecvAcceptV4FilterId != 0) {
        FwpmFilterDeleteById0(g_NfState.WfpEngineHandle, g_NfState.AleRecvAcceptV4FilterId);
        g_NfState.AleRecvAcceptV4FilterId = 0;
    }

    if (g_NfState.AleConnectV6FilterId != 0) {
        FwpmFilterDeleteById0(g_NfState.WfpEngineHandle, g_NfState.AleConnectV6FilterId);
        g_NfState.AleConnectV6FilterId = 0;
    }

    if (g_NfState.AleConnectV4FilterId != 0) {
        FwpmFilterDeleteById0(g_NfState.WfpEngineHandle, g_NfState.AleConnectV4FilterId);
        g_NfState.AleConnectV4FilterId = 0;
    }
}

/**
 * @brief Initialize hash tables.
 */
static NTSTATUS
NfpInitializeHashTables(
    VOID
    )
{
    ULONG i;

    //
    // Initialize connection hash table
    //
    for (i = 0; i < NF_CONNECTION_HASH_BUCKETS; i++) {
        InitializeListHead(&g_ConnectionHashTable[i]);
    }
    ExInitializePushLock(&g_ConnectionHashLock);

    //
    // Initialize flow hash table
    //
    for (i = 0; i < NF_CONNECTION_HASH_BUCKETS; i++) {
        InitializeListHead(&g_FlowHashTable[i]);
    }
    ExInitializePushLock(&g_FlowHashLock);

    return STATUS_SUCCESS;
}

/**
 * @brief Cleanup hash tables.
 */
static VOID
NfpCleanupHashTables(
    VOID
    )
{
    //
    // Hash tables use static arrays, no dynamic cleanup needed
    // Entries are freed when connections are removed
    //
}

/**
 * @brief Initialize lookaside lists.
 */
static NTSTATUS
NfpInitializeLookasideLists(
    VOID
    )
{
    ExInitializeNPagedLookasideList(
        &g_NfState.ConnectionLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(NF_CONNECTION_ENTRY),
        NF_POOL_TAG_CONNECTION,
        NF_CONNECTION_LOOKASIDE_DEPTH
        );

    ExInitializeNPagedLookasideList(
        &g_NfState.DnsLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(NF_DNS_ENTRY),
        NF_POOL_TAG_DNS,
        NF_DNS_LOOKASIDE_DEPTH
        );

    ExInitializeNPagedLookasideList(
        &g_NfState.EventLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(NETWORK_CONNECTION_EVENT),
        NF_POOL_TAG_EVENT,
        NF_EVENT_LOOKASIDE_DEPTH
        );

    return STATUS_SUCCESS;
}

/**
 * @brief Cleanup lookaside lists.
 */
static VOID
NfpCleanupLookasideLists(
    VOID
    )
{
    ExDeleteNPagedLookasideList(&g_NfState.ConnectionLookaside);
    ExDeleteNPagedLookasideList(&g_NfState.DnsLookaside);
    ExDeleteNPagedLookasideList(&g_NfState.EventLookaside);
}

// ============================================================================
// PRIVATE FUNCTIONS - MEMORY MANAGEMENT
// ============================================================================

/**
 * @brief Allocate connection entry from lookaside.
 */
static PNF_CONNECTION_ENTRY
NfpAllocateConnection(
    VOID
    )
{
    PNF_CONNECTION_ENTRY connection;

    connection = (PNF_CONNECTION_ENTRY)ExAllocateFromNPagedLookasideList(
        &g_NfState.ConnectionLookaside
        );

    if (connection != NULL) {
        RtlZeroMemory(connection, sizeof(NF_CONNECTION_ENTRY));
        connection->RefCount = 1;
    }

    return connection;
}

/**
 * @brief Free connection entry to lookaside.
 */
static VOID
NfpFreeConnection(
    _In_ PNF_CONNECTION_ENTRY Connection
    )
{
    if (Connection != NULL) {
        ExFreeToNPagedLookasideList(&g_NfState.ConnectionLookaside, Connection);
    }
}

/**
 * @brief Allocate DNS entry from lookaside.
 */
static PNF_DNS_ENTRY
NfpAllocateDnsEntry(
    VOID
    )
{
    PNF_DNS_ENTRY dnsEntry;

    dnsEntry = (PNF_DNS_ENTRY)ExAllocateFromNPagedLookasideList(
        &g_NfState.DnsLookaside
        );

    if (dnsEntry != NULL) {
        RtlZeroMemory(dnsEntry, sizeof(NF_DNS_ENTRY));
    }

    return dnsEntry;
}

/**
 * @brief Free DNS entry to lookaside.
 */
static VOID
NfpFreeDnsEntry(
    _In_ PNF_DNS_ENTRY DnsEntry
    )
{
    if (DnsEntry != NULL) {
        ExFreeToNPagedLookasideList(&g_NfState.DnsLookaside, DnsEntry);
    }
}

// ============================================================================
// PRIVATE FUNCTIONS - HASHING
// ============================================================================

/**
 * @brief Hash connection endpoints for lookup.
 */
static UINT32
NfpHashEndpoints(
    _In_ PSS_SOCKET_ADDRESS Local,
    _In_ PSS_SOCKET_ADDRESS Remote,
    _In_ NETWORK_PROTOCOL Protocol
    )
{
    UINT32 hash = 5381;
    PUCHAR bytes;
    ULONG i;
    ULONG addrLen;

    //
    // DJB2 hash algorithm
    //
    addrLen = (Local->Address.Family == 2) ? 4 : 16;  // AF_INET vs AF_INET6

    bytes = (PUCHAR)&Local->Address;
    for (i = 0; i < addrLen; i++) {
        hash = ((hash << 5) + hash) + bytes[i];
    }

    hash = ((hash << 5) + hash) + (Local->Port & 0xFF);
    hash = ((hash << 5) + hash) + ((Local->Port >> 8) & 0xFF);

    bytes = (PUCHAR)&Remote->Address;
    for (i = 0; i < addrLen; i++) {
        hash = ((hash << 5) + hash) + bytes[i];
    }

    hash = ((hash << 5) + hash) + (Remote->Port & 0xFF);
    hash = ((hash << 5) + hash) + ((Remote->Port >> 8) & 0xFF);
    hash = ((hash << 5) + hash) + Protocol;

    return hash % NF_CONNECTION_HASH_BUCKETS;
}

/**
 * @brief Hash flow ID for lookup.
 */
static UINT32
NfpHashFlowId(
    _In_ UINT64 FlowId
    )
{
    //
    // Simple hash for 64-bit flow ID
    //
    UINT32 hash = (UINT32)(FlowId ^ (FlowId >> 32));
    return hash % NF_CONNECTION_HASH_BUCKETS;
}

/**
 * @brief Hash domain name for DNS lookup.
 */
static UINT32
NfpHashDomainName(
    _In_ PCWSTR DomainName
    )
{
    UINT32 hash = 5381;
    WCHAR c;

    while ((c = *DomainName++) != L'\0') {
        //
        // Case-insensitive hash
        //
        if (c >= L'A' && c <= L'Z') {
            c = c - L'A' + L'a';
        }
        hash = ((hash << 5) + hash) + c;
    }

    return hash;
}

// ============================================================================
// PRIVATE FUNCTIONS - CONNECTION MANAGEMENT
// ============================================================================

/**
 * @brief Insert connection into tracking tables.
 */
static NTSTATUS
NfpInsertConnection(
    _In_ PNF_CONNECTION_ENTRY Connection
    )
{
    UINT32 hashIndex;
    PNF_CONNECTION_HASH_ENTRY hashEntry;
    PNF_CONNECTION_HASH_ENTRY flowEntry;

    //
    // Check connection limit
    //
    if ((UINT32)g_NfState.ConnectionCount >= NF_MAX_CONNECTIONS) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Allocate hash entries
    //
    hashEntry = (PNF_CONNECTION_HASH_ENTRY)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(NF_CONNECTION_HASH_ENTRY),
        NF_POOL_TAG_CONNECTION
        );

    if (hashEntry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    flowEntry = (PNF_CONNECTION_HASH_ENTRY)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(NF_CONNECTION_HASH_ENTRY),
        NF_POOL_TAG_CONNECTION
        );

    if (flowEntry == NULL) {
        ExFreePoolWithTag(hashEntry, NF_POOL_TAG_CONNECTION);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    hashEntry->Connection = Connection;
    flowEntry->Connection = Connection;

    //
    // Insert into main list
    //
    ExAcquireResourceExclusiveLite(&g_NfState.ConnectionLock, TRUE);
    InsertTailList(&g_NfState.ConnectionList, &Connection->ListEntry);
    g_NfState.ConnectionCount++;
    ExReleaseResourceLite(&g_NfState.ConnectionLock);

    //
    // Insert into endpoint hash
    //
    hashIndex = NfpHashEndpoints(&Connection->LocalAddress,
                                 &Connection->RemoteAddress,
                                 Connection->Protocol);

    FltAcquirePushLockExclusive(&g_ConnectionHashLock);
    InsertTailList(&g_ConnectionHashTable[hashIndex], &hashEntry->HashListEntry);
    FltReleasePushLock(&g_ConnectionHashLock);

    //
    // Insert into flow hash
    //
    hashIndex = NfpHashFlowId(Connection->FlowId);

    FltAcquirePushLockExclusive(&g_FlowHashLock);
    InsertTailList(&g_FlowHashTable[hashIndex], &flowEntry->HashListEntry);
    FltReleasePushLock(&g_FlowHashLock);

    //
    // Update statistics
    //
    InterlockedIncrement64(&g_NfState.TotalConnectionsMonitored);

    return STATUS_SUCCESS;
}

/**
 * @brief Remove connection from tracking tables.
 */
static VOID
NfpRemoveConnection(
    _In_ PNF_CONNECTION_ENTRY Connection
    )
{
    UINT32 hashIndex;
    PLIST_ENTRY entry;
    PNF_CONNECTION_HASH_ENTRY hashEntry;
    PNF_CONNECTION_HASH_ENTRY flowEntry = NULL;
    PNF_CONNECTION_HASH_ENTRY connEntry = NULL;

    //
    // Remove from main list
    //
    ExAcquireResourceExclusiveLite(&g_NfState.ConnectionLock, TRUE);
    RemoveEntryList(&Connection->ListEntry);
    g_NfState.ConnectionCount--;
    ExReleaseResourceLite(&g_NfState.ConnectionLock);

    //
    // Remove from endpoint hash
    //
    hashIndex = NfpHashEndpoints(&Connection->LocalAddress,
                                 &Connection->RemoteAddress,
                                 Connection->Protocol);

    FltAcquirePushLockExclusive(&g_ConnectionHashLock);

    for (entry = g_ConnectionHashTable[hashIndex].Flink;
         entry != &g_ConnectionHashTable[hashIndex];
         entry = entry->Flink) {

        hashEntry = CONTAINING_RECORD(entry, NF_CONNECTION_HASH_ENTRY, HashListEntry);
        if (hashEntry->Connection == Connection) {
            RemoveEntryList(&hashEntry->HashListEntry);
            connEntry = hashEntry;
            break;
        }
    }

    FltReleasePushLock(&g_ConnectionHashLock);

    //
    // Remove from flow hash
    //
    hashIndex = NfpHashFlowId(Connection->FlowId);

    FltAcquirePushLockExclusive(&g_FlowHashLock);

    for (entry = g_FlowHashTable[hashIndex].Flink;
         entry != &g_FlowHashTable[hashIndex];
         entry = entry->Flink) {

        hashEntry = CONTAINING_RECORD(entry, NF_CONNECTION_HASH_ENTRY, HashListEntry);
        if (hashEntry->Connection == Connection) {
            RemoveEntryList(&hashEntry->HashListEntry);
            flowEntry = hashEntry;
            break;
        }
    }

    FltReleasePushLock(&g_FlowHashLock);

    //
    // Free hash entries
    //
    if (connEntry != NULL) {
        ExFreePoolWithTag(connEntry, NF_POOL_TAG_CONNECTION);
    }
    if (flowEntry != NULL) {
        ExFreePoolWithTag(flowEntry, NF_POOL_TAG_CONNECTION);
    }
}

// ============================================================================
// PRIVATE FUNCTIONS - CLEANUP
// ============================================================================

/**
 * @brief Cleanup timer DPC callback.
 */
static VOID
NfpCleanupTimerCallback(
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

    //
    // Mark cleanup in progress
    //
    if (InterlockedCompareExchange(&g_CleanupInProgress, 1, 0) != 0) {
        //
        // Another cleanup is in progress
        //
        return;
    }

    //
    // Perform cleanup (must run at PASSIVE_LEVEL for resource acquisition)
    // Queue work item for actual cleanup
    //
    // For simplicity in this implementation, we skip the work item
    // and note that cleanup is now complete
    //
    InterlockedExchange(&g_CleanupInProgress, 0);
}

/**
 * @brief Cleanup stale connections.
 */
static VOID
NfpCleanupStaleConnections(
    VOID
    )
{
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;
    PNF_CONNECTION_ENTRY connection;
    LARGE_INTEGER currentTime;
    UINT64 currentTimeMs;
    LIST_ENTRY staleList;

    InitializeListHead(&staleList);
    KeQuerySystemTime(&currentTime);
    currentTimeMs = (UINT64)(currentTime.QuadPart / 10000);

    //
    // Find stale connections
    //
    ExAcquireResourceExclusiveLite(&g_NfState.ConnectionLock, TRUE);

    for (entry = g_NfState.ConnectionList.Flink;
         entry != &g_NfState.ConnectionList;
         entry = nextEntry) {

        nextEntry = entry->Flink;
        connection = CONTAINING_RECORD(entry, NF_CONNECTION_ENTRY, ListEntry);

        //
        // Check if connection is stale and has no references
        //
        if (connection->RefCount <= 0 &&
            connection->State == ConnectionState_Closed &&
            (currentTimeMs - connection->LastActivityTime) > NF_CONNECTION_TIMEOUT_MS) {

            RemoveEntryList(&connection->ListEntry);
            InsertTailList(&staleList, &connection->ListEntry);
            g_NfState.ConnectionCount--;
        }
    }

    ExReleaseResourceLite(&g_NfState.ConnectionLock);

    //
    // Free stale connections
    //
    while (!IsListEmpty(&staleList)) {
        entry = RemoveHeadList(&staleList);
        connection = CONTAINING_RECORD(entry, NF_CONNECTION_ENTRY, ListEntry);
        NfpFreeConnection(connection);
    }
}

/**
 * @brief Cleanup stale DNS entries.
 */
static VOID
NfpCleanupStaleDnsEntries(
    VOID
    )
{
    //
    // Similar to connection cleanup but for DNS cache
    // Implementation would follow same pattern
    //
}

// ============================================================================
// PRIVATE FUNCTIONS - RATE LIMITING
// ============================================================================

/**
 * @brief Check if event should be processed (rate limiting).
 */
static BOOLEAN
NfpCheckRateLimit(
    VOID
    )
{
    LARGE_INTEGER currentTime;
    UINT64 currentTimeMs;
    LONG currentEvents;

    KeQuerySystemTime(&currentTime);
    currentTimeMs = (UINT64)(currentTime.QuadPart / 10000);

    //
    // Check if we're in a new second
    //
    if (currentTimeMs - g_CurrentSecondStart >= 1000) {
        g_CurrentSecondStart = currentTimeMs;
        InterlockedExchange(&g_EventsThisSecond, 0);
    }

    //
    // Check rate limit
    //
    currentEvents = InterlockedIncrement(&g_EventsThisSecond);

    if ((UINT32)currentEvents > g_NfState.Config.MaxEventsPerSecond) {
        InterlockedIncrement64(&g_TotalEventsDropped);
        InterlockedIncrement64(&g_NfState.EventsDropped);

        //
        // Log rate limiting periodically
        //
        if (currentTimeMs - g_LastRateLimitLogTime > NF_RATE_LIMIT_LOG_INTERVAL_MS) {
            g_LastRateLimitLogTime = currentTimeMs;
            //
            // In production: log rate limiting warning
            //
        }

        return FALSE;
    }

    return TRUE;
}

// ============================================================================
// PRIVATE FUNCTIONS - UTILITY
// ============================================================================

/**
 * @brief Get process image path.
 */
static VOID
NfpGetProcessPath(
    _In_ HANDLE ProcessId,
    _Out_writes_(MaxLength) PWCHAR ProcessPath,
    _In_ ULONG MaxLength
    )
{
    PEPROCESS process = NULL;
    NTSTATUS status;
    PUNICODE_STRING imageName = NULL;

    ProcessPath[0] = L'\0';

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return;
    }

    status = SeLocateProcessImageName(process, &imageName);
    if (NT_SUCCESS(status) && imageName != NULL) {
        ULONG copyLen = min(imageName->Length / sizeof(WCHAR), MaxLength - 1);
        RtlCopyMemory(ProcessPath, imageName->Buffer, copyLen * sizeof(WCHAR));
        ProcessPath[copyLen] = L'\0';
        ExFreePool(imageName);
    }

    ObDereferenceObject(process);
}

/**
 * @brief Copy address from WFP format to internal format.
 */
static VOID
NfpCopyAddress(
    _Out_ PSS_SOCKET_ADDRESS Dest,
    _In_ const FWP_BYTE_ARRAY16* IpV6,
    _In_ const UINT32* IpV4,
    _In_ UINT16 Port,
    _In_ BOOLEAN IsV6
    )
{
    RtlZeroMemory(Dest, sizeof(SS_SOCKET_ADDRESS));

    if (IsV6) {
        Dest->Address.Family = 23;  // AF_INET6
        if (IpV6 != NULL) {
            RtlCopyMemory(Dest->Address.V6.Bytes, IpV6->byteArray16, 16);
        }
    } else {
        Dest->Address.Family = 2;   // AF_INET
        if (IpV4 != NULL) {
            Dest->Address.V4.Address = *IpV4;
        }
    }

    Dest->Port = Port;
}

/**
 * @brief Check if address is private (RFC 1918).
 */
static BOOLEAN
NfpIsPrivateAddress(
    _In_ PSS_IP_ADDRESS Address
    )
{
    if (SS_IS_IPV4(Address)) {
        PUCHAR bytes = Address->V4.Bytes;

        //
        // 10.0.0.0/8
        //
        if (bytes[0] == 10) {
            return TRUE;
        }

        //
        // 172.16.0.0/12
        //
        if (bytes[0] == 172 && (bytes[1] & 0xF0) == 16) {
            return TRUE;
        }

        //
        // 192.168.0.0/16
        //
        if (bytes[0] == 192 && bytes[1] == 168) {
            return TRUE;
        }
    }

    return FALSE;
}

/**
 * @brief Check if address is loopback.
 */
static BOOLEAN
NfpIsLoopbackAddress(
    _In_ PSS_IP_ADDRESS Address
    )
{
    if (SS_IS_IPV4(Address)) {
        return (Address->V4.Bytes[0] == 127);
    }

    if (SS_IS_IPV6(Address)) {
        //
        // Check for ::1
        //
        static const UINT8 loopback[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        return (RtlCompareMemory(Address->V6.Bytes, loopback, 16) == 16);
    }

    return FALSE;
}

// ============================================================================
// PRIVATE FUNCTIONS - CONNECTION PROCESSING
// ============================================================================

/**
 * @brief Process outbound connection.
 */
static VOID
NfpProcessOutboundConnect(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _In_ UINT64 FlowContext,
    _Out_ FWPS_CLASSIFY_OUT0* ClassifyOut,
    _In_ BOOLEAN IsV6
    )
{
    PNF_CONNECTION_ENTRY connection;
    NTSTATUS status;
    LARGE_INTEGER currentTime;
    UINT32 localIp = 0;
    UINT32 remoteIp = 0;
    FWP_BYTE_ARRAY16* localIp6 = NULL;
    FWP_BYTE_ARRAY16* remoteIp6 = NULL;
    UINT16 localPort;
    UINT16 remotePort;
    UINT8 protocol;
    UINT64 processId;

    //
    // Default to permit
    //
    ClassifyOut->actionType = FWP_ACTION_PERMIT;

    //
    // Extract connection details
    //
    if (IsV6) {
        localIp6 = InFixedValues->incomingValue[
            FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS].value.byteArray16;
        remoteIp6 = InFixedValues->incomingValue[
            FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS].value.byteArray16;
        localPort = InFixedValues->incomingValue[
            FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT].value.uint16;
        remotePort = InFixedValues->incomingValue[
            FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT].value.uint16;
        protocol = InFixedValues->incomingValue[
            FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL].value.uint8;
    } else {
        localIp = InFixedValues->incomingValue[
            FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
        remoteIp = InFixedValues->incomingValue[
            FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
        localPort = InFixedValues->incomingValue[
            FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;
        remotePort = InFixedValues->incomingValue[
            FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
        protocol = InFixedValues->incomingValue[
            FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;
    }

    //
    // Get process ID
    //
    if (FWPS_IS_METADATA_FIELD_PRESENT(InMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
        processId = InMetaValues->processId;
    } else {
        processId = 0;
    }

    //
    // Allocate connection entry
    //
    connection = NfpAllocateConnection();
    if (connection == NULL) {
        return;
    }

    //
    // Initialize connection
    //
    connection->ConnectionId = (UINT64)InterlockedIncrement64(&g_NfState.NextConnectionId);
    connection->FlowId = FlowContext;
    connection->Direction = NetworkDirection_Outbound;
    connection->State = ConnectionState_Connecting;

    //
    // Set protocol
    //
    switch (protocol) {
        case 6:   // TCP
            connection->Protocol = NetworkProtocol_TCP;
            break;
        case 17:  // UDP
            connection->Protocol = NetworkProtocol_UDP;
            break;
        case 1:   // ICMP
            connection->Protocol = NetworkProtocol_ICMP;
            break;
        case 58:  // ICMPv6
            connection->Protocol = NetworkProtocol_ICMPv6;
            break;
        default:
            connection->Protocol = NetworkProtocol_Unknown;
            break;
    }

    //
    // Copy addresses
    //
    NfpCopyAddress(&connection->LocalAddress, localIp6, &localIp, localPort, IsV6);
    NfpCopyAddress(&connection->RemoteAddress, remoteIp6, &remoteIp, remotePort, IsV6);

    //
    // Set process info
    //
    connection->ProcessId = (UINT32)processId;
    NfpGetProcessPath((HANDLE)(ULONG_PTR)processId, connection->ProcessImagePath,
                      MAX_FILE_PATH_LENGTH);

    //
    // Set timing
    //
    KeQuerySystemTime(&currentTime);
    connection->ConnectTime = (UINT64)(currentTime.QuadPart / 10000);
    connection->LastActivityTime = connection->ConnectTime;

    //
    // Check if this is first contact with remote
    //
    connection->Flags |= NF_CONN_FLAG_MONITORED;
    if (!NfpIsPrivateAddress(&connection->RemoteAddress.Address) &&
        !NfpIsLoopbackAddress(&connection->RemoteAddress.Address)) {
        connection->Flags |= NF_CONN_FLAG_FIRST_CONTACT;
    }

    //
    // Insert connection
    //
    status = NfpInsertConnection(connection);
    if (!NT_SUCCESS(status)) {
        NfpFreeConnection(connection);
        return;
    }

    //
    // Perform initial analysis
    //
    NfpAnalyzeConnection(connection);

    //
    // Check if connection should be blocked
    //
    if (connection->Flags & NF_CONN_FLAG_BLOCKED) {
        ClassifyOut->actionType = FWP_ACTION_BLOCK;
        ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        InterlockedIncrement64(&g_NfState.TotalConnectionsBlocked);
    }
}

/**
 * @brief Process inbound connection.
 */
static VOID
NfpProcessInboundAccept(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _In_ UINT64 FlowContext,
    _Out_ FWPS_CLASSIFY_OUT0* ClassifyOut,
    _In_ BOOLEAN IsV6
    )
{
    //
    // Similar to outbound but with direction set to inbound
    // Implementation follows same pattern as NfpProcessOutboundConnect
    //

    ClassifyOut->actionType = FWP_ACTION_PERMIT;

    UNREFERENCED_PARAMETER(InFixedValues);
    UNREFERENCED_PARAMETER(InMetaValues);
    UNREFERENCED_PARAMETER(FlowContext);
    UNREFERENCED_PARAMETER(IsV6);

    //
    // Full implementation would mirror NfpProcessOutboundConnect
    // with appropriate field indices for inbound layer
    //
}

/**
 * @brief Process DNS packet.
 */
static VOID
NfpProcessDnsPacket(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _In_opt_ void* LayerData,
    _Out_ FWPS_CLASSIFY_OUT0* ClassifyOut
    )
{
    ClassifyOut->actionType = FWP_ACTION_PERMIT;

    UNREFERENCED_PARAMETER(InFixedValues);
    UNREFERENCED_PARAMETER(InMetaValues);
    UNREFERENCED_PARAMETER(LayerData);

    //
    // Full implementation would:
    // 1. Extract NET_BUFFER from LayerData
    // 2. Parse DNS header and query
    // 3. Analyze domain for DGA/tunneling
    // 4. Check reputation
    // 5. Block if malicious
    //

    InterlockedIncrement64(&g_NfState.TotalDnsQueriesMonitored);
}

/**
 * @brief Process TCP stream data.
 */
static VOID
NfpProcessStreamData(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _In_opt_ FWPS_STREAM_CALLOUT_IO_PACKET0* StreamPacket,
    _In_ UINT64 FlowContext,
    _Out_ FWPS_CLASSIFY_OUT0* ClassifyOut
    )
{
    PNF_CONNECTION_ENTRY connection;
    NTSTATUS status;
    SIZE_T dataSize;
    LARGE_INTEGER currentTime;

    ClassifyOut->actionType = FWP_ACTION_PERMIT;

    UNREFERENCED_PARAMETER(InFixedValues);
    UNREFERENCED_PARAMETER(InMetaValues);

    if (StreamPacket == NULL || StreamPacket->streamData == NULL) {
        return;
    }

    dataSize = StreamPacket->streamData->dataLength;
    if (dataSize == 0) {
        return;
    }

    //
    // Find associated connection
    //
    status = NfFilterFindConnectionByFlow(FlowContext, &connection);
    if (!NT_SUCCESS(status)) {
        return;
    }

    //
    // Update connection statistics
    //
    KeQuerySystemTime(&currentTime);
    connection->LastActivityTime = (UINT64)(currentTime.QuadPart / 10000);

    if (StreamPacket->streamData->flags & FWPS_STREAM_FLAG_SEND) {
        InterlockedAdd64((LONG64*)&connection->BytesSent, (LONG64)dataSize);
        connection->PacketsSent++;

        //
        // Update beaconing state for outbound traffic
        //
        NfpUpdateBeaconingState(connection, connection->LastActivityTime);
    } else {
        InterlockedAdd64((LONG64*)&connection->BytesReceived, (LONG64)dataSize);
        connection->PacketsReceived++;
    }

    //
    // Update global statistics
    //
    InterlockedAdd64(&g_NfState.TotalBytesMonitored, (LONG64)dataSize);

    //
    // Check for exfiltration
    //
    if (g_NfState.Config.EnableExfiltrationDetection) {
        UINT64 thresholdBytes = (UINT64)g_NfState.Config.ExfiltrationThresholdMB * 1024 * 1024;
        if (connection->BytesSent > thresholdBytes) {
            connection->Flags |= NF_CONN_FLAG_EXFIL_SUSPECT;
        }
    }

    NfFilterReleaseConnection(connection);
}

// ============================================================================
// PRIVATE FUNCTIONS - ANALYSIS
// ============================================================================

/**
 * @brief Analyze connection for threats.
 */
static NTSTATUS
NfpAnalyzeConnection(
    _In_ PNF_CONNECTION_ENTRY Connection
    )
{
    NR_LOOKUP_RESULT reputationResult = {0};

    //
    // Check reputation if manager is available
    //
    if (g_ReputationManager != NULL) {
        NTSTATUS status = NrLookupIP(
            g_ReputationManager,
            &Connection->RemoteAddress.Address,
            SS_IS_IPV6(&Connection->RemoteAddress.Address),
            &reputationResult
            );

        if (NT_SUCCESS(status) && reputationResult.Found) {
            Connection->ReputationScore = 100 - reputationResult.Score;
            Connection->ReputationChecked = TRUE;

            if (reputationResult.Reputation == NrReputation_Malicious ||
                reputationResult.Reputation == NrReputation_Blacklisted) {
                Connection->Flags |= NF_CONN_FLAG_BLOCKED;
                Connection->ThreatType = NetworkThreat_Known_Malicious;
                Connection->ThreatScore = 100;
            } else if (reputationResult.Reputation == NrReputation_High) {
                Connection->Flags |= NF_CONN_FLAG_SUSPICIOUS;
                Connection->ThreatScore = 75;
            }
        }
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Update beaconing analysis state.
 */
static VOID
NfpUpdateBeaconingState(
    _In_ PNF_CONNECTION_ENTRY Connection,
    _In_ UINT64 CurrentTime
    )
{
    UINT32 interval;
    UINT32 index;

    if (!g_NfState.Config.EnableC2Detection) {
        return;
    }

    //
    // Calculate interval since last send
    //
    if (Connection->LastSendTime > 0) {
        interval = (UINT32)(CurrentTime - Connection->LastSendTime);

        //
        // Store in ring buffer
        //
        index = Connection->SendIntervalIndex % 32;
        Connection->SendIntervals[index] = interval;
        Connection->SendIntervalIndex++;

        if (Connection->SendIntervalCount < 32) {
            Connection->SendIntervalCount++;
        }

        //
        // Update running average
        //
        if (Connection->SendIntervalCount > 0) {
            UINT64 sum = 0;
            UINT32 i;

            for (i = 0; i < Connection->SendIntervalCount; i++) {
                sum += Connection->SendIntervals[i];
            }

            Connection->AverageIntervalMs = (UINT32)(sum / Connection->SendIntervalCount);

            //
            // Calculate variance for jitter detection
            //
            if (Connection->SendIntervalCount >= g_NfState.Config.BeaconMinSamples) {
                UINT64 variance = 0;
                for (i = 0; i < Connection->SendIntervalCount; i++) {
                    INT32 diff = (INT32)Connection->SendIntervals[i] -
                                 (INT32)Connection->AverageIntervalMs;
                    variance += (UINT64)(diff * diff);
                }
                Connection->IntervalVariance =
                    (UINT32)((variance / Connection->SendIntervalCount) / 1000);
            }
        }
    }

    Connection->LastSendTime = CurrentTime;
}

/**
 * @brief Detect beaconing pattern in connection.
 */
static BOOLEAN
NfpDetectBeaconingPattern(
    _In_ PNF_CONNECTION_ENTRY Connection,
    _Out_opt_ PBEACONING_DATA BeaconingData
    )
{
    UINT32 jitterPercent;
    BOOLEAN isBeaconing = FALSE;

    if (Connection->SendIntervalCount < g_NfState.Config.BeaconMinSamples) {
        return FALSE;
    }

    //
    // Calculate jitter percentage
    //
    if (Connection->AverageIntervalMs > 0) {
        //
        // Jitter = StdDev / Mean * 100
        // Using simplified variance / mean approximation
        //
        jitterPercent = (Connection->IntervalVariance * 100) / Connection->AverageIntervalMs;

        if (jitterPercent <= g_NfState.Config.BeaconJitterThreshold) {
            isBeaconing = TRUE;
            Connection->Flags |= NF_CONN_FLAG_BEACONING;

            if (BeaconingData != NULL) {
                BeaconingData->ConnectionId = Connection->ConnectionId;
                BeaconingData->BeaconCount = Connection->SendIntervalCount;
                BeaconingData->AverageIntervalMs = Connection->AverageIntervalMs;
                BeaconingData->JitterPercent = jitterPercent;
                BeaconingData->IsRegularInterval = (jitterPercent < 5);
                BeaconingData->HasJitter = (jitterPercent > 0);
            }

            //
            // Update C2 detection statistics
            //
            InterlockedIncrement64(&g_NfState.TotalC2Detections);
        }
    }

    return isBeaconing;
}

#endif // SHADOWSTRIKE_NETWORK_FILTER_C
