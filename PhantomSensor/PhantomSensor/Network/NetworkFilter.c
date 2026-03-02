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
 * ShadowStrike NGAV - ENTERPRISE WFP NETWORK FILTER IMPLEMENTATION
 * ============================================================================
 *
 * @file NetworkFilter.c
 * @brief Enterprise-grade Windows Filtering Platform (WFP) network monitoring.
 *
 * Implements WFP-based network filtering:
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
 *
 * WFP Layer Coverage:
 * - FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6: Outbound connection authorization
 * - FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6: Inbound connection authorization
 * - FWPM_LAYER_OUTBOUND_TRANSPORT_V4: DNS query interception
 * - FWPM_LAYER_STREAM_V4: TCP stream data inspection
 *
 * Synchronization Model:
 * - EX_PUSH_LOCK for all data structure locks (safe at DISPATCH_LEVEL)
 * - Interlocked operations for all shared mutable fields
 * - DPC -> IoWorkItem for cleanup (PASSIVE_LEVEL requirement)
 * - Single-lock insertion for connection tables (atomic visibility)
 *
 * @author ShadowStrike Security Team
 * @version 2.1.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include <initguid.h>
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
// GUID DEFINITIONS (INITGUID included above, so DEFINE_GUID emits storage)
// ============================================================================

// {A5E8F2D1-3B4C-4D5E-9F6A-7B8C9D0E1F2A}
DEFINE_GUID(SHADOWSTRIKE_WFP_PROVIDER_GUID,
    0xa5e8f2d1, 0x3b4c, 0x4d5e, 0x9f, 0x6a, 0x7b, 0x8c, 0x9d, 0x0e, 0x1f, 0x2a);

// {B6F9A3E2-4C5D-5E6F-A071-8C9D0E1F2A3B}
DEFINE_GUID(SHADOWSTRIKE_WFP_SUBLAYER_GUID,
    0xb6f9a3e2, 0x4c5d, 0x5e6f, 0xa0, 0x71, 0x8c, 0x9d, 0x0e, 0x1f, 0x2a, 0x3b);

// {C7A0B4F3-5D6E-6F70-B182-9D0E1F2A3B4C}
DEFINE_GUID(SHADOWSTRIKE_ALE_CONNECT_V4_CALLOUT_GUID,
    0xc7a0b4f3, 0x5d6e, 0x6f70, 0xb1, 0x82, 0x9d, 0x0e, 0x1f, 0x2a, 0x3b, 0x4c);

// {D8B1C5A4-6E7F-7081-C293-0E1F2A3B4C5D}
DEFINE_GUID(SHADOWSTRIKE_ALE_CONNECT_V6_CALLOUT_GUID,
    0xd8b1c5a4, 0x6e7f, 0x7081, 0xc2, 0x93, 0x0e, 0x1f, 0x2a, 0x3b, 0x4c, 0x5d);

// {E9C2D6B5-7F80-8192-D3A4-1F2A3B4C5D6E}
DEFINE_GUID(SHADOWSTRIKE_ALE_RECV_ACCEPT_V4_CALLOUT_GUID,
    0xe9c2d6b5, 0x7f80, 0x8192, 0xd3, 0xa4, 0x1f, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e);

// {F0D3E7C6-8091-92A3-E4B5-2A3B4C5D6E7F}
DEFINE_GUID(SHADOWSTRIKE_ALE_RECV_ACCEPT_V6_CALLOUT_GUID,
    0xf0d3e7c6, 0x8091, 0x92a3, 0xe4, 0xb5, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e, 0x7f);

// {01E4F8D7-91A2-A3B4-F5C6-3B4C5D6E7F80}
DEFINE_GUID(SHADOWSTRIKE_OUTBOUND_TRANSPORT_V4_CALLOUT_GUID,
    0x01e4f8d7, 0x91a2, 0xa3b4, 0xf5, 0xc6, 0x3b, 0x4c, 0x5d, 0x6e, 0x7f, 0x80);

// {12F5A9E8-02B3-B4C5-A6D7-4C5D6E7F8091}
DEFINE_GUID(SHADOWSTRIKE_STREAM_V4_CALLOUT_GUID,
    0x12f5a9e8, 0x02b3, 0xb4c5, 0xa6, 0xd7, 0x4c, 0x5d, 0x6e, 0x7f, 0x80, 0x91);

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define NF_MAX_CONNECTIONS              65536
#define NF_CONNECTION_HASH_BUCKETS      4096
#define NF_DNS_HASH_BUCKETS             2048
#define NF_CONNECTION_TIMEOUT_MS        300000      // 5 minutes
#define NF_DNS_ENTRY_TIMEOUT_MS         600000      // 10 minutes
#define NF_CLEANUP_INTERVAL_MS          30000       // 30 seconds
#define NF_MAX_EVENTS_PER_SECOND        10000
#define NF_RATE_LIMIT_LOG_INTERVAL_MS   60000       // 1 minute
#define NF_CONNECTION_LOOKASIDE_DEPTH   256
#define NF_DNS_LOOKASIDE_DEPTH          512
#define NF_EVENT_LOOKASIDE_DEPTH        1024
#define NF_DNS_PORT                     53
#define NF_MAX_PROCESS_PATH             512
#define NF_MAX_PENDING_DNS              8192
#define NF_DNS_HEADER_SIZE              12          // Minimum DNS header

// ============================================================================
// PRIVATE TYPES
// ============================================================================

typedef struct _NF_CONNECTION_HASH_ENTRY {
    LIST_ENTRY HashListEntry;
    PNF_CONNECTION_ENTRY Connection;
} NF_CONNECTION_HASH_ENTRY, *PNF_CONNECTION_HASH_ENTRY;

typedef struct _NF_DNS_HASH_ENTRY {
    LIST_ENTRY HashListEntry;
    PNF_DNS_ENTRY DnsEntry;
} NF_DNS_HASH_ENTRY, *PNF_DNS_HASH_ENTRY;

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

static NETWORK_FILTER_GLOBALS g_NfState = {0};

// Connection hash table (endpoint-based)
static LIST_ENTRY g_ConnectionHashTable[NF_CONNECTION_HASH_BUCKETS];

// Flow ID to connection hash table
static LIST_ENTRY g_FlowHashTable[NF_CONNECTION_HASH_BUCKETS];

// ConnectionId to connection hash table (for O(1) lookup by ID)
static LIST_ENTRY g_ConnIdHashTable[NF_CONNECTION_HASH_BUCKETS];

// Pending DNS queries
static LIST_ENTRY g_PendingDnsList;
static EX_PUSH_LOCK g_PendingDnsLock;
static volatile LONG g_PendingDnsCount;

// Cleanup timer and DPC
static KTIMER g_CleanupTimer;
static KDPC g_CleanupDpc;
static volatile LONG g_CleanupInProgress;

// Subsystem pointers (from other Network modules)
static PCT_TRACKER g_ConnectionTracker;
static PDNS_MONITOR g_DnsMonitor;
static PC2_DETECTOR g_C2Detector;
static PNR_MANAGER g_ReputationManager;

// Rate limiting state (all atomic)
static volatile LONG g_EventsThisSecond;
static volatile LONG64 g_CurrentSecondStart;
static volatile LONG64 g_LastRateLimitLogTime;
static volatile LONG64 g_TotalEventsDropped;
// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static NTSTATUS
NfpRegisterCallouts(_In_ PDEVICE_OBJECT DeviceObject);

static VOID
NfpUnregisterCallouts(VOID);

static NTSTATUS
NfpRegisterFilters(VOID);

static VOID
NfpUnregisterFilters(VOID);

static NTSTATUS
NfpInitializeHashTables(VOID);

static VOID
NfpCleanupHashTables(VOID);

static NTSTATUS
NfpInitializeLookasideLists(VOID);

static VOID
NfpCleanupLookasideLists(VOID);

static PNF_CONNECTION_ENTRY
NfpAllocateConnection(VOID);

static VOID
NfpFreeConnection(_In_ PNF_CONNECTION_ENTRY Connection);

static PNF_DNS_ENTRY
NfpAllocateDnsEntry(VOID);

static VOID
NfpFreeDnsEntry(_In_ PNF_DNS_ENTRY DnsEntry);

static UINT32
NfpHashEndpoints(
    _In_ PSS_SOCKET_ADDRESS Local,
    _In_ PSS_SOCKET_ADDRESS Remote,
    _In_ NETWORK_PROTOCOL Protocol);

static UINT32
NfpHashFlowId(_In_ UINT64 FlowId);

static UINT32
NfpHashConnectionId(_In_ UINT64 ConnectionId);

static UINT32
NfpHashDomainName(_In_ PCWSTR DomainName);

static NTSTATUS
NfpInsertConnection(_In_ PNF_CONNECTION_ENTRY Connection);

static VOID
NfpRemoveConnection(_In_ PNF_CONNECTION_ENTRY Connection);

static VOID
NfpCleanupTimerCallback(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2);

static VOID
NfpCleanupWorkItemRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context);

static VOID
NfpCleanupStaleConnections(VOID);

static VOID
NfpCleanupStaleDnsEntries(VOID);

static VOID
NfpCleanupStalePendingDns(VOID);

static BOOLEAN
NfpCheckRateLimit(VOID);

static VOID
NfpGetProcessPath(
    _In_ HANDLE ProcessId,
    _Out_writes_(MaxLength) PWCHAR ProcessPath,
    _In_ ULONG MaxLength);

static VOID
NfpCopyAddress(
    _Out_ PSS_SOCKET_ADDRESS Dest,
    _In_opt_ const FWP_BYTE_ARRAY16* IpV6,
    _In_opt_ const UINT32* IpV4,
    _In_ UINT16 Port,
    _In_ BOOLEAN IsV6);

static BOOLEAN
NfpIsPrivateAddress(_In_ PSS_IP_ADDRESS Address);

static BOOLEAN
NfpIsLoopbackAddress(_In_ PSS_IP_ADDRESS Address);

static VOID
NfpProcessOutboundConnect(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _In_ UINT64 FlowContext,
    _Out_ FWPS_CLASSIFY_OUT0* ClassifyOut,
    _In_ BOOLEAN IsV6);

static VOID
NfpProcessInboundAccept(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _In_ UINT64 FlowContext,
    _Out_ FWPS_CLASSIFY_OUT0* ClassifyOut,
    _In_ BOOLEAN IsV6);

static VOID
NfpProcessDnsPacket(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _In_opt_ void* LayerData,
    _Out_ FWPS_CLASSIFY_OUT0* ClassifyOut);

static VOID
NfpProcessStreamData(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _In_opt_ FWPS_STREAM_CALLOUT_IO_PACKET0* StreamPacket,
    _In_ UINT64 FlowContext,
    _Out_ FWPS_CLASSIFY_OUT0* ClassifyOut);

static NTSTATUS
NfpAnalyzeConnection(_In_ PNF_CONNECTION_ENTRY Connection);

static VOID
NfpUpdateBeaconingState(
    _In_ PNF_CONNECTION_ENTRY Connection,
    _In_ UINT64 CurrentTime);

static BOOLEAN
NfpDetectBeaconingPattern(
    _In_ PNF_CONNECTION_ENTRY Connection,
    _Out_opt_ PBEACONING_DATA BeaconingData);

static BOOLEAN
NfpIsDomainBlocked(_In_ PCWSTR DomainName);

static VOID
NfpParseDnsQueryName(
    _In_reads_bytes_(DataLength) const UCHAR* DnsData,
    _In_ ULONG DataLength,
    _Out_writes_(MaxNameLength) PWCHAR QueryName,
    _In_ ULONG MaxNameLength);

// Inline helpers for atomic init/enabled state checks
#define NfpIsInitialized() \
    (InterlockedCompareExchange(&g_NfState.InitState, 0, 0) == NF_INIT_STATE_INITIALIZED)

#define NfpIsEnabled() \
    (InterlockedCompareExchange(&g_NfState.Enabled, 0, 0) != 0)

// Safe config read (copies under lock)
static __forceinline VOID
NfpReadConfig(_Out_ PNETWORK_MONITOR_CONFIG ConfigOut)
{
    FltAcquirePushLockShared(&g_NfState.ConfigLock);
    RtlCopyMemory(ConfigOut, &g_NfState.Config, sizeof(NETWORK_MONITOR_CONFIG));
    FltReleasePushLock(&g_NfState.ConfigLock);
}

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the network filtering subsystem.
 *
 * Uses atomic init state to prevent double-initialization races.
 * All WFP registration is done in a single transaction.
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

    if (DeviceObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Atomic double-init guard: only one thread can transition 0->1
    //
    if (InterlockedCompareExchange(&g_NfState.InitState,
                                    NF_INIT_STATE_INITIALIZING,
                                    NF_INIT_STATE_UNINITIALIZED)
            != NF_INIT_STATE_UNINITIALIZED) {
        return STATUS_ALREADY_INITIALIZED;
    }

    RtlZeroMemory(&g_NfState, sizeof(NETWORK_FILTER_GLOBALS));
    g_NfState.InitState = NF_INIT_STATE_INITIALIZING;
    g_NfState.WfpDeviceObject = DeviceObject;

    //
    // Initialize locks
    //
    ExInitializePushLock(&g_NfState.ConnectionLock);
    ExInitializePushLock(&g_NfState.DnsLock);
    ExInitializePushLock(&g_NfState.ConfigLock);
    ExInitializePushLock(&g_PendingDnsLock);

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
    // Initialize lists
    //
    InitializeListHead(&g_NfState.ConnectionList);
    g_NfState.ConnectionCount = 0;

    InitializeListHead(&g_NfState.DnsQueryList);
    g_NfState.DnsQueryCount = 0;

    InitializeListHead(&g_NfState.DnsTunnelStateList);
    g_NfState.DnsTunnelStateCount = 0;

    InitializeListHead(&g_NfState.BlockedDomainList);
    g_NfState.BlockedDomainCount = 0;

    InitializeListHead(&g_PendingDnsList);
    g_PendingDnsCount = 0;

    //
    // Open WFP engine — use DYNAMIC session so objects are auto-cleaned on close
    //
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    session.displayData.name = L"ShadowStrike Network Monitor";
    session.displayData.description = L"Enterprise WFP-based network filtering";

    status = FwpmEngineOpen0(
        NULL,
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
    // Register provider — NOT persistent (dynamic session cleans up)
    //
    provider.providerKey = SHADOWSTRIKE_WFP_PROVIDER_GUID;
    provider.displayData.name = L"ShadowStrike NGAV Provider";
    provider.displayData.description = L"Network monitoring for threat detection";
    provider.flags = 0;

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
    sublayer.weight = 0xFFFF;
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
    // Allocate cleanup work item (must be done before starting timer)
    //
    g_NfState.CleanupWorkItem = IoAllocateWorkItem(DeviceObject);
    if (g_NfState.CleanupWorkItem == NULL) {
        NfpUnregisterFilters();
        NfpUnregisterCallouts();
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto CleanupEngine;
    }

    //
    // Initialize and start cleanup timer
    //
    KeInitializeTimer(&g_CleanupTimer);
    KeInitializeDpc(&g_CleanupDpc, NfpCleanupTimerCallback, NULL);
    g_CleanupInProgress = 0;

    dueTime.QuadPart = -((LONGLONG)NF_CLEANUP_INTERVAL_MS * 10000);
    KeSetTimerEx(
        &g_CleanupTimer,
        dueTime,
        NF_CLEANUP_INTERVAL_MS,
        &g_CleanupDpc
        );

    //
    // Initialize default configuration under lock
    //
    FltAcquirePushLockExclusive(&g_NfState.ConfigLock);
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
    FltReleasePushLock(&g_NfState.ConfigLock);

    //
    // Initialize rate limiting
    //
    InterlockedExchange(&g_EventsThisSecond, 0);
    InterlockedExchange64(&g_CurrentSecondStart, 0);
    InterlockedExchange64(&g_LastRateLimitLogTime, 0);
    InterlockedExchange64(&g_TotalEventsDropped, 0);

    //
    // Mark as initialized and enabled (atomic)
    //
    InterlockedExchange(&g_NfState.Enabled, 1);
    InterlockedExchange(&g_NfState.InitState, NF_INIT_STATE_INITIALIZED);

    return STATUS_SUCCESS;

CleanupEngine:
    FwpmEngineClose0(g_NfState.WfpEngineHandle);
    g_NfState.WfpEngineHandle = NULL;

CleanupLists:
    NfpCleanupLookasideLists();
    NfpCleanupHashTables();

Cleanup:
    InterlockedExchange(&g_NfState.InitState, NF_INIT_STATE_UNINITIALIZED);
    return status;
}

/**
 * @brief Shutdown the network filtering subsystem.
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
    PNF_DNS_TUNNEL_STATE tunnelState;
    PNF_BLOCKED_DOMAIN blockedDomain;
    LARGE_INTEGER timeout;

    PAGED_CODE();

    if (!NfpIsInitialized()) {
        return;
    }

    //
    // Disable first to stop new operations (atomic)
    //
    InterlockedExchange(&g_NfState.Enabled, 0);

    //
    // Cancel and wait for cleanup timer
    //
    KeCancelTimer(&g_CleanupTimer);
    KeFlushQueuedDpcs();

    //
    // Wait for any in-progress cleanup work item to complete
    //
    timeout.QuadPart = -10000000LL;  // 1 second
    while (InterlockedCompareExchange(&g_CleanupInProgress, 0, 0) != 0) {
        KeDelayExecutionThread(KernelMode, FALSE, &timeout);
    }

    //
    // Free cleanup work item
    //
    if (g_NfState.CleanupWorkItem != NULL) {
        IoFreeWorkItem(g_NfState.CleanupWorkItem);
        g_NfState.CleanupWorkItem = NULL;
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
    // Free all connections (with proper hash table cleanup)
    //
    FltAcquirePushLockExclusive(&g_NfState.ConnectionLock);

    while (!IsListEmpty(&g_NfState.ConnectionList)) {
        entry = RemoveHeadList(&g_NfState.ConnectionList);
        connection = CONTAINING_RECORD(entry, NF_CONNECTION_ENTRY, ListEntry);
        InterlockedDecrement(&g_NfState.ConnectionCount);

        //
        // Remove from hash tables (we hold ConnectionLock exclusively,
        // which is the single lock protecting all tables now)
        //
        {
            UINT32 hashIdx;
            PLIST_ENTRY hashEntry;
            PNF_CONNECTION_HASH_ENTRY hEntry;

            // Remove from endpoint hash
            hashIdx = NfpHashEndpoints(&connection->LocalAddress,
                                       &connection->RemoteAddress,
                                       connection->Protocol);
            for (hashEntry = g_ConnectionHashTable[hashIdx].Flink;
                 hashEntry != &g_ConnectionHashTable[hashIdx];
                 hashEntry = hashEntry->Flink) {
                hEntry = CONTAINING_RECORD(hashEntry, NF_CONNECTION_HASH_ENTRY, HashListEntry);
                if (hEntry->Connection == connection) {
                    RemoveEntryList(&hEntry->HashListEntry);
                    ExFreePoolWithTag(hEntry, NF_POOL_TAG_CONNECTION);
                    break;
                }
            }

            // Remove from flow hash
            hashIdx = NfpHashFlowId(connection->FlowId);
            for (hashEntry = g_FlowHashTable[hashIdx].Flink;
                 hashEntry != &g_FlowHashTable[hashIdx];
                 hashEntry = hashEntry->Flink) {
                hEntry = CONTAINING_RECORD(hashEntry, NF_CONNECTION_HASH_ENTRY, HashListEntry);
                if (hEntry->Connection == connection) {
                    RemoveEntryList(&hEntry->HashListEntry);
                    ExFreePoolWithTag(hEntry, NF_POOL_TAG_CONNECTION);
                    break;
                }
            }

            // Remove from connId hash
            hashIdx = NfpHashConnectionId(connection->ConnectionId);
            for (hashEntry = g_ConnIdHashTable[hashIdx].Flink;
                 hashEntry != &g_ConnIdHashTable[hashIdx];
                 hashEntry = hashEntry->Flink) {
                hEntry = CONTAINING_RECORD(hashEntry, NF_CONNECTION_HASH_ENTRY, HashListEntry);
                if (hEntry->Connection == connection) {
                    RemoveEntryList(&hEntry->HashListEntry);
                    ExFreePoolWithTag(hEntry, NF_POOL_TAG_CONNECTION);
                    break;
                }
            }
        }

        NfpFreeConnection(connection);
    }

    FltReleasePushLock(&g_NfState.ConnectionLock);

    //
    // Free all DNS entries
    //
    FltAcquirePushLockExclusive(&g_NfState.DnsLock);

    while (!IsListEmpty(&g_NfState.DnsQueryList)) {
        entry = RemoveHeadList(&g_NfState.DnsQueryList);
        dnsEntry = CONTAINING_RECORD(entry, NF_DNS_ENTRY, ListEntry);
        NfpFreeDnsEntry(dnsEntry);
    }
    g_NfState.DnsQueryCount = 0;

    while (!IsListEmpty(&g_NfState.DnsTunnelStateList)) {
        entry = RemoveHeadList(&g_NfState.DnsTunnelStateList);
        tunnelState = CONTAINING_RECORD(entry, NF_DNS_TUNNEL_STATE, ListEntry);
        ExFreePoolWithTag(tunnelState, NF_POOL_TAG_DNS);
    }
    g_NfState.DnsTunnelStateCount = 0;

    while (!IsListEmpty(&g_NfState.BlockedDomainList)) {
        entry = RemoveHeadList(&g_NfState.BlockedDomainList);
        blockedDomain = CONTAINING_RECORD(entry, NF_BLOCKED_DOMAIN, ListEntry);
        ExFreePoolWithTag(blockedDomain, NF_POOL_TAG_DNS);
    }
    g_NfState.BlockedDomainCount = 0;

    FltReleasePushLock(&g_NfState.DnsLock);

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
    // Cleanup lookaside lists and hash tables
    //
    NfpCleanupLookasideLists();
    NfpCleanupHashTables();

    //
    // Mark as uninitialized
    //
    InterlockedExchange(&g_NfState.InitState, NF_INIT_STATE_UNINITIALIZED);
}

/**
 * @brief Enable or disable network filtering (atomic).
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
NfFilterSetEnabled(
    _In_ BOOLEAN Enable
    )
{
    if (!NfpIsInitialized()) {
        return STATUS_DEVICE_NOT_READY;
    }

    InterlockedExchange(&g_NfState.Enabled, Enable ? 1 : 0);
    return STATUS_SUCCESS;
}

/**
 * @brief Update network filter configuration (under lock).
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
NfFilterUpdateConfig(
    _In_ PNETWORK_MONITOR_CONFIG Config
    )
{
    PAGED_CODE();

    if (!NfpIsInitialized()) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (Config == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Config->BeaconMinSamples < 5 || Config->BeaconMinSamples > 1000) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Config->BeaconJitterThreshold > 100) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Config->MaxEventsPerSecond == 0 || Config->MaxEventsPerSecond > 100000) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Copy configuration atomically under lock
    //
    FltAcquirePushLockExclusive(&g_NfState.ConfigLock);
    RtlCopyMemory(&g_NfState.Config, Config, sizeof(NETWORK_MONITOR_CONFIG));
    FltReleasePushLock(&g_NfState.ConfigLock);

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - CONNECTION MANAGEMENT
// ============================================================================

/**
 * @brief Find connection by ID using O(1) hash table lookup.
 *
 * Acquires a shared push lock, increments reference count before returning.
 * Caller MUST call NfFilterReleaseConnection when done.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
NfFilterFindConnection(
    _In_ UINT64 ConnectionId,
    _Out_ PNF_CONNECTION_ENTRY* Connection
    )
{
    UINT32 hashIndex;
    PLIST_ENTRY entry;
    PNF_CONNECTION_HASH_ENTRY hashEntry;
    PNF_CONNECTION_ENTRY current;
    NTSTATUS status = STATUS_NOT_FOUND;

    if (Connection == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Connection = NULL;

    if (!NfpIsInitialized() || !NfpIsEnabled()) {
        return STATUS_DEVICE_NOT_READY;
    }

    hashIndex = NfpHashConnectionId(ConnectionId);

    FltAcquirePushLockShared(&g_NfState.ConnectionLock);

    for (entry = g_ConnIdHashTable[hashIndex].Flink;
         entry != &g_ConnIdHashTable[hashIndex];
         entry = entry->Flink) {

        hashEntry = CONTAINING_RECORD(entry, NF_CONNECTION_HASH_ENTRY, HashListEntry);
        current = hashEntry->Connection;

        if (current->ConnectionId == ConnectionId) {
            InterlockedIncrement(&current->RefCount);
            *Connection = current;
            status = STATUS_SUCCESS;
            break;
        }
    }

    FltReleasePushLock(&g_NfState.ConnectionLock);
    return status;
}

/**
 * @brief Find connection by WFP flow ID using hash table.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
NfFilterFindConnectionByFlow(
    _In_ UINT64 FlowId,
    _Out_ PNF_CONNECTION_ENTRY* Connection
    )
{
    UINT32 hashIndex;
    PLIST_ENTRY entry;
    PNF_CONNECTION_HASH_ENTRY hashEntry;
    PNF_CONNECTION_ENTRY current;
    NTSTATUS status = STATUS_NOT_FOUND;

    if (Connection == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Connection = NULL;

    if (!NfpIsInitialized() || !NfpIsEnabled()) {
        return STATUS_DEVICE_NOT_READY;
    }

    hashIndex = NfpHashFlowId(FlowId);

    FltAcquirePushLockShared(&g_NfState.ConnectionLock);

    for (entry = g_FlowHashTable[hashIndex].Flink;
         entry != &g_FlowHashTable[hashIndex];
         entry = entry->Flink) {

        hashEntry = CONTAINING_RECORD(entry, NF_CONNECTION_HASH_ENTRY, HashListEntry);
        current = hashEntry->Connection;

        if (current->FlowId == FlowId) {
            InterlockedIncrement(&current->RefCount);
            *Connection = current;
            status = STATUS_SUCCESS;
            break;
        }
    }

    FltReleasePushLock(&g_NfState.ConnectionLock);
    return status;
}

/**
 * @brief Release connection reference with underflow detection.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
NfFilterReleaseConnection(
    _In_ PNF_CONNECTION_ENTRY Connection
    )
{
    LONG refCount;

    if (Connection == NULL) {
        return;
    }

    refCount = InterlockedDecrement(&Connection->RefCount);

    NT_ASSERT(refCount >= 0);

    if (refCount < 0) {
        //
        // RefCount underflow — serious bug. Clamp to 0 and log.
        // Do not free here; cleanup timer handles final free.
        //
        InterlockedIncrement(&Connection->RefCount);
    }
}

/**
 * @brief Block a connection.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
NfFilterBlockConnection(
    _In_ UINT64 ConnectionId,
    _In_ NETWORK_BLOCK_REASON Reason
    )
{
    PNF_CONNECTION_ENTRY connection;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Reason);

    status = NfFilterFindConnection(ConnectionId, &connection);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    InterlockedExchange((LONG*)&connection->State, (LONG)ConnectionState_Blocked);
    InterlockedOr((LONG*)&connection->Flags, NF_CONN_FLAG_BLOCKED);

    InterlockedIncrement64(&g_NfState.TotalConnectionsBlocked);

    NfFilterReleaseConnection(connection);
    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - DNS
// ============================================================================

/**
 * @brief Query DNS cache for domain.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
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

    if (!NfpIsInitialized() || !NfpIsEnabled()) {
        return STATUS_DEVICE_NOT_READY;
    }

    hashValue = NfpHashDomainName(DomainName);

    FltAcquirePushLockShared(&g_NfState.DnsLock);

    for (entry = g_NfState.DnsQueryList.Flink;
         entry != &g_NfState.DnsQueryList;
         entry = entry->Flink) {

        current = CONTAINING_RECORD(entry, NF_DNS_ENTRY, ListEntry);

        if (current->QueryNameHash == hashValue) {
            if (_wcsicmp(current->QueryName, DomainName) == 0) {
                RtlCopyMemory(Entry, current, sizeof(NF_DNS_ENTRY));
                status = STATUS_SUCCESS;
                break;
            }
        }
    }

    FltReleasePushLock(&g_NfState.DnsLock);
    return status;
}

/**
 * @brief Block DNS queries to domain.
 *
 * Adds the domain to the blocked domain list. Checked during DNS processing.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
NfFilterBlockDomain(
    _In_ PCWSTR DomainName,
    _In_ NETWORK_BLOCK_REASON Reason
    )
{
    PNF_BLOCKED_DOMAIN blockedEntry;
    UINT32 domainHash;
    PLIST_ENTRY entry;
    PNF_BLOCKED_DOMAIN existing;

    if (DomainName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!NfpIsInitialized()) {
        return STATUS_DEVICE_NOT_READY;
    }

    domainHash = NfpHashDomainName(DomainName);

    //
    // Check if already blocked
    //
    FltAcquirePushLockShared(&g_NfState.DnsLock);

    for (entry = g_NfState.BlockedDomainList.Flink;
         entry != &g_NfState.BlockedDomainList;
         entry = entry->Flink) {

        existing = CONTAINING_RECORD(entry, NF_BLOCKED_DOMAIN, ListEntry);
        if (existing->DomainHash == domainHash &&
            _wcsicmp(existing->DomainName, DomainName) == 0) {
            FltReleasePushLock(&g_NfState.DnsLock);
            return STATUS_SUCCESS;
        }
    }

    FltReleasePushLock(&g_NfState.DnsLock);

    //
    // Check limit
    //
    if ((ULONG)InterlockedCompareExchange(&g_NfState.BlockedDomainCount, 0, 0)
            >= NF_MAX_BLOCKED_DOMAINS) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Allocate and insert
    //
    blockedEntry = (PNF_BLOCKED_DOMAIN)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(NF_BLOCKED_DOMAIN),
        NF_POOL_TAG_DNS
        );

    if (blockedEntry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(blockedEntry, sizeof(NF_BLOCKED_DOMAIN));
    blockedEntry->DomainHash = domainHash;
    blockedEntry->Reason = Reason;

    RtlStringCchCopyW(blockedEntry->DomainName, MAX_DNS_NAME_LENGTH, DomainName);

    FltAcquirePushLockExclusive(&g_NfState.DnsLock);
    InsertTailList(&g_NfState.BlockedDomainList, &blockedEntry->ListEntry);
    InterlockedIncrement(&g_NfState.BlockedDomainCount);
    FltReleasePushLock(&g_NfState.DnsLock);

    return STATUS_SUCCESS;
}

/**
 * @brief Check if a domain is on the blocked list.
 */
static BOOLEAN
NfpIsDomainBlocked(
    _In_ PCWSTR DomainName
    )
{
    UINT32 domainHash;
    PLIST_ENTRY entry;
    PNF_BLOCKED_DOMAIN blocked;
    BOOLEAN isBlocked = FALSE;

    if (DomainName == NULL) {
        return FALSE;
    }

    domainHash = NfpHashDomainName(DomainName);

    FltAcquirePushLockShared(&g_NfState.DnsLock);

    for (entry = g_NfState.BlockedDomainList.Flink;
         entry != &g_NfState.BlockedDomainList;
         entry = entry->Flink) {

        blocked = CONTAINING_RECORD(entry, NF_BLOCKED_DOMAIN, ListEntry);
        if (blocked->DomainHash == domainHash &&
            _wcsicmp(blocked->DomainName, DomainName) == 0) {
            isBlocked = TRUE;
            break;
        }
    }

    FltReleasePushLock(&g_NfState.DnsLock);
    return isBlocked;
}

// ============================================================================
// PUBLIC API - DETECTION
// ============================================================================

/**
 * @brief Check if connection exhibits C2 beaconing.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
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
_IRQL_requires_max_(DISPATCH_LEVEL)
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
    NETWORK_MONITOR_CONFIG config;

    if (BaseDomain == NULL) {
        return FALSE;
    }

    if (!NfpIsInitialized()) {
        return FALSE;
    }

    NfpReadConfig(&config);
    if (!config.EnableDnsTunnelingDetection) {
        return FALSE;
    }

    domainHash = NfpHashDomainName(BaseDomain);

    FltAcquirePushLockShared(&g_NfState.DnsLock);

    for (entry = g_NfState.DnsTunnelStateList.Flink;
         entry != &g_NfState.DnsTunnelStateList;
         entry = entry->Flink) {

        state = CONTAINING_RECORD(entry, NF_DNS_TUNNEL_STATE, ListEntry);

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

    FltReleasePushLock(&g_NfState.DnsLock);
    return found;
}

/**
 * @brief Analyze connection for data exfiltration.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
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
    NETWORK_MONITOR_CONFIG config;

    status = NfFilterFindConnection(ConnectionId, &connection);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    NfpReadConfig(&config);
    if (!config.EnableExfiltrationDetection) {
        NfFilterReleaseConnection(connection);
        return FALSE;
    }

    thresholdBytes = (UINT64)config.ExfiltrationThresholdMB * 1024ULL * 1024ULL;

    if (connection->BytesSent > thresholdBytes) {
        if (connection->BytesReceived > 0) {
            UINT64 ratio = (connection->BytesSent * 100ULL) / connection->BytesReceived;

            if (ratio > 500) {
                isExfiltration = TRUE;
                InterlockedOr((LONG*)&connection->Flags, NF_CONN_FLAG_EXFIL_SUSPECT);

                if (Event != NULL) {
                    RtlZeroMemory(Event, sizeof(NETWORK_EXFIL_EVENT));
                    Event->Header.EventType = NetworkEvent_DataExfiltration;
                    Event->ConnectionId = connection->ConnectionId;
                    Event->TotalBytesSent = connection->BytesSent;
                    Event->TotalBytesReceived = connection->BytesReceived;
                    Event->UploadDownloadRatio = (UINT32)min(ratio, MAXUINT32);

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
 *
 * Parses the hex-encoded JA3 string to raw bytes and queries the C2 detector.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
NfFilterIsKnownMaliciousJA3(
    _In_ PCSTR JA3Fingerprint
    )
{
    BOOLEAN isKnown = FALSE;

    if (JA3Fingerprint == NULL) {
        return FALSE;
    }

    if (g_C2Detector == NULL) {
        return FALSE;
    }

    {
        UCHAR ja3Hash[16];
        ULONG i;
        SIZE_T len = 0;
        NTSTATUS status;
        CHAR malwareFamily[64] = {0};

        //
        // Parse 32-char hex MD5 string to 16 raw bytes
        //
        while (JA3Fingerprint[len] != '\0' && len < 33) {
            len++;
        }

        if (len != 32) {
            return FALSE;
        }

        for (i = 0; i < 16; i++) {
            UCHAR hi, lo;
            CHAR ch;

            ch = JA3Fingerprint[i * 2];
            if (ch >= '0' && ch <= '9')      hi = (UCHAR)(ch - '0');
            else if (ch >= 'a' && ch <= 'f') hi = (UCHAR)(ch - 'a' + 10);
            else if (ch >= 'A' && ch <= 'F') hi = (UCHAR)(ch - 'A' + 10);
            else return FALSE;

            ch = JA3Fingerprint[i * 2 + 1];
            if (ch >= '0' && ch <= '9')      lo = (UCHAR)(ch - '0');
            else if (ch >= 'a' && ch <= 'f') lo = (UCHAR)(ch - 'a' + 10);
            else if (ch >= 'A' && ch <= 'F') lo = (UCHAR)(ch - 'A' + 10);
            else return FALSE;

            ja3Hash[i] = (hi << 4) | lo;
        }

        status = C2LookupJA3(g_C2Detector, ja3Hash, &isKnown, malwareFamily,
                              sizeof(malwareFamily));
        if (!NT_SUCCESS(status)) {
            isKnown = FALSE;
        }
    }

    return isKnown;
}

// ============================================================================
// PUBLIC API - STATISTICS
// ============================================================================

/**
 * @brief Get network filter statistics (safe snapshot, no kernel pointers).
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
NfFilterGetStatistics(
    _Out_ PNF_FILTER_STATISTICS Stats
    )
{
    if (Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!NfpIsInitialized()) {
        return STATUS_DEVICE_NOT_READY;
    }

    RtlZeroMemory(Stats, sizeof(NF_FILTER_STATISTICS));

    Stats->Initialized = TRUE;
    Stats->Enabled = NfpIsEnabled() ? TRUE : FALSE;
    Stats->ActiveConnectionCount = (UINT32)InterlockedCompareExchange(
        &g_NfState.ConnectionCount, 0, 0);
    Stats->ActiveDnsQueryCount = (UINT32)InterlockedCompareExchange(
        &g_NfState.DnsQueryCount, 0, 0);
    Stats->BlockedDomainCount = (UINT32)InterlockedCompareExchange(
        &g_NfState.BlockedDomainCount, 0, 0);

    Stats->TotalConnectionsMonitored = InterlockedCompareExchange64(
        &g_NfState.TotalConnectionsMonitored, 0, 0);
    Stats->TotalConnectionsBlocked = InterlockedCompareExchange64(
        &g_NfState.TotalConnectionsBlocked, 0, 0);
    Stats->TotalDnsQueriesMonitored = InterlockedCompareExchange64(
        &g_NfState.TotalDnsQueriesMonitored, 0, 0);
    Stats->TotalDnsQueriesBlocked = InterlockedCompareExchange64(
        &g_NfState.TotalDnsQueriesBlocked, 0, 0);
    Stats->TotalBytesMonitored = InterlockedCompareExchange64(
        &g_NfState.TotalBytesMonitored, 0, 0);
    Stats->TotalC2Detections = InterlockedCompareExchange64(
        &g_NfState.TotalC2Detections, 0, 0);
    Stats->TotalExfiltrationDetections = InterlockedCompareExchange64(
        &g_NfState.TotalExfiltrationDetections, 0, 0);
    Stats->TotalDnsTunnelingDetections = InterlockedCompareExchange64(
        &g_NfState.TotalDnsTunnelingDetections, 0, 0);
    Stats->EventsDropped = InterlockedCompareExchange64(
        &g_NfState.EventsDropped, 0, 0);

    NfpReadConfig(&Stats->CurrentConfig);

    return STATUS_SUCCESS;
}

/**
 * @brief Get connection statistics for process.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
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

    if (!NfpIsInitialized()) {
        return STATUS_DEVICE_NOT_READY;
    }

    FltAcquirePushLockShared(&g_NfState.ConnectionLock);

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

    FltReleasePushLock(&g_NfState.ConnectionLock);

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

    if (!NfpIsInitialized() || !NfpIsEnabled()) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    {
        NETWORK_MONITOR_CONFIG config;
        NfpReadConfig(&config);
        if (!config.EnableConnectionMonitoring) {
            classifyOut->actionType = FWP_ACTION_PERMIT;
            return;
        }
    }

    if (!NfpCheckRateLimit()) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    isV6 = (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6);

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

    if (!NfpIsInitialized() || !NfpIsEnabled()) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    {
        NETWORK_MONITOR_CONFIG config;
        NfpReadConfig(&config);
        if (!config.EnableConnectionMonitoring) {
            classifyOut->actionType = FWP_ACTION_PERMIT;
            return;
        }
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

    if (!NfpIsInitialized() || !NfpIsEnabled()) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    {
        NETWORK_MONITOR_CONFIG config;
        NfpReadConfig(&config);
        if (!config.EnableDnsMonitoring) {
            classifyOut->actionType = FWP_ACTION_PERMIT;
            return;
        }
    }

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

    if (!NfpIsInitialized() || !NfpIsEnabled()) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    {
        NETWORK_MONITOR_CONFIG config;
        NfpReadConfig(&config);
        if (!config.EnableDataInspection) {
            classifyOut->actionType = FWP_ACTION_PERMIT;
            return;
        }
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
 *
 * Handles filter add/delete notifications from WFP.
 */
NTSTATUS NTAPI
NfCalloutNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER3* filter
    )
{
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);

    switch (notifyType) {
    case FWPS_CALLOUT_NOTIFY_ADD_FILTER:
        break;

    case FWPS_CALLOUT_NOTIFY_DELETE_FILTER:
        //
        // A filter referencing our callout was removed.
        // Log for diagnostics — may indicate policy tampering.
        //
        break;

    default:
        break;
    }

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

    if (!NfpIsInitialized()) {
        return;
    }

    status = NfFilterFindConnectionByFlow(flowContext, &connection);
    if (NT_SUCCESS(status)) {
        InterlockedExchange((LONG*)&connection->State, (LONG)ConnectionState_Closed);
        NfFilterReleaseConnection(connection);
    }
}

// ============================================================================
// PRIVATE FUNCTIONS - WFP REGISTRATION
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
    // ALE Connect v4
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
    // ALE Connect v6
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
    // ALE Recv Accept v4
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
    // ALE Recv Accept v6
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
    // Outbound Transport v4 (DNS)
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
    // Stream v4 (TCP data)
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

static VOID
NfpUnregisterCallouts(VOID)
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
NfpRegisterFilters(VOID)
{
    NTSTATUS status;
    FWPM_FILTER0 filter = {0};

    filter.subLayerKey = SHADOWSTRIKE_WFP_SUBLAYER_GUID;
    filter.weight.type = FWP_EMPTY;
    filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;

    // ALE Connect v4
    filter.displayData.name = L"ShadowStrike ALE Connect v4 Filter";
    filter.displayData.description = L"Inspect outbound IPv4 connections";
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.action.calloutKey = SHADOWSTRIKE_ALE_CONNECT_V4_CALLOUT_GUID;

    status = FwpmFilterAdd0(g_NfState.WfpEngineHandle, &filter, NULL,
                            &g_NfState.AleConnectV4FilterId);
    if (!NT_SUCCESS(status)) return status;

    // ALE Connect v6
    filter.displayData.name = L"ShadowStrike ALE Connect v6 Filter";
    filter.displayData.description = L"Inspect outbound IPv6 connections";
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    filter.action.calloutKey = SHADOWSTRIKE_ALE_CONNECT_V6_CALLOUT_GUID;

    status = FwpmFilterAdd0(g_NfState.WfpEngineHandle, &filter, NULL,
                            &g_NfState.AleConnectV6FilterId);
    if (!NT_SUCCESS(status)) goto CleanupV4Connect;

    // ALE Recv Accept v4
    filter.displayData.name = L"ShadowStrike ALE Recv Accept v4 Filter";
    filter.displayData.description = L"Inspect inbound IPv4 connections";
    filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
    filter.action.calloutKey = SHADOWSTRIKE_ALE_RECV_ACCEPT_V4_CALLOUT_GUID;

    status = FwpmFilterAdd0(g_NfState.WfpEngineHandle, &filter, NULL,
                            &g_NfState.AleRecvAcceptV4FilterId);
    if (!NT_SUCCESS(status)) goto CleanupV6Connect;

    // ALE Recv Accept v6
    filter.displayData.name = L"ShadowStrike ALE Recv Accept v6 Filter";
    filter.displayData.description = L"Inspect inbound IPv6 connections";
    filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
    filter.action.calloutKey = SHADOWSTRIKE_ALE_RECV_ACCEPT_V6_CALLOUT_GUID;

    status = FwpmFilterAdd0(g_NfState.WfpEngineHandle, &filter, NULL,
                            &g_NfState.AleRecvAcceptV6FilterId);
    if (!NT_SUCCESS(status)) goto CleanupV4Accept;

    // Outbound Transport v4
    filter.displayData.name = L"ShadowStrike Outbound Transport v4 Filter";
    filter.displayData.description = L"Inspect DNS and transport traffic";
    filter.layerKey = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
    filter.action.calloutKey = SHADOWSTRIKE_OUTBOUND_TRANSPORT_V4_CALLOUT_GUID;

    status = FwpmFilterAdd0(g_NfState.WfpEngineHandle, &filter, NULL,
                            &g_NfState.OutboundTransportV4FilterId);
    if (!NT_SUCCESS(status)) goto CleanupV6Accept;

    // Stream v4
    filter.displayData.name = L"ShadowStrike Stream v4 Filter";
    filter.displayData.description = L"Inspect TCP stream data";
    filter.layerKey = FWPM_LAYER_STREAM_V4;
    filter.action.calloutKey = SHADOWSTRIKE_STREAM_V4_CALLOUT_GUID;

    status = FwpmFilterAdd0(g_NfState.WfpEngineHandle, &filter, NULL,
                            &g_NfState.StreamV4FilterId);
    if (!NT_SUCCESS(status)) goto CleanupTransport;

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

static VOID
NfpUnregisterFilters(VOID)
{
    if (g_NfState.WfpEngineHandle == NULL) return;

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

// ============================================================================
// PRIVATE FUNCTIONS - HASH TABLES & MEMORY
// ============================================================================

static NTSTATUS
NfpInitializeHashTables(VOID)
{
    ULONG i;

    for (i = 0; i < NF_CONNECTION_HASH_BUCKETS; i++) {
        InitializeListHead(&g_ConnectionHashTable[i]);
        InitializeListHead(&g_FlowHashTable[i]);
        InitializeListHead(&g_ConnIdHashTable[i]);
    }

    return STATUS_SUCCESS;
}

static VOID
NfpCleanupHashTables(VOID)
{
    // Static arrays — no dynamic memory to free.
    // Entries are freed during connection/dns cleanup.
}

static NTSTATUS
NfpInitializeLookasideLists(VOID)
{
    ExInitializeNPagedLookasideList(
        &g_NfState.ConnectionLookaside, NULL, NULL,
        POOL_NX_ALLOCATION, sizeof(NF_CONNECTION_ENTRY),
        NF_POOL_TAG_CONNECTION, NF_CONNECTION_LOOKASIDE_DEPTH);

    ExInitializeNPagedLookasideList(
        &g_NfState.DnsLookaside, NULL, NULL,
        POOL_NX_ALLOCATION, sizeof(NF_DNS_ENTRY),
        NF_POOL_TAG_DNS, NF_DNS_LOOKASIDE_DEPTH);

    ExInitializeNPagedLookasideList(
        &g_NfState.EventLookaside, NULL, NULL,
        POOL_NX_ALLOCATION, sizeof(NETWORK_CONNECTION_EVENT),
        NF_POOL_TAG_EVENT, NF_EVENT_LOOKASIDE_DEPTH);

    return STATUS_SUCCESS;
}

static VOID
NfpCleanupLookasideLists(VOID)
{
    ExDeleteNPagedLookasideList(&g_NfState.ConnectionLookaside);
    ExDeleteNPagedLookasideList(&g_NfState.DnsLookaside);
    ExDeleteNPagedLookasideList(&g_NfState.EventLookaside);
}

static PNF_CONNECTION_ENTRY
NfpAllocateConnection(VOID)
{
    PNF_CONNECTION_ENTRY connection;

    connection = (PNF_CONNECTION_ENTRY)ExAllocateFromNPagedLookasideList(
        &g_NfState.ConnectionLookaside);

    if (connection != NULL) {
        RtlZeroMemory(connection, sizeof(NF_CONNECTION_ENTRY));
        connection->RefCount = 1;
    }

    return connection;
}

static VOID
NfpFreeConnection(_In_ PNF_CONNECTION_ENTRY Connection)
{
    if (Connection != NULL) {
        ExFreeToNPagedLookasideList(&g_NfState.ConnectionLookaside, Connection);
    }
}

static PNF_DNS_ENTRY
NfpAllocateDnsEntry(VOID)
{
    PNF_DNS_ENTRY dnsEntry;

    dnsEntry = (PNF_DNS_ENTRY)ExAllocateFromNPagedLookasideList(
        &g_NfState.DnsLookaside);

    if (dnsEntry != NULL) {
        RtlZeroMemory(dnsEntry, sizeof(NF_DNS_ENTRY));
    }

    return dnsEntry;
}

static VOID
NfpFreeDnsEntry(_In_ PNF_DNS_ENTRY DnsEntry)
{
    if (DnsEntry != NULL) {
        ExFreeToNPagedLookasideList(&g_NfState.DnsLookaside, DnsEntry);
    }
}

// ============================================================================
// PRIVATE FUNCTIONS - HASHING
// ============================================================================

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

    addrLen = (Local->Address.Family == AF_INET) ? 4 : 16;

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

static UINT32
NfpHashFlowId(_In_ UINT64 FlowId)
{
    UINT32 hash = (UINT32)(FlowId ^ (FlowId >> 32));
    return hash % NF_CONNECTION_HASH_BUCKETS;
}

static UINT32
NfpHashConnectionId(_In_ UINT64 ConnectionId)
{
    UINT32 hash = (UINT32)(ConnectionId ^ (ConnectionId >> 16));
    hash ^= (hash >> 8);
    return hash % NF_CONNECTION_HASH_BUCKETS;
}

static UINT32
NfpHashDomainName(_In_ PCWSTR DomainName)
{
    UINT32 hash = 5381;
    WCHAR c;

    while ((c = *DomainName++) != L'\0') {
        if (c >= L'A' && c <= L'Z') {
            c = c - L'A' + L'a';
        }
        hash = ((hash << 5) + hash) + c;
    }

    return hash;
}

// ============================================================================
// PRIVATE FUNCTIONS - CONNECTION TABLE MANAGEMENT
// ============================================================================

/**
 * @brief Insert connection into all tracking tables atomically.
 *
 * Uses a single lock (ConnectionLock) for all three tables to prevent
 * partial-visibility races.
 */
static NTSTATUS
NfpInsertConnection(
    _In_ PNF_CONNECTION_ENTRY Connection
    )
{
    UINT32 epHashIndex, flowHashIndex, idHashIndex;
    PNF_CONNECTION_HASH_ENTRY epEntry = NULL;
    PNF_CONNECTION_HASH_ENTRY flowEntry = NULL;
    PNF_CONNECTION_HASH_ENTRY idEntry = NULL;

    //
    // Check connection limit
    //
    if ((UINT32)InterlockedCompareExchange(&g_NfState.ConnectionCount, 0, 0)
            >= NF_MAX_CONNECTIONS) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Allocate all hash entries BEFORE locking
    //
    epEntry = (PNF_CONNECTION_HASH_ENTRY)ExAllocatePoolWithTag(
        NonPagedPoolNx, sizeof(NF_CONNECTION_HASH_ENTRY), NF_POOL_TAG_CONNECTION);
    if (epEntry == NULL) goto AllocFail;

    flowEntry = (PNF_CONNECTION_HASH_ENTRY)ExAllocatePoolWithTag(
        NonPagedPoolNx, sizeof(NF_CONNECTION_HASH_ENTRY), NF_POOL_TAG_CONNECTION);
    if (flowEntry == NULL) goto AllocFail;

    idEntry = (PNF_CONNECTION_HASH_ENTRY)ExAllocatePoolWithTag(
        NonPagedPoolNx, sizeof(NF_CONNECTION_HASH_ENTRY), NF_POOL_TAG_CONNECTION);
    if (idEntry == NULL) goto AllocFail;

    epEntry->Connection = Connection;
    flowEntry->Connection = Connection;
    idEntry->Connection = Connection;

    //
    // Compute hash indices
    //
    epHashIndex = NfpHashEndpoints(&Connection->LocalAddress,
                                    &Connection->RemoteAddress,
                                    Connection->Protocol);
    flowHashIndex = NfpHashFlowId(Connection->FlowId);
    idHashIndex = NfpHashConnectionId(Connection->ConnectionId);

    //
    // Insert into ALL tables under a single exclusive lock
    //
    FltAcquirePushLockExclusive(&g_NfState.ConnectionLock);

    InsertTailList(&g_NfState.ConnectionList, &Connection->ListEntry);
    InsertTailList(&g_ConnectionHashTable[epHashIndex], &epEntry->HashListEntry);
    InsertTailList(&g_FlowHashTable[flowHashIndex], &flowEntry->HashListEntry);
    InsertTailList(&g_ConnIdHashTable[idHashIndex], &idEntry->HashListEntry);
    InterlockedIncrement(&g_NfState.ConnectionCount);

    FltReleasePushLock(&g_NfState.ConnectionLock);

    InterlockedIncrement64(&g_NfState.TotalConnectionsMonitored);

    return STATUS_SUCCESS;

AllocFail:
    if (epEntry != NULL) ExFreePoolWithTag(epEntry, NF_POOL_TAG_CONNECTION);
    if (flowEntry != NULL) ExFreePoolWithTag(flowEntry, NF_POOL_TAG_CONNECTION);
    if (idEntry != NULL) ExFreePoolWithTag(idEntry, NF_POOL_TAG_CONNECTION);
    return STATUS_INSUFFICIENT_RESOURCES;
}

/**
 * @brief Remove connection from all tracking tables atomically.
 *
 * Caller must NOT hold ConnectionLock. This function acquires it exclusively.
 */
static VOID
NfpRemoveConnection(
    _In_ PNF_CONNECTION_ENTRY Connection
    )
{
    UINT32 hashIndex;
    PLIST_ENTRY entry;
    PNF_CONNECTION_HASH_ENTRY hashEntry;
    PNF_CONNECTION_HASH_ENTRY foundEp = NULL;
    PNF_CONNECTION_HASH_ENTRY foundFlow = NULL;
    PNF_CONNECTION_HASH_ENTRY foundId = NULL;

    FltAcquirePushLockExclusive(&g_NfState.ConnectionLock);

    //
    // Remove from main list
    //
    RemoveEntryList(&Connection->ListEntry);
    InterlockedDecrement(&g_NfState.ConnectionCount);

    //
    // Remove from endpoint hash
    //
    hashIndex = NfpHashEndpoints(&Connection->LocalAddress,
                                  &Connection->RemoteAddress,
                                  Connection->Protocol);
    for (entry = g_ConnectionHashTable[hashIndex].Flink;
         entry != &g_ConnectionHashTable[hashIndex];
         entry = entry->Flink) {
        hashEntry = CONTAINING_RECORD(entry, NF_CONNECTION_HASH_ENTRY, HashListEntry);
        if (hashEntry->Connection == Connection) {
            RemoveEntryList(&hashEntry->HashListEntry);
            foundEp = hashEntry;
            break;
        }
    }

    //
    // Remove from flow hash
    //
    hashIndex = NfpHashFlowId(Connection->FlowId);
    for (entry = g_FlowHashTable[hashIndex].Flink;
         entry != &g_FlowHashTable[hashIndex];
         entry = entry->Flink) {
        hashEntry = CONTAINING_RECORD(entry, NF_CONNECTION_HASH_ENTRY, HashListEntry);
        if (hashEntry->Connection == Connection) {
            RemoveEntryList(&hashEntry->HashListEntry);
            foundFlow = hashEntry;
            break;
        }
    }

    //
    // Remove from connId hash
    //
    hashIndex = NfpHashConnectionId(Connection->ConnectionId);
    for (entry = g_ConnIdHashTable[hashIndex].Flink;
         entry != &g_ConnIdHashTable[hashIndex];
         entry = entry->Flink) {
        hashEntry = CONTAINING_RECORD(entry, NF_CONNECTION_HASH_ENTRY, HashListEntry);
        if (hashEntry->Connection == Connection) {
            RemoveEntryList(&hashEntry->HashListEntry);
            foundId = hashEntry;
            break;
        }
    }

    FltReleasePushLock(&g_NfState.ConnectionLock);

    //
    // Free hash entries outside lock
    //
    if (foundEp != NULL) ExFreePoolWithTag(foundEp, NF_POOL_TAG_CONNECTION);
    if (foundFlow != NULL) ExFreePoolWithTag(foundFlow, NF_POOL_TAG_CONNECTION);
    if (foundId != NULL) ExFreePoolWithTag(foundId, NF_POOL_TAG_CONNECTION);
}

// ============================================================================
// PRIVATE FUNCTIONS - CLEANUP (DPC -> WorkItem -> PASSIVE_LEVEL)
// ============================================================================

/**
 * @brief DPC callback — queues a work item for cleanup at PASSIVE_LEVEL.
 *
 * DPCs run at DISPATCH_LEVEL. Push locks can be acquired at DISPATCH
 * via KeAcquireInStackQueuedSpinLock, but for simplicity and to allow
 * process path lookups, we defer to a work item.
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
    // Only queue if not already in progress and we are still initialized
    //
    if (InterlockedCompareExchange(&g_CleanupInProgress, 1, 0) != 0) {
        return;
    }

    if (!NfpIsInitialized() || g_NfState.CleanupWorkItem == NULL) {
        InterlockedExchange(&g_CleanupInProgress, 0);
        return;
    }

    IoQueueWorkItem(
        g_NfState.CleanupWorkItem,
        NfpCleanupWorkItemRoutine,
        DelayedWorkQueue,
        NULL
        );
}

/**
 * @brief Work item routine — runs cleanup at PASSIVE_LEVEL.
 */
static VOID
NfpCleanupWorkItemRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Context);

    if (NfpIsInitialized()) {
        NfpCleanupStaleConnections();
        NfpCleanupStaleDnsEntries();
        NfpCleanupStalePendingDns();
    }

    InterlockedExchange(&g_CleanupInProgress, 0);
}

/**
 * @brief Cleanup stale connections.
 *
 * Collects stale connections under lock, then removes them properly
 * via NfpRemoveConnection (which cleans all hash tables).
 */
static VOID
NfpCleanupStaleConnections(VOID)
{
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;
    PNF_CONNECTION_ENTRY connection;
    LARGE_INTEGER currentTime;
    UINT64 currentTimeMs;

    // Temporary array to hold connections to remove (avoid nested lock)
    PNF_CONNECTION_ENTRY staleConnections[64];
    ULONG staleCount = 0;
    ULONG i;

    KeQuerySystemTime(&currentTime);
    currentTimeMs = (UINT64)(currentTime.QuadPart / 10000);

    //
    // Phase 1: Identify stale connections under shared lock
    //
    FltAcquirePushLockShared(&g_NfState.ConnectionLock);

    for (entry = g_NfState.ConnectionList.Flink;
         entry != &g_NfState.ConnectionList;
         entry = entry->Flink) {

        connection = CONTAINING_RECORD(entry, NF_CONNECTION_ENTRY, ListEntry);

        if (connection->RefCount <= 0 &&
            connection->State == ConnectionState_Closed &&
            (currentTimeMs - connection->LastActivityTime) > NF_CONNECTION_TIMEOUT_MS) {

            if (staleCount < ARRAYSIZE(staleConnections)) {
                //
                // Take a reference to prevent premature free
                //
                InterlockedIncrement(&connection->RefCount);
                staleConnections[staleCount++] = connection;
            }
        }
    }

    FltReleasePushLock(&g_NfState.ConnectionLock);

    //
    // Phase 2: Remove and free stale connections (NfpRemoveConnection acquires exclusive lock)
    //
    for (i = 0; i < staleCount; i++) {
        connection = staleConnections[i];
        InterlockedDecrement(&connection->RefCount);
        NfpRemoveConnection(connection);
        NfpFreeConnection(connection);
    }
}

/**
 * @brief Cleanup stale DNS entries.
 */
static VOID
NfpCleanupStaleDnsEntries(VOID)
{
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;
    PNF_DNS_ENTRY dnsEntry;
    LARGE_INTEGER currentTime;
    UINT64 currentTimeMs;
    LIST_ENTRY staleList;

    InitializeListHead(&staleList);
    KeQuerySystemTime(&currentTime);
    currentTimeMs = (UINT64)(currentTime.QuadPart / 10000);

    FltAcquirePushLockExclusive(&g_NfState.DnsLock);

    for (entry = g_NfState.DnsQueryList.Flink;
         entry != &g_NfState.DnsQueryList;
         entry = nextEntry) {

        nextEntry = entry->Flink;
        dnsEntry = CONTAINING_RECORD(entry, NF_DNS_ENTRY, ListEntry);

        if ((currentTimeMs - dnsEntry->QueryTime) > NF_DNS_ENTRY_TIMEOUT_MS) {
            RemoveEntryList(&dnsEntry->ListEntry);
            InsertTailList(&staleList, &dnsEntry->ListEntry);
            InterlockedDecrement(&g_NfState.DnsQueryCount);
        }
    }

    FltReleasePushLock(&g_NfState.DnsLock);

    while (!IsListEmpty(&staleList)) {
        entry = RemoveHeadList(&staleList);
        dnsEntry = CONTAINING_RECORD(entry, NF_DNS_ENTRY, ListEntry);
        NfpFreeDnsEntry(dnsEntry);
    }
}

/**
 * @brief Cleanup stale pending DNS queries.
 */
static VOID
NfpCleanupStalePendingDns(VOID)
{
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;
    PNF_PENDING_DNS pendingDns;
    LARGE_INTEGER currentTime;
    UINT64 currentTimeMs;
    LIST_ENTRY staleList;

    InitializeListHead(&staleList);
    KeQuerySystemTime(&currentTime);
    currentTimeMs = (UINT64)(currentTime.QuadPart / 10000);

    FltAcquirePushLockExclusive(&g_PendingDnsLock);

    for (entry = g_PendingDnsList.Flink;
         entry != &g_PendingDnsList;
         entry = nextEntry) {

        nextEntry = entry->Flink;
        pendingDns = CONTAINING_RECORD(entry, NF_PENDING_DNS, ListEntry);

        // DNS queries older than 30 seconds are stale
        if ((currentTimeMs - pendingDns->QueryTime) > 30000) {
            RemoveEntryList(&pendingDns->ListEntry);
            InsertTailList(&staleList, &pendingDns->ListEntry);
            InterlockedDecrement(&g_PendingDnsCount);
        }
    }

    FltReleasePushLock(&g_PendingDnsLock);

    while (!IsListEmpty(&staleList)) {
        entry = RemoveHeadList(&staleList);
        pendingDns = CONTAINING_RECORD(entry, NF_PENDING_DNS, ListEntry);
        ExFreePoolWithTag(pendingDns, NF_POOL_TAG_DNS);
    }
}

// ============================================================================
// PRIVATE FUNCTIONS - RATE LIMITING
// ============================================================================

/**
 * @brief Thread-safe rate limiting using interlocked operations.
 *
 * Uses InterlockedCompareExchange64 for the second boundary to prevent
 * TOCTOU races on the reset path.
 */
static BOOLEAN
NfpCheckRateLimit(VOID)
{
    LARGE_INTEGER currentTime;
    UINT64 currentTimeMs;
    LONG64 lastSecondStart;
    LONG currentEvents;
    NETWORK_MONITOR_CONFIG config;

    KeQuerySystemTime(&currentTime);
    currentTimeMs = (UINT64)(currentTime.QuadPart / 10000);

    lastSecondStart = InterlockedCompareExchange64(&g_CurrentSecondStart, 0, 0);

    //
    // If we're in a new second, try to atomically reset
    //
    if ((UINT64)(currentTimeMs - (UINT64)lastSecondStart) >= 1000) {
        //
        // CAS: only one thread wins the reset
        //
        if (InterlockedCompareExchange64(&g_CurrentSecondStart,
                                          (LONG64)currentTimeMs,
                                          lastSecondStart) == lastSecondStart) {
            InterlockedExchange(&g_EventsThisSecond, 0);
        }
    }

    currentEvents = InterlockedIncrement(&g_EventsThisSecond);

    NfpReadConfig(&config);

    if ((UINT32)currentEvents > config.MaxEventsPerSecond) {
        InterlockedIncrement64(&g_TotalEventsDropped);
        InterlockedIncrement64(&g_NfState.EventsDropped);

        {
            LONG64 lastLog = InterlockedCompareExchange64(
                &g_LastRateLimitLogTime, 0, 0);
            if ((currentTimeMs - (UINT64)lastLog) > NF_RATE_LIMIT_LOG_INTERVAL_MS) {
                InterlockedExchange64(&g_LastRateLimitLogTime, (LONG64)currentTimeMs);
            }
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
 *
 * MUST be called at PASSIVE_LEVEL (PsLookupProcessByProcessId requirement).
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
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

static VOID
NfpCopyAddress(
    _Out_ PSS_SOCKET_ADDRESS Dest,
    _In_opt_ const FWP_BYTE_ARRAY16* IpV6,
    _In_opt_ const UINT32* IpV4,
    _In_ UINT16 Port,
    _In_ BOOLEAN IsV6
    )
{
    RtlZeroMemory(Dest, sizeof(SS_SOCKET_ADDRESS));

    if (IsV6) {
        Dest->Address.Family = AF_INET6;
        if (IpV6 != NULL) {
            RtlCopyMemory(Dest->Address.V6.Bytes, IpV6->byteArray16, 16);
        }
    } else {
        Dest->Address.Family = AF_INET;
        if (IpV4 != NULL) {
            Dest->Address.V4.Address = *IpV4;
        }
    }

    Dest->Port = Port;
}

static BOOLEAN
NfpIsPrivateAddress(_In_ PSS_IP_ADDRESS Address)
{
    if (SS_IS_IPV4(Address)) {
        PUCHAR bytes = Address->V4.Bytes;
        if (bytes[0] == 10) return TRUE;
        if (bytes[0] == 172 && (bytes[1] & 0xF0) == 16) return TRUE;
        if (bytes[0] == 192 && bytes[1] == 168) return TRUE;
    }
    return FALSE;
}

static BOOLEAN
NfpIsLoopbackAddress(_In_ PSS_IP_ADDRESS Address)
{
    if (SS_IS_IPV4(Address)) {
        return (Address->V4.Bytes[0] == 127);
    }

    if (SS_IS_IPV6(Address)) {
        static const UINT8 loopback[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        return (RtlCompareMemory(Address->V6.Bytes, loopback, 16) == 16);
    }

    return FALSE;
}

/**
 * @brief Parse DNS query name from wire format to wide string.
 *
 * DNS wire format: length-prefixed labels (e.g., \x03www\x06google\x03com\x00).
 */
static VOID
NfpParseDnsQueryName(
    _In_reads_bytes_(DataLength) const UCHAR* DnsData,
    _In_ ULONG DataLength,
    _Out_writes_(MaxNameLength) PWCHAR QueryName,
    _In_ ULONG MaxNameLength
    )
{
    ULONG offset = 0;
    ULONG namePos = 0;
    UCHAR labelLen;

    QueryName[0] = L'\0';

    if (DataLength < NF_DNS_HEADER_SIZE + 1 || MaxNameLength < 2) {
        return;
    }

    //
    // Skip DNS header (12 bytes)
    //
    offset = NF_DNS_HEADER_SIZE;

    while (offset < DataLength) {
        labelLen = DnsData[offset++];

        if (labelLen == 0) break;

        //
        // Check for compression pointer (not expected in queries, but guard)
        //
        if ((labelLen & 0xC0) == 0xC0) break;

        if (labelLen > 63) break;

        if (offset + labelLen > DataLength) break;

        //
        // Add dot separator (except for first label)
        //
        if (namePos > 0) {
            if (namePos + 1 >= MaxNameLength) break;
            QueryName[namePos++] = L'.';
        }

        //
        // Copy label characters
        //
        for (ULONG i = 0; i < labelLen && namePos + 1 < MaxNameLength; i++) {
            QueryName[namePos++] = (WCHAR)DnsData[offset + i];
        }

        offset += labelLen;
    }

    QueryName[namePos] = L'\0';
}

// ============================================================================
// PRIVATE FUNCTIONS - CONNECTION PROCESSING
// ============================================================================

/**
 * @brief Common connection creation logic for both inbound and outbound.
 */
static VOID
NfpCreateAndInsertConnection(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _In_ UINT64 FlowContext,
    _Out_ FWPS_CLASSIFY_OUT0* ClassifyOut,
    _In_ BOOLEAN IsV6,
    _In_ NETWORK_DIRECTION Direction,
    _In_ ULONG LocalAddrIdx,
    _In_ ULONG RemoteAddrIdx,
    _In_ ULONG LocalPortIdx,
    _In_ ULONG RemotePortIdx,
    _In_ ULONG ProtocolIdx
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

    ClassifyOut->actionType = FWP_ACTION_PERMIT;

    //
    // Extract connection details
    //
    if (IsV6) {
        localIp6 = InFixedValues->incomingValue[LocalAddrIdx].value.byteArray16;
        remoteIp6 = InFixedValues->incomingValue[RemoteAddrIdx].value.byteArray16;
    } else {
        localIp = InFixedValues->incomingValue[LocalAddrIdx].value.uint32;
        remoteIp = InFixedValues->incomingValue[RemoteAddrIdx].value.uint32;
    }

    localPort = InFixedValues->incomingValue[LocalPortIdx].value.uint16;
    remotePort = InFixedValues->incomingValue[RemotePortIdx].value.uint16;
    protocol = InFixedValues->incomingValue[ProtocolIdx].value.uint8;

    if (FWPS_IS_METADATA_FIELD_PRESENT(InMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
        processId = InMetaValues->processId;
    } else {
        processId = 0;
    }

    connection = NfpAllocateConnection();
    if (connection == NULL) {
        return;
    }

    connection->ConnectionId = (UINT64)InterlockedIncrement64(&g_NfState.NextConnectionId);
    connection->FlowId = FlowContext;
    connection->Direction = Direction;
    connection->State = ConnectionState_Connecting;

    switch (protocol) {
        case IPPROTO_TCP:
            connection->Protocol = NetworkProtocol_TCP;
            break;
        case IPPROTO_UDP:
            connection->Protocol = NetworkProtocol_UDP;
            break;
        case IPPROTO_ICMP:
            connection->Protocol = NetworkProtocol_ICMP;
            break;
        case 58:    // IPPROTO_ICMPV6
            connection->Protocol = NetworkProtocol_ICMPv6;
            break;
        default:
            connection->Protocol = NetworkProtocol_Unknown;
            break;
    }

    NfpCopyAddress(&connection->LocalAddress, localIp6, &localIp, localPort, IsV6);
    NfpCopyAddress(&connection->RemoteAddress, remoteIp6, &remoteIp, remotePort, IsV6);

    connection->ProcessId = (UINT32)processId;

    //
    // ALE classify runs at PASSIVE_LEVEL, safe to call PsLookupProcessByProcessId
    //
    NfpGetProcessPath((HANDLE)(ULONG_PTR)processId, connection->ProcessImagePath,
                      MAX_FILE_PATH_LENGTH);

    KeQuerySystemTime(&currentTime);
    connection->ConnectTime = (UINT64)(currentTime.QuadPart / 10000);
    connection->LastActivityTime = connection->ConnectTime;

    InterlockedOr((LONG*)&connection->Flags, NF_CONN_FLAG_MONITORED);
    if (!NfpIsPrivateAddress(&connection->RemoteAddress.Address) &&
        !NfpIsLoopbackAddress(&connection->RemoteAddress.Address)) {
        InterlockedOr((LONG*)&connection->Flags, NF_CONN_FLAG_FIRST_CONTACT);
    }

    status = NfpInsertConnection(connection);
    if (!NT_SUCCESS(status)) {
        NfpFreeConnection(connection);
        return;
    }

    NfpAnalyzeConnection(connection);

    if (InterlockedCompareExchange((LONG*)&connection->Flags, 0, 0) & NF_CONN_FLAG_BLOCKED) {
        ClassifyOut->actionType = FWP_ACTION_BLOCK;
        ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        InterlockedIncrement64(&g_NfState.TotalConnectionsBlocked);
    }
}

/**
 * @brief Process outbound connection (fully implemented).
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
    if (IsV6) {
        NfpCreateAndInsertConnection(
            InFixedValues, InMetaValues, FlowContext, ClassifyOut, TRUE,
            NetworkDirection_Outbound,
            FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS,
            FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS,
            FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT,
            FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT,
            FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL);
    } else {
        NfpCreateAndInsertConnection(
            InFixedValues, InMetaValues, FlowContext, ClassifyOut, FALSE,
            NetworkDirection_Outbound,
            FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS,
            FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS,
            FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT,
            FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT,
            FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL);
    }
}

/**
 * @brief Process inbound connection (fully implemented).
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
    if (IsV6) {
        NfpCreateAndInsertConnection(
            InFixedValues, InMetaValues, FlowContext, ClassifyOut, TRUE,
            NetworkDirection_Inbound,
            FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS,
            FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS,
            FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT,
            FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT,
            FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL);
    } else {
        NfpCreateAndInsertConnection(
            InFixedValues, InMetaValues, FlowContext, ClassifyOut, FALSE,
            NetworkDirection_Inbound,
            FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS,
            FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS,
            FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT,
            FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT,
            FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL);
    }
}

/**
 * @brief Process DNS packet — extracts query from NET_BUFFER, parses, inspects.
 */
static VOID
NfpProcessDnsPacket(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _In_opt_ void* LayerData,
    _Out_ FWPS_CLASSIFY_OUT0* ClassifyOut
    )
{
    NET_BUFFER_LIST* nbl;
    NET_BUFFER* nb;
    ULONG dataLength;
    UCHAR* dnsData = NULL;
    UCHAR localBuffer[512];
    BOOLEAN allocated = FALSE;
    WCHAR queryName[MAX_DNS_NAME_LENGTH];
    UINT16 transactionId;
    UINT32 processId;
    LARGE_INTEGER currentTime;
    PNF_DNS_ENTRY dnsEntry;
    UINT32 domainHash;

    ClassifyOut->actionType = FWP_ACTION_PERMIT;

    if (LayerData == NULL) {
        goto Done;
    }

    nbl = (NET_BUFFER_LIST*)LayerData;
    nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (nb == NULL) {
        goto Done;
    }

    dataLength = NET_BUFFER_DATA_LENGTH(nb);
    if (dataLength < NF_DNS_HEADER_SIZE) {
        goto Done;
    }

    //
    // Get contiguous access to the DNS data
    //
    if (dataLength <= sizeof(localBuffer)) {
        dnsData = (UCHAR*)NdisGetDataBuffer(nb, dataLength, localBuffer, 1, 0);
    } else {
        //
        // For large packets, allocate from pool
        //
        dnsData = (UCHAR*)ExAllocatePoolWithTag(
            NonPagedPoolNx, dataLength, NF_POOL_TAG_DNS);
        if (dnsData == NULL) {
            goto Done;
        }
        allocated = TRUE;

        if (NdisGetDataBuffer(nb, dataLength, dnsData, 1, 0) == NULL) {
            goto Done;
        }
    }

    if (dnsData == NULL) {
        goto Done;
    }

    //
    // Parse DNS header
    //
    transactionId = (UINT16)((dnsData[0] << 8) | dnsData[1]);

    //
    // Check QR bit (bit 15 of flags) — 0 = query, 1 = response
    // We only process queries here
    //
    if ((dnsData[2] & 0x80) != 0) {
        goto Done;
    }

    //
    // Parse query name
    //
    NfpParseDnsQueryName(dnsData, dataLength, queryName, MAX_DNS_NAME_LENGTH);
    if (queryName[0] == L'\0') {
        goto Done;
    }

    //
    // Check if domain is blocked
    //
    if (NfpIsDomainBlocked(queryName)) {
        ClassifyOut->actionType = FWP_ACTION_BLOCK;
        ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        InterlockedIncrement64(&g_NfState.TotalDnsQueriesBlocked);
        goto Done;
    }

    //
    // Get process ID
    //
    if (FWPS_IS_METADATA_FIELD_PRESENT(InMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
        processId = (UINT32)InMetaValues->processId;
    } else {
        processId = 0;
    }

    //
    // Create DNS entry
    //
    dnsEntry = NfpAllocateDnsEntry();
    if (dnsEntry == NULL) {
        goto Done;
    }

    dnsEntry->TransactionId = transactionId;
    dnsEntry->ProcessId = processId;
    KeQuerySystemTime(&currentTime);
    dnsEntry->QueryTime = (UINT64)(currentTime.QuadPart / 10000);

    RtlStringCchCopyW(dnsEntry->QueryName, MAX_DNS_NAME_LENGTH, queryName);
    dnsEntry->QueryNameHash = NfpHashDomainName(queryName);

    //
    // Extract query type (after query name + null + 2 bytes for type)
    //
    {
        ULONG nameEnd = NF_DNS_HEADER_SIZE;
        while (nameEnd < dataLength && dnsData[nameEnd] != 0) {
            UCHAR lbl = dnsData[nameEnd];
            if ((lbl & 0xC0) == 0xC0) { nameEnd += 2; break; }
            nameEnd += 1 + lbl;
        }
        if (nameEnd < dataLength && dnsData[nameEnd] == 0) nameEnd++;
        if (nameEnd + 2 <= dataLength) {
            dnsEntry->QueryType = (UINT16)((dnsData[nameEnd] << 8) | dnsData[nameEnd + 1]);
        }
    }

    //
    // Compute domain entropy for DGA detection
    //
    {
        UINT32 charCounts[36] = {0};
        ULONG totalChars = 0;
        UINT64 entropy = 0;
        ULONG i;

        for (i = 0; queryName[i] != L'\0'; i++) {
            WCHAR c = queryName[i];
            if (c == L'.') continue;
            if (c >= L'a' && c <= L'z') charCounts[c - L'a']++;
            else if (c >= L'A' && c <= L'Z') charCounts[c - L'A']++;
            else if (c >= L'0' && c <= L'9') charCounts[26 + c - L'0']++;
            totalChars++;
        }

        if (totalChars > 0) {
            for (i = 0; i < 36; i++) {
                if (charCounts[i] > 0) {
                    UINT32 freq = (charCounts[i] * 1000) / totalChars;
                    if (freq > 0) {
                        // Simplified entropy: sum of freq * log2(freq) approximation
                        entropy += freq;
                    }
                }
            }
            dnsEntry->DomainEntropy = (UINT32)((entropy * 100) / 1000);
        }

        // High entropy with long subdomain suggests DGA
        ULONG dotCount = 0;
        ULONG lastDotPos = 0;
        for (i = 0; queryName[i] != L'\0'; i++) {
            if (queryName[i] == L'.') { dotCount++; lastDotPos = i; }
        }
        dnsEntry->SubdomainLength = (dotCount > 1) ? lastDotPos : 0;

        if (dnsEntry->DomainEntropy > 350 && totalChars > 20) {
            dnsEntry->IsDGA = TRUE;
            dnsEntry->IsSuspicious = TRUE;
            dnsEntry->ThreatScore = 70;
        }
    }

    //
    // Insert into DNS tracking list
    //
    FltAcquirePushLockExclusive(&g_NfState.DnsLock);
    InsertTailList(&g_NfState.DnsQueryList, &dnsEntry->ListEntry);
    InterlockedIncrement(&g_NfState.DnsQueryCount);
    FltReleasePushLock(&g_NfState.DnsLock);

    InterlockedIncrement64(&g_NfState.TotalDnsQueriesMonitored);

Done:
    if (allocated && dnsData != NULL) {
        ExFreePoolWithTag(dnsData, NF_POOL_TAG_DNS);
    }

    UNREFERENCED_PARAMETER(InFixedValues);
}

/**
 * @brief Process TCP stream data — update statistics using atomic operations.
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
    NETWORK_MONITOR_CONFIG config;

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

    status = NfFilterFindConnectionByFlow(FlowContext, &connection);
    if (!NT_SUCCESS(status)) {
        return;
    }

    KeQuerySystemTime(&currentTime);
    InterlockedExchange64(
        (LONG64*)&connection->LastActivityTime,
        (LONG64)(currentTime.QuadPart / 10000));

    if (StreamPacket->streamData->flags & FWPS_STREAM_FLAG_SEND) {
        InterlockedAdd64((LONG64*)&connection->BytesSent, (LONG64)dataSize);
        InterlockedIncrement((LONG*)&connection->PacketsSent);

        NfpUpdateBeaconingState(connection, (UINT64)(currentTime.QuadPart / 10000));
    } else {
        InterlockedAdd64((LONG64*)&connection->BytesReceived, (LONG64)dataSize);
        InterlockedIncrement((LONG*)&connection->PacketsReceived);
    }

    InterlockedAdd64(&g_NfState.TotalBytesMonitored, (LONG64)dataSize);

    NfpReadConfig(&config);
    if (config.EnableExfiltrationDetection) {
        UINT64 thresholdBytes = (UINT64)config.ExfiltrationThresholdMB * 1024ULL * 1024ULL;
        if (connection->BytesSent > thresholdBytes) {
            InterlockedOr((LONG*)&connection->Flags, NF_CONN_FLAG_EXFIL_SUSPECT);
        }
    }

    NfFilterReleaseConnection(connection);
}

// ============================================================================
// PRIVATE FUNCTIONS - ANALYSIS
// ============================================================================

/**
 * @brief Analyze connection for threats (reputation check).
 */
static NTSTATUS
NfpAnalyzeConnection(
    _In_ PNF_CONNECTION_ENTRY Connection
    )
{
    NR_LOOKUP_RESULT reputationResult = {0};

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
                InterlockedOr((LONG*)&Connection->Flags, NF_CONN_FLAG_BLOCKED);
                InterlockedExchange(
                    (LONG*)&Connection->ThreatType,
                    (LONG)NetworkThreat_Known_Malicious);
                Connection->ThreatScore = 100;
            } else if (reputationResult.Reputation == NrReputation_High) {
                InterlockedOr((LONG*)&Connection->Flags, NF_CONN_FLAG_SUSPICIOUS);
                Connection->ThreatScore = 75;
            }
        }
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Update beaconing analysis state using atomic operations.
 *
 * Uses clamped arithmetic to prevent integer overflow on large intervals.
 */
static VOID
NfpUpdateBeaconingState(
    _In_ PNF_CONNECTION_ENTRY Connection,
    _In_ UINT64 CurrentTime
    )
{
    UINT32 interval;
    UINT32 index;
    NETWORK_MONITOR_CONFIG config;

    NfpReadConfig(&config);
    if (!config.EnableC2Detection) {
        return;
    }

    if (Connection->LastSendTime > 0 && CurrentTime > Connection->LastSendTime) {
        UINT64 rawInterval = CurrentTime - Connection->LastSendTime;

        //
        // Clamp to UINT32 max to prevent overflow in variance calculation
        //
        interval = (rawInterval > MAXUINT32) ? MAXUINT32 : (UINT32)rawInterval;

        //
        // Store in ring buffer (atomic index update)
        //
        index = InterlockedIncrement((LONG*)&Connection->SendIntervalIndex) - 1;
        index = index % 32;
        Connection->SendIntervals[index] = interval;

        {
            LONG count = InterlockedCompareExchange(
                (LONG*)&Connection->SendIntervalCount, 0, 0);
            if (count < 32) {
                InterlockedIncrement((LONG*)&Connection->SendIntervalCount);
            }
        }

        //
        // Update running average
        //
        {
            LONG count = InterlockedCompareExchange(
                (LONG*)&Connection->SendIntervalCount, 0, 0);
            if (count > 0) {
                UINT64 sum = 0;
                UINT32 i;

                for (i = 0; i < (UINT32)count; i++) {
                    sum += Connection->SendIntervals[i];
                }

                Connection->AverageIntervalMs = (UINT32)(sum / (UINT32)count);

                if ((UINT32)count >= config.BeaconMinSamples) {
                    UINT64 variance = 0;
                    for (i = 0; i < (UINT32)count; i++) {
                        //
                        // Use UINT64 arithmetic to prevent signed overflow
                        //
                        UINT64 val = Connection->SendIntervals[i];
                        UINT64 avg = Connection->AverageIntervalMs;
                        UINT64 diff = (val > avg) ? (val - avg) : (avg - val);
                        variance += diff * diff;
                    }
                    //
                    // Normalize variance (divide by count, scale down)
                    //
                    Connection->IntervalVariance =
                        (UINT32)min(variance / (UINT32)count / 1000, MAXUINT32);
                }
            }
        }
    }

    InterlockedExchange64((LONG64*)&Connection->LastSendTime, (LONG64)CurrentTime);
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
    NETWORK_MONITOR_CONFIG config;

    NfpReadConfig(&config);

    if (Connection->SendIntervalCount < config.BeaconMinSamples) {
        return FALSE;
    }

    if (Connection->AverageIntervalMs > 0) {
        //
        // Jitter = Variance / Mean (simplified coefficient of variation)
        //
        jitterPercent = (Connection->IntervalVariance * 100) / Connection->AverageIntervalMs;

        if (jitterPercent <= config.BeaconJitterThreshold) {
            isBeaconing = TRUE;
            InterlockedOr((LONG*)&Connection->Flags, NF_CONN_FLAG_BEACONING);

            if (BeaconingData != NULL) {
                RtlZeroMemory(BeaconingData, sizeof(BEACONING_DATA));
                BeaconingData->ConnectionId = Connection->ConnectionId;
                BeaconingData->BeaconCount = Connection->SendIntervalCount;
                BeaconingData->AverageIntervalMs = Connection->AverageIntervalMs;
                BeaconingData->JitterPercent = jitterPercent;
                BeaconingData->IsRegularInterval = (jitterPercent < 5);
                BeaconingData->HasJitter = (jitterPercent > 0);
            }

            InterlockedIncrement64(&g_NfState.TotalC2Detections);
        }
    }

    return isBeaconing;
}
