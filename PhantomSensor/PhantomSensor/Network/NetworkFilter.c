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

#pragma warning(push)
#pragma warning(disable:4324)   // structure padded due to __declspec(align()) â€” fltKernel.h
#include "NetworkFilter.h"
#pragma warning(pop)

#include "ConnectionTracker.h"
#include "DnsMonitor.h"
#include "C2Detection.h"
#include "NetworkReputation.h"
#include "SSLInspection.h"
#include "DataExfiltration.h"
#include "PortScanner.h"
#include "ProtocolParser.h"
#include "../Core/Globals.h"
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/StringUtils.h"
#include <ntstrsafe.h>
#include <ip2string.h>
#include "../Behavioral/BehaviorEngine.h"
#include "../ETW/ETWConsumer.h"
#include "../ETW/ETWProvider.h"
#include "../ETW/TelemetryEvents.h"
#include "../Behavioral/ThreatScoring.h"
#include "../Core/DriverEntry.h"
#include "../Sync/TimerManager.h"

// ============================================================================
// GUID DEFINITIONS
// ============================================================================
//
// Direct initialization avoids the INITGUID/DEFINE_GUID hazard: fwpmk.h has
// NO include guard, so any re-inclusion after INITGUID creates duplicate
// storage definitions (C2374). Using DECLSPEC_SELECTANY with direct
// initializers is linker-safe and doesn't require INITGUID at all.
//

// {A5E8F2D1-3B4C-4D5E-9F6A-7B8C9D0E1F2A}
EXTERN_C __declspec(selectany) const GUID SHADOWSTRIKE_WFP_PROVIDER_GUID =
    {0xa5e8f2d1, 0x3b4c, 0x4d5e, {0x9f, 0x6a, 0x7b, 0x8c, 0x9d, 0x0e, 0x1f, 0x2a}};

// {B6F9A3E2-4C5D-5E6F-A071-8C9D0E1F2A3B}
EXTERN_C __declspec(selectany) const GUID SHADOWSTRIKE_WFP_SUBLAYER_GUID =
    {0xb6f9a3e2, 0x4c5d, 0x5e6f, {0xa0, 0x71, 0x8c, 0x9d, 0x0e, 0x1f, 0x2a, 0x3b}};

// {C7A0B4F3-5D6E-6F70-B182-9D0E1F2A3B4C}
EXTERN_C __declspec(selectany) const GUID SHADOWSTRIKE_ALE_CONNECT_V4_CALLOUT_GUID =
    {0xc7a0b4f3, 0x5d6e, 0x6f70, {0xb1, 0x82, 0x9d, 0x0e, 0x1f, 0x2a, 0x3b, 0x4c}};

// {D8B1C5A4-6E7F-7081-C293-0E1F2A3B4C5D}
EXTERN_C __declspec(selectany) const GUID SHADOWSTRIKE_ALE_CONNECT_V6_CALLOUT_GUID =
    {0xd8b1c5a4, 0x6e7f, 0x7081, {0xc2, 0x93, 0x0e, 0x1f, 0x2a, 0x3b, 0x4c, 0x5d}};

// {E9C2D6B5-7F80-8192-D3A4-1F2A3B4C5D6E}
EXTERN_C __declspec(selectany) const GUID SHADOWSTRIKE_ALE_RECV_ACCEPT_V4_CALLOUT_GUID =
    {0xe9c2d6b5, 0x7f80, 0x8192, {0xd3, 0xa4, 0x1f, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e}};

// {F0D3E7C6-8091-92A3-E4B5-2A3B4C5D6E7F}
EXTERN_C __declspec(selectany) const GUID SHADOWSTRIKE_ALE_RECV_ACCEPT_V6_CALLOUT_GUID =
    {0xf0d3e7c6, 0x8091, 0x92a3, {0xe4, 0xb5, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e, 0x7f}};

// {01E4F8D7-91A2-A3B4-F5C6-3B4C5D6E7F80}
EXTERN_C __declspec(selectany) const GUID SHADOWSTRIKE_OUTBOUND_TRANSPORT_V4_CALLOUT_GUID =
    {0x01e4f8d7, 0x91a2, 0xa3b4, {0xf5, 0xc6, 0x3b, 0x4c, 0x5d, 0x6e, 0x7f, 0x80}};

// {23A6BAF9-B2C3-C4D5-D6E7-5D6E7F809102}
EXTERN_C __declspec(selectany) const GUID SHADOWSTRIKE_INBOUND_TRANSPORT_V4_CALLOUT_GUID =
    {0x23a6baf9, 0xb2c3, 0xc4d5, {0xd6, 0xe7, 0x5d, 0x6e, 0x7f, 0x80, 0x91, 0x02}};

// {12F5A9E8-02B3-B4C5-A6D7-4C5D6E7F8091}
EXTERN_C __declspec(selectany) const GUID SHADOWSTRIKE_STREAM_V4_CALLOUT_GUID =
    {0x12f5a9e8, 0x02b3, 0xb4c5, {0xa6, 0xd7, 0x4c, 0x5d, 0x6e, 0x7f, 0x80, 0x91}};

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
#define NF_MAX_DNS_ENTRIES              32768       // Cap DNS tracking to prevent pool exhaustion
#define NF_DNS_HEADER_SIZE              12          // Minimum DNS header
#define NF_MAX_DNS_PACKET_SIZE          65535       // Max DNS packet (TCP max)
#define NF_FORCE_CLOSE_TIMEOUT_MS       1200000     // 20 min â€” force-close non-Closed stale connections

#ifndef MAXUINT32
#define MAXUINT32   ((UINT32)0xFFFFFFFF)
#endif

// ExAllocatePool2 requires Windows 10 2004+ (19041). Zero-initialized, NX by default.

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

// Cleanup timer (managed by TimerManager)
static ULONG g_CleanupTimerId;
static volatile LONG g_CleanupInProgress;

// Subsystem pointers (from other Network modules)
static PCONNECTION_TRACKER g_ConnectionTracker;
static PDNS_MONITOR g_DnsMonitor;
static PC2_DETECTOR g_C2Detector;
static PNR_MANAGER g_ReputationManager;
static PSSL_INSPECTOR g_SslInspector;
static PDX_DETECTOR g_DxDetector;
static PSSPS_DETECTOR g_PortScanner;
static PPP_PARSER g_ProtocolParser;

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
    _In_ ULONG TimerId,
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
NfpProcessInboundDnsResponse(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
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
    _In_ ULONG ProtocolIdx);

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
// PAGE SECTION DIRECTIVES
// ============================================================================

#pragma alloc_text(PAGE, NfFilterInitialize)
#pragma alloc_text(PAGE, NfFilterShutdown)
#pragma alloc_text(PAGE, NfFilterUpdateConfig)
#pragma alloc_text(PAGE, NfpRegisterCallouts)
#pragma alloc_text(PAGE, NfpUnregisterCallouts)
#pragma alloc_text(PAGE, NfpRegisterFilters)
#pragma alloc_text(PAGE, NfpUnregisterFilters)
#pragma alloc_text(PAGE, NfpInitializeHashTables)
#pragma alloc_text(PAGE, NfpCleanupHashTables)
#pragma alloc_text(PAGE, NfpInitializeLookasideLists)
#pragma alloc_text(PAGE, NfpCleanupLookasideLists)
#pragma alloc_text(PAGE, NfpCleanupTimerCallback)
#pragma alloc_text(PAGE, NfpCleanupStaleConnections)
#pragma alloc_text(PAGE, NfpCleanupStaleDnsEntries)
#pragma alloc_text(PAGE, NfpCleanupStalePendingDns)
#pragma alloc_text(PAGE, NfpGetProcessPath)
#pragma alloc_text(PAGE, NfpInsertConnection)
#pragma alloc_text(PAGE, NfpRemoveConnection)
#pragma alloc_text(PAGE, NfpCreateAndInsertConnection)
#pragma alloc_text(PAGE, NfpProcessOutboundConnect)
#pragma alloc_text(PAGE, NfpProcessInboundAccept)
#pragma alloc_text(PAGE, NfpAnalyzeConnection)

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
    // Open WFP engine â€” use DYNAMIC session so objects are auto-cleaned on close
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
    // Register provider â€” NOT persistent (dynamic session cleans up)
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
    // Create periodic cleanup timer via TimerManager (auto-starts)
    //
    g_CleanupInProgress = 0;
    {
        PTM_MANAGER tmMgr = ShadowStrikeGetTimerManager();
        if (tmMgr) {
            TM_TIMER_OPTIONS opts = {0};
            opts.Flags = TmFlag_WorkItemCallback | TmFlag_Coalescable;
            opts.Name = "NfCleanup";

            status = TmCreatePeriodic(
                tmMgr,
                NF_CLEANUP_INTERVAL_MS,
                NfpCleanupTimerCallback,
                NULL,
                &opts,
                &g_CleanupTimerId
                );
            if (!NT_SUCCESS(status)) {
                NfpUnregisterFilters();
                NfpUnregisterCallouts();
                goto CleanupEngine;
            }
        } else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "[ShadowStrike] WARNING: NetworkFilter timer creation failed: TimerManager unavailable\n");
        }
    }

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
    // Initialize network detection sub-modules (non-fatal â€” graceful degradation)
    // Order: ConnectionTracker â†’ DnsMonitor â†’ C2Detection â†’ NetworkReputation â†’
    //        SSLInspection â†’ DataExfiltration
    //
    status = CtInitialize(&g_ConnectionTracker);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/NF] WARNING: ConnectionTracker init failed: 0x%08X (continuing)\n",
                   status);
        g_ConnectionTracker = NULL;
    }

    status = DnsInitialize(&g_DnsMonitor);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/NF] WARNING: DnsMonitor init failed: 0x%08X (continuing)\n",
                   status);
        g_DnsMonitor = NULL;
    }

    status = C2Initialize(DeviceObject, &g_C2Detector);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/NF] WARNING: C2Detection init failed: 0x%08X (continuing)\n",
                   status);
        g_C2Detector = NULL;
    }

    status = NrInitialize(&g_ReputationManager);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/NF] WARNING: NetworkReputation init failed: 0x%08X (continuing)\n",
                   status);
        g_ReputationManager = NULL;
    }

    status = SslInitialize(&g_SslInspector);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/NF] WARNING: SSLInspection init failed: 0x%08X (continuing)\n",
                   status);
        g_SslInspector = NULL;
    }

    status = DxInitialize(&g_DxDetector);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/NF] WARNING: DataExfiltration init failed: 0x%08X (continuing)\n",
                   status);
        g_DxDetector = NULL;
    }

    status = SsPsInitialize(&g_PortScanner);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/NF] WARNING: PortScanner init failed: 0x%08X (continuing)\n",
                   status);
        g_PortScanner = NULL;
    }

    status = PpInitialize(&g_ProtocolParser);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/NF] WARNING: ProtocolParser init failed: 0x%08X (continuing)\n",
                   status);
        g_ProtocolParser = NULL;
    }

    //
    // Reset status â€” sub-module failures are non-fatal
    //
    status = STATUS_SUCCESS;

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
    // Cancel cleanup timer and wait for in-flight callback
    //
    {
        PTM_MANAGER tmMgr = ShadowStrikeGetTimerManager();
        if (tmMgr && g_CleanupTimerId != 0) {
            TmCancel(tmMgr, g_CleanupTimerId, TRUE);
        }
    }

    //
    // Safety: wait for any in-progress cleanup to complete
    //
    timeout.QuadPart = -10000000LL;  // 1 second
    while (InterlockedCompareExchange(&g_CleanupInProgress, 0, 0) != 0) {
        KeDelayExecutionThread(KernelMode, FALSE, &timeout);
    }

    //
    // Unregister WFP filters and callouts FIRST â€” this drains in-flight
    // classify callbacks so sub-module pointers are no longer accessed
    // from WFP context.  Only then is it safe to destroy sub-modules.
    //
    NfpUnregisterFilters();
    NfpUnregisterCallouts();

    //
    // Shutdown network detection sub-modules (reverse init order).
    // WFP callouts are fully drained at this point â€” no UAF risk.
    //
    if (g_ProtocolParser != NULL) {
        PpShutdown(&g_ProtocolParser);
        g_ProtocolParser = NULL;
    }

    if (g_PortScanner != NULL) {
        SsPsShutdown(g_PortScanner);
        g_PortScanner = NULL;
    }

    if (g_DxDetector != NULL) {
        DxShutdown(g_DxDetector);
        g_DxDetector = NULL;
    }

    if (g_SslInspector != NULL) {
        SslShutdown(g_SslInspector);
        g_SslInspector = NULL;
    }

    if (g_ReputationManager != NULL) {
        NrShutdown(g_ReputationManager);
        g_ReputationManager = NULL;
    }

    if (g_C2Detector != NULL) {
        C2Shutdown(g_C2Detector);
        g_C2Detector = NULL;
    }

    if (g_DnsMonitor != NULL) {
        DnsShutdown(g_DnsMonitor);
        g_DnsMonitor = NULL;
    }

    if (g_ConnectionTracker != NULL) {
        CtShutdown(g_ConnectionTracker);
        g_ConnectionTracker = NULL;
    }

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
        PNF_PENDING_DNS pendingDns;
        entry = RemoveHeadList(&g_PendingDnsList);
        pendingDns = CONTAINING_RECORD(entry, NF_PENDING_DNS, ListEntry);
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
        // RefCount underflow â€” serious bug. Clamp to 0 and log.
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
    // Allocate BEFORE locking to minimize time under exclusive lock
    //
    blockedEntry = (PNF_BLOCKED_DOMAIN)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(NF_BLOCKED_DOMAIN),
        NF_POOL_TAG_DNS
        );

    if (blockedEntry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // ExAllocatePool2 zero-initializes; no RtlZeroMemory needed
    blockedEntry->DomainHash = domainHash;
    blockedEntry->Reason = Reason;

    RtlStringCchCopyW(blockedEntry->DomainName, MAX_DNS_NAME_LENGTH, DomainName);

    //
    // Atomic check-and-insert under exclusive lock to prevent TOCTOU duplicates
    //
    FltAcquirePushLockExclusive(&g_NfState.DnsLock);

    {
        BOOLEAN duplicate = FALSE;

        for (entry = g_NfState.BlockedDomainList.Flink;
             entry != &g_NfState.BlockedDomainList;
             entry = entry->Flink) {

            existing = CONTAINING_RECORD(entry, NF_BLOCKED_DOMAIN, ListEntry);
            if (existing->DomainHash == domainHash &&
                _wcsicmp(existing->DomainName, DomainName) == 0) {
                duplicate = TRUE;
                break;
            }
        }

        if (duplicate) {
            FltReleasePushLock(&g_NfState.DnsLock);
            ExFreePoolWithTag(blockedEntry, NF_POOL_TAG_DNS);
            return STATUS_SUCCESS;
        }

        if ((ULONG)InterlockedCompareExchange(&g_NfState.BlockedDomainCount, 0, 0)
                >= NF_MAX_BLOCKED_DOMAINS) {
            FltReleasePushLock(&g_NfState.DnsLock);
            ExFreePoolWithTag(blockedEntry, NF_POOL_TAG_DNS);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        InsertTailList(&g_NfState.BlockedDomainList, &blockedEntry->ListEntry);
        InterlockedIncrement(&g_NfState.BlockedDomainCount);
    }

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
        while (len < 33 && JA3Fingerprint[len] != '\0') {
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
// TELEMETRY HELPERS
// ============================================================================

/**
 * @brief Emit a TE_NETWORK_EVENT for a detected network threat.
 *
 * Allocates from NonPagedPool because TE_NETWORK_EVENT is ~1.2KB,
 * too large for the stack at DISPATCH_LEVEL (WFP classify context).
 */
static
VOID
NfpEmitNetworkTelemetry(
    _In_ TE_EVENT_ID EventId,
    _In_ PNF_CONNECTION_ENTRY Connection,
    _In_ UINT32 ThreatScore,
    _In_ UINT32 TeNetFlags
    )
{
    PTE_NETWORK_EVENT netEvent;

    netEvent = (PTE_NETWORK_EVENT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(TE_NETWORK_EVENT), 'tENF');
    if (netEvent == NULL) {
        return;
    }

    RtlZeroMemory(netEvent, sizeof(TE_NETWORK_EVENT));

    netEvent->Header.Size = sizeof(TE_NETWORK_EVENT);
    netEvent->Header.EventId = (UINT32)EventId;
    netEvent->Header.ProcessId = Connection->ProcessId;

    netEvent->Protocol = (UINT32)Connection->Protocol;
    netEvent->Direction = (UINT32)Connection->Direction;
    netEvent->LocalPort = Connection->LocalAddress.Port;
    netEvent->RemotePort = Connection->RemoteAddress.Port;

    if (Connection->RemoteAddress.Address.Family == AF_INET) {
        netEvent->LocalAddressV4 = Connection->LocalAddress.Address.V4.Address;
        netEvent->RemoteAddressV4 = Connection->RemoteAddress.Address.V4.Address;
    } else if (Connection->RemoteAddress.Address.Family == AF_INET6) {
        RtlCopyMemory(netEvent->LocalAddressV6,
                       Connection->LocalAddress.Address.V6.Bytes, 16);
        RtlCopyMemory(netEvent->RemoteAddressV6,
                       Connection->RemoteAddress.Address.V6.Bytes, 16);
    }

    netEvent->BytesSent = Connection->BytesSent;
    netEvent->BytesReceived = Connection->BytesReceived;
    netEvent->ThreatScore = ThreatScore;
    netEvent->ThreatType = (UINT32)Connection->ThreatType;
    netEvent->Flags = TeNetFlags;

    RtlStringCchCopyW(netEvent->RemoteHostname,
                       RTL_NUMBER_OF(netEvent->RemoteHostname),
                       Connection->RemoteHostname);
    RtlStringCchCopyW(netEvent->ProcessPath,
                       RTL_NUMBER_OF(netEvent->ProcessPath),
                       Connection->ProcessImagePath);

    TeLogNetworkEvent(EventId, netEvent);

    ExFreePoolWithTag(netEvent, 'tENF');
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

    //
    // Transport layer classify can be at DISPATCH_LEVEL for forwarded/injected
    // packets. Our DNS processing uses push locks which require <= APC_LEVEL.
    // For outbound UDP sends from user threads this is always PASSIVE, but
    // guard against unexpected DISPATCH calls to prevent bugcheck.
    //
    if (KeGetCurrentIrql() > APC_LEVEL) {
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
 * @brief Inbound transport classify for DNS responses (source port 53).
 *
 * Captures DNS response packets from recursive resolvers so DnsProcessResponse
 * can correlate answers with pending queries and detect fast-flux, DGA with
 * NXDOMAIN ratios, and response-based tunneling.
 */
VOID NTAPI
NfInboundTransportClassify(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER3* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
    )
{
    UINT16 sourcePort;

    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    if (!NfpIsInitialized() || !NfpIsEnabled()) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    if (KeGetCurrentIrql() > APC_LEVEL) {
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

    sourcePort = inFixedValues->incomingValue[
        FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;

    if (sourcePort == NF_DNS_PORT) {
        if (NfpCheckRateLimit()) {
            NfpProcessInboundDnsResponse(inFixedValues, layerData, classifyOut);
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
    UNREFERENCED_PARAMETER(flowContext);

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
        //
        // Use flow handle from metadata (not flowContext, which requires
        // FwpsFlowAssociateContext0 at the stream layer).
        //
        UINT64 streamFlowHandle = 0;
        if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_FLOW_HANDLE)) {
            streamFlowHandle = inMetaValues->flowHandle;
        }
        NfpProcessStreamData(inFixedValues, inMetaValues, streamPacket,
                             streamFlowHandle, classifyOut);
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
        // Log for diagnostics â€” may indicate policy tampering.
        //
        break;

    default:
        break;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Flow delete notify function.
 *
 * Called when a WFP flow terminates. The flowContext is the ConnectionId
 * that we associated via FwpsFlowAssociateContext0 during ALE classify.
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

    if (!NfpIsInitialized() || flowContext == 0) {
        return;
    }

    //
    // flowContext is the ConnectionId we stored via FwpsFlowAssociateContext0
    //
    status = NfFilterFindConnection(flowContext, &connection);
    if (NT_SUCCESS(status)) {
        InterlockedExchange((LONG*)&connection->State, (LONG)ConnectionState_Closed);

        //
        // === Beaconing Detection on Connection Close (T1071/T1573) ===
        // Analyze the completed connection's send-interval pattern for
        // periodic beaconing behavior. This is the ideal time â€” the full
        // timing history is available and no further data will arrive.
        //
        {
            BEACONING_DATA beaconData;
            RtlZeroMemory(&beaconData, sizeof(beaconData));

            if (NfFilterDetectBeaconing(connection->ConnectionId, &beaconData)) {
                InterlockedOr(
                    (LONG*)&connection->Flags,
                    NF_CONN_FLAG_BEACONING);

                BeEngineSubmitEvent(
                    BehaviorEvent_C2Communication,
                    BehaviorCategory_NetworkOperation,
                    connection->ProcessId,
                    NULL,
                    0,
                    75,
                    FALSE,
                    NULL
                );

                if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
                    PTS_SCORING_ENGINE tsEngine = (PTS_SCORING_ENGINE)ShadowStrikeGetThreatScoringEngine();
                    if (tsEngine != NULL) {
                        TsAddFactor(tsEngine, (HANDLE)(ULONG_PTR)connection->ProcessId,
                            TsFactor_Behavioral, "NetworkBeaconing",
                            75, "Beaconing pattern detected (T1071)");
                    }
                }

                TeLogThreatDetection(
                    connection->ProcessId,
                    L"Network.Beaconing",
                    75,
                    ThreatSeverity_Medium,
                    0x042F,
                    L"Beaconing pattern detected (T1071)",
                    0
                );

                NfpEmitNetworkTelemetry(TeEvent_NetBeaconing, connection,
                                        75, TE_NET_FLAG_BEACONING);

                InterlockedIncrement64(&g_NfState.TotalC2Detections);
            }
        }

        //
        // === Exfiltration Detection on Connection Close (T1041) ===
        // Check final send/receive ratio for asymmetric data transfer
        // indicative of data exfiltration.
        //
        {
            NETWORK_EXFIL_EVENT exfilEvent;
            RtlZeroMemory(&exfilEvent, sizeof(exfilEvent));

            if (NfFilterDetectExfiltration(connection->ConnectionId, &exfilEvent)) {
                BeEngineSubmitEvent(
                    BehaviorEvent_DataExfiltration,
                    BehaviorCategory_NetworkOperation,
                    connection->ProcessId,
                    NULL,
                    0,
                    65,
                    FALSE,
                    NULL
                );

                if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
                    PTS_SCORING_ENGINE tsEngine = (PTS_SCORING_ENGINE)ShadowStrikeGetThreatScoringEngine();
                    if (tsEngine != NULL) {
                        TsAddFactor(tsEngine, (HANDLE)(ULONG_PTR)connection->ProcessId,
                            TsFactor_Behavioral, "DataExfiltration",
                            65, "Data exfiltration detected (T1041)");
                    }
                }

                TeLogThreatDetection(
                    connection->ProcessId,
                    L"Network.Exfiltration",
                    65,
                    ThreatSeverity_Medium,
                    0x0411,
                    L"Data exfiltration pattern detected (T1041)",
                    0
                );
            }
        }

        //
        // C2 process-level analysis on connection close (T1071) â€” aggregate
        // all connection data for this process to detect C2 patterns.
        //
        if (g_C2Detector != NULL) {
            PC2_DETECTION_RESULT c2ProcResult = NULL;
            NTSTATUS c2ProcStatus = C2AnalyzeProcess(
                g_C2Detector,
                (HANDLE)(ULONG_PTR)connection->ProcessId,
                &c2ProcResult
            );

            if (NT_SUCCESS(c2ProcStatus) && c2ProcResult != NULL) {
                if (c2ProcResult->C2Detected) {
                    InterlockedOr(
                        (LONG*)&connection->Flags,
                        NF_CONN_FLAG_C2_SUSPECT);

                    if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
                        PTS_SCORING_ENGINE tsEngine = (PTS_SCORING_ENGINE)ShadowStrikeGetThreatScoringEngine();
                        if (tsEngine != NULL) {
                            TsAddFactor(tsEngine, (HANDLE)(ULONG_PTR)connection->ProcessId,
                                TsFactor_Behavioral, "C2ProcessAnalysis",
                                (LONG)c2ProcResult->ConfidenceScore,
                                "Process-level C2 analysis detection (T1071)");
                        }
                    }

                    TeLogThreatDetection(
                        connection->ProcessId,
                        L"Network.C2ProcessAnalysis",
                        c2ProcResult->ConfidenceScore,
                        (c2ProcResult->ConfidenceScore >= 80)
                            ? ThreatSeverity_High : ThreatSeverity_Medium,
                        0x042F,
                        L"Process-level C2 communication detected (T1071)",
                        (c2ProcResult->ConfidenceScore >= 80) ? 1 : 0
                    );
                }
                C2FreeResult(c2ProcResult);
            }
        }

        //
        // Transition connection in ConnectionTracker to Closed.
        // Uses WFP FlowId which was stored at NfpCreateAndInsertConnection time.
        // Update state to Closed before removing â€” allows ConnectionTracker
        // to record final state for forensics/telemetry before cleanup.
        //
        if (g_ConnectionTracker != NULL && connection->FlowId != 0) {
            (VOID)CtUpdateConnectionState(
                g_ConnectionTracker,
                connection->FlowId,
                CtState_Closed
            );
            CtRemoveConnection(g_ConnectionTracker, connection->FlowId);
        }

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

    PAGED_CODE();

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
    // Inbound Transport v4 (DNS responses)
    //
    sCallout.calloutKey = SHADOWSTRIKE_INBOUND_TRANSPORT_V4_CALLOUT_GUID;
    sCallout.classifyFn = NfInboundTransportClassify;
    sCallout.flowDeleteFn = NULL;
    sCallout.flags = 0;

    status = FwpsCalloutRegister3(DeviceObject, &sCallout,
                                  &g_NfState.InboundTransportV4CalloutId);
    if (!NT_SUCCESS(status)) {
        goto CleanupOutboundTransport;
    }

    displayData.name = L"ShadowStrike Inbound Transport v4";
    displayData.description = L"Captures DNS response packets";

    mCallout.calloutKey = SHADOWSTRIKE_INBOUND_TRANSPORT_V4_CALLOUT_GUID;
    mCallout.displayData = displayData;
    mCallout.applicableLayer = FWPM_LAYER_INBOUND_TRANSPORT_V4;

    status = FwpmCalloutAdd0(g_NfState.WfpEngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        FwpsCalloutUnregisterById0(g_NfState.InboundTransportV4CalloutId);
        goto CleanupOutboundTransport;
    }

    //
    // Stream v4 (TCP data)
    // NOTE: Do NOT use FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW here.
    // We don't associate flow context at the stream layer, so the flag
    // would prevent the classify from ever being invoked.
    //
    sCallout.calloutKey = SHADOWSTRIKE_STREAM_V4_CALLOUT_GUID;
    sCallout.classifyFn = NfStreamClassify;
    sCallout.flags = 0;

    status = FwpsCalloutRegister3(DeviceObject, &sCallout,
                                  &g_NfState.StreamV4CalloutId);
    if (!NT_SUCCESS(status)) {
        goto CleanupInboundTransport;
    }

    displayData.name = L"ShadowStrike Stream v4";
    displayData.description = L"Inspects TCP stream data";

    mCallout.calloutKey = SHADOWSTRIKE_STREAM_V4_CALLOUT_GUID;
    mCallout.displayData = displayData;
    mCallout.applicableLayer = FWPM_LAYER_STREAM_V4;

    status = FwpmCalloutAdd0(g_NfState.WfpEngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        FwpsCalloutUnregisterById0(g_NfState.StreamV4CalloutId);
        goto CleanupInboundTransport;
    }

    return STATUS_SUCCESS;

CleanupInboundTransport:
    FwpsCalloutUnregisterById0(g_NfState.InboundTransportV4CalloutId);
CleanupOutboundTransport:
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
    PAGED_CODE();

    if (g_NfState.StreamV4CalloutId != 0) {
        FwpsCalloutUnregisterById0(g_NfState.StreamV4CalloutId);
        g_NfState.StreamV4CalloutId = 0;
    }
    if (g_NfState.InboundTransportV4CalloutId != 0) {
        FwpsCalloutUnregisterById0(g_NfState.InboundTransportV4CalloutId);
        g_NfState.InboundTransportV4CalloutId = 0;
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

    PAGED_CODE();

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

    // Inbound Transport v4 (DNS responses)
    filter.displayData.name = L"ShadowStrike Inbound Transport v4 Filter";
    filter.displayData.description = L"Capture DNS response packets";
    filter.layerKey = FWPM_LAYER_INBOUND_TRANSPORT_V4;
    filter.action.calloutKey = SHADOWSTRIKE_INBOUND_TRANSPORT_V4_CALLOUT_GUID;

    status = FwpmFilterAdd0(g_NfState.WfpEngineHandle, &filter, NULL,
                            &g_NfState.InboundTransportV4FilterId);
    if (!NT_SUCCESS(status)) goto CleanupOutboundTransport;

    // Stream v4
    filter.displayData.name = L"ShadowStrike Stream v4 Filter";
    filter.displayData.description = L"Inspect TCP stream data";
    filter.layerKey = FWPM_LAYER_STREAM_V4;
    filter.action.calloutKey = SHADOWSTRIKE_STREAM_V4_CALLOUT_GUID;

    status = FwpmFilterAdd0(g_NfState.WfpEngineHandle, &filter, NULL,
                            &g_NfState.StreamV4FilterId);
    if (!NT_SUCCESS(status)) goto CleanupInboundTransport;

    return STATUS_SUCCESS;

CleanupInboundTransport:
    FwpmFilterDeleteById0(g_NfState.WfpEngineHandle, g_NfState.InboundTransportV4FilterId);
CleanupOutboundTransport:
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
    PAGED_CODE();

    if (g_NfState.WfpEngineHandle == NULL) return;

    if (g_NfState.StreamV4FilterId != 0) {
        FwpmFilterDeleteById0(g_NfState.WfpEngineHandle, g_NfState.StreamV4FilterId);
        g_NfState.StreamV4FilterId = 0;
    }
    if (g_NfState.InboundTransportV4FilterId != 0) {
        FwpmFilterDeleteById0(g_NfState.WfpEngineHandle, g_NfState.InboundTransportV4FilterId);
        g_NfState.InboundTransportV4FilterId = 0;
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

    PAGED_CODE();

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
    PAGED_CODE();

    // Static arrays â€” no dynamic memory to free.
    // Entries are freed during connection/dns cleanup.
}

static NTSTATUS
NfpInitializeLookasideLists(VOID)
{
    PAGED_CODE();
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
    PAGED_CODE();
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
        //
        // If this connection had a TLS session tracked by SSLInspection,
        // remove it to prevent NonPaged pool leaks (SSL2-02).
        //
        if (Connection->TlsHandshakeComplete && g_SslInspector != NULL &&
            KeGetCurrentIrql() <= APC_LEVEL) {
            BOOLEAN isV6 = (Connection->RemoteAddress.Address.Family == 23);
            SslRemoveSession(
                g_SslInspector,
                isV6 ? (PVOID)&Connection->RemoteAddress.Address.V6
                      : (PVOID)&Connection->RemoteAddress.Address.V4,
                Connection->RemoteAddress.Port,
                isV6);
        }

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

    //
    // Hash the actual address bytes (V4.Bytes or V6.Bytes), NOT the
    // SS_IP_ADDRESS header (Family+Reserved precede the address union).
    //
    if (Local->Address.Family == AF_INET) {
        addrLen = 4;
        bytes = Local->Address.V4.Bytes;
    } else {
        addrLen = 16;
        bytes = Local->Address.V6.Bytes;
    }

    for (i = 0; i < addrLen; i++) {
        hash = ((hash << 5) + hash) + bytes[i];
    }

    hash = ((hash << 5) + hash) + (Local->Port & 0xFF);
    hash = ((hash << 5) + hash) + ((Local->Port >> 8) & 0xFF);

    if (Remote->Address.Family == AF_INET) {
        addrLen = 4;
        bytes = Remote->Address.V4.Bytes;
    } else {
        addrLen = 16;
        bytes = Remote->Address.V6.Bytes;
    }

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

    PAGED_CODE();

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
    epEntry = (PNF_CONNECTION_HASH_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(NF_CONNECTION_HASH_ENTRY), NF_POOL_TAG_CONNECTION);
    if (epEntry == NULL) goto AllocFail;

    flowEntry = (PNF_CONNECTION_HASH_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(NF_CONNECTION_HASH_ENTRY), NF_POOL_TAG_CONNECTION);
    if (flowEntry == NULL) goto AllocFail;

    idEntry = (PNF_CONNECTION_HASH_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(NF_CONNECTION_HASH_ENTRY), NF_POOL_TAG_CONNECTION);
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

    PAGED_CODE();

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
 * @brief Periodic cleanup callback â€” runs at PASSIVE_LEVEL via TmFlag_WorkItemCallback.
 */
static VOID
NfpCleanupTimerCallback(
    _In_ ULONG TimerId,
    _In_opt_ PVOID Context
    )
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(TimerId);
    UNREFERENCED_PARAMETER(Context);

    if (InterlockedCompareExchange(&g_CleanupInProgress, 1, 0) != 0) {
        return;
    }

    if (NfpIsInitialized()) {
        NfpCleanupStaleConnections();
        NfpCleanupStaleDnsEntries();
        NfpCleanupStalePendingDns();

        //
        // Evict stale SSL sessions â€” prevents NonPaged pool exhaustion
        // and STATUS_QUOTA_EXCEEDED after 65536 accumulated sessions.
        //
        if (g_SslInspector != NULL) {
            SslCleanupStaleSessions(g_SslInspector);
        }
    }

    InterlockedExchange(&g_CleanupInProgress, 0);
}

/**
 * @brief Cleanup stale connections.
 *
 * Phase 1: Collect candidate stale connections under shared lock (increment ref).
 * Phase 2: Re-verify under exclusive lock (decrement ref, check again).
 *          Only remove + free if ref == 0 under exclusive lock â€” prevents
 *          use-after-free from concurrent FindConnection taking a reference
 *          between Phase 1 scan and Phase 2 removal.
 */
static VOID
NfpCleanupStaleConnections(VOID)
{
    PLIST_ENTRY entry;
    PNF_CONNECTION_ENTRY connection;
    LARGE_INTEGER currentTime;
    UINT64 currentTimeMs;

    PNF_CONNECTION_ENTRY staleConnections[64];
    ULONG staleCount = 0;
    ULONG i;

    PAGED_CODE();

    KeQuerySystemTime(&currentTime);
    currentTimeMs = (UINT64)(currentTime.QuadPart / 10000);

    //
    // Phase 1: Identify candidate stale connections under shared lock
    //
    FltAcquirePushLockShared(&g_NfState.ConnectionLock);

    for (entry = g_NfState.ConnectionList.Flink;
         entry != &g_NfState.ConnectionList;
         entry = entry->Flink) {

        connection = CONTAINING_RECORD(entry, NF_CONNECTION_ENTRY, ListEntry);

        if (connection->RefCount > 0) {
            continue;
        }

        {
            BOOLEAN isCandidate = FALSE;

            if (connection->State == ConnectionState_Closed &&
                (currentTimeMs - connection->LastActivityTime) > NF_CONNECTION_TIMEOUT_MS) {
                isCandidate = TRUE;
            } else if (connection->State != ConnectionState_Closed &&
                       (currentTimeMs - connection->LastActivityTime) > NF_FORCE_CLOSE_TIMEOUT_MS) {
                isCandidate = TRUE;
            }

            if (isCandidate && staleCount < ARRAYSIZE(staleConnections)) {
                InterlockedIncrement(&connection->RefCount);
                staleConnections[staleCount++] = connection;
            }
        }
    }

    FltReleasePushLock(&g_NfState.ConnectionLock);

    //
    // Phase 2: Re-verify under exclusive lock to prevent use-after-free.
    // Under exclusive lock, no concurrent FindConnection can take a new reference.
    //
    for (i = 0; i < staleCount; i++) {
        BOOLEAN shouldFree = FALSE;
        PNF_CONNECTION_HASH_ENTRY foundEp = NULL;
        PNF_CONNECTION_HASH_ENTRY foundFlow = NULL;
        PNF_CONNECTION_HASH_ENTRY foundId = NULL;
        UINT32 hashIdx;
        PLIST_ENTRY hashEntry;
        PNF_CONNECTION_HASH_ENTRY hEntry;

        connection = staleConnections[i];

        FltAcquirePushLockExclusive(&g_NfState.ConnectionLock);

        //
        // Release our scan reference under the lock.
        // Under exclusive lock, nobody can call FindConnection (requires shared lock).
        //
        InterlockedDecrement(&connection->RefCount);

        if (connection->RefCount <= 0) {
            //
            // Safe to remove â€” no other thread holds a reference
            //
            RemoveEntryList(&connection->ListEntry);
            InterlockedDecrement(&g_NfState.ConnectionCount);

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
                    foundEp = hEntry;
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
                    foundFlow = hEntry;
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
                    foundId = hEntry;
                    break;
                }
            }

            shouldFree = TRUE;
        }
        //
        // else: Another thread took a reference between Phase 1 and now.
        // Leave connection in tables for next cleanup cycle.
        //

        FltReleasePushLock(&g_NfState.ConnectionLock);

        if (shouldFree) {
            if (foundEp != NULL) ExFreePoolWithTag(foundEp, NF_POOL_TAG_CONNECTION);
            if (foundFlow != NULL) ExFreePoolWithTag(foundFlow, NF_POOL_TAG_CONNECTION);
            if (foundId != NULL) ExFreePoolWithTag(foundId, NF_POOL_TAG_CONNECTION);
            NfpFreeConnection(connection);
        }
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

    PAGED_CODE();

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

    PAGED_CODE();

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

    PAGED_CODE();

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

    if (SS_IS_IPV6(Address)) {
        PUCHAR bytes = Address->V6.Bytes;

        // fc00::/7 â€” Unique Local Address (ULA)
        if ((bytes[0] & 0xFE) == 0xFC) return TRUE;

        // fe80::/10 â€” Link-local
        if (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80) return TRUE;
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

    PAGED_CODE();

    UNREFERENCED_PARAMETER(FlowContext);

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

    //
    // Emit network connect event into ETW consumer pipeline
    //
    {
        PEC_CONSUMER EtwConsumer = ShadowStrikeGetETWConsumer();
        if (EtwConsumer != NULL) {
            EcEmitKernelEvent(
                EtwConsumer,
                &GUID_KERNEL_NETWORK_PROVIDER,
                EC_EVENTID_NETWORK_CONNECT,
                4, // Information
                0xFFFFFFFFFFFFFFFFULL,
                (ULONG)processId,
                HandleToULong(PsGetCurrentThreadId()),
                NULL, 0);
        }
    }

    //
    // Emit network connect to external ETW provider for SIEM consumers.
    // Full ETW_NETWORK_EVENT populated downstream after connection setup;
    // here we emit a lightweight notification for immediate visibility.
    //
    {
        ETW_NETWORK_EVENT nfEtwEvent;
        RtlZeroMemory(&nfEtwEvent, sizeof(nfEtwEvent));
        nfEtwEvent.Common.ProcessId = (UINT32)processId;
        nfEtwEvent.Protocol = (UINT32)protocol;
        nfEtwEvent.Direction = (UINT32)Direction;
        nfEtwEvent.RemotePort = remotePort;
        nfEtwEvent.LocalPort = localPort;
        EtwWriteNetworkEvent(EtwEventId_NetworkConnect, &nfEtwEvent);
    }

    connection = NfpAllocateConnection();
    if (connection == NULL) {
        return;
    }

    connection->ConnectionId = (UINT64)InterlockedIncrement64(&g_NfState.NextConnectionId);

    //
    // Use WFP flow handle for flow tracking â€” NOT the classify flowContext
    // parameter, which is always 0 unless FwpsFlowAssociateContext0 is called
    // at this layer. The flow handle uniquely identifies flows across layers.
    //
    if (FWPS_IS_METADATA_FIELD_PRESENT(InMetaValues, FWPS_METADATA_FIELD_FLOW_HANDLE)) {
        connection->FlowId = InMetaValues->flowHandle;
    } else {
        connection->FlowId = 0;
    }

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
    if (NfpIsPrivateAddress(&connection->RemoteAddress.Address) ||
        NfpIsLoopbackAddress(&connection->RemoteAddress.Address)) {
        //
        // NF-PERF: Tag private/loopback connections so NfpProcessStreamData
        // can skip expensive C2/DLP analysis on local traffic.
        //
        InterlockedOr((LONG*)&connection->Flags, NF_CONN_FLAG_PRIVATE_NET);
    } else {
        InterlockedOr((LONG*)&connection->Flags, NF_CONN_FLAG_FIRST_CONTACT);
    }

    status = NfpInsertConnection(connection);
    if (!NT_SUCCESS(status)) {
        NfpFreeConnection(connection);
        return;
    }

    //
    // Associate flow context at the ALE layer so NfFlowDeleteNotify receives
    // our ConnectionId when the flow terminates. This enables proper connection
    // lifecycle tracking (mark as Closed on flow end).
    //
    if (connection->FlowId != 0) {
        UINT32 calloutId = 0;

        switch (InFixedValues->layerId) {
            case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
                calloutId = g_NfState.AleConnectV4CalloutId; break;
            case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
                calloutId = g_NfState.AleConnectV6CalloutId; break;
            case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
                calloutId = g_NfState.AleRecvAcceptV4CalloutId; break;
            case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
                calloutId = g_NfState.AleRecvAcceptV6CalloutId; break;
        }

        if (calloutId != 0) {
            FwpsFlowAssociateContext0(
                connection->FlowId,
                InFixedValues->layerId,
                calloutId,
                connection->ConnectionId
                );
        }
    }

    NfpAnalyzeConnection(connection);

    //
    // Feed connection into ConnectionTracker for per-process network context,
    // 5-tuple lookup, state machine, and bandwidth monitoring.
    //
    if (g_ConnectionTracker != NULL) {
        PVOID ctLocalAddr = IsV6 ? (PVOID)localIp6 : (PVOID)&localIp;
        PVOID ctRemoteAddr = IsV6 ? (PVOID)remoteIp6 : (PVOID)&remoteIp;
        CT_DIRECTION ctDir = (Direction == NetworkDirection_Outbound)
            ? CtDirection_Outbound : CtDirection_Inbound;
        PCT_CONNECTION ctConn = NULL;

        NTSTATUS ctStatus = CtCreateConnection(
            g_ConnectionTracker,
            connection->FlowId,
            (HANDLE)(ULONG_PTR)processId,
            ctDir,
            protocol,
            ctLocalAddr,
            localPort,
            ctRemoteAddr,
            remotePort,
            IsV6,
            &ctConn
        );

        if (NT_SUCCESS(ctStatus) && ctConn != NULL) {
            CtRelease(ctConn);
        }
    }

    //
    // Feed connection to C2Detection for beaconing/IOC analysis (T1071/T1573).
    // Passes the raw remote address pointer â€” C2RecordConnection copies it.
    //
    if (g_C2Detector != NULL) {
        PVOID remoteAddr = IsV6 ? (PVOID)remoteIp6 : (PVOID)&remoteIp;

        //
        // C2 IOC check (T1071) â€” check if the destination is a known C2
        // indicator of compromise before recording the connection.
        //
        {
            BOOLEAN isKnownC2 = FALSE;
            NTSTATUS iocStatus = C2CheckIOC(
                g_C2Detector,
                remoteAddr,
                IsV6,
                NULL,
                &isKnownC2,
                NULL
            );

            if (NT_SUCCESS(iocStatus) && isKnownC2) {
                InterlockedOr(
                    (LONG*)&connection->Flags,
                    NF_CONN_FLAG_C2_SUSPECT | NF_CONN_FLAG_SUSPICIOUS);

                BeEngineSubmitEvent(
                    BehaviorEvent_C2Communication,
                    BehaviorCategory_NetworkOperation,
                    connection->ProcessId,
                    NULL,
                    0,
                    90,
                    TRUE,
                    NULL
                );

                if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
                    PTS_SCORING_ENGINE tsEngine = (PTS_SCORING_ENGINE)ShadowStrikeGetThreatScoringEngine();
                    if (tsEngine != NULL) {
                        TsAddFactor(tsEngine, (HANDLE)(ULONG_PTR)connection->ProcessId,
                            TsFactor_IOC, "KnownC2IOC",
                            90, "Connection to known C2 IOC detected");
                    }
                }

                TeLogThreatDetection(
                    connection->ProcessId,
                    L"Network.KnownC2IOC",
                    90,
                    ThreatSeverity_High,
                    0x042F,
                    L"Connection to known C2 indicator of compromise",
                    1
                );

                NfpEmitNetworkTelemetry(TeEvent_NetC2Detected, connection,
                                        90, TE_NET_FLAG_C2);
            }
        }

        C2RecordConnection(
            g_C2Detector,
            (HANDLE)(ULONG_PTR)processId,
            remoteAddr,
            remotePort,
            IsV6,
            NULL
        );

        //
        // C2 destination analysis (T1071/T1573) â€” analyze the remote endpoint
        // for known C2 patterns, IOC matches, and behavioral indicators.
        // C2AnalyzeDestination aggregates beaconing, reputation, IOC, and JA3
        // data to produce a composite C2 confidence score.
        //
        {
            PC2_DETECTION_RESULT c2Result = NULL;
            NTSTATUS c2Status = C2AnalyzeDestination(
                g_C2Detector,
                remoteAddr,
                remotePort,
                IsV6,
                &c2Result
            );

            if (NT_SUCCESS(c2Status) && c2Result != NULL) {
                if (c2Result->C2Detected) {
                    InterlockedOr(
                        (LONG*)&connection->Flags,
                        NF_CONN_FLAG_C2_SUSPECT);
                    connection->ThreatScore = max(
                        connection->ThreatScore,
                        c2Result->SeverityScore);

                    BeEngineSubmitEvent(
                        BehaviorEvent_C2Communication,
                        BehaviorCategory_NetworkOperation,
                        connection->ProcessId,
                        NULL,
                        0,
                        c2Result->ConfidenceScore,
                        (c2Result->ConfidenceScore >= 80),
                        NULL
                    );

                    if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
                        PTS_SCORING_ENGINE tsEngine = (PTS_SCORING_ENGINE)ShadowStrikeGetThreatScoringEngine();
                        if (tsEngine != NULL) {
                            TsAddFactor(tsEngine, (HANDLE)(ULONG_PTR)connection->ProcessId,
                                TsFactor_Behavioral, "C2Communication",
                                (LONG)c2Result->ConfidenceScore,
                                "C2 destination detected (T1071)");
                        }
                    }

                    TeLogThreatDetection(
                        connection->ProcessId,
                        L"Network.C2Detected",
                        c2Result->ConfidenceScore,
                        (c2Result->ConfidenceScore >= 80)
                            ? ThreatSeverity_High : ThreatSeverity_Medium,
                        0x042F,
                        L"C2 communication detected (T1071)",
                        (c2Result->ConfidenceScore >= 80) ? 1 : 0
                    );
                }
                C2FreeResult(c2Result);
            }
        }
    }

    //
    // Feed connection to PortScanner for reconnaissance detection (T1046)
    //
    if (g_PortScanner != NULL) {
        LARGE_INTEGER processCreateTime = {0};
        SsPsRecordConnection(
            g_PortScanner,
            (HANDLE)(ULONG_PTR)processId,
            processCreateTime,
            IsV6 ? (PVOID)remoteIp6 : (PVOID)&remoteIp,
            remotePort,
            IsV6,
            protocol,
            (protocol == IPPROTO_TCP) ? SSPS_TCP_FLAG_SYN : 0,
            TRUE
        );

        //
        // Port scan detection (T1046) â€” check if this process has accumulated
        // enough connection attempts to trigger port scan detection.
        // SsPsCheckForScan returns a detection result when the scanner
        // determines that the process is conducting network reconnaissance.
        //
        {
            PSSPS_DETECTION_RESULT psResult = NULL;
            NTSTATUS psStatus = SsPsCheckForScan(
                g_PortScanner,
                (HANDLE)(ULONG_PTR)processId,
                processCreateTime,
                &psResult
            );

            if (NT_SUCCESS(psStatus) && psResult != NULL) {
                InterlockedOr(
                    (LONG*)&connection->Flags,
                    NF_CONN_FLAG_SUSPICIOUS);

                BeEngineSubmitEvent(
                    BehaviorEvent_PortScanning,
                    BehaviorCategory_NetworkOperation,
                    connection->ProcessId,
                    NULL,
                    0,
                    70,
                    FALSE,
                    NULL
                );

                if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
                    PTS_SCORING_ENGINE tsEngine = (PTS_SCORING_ENGINE)ShadowStrikeGetThreatScoringEngine();
                    if (tsEngine != NULL) {
                        TsAddFactor(tsEngine, (HANDLE)(ULONG_PTR)connection->ProcessId,
                            TsFactor_Behavioral, "PortScanning",
                            70, "Port scanning detected (T1046)");
                    }
                }

                TeLogThreatDetection(
                    connection->ProcessId,
                    L"Network.PortScan",
                    70,
                    ThreatSeverity_Medium,
                    0x0416,
                    L"Port scanning activity detected (T1046)",
                    0
                );

                SsPsFreeResult(psResult);
            }
        }
    }

    if (InterlockedCompareExchange((LONG*)&connection->Flags, 0, 0) & NF_CONN_FLAG_BLOCKED) {
        ClassifyOut->actionType = FWP_ACTION_BLOCK;
        ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        InterlockedIncrement64(&g_NfState.TotalConnectionsBlocked);

        BeEngineSubmitEvent(
            BehaviorEvent_C2Communication,
            BehaviorCategory_NetworkOperation,
            connection->ProcessId,
            NULL,
            0,
            80,
            TRUE,
            NULL
        );

        if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
            PTS_SCORING_ENGINE tsEngine = (PTS_SCORING_ENGINE)ShadowStrikeGetThreatScoringEngine();
            if (tsEngine != NULL) {
                TsAddFactor(tsEngine, (HANDLE)(ULONG_PTR)connection->ProcessId,
                    TsFactor_Behavioral, "BlockedConnection",
                    80, "Blocked suspicious connection");
            }
        }

        TeLogThreatDetection(
            connection->ProcessId,
            L"Network.ConnectionBlocked",
            80,
            ThreatSeverity_High,
            0x042F,
            L"Suspicious connection blocked",
            1
        );

        NfpEmitNetworkTelemetry(TeEvent_NetBlocked, connection,
                                80, TE_NET_FLAG_BLOCKED);
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
    PAGED_CODE();
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
    PAGED_CODE();
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
 * @brief Process DNS packet â€” extracts query from NET_BUFFER, parses, inspects.
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
    if (dataLength < NF_DNS_HEADER_SIZE || dataLength > NF_MAX_DNS_PACKET_SIZE) {
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
        dnsData = (UCHAR*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, dataLength, NF_POOL_TAG_DNS);
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
    // Check QR bit (bit 15 of flags) â€” 0 = query, 1 = response
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
    // Route through DnsMonitor's sophisticated analysis pipeline.
    // This provides tunneling detection, DGA (bigram+consonant), process
    // context tracking, domain caching, and BehaviorEngine integration.
    //
    if (g_DnsMonitor != NULL) {
        NTSTATUS dnsStatus;
        UINT32 srcAddr = InFixedValues->incomingValue[
            FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value.uint32;
        UINT16 srcPort = InFixedValues->incomingValue[
            FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;
        UINT32 srvAddr = InFixedValues->incomingValue[
            FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32;

        dnsStatus = DnsProcessQuery(
            g_DnsMonitor,
            ULongToHandle(processId),
            dnsData,
            dataLength,
            &srcAddr,
            srcPort,
            &srvAddr,
            NF_DNS_PORT,
            FALSE,
            NULL
            );

        if (dnsStatus == STATUS_ACCESS_DENIED) {
            ClassifyOut->actionType = FWP_ACTION_BLOCK;
            ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
            InterlockedIncrement64(&g_NfState.TotalDnsQueriesBlocked);
            goto Done;
        }
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
    // Compute domain entropy for DGA detection.
    //
    // Shannon entropy approximation using integer arithmetic:
    //   H = -Î£ (p_i * log2(p_i))
    // We use: H * 100 = Î£ (count_i * log2(totalChars/count_i) * 100 / totalChars)
    // Approximation via lookup table for log2(n) * 100 for n in [1..32].
    //
    {
        UINT32 charCounts[36] = {0};
        ULONG totalChars = 0;
        UINT32 entropyX100 = 0;
        ULONG i;

        //
        // log2(n) * 100, indexed by n (1-based). log2(1)=0, log2(2)=100, etc.
        // Used for integer Shannon entropy: H = Î£ count[i]/total * log2(total/count[i])
        //
        static const UINT16 log2x100[] = {
            0,    0,  100, 158, 200, 232, 258, 280, 300, 317,   // 0-9
            332, 346, 358, 370, 381, 391, 400, 409, 417, 424,   // 10-19
            432, 439, 446, 452, 458, 464, 470, 475, 481, 486,   // 20-29
            491, 496, 500                                         // 30-32
        };
        #define LOG2X100_MAX_IDX 32

        for (i = 0; queryName[i] != L'\0'; i++) {
            WCHAR c = queryName[i];
            if (c == L'.') continue;
            if (c >= L'a' && c <= L'z') charCounts[c - L'a']++;
            else if (c >= L'A' && c <= L'Z') charCounts[c - L'A']++;
            else if (c >= L'0' && c <= L'9') charCounts[26 + c - L'0']++;
            totalChars++;
        }

        if (totalChars > 1 && totalChars <= LOG2X100_MAX_IDX) {
            //
            // H * 100 = Î£ (count_i / totalChars) * log2(totalChars / count_i) * 100
            //         = Î£ count_i * (log2(totalChars) - log2(count_i)) * 100 / totalChars
            //
            UINT32 log2Total = log2x100[totalChars];

            for (i = 0; i < 36; i++) {
                if (charCounts[i] > 0 && charCounts[i] <= LOG2X100_MAX_IDX) {
                    UINT32 log2Count = log2x100[charCounts[i]];
                    if (log2Total > log2Count) {
                        entropyX100 += charCounts[i] * (log2Total - log2Count);
                    }
                }
            }
            entropyX100 = entropyX100 / totalChars;
        } else if (totalChars > LOG2X100_MAX_IDX) {
            //
            // For very long names (>32 chars), use unique-char ratio as proxy.
            // Ratio = uniqueChars * 100 / min(totalChars, 36).
            // Random strings â†’ high ratio, dictionary â†’ low ratio.
            //
            UINT32 uniqueChars = 0;
            for (i = 0; i < 36; i++) {
                if (charCounts[i] > 0) uniqueChars++;
            }
            entropyX100 = (uniqueChars * 100) / min(totalChars, 36);
            //
            // Scale: 36 unique in 36 chars â†’ 100.
            // True Shannon entropy for uniform 36-char â†’ ~514.
            // Map ratio to entropy-like scale: ratio * 5 approximates H*100.
            //
            entropyX100 = entropyX100 * 5;
        }

        dnsEntry->DomainEntropy = entropyX100;

        // Compute subdomain length
        {
            ULONG dotCount = 0;
            ULONG lastDotPos = 0;
            for (i = 0; queryName[i] != L'\0'; i++) {
                if (queryName[i] == L'.') { dotCount++; lastDotPos = i; }
            }
            dnsEntry->SubdomainLength = (dotCount > 1) ? lastDotPos : 0;
        }

        //
        // High entropy (>350 â‰ˆ 3.5 bits/char) with long name suggests DGA.
        // Typical DGA domains: 400-500. Legitimate domains: 200-350.
        //
        if (dnsEntry->DomainEntropy > 350 && totalChars > 20) {
            dnsEntry->IsDGA = TRUE;
            dnsEntry->IsSuspicious = TRUE;
            dnsEntry->ThreatScore = 70;
        }
    }

    //
    // Insert into DNS tracking list (with cap to prevent pool exhaustion).
    // Double-check count under exclusive lock to close TOCTOU window.
    //
    FltAcquirePushLockExclusive(&g_NfState.DnsLock);

    if ((ULONG)g_NfState.DnsQueryCount >= NF_MAX_DNS_ENTRIES) {
        FltReleasePushLock(&g_NfState.DnsLock);
        NfpFreeDnsEntry(dnsEntry);
        goto Done;
    }

    InsertTailList(&g_NfState.DnsQueryList, &dnsEntry->ListEntry);
    InterlockedIncrement(&g_NfState.DnsQueryCount);
    FltReleasePushLock(&g_NfState.DnsLock);

    InterlockedIncrement64(&g_NfState.TotalDnsQueriesMonitored);

Done:
    if (allocated && dnsData != NULL) {
        ExFreePoolWithTag(dnsData, NF_POOL_TAG_DNS);
    }
}

/**
 * @brief Process inbound DNS response from recursive resolver.
 *
 * Called from NfInboundTransportClassify when source port == 53.
 * Routes the raw response packet to DnsProcessResponse for correlation
 * with pending queries and answer analysis.
 */
static VOID
NfpProcessInboundDnsResponse(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
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
    UINT32 serverAddr;

    ClassifyOut->actionType = FWP_ACTION_PERMIT;

    if (LayerData == NULL || g_DnsMonitor == NULL) {
        return;
    }

    nbl = (NET_BUFFER_LIST*)LayerData;
    nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (nb == NULL) {
        return;
    }

    dataLength = NET_BUFFER_DATA_LENGTH(nb);
    if (dataLength < NF_DNS_HEADER_SIZE || dataLength > NF_MAX_DNS_PACKET_SIZE) {
        return;
    }

    //
    // Verify QR bit indicates response (bit 7 of byte 2 == 1)
    //
    if (dataLength <= sizeof(localBuffer)) {
        dnsData = (UCHAR*)NdisGetDataBuffer(nb, dataLength, localBuffer, 1, 0);
    } else {
        dnsData = (UCHAR*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, dataLength, NF_POOL_TAG_DNS);
        if (dnsData == NULL) {
            return;
        }
        allocated = TRUE;

        if (NdisGetDataBuffer(nb, dataLength, dnsData, 1, 0) == NULL) {
            goto Cleanup;
        }
    }

    if (dnsData == NULL) {
        goto Cleanup;
    }

    //
    // Only process DNS responses (QR bit set)
    //
    if ((dnsData[2] & 0x80) == 0) {
        goto Cleanup;
    }

    serverAddr = InFixedValues->incomingValue[
        FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32;

    DnsProcessResponse(
        g_DnsMonitor,
        dnsData,
        dataLength,
        &serverAddr,
        FALSE
        );

Cleanup:
    if (allocated && dnsData != NULL) {
        ExFreePoolWithTag(dnsData, NF_POOL_TAG_DNS);
    }
}

/**
 * @brief Process TCP stream data â€” update statistics using atomic operations.
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

    //
    // Stream callouts can fire at DISPATCH_LEVEL. NfFilterFindConnectionByFlow
    // acquires a push lock (requires IRQL <= APC_LEVEL). Bail early if elevated.
    //
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return;
    }

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

    //
    // NF-PERF: Fast-path for private/loopback traffic. Update byte counters
    // only — skip protocol parsing, C2 detection, and DLP analysis.
    // Private network traffic (RFC1918, loopback) is extremely unlikely to be
    // C2 or exfiltration, and inspecting it wastes significant CPU on every
    // LAN packet (file shares, printers, localhost services).
    //
    if (connection->Flags & NF_CONN_FLAG_PRIVATE_NET) {
        if (StreamPacket->streamData->flags & FWPS_STREAM_FLAG_SEND) {
            InterlockedAdd64((LONG64*)&connection->BytesSent, (LONG64)dataSize);
            InterlockedIncrement((LONG*)&connection->PacketsSent);
        } else {
            InterlockedAdd64((LONG64*)&connection->BytesReceived, (LONG64)dataSize);
            InterlockedIncrement((LONG*)&connection->PacketsReceived);
        }
        InterlockedAdd64(&g_NfState.TotalBytesMonitored, (LONG64)dataSize);
        NfFilterReleaseConnection(connection);
        return;
    }

    if (StreamPacket->streamData->flags & FWPS_STREAM_FLAG_SEND) {
        InterlockedAdd64((LONG64*)&connection->BytesSent, (LONG64)dataSize);
        InterlockedIncrement((LONG*)&connection->PacketsSent);

        NfpUpdateBeaconingState(connection, (UINT64)(currentTime.QuadPart / 10000));

        //
        // Attempt HTTP protocol parsing on outbound sends for C2 detection (T1071.001).
        // Only parse if ProtocolParser is available and data is plausible HTTP size.
        // NF-PERF: Parse only the first outbound packet per connection — subsequent
        // packets on the same connection don't carry new HTTP request headers.
        //
        if (g_ProtocolParser != NULL && dataSize >= 16 && dataSize <= 65536 &&
            !(connection->Flags & NF_CONN_FLAG_HTTP_PARSED) &&
            KeGetCurrentIrql() == PASSIVE_LEVEL) {

            PVOID contiguousData = NULL;
            BOOLEAN ppAllocated = FALSE;
            UCHAR ppLocalBuf[512];

            //
            // Get contiguous view of stream data
            //
            if (dataSize <= sizeof(ppLocalBuf)) {
                SIZE_T bytesCopied = 0;
                FwpsCopyStreamDataToBuffer0(
                    StreamPacket->streamData, ppLocalBuf, (SIZE_T)sizeof(ppLocalBuf), &bytesCopied);
                if (bytesCopied > 0) {
                    contiguousData = ppLocalBuf;
                }
            } else {
                contiguousData = ExAllocatePool2(
                    POOL_FLAG_PAGED, (SIZE_T)dataSize, 'pPfN');
                if (contiguousData != NULL) {
                    SIZE_T bytesCopied = 0;
                    FwpsCopyStreamDataToBuffer0(
                        StreamPacket->streamData, contiguousData, (SIZE_T)dataSize, &bytesCopied);
                    ppAllocated = TRUE;
                    if (bytesCopied == 0) {
                        ExFreePoolWithTag(contiguousData, 'pPfN');
                        contiguousData = NULL;
                        ppAllocated = FALSE;
                    }
                }
            }

            if (contiguousData != NULL) {
                //
                // Quick check: does data look like HTTP? (GET, POST, PUT, HEAD, etc.)
                //
                UCHAR firstByte = *(UCHAR*)contiguousData;
                if (firstByte == 'G' || firstByte == 'P' || firstByte == 'H' ||
                    firstByte == 'D' || firstByte == 'O' || firstByte == 'C' ||
                    firstByte == 'T') {

                    PPP_HTTP_REQUEST httpRequest = NULL;
                    NTSTATUS parseStatus = PpParseHTTPRequest(
                        g_ProtocolParser, contiguousData, (ULONG)dataSize, &httpRequest);

                    if (NT_SUCCESS(parseStatus) && httpRequest != NULL) {
                        if (httpRequest->SuspicionScore > 50) {
                            BeEngineSubmitEvent(
                                BehaviorEvent_C2Communication,
                                BehaviorCategory_NetworkOperation,
                                connection->ProcessId,
                                NULL, 0,
                                httpRequest->SuspicionScore,
                                TRUE, NULL);

                            if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
                                PTS_SCORING_ENGINE tsEngine = (PTS_SCORING_ENGINE)ShadowStrikeGetThreatScoringEngine();
                                if (tsEngine != NULL) {
                                    TsAddFactor(tsEngine, (HANDLE)(ULONG_PTR)connection->ProcessId,
                                        TsFactor_Behavioral, "SuspiciousHTTP",
                                        (LONG)httpRequest->SuspicionScore,
                                        "Suspicious HTTP request detected (T1071)");
                                }
                            }

                            TeLogThreatDetection(
                                connection->ProcessId,
                                L"Network.SuspiciousHTTP",
                                httpRequest->SuspicionScore,
                                ThreatSeverity_Medium,
                                0x042F,
                                L"Suspicious HTTP request detected (T1071)",
                                1
                            );
                        }
                        PpFreeHTTPRequest(httpRequest);
                    }
                }

                if (ppAllocated) {
                    ExFreePoolWithTag(contiguousData, 'pPfN');
                }
            }

            //
            // NF-PERF: Mark connection as HTTP-parsed so subsequent packets
            // on this connection skip protocol parsing entirely.
            //
            InterlockedOr((LONG*)&connection->Flags, NF_CONN_FLAG_HTTP_PARSED);
        }

        //
        // Detect TLS ClientHello and feed JA3 to C2Detection (T1573).
        // Only on first handshake for this connection, at PASSIVE_LEVEL.
        // TLS record: byte[0]=0x16 (Handshake), byte[5]=0x01 (ClientHello).
        //
        if (g_SslInspector != NULL && g_C2Detector != NULL &&
            !connection->TlsHandshakeComplete &&
            dataSize >= 6 && KeGetCurrentIrql() == PASSIVE_LEVEL) {

            UCHAR tlsPeek[6];
            SIZE_T peekCopied = 0;
            FwpsCopyStreamDataToBuffer0(
                StreamPacket->streamData, tlsPeek, sizeof(tlsPeek), &peekCopied);

            if (peekCopied >= 6 &&
                tlsPeek[0] == 0x16 &&
                tlsPeek[1] == 0x03 &&
                (tlsPeek[2] >= 0x01 && tlsPeek[2] <= 0x03) &&
                tlsPeek[5] == 0x01) {

                PVOID tlsData = NULL;
                BOOLEAN tlsAllocated = FALSE;
                UCHAR tlsLocalBuf[512];
                SIZE_T tlsCopied = 0;

                if (dataSize <= sizeof(tlsLocalBuf)) {
                    FwpsCopyStreamDataToBuffer0(
                        StreamPacket->streamData, tlsLocalBuf, sizeof(tlsLocalBuf), &tlsCopied);
                    if (tlsCopied > 0) {
                        tlsData = tlsLocalBuf;
                    }
                } else if (dataSize <= 16384) {
                    tlsData = ExAllocatePool2(POOL_FLAG_PAGED, (SIZE_T)dataSize, 'lTfN');
                    if (tlsData != NULL) {
                        FwpsCopyStreamDataToBuffer0(
                            StreamPacket->streamData, tlsData, (SIZE_T)dataSize, &tlsCopied);
                        tlsAllocated = TRUE;
                        if (tlsCopied == 0) {
                            ExFreePoolWithTag(tlsData, 'lTfN');
                            tlsData = NULL;
                            tlsAllocated = FALSE;
                        }
                    }
                }

                if (tlsData != NULL && tlsCopied >= 6) {
                    PSSL_SESSION_INFO sessionInfo = NULL;
                    BOOLEAN isV6 = (connection->RemoteAddress.Address.Family == 23);

                    NTSTATUS sslStatus = SslInspectClientHello(
                        g_SslInspector,
                        (HANDLE)(ULONG_PTR)connection->ProcessId,
                        isV6 ? (PVOID)&connection->RemoteAddress.Address.V6
                              : (PVOID)&connection->RemoteAddress.Address.V4,
                        connection->RemoteAddress.Port,
                        isV6,
                        tlsData,
                        (ULONG)tlsCopied,
                        &sessionInfo);

                    if (NT_SUCCESS(sslStatus) && sessionInfo != NULL) {
                        C2_JA3_FINGERPRINT ja3fp;
                        RtlZeroMemory(&ja3fp, sizeof(ja3fp));
                        RtlCopyMemory(ja3fp.JA3String, sessionInfo->JA3.JA3String,
                                      sizeof(ja3fp.JA3String));
                        RtlCopyMemory(ja3fp.JA3Hash, sessionInfo->JA3.JA3Hash,
                                      sizeof(ja3fp.JA3Hash));
                        RtlCopyMemory(ja3fp.JA3SString, sessionInfo->JA3.JA3SString,
                                      sizeof(ja3fp.JA3SString));
                        RtlCopyMemory(ja3fp.JA3SHash, sessionInfo->JA3.JA3SHash,
                                      sizeof(ja3fp.JA3SHash));

                        C2RecordTLSHandshake(
                            g_C2Detector,
                            (HANDLE)(ULONG_PTR)connection->ProcessId,
                            isV6 ? (PVOID)&connection->RemoteAddress.Address.V6
                                  : (PVOID)&connection->RemoteAddress.Address.V4,
                            connection->RemoteAddress.Port,
                            isV6,
                            &ja3fp);

                        //
                        // JA3 known-bad check (T1573) â€” compare the computed
                        // JA3 hash against the SSL inspector's blocklist of
                        // known malware/C2 JA3 fingerprints.
                        //
                        {
                            BOOLEAN isBadJA3 = FALSE;
                            CHAR malwareFamily[64] = {0};
                            NTSTATUS ja3Status = SslCheckJA3(
                                g_SslInspector,
                                ja3fp.JA3Hash,
                                &isBadJA3,
                                malwareFamily,
                                sizeof(malwareFamily)
                            );

                            if (NT_SUCCESS(ja3Status) && isBadJA3) {
                                InterlockedOr(
                                    (LONG*)&connection->Flags,
                                    NF_CONN_FLAG_C2_SUSPECT | NF_CONN_FLAG_SUSPICIOUS);

                                BeEngineSubmitEvent(
                                    BehaviorEvent_C2Communication,
                                    BehaviorCategory_NetworkOperation,
                                    connection->ProcessId,
                                    NULL,
                                    0,
                                    85,
                                    TRUE,
                                    NULL
                                );

                                if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
                                    PTS_SCORING_ENGINE tsEngine = (PTS_SCORING_ENGINE)ShadowStrikeGetThreatScoringEngine();
                                    if (tsEngine != NULL) {
                                        TsAddFactor(tsEngine, (HANDLE)(ULONG_PTR)connection->ProcessId,
                                            TsFactor_IOC, "MaliciousJA3",
                                            85, "Known-bad JA3 fingerprint detected (T1573)");
                                    }
                                }

                                TeLogThreatDetection(
                                    connection->ProcessId,
                                    L"Network.MaliciousJA3",
                                    85,
                                    ThreatSeverity_High,
                                    0x0625,
                                    L"Known-bad JA3 fingerprint detected (T1573)",
                                    1
                                );
                            }
                        }

                        connection->TlsHandshakeComplete = TRUE;
                        SslFreeSessionInfo(sessionInfo);
                    }
                }

                if (tlsAllocated && tlsData != NULL) {
                    ExFreePoolWithTag(tlsData, 'lTfN');
                }
            }
        }
    } else {
        InterlockedAdd64((LONG64*)&connection->BytesReceived, (LONG64)dataSize);
        InterlockedIncrement((LONG*)&connection->PacketsReceived);

        //
        // Detect TLS ServerHello on inbound data and feed to SSLInspection (SSL2-02).
        // Only after ClientHello has been processed and ServerHello not yet seen.
        // ServerHello: byte[0]=0x16 (Handshake), byte[5]=0x02.
        //
        if (g_SslInspector != NULL &&
            connection->TlsHandshakeComplete &&
            !connection->TlsServerHelloComplete &&
            dataSize >= 6 && KeGetCurrentIrql() == PASSIVE_LEVEL) {

            UCHAR shPeek[6];
            SIZE_T shPeekCopied = 0;
            FwpsCopyStreamDataToBuffer0(
                StreamPacket->streamData, shPeek, sizeof(shPeek), &shPeekCopied);

            if (shPeekCopied >= 6 &&
                shPeek[0] == 0x16 &&
                shPeek[1] == 0x03 &&
                (shPeek[2] >= 0x01 && shPeek[2] <= 0x03) &&
                shPeek[5] == 0x02) {

                PVOID shData = NULL;
                BOOLEAN shAllocated = FALSE;
                UCHAR shLocalBuf[512];
                SIZE_T shCopied = 0;

                if (dataSize <= sizeof(shLocalBuf)) {
                    FwpsCopyStreamDataToBuffer0(
                        StreamPacket->streamData, shLocalBuf, sizeof(shLocalBuf), &shCopied);
                    if (shCopied > 0) {
                        shData = shLocalBuf;
                    }
                } else if (dataSize <= 16384) {
                    shData = ExAllocatePool2(POOL_FLAG_PAGED, (SIZE_T)dataSize, 'hSfN');
                    if (shData != NULL) {
                        FwpsCopyStreamDataToBuffer0(
                            StreamPacket->streamData, shData, (SIZE_T)dataSize, &shCopied);
                        shAllocated = TRUE;
                        if (shCopied == 0) {
                            ExFreePoolWithTag(shData, 'hSfN');
                            shData = NULL;
                            shAllocated = FALSE;
                        }
                    }
                }

                if (shData != NULL && shCopied >= 6) {
                    BOOLEAN isV6 = (connection->RemoteAddress.Address.Family == 23);

                    SslInspectServerHello(
                        g_SslInspector,
                        isV6 ? (PVOID)&connection->RemoteAddress.Address.V6
                              : (PVOID)&connection->RemoteAddress.Address.V4,
                        connection->RemoteAddress.Port,
                        isV6,
                        shData,
                        (ULONG)shCopied);

                    connection->TlsServerHelloComplete = TRUE;
                }

                if (shAllocated && shData != NULL) {
                    ExFreePoolWithTag(shData, 'hSfN');
                }
            }
        }
    }

    //
    // NET-PP: Parse HTTP responses on inbound (receive) data for C2 response
    // fingerprinting (T1071.001). Detect suspicious Server headers, unusual
    // content types, and C2 framework response patterns.
    // NF-PERF: Parse only first response per connection.
    //
    if (g_ProtocolParser != NULL && dataSize >= 12 && dataSize <= 65536 &&
        !(connection->Flags & NF_CONN_FLAG_HTTP_RESP_PARSED) &&
        KeGetCurrentIrql() == PASSIVE_LEVEL &&
        !connection->TlsHandshakeComplete) {

        PVOID respData = NULL;
        BOOLEAN respAllocated = FALSE;
        UCHAR respLocalBuf[512];
        SIZE_T respCopied = 0;

        if (dataSize <= sizeof(respLocalBuf)) {
            FwpsCopyStreamDataToBuffer0(
                StreamPacket->streamData, respLocalBuf, sizeof(respLocalBuf), &respCopied);
            if (respCopied >= 12) {
                respData = respLocalBuf;
            }
        } else if (dataSize <= 32768) {
            respData = ExAllocatePool2(POOL_FLAG_PAGED, (SIZE_T)dataSize, 'pRfN');
            if (respData != NULL) {
                FwpsCopyStreamDataToBuffer0(
                    StreamPacket->streamData, respData, (SIZE_T)dataSize, &respCopied);
                respAllocated = TRUE;
                if (respCopied < 12) {
                    ExFreePoolWithTag(respData, 'pRfN');
                    respData = NULL;
                    respAllocated = FALSE;
                }
            }
        }

        //
        // Check for "HTTP/" prefix before parsing â€” avoid wasting cycles
        // on binary protocols.
        //
        if (respData != NULL && respCopied >= 5 &&
            ((PUCHAR)respData)[0] == 'H' &&
            ((PUCHAR)respData)[1] == 'T' &&
            ((PUCHAR)respData)[2] == 'T' &&
            ((PUCHAR)respData)[3] == 'P' &&
            ((PUCHAR)respData)[4] == '/') {

            PPP_HTTP_RESPONSE httpResponse = NULL;
            NTSTATUS parseStatus = PpParseHTTPResponse(
                g_ProtocolParser,
                respData,
                (ULONG)respCopied,
                &httpResponse
            );

            if (NT_SUCCESS(parseStatus) && httpResponse != NULL) {
                //
                // HTTP response successfully parsed â€” enrichment data available.
                // Future: analyze Server header, Content-Type, response timing
                // for C2 framework fingerprinting.
                //
                PpFreeHTTPResponse(httpResponse);
            }
        }

        if (respAllocated && respData != NULL) {
            ExFreePoolWithTag(respData, 'pRfN');
        }

        InterlockedOr((LONG*)&connection->Flags, NF_CONN_FLAG_HTTP_RESP_PARSED);
    }

    InterlockedAdd64(&g_NfState.TotalBytesMonitored, (LONG64)dataSize);

    //
    // Update ConnectionTracker per-connection and per-process byte/packet stats.
    // Uses flow context (NF ConnectionId) â€” ConnectionTracker keyed by WFP FlowId.
    //
    if (g_ConnectionTracker != NULL && connection->FlowId != 0) {
        BOOLEAN isSend = !!(StreamPacket->streamData->flags & FWPS_STREAM_FLAG_SEND);
        CtUpdateStats(
            g_ConnectionTracker,
            connection->FlowId,
            isSend ? dataSize : 0,
            isSend ? 0 : dataSize,
            isSend ? 1 : 0,
            isSend ? 0 : 1
        );

        //
        // NET-CT: Transition connection to Established on first data flow.
        // CAS-style: only transitions from New/Connected â†’ Established.
        // CtUpdateConnectionState internally ignores invalid transitions.
        //
        if (!(connection->Flags & NF_CONN_FLAG_STATE_ESTABLISHED)) {
            NTSTATUS ctStateStatus = CtUpdateConnectionState(
                g_ConnectionTracker,
                connection->FlowId,
                CtState_Established
            );
            if (NT_SUCCESS(ctStateStatus)) {
                InterlockedOr((LONG*)&connection->Flags, NF_CONN_FLAG_STATE_ESTABLISHED);
            }
        }
    }

    //
    // Feed traffic to C2Detection for beacon interval analysis (T1071/T1573).
    // Uses the connection's remote address which is stable for the connection lifetime.
    //
    if (g_C2Detector != NULL) {
        BOOLEAN isV6 = (connection->RemoteAddress.Address.Family == 23); // AF_INET6
        PVOID remoteAddr = isV6
            ? (PVOID)&connection->RemoteAddress.Address.V6
            : (PVOID)&connection->RemoteAddress.Address.V4;
        CT_DIRECTION dir = (StreamPacket->streamData->flags & FWPS_STREAM_FLAG_SEND)
            ? CtDirection_Outbound : CtDirection_Inbound;

        C2RecordTraffic(
            g_C2Detector,
            (HANDLE)(ULONG_PTR)connection->ProcessId,
            remoteAddr,
            connection->RemoteAddress.Port,
            isV6,
            (ULONG)dataSize,
            dir
        );
    }

    //
    // Feed outbound data to DataExfiltration DLP engine for content inspection,
    // entropy analysis, cloud storage detection, and sensitive pattern matching.
    // Only on outbound sends at PASSIVE_LEVEL (DxAnalyzeTraffic requires PASSIVE).
    //
    if (g_DxDetector != NULL &&
        (StreamPacket->streamData->flags & FWPS_STREAM_FLAG_SEND) &&
        KeGetCurrentIrql() == PASSIVE_LEVEL) {

        PVOID dxContiguousData = NULL;
        BOOLEAN dxAllocated = FALSE;
        UCHAR dxLocalBuf[512];
        SIZE_T dxInspectSize = min(dataSize, DX_MAX_INSPECT_SIZE);

        //
        // Get contiguous view of stream data for DLP inspection
        //
        if (dxInspectSize <= sizeof(dxLocalBuf)) {
            SIZE_T dxCopied = 0;
            FwpsCopyStreamDataToBuffer0(
                StreamPacket->streamData, dxLocalBuf, sizeof(dxLocalBuf), &dxCopied);
            if (dxCopied > 0) {
                dxContiguousData = dxLocalBuf;
                dxInspectSize = dxCopied;
            }
        } else {
            dxContiguousData = ExAllocatePool2(
                POOL_FLAG_NON_PAGED, dxInspectSize, 'xDfN');
            if (dxContiguousData != NULL) {
                SIZE_T dxCopied = 0;
                FwpsCopyStreamDataToBuffer0(
                    StreamPacket->streamData, dxContiguousData, dxInspectSize, &dxCopied);
                dxAllocated = TRUE;
                if (dxCopied == 0) {
                    ExFreePoolWithTag(dxContiguousData, 'xDfN');
                    dxContiguousData = NULL;
                    dxAllocated = FALSE;
                } else {
                    dxInspectSize = dxCopied;
                }
            }
        }

        if (dxContiguousData != NULL && dxInspectSize > 0) {
            BOOLEAN isSuspicious = FALSE;
            BOOLEAN wasBlocked = FALSE;
            ULONG suspicionScore = 0;
            BOOLEAN isV6 = (connection->RemoteAddress.Address.Family == 23); // AF_INET6
            PVOID remoteAddr = isV6
                ? (PVOID)&connection->RemoteAddress.Address.V6
                : (PVOID)&connection->RemoteAddress.Address.V4;
            ULONG addrSize = isV6 ? sizeof(IN6_ADDR) : sizeof(IN_ADDR);

            //
            // Convert WCHAR hostname to ANSI for DxAnalyzeTraffic.
            // Stack buffer is sufficient â€” hostnames are at most 255 chars.
            //
            CHAR ansiHostname[256] = { 0 };
            PCSTR hostnamePtr = NULL;
            if (connection->RemoteHostname[0] != L'\0') {
                UNICODE_STRING uniHost;
                ANSI_STRING ansiHost;
                RtlInitUnicodeString(&uniHost, connection->RemoteHostname);
                ansiHost.Buffer = ansiHostname;
                ansiHost.Length = 0;
                ansiHost.MaximumLength = sizeof(ansiHostname) - 1;
                if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiHost, &uniHost, FALSE))) {
                    ansiHostname[ansiHost.Length] = '\0';
                    hostnamePtr = ansiHostname;
                }
            }

            NTSTATUS dxStatus = DxAnalyzeTraffic(
                g_DxDetector,
                (HANDLE)(ULONG_PTR)connection->ProcessId,
                remoteAddr,
                addrSize,
                connection->RemoteAddress.Port,
                isV6,
                hostnamePtr,
                dxContiguousData,
                dxInspectSize,
                &isSuspicious,
                &wasBlocked,
                &suspicionScore
            );

            if (NT_SUCCESS(dxStatus) && isSuspicious) {
                InterlockedOr((LONG*)&connection->Flags, NF_CONN_FLAG_EXFIL_SUSPECT);

                if (suspicionScore >= 70) {
                    InterlockedOr((LONG*)&connection->Flags, NF_CONN_FLAG_SUSPICIOUS);
                }
            }
        }

        if (dxAllocated && dxContiguousData != NULL) {
            ExFreePoolWithTag(dxContiguousData, 'xDfN');
        }
    }

    //
    // Also record volume-only transfer stats for burst/threshold detection.
    // This works independently of content inspection â€” records byte counts
    // even when content copy was not possible.
    //
    if (g_DxDetector != NULL &&
        (StreamPacket->streamData->flags & FWPS_STREAM_FLAG_SEND)) {

        BOOLEAN isV6 = (connection->RemoteAddress.Address.Family == 23);
        PVOID remoteAddr = isV6
            ? (PVOID)&connection->RemoteAddress.Address.V6
            : (PVOID)&connection->RemoteAddress.Address.V4;
        ULONG addrSize = isV6 ? sizeof(IN6_ADDR) : sizeof(IN_ADDR);

        if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
            DxRecordTransfer(
                g_DxDetector,
                (HANDLE)(ULONG_PTR)connection->ProcessId,
                remoteAddr,
                addrSize,
                connection->RemoteAddress.Port,
                isV6,
                dataSize
            );
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

    PAGED_CODE();

    if (g_ReputationManager != NULL) {
        //
        // NrLookupIP expects raw IN_ADDR* / IN6_ADDR*, NOT SS_IP_ADDRESS*
        // (which starts with Family+Reserved before the address union).
        //
        BOOLEAN isIpv6 = SS_IS_IPV6(&Connection->RemoteAddress.Address);
        const VOID* rawAddr = isIpv6
            ? (const VOID*)&Connection->RemoteAddress.Address.V6
            : (const VOID*)&Connection->RemoteAddress.Address.V4;

        NTSTATUS status = NrLookupIP(
            g_ReputationManager,
            rawAddr,
            isIpv6,
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

// ============================================================================
// MODULE ACCESSOR FUNCTIONS
// ============================================================================

PC2_DETECTOR
NfFilterGetC2Detector(
    VOID
    )
{
    return g_C2Detector;
}

PCONNECTION_TRACKER
NfFilterGetConnectionTracker(
    VOID
    )
{
    return g_ConnectionTracker;
}

PDNS_MONITOR
NfFilterGetDnsMonitor(
    VOID
    )
{
    return g_DnsMonitor;
}

PNR_MANAGER
NfFilterGetReputationManager(
    VOID
    )
{
    return g_ReputationManager;
}

PSSL_INSPECTOR
NfFilterGetSslInspector(
    VOID
    )
{
    return g_SslInspector;
}

PDX_DETECTOR
NfFilterGetDxDetector(
    VOID
    )
{
    return g_DxDetector;
}

PSSPS_DETECTOR
NfFilterGetPortScanner(
    VOID
    )
{
    return g_PortScanner;
}

PPP_PARSER
NfFilterGetProtocolParser(
    VOID
    )
{
    return g_ProtocolParser;
}
