/**
 * ============================================================================
 * ShadowStrike NGAV - NETWORK FILTER (WFP)
 * ============================================================================
 *
 * @file NetworkFilter.h
 * @brief WFP-based network filtering subsystem header for ShadowSensor.
 *
 * This module provides comprehensive network monitoring using the
 * Windows Filtering Platform (WFP):
 * - Outbound/inbound connection monitoring
 * - DNS query inspection
 * - Data transfer monitoring
 * - C2 detection
 * - DNS tunneling detection
 * - Data exfiltration prevention
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#pragma once

#include <fltKernel.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include "../../Shared/NetworkTypes.h"
#include "../../Shared/BehaviorTypes.h"

// ============================================================================
// WFP FILTER CONFIGURATION
// ============================================================================

/**
 * @brief WFP provider GUID.
 */
// {A5E8F2D1-3B4C-4D5E-9F6A-7B8C9D0E1F2A}
DEFINE_GUID(SHADOWSTRIKE_WFP_PROVIDER_GUID,
    0xa5e8f2d1, 0x3b4c, 0x4d5e, 0x9f, 0x6a, 0x7b, 0x8c, 0x9d, 0x0e, 0x1f, 0x2a);

/**
 * @brief WFP sublayer GUID.
 */
// {B6F9A3E2-4C5D-5E6F-A071-8C9D0E1F2A3B}
DEFINE_GUID(SHADOWSTRIKE_WFP_SUBLAYER_GUID,
    0xb6f9a3e2, 0x4c5d, 0x5e6f, 0xa0, 0x71, 0x8c, 0x9d, 0x0e, 0x1f, 0x2a, 0x3b);

/**
 * @brief Callout GUIDs for each layer.
 */
// ALE Connect v4
// {C7A0B4F3-5D6E-6F70-B182-9D0E1F2A3B4C}
DEFINE_GUID(SHADOWSTRIKE_ALE_CONNECT_V4_CALLOUT_GUID,
    0xc7a0b4f3, 0x5d6e, 0x6f70, 0xb1, 0x82, 0x9d, 0x0e, 0x1f, 0x2a, 0x3b, 0x4c);

// ALE Connect v6
// {D8B1C5A4-6E7F-7081-C293-0E1F2A3B4C5D}
DEFINE_GUID(SHADOWSTRIKE_ALE_CONNECT_V6_CALLOUT_GUID,
    0xd8b1c5a4, 0x6e7f, 0x7081, 0xc2, 0x93, 0x0e, 0x1f, 0x2a, 0x3b, 0x4c, 0x5d);

// ALE Recv Accept v4
// {E9C2D6B5-7F80-8192-D3A4-1F2A3B4C5D6E}
DEFINE_GUID(SHADOWSTRIKE_ALE_RECV_ACCEPT_V4_CALLOUT_GUID,
    0xe9c2d6b5, 0x7f80, 0x8192, 0xd3, 0xa4, 0x1f, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e);

// ALE Recv Accept v6
// {F0D3E7C6-8091-92A3-E4B5-2A3B4C5D6E7F}
DEFINE_GUID(SHADOWSTRIKE_ALE_RECV_ACCEPT_V6_CALLOUT_GUID,
    0xf0d3e7c6, 0x8091, 0x92a3, 0xe4, 0xb5, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e, 0x7f);

// Outbound Transport v4 (for DNS)
// {01E4F8D7-91A2-A3B4-F5C6-3B4C5D6E7F80}
DEFINE_GUID(SHADOWSTRIKE_OUTBOUND_TRANSPORT_V4_CALLOUT_GUID,
    0x01e4f8d7, 0x91a2, 0xa3b4, 0xf5, 0xc6, 0x3b, 0x4c, 0x5d, 0x6e, 0x7f, 0x80);

// Stream v4 (TCP data inspection)
// {12F5A9E8-02B3-B4C5-A6D7-4C5D6E7F8091}
DEFINE_GUID(SHADOWSTRIKE_STREAM_V4_CALLOUT_GUID,
    0x12f5a9e8, 0x02b3, 0xb4c5, 0xa6, 0xd7, 0x4c, 0x5d, 0x6e, 0x7f, 0x80, 0x91);

/**
 * @brief Pool tags.
 */
#define NF_POOL_TAG_GENERAL     'nFsS'
#define NF_POOL_TAG_CONNECTION  'cFsS'
#define NF_POOL_TAG_EVENT       'eFsS'
#define NF_POOL_TAG_DNS         'dFsS'

/**
 * @brief Default configuration values.
 */
#define NF_DEFAULT_BEACON_MIN_SAMPLES       10
#define NF_DEFAULT_BEACON_JITTER_THRESHOLD  20      // 20%
#define NF_DEFAULT_EXFIL_THRESHOLD_MB       100     // 100MB
#define NF_DEFAULT_DNS_RATE_THRESHOLD       100     // queries per minute
#define NF_DEFAULT_PORT_SCAN_THRESHOLD      50      // unique ports per minute
#define NF_DEFAULT_MAX_EVENTS_PER_SEC       5000
#define NF_DEFAULT_DATA_SAMPLE_SIZE         256
#define NF_DEFAULT_DATA_SAMPLE_INTERVAL     10      // every 10th packet

// ============================================================================
// CONNECTION TRACKING
// ============================================================================

/**
 * @brief Tracked connection entry.
 */
typedef struct _NF_CONNECTION_ENTRY {
    LIST_ENTRY ListEntry;
    
    // Connection identification
    UINT64 ConnectionId;
    UINT64 FlowId;
    
    // Endpoints
    SS_SOCKET_ADDRESS LocalAddress;
    SS_SOCKET_ADDRESS RemoteAddress;
    
    // Protocol info
    NETWORK_PROTOCOL Protocol;
    NETWORK_DIRECTION Direction;
    CONNECTION_STATE State;
    UINT32 Flags;
    
    // Process info
    UINT32 ProcessId;
    UINT64 ProcessCreateTime;
    WCHAR ProcessImagePath[MAX_FILE_PATH_LENGTH];
    
    // Remote info
    WCHAR RemoteHostname[MAX_HOSTNAME_LENGTH];
    UINT32 ReputationScore;               // 0-100, 100=trusted
    BOOLEAN ReputationChecked;
    UINT8 Reserved1[3];
    
    // Statistics
    UINT64 BytesSent;
    UINT64 BytesReceived;
    UINT32 PacketsSent;
    UINT32 PacketsReceived;
    UINT64 ConnectTime;
    UINT64 LastActivityTime;
    
    // Beaconing analysis
    UINT64 LastSendTime;
    UINT32 SendIntervals[32];             // Ring buffer of intervals
    UINT32 SendIntervalIndex;
    UINT32 SendIntervalCount;
    UINT32 AverageIntervalMs;
    UINT32 IntervalVariance;
    
    // TLS info (if applicable)
    UINT16 TlsVersion;
    UINT16 CipherSuite;
    CHAR JA3Fingerprint[MAX_JA3_FINGERPRINT_LENGTH];
    BOOLEAN TlsHandshakeComplete;
    BOOLEAN IsMaliciousJA3;
    UINT8 Reserved2[2];
    
    // Threat assessment
    UINT32 ThreatScore;
    NETWORK_THREAT_TYPE ThreatType;
    
    // Reference counting
    volatile LONG RefCount;
} NF_CONNECTION_ENTRY, *PNF_CONNECTION_ENTRY;

// Connection flags
#define NF_CONN_FLAG_MONITORED            0x00000001
#define NF_CONN_FLAG_BLOCKED              0x00000002
#define NF_CONN_FLAG_SUSPICIOUS           0x00000004
#define NF_CONN_FLAG_C2_SUSPECT           0x00000008
#define NF_CONN_FLAG_EXFIL_SUSPECT        0x00000010
#define NF_CONN_FLAG_BEACONING            0x00000020
#define NF_CONN_FLAG_TLS_INSPECTED        0x00000040
#define NF_CONN_FLAG_DNS_OVER_HTTPS       0x00000080
#define NF_CONN_FLAG_FIRST_CONTACT        0x00000100

// ============================================================================
// DNS TRACKING
// ============================================================================

/**
 * @brief DNS query tracking entry.
 */
typedef struct _NF_DNS_ENTRY {
    LIST_ENTRY ListEntry;
    
    // Query info
    UINT16 TransactionId;
    UINT16 QueryType;
    WCHAR QueryName[MAX_DNS_NAME_LENGTH];
    UINT32 QueryNameHash;
    
    // Process info
    UINT32 ProcessId;
    UINT64 QueryTime;
    
    // Response info (if received)
    UINT16 ResponseCode;
    UINT16 AnswerCount;
    SS_IP_ADDRESS ResolvedAddresses[MAX_DNS_ANSWERS];
    UINT32 ResolvedAddressCount;
    UINT32 TTL;
    
    // Analysis
    UINT32 DomainEntropy;                 // * 100
    UINT32 SubdomainLength;
    BOOLEAN IsDGA;
    BOOLEAN IsNewlyRegistered;
    BOOLEAN IsFastFlux;
    BOOLEAN IsSuspicious;
    
    // Threat assessment
    UINT32 ThreatScore;
    NETWORK_THREAT_TYPE ThreatType;
} NF_DNS_ENTRY, *PNF_DNS_ENTRY;

/**
 * @brief DNS tunneling detection state.
 */
typedef struct _NF_DNS_TUNNEL_STATE {
    WCHAR BaseDomain[MAX_DNS_NAME_LENGTH];
    UINT32 BaseDomainHash;
    
    // Statistics
    UINT64 FirstQueryTime;
    UINT64 LastQueryTime;
    UINT32 TotalQueries;
    UINT32 TxtQueries;
    UINT32 UniqueSubdomains;
    UINT32 TotalSubdomainLength;
    UINT32 MaxSubdomainLength;
    UINT64 TotalResponseSize;
    
    // Analysis
    UINT32 AverageEntropy;
    UINT32 QueriesPerMinute;
    BOOLEAN IsTunneling;
    UINT8 Reserved[3];
    
    UINT32 ThreatScore;
    UINT32 Confidence;
} NF_DNS_TUNNEL_STATE, *PNF_DNS_TUNNEL_STATE;

// ============================================================================
// NETWORK FILTER GLOBAL STATE
// ============================================================================

/**
 * @brief Network filter global state.
 */
typedef struct _NETWORK_FILTER_GLOBALS {
    // Initialization state
    BOOLEAN Initialized;
    BOOLEAN Enabled;
    UINT16 Reserved1;
    
    // Configuration
    NETWORK_MONITOR_CONFIG Config;
    
    // WFP handles
    HANDLE WfpEngineHandle;
    UINT32 AleConnectV4CalloutId;
    UINT32 AleConnectV6CalloutId;
    UINT32 AleRecvAcceptV4CalloutId;
    UINT32 AleRecvAcceptV6CalloutId;
    UINT32 OutboundTransportV4CalloutId;
    UINT32 StreamV4CalloutId;
    
    // Filter IDs
    UINT64 AleConnectV4FilterId;
    UINT64 AleConnectV6FilterId;
    UINT64 AleRecvAcceptV4FilterId;
    UINT64 AleRecvAcceptV6FilterId;
    UINT64 OutboundTransportV4FilterId;
    UINT64 StreamV4FilterId;
    
    // Connection tracking
    LIST_ENTRY ConnectionList;
    ERESOURCE ConnectionLock;
    UINT32 ConnectionCount;
    volatile LONG64 NextConnectionId;
    
    // DNS tracking
    LIST_ENTRY DnsQueryList;
    ERESOURCE DnsLock;
    UINT32 DnsQueryCount;
    
    // DNS tunneling state (per domain)
    LIST_ENTRY DnsTunnelStateList;
    UINT32 DnsTunnelStateCount;
    
    // Lookaside lists
    NPAGED_LOOKASIDE_LIST ConnectionLookaside;
    NPAGED_LOOKASIDE_LIST DnsLookaside;
    NPAGED_LOOKASIDE_LIST EventLookaside;
    
    // Statistics
    volatile LONG64 TotalConnectionsMonitored;
    volatile LONG64 TotalConnectionsBlocked;
    volatile LONG64 TotalDnsQueriesMonitored;
    volatile LONG64 TotalDnsQueriesBlocked;
    volatile LONG64 TotalBytesMonitored;
    volatile LONG64 TotalC2Detections;
    volatile LONG64 TotalExfiltrationDetections;
    volatile LONG64 TotalDnsTunnelingDetections;
    volatile LONG64 EventsDropped;
    
    // Rate limiting
    volatile LONG EventsThisSecond;
    UINT64 CurrentSecondStart;
    
    // Device object for WFP
    PDEVICE_OBJECT WfpDeviceObject;
} NETWORK_FILTER_GLOBALS, *PNETWORK_FILTER_GLOBALS;

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the network filtering subsystem.
 * @param DeviceObject Device object for WFP.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
NfFilterInitialize(
    _In_ PDEVICE_OBJECT DeviceObject
    );

/**
 * @brief Shutdown the network filtering subsystem.
 */
VOID
NfFilterShutdown(VOID);

/**
 * @brief Enable or disable network filtering.
 * @param Enable TRUE to enable, FALSE to disable.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
NfFilterSetEnabled(
    _In_ BOOLEAN Enable
    );

/**
 * @brief Update network filter configuration.
 * @param Config New configuration.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
NfFilterUpdateConfig(
    _In_ PNETWORK_MONITOR_CONFIG Config
    );

// ============================================================================
// PUBLIC API - CONNECTION MANAGEMENT
// ============================================================================

/**
 * @brief Find connection by ID.
 * @param ConnectionId Connection ID.
 * @param Connection Output connection pointer.
 * @return STATUS_SUCCESS if found.
 */
NTSTATUS
NfFilterFindConnection(
    _In_ UINT64 ConnectionId,
    _Out_ PNF_CONNECTION_ENTRY* Connection
    );

/**
 * @brief Find connection by flow context.
 * @param FlowId WFP flow ID.
 * @param Connection Output connection pointer.
 * @return STATUS_SUCCESS if found.
 */
NTSTATUS
NfFilterFindConnectionByFlow(
    _In_ UINT64 FlowId,
    _Out_ PNF_CONNECTION_ENTRY* Connection
    );

/**
 * @brief Release connection reference.
 * @param Connection Connection to release.
 */
VOID
NfFilterReleaseConnection(
    _In_ PNF_CONNECTION_ENTRY Connection
    );

/**
 * @brief Block a connection.
 * @param ConnectionId Connection ID.
 * @param Reason Block reason.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
NfFilterBlockConnection(
    _In_ UINT64 ConnectionId,
    _In_ NETWORK_BLOCK_REASON Reason
    );

// ============================================================================
// PUBLIC API - DNS
// ============================================================================

/**
 * @brief Query DNS cache for domain.
 * @param DomainName Domain name.
 * @param Entry Output DNS entry.
 * @return STATUS_SUCCESS if found.
 */
NTSTATUS
NfFilterQueryDnsCache(
    _In_ PCWSTR DomainName,
    _Out_ PNF_DNS_ENTRY Entry
    );

/**
 * @brief Block DNS queries to domain.
 * @param DomainName Domain to block.
 * @param Reason Block reason.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
NfFilterBlockDomain(
    _In_ PCWSTR DomainName,
    _In_ NETWORK_BLOCK_REASON Reason
    );

// ============================================================================
// PUBLIC API - DETECTION
// ============================================================================

/**
 * @brief Check if connection exhibits C2 beaconing.
 * @param ConnectionId Connection ID.
 * @param BeaconingData Output beaconing analysis.
 * @return TRUE if beaconing detected.
 */
BOOLEAN
NfFilterDetectBeaconing(
    _In_ UINT64 ConnectionId,
    _Out_opt_ PBEACONING_DATA BeaconingData
    );

/**
 * @brief Detect DNS tunneling for domain.
 * @param BaseDomain Base domain to analyze.
 * @param TunnelState Output tunnel analysis.
 * @return TRUE if tunneling detected.
 */
BOOLEAN
NfFilterDetectDnsTunneling(
    _In_ PCWSTR BaseDomain,
    _Out_opt_ PNF_DNS_TUNNEL_STATE TunnelState
    );

/**
 * @brief Analyze connection for data exfiltration.
 * @param ConnectionId Connection ID.
 * @param Event Output exfiltration event.
 * @return TRUE if exfiltration detected.
 */
BOOLEAN
NfFilterDetectExfiltration(
    _In_ UINT64 ConnectionId,
    _Out_opt_ PNETWORK_EXFIL_EVENT Event
    );

/**
 * @brief Check JA3 fingerprint against known malicious list.
 * @param JA3Fingerprint JA3 fingerprint string.
 * @return TRUE if fingerprint is known malicious.
 */
BOOLEAN
NfFilterIsKnownMaliciousJA3(
    _In_ PCSTR JA3Fingerprint
    );

// ============================================================================
// PUBLIC API - STATISTICS
// ============================================================================

/**
 * @brief Get network filter statistics.
 * @param Stats Output statistics.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
NfFilterGetStatistics(
    _Out_ PNETWORK_FILTER_GLOBALS Stats
    );

/**
 * @brief Get connection statistics for process.
 * @param ProcessId Process ID.
 * @param ConnectionCount Output connection count.
 * @param BytesSent Output total bytes sent.
 * @param BytesReceived Output total bytes received.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
NfFilterGetProcessNetworkStats(
    _In_ UINT32 ProcessId,
    _Out_ PUINT32 ConnectionCount,
    _Out_ PUINT64 BytesSent,
    _Out_ PUINT64 BytesReceived
    );

// ============================================================================
// WFP CALLOUT FUNCTIONS (Internal)
// ============================================================================

/**
 * @brief ALE Connect classify function.
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
    );

/**
 * @brief ALE Recv Accept classify function.
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
    );

/**
 * @brief Outbound transport classify function (DNS).
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
    );

/**
 * @brief Stream data classify function.
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
    );

/**
 * @brief Callout notify function.
 */
NTSTATUS NTAPI
NfCalloutNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER3* filter
    );

/**
 * @brief Flow delete notify function.
 */
VOID NTAPI
NfFlowDeleteNotify(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext
    );

#endif // SHADOWSTRIKE_NETWORK_FILTER_H
