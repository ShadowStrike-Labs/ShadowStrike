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
 * @version 2.1.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_NETWORK_FILTER_H
#define SHADOWSTRIKE_NETWORK_FILTER_H

#include <fltKernel.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include "../../Shared/NetworkTypes.h"
#include "../../Shared/BehaviorTypes.h"

// ============================================================================
// WFP FILTER CONFIGURATION
// ============================================================================

// GUIDs are declared here, defined via INITGUID in NetworkFilter.c
EXTERN_C const GUID SHADOWSTRIKE_WFP_PROVIDER_GUID;
EXTERN_C const GUID SHADOWSTRIKE_WFP_SUBLAYER_GUID;
EXTERN_C const GUID SHADOWSTRIKE_ALE_CONNECT_V4_CALLOUT_GUID;
EXTERN_C const GUID SHADOWSTRIKE_ALE_CONNECT_V6_CALLOUT_GUID;
EXTERN_C const GUID SHADOWSTRIKE_ALE_RECV_ACCEPT_V4_CALLOUT_GUID;
EXTERN_C const GUID SHADOWSTRIKE_ALE_RECV_ACCEPT_V6_CALLOUT_GUID;
EXTERN_C const GUID SHADOWSTRIKE_OUTBOUND_TRANSPORT_V4_CALLOUT_GUID;
EXTERN_C const GUID SHADOWSTRIKE_STREAM_V4_CALLOUT_GUID;

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
    LIST_ENTRY ListEntry;
    
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
// BLOCKED DOMAIN ENTRY
// ============================================================================

/**
 * @brief Maximum number of blocked domains.
 */
#define NF_MAX_BLOCKED_DOMAINS          4096

/**
 * @brief Blocked domain entry.
 */
typedef struct _NF_BLOCKED_DOMAIN {
    LIST_ENTRY ListEntry;
    WCHAR DomainName[MAX_DNS_NAME_LENGTH];
    UINT32 DomainHash;
    NETWORK_BLOCK_REASON Reason;
} NF_BLOCKED_DOMAIN, *PNF_BLOCKED_DOMAIN;

// ============================================================================
// SAFE STATISTICS STRUCTURE (for external consumption)
// ============================================================================

/**
 * @brief Safe, read-only statistics snapshot.
 *
 * This structure contains only counter values and is safe to copy
 * to user-mode or other kernel components. It does NOT expose
 * kernel handles, locks, or internal pointers.
 */
typedef struct _NF_FILTER_STATISTICS {
    BOOLEAN Initialized;
    BOOLEAN Enabled;
    UINT16 Reserved1;
    
    UINT32 ActiveConnectionCount;
    UINT32 ActiveDnsQueryCount;
    UINT32 BlockedDomainCount;
    
    LONG64 TotalConnectionsMonitored;
    LONG64 TotalConnectionsBlocked;
    LONG64 TotalDnsQueriesMonitored;
    LONG64 TotalDnsQueriesBlocked;
    LONG64 TotalBytesMonitored;
    LONG64 TotalC2Detections;
    LONG64 TotalExfiltrationDetections;
    LONG64 TotalDnsTunnelingDetections;
    LONG64 EventsDropped;
    
    NETWORK_MONITOR_CONFIG CurrentConfig;
} NF_FILTER_STATISTICS, *PNF_FILTER_STATISTICS;

// ============================================================================
// NETWORK FILTER GLOBAL STATE (internal — do not expose outside module)
// ============================================================================

/**
 * @brief Network filter global state.
 */
typedef struct _NETWORK_FILTER_GLOBALS {
    // Initialization state (atomic access only)
    volatile LONG InitState;              // 0=uninit, 1=initializing, 2=initialized
    volatile LONG Enabled;                // 0=disabled, 1=enabled
    
    // Configuration (protected by ConfigLock)
    NETWORK_MONITOR_CONFIG Config;
    EX_PUSH_LOCK ConfigLock;
    
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
    
    // Connection tracking (protected by ConnectionLock)
    LIST_ENTRY ConnectionList;
    EX_PUSH_LOCK ConnectionLock;
    volatile LONG ConnectionCount;
    volatile LONG64 NextConnectionId;
    
    // DNS tracking (protected by DnsLock)
    LIST_ENTRY DnsQueryList;
    EX_PUSH_LOCK DnsLock;
    volatile LONG DnsQueryCount;
    
    // DNS tunneling state (protected by DnsLock)
    LIST_ENTRY DnsTunnelStateList;
    UINT32 DnsTunnelStateCount;
    
    // Blocked domain list (protected by DnsLock)
    LIST_ENTRY BlockedDomainList;
    volatile LONG BlockedDomainCount;
    
    // Lookaside lists
    NPAGED_LOOKASIDE_LIST ConnectionLookaside;
    NPAGED_LOOKASIDE_LIST DnsLookaside;
    NPAGED_LOOKASIDE_LIST EventLookaside;
    
    // Statistics (lock-free atomic access)
    volatile LONG64 TotalConnectionsMonitored;
    volatile LONG64 TotalConnectionsBlocked;
    volatile LONG64 TotalDnsQueriesMonitored;
    volatile LONG64 TotalDnsQueriesBlocked;
    volatile LONG64 TotalBytesMonitored;
    volatile LONG64 TotalC2Detections;
    volatile LONG64 TotalExfiltrationDetections;
    volatile LONG64 TotalDnsTunnelingDetections;
    volatile LONG64 EventsDropped;
    
    // Rate limiting (atomic access)
    volatile LONG EventsThisSecond;
    volatile LONG64 CurrentSecondStart;
    
    // Device object for WFP
    PDEVICE_OBJECT WfpDeviceObject;
    
    // Cleanup work item
    PIO_WORKITEM CleanupWorkItem;
} NETWORK_FILTER_GLOBALS, *PNETWORK_FILTER_GLOBALS;

// Init state constants
#define NF_INIT_STATE_UNINITIALIZED     0
#define NF_INIT_STATE_INITIALIZING      1
#define NF_INIT_STATE_INITIALIZED       2

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
 * @brief Get network filter statistics (safe snapshot).
 * @param Stats Output statistics — contains only counters, no kernel pointers.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
NfFilterGetStatistics(
    _Out_ PNF_FILTER_STATISTICS Stats
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
