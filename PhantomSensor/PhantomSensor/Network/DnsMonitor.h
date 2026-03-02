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
/*++
    ShadowStrike Next-Generation Antivirus
    Module: DnsMonitor.h
    
    Purpose: DNS query monitoring and analysis for detecting
             malicious domain lookups and DNS-based attacks.
             
    Architecture:
    - Intercept DNS queries via WFP
    - Parse and analyze DNS packets
    - Detect DNS tunneling
    - Domain reputation integration
    
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include "../../Shared/NetworkTypes.h"

//=============================================================================
// Pool Tags
//=============================================================================

#define DNS_POOL_TAG_QUERY      'QSND'  // DNS Monitor - Query
#define DNS_POOL_TAG_CACHE      'CSND'  // DNS Monitor - Cache
#define DNS_POOL_TAG_DOMAIN     'DSND'  // DNS Monitor - Domain

//=============================================================================
// Configuration Constants
//=============================================================================

#define DNS_MAX_NAME_LENGTH             255
#define DNS_MAX_LABEL_LENGTH            63
#define DNS_MAX_CACHED_QUERIES          65536
#define DNS_QUERY_TIMEOUT_MS            30000
#define DNS_CACHE_TTL_SECONDS           3600
#define DNS_TUNNEL_ENTROPY_THRESHOLD    75
#define DNS_MAX_PROCESS_CONTEXTS        4096
#define DNS_MAX_TUNNEL_CONTEXTS         4096
#define DNS_MAX_RESPONSE_ADDRESSES      16
#define DNS_MAX_CNAMES                  4
#define DNS_MAX_CACHED_ADDRESSES        8

//=============================================================================
// DNS Record Types
//=============================================================================

typedef enum _DNS_RECORD_TYPE {
    DnsType_A           = 1,
    DnsType_NS          = 2,
    DnsType_CNAME       = 5,
    DnsType_SOA         = 6,
    DnsType_NULL        = 10,
    DnsType_PTR         = 12,
    DnsType_MX          = 15,
    DnsType_TXT         = 16,
    DnsType_AAAA        = 28,
    DnsType_SRV         = 33,
    DnsType_NAPTR       = 35,
    DnsType_ANY         = 255
} DNS_RECORD_TYPE;

//=============================================================================
// DNS Query Flags
//=============================================================================

typedef enum _DNS_QUERY_FLAGS {
    DnsFlag_None            = 0x00000000,
    DnsFlag_Recursive       = 0x00000001,
    DnsFlag_Truncated       = 0x00000002,
    DnsFlag_Authoritative   = 0x00000004,
    DnsFlag_Authenticated   = 0x00000008,
    DnsFlag_CheckingDisabled = 0x00000010,
    DnsFlag_DNSSec          = 0x00000020,
} DNS_QUERY_FLAGS;

//=============================================================================
// DNS Suspicion Flags
//=============================================================================

typedef enum _DNS_SUSPICION {
    DnsSuspicion_None               = 0x00000000,
    DnsSuspicion_HighEntropy        = 0x00000001,
    DnsSuspicion_LongSubdomain      = 0x00000002,
    DnsSuspicion_ManySubdomains     = 0x00000004,
    DnsSuspicion_DGA                = 0x00000008,
    DnsSuspicion_FastFlux           = 0x00000010,
    DnsSuspicion_NewlyRegistered    = 0x00000020,
    DnsSuspicion_TunnelPattern      = 0x00000040,
    DnsSuspicion_UnusualType        = 0x00000080,
    DnsSuspicion_HighVolume         = 0x00000100,
    DnsSuspicion_KnownBad           = 0x00000200,
    DnsSuspicion_HomoglyphAttack    = 0x00000400,
    DnsSuspicion_Typosquatting      = 0x00000800,
} DNS_SUSPICION;

//=============================================================================
// Domain Reputation (named enum, not anonymous inside struct)
//=============================================================================

typedef enum _DNS_REPUTATION {
    DnsReputation_Unknown = 0,
    DnsReputation_Safe,
    DnsReputation_Suspicious,
    DnsReputation_Malicious,
    DnsReputation_Whitelisted,
    DnsReputation_MaxValue
} DNS_REPUTATION;

//=============================================================================
// Resolved Address Entry (supports mixed A/AAAA)
//=============================================================================

typedef struct _DNS_RESOLVED_ADDRESS {
    BOOLEAN IsIPv6;
    union {
        IN_ADDR IPv4;
        IN6_ADDR IPv6;
    } Address;
} DNS_RESOLVED_ADDRESS, *PDNS_RESOLVED_ADDRESS;

//=============================================================================
// DNS Query Entry
//=============================================================================

typedef struct _DNS_QUERY {
    //
    // Query identification
    //
    ULONG64 QueryId;
    USHORT TransactionId;
    
    //
    // Query details
    //
    CHAR DomainName[DNS_MAX_NAME_LENGTH + 1];
    DNS_RECORD_TYPE RecordType;
    DNS_QUERY_FLAGS Flags;
    
    //
    // Source information
    //
    HANDLE ProcessId;
    WCHAR ProcessNameBuffer[260];
    USHORT ProcessNameLength;       // in bytes
    union {
        IN_ADDR IPv4;
        IN6_ADDR IPv6;
    } SourceAddress;
    USHORT SourcePort;
    BOOLEAN IsIPv6;
    
    //
    // DNS server
    //
    union {
        IN_ADDR IPv4;
        IN6_ADDR IPv6;
    } ServerAddress;
    USHORT ServerPort;
    
    //
    // Response (if received)
    //
    struct {
        BOOLEAN Received;
        USHORT ResponseCode;
        ULONG AnswerCount;
        ULONG TTL;
        DNS_RESOLVED_ADDRESS Addresses[DNS_MAX_RESPONSE_ADDRESSES];
        ULONG AddressCount;
        CHAR CNAMEs[DNS_MAX_CNAMES][DNS_MAX_NAME_LENGTH + 1];
        ULONG CNAMECount;
    } Response;
    
    //
    // Timing
    //
    LARGE_INTEGER QueryTime;
    LARGE_INTEGER ResponseTime;
    ULONG LatencyMs;
    
    //
    // Suspicion tracking
    //
    DNS_SUSPICION SuspicionFlags;
    ULONG SuspicionScore;
    
    //
    // Analysis results
    //
    struct {
        ULONG Entropy;                  // 0-800 (scaled by 100)
        ULONG SubdomainCount;
        ULONG MaxLabelLength;
        BOOLEAN ContainsNumbers;
        BOOLEAN ContainsHex;
        BOOLEAN IsBase64Like;
    } Analysis;
    
    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
    LIST_ENTRY ProcessListEntry;
    LIST_ENTRY HashEntry;
    
} DNS_QUERY, *PDNS_QUERY;

//=============================================================================
// Domain Cache Entry
//=============================================================================

typedef struct _DNS_DOMAIN_CACHE {
    //
    // Domain name
    //
    CHAR DomainName[DNS_MAX_NAME_LENGTH + 1];
    ULONG DomainHash;
    
    //
    // Query statistics
    //
    volatile LONG QueryCount;
    volatile LONG UniqueProcesses;
    LARGE_INTEGER FirstSeen;
    LARGE_INTEGER LastSeen;
    
    //
    // Resolution data (supports mixed A/AAAA)
    //
    DNS_RESOLVED_ADDRESS KnownAddresses[DNS_MAX_CACHED_ADDRESSES];
    ULONG AddressCount;
    
    //
    // Reputation
    //
    DNS_REPUTATION Reputation;
    ULONG ReputationScore;              // 0-100 (higher = safer)
    
    //
    // TTL
    //
    LARGE_INTEGER ExpirationTime;
    
    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
    LIST_ENTRY HashEntry;
    
} DNS_DOMAIN_CACHE, *PDNS_DOMAIN_CACHE;

//=============================================================================
// Process DNS Context
//=============================================================================

typedef struct _DNS_PROCESS_CONTEXT {
    //
    // Process identification
    //
    HANDLE ProcessId;
    WCHAR ProcessNameBuffer[260];
    USHORT ProcessNameLength;       // in bytes
    
    //
    // Query tracking
    //
    LIST_ENTRY QueryList;
    KSPIN_LOCK QueryLock;
    volatile LONG QueryCount;
    
    //
    // Statistics
    //
    volatile LONG TotalQueries;
    volatile LONG UniqueDomainsQueried;
    volatile LONG SuspiciousQueries;
    volatile LONG BlockedQueries;
    
    //
    // Behavior tracking
    //
    ULONG QueriesPerMinute;
    ULONG UniqueDomainsPerMinute;
    BOOLEAN HighDnsActivity;
    LARGE_INTEGER CreationTime;
    
    //
    // Reference counting
    //
    volatile LONG RefCount;
    
    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
    
} DNS_PROCESS_CONTEXT, *PDNS_PROCESS_CONTEXT;

//=============================================================================
// DNS Monitor (opaque handle — internals hidden in .c)
//=============================================================================

typedef struct _DNS_MONITOR DNS_MONITOR, *PDNS_MONITOR;

//=============================================================================
// Callback Types
//=============================================================================

typedef VOID (*DNS_QUERY_CALLBACK)(
    _In_ PDNS_QUERY Query,
    _In_opt_ PVOID Context
    );

typedef BOOLEAN (*DNS_BLOCK_CALLBACK)(
    _In_ PDNS_QUERY Query,
    _In_opt_ PVOID Context
    );

//=============================================================================
// Public API - Initialization
//=============================================================================

NTSTATUS
DnsInitialize(
    _Out_ PDNS_MONITOR* Monitor
    );

VOID
DnsShutdown(
    _Inout_ PDNS_MONITOR Monitor
    );

//=============================================================================
// Public API - Query Processing
//=============================================================================

NTSTATUS
DnsProcessQuery(
    _In_ PDNS_MONITOR Monitor,
    _In_ HANDLE ProcessId,
    _In_reads_bytes_(PacketSize) PVOID DnsPacket,
    _In_ ULONG PacketSize,
    _In_ PVOID SourceAddress,
    _In_ USHORT SourcePort,
    _In_ PVOID ServerAddress,
    _In_ USHORT ServerPort,
    _In_ BOOLEAN IsIPv6,
    _Out_opt_ PDNS_QUERY* Query
    );

NTSTATUS
DnsProcessResponse(
    _In_ PDNS_MONITOR Monitor,
    _In_reads_bytes_(PacketSize) PVOID DnsPacket,
    _In_ ULONG PacketSize,
    _In_ PVOID ServerAddress,
    _In_ BOOLEAN IsIPv6
    );

//=============================================================================
// Public API - Query Analysis
//=============================================================================

NTSTATUS
DnsAnalyzeQuery(
    _In_ PDNS_MONITOR Monitor,
    _In_ PCSTR DomainName,
    _Out_ PDNS_SUSPICION SuspicionFlags,
    _Out_ PULONG SuspicionScore
    );

NTSTATUS
DnsDetectTunneling(
    _In_ PDNS_MONITOR Monitor,
    _In_ HANDLE ProcessId,
    _Out_ PBOOLEAN TunnelingDetected,
    _Out_opt_ PULONG Score
    );

NTSTATUS
DnsDetectDGA(
    _In_ PDNS_MONITOR Monitor,
    _In_ PCSTR DomainName,
    _Out_ PBOOLEAN IsDGA,
    _Out_opt_ PULONG Confidence
    );

//=============================================================================
// Public API - Domain Cache
//=============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
DnsLookupDomain(
    _In_ PDNS_MONITOR Monitor,
    _In_ PCSTR DomainName,
    _Out_ PDNS_DOMAIN_CACHE EntryCopy
    );

NTSTATUS
DnsSetDomainReputation(
    _In_ PDNS_MONITOR Monitor,
    _In_ PCSTR DomainName,
    _In_ DNS_REPUTATION Reputation,
    _In_ ULONG Score
    );

//=============================================================================
// Public API - Process Queries
//=============================================================================

NTSTATUS
DnsGetProcessQueries(
    _In_ PDNS_MONITOR Monitor,
    _In_ HANDLE ProcessId,
    _Out_writes_to_(MaxQueries, *QueryCount) PDNS_QUERY* Queries,
    _In_ ULONG MaxQueries,
    _Out_ PULONG QueryCount
    );

NTSTATUS
DnsGetProcessStats(
    _In_ PDNS_MONITOR Monitor,
    _In_ HANDLE ProcessId,
    _Out_ PULONG TotalQueries,
    _Out_ PULONG UniqueDomains,
    _Out_ PULONG SuspiciousQueries
    );

//=============================================================================
// Public API - Callbacks
//=============================================================================

NTSTATUS
DnsRegisterQueryCallback(
    _In_ PDNS_MONITOR Monitor,
    _In_ DNS_QUERY_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

NTSTATUS
DnsRegisterBlockCallback(
    _In_ PDNS_MONITOR Monitor,
    _In_ DNS_BLOCK_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

VOID
DnsUnregisterCallbacks(
    _In_ PDNS_MONITOR Monitor
    );

//=============================================================================
// Public API - Statistics
//=============================================================================

typedef struct _DNS_STATISTICS {
    ULONG64 TotalQueries;
    ULONG64 TotalResponses;
    ULONG64 SuspiciousQueries;
    ULONG64 BlockedQueries;
    ULONG64 TunnelDetections;
    ULONG CacheEntries;
    ULONG TrackedProcesses;
    LARGE_INTEGER UpTime;
} DNS_STATISTICS, *PDNS_STATISTICS;

NTSTATUS
DnsGetStatistics(
    _In_ PDNS_MONITOR Monitor,
    _Out_ PDNS_STATISTICS Stats
    );

#ifdef __cplusplus
}
#endif
