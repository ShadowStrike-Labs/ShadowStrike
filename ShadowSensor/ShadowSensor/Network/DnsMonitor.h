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

//=============================================================================
// DNS Record Types
//=============================================================================

typedef enum _DNS_RECORD_TYPE {
    DnsType_A           = 1,
    DnsType_NS          = 2,
    DnsType_CNAME       = 5,
    DnsType_SOA         = 6,
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
    DnsSuspicion_HighEntropy        = 0x00000001,   // High entropy subdomain
    DnsSuspicion_LongSubdomain      = 0x00000002,   // Unusually long
    DnsSuspicion_ManySubdomains     = 0x00000004,   // Many subdomain levels
    DnsSuspicion_DGA                = 0x00000008,   // DGA-like pattern
    DnsSuspicion_FastFlux           = 0x00000010,   // Fast-flux DNS
    DnsSuspicion_NewlyRegistered    = 0x00000020,   // New domain
    DnsSuspicion_TunnelPattern      = 0x00000040,   // Tunneling pattern
    DnsSuspicion_UnusualType        = 0x00000080,   // Unusual record type
    DnsSuspicion_HighVolume         = 0x00000100,   // High query volume
    DnsSuspicion_KnownBad           = 0x00000200,   // Known malicious
    DnsSuspicion_HomoglyphAttack    = 0x00000400,   // IDN homoglyph
    DnsSuspicion_Typosquatting      = 0x00000800,   // Typosquat of known
} DNS_SUSPICION;

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
    UNICODE_STRING ProcessName;
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
        union {
            IN_ADDR IPv4[16];
            IN6_ADDR IPv6[16];
        } Addresses;
        ULONG AddressCount;
        CHAR CNAMEs[4][DNS_MAX_NAME_LENGTH + 1];
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
        ULONG Entropy;                  // 0-100
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
    // Resolution data
    //
    union {
        IN_ADDR IPv4[8];
        IN6_ADDR IPv6[8];
    } KnownAddresses;
    ULONG AddressCount;
    
    //
    // Reputation
    //
    enum {
        Reputation_Unknown = 0,
        Reputation_Safe,
        Reputation_Suspicious,
        Reputation_Malicious,
        Reputation_Whitelisted
    } Reputation;
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
    UNICODE_STRING ProcessName;
    
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
// DNS Monitor
//=============================================================================

typedef struct _DNS_MONITOR {
    //
    // Initialization state
    //
    BOOLEAN Initialized;
    
    //
    // Query tracking
    //
    LIST_ENTRY QueryList;
    EX_PUSH_LOCK QueryListLock;
    volatile LONG QueryCount;
    volatile LONG64 NextQueryId;
    
    //
    // Transaction ID lookup
    //
    struct {
        LIST_ENTRY* Buckets;
        ULONG BucketCount;
        KSPIN_LOCK Lock;
    } TransactionHash;
    
    //
    // Domain cache
    //
    LIST_ENTRY DomainCache;
    EX_PUSH_LOCK DomainCacheLock;
    volatile LONG CacheEntryCount;
    struct {
        LIST_ENTRY* Buckets;
        ULONG BucketCount;
    } DomainHash;
    
    //
    // Process contexts
    //
    LIST_ENTRY ProcessList;
    EX_PUSH_LOCK ProcessListLock;
    volatile LONG ProcessCount;
    
    //
    // Cleanup timer
    //
    KTIMER CleanupTimer;
    KDPC CleanupDpc;
    
    //
    // Statistics
    //
    struct {
        volatile LONG64 TotalQueries;
        volatile LONG64 TotalResponses;
        volatile LONG64 SuspiciousQueries;
        volatile LONG64 BlockedQueries;
        volatile LONG64 TunnelDetections;
        LARGE_INTEGER StartTime;
    } Stats;
    
    //
    // Configuration
    //
    struct {
        BOOLEAN EnableTunnelingDetection;
        BOOLEAN EnableDGADetection;
        ULONG EntropyThreshold;
        ULONG MaxSubdomainLength;
        ULONG QueryRateThreshold;
    } Config;
    
} DNS_MONITOR, *PDNS_MONITOR;

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

NTSTATUS
DnsLookupDomain(
    _In_ PDNS_MONITOR Monitor,
    _In_ PCSTR DomainName,
    _Out_ PDNS_DOMAIN_CACHE* Entry
    );

NTSTATUS
DnsSetDomainReputation(
    _In_ PDNS_MONITOR Monitor,
    _In_ PCSTR DomainName,
    _In_ ULONG Reputation,
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
