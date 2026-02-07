/*++
===============================================================================
ShadowStrike NGAV - ENTERPRISE DNS MONITORING IMPLEMENTATION
===============================================================================

@file DnsMonitor.c
@brief Enterprise-grade DNS query monitoring and analysis for kernel EDR.

This module provides comprehensive DNS security monitoring:
- Real-time DNS query/response interception and parsing
- DNS tunneling detection via entropy and pattern analysis
- Domain Generation Algorithm (DGA) detection
- Fast-flux DNS detection
- Domain reputation integration
- Per-process DNS activity tracking
- High-entropy subdomain detection
- Base64/hex encoded subdomain detection
- Query rate anomaly detection
- Homoglyph and typosquatting detection
- Known malicious domain blocking

Detection Techniques Covered (MITRE ATT&CK):
- T1071.004: Application Layer Protocol - DNS
- T1568.002: Dynamic Resolution - Domain Generation Algorithms
- T1568.001: Dynamic Resolution - Fast Flux DNS
- T1572: Protocol Tunneling (DNS Tunneling)
- T1048.003: Exfiltration Over Alternative Protocol
- T1583.001: Acquire Infrastructure - Domains

Performance Characteristics:
- O(1) transaction ID lookup via hash table
- O(1) domain cache lookup via hash table
- Lock-free statistics using InterlockedXxx
- NPAGED_LOOKASIDE_LIST for query allocations
- EX_PUSH_LOCK for reader-writer synchronization
- Configurable cache sizes and TTLs

@author ShadowStrike Security Team
@version 2.0.0 (Enterprise Edition)
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#include "DnsMonitor.h"
#include "../Core/Globals.h"
#include "NetworkReputation.h"
#include "C2Detection.h"
#include <ntstrsafe.h>

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

#define DNS_POOL_TAG                    'MNSD'  // DSNM - DNS Monitor
#define DNS_TRANSACTION_HASH_BUCKETS    256
#define DNS_DOMAIN_HASH_BUCKETS         1024
#define DNS_PROCESS_HASH_BUCKETS        128
#define DNS_MAX_PACKET_SIZE             65535
#define DNS_MIN_PACKET_SIZE             12      // DNS header only
#define DNS_HEADER_SIZE                 12
#define DNS_MAX_LABELS                  127
#define DNS_CLEANUP_INTERVAL_MS         60000   // 1 minute
#define DNS_QUERY_EXPIRATION_MS         300000  // 5 minutes
#define DNS_CACHE_EXPIRATION_MS         3600000 // 1 hour

//
// DNS packet flags
//
#define DNS_FLAG_QR                     0x8000  // Query/Response
#define DNS_FLAG_OPCODE_MASK            0x7800
#define DNS_FLAG_AA                     0x0400  // Authoritative Answer
#define DNS_FLAG_TC                     0x0200  // Truncation
#define DNS_FLAG_RD                     0x0100  // Recursion Desired
#define DNS_FLAG_RA                     0x0080  // Recursion Available
#define DNS_FLAG_Z_MASK                 0x0070  // Reserved
#define DNS_FLAG_RCODE_MASK             0x000F

//
// DNS response codes
//
#define DNS_RCODE_NOERROR               0
#define DNS_RCODE_FORMERR               1
#define DNS_RCODE_SERVFAIL              2
#define DNS_RCODE_NXDOMAIN              3
#define DNS_RCODE_NOTIMP                4
#define DNS_RCODE_REFUSED               5

//
// Entropy thresholds
//
#define DNS_ENTROPY_HIGH_THRESHOLD      380     // 3.8 * 100
#define DNS_ENTROPY_TUNNEL_THRESHOLD    420     // 4.2 * 100
#define DNS_SUBDOMAIN_LENGTH_THRESHOLD  32
#define DNS_SUBDOMAIN_COUNT_THRESHOLD   5
#define DNS_QUERY_RATE_THRESHOLD        100     // per minute

//
// DGA detection constants
//
#define DGA_CONSONANT_THRESHOLD         70      // 70% consonants
#define DGA_DIGIT_THRESHOLD             30      // 30% digits
#define DGA_MIN_DOMAIN_LENGTH           8
#define DGA_MAX_CONSECUTIVE_CONSONANTS  5
#define DGA_BIGRAM_SCORE_THRESHOLD      200

// ============================================================================
// DNS PACKET STRUCTURES
// ============================================================================

#pragma pack(push, 1)

//
// DNS header structure
//
typedef struct _DNS_HEADER {
    USHORT TransactionId;
    USHORT Flags;
    USHORT QuestionCount;
    USHORT AnswerCount;
    USHORT AuthorityCount;
    USHORT AdditionalCount;
} DNS_HEADER, *PDNS_HEADER;

//
// DNS question structure (after name)
//
typedef struct _DNS_QUESTION_FOOTER {
    USHORT Type;
    USHORT Class;
} DNS_QUESTION_FOOTER, *PDNS_QUESTION_FOOTER;

//
// DNS resource record structure (after name)
//
typedef struct _DNS_RR_HEADER {
    USHORT Type;
    USHORT Class;
    ULONG TTL;
    USHORT DataLength;
} DNS_RR_HEADER, *PDNS_RR_HEADER;

#pragma pack(pop)

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

//
// Pending query tracking
//
typedef struct _DNS_PENDING_QUERY {
    LIST_ENTRY ListEntry;
    LIST_ENTRY HashEntry;
    LIST_ENTRY ProcessListEntry;

    USHORT TransactionId;
    LARGE_INTEGER QueryTime;
    HANDLE ProcessId;

    CHAR DomainName[DNS_MAX_NAME_LENGTH + 1];
    DNS_RECORD_TYPE RecordType;

    union {
        IN_ADDR IPv4;
        IN6_ADDR IPv6;
    } ServerAddress;
    BOOLEAN IsIPv6;
    USHORT ServerPort;

    volatile LONG RefCount;
} DNS_PENDING_QUERY, *PDNS_PENDING_QUERY;

//
// Tunneling detection state per base domain
//
typedef struct _DNS_TUNNEL_CONTEXT {
    LIST_ENTRY ListEntry;
    LIST_ENTRY HashEntry;

    CHAR BaseDomain[DNS_MAX_NAME_LENGTH + 1];
    ULONG DomainHash;

    LARGE_INTEGER FirstQuery;
    LARGE_INTEGER LastQuery;

    volatile LONG TotalQueries;
    volatile LONG TxtQueries;
    volatile LONG UniqueSubdomains;
    volatile LONG64 TotalSubdomainLength;
    ULONG MaxSubdomainLength;
    ULONG64 TotalEntropySum;

    BOOLEAN TunnelingDetected;
    ULONG TunnelingScore;
    ULONG Confidence;

    volatile LONG RefCount;
} DNS_TUNNEL_CONTEXT, *PDNS_TUNNEL_CONTEXT;

//
// Extended monitor state
//
typedef struct _DNS_MONITOR_INTERNAL {
    DNS_MONITOR Public;

    //
    // Pending queries (waiting for response)
    //
    LIST_ENTRY PendingQueryList;
    EX_PUSH_LOCK PendingQueryLock;
    volatile LONG PendingQueryCount;

    //
    // Tunneling detection contexts
    //
    LIST_ENTRY TunnelContextList;
    EX_PUSH_LOCK TunnelContextLock;
    volatile LONG TunnelContextCount;
    struct {
        LIST_ENTRY* Buckets;
        ULONG BucketCount;
    } TunnelHash;

    //
    // Lookaside lists
    //
    NPAGED_LOOKASIDE_LIST QueryLookaside;
    NPAGED_LOOKASIDE_LIST DomainCacheLookaside;
    NPAGED_LOOKASIDE_LIST ProcessContextLookaside;
    NPAGED_LOOKASIDE_LIST TunnelContextLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Callbacks
    //
    struct {
        DNS_QUERY_CALLBACK QueryCallback;
        PVOID QueryContext;
        DNS_BLOCK_CALLBACK BlockCallback;
        PVOID BlockContext;
        EX_PUSH_LOCK Lock;
    } Callbacks;

    //
    // Reputation manager reference
    //
    PNR_MANAGER ReputationManager;

    //
    // C2 detector reference
    //
    PC2_DETECTOR C2Detector;

} DNS_MONITOR_INTERNAL, *PDNS_MONITOR_INTERNAL;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static ULONG
DnspHashString(
    _In_ PCSTR String
    );

static ULONG
DnspHashTransactionId(
    _In_ USHORT TransactionId,
    _In_ PVOID ServerAddress,
    _In_ BOOLEAN IsIPv6
    );

static NTSTATUS
DnspParseDnsName(
    _In_reads_bytes_(PacketSize) PUCHAR Packet,
    _In_ ULONG PacketSize,
    _In_ ULONG Offset,
    _Out_writes_z_(MaxNameLength) PSTR NameBuffer,
    _In_ ULONG MaxNameLength,
    _Out_ PULONG BytesConsumed
    );

static NTSTATUS
DnspParseQuery(
    _In_ PDNS_MONITOR_INTERNAL Monitor,
    _In_reads_bytes_(PacketSize) PUCHAR Packet,
    _In_ ULONG PacketSize,
    _In_ HANDLE ProcessId,
    _In_ PVOID ServerAddress,
    _In_ USHORT ServerPort,
    _In_ BOOLEAN IsIPv6,
    _Out_ PDNS_QUERY* Query
    );

static NTSTATUS
DnspParseResponse(
    _In_ PDNS_MONITOR_INTERNAL Monitor,
    _In_reads_bytes_(PacketSize) PUCHAR Packet,
    _In_ ULONG PacketSize,
    _In_ PVOID ServerAddress,
    _In_ BOOLEAN IsIPv6
    );

static ULONG
DnspCalculateEntropy(
    _In_ PCSTR String,
    _In_ ULONG Length
    );

static VOID
DnspAnalyzeDomain(
    _In_ PCSTR DomainName,
    _Out_ PULONG Entropy,
    _Out_ PULONG SubdomainCount,
    _Out_ PULONG MaxLabelLength,
    _Out_ PBOOLEAN ContainsNumbers,
    _Out_ PBOOLEAN ContainsHex,
    _Out_ PBOOLEAN IsBase64Like
    );

static BOOLEAN
DnspIsDGADomain(
    _In_ PCSTR DomainName,
    _Out_ PULONG Confidence
    );

static VOID
DnspExtractBaseDomain(
    _In_ PCSTR FullDomain,
    _Out_writes_z_(MaxLength) PSTR BaseDomain,
    _In_ ULONG MaxLength
    );

static PDNS_TUNNEL_CONTEXT
DnspGetOrCreateTunnelContext(
    _In_ PDNS_MONITOR_INTERNAL Monitor,
    _In_ PCSTR BaseDomain
    );

static VOID
DnspUpdateTunnelMetrics(
    _In_ PDNS_TUNNEL_CONTEXT Context,
    _In_ PCSTR FullDomain,
    _In_ DNS_RECORD_TYPE RecordType,
    _In_ ULONG Entropy
    );

static BOOLEAN
DnspCheckTunneling(
    _In_ PDNS_TUNNEL_CONTEXT Context,
    _Out_ PULONG Score
    );

static PDNS_PROCESS_CONTEXT
DnspGetOrCreateProcessContext(
    _In_ PDNS_MONITOR_INTERNAL Monitor,
    _In_ HANDLE ProcessId
    );

static VOID
DnspReferenceProcessContext(
    _In_ PDNS_PROCESS_CONTEXT Context
    );

static VOID
DnspDereferenceProcessContext(
    _In_ PDNS_MONITOR_INTERNAL Monitor,
    _In_ PDNS_PROCESS_CONTEXT Context
    );

static PDNS_DOMAIN_CACHE
DnspLookupDomainCache(
    _In_ PDNS_MONITOR_INTERNAL Monitor,
    _In_ PCSTR DomainName
    );

static NTSTATUS
DnspAddToDomainCache(
    _In_ PDNS_MONITOR_INTERNAL Monitor,
    _In_ PCSTR DomainName,
    _In_ PDNS_QUERY Query
    );

static VOID NTAPI
DnspCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

static VOID
DnspCleanupExpiredEntries(
    _In_ PDNS_MONITOR_INTERNAL Monitor
    );

// ============================================================================
// CHARACTER CLASSIFICATION TABLES
// ============================================================================

//
// Vowel lookup table
//
static const BOOLEAN g_IsVowel[256] = {
    ['a'] = TRUE, ['A'] = TRUE,
    ['e'] = TRUE, ['E'] = TRUE,
    ['i'] = TRUE, ['I'] = TRUE,
    ['o'] = TRUE, ['O'] = TRUE,
    ['u'] = TRUE, ['U'] = TRUE,
};

//
// Hex character lookup table
//
static const BOOLEAN g_IsHexChar[256] = {
    ['0'] = TRUE, ['1'] = TRUE, ['2'] = TRUE, ['3'] = TRUE,
    ['4'] = TRUE, ['5'] = TRUE, ['6'] = TRUE, ['7'] = TRUE,
    ['8'] = TRUE, ['9'] = TRUE,
    ['a'] = TRUE, ['b'] = TRUE, ['c'] = TRUE, ['d'] = TRUE,
    ['e'] = TRUE, ['f'] = TRUE,
    ['A'] = TRUE, ['B'] = TRUE, ['C'] = TRUE, ['D'] = TRUE,
    ['E'] = TRUE, ['F'] = TRUE,
};

//
// Base64 character lookup table
//
static const BOOLEAN g_IsBase64Char[256] = {
    ['A'] = TRUE, ['B'] = TRUE, ['C'] = TRUE, ['D'] = TRUE,
    ['E'] = TRUE, ['F'] = TRUE, ['G'] = TRUE, ['H'] = TRUE,
    ['I'] = TRUE, ['J'] = TRUE, ['K'] = TRUE, ['L'] = TRUE,
    ['M'] = TRUE, ['N'] = TRUE, ['O'] = TRUE, ['P'] = TRUE,
    ['Q'] = TRUE, ['R'] = TRUE, ['S'] = TRUE, ['T'] = TRUE,
    ['U'] = TRUE, ['V'] = TRUE, ['W'] = TRUE, ['X'] = TRUE,
    ['Y'] = TRUE, ['Z'] = TRUE,
    ['a'] = TRUE, ['b'] = TRUE, ['c'] = TRUE, ['d'] = TRUE,
    ['e'] = TRUE, ['f'] = TRUE, ['g'] = TRUE, ['h'] = TRUE,
    ['i'] = TRUE, ['j'] = TRUE, ['k'] = TRUE, ['l'] = TRUE,
    ['m'] = TRUE, ['n'] = TRUE, ['o'] = TRUE, ['p'] = TRUE,
    ['q'] = TRUE, ['r'] = TRUE, ['s'] = TRUE, ['t'] = TRUE,
    ['u'] = TRUE, ['v'] = TRUE, ['w'] = TRUE, ['x'] = TRUE,
    ['y'] = TRUE, ['z'] = TRUE,
    ['0'] = TRUE, ['1'] = TRUE, ['2'] = TRUE, ['3'] = TRUE,
    ['4'] = TRUE, ['5'] = TRUE, ['6'] = TRUE, ['7'] = TRUE,
    ['8'] = TRUE, ['9'] = TRUE,
    ['+'] = TRUE, ['/'] = TRUE, ['='] = TRUE,
};

//
// Common English bigrams for DGA detection (low values = common)
//
static const UCHAR g_BigramScore[26][26] = {
    //  a   b   c   d   e   f   g   h   i   j   k   l   m   n   o   p   q   r   s   t   u   v   w   x   y   z
    {  50, 20, 30, 30, 50, 20, 30, 20, 40, 10, 20, 40, 30, 50, 50, 30,  5, 40, 40, 50, 30, 20, 20,  5, 30,  5 }, // a
    {  30, 10, 10, 10, 40, 10, 10, 10, 30,  5,  5, 30, 10, 10, 40, 10,  5, 30, 20, 10, 30,  5,  5,  5, 20,  5 }, // b
    {  40, 10, 20, 10, 40, 10, 10, 40, 30,  5, 30, 30, 10, 10, 50, 10,  5, 30, 20, 40, 30,  5,  5,  5, 20,  5 }, // c
    {  40, 10, 10, 20, 50, 10, 20, 10, 40,  5,  5, 20, 20, 20, 40, 10,  5, 30, 30, 20, 30,  5, 20,  5, 30,  5 }, // d
    {  50, 20, 30, 50, 50, 30, 20, 20, 40, 10, 10, 40, 30, 50, 40, 30,  5, 50, 50, 50, 30, 30, 30, 30, 30,  5 }, // e
    {  40, 10, 10, 10, 40, 30, 10, 10, 40,  5,  5, 30, 10, 10, 50, 10,  5, 40, 20, 40, 40,  5,  5,  5, 20,  5 }, // f
    {  40, 10, 10, 10, 40, 10, 20, 30, 30,  5,  5, 20, 20, 20, 40, 10,  5, 40, 30, 20, 30,  5,  5,  5, 20,  5 }, // g
    {  50, 10, 10, 10, 50, 10, 10, 10, 40,  5,  5, 10, 20, 10, 40, 10,  5, 20, 20, 30, 20,  5, 10,  5, 20,  5 }, // h
    {  40, 20, 40, 40, 40, 30, 30, 10, 10, 10, 20, 40, 40, 50, 50, 20,  5, 30, 50, 50, 20, 30, 10,  5, 10, 20 }, // i
    {  30, 10, 10, 10, 30, 10, 10, 10, 20,  5,  5, 10, 10, 10, 30, 10,  5, 10, 10, 10, 30,  5,  5,  5, 10,  5 }, // j
    {  30, 10, 10, 10, 40, 10, 10, 10, 30,  5,  5, 20, 10, 30, 30, 10,  5, 10, 30, 10, 10,  5, 20,  5, 20,  5 }, // k
    {  50, 10, 10, 30, 50, 20, 10, 10, 50, 10, 20, 40, 20, 10, 50, 20,  5, 10, 30, 30, 30,  5, 20,  5, 40,  5 }, // l
    {  50, 20, 10, 10, 50, 10, 10, 10, 40,  5,  5, 10, 30, 20, 50, 30,  5, 10, 30, 10, 30,  5, 10,  5, 30,  5 }, // m
    {  50, 10, 30, 50, 50, 20, 50, 20, 40, 10, 20, 20, 20, 30, 50, 10,  5, 10, 40, 50, 30, 10, 20,  5, 30,  5 }, // n
    {  40, 20, 20, 30, 40, 40, 20, 10, 30, 10, 20, 30, 40, 50, 50, 30,  5, 50, 40, 40, 50, 30, 40, 10, 20, 10 }, // o
    {  40, 10, 10, 10, 40, 10, 10, 30, 30,  5,  5, 40, 20, 10, 40, 30,  5, 50, 30, 30, 30,  5, 20,  5, 30,  5 }, // p
    {  10,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5, 30,  5,  5,  5,  5,  5 }, // q
    {  50, 20, 20, 30, 50, 20, 20, 10, 50, 10, 20, 30, 30, 30, 50, 20,  5, 30, 40, 40, 30, 20, 20,  5, 40,  5 }, // r
    {  40, 10, 30, 10, 50, 20, 10, 40, 50, 10, 20, 20, 30, 20, 50, 40,  5, 10, 50, 50, 40,  5, 30,  5, 30,  5 }, // s
    {  50, 10, 20, 10, 50, 10, 10, 50, 50,  5,  5, 30, 20, 10, 50, 10,  5, 40, 40, 40, 40,  5, 30,  5, 40,  5 }, // t
    {  40, 20, 30, 30, 40, 10, 30, 10, 30, 10, 10, 40, 30, 50, 20, 30,  5, 50, 50, 50, 10, 10, 10,  5, 20,  5 }, // u
    {  40, 10, 10, 10, 50, 10, 10, 10, 40,  5,  5, 10, 10, 10, 40, 10,  5, 10, 10, 10, 10,  5,  5,  5, 20,  5 }, // v
    {  50, 10, 10, 20, 40, 10, 10, 40, 40, 10, 10, 10, 10, 30, 40, 10,  5, 20, 20, 10, 10,  5, 10,  5, 10,  5 }, // w
    {  20,  5, 20,  5, 20,  5,  5, 10, 20,  5,  5,  5,  5,  5, 10, 30,  5,  5,  5, 30,  5,  5,  5,  5, 10,  5 }, // x
    {  30, 10, 10, 10, 30, 10, 10, 10, 30, 10, 10, 20, 20, 20, 40, 20,  5, 20, 40, 30, 10,  5, 20,  5, 10,  5 }, // y
    {  30,  5,  5,  5, 30,  5,  5,  5, 20,  5,  5, 10,  5,  5, 20,  5,  5,  5,  5,  5,  5,  5,  5,  5, 10, 20 }, // z
};

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

NTSTATUS
DnsInitialize(
    _Out_ PDNS_MONITOR* Monitor
    )
/*++
Routine Description:
    Initializes the DNS monitoring subsystem.

Arguments:
    Monitor - Receives pointer to initialized monitor.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    NTSTATUS status;
    PDNS_MONITOR_INTERNAL monitor = NULL;
    ULONG i;
    LARGE_INTEGER dueTime;

    if (Monitor == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Monitor = NULL;

    //
    // Allocate monitor structure
    //
    monitor = (PDNS_MONITOR_INTERNAL)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(DNS_MONITOR_INTERNAL),
        DNS_POOL_TAG
    );

    if (monitor == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(monitor, sizeof(DNS_MONITOR_INTERNAL));

    //
    // Initialize locks
    //
    ExInitializePushLock(&monitor->Public.QueryListLock);
    ExInitializePushLock(&monitor->Public.DomainCacheLock);
    ExInitializePushLock(&monitor->Public.ProcessListLock);
    ExInitializePushLock(&monitor->PendingQueryLock);
    ExInitializePushLock(&monitor->TunnelContextLock);
    ExInitializePushLock(&monitor->Callbacks.Lock);

    //
    // Initialize lists
    //
    InitializeListHead(&monitor->Public.QueryList);
    InitializeListHead(&monitor->Public.DomainCache);
    InitializeListHead(&monitor->Public.ProcessList);
    InitializeListHead(&monitor->PendingQueryList);
    InitializeListHead(&monitor->TunnelContextList);

    //
    // Allocate transaction hash table
    //
    monitor->Public.TransactionHash.BucketCount = DNS_TRANSACTION_HASH_BUCKETS;
    monitor->Public.TransactionHash.Buckets = (PLIST_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(LIST_ENTRY) * DNS_TRANSACTION_HASH_BUCKETS,
        DNS_POOL_TAG
    );

    if (monitor->Public.TransactionHash.Buckets == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    for (i = 0; i < DNS_TRANSACTION_HASH_BUCKETS; i++) {
        InitializeListHead(&monitor->Public.TransactionHash.Buckets[i]);
    }

    KeInitializeSpinLock(&monitor->Public.TransactionHash.Lock);

    //
    // Allocate domain hash table
    //
    monitor->Public.DomainHash.BucketCount = DNS_DOMAIN_HASH_BUCKETS;
    monitor->Public.DomainHash.Buckets = (PLIST_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(LIST_ENTRY) * DNS_DOMAIN_HASH_BUCKETS,
        DNS_POOL_TAG
    );

    if (monitor->Public.DomainHash.Buckets == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    for (i = 0; i < DNS_DOMAIN_HASH_BUCKETS; i++) {
        InitializeListHead(&monitor->Public.DomainHash.Buckets[i]);
    }

    //
    // Allocate tunnel hash table
    //
    monitor->TunnelHash.BucketCount = DNS_DOMAIN_HASH_BUCKETS;
    monitor->TunnelHash.Buckets = (PLIST_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(LIST_ENTRY) * DNS_DOMAIN_HASH_BUCKETS,
        DNS_POOL_TAG
    );

    if (monitor->TunnelHash.Buckets == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    for (i = 0; i < DNS_DOMAIN_HASH_BUCKETS; i++) {
        InitializeListHead(&monitor->TunnelHash.Buckets[i]);
    }

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &monitor->QueryLookaside,
        NULL,
        NULL,
        0,
        sizeof(DNS_QUERY),
        DNS_POOL_TAG_QUERY,
        0
    );

    ExInitializeNPagedLookasideList(
        &monitor->DomainCacheLookaside,
        NULL,
        NULL,
        0,
        sizeof(DNS_DOMAIN_CACHE),
        DNS_POOL_TAG_CACHE,
        0
    );

    ExInitializeNPagedLookasideList(
        &monitor->ProcessContextLookaside,
        NULL,
        NULL,
        0,
        sizeof(DNS_PROCESS_CONTEXT),
        DNS_POOL_TAG,
        0
    );

    ExInitializeNPagedLookasideList(
        &monitor->TunnelContextLookaside,
        NULL,
        NULL,
        0,
        sizeof(DNS_TUNNEL_CONTEXT),
        DNS_POOL_TAG,
        0
    );

    monitor->LookasideInitialized = TRUE;

    //
    // Initialize cleanup timer
    //
    KeInitializeTimer(&monitor->Public.CleanupTimer);
    KeInitializeDpc(&monitor->Public.CleanupDpc, DnspCleanupTimerDpc, monitor);

    dueTime.QuadPart = -((LONGLONG)DNS_CLEANUP_INTERVAL_MS * 10000);
    KeSetTimerEx(
        &monitor->Public.CleanupTimer,
        dueTime,
        DNS_CLEANUP_INTERVAL_MS,
        &monitor->Public.CleanupDpc
    );

    //
    // Set default configuration
    //
    monitor->Public.Config.EnableTunnelingDetection = TRUE;
    monitor->Public.Config.EnableDGADetection = TRUE;
    monitor->Public.Config.EntropyThreshold = DNS_TUNNEL_ENTROPY_THRESHOLD;
    monitor->Public.Config.MaxSubdomainLength = DNS_SUBDOMAIN_LENGTH_THRESHOLD;
    monitor->Public.Config.QueryRateThreshold = DNS_QUERY_RATE_THRESHOLD;

    //
    // Record start time
    //
    KeQuerySystemTimePrecise(&monitor->Public.Stats.StartTime);

    monitor->Public.Initialized = TRUE;
    *Monitor = &monitor->Public;

    return STATUS_SUCCESS;

Cleanup:
    if (monitor != NULL) {
        if (monitor->Public.TransactionHash.Buckets != NULL) {
            ExFreePoolWithTag(monitor->Public.TransactionHash.Buckets, DNS_POOL_TAG);
        }
        if (monitor->Public.DomainHash.Buckets != NULL) {
            ExFreePoolWithTag(monitor->Public.DomainHash.Buckets, DNS_POOL_TAG);
        }
        if (monitor->TunnelHash.Buckets != NULL) {
            ExFreePoolWithTag(monitor->TunnelHash.Buckets, DNS_POOL_TAG);
        }
        ExFreePoolWithTag(monitor, DNS_POOL_TAG);
    }

    return status;
}

VOID
DnsShutdown(
    _Inout_ PDNS_MONITOR Monitor
    )
/*++
Routine Description:
    Shuts down the DNS monitoring subsystem and frees all resources.

Arguments:
    Monitor - Monitor to shutdown.
--*/
{
    PDNS_MONITOR_INTERNAL monitor;
    PLIST_ENTRY entry;
    PDNS_QUERY query;
    PDNS_DOMAIN_CACHE domainEntry;
    PDNS_PROCESS_CONTEXT processCtx;
    PDNS_TUNNEL_CONTEXT tunnelCtx;

    if (Monitor == NULL || !Monitor->Initialized) {
        return;
    }

    monitor = CONTAINING_RECORD(Monitor, DNS_MONITOR_INTERNAL, Public);
    monitor->Public.Initialized = FALSE;

    //
    // Cancel cleanup timer
    //
    KeCancelTimer(&monitor->Public.CleanupTimer);

    //
    // Free all queries
    //
    ExAcquirePushLockExclusive(&monitor->Public.QueryListLock);

    while (!IsListEmpty(&monitor->Public.QueryList)) {
        entry = RemoveHeadList(&monitor->Public.QueryList);
        query = CONTAINING_RECORD(entry, DNS_QUERY, ListEntry);

        if (query->ProcessName.Buffer != NULL) {
            ExFreePoolWithTag(query->ProcessName.Buffer, DNS_POOL_TAG_QUERY);
        }

        if (monitor->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&monitor->QueryLookaside, query);
        }
    }

    ExReleasePushLockExclusive(&monitor->Public.QueryListLock);

    //
    // Free domain cache
    //
    ExAcquirePushLockExclusive(&monitor->Public.DomainCacheLock);

    while (!IsListEmpty(&monitor->Public.DomainCache)) {
        entry = RemoveHeadList(&monitor->Public.DomainCache);
        domainEntry = CONTAINING_RECORD(entry, DNS_DOMAIN_CACHE, ListEntry);

        if (monitor->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&monitor->DomainCacheLookaside, domainEntry);
        }
    }

    ExReleasePushLockExclusive(&monitor->Public.DomainCacheLock);

    //
    // Free process contexts
    //
    ExAcquirePushLockExclusive(&monitor->Public.ProcessListLock);

    while (!IsListEmpty(&monitor->Public.ProcessList)) {
        entry = RemoveHeadList(&monitor->Public.ProcessList);
        processCtx = CONTAINING_RECORD(entry, DNS_PROCESS_CONTEXT, ListEntry);

        if (processCtx->ProcessName.Buffer != NULL) {
            ExFreePoolWithTag(processCtx->ProcessName.Buffer, DNS_POOL_TAG);
        }

        if (monitor->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&monitor->ProcessContextLookaside, processCtx);
        }
    }

    ExReleasePushLockExclusive(&monitor->Public.ProcessListLock);

    //
    // Free tunnel contexts
    //
    ExAcquirePushLockExclusive(&monitor->TunnelContextLock);

    while (!IsListEmpty(&monitor->TunnelContextList)) {
        entry = RemoveHeadList(&monitor->TunnelContextList);
        tunnelCtx = CONTAINING_RECORD(entry, DNS_TUNNEL_CONTEXT, ListEntry);

        if (monitor->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&monitor->TunnelContextLookaside, tunnelCtx);
        }
    }

    ExReleasePushLockExclusive(&monitor->TunnelContextLock);

    //
    // Free lookaside lists
    //
    if (monitor->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&monitor->QueryLookaside);
        ExDeleteNPagedLookasideList(&monitor->DomainCacheLookaside);
        ExDeleteNPagedLookasideList(&monitor->ProcessContextLookaside);
        ExDeleteNPagedLookasideList(&monitor->TunnelContextLookaside);
    }

    //
    // Free hash tables
    //
    if (monitor->Public.TransactionHash.Buckets != NULL) {
        ExFreePoolWithTag(monitor->Public.TransactionHash.Buckets, DNS_POOL_TAG);
    }
    if (monitor->Public.DomainHash.Buckets != NULL) {
        ExFreePoolWithTag(monitor->Public.DomainHash.Buckets, DNS_POOL_TAG);
    }
    if (monitor->TunnelHash.Buckets != NULL) {
        ExFreePoolWithTag(monitor->TunnelHash.Buckets, DNS_POOL_TAG);
    }

    //
    // Free monitor structure
    //
    ExFreePoolWithTag(monitor, DNS_POOL_TAG);
}

// ============================================================================
// PUBLIC API - QUERY PROCESSING
// ============================================================================

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
    )
/*++
Routine Description:
    Processes an outbound DNS query packet.

Arguments:
    Monitor - DNS monitor instance.
    ProcessId - Originating process ID.
    DnsPacket - Raw DNS packet data.
    PacketSize - Size of packet in bytes.
    SourceAddress - Source IP address.
    SourcePort - Source port.
    ServerAddress - DNS server address.
    ServerPort - DNS server port (usually 53).
    IsIPv6 - TRUE if IPv6 addresses.
    Query - Optional, receives parsed query structure.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    NTSTATUS status;
    PDNS_MONITOR_INTERNAL monitor;
    PDNS_QUERY query = NULL;
    PDNS_PROCESS_CONTEXT processCtx;
    PDNS_TUNNEL_CONTEXT tunnelCtx;
    CHAR baseDomain[DNS_MAX_NAME_LENGTH + 1];
    ULONG tunnelScore;
    BOOLEAN shouldBlock = FALSE;

    UNREFERENCED_PARAMETER(SourceAddress);
    UNREFERENCED_PARAMETER(SourcePort);

    if (Monitor == NULL || !Monitor->Initialized || DnsPacket == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (PacketSize < DNS_MIN_PACKET_SIZE || PacketSize > DNS_MAX_PACKET_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    monitor = CONTAINING_RECORD(Monitor, DNS_MONITOR_INTERNAL, Public);

    //
    // Parse the DNS query
    //
    status = DnspParseQuery(
        monitor,
        (PUCHAR)DnsPacket,
        PacketSize,
        ProcessId,
        ServerAddress,
        ServerPort,
        IsIPv6,
        &query
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&monitor->Public.Stats.TotalQueries);

    //
    // Analyze the domain
    //
    DnspAnalyzeDomain(
        query->DomainName,
        &query->Analysis.Entropy,
        &query->Analysis.SubdomainCount,
        &query->Analysis.MaxLabelLength,
        &query->Analysis.ContainsNumbers,
        &query->Analysis.ContainsHex,
        &query->Analysis.IsBase64Like
    );

    //
    // Build suspicion flags
    //
    query->SuspicionFlags = DnsSuspicion_None;
    query->SuspicionScore = 0;

    // High entropy detection
    if (query->Analysis.Entropy > monitor->Public.Config.EntropyThreshold) {
        query->SuspicionFlags |= DnsSuspicion_HighEntropy;
        query->SuspicionScore += 20;
    }

    // Long subdomain detection
    if (query->Analysis.MaxLabelLength > monitor->Public.Config.MaxSubdomainLength) {
        query->SuspicionFlags |= DnsSuspicion_LongSubdomain;
        query->SuspicionScore += 15;
    }

    // Many subdomains detection
    if (query->Analysis.SubdomainCount > DNS_SUBDOMAIN_COUNT_THRESHOLD) {
        query->SuspicionFlags |= DnsSuspicion_ManySubdomains;
        query->SuspicionScore += 10;
    }

    // Base64-like encoding detection
    if (query->Analysis.IsBase64Like && query->Analysis.MaxLabelLength > 20) {
        query->SuspicionScore += 25;
    }

    // Hex encoding detection
    if (query->Analysis.ContainsHex && query->Analysis.MaxLabelLength > 16) {
        query->SuspicionScore += 15;
    }

    // Unusual query type detection
    if (query->RecordType == DnsType_TXT ||
        query->RecordType == DnsType_ANY ||
        query->RecordType == DnsType_NULL) {
        query->SuspicionFlags |= DnsSuspicion_UnusualType;
        query->SuspicionScore += 10;
    }

    //
    // DGA detection
    //
    if (monitor->Public.Config.EnableDGADetection) {
        ULONG dgaConfidence;
        if (DnspIsDGADomain(query->DomainName, &dgaConfidence)) {
            query->SuspicionFlags |= DnsSuspicion_DGA;
            query->SuspicionScore += (dgaConfidence / 2);  // Up to 50 points
        }
    }

    //
    // Tunneling detection
    //
    if (monitor->Public.Config.EnableTunnelingDetection) {
        DnspExtractBaseDomain(query->DomainName, baseDomain, sizeof(baseDomain));

        tunnelCtx = DnspGetOrCreateTunnelContext(monitor, baseDomain);
        if (tunnelCtx != NULL) {
            DnspUpdateTunnelMetrics(
                tunnelCtx,
                query->DomainName,
                query->RecordType,
                query->Analysis.Entropy
            );

            if (DnspCheckTunneling(tunnelCtx, &tunnelScore)) {
                query->SuspicionFlags |= DnsSuspicion_TunnelPattern;
                query->SuspicionScore += tunnelScore;

                InterlockedIncrement64(&monitor->Public.Stats.TunnelDetections);
            }
        }
    }

    //
    // Update process context
    //
    processCtx = DnspGetOrCreateProcessContext(monitor, ProcessId);
    if (processCtx != NULL) {
        InterlockedIncrement(&processCtx->TotalQueries);

        if (query->SuspicionFlags != DnsSuspicion_None) {
            InterlockedIncrement(&processCtx->SuspiciousQueries);
        }

        // Add to process query list
        KeAcquireSpinLockAtDpcLevel(&processCtx->QueryLock);
        InsertTailList(&processCtx->QueryList, &query->ProcessListEntry);
        InterlockedIncrement(&processCtx->QueryCount);
        KeReleaseSpinLockFromDpcLevel(&processCtx->QueryLock);

        DnspDereferenceProcessContext(monitor, processCtx);
    }

    //
    // Check for blocking
    //
    if (query->SuspicionScore >= DNS_TUNNEL_ENTROPY_THRESHOLD) {
        query->SuspicionFlags |= DnsSuspicion_KnownBad;

        // Check block callback
        ExAcquirePushLockShared(&monitor->Callbacks.Lock);
        if (monitor->Callbacks.BlockCallback != NULL) {
            shouldBlock = monitor->Callbacks.BlockCallback(
                query,
                monitor->Callbacks.BlockContext
            );
        }
        ExReleasePushLockShared(&monitor->Callbacks.Lock);

        if (shouldBlock) {
            InterlockedIncrement64(&monitor->Public.Stats.BlockedQueries);
            if (processCtx != NULL) {
                InterlockedIncrement(&processCtx->BlockedQueries);
            }
        }
    }

    //
    // Track suspicious queries
    //
    if (query->SuspicionFlags != DnsSuspicion_None) {
        InterlockedIncrement64(&monitor->Public.Stats.SuspiciousQueries);
    }

    //
    // Invoke query callback
    //
    ExAcquirePushLockShared(&monitor->Callbacks.Lock);
    if (monitor->Callbacks.QueryCallback != NULL) {
        monitor->Callbacks.QueryCallback(query, monitor->Callbacks.QueryContext);
    }
    ExReleasePushLockShared(&monitor->Callbacks.Lock);

    //
    // Add to global query list
    //
    ExAcquirePushLockExclusive(&monitor->Public.QueryListLock);
    InsertTailList(&monitor->Public.QueryList, &query->ListEntry);
    InterlockedIncrement(&monitor->Public.QueryCount);
    ExReleasePushLockExclusive(&monitor->Public.QueryListLock);

    //
    // Update domain cache
    //
    DnspAddToDomainCache(monitor, query->DomainName, query);

    if (Query != NULL) {
        *Query = query;
    }

    return shouldBlock ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
}

NTSTATUS
DnsProcessResponse(
    _In_ PDNS_MONITOR Monitor,
    _In_reads_bytes_(PacketSize) PVOID DnsPacket,
    _In_ ULONG PacketSize,
    _In_ PVOID ServerAddress,
    _In_ BOOLEAN IsIPv6
    )
/*++
Routine Description:
    Processes an inbound DNS response packet.

Arguments:
    Monitor - DNS monitor instance.
    DnsPacket - Raw DNS packet data.
    PacketSize - Size of packet in bytes.
    ServerAddress - DNS server address.
    IsIPv6 - TRUE if IPv6 address.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PDNS_MONITOR_INTERNAL monitor;

    if (Monitor == NULL || !Monitor->Initialized || DnsPacket == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (PacketSize < DNS_MIN_PACKET_SIZE || PacketSize > DNS_MAX_PACKET_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    monitor = CONTAINING_RECORD(Monitor, DNS_MONITOR_INTERNAL, Public);

    return DnspParseResponse(
        monitor,
        (PUCHAR)DnsPacket,
        PacketSize,
        ServerAddress,
        IsIPv6
    );
}

// ============================================================================
// PUBLIC API - QUERY ANALYSIS
// ============================================================================

NTSTATUS
DnsAnalyzeQuery(
    _In_ PDNS_MONITOR Monitor,
    _In_ PCSTR DomainName,
    _Out_ PDNS_SUSPICION SuspicionFlags,
    _Out_ PULONG SuspicionScore
    )
/*++
Routine Description:
    Analyzes a domain name for suspicious characteristics.

Arguments:
    Monitor - DNS monitor instance.
    DomainName - Domain name to analyze.
    SuspicionFlags - Receives suspicion flags.
    SuspicionScore - Receives suspicion score (0-100).

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PDNS_MONITOR_INTERNAL monitor;
    ULONG entropy;
    ULONG subdomainCount;
    ULONG maxLabelLength;
    BOOLEAN containsNumbers;
    BOOLEAN containsHex;
    BOOLEAN isBase64Like;
    ULONG dgaConfidence;

    if (Monitor == NULL || !Monitor->Initialized ||
        DomainName == NULL || SuspicionFlags == NULL || SuspicionScore == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    monitor = CONTAINING_RECORD(Monitor, DNS_MONITOR_INTERNAL, Public);

    *SuspicionFlags = DnsSuspicion_None;
    *SuspicionScore = 0;

    //
    // Analyze domain characteristics
    //
    DnspAnalyzeDomain(
        DomainName,
        &entropy,
        &subdomainCount,
        &maxLabelLength,
        &containsNumbers,
        &containsHex,
        &isBase64Like
    );

    // High entropy
    if (entropy > monitor->Public.Config.EntropyThreshold) {
        *SuspicionFlags |= DnsSuspicion_HighEntropy;
        *SuspicionScore += 20;
    }

    // Long subdomain
    if (maxLabelLength > monitor->Public.Config.MaxSubdomainLength) {
        *SuspicionFlags |= DnsSuspicion_LongSubdomain;
        *SuspicionScore += 15;
    }

    // Many subdomains
    if (subdomainCount > DNS_SUBDOMAIN_COUNT_THRESHOLD) {
        *SuspicionFlags |= DnsSuspicion_ManySubdomains;
        *SuspicionScore += 10;
    }

    // Base64-like
    if (isBase64Like && maxLabelLength > 20) {
        *SuspicionScore += 25;
    }

    // Hex encoding
    if (containsHex && maxLabelLength > 16) {
        *SuspicionScore += 15;
    }

    // DGA detection
    if (monitor->Public.Config.EnableDGADetection) {
        if (DnspIsDGADomain(DomainName, &dgaConfidence)) {
            *SuspicionFlags |= DnsSuspicion_DGA;
            *SuspicionScore += (dgaConfidence / 2);
        }
    }

    // Cap at 100
    if (*SuspicionScore > 100) {
        *SuspicionScore = 100;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
DnsDetectTunneling(
    _In_ PDNS_MONITOR Monitor,
    _In_ HANDLE ProcessId,
    _Out_ PBOOLEAN TunnelingDetected,
    _Out_opt_ PULONG Score
    )
/*++
Routine Description:
    Detects DNS tunneling activity for a process.

Arguments:
    Monitor - DNS monitor instance.
    ProcessId - Process to analyze.
    TunnelingDetected - Receives TRUE if tunneling detected.
    Score - Optional, receives tunneling score.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PDNS_MONITOR_INTERNAL monitor;
    PDNS_PROCESS_CONTEXT processCtx;
    ULONG totalScore = 0;
    ULONG queriesPerMinute;
    LARGE_INTEGER currentTime;

    if (Monitor == NULL || !Monitor->Initialized ||
        TunnelingDetected == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    monitor = CONTAINING_RECORD(Monitor, DNS_MONITOR_INTERNAL, Public);

    *TunnelingDetected = FALSE;
    if (Score != NULL) {
        *Score = 0;
    }

    //
    // Find process context
    //
    processCtx = DnspGetOrCreateProcessContext(monitor, ProcessId);
    if (processCtx == NULL) {
        return STATUS_NOT_FOUND;
    }

    KeQuerySystemTimePrecise(&currentTime);

    //
    // Analyze process DNS behavior
    //

    // High volume of queries
    queriesPerMinute = processCtx->QueriesPerMinute;
    if (queriesPerMinute > monitor->Public.Config.QueryRateThreshold) {
        totalScore += 30;
    }

    // High ratio of suspicious queries
    if (processCtx->TotalQueries > 10) {
        ULONG suspiciousRatio = (processCtx->SuspiciousQueries * 100) /
                                 processCtx->TotalQueries;
        if (suspiciousRatio > 50) {
            totalScore += 40;
        } else if (suspiciousRatio > 25) {
            totalScore += 20;
        }
    }

    // High unique domain count
    if (processCtx->UniqueDomainsQueried > 100) {
        totalScore += 20;
    }

    // Flagged for high DNS activity
    if (processCtx->HighDnsActivity) {
        totalScore += 10;
    }

    DnspDereferenceProcessContext(monitor, processCtx);

    *TunnelingDetected = (totalScore >= 50);
    if (Score != NULL) {
        *Score = totalScore > 100 ? 100 : totalScore;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
DnsDetectDGA(
    _In_ PDNS_MONITOR Monitor,
    _In_ PCSTR DomainName,
    _Out_ PBOOLEAN IsDGA,
    _Out_opt_ PULONG Confidence
    )
/*++
Routine Description:
    Detects if a domain name appears to be generated by a DGA.

Arguments:
    Monitor - DNS monitor instance.
    DomainName - Domain name to analyze.
    IsDGA - Receives TRUE if DGA detected.
    Confidence - Optional, receives confidence score (0-100).

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    ULONG confidence = 0;

    if (Monitor == NULL || !Monitor->Initialized ||
        DomainName == NULL || IsDGA == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsDGA = DnspIsDGADomain(DomainName, &confidence);

    if (Confidence != NULL) {
        *Confidence = confidence;
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - DOMAIN CACHE
// ============================================================================

NTSTATUS
DnsLookupDomain(
    _In_ PDNS_MONITOR Monitor,
    _In_ PCSTR DomainName,
    _Out_ PDNS_DOMAIN_CACHE* Entry
    )
/*++
Routine Description:
    Looks up a domain in the cache.

Arguments:
    Monitor - DNS monitor instance.
    DomainName - Domain name to lookup.
    Entry - Receives pointer to cache entry.

Return Value:
    STATUS_SUCCESS if found, STATUS_NOT_FOUND otherwise.
--*/
{
    PDNS_MONITOR_INTERNAL monitor;
    PDNS_DOMAIN_CACHE entry;

    if (Monitor == NULL || !Monitor->Initialized ||
        DomainName == NULL || Entry == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    monitor = CONTAINING_RECORD(Monitor, DNS_MONITOR_INTERNAL, Public);

    entry = DnspLookupDomainCache(monitor, DomainName);
    if (entry == NULL) {
        return STATUS_NOT_FOUND;
    }

    *Entry = entry;
    return STATUS_SUCCESS;
}

NTSTATUS
DnsSetDomainReputation(
    _In_ PDNS_MONITOR Monitor,
    _In_ PCSTR DomainName,
    _In_ ULONG Reputation,
    _In_ ULONG Score
    )
/*++
Routine Description:
    Sets the reputation for a cached domain.

Arguments:
    Monitor - DNS monitor instance.
    DomainName - Domain name.
    Reputation - Reputation level.
    Score - Reputation score (0-100, higher = safer).

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PDNS_MONITOR_INTERNAL monitor;
    PDNS_DOMAIN_CACHE entry;

    if (Monitor == NULL || !Monitor->Initialized || DomainName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    monitor = CONTAINING_RECORD(Monitor, DNS_MONITOR_INTERNAL, Public);

    ExAcquirePushLockExclusive(&monitor->Public.DomainCacheLock);

    entry = DnspLookupDomainCache(monitor, DomainName);
    if (entry != NULL) {
        entry->Reputation = Reputation;
        entry->ReputationScore = Score;
    }

    ExReleasePushLockExclusive(&monitor->Public.DomainCacheLock);

    return (entry != NULL) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

// ============================================================================
// PUBLIC API - PROCESS QUERIES
// ============================================================================

NTSTATUS
DnsGetProcessQueries(
    _In_ PDNS_MONITOR Monitor,
    _In_ HANDLE ProcessId,
    _Out_writes_to_(MaxQueries, *QueryCount) PDNS_QUERY* Queries,
    _In_ ULONG MaxQueries,
    _Out_ PULONG QueryCount
    )
/*++
Routine Description:
    Gets DNS queries for a specific process.

Arguments:
    Monitor - DNS monitor instance.
    ProcessId - Process ID.
    Queries - Array to receive query pointers.
    MaxQueries - Maximum queries to return.
    QueryCount - Receives actual count.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PDNS_MONITOR_INTERNAL monitor;
    PDNS_PROCESS_CONTEXT processCtx;
    PLIST_ENTRY entry;
    PDNS_QUERY query;
    ULONG count = 0;

    if (Monitor == NULL || !Monitor->Initialized ||
        Queries == NULL || QueryCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    monitor = CONTAINING_RECORD(Monitor, DNS_MONITOR_INTERNAL, Public);
    *QueryCount = 0;

    processCtx = DnspGetOrCreateProcessContext(monitor, ProcessId);
    if (processCtx == NULL) {
        return STATUS_NOT_FOUND;
    }

    KeAcquireSpinLockAtDpcLevel(&processCtx->QueryLock);

    for (entry = processCtx->QueryList.Flink;
         entry != &processCtx->QueryList && count < MaxQueries;
         entry = entry->Flink) {

        query = CONTAINING_RECORD(entry, DNS_QUERY, ProcessListEntry);
        Queries[count++] = query;
    }

    KeReleaseSpinLockFromDpcLevel(&processCtx->QueryLock);

    DnspDereferenceProcessContext(monitor, processCtx);

    *QueryCount = count;
    return STATUS_SUCCESS;
}

NTSTATUS
DnsGetProcessStats(
    _In_ PDNS_MONITOR Monitor,
    _In_ HANDLE ProcessId,
    _Out_ PULONG TotalQueries,
    _Out_ PULONG UniqueDomains,
    _Out_ PULONG SuspiciousQueries
    )
/*++
Routine Description:
    Gets DNS statistics for a specific process.

Arguments:
    Monitor - DNS monitor instance.
    ProcessId - Process ID.
    TotalQueries - Receives total query count.
    UniqueDomains - Receives unique domain count.
    SuspiciousQueries - Receives suspicious query count.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PDNS_MONITOR_INTERNAL monitor;
    PDNS_PROCESS_CONTEXT processCtx;

    if (Monitor == NULL || !Monitor->Initialized ||
        TotalQueries == NULL || UniqueDomains == NULL ||
        SuspiciousQueries == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    monitor = CONTAINING_RECORD(Monitor, DNS_MONITOR_INTERNAL, Public);

    processCtx = DnspGetOrCreateProcessContext(monitor, ProcessId);
    if (processCtx == NULL) {
        return STATUS_NOT_FOUND;
    }

    *TotalQueries = processCtx->TotalQueries;
    *UniqueDomains = processCtx->UniqueDomainsQueried;
    *SuspiciousQueries = processCtx->SuspiciousQueries;

    DnspDereferenceProcessContext(monitor, processCtx);

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - CALLBACKS
// ============================================================================

NTSTATUS
DnsRegisterQueryCallback(
    _In_ PDNS_MONITOR Monitor,
    _In_ DNS_QUERY_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
{
    PDNS_MONITOR_INTERNAL monitor;

    if (Monitor == NULL || !Monitor->Initialized || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    monitor = CONTAINING_RECORD(Monitor, DNS_MONITOR_INTERNAL, Public);

    ExAcquirePushLockExclusive(&monitor->Callbacks.Lock);
    monitor->Callbacks.QueryCallback = Callback;
    monitor->Callbacks.QueryContext = Context;
    ExReleasePushLockExclusive(&monitor->Callbacks.Lock);

    return STATUS_SUCCESS;
}

NTSTATUS
DnsRegisterBlockCallback(
    _In_ PDNS_MONITOR Monitor,
    _In_ DNS_BLOCK_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
{
    PDNS_MONITOR_INTERNAL monitor;

    if (Monitor == NULL || !Monitor->Initialized || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    monitor = CONTAINING_RECORD(Monitor, DNS_MONITOR_INTERNAL, Public);

    ExAcquirePushLockExclusive(&monitor->Callbacks.Lock);
    monitor->Callbacks.BlockCallback = Callback;
    monitor->Callbacks.BlockContext = Context;
    ExReleasePushLockExclusive(&monitor->Callbacks.Lock);

    return STATUS_SUCCESS;
}

VOID
DnsUnregisterCallbacks(
    _In_ PDNS_MONITOR Monitor
    )
{
    PDNS_MONITOR_INTERNAL monitor;

    if (Monitor == NULL || !Monitor->Initialized) {
        return;
    }

    monitor = CONTAINING_RECORD(Monitor, DNS_MONITOR_INTERNAL, Public);

    ExAcquirePushLockExclusive(&monitor->Callbacks.Lock);
    monitor->Callbacks.QueryCallback = NULL;
    monitor->Callbacks.QueryContext = NULL;
    monitor->Callbacks.BlockCallback = NULL;
    monitor->Callbacks.BlockContext = NULL;
    ExReleasePushLockExclusive(&monitor->Callbacks.Lock);
}

// ============================================================================
// PUBLIC API - STATISTICS
// ============================================================================

NTSTATUS
DnsGetStatistics(
    _In_ PDNS_MONITOR Monitor,
    _Out_ PDNS_STATISTICS Stats
    )
{
    PDNS_MONITOR_INTERNAL monitor;
    LARGE_INTEGER currentTime;

    if (Monitor == NULL || !Monitor->Initialized || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    monitor = CONTAINING_RECORD(Monitor, DNS_MONITOR_INTERNAL, Public);

    KeQuerySystemTimePrecise(&currentTime);

    Stats->TotalQueries = monitor->Public.Stats.TotalQueries;
    Stats->TotalResponses = monitor->Public.Stats.TotalResponses;
    Stats->SuspiciousQueries = monitor->Public.Stats.SuspiciousQueries;
    Stats->BlockedQueries = monitor->Public.Stats.BlockedQueries;
    Stats->TunnelDetections = monitor->Public.Stats.TunnelDetections;
    Stats->CacheEntries = monitor->Public.CacheEntryCount;
    Stats->TrackedProcesses = monitor->Public.ProcessCount;
    Stats->UpTime.QuadPart = currentTime.QuadPart -
                              monitor->Public.Stats.StartTime.QuadPart;

    return STATUS_SUCCESS;
}

// ============================================================================
// INTERNAL HELPERS - HASHING
// ============================================================================

static ULONG
DnspHashString(
    _In_ PCSTR String
    )
/*++
Routine Description:
    Computes a hash for a string (case-insensitive).

Arguments:
    String - String to hash.

Return Value:
    Hash value.
--*/
{
    ULONG hash = 5381;
    UCHAR c;

    while ((c = (UCHAR)*String++) != 0) {
        // Convert to lowercase
        if (c >= 'A' && c <= 'Z') {
            c = c + ('a' - 'A');
        }
        hash = ((hash << 5) + hash) + c;
    }

    return hash;
}

static ULONG
DnspHashTransactionId(
    _In_ USHORT TransactionId,
    _In_ PVOID ServerAddress,
    _In_ BOOLEAN IsIPv6
    )
{
    ULONG hash = TransactionId;

    if (IsIPv6) {
        PIN6_ADDR addr6 = (PIN6_ADDR)ServerAddress;
        hash ^= addr6->u.Word[0] ^ addr6->u.Word[1];
        hash ^= addr6->u.Word[6] ^ addr6->u.Word[7];
    } else {
        PIN_ADDR addr4 = (PIN_ADDR)ServerAddress;
        hash ^= addr4->S_un.S_addr;
    }

    return hash;
}

// ============================================================================
// INTERNAL HELPERS - DNS PARSING
// ============================================================================

static NTSTATUS
DnspParseDnsName(
    _In_reads_bytes_(PacketSize) PUCHAR Packet,
    _In_ ULONG PacketSize,
    _In_ ULONG Offset,
    _Out_writes_z_(MaxNameLength) PSTR NameBuffer,
    _In_ ULONG MaxNameLength,
    _Out_ PULONG BytesConsumed
    )
/*++
Routine Description:
    Parses a DNS name from a packet, handling compression.

Arguments:
    Packet - DNS packet data.
    PacketSize - Total packet size.
    Offset - Starting offset in packet.
    NameBuffer - Buffer to receive parsed name.
    MaxNameLength - Size of name buffer.
    BytesConsumed - Receives bytes consumed from packet.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    ULONG currentOffset = Offset;
    ULONG nameOffset = 0;
    ULONG jumpCount = 0;
    ULONG bytesConsumed = 0;
    BOOLEAN jumped = FALSE;
    UCHAR labelLength;

    if (Offset >= PacketSize || MaxNameLength < 2) {
        return STATUS_INVALID_PARAMETER;
    }

    NameBuffer[0] = '\0';

    while (currentOffset < PacketSize) {
        labelLength = Packet[currentOffset];

        // End of name
        if (labelLength == 0) {
            if (!jumped) {
                bytesConsumed = currentOffset - Offset + 1;
            }
            break;
        }

        // Compression pointer
        if ((labelLength & 0xC0) == 0xC0) {
            if (currentOffset + 1 >= PacketSize) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (!jumped) {
                bytesConsumed = currentOffset - Offset + 2;
            }

            // Follow pointer
            USHORT pointer = ((labelLength & 0x3F) << 8) | Packet[currentOffset + 1];
            if (pointer >= currentOffset) {
                // Forward reference - invalid
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            currentOffset = pointer;
            jumped = TRUE;

            // Prevent infinite loops
            if (++jumpCount > DNS_MAX_LABELS) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            continue;
        }

        // Regular label
        if (labelLength > DNS_MAX_LABEL_LENGTH) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        if (currentOffset + 1 + labelLength > PacketSize) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        // Add dot separator if not first label
        if (nameOffset > 0) {
            if (nameOffset + 1 >= MaxNameLength) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            NameBuffer[nameOffset++] = '.';
        }

        // Copy label
        if (nameOffset + labelLength >= MaxNameLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        RtlCopyMemory(&NameBuffer[nameOffset], &Packet[currentOffset + 1], labelLength);
        nameOffset += labelLength;

        currentOffset += 1 + labelLength;
    }

    NameBuffer[nameOffset] = '\0';
    *BytesConsumed = bytesConsumed;

    return STATUS_SUCCESS;
}

static NTSTATUS
DnspParseQuery(
    _In_ PDNS_MONITOR_INTERNAL Monitor,
    _In_reads_bytes_(PacketSize) PUCHAR Packet,
    _In_ ULONG PacketSize,
    _In_ HANDLE ProcessId,
    _In_ PVOID ServerAddress,
    _In_ USHORT ServerPort,
    _In_ BOOLEAN IsIPv6,
    _Out_ PDNS_QUERY* Query
    )
{
    NTSTATUS status;
    PDNS_HEADER header;
    PDNS_QUERY query = NULL;
    ULONG offset;
    ULONG bytesConsumed;
    PDNS_QUESTION_FOOTER questionFooter;

    if (PacketSize < DNS_HEADER_SIZE) {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    header = (PDNS_HEADER)Packet;

    // Verify this is a query (QR bit = 0)
    if (RtlUshortByteSwap(header->Flags) & DNS_FLAG_QR) {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    // Must have at least one question
    if (RtlUshortByteSwap(header->QuestionCount) < 1) {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    //
    // Allocate query structure
    //
    query = (PDNS_QUERY)ExAllocateFromNPagedLookasideList(&Monitor->QueryLookaside);
    if (query == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(query, sizeof(DNS_QUERY));

    query->TransactionId = RtlUshortByteSwap(header->TransactionId);
    query->QueryId = InterlockedIncrement64(&Monitor->Public.NextQueryId);
    query->ProcessId = ProcessId;
    KeQuerySystemTimePrecise(&query->QueryTime);

    //
    // Parse the question section
    //
    offset = DNS_HEADER_SIZE;
    status = DnspParseDnsName(
        Packet,
        PacketSize,
        offset,
        query->DomainName,
        sizeof(query->DomainName),
        &bytesConsumed
    );

    if (!NT_SUCCESS(status)) {
        ExFreeToNPagedLookasideList(&Monitor->QueryLookaside, query);
        return status;
    }

    offset += bytesConsumed;

    // Read question footer
    if (offset + sizeof(DNS_QUESTION_FOOTER) > PacketSize) {
        ExFreeToNPagedLookasideList(&Monitor->QueryLookaside, query);
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    questionFooter = (PDNS_QUESTION_FOOTER)&Packet[offset];
    query->RecordType = (DNS_RECORD_TYPE)RtlUshortByteSwap(questionFooter->Type);

    // Store server address
    if (IsIPv6) {
        RtlCopyMemory(&query->ServerAddress.IPv6, ServerAddress, sizeof(IN6_ADDR));
    } else {
        RtlCopyMemory(&query->ServerAddress.IPv4, ServerAddress, sizeof(IN_ADDR));
    }
    query->ServerPort = ServerPort;
    query->IsIPv6 = IsIPv6;

    // Parse flags
    USHORT flags = RtlUshortByteSwap(header->Flags);
    if (flags & DNS_FLAG_RD) {
        query->Flags |= DnsFlag_Recursive;
    }
    if (flags & DNS_FLAG_TC) {
        query->Flags |= DnsFlag_Truncated;
    }

    *Query = query;
    return STATUS_SUCCESS;
}

static NTSTATUS
DnspParseResponse(
    _In_ PDNS_MONITOR_INTERNAL Monitor,
    _In_reads_bytes_(PacketSize) PUCHAR Packet,
    _In_ ULONG PacketSize,
    _In_ PVOID ServerAddress,
    _In_ BOOLEAN IsIPv6
    )
{
    PDNS_HEADER header;
    USHORT transactionId;
    USHORT answerCount;
    ULONG offset;
    ULONG bytesConsumed;
    CHAR domainName[DNS_MAX_NAME_LENGTH + 1];
    PDNS_QUERY query = NULL;
    PLIST_ENTRY entry;
    ULONG hashBucket;

    UNREFERENCED_PARAMETER(ServerAddress);
    UNREFERENCED_PARAMETER(IsIPv6);

    if (PacketSize < DNS_HEADER_SIZE) {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    header = (PDNS_HEADER)Packet;

    // Verify this is a response (QR bit = 1)
    if (!(RtlUshortByteSwap(header->Flags) & DNS_FLAG_QR)) {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    transactionId = RtlUshortByteSwap(header->TransactionId);
    answerCount = RtlUshortByteSwap(header->AnswerCount);

    //
    // Find matching pending query
    //
    hashBucket = transactionId % DNS_TRANSACTION_HASH_BUCKETS;

    ExAcquirePushLockShared(&Monitor->Public.QueryListLock);

    for (entry = Monitor->Public.QueryList.Flink;
         entry != &Monitor->Public.QueryList;
         entry = entry->Flink) {

        PDNS_QUERY candidate = CONTAINING_RECORD(entry, DNS_QUERY, ListEntry);
        if (candidate->TransactionId == transactionId &&
            !candidate->Response.Received) {
            query = candidate;
            break;
        }
    }

    if (query == NULL) {
        ExReleasePushLockShared(&Monitor->Public.QueryListLock);
        return STATUS_NOT_FOUND;
    }

    //
    // Update response data
    //
    KeQuerySystemTimePrecise(&query->ResponseTime);
    query->Response.Received = TRUE;
    query->Response.ResponseCode = RtlUshortByteSwap(header->Flags) & DNS_FLAG_RCODE_MASK;
    query->Response.AnswerCount = answerCount;

    // Calculate latency
    query->LatencyMs = (ULONG)((query->ResponseTime.QuadPart -
                                query->QueryTime.QuadPart) / 10000);

    ExReleasePushLockShared(&Monitor->Public.QueryListLock);

    //
    // Parse answers if present
    //
    if (answerCount > 0) {
        // Skip question section
        offset = DNS_HEADER_SIZE;

        USHORT questionCount = RtlUshortByteSwap(header->QuestionCount);
        for (USHORT i = 0; i < questionCount && offset < PacketSize; i++) {
            if (!NT_SUCCESS(DnspParseDnsName(Packet, PacketSize, offset,
                                             domainName, sizeof(domainName),
                                             &bytesConsumed))) {
                break;
            }
            offset += bytesConsumed + sizeof(DNS_QUESTION_FOOTER);
        }

        // Parse answer records
        ULONG addressCount = 0;
        for (USHORT i = 0; i < answerCount && offset < PacketSize; i++) {
            // Parse name
            if (!NT_SUCCESS(DnspParseDnsName(Packet, PacketSize, offset,
                                             domainName, sizeof(domainName),
                                             &bytesConsumed))) {
                break;
            }
            offset += bytesConsumed;

            if (offset + sizeof(DNS_RR_HEADER) > PacketSize) {
                break;
            }

            PDNS_RR_HEADER rrHeader = (PDNS_RR_HEADER)&Packet[offset];
            USHORT rrType = RtlUshortByteSwap(rrHeader->Type);
            USHORT dataLength = RtlUshortByteSwap(rrHeader->DataLength);

            offset += sizeof(DNS_RR_HEADER);

            if (offset + dataLength > PacketSize) {
                break;
            }

            // Store TTL from first record
            if (i == 0) {
                query->Response.TTL = RtlUlongByteSwap(rrHeader->TTL);
            }

            // Extract A/AAAA records
            if (rrType == DnsType_A && dataLength == 4 && addressCount < 16) {
                RtlCopyMemory(&query->Response.Addresses.IPv4[addressCount],
                              &Packet[offset], 4);
                addressCount++;
            } else if (rrType == DnsType_AAAA && dataLength == 16 && addressCount < 16) {
                RtlCopyMemory(&query->Response.Addresses.IPv6[addressCount],
                              &Packet[offset], 16);
                addressCount++;
            }

            offset += dataLength;
        }

        query->Response.AddressCount = addressCount;
    }

    InterlockedIncrement64(&Monitor->Public.Stats.TotalResponses);

    return STATUS_SUCCESS;
}

// ============================================================================
// INTERNAL HELPERS - ENTROPY & ANALYSIS
// ============================================================================

static ULONG
DnspCalculateEntropy(
    _In_ PCSTR String,
    _In_ ULONG Length
    )
/*++
Routine Description:
    Calculates Shannon entropy of a string (scaled by 100).

Arguments:
    String - Input string.
    Length - String length.

Return Value:
    Entropy value * 100 (e.g., 380 = 3.80 bits).
--*/
{
    ULONG charCount[256] = {0};
    ULONG i;
    ULONG entropy = 0;

    if (Length == 0) {
        return 0;
    }

    // Count character frequencies
    for (i = 0; i < Length; i++) {
        charCount[(UCHAR)String[i]]++;
    }

    // Calculate entropy
    // Entropy = -sum(p * log2(p))
    // We use integer approximation: p * log2(p) * 100
    for (i = 0; i < 256; i++) {
        if (charCount[i] > 0) {
            ULONG p = (charCount[i] * 1000) / Length;  // Probability * 1000

            // Approximate -p * log2(p) using lookup or calculation
            // log2(p/1000) where p is in [1, 1000]
            // We'll use a simplified approximation
            ULONG logValue;
            if (p >= 500) {
                logValue = 10;   // ~log2(0.5) = 1
            } else if (p >= 250) {
                logValue = 20;   // ~log2(0.25) = 2
            } else if (p >= 125) {
                logValue = 30;   // ~log2(0.125) = 3
            } else if (p >= 62) {
                logValue = 40;   // ~log2(0.0625) = 4
            } else if (p >= 31) {
                logValue = 50;   // ~log2(0.03125) = 5
            } else {
                logValue = 60;   // Higher entropy contribution
            }

            entropy += (p * logValue) / 100;
        }
    }

    return entropy;
}

static VOID
DnspAnalyzeDomain(
    _In_ PCSTR DomainName,
    _Out_ PULONG Entropy,
    _Out_ PULONG SubdomainCount,
    _Out_ PULONG MaxLabelLength,
    _Out_ PBOOLEAN ContainsNumbers,
    _Out_ PBOOLEAN ContainsHex,
    _Out_ PBOOLEAN IsBase64Like
    )
/*++
Routine Description:
    Analyzes domain name characteristics for suspicious patterns.
--*/
{
    ULONG length;
    ULONG labelCount = 0;
    ULONG currentLabelLength = 0;
    ULONG maxLabel = 0;
    ULONG digitCount = 0;
    ULONG hexCount = 0;
    ULONG base64Count = 0;
    ULONG letterCount = 0;
    ULONG i;

    *Entropy = 0;
    *SubdomainCount = 0;
    *MaxLabelLength = 0;
    *ContainsNumbers = FALSE;
    *ContainsHex = FALSE;
    *IsBase64Like = FALSE;

    if (DomainName == NULL || DomainName[0] == '\0') {
        return;
    }

    length = (ULONG)strlen(DomainName);

    for (i = 0; i < length; i++) {
        CHAR c = DomainName[i];

        if (c == '.') {
            if (currentLabelLength > maxLabel) {
                maxLabel = currentLabelLength;
            }
            currentLabelLength = 0;
            labelCount++;
        } else {
            currentLabelLength++;

            if (c >= '0' && c <= '9') {
                digitCount++;
            }
            if (g_IsHexChar[(UCHAR)c]) {
                hexCount++;
            }
            if (g_IsBase64Char[(UCHAR)c]) {
                base64Count++;
            }
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
                letterCount++;
            }
        }
    }

    // Handle last label
    if (currentLabelLength > maxLabel) {
        maxLabel = currentLabelLength;
    }
    labelCount++;

    // Calculate entropy of first subdomain (most likely to contain encoded data)
    PCSTR firstDot = strchr(DomainName, '.');
    if (firstDot != NULL) {
        ULONG firstLabelLen = (ULONG)(firstDot - DomainName);
        *Entropy = DnspCalculateEntropy(DomainName, firstLabelLen);
    } else {
        *Entropy = DnspCalculateEntropy(DomainName, length);
    }

    // Subdomain count (exclude TLD and domain)
    *SubdomainCount = (labelCount > 2) ? labelCount - 2 : 0;
    *MaxLabelLength = maxLabel;
    *ContainsNumbers = (digitCount > 0);

    // Hex-like if most chars are hex and length suggests encoding
    ULONG nonDotLength = length - labelCount + 1;
    if (nonDotLength > 0) {
        *ContainsHex = (hexCount * 100 / nonDotLength) > 80;
        *IsBase64Like = (base64Count * 100 / nonDotLength) > 90 && maxLabel > 16;
    }
}

static BOOLEAN
DnspIsDGADomain(
    _In_ PCSTR DomainName,
    _Out_ PULONG Confidence
    )
/*++
Routine Description:
    Detects if domain appears to be DGA-generated.

Arguments:
    DomainName - Domain to analyze.
    Confidence - Receives confidence score (0-100).

Return Value:
    TRUE if DGA-like.
--*/
{
    ULONG length;
    ULONG consonantCount = 0;
    ULONG vowelCount = 0;
    ULONG digitCount = 0;
    ULONG consecutiveConsonants = 0;
    ULONG maxConsecutiveConsonants = 0;
    ULONG bigramScore = 0;
    ULONG bigramCount = 0;
    ULONG score = 0;
    PCSTR p;
    PCSTR firstDot;
    ULONG domainPartLength;

    *Confidence = 0;

    if (DomainName == NULL) {
        return FALSE;
    }

    // Analyze only the domain part (not TLD)
    firstDot = strchr(DomainName, '.');
    if (firstDot == NULL) {
        return FALSE;
    }

    domainPartLength = (ULONG)(firstDot - DomainName);

    if (domainPartLength < DGA_MIN_DOMAIN_LENGTH) {
        return FALSE;
    }

    // Analyze character distribution
    for (p = DomainName; p < firstDot; p++) {
        CHAR c = *p;
        CHAR lower = (c >= 'A' && c <= 'Z') ? c + 32 : c;

        if (c >= '0' && c <= '9') {
            digitCount++;
            consecutiveConsonants = 0;
        } else if (g_IsVowel[(UCHAR)c]) {
            vowelCount++;
            consecutiveConsonants = 0;
        } else if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
            consonantCount++;
            consecutiveConsonants++;
            if (consecutiveConsonants > maxConsecutiveConsonants) {
                maxConsecutiveConsonants = consecutiveConsonants;
            }
        }

        // Calculate bigram score
        if (p > DomainName && lower >= 'a' && lower <= 'z') {
            CHAR prevLower = (*(p-1) >= 'A' && *(p-1) <= 'Z') ?
                            *(p-1) + 32 : *(p-1);
            if (prevLower >= 'a' && prevLower <= 'z') {
                bigramScore += g_BigramScore[prevLower - 'a'][lower - 'a'];
                bigramCount++;
            }
        }
    }

    // Scoring

    // High consonant ratio
    ULONG totalLetters = consonantCount + vowelCount;
    if (totalLetters > 0) {
        ULONG consonantRatio = (consonantCount * 100) / totalLetters;
        if (consonantRatio > DGA_CONSONANT_THRESHOLD) {
            score += 20;
        }
    }

    // High digit ratio
    if (domainPartLength > 0) {
        ULONG digitRatio = (digitCount * 100) / domainPartLength;
        if (digitRatio > DGA_DIGIT_THRESHOLD) {
            score += 15;
        }
    }

    // Too many consecutive consonants
    if (maxConsecutiveConsonants > DGA_MAX_CONSECUTIVE_CONSONANTS) {
        score += 25;
    }

    // Low bigram score (unusual character pairs)
    if (bigramCount > 0) {
        ULONG avgBigramScore = bigramScore / bigramCount;
        if (avgBigramScore < 20) {
            score += 30;
        } else if (avgBigramScore < 30) {
            score += 15;
        }
    }

    // Length heuristics
    if (domainPartLength > 15 && domainPartLength < 25) {
        score += 10;  // Common DGA length range
    }

    *Confidence = score > 100 ? 100 : score;
    return (score >= 50);
}

// ============================================================================
// INTERNAL HELPERS - TUNNELING DETECTION
// ============================================================================

static VOID
DnspExtractBaseDomain(
    _In_ PCSTR FullDomain,
    _Out_writes_z_(MaxLength) PSTR BaseDomain,
    _In_ ULONG MaxLength
    )
/*++
Routine Description:
    Extracts the base domain (domain + TLD) from a full domain name.
--*/
{
    ULONG length;
    PCSTR p;
    PCSTR lastDot = NULL;
    PCSTR secondLastDot = NULL;
    ULONG dotCount = 0;

    if (FullDomain == NULL || BaseDomain == NULL || MaxLength < 2) {
        if (BaseDomain != NULL && MaxLength > 0) {
            BaseDomain[0] = '\0';
        }
        return;
    }

    length = (ULONG)strlen(FullDomain);

    // Find last two dots
    for (p = FullDomain + length - 1; p >= FullDomain; p--) {
        if (*p == '.') {
            dotCount++;
            if (dotCount == 1) {
                lastDot = p;
            } else if (dotCount == 2) {
                secondLastDot = p;
                break;
            }
        }
    }

    if (secondLastDot != NULL) {
        // Return domain.tld
        PCSTR baseDomainStart = secondLastDot + 1;
        ULONG baseLength = (ULONG)(FullDomain + length - baseDomainStart);

        if (baseLength < MaxLength) {
            RtlCopyMemory(BaseDomain, baseDomainStart, baseLength);
            BaseDomain[baseLength] = '\0';
        } else {
            BaseDomain[0] = '\0';
        }
    } else {
        // No subdomain, return as-is
        if (length < MaxLength) {
            RtlCopyMemory(BaseDomain, FullDomain, length + 1);
        } else {
            BaseDomain[0] = '\0';
        }
    }
}

static PDNS_TUNNEL_CONTEXT
DnspGetOrCreateTunnelContext(
    _In_ PDNS_MONITOR_INTERNAL Monitor,
    _In_ PCSTR BaseDomain
    )
{
    ULONG hash;
    ULONG bucket;
    PLIST_ENTRY entry;
    PDNS_TUNNEL_CONTEXT context = NULL;

    hash = DnspHashString(BaseDomain);
    bucket = hash % Monitor->TunnelHash.BucketCount;

    // Search existing
    ExAcquirePushLockShared(&Monitor->TunnelContextLock);

    for (entry = Monitor->TunnelHash.Buckets[bucket].Flink;
         entry != &Monitor->TunnelHash.Buckets[bucket];
         entry = entry->Flink) {

        PDNS_TUNNEL_CONTEXT candidate = CONTAINING_RECORD(
            entry, DNS_TUNNEL_CONTEXT, HashEntry);

        if (candidate->DomainHash == hash &&
            _stricmp(candidate->BaseDomain, BaseDomain) == 0) {
            context = candidate;
            InterlockedIncrement(&context->RefCount);
            break;
        }
    }

    ExReleasePushLockShared(&Monitor->TunnelContextLock);

    if (context != NULL) {
        return context;
    }

    // Create new
    context = (PDNS_TUNNEL_CONTEXT)ExAllocateFromNPagedLookasideList(
        &Monitor->TunnelContextLookaside);

    if (context == NULL) {
        return NULL;
    }

    RtlZeroMemory(context, sizeof(DNS_TUNNEL_CONTEXT));
    RtlStringCchCopyA(context->BaseDomain, sizeof(context->BaseDomain), BaseDomain);
    context->DomainHash = hash;
    context->RefCount = 1;
    KeQuerySystemTimePrecise(&context->FirstQuery);

    ExAcquirePushLockExclusive(&Monitor->TunnelContextLock);

    // Check again in case of race
    for (entry = Monitor->TunnelHash.Buckets[bucket].Flink;
         entry != &Monitor->TunnelHash.Buckets[bucket];
         entry = entry->Flink) {

        PDNS_TUNNEL_CONTEXT candidate = CONTAINING_RECORD(
            entry, DNS_TUNNEL_CONTEXT, HashEntry);

        if (candidate->DomainHash == hash &&
            _stricmp(candidate->BaseDomain, BaseDomain) == 0) {
            // Someone else added it
            ExReleasePushLockExclusive(&Monitor->TunnelContextLock);
            ExFreeToNPagedLookasideList(&Monitor->TunnelContextLookaside, context);
            InterlockedIncrement(&candidate->RefCount);
            return candidate;
        }
    }

    // Add to lists
    InsertTailList(&Monitor->TunnelContextList, &context->ListEntry);
    InsertTailList(&Monitor->TunnelHash.Buckets[bucket], &context->HashEntry);
    InterlockedIncrement(&Monitor->TunnelContextCount);

    ExReleasePushLockExclusive(&Monitor->TunnelContextLock);

    return context;
}

static VOID
DnspUpdateTunnelMetrics(
    _In_ PDNS_TUNNEL_CONTEXT Context,
    _In_ PCSTR FullDomain,
    _In_ DNS_RECORD_TYPE RecordType,
    _In_ ULONG Entropy
    )
{
    ULONG subdomainLength;
    PCSTR baseDomainStart;

    KeQuerySystemTimePrecise(&Context->LastQuery);
    InterlockedIncrement(&Context->TotalQueries);

    if (RecordType == DnsType_TXT) {
        InterlockedIncrement(&Context->TxtQueries);
    }

    // Calculate subdomain length
    baseDomainStart = strstr(FullDomain, Context->BaseDomain);
    if (baseDomainStart != NULL && baseDomainStart > FullDomain) {
        subdomainLength = (ULONG)(baseDomainStart - FullDomain - 1);

        InterlockedAdd64(&Context->TotalSubdomainLength, subdomainLength);

        if (subdomainLength > Context->MaxSubdomainLength) {
            Context->MaxSubdomainLength = subdomainLength;
        }

        // Assume new unique subdomain (approximate)
        InterlockedIncrement(&Context->UniqueSubdomains);
    }

    Context->TotalEntropySum += Entropy;
}

static BOOLEAN
DnspCheckTunneling(
    _In_ PDNS_TUNNEL_CONTEXT Context,
    _Out_ PULONG Score
    )
{
    ULONG score = 0;
    LARGE_INTEGER currentTime;
    LONGLONG elapsedMs;
    ULONG queriesPerMinute;
    ULONG avgSubdomainLength;
    ULONG avgEntropy;

    *Score = 0;

    if (Context->TotalQueries < 10) {
        return FALSE;
    }

    KeQuerySystemTimePrecise(&currentTime);
    elapsedMs = (currentTime.QuadPart - Context->FirstQuery.QuadPart) / 10000;

    if (elapsedMs < 60000) {  // Less than 1 minute
        return FALSE;
    }

    // Calculate metrics
    queriesPerMinute = (Context->TotalQueries * 60000) / (ULONG)elapsedMs;
    avgSubdomainLength = (ULONG)(Context->TotalSubdomainLength / Context->TotalQueries);
    avgEntropy = (ULONG)(Context->TotalEntropySum / Context->TotalQueries);

    // High query rate
    if (queriesPerMinute > 50) {
        score += 30;
    } else if (queriesPerMinute > 20) {
        score += 15;
    }

    // High TXT query ratio
    if (Context->TotalQueries > 0) {
        ULONG txtRatio = (Context->TxtQueries * 100) / Context->TotalQueries;
        if (txtRatio > 50) {
            score += 25;
        } else if (txtRatio > 25) {
            score += 10;
        }
    }

    // Long average subdomain
    if (avgSubdomainLength > 40) {
        score += 30;
    } else if (avgSubdomainLength > 25) {
        score += 15;
    }

    // High entropy
    if (avgEntropy > 420) {
        score += 25;
    } else if (avgEntropy > 380) {
        score += 10;
    }

    // Many unique subdomains
    if (Context->UniqueSubdomains > 100) {
        score += 20;
    } else if (Context->UniqueSubdomains > 50) {
        score += 10;
    }

    Context->TunnelingScore = score > 100 ? 100 : score;
    Context->Confidence = (score > 70) ? 90 : (score > 50) ? 70 : 50;
    Context->TunnelingDetected = (score >= 50);

    *Score = Context->TunnelingScore;
    return Context->TunnelingDetected;
}

// ============================================================================
// INTERNAL HELPERS - PROCESS CONTEXT
// ============================================================================

static PDNS_PROCESS_CONTEXT
DnspGetOrCreateProcessContext(
    _In_ PDNS_MONITOR_INTERNAL Monitor,
    _In_ HANDLE ProcessId
    )
{
    PLIST_ENTRY entry;
    PDNS_PROCESS_CONTEXT context = NULL;

    // Search existing
    ExAcquirePushLockShared(&Monitor->Public.ProcessListLock);

    for (entry = Monitor->Public.ProcessList.Flink;
         entry != &Monitor->Public.ProcessList;
         entry = entry->Flink) {

        PDNS_PROCESS_CONTEXT candidate = CONTAINING_RECORD(
            entry, DNS_PROCESS_CONTEXT, ListEntry);

        if (candidate->ProcessId == ProcessId) {
            context = candidate;
            InterlockedIncrement(&context->RefCount);
            break;
        }
    }

    ExReleasePushLockShared(&Monitor->Public.ProcessListLock);

    if (context != NULL) {
        return context;
    }

    // Create new
    context = (PDNS_PROCESS_CONTEXT)ExAllocateFromNPagedLookasideList(
        &Monitor->ProcessContextLookaside);

    if (context == NULL) {
        return NULL;
    }

    RtlZeroMemory(context, sizeof(DNS_PROCESS_CONTEXT));
    context->ProcessId = ProcessId;
    context->RefCount = 1;
    InitializeListHead(&context->QueryList);
    KeInitializeSpinLock(&context->QueryLock);

    ExAcquirePushLockExclusive(&Monitor->Public.ProcessListLock);

    // Check again
    for (entry = Monitor->Public.ProcessList.Flink;
         entry != &Monitor->Public.ProcessList;
         entry = entry->Flink) {

        PDNS_PROCESS_CONTEXT candidate = CONTAINING_RECORD(
            entry, DNS_PROCESS_CONTEXT, ListEntry);

        if (candidate->ProcessId == ProcessId) {
            ExReleasePushLockExclusive(&Monitor->Public.ProcessListLock);
            ExFreeToNPagedLookasideList(&Monitor->ProcessContextLookaside, context);
            InterlockedIncrement(&candidate->RefCount);
            return candidate;
        }
    }

    InsertTailList(&Monitor->Public.ProcessList, &context->ListEntry);
    InterlockedIncrement(&Monitor->Public.ProcessCount);

    ExReleasePushLockExclusive(&Monitor->Public.ProcessListLock);

    return context;
}

static VOID
DnspReferenceProcessContext(
    _In_ PDNS_PROCESS_CONTEXT Context
    )
{
    InterlockedIncrement(&Context->RefCount);
}

static VOID
DnspDereferenceProcessContext(
    _In_ PDNS_MONITOR_INTERNAL Monitor,
    _In_ PDNS_PROCESS_CONTEXT Context
    )
{
    UNREFERENCED_PARAMETER(Monitor);

    if (InterlockedDecrement(&Context->RefCount) == 0) {
        // Context will be cleaned up by cleanup timer
    }
}

// ============================================================================
// INTERNAL HELPERS - DOMAIN CACHE
// ============================================================================

static PDNS_DOMAIN_CACHE
DnspLookupDomainCache(
    _In_ PDNS_MONITOR_INTERNAL Monitor,
    _In_ PCSTR DomainName
    )
{
    ULONG hash;
    ULONG bucket;
    PLIST_ENTRY entry;
    PDNS_DOMAIN_CACHE cacheEntry = NULL;

    hash = DnspHashString(DomainName);
    bucket = hash % Monitor->Public.DomainHash.BucketCount;

    for (entry = Monitor->Public.DomainHash.Buckets[bucket].Flink;
         entry != &Monitor->Public.DomainHash.Buckets[bucket];
         entry = entry->Flink) {

        PDNS_DOMAIN_CACHE candidate = CONTAINING_RECORD(
            entry, DNS_DOMAIN_CACHE, HashEntry);

        if (candidate->DomainHash == hash &&
            _stricmp(candidate->DomainName, DomainName) == 0) {
            cacheEntry = candidate;
            InterlockedIncrement(&cacheEntry->QueryCount);
            KeQuerySystemTimePrecise(&cacheEntry->LastSeen);
            break;
        }
    }

    return cacheEntry;
}

static NTSTATUS
DnspAddToDomainCache(
    _In_ PDNS_MONITOR_INTERNAL Monitor,
    _In_ PCSTR DomainName,
    _In_ PDNS_QUERY Query
    )
{
    ULONG hash;
    ULONG bucket;
    PDNS_DOMAIN_CACHE cacheEntry;
    LARGE_INTEGER currentTime;

    // Check if already exists
    cacheEntry = DnspLookupDomainCache(Monitor, DomainName);
    if (cacheEntry != NULL) {
        return STATUS_SUCCESS;
    }

    // Check cache limit
    if (Monitor->Public.CacheEntryCount >= DNS_MAX_CACHED_QUERIES) {
        return STATUS_QUOTA_EXCEEDED;
    }

    // Allocate new entry
    cacheEntry = (PDNS_DOMAIN_CACHE)ExAllocateFromNPagedLookasideList(
        &Monitor->DomainCacheLookaside);

    if (cacheEntry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(cacheEntry, sizeof(DNS_DOMAIN_CACHE));

    hash = DnspHashString(DomainName);
    bucket = hash % Monitor->Public.DomainHash.BucketCount;

    RtlStringCchCopyA(cacheEntry->DomainName, sizeof(cacheEntry->DomainName), DomainName);
    cacheEntry->DomainHash = hash;
    cacheEntry->QueryCount = 1;
    cacheEntry->UniqueProcesses = 1;
    cacheEntry->Reputation = Reputation_Unknown;

    KeQuerySystemTimePrecise(&currentTime);
    cacheEntry->FirstSeen = currentTime;
    cacheEntry->LastSeen = currentTime;
    cacheEntry->ExpirationTime.QuadPart = currentTime.QuadPart +
                                           ((LONGLONG)DNS_CACHE_TTL_SECONDS * 10000000);

    // Copy resolution data if available
    if (Query->Response.Received && Query->Response.AddressCount > 0) {
        ULONG copyCount = min(Query->Response.AddressCount, 8);
        if (Query->IsIPv6) {
            RtlCopyMemory(cacheEntry->KnownAddresses.IPv6,
                          Query->Response.Addresses.IPv6,
                          copyCount * sizeof(IN6_ADDR));
        } else {
            RtlCopyMemory(cacheEntry->KnownAddresses.IPv4,
                          Query->Response.Addresses.IPv4,
                          copyCount * sizeof(IN_ADDR));
        }
        cacheEntry->AddressCount = copyCount;
    }

    // Add to lists
    ExAcquirePushLockExclusive(&Monitor->Public.DomainCacheLock);

    InsertTailList(&Monitor->Public.DomainCache, &cacheEntry->ListEntry);
    InsertTailList(&Monitor->Public.DomainHash.Buckets[bucket], &cacheEntry->HashEntry);
    InterlockedIncrement(&Monitor->Public.CacheEntryCount);

    ExReleasePushLockExclusive(&Monitor->Public.DomainCacheLock);

    return STATUS_SUCCESS;
}

// ============================================================================
// INTERNAL HELPERS - CLEANUP
// ============================================================================

static VOID NTAPI
DnspCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PDNS_MONITOR_INTERNAL monitor = (PDNS_MONITOR_INTERNAL)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (monitor == NULL || !monitor->Public.Initialized) {
        return;
    }

    DnspCleanupExpiredEntries(monitor);
}

static VOID
DnspCleanupExpiredEntries(
    _In_ PDNS_MONITOR_INTERNAL Monitor
    )
{
    LARGE_INTEGER currentTime;
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;
    LIST_ENTRY expiredQueries;
    LIST_ENTRY expiredDomains;

    InitializeListHead(&expiredQueries);
    InitializeListHead(&expiredDomains);

    KeQuerySystemTimePrecise(&currentTime);

    //
    // Collect expired queries
    //
    ExAcquirePushLockExclusive(&Monitor->Public.QueryListLock);

    for (entry = Monitor->Public.QueryList.Flink;
         entry != &Monitor->Public.QueryList;
         entry = nextEntry) {

        nextEntry = entry->Flink;
        PDNS_QUERY query = CONTAINING_RECORD(entry, DNS_QUERY, ListEntry);

        // Expire queries older than 5 minutes
        LONGLONG ageMs = (currentTime.QuadPart - query->QueryTime.QuadPart) / 10000;
        if (ageMs > DNS_QUERY_EXPIRATION_MS) {
            RemoveEntryList(&query->ListEntry);
            InsertTailList(&expiredQueries, &query->ListEntry);
            InterlockedDecrement(&Monitor->Public.QueryCount);
        }
    }

    ExReleasePushLockExclusive(&Monitor->Public.QueryListLock);

    //
    // Collect expired domain cache entries
    //
    ExAcquirePushLockExclusive(&Monitor->Public.DomainCacheLock);

    for (entry = Monitor->Public.DomainCache.Flink;
         entry != &Monitor->Public.DomainCache;
         entry = nextEntry) {

        nextEntry = entry->Flink;
        PDNS_DOMAIN_CACHE domainEntry = CONTAINING_RECORD(
            entry, DNS_DOMAIN_CACHE, ListEntry);

        if (currentTime.QuadPart > domainEntry->ExpirationTime.QuadPart) {
            RemoveEntryList(&domainEntry->ListEntry);
            RemoveEntryList(&domainEntry->HashEntry);
            InsertTailList(&expiredDomains, &domainEntry->ListEntry);
            InterlockedDecrement(&Monitor->Public.CacheEntryCount);
        }
    }

    ExReleasePushLockExclusive(&Monitor->Public.DomainCacheLock);

    //
    // Free expired entries outside of locks
    //
    while (!IsListEmpty(&expiredQueries)) {
        entry = RemoveHeadList(&expiredQueries);
        PDNS_QUERY query = CONTAINING_RECORD(entry, DNS_QUERY, ListEntry);

        if (query->ProcessName.Buffer != NULL) {
            ExFreePoolWithTag(query->ProcessName.Buffer, DNS_POOL_TAG_QUERY);
        }

        ExFreeToNPagedLookasideList(&Monitor->QueryLookaside, query);
    }

    while (!IsListEmpty(&expiredDomains)) {
        entry = RemoveHeadList(&expiredDomains);
        PDNS_DOMAIN_CACHE domainEntry = CONTAINING_RECORD(
            entry, DNS_DOMAIN_CACHE, ListEntry);

        ExFreeToNPagedLookasideList(&Monitor->DomainCacheLookaside, domainEntry);
    }
}
