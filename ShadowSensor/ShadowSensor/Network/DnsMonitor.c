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
- NPAGED_LOOKASIDE_LIST for frequent allocations
- EX_PUSH_LOCK for reader-writer synchronization
- Configurable cache sizes and TTLs

@author ShadowStrike Security Team
@version 3.0.0 (Enterprise Edition - Security Hardened)
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

#define DNS_POOL_TAG                    'MNSD'
#define DNS_TRANSACTION_HASH_BUCKETS    256
#define DNS_DOMAIN_HASH_BUCKETS         1024
#define DNS_MAX_PACKET_SIZE             65535
#define DNS_MIN_PACKET_SIZE             12
#define DNS_HEADER_SIZE                 12
#define DNS_MAX_LABELS                  127
#define DNS_CLEANUP_INTERVAL_MS         60000
#define DNS_QUERY_EXPIRATION_MS         300000
#define DNS_CACHE_EXPIRATION_MS         3600000
#define DNS_PROCESS_IDLE_EXPIRATION_MS  600000   // 10 min idle
#define DNS_TUNNEL_IDLE_EXPIRATION_MS   1800000  // 30 min idle

//
// DNS packet flags
//
#define DNS_FLAG_QR                     0x8000
#define DNS_FLAG_OPCODE_MASK            0x7800
#define DNS_FLAG_AA                     0x0400
#define DNS_FLAG_TC                     0x0200
#define DNS_FLAG_RD                     0x0100
#define DNS_FLAG_RA                     0x0080
#define DNS_FLAG_Z_MASK                 0x0070
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
#define DNS_ENTROPY_HIGH_THRESHOLD      380
#define DNS_ENTROPY_TUNNEL_THRESHOLD    420
#define DNS_SUBDOMAIN_LENGTH_THRESHOLD  32
#define DNS_SUBDOMAIN_COUNT_THRESHOLD   5
#define DNS_QUERY_RATE_THRESHOLD        100

//
// DGA detection constants
//
#define DGA_CONSONANT_THRESHOLD         70
#define DGA_DIGIT_THRESHOLD             30
#define DGA_MIN_DOMAIN_LENGTH           8
#define DGA_MAX_CONSECUTIVE_CONSONANTS  5
#define DGA_BIGRAM_SCORE_THRESHOLD      200

// ============================================================================
// DNS PACKET STRUCTURES
// ============================================================================

#pragma pack(push, 1)

typedef struct _DNS_HEADER {
    USHORT TransactionId;
    USHORT Flags;
    USHORT QuestionCount;
    USHORT AnswerCount;
    USHORT AuthorityCount;
    USHORT AdditionalCount;
} DNS_HEADER, *PDNS_HEADER;

typedef struct _DNS_QUESTION_FOOTER {
    USHORT Type;
    USHORT Class;
} DNS_QUESTION_FOOTER, *PDNS_QUESTION_FOOTER;

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
    volatile LONG MaxSubdomainLength;
    volatile LONG64 TotalEntropySum;

    BOOLEAN TunnelingDetected;
    ULONG TunnelingScore;
    ULONG Confidence;

    volatile LONG RefCount;
} DNS_TUNNEL_CONTEXT, *PDNS_TUNNEL_CONTEXT;

//
// Full monitor state (opaque to callers; DNS_MONITOR is this struct)
//
struct _DNS_MONITOR {
    //
    // Initialization state
    //
    volatile LONG Initialized;

    //
    // Query tracking
    //
    LIST_ENTRY QueryList;
    EX_PUSH_LOCK QueryListLock;
    volatile LONG QueryCount;
    volatile LONG64 NextQueryId;

    //
    // Transaction ID hash for O(1) response correlation
    //
    struct {
        LIST_ENTRY* Buckets;
        ULONG BucketCount;
        EX_PUSH_LOCK Lock;
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
    // Cleanup: timer fires DPC, DPC queues work item at PASSIVE_LEVEL
    //
    KTIMER CleanupTimer;
    KDPC CleanupDpc;
    PIO_WORKITEM CleanupWorkItem;
    PDEVICE_OBJECT DeviceObject;
    volatile LONG CleanupInProgress;

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
};


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
    _In_ PDNS_MONITOR Monitor,
    _In_reads_bytes_(PacketSize) PUCHAR Packet,
    _In_ ULONG PacketSize,
    _In_ HANDLE ProcessId,
    _In_ PVOID SourceAddress,
    _In_ USHORT SourcePort,
    _In_ PVOID ServerAddress,
    _In_ USHORT ServerPort,
    _In_ BOOLEAN IsIPv6,
    _Out_ PDNS_QUERY* Query
    );

static NTSTATUS
DnspParseResponse(
    _In_ PDNS_MONITOR Monitor,
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
    _In_ PDNS_MONITOR Monitor,
    _In_ PCSTR BaseDomain
    );

static VOID
DnspDereferenceTunnelContext(
    _In_ PDNS_MONITOR Monitor,
    _In_ PDNS_TUNNEL_CONTEXT Context
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
DnspFindProcessContext(
    _In_ PDNS_MONITOR Monitor,
    _In_ HANDLE ProcessId
    );

static PDNS_PROCESS_CONTEXT
DnspGetOrCreateProcessContext(
    _In_ PDNS_MONITOR Monitor,
    _In_ HANDLE ProcessId
    );

static VOID
DnspReferenceProcessContext(
    _In_ PDNS_PROCESS_CONTEXT Context
    );

static VOID
DnspDereferenceProcessContext(
    _In_ PDNS_MONITOR Monitor,
    _In_ PDNS_PROCESS_CONTEXT Context
    );

_Requires_lock_held_(Monitor->DomainCacheLock)
static PDNS_DOMAIN_CACHE
DnspLookupDomainCacheLocked(
    _In_ PDNS_MONITOR Monitor,
    _In_ PCSTR DomainName
    );

static NTSTATUS
DnspAddToDomainCache(
    _In_ PDNS_MONITOR Monitor,
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
DnspCleanupWorkItemRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    );

static VOID
DnspCleanupExpiredEntries(
    _In_ PDNS_MONITOR Monitor
    );

static VOID
DnspFreeQuery(
    _In_ PDNS_MONITOR Monitor,
    _In_ PDNS_QUERY Query
    );

static VOID
DnspPopulateProcessName(
    _In_ HANDLE ProcessId,
    _Out_writes_(MaxChars) PWCHAR Buffer,
    _In_ ULONG MaxChars,
    _Out_ PUSHORT LengthInBytes
    );

// ============================================================================
// CHARACTER CLASSIFICATION TABLES
// ============================================================================

static const BOOLEAN g_IsVowel[256] = {
    ['a'] = TRUE, ['A'] = TRUE,
    ['e'] = TRUE, ['E'] = TRUE,
    ['i'] = TRUE, ['I'] = TRUE,
    ['o'] = TRUE, ['O'] = TRUE,
    ['u'] = TRUE, ['U'] = TRUE,
};

static const BOOLEAN g_IsHexChar[256] = {
    ['0'] = TRUE, ['1'] = TRUE, ['2'] = TRUE, ['3'] = TRUE,
    ['4'] = TRUE, ['5'] = TRUE, ['6'] = TRUE, ['7'] = TRUE,
    ['8'] = TRUE, ['9'] = TRUE,
    ['a'] = TRUE, ['b'] = TRUE, ['c'] = TRUE, ['d'] = TRUE,
    ['e'] = TRUE, ['f'] = TRUE,
    ['A'] = TRUE, ['B'] = TRUE, ['C'] = TRUE, ['D'] = TRUE,
    ['E'] = TRUE, ['F'] = TRUE,
};

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
// Fixed-point log2 lookup table: -log2(p/256)*256 for p in [1..255]
// Used for Shannon entropy calculation without floating point.
// Entry i = round(-log2(i/256) * 256) for i >= 1.
//
static const USHORT g_Log2Table[256] = {
       0, 2048, 1792, 1664, 1536, 1446, 1378, 1322, 1280, 1238, 1202, 1170,
    1142, 1116, 1092, 1070, 1024, 1004,  986,  968,  952,  936,  922,  908,
     896,  884,  872,  860,  850,  840,  830,  822,  768,  760,  752,  744,
     736,  730,  722,  716,  710,  704,  698,  692,  686,  680,  676,  670,
     666,  660,  656,  650,  646,  642,  638,  634,  630,  626,  622,  618,
     614,  610,  608,  604,  512,  508,  506,  502,  500,  496,  494,  490,
     488,  486,  482,  480,  478,  474,  472,  470,  468,  466,  462,  460,
     458,  456,  454,  452,  450,  448,  446,  444,  442,  440,  438,  436,
     434,  432,  430,  428,  426,  424,  422,  420,  418,  416,  414,  412,
     410,  410,  408,  406,  404,  402,  400,  398,  398,  396,  394,  392,
     390,  390,  388,  386,  384,  384,  382,  380,  256,  254,  254,  252,
     252,  250,  250,  248,  248,  246,  246,  244,  244,  242,  242,  240,
     240,  238,  238,  236,  236,  236,  234,  234,  232,  232,  230,  230,
     228,  228,  228,  226,  226,  224,  224,  224,  222,  222,  220,  220,
     220,  218,  218,  216,  216,  216,  214,  214,  214,  212,  212,  210,
     210,  210,  208,  208,  208,  206,  206,  206,  204,  204,  204,  202,
     202,  202,  200,  200,  200,  198,  198,  198,  196,  196,  196,  194,
     194,  194,  194,  192,  192,  192,  190,  190,  190,  188,  188,  188,
     188,  186,  186,  186,  184,  184,  184,  184,  182,  182,  182,  180,
     180,  180,  180,  178,  178,  178,  178,  176,  176,  176,  176,  174,
     174,  174,  174,  172,  172,  172,  172,  170,  170,  170,  170,  168,
     168,  168,  168,  168,
};

static const UCHAR g_BigramScore[26][26] = {
    //  a   b   c   d   e   f   g   h   i   j   k   l   m   n   o   p   q   r   s   t   u   v   w   x   y   z
    {  50, 20, 30, 30, 50, 20, 30, 20, 40, 10, 20, 40, 30, 50, 50, 30,  5, 40, 40, 50, 30, 20, 20,  5, 30,  5 },
    {  30, 10, 10, 10, 40, 10, 10, 10, 30,  5,  5, 30, 10, 10, 40, 10,  5, 30, 20, 10, 30,  5,  5,  5, 20,  5 },
    {  40, 10, 20, 10, 40, 10, 10, 40, 30,  5, 30, 30, 10, 10, 50, 10,  5, 30, 20, 40, 30,  5,  5,  5, 20,  5 },
    {  40, 10, 10, 20, 50, 10, 20, 10, 40,  5,  5, 20, 20, 20, 40, 10,  5, 30, 30, 20, 30,  5, 20,  5, 30,  5 },
    {  50, 20, 30, 50, 50, 30, 20, 20, 40, 10, 10, 40, 30, 50, 40, 30,  5, 50, 50, 50, 30, 30, 30, 30, 30,  5 },
    {  40, 10, 10, 10, 40, 30, 10, 10, 40,  5,  5, 30, 10, 10, 50, 10,  5, 40, 20, 40, 40,  5,  5,  5, 20,  5 },
    {  40, 10, 10, 10, 40, 10, 20, 30, 30,  5,  5, 20, 20, 20, 40, 10,  5, 40, 30, 20, 30,  5,  5,  5, 20,  5 },
    {  50, 10, 10, 10, 50, 10, 10, 10, 40,  5,  5, 10, 20, 10, 40, 10,  5, 20, 20, 30, 20,  5, 10,  5, 20,  5 },
    {  40, 20, 40, 40, 40, 30, 30, 10, 10, 10, 20, 40, 40, 50, 50, 20,  5, 30, 50, 50, 20, 30, 10,  5, 10, 20 },
    {  30, 10, 10, 10, 30, 10, 10, 10, 20,  5,  5, 10, 10, 10, 30, 10,  5, 10, 10, 10, 30,  5,  5,  5, 10,  5 },
    {  30, 10, 10, 10, 40, 10, 10, 10, 30,  5,  5, 20, 10, 30, 30, 10,  5, 10, 30, 10, 10,  5, 20,  5, 20,  5 },
    {  50, 10, 10, 30, 50, 20, 10, 10, 50, 10, 20, 40, 20, 10, 50, 20,  5, 10, 30, 30, 30,  5, 20,  5, 40,  5 },
    {  50, 20, 10, 10, 50, 10, 10, 10, 40,  5,  5, 10, 30, 20, 50, 30,  5, 10, 30, 10, 30,  5, 10,  5, 30,  5 },
    {  50, 10, 30, 50, 50, 20, 50, 20, 40, 10, 20, 20, 20, 30, 50, 10,  5, 10, 40, 50, 30, 10, 20,  5, 30,  5 },
    {  40, 20, 20, 30, 40, 40, 20, 10, 30, 10, 20, 30, 40, 50, 50, 30,  5, 50, 40, 40, 50, 30, 40, 10, 20, 10 },
    {  40, 10, 10, 10, 40, 10, 10, 30, 30,  5,  5, 40, 20, 10, 40, 30,  5, 50, 30, 30, 30,  5, 20,  5, 30,  5 },
    {  10,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5, 30,  5,  5,  5,  5,  5 },
    {  50, 20, 20, 30, 50, 20, 20, 10, 50, 10, 20, 30, 30, 30, 50, 20,  5, 30, 40, 40, 30, 20, 20,  5, 40,  5 },
    {  40, 10, 30, 10, 50, 20, 10, 40, 50, 10, 20, 20, 30, 20, 50, 40,  5, 10, 50, 50, 40,  5, 30,  5, 30,  5 },
    {  50, 10, 20, 10, 50, 10, 10, 50, 50,  5,  5, 30, 20, 10, 50, 10,  5, 40, 40, 40, 40,  5, 30,  5, 40,  5 },
    {  40, 20, 30, 30, 40, 10, 30, 10, 30, 10, 10, 40, 30, 50, 20, 30,  5, 50, 50, 50, 10, 10, 10,  5, 20,  5 },
    {  40, 10, 10, 10, 50, 10, 10, 10, 40,  5,  5, 10, 10, 10, 40, 10,  5, 10, 10, 10, 10,  5,  5,  5, 20,  5 },
    {  50, 10, 10, 20, 40, 10, 10, 40, 40, 10, 10, 10, 10, 30, 40, 10,  5, 20, 20, 10, 10,  5, 10,  5, 10,  5 },
    {  20,  5, 20,  5, 20,  5,  5, 10, 20,  5,  5,  5,  5,  5, 10, 30,  5,  5,  5, 30,  5,  5,  5,  5, 10,  5 },
    {  30, 10, 10, 10, 30, 10, 10, 10, 30, 10, 10, 20, 20, 20, 40, 20,  5, 20, 40, 30, 10,  5, 20,  5, 10,  5 },
    {  30,  5,  5,  5, 30,  5,  5,  5, 20,  5,  5, 10,  5,  5, 20,  5,  5,  5,  5,  5,  5,  5,  5,  5, 10, 20 },
};


// ============================================================================
// HELPER - PROCESS NAME POPULATION
// ============================================================================

static VOID
DnspPopulateProcessName(
    _In_ HANDLE ProcessId,
    _Out_writes_(MaxChars) PWCHAR Buffer,
    _In_ ULONG MaxChars,
    _Out_ PUSHORT LengthInBytes
    )
/*++
Routine Description:
    Best-effort population of process image name.
    Safe to call at PASSIVE_LEVEL only.
--*/
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PUNICODE_STRING imageName = NULL;

    Buffer[0] = L'\0';
    *LengthInBytes = 0;

    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        return;
    }

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return;
    }

    status = SeLocateProcessImageName(process, &imageName);
    if (NT_SUCCESS(status) && imageName != NULL && imageName->Buffer != NULL) {
        ULONG copyChars = imageName->Length / sizeof(WCHAR);
        if (copyChars >= MaxChars) {
            copyChars = MaxChars - 1;
        }
        RtlCopyMemory(Buffer, imageName->Buffer, copyChars * sizeof(WCHAR));
        Buffer[copyChars] = L'\0';
        *LengthInBytes = (USHORT)(copyChars * sizeof(WCHAR));
        ExFreePool(imageName);
    }

    ObDereferenceObject(process);
}

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

NTSTATUS
DnsInitialize(
    _Out_ PDNS_MONITOR* Monitor
    )
{
    NTSTATUS status;
    PDNS_MONITOR monitor = NULL;
    ULONG i;
    LARGE_INTEGER dueTime;

    if (Monitor == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Monitor = NULL;

    monitor = (PDNS_MONITOR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(DNS_MONITOR),
        DNS_POOL_TAG
    );

    if (monitor == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // ExAllocatePool2 zeroes memory; no redundant RtlZeroMemory needed.

    //
    // Initialize locks
    //
    ExInitializePushLock(&monitor->QueryListLock);
    ExInitializePushLock(&monitor->DomainCacheLock);
    ExInitializePushLock(&monitor->ProcessListLock);
    ExInitializePushLock(&monitor->TunnelContextLock);
    ExInitializePushLock(&monitor->Callbacks.Lock);
    ExInitializePushLock(&monitor->TransactionHash.Lock);

    //
    // Initialize lists
    //
    InitializeListHead(&monitor->QueryList);
    InitializeListHead(&monitor->DomainCache);
    InitializeListHead(&monitor->ProcessList);
    InitializeListHead(&monitor->TunnelContextList);

    //
    // Allocate transaction hash table
    //
    monitor->TransactionHash.BucketCount = DNS_TRANSACTION_HASH_BUCKETS;
    monitor->TransactionHash.Buckets = (PLIST_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(LIST_ENTRY) * DNS_TRANSACTION_HASH_BUCKETS,
        DNS_POOL_TAG
    );

    if (monitor->TransactionHash.Buckets == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    for (i = 0; i < DNS_TRANSACTION_HASH_BUCKETS; i++) {
        InitializeListHead(&monitor->TransactionHash.Buckets[i]);
    }

    //
    // Allocate domain hash table
    //
    monitor->DomainHash.BucketCount = DNS_DOMAIN_HASH_BUCKETS;
    monitor->DomainHash.Buckets = (PLIST_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(LIST_ENTRY) * DNS_DOMAIN_HASH_BUCKETS,
        DNS_POOL_TAG
    );

    if (monitor->DomainHash.Buckets == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    for (i = 0; i < DNS_DOMAIN_HASH_BUCKETS; i++) {
        InitializeListHead(&monitor->DomainHash.Buckets[i]);
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
        &monitor->QueryLookaside, NULL, NULL, 0,
        sizeof(DNS_QUERY), DNS_POOL_TAG_QUERY, 0
    );

    ExInitializeNPagedLookasideList(
        &monitor->DomainCacheLookaside, NULL, NULL, 0,
        sizeof(DNS_DOMAIN_CACHE), DNS_POOL_TAG_CACHE, 0
    );

    ExInitializeNPagedLookasideList(
        &monitor->ProcessContextLookaside, NULL, NULL, 0,
        sizeof(DNS_PROCESS_CONTEXT), DNS_POOL_TAG, 0
    );

    ExInitializeNPagedLookasideList(
        &monitor->TunnelContextLookaside, NULL, NULL, 0,
        sizeof(DNS_TUNNEL_CONTEXT), DNS_POOL_TAG, 0
    );

    monitor->LookasideInitialized = TRUE;

    //
    // Initialize cleanup timer + work item.
    // DPC fires at DISPATCH_LEVEL and queues a work item at PASSIVE_LEVEL.
    //
    KeInitializeTimer(&monitor->CleanupTimer);
    KeInitializeDpc(&monitor->CleanupDpc, DnspCleanupTimerDpc, monitor);

    //
    // Work item requires a device object. Obtain from globals.
    // If DeviceObject is not available, cleanup will be deferred to shutdown.
    //
    if (g_DriverData.DeviceObject != NULL) {
        monitor->DeviceObject = g_DriverData.DeviceObject;
        monitor->CleanupWorkItem = IoAllocateWorkItem(monitor->DeviceObject);
        if (monitor->CleanupWorkItem == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }
    }

    monitor->CleanupInProgress = 0;

    dueTime.QuadPart = -((LONGLONG)DNS_CLEANUP_INTERVAL_MS * 10000);
    KeSetTimerEx(
        &monitor->CleanupTimer,
        dueTime,
        DNS_CLEANUP_INTERVAL_MS,
        &monitor->CleanupDpc
    );

    //
    // Set default configuration
    //
    monitor->Config.EnableTunnelingDetection = TRUE;
    monitor->Config.EnableDGADetection = TRUE;
    monitor->Config.EntropyThreshold = DNS_TUNNEL_ENTROPY_THRESHOLD;
    monitor->Config.MaxSubdomainLength = DNS_SUBDOMAIN_LENGTH_THRESHOLD;
    monitor->Config.QueryRateThreshold = DNS_QUERY_RATE_THRESHOLD;

    KeQuerySystemTimePrecise(&monitor->Stats.StartTime);

    InterlockedExchange(&monitor->Initialized, TRUE);
    *Monitor = monitor;

    return STATUS_SUCCESS;

Cleanup:
    if (monitor != NULL) {
        if (monitor->CleanupWorkItem != NULL) {
            IoFreeWorkItem(monitor->CleanupWorkItem);
        }
        if (monitor->LookasideInitialized) {
            ExDeleteNPagedLookasideList(&monitor->QueryLookaside);
            ExDeleteNPagedLookasideList(&monitor->DomainCacheLookaside);
            ExDeleteNPagedLookasideList(&monitor->ProcessContextLookaside);
            ExDeleteNPagedLookasideList(&monitor->TunnelContextLookaside);
        }
        if (monitor->TransactionHash.Buckets != NULL) {
            ExFreePoolWithTag(monitor->TransactionHash.Buckets, DNS_POOL_TAG);
        }
        if (monitor->DomainHash.Buckets != NULL) {
            ExFreePoolWithTag(monitor->DomainHash.Buckets, DNS_POOL_TAG);
        }
        if (monitor->TunnelHash.Buckets != NULL) {
            ExFreePoolWithTag(monitor->TunnelHash.Buckets, DNS_POOL_TAG);
        }
        ExFreePoolWithTag(monitor, DNS_POOL_TAG);
    }

    return status;
}


// ============================================================================
// PUBLIC API - SHUTDOWN
// ============================================================================

VOID
DnsShutdown(
    _Inout_ PDNS_MONITOR Monitor
    )
{
    PLIST_ENTRY entry;
    PDNS_QUERY query;
    PDNS_DOMAIN_CACHE domainEntry;
    PDNS_PROCESS_CONTEXT processCtx;
    PDNS_TUNNEL_CONTEXT tunnelCtx;

    if (Monitor == NULL || !InterlockedExchange(&Monitor->Initialized, FALSE)) {
        return;
    }

    //
    // Cancel cleanup timer and wait for any in-flight DPC to complete.
    //
    KeCancelTimer(&Monitor->CleanupTimer);
    KeFlushQueuedDpcs();

    //
    // Wait for any in-progress work item to finish.
    //
    while (InterlockedCompareExchange(&Monitor->CleanupInProgress, 0, 0) != 0) {
        LARGE_INTEGER delay;
        delay.QuadPart = -10000; // 1ms
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }

    //
    // Free all queries — remove from ALL lists
    //
    ExAcquirePushLockExclusive(&Monitor->QueryListLock);
    ExAcquirePushLockExclusive(&Monitor->TransactionHash.Lock);

    while (!IsListEmpty(&Monitor->QueryList)) {
        entry = RemoveHeadList(&Monitor->QueryList);
        query = CONTAINING_RECORD(entry, DNS_QUERY, ListEntry);

        // Remove from transaction hash
        RemoveEntryList(&query->HashEntry);

        // Remove from process list (if linked)
        if (query->ProcessListEntry.Flink != NULL &&
            query->ProcessListEntry.Blink != NULL) {
            RemoveEntryList(&query->ProcessListEntry);
        }

        if (Monitor->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&Monitor->QueryLookaside, query);
        }
    }

    ExReleasePushLockExclusive(&Monitor->TransactionHash.Lock);
    ExReleasePushLockExclusive(&Monitor->QueryListLock);

    //
    // Free domain cache
    //
    ExAcquirePushLockExclusive(&Monitor->DomainCacheLock);

    while (!IsListEmpty(&Monitor->DomainCache)) {
        entry = RemoveHeadList(&Monitor->DomainCache);
        domainEntry = CONTAINING_RECORD(entry, DNS_DOMAIN_CACHE, ListEntry);
        RemoveEntryList(&domainEntry->HashEntry);

        if (Monitor->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&Monitor->DomainCacheLookaside, domainEntry);
        }
    }

    ExReleasePushLockExclusive(&Monitor->DomainCacheLock);

    //
    // Free process contexts
    //
    ExAcquirePushLockExclusive(&Monitor->ProcessListLock);

    while (!IsListEmpty(&Monitor->ProcessList)) {
        entry = RemoveHeadList(&Monitor->ProcessList);
        processCtx = CONTAINING_RECORD(entry, DNS_PROCESS_CONTEXT, ListEntry);

        if (Monitor->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&Monitor->ProcessContextLookaside, processCtx);
        }
    }

    ExReleasePushLockExclusive(&Monitor->ProcessListLock);

    //
    // Free tunnel contexts
    //
    ExAcquirePushLockExclusive(&Monitor->TunnelContextLock);

    while (!IsListEmpty(&Monitor->TunnelContextList)) {
        entry = RemoveHeadList(&Monitor->TunnelContextList);
        tunnelCtx = CONTAINING_RECORD(entry, DNS_TUNNEL_CONTEXT, ListEntry);
        RemoveEntryList(&tunnelCtx->HashEntry);

        if (Monitor->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&Monitor->TunnelContextLookaside, tunnelCtx);
        }
    }

    ExReleasePushLockExclusive(&Monitor->TunnelContextLock);

    //
    // Free lookaside lists
    //
    if (Monitor->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&Monitor->QueryLookaside);
        ExDeleteNPagedLookasideList(&Monitor->DomainCacheLookaside);
        ExDeleteNPagedLookasideList(&Monitor->ProcessContextLookaside);
        ExDeleteNPagedLookasideList(&Monitor->TunnelContextLookaside);
    }

    //
    // Free work item
    //
    if (Monitor->CleanupWorkItem != NULL) {
        IoFreeWorkItem(Monitor->CleanupWorkItem);
    }

    //
    // Free hash tables
    //
    if (Monitor->TransactionHash.Buckets != NULL) {
        ExFreePoolWithTag(Monitor->TransactionHash.Buckets, DNS_POOL_TAG);
    }
    if (Monitor->DomainHash.Buckets != NULL) {
        ExFreePoolWithTag(Monitor->DomainHash.Buckets, DNS_POOL_TAG);
    }
    if (Monitor->TunnelHash.Buckets != NULL) {
        ExFreePoolWithTag(Monitor->TunnelHash.Buckets, DNS_POOL_TAG);
    }

    ExFreePoolWithTag(Monitor, DNS_POOL_TAG);
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
{
    NTSTATUS status;
    PDNS_QUERY query = NULL;
    PDNS_PROCESS_CONTEXT processCtx;
    PDNS_TUNNEL_CONTEXT tunnelCtx;
    CHAR baseDomain[DNS_MAX_NAME_LENGTH + 1];
    ULONG tunnelScore;
    BOOLEAN shouldBlock = FALSE;
    ULONG txHashBucket;
    KIRQL oldIrql;

    if (Monitor == NULL || !Monitor->Initialized || DnsPacket == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (PacketSize < DNS_MIN_PACKET_SIZE || PacketSize > DNS_MAX_PACKET_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Parse the DNS query — now also receives source address info
    //
    status = DnspParseQuery(
        Monitor,
        (PUCHAR)DnsPacket,
        PacketSize,
        ProcessId,
        SourceAddress,
        SourcePort,
        ServerAddress,
        ServerPort,
        IsIPv6,
        &query
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    InterlockedIncrement64(&Monitor->Stats.TotalQueries);

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

    if (query->Analysis.Entropy > Monitor->Config.EntropyThreshold) {
        query->SuspicionFlags |= DnsSuspicion_HighEntropy;
        query->SuspicionScore += 20;
    }

    if (query->Analysis.MaxLabelLength > Monitor->Config.MaxSubdomainLength) {
        query->SuspicionFlags |= DnsSuspicion_LongSubdomain;
        query->SuspicionScore += 15;
    }

    if (query->Analysis.SubdomainCount > DNS_SUBDOMAIN_COUNT_THRESHOLD) {
        query->SuspicionFlags |= DnsSuspicion_ManySubdomains;
        query->SuspicionScore += 10;
    }

    if (query->Analysis.IsBase64Like && query->Analysis.MaxLabelLength > 20) {
        query->SuspicionScore += 25;
    }

    if (query->Analysis.ContainsHex && query->Analysis.MaxLabelLength > 16) {
        query->SuspicionScore += 15;
    }

    if (query->RecordType == DnsType_TXT ||
        query->RecordType == DnsType_ANY ||
        query->RecordType == DnsType_NULL) {
        query->SuspicionFlags |= DnsSuspicion_UnusualType;
        query->SuspicionScore += 10;
    }

    //
    // DGA detection
    //
    if (Monitor->Config.EnableDGADetection) {
        ULONG dgaConfidence;
        if (DnspIsDGADomain(query->DomainName, &dgaConfidence)) {
            query->SuspicionFlags |= DnsSuspicion_DGA;
            query->SuspicionScore += (dgaConfidence / 2);
        }
    }

    //
    // Tunneling detection
    //
    tunnelCtx = NULL;
    if (Monitor->Config.EnableTunnelingDetection) {
        DnspExtractBaseDomain(query->DomainName, baseDomain, sizeof(baseDomain));

        tunnelCtx = DnspGetOrCreateTunnelContext(Monitor, baseDomain);
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
                InterlockedIncrement64(&Monitor->Stats.TunnelDetections);
            }

            DnspDereferenceTunnelContext(Monitor, tunnelCtx);
            tunnelCtx = NULL;
        }
    }

    //
    // Cap score at 100
    //
    if (query->SuspicionScore > 100) {
        query->SuspicionScore = 100;
    }

    //
    // Update process context — hold reference until done with ALL uses
    //
    processCtx = DnspGetOrCreateProcessContext(Monitor, ProcessId);
    if (processCtx != NULL) {
        InterlockedIncrement(&processCtx->TotalQueries);

        if (query->SuspicionFlags != DnsSuspicion_None) {
            InterlockedIncrement(&processCtx->SuspiciousQueries);
        }

        // Correct spinlock usage: acquire at current IRQL
        KeAcquireSpinLock(&processCtx->QueryLock, &oldIrql);
        InsertTailList(&processCtx->QueryList, &query->ProcessListEntry);
        InterlockedIncrement(&processCtx->QueryCount);
        KeReleaseSpinLock(&processCtx->QueryLock, oldIrql);
    }

    //
    // Check for blocking
    //
    if (query->SuspicionScore >= DNS_TUNNEL_ENTROPY_THRESHOLD) {
        query->SuspicionFlags |= DnsSuspicion_KnownBad;

        ExAcquirePushLockShared(&Monitor->Callbacks.Lock);
        if (Monitor->Callbacks.BlockCallback != NULL) {
            shouldBlock = Monitor->Callbacks.BlockCallback(
                query,
                Monitor->Callbacks.BlockContext
            );
        }
        ExReleasePushLockShared(&Monitor->Callbacks.Lock);

        if (shouldBlock) {
            InterlockedIncrement64(&Monitor->Stats.BlockedQueries);
            if (processCtx != NULL) {
                InterlockedIncrement(&processCtx->BlockedQueries);
            }
        }
    }

    if (query->SuspicionFlags != DnsSuspicion_None) {
        InterlockedIncrement64(&Monitor->Stats.SuspiciousQueries);
    }

    //
    // Invoke query callback
    //
    ExAcquirePushLockShared(&Monitor->Callbacks.Lock);
    if (Monitor->Callbacks.QueryCallback != NULL) {
        Monitor->Callbacks.QueryCallback(query, Monitor->Callbacks.QueryContext);
    }
    ExReleasePushLockShared(&Monitor->Callbacks.Lock);

    //
    // Now dereference process context after all uses are done (fix HIGH-02)
    //
    if (processCtx != NULL) {
        DnspDereferenceProcessContext(Monitor, processCtx);
        processCtx = NULL;
    }

    //
    // Add to global query list AND transaction hash atomically
    //
    txHashBucket = DnspHashTransactionId(
        query->TransactionId,
        &query->ServerAddress,
        query->IsIPv6
    ) % Monitor->TransactionHash.BucketCount;

    ExAcquirePushLockExclusive(&Monitor->QueryListLock);
    ExAcquirePushLockExclusive(&Monitor->TransactionHash.Lock);

    InsertTailList(&Monitor->QueryList, &query->ListEntry);
    InsertTailList(&Monitor->TransactionHash.Buckets[txHashBucket], &query->HashEntry);
    InterlockedIncrement(&Monitor->QueryCount);

    ExReleasePushLockExclusive(&Monitor->TransactionHash.Lock);
    ExReleasePushLockExclusive(&Monitor->QueryListLock);

    DnspAddToDomainCache(Monitor, query->DomainName, query);

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
{
    if (Monitor == NULL || !Monitor->Initialized || DnsPacket == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (PacketSize < DNS_MIN_PACKET_SIZE || PacketSize > DNS_MAX_PACKET_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    return DnspParseResponse(
        Monitor,
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
{
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

    *SuspicionFlags = DnsSuspicion_None;
    *SuspicionScore = 0;

    DnspAnalyzeDomain(
        DomainName,
        &entropy,
        &subdomainCount,
        &maxLabelLength,
        &containsNumbers,
        &containsHex,
        &isBase64Like
    );

    if (entropy > Monitor->Config.EntropyThreshold) {
        *SuspicionFlags |= DnsSuspicion_HighEntropy;
        *SuspicionScore += 20;
    }

    if (maxLabelLength > Monitor->Config.MaxSubdomainLength) {
        *SuspicionFlags |= DnsSuspicion_LongSubdomain;
        *SuspicionScore += 15;
    }

    if (subdomainCount > DNS_SUBDOMAIN_COUNT_THRESHOLD) {
        *SuspicionFlags |= DnsSuspicion_ManySubdomains;
        *SuspicionScore += 10;
    }

    if (isBase64Like && maxLabelLength > 20) {
        *SuspicionScore += 25;
    }

    if (containsHex && maxLabelLength > 16) {
        *SuspicionScore += 15;
    }

    if (Monitor->Config.EnableDGADetection) {
        if (DnspIsDGADomain(DomainName, &dgaConfidence)) {
            *SuspicionFlags |= DnsSuspicion_DGA;
            *SuspicionScore += (dgaConfidence / 2);
        }
    }

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
{
    PDNS_PROCESS_CONTEXT processCtx;
    ULONG totalScore = 0;
    ULONG queriesPerMinute;

    if (Monitor == NULL || !Monitor->Initialized ||
        TunnelingDetected == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *TunnelingDetected = FALSE;
    if (Score != NULL) {
        *Score = 0;
    }

    // Lookup only — do not create context for a read-only query
    processCtx = DnspFindProcessContext(Monitor, ProcessId);
    if (processCtx == NULL) {
        return STATUS_NOT_FOUND;
    }

    queriesPerMinute = processCtx->QueriesPerMinute;
    if (queriesPerMinute > Monitor->Config.QueryRateThreshold) {
        totalScore += 30;
    }

    if (processCtx->TotalQueries > 10) {
        LONG total = processCtx->TotalQueries;
        LONG suspicious = processCtx->SuspiciousQueries;
        if (total > 0) {
            ULONG suspiciousRatio = ((ULONG)suspicious * 100) / (ULONG)total;
            if (suspiciousRatio > 50) {
                totalScore += 40;
            } else if (suspiciousRatio > 25) {
                totalScore += 20;
            }
        }
    }

    if (processCtx->UniqueDomainsQueried > 100) {
        totalScore += 20;
    }

    if (processCtx->HighDnsActivity) {
        totalScore += 10;
    }

    DnspDereferenceProcessContext(Monitor, processCtx);

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

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
DnsLookupDomain(
    _In_ PDNS_MONITOR Monitor,
    _In_ PCSTR DomainName,
    _Out_ PDNS_DOMAIN_CACHE EntryCopy
    )
/*++
Routine Description:
    Looks up a domain in the cache and returns a COPY of the entry.
    Caller does not receive a live pointer — safe against concurrent cleanup.
--*/
{
    PDNS_DOMAIN_CACHE entry;

    if (Monitor == NULL || !Monitor->Initialized ||
        DomainName == NULL || EntryCopy == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquirePushLockShared(&Monitor->DomainCacheLock);

    entry = DnspLookupDomainCacheLocked(Monitor, DomainName);
    if (entry == NULL) {
        ExReleasePushLockShared(&Monitor->DomainCacheLock);
        return STATUS_NOT_FOUND;
    }

    RtlCopyMemory(EntryCopy, entry, sizeof(DNS_DOMAIN_CACHE));

    // Invalidate list linkage in the copy so caller cannot corrupt lists
    InitializeListHead(&EntryCopy->ListEntry);
    InitializeListHead(&EntryCopy->HashEntry);

    ExReleasePushLockShared(&Monitor->DomainCacheLock);

    return STATUS_SUCCESS;
}

NTSTATUS
DnsSetDomainReputation(
    _In_ PDNS_MONITOR Monitor,
    _In_ PCSTR DomainName,
    _In_ DNS_REPUTATION Reputation,
    _In_ ULONG Score
    )
{
    PDNS_DOMAIN_CACHE entry;

    if (Monitor == NULL || !Monitor->Initialized || DomainName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Reputation >= DnsReputation_MaxValue) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Score > 100) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquirePushLockExclusive(&Monitor->DomainCacheLock);

    entry = DnspLookupDomainCacheLocked(Monitor, DomainName);
    if (entry != NULL) {
        entry->Reputation = Reputation;
        entry->ReputationScore = Score;
    }

    ExReleasePushLockExclusive(&Monitor->DomainCacheLock);

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
{
    PDNS_PROCESS_CONTEXT processCtx;
    PLIST_ENTRY entry;
    PDNS_QUERY query;
    ULONG count = 0;
    KIRQL oldIrql;

    if (Monitor == NULL || !Monitor->Initialized ||
        Queries == NULL || QueryCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *QueryCount = 0;

    // Lookup only — do not create for read-only query
    processCtx = DnspFindProcessContext(Monitor, ProcessId);
    if (processCtx == NULL) {
        return STATUS_NOT_FOUND;
    }

    KeAcquireSpinLock(&processCtx->QueryLock, &oldIrql);

    for (entry = processCtx->QueryList.Flink;
         entry != &processCtx->QueryList && count < MaxQueries;
         entry = entry->Flink) {

        query = CONTAINING_RECORD(entry, DNS_QUERY, ProcessListEntry);
        Queries[count++] = query;
    }

    KeReleaseSpinLock(&processCtx->QueryLock, oldIrql);

    DnspDereferenceProcessContext(Monitor, processCtx);

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
{
    PDNS_PROCESS_CONTEXT processCtx;

    if (Monitor == NULL || !Monitor->Initialized ||
        TotalQueries == NULL || UniqueDomains == NULL ||
        SuspiciousQueries == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Lookup only
    processCtx = DnspFindProcessContext(Monitor, ProcessId);
    if (processCtx == NULL) {
        return STATUS_NOT_FOUND;
    }

    *TotalQueries = processCtx->TotalQueries;
    *UniqueDomains = processCtx->UniqueDomainsQueried;
    *SuspiciousQueries = processCtx->SuspiciousQueries;

    DnspDereferenceProcessContext(Monitor, processCtx);

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
    if (Monitor == NULL || !Monitor->Initialized || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquirePushLockExclusive(&Monitor->Callbacks.Lock);
    Monitor->Callbacks.QueryCallback = Callback;
    Monitor->Callbacks.QueryContext = Context;
    ExReleasePushLockExclusive(&Monitor->Callbacks.Lock);

    return STATUS_SUCCESS;
}

NTSTATUS
DnsRegisterBlockCallback(
    _In_ PDNS_MONITOR Monitor,
    _In_ DNS_BLOCK_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
{
    if (Monitor == NULL || !Monitor->Initialized || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquirePushLockExclusive(&Monitor->Callbacks.Lock);
    Monitor->Callbacks.BlockCallback = Callback;
    Monitor->Callbacks.BlockContext = Context;
    ExReleasePushLockExclusive(&Monitor->Callbacks.Lock);

    return STATUS_SUCCESS;
}

VOID
DnsUnregisterCallbacks(
    _In_ PDNS_MONITOR Monitor
    )
{
    if (Monitor == NULL || !Monitor->Initialized) {
        return;
    }

    ExAcquirePushLockExclusive(&Monitor->Callbacks.Lock);
    Monitor->Callbacks.QueryCallback = NULL;
    Monitor->Callbacks.QueryContext = NULL;
    Monitor->Callbacks.BlockCallback = NULL;
    Monitor->Callbacks.BlockContext = NULL;
    ExReleasePushLockExclusive(&Monitor->Callbacks.Lock);
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
    LARGE_INTEGER currentTime;

    if (Monitor == NULL || !Monitor->Initialized || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeQuerySystemTimePrecise(&currentTime);

    Stats->TotalQueries = Monitor->Stats.TotalQueries;
    Stats->TotalResponses = Monitor->Stats.TotalResponses;
    Stats->SuspiciousQueries = Monitor->Stats.SuspiciousQueries;
    Stats->BlockedQueries = Monitor->Stats.BlockedQueries;
    Stats->TunnelDetections = Monitor->Stats.TunnelDetections;
    Stats->CacheEntries = Monitor->CacheEntryCount;
    Stats->TrackedProcesses = Monitor->ProcessCount;
    Stats->UpTime.QuadPart = currentTime.QuadPart -
                              Monitor->Stats.StartTime.QuadPart;

    return STATUS_SUCCESS;
}


// ============================================================================
// INTERNAL HELPERS - HASHING
// ============================================================================

static ULONG
DnspHashString(
    _In_ PCSTR String
    )
{
    ULONG hash = 5381;
    UCHAR c;

    while ((c = (UCHAR)*String++) != 0) {
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

            USHORT pointer = ((labelLength & 0x3F) << 8) | Packet[currentOffset + 1];
            if (pointer >= currentOffset) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            currentOffset = pointer;
            jumped = TRUE;

            if (++jumpCount > DNS_MAX_LABELS) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            continue;
        }

        // Reject reserved label types (bits 7-6 = 01 or 10)
        if ((labelLength & 0xC0) != 0x00) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        if (labelLength > DNS_MAX_LABEL_LENGTH) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        if (currentOffset + 1 + labelLength > PacketSize) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        if (nameOffset > 0) {
            if (nameOffset + 1 >= MaxNameLength) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            NameBuffer[nameOffset++] = '.';
        }

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
    _In_ PDNS_MONITOR Monitor,
    _In_reads_bytes_(PacketSize) PUCHAR Packet,
    _In_ ULONG PacketSize,
    _In_ HANDLE ProcessId,
    _In_ PVOID SourceAddress,
    _In_ USHORT SourcePort,
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

    if (RtlUshortByteSwap(header->Flags) & DNS_FLAG_QR) {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    if (RtlUshortByteSwap(header->QuestionCount) < 1) {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    query = (PDNS_QUERY)ExAllocateFromNPagedLookasideList(&Monitor->QueryLookaside);
    if (query == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Lookaside does NOT zero memory — must zero explicitly
    RtlZeroMemory(query, sizeof(DNS_QUERY));

    query->TransactionId = RtlUshortByteSwap(header->TransactionId);
    query->QueryId = InterlockedIncrement64(&Monitor->NextQueryId);
    query->ProcessId = ProcessId;
    KeQuerySystemTimePrecise(&query->QueryTime);

    // Initialize list entries to safe state
    InitializeListHead(&query->ListEntry);
    InitializeListHead(&query->ProcessListEntry);
    InitializeListHead(&query->HashEntry);

    //
    // Parse the question section
    //
    offset = DNS_HEADER_SIZE;
    status = DnspParseDnsName(
        Packet, PacketSize, offset,
        query->DomainName, sizeof(query->DomainName),
        &bytesConsumed
    );

    if (!NT_SUCCESS(status)) {
        ExFreeToNPagedLookasideList(&Monitor->QueryLookaside, query);
        return status;
    }

    offset += bytesConsumed;

    if (offset + sizeof(DNS_QUESTION_FOOTER) > PacketSize) {
        ExFreeToNPagedLookasideList(&Monitor->QueryLookaside, query);
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    questionFooter = (PDNS_QUESTION_FOOTER)&Packet[offset];
    query->RecordType = (DNS_RECORD_TYPE)RtlUshortByteSwap(questionFooter->Type);

    // Populate source address (fix MED-04)
    if (IsIPv6) {
        RtlCopyMemory(&query->SourceAddress.IPv6, SourceAddress, sizeof(IN6_ADDR));
        RtlCopyMemory(&query->ServerAddress.IPv6, ServerAddress, sizeof(IN6_ADDR));
    } else {
        RtlCopyMemory(&query->SourceAddress.IPv4, SourceAddress, sizeof(IN_ADDR));
        RtlCopyMemory(&query->ServerAddress.IPv4, ServerAddress, sizeof(IN_ADDR));
    }
    query->SourcePort = SourcePort;
    query->ServerPort = ServerPort;
    query->IsIPv6 = IsIPv6;

    // Parse flags
    USHORT flags = RtlUshortByteSwap(header->Flags);
    if (flags & DNS_FLAG_RD) query->Flags |= DnsFlag_Recursive;
    if (flags & DNS_FLAG_TC) query->Flags |= DnsFlag_Truncated;

    // Populate process name (best-effort, PASSIVE_LEVEL only)
    DnspPopulateProcessName(
        ProcessId,
        query->ProcessNameBuffer,
        ARRAYSIZE(query->ProcessNameBuffer),
        &query->ProcessNameLength
    );

    *Query = query;
    return STATUS_SUCCESS;
}


static NTSTATUS
DnspParseResponse(
    _In_ PDNS_MONITOR Monitor,
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

    if (PacketSize < DNS_HEADER_SIZE) {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    header = (PDNS_HEADER)Packet;

    if (!(RtlUshortByteSwap(header->Flags) & DNS_FLAG_QR)) {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    transactionId = RtlUshortByteSwap(header->TransactionId);
    answerCount = RtlUshortByteSwap(header->AnswerCount);

    //
    // O(1) lookup via transaction hash table — EXCLUSIVE lock for writes
    //
    hashBucket = DnspHashTransactionId(transactionId, ServerAddress, IsIPv6)
                 % Monitor->TransactionHash.BucketCount;

    ExAcquirePushLockExclusive(&Monitor->TransactionHash.Lock);

    for (entry = Monitor->TransactionHash.Buckets[hashBucket].Flink;
         entry != &Monitor->TransactionHash.Buckets[hashBucket];
         entry = entry->Flink) {

        PDNS_QUERY candidate = CONTAINING_RECORD(entry, DNS_QUERY, HashEntry);
        if (candidate->TransactionId == transactionId &&
            !candidate->Response.Received) {
            query = candidate;
            break;
        }
    }

    if (query == NULL) {
        ExReleasePushLockExclusive(&Monitor->TransactionHash.Lock);
        return STATUS_NOT_FOUND;
    }

    //
    // All writes to query happen under exclusive lock
    //
    KeQuerySystemTimePrecise(&query->ResponseTime);
    query->Response.Received = TRUE;
    query->Response.ResponseCode = RtlUshortByteSwap(header->Flags) & DNS_FLAG_RCODE_MASK;
    query->Response.AnswerCount = answerCount;

    query->LatencyMs = (ULONG)((query->ResponseTime.QuadPart -
                                query->QueryTime.QuadPart) / 10000);

    //
    // Parse answers within the lock
    //
    if (answerCount > 0) {
        offset = DNS_HEADER_SIZE;

        // Skip question section with bounds checking
        USHORT questionCount = RtlUshortByteSwap(header->QuestionCount);
        for (USHORT i = 0; i < questionCount && offset < PacketSize; i++) {
            if (!NT_SUCCESS(DnspParseDnsName(Packet, PacketSize, offset,
                                             domainName, sizeof(domainName),
                                             &bytesConsumed))) {
                break;
            }
            offset += bytesConsumed;
            // Bounds check before adding footer size
            if (offset + sizeof(DNS_QUESTION_FOOTER) > PacketSize) {
                goto DoneParsingAnswers;
            }
            offset += sizeof(DNS_QUESTION_FOOTER);
        }

        // Parse answer records
        ULONG addressCount = 0;
        ULONG cnameCount = 0;
        for (USHORT i = 0; i < answerCount && offset < PacketSize; i++) {
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

            if (i == 0) {
                query->Response.TTL = RtlUlongByteSwap(rrHeader->TTL);
            }

            // A records
            if (rrType == DnsType_A && dataLength == 4 &&
                addressCount < DNS_MAX_RESPONSE_ADDRESSES) {
                query->Response.Addresses[addressCount].IsIPv6 = FALSE;
                RtlCopyMemory(&query->Response.Addresses[addressCount].Address.IPv4,
                              &Packet[offset], 4);
                addressCount++;
            }
            // AAAA records
            else if (rrType == DnsType_AAAA && dataLength == 16 &&
                     addressCount < DNS_MAX_RESPONSE_ADDRESSES) {
                query->Response.Addresses[addressCount].IsIPv6 = TRUE;
                RtlCopyMemory(&query->Response.Addresses[addressCount].Address.IPv6,
                              &Packet[offset], 16);
                addressCount++;
            }
            // CNAME records (fix INCOMPLETE-05)
            else if (rrType == DnsType_CNAME && cnameCount < DNS_MAX_CNAMES) {
                ULONG cnameConsumed;
                if (NT_SUCCESS(DnspParseDnsName(
                        Packet, PacketSize, offset,
                        query->Response.CNAMEs[cnameCount],
                        sizeof(query->Response.CNAMEs[cnameCount]),
                        &cnameConsumed))) {
                    cnameCount++;
                }
            }

            offset += dataLength;
        }

        query->Response.AddressCount = addressCount;
        query->Response.CNAMECount = cnameCount;
    }

DoneParsingAnswers:
    ExReleasePushLockExclusive(&Monitor->TransactionHash.Lock);

    InterlockedIncrement64(&Monitor->Stats.TotalResponses);

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
    Calculates Shannon entropy using fixed-point arithmetic and a log2 lookup
    table. Returns entropy * 100 (e.g., 380 = 3.80 bits per character).
    Uses pool-allocated frequency table to reduce stack pressure.
--*/
{
    PULONG charCount;
    ULONG i;
    ULONG64 entropy = 0;

    if (Length == 0) {
        return 0;
    }

    // Allocate frequency table from pool to avoid 1KB stack allocation
    charCount = (PULONG)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(ULONG) * 256,
        DNS_POOL_TAG
    );

    if (charCount == NULL) {
        return 0;
    }

    for (i = 0; i < Length; i++) {
        charCount[(UCHAR)String[i]]++;
    }

    //
    // Shannon entropy: H = -sum( (count/len) * log2(count/len) )
    //                    = log2(len) - (1/len) * sum( count * log2(count) )
    //
    // Using lookup table: g_Log2Table[i] ~ -log2(i/256)*256
    // We normalize counts to [0..255] range for the lookup.
    //
    for (i = 0; i < 256; i++) {
        if (charCount[i] > 0) {
            // p = charCount[i] / Length, scaled to [0..255]
            ULONG scaled = (charCount[i] * 255) / Length;
            if (scaled == 0) scaled = 1;
            if (scaled > 255) scaled = 255;

            // Contribution: p * (-log2(p)) = (count/len) * g_Log2Table[scaled]/256
            // Scaled by 100 for output
            ULONG64 contribution = (ULONG64)charCount[i] * g_Log2Table[scaled];
            entropy += contribution;
        }
    }

    ExFreePoolWithTag(charCount, DNS_POOL_TAG);

    // entropy is sum(count * g_Log2Table[scaled])
    // Divide by Length (for probability) and by 256 (log table scale), multiply by 100
    ULONG result = (ULONG)((entropy * 100) / ((ULONG64)Length * 256));

    return result;
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
{
    ULONG length;
    ULONG labelCount = 0;
    ULONG currentLabelLength = 0;
    ULONG maxLabel = 0;
    ULONG digitCount = 0;
    ULONG hexCount = 0;
    ULONG base64Count = 0;
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
        }
    }

    if (currentLabelLength > maxLabel) {
        maxLabel = currentLabelLength;
    }
    labelCount++;

    // Entropy of first subdomain
    PCSTR firstDot = strchr(DomainName, '.');
    if (firstDot != NULL) {
        ULONG firstLabelLen = (ULONG)(firstDot - DomainName);
        *Entropy = DnspCalculateEntropy(DomainName, firstLabelLen);
    } else {
        *Entropy = DnspCalculateEntropy(DomainName, length);
    }

    *SubdomainCount = (labelCount > 2) ? labelCount - 2 : 0;
    *MaxLabelLength = maxLabel;
    *ContainsNumbers = (digitCount > 0);

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
{
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

    firstDot = strchr(DomainName, '.');
    if (firstDot == NULL) {
        return FALSE;
    }

    domainPartLength = (ULONG)(firstDot - DomainName);

    if (domainPartLength < DGA_MIN_DOMAIN_LENGTH) {
        return FALSE;
    }

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

        if (p > DomainName && lower >= 'a' && lower <= 'z') {
            CHAR prevLower = (*(p-1) >= 'A' && *(p-1) <= 'Z') ?
                            *(p-1) + 32 : *(p-1);
            if (prevLower >= 'a' && prevLower <= 'z') {
                bigramScore += g_BigramScore[prevLower - 'a'][lower - 'a'];
                bigramCount++;
            }
        }
    }

    ULONG totalLetters = consonantCount + vowelCount;
    if (totalLetters > 0) {
        ULONG consonantRatio = (consonantCount * 100) / totalLetters;
        if (consonantRatio > DGA_CONSONANT_THRESHOLD) {
            score += 20;
        }
    }

    if (domainPartLength > 0) {
        ULONG digitRatio = (digitCount * 100) / domainPartLength;
        if (digitRatio > DGA_DIGIT_THRESHOLD) {
            score += 15;
        }
    }

    if (maxConsecutiveConsonants > DGA_MAX_CONSECUTIVE_CONSONANTS) {
        score += 25;
    }

    if (bigramCount > 0) {
        ULONG avgBigramScore = bigramScore / bigramCount;
        if (avgBigramScore < 20) {
            score += 30;
        } else if (avgBigramScore < 30) {
            score += 15;
        }
    }

    if (domainPartLength > 15 && domainPartLength < 25) {
        score += 10;
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
    if (length == 0) {
        BaseDomain[0] = '\0';
        return;
    }

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
        PCSTR baseDomainStart = secondLastDot + 1;
        ULONG baseLength = (ULONG)(FullDomain + length - baseDomainStart);

        if (baseLength < MaxLength) {
            RtlCopyMemory(BaseDomain, baseDomainStart, baseLength);
            BaseDomain[baseLength] = '\0';
        } else {
            BaseDomain[0] = '\0';
        }
    } else {
        // MaxLength is count of CHARs, sizeof() matches for CHAR arrays
        if (length < MaxLength) {
            RtlCopyMemory(BaseDomain, FullDomain, length + 1);
        } else {
            BaseDomain[0] = '\0';
        }
    }
}

static PDNS_TUNNEL_CONTEXT
DnspGetOrCreateTunnelContext(
    _In_ PDNS_MONITOR Monitor,
    _In_ PCSTR BaseDomain
    )
{
    ULONG hash;
    ULONG bucket;
    PLIST_ENTRY entry;
    PDNS_TUNNEL_CONTEXT context = NULL;

    hash = DnspHashString(BaseDomain);
    bucket = hash % Monitor->TunnelHash.BucketCount;

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

    // Enforce limit (fix DESIGN-03)
    if (Monitor->TunnelContextCount >= DNS_MAX_TUNNEL_CONTEXTS) {
        return NULL;
    }

    context = (PDNS_TUNNEL_CONTEXT)ExAllocateFromNPagedLookasideList(
        &Monitor->TunnelContextLookaside);

    if (context == NULL) {
        return NULL;
    }

    RtlZeroMemory(context, sizeof(DNS_TUNNEL_CONTEXT));
    // RtlStringCchCopyA: second param is count of chars, sizeof(CHAR[]) == char count
    RtlStringCchCopyA(context->BaseDomain,
                       ARRAYSIZE(context->BaseDomain),
                       BaseDomain);
    context->DomainHash = hash;
    context->RefCount = 2;  // One for list, one for caller
    KeQuerySystemTimePrecise(&context->FirstQuery);
    InitializeListHead(&context->ListEntry);
    InitializeListHead(&context->HashEntry);

    ExAcquirePushLockExclusive(&Monitor->TunnelContextLock);

    // Double-check race
    for (entry = Monitor->TunnelHash.Buckets[bucket].Flink;
         entry != &Monitor->TunnelHash.Buckets[bucket];
         entry = entry->Flink) {

        PDNS_TUNNEL_CONTEXT candidate = CONTAINING_RECORD(
            entry, DNS_TUNNEL_CONTEXT, HashEntry);

        if (candidate->DomainHash == hash &&
            _stricmp(candidate->BaseDomain, BaseDomain) == 0) {
            ExReleasePushLockExclusive(&Monitor->TunnelContextLock);
            ExFreeToNPagedLookasideList(&Monitor->TunnelContextLookaside, context);
            InterlockedIncrement(&candidate->RefCount);
            return candidate;
        }
    }

    InsertTailList(&Monitor->TunnelContextList, &context->ListEntry);
    InsertTailList(&Monitor->TunnelHash.Buckets[bucket], &context->HashEntry);
    InterlockedIncrement(&Monitor->TunnelContextCount);

    ExReleasePushLockExclusive(&Monitor->TunnelContextLock);

    return context;
}

static VOID
DnspDereferenceTunnelContext(
    _In_ PDNS_MONITOR Monitor,
    _In_ PDNS_TUNNEL_CONTEXT Context
    )
{
    UNREFERENCED_PARAMETER(Monitor);

    // Just release caller's reference. Cleanup timer handles removal.
    InterlockedDecrement(&Context->RefCount);
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
    LONG currentMax;
    LONG newVal;

    KeQuerySystemTimePrecise(&Context->LastQuery);
    InterlockedIncrement(&Context->TotalQueries);

    if (RecordType == DnsType_TXT) {
        InterlockedIncrement(&Context->TxtQueries);
    }

    baseDomainStart = strstr(FullDomain, Context->BaseDomain);
    if (baseDomainStart != NULL && baseDomainStart > FullDomain) {
        subdomainLength = (ULONG)(baseDomainStart - FullDomain - 1);

        InterlockedAdd64(&Context->TotalSubdomainLength, (LONG64)subdomainLength);

        // Atomic max update via InterlockedCompareExchange
        newVal = (LONG)subdomainLength;
        do {
            currentMax = Context->MaxSubdomainLength;
            if (newVal <= currentMax) break;
        } while (InterlockedCompareExchange(&Context->MaxSubdomainLength,
                                            newVal, currentMax) != currentMax);

        InterlockedIncrement(&Context->UniqueSubdomains);
    }

    // Atomic 64-bit add for entropy sum
    InterlockedAdd64(&Context->TotalEntropySum, (LONG64)Entropy);
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
    LONG totalQueries;

    *Score = 0;

    totalQueries = Context->TotalQueries;
    if (totalQueries < 10) {
        return FALSE;
    }

    KeQuerySystemTimePrecise(&currentTime);
    elapsedMs = (currentTime.QuadPart - Context->FirstQuery.QuadPart) / 10000;

    if (elapsedMs < 60000) {
        return FALSE;
    }

    // Safe division: use LONGLONG arithmetic, guard against zero/overflow
    if (elapsedMs > 0) {
        LONGLONG qpm = ((LONGLONG)totalQueries * 60000LL) / elapsedMs;
        if (qpm > 50) {
            score += 30;
        } else if (qpm > 20) {
            score += 15;
        }
    }

    // TXT query ratio
    if (totalQueries > 0) {
        ULONG txtRatio = ((ULONG)Context->TxtQueries * 100) / (ULONG)totalQueries;
        if (txtRatio > 50) {
            score += 25;
        } else if (txtRatio > 25) {
            score += 10;
        }
    }

    // Average subdomain length
    if (totalQueries > 0) {
        ULONG avgSubdomainLength = (ULONG)(Context->TotalSubdomainLength / totalQueries);
        if (avgSubdomainLength > 40) {
            score += 30;
        } else if (avgSubdomainLength > 25) {
            score += 15;
        }
    }

    // Average entropy
    if (totalQueries > 0) {
        ULONG avgEntropy = (ULONG)(Context->TotalEntropySum / totalQueries);
        if (avgEntropy > 420) {
            score += 25;
        } else if (avgEntropy > 380) {
            score += 10;
        }
    }

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
DnspFindProcessContext(
    _In_ PDNS_MONITOR Monitor,
    _In_ HANDLE ProcessId
    )
/*++
Routine Description:
    Lookup-only process context search. Does NOT create a new context.
    Returns with RefCount incremented, caller must dereference.
--*/
{
    PLIST_ENTRY entry;
    PDNS_PROCESS_CONTEXT context = NULL;

    ExAcquirePushLockShared(&Monitor->ProcessListLock);

    for (entry = Monitor->ProcessList.Flink;
         entry != &Monitor->ProcessList;
         entry = entry->Flink) {

        PDNS_PROCESS_CONTEXT candidate = CONTAINING_RECORD(
            entry, DNS_PROCESS_CONTEXT, ListEntry);

        if (candidate->ProcessId == ProcessId) {
            context = candidate;
            InterlockedIncrement(&context->RefCount);
            break;
        }
    }

    ExReleasePushLockShared(&Monitor->ProcessListLock);

    return context;
}

static PDNS_PROCESS_CONTEXT
DnspGetOrCreateProcessContext(
    _In_ PDNS_MONITOR Monitor,
    _In_ HANDLE ProcessId
    )
{
    PLIST_ENTRY entry;
    PDNS_PROCESS_CONTEXT context = NULL;

    // Try lookup first
    context = DnspFindProcessContext(Monitor, ProcessId);
    if (context != NULL) {
        return context;
    }

    // Enforce limit (fix DESIGN-03)
    if (Monitor->ProcessCount >= DNS_MAX_PROCESS_CONTEXTS) {
        return NULL;
    }

    context = (PDNS_PROCESS_CONTEXT)ExAllocateFromNPagedLookasideList(
        &Monitor->ProcessContextLookaside);

    if (context == NULL) {
        return NULL;
    }

    RtlZeroMemory(context, sizeof(DNS_PROCESS_CONTEXT));
    context->ProcessId = ProcessId;
    context->RefCount = 2;  // One for list, one for caller
    InitializeListHead(&context->QueryList);
    KeInitializeSpinLock(&context->QueryLock);
    KeQuerySystemTimePrecise(&context->CreationTime);

    // Populate process name (best-effort)
    DnspPopulateProcessName(
        ProcessId,
        context->ProcessNameBuffer,
        ARRAYSIZE(context->ProcessNameBuffer),
        &context->ProcessNameLength
    );

    ExAcquirePushLockExclusive(&Monitor->ProcessListLock);

    // Double-check race
    for (entry = Monitor->ProcessList.Flink;
         entry != &Monitor->ProcessList;
         entry = entry->Flink) {

        PDNS_PROCESS_CONTEXT candidate = CONTAINING_RECORD(
            entry, DNS_PROCESS_CONTEXT, ListEntry);

        if (candidate->ProcessId == ProcessId) {
            ExReleasePushLockExclusive(&Monitor->ProcessListLock);
            ExFreeToNPagedLookasideList(&Monitor->ProcessContextLookaside, context);
            InterlockedIncrement(&candidate->RefCount);
            return candidate;
        }
    }

    InsertTailList(&Monitor->ProcessList, &context->ListEntry);
    InterlockedIncrement(&Monitor->ProcessCount);

    ExReleasePushLockExclusive(&Monitor->ProcessListLock);

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
    _In_ PDNS_MONITOR Monitor,
    _In_ PDNS_PROCESS_CONTEXT Context
    )
{
    UNREFERENCED_PARAMETER(Monitor);

    // Caller's reference released. List reference + cleanup timer handle lifetime.
    InterlockedDecrement(&Context->RefCount);
}

// ============================================================================
// INTERNAL HELPERS - DOMAIN CACHE
// ============================================================================

_Requires_lock_held_(Monitor->DomainCacheLock)
static PDNS_DOMAIN_CACHE
DnspLookupDomainCacheLocked(
    _In_ PDNS_MONITOR Monitor,
    _In_ PCSTR DomainName
    )
/*++
Routine Description:
    Looks up a domain in the hash table.
    CALLER MUST HOLD DomainCacheLock (shared or exclusive).
    Updates QueryCount and LastSeen atomically.
--*/
{
    ULONG hash;
    ULONG bucket;
    PLIST_ENTRY entry;
    PDNS_DOMAIN_CACHE cacheEntry = NULL;

    hash = DnspHashString(DomainName);
    bucket = hash % Monitor->DomainHash.BucketCount;

    for (entry = Monitor->DomainHash.Buckets[bucket].Flink;
         entry != &Monitor->DomainHash.Buckets[bucket];
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
    _In_ PDNS_MONITOR Monitor,
    _In_ PCSTR DomainName,
    _In_ PDNS_QUERY Query
    )
{
    ULONG hash;
    ULONG bucket;
    PDNS_DOMAIN_CACHE cacheEntry;
    LARGE_INTEGER currentTime;
    PLIST_ENTRY entry;

    // Acquire exclusive lock for the entire check-and-insert (fix CRITICAL-05)
    ExAcquirePushLockExclusive(&Monitor->DomainCacheLock);

    // Check if already exists under lock
    if (DnspLookupDomainCacheLocked(Monitor, DomainName) != NULL) {
        ExReleasePushLockExclusive(&Monitor->DomainCacheLock);
        return STATUS_SUCCESS;
    }

    // Check cache limit
    if (Monitor->CacheEntryCount >= DNS_MAX_CACHED_QUERIES) {
        ExReleasePushLockExclusive(&Monitor->DomainCacheLock);
        return STATUS_QUOTA_EXCEEDED;
    }

    cacheEntry = (PDNS_DOMAIN_CACHE)ExAllocateFromNPagedLookasideList(
        &Monitor->DomainCacheLookaside);

    if (cacheEntry == NULL) {
        ExReleasePushLockExclusive(&Monitor->DomainCacheLock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(cacheEntry, sizeof(DNS_DOMAIN_CACHE));

    hash = DnspHashString(DomainName);
    bucket = hash % Monitor->DomainHash.BucketCount;

    RtlStringCchCopyA(cacheEntry->DomainName,
                       ARRAYSIZE(cacheEntry->DomainName),
                       DomainName);
    cacheEntry->DomainHash = hash;
    cacheEntry->QueryCount = 1;
    cacheEntry->UniqueProcesses = 1;
    cacheEntry->Reputation = DnsReputation_Unknown;

    KeQuerySystemTimePrecise(&currentTime);
    cacheEntry->FirstSeen = currentTime;
    cacheEntry->LastSeen = currentTime;
    cacheEntry->ExpirationTime.QuadPart = currentTime.QuadPart +
                                           ((LONGLONG)DNS_CACHE_TTL_SECONDS * 10000000);

    // Copy resolution data with proper per-address type tracking
    if (Query->Response.Received && Query->Response.AddressCount > 0) {
        ULONG copyCount = min(Query->Response.AddressCount, DNS_MAX_CACHED_ADDRESSES);
        for (ULONG i = 0; i < copyCount; i++) {
            cacheEntry->KnownAddresses[i] = Query->Response.Addresses[i];
        }
        cacheEntry->AddressCount = copyCount;
    }

    InitializeListHead(&cacheEntry->ListEntry);
    InitializeListHead(&cacheEntry->HashEntry);

    InsertTailList(&Monitor->DomainCache, &cacheEntry->ListEntry);
    InsertTailList(&Monitor->DomainHash.Buckets[bucket], &cacheEntry->HashEntry);
    InterlockedIncrement(&Monitor->CacheEntryCount);

    ExReleasePushLockExclusive(&Monitor->DomainCacheLock);

    return STATUS_SUCCESS;
}


// ============================================================================
// INTERNAL HELPERS - QUERY FREE
// ============================================================================

static VOID
DnspFreeQuery(
    _In_ PDNS_MONITOR Monitor,
    _In_ PDNS_QUERY Query
    )
/*++
Routine Description:
    Frees a query. Caller must have already removed Query from
    QueryList and HashEntry lists. This function removes from
    ProcessListEntry if still linked.
--*/
{
    // Remove from process query list if still linked
    if (Query->ProcessListEntry.Flink != NULL &&
        Query->ProcessListEntry.Blink != NULL &&
        !IsListEmpty(&Query->ProcessListEntry)) {
        // Need process context lock — find process context
        PDNS_PROCESS_CONTEXT processCtx = DnspFindProcessContext(Monitor, Query->ProcessId);
        if (processCtx != NULL) {
            KIRQL oldIrql;
            KeAcquireSpinLock(&processCtx->QueryLock, &oldIrql);
            RemoveEntryList(&Query->ProcessListEntry);
            InterlockedDecrement(&processCtx->QueryCount);
            KeReleaseSpinLock(&processCtx->QueryLock, oldIrql);
            DnspDereferenceProcessContext(Monitor, processCtx);
        } else {
            // Process context already gone — just unlink safely
            RemoveEntryList(&Query->ProcessListEntry);
        }
    }

    ExFreeToNPagedLookasideList(&Monitor->QueryLookaside, Query);
}

// ============================================================================
// INTERNAL HELPERS - CLEANUP (RUNS AT PASSIVE_LEVEL VIA WORK ITEM)
// ============================================================================

static VOID NTAPI
DnspCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
/*++
Routine Description:
    DPC callback for cleanup timer. Runs at DISPATCH_LEVEL.
    We CANNOT acquire push locks here. Queue a work item instead.
--*/
{
    PDNS_MONITOR monitor = (PDNS_MONITOR)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (monitor == NULL || !monitor->Initialized) {
        return;
    }

    if (monitor->CleanupWorkItem == NULL) {
        return;
    }

    // Only queue if no cleanup already in progress
    if (InterlockedCompareExchange(&monitor->CleanupInProgress, 1, 0) == 0) {
        IoQueueWorkItem(
            monitor->CleanupWorkItem,
            DnspCleanupWorkItemRoutine,
            DelayedWorkQueue,
            monitor
        );
    }
}

static VOID
DnspCleanupWorkItemRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    )
/*++
Routine Description:
    Work item callback. Runs at PASSIVE_LEVEL — safe to acquire push locks.
--*/
{
    PDNS_MONITOR monitor = (PDNS_MONITOR)Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (monitor == NULL) {
        return;
    }

    if (!monitor->Initialized) {
        InterlockedExchange(&monitor->CleanupInProgress, 0);
        return;
    }

    DnspCleanupExpiredEntries(monitor);

    InterlockedExchange(&monitor->CleanupInProgress, 0);
}

static VOID
DnspCleanupExpiredEntries(
    _In_ PDNS_MONITOR Monitor
    )
/*++
Routine Description:
    Removes expired queries, domain cache entries, idle process contexts,
    and idle tunnel contexts. Runs at PASSIVE_LEVEL.
--*/
{
    LARGE_INTEGER currentTime;
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;
    LIST_ENTRY expiredQueries;
    LIST_ENTRY expiredDomains;
    LIST_ENTRY expiredProcesses;
    LIST_ENTRY expiredTunnels;

    InitializeListHead(&expiredQueries);
    InitializeListHead(&expiredDomains);
    InitializeListHead(&expiredProcesses);
    InitializeListHead(&expiredTunnels);

    KeQuerySystemTimePrecise(&currentTime);

    //
    // Collect expired queries — remove from BOTH QueryList and TransactionHash
    //
    ExAcquirePushLockExclusive(&Monitor->QueryListLock);
    ExAcquirePushLockExclusive(&Monitor->TransactionHash.Lock);

    for (entry = Monitor->QueryList.Flink;
         entry != &Monitor->QueryList;
         entry = nextEntry) {

        nextEntry = entry->Flink;
        PDNS_QUERY query = CONTAINING_RECORD(entry, DNS_QUERY, ListEntry);

        LONGLONG ageMs = (currentTime.QuadPart - query->QueryTime.QuadPart) / 10000;
        if (ageMs > DNS_QUERY_EXPIRATION_MS) {
            RemoveEntryList(&query->ListEntry);
            RemoveEntryList(&query->HashEntry);
            InsertTailList(&expiredQueries, &query->ListEntry);
            InterlockedDecrement(&Monitor->QueryCount);
        }
    }

    ExReleasePushLockExclusive(&Monitor->TransactionHash.Lock);
    ExReleasePushLockExclusive(&Monitor->QueryListLock);

    //
    // Collect expired domain cache entries
    //
    ExAcquirePushLockExclusive(&Monitor->DomainCacheLock);

    for (entry = Monitor->DomainCache.Flink;
         entry != &Monitor->DomainCache;
         entry = nextEntry) {

        nextEntry = entry->Flink;
        PDNS_DOMAIN_CACHE domainEntry = CONTAINING_RECORD(
            entry, DNS_DOMAIN_CACHE, ListEntry);

        if (currentTime.QuadPart > domainEntry->ExpirationTime.QuadPart) {
            RemoveEntryList(&domainEntry->ListEntry);
            RemoveEntryList(&domainEntry->HashEntry);
            InsertTailList(&expiredDomains, &domainEntry->ListEntry);
            InterlockedDecrement(&Monitor->CacheEntryCount);
        }
    }

    ExReleasePushLockExclusive(&Monitor->DomainCacheLock);

    //
    // Collect idle process contexts (RefCount == 1 means only list reference)
    //
    ExAcquirePushLockExclusive(&Monitor->ProcessListLock);

    for (entry = Monitor->ProcessList.Flink;
         entry != &Monitor->ProcessList;
         entry = nextEntry) {

        nextEntry = entry->Flink;
        PDNS_PROCESS_CONTEXT processCtx = CONTAINING_RECORD(
            entry, DNS_PROCESS_CONTEXT, ListEntry);

        // Only remove if refcount is exactly 1 (list reference only) and idle
        if (processCtx->RefCount == 1) {
            LONGLONG idleMs = (currentTime.QuadPart - processCtx->CreationTime.QuadPart) / 10000;
            if (idleMs > DNS_PROCESS_IDLE_EXPIRATION_MS && processCtx->TotalQueries == 0) {
                RemoveEntryList(&processCtx->ListEntry);
                InsertTailList(&expiredProcesses, &processCtx->ListEntry);
                InterlockedDecrement(&Monitor->ProcessCount);
            }
        }
    }

    ExReleasePushLockExclusive(&Monitor->ProcessListLock);

    //
    // Collect idle tunnel contexts
    //
    ExAcquirePushLockExclusive(&Monitor->TunnelContextLock);

    for (entry = Monitor->TunnelContextList.Flink;
         entry != &Monitor->TunnelContextList;
         entry = nextEntry) {

        nextEntry = entry->Flink;
        PDNS_TUNNEL_CONTEXT tunnelCtx = CONTAINING_RECORD(
            entry, DNS_TUNNEL_CONTEXT, ListEntry);

        if (tunnelCtx->RefCount == 1) {
            LONGLONG idleMs = (currentTime.QuadPart - tunnelCtx->LastQuery.QuadPart) / 10000;
            if (idleMs > DNS_TUNNEL_IDLE_EXPIRATION_MS) {
                RemoveEntryList(&tunnelCtx->ListEntry);
                RemoveEntryList(&tunnelCtx->HashEntry);
                InsertTailList(&expiredTunnels, &tunnelCtx->ListEntry);
                InterlockedDecrement(&Monitor->TunnelContextCount);
            }
        }
    }

    ExReleasePushLockExclusive(&Monitor->TunnelContextLock);

    //
    // Free expired entries outside of locks
    //
    while (!IsListEmpty(&expiredQueries)) {
        entry = RemoveHeadList(&expiredQueries);
        PDNS_QUERY query = CONTAINING_RECORD(entry, DNS_QUERY, ListEntry);
        // DnspFreeQuery handles ProcessListEntry removal
        DnspFreeQuery(Monitor, query);
    }

    while (!IsListEmpty(&expiredDomains)) {
        entry = RemoveHeadList(&expiredDomains);
        PDNS_DOMAIN_CACHE domainEntry = CONTAINING_RECORD(
            entry, DNS_DOMAIN_CACHE, ListEntry);
        ExFreeToNPagedLookasideList(&Monitor->DomainCacheLookaside, domainEntry);
    }

    while (!IsListEmpty(&expiredProcesses)) {
        entry = RemoveHeadList(&expiredProcesses);
        PDNS_PROCESS_CONTEXT processCtx = CONTAINING_RECORD(
            entry, DNS_PROCESS_CONTEXT, ListEntry);
        ExFreeToNPagedLookasideList(&Monitor->ProcessContextLookaside, processCtx);
    }

    while (!IsListEmpty(&expiredTunnels)) {
        entry = RemoveHeadList(&expiredTunnels);
        PDNS_TUNNEL_CONTEXT tunnelCtx = CONTAINING_RECORD(
            entry, DNS_TUNNEL_CONTEXT, ListEntry);
        ExFreeToNPagedLookasideList(&Monitor->TunnelContextLookaside, tunnelCtx);
    }
}
