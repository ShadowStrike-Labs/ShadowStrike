/*++
    ShadowStrike Next-Generation Antivirus
    Module: NetworkReputation.h

    Purpose: IP and domain reputation lookup and caching.

    Design:
    - EX_RUNDOWN_REF protects manager lifetime during concurrent operations.
    - EX_PUSH_LOCK (shared/exclusive) guards the cache data structures.
    - Periodic cleanup runs at PASSIVE_LEVEL via IoWorkItem (NOT DPC).
    - Entries are allocated from PagedPool (accessed only at <= APC_LEVEL).
    - Duplicate entries are detected and updated in-place on re-add.
    - No hardcoded safe-IP whitelist; private/loopback return Unknown
      with an NR_FLAG_INTERNAL flag so callers can apply policy.

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

#define NR_POOL_TAG_ENTRY       'ENRN'  // Network Reputation - Entry
#define NR_POOL_TAG_CACHE       'CNRN'  // Network Reputation - Cache
#define NR_POOL_TAG_WORK        'WNRN'  // Network Reputation - Work Item

//=============================================================================
// Configuration
//=============================================================================

#define NR_MAX_CACHE_ENTRIES            65536
#define NR_CACHE_TTL_SECONDS            3600
#define NR_MAX_DOMAIN_LENGTH            255

//=============================================================================
// Reputation Levels
//=============================================================================

typedef enum _NR_REPUTATION {
    NrReputation_Unknown = 0,
    NrReputation_Safe = 1,
    NrReputation_Low = 2,
    NrReputation_Medium = 3,
    NrReputation_High = 4,
    NrReputation_Malicious = 5,
    NrReputation_Whitelisted = 100,
    NrReputation_Blacklisted = 101,
} NR_REPUTATION;

//=============================================================================
// Reputation Categories
//=============================================================================

typedef enum _NR_CATEGORY {
    NrCategory_None                 = 0x00000000,
    NrCategory_Malware              = 0x00000001,
    NrCategory_Phishing             = 0x00000002,
    NrCategory_C2                   = 0x00000004,
    NrCategory_Botnet               = 0x00000008,
    NrCategory_Spam                 = 0x00000010,
    NrCategory_TorExitNode          = 0x00000020,
    NrCategory_VPN                  = 0x00000040,
    NrCategory_Proxy                = 0x00000080,
    NrCategory_Cryptomining         = 0x00000100,
    NrCategory_Ransomware           = 0x00000200,
    NrCategory_DGA                  = 0x00000400,
    NrCategory_Exploit              = 0x00000800,
} NR_CATEGORY;

//=============================================================================
// Lookup Result Flags
//=============================================================================

#define NR_FLAG_NONE            0x00000000
#define NR_FLAG_FROM_CACHE      0x00000001
#define NR_FLAG_INTERNAL        0x00000002  // Private / loopback IP
#define NR_FLAG_LOOPBACK        0x00000004
#define NR_FLAG_DGA_HEURISTIC   0x00000008  // Score from heuristic, not DB

//=============================================================================
// Reputation Entry
//=============================================================================

typedef enum _NR_ENTRY_TYPE {
    NrType_IP = 0,
    NrType_Domain = 1,
} NR_ENTRY_TYPE;

typedef struct _NR_ENTRY {
    NR_ENTRY_TYPE Type;

    union {
        struct {
            IN_ADDR Address;
            BOOLEAN IsIPv6;
            IN6_ADDR Address6;
        } IP;
        CHAR Domain[NR_MAX_DOMAIN_LENGTH + 1];
    } Value;
    ULONG Hash;

    // Reputation
    NR_REPUTATION Reputation;
    NR_CATEGORY Categories;
    ULONG Score;                        // 0-100 (lower = safer)

    // Threat info
    CHAR ThreatName[64];
    CHAR MalwareFamily[64];

    // Cache management
    LARGE_INTEGER AddedTime;
    LARGE_INTEGER ExpirationTime;
    volatile LONGLONG LastAccessTime;   // Updated atomically via InterlockedExchange64
    volatile LONG HitCount;

    // List linkage
    LIST_ENTRY ListEntry;               // Global LRU list
    LIST_ENTRY HashEntry;               // Per-bucket chain

} NR_ENTRY, *PNR_ENTRY;

//=============================================================================
// Reputation Manager
//=============================================================================

typedef struct _NR_MANAGER {
    //
    // Rundown protection: all public operations acquire this before
    // touching any state. Shutdown waits for rundown to drain.
    //
    EX_RUNDOWN_REF RundownRef;

    // Cache
    LIST_ENTRY EntryList;
    EX_PUSH_LOCK EntryLock;
    volatile LONG EntryCount;

    // Hash table
    struct {
        LIST_ENTRY* Buckets;
        ULONG BucketCount;
    } Hash;

    // Periodic cleanup (work item, runs at PASSIVE_LEVEL)
    KTIMER CleanupTimer;
    KDPC CleanupDpc;
    PIO_WORKITEM CleanupWorkItem;
    volatile LONG CleanupInProgress;    // Prevent overlapping work items

    // Statistics
    struct {
        volatile LONG64 Lookups;
        volatile LONG64 Hits;
        volatile LONG64 Misses;
        LARGE_INTEGER StartTime;
    } Stats;

    // Configuration
    struct {
        ULONG MaxEntries;
        ULONG TTLSeconds;
        BOOLEAN EnableExpirations;
    } Config;

    // Back-pointer to device object (needed for IoAllocateWorkItem)
    PDEVICE_OBJECT DeviceObject;

} NR_MANAGER, *PNR_MANAGER;

//=============================================================================
// Lookup Result
//=============================================================================

typedef struct _NR_LOOKUP_RESULT {
    BOOLEAN Found;
    NR_REPUTATION Reputation;
    NR_CATEGORY Categories;
    ULONG Score;
    CHAR ThreatName[64];
    CHAR MalwareFamily[64];
    ULONG Flags;                        // NR_FLAG_*
} NR_LOOKUP_RESULT, *PNR_LOOKUP_RESULT;

//=============================================================================
// Public API
//=============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
NrInitialize(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PNR_MANAGER* Manager
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
NrShutdown(
    _Inout_ PNR_MANAGER Manager
    );

// Lookup
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NrLookupIP(
    _In_ PNR_MANAGER Manager,
    _In_reads_bytes_(IsIPv6 ? sizeof(IN6_ADDR) : sizeof(IN_ADDR)) const VOID* Address,
    _In_ BOOLEAN IsIPv6,
    _Out_ PNR_LOOKUP_RESULT Result
    );

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NrLookupDomain(
    _In_ PNR_MANAGER Manager,
    _In_z_ PCSTR Domain,
    _Out_ PNR_LOOKUP_RESULT Result
    );

// Cache management
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NrAddIP(
    _In_ PNR_MANAGER Manager,
    _In_reads_bytes_(IsIPv6 ? sizeof(IN6_ADDR) : sizeof(IN_ADDR)) const VOID* Address,
    _In_ BOOLEAN IsIPv6,
    _In_ NR_REPUTATION Reputation,
    _In_ NR_CATEGORY Categories,
    _In_ ULONG Score,
    _In_opt_z_ PCSTR ThreatName
    );

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NrAddDomain(
    _In_ PNR_MANAGER Manager,
    _In_z_ PCSTR Domain,
    _In_ NR_REPUTATION Reputation,
    _In_ NR_CATEGORY Categories,
    _In_ ULONG Score,
    _In_opt_z_ PCSTR ThreatName
    );

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NrRemoveIP(
    _In_ PNR_MANAGER Manager,
    _In_reads_bytes_(IsIPv6 ? sizeof(IN6_ADDR) : sizeof(IN_ADDR)) const VOID* Address,
    _In_ BOOLEAN IsIPv6
    );

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NrRemoveDomain(
    _In_ PNR_MANAGER Manager,
    _In_z_ PCSTR Domain
    );

// Statistics
typedef struct _NR_STATISTICS {
    ULONG CacheEntries;
    ULONG64 Lookups;
    ULONG64 CacheHits;
    ULONG64 CacheMisses;
    ULONG HitRatePercent;
    LARGE_INTEGER UpTime;
} NR_STATISTICS, *PNR_STATISTICS;

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
NrGetStatistics(
    _In_ PNR_MANAGER Manager,
    _Out_ PNR_STATISTICS Stats
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
NrClearCache(
    _In_ PNR_MANAGER Manager
    );

#ifdef __cplusplus
}
#endif
