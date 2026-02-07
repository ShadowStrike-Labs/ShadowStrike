/*++
    ShadowStrike Next-Generation Antivirus
    Module: NetworkReputation.h
    
    Purpose: IP and domain reputation lookup and caching.
    
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
// Reputation Entry
//=============================================================================

typedef struct _NR_ENTRY {
    // Entry type
    enum {
        NrType_IP,
        NrType_Domain,
        NrType_URL,
    } Type;
    
    // Value
    union {
        struct {
            IN_ADDR Address;
            BOOLEAN IsIPv6;
            IN6_ADDR Address6;
        } IP;
        CHAR Domain[NR_MAX_DOMAIN_LENGTH + 1];
        CHAR URL[512];
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
    LARGE_INTEGER LastAccessTime;
    volatile LONG HitCount;
    
    // List linkage
    LIST_ENTRY ListEntry;
    LIST_ENTRY HashEntry;
    
} NR_ENTRY, *PNR_ENTRY;

//=============================================================================
// Reputation Manager
//=============================================================================

typedef struct _NR_MANAGER {
    BOOLEAN Initialized;
    
    // Cache
    LIST_ENTRY EntryList;
    EX_PUSH_LOCK EntryLock;
    volatile LONG EntryCount;
    
    // Hash table
    struct {
        LIST_ENTRY* Buckets;
        ULONG BucketCount;
    } Hash;
    
    // Cleanup timer
    KTIMER CleanupTimer;
    KDPC CleanupDpc;
    
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
    BOOLEAN FromCache;
} NR_LOOKUP_RESULT, *PNR_LOOKUP_RESULT;

//=============================================================================
// Public API
//=============================================================================

NTSTATUS
NrInitialize(
    _Out_ PNR_MANAGER* Manager
    );

VOID
NrShutdown(
    _Inout_ PNR_MANAGER Manager
    );

// Lookup
NTSTATUS
NrLookupIP(
    _In_ PNR_MANAGER Manager,
    _In_ PVOID Address,
    _In_ BOOLEAN IsIPv6,
    _Out_ PNR_LOOKUP_RESULT Result
    );

NTSTATUS
NrLookupDomain(
    _In_ PNR_MANAGER Manager,
    _In_ PCSTR Domain,
    _Out_ PNR_LOOKUP_RESULT Result
    );

// Cache management
NTSTATUS
NrAddEntry(
    _In_ PNR_MANAGER Manager,
    _In_ PNR_ENTRY Entry
    );

NTSTATUS
NrAddIP(
    _In_ PNR_MANAGER Manager,
    _In_ PVOID Address,
    _In_ BOOLEAN IsIPv6,
    _In_ NR_REPUTATION Reputation,
    _In_ NR_CATEGORY Categories,
    _In_ ULONG Score,
    _In_opt_ PCSTR ThreatName
    );

NTSTATUS
NrAddDomain(
    _In_ PNR_MANAGER Manager,
    _In_ PCSTR Domain,
    _In_ NR_REPUTATION Reputation,
    _In_ NR_CATEGORY Categories,
    _In_ ULONG Score,
    _In_opt_ PCSTR ThreatName
    );

NTSTATUS
NrRemoveIP(
    _In_ PNR_MANAGER Manager,
    _In_ PVOID Address,
    _In_ BOOLEAN IsIPv6
    );

NTSTATUS
NrRemoveDomain(
    _In_ PNR_MANAGER Manager,
    _In_ PCSTR Domain
    );

// Bulk loading
NTSTATUS
NrLoadFromFile(
    _In_ PNR_MANAGER Manager,
    _In_ PUNICODE_STRING FilePath
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

NTSTATUS
NrGetStatistics(
    _In_ PNR_MANAGER Manager,
    _Out_ PNR_STATISTICS Stats
    );

VOID
NrClearCache(
    _In_ PNR_MANAGER Manager
    );

#ifdef __cplusplus
}
#endif
