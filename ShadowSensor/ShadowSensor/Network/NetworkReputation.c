/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE NETWORK REPUTATION ENGINE
 * ============================================================================
 *
 * @file NetworkReputation.c
 * @brief Enterprise-grade IP and domain reputation lookup with caching.
 *
 * Implements CrowdStrike Falcon-class network reputation with:
 * - High-performance hash-based IP/domain lookup (O(1) average)
 * - LRU cache with configurable TTL and size limits
 * - Thread-safe operations with reader-writer locks
 * - Automatic cache cleanup via kernel timer/DPC
 * - Support for IPv4, IPv6, and domain reputation
 * - Category-based threat classification
 * - Whitelist/blacklist support
 * - Statistics and telemetry
 *
 * Threat Categories Supported:
 * - Malware distribution sites
 * - Phishing domains
 * - C2 (Command & Control) servers
 * - Botnet infrastructure
 * - Tor exit nodes
 * - Known VPN/Proxy services
 * - Cryptomining pools
 * - Ransomware infrastructure
 * - DGA (Domain Generation Algorithm) domains
 * - Exploit kit hosting
 *
 * Performance Characteristics:
 * - O(1) average lookup time via hash table
 * - Minimal lock contention with push locks
 * - Lazy expiration during lookup
 * - Background cleanup for expired entries
 * - Memory-efficient entry storage
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "NetworkReputation.h"
#include <ntstrsafe.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, NrInitialize)
#pragma alloc_text(PAGE, NrShutdown)
#pragma alloc_text(PAGE, NrClearCache)
#pragma alloc_text(PAGE, NrLoadFromFile)
#endif

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

/**
 * @brief Default hash bucket count (power of 2 for fast modulo)
 */
#define NR_HASH_BUCKET_COUNT            4096

/**
 * @brief Cleanup timer interval in milliseconds
 */
#define NR_CLEANUP_INTERVAL_MS          60000

/**
 * @brief Maximum entries to clean per timer tick
 */
#define NR_MAX_CLEANUP_PER_TICK         256

/**
 * @brief FNV-1a hash constants
 */
#define NR_FNV_OFFSET_BASIS             2166136261UL
#define NR_FNV_PRIME                    16777619UL

/**
 * @brief Known malicious IP ranges (Tor exit nodes, etc.)
 * Format: Start IP, End IP (network byte order)
 */
typedef struct _NR_KNOWN_BAD_RANGE {
    ULONG StartIP;
    ULONG EndIP;
    NR_CATEGORY Category;
} NR_KNOWN_BAD_RANGE;

/**
 * @brief Known safe IP ranges (Microsoft, Google, etc.)
 */
typedef struct _NR_KNOWN_SAFE_RANGE {
    ULONG StartIP;
    ULONG EndIP;
    PCSTR Description;
} NR_KNOWN_SAFE_RANGE;

// ============================================================================
// PRIVATE FUNCTION PROTOTYPES
// ============================================================================

static ULONG
NrpHashIP(
    _In_ PVOID Address,
    _In_ BOOLEAN IsIPv6
    );

static ULONG
NrpHashDomain(
    _In_ PCSTR Domain
    );

static ULONG
NrpHashToIndex(
    _In_ PNR_MANAGER Manager,
    _In_ ULONG Hash
    );

static PNR_ENTRY
NrpFindEntryByIP(
    _In_ PNR_MANAGER Manager,
    _In_ PVOID Address,
    _In_ BOOLEAN IsIPv6,
    _In_ ULONG Hash
    );

static PNR_ENTRY
NrpFindEntryByDomain(
    _In_ PNR_MANAGER Manager,
    _In_ PCSTR Domain,
    _In_ ULONG Hash
    );

static PNR_ENTRY
NrpAllocateEntry(
    VOID
    );

static VOID
NrpFreeEntry(
    _In_ PNR_ENTRY Entry
    );

static VOID
NrpInsertEntry(
    _In_ PNR_MANAGER Manager,
    _In_ PNR_ENTRY Entry
    );

static VOID
NrpRemoveEntry(
    _In_ PNR_MANAGER Manager,
    _In_ PNR_ENTRY Entry
    );

static BOOLEAN
NrpIsEntryExpired(
    _In_ PNR_ENTRY Entry
    );

static VOID
NrpEvictOldestEntry(
    _In_ PNR_MANAGER Manager
    );

static VOID
NrpCleanupExpiredEntries(
    _In_ PNR_MANAGER Manager,
    _In_ ULONG MaxToClean
    );

static KDEFERRED_ROUTINE NrpCleanupTimerDpc;

static BOOLEAN
NrpIsKnownSafeIP(
    _In_ ULONG IPv4Address
    );

static BOOLEAN
NrpIsPrivateIP(
    _In_ ULONG IPv4Address
    );

static BOOLEAN
NrpIsLoopbackIP(
    _In_ ULONG IPv4Address
    );

static ULONG
NrpCalculateDGAScore(
    _In_ PCSTR Domain
    );

static VOID
NrpNormalizeDomain(
    _In_ PCSTR Domain,
    _Out_writes_z_(BufferSize) PSTR NormalizedDomain,
    _In_ ULONG BufferSize
    );

// ============================================================================
// KNOWN SAFE IP RANGES (Major cloud providers, CDNs)
// ============================================================================

static const NR_KNOWN_SAFE_RANGE g_KnownSafeRanges[] = {
    //
    // Google DNS
    //
    { 0x08080808, 0x08080808, "Google DNS" },           // 8.8.8.8
    { 0x08080404, 0x08080404, "Google DNS" },           // 8.8.4.4

    //
    // Cloudflare DNS
    //
    { 0x01010101, 0x01010101, "Cloudflare DNS" },       // 1.1.1.1
    { 0x01000001, 0x01000001, "Cloudflare DNS" },       // 1.0.0.1

    //
    // Microsoft DNS
    //
    { 0x04020204, 0x04020204, "Microsoft DNS" },        // 4.2.2.4

    //
    // End marker
    //
    { 0, 0, NULL }
};

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the network reputation manager.
 *
 * @param Manager   Receives initialized manager handle.
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
NrInitialize(
    _Out_ PNR_MANAGER* Manager
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PNR_MANAGER manager = NULL;
    ULONG i;
    LARGE_INTEGER dueTime;

    PAGED_CODE();

    if (Manager == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Manager = NULL;

    //
    // Allocate manager structure
    //
    manager = (PNR_MANAGER)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(NR_MANAGER),
        NR_POOL_TAG_CACHE
    );

    if (manager == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize entry list and lock
    //
    InitializeListHead(&manager->EntryList);
    ExInitializePushLock(&manager->EntryLock);
    manager->EntryCount = 0;

    //
    // Allocate hash buckets
    //
    manager->Hash.BucketCount = NR_HASH_BUCKET_COUNT;
    manager->Hash.Buckets = (PLIST_ENTRY)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(LIST_ENTRY) * manager->Hash.BucketCount,
        NR_POOL_TAG_CACHE
    );

    if (manager->Hash.Buckets == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    //
    // Initialize hash buckets
    //
    for (i = 0; i < manager->Hash.BucketCount; i++) {
        InitializeListHead(&manager->Hash.Buckets[i]);
    }

    //
    // Initialize configuration
    //
    manager->Config.MaxEntries = NR_MAX_CACHE_ENTRIES;
    manager->Config.TTLSeconds = NR_CACHE_TTL_SECONDS;
    manager->Config.EnableExpirations = TRUE;

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&manager->Stats.StartTime);

    //
    // Initialize cleanup timer
    //
    KeInitializeTimer(&manager->CleanupTimer);
    KeInitializeDpc(&manager->CleanupDpc, NrpCleanupTimerDpc, manager);

    //
    // Start cleanup timer (periodic)
    //
    dueTime.QuadPart = -((LONGLONG)NR_CLEANUP_INTERVAL_MS * 10000);
    KeSetTimerEx(
        &manager->CleanupTimer,
        dueTime,
        NR_CLEANUP_INTERVAL_MS,
        &manager->CleanupDpc
    );

    manager->Initialized = TRUE;
    *Manager = manager;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Network reputation manager initialized (buckets=%u, maxEntries=%u)\n",
               manager->Hash.BucketCount,
               manager->Config.MaxEntries);

    return STATUS_SUCCESS;

Cleanup:
    if (manager != NULL) {
        if (manager->Hash.Buckets != NULL) {
            ExFreePoolWithTag(manager->Hash.Buckets, NR_POOL_TAG_CACHE);
        }
        ExFreePoolWithTag(manager, NR_POOL_TAG_CACHE);
    }

    return status;
}

/**
 * @brief Shutdown the network reputation manager.
 *
 * @param Manager   Manager to shutdown.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
NrShutdown(
    _Inout_ PNR_MANAGER Manager
    )
{
    PAGED_CODE();

    if (Manager == NULL) {
        return;
    }

    if (!Manager->Initialized) {
        return;
    }

    Manager->Initialized = FALSE;

    //
    // Cancel cleanup timer
    //
    KeCancelTimer(&Manager->CleanupTimer);

    //
    // Wait for any pending DPCs
    //
    KeFlushQueuedDpcs();

    //
    // Clear all entries
    //
    NrClearCache(Manager);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Network reputation manager shutdown (lookups=%lld, hits=%lld, misses=%lld)\n",
               Manager->Stats.Lookups,
               Manager->Stats.Hits,
               Manager->Stats.Misses);

    //
    // Free hash buckets
    //
    if (Manager->Hash.Buckets != NULL) {
        ExFreePoolWithTag(Manager->Hash.Buckets, NR_POOL_TAG_CACHE);
        Manager->Hash.Buckets = NULL;
    }

    //
    // Free manager
    //
    ExFreePoolWithTag(Manager, NR_POOL_TAG_CACHE);
}

// ============================================================================
// PUBLIC API - LOOKUP FUNCTIONS
// ============================================================================

/**
 * @brief Lookup IP address reputation.
 *
 * @param Manager   Reputation manager.
 * @param Address   IP address (IN_ADDR* or IN6_ADDR*).
 * @param IsIPv6    TRUE for IPv6, FALSE for IPv4.
 * @param Result    Receives lookup result.
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
NrLookupIP(
    _In_ PNR_MANAGER Manager,
    _In_ PVOID Address,
    _In_ BOOLEAN IsIPv6,
    _Out_ PNR_LOOKUP_RESULT Result
    )
{
    ULONG hash;
    PNR_ENTRY entry;

    if (Manager == NULL || Address == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Result, sizeof(NR_LOOKUP_RESULT));

    if (!Manager->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    InterlockedIncrement64(&Manager->Stats.Lookups);

    //
    // Check for private/loopback IPs (always safe)
    //
    if (!IsIPv6) {
        ULONG ipv4 = ((PIN_ADDR)Address)->S_un.S_addr;

        if (NrpIsLoopbackIP(ipv4)) {
            Result->Found = TRUE;
            Result->Reputation = NrReputation_Safe;
            Result->Score = 0;
            Result->FromCache = FALSE;
            InterlockedIncrement64(&Manager->Stats.Hits);
            return STATUS_SUCCESS;
        }

        if (NrpIsPrivateIP(ipv4)) {
            Result->Found = TRUE;
            Result->Reputation = NrReputation_Safe;
            Result->Score = 0;
            Result->FromCache = FALSE;
            InterlockedIncrement64(&Manager->Stats.Hits);
            return STATUS_SUCCESS;
        }

        //
        // Check known safe ranges
        //
        if (NrpIsKnownSafeIP(ipv4)) {
            Result->Found = TRUE;
            Result->Reputation = NrReputation_Safe;
            Result->Score = 0;
            Result->FromCache = FALSE;
            InterlockedIncrement64(&Manager->Stats.Hits);
            return STATUS_SUCCESS;
        }
    }

    //
    // Calculate hash
    //
    hash = NrpHashIP(Address, IsIPv6);

    //
    // Lookup in cache
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Manager->EntryLock);

    entry = NrpFindEntryByIP(Manager, Address, IsIPv6, hash);

    if (entry != NULL) {
        //
        // Check expiration
        //
        if (NrpIsEntryExpired(entry)) {
            ExReleasePushLockShared(&Manager->EntryLock);
            KeLeaveCriticalRegion();

            InterlockedIncrement64(&Manager->Stats.Misses);
            Result->Found = FALSE;
            return STATUS_SUCCESS;
        }

        //
        // Found valid entry
        //
        Result->Found = TRUE;
        Result->Reputation = entry->Reputation;
        Result->Categories = entry->Categories;
        Result->Score = entry->Score;
        Result->FromCache = TRUE;

        if (entry->ThreatName[0] != '\0') {
            RtlStringCchCopyA(Result->ThreatName,
                              sizeof(Result->ThreatName),
                              entry->ThreatName);
        }

        if (entry->MalwareFamily[0] != '\0') {
            RtlStringCchCopyA(Result->MalwareFamily,
                              sizeof(Result->MalwareFamily),
                              entry->MalwareFamily);
        }

        //
        // Update access time and hit count
        //
        KeQuerySystemTime(&entry->LastAccessTime);
        InterlockedIncrement(&entry->HitCount);
        InterlockedIncrement64(&Manager->Stats.Hits);

    } else {
        InterlockedIncrement64(&Manager->Stats.Misses);
        Result->Found = FALSE;
    }

    ExReleasePushLockShared(&Manager->EntryLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

/**
 * @brief Lookup domain reputation.
 *
 * @param Manager   Reputation manager.
 * @param Domain    Domain name to lookup.
 * @param Result    Receives lookup result.
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
NrLookupDomain(
    _In_ PNR_MANAGER Manager,
    _In_ PCSTR Domain,
    _Out_ PNR_LOOKUP_RESULT Result
    )
{
    ULONG hash;
    PNR_ENTRY entry;
    CHAR normalizedDomain[NR_MAX_DOMAIN_LENGTH + 1];
    ULONG dgaScore;

    if (Manager == NULL || Domain == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Result, sizeof(NR_LOOKUP_RESULT));

    if (!Manager->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (Domain[0] == '\0') {
        return STATUS_INVALID_PARAMETER;
    }

    InterlockedIncrement64(&Manager->Stats.Lookups);

    //
    // Normalize domain (lowercase, remove trailing dot)
    //
    NrpNormalizeDomain(Domain, normalizedDomain, sizeof(normalizedDomain));

    //
    // Calculate DGA score for suspicious domain detection
    //
    dgaScore = NrpCalculateDGAScore(normalizedDomain);

    //
    // Calculate hash
    //
    hash = NrpHashDomain(normalizedDomain);

    //
    // Lookup in cache
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Manager->EntryLock);

    entry = NrpFindEntryByDomain(Manager, normalizedDomain, hash);

    if (entry != NULL) {
        //
        // Check expiration
        //
        if (NrpIsEntryExpired(entry)) {
            ExReleasePushLockShared(&Manager->EntryLock);
            KeLeaveCriticalRegion();

            InterlockedIncrement64(&Manager->Stats.Misses);
            Result->Found = FALSE;

            //
            // Even if not in cache, flag high DGA score
            //
            if (dgaScore >= 70) {
                Result->Found = TRUE;
                Result->Reputation = NrReputation_Medium;
                Result->Categories = NrCategory_DGA;
                Result->Score = dgaScore;
                RtlStringCchCopyA(Result->ThreatName,
                                  sizeof(Result->ThreatName),
                                  "Suspicious DGA-like domain");
            }

            return STATUS_SUCCESS;
        }

        //
        // Found valid entry
        //
        Result->Found = TRUE;
        Result->Reputation = entry->Reputation;
        Result->Categories = entry->Categories;
        Result->Score = entry->Score;
        Result->FromCache = TRUE;

        if (entry->ThreatName[0] != '\0') {
            RtlStringCchCopyA(Result->ThreatName,
                              sizeof(Result->ThreatName),
                              entry->ThreatName);
        }

        if (entry->MalwareFamily[0] != '\0') {
            RtlStringCchCopyA(Result->MalwareFamily,
                              sizeof(Result->MalwareFamily),
                              entry->MalwareFamily);
        }

        //
        // Update access time and hit count
        //
        KeQuerySystemTime(&entry->LastAccessTime);
        InterlockedIncrement(&entry->HitCount);
        InterlockedIncrement64(&Manager->Stats.Hits);

    } else {
        InterlockedIncrement64(&Manager->Stats.Misses);
        Result->Found = FALSE;

        //
        // Even if not in cache, flag high DGA score
        //
        if (dgaScore >= 70) {
            Result->Found = TRUE;
            Result->Reputation = NrReputation_Medium;
            Result->Categories = NrCategory_DGA;
            Result->Score = dgaScore;
            RtlStringCchCopyA(Result->ThreatName,
                              sizeof(Result->ThreatName),
                              "Suspicious DGA-like domain");
        }
    }

    ExReleasePushLockShared(&Manager->EntryLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - CACHE MANAGEMENT
// ============================================================================

/**
 * @brief Add a reputation entry to the cache.
 */
NTSTATUS
NrAddEntry(
    _In_ PNR_MANAGER Manager,
    _In_ PNR_ENTRY Entry
    )
{
    PNR_ENTRY newEntry;

    if (Manager == NULL || Entry == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Manager->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Allocate new entry (copy)
    //
    newEntry = NrpAllocateEntry();
    if (newEntry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(newEntry, Entry, sizeof(NR_ENTRY));
    InitializeListHead(&newEntry->ListEntry);
    InitializeListHead(&newEntry->HashEntry);

    //
    // Set timestamps
    //
    KeQuerySystemTime(&newEntry->AddedTime);
    newEntry->LastAccessTime = newEntry->AddedTime;
    newEntry->ExpirationTime.QuadPart =
        newEntry->AddedTime.QuadPart + ((LONGLONG)Manager->Config.TTLSeconds * 10000000LL);
    newEntry->HitCount = 0;

    //
    // Check cache size and evict if necessary
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Manager->EntryLock);

    while ((ULONG)Manager->EntryCount >= Manager->Config.MaxEntries) {
        NrpEvictOldestEntry(Manager);
    }

    NrpInsertEntry(Manager, newEntry);

    ExReleasePushLockExclusive(&Manager->EntryLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

/**
 * @brief Add an IP address to the reputation cache.
 */
NTSTATUS
NrAddIP(
    _In_ PNR_MANAGER Manager,
    _In_ PVOID Address,
    _In_ BOOLEAN IsIPv6,
    _In_ NR_REPUTATION Reputation,
    _In_ NR_CATEGORY Categories,
    _In_ ULONG Score,
    _In_opt_ PCSTR ThreatName
    )
{
    NR_ENTRY entry;

    if (Manager == NULL || Address == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&entry, sizeof(NR_ENTRY));

    entry.Type = NrType_IP;
    entry.Value.IP.IsIPv6 = IsIPv6;

    if (IsIPv6) {
        RtlCopyMemory(&entry.Value.IP.Address6, Address, sizeof(IN6_ADDR));
    } else {
        RtlCopyMemory(&entry.Value.IP.Address, Address, sizeof(IN_ADDR));
    }

    entry.Hash = NrpHashIP(Address, IsIPv6);
    entry.Reputation = Reputation;
    entry.Categories = Categories;
    entry.Score = Score;

    if (ThreatName != NULL) {
        RtlStringCchCopyA(entry.ThreatName, sizeof(entry.ThreatName), ThreatName);
    }

    return NrAddEntry(Manager, &entry);
}

/**
 * @brief Add a domain to the reputation cache.
 */
NTSTATUS
NrAddDomain(
    _In_ PNR_MANAGER Manager,
    _In_ PCSTR Domain,
    _In_ NR_REPUTATION Reputation,
    _In_ NR_CATEGORY Categories,
    _In_ ULONG Score,
    _In_opt_ PCSTR ThreatName
    )
{
    NR_ENTRY entry;
    CHAR normalizedDomain[NR_MAX_DOMAIN_LENGTH + 1];

    if (Manager == NULL || Domain == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Domain[0] == '\0') {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&entry, sizeof(NR_ENTRY));

    //
    // Normalize domain
    //
    NrpNormalizeDomain(Domain, normalizedDomain, sizeof(normalizedDomain));

    entry.Type = NrType_Domain;
    RtlStringCchCopyA(entry.Value.Domain, sizeof(entry.Value.Domain), normalizedDomain);

    entry.Hash = NrpHashDomain(normalizedDomain);
    entry.Reputation = Reputation;
    entry.Categories = Categories;
    entry.Score = Score;

    if (ThreatName != NULL) {
        RtlStringCchCopyA(entry.ThreatName, sizeof(entry.ThreatName), ThreatName);
    }

    return NrAddEntry(Manager, &entry);
}

/**
 * @brief Remove an IP address from the cache.
 */
NTSTATUS
NrRemoveIP(
    _In_ PNR_MANAGER Manager,
    _In_ PVOID Address,
    _In_ BOOLEAN IsIPv6
    )
{
    ULONG hash;
    PNR_ENTRY entry;

    if (Manager == NULL || Address == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Manager->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    hash = NrpHashIP(Address, IsIPv6);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Manager->EntryLock);

    entry = NrpFindEntryByIP(Manager, Address, IsIPv6, hash);

    if (entry != NULL) {
        NrpRemoveEntry(Manager, entry);
        NrpFreeEntry(entry);
    }

    ExReleasePushLockExclusive(&Manager->EntryLock);
    KeLeaveCriticalRegion();

    return (entry != NULL) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

/**
 * @brief Remove a domain from the cache.
 */
NTSTATUS
NrRemoveDomain(
    _In_ PNR_MANAGER Manager,
    _In_ PCSTR Domain
    )
{
    ULONG hash;
    PNR_ENTRY entry;
    CHAR normalizedDomain[NR_MAX_DOMAIN_LENGTH + 1];

    if (Manager == NULL || Domain == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Manager->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    NrpNormalizeDomain(Domain, normalizedDomain, sizeof(normalizedDomain));
    hash = NrpHashDomain(normalizedDomain);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Manager->EntryLock);

    entry = NrpFindEntryByDomain(Manager, normalizedDomain, hash);

    if (entry != NULL) {
        NrpRemoveEntry(Manager, entry);
        NrpFreeEntry(entry);
    }

    ExReleasePushLockExclusive(&Manager->EntryLock);
    KeLeaveCriticalRegion();

    return (entry != NULL) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

/**
 * @brief Clear all entries from the cache.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
NrClearCache(
    _In_ PNR_MANAGER Manager
    )
{
    PLIST_ENTRY listEntry;
    PNR_ENTRY entry;
    LIST_ENTRY tempList;

    PAGED_CODE();

    if (Manager == NULL || !Manager->Initialized) {
        return;
    }

    InitializeListHead(&tempList);

    //
    // Move all entries to temp list under lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Manager->EntryLock);

    while (!IsListEmpty(&Manager->EntryList)) {
        listEntry = RemoveHeadList(&Manager->EntryList);
        entry = CONTAINING_RECORD(listEntry, NR_ENTRY, ListEntry);

        //
        // Remove from hash bucket
        //
        RemoveEntryList(&entry->HashEntry);

        InsertTailList(&tempList, &entry->ListEntry);
    }

    Manager->EntryCount = 0;

    ExReleasePushLockExclusive(&Manager->EntryLock);
    KeLeaveCriticalRegion();

    //
    // Free entries outside lock
    //
    while (!IsListEmpty(&tempList)) {
        listEntry = RemoveHeadList(&tempList);
        entry = CONTAINING_RECORD(listEntry, NR_ENTRY, ListEntry);
        NrpFreeEntry(entry);
    }
}

/**
 * @brief Load reputation data from file.
 *
 * File format (text, one entry per line):
 * IP,Reputation,Score,Categories,ThreatName
 * or
 * DOMAIN,Reputation,Score,Categories,ThreatName
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
NrLoadFromFile(
    _In_ PNR_MANAGER Manager,
    _In_ PUNICODE_STRING FilePath
    )
{
    PAGED_CODE();

    //
    // File loading would be implemented via ZwCreateFile/ZwReadFile
    // For now, return not implemented as this is typically done
    // by user-mode service pushing data via IOCTL
    //
    UNREFERENCED_PARAMETER(Manager);
    UNREFERENCED_PARAMETER(FilePath);

    return STATUS_NOT_IMPLEMENTED;
}

/**
 * @brief Get reputation manager statistics.
 */
NTSTATUS
NrGetStatistics(
    _In_ PNR_MANAGER Manager,
    _Out_ PNR_STATISTICS Stats
    )
{
    LARGE_INTEGER currentTime;

    if (Manager == NULL || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Stats, sizeof(NR_STATISTICS));

    if (!Manager->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    Stats->CacheEntries = (ULONG)Manager->EntryCount;
    Stats->Lookups = Manager->Stats.Lookups;
    Stats->CacheHits = Manager->Stats.Hits;
    Stats->CacheMisses = Manager->Stats.Misses;

    if (Stats->Lookups > 0) {
        Stats->HitRatePercent = (ULONG)((Stats->CacheHits * 100) / Stats->Lookups);
    }

    KeQuerySystemTime(&currentTime);
    Stats->UpTime.QuadPart = currentTime.QuadPart - Manager->Stats.StartTime.QuadPart;

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - HASHING
// ============================================================================

/**
 * @brief Calculate FNV-1a hash for IP address.
 */
static ULONG
NrpHashIP(
    _In_ PVOID Address,
    _In_ BOOLEAN IsIPv6
    )
{
    ULONG hash = NR_FNV_OFFSET_BASIS;
    PCUCHAR bytes;
    ULONG length;
    ULONG i;

    if (IsIPv6) {
        bytes = (PCUCHAR)Address;
        length = sizeof(IN6_ADDR);
    } else {
        bytes = (PCUCHAR)Address;
        length = sizeof(IN_ADDR);
    }

    for (i = 0; i < length; i++) {
        hash ^= bytes[i];
        hash *= NR_FNV_PRIME;
    }

    return hash;
}

/**
 * @brief Calculate FNV-1a hash for domain name.
 */
static ULONG
NrpHashDomain(
    _In_ PCSTR Domain
    )
{
    ULONG hash = NR_FNV_OFFSET_BASIS;
    PCSTR ptr = Domain;

    while (*ptr != '\0') {
        //
        // Case-insensitive hash
        //
        CHAR ch = *ptr;
        if (ch >= 'A' && ch <= 'Z') {
            ch = ch - 'A' + 'a';
        }

        hash ^= (UCHAR)ch;
        hash *= NR_FNV_PRIME;
        ptr++;
    }

    return hash;
}

/**
 * @brief Convert hash to bucket index.
 */
static ULONG
NrpHashToIndex(
    _In_ PNR_MANAGER Manager,
    _In_ ULONG Hash
    )
{
    return Hash % Manager->Hash.BucketCount;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - ENTRY MANAGEMENT
// ============================================================================

static PNR_ENTRY
NrpFindEntryByIP(
    _In_ PNR_MANAGER Manager,
    _In_ PVOID Address,
    _In_ BOOLEAN IsIPv6,
    _In_ ULONG Hash
    )
{
    ULONG index = NrpHashToIndex(Manager, Hash);
    PLIST_ENTRY bucket = &Manager->Hash.Buckets[index];
    PLIST_ENTRY listEntry;
    PNR_ENTRY entry;

    for (listEntry = bucket->Flink;
         listEntry != bucket;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, NR_ENTRY, HashEntry);

        if (entry->Type != NrType_IP) {
            continue;
        }

        if (entry->Hash != Hash) {
            continue;
        }

        if (entry->Value.IP.IsIPv6 != IsIPv6) {
            continue;
        }

        if (IsIPv6) {
            if (RtlCompareMemory(&entry->Value.IP.Address6, Address, sizeof(IN6_ADDR)) == sizeof(IN6_ADDR)) {
                return entry;
            }
        } else {
            if (RtlCompareMemory(&entry->Value.IP.Address, Address, sizeof(IN_ADDR)) == sizeof(IN_ADDR)) {
                return entry;
            }
        }
    }

    return NULL;
}

static PNR_ENTRY
NrpFindEntryByDomain(
    _In_ PNR_MANAGER Manager,
    _In_ PCSTR Domain,
    _In_ ULONG Hash
    )
{
    ULONG index = NrpHashToIndex(Manager, Hash);
    PLIST_ENTRY bucket = &Manager->Hash.Buckets[index];
    PLIST_ENTRY listEntry;
    PNR_ENTRY entry;

    for (listEntry = bucket->Flink;
         listEntry != bucket;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, NR_ENTRY, HashEntry);

        if (entry->Type != NrType_Domain) {
            continue;
        }

        if (entry->Hash != Hash) {
            continue;
        }

        if (_stricmp(entry->Value.Domain, Domain) == 0) {
            return entry;
        }
    }

    return NULL;
}

static PNR_ENTRY
NrpAllocateEntry(
    VOID
    )
{
    PNR_ENTRY entry;

    entry = (PNR_ENTRY)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(NR_ENTRY),
        NR_POOL_TAG_ENTRY
    );

    if (entry != NULL) {
        InitializeListHead(&entry->ListEntry);
        InitializeListHead(&entry->HashEntry);
    }

    return entry;
}

static VOID
NrpFreeEntry(
    _In_ PNR_ENTRY Entry
    )
{
    if (Entry != NULL) {
        ExFreePoolWithTag(Entry, NR_POOL_TAG_ENTRY);
    }
}

static VOID
NrpInsertEntry(
    _In_ PNR_MANAGER Manager,
    _In_ PNR_ENTRY Entry
    )
{
    ULONG index = NrpHashToIndex(Manager, Entry->Hash);

    //
    // Insert at head of entry list (MRU)
    //
    InsertHeadList(&Manager->EntryList, &Entry->ListEntry);

    //
    // Insert into hash bucket
    //
    InsertHeadList(&Manager->Hash.Buckets[index], &Entry->HashEntry);

    InterlockedIncrement(&Manager->EntryCount);
}

static VOID
NrpRemoveEntry(
    _In_ PNR_MANAGER Manager,
    _In_ PNR_ENTRY Entry
    )
{
    //
    // Remove from entry list
    //
    RemoveEntryList(&Entry->ListEntry);

    //
    // Remove from hash bucket
    //
    RemoveEntryList(&Entry->HashEntry);

    InterlockedDecrement(&Manager->EntryCount);
}

static BOOLEAN
NrpIsEntryExpired(
    _In_ PNR_ENTRY Entry
    )
{
    LARGE_INTEGER currentTime;

    //
    // Whitelisted/blacklisted entries never expire
    //
    if (Entry->Reputation == NrReputation_Whitelisted ||
        Entry->Reputation == NrReputation_Blacklisted) {
        return FALSE;
    }

    if (Entry->ExpirationTime.QuadPart == 0) {
        return FALSE;
    }

    KeQuerySystemTime(&currentTime);

    return (currentTime.QuadPart > Entry->ExpirationTime.QuadPart);
}

static VOID
NrpEvictOldestEntry(
    _In_ PNR_MANAGER Manager
    )
{
    PLIST_ENTRY listEntry;
    PNR_ENTRY entry;
    PNR_ENTRY oldestEntry = NULL;
    LARGE_INTEGER oldestTime = { 0 };

    oldestTime.QuadPart = MAXLONGLONG;

    //
    // Find oldest non-permanent entry
    //
    for (listEntry = Manager->EntryList.Flink;
         listEntry != &Manager->EntryList;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, NR_ENTRY, ListEntry);

        //
        // Skip permanent entries
        //
        if (entry->Reputation == NrReputation_Whitelisted ||
            entry->Reputation == NrReputation_Blacklisted) {
            continue;
        }

        if (entry->LastAccessTime.QuadPart < oldestTime.QuadPart) {
            oldestTime = entry->LastAccessTime;
            oldestEntry = entry;
        }
    }

    if (oldestEntry != NULL) {
        NrpRemoveEntry(Manager, oldestEntry);
        NrpFreeEntry(oldestEntry);
    }
}

static VOID
NrpCleanupExpiredEntries(
    _In_ PNR_MANAGER Manager,
    _In_ ULONG MaxToClean
    )
{
    PLIST_ENTRY listEntry;
    PLIST_ENTRY nextEntry;
    PNR_ENTRY entry;
    LIST_ENTRY expiredList;
    ULONG cleanedCount = 0;

    InitializeListHead(&expiredList);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Manager->EntryLock);

    for (listEntry = Manager->EntryList.Flink;
         listEntry != &Manager->EntryList && cleanedCount < MaxToClean;
         listEntry = nextEntry) {

        nextEntry = listEntry->Flink;
        entry = CONTAINING_RECORD(listEntry, NR_ENTRY, ListEntry);

        if (NrpIsEntryExpired(entry)) {
            NrpRemoveEntry(Manager, entry);
            InsertTailList(&expiredList, &entry->ListEntry);
            cleanedCount++;
        }
    }

    ExReleasePushLockExclusive(&Manager->EntryLock);
    KeLeaveCriticalRegion();

    //
    // Free expired entries outside lock
    //
    while (!IsListEmpty(&expiredList)) {
        listEntry = RemoveHeadList(&expiredList);
        entry = CONTAINING_RECORD(listEntry, NR_ENTRY, ListEntry);
        NrpFreeEntry(entry);
    }
}

// ============================================================================
// PRIVATE IMPLEMENTATION - TIMER DPC
// ============================================================================

static VOID
NrpCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PNR_MANAGER manager = (PNR_MANAGER)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (manager == NULL || !manager->Initialized) {
        return;
    }

    if (!manager->Config.EnableExpirations) {
        return;
    }

    //
    // Clean up expired entries
    //
    NrpCleanupExpiredEntries(manager, NR_MAX_CLEANUP_PER_TICK);
}

// ============================================================================
// PRIVATE IMPLEMENTATION - IP HELPERS
// ============================================================================

static BOOLEAN
NrpIsKnownSafeIP(
    _In_ ULONG IPv4Address
    )
{
    ULONG i;

    for (i = 0; g_KnownSafeRanges[i].Description != NULL; i++) {
        if (IPv4Address >= g_KnownSafeRanges[i].StartIP &&
            IPv4Address <= g_KnownSafeRanges[i].EndIP) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
NrpIsPrivateIP(
    _In_ ULONG IPv4Address
    )
{
    UCHAR firstOctet = (UCHAR)(IPv4Address & 0xFF);
    UCHAR secondOctet = (UCHAR)((IPv4Address >> 8) & 0xFF);

    //
    // 10.0.0.0/8
    //
    if (firstOctet == 10) {
        return TRUE;
    }

    //
    // 172.16.0.0/12
    //
    if (firstOctet == 172 && (secondOctet >= 16 && secondOctet <= 31)) {
        return TRUE;
    }

    //
    // 192.168.0.0/16
    //
    if (firstOctet == 192 && secondOctet == 168) {
        return TRUE;
    }

    //
    // 169.254.0.0/16 (link-local)
    //
    if (firstOctet == 169 && secondOctet == 254) {
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN
NrpIsLoopbackIP(
    _In_ ULONG IPv4Address
    )
{
    UCHAR firstOctet = (UCHAR)(IPv4Address & 0xFF);

    //
    // 127.0.0.0/8
    //
    return (firstOctet == 127);
}

// ============================================================================
// PRIVATE IMPLEMENTATION - DOMAIN HELPERS
// ============================================================================

static ULONG
NrpCalculateDGAScore(
    _In_ PCSTR Domain
    )
{
    ULONG score = 0;
    ULONG length = 0;
    ULONG consonantRun = 0;
    ULONG vowelRun = 0;
    ULONG digitCount = 0;
    ULONG hyphenCount = 0;
    ULONG uniqueChars = 0;
    ULONG charCounts[256] = { 0 };
    PCSTR ptr = Domain;
    PCSTR dotPos = NULL;
    ULONG i;

    if (Domain == NULL || Domain[0] == '\0') {
        return 0;
    }

    //
    // Find first dot (to get base domain)
    //
    dotPos = strchr(Domain, '.');
    if (dotPos == NULL) {
        dotPos = Domain + strlen(Domain);
    }

    length = (ULONG)(dotPos - Domain);

    //
    // Analyze characters
    //
    for (ptr = Domain; ptr < dotPos; ptr++) {
        CHAR ch = *ptr;

        if (ch >= 'A' && ch <= 'Z') {
            ch = ch - 'A' + 'a';
        }

        charCounts[(UCHAR)ch]++;

        if (ch >= '0' && ch <= '9') {
            digitCount++;
            consonantRun = 0;
            vowelRun = 0;
        } else if (ch == '-') {
            hyphenCount++;
            consonantRun = 0;
            vowelRun = 0;
        } else if (ch == 'a' || ch == 'e' || ch == 'i' || ch == 'o' || ch == 'u') {
            vowelRun++;
            consonantRun = 0;

            if (vowelRun > 3) {
                score += 10;  // Unusual vowel run
            }
        } else if (ch >= 'a' && ch <= 'z') {
            consonantRun++;
            vowelRun = 0;

            if (consonantRun > 4) {
                score += 15;  // Long consonant run (DGA indicator)
            }
        }
    }

    //
    // Count unique characters
    //
    for (i = 0; i < 256; i++) {
        if (charCounts[i] > 0) {
            uniqueChars++;
        }
    }

    //
    // High digit ratio is suspicious
    //
    if (length > 0) {
        ULONG digitRatio = (digitCount * 100) / length;
        if (digitRatio > 30) {
            score += 25;
        } else if (digitRatio > 20) {
            score += 15;
        }
    }

    //
    // Very long domains are suspicious
    //
    if (length > 20) {
        score += 10;
    }
    if (length > 30) {
        score += 15;
    }

    //
    // Many hyphens are suspicious
    //
    if (hyphenCount > 2) {
        score += 10;
    }

    //
    // Low character diversity is suspicious (repeated patterns)
    //
    if (length > 8 && uniqueChars < length / 2) {
        score += 15;
    }

    //
    // High entropy (many unique chars) for short domain is suspicious
    //
    if (length > 0 && length <= 12 && uniqueChars > (length * 3) / 4) {
        score += 10;
    }

    //
    // Cap score at 100
    //
    if (score > 100) {
        score = 100;
    }

    return score;
}

static VOID
NrpNormalizeDomain(
    _In_ PCSTR Domain,
    _Out_writes_z_(BufferSize) PSTR NormalizedDomain,
    _In_ ULONG BufferSize
    )
{
    ULONG i;
    ULONG len;

    if (BufferSize == 0) {
        return;
    }

    NormalizedDomain[0] = '\0';

    if (Domain == NULL || Domain[0] == '\0') {
        return;
    }

    //
    // Copy and lowercase
    //
    len = (ULONG)strlen(Domain);
    if (len >= BufferSize) {
        len = BufferSize - 1;
    }

    for (i = 0; i < len; i++) {
        CHAR ch = Domain[i];
        if (ch >= 'A' && ch <= 'Z') {
            ch = ch - 'A' + 'a';
        }
        NormalizedDomain[i] = ch;
    }

    NormalizedDomain[len] = '\0';

    //
    // Remove trailing dot if present
    //
    if (len > 0 && NormalizedDomain[len - 1] == '.') {
        NormalizedDomain[len - 1] = '\0';
    }
}
