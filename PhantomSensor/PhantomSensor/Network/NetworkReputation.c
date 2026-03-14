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
 * ShadowStrike NGAV - ENTERPRISE NETWORK REPUTATION ENGINE
 * ============================================================================
 *
 * @file NetworkReputation.c
 * @brief Enterprise-grade IP and domain reputation lookup with caching.
 *
 * Architecture:
 * - EX_RUNDOWN_REF protects manager lifetime (all operations acquire it).
 * - EX_PUSH_LOCK (shared/exclusive) guards cache data structures.
 * - Periodic cleanup runs at PASSIVE_LEVEL via TimerManager (WorkItemCallback).
 * - Entries allocated from PagedPool (only accessed at <= APC_LEVEL).
 * - Duplicate entries detected and updated in-place on re-add.
 * - Private/loopback IPs return NrReputation_Unknown with NR_FLAG_INTERNAL,
 *   allowing callers to apply their own policy without blind-spot.
 * - DGA scoring enhanced with bigram frequency analysis.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition - Hardened)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#pragma warning(push)
#pragma warning(disable: 4324) // structure was padded due to alignment (fltKernel.h)
#include "NetworkReputation.h"
#pragma warning(pop)

#include <ntstrsafe.h>
#include "../../Sync/TimerManager.h"
#include "../../Core/DriverEntry.h"
#include "../../Behavioral/BehaviorEngine.h"

//
// Forward declarations needed before alloc_text (defined later in file)
//
static NTSTATUS
NrpAddEntryInternal(
    _In_ PNR_MANAGER Manager,
    _In_ PNR_ENTRY TemplateEntry
    );

static BOOLEAN
NrpIsPrivateIPv6(
    _In_reads_bytes_(sizeof(IN6_ADDR)) const UCHAR* IPv6Bytes
    );

static BOOLEAN
NrpIsLoopbackIPv6(
    _In_reads_bytes_(sizeof(IN6_ADDR)) const UCHAR* IPv6Bytes
    );

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define NR_HASH_BUCKET_COUNT            4096
#define NR_CLEANUP_INTERVAL_MS          60000
#define NR_MAX_CLEANUP_PER_TICK         256

// FNV-1a hash constants
#define NR_FNV_OFFSET_BASIS             2166136261UL
#define NR_FNV_PRIME                    16777619UL

// ============================================================================
// PRIVATE FUNCTION PROTOTYPES
// ============================================================================

static ULONG
NrpHashIP(
    _In_reads_bytes_(IsIPv6 ? sizeof(IN6_ADDR) : sizeof(IN_ADDR)) const VOID* Address,
    _In_ BOOLEAN IsIPv6
    );

static ULONG
NrpHashDomain(
    _In_z_ PCSTR Domain,
    _In_ ULONG MaxLength
    );

static ULONG
NrpHashToIndex(
    _In_ PNR_MANAGER Manager,
    _In_ ULONG Hash
    );

static PNR_ENTRY
NrpFindEntryByIP(
    _In_ PNR_MANAGER Manager,
    _In_reads_bytes_(IsIPv6 ? sizeof(IN6_ADDR) : sizeof(IN_ADDR)) const VOID* Address,
    _In_ BOOLEAN IsIPv6,
    _In_ ULONG Hash
    );

static PNR_ENTRY
NrpFindEntryByDomain(
    _In_ PNR_MANAGER Manager,
    _In_z_ PCSTR Domain,
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

static VOID
NrpUpdateEntryInPlace(
    _Inout_ PNR_ENTRY Existing,
    _In_ PNR_ENTRY Source,
    _In_ ULONG TTLSeconds
    );

static BOOLEAN
NrpIsEntryExpired(
    _In_ PNR_ENTRY Entry
    );

static BOOLEAN
NrpEvictOldestEntry(
    _In_ PNR_MANAGER Manager
    );

static VOID
NrpCleanupExpiredEntries(
    _In_ PNR_MANAGER Manager,
    _In_ ULONG MaxToClean
    );

static VOID
NrpCleanupTimerCallback(
    _In_ ULONG TimerId,
    _In_opt_ PVOID Context
    );

static BOOLEAN
NrpIsPrivateIP(
    _In_reads_bytes_(sizeof(ULONG)) const UCHAR* IPv4Bytes
    );

static BOOLEAN
NrpIsLoopbackIP(
    _In_reads_bytes_(sizeof(ULONG)) const UCHAR* IPv4Bytes
    );

static ULONG
NrpCalculateDGAScore(
    _In_z_ PCSTR Domain,
    _In_ ULONG MaxLength
    );

static VOID
NrpNormalizeDomain(
    _In_z_ PCSTR Domain,
    _In_ ULONG DomainMaxLength,
    _Out_writes_z_(BufferSize) PSTR NormalizedDomain,
    _In_ ULONG BufferSize
    );

static int
NrpSafeCompareStringOrdinalA(
    _In_z_ PCSTR String1,
    _In_z_ PCSTR String2,
    _In_ ULONG MaxLength
    );

static PCSTR
NrpSafeFindCharA(
    _In_z_ PCSTR String,
    _In_ CHAR Ch,
    _In_ ULONG MaxLength
    );

static NTSTATUS
NrpSafeStringLengthA(
    _In_z_ PCSTR String,
    _In_ ULONG MaxLength,
    _Out_ ULONG* Length
    );

#ifdef ALLOC_PRAGMA
// Public API
#pragma alloc_text(PAGE, NrInitialize)
#pragma alloc_text(PAGE, NrShutdown)
#pragma alloc_text(PAGE, NrClearCache)
#pragma alloc_text(PAGE, NrLookupIP)
#pragma alloc_text(PAGE, NrLookupDomain)
#pragma alloc_text(PAGE, NrAddIP)
#pragma alloc_text(PAGE, NrAddDomain)
#pragma alloc_text(PAGE, NrRemoveIP)
#pragma alloc_text(PAGE, NrRemoveDomain)
#pragma alloc_text(PAGE, NrGetStatistics)
// Private - entry management
#pragma alloc_text(PAGE, NrpAddEntryInternal)
#pragma alloc_text(PAGE, NrpFindEntryByIP)
#pragma alloc_text(PAGE, NrpFindEntryByDomain)
#pragma alloc_text(PAGE, NrpAllocateEntry)
#pragma alloc_text(PAGE, NrpFreeEntry)
#pragma alloc_text(PAGE, NrpInsertEntry)
#pragma alloc_text(PAGE, NrpRemoveEntry)
#pragma alloc_text(PAGE, NrpUpdateEntryInPlace)
#pragma alloc_text(PAGE, NrpIsEntryExpired)
#pragma alloc_text(PAGE, NrpEvictOldestEntry)
#pragma alloc_text(PAGE, NrpCleanupExpiredEntries)
#pragma alloc_text(PAGE, NrpCleanupTimerCallback)
// Private - hashing
#pragma alloc_text(PAGE, NrpHashIP)
#pragma alloc_text(PAGE, NrpHashDomain)
#pragma alloc_text(PAGE, NrpHashToIndex)
// Private - string helpers
#pragma alloc_text(PAGE, NrpSafeStringLengthA)
#pragma alloc_text(PAGE, NrpSafeCompareStringOrdinalA)
#pragma alloc_text(PAGE, NrpSafeFindCharA)
// Private - IP helpers
#pragma alloc_text(PAGE, NrpIsPrivateIP)
#pragma alloc_text(PAGE, NrpIsLoopbackIP)
#pragma alloc_text(PAGE, NrpIsPrivateIPv6)
#pragma alloc_text(PAGE, NrpIsLoopbackIPv6)
// Private - domain helpers
#pragma alloc_text(PAGE, NrpCalculateDGAScore)
#pragma alloc_text(PAGE, NrpNormalizeDomain)
#endif

// ============================================================================
// PRIVATE - BIGRAM FREQUENCY TABLE FOR DGA DETECTION
// ============================================================================

//
// Pre-computed English bigram frequencies (0-255 scaled).
// A value of 0 means the bigram never/rarely appears in English.
// High values mean common bigrams. This detects non-English random strings.
//
static const UCHAR g_BigramFrequency[26][26] = {
    // a  b  c  d  e  f  g  h  i  j  k  l  m  n  o  p  q  r  s  t  u  v  w  x  y  z
    {  2, 8, 8, 8,  2, 4, 6, 2, 6, 1, 4,16,10,24, 2, 6, 1,20,16,20, 4, 4, 4, 1, 6, 1 }, // a_
    {  6, 2, 1, 1, 8, 1, 1, 1, 4, 1, 1, 6, 1, 1, 6, 1, 1, 4, 4, 1, 6, 1, 1, 1, 4, 1 }, // b_
    {  8, 1, 2, 1, 8, 1, 1, 6, 6, 1, 6, 4, 1, 1,10, 1, 1, 4, 2, 6, 4, 1, 1, 1, 2, 1 }, // c_
    {  6, 2, 1, 2, 8, 2, 2, 2, 8, 1, 1, 2, 2, 2, 6, 1, 1, 4, 6, 2, 4, 1, 2, 1, 4, 1 }, // d_
    {  8, 4, 6, 8, 6, 4, 4, 2,10, 1, 2, 8, 6,16, 6, 6, 1,20,16,12, 2, 4, 4, 4, 4, 1 }, // e_
    {  6, 1, 1, 1, 6, 4, 1, 1, 6, 1, 1, 4, 1, 1, 8, 1, 1, 6, 2, 6, 4, 1, 1, 1, 2, 1 }, // f_
    {  6, 1, 1, 1, 6, 1, 2, 4, 6, 1, 1, 4, 2, 4, 6, 1, 1, 6, 4, 4, 4, 1, 2, 1, 2, 1 }, // g_
    {  8, 1, 1, 1,16, 1, 1, 1, 8, 1, 1, 2, 2, 2, 8, 1, 1, 4, 4, 6, 4, 1, 2, 1, 2, 1 }, // h_
    {  6, 4, 8, 6, 6, 4, 6, 1, 1, 1, 4, 8, 6,20, 8, 4, 1, 8,16,16, 2, 6, 1, 1, 1, 4 }, // i_
    {  4, 1, 1, 1, 4, 1, 1, 1, 2, 1, 1, 1, 1, 1, 4, 1, 1, 1, 1, 1, 6, 1, 1, 1, 1, 1 }, // j_
    {  4, 1, 1, 1, 8, 2, 1, 2, 6, 1, 1, 2, 2, 4, 2, 1, 1, 2, 4, 2, 2, 1, 2, 1, 2, 1 }, // k_
    {  8, 2, 2, 6, 10, 4, 2, 2, 8, 1, 2, 8, 4, 2, 8, 2, 1, 2, 6, 6, 6, 2, 2, 1, 8, 1 }, // l_
    {  8, 4, 1, 1, 8, 1, 1, 1, 6, 1, 1, 1, 4, 2, 8, 4, 1, 2, 4, 2, 4, 1, 1, 1, 4, 1 }, // m_
    {  8, 2, 6, 8,12, 4, 10,4, 8, 1, 4, 4, 2, 4, 8, 2, 1, 2,10,16, 4, 2, 2, 1, 4, 1 }, // n_
    {  2, 4, 4, 6, 4, 10, 4, 2, 4, 1, 4, 8, 8,20, 6, 6, 1,14, 8, 8,12, 4, 6, 1, 2, 2 }, // o_
    {  6, 1, 1, 1, 8, 1, 1, 4, 6, 1, 1, 6, 2, 1, 6, 4, 1, 8, 4, 6, 4, 1, 1, 1, 2, 1 }, // p_
    {  2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 6, 1, 1, 1, 1, 1 }, // q_
    {  8, 2, 4, 4,16, 2, 4, 2,10, 1, 4, 4, 4, 6, 8, 4, 1, 4,10, 8, 4, 2, 2, 1, 6, 1 }, // r_
    {  6, 2, 6, 2,10, 4, 2,10, 8, 1, 4, 4, 4, 4, 8, 6, 2, 2,10,16, 6, 1, 4, 1, 4, 1 }, // s_
    {  8, 2, 4, 2,10, 2, 2,16,12, 1, 1, 6, 4, 2,10, 2, 1, 8, 8, 6, 6, 1, 6, 1, 6, 1 }, // t_
    {  4, 4, 6, 4, 4, 2, 6, 1, 4, 1, 2, 8, 6,12, 2, 6, 1,12, 10, 10, 1, 1, 1, 1, 2, 2 }, // u_
    {  6, 1, 1, 1, 10, 1, 1, 1, 8, 1, 1, 1, 1, 1, 4, 1, 1, 2, 2, 1, 2, 1, 1, 1, 2, 1 }, // v_
    {  6, 1, 1, 2, 6, 1, 1, 6, 8, 1, 1, 2, 1, 6, 6, 1, 1, 2, 4, 2, 1, 1, 2, 1, 1, 1 }, // w_
    {  4, 1, 4, 1, 4, 1, 1, 2, 6, 1, 1, 1, 1, 1, 2, 6, 1, 1, 1, 6, 2, 1, 1, 1, 2, 1 }, // x_
    {  4, 2, 4, 2, 6, 2, 2, 2, 4, 1, 1, 4, 4, 2, 6, 4, 1, 2, 8, 4, 1, 1, 4, 1, 1, 1 }, // y_
    {  6, 1, 1, 1, 6, 1, 1, 1, 4, 1, 1, 2, 1, 1, 4, 1, 1, 1, 1, 1, 2, 1, 1, 1, 2, 4 }, // z_
};

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

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
    PTM_MANAGER timerManager = NULL;
    TM_TIMER_OPTIONS opts = {0};

    PAGED_CODE();

    if (Manager == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Manager = NULL;

    //
    // Allocate manager structure from NonPagedPool (contains
    // EX_RUNDOWN_REF which must be non-paged).
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
    // Initialize rundown protection. All public operations acquire this
    // before touching state. Shutdown waits for it to drain.
    //
    ExInitializeRundownProtection(&manager->RundownRef);

    //
    // Initialize entry list and lock
    //
    InitializeListHead(&manager->EntryList);
    ExInitializePushLock(&manager->EntryLock);
    manager->EntryCount = 0;

    //
    // Allocate hash buckets (NonPagedPool - accessed at DPC level indirectly
    // through the work item, but keeping NonPaged for list heads is safe)
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

    for (i = 0; i < manager->Hash.BucketCount; i++) {
        InitializeListHead(&manager->Hash.Buckets[i]);
    }

    //
    // Configuration
    //
    manager->Config.MaxEntries = NR_MAX_CACHE_ENTRIES;
    manager->Config.TTLSeconds = NR_CACHE_TTL_SECONDS;
    manager->Config.EnableExpirations = TRUE;

    //
    // Statistics
    //
    KeQuerySystemTime(&manager->Stats.StartTime);

    //
    // Create periodic cleanup timer via centralized TimerManager.
    // TmFlag_WorkItemCallback ensures the callback runs at PASSIVE_LEVEL.
    //
    manager->CleanupInProgress = 0;

    timerManager = ShadowStrikeGetTimerManager();
    if (timerManager == NULL) {
        status = STATUS_DEVICE_NOT_READY;
        goto Cleanup;
    }

    opts.Flags = TmFlag_WorkItemCallback | TmFlag_Coalescable;
    opts.Name = "NrCleanup";

    status = TmCreatePeriodic(
        timerManager,
        NR_CLEANUP_INTERVAL_MS,
        NrpCleanupTimerCallback,
        manager,
        &opts,
        &manager->CleanupTimerId
    );
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    *Manager = manager;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Network reputation manager initialized "
               "(buckets=%u, maxEntries=%u)\n",
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

// ============================================================================
// PUBLIC API - SHUTDOWN
// ============================================================================

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

    //
    // 1. Cancel the periodic cleanup timer. TmCancel with Wait=TRUE
    //    blocks until any in-flight callback completes, replacing the
    //    old KeCancelTimer + KeFlushQueuedDpcs + spin-wait pattern.
    //
    {
        PTM_MANAGER tmMgr = ShadowStrikeGetTimerManager();
        if (tmMgr != NULL && Manager->CleanupTimerId != 0) {
            TmCancel(tmMgr, Manager->CleanupTimerId, TRUE);
        }
    }

    //
    // 2. Wait for rundown: blocks until every thread that called
    //    ExAcquireRundownProtection has released it. After this returns
    //    no new acquisitions will succeed.
    //
    ExWaitForRundownProtectionRelease(&Manager->RundownRef);

    //
    // 3. Now we are the sole owner. Clear the cache (no lock needed
    //    since rundown is complete, but we still take it for correctness
    //    because NrpClearCacheInternal expects it).
    //
    {
        PLIST_ENTRY listEntry;
        PNR_ENTRY entry;

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Manager->EntryLock);

        while (!IsListEmpty(&Manager->EntryList)) {
            listEntry = RemoveHeadList(&Manager->EntryList);
            entry = CONTAINING_RECORD(listEntry, NR_ENTRY, ListEntry);
            RemoveEntryList(&entry->HashEntry);
            NrpFreeEntry(entry);
        }
        Manager->EntryCount = 0;

        ExReleasePushLockExclusive(&Manager->EntryLock);
        KeLeaveCriticalRegion();
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Network reputation manager shutdown "
               "(lookups=%lld, hits=%lld, misses=%lld)\n",
               Manager->Stats.Lookups,
               Manager->Stats.Hits,
               Manager->Stats.Misses);

    //
    // 4. Free resources
    //
    if (Manager->Hash.Buckets != NULL) {
        ExFreePoolWithTag(Manager->Hash.Buckets, NR_POOL_TAG_CACHE);
        Manager->Hash.Buckets = NULL;
    }

    ExFreePoolWithTag(Manager, NR_POOL_TAG_CACHE);
}

// ============================================================================
// PUBLIC API - LOOKUP FUNCTIONS
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NrLookupIP(
    _In_ PNR_MANAGER Manager,
    _In_reads_bytes_(IsIPv6 ? sizeof(IN6_ADDR) : sizeof(IN_ADDR)) const VOID* Address,
    _In_ BOOLEAN IsIPv6,
    _Out_ PNR_LOOKUP_RESULT Result
    )
{
    ULONG hash;
    PNR_ENTRY entry;
    LARGE_INTEGER now;

    PAGED_CODE();

    if (Manager == NULL || Address == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Result, sizeof(NR_LOOKUP_RESULT));

    //
    // Acquire rundown protection; if shutdown is in progress this fails.
    //
    if (!ExAcquireRundownProtection(&Manager->RundownRef)) {
        return STATUS_DEVICE_NOT_READY;
    }

    InterlockedIncrement64(&Manager->Stats.Lookups);

    //
    // Private / loopback IPs: return Unknown with NR_FLAG_INTERNAL so
    // callers can apply policy. Do NOT blanket-whitelist.
    //
    if (!IsIPv6) {
        const UCHAR* ipBytes = (const UCHAR*)Address;

        if (NrpIsLoopbackIP(ipBytes)) {
            Result->Found = TRUE;
            Result->Reputation = NrReputation_Unknown;
            Result->Score = 0;
            Result->Flags = NR_FLAG_INTERNAL | NR_FLAG_LOOPBACK;
            InterlockedIncrement64(&Manager->Stats.Hits);
            ExReleaseRundownProtection(&Manager->RundownRef);
            return STATUS_SUCCESS;
        }

        if (NrpIsPrivateIP(ipBytes)) {
            Result->Found = TRUE;
            Result->Reputation = NrReputation_Unknown;
            Result->Score = 0;
            Result->Flags = NR_FLAG_INTERNAL;
            InterlockedIncrement64(&Manager->Stats.Hits);
            ExReleaseRundownProtection(&Manager->RundownRef);
            return STATUS_SUCCESS;
        }
    } else {
        const UCHAR* ipBytes = (const UCHAR*)Address;

        if (NrpIsLoopbackIPv6(ipBytes)) {
            Result->Found = TRUE;
            Result->Reputation = NrReputation_Unknown;
            Result->Score = 0;
            Result->Flags = NR_FLAG_INTERNAL | NR_FLAG_LOOPBACK;
            InterlockedIncrement64(&Manager->Stats.Hits);
            ExReleaseRundownProtection(&Manager->RundownRef);
            return STATUS_SUCCESS;
        }

        if (NrpIsPrivateIPv6(ipBytes)) {
            Result->Found = TRUE;
            Result->Reputation = NrReputation_Unknown;
            Result->Score = 0;
            Result->Flags = NR_FLAG_INTERNAL;
            InterlockedIncrement64(&Manager->Stats.Hits);
            ExReleaseRundownProtection(&Manager->RundownRef);
            return STATUS_SUCCESS;
        }
    }

    hash = NrpHashIP(Address, IsIPv6);

    //
    // Lookup in cache under shared lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Manager->EntryLock);

    entry = NrpFindEntryByIP(Manager, Address, IsIPv6, hash);

    if (entry != NULL) {
        if (NrpIsEntryExpired(entry)) {
            ExReleasePushLockShared(&Manager->EntryLock);
            KeLeaveCriticalRegion();

            InterlockedIncrement64(&Manager->Stats.Misses);
            Result->Found = FALSE;
            ExReleaseRundownProtection(&Manager->RundownRef);
            return STATUS_SUCCESS;
        }

        Result->Found = TRUE;
        Result->Reputation = entry->Reputation;
        Result->Categories = entry->Categories;
        Result->Score = entry->Score;
        Result->Flags = NR_FLAG_FROM_CACHE;

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
        // Submit known-bad reputation to behavioral engine (MITRE T1071)
        //
        if (entry->Reputation >= NrReputation_Malicious) {
            BeEngineSubmitEvent(
                BehaviorEvent_C2Communication,
                BehaviorCategory_NetworkOperation,
                0,  // ProcessId not available at lookup layer
                NULL,
                0,
                (UINT32)entry->Score,
                FALSE,
                NULL
                );
        }

        //
        // Atomically update access time (64-bit atomic write).
        // HitCount is already interlocked.
        //
        KeQuerySystemTime(&now);
        InterlockedExchange64(&entry->LastAccessTime, now.QuadPart);
        InterlockedIncrement(&entry->HitCount);
        InterlockedIncrement64(&Manager->Stats.Hits);

    } else {
        InterlockedIncrement64(&Manager->Stats.Misses);
        Result->Found = FALSE;
    }

    ExReleasePushLockShared(&Manager->EntryLock);
    KeLeaveCriticalRegion();
    ExReleaseRundownProtection(&Manager->RundownRef);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NrLookupDomain(
    _In_ PNR_MANAGER Manager,
    _In_z_ PCSTR Domain,
    _Out_ PNR_LOOKUP_RESULT Result
    )
{
    ULONG hash;
    PNR_ENTRY entry;
    CHAR normalizedDomain[NR_MAX_DOMAIN_LENGTH + 1];
    ULONG dgaScore;
    LARGE_INTEGER now;

    PAGED_CODE();

    if (Manager == NULL || Domain == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Result, sizeof(NR_LOOKUP_RESULT));

    if (!ExAcquireRundownProtection(&Manager->RundownRef)) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (Domain[0] == '\0') {
        ExReleaseRundownProtection(&Manager->RundownRef);
        return STATUS_INVALID_PARAMETER;
    }

    InterlockedIncrement64(&Manager->Stats.Lookups);

    NrpNormalizeDomain(Domain, NR_MAX_DOMAIN_LENGTH,
                       normalizedDomain, sizeof(normalizedDomain));

    dgaScore = NrpCalculateDGAScore(normalizedDomain, NR_MAX_DOMAIN_LENGTH);

    hash = NrpHashDomain(normalizedDomain, NR_MAX_DOMAIN_LENGTH);

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Manager->EntryLock);

    entry = NrpFindEntryByDomain(Manager, normalizedDomain, hash);

    if (entry != NULL) {
        if (NrpIsEntryExpired(entry)) {
            ExReleasePushLockShared(&Manager->EntryLock);
            KeLeaveCriticalRegion();

            InterlockedIncrement64(&Manager->Stats.Misses);
            Result->Found = FALSE;

            if (dgaScore >= 70) {
                Result->Found = TRUE;
                Result->Reputation = NrReputation_Medium;
                Result->Categories = NrCategory_DGA;
                Result->Score = dgaScore;
                Result->Flags = NR_FLAG_DGA_HEURISTIC;
                RtlStringCchCopyA(Result->ThreatName,
                                  sizeof(Result->ThreatName),
                                  "Suspicious DGA-like domain");

                BeEngineSubmitEvent(
                    BehaviorEvent_DGADomain,
                    BehaviorCategory_NetworkOperation,
                    0,
                    NULL,
                    0,
                    (UINT32)dgaScore,
                    FALSE,
                    NULL
                    );
            }

            ExReleaseRundownProtection(&Manager->RundownRef);
            return STATUS_SUCCESS;
        }

        Result->Found = TRUE;
        Result->Reputation = entry->Reputation;
        Result->Categories = entry->Categories;
        Result->Score = entry->Score;
        Result->Flags = NR_FLAG_FROM_CACHE;

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
        // Submit known-bad domain reputation to behavioral engine (MITRE T1071)
        //
        if (entry->Reputation >= NrReputation_Malicious) {
            BeEngineSubmitEvent(
                BehaviorEvent_C2Communication,
                BehaviorCategory_NetworkOperation,
                0,
                NULL,
                0,
                (UINT32)entry->Score,
                FALSE,
                NULL
                );
        }

        KeQuerySystemTime(&now);
        InterlockedExchange64(&entry->LastAccessTime, now.QuadPart);
        InterlockedIncrement(&entry->HitCount);
        InterlockedIncrement64(&Manager->Stats.Hits);

    } else {
        InterlockedIncrement64(&Manager->Stats.Misses);
        Result->Found = FALSE;

        if (dgaScore >= 70) {
            Result->Found = TRUE;
            Result->Reputation = NrReputation_Medium;
            Result->Categories = NrCategory_DGA;
            Result->Score = dgaScore;
            Result->Flags = NR_FLAG_DGA_HEURISTIC;
            RtlStringCchCopyA(Result->ThreatName,
                              sizeof(Result->ThreatName),
                              "Suspicious DGA-like domain");

            BeEngineSubmitEvent(
                BehaviorEvent_DGADomain,
                BehaviorCategory_NetworkOperation,
                0,
                NULL,
                0,
                (UINT32)dgaScore,
                FALSE,
                NULL
                );
        }
    }

    ExReleasePushLockShared(&Manager->EntryLock);
    KeLeaveCriticalRegion();
    ExReleaseRundownProtection(&Manager->RundownRef);

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - CACHE MANAGEMENT
// ============================================================================

//
// Internal add with duplicate detection. If an entry with the same key
// already exists, it is updated in-place (no double-insert).
//
static NTSTATUS
NrpAddEntryInternal(
    _In_ PNR_MANAGER Manager,
    _In_ PNR_ENTRY TemplateEntry
    )
{
    PNR_ENTRY existingEntry = NULL;
    PNR_ENTRY newEntry = NULL;

    PAGED_CODE();

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Manager->EntryLock);

    //
    // Check for existing duplicate
    //
    if (TemplateEntry->Type == NrType_IP) {
        existingEntry = NrpFindEntryByIP(
            Manager,
            TemplateEntry->Value.IP.IsIPv6
                ? (const VOID*)&TemplateEntry->Value.IP.Address6
                : (const VOID*)&TemplateEntry->Value.IP.Address,
            TemplateEntry->Value.IP.IsIPv6,
            TemplateEntry->Hash
        );
    } else if (TemplateEntry->Type == NrType_Domain) {
        existingEntry = NrpFindEntryByDomain(
            Manager,
            TemplateEntry->Value.Domain,
            TemplateEntry->Hash
        );
    }

    if (existingEntry != NULL) {
        //
        // Update in-place (atomic from caller's perspective)
        //
        NrpUpdateEntryInPlace(existingEntry, TemplateEntry,
                              Manager->Config.TTLSeconds);

        ExReleasePushLockExclusive(&Manager->EntryLock);
        KeLeaveCriticalRegion();
        return STATUS_SUCCESS;
    }

    //
    // Must allocate outside the lock? No — we hold exclusive so we are safe,
    // and PagedPool allocation at APC_LEVEL is fine (critical region raises
    // to APC_LEVEL which is still legal for paged allocations).
    //
    newEntry = NrpAllocateEntry();
    if (newEntry == NULL) {
        ExReleasePushLockExclusive(&Manager->EntryLock);
        KeLeaveCriticalRegion();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(newEntry, TemplateEntry, sizeof(NR_ENTRY));
    InitializeListHead(&newEntry->ListEntry);
    InitializeListHead(&newEntry->HashEntry);

    //
    // Set timestamps
    //
    {
        LARGE_INTEGER addedTime;
        KeQuerySystemTime(&addedTime);
        newEntry->AddedTime = addedTime;
        InterlockedExchange64(&newEntry->LastAccessTime, addedTime.QuadPart);
        newEntry->ExpirationTime.QuadPart =
            addedTime.QuadPart +
            ((LONGLONG)Manager->Config.TTLSeconds * 10000000LL);
        newEntry->HitCount = 0;
    }

    //
    // Evict if at capacity. NrpEvictOldestEntry returns FALSE if it
    // cannot evict (all entries permanent). Break to avoid infinite loop.
    //
    while ((ULONG)Manager->EntryCount >= Manager->Config.MaxEntries) {
        if (!NrpEvictOldestEntry(Manager)) {
            break;
        }
    }

    //
    // If still at capacity after eviction attempts, we still insert
    // (slightly over limit is safer than rejecting).
    //
    NrpInsertEntry(Manager, newEntry);

    ExReleasePushLockExclusive(&Manager->EntryLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

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
    )
{
    NR_ENTRY entry;

    PAGED_CODE();

    if (Manager == NULL || Address == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Score > 100) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Manager->RundownRef)) {
        return STATUS_DEVICE_NOT_READY;
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
        RtlStringCchCopyA(entry.ThreatName,
                          RTL_NUMBER_OF(entry.ThreatName),
                          ThreatName);
    }

    {
        NTSTATUS status = NrpAddEntryInternal(Manager, &entry);
        ExReleaseRundownProtection(&Manager->RundownRef);
        return status;
    }
}

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
    )
{
    NR_ENTRY entry;
    CHAR normalizedDomain[NR_MAX_DOMAIN_LENGTH + 1];

    PAGED_CODE();

    if (Manager == NULL || Domain == NULL || Domain[0] == '\0') {
        return STATUS_INVALID_PARAMETER;
    }
    if (Score > 100) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Manager->RundownRef)) {
        return STATUS_DEVICE_NOT_READY;
    }

    RtlZeroMemory(&entry, sizeof(NR_ENTRY));

    NrpNormalizeDomain(Domain, NR_MAX_DOMAIN_LENGTH,
                       normalizedDomain, sizeof(normalizedDomain));

    entry.Type = NrType_Domain;
    RtlStringCchCopyA(entry.Value.Domain,
                      RTL_NUMBER_OF(entry.Value.Domain),
                      normalizedDomain);

    entry.Hash = NrpHashDomain(normalizedDomain, NR_MAX_DOMAIN_LENGTH);
    entry.Reputation = Reputation;
    entry.Categories = Categories;
    entry.Score = Score;

    if (ThreatName != NULL) {
        RtlStringCchCopyA(entry.ThreatName,
                          RTL_NUMBER_OF(entry.ThreatName),
                          ThreatName);
    }

    {
        NTSTATUS status = NrpAddEntryInternal(Manager, &entry);
        ExReleaseRundownProtection(&Manager->RundownRef);
        return status;
    }
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NrRemoveIP(
    _In_ PNR_MANAGER Manager,
    _In_reads_bytes_(IsIPv6 ? sizeof(IN6_ADDR) : sizeof(IN_ADDR)) const VOID* Address,
    _In_ BOOLEAN IsIPv6
    )
{
    ULONG hash;
    PNR_ENTRY entry;

    PAGED_CODE();

    if (Manager == NULL || Address == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Manager->RundownRef)) {
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
    ExReleaseRundownProtection(&Manager->RundownRef);

    return (entry != NULL) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NrRemoveDomain(
    _In_ PNR_MANAGER Manager,
    _In_z_ PCSTR Domain
    )
{
    ULONG hash;
    PNR_ENTRY entry;
    CHAR normalizedDomain[NR_MAX_DOMAIN_LENGTH + 1];

    PAGED_CODE();

    if (Manager == NULL || Domain == NULL || Domain[0] == '\0') {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Manager->RundownRef)) {
        return STATUS_DEVICE_NOT_READY;
    }

    NrpNormalizeDomain(Domain, NR_MAX_DOMAIN_LENGTH,
                       normalizedDomain, sizeof(normalizedDomain));
    hash = NrpHashDomain(normalizedDomain, NR_MAX_DOMAIN_LENGTH);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Manager->EntryLock);

    entry = NrpFindEntryByDomain(Manager, normalizedDomain, hash);

    if (entry != NULL) {
        NrpRemoveEntry(Manager, entry);
        NrpFreeEntry(entry);
    }

    ExReleasePushLockExclusive(&Manager->EntryLock);
    KeLeaveCriticalRegion();
    ExReleaseRundownProtection(&Manager->RundownRef);

    return (entry != NULL) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

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

    if (Manager == NULL) {
        return;
    }

    //
    // Acquire rundown protection so this is safe to call while the manager
    // is live. If shutdown is in progress, bail out cleanly.
    //
    if (!ExAcquireRundownProtection(&Manager->RundownRef)) {
        return;
    }

    InitializeListHead(&tempList);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Manager->EntryLock);

    while (!IsListEmpty(&Manager->EntryList)) {
        listEntry = RemoveHeadList(&Manager->EntryList);
        entry = CONTAINING_RECORD(listEntry, NR_ENTRY, ListEntry);
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

    ExReleaseRundownProtection(&Manager->RundownRef);
}

// ============================================================================
// PUBLIC API - STATISTICS
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
NrGetStatistics(
    _In_ PNR_MANAGER Manager,
    _Out_ PNR_STATISTICS Stats
    )
{
    LARGE_INTEGER currentTime;

    PAGED_CODE();

    if (Manager == NULL || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Stats, sizeof(NR_STATISTICS));

    if (!ExAcquireRundownProtection(&Manager->RundownRef)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Snapshot stats under shared lock for consistency
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Manager->EntryLock);

    Stats->CacheEntries = (ULONG)Manager->EntryCount;
    Stats->Lookups = (ULONG64)InterlockedCompareExchange64(
        &Manager->Stats.Lookups, 0, 0);
    Stats->CacheHits = (ULONG64)InterlockedCompareExchange64(
        &Manager->Stats.Hits, 0, 0);
    Stats->CacheMisses = (ULONG64)InterlockedCompareExchange64(
        &Manager->Stats.Misses, 0, 0);

    ExReleasePushLockShared(&Manager->EntryLock);
    KeLeaveCriticalRegion();

    if (Stats->Lookups > 0) {
        Stats->HitRatePercent =
            (ULONG)((Stats->CacheHits * 100) / Stats->Lookups);
    }

    KeQuerySystemTime(&currentTime);
    Stats->UpTime.QuadPart =
        currentTime.QuadPart - Manager->Stats.StartTime.QuadPart;

    ExReleaseRundownProtection(&Manager->RundownRef);
    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - HASHING
// ============================================================================

static ULONG
NrpHashIP(
    _In_reads_bytes_(IsIPv6 ? sizeof(IN6_ADDR) : sizeof(IN_ADDR)) const VOID* Address,
    _In_ BOOLEAN IsIPv6
    )
{
    ULONG hash = NR_FNV_OFFSET_BASIS;
    const UCHAR* bytes = (const UCHAR*)Address;
    ULONG length = IsIPv6 ? sizeof(IN6_ADDR) : sizeof(IN_ADDR);
    ULONG i;

    PAGED_CODE();

    for (i = 0; i < length; i++) {
        hash ^= bytes[i];
        hash *= NR_FNV_PRIME;
    }

    return hash;
}

static ULONG
NrpHashDomain(
    _In_z_ PCSTR Domain,
    _In_ ULONG MaxLength
    )
{
    ULONG hash = NR_FNV_OFFSET_BASIS;
    ULONG i;

    PAGED_CODE();

    for (i = 0; i < MaxLength && Domain[i] != '\0'; i++) {
        CHAR ch = Domain[i];
        if (ch >= 'A' && ch <= 'Z') {
            ch = ch - 'A' + 'a';
        }
        hash ^= (UCHAR)ch;
        hash *= NR_FNV_PRIME;
    }

    return hash;
}

static ULONG
NrpHashToIndex(
    _In_ PNR_MANAGER Manager,
    _In_ ULONG Hash
    )
{
    //
    // BucketCount is a power of 2, so use bitmask for speed
    //
    PAGED_CODE();
    return Hash & (Manager->Hash.BucketCount - 1);
}

// ============================================================================
// PRIVATE IMPLEMENTATION - STRING HELPERS (NO CRT DEPENDENCY)
// ============================================================================

//
// Safe bounded string length (replaces strlen)
//
static NTSTATUS
NrpSafeStringLengthA(
    _In_z_ PCSTR String,
    _In_ ULONG MaxLength,
    _Out_ ULONG* Length
    )
{
    ULONG i;

    PAGED_CODE();

    *Length = 0;

    if (String == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    for (i = 0; i < MaxLength; i++) {
        if (String[i] == '\0') {
            *Length = i;
            return STATUS_SUCCESS;
        }
    }

    *Length = MaxLength;
    return STATUS_BUFFER_OVERFLOW;
}

//
// Case-insensitive ordinal comparison (replaces _stricmp)
//
static int
NrpSafeCompareStringOrdinalA(
    _In_z_ PCSTR String1,
    _In_z_ PCSTR String2,
    _In_ ULONG MaxLength
    )
{
    ULONG i;

    PAGED_CODE();

    for (i = 0; i < MaxLength; i++) {
        CHAR c1 = String1[i];
        CHAR c2 = String2[i];

        if (c1 >= 'A' && c1 <= 'Z') c1 = c1 - 'A' + 'a';
        if (c2 >= 'A' && c2 <= 'Z') c2 = c2 - 'A' + 'a';

        if (c1 != c2) {
            return (int)(UCHAR)c1 - (int)(UCHAR)c2;
        }
        if (c1 == '\0') {
            return 0;
        }
    }
    return 0;
}

//
// Bounded character search (replaces strchr)
//
static PCSTR
NrpSafeFindCharA(
    _In_z_ PCSTR String,
    _In_ CHAR Ch,
    _In_ ULONG MaxLength
    )
{
    ULONG i;

    PAGED_CODE();

    for (i = 0; i < MaxLength && String[i] != '\0'; i++) {
        if (String[i] == Ch) {
            return &String[i];
        }
    }
    return NULL;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - ENTRY MANAGEMENT
// ============================================================================

static PNR_ENTRY
NrpFindEntryByIP(
    _In_ PNR_MANAGER Manager,
    _In_reads_bytes_(IsIPv6 ? sizeof(IN6_ADDR) : sizeof(IN_ADDR)) const VOID* Address,
    _In_ BOOLEAN IsIPv6,
    _In_ ULONG Hash
    )
{
    ULONG index = NrpHashToIndex(Manager, Hash);
    PLIST_ENTRY bucket = &Manager->Hash.Buckets[index];
    PLIST_ENTRY listEntry;
    PNR_ENTRY entry;

    PAGED_CODE();

    for (listEntry = bucket->Flink;
         listEntry != bucket;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, NR_ENTRY, HashEntry);

        if (entry->Type != NrType_IP || entry->Hash != Hash) {
            continue;
        }
        if (entry->Value.IP.IsIPv6 != IsIPv6) {
            continue;
        }

        if (IsIPv6) {
            if (RtlCompareMemory(&entry->Value.IP.Address6,
                                 Address,
                                 sizeof(IN6_ADDR)) == sizeof(IN6_ADDR)) {
                return entry;
            }
        } else {
            if (RtlCompareMemory(&entry->Value.IP.Address,
                                 Address,
                                 sizeof(IN_ADDR)) == sizeof(IN_ADDR)) {
                return entry;
            }
        }
    }

    return NULL;
}

static PNR_ENTRY
NrpFindEntryByDomain(
    _In_ PNR_MANAGER Manager,
    _In_z_ PCSTR Domain,
    _In_ ULONG Hash
    )
{
    ULONG index = NrpHashToIndex(Manager, Hash);
    PLIST_ENTRY bucket = &Manager->Hash.Buckets[index];
    PLIST_ENTRY listEntry;
    PNR_ENTRY entry;

    PAGED_CODE();

    for (listEntry = bucket->Flink;
         listEntry != bucket;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, NR_ENTRY, HashEntry);

        if (entry->Type != NrType_Domain || entry->Hash != Hash) {
            continue;
        }

        if (NrpSafeCompareStringOrdinalA(entry->Value.Domain, Domain,
                                         NR_MAX_DOMAIN_LENGTH) == 0) {
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

    PAGED_CODE();

    //
    // PagedPool: entries are only accessed at <= APC_LEVEL
    //
    entry = (PNR_ENTRY)ExAllocatePoolZero(
        PagedPool,
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
    PAGED_CODE();

    if (Entry != NULL) {
        //
        // Scrub threat info before freeing
        //
        RtlSecureZeroMemory(Entry, sizeof(NR_ENTRY));
        ExFreePoolWithTag(Entry, NR_POOL_TAG_ENTRY);
    }
}

static VOID
NrpInsertEntry(
    _In_ PNR_MANAGER Manager,
    _In_ PNR_ENTRY Entry
    )
{
    ULONG index;

    PAGED_CODE();

    index = NrpHashToIndex(Manager, Entry->Hash);

    InsertHeadList(&Manager->EntryList, &Entry->ListEntry);
    InsertHeadList(&Manager->Hash.Buckets[index], &Entry->HashEntry);

    InterlockedIncrement(&Manager->EntryCount);
}

static VOID
NrpRemoveEntry(
    _In_ PNR_MANAGER Manager,
    _In_ PNR_ENTRY Entry
    )
{
    PAGED_CODE();

    RemoveEntryList(&Entry->ListEntry);
    InitializeListHead(&Entry->ListEntry);

    RemoveEntryList(&Entry->HashEntry);
    InitializeListHead(&Entry->HashEntry);

    InterlockedDecrement(&Manager->EntryCount);
}

//
// Update an existing entry with new reputation data. Called under
// exclusive lock.
//
static VOID
NrpUpdateEntryInPlace(
    _Inout_ PNR_ENTRY Existing,
    _In_ PNR_ENTRY Source,
    _In_ ULONG TTLSeconds
    )
{
    LARGE_INTEGER now;

    PAGED_CODE();

    Existing->Reputation = Source->Reputation;
    Existing->Categories = Source->Categories;
    Existing->Score = Source->Score;

    RtlCopyMemory(Existing->ThreatName, Source->ThreatName,
                   sizeof(Existing->ThreatName));
    RtlCopyMemory(Existing->MalwareFamily, Source->MalwareFamily,
                   sizeof(Existing->MalwareFamily));

    KeQuerySystemTime(&now);
    Existing->AddedTime = now;
    InterlockedExchange64(&Existing->LastAccessTime, now.QuadPart);
    Existing->ExpirationTime.QuadPart =
        now.QuadPart + ((LONGLONG)TTLSeconds * 10000000LL);
    Existing->HitCount = 0;
}

static BOOLEAN
NrpIsEntryExpired(
    _In_ PNR_ENTRY Entry
    )
{
    LARGE_INTEGER currentTime;

    PAGED_CODE();

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

//
// Returns TRUE if an entry was evicted, FALSE if none could be evicted
// (e.g., all are permanent). Prevents infinite loops in the caller.
//
static BOOLEAN
NrpEvictOldestEntry(
    _In_ PNR_MANAGER Manager
    )
{
    PLIST_ENTRY listEntry;
    PNR_ENTRY entry;
    PNR_ENTRY oldestEntry = NULL;
    LONGLONG oldestTime = MAXLONGLONG;
    LONGLONG accessTime;

    PAGED_CODE();

    for (listEntry = Manager->EntryList.Flink;
         listEntry != &Manager->EntryList;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, NR_ENTRY, ListEntry);

        if (entry->Reputation == NrReputation_Whitelisted ||
            entry->Reputation == NrReputation_Blacklisted) {
            continue;
        }

        accessTime = InterlockedCompareExchange64(
            &entry->LastAccessTime, 0, 0);

        if (accessTime < oldestTime) {
            oldestTime = accessTime;
            oldestEntry = entry;
        }
    }

    if (oldestEntry != NULL) {
        NrpRemoveEntry(Manager, oldestEntry);
        NrpFreeEntry(oldestEntry);
        return TRUE;
    }

    return FALSE;
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

    PAGED_CODE();

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

    while (!IsListEmpty(&expiredList)) {
        listEntry = RemoveHeadList(&expiredList);
        entry = CONTAINING_RECORD(listEntry, NR_ENTRY, ListEntry);
        NrpFreeEntry(entry);
    }
}

// ============================================================================
// PRIVATE IMPLEMENTATION - TIMER CALLBACK (VIA TimerManager)
// ============================================================================

//
// TimerManager callback: runs at PASSIVE_LEVEL (TmFlag_WorkItemCallback).
// Replaces the old DPC + IoWorkItem two-stage pattern.
//
static VOID
NrpCleanupTimerCallback(
    _In_ ULONG TimerId,
    _In_opt_ PVOID Context
    )
{
    PNR_MANAGER manager = (PNR_MANAGER)Context;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(TimerId);

    if (manager == NULL) {
        return;
    }
    if (!manager->Config.EnableExpirations) {
        return;
    }

    //
    // Prevent overlapping callbacks (non-reentrant guard).
    //
    if (InterlockedCompareExchange(&manager->CleanupInProgress, 1, 0) != 0) {
        return;
    }

    //
    // Acquire rundown at PASSIVE_LEVEL. If shutdown has already started,
    // ExWaitForRundownProtectionRelease makes the ref permanently
    // non-acquirable, so this fails and we exit cleanly.
    //
    if (!ExAcquireRundownProtection(&manager->RundownRef)) {
        InterlockedExchange(&manager->CleanupInProgress, 0);
        return;
    }

    NrpCleanupExpiredEntries(manager, NR_MAX_CLEANUP_PER_TICK);

    //
    // Release rundown BEFORE clearing the in-progress flag.
    //
    ExReleaseRundownProtection(&manager->RundownRef);
    InterlockedExchange(&manager->CleanupInProgress, 0);
}

// ============================================================================
// PRIVATE IMPLEMENTATION - IP HELPERS (BYTE-LEVEL, PORTABLE)
// ============================================================================

static BOOLEAN
NrpIsPrivateIP(
    _In_reads_bytes_(sizeof(ULONG)) const UCHAR* IPv4Bytes
    )
{
    UCHAR first;
    UCHAR second;

    PAGED_CODE();

    //
    // IN_ADDR.S_addr is in network byte order. The first octet is
    // at offset 0 regardless of host endianness.
    //
    first  = IPv4Bytes[0];
    second = IPv4Bytes[1];

    // 10.0.0.0/8
    if (first == 10) return TRUE;

    // 172.16.0.0/12
    if (first == 172 && second >= 16 && second <= 31) return TRUE;

    // 192.168.0.0/16
    if (first == 192 && second == 168) return TRUE;

    // 169.254.0.0/16 (link-local)
    if (first == 169 && second == 254) return TRUE;

    return FALSE;
}

static BOOLEAN
NrpIsLoopbackIP(
    _In_reads_bytes_(sizeof(ULONG)) const UCHAR* IPv4Bytes
    )
{
    PAGED_CODE();
    // 127.0.0.0/8
    return (IPv4Bytes[0] == 127);
}

static BOOLEAN
NrpIsLoopbackIPv6(
    _In_reads_bytes_(sizeof(IN6_ADDR)) const UCHAR* IPv6Bytes
    )
{
    ULONG i;

    PAGED_CODE();

    // ::1 — all zeros except last byte is 1
    for (i = 0; i < 15; i++) {
        if (IPv6Bytes[i] != 0) return FALSE;
    }
    return (IPv6Bytes[15] == 1);
}

static BOOLEAN
NrpIsPrivateIPv6(
    _In_reads_bytes_(sizeof(IN6_ADDR)) const UCHAR* IPv6Bytes
    )
{
    PAGED_CODE();

    // fc00::/7 — Unique Local Address (ULA): first byte fc or fd
    if ((IPv6Bytes[0] & 0xFE) == 0xFC) return TRUE;

    // fe80::/10 — Link-local: first byte fe, second byte 80-bf (top 2 bits = 10)
    if (IPv6Bytes[0] == 0xFE && (IPv6Bytes[1] & 0xC0) == 0x80) return TRUE;

    return FALSE;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - DOMAIN HELPERS
// ============================================================================

static ULONG
NrpCalculateDGAScore(
    _In_z_ PCSTR Domain,
    _In_ ULONG MaxLength
    )
{
    ULONG score = 0;
    ULONG length = 0;
    ULONG consonantRun = 0;
    ULONG vowelRun = 0;
    ULONG digitCount = 0;
    ULONG hyphenCount = 0;
    ULONG uniqueChars = 0;
    UCHAR charCounts[128];   // ASCII only — 128 bytes, not 1KB
    PCSTR dotPos = NULL;
    ULONG i;
    ULONG bigramPenalty = 0;
    ULONG bigramCount = 0;
    CHAR prevCh = 0;

    PAGED_CODE();

    RtlZeroMemory(charCounts, sizeof(charCounts));

    if (Domain == NULL || Domain[0] == '\0') {
        return 0;
    }

    //
    // Find first dot (base domain label) with bounded search
    //
    dotPos = NrpSafeFindCharA(Domain, '.', MaxLength);
    if (dotPos == NULL) {
        NrpSafeStringLengthA(Domain, MaxLength, &length);
    } else {
        length = (ULONG)(dotPos - Domain);
    }

    if (length == 0) {
        return 0;
    }

    //
    // Analyze characters + bigram frequency
    //
    for (i = 0; i < length; i++) {
        CHAR ch = Domain[i];
        if (ch >= 'A' && ch <= 'Z') {
            ch = ch - 'A' + 'a';
        }

        if ((UCHAR)ch < 128) {
            charCounts[(UCHAR)ch]++;
        }

        //
        // Bigram analysis: check how common this letter pair is in English.
        // Low frequency bigrams strongly indicate DGA-generated strings.
        //
        if (prevCh >= 'a' && prevCh <= 'z' && ch >= 'a' && ch <= 'z') {
            UCHAR freq = g_BigramFrequency[prevCh - 'a'][ch - 'a'];
            if (freq <= 1) {
                bigramPenalty += 8;
            } else if (freq <= 2) {
                bigramPenalty += 3;
            }
            bigramCount++;
        }
        prevCh = ch;

        if (ch >= '0' && ch <= '9') {
            digitCount++;
            consonantRun = 0;
            vowelRun = 0;
        } else if (ch == '-') {
            hyphenCount++;
            consonantRun = 0;
            vowelRun = 0;
        } else if (ch == 'a' || ch == 'e' || ch == 'i' ||
                   ch == 'o' || ch == 'u') {
            vowelRun++;
            consonantRun = 0;
            if (vowelRun > 3) {
                score += 10;
            }
        } else if (ch >= 'a' && ch <= 'z') {
            consonantRun++;
            vowelRun = 0;
            if (consonantRun > 4) {
                score += 15;
            }
        }
    }

    //
    // Apply bigram penalty (normalized by count to avoid length bias)
    //
    if (bigramCount > 0) {
        ULONG avgPenalty = bigramPenalty / bigramCount;
        if (avgPenalty > 5) {
            score += min(avgPenalty * 3, 30);
        }
    }

    //
    // Count unique characters
    //
    for (i = 0; i < 128; i++) {
        if (charCounts[i] > 0) {
            uniqueChars++;
        }
    }

    //
    // High digit ratio
    //
    if (length > 0) {
        ULONG digitRatio = (digitCount * 100) / length;
        if (digitRatio > 30)      score += 25;
        else if (digitRatio > 20) score += 15;
    }

    // Very long domains
    if (length > 20) score += 10;
    if (length > 30) score += 15;

    // Many hyphens
    if (hyphenCount > 2) score += 10;

    // Low character diversity
    if (length > 8 && uniqueChars < length / 2) score += 15;

    // High entropy short domain
    if (length > 0 && length <= 12 && uniqueChars > (length * 3) / 4) {
        score += 10;
    }

    if (score > 100) score = 100;

    return score;
}

static VOID
NrpNormalizeDomain(
    _In_z_ PCSTR Domain,
    _In_ ULONG DomainMaxLength,
    _Out_writes_z_(BufferSize) PSTR NormalizedDomain,
    _In_ ULONG BufferSize
    )
{
    ULONG i;
    ULONG len = 0;

    PAGED_CODE();

    if (BufferSize == 0) {
        return;
    }
    NormalizedDomain[0] = '\0';

    if (Domain == NULL || Domain[0] == '\0') {
        return;
    }

    //
    // Safe bounded length (replaces strlen)
    //
    NrpSafeStringLengthA(Domain, DomainMaxLength, &len);

    if (len >= BufferSize) {
        len = BufferSize - 1;
    }

    //
    // Copy and lowercase
    //
    for (i = 0; i < len; i++) {
        CHAR ch = Domain[i];
        if (ch >= 'A' && ch <= 'Z') {
            ch = ch - 'A' + 'a';
        }
        NormalizedDomain[i] = ch;
    }
    NormalizedDomain[len] = '\0';

    //
    // Remove trailing dot
    //
    if (len > 0 && NormalizedDomain[len - 1] == '.') {
        NormalizedDomain[len - 1] = '\0';
    }
}
