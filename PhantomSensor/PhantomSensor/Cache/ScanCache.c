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
 * ShadowStrike NGAV - SCAN CACHE IMPLEMENTATION
 * ============================================================================
 *
 * @file ScanCache.c
 * @brief Kernel-mode verdict caching implementation.
 *
 * Provides high-performance caching of scan verdicts to reduce
 * redundant user-mode communication for recently scanned files.
 *
 * SAFETY GUARANTEES:
 * - All pointer parameters validated before use
 * - All locks acquired with proper IRQL awareness
 * - Lookaside list for predictable memory allocation
 * - Fail-safe on any allocation failure
 * - Proper work item lifecycle management (IoAllocateWorkItem)
 * - Shutdown synchronization with KeFlushQueuedDpcs()
 * - No floating-point operations
 * - Proper volume serial retrieval (not pointer-based)
 * - All statistics operations are atomic
 *
 * @author ShadowStrike Security Team
 * @version 1.1.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "ScanCache.h"
#include "../Core/Globals.h"
#include "../Core/DriverEntry.h"
#include "../Sync/TimerManager.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ShadowStrikeCacheInitialize)
#pragma alloc_text(PAGE, ShadowStrikeCacheShutdown)
#pragma alloc_text(PAGE, ShadowStrikeCacheClear)
#pragma alloc_text(PAGE, ShadowStrikeCacheCleanup)
#pragma alloc_text(PAGE, ShadowStrikeCacheBuildKey)
#endif

// ============================================================================
// GLOBAL CACHE INSTANCE
// ============================================================================

static SHADOWSTRIKE_SCAN_CACHE g_ScanCache = {0};

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static
VOID
ShadowStrikeCacheCleanupTimerCallback(
    _In_ ULONG TimerId,
    _In_opt_ PVOID Context
    );

static
BOOLEAN
ShadowStrikeCacheKeyEquals(
    _In_ PSHADOWSTRIKE_CACHE_KEY Key1,
    _In_ PSHADOWSTRIKE_CACHE_KEY Key2
    );

static
PSHADOWSTRIKE_CACHE_ENTRY
ShadowStrikeCacheFindEntry(
    _In_ PSHADOWSTRIKE_CACHE_BUCKET Bucket,
    _In_ PSHADOWSTRIKE_CACHE_KEY Key
    );

static
VOID
ShadowStrikeCacheFreeEntry(
    _In_ PSHADOWSTRIKE_CACHE_ENTRY Entry
    );

static
BOOLEAN
ShadowStrikeCacheAcquireReference(
    VOID
    );

static
VOID
ShadowStrikeCacheReleaseReference(
    VOID
    );

// ============================================================================
// REFERENCE COUNTING FOR SHUTDOWN SYNCHRONIZATION
// ============================================================================

/**
 * @brief Acquire a reference to prevent shutdown during operation.
 *
 * @return TRUE if reference acquired, FALSE if shutdown in progress.
 */
static
BOOLEAN
ShadowStrikeCacheAcquireReference(
    VOID
    )
{
    //
    // Check shutdown flag first
    //
    if (g_ScanCache.ShutdownInProgress) {
        return FALSE;
    }

    //
    // Increment reference count
    //
    InterlockedIncrement(&g_ScanCache.ActiveReferences);

    //
    // Double-check shutdown flag after incrementing
    // (prevents race with shutdown)
    //
    if (g_ScanCache.ShutdownInProgress) {
        //
        // CRITICAL FIX: Must use ReleaseReference (not bare InterlockedDecrement)
        // so the shutdown event is signaled if this was the last reference.
        // Without this, shutdown hangs for 30s on the ShutdownEvent timeout.
        //
        ShadowStrikeCacheReleaseReference();
        return FALSE;
    }

    return TRUE;
}

/**
 * @brief Release reference and signal shutdown event if last reference.
 */
static
VOID
ShadowStrikeCacheReleaseReference(
    VOID
    )
{
    LONG refCount = InterlockedDecrement(&g_ScanCache.ActiveReferences);

    //
    // If this was the last reference and shutdown is pending, signal event
    //
    if (refCount == 0 && g_ScanCache.ShutdownInProgress) {
        KeSetEvent(&g_ScanCache.ShutdownEvent, IO_NO_INCREMENT, FALSE);
    }
}

// ============================================================================
// INITIALIZATION / SHUTDOWN
// ============================================================================

NTSTATUS
ShadowStrikeCacheInitialize(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG TTLSeconds
    )
{
    ULONG i;
    ULONG clampedTTL;

    PAGED_CODE();

    //
    // DeviceObject parameter retained for ABI compatibility but no longer required
    // (TimerManager handles work item allocation internally)
    //
    UNREFERENCED_PARAMETER(DeviceObject);

    if (g_ScanCache.Initialized) {
        return STATUS_SUCCESS;
    }

    //
    // Clamp TTL to prevent overflow
    //
    if (TTLSeconds == 0) {
        clampedTTL = SHADOWSTRIKE_CACHE_DEFAULT_TTL;
    } else if (TTLSeconds > SHADOWSTRIKE_CACHE_MAX_TTL) {
        clampedTTL = SHADOWSTRIKE_CACHE_MAX_TTL;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] ScanCache: TTL clamped from %lu to %lu seconds\n",
                   TTLSeconds, clampedTTL);
    } else {
        clampedTTL = TTLSeconds;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Initializing scan cache (TTL=%lu seconds)\n",
               clampedTTL);

    RtlZeroMemory(&g_ScanCache, sizeof(g_ScanCache));

    //
    // Initialize shutdown event (manual reset, initially not signaled)
    //
    KeInitializeEvent(&g_ScanCache.ShutdownEvent, NotificationEvent, FALSE);

    //
    // Initialize all buckets
    //
    for (i = 0; i < SHADOWSTRIKE_CACHE_BUCKET_COUNT; i++) {
        InitializeListHead(&g_ScanCache.Buckets[i].ListHead);
        ExInitializePushLock(&g_ScanCache.Buckets[i].Lock);
        g_ScanCache.Buckets[i].EntryCount = 0;
    }

    //
    // Initialize lookaside list for entry allocations
    //
    ExInitializeNPagedLookasideList(
        &g_ScanCache.EntryLookaside,
        NULL,                           // Allocate function (use default)
        NULL,                           // Free function (use default)
        POOL_NX_ALLOCATION,             // Flags
        sizeof(SHADOWSTRIKE_CACHE_ENTRY),
        SHADOWSTRIKE_CACHE_POOL_TAG,
        0                               // Depth (0 = system default)
    );
    g_ScanCache.LookasideInitialized = TRUE;

    //
    // Set TTL (convert seconds to 100-ns intervals)
    // clampedTTL is already validated to be <= MAX_TTL (86400)
    // Max value: 86400 * 10000000 = 864,000,000,000,000 (fits in LONGLONG)
    //
    g_ScanCache.TTLInterval.QuadPart = (LONGLONG)clampedTTL * 10000000LL;

    //
    // Initialize cleanup timer via centralized TimerManager.
    // TmFlag_WorkItemCallback ensures the callback runs at PASSIVE_LEVEL,
    // eliminating the need for a separate DPC→WorkItem indirection.
    //
    {
        PTM_MANAGER timerManager = ShadowStrikeGetTimerManager();
        if (timerManager != NULL) {
            TM_TIMER_OPTIONS opts = {0};
            opts.Flags = TmFlag_WorkItemCallback | TmFlag_Coalescable;
            opts.ToleranceMs = 5000;
            opts.Name = "ScanCacheCleanup";

            NTSTATUS tmStatus = TmCreatePeriodic(
                timerManager,
                SHADOWSTRIKE_CACHE_CLEANUP_INTERVAL * 1000,
                ShadowStrikeCacheCleanupTimerCallback,
                NULL,
                &opts,
                &g_ScanCache.CleanupTimerId
            );
            if (!NT_SUCCESS(tmStatus)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike] ScanCache: Failed to create cleanup timer: 0x%08X\n",
                           tmStatus);
                g_ScanCache.CleanupTimerId = 0;
            }
        } else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] ScanCache: TimerManager not available — periodic cleanup disabled\n");
            g_ScanCache.CleanupTimerId = 0;
        }
    }

    g_ScanCache.Initialized = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Scan cache initialized (%lu buckets)\n",
               SHADOWSTRIKE_CACHE_BUCKET_COUNT);

    return STATUS_SUCCESS;
}

VOID
ShadowStrikeCacheShutdown(
    VOID
    )
{
    LARGE_INTEGER timeout;

    PAGED_CODE();

    if (!g_ScanCache.Initialized) {
        return;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Shutting down scan cache\n");

    //
    // Step 1: Set shutdown flag to prevent new operations.
    // Use MemoryBarrier to ensure cross-CPU visibility before we cancel
    // timers and wait for references.
    //
    InterlockedExchange8((volatile CHAR*)&g_ScanCache.ShutdownInProgress, TRUE);
    MemoryBarrier();

    //
    // Step 2: Cancel the cleanup timer via TimerManager.
    // TmCancel with Wait=TRUE blocks until any in-flight callback completes,
    // replacing the old KeCancelTimer + KeFlushQueuedDpcs + spin-wait pattern.
    //
    if (g_ScanCache.CleanupTimerId != 0) {
        PTM_MANAGER timerManager = ShadowStrikeGetTimerManager();
        if (timerManager != NULL) {
            TmCancel(timerManager, g_ScanCache.CleanupTimerId, TRUE);
        }
        g_ScanCache.CleanupTimerId = 0;
    }

    //
    // Step 3: Wait for any active references (work item or operations in progress)
    //
    if (g_ScanCache.ActiveReferences > 0) {
        NTSTATUS waitStatus;

        //
        // Wait with timeout to prevent infinite hang.
        // 30 seconds should be more than enough for any operation.
        //
        timeout.QuadPart = -300000000LL;  // 30 seconds in 100-ns units

        waitStatus = KeWaitForSingleObject(
            &g_ScanCache.ShutdownEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout
        );

        if (waitStatus == STATUS_TIMEOUT) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike] ScanCache: CRITICAL — shutdown wait timed out "
                       "(ActiveReferences=%ld). Possible reference leak.\n",
                       g_ScanCache.ActiveReferences);
        }
    }

    //
    // Step 4: Wait for cleanup to complete if it's in progress (bounded)
    //
    {
        ULONG spinCount = 0;
        while (InterlockedCompareExchange(&g_ScanCache.CleanupInProgress, 0, 0) != 0) {
            LARGE_INTEGER interval;
            interval.QuadPart = -100000;  // 10ms
            KeDelayExecutionThread(KernelMode, FALSE, &interval);
            if (++spinCount > 3000) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                           "[ShadowStrike] ScanCache: Cleanup spin-wait exceeded 30s, forcing shutdown\n");
                break;
            }
        }
    }

    //
    // Step 5: Clear all entries
    //
    ShadowStrikeCacheClear();

    //
    // Step 6: Delete lookaside list
    //
    if (g_ScanCache.LookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_ScanCache.EntryLookaside);
        g_ScanCache.LookasideInitialized = FALSE;
    }

    g_ScanCache.Initialized = FALSE;

    //
    // Log final statistics (using integer math only - no floating point!)
    //
    {
        LONG64 totalLookups = g_ScanCache.Stats.TotalLookups;
        LONG64 hits = g_ScanCache.Stats.Hits;
        LONG64 misses = g_ScanCache.Stats.Misses;
        LONG hitRatePercent = 0;

        if (totalLookups > 0) {
            //
            // Integer percentage: (hits * 100) / totalLookups
            //
            hitRatePercent = (LONG)((hits * 100) / totalLookups);
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike] Scan cache shutdown complete "
                   "(Hits=%lld, Misses=%lld, HitRate=%ld%%)\n",
                   hits, misses, hitRatePercent);
    }
}

// ============================================================================
// CACHE OPERATIONS
// ============================================================================

BOOLEAN
ShadowStrikeCacheLookup(
    _In_ PSHADOWSTRIKE_CACHE_KEY Key,
    _Out_ PSHADOWSTRIKE_CACHE_RESULT Result
    )
{
    ULONG bucketIndex;
    PSHADOWSTRIKE_CACHE_BUCKET bucket;
    PSHADOWSTRIKE_CACHE_ENTRY entry;
    LARGE_INTEGER currentTime;
    BOOLEAN found = FALSE;

    //
    // Validate parameters (before any dereference)
    //
    if (Key == NULL || Result == NULL) {
        return FALSE;
    }

    //
    // Initialize result
    //
    RtlZeroMemory(Result, sizeof(SHADOWSTRIKE_CACHE_RESULT));

    //
    // Check if cache is ready
    //
    if (!g_ScanCache.Initialized || g_ScanCache.ShutdownInProgress) {
        return FALSE;
    }

    //
    // Validate g_DriverData is initialized before accessing Config
    //
    if (!g_DriverData.Initialized) {
        return FALSE;
    }

    //
    // Check if caching is enabled
    //
    if (!g_DriverData.Config.CacheEnabled) {
        return FALSE;
    }

    //
    // Acquire shutdown reference to prevent cache teardown while we hold
    // a bucket lock. Without this, shutdown can proceed and free entries
    // underneath us (TOCTOU between ShutdownInProgress check and lock).
    //
    if (!ShadowStrikeCacheAcquireReference()) {
        return FALSE;
    }

    //
    // Calculate bucket index
    //
    bucketIndex = ShadowStrikeCacheHash(Key) & SHADOWSTRIKE_CACHE_BUCKET_MASK;
    bucket = &g_ScanCache.Buckets[bucketIndex];

    //
    // Get current monotonic time for expiration check.
    // KeQueryInterruptTime is boot-relative and immune to NTP / clock adjustments,
    // preventing TTL bypass via wall-clock manipulation.
    //
    currentTime.QuadPart = (LONGLONG)KeQueryInterruptTime();

    //
    // Acquire bucket lock (shared for read)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&bucket->Lock);

    //
    // Search for entry
    //
    entry = ShadowStrikeCacheFindEntry(bucket, Key);

    if (entry != NULL && entry->Valid) {
        //
        // Check if entry has expired
        //
        if (currentTime.QuadPart < entry->ExpireTime.QuadPart) {
            //
            // Entry found and valid
            //
            Result->Found = TRUE;
            Result->Verdict = entry->Verdict;
            Result->ThreatScore = entry->ThreatScore;
            Result->HitCount = InterlockedIncrement(&entry->HitCount);
            found = TRUE;

            InterlockedIncrement64(&g_ScanCache.Stats.Hits);
        }
        // Expired entries will be cleaned up by periodic cleanup
    }

    ExReleasePushLockShared(&bucket->Lock);
    KeLeaveCriticalRegion();

    //
    // Update statistics
    //
    InterlockedIncrement64(&g_ScanCache.Stats.TotalLookups);
    if (!found) {
        InterlockedIncrement64(&g_ScanCache.Stats.Misses);
    }

    ShadowStrikeCacheReleaseReference();
    return found;
}

NTSTATUS
ShadowStrikeCacheInsert(
    _In_ PSHADOWSTRIKE_CACHE_KEY Key,
    _In_ SHADOWSTRIKE_SCAN_VERDICT Verdict,
    _In_ UINT8 ThreatScore,
    _In_ ULONG TTLSeconds
    )
{
    ULONG bucketIndex;
    PSHADOWSTRIKE_CACHE_BUCKET bucket;
    PSHADOWSTRIKE_CACHE_ENTRY entry;
    PSHADOWSTRIKE_CACHE_ENTRY existingEntry;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER ttlInterval;
    LONG currentEntries;
    ULONG clampedTTL;

    //
    // Validate parameters
    //
    if (Key == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate verdict enum range
    //
    if (!ShadowStrikeCacheIsValidVerdict(Verdict)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] ScanCache: Invalid verdict value %d\n",
                   (int)Verdict);
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Check if cache is ready
    //
    if (!g_ScanCache.Initialized || g_ScanCache.ShutdownInProgress) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Validate g_DriverData is initialized before accessing Config
    //
    if (!g_DriverData.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Check if caching is enabled
    //
    if (!g_DriverData.Config.CacheEnabled) {
        return STATUS_SUCCESS;
    }

    //
    // Acquire shutdown reference
    //
    if (!ShadowStrikeCacheAcquireReference()) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Check entry limit (soft cap — read is outside bucket lock for performance).
    // Multiple threads may pass this check simultaneously when near the limit,
    // allowing a bounded overshoot of at most (concurrent_insert_threads - 1)
    // entries. This is acceptable: the limit is a memory budget guard, not a
    // security boundary. Overshoot is bounded by CPU count (~64 max).
    //
    currentEntries = g_ScanCache.Stats.CurrentEntries;
    if (currentEntries >= SHADOWSTRIKE_CACHE_MAX_ENTRIES) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Cache full, not inserting new entry\n");
        ShadowStrikeCacheReleaseReference();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Calculate TTL with overflow protection
    //
    if (TTLSeconds == 0) {
        ttlInterval = g_ScanCache.TTLInterval;
    } else {
        //
        // Clamp TTL to prevent overflow
        //
        clampedTTL = (TTLSeconds > SHADOWSTRIKE_CACHE_MAX_TTL) ?
                     SHADOWSTRIKE_CACHE_MAX_TTL : TTLSeconds;
        ttlInterval.QuadPart = (LONGLONG)clampedTTL * 10000000LL;
    }

    //
    // Get current monotonic time (boot-relative, immune to clock adjustments)
    //
    currentTime.QuadPart = (LONGLONG)KeQueryInterruptTime();

    //
    // Calculate bucket index
    //
    bucketIndex = ShadowStrikeCacheHash(Key) & SHADOWSTRIKE_CACHE_BUCKET_MASK;
    bucket = &g_ScanCache.Buckets[bucketIndex];

    //
    // Acquire bucket lock (exclusive for write)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&bucket->Lock);

    //
    // Check if entry already exists
    //
    existingEntry = ShadowStrikeCacheFindEntry(bucket, Key);

    if (existingEntry != NULL) {
        //
        // Update existing entry
        //
        existingEntry->Verdict = Verdict;
        existingEntry->ThreatScore = ThreatScore;
        existingEntry->CreateTime = currentTime;
        existingEntry->ExpireTime.QuadPart = currentTime.QuadPart + ttlInterval.QuadPart;
        existingEntry->Valid = TRUE;

        ExReleasePushLockExclusive(&bucket->Lock);
        KeLeaveCriticalRegion();

        ShadowStrikeCacheReleaseReference();
        return STATUS_SUCCESS;
    }

    //
    // Allocate new entry from lookaside list
    //
    entry = (PSHADOWSTRIKE_CACHE_ENTRY)ExAllocateFromNPagedLookasideList(
        &g_ScanCache.EntryLookaside
    );

    if (entry == NULL) {
        ExReleasePushLockExclusive(&bucket->Lock);
        KeLeaveCriticalRegion();
        ShadowStrikeCacheReleaseReference();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize entry
    //
    RtlZeroMemory(entry, sizeof(SHADOWSTRIKE_CACHE_ENTRY));
    RtlCopyMemory(&entry->Key, Key, sizeof(SHADOWSTRIKE_CACHE_KEY));
    entry->Verdict = Verdict;
    entry->ThreatScore = ThreatScore;
    entry->Valid = TRUE;
    entry->CreateTime = currentTime;
    entry->ExpireTime.QuadPart = currentTime.QuadPart + ttlInterval.QuadPart;
    entry->HitCount = 0;

    //
    // Insert into bucket
    //
    InsertHeadList(&bucket->ListHead, &entry->ListEntry);
    InterlockedIncrement(&bucket->EntryCount);

    ExReleasePushLockExclusive(&bucket->Lock);
    KeLeaveCriticalRegion();

    //
    // Update global statistics using proper atomic peak update
    //
    currentEntries = InterlockedIncrement(&g_ScanCache.Stats.CurrentEntries);
    ShadowStrikeCacheUpdatePeak(&g_ScanCache.Stats.PeakEntries, currentEntries);
    InterlockedIncrement64(&g_ScanCache.Stats.Inserts);

    ShadowStrikeCacheReleaseReference();
    return STATUS_SUCCESS;
}

BOOLEAN
ShadowStrikeCacheRemove(
    _In_ PSHADOWSTRIKE_CACHE_KEY Key
    )
{
    ULONG bucketIndex;
    PSHADOWSTRIKE_CACHE_BUCKET bucket;
    PSHADOWSTRIKE_CACHE_ENTRY entry;
    BOOLEAN removed = FALSE;

    if (Key == NULL || !g_ScanCache.Initialized) {
        return FALSE;
    }

    if (!ShadowStrikeCacheAcquireReference()) {
        return FALSE;
    }

    bucketIndex = ShadowStrikeCacheHash(Key) & SHADOWSTRIKE_CACHE_BUCKET_MASK;
    bucket = &g_ScanCache.Buckets[bucketIndex];

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&bucket->Lock);

    entry = ShadowStrikeCacheFindEntry(bucket, Key);

    if (entry != NULL) {
        //
        // Remove from list
        //
        RemoveEntryList(&entry->ListEntry);
        InterlockedDecrement(&bucket->EntryCount);

        //
        // Free entry WHILE holding lock to prevent use-after-free.
        // Another thread cannot access this entry once removed from list
        // and we still hold the exclusive lock.
        //
        ShadowStrikeCacheFreeEntry(entry);
        removed = TRUE;
    }

    ExReleasePushLockExclusive(&bucket->Lock);
    KeLeaveCriticalRegion();

    if (removed) {
        InterlockedDecrement(&g_ScanCache.Stats.CurrentEntries);
        InterlockedIncrement64(&g_ScanCache.Stats.Evictions);
    }

    ShadowStrikeCacheReleaseReference();
    return removed;
}

ULONG
ShadowStrikeCacheInvalidateVolume(
    _In_ ULONG VolumeSerial
    )
{
    ULONG i;
    ULONG removedCount = 0;
    PLIST_ENTRY listEntry;
    PLIST_ENTRY nextEntry;
    PSHADOWSTRIKE_CACHE_ENTRY entry;
    LIST_ENTRY removeList;

    if (!g_ScanCache.Initialized) {
        return 0;
    }

    if (!ShadowStrikeCacheAcquireReference()) {
        return 0;
    }

    InitializeListHead(&removeList);

    //
    // Iterate all buckets
    //
    for (i = 0; i < SHADOWSTRIKE_CACHE_BUCKET_COUNT; i++) {
        PSHADOWSTRIKE_CACHE_BUCKET bucket = &g_ScanCache.Buckets[i];

        //
        // Skip empty buckets (quick check without lock)
        //
        if (bucket->EntryCount == 0) {
            continue;
        }

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&bucket->Lock);

        for (listEntry = bucket->ListHead.Flink;
             listEntry != &bucket->ListHead;
             listEntry = nextEntry) {

            nextEntry = listEntry->Flink;
            entry = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_CACHE_ENTRY, ListEntry);

            if (entry->Key.VolumeSerial == VolumeSerial) {
                RemoveEntryList(listEntry);
                InterlockedDecrement(&bucket->EntryCount);
                InsertTailList(&removeList, listEntry);
                removedCount++;
            }
        }

        ExReleasePushLockExclusive(&bucket->Lock);
        KeLeaveCriticalRegion();
    }

    //
    // Free removed entries (outside of locks)
    //
    while (!IsListEmpty(&removeList)) {
        listEntry = RemoveHeadList(&removeList);
        entry = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_CACHE_ENTRY, ListEntry);
        ShadowStrikeCacheFreeEntry(entry);
    }

    if (removedCount > 0) {
        InterlockedAdd(&g_ScanCache.Stats.CurrentEntries, -(LONG)removedCount);
        InterlockedAdd64(&g_ScanCache.Stats.Evictions, removedCount);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike] Invalidated %lu cache entries for volume 0x%08X\n",
                   removedCount, VolumeSerial);
    }

    ShadowStrikeCacheReleaseReference();
    return removedCount;
}

VOID
ShadowStrikeCacheClear(
    VOID
    )
{
    ULONG i;
    ULONG totalRemoved = 0;
    PLIST_ENTRY listEntry;
    PSHADOWSTRIKE_CACHE_ENTRY entry;
    LIST_ENTRY removeList;

    PAGED_CODE();

    if (!g_ScanCache.Initialized && !g_ScanCache.ShutdownInProgress) {
        return;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Clearing scan cache\n");

    for (i = 0; i < SHADOWSTRIKE_CACHE_BUCKET_COUNT; i++) {
        PSHADOWSTRIKE_CACHE_BUCKET bucket = &g_ScanCache.Buckets[i];

        //
        // Skip empty buckets (quick check without lock)
        //
        if (bucket->EntryCount == 0) {
            continue;
        }

        InitializeListHead(&removeList);

        //
        // Collect entries under exclusive lock, then free outside lock.
        // This matches the pattern in Cleanup/InvalidateVolume and
        // minimizes exclusive lock hold time.
        //
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&bucket->Lock);

        while (!IsListEmpty(&bucket->ListHead)) {
            listEntry = RemoveHeadList(&bucket->ListHead);
            InsertTailList(&removeList, listEntry);
            totalRemoved++;
        }

        bucket->EntryCount = 0;

        ExReleasePushLockExclusive(&bucket->Lock);
        KeLeaveCriticalRegion();

        //
        // Free entries outside lock
        //
        while (!IsListEmpty(&removeList)) {
            listEntry = RemoveHeadList(&removeList);
            entry = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_CACHE_ENTRY, ListEntry);
            ShadowStrikeCacheFreeEntry(entry);
        }
    }

    InterlockedExchange(&g_ScanCache.Stats.CurrentEntries, 0);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Cache cleared (%lu entries removed)\n", totalRemoved);
}

VOID
ShadowStrikeCacheCleanup(
    VOID
    )
{
    ULONG i;
    ULONG expiredCount = 0;
    LARGE_INTEGER currentTime;
    PLIST_ENTRY listEntry;
    PLIST_ENTRY nextEntry;
    PSHADOWSTRIKE_CACHE_ENTRY entry;
    LIST_ENTRY removeList;

    PAGED_CODE();

    if (!g_ScanCache.Initialized || g_ScanCache.ShutdownInProgress) {
        return;
    }

    //
    // Prevent concurrent cleanup
    //
    if (InterlockedCompareExchange(&g_ScanCache.CleanupInProgress, 1, 0) != 0) {
        return;
    }

    currentTime.QuadPart = (LONGLONG)KeQueryInterruptTime();
    InitializeListHead(&removeList);

    //
    // Scan all buckets for expired entries
    //
    for (i = 0; i < SHADOWSTRIKE_CACHE_BUCKET_COUNT; i++) {
        PSHADOWSTRIKE_CACHE_BUCKET bucket = &g_ScanCache.Buckets[i];

        //
        // Skip empty buckets
        //
        if (bucket->EntryCount == 0) {
            continue;
        }

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&bucket->Lock);

        for (listEntry = bucket->ListHead.Flink;
             listEntry != &bucket->ListHead;
             listEntry = nextEntry) {

            nextEntry = listEntry->Flink;
            entry = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_CACHE_ENTRY, ListEntry);

            //
            // Check if expired
            //
            if (currentTime.QuadPart >= entry->ExpireTime.QuadPart) {
                RemoveEntryList(listEntry);
                InterlockedDecrement(&bucket->EntryCount);
                InsertTailList(&removeList, listEntry);
                expiredCount++;
            }
        }

        ExReleasePushLockExclusive(&bucket->Lock);
        KeLeaveCriticalRegion();
    }

    //
    // Free expired entries (outside of locks)
    //
    while (!IsListEmpty(&removeList)) {
        listEntry = RemoveHeadList(&removeList);
        entry = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_CACHE_ENTRY, ListEntry);
        ShadowStrikeCacheFreeEntry(entry);
    }

    //
    // Update statistics
    //
    if (expiredCount > 0) {
        InterlockedAdd(&g_ScanCache.Stats.CurrentEntries, -(LONG)expiredCount);
        InterlockedAdd64(&g_ScanCache.Stats.CleanupEvictions, expiredCount);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                   "[ShadowStrike] Cache cleanup: %lu expired entries removed\n",
                   expiredCount);
    }

    InterlockedIncrement64(&g_ScanCache.Stats.CleanupCycles);
    InterlockedExchange(&g_ScanCache.CleanupInProgress, 0);
}

// ============================================================================
// STATISTICS
// ============================================================================

VOID
ShadowStrikeCacheGetStats(
    _Out_ PSHADOWSTRIKE_CACHE_STATS Stats
    )
{
    if (Stats == NULL) {
        return;
    }

    //
    // Use atomic reads for 64-bit values to ensure consistency
    // InterlockedCompareExchange64 returns the current value atomically
    //
    Stats->TotalLookups = InterlockedCompareExchange64(
        &g_ScanCache.Stats.TotalLookups, 0, 0);
    Stats->Hits = InterlockedCompareExchange64(
        &g_ScanCache.Stats.Hits, 0, 0);
    Stats->Misses = InterlockedCompareExchange64(
        &g_ScanCache.Stats.Misses, 0, 0);
    Stats->Inserts = InterlockedCompareExchange64(
        &g_ScanCache.Stats.Inserts, 0, 0);
    Stats->Evictions = InterlockedCompareExchange64(
        &g_ScanCache.Stats.Evictions, 0, 0);
    Stats->CleanupCycles = InterlockedCompareExchange64(
        &g_ScanCache.Stats.CleanupCycles, 0, 0);
    Stats->CleanupEvictions = InterlockedCompareExchange64(
        &g_ScanCache.Stats.CleanupEvictions, 0, 0);

    //
    // 32-bit values are naturally atomic on x86/x64
    //
    Stats->CurrentEntries = g_ScanCache.Stats.CurrentEntries;
    Stats->PeakEntries = g_ScanCache.Stats.PeakEntries;
}

VOID
ShadowStrikeCacheResetStats(
    VOID
    )
{
    InterlockedExchange64(&g_ScanCache.Stats.TotalLookups, 0);
    InterlockedExchange64(&g_ScanCache.Stats.Hits, 0);
    InterlockedExchange64(&g_ScanCache.Stats.Misses, 0);
    InterlockedExchange64(&g_ScanCache.Stats.Inserts, 0);
    InterlockedExchange64(&g_ScanCache.Stats.Evictions, 0);
    InterlockedExchange64(&g_ScanCache.Stats.CleanupCycles, 0);
    InterlockedExchange64(&g_ScanCache.Stats.CleanupEvictions, 0);
    // Don't reset CurrentEntries or PeakEntries as they reflect actual state
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

NTSTATUS
ShadowStrikeCacheBuildKey(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PSHADOWSTRIKE_CACHE_KEY Key
    )
{
    NTSTATUS status;
    FILE_INTERNAL_INFORMATION internalInfo;
    FILE_BASIC_INFORMATION basicInfo;
    FILE_STANDARD_INFORMATION stdInfo;
    BOOLEAN haveFileId = FALSE;
    BOOLEAN haveWriteTime = FALSE;
    BOOLEAN haveFileSize = FALSE;
    BOOLEAN haveVolumeSerial = FALSE;

    PAGED_CODE();

    if (FltObjects == NULL || Key == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (FltObjects->Instance == NULL || FltObjects->FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Key, sizeof(SHADOWSTRIKE_CACHE_KEY));

    //
    // Get file ID (REQUIRED)
    //
    status = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &internalInfo,
        sizeof(internalInfo),
        FileInternalInformation,
        NULL
    );

    if (NT_SUCCESS(status)) {
        Key->FileId = internalInfo.IndexNumber.QuadPart;
        haveFileId = TRUE;
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] ScanCache: Failed to get FileId, status=0x%08X\n",
                   status);
    }

    //
    // Get basic info (last write time) (REQUIRED)
    //
    status = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &basicInfo,
        sizeof(basicInfo),
        FileBasicInformation,
        NULL
    );

    if (NT_SUCCESS(status)) {
        Key->LastWriteTime = basicInfo.LastWriteTime;
        haveWriteTime = TRUE;
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] ScanCache: Failed to get LastWriteTime, status=0x%08X\n",
                   status);
    }

    //
    // Get file size (REQUIRED)
    //
    status = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &stdInfo,
        sizeof(stdInfo),
        FileStandardInformation,
        NULL
    );

    if (NT_SUCCESS(status)) {
        Key->FileSize = stdInfo.EndOfFile.QuadPart;
        haveFileSize = TRUE;
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] ScanCache: Failed to get FileSize, status=0x%08X\n",
                   status);
    }

    //
    // Get proper volume serial number (REQUIRED)
    // Primary: FltQueryVolumeInformation gets the real NTFS/FAT volume serial.
    // Fallback: Derive from volume properties (weak but usable).
    //
    if (FltObjects->Volume != NULL) {
        //
        // Primary: Get actual volume serial number from filesystem metadata
        //
        {
            FILE_FS_VOLUME_INFORMATION volumeInfo;
            IO_STATUS_BLOCK ioStatus;

            status = FltQueryVolumeInformation(
                FltObjects->Instance,
                &ioStatus,
                &volumeInfo,
                sizeof(volumeInfo),
                FileFsVolumeInformation
            );

            if (NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW) {
                //
                // STATUS_BUFFER_OVERFLOW is acceptable — the fixed-size fields
                // (including VolumeSerialNumber) are populated before the
                // variable-length VolumeLabel.
                //
                Key->VolumeSerial = volumeInfo.VolumeSerialNumber;
                haveVolumeSerial = TRUE;
            }
        }

        //
        // SECURITY FIX: No fallback. If the real volume serial is unavailable,
        // caching is disabled for this file. The previous fallback derived a
        // pseudo-serial from DeviceCharacteristics XOR SectorSize, which is
        // NOT unique across volumes and enables cache poisoning via key collision.
        // For an NGAV product, fail-secure: no unique ID → no caching.
        //
        if (!haveVolumeSerial) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] ScanCache: Real volume serial unavailable — "
                       "caching disabled for this file (fail-secure)\n");
        }
    }

    //
    // SECURITY: All required fields must be populated
    // If any field is missing, the key is not reliable and could cause
    // cache collisions leading to security bypass
    //
    if (!haveFileId || !haveWriteTime || !haveFileSize || !haveVolumeSerial) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] ScanCache: Incomplete key (FileId=%d, WriteTime=%d, "
                   "Size=%d, Volume=%d)\n",
                   haveFileId, haveWriteTime, haveFileSize, haveVolumeSerial);
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

static
BOOLEAN
ShadowStrikeCacheKeyEquals(
    _In_ PSHADOWSTRIKE_CACHE_KEY Key1,
    _In_ PSHADOWSTRIKE_CACHE_KEY Key2
    )
{
    return (Key1->VolumeSerial == Key2->VolumeSerial &&
            Key1->FileId == Key2->FileId &&
            Key1->FileSize == Key2->FileSize &&
            Key1->LastWriteTime.QuadPart == Key2->LastWriteTime.QuadPart);
}

static
PSHADOWSTRIKE_CACHE_ENTRY
ShadowStrikeCacheFindEntry(
    _In_ PSHADOWSTRIKE_CACHE_BUCKET Bucket,
    _In_ PSHADOWSTRIKE_CACHE_KEY Key
    )
{
    PLIST_ENTRY listEntry;
    PSHADOWSTRIKE_CACHE_ENTRY entry;

    for (listEntry = Bucket->ListHead.Flink;
         listEntry != &Bucket->ListHead;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_CACHE_ENTRY, ListEntry);

        if (ShadowStrikeCacheKeyEquals(&entry->Key, Key)) {
            return entry;
        }
    }

    return NULL;
}

static
VOID
ShadowStrikeCacheFreeEntry(
    _In_ PSHADOWSTRIKE_CACHE_ENTRY Entry
    )
{
    if (Entry != NULL && g_ScanCache.LookasideInitialized) {
        ExFreeToNPagedLookasideList(&g_ScanCache.EntryLookaside, Entry);
    }
}

// ============================================================================
// TIMER/DPC CALLBACKS
// ============================================================================

static
VOID
ShadowStrikeCacheCleanupTimerCallback(
    _In_ ULONG TimerId,
    _In_opt_ PVOID Context
    )
/*++

Routine Description:

    TimerManager callback for periodic cache cleanup. Runs at PASSIVE_LEVEL
    via TmFlag_WorkItemCallback. Replaces the old DPC->IoWorkItem pattern.

    NOTE: This function must NOT touch CleanupInProgress — that guard is
    owned exclusively by ShadowStrikeCacheCleanup(). Previous code set it
    here, causing ShadowStrikeCacheCleanup to see it as 1 and return
    immediately, making periodic cleanup a no-op.

--*/
{
    UNREFERENCED_PARAMETER(TimerId);
    UNREFERENCED_PARAMETER(Context);

    //
    // Check shutdown flag
    //
    if (g_ScanCache.ShutdownInProgress) {
        return;
    }

    if (!g_ScanCache.Initialized) {
        return;
    }

    //
    // Acquire reference for shutdown synchronization
    //
    if (!ShadowStrikeCacheAcquireReference()) {
        return;
    }

    //
    // Perform cleanup at PASSIVE_LEVEL (guaranteed by TmFlag_WorkItemCallback).
    // ShadowStrikeCacheCleanup owns the CleanupInProgress re-entrancy guard.
    //
    ShadowStrikeCacheCleanup();

    ShadowStrikeCacheReleaseReference();
}
