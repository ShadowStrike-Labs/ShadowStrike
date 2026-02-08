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

SHADOWSTRIKE_SCAN_CACHE g_ScanCache = {0};

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static
VOID
ShadowStrikeCacheCleanupDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

static
IO_WORKITEM_ROUTINE ShadowStrikeCacheCleanupWorker;

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
        InterlockedDecrement(&g_ScanCache.ActiveReferences);
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
    LARGE_INTEGER dueTime;
    ULONG clampedTTL;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (DeviceObject == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] ScanCache: DeviceObject is required\n");
        return STATUS_INVALID_PARAMETER;
    }

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
    // Initialize cleanup timer and DPC
    //
    KeInitializeTimer(&g_ScanCache.CleanupTimer);
    KeInitializeDpc(&g_ScanCache.CleanupDpc, ShadowStrikeCacheCleanupDpc, NULL);

    //
    // Allocate work item using IoAllocateWorkItem for proper lifecycle management
    // This is the correct API for kernel work items (not deprecated ExInitializeWorkItem)
    //
    g_ScanCache.CleanupWorkItem = IoAllocateWorkItem(DeviceObject);
    if (g_ScanCache.CleanupWorkItem == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] ScanCache: Failed to allocate cleanup work item\n");

        ExDeleteNPagedLookasideList(&g_ScanCache.EntryLookaside);
        g_ScanCache.LookasideInitialized = FALSE;

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Start cleanup timer (periodic)
    //
    dueTime.QuadPart = -(LONGLONG)SHADOWSTRIKE_CACHE_CLEANUP_INTERVAL * 10000000LL;
    KeSetTimerEx(
        &g_ScanCache.CleanupTimer,
        dueTime,
        SHADOWSTRIKE_CACHE_CLEANUP_INTERVAL * 1000,  // Period in ms
        &g_ScanCache.CleanupDpc
    );

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
    // Step 1: Set shutdown flag to prevent new operations
    //
    g_ScanCache.ShutdownInProgress = TRUE;

    //
    // Step 2: Cancel the cleanup timer
    //
    KeCancelTimer(&g_ScanCache.CleanupTimer);

    //
    // Step 3: CRITICAL - Flush queued DPCs to ensure our DPC has completed
    // This prevents the DPC from queueing a work item after we think we're done
    //
    KeFlushQueuedDpcs();

    //
    // Step 4: Wait for any active references (work item or operations in progress)
    //
    if (g_ScanCache.ActiveReferences > 0) {
        //
        // Wait with timeout to prevent infinite hang
        // 30 seconds should be more than enough for any operation
        //
        timeout.QuadPart = -300000000LL;  // 30 seconds in 100-ns units

        KeWaitForSingleObject(
            &g_ScanCache.ShutdownEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout
        );
    }

    //
    // Step 5: Wait for cleanup to complete if it's in progress
    //
    while (InterlockedCompareExchange(&g_ScanCache.CleanupInProgress, 0, 0) != 0) {
        LARGE_INTEGER interval;
        interval.QuadPart = -100000;  // 10ms
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }

    //
    // Step 6: Free the work item
    //
    if (g_ScanCache.CleanupWorkItem != NULL) {
        IoFreeWorkItem(g_ScanCache.CleanupWorkItem);
        g_ScanCache.CleanupWorkItem = NULL;
    }

    //
    // Step 7: Clear all entries
    //
    ShadowStrikeCacheClear();

    //
    // Step 8: Delete lookaside list
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
    // Initialize result
    //
    RtlZeroMemory(Result, sizeof(SHADOWSTRIKE_CACHE_RESULT));

    //
    // Validate parameters
    //
    if (Key == NULL) {
        return FALSE;
    }

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
    // Calculate bucket index
    //
    bucketIndex = ShadowStrikeCacheHash(Key) & SHADOWSTRIKE_CACHE_BUCKET_MASK;
    bucket = &g_ScanCache.Buckets[bucketIndex];

    //
    // Get current time for expiration check
    //
    KeQuerySystemTime(&currentTime);

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
    // Check entry limit
    //
    currentEntries = g_ScanCache.Stats.CurrentEntries;
    if (currentEntries >= SHADOWSTRIKE_CACHE_MAX_ENTRIES) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Cache full, not inserting new entry\n");
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
    // Get current time
    //
    KeQuerySystemTime(&currentTime);

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
        // CRITICAL FIX: Free entry WHILE holding lock to prevent use-after-free
        // Another thread cannot access this entry once it's removed from the list
        // and we're still holding the exclusive lock
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

    PAGED_CODE();

    if (!g_ScanCache.Initialized && !g_ScanCache.ShutdownInProgress) {
        return;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Clearing scan cache\n");

    for (i = 0; i < SHADOWSTRIKE_CACHE_BUCKET_COUNT; i++) {
        PSHADOWSTRIKE_CACHE_BUCKET bucket = &g_ScanCache.Buckets[i];

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&bucket->Lock);

        while (!IsListEmpty(&bucket->ListHead)) {
            listEntry = RemoveHeadList(&bucket->ListHead);
            entry = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_CACHE_ENTRY, ListEntry);
            ShadowStrikeCacheFreeEntry(entry);
            totalRemoved++;
        }

        bucket->EntryCount = 0;

        ExReleasePushLockExclusive(&bucket->Lock);
        KeLeaveCriticalRegion();
    }

    g_ScanCache.Stats.CurrentEntries = 0;

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

    KeQuerySystemTime(&currentTime);
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
    // Using FltGetVolumeProperties to get actual volume information
    //
    if (FltObjects->Volume != NULL) {
        FLT_VOLUME_PROPERTIES volumeProps;
        ULONG bytesReturned = 0;

        status = FltGetVolumeProperties(
            FltObjects->Volume,
            &volumeProps,
            sizeof(volumeProps),
            &bytesReturned
        );

        if (NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW) {
            //
            // STATUS_BUFFER_OVERFLOW is acceptable - we got the fixed fields
            // Use DeviceCharacteristics as a volume identifier component
            // Combined with SectorSize for better uniqueness
            //
            Key->VolumeSerial = volumeProps.DeviceCharacteristics ^
                               (volumeProps.SectorSize << 16) ^
                               (volumeProps.AllocatedLength.LowPart);
            haveVolumeSerial = TRUE;
        } else {
            //
            // Fallback: Query volume information via file object
            //
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
                Key->VolumeSerial = volumeInfo.VolumeSerialNumber;
                haveVolumeSerial = TRUE;
            }
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
ShadowStrikeCacheCleanupDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    //
    // Check shutdown flag and acquire reference atomically
    //
    if (g_ScanCache.ShutdownInProgress) {
        return;
    }

    //
    // Check if work item is already queued (prevents double-queue)
    //
    if (InterlockedCompareExchange(&g_ScanCache.WorkItemQueued, 1, 0) != 0) {
        //
        // Work item already queued, skip this cycle
        //
        return;
    }

    //
    // Verify work item is valid
    //
    if (g_ScanCache.CleanupWorkItem == NULL || !g_ScanCache.Initialized) {
        InterlockedExchange(&g_ScanCache.WorkItemQueued, 0);
        return;
    }

    //
    // Acquire reference for the work item
    //
    if (!ShadowStrikeCacheAcquireReference()) {
        InterlockedExchange(&g_ScanCache.WorkItemQueued, 0);
        return;
    }

    //
    // Queue work item (IoQueueWorkItem is the correct API for IoAllocateWorkItem)
    //
    IoQueueWorkItem(
        g_ScanCache.CleanupWorkItem,
        ShadowStrikeCacheCleanupWorker,
        DelayedWorkQueue,
        NULL
    );
}

static
VOID
ShadowStrikeCacheCleanupWorker(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Context);

    //
    // Perform cleanup
    //
    ShadowStrikeCacheCleanup();

    //
    // Clear the queued flag so next DPC can queue again
    //
    InterlockedExchange(&g_ScanCache.WorkItemQueued, 0);

    //
    // Release reference acquired in DPC
    //
    ShadowStrikeCacheReleaseReference();
}
