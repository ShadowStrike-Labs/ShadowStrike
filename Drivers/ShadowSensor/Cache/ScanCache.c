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
 * BSOD PREVENTION:
 * - All pointer parameters validated before use
 * - All locks acquired with proper IRQL awareness
 * - Lookaside list for predictable memory allocation
 * - Fail-safe on any allocation failure
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
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
VOID
ShadowStrikeCacheCleanupWorker(
    _In_ PVOID Context
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

// ============================================================================
// INITIALIZATION / SHUTDOWN
// ============================================================================

NTSTATUS
ShadowStrikeCacheInitialize(
    _In_ ULONG TTLSeconds
    )
{
    ULONG i;
    LARGE_INTEGER dueTime;

    PAGED_CODE();

    if (g_ScanCache.Initialized) {
        return STATUS_SUCCESS;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Initializing scan cache (TTL=%lu seconds)\n",
               TTLSeconds);

    RtlZeroMemory(&g_ScanCache, sizeof(g_ScanCache));

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
    //
    if (TTLSeconds == 0) {
        TTLSeconds = SHADOWSTRIKE_CACHE_DEFAULT_TTL;
    }
    g_ScanCache.TTLInterval.QuadPart = (LONGLONG)TTLSeconds * 10000000LL;

    //
    // Initialize cleanup timer and DPC
    //
    KeInitializeTimer(&g_ScanCache.CleanupTimer);
    KeInitializeDpc(&g_ScanCache.CleanupDpc, ShadowStrikeCacheCleanupDpc, NULL);

    //
    // Initialize work item for cleanup (runs at PASSIVE_LEVEL)
    // Using legacy ExInitializeWorkItem which doesn't require a DeviceObject
    // (minifilters don't have a DeviceObject)
    //
    ExInitializeWorkItem(
        &g_ScanCache.CleanupWorkItem,
        ShadowStrikeCacheCleanupWorker,
        NULL
    );
    g_ScanCache.WorkItemInitialized = TRUE;

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
    PAGED_CODE();

    if (!g_ScanCache.Initialized) {
        return;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Shutting down scan cache\n");

    //
    // Cancel cleanup timer
    //
    KeCancelTimer(&g_ScanCache.CleanupTimer);

    //
    // Wait for any cleanup in progress
    //
    while (InterlockedCompareExchange(&g_ScanCache.CleanupInProgress, 0, 0) != 0) {
        LARGE_INTEGER interval;
        interval.QuadPart = -100000;  // 10ms
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }

    //
    // Mark work item as not initialized (ExInitializeWorkItem doesn't allocate,
    // so there's nothing to free - just prevent further queuing)
    //
    g_ScanCache.WorkItemInitialized = FALSE;

    //
    // Clear all entries
    //
    ShadowStrikeCacheClear();

    //
    // Delete lookaside list
    //
    if (g_ScanCache.LookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_ScanCache.EntryLookaside);
        g_ScanCache.LookasideInitialized = FALSE;
    }

    g_ScanCache.Initialized = FALSE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Scan cache shutdown complete "
               "(Hits=%lld, Misses=%lld, HitRate=%.1f%%)\n",
               g_ScanCache.Stats.Hits,
               g_ScanCache.Stats.Misses,
               g_ScanCache.Stats.TotalLookups > 0 ?
                   (double)g_ScanCache.Stats.Hits * 100.0 / g_ScanCache.Stats.TotalLookups : 0.0);
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
    if (Key == NULL || !g_ScanCache.Initialized) {
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
    _In_ SHADOWSTRIKE_VERDICT Verdict,
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

    //
    // Validate parameters
    //
    if (Key == NULL || !g_ScanCache.Initialized) {
        return STATUS_INVALID_PARAMETER;
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
    // Calculate TTL
    //
    if (TTLSeconds == 0) {
        ttlInterval = g_ScanCache.TTLInterval;
    } else {
        ttlInterval.QuadPart = (LONGLONG)TTLSeconds * 10000000LL;
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
    // Update global statistics
    //
    currentEntries = InterlockedIncrement(&g_ScanCache.Stats.CurrentEntries);
    if (currentEntries > g_ScanCache.Stats.PeakEntries) {
        InterlockedExchange(&g_ScanCache.Stats.PeakEntries, currentEntries);
    }
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
        RemoveEntryList(&entry->ListEntry);
        InterlockedDecrement(&bucket->EntryCount);
        removed = TRUE;
    }

    ExReleasePushLockExclusive(&bucket->Lock);
    KeLeaveCriticalRegion();

    if (removed && entry != NULL) {
        ShadowStrikeCacheFreeEntry(entry);
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
    // Free removed entries
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

    if (!g_ScanCache.Initialized) {
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

    if (!g_ScanCache.Initialized) {
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

    Stats->TotalLookups = g_ScanCache.Stats.TotalLookups;
    Stats->Hits = g_ScanCache.Stats.Hits;
    Stats->Misses = g_ScanCache.Stats.Misses;
    Stats->Inserts = g_ScanCache.Stats.Inserts;
    Stats->Evictions = g_ScanCache.Stats.Evictions;
    Stats->CurrentEntries = g_ScanCache.Stats.CurrentEntries;
    Stats->PeakEntries = g_ScanCache.Stats.PeakEntries;
    Stats->CleanupCycles = g_ScanCache.Stats.CleanupCycles;
    Stats->CleanupEvictions = g_ScanCache.Stats.CleanupEvictions;
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

    if (FltObjects == NULL || Key == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Key, sizeof(SHADOWSTRIKE_CACHE_KEY));

    //
    // Get file ID
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
    }

    //
    // Get basic info (last write time)
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
    }

    //
    // Get file size
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
    }

    //
    // Get volume serial (from volume properties if available)
    // For simplicity, use a hash of the volume name or device object
    //
    if (FltObjects->Volume != NULL) {
        Key->VolumeSerial = (ULONG)(ULONG_PTR)FltObjects->Volume;
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
    // Queue work item to run cleanup at PASSIVE_LEVEL
    // Using legacy ExQueueWorkItem which doesn't require a DeviceObject
    //
    if (g_ScanCache.WorkItemInitialized && g_ScanCache.Initialized) {
        //
        // Re-initialize the work item before each queue
        // (required for ExQueueWorkItem - work items are single-use)
        //
        ExInitializeWorkItem(
            &g_ScanCache.CleanupWorkItem,
            ShadowStrikeCacheCleanupWorker,
            NULL
        );
        ExQueueWorkItem(&g_ScanCache.CleanupWorkItem, DelayedWorkQueue);
    }
}

static
VOID
ShadowStrikeCacheCleanupWorker(
    _In_ PVOID Context
    )
{
    UNREFERENCED_PARAMETER(Context);

    ShadowStrikeCacheCleanup();
}
