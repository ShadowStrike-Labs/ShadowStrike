/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE CACHE OPTIMIZATION ENGINE
 * ============================================================================
 *
 * @file CacheOptimization.c
 * @brief High-performance, lock-optimized caching infrastructure for kernel EDR.
 *
 * Implementation provides CrowdStrike Falcon-class caching with:
 * - Multiple cache types (Process, File Hash, Module, Verdict, IOC, Network)
 * - O(1) hash-based lookups with configurable bucket counts
 * - LRU eviction with aging and TTL expiration
 * - Fine-grained per-bucket locking (reader-writer)
 * - Memory pressure handling with adaptive eviction
 * - Cache sharding for reduced lock contention
 * - Statistics and hit-rate monitoring
 * - Automatic background maintenance
 * - Zero-copy data access patterns
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "CacheOptimization.h"
#include "../Utilities/MemoryUtils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, CoInitialize)
#pragma alloc_text(PAGE, CoShutdown)
#pragma alloc_text(PAGE, CoCreateCache)
#pragma alloc_text(PAGE, CoDestroyCache)
#endif

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

#define CO_MANAGER_MAGIC            0x434F4D47  // 'COMG'
#define CO_CACHE_MAGIC              0x434F4348  // 'COCH'
#define CO_ENTRY_MAGIC              0x434F454E  // 'COEN'

#define CO_DEFAULT_MAX_MEMORY       (256 * 1024 * 1024)  // 256 MB default

#define CO_100NS_PER_SECOND         10000000LL
#define CO_100NS_PER_MS             10000LL

// ============================================================================
// INTERNAL FUNCTION PROTOTYPES
// ============================================================================

static
NTSTATUS
CopAllocateEntry(
    _In_ PCO_CACHE Cache,
    _Out_ PCO_CACHE_ENTRY* Entry
    );

static
VOID
CopFreeEntry(
    _In_ PCO_CACHE Cache,
    _In_ PCO_CACHE_ENTRY Entry
    );

static
PCO_CACHE_ENTRY
CopFindEntryInBucket(
    _In_ PCO_CACHE Cache,
    _In_ ULONG BucketIndex,
    _In_ ULONG64 Key
    );

static
VOID
CopInsertIntoLRU(
    _In_ PCO_CACHE Cache,
    _In_ PCO_CACHE_ENTRY Entry
    );

static
VOID
CopRemoveFromLRU(
    _In_ PCO_CACHE Cache,
    _In_ PCO_CACHE_ENTRY Entry
    );

static
VOID
CopPromoteInLRU(
    _In_ PCO_CACHE Cache,
    _In_ PCO_CACHE_ENTRY Entry
    );

static
VOID
CopEvictLRUEntry(
    _In_ PCO_CACHE Cache,
    _In_ PCO_CACHE_SHARD* Shard
    );

static
BOOLEAN
CopIsEntryExpired(
    _In_ PCO_CACHE_ENTRY Entry,
    _In_ PLARGE_INTEGER CurrentTime
    );

static
VOID
CopUpdateAccessTime(
    _In_ PCO_CACHE_ENTRY Entry
    );

static
VOID
CopCallCleanupCallback(
    _In_ PCO_CACHE Cache,
    _In_ PCO_CACHE_ENTRY Entry
    );

static
VOID
CopRemoveEntryFromCache(
    _In_ PCO_CACHE Cache,
    _In_ PCO_CACHE_ENTRY Entry,
    _In_ BOOLEAN CallCleanup
    );

static
ULONG
CopEvictExpiredEntries(
    _In_ PCO_CACHE Cache,
    _In_ ULONG MaxToEvict
    );

static
ULONG
CopEvictLRUEntries(
    _In_ PCO_CACHE Cache,
    _In_ ULONG Count
    );

static
VOID
CopMaintenanceWorker(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    );

static
VOID
CopMaintenanceDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

static
VOID
CopUpdateMemoryPressure(
    _In_ PCO_MANAGER Manager
    );

static
NTSTATUS
CopValidateBucketCount(
    _In_ ULONG BucketCount,
    _Out_ PULONG ValidatedCount
    );

static
FORCEINLINE
LARGE_INTEGER
CopGetCurrentTime(
    VOID
    )
{
    LARGE_INTEGER time;
    KeQuerySystemTime(&time);
    return time;
}

static
FORCEINLINE
LARGE_INTEGER
CopCalculateExpireTime(
    _In_ PLARGE_INTEGER CreateTime,
    _In_ ULONG TTLSeconds
    )
{
    LARGE_INTEGER expireTime;
    expireTime.QuadPart = CreateTime->QuadPart +
                          ((LONGLONG)TTLSeconds * CO_100NS_PER_SECOND);
    return expireTime;
}

// ============================================================================
// MANAGER INITIALIZATION AND SHUTDOWN
// ============================================================================

_Use_decl_annotations_
NTSTATUS
CoInitialize(
    PCO_MANAGER* Manager,
    SIZE_T MaxTotalMemory,
    PDEVICE_OBJECT DeviceObject
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PCO_MANAGER manager = NULL;
    LARGE_INTEGER dueTime;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Manager == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Manager = NULL;

    //
    // Allocate manager structure
    //
    manager = (PCO_MANAGER)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(CO_MANAGER),
        CO_POOL_TAG
    );

    if (manager == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(manager, sizeof(CO_MANAGER));

    //
    // Initialize state
    //
    manager->MaxTotalMemory = (MaxTotalMemory != 0) ?
                              MaxTotalMemory : CO_DEFAULT_MAX_MEMORY;
    manager->DeviceObject = DeviceObject;
    manager->MaintenanceIntervalMs = CO_MAINTENANCE_INTERVAL_MS;
    manager->NextCacheId = 1;

    //
    // Initialize synchronization primitives
    //
    InitializeListHead(&manager->CacheList);
    ExInitializePushLock(&manager->CacheListLock);
    KeInitializeEvent(&manager->ShutdownEvent, NotificationEvent, FALSE);

    //
    // Initialize maintenance timer and DPC
    //
    KeInitializeTimer(&manager->MaintenanceTimer);
    KeInitializeDpc(&manager->MaintenanceDpc, CopMaintenanceDpcRoutine, manager);

    //
    // Allocate work item for maintenance if device object provided
    //
    if (DeviceObject != NULL) {
        manager->MaintenanceWorkItem = IoAllocateWorkItem(DeviceObject);
        if (manager->MaintenanceWorkItem == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }
    }

    //
    // Record start time
    //
    KeQuerySystemTime(&manager->StartTime);

    //
    // Start maintenance timer
    //
    dueTime.QuadPart = -((LONGLONG)manager->MaintenanceIntervalMs * CO_100NS_PER_MS);
    KeSetTimerEx(
        &manager->MaintenanceTimer,
        dueTime,
        manager->MaintenanceIntervalMs,
        &manager->MaintenanceDpc
    );

    //
    // Mark as initialized
    //
    InterlockedExchange(&manager->Initialized, TRUE);

    *Manager = manager;
    return STATUS_SUCCESS;

Cleanup:
    if (manager != NULL) {
        if (manager->MaintenanceWorkItem != NULL) {
            IoFreeWorkItem(manager->MaintenanceWorkItem);
        }
        ShadowStrikeFreePoolWithTag(manager, CO_POOL_TAG);
    }

    return status;
}

_Use_decl_annotations_
VOID
CoShutdown(
    PCO_MANAGER Manager
    )
{
    PLIST_ENTRY entry;
    PCO_CACHE cache;

    PAGED_CODE();

    if (Manager == NULL || !Manager->Initialized) {
        return;
    }

    //
    // Signal shutdown
    //
    InterlockedExchange(&Manager->ShuttingDown, TRUE);

    //
    // Cancel maintenance timer
    //
    KeCancelTimer(&Manager->MaintenanceTimer);

    //
    // Wait for any running maintenance to complete
    //
    while (Manager->MaintenanceRunning) {
        LARGE_INTEGER delay;
        delay.QuadPart = -10 * CO_100NS_PER_MS;  // 10ms
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }

    //
    // Destroy all caches
    //
    ExAcquirePushLockExclusive(&Manager->CacheListLock);

    while (!IsListEmpty(&Manager->CacheList)) {
        entry = RemoveHeadList(&Manager->CacheList);
        cache = CONTAINING_RECORD(entry, CO_CACHE, ManagerEntry);
        Manager->CacheCount--;

        ExReleasePushLockExclusive(&Manager->CacheListLock);

        //
        // Destroy cache (this flushes all entries)
        //
        CoDestroyCache(cache);

        ExAcquirePushLockExclusive(&Manager->CacheListLock);
    }

    ExReleasePushLockExclusive(&Manager->CacheListLock);

    //
    // Free work item
    //
    if (Manager->MaintenanceWorkItem != NULL) {
        IoFreeWorkItem(Manager->MaintenanceWorkItem);
        Manager->MaintenanceWorkItem = NULL;
    }

    //
    // Mark as not initialized and free
    //
    Manager->Initialized = FALSE;
    ShadowStrikeFreePoolWithTag(Manager, CO_POOL_TAG);
}

_Use_decl_annotations_
NTSTATUS
CoSetMemoryLimit(
    PCO_MANAGER Manager,
    SIZE_T MaxBytes
    )
{
    if (Manager == NULL || !Manager->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    Manager->MaxTotalMemory = MaxBytes;
    CopUpdateMemoryPressure(Manager);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
CoRegisterMemoryCallback(
    PCO_MANAGER Manager,
    CO_MEMORY_PRESSURE_CALLBACK Callback,
    PVOID Context
    )
{
    if (Manager == NULL || !Manager->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    Manager->MemoryCallback = Callback;
    Manager->MemoryCallbackContext = Context;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
CoGetManagerStats(
    PCO_MANAGER Manager,
    PSIZE_T TotalMemory,
    PULONG TotalCaches,
    PULONG TotalEntries,
    double* HitRate
    )
{
    LONG64 totalHits;
    LONG64 totalMisses;
    LONG64 totalLookups;

    if (Manager == NULL || !Manager->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (TotalMemory != NULL) {
        *TotalMemory = (SIZE_T)Manager->CurrentTotalMemory;
    }

    if (TotalCaches != NULL) {
        *TotalCaches = (ULONG)Manager->CacheCount;
    }

    if (TotalEntries != NULL) {
        ULONG count = 0;
        PLIST_ENTRY entry;

        ExAcquirePushLockShared(&Manager->CacheListLock);
        for (entry = Manager->CacheList.Flink;
             entry != &Manager->CacheList;
             entry = entry->Flink) {
            PCO_CACHE cache = CONTAINING_RECORD(entry, CO_CACHE, ManagerEntry);
            count += (ULONG)cache->EntryCount;
        }
        ExReleasePushLockShared(&Manager->CacheListLock);
        *TotalEntries = count;
    }

    if (HitRate != NULL) {
        totalHits = Manager->TotalHits;
        totalMisses = Manager->TotalMisses;
        totalLookups = totalHits + totalMisses;

        if (totalLookups > 0) {
            *HitRate = (double)totalHits / (double)totalLookups;
        } else {
            *HitRate = 0.0;
        }
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// CACHE LIFECYCLE
// ============================================================================

_Use_decl_annotations_
NTSTATUS
CoCreateCache(
    PCO_MANAGER Manager,
    CO_CACHE_TYPE Type,
    PCSTR Name,
    PCO_CACHE_CONFIG Config,
    PCO_CACHE* Cache
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PCO_CACHE cache = NULL;
    CO_CACHE_CONFIG localConfig;
    ULONG bucketCount;
    ULONG i;
    SIZE_T bucketArraySize;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Manager == NULL || !Manager->Initialized || Cache == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Name == NULL || Name[0] == '\0') {
        return STATUS_INVALID_PARAMETER;
    }

    if (Type >= CoCacheTypeMax) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Check cache limit
    //
    if (Manager->CacheCount >= CO_MAX_CACHES) {
        return STATUS_QUOTA_EXCEEDED;
    }

    *Cache = NULL;

    //
    // Use provided config or defaults
    //
    if (Config != NULL) {
        RtlCopyMemory(&localConfig, Config, sizeof(CO_CACHE_CONFIG));
    } else {
        CoInitDefaultConfig(&localConfig);
    }

    //
    // Validate and adjust bucket count
    //
    status = CopValidateBucketCount(localConfig.BucketCount, &bucketCount);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Calculate bucket array size with overflow check
    //
    if (!ShadowStrikeSafeMultiply(
            sizeof(CO_HASH_BUCKET),
            bucketCount,
            &bucketArraySize)) {
        return STATUS_INTEGER_OVERFLOW;
    }

    //
    // Allocate cache structure
    //
    cache = (PCO_CACHE)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(CO_CACHE),
        CO_POOL_TAG
    );

    if (cache == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(cache, sizeof(CO_CACHE));

    //
    // Initialize basic fields
    //
    cache->Type = Type;
    cache->CacheId = InterlockedIncrement((PLONG)&Manager->NextCacheId);
    cache->Manager = Manager;

    //
    // Copy name safely
    //
    RtlStringCchCopyA(cache->Name, CO_CACHE_NAME_MAX, Name);

    //
    // Copy configuration
    //
    RtlCopyMemory(&cache->Config, &localConfig, sizeof(CO_CACHE_CONFIG));

    //
    // Setup hash table parameters
    //
    cache->BucketCount = bucketCount;
    cache->BucketMask = bucketCount - 1;

    //
    // Allocate bucket array
    //
    cache->Buckets = (PCO_HASH_BUCKET)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        bucketArraySize,
        CO_HASH_POOL_TAG
    );

    if (cache->Buckets == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    RtlZeroMemory(cache->Buckets, bucketArraySize);

    //
    // Initialize each bucket
    //
    for (i = 0; i < bucketCount; i++) {
        InitializeListHead(&cache->Buckets[i].Head);
        ExInitializePushLock(&cache->Buckets[i].Lock);
    }

    //
    // Initialize shards
    //
    for (i = 0; i < CO_SHARD_COUNT; i++) {
        InitializeListHead(&cache->Shards[i].LRUHead);
        ExInitializePushLock(&cache->Shards[i].LRULock);
    }

    //
    // Initialize global entry list
    //
    InitializeListHead(&cache->GlobalEntryList);
    ExInitializePushLock(&cache->GlobalListLock);

    //
    // Initialize lookaside list if requested
    //
    if (localConfig.UseLookaside) {
        ExInitializeNPagedLookasideList(
            &cache->EntryLookaside,
            NULL,
            NULL,
            POOL_NX_ALLOCATION,
            sizeof(CO_CACHE_ENTRY),
            CO_ENTRY_POOL_TAG,
            0
        );
        cache->LookasideInitialized = TRUE;
    }

    //
    // Record memory usage for cache structure and buckets
    //
    InterlockedAdd64(
        &cache->MemoryUsage,
        (LONG64)(sizeof(CO_CACHE) + bucketArraySize)
    );
    InterlockedAdd64(
        &Manager->CurrentTotalMemory,
        (LONG64)(sizeof(CO_CACHE) + bucketArraySize)
    );

    //
    // Update peak memory if needed
    //
    if (Manager->CurrentTotalMemory > Manager->PeakTotalMemory) {
        Manager->PeakTotalMemory = Manager->CurrentTotalMemory;
    }

    //
    // Add to manager's cache list
    //
    ExAcquirePushLockExclusive(&Manager->CacheListLock);
    InsertTailList(&Manager->CacheList, &cache->ManagerEntry);
    InterlockedIncrement(&Manager->CacheCount);
    ExReleasePushLockExclusive(&Manager->CacheListLock);

    //
    // Mark as initialized
    //
    InterlockedExchange(&cache->Initialized, TRUE);

    *Cache = cache;
    return STATUS_SUCCESS;

Cleanup:
    if (cache != NULL) {
        if (cache->Buckets != NULL) {
            ShadowStrikeFreePoolWithTag(cache->Buckets, CO_HASH_POOL_TAG);
        }
        ShadowStrikeFreePoolWithTag(cache, CO_POOL_TAG);
    }

    return status;
}

_Use_decl_annotations_
NTSTATUS
CoDestroyCache(
    PCO_CACHE Cache
    )
{
    PCO_MANAGER manager;
    SIZE_T memoryFreed;

    PAGED_CODE();

    if (Cache == NULL || !Cache->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    manager = Cache->Manager;

    //
    // Signal shutdown
    //
    InterlockedExchange(&Cache->ShuttingDown, TRUE);

    //
    // Remove from manager's list
    //
    if (manager != NULL) {
        ExAcquirePushLockExclusive(&manager->CacheListLock);
        RemoveEntryList(&Cache->ManagerEntry);
        InterlockedDecrement(&manager->CacheCount);
        ExReleasePushLockExclusive(&manager->CacheListLock);
    }

    //
    // Flush all entries
    //
    CoFlush(Cache);

    //
    // Calculate memory to free
    //
    memoryFreed = sizeof(CO_CACHE) +
                  (Cache->BucketCount * sizeof(CO_HASH_BUCKET));

    //
    // Cleanup lookaside list
    //
    if (Cache->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&Cache->EntryLookaside);
        Cache->LookasideInitialized = FALSE;
    }

    //
    // Free bucket array
    //
    if (Cache->Buckets != NULL) {
        ShadowStrikeFreePoolWithTag(Cache->Buckets, CO_HASH_POOL_TAG);
        Cache->Buckets = NULL;
    }

    //
    // Update manager memory tracking
    //
    if (manager != NULL) {
        InterlockedAdd64(&manager->CurrentTotalMemory, -(LONG64)memoryFreed);
    }

    //
    // Free cache structure
    //
    Cache->Initialized = FALSE;
    ShadowStrikeFreePoolWithTag(Cache, CO_POOL_TAG);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
CoFlush(
    PCO_CACHE Cache
    )
{
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;
    PCO_CACHE_ENTRY cacheEntry;

    if (Cache == NULL || !Cache->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Acquire global list lock exclusively
    //
    ExAcquirePushLockExclusive(&Cache->GlobalListLock);

    //
    // Iterate and remove all entries
    //
    for (entry = Cache->GlobalEntryList.Flink;
         entry != &Cache->GlobalEntryList;
         entry = nextEntry) {

        nextEntry = entry->Flink;
        cacheEntry = CONTAINING_RECORD(entry, CO_CACHE_ENTRY, GlobalEntry);

        //
        // Remove from all lists and free
        //
        CopRemoveEntryFromCache(Cache, cacheEntry, TRUE);
    }

    ExReleasePushLockExclusive(&Cache->GlobalListLock);

    return STATUS_SUCCESS;
}

// ============================================================================
// CACHE OPERATIONS - PUT
// ============================================================================

_Use_decl_annotations_
NTSTATUS
CoPut(
    PCO_CACHE Cache,
    ULONG64 Key,
    PVOID Data,
    SIZE_T DataSize,
    ULONG TTLSeconds
    )
{
    return CoPutEx(Cache, Key, 0, Data, DataSize, TTLSeconds, 0, NULL);
}

_Use_decl_annotations_
NTSTATUS
CoPutEx(
    PCO_CACHE Cache,
    ULONG64 Key,
    ULONG64 SecondaryKey,
    PVOID Data,
    SIZE_T DataSize,
    ULONG TTLSeconds,
    ULONG Flags,
    PVOID UserContext
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PCO_CACHE_ENTRY entry = NULL;
    PCO_CACHE_ENTRY existingEntry = NULL;
    ULONG bucketIndex;
    ULONG shardIndex;
    PCO_HASH_BUCKET bucket;
    PCO_CACHE_SHARD shard;
    LARGE_INTEGER currentTime;
    PVOID dataCopy = NULL;
    SIZE_T totalMemory;
    BOOLEAN isUpdate = FALSE;

    //
    // Validate parameters
    //
    if (Cache == NULL || !Cache->Initialized || Cache->ShuttingDown) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Apply default TTL if not specified
    //
    if (TTLSeconds == 0) {
        TTLSeconds = Cache->Config.DefaultTTLSeconds;
    }

    //
    // Cap TTL to maximum
    //
    if (TTLSeconds > CO_MAX_TTL_SECONDS) {
        TTLSeconds = CO_MAX_TTL_SECONDS;
    }

    //
    // Calculate indices
    //
    bucketIndex = CoGetBucketIndex(Cache, Key);
    shardIndex = CoGetShardIndex(Key);
    bucket = &Cache->Buckets[bucketIndex];
    shard = &Cache->Shards[shardIndex];

    //
    // Get current time
    //
    currentTime = CopGetCurrentTime();

    //
    // Check if we need to copy data
    //
    if (Data != NULL && DataSize > 0 && Cache->Config.CopyDataOnInsert) {
        dataCopy = ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            DataSize,
            CO_DATA_POOL_TAG
        );

        if (dataCopy == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(dataCopy, Data, DataSize);
    }

    //
    // Acquire bucket lock exclusively
    //
    ExAcquirePushLockExclusive(&bucket->Lock);

    //
    // Check if key already exists
    //
    existingEntry = CopFindEntryInBucket(Cache, bucketIndex, Key);

    if (existingEntry != NULL) {
        //
        // Update existing entry
        //
        isUpdate = TRUE;

        //
        // Free old data if we owned it
        //
        if (existingEntry->DataOwned && existingEntry->Data != NULL) {
            SIZE_T oldSize = existingEntry->DataSize;
            ShadowStrikeFreePoolWithTag(existingEntry->Data, CO_DATA_POOL_TAG);
            InterlockedAdd64(&Cache->MemoryUsage, -(LONG64)oldSize);
            if (Cache->Manager != NULL) {
                InterlockedAdd64(&Cache->Manager->CurrentTotalMemory, -(LONG64)oldSize);
            }
        }

        //
        // Update entry fields
        //
        existingEntry->Data = (dataCopy != NULL) ? dataCopy : Data;
        existingEntry->DataSize = DataSize;
        existingEntry->DataOwned = (dataCopy != NULL);
        existingEntry->SecondaryKey = SecondaryKey;
        existingEntry->TTLSeconds = TTLSeconds;
        existingEntry->ExpireTime = CopCalculateExpireTime(&currentTime, TTLSeconds);
        existingEntry->Flags = Flags;
        existingEntry->UserContext = UserContext;

        //
        // Update access tracking
        //
        CopUpdateAccessTime(existingEntry);

        //
        // Update memory tracking for new data
        //
        if (dataCopy != NULL) {
            InterlockedAdd64(&Cache->MemoryUsage, (LONG64)DataSize);
            if (Cache->Manager != NULL) {
                InterlockedAdd64(&Cache->Manager->CurrentTotalMemory, (LONG64)DataSize);
            }
        }

        //
        // Update statistics
        //
        InterlockedIncrement64(&Cache->Stats.Updates);

        ExReleasePushLockExclusive(&bucket->Lock);

        //
        // Promote in LRU (outside bucket lock)
        //
        CopPromoteInLRU(Cache, existingEntry);

        return STATUS_SUCCESS;
    }

    //
    // Check capacity before inserting new entry
    //
    if ((ULONG)Cache->EntryCount >= Cache->Config.MaxEntries) {
        //
        // Need to evict
        //
        ExReleasePushLockExclusive(&bucket->Lock);

        CopEvictLRUEntries(Cache, CO_EVICTION_BATCH_SIZE);

        //
        // Re-acquire lock and check again
        //
        ExAcquirePushLockExclusive(&bucket->Lock);

        if ((ULONG)Cache->EntryCount >= Cache->Config.MaxEntries) {
            ExReleasePushLockExclusive(&bucket->Lock);

            if (dataCopy != NULL) {
                ShadowStrikeFreePoolWithTag(dataCopy, CO_DATA_POOL_TAG);
            }

            InterlockedIncrement64(&Cache->Stats.CapacityEvictions);
            return STATUS_QUOTA_EXCEEDED;
        }
    }

    //
    // Allocate new entry
    //
    status = CopAllocateEntry(Cache, &entry);
    if (!NT_SUCCESS(status)) {
        ExReleasePushLockExclusive(&bucket->Lock);

        if (dataCopy != NULL) {
            ShadowStrikeFreePoolWithTag(dataCopy, CO_DATA_POOL_TAG);
        }

        return status;
    }

    //
    // Initialize entry
    //
    entry->Key = Key;
    entry->SecondaryKey = SecondaryKey;
    entry->Data = (dataCopy != NULL) ? dataCopy : Data;
    entry->DataSize = DataSize;
    entry->DataOwned = (dataCopy != NULL);
    entry->State = CoEntryStateValid;
    entry->RefCount = 1;
    entry->AccessCount = 1;
    entry->HitCount = 0;
    entry->CreateTime = currentTime;
    entry->LastAccessTime = currentTime;
    entry->TTLSeconds = TTLSeconds;
    entry->ExpireTime = CopCalculateExpireTime(&currentTime, TTLSeconds);
    entry->Flags = Flags;
    entry->BucketIndex = bucketIndex;
    entry->ShardIndex = shardIndex;
    entry->UserContext = UserContext;

    //
    // Insert into hash bucket
    //
    InsertHeadList(&bucket->Head, &entry->HashEntry);
    InterlockedIncrement(&bucket->EntryCount);

    //
    // Track collisions
    //
    if (bucket->EntryCount > 1) {
        InterlockedIncrement(&bucket->Collisions);
    }

    ExReleasePushLockExclusive(&bucket->Lock);

    //
    // Insert into global list
    //
    ExAcquirePushLockExclusive(&Cache->GlobalListLock);
    InsertTailList(&Cache->GlobalEntryList, &entry->GlobalEntry);
    ExReleasePushLockExclusive(&Cache->GlobalListLock);

    //
    // Insert into LRU
    //
    CopInsertIntoLRU(Cache, entry);

    //
    // Update counters
    //
    InterlockedIncrement(&Cache->EntryCount);
    InterlockedIncrement64(&Cache->Stats.Inserts);
    InterlockedIncrement(&Cache->Stats.CurrentEntries);

    //
    // Update peak entries
    //
    if (Cache->Stats.CurrentEntries > Cache->Stats.PeakEntries) {
        Cache->Stats.PeakEntries = Cache->Stats.CurrentEntries;
    }

    //
    // Update memory tracking
    //
    totalMemory = sizeof(CO_CACHE_ENTRY);
    if (dataCopy != NULL) {
        totalMemory += DataSize;
    }

    InterlockedAdd64(&Cache->MemoryUsage, (LONG64)totalMemory);
    InterlockedAdd64(&Cache->Stats.CurrentMemory, (LONG64)totalMemory);

    if (Cache->Manager != NULL) {
        InterlockedAdd64(&Cache->Manager->CurrentTotalMemory, (LONG64)totalMemory);

        if (Cache->Manager->CurrentTotalMemory > Cache->Manager->PeakTotalMemory) {
            Cache->Manager->PeakTotalMemory = Cache->Manager->CurrentTotalMemory;
        }
    }

    if (Cache->Stats.CurrentMemory > Cache->Stats.PeakMemory) {
        Cache->Stats.PeakMemory = Cache->Stats.CurrentMemory;
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// CACHE OPERATIONS - GET
// ============================================================================

_Use_decl_annotations_
NTSTATUS
CoGet(
    PCO_CACHE Cache,
    ULONG64 Key,
    PVOID* Data,
    PSIZE_T DataSize
    )
{
    PCO_CACHE_ENTRY entry;
    ULONG bucketIndex;
    PCO_HASH_BUCKET bucket;
    LARGE_INTEGER currentTime;

    //
    // Validate parameters
    //
    if (Cache == NULL || !Cache->Initialized || Cache->ShuttingDown) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Update total lookups
    //
    InterlockedIncrement64(&Cache->Stats.TotalLookups);
    if (Cache->Manager != NULL) {
        InterlockedIncrement64(&Cache->Manager->TotalOperations);
    }

    //
    // Calculate bucket index
    //
    bucketIndex = CoGetBucketIndex(Cache, Key);
    bucket = &Cache->Buckets[bucketIndex];

    //
    // Get current time for expiration check
    //
    currentTime = CopGetCurrentTime();

    //
    // Acquire bucket lock for reading
    //
    ExAcquirePushLockShared(&bucket->Lock);

    //
    // Find entry
    //
    entry = CopFindEntryInBucket(Cache, bucketIndex, Key);

    if (entry == NULL) {
        ExReleasePushLockShared(&bucket->Lock);

        InterlockedIncrement64(&Cache->Stats.Misses);
        if (Cache->Manager != NULL) {
            InterlockedIncrement64(&Cache->Manager->TotalMisses);
        }

        return STATUS_NOT_FOUND;
    }

    //
    // Check if expired
    //
    if (CopIsEntryExpired(entry, &currentTime)) {
        ExReleasePushLockShared(&bucket->Lock);

        //
        // Remove expired entry (need exclusive lock)
        //
        ExAcquirePushLockExclusive(&bucket->Lock);
        entry = CopFindEntryInBucket(Cache, bucketIndex, Key);
        if (entry != NULL && CopIsEntryExpired(entry, &currentTime)) {
            CopRemoveEntryFromCache(Cache, entry, TRUE);
            InterlockedIncrement64(&Cache->Stats.TTLEvictions);
        }
        ExReleasePushLockExclusive(&bucket->Lock);

        InterlockedIncrement64(&Cache->Stats.Misses);
        if (Cache->Manager != NULL) {
            InterlockedIncrement64(&Cache->Manager->TotalMisses);
        }

        return STATUS_NOT_FOUND;
    }

    //
    // Return data
    //
    if (Data != NULL) {
        *Data = entry->Data;
    }
    if (DataSize != NULL) {
        *DataSize = entry->DataSize;
    }

    //
    // Update access tracking
    //
    CopUpdateAccessTime(entry);
    InterlockedIncrement(&entry->AccessCount);
    InterlockedIncrement(&entry->HitCount);

    ExReleasePushLockShared(&bucket->Lock);

    //
    // Update statistics
    //
    InterlockedIncrement64(&Cache->Stats.Hits);
    if (Cache->Manager != NULL) {
        InterlockedIncrement64(&Cache->Manager->TotalHits);
    }

    //
    // Promote in LRU if hit count threshold reached
    //
    if (entry->HitCount >= CO_LRU_PROMOTION_THRESHOLD) {
        InterlockedExchange(&entry->HitCount, 0);
        CopPromoteInLRU(Cache, entry);
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
CoGetEx(
    PCO_CACHE Cache,
    ULONG64 Key,
    PCO_LOOKUP_RESULT Result
    )
{
    NTSTATUS status;
    PVOID data = NULL;
    SIZE_T dataSize = 0;
    PCO_CACHE_ENTRY entry;
    ULONG bucketIndex;
    PCO_HASH_BUCKET bucket;
    LARGE_INTEGER currentTime;

    if (Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Result, sizeof(CO_LOOKUP_RESULT));
    Result->Key = Key;

    status = CoGet(Cache, Key, &data, &dataSize);

    if (NT_SUCCESS(status)) {
        Result->Result = CoResultSuccess;
        Result->Data = data;
        Result->DataSize = dataSize;

        //
        // Get additional entry info
        //
        bucketIndex = CoGetBucketIndex(Cache, Key);
        bucket = &Cache->Buckets[bucketIndex];
        currentTime = CopGetCurrentTime();

        ExAcquirePushLockShared(&bucket->Lock);
        entry = CopFindEntryInBucket(Cache, bucketIndex, Key);
        if (entry != NULL) {
            Result->CreateTime = entry->CreateTime;
            Result->ExpireTime = entry->ExpireTime;
            Result->AccessCount = entry->AccessCount;
            Result->WasExpired = FALSE;
        }
        ExReleasePushLockShared(&bucket->Lock);
    } else if (status == STATUS_NOT_FOUND) {
        Result->Result = CoResultNotFound;
    } else {
        Result->Result = CoResultError;
    }

    return status;
}

_Use_decl_annotations_
BOOLEAN
CoContains(
    PCO_CACHE Cache,
    ULONG64 Key
    )
{
    PCO_CACHE_ENTRY entry;
    ULONG bucketIndex;
    PCO_HASH_BUCKET bucket;
    LARGE_INTEGER currentTime;
    BOOLEAN found = FALSE;

    if (Cache == NULL || !Cache->Initialized || Cache->ShuttingDown) {
        return FALSE;
    }

    bucketIndex = CoGetBucketIndex(Cache, Key);
    bucket = &Cache->Buckets[bucketIndex];
    currentTime = CopGetCurrentTime();

    ExAcquirePushLockShared(&bucket->Lock);

    entry = CopFindEntryInBucket(Cache, bucketIndex, Key);
    if (entry != NULL && !CopIsEntryExpired(entry, &currentTime)) {
        found = TRUE;
    }

    ExReleasePushLockShared(&bucket->Lock);

    return found;
}

// ============================================================================
// CACHE OPERATIONS - INVALIDATE/TOUCH/PIN
// ============================================================================

_Use_decl_annotations_
NTSTATUS
CoInvalidate(
    PCO_CACHE Cache,
    ULONG64 Key
    )
{
    PCO_CACHE_ENTRY entry;
    ULONG bucketIndex;
    PCO_HASH_BUCKET bucket;

    if (Cache == NULL || !Cache->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    bucketIndex = CoGetBucketIndex(Cache, Key);
    bucket = &Cache->Buckets[bucketIndex];

    ExAcquirePushLockExclusive(&bucket->Lock);

    entry = CopFindEntryInBucket(Cache, bucketIndex, Key);
    if (entry == NULL) {
        ExReleasePushLockExclusive(&bucket->Lock);
        return STATUS_NOT_FOUND;
    }

    CopRemoveEntryFromCache(Cache, entry, TRUE);
    InterlockedIncrement64(&Cache->Stats.Removes);

    ExReleasePushLockExclusive(&bucket->Lock);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
CoTouch(
    PCO_CACHE Cache,
    ULONG64 Key
    )
{
    PCO_CACHE_ENTRY entry;
    ULONG bucketIndex;
    PCO_HASH_BUCKET bucket;
    LARGE_INTEGER currentTime;

    if (Cache == NULL || !Cache->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    bucketIndex = CoGetBucketIndex(Cache, Key);
    bucket = &Cache->Buckets[bucketIndex];
    currentTime = CopGetCurrentTime();

    ExAcquirePushLockShared(&bucket->Lock);

    entry = CopFindEntryInBucket(Cache, bucketIndex, Key);
    if (entry == NULL || CopIsEntryExpired(entry, &currentTime)) {
        ExReleasePushLockShared(&bucket->Lock);
        return STATUS_NOT_FOUND;
    }

    CopUpdateAccessTime(entry);

    ExReleasePushLockShared(&bucket->Lock);

    CopPromoteInLRU(Cache, entry);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
CoPin(
    PCO_CACHE Cache,
    ULONG64 Key
    )
{
    PCO_CACHE_ENTRY entry;
    ULONG bucketIndex;
    PCO_HASH_BUCKET bucket;

    if (Cache == NULL || !Cache->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    bucketIndex = CoGetBucketIndex(Cache, Key);
    bucket = &Cache->Buckets[bucketIndex];

    ExAcquirePushLockExclusive(&bucket->Lock);

    entry = CopFindEntryInBucket(Cache, bucketIndex, Key);
    if (entry == NULL) {
        ExReleasePushLockExclusive(&bucket->Lock);
        return STATUS_NOT_FOUND;
    }

    InterlockedExchange(&entry->State, CoEntryStatePinned);

    ExReleasePushLockExclusive(&bucket->Lock);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
CoUnpin(
    PCO_CACHE Cache,
    ULONG64 Key
    )
{
    PCO_CACHE_ENTRY entry;
    ULONG bucketIndex;
    PCO_HASH_BUCKET bucket;

    if (Cache == NULL || !Cache->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    bucketIndex = CoGetBucketIndex(Cache, Key);
    bucket = &Cache->Buckets[bucketIndex];

    ExAcquirePushLockExclusive(&bucket->Lock);

    entry = CopFindEntryInBucket(Cache, bucketIndex, Key);
    if (entry == NULL) {
        ExReleasePushLockExclusive(&bucket->Lock);
        return STATUS_NOT_FOUND;
    }

    if (entry->State == CoEntryStatePinned) {
        InterlockedExchange(&entry->State, CoEntryStateValid);
    }

    ExReleasePushLockExclusive(&bucket->Lock);

    return STATUS_SUCCESS;
}

// ============================================================================
// STATISTICS AND MONITORING
// ============================================================================

_Use_decl_annotations_
VOID
CoGetStats(
    PCO_CACHE Cache,
    PCO_CACHE_STATS Stats
    )
{
    if (Cache == NULL || Stats == NULL) {
        return;
    }

    RtlCopyMemory(Stats, &Cache->Stats, sizeof(CO_CACHE_STATS));
}

_Use_decl_annotations_
VOID
CoResetStats(
    PCO_CACHE Cache
    )
{
    if (Cache == NULL) {
        return;
    }

    //
    // Reset counters but preserve current state metrics
    //
    InterlockedExchange64(&Cache->Stats.TotalLookups, 0);
    InterlockedExchange64(&Cache->Stats.Hits, 0);
    InterlockedExchange64(&Cache->Stats.Misses, 0);
    InterlockedExchange64(&Cache->Stats.Inserts, 0);
    InterlockedExchange64(&Cache->Stats.Updates, 0);
    InterlockedExchange64(&Cache->Stats.Removes, 0);
    InterlockedExchange64(&Cache->Stats.TTLEvictions, 0);
    InterlockedExchange64(&Cache->Stats.LRUEvictions, 0);
    InterlockedExchange64(&Cache->Stats.CapacityEvictions, 0);
    InterlockedExchange64(&Cache->Stats.MemoryEvictions, 0);
    InterlockedExchange64(&Cache->Stats.MaintenanceCycles, 0);
    InterlockedExchange64(&Cache->Stats.EntriesScanned, 0);
    InterlockedExchange64(&Cache->Stats.TotalLookupTimeNs, 0);
    InterlockedExchange64(&Cache->Stats.TotalInsertTimeNs, 0);
}

_Use_decl_annotations_
double
CoGetHitRate(
    PCO_CACHE Cache
    )
{
    LONG64 hits;
    LONG64 misses;
    LONG64 total;

    if (Cache == NULL) {
        return 0.0;
    }

    hits = Cache->Stats.Hits;
    misses = Cache->Stats.Misses;
    total = hits + misses;

    if (total == 0) {
        return 0.0;
    }

    return (double)hits / (double)total;
}

_Use_decl_annotations_
ULONG
CoGetEntryCount(
    PCO_CACHE Cache
    )
{
    if (Cache == NULL) {
        return 0;
    }

    return (ULONG)Cache->EntryCount;
}

_Use_decl_annotations_
SIZE_T
CoGetMemoryUsage(
    PCO_CACHE Cache
    )
{
    if (Cache == NULL) {
        return 0;
    }

    return (SIZE_T)Cache->MemoryUsage;
}

// ============================================================================
// MAINTENANCE FUNCTIONS
// ============================================================================

_Use_decl_annotations_
ULONG
CoRunMaintenance(
    PCO_CACHE Cache
    )
{
    ULONG evicted = 0;

    if (Cache == NULL || !Cache->Initialized || Cache->ShuttingDown) {
        return 0;
    }

    //
    // Mark maintenance as active
    //
    if (InterlockedCompareExchange(&Cache->MaintenanceActive, TRUE, FALSE) != FALSE) {
        //
        // Already running
        //
        return 0;
    }

    //
    // Evict expired entries
    //
    evicted = CopEvictExpiredEntries(Cache, CO_EVICTION_BATCH_SIZE * 2);

    //
    // Update statistics
    //
    InterlockedIncrement64(&Cache->Stats.MaintenanceCycles);
    KeQuerySystemTime(&Cache->Stats.LastMaintenanceTime);

    //
    // Check memory pressure and evict if needed
    //
    if (Cache->Manager != NULL && Cache->Manager->MaxTotalMemory > 0) {
        LONG64 currentMem = Cache->Manager->CurrentTotalMemory;
        LONG64 maxMem = (LONG64)Cache->Manager->MaxTotalMemory;
        ULONG pressurePercent = (ULONG)((currentMem * 100) / maxMem);

        if (pressurePercent > CO_MEMORY_PRESSURE_THRESHOLD) {
            //
            // Evict additional entries to reduce memory
            //
            ULONG additionalEvictions = CopEvictLRUEntries(
                Cache,
                CO_EVICTION_BATCH_SIZE
            );
            evicted += additionalEvictions;
            InterlockedAdd64(&Cache->Stats.MemoryEvictions, additionalEvictions);
        }
    }

    InterlockedExchange(&Cache->MaintenanceActive, FALSE);

    return evicted;
}

_Use_decl_annotations_
SIZE_T
CoEvictToSize(
    PCO_CACHE Cache,
    SIZE_T TargetBytes
    )
{
    SIZE_T bytesFreed = 0;
    SIZE_T initialUsage;
    ULONG evictBatch;

    if (Cache == NULL || !Cache->Initialized) {
        return 0;
    }

    initialUsage = (SIZE_T)Cache->MemoryUsage;

    if (initialUsage <= TargetBytes) {
        return 0;
    }

    //
    // Evict in batches until we reach target
    //
    while ((SIZE_T)Cache->MemoryUsage > TargetBytes && Cache->EntryCount > 0) {
        evictBatch = CopEvictLRUEntries(Cache, CO_EVICTION_BATCH_SIZE);
        if (evictBatch == 0) {
            break;  // No more evictable entries
        }
    }

    bytesFreed = initialUsage - (SIZE_T)Cache->MemoryUsage;
    return bytesFreed;
}

// ============================================================================
// INTERNAL HELPER FUNCTIONS
// ============================================================================

static
NTSTATUS
CopAllocateEntry(
    _In_ PCO_CACHE Cache,
    _Out_ PCO_CACHE_ENTRY* Entry
    )
{
    PCO_CACHE_ENTRY entry;

    *Entry = NULL;

    if (Cache->LookasideInitialized) {
        entry = (PCO_CACHE_ENTRY)ExAllocateFromNPagedLookasideList(
            &Cache->EntryLookaside
        );
    } else {
        entry = (PCO_CACHE_ENTRY)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(CO_CACHE_ENTRY),
            CO_ENTRY_POOL_TAG
        );
    }

    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(entry, sizeof(CO_CACHE_ENTRY));
    InitializeListHead(&entry->HashEntry);
    InitializeListHead(&entry->LRUEntry);
    InitializeListHead(&entry->GlobalEntry);

    *Entry = entry;
    return STATUS_SUCCESS;
}

static
VOID
CopFreeEntry(
    _In_ PCO_CACHE Cache,
    _In_ PCO_CACHE_ENTRY Entry
    )
{
    if (Entry == NULL) {
        return;
    }

    //
    // Free owned data
    //
    if (Entry->DataOwned && Entry->Data != NULL) {
        ShadowStrikeFreePoolWithTag(Entry->Data, CO_DATA_POOL_TAG);
    }

    //
    // Free entry
    //
    if (Cache->LookasideInitialized) {
        ExFreeToNPagedLookasideList(&Cache->EntryLookaside, Entry);
    } else {
        ShadowStrikeFreePoolWithTag(Entry, CO_ENTRY_POOL_TAG);
    }
}

static
PCO_CACHE_ENTRY
CopFindEntryInBucket(
    _In_ PCO_CACHE Cache,
    _In_ ULONG BucketIndex,
    _In_ ULONG64 Key
    )
{
    PLIST_ENTRY listEntry;
    PCO_CACHE_ENTRY entry;
    PCO_HASH_BUCKET bucket;

    bucket = &Cache->Buckets[BucketIndex];

    for (listEntry = bucket->Head.Flink;
         listEntry != &bucket->Head;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, CO_CACHE_ENTRY, HashEntry);

        if (entry->Key == Key && entry->State != CoEntryStateInvalid) {
            return entry;
        }
    }

    return NULL;
}

static
VOID
CopInsertIntoLRU(
    _In_ PCO_CACHE Cache,
    _In_ PCO_CACHE_ENTRY Entry
    )
{
    PCO_CACHE_SHARD shard;

    shard = &Cache->Shards[Entry->ShardIndex];

    ExAcquirePushLockExclusive(&shard->LRULock);

    //
    // Insert at head (most recently used)
    //
    InsertHeadList(&shard->LRUHead, &Entry->LRUEntry);
    InterlockedIncrement(&shard->EntryCount);

    ExReleasePushLockExclusive(&shard->LRULock);
}

static
VOID
CopRemoveFromLRU(
    _In_ PCO_CACHE Cache,
    _In_ PCO_CACHE_ENTRY Entry
    )
{
    PCO_CACHE_SHARD shard;

    shard = &Cache->Shards[Entry->ShardIndex];

    ExAcquirePushLockExclusive(&shard->LRULock);

    if (!IsListEmpty(&Entry->LRUEntry)) {
        RemoveEntryList(&Entry->LRUEntry);
        InitializeListHead(&Entry->LRUEntry);
        InterlockedDecrement(&shard->EntryCount);
    }

    ExReleasePushLockExclusive(&shard->LRULock);
}

static
VOID
CopPromoteInLRU(
    _In_ PCO_CACHE Cache,
    _In_ PCO_CACHE_ENTRY Entry
    )
{
    PCO_CACHE_SHARD shard;

    shard = &Cache->Shards[Entry->ShardIndex];

    ExAcquirePushLockExclusive(&shard->LRULock);

    if (!IsListEmpty(&Entry->LRUEntry)) {
        //
        // Remove from current position
        //
        RemoveEntryList(&Entry->LRUEntry);

        //
        // Insert at head (MRU position)
        //
        InsertHeadList(&shard->LRUHead, &Entry->LRUEntry);
    }

    ExReleasePushLockExclusive(&shard->LRULock);
}

static
VOID
CopEvictLRUEntry(
    _In_ PCO_CACHE Cache,
    _In_ PCO_CACHE_SHARD* Shard
    )
{
    PLIST_ENTRY tailEntry;
    PCO_CACHE_ENTRY entry;
    PCO_HASH_BUCKET bucket;

    //
    // Get LRU entry (tail of list)
    //
    ExAcquirePushLockExclusive(&Shard->LRULock);

    if (IsListEmpty(&Shard->LRUHead)) {
        ExReleasePushLockExclusive(&Shard->LRULock);
        return;
    }

    tailEntry = Shard->LRUHead.Blink;
    entry = CONTAINING_RECORD(tailEntry, CO_CACHE_ENTRY, LRUEntry);

    //
    // Don't evict pinned entries
    //
    if (entry->State == CoEntryStatePinned) {
        ExReleasePushLockExclusive(&Shard->LRULock);
        return;
    }

    //
    // Remove from LRU
    //
    RemoveEntryList(&entry->LRUEntry);
    InitializeListHead(&entry->LRUEntry);
    InterlockedDecrement(&Shard->EntryCount);

    ExReleasePushLockExclusive(&Shard->LRULock);

    //
    // Mark as evicting
    //
    InterlockedExchange(&entry->State, CoEntryStateEvicting);

    //
    // Remove from bucket
    //
    bucket = &Cache->Buckets[entry->BucketIndex];

    ExAcquirePushLockExclusive(&bucket->Lock);
    if (!IsListEmpty(&entry->HashEntry)) {
        RemoveEntryList(&entry->HashEntry);
        InitializeListHead(&entry->HashEntry);
        InterlockedDecrement(&bucket->EntryCount);
    }
    ExReleasePushLockExclusive(&bucket->Lock);

    //
    // Remove from global list
    //
    ExAcquirePushLockExclusive(&Cache->GlobalListLock);
    if (!IsListEmpty(&entry->GlobalEntry)) {
        RemoveEntryList(&entry->GlobalEntry);
        InitializeListHead(&entry->GlobalEntry);
    }
    ExReleasePushLockExclusive(&Cache->GlobalListLock);

    //
    // Call cleanup callback
    //
    CopCallCleanupCallback(Cache, entry);

    //
    // Update memory tracking
    //
    SIZE_T memoryFreed = sizeof(CO_CACHE_ENTRY);
    if (entry->DataOwned && entry->Data != NULL) {
        memoryFreed += entry->DataSize;
    }

    InterlockedAdd64(&Cache->MemoryUsage, -(LONG64)memoryFreed);
    InterlockedAdd64(&Cache->Stats.CurrentMemory, -(LONG64)memoryFreed);
    if (Cache->Manager != NULL) {
        InterlockedAdd64(&Cache->Manager->CurrentTotalMemory, -(LONG64)memoryFreed);
    }

    //
    // Update counters
    //
    InterlockedDecrement(&Cache->EntryCount);
    InterlockedDecrement(&Cache->Stats.CurrentEntries);
    InterlockedIncrement64(&Shard->Evictions);

    //
    // Free entry
    //
    CopFreeEntry(Cache, entry);
}

static
BOOLEAN
CopIsEntryExpired(
    _In_ PCO_CACHE_ENTRY Entry,
    _In_ PLARGE_INTEGER CurrentTime
    )
{
    if (Entry->State == CoEntryStatePinned) {
        return FALSE;
    }

    return CurrentTime->QuadPart >= Entry->ExpireTime.QuadPart;
}

static
VOID
CopUpdateAccessTime(
    _In_ PCO_CACHE_ENTRY Entry
    )
{
    LARGE_INTEGER currentTime;
    KeQuerySystemTime(&currentTime);
    Entry->LastAccessTime = currentTime;
}

static
VOID
CopCallCleanupCallback(
    _In_ PCO_CACHE Cache,
    _In_ PCO_CACHE_ENTRY Entry
    )
{
    if (Cache->Config.CleanupCallback != NULL) {
        Cache->Config.CleanupCallback(
            Cache,
            Entry->Key,
            Entry->Data,
            Entry->DataSize,
            Cache->Config.CleanupContext
        );
    }
}

static
VOID
CopRemoveEntryFromCache(
    _In_ PCO_CACHE Cache,
    _In_ PCO_CACHE_ENTRY Entry,
    _In_ BOOLEAN CallCleanup
    )
{
    SIZE_T memoryFreed;
    PCO_HASH_BUCKET bucket;

    //
    // Mark as evicting
    //
    InterlockedExchange(&Entry->State, CoEntryStateEvicting);

    //
    // Remove from hash bucket (caller should hold bucket lock)
    //
    bucket = &Cache->Buckets[Entry->BucketIndex];
    if (!IsListEmpty(&Entry->HashEntry)) {
        RemoveEntryList(&Entry->HashEntry);
        InitializeListHead(&Entry->HashEntry);
        InterlockedDecrement(&bucket->EntryCount);
    }

    //
    // Remove from LRU
    //
    CopRemoveFromLRU(Cache, Entry);

    //
    // Remove from global list (we may or may not hold this lock)
    //
    if (!IsListEmpty(&Entry->GlobalEntry)) {
        RemoveEntryList(&Entry->GlobalEntry);
        InitializeListHead(&Entry->GlobalEntry);
    }

    //
    // Call cleanup callback if requested
    //
    if (CallCleanup) {
        CopCallCleanupCallback(Cache, Entry);
    }

    //
    // Calculate memory freed
    //
    memoryFreed = sizeof(CO_CACHE_ENTRY);
    if (Entry->DataOwned && Entry->Data != NULL) {
        memoryFreed += Entry->DataSize;
    }

    //
    // Update memory tracking
    //
    InterlockedAdd64(&Cache->MemoryUsage, -(LONG64)memoryFreed);
    InterlockedAdd64(&Cache->Stats.CurrentMemory, -(LONG64)memoryFreed);
    if (Cache->Manager != NULL) {
        InterlockedAdd64(&Cache->Manager->CurrentTotalMemory, -(LONG64)memoryFreed);
    }

    //
    // Update counters
    //
    InterlockedDecrement(&Cache->EntryCount);
    InterlockedDecrement(&Cache->Stats.CurrentEntries);

    //
    // Free entry
    //
    CopFreeEntry(Cache, Entry);
}

static
ULONG
CopEvictExpiredEntries(
    _In_ PCO_CACHE Cache,
    _In_ ULONG MaxToEvict
    )
{
    ULONG evicted = 0;
    ULONG i;
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;
    PCO_CACHE_ENTRY cacheEntry;
    LARGE_INTEGER currentTime;
    PCO_HASH_BUCKET bucket;

    currentTime = CopGetCurrentTime();

    //
    // Scan buckets for expired entries
    //
    for (i = 0; i < Cache->BucketCount && evicted < MaxToEvict; i++) {
        bucket = &Cache->Buckets[i];

        if (bucket->EntryCount == 0) {
            continue;
        }

        ExAcquirePushLockExclusive(&bucket->Lock);

        for (entry = bucket->Head.Flink;
             entry != &bucket->Head && evicted < MaxToEvict;
             entry = nextEntry) {

            nextEntry = entry->Flink;
            cacheEntry = CONTAINING_RECORD(entry, CO_CACHE_ENTRY, HashEntry);

            InterlockedIncrement64(&Cache->Stats.EntriesScanned);

            if (CopIsEntryExpired(cacheEntry, &currentTime)) {
                CopRemoveEntryFromCache(Cache, cacheEntry, TRUE);
                InterlockedIncrement64(&Cache->Stats.TTLEvictions);
                evicted++;
            }
        }

        ExReleasePushLockExclusive(&bucket->Lock);
    }

    return evicted;
}

static
ULONG
CopEvictLRUEntries(
    _In_ PCO_CACHE Cache,
    _In_ ULONG Count
    )
{
    ULONG evicted = 0;
    ULONG shardIndex;

    //
    // Round-robin through shards to evict entries
    //
    for (shardIndex = 0; shardIndex < CO_SHARD_COUNT && evicted < Count; shardIndex++) {
        PCO_CACHE_SHARD shard = &Cache->Shards[shardIndex];

        while (shard->EntryCount > 0 && evicted < Count) {
            CopEvictLRUEntry(Cache, shard);
            evicted++;
            InterlockedIncrement64(&Cache->Stats.LRUEvictions);
        }
    }

    return evicted;
}

static
VOID
CopMaintenanceWorker(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    )
{
    PCO_MANAGER manager = (PCO_MANAGER)Context;
    PLIST_ENTRY entry;
    PCO_CACHE cache;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (manager == NULL || manager->ShuttingDown) {
        if (manager != NULL) {
            InterlockedExchange(&manager->MaintenanceRunning, FALSE);
        }
        return;
    }

    //
    // Run maintenance on all caches
    //
    ExAcquirePushLockShared(&manager->CacheListLock);

    for (entry = manager->CacheList.Flink;
         entry != &manager->CacheList;
         entry = entry->Flink) {

        cache = CONTAINING_RECORD(entry, CO_CACHE, ManagerEntry);

        if (cache->Initialized && !cache->ShuttingDown) {
            CoRunMaintenance(cache);
        }
    }

    ExReleasePushLockShared(&manager->CacheListLock);

    //
    // Update memory pressure
    //
    CopUpdateMemoryPressure(manager);

    InterlockedExchange(&manager->MaintenanceRunning, FALSE);
}

static
VOID
CopMaintenanceDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PCO_MANAGER manager = (PCO_MANAGER)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (manager == NULL || manager->ShuttingDown) {
        return;
    }

    //
    // Don't queue if already running
    //
    if (InterlockedCompareExchange(&manager->MaintenanceRunning, TRUE, FALSE) != FALSE) {
        return;
    }

    //
    // Queue work item for passive level processing
    //
    if (manager->MaintenanceWorkItem != NULL) {
        IoQueueWorkItem(
            manager->MaintenanceWorkItem,
            CopMaintenanceWorker,
            DelayedWorkQueue,
            manager
        );
    } else {
        //
        // No work item available, reset flag
        //
        InterlockedExchange(&manager->MaintenanceRunning, FALSE);
    }
}

static
VOID
CopUpdateMemoryPressure(
    _In_ PCO_MANAGER Manager
    )
{
    LONG64 currentMem;
    LONG64 maxMem;
    ULONG pressurePercent;

    if (Manager->MaxTotalMemory == 0) {
        Manager->MemoryPressure = 0;
        return;
    }

    currentMem = Manager->CurrentTotalMemory;
    maxMem = (LONG64)Manager->MaxTotalMemory;

    if (maxMem > 0) {
        pressurePercent = (ULONG)((currentMem * 100) / maxMem);
    } else {
        pressurePercent = 0;
    }

    InterlockedExchange(&Manager->MemoryPressure, pressurePercent);

    //
    // Invoke callback if registered
    //
    if (Manager->MemoryCallback != NULL &&
        pressurePercent >= CO_MEMORY_PRESSURE_THRESHOLD) {
        Manager->MemoryCallback(
            Manager,
            (SIZE_T)currentMem,
            Manager->MaxTotalMemory,
            Manager->MemoryCallbackContext
        );
    }
}

static
NTSTATUS
CopValidateBucketCount(
    _In_ ULONG BucketCount,
    _Out_ PULONG ValidatedCount
    )
{
    ULONG count;

    //
    // Use default if zero
    //
    if (BucketCount == 0) {
        *ValidatedCount = CO_DEFAULT_BUCKET_COUNT;
        return STATUS_SUCCESS;
    }

    //
    // Clamp to valid range
    //
    count = BucketCount;
    if (count < CO_MIN_BUCKET_COUNT) {
        count = CO_MIN_BUCKET_COUNT;
    }
    if (count > CO_MAX_BUCKET_COUNT) {
        count = CO_MAX_BUCKET_COUNT;
    }

    //
    // Round up to power of 2
    //
    count--;
    count |= count >> 1;
    count |= count >> 2;
    count |= count >> 4;
    count |= count >> 8;
    count |= count >> 16;
    count++;

    //
    // Final bounds check after rounding
    //
    if (count > CO_MAX_BUCKET_COUNT) {
        count = CO_MAX_BUCKET_COUNT;
    }

    *ValidatedCount = count;
    return STATUS_SUCCESS;
}
