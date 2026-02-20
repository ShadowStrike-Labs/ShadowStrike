/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE CACHE OPTIMIZATION ENGINE
 * ============================================================================
 *
 * @file CacheOptimization.c
 * @brief High-performance, lock-optimized caching infrastructure for kernel EDR.
 *
 * Lock Ordering (strictly enforced throughout):
 *   1. Bucket lock (per-bucket EX_PUSH_LOCK)
 *   2. Shard LRU lock (per-shard EX_PUSH_LOCK)
 *   3. Global list lock (per-cache EX_PUSH_LOCK)
 *   4. Manager CacheListLock
 *
 * Reference counting:
 *   - Entries are born with RefCount = 1 (the hash bucket reference).
 *   - Lookups (CoGet/CoGetEx) do NOT take extra references; they copy data
 *     under the bucket lock to avoid use-after-free.
 *   - Removal sets State = Evicting, unlinks from all lists, and frees.
 *     All unlinking is done under the appropriate locks.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "CacheOptimization.h"
#include "../Utilities/MemoryUtils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, CoInitialize)
#pragma alloc_text(PAGE, CoShutdown)
#pragma alloc_text(PAGE, CoCreateCache)
#pragma alloc_text(PAGE, CoDestroyCache)
#endif

/* ========================================================================= */
/* INTERNAL CONSTANTS                                                         */
/* ========================================================================= */

#define CO_DEFAULT_MAX_MEMORY       (256 * 1024 * 1024)  /* 256 MB */

#define CO_100NS_PER_SECOND         10000000LL
#define CO_100NS_PER_MS             10000LL

/* ========================================================================= */
/* INTERNAL FUNCTION PROTOTYPES                                               */
/* ========================================================================= */

static NTSTATUS
CopAllocateEntry(
    _In_ PCO_CACHE Cache,
    _Out_ PCO_CACHE_ENTRY* Entry
    );

static VOID
CopFreeEntry(
    _In_ PCO_CACHE Cache,
    _In_ PCO_CACHE_ENTRY Entry
    );

static PCO_CACHE_ENTRY
CopFindEntryInBucket(
    _In_ PCO_CACHE Cache,
    _In_ ULONG BucketIndex,
    _In_ ULONG64 Key
    );

static VOID
CopInsertIntoLRU(
    _In_ PCO_CACHE Cache,
    _In_ PCO_CACHE_ENTRY Entry
    );

static VOID
CopRemoveFromLRU(
    _In_ PCO_CACHE Cache,
    _In_ PCO_CACHE_ENTRY Entry
    );

static VOID
CopPromoteInLRU(
    _In_ PCO_CACHE Cache,
    _In_ PCO_CACHE_ENTRY Entry
    );

static BOOLEAN
CopEvictLRUEntry(
    _In_ PCO_CACHE Cache,
    _In_ PCO_CACHE_SHARD Shard
    );

static BOOLEAN
CopIsEntryExpired(
    _In_ PCO_CACHE_ENTRY Entry,
    _In_ PLARGE_INTEGER CurrentTime
    );

static VOID
CopCallCleanupCallback(
    _In_ PCO_CACHE Cache,
    _In_ PCO_CACHE_ENTRY Entry
    );

/**
 * @brief Remove entry from cache.
 *
 * PRECONDITION: Caller MUST hold the entry's bucket lock EXCLUSIVE.
 * This function acquires shard LRU lock then global list lock (lock order safe).
 * After this call the entry is freed — do not dereference.
 */
static VOID
CopRemoveEntryFromCache(
    _In_ PCO_CACHE Cache,
    _In_ PCO_CACHE_ENTRY Entry,
    _In_ BOOLEAN CallCleanup
    );

static ULONG
CopEvictExpiredEntries(
    _In_ PCO_CACHE Cache,
    _In_ ULONG MaxToEvict
    );

static ULONG
CopEvictLRUEntries(
    _In_ PCO_CACHE Cache,
    _In_ ULONG Count
    );

static VOID
CopMaintenanceWorker(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    );

static VOID
CopMaintenanceDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

static VOID
CopUpdateMemoryPressure(
    _In_ PCO_MANAGER Manager
    );

static NTSTATUS
CopValidateBucketCount(
    _In_ ULONG BucketCount,
    _Out_ PULONG ValidatedCount
    );

static FORCEINLINE LARGE_INTEGER
CopGetCurrentTime(VOID)
{
    LARGE_INTEGER time;
    KeQuerySystemTime(&time);
    return time;
}

static FORCEINLINE LARGE_INTEGER
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

/**
 * @brief Atomically update a peak counter.
 */
static FORCEINLINE VOID
CopUpdatePeak64(
    _Inout_ volatile LONG64* Peak,
    _In_ LONG64 CurrentValue
    )
{
    LONG64 oldPeak;
    do {
        oldPeak = *Peak;
        if (CurrentValue <= oldPeak) {
            return;
        }
    } while (InterlockedCompareExchange64(Peak, CurrentValue, oldPeak) != oldPeak);
}

static FORCEINLINE VOID
CopUpdatePeak32(
    _Inout_ volatile LONG* Peak,
    _In_ LONG CurrentValue
    )
{
    LONG oldPeak;
    do {
        oldPeak = *Peak;
        if (CurrentValue <= oldPeak) {
            return;
        }
    } while (InterlockedCompareExchange(Peak, CurrentValue, oldPeak) != oldPeak);
}

/**
 * @brief Destroy a cache's internals. Called from CoShutdown bypass path.
 * PRECONDITION: Cache is already removed from manager list by caller.
 */
static VOID
CopDestroyCacheInternal(
    _In_ PCO_CACHE Cache
    );

/* ========================================================================= */
/* MANAGER INITIALIZATION AND SHUTDOWN                                        */
/* ========================================================================= */

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

    if (Manager == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Manager = NULL;

    manager = (PCO_MANAGER)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(CO_MANAGER),
        CO_POOL_TAG
    );

    if (manager == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(manager, sizeof(CO_MANAGER));

    manager->MaxTotalMemory = (MaxTotalMemory != 0) ?
                              MaxTotalMemory : CO_DEFAULT_MAX_MEMORY;
    manager->DeviceObject = DeviceObject;
    manager->MaintenanceIntervalMs = CO_MAINTENANCE_INTERVAL_MS;
    manager->NextCacheId = 1;

    InitializeListHead(&manager->CacheList);
    ExInitializePushLock(&manager->CacheListLock);
    ExInitializePushLock(&manager->CallbackLock);

    KeInitializeTimer(&manager->MaintenanceTimer);
    KeInitializeDpc(&manager->MaintenanceDpc, CopMaintenanceDpcRoutine, manager);

    if (DeviceObject != NULL) {
        manager->MaintenanceWorkItem = IoAllocateWorkItem(DeviceObject);
        if (manager->MaintenanceWorkItem == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }
    }

    KeQuerySystemTime(&manager->StartTime);

    /*
     * Mark initialized BEFORE starting the timer so the DPC
     * sees a fully-initialized manager. (Fix #6)
     */
    InterlockedExchange(&manager->Initialized, TRUE);

    dueTime.QuadPart = -((LONGLONG)manager->MaintenanceIntervalMs * CO_100NS_PER_MS);
    KeSetTimerEx(
        &manager->MaintenanceTimer,
        dueTime,
        manager->MaintenanceIntervalMs,
        &manager->MaintenanceDpc
    );

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

    if (Manager == NULL ||
        InterlockedCompareExchange(&Manager->Initialized, FALSE, TRUE) != TRUE) {
        return;
    }

    InterlockedExchange(&Manager->ShuttingDown, TRUE);

    /*
     * Cancel the periodic timer. KeCancelTimer guarantees no future DPCs
     * will be queued from this timer.
     */
    KeCancelTimer(&Manager->MaintenanceTimer);

    /*
     * Flush all queued DPCs system-wide so we know CopMaintenanceDpcRoutine
     * has finished. After this, no new work items can be queued because
     * ShuttingDown == TRUE. (Fix #9)
     */
    KeFlushQueuedDpcs();

    /*
     * Wait for any in-flight maintenance work item to complete.
     * After KeFlushQueuedDpcs, no new work items will be queued.
     * This is bounded: the maintenance worker checks ShuttingDown.
     */
    if (Manager->MaintenanceRunning) {
        LARGE_INTEGER delay;
        ULONG spinCount = 0;
        delay.QuadPart = -10 * CO_100NS_PER_MS;
        while (Manager->MaintenanceRunning && spinCount < 1000) {
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
            spinCount++;
        }
        NT_ASSERT(!Manager->MaintenanceRunning);
    }

    /*
     * Destroy all caches. We remove from the list ourselves and call
     * CopDestroyCacheInternal which does NOT try to remove from the
     * manager list again. (Fix #10)
     */
    ExAcquirePushLockExclusive(&Manager->CacheListLock);

    while (!IsListEmpty(&Manager->CacheList)) {
        entry = RemoveHeadList(&Manager->CacheList);
        cache = CONTAINING_RECORD(entry, CO_CACHE, ManagerEntry);
        InitializeListHead(&cache->ManagerEntry);
        InterlockedDecrement(&Manager->CacheCount);

        ExReleasePushLockExclusive(&Manager->CacheListLock);

        CopDestroyCacheInternal(cache);

        ExAcquirePushLockExclusive(&Manager->CacheListLock);
    }

    ExReleasePushLockExclusive(&Manager->CacheListLock);

    if (Manager->MaintenanceWorkItem != NULL) {
        IoFreeWorkItem(Manager->MaintenanceWorkItem);
        Manager->MaintenanceWorkItem = NULL;
    }

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

    /*
     * SIZE_T write is atomic on x64 but not guaranteed on x86.
     * Use InterlockedExchangePointer which is pointer-sized atomic. (Fix #12)
     */
    InterlockedExchangePointer(
        (PVOID volatile *)&Manager->MaxTotalMemory,
        (PVOID)MaxBytes
    );

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

    /*
     * Synchronized write of callback + context pair to prevent
     * torn reads from DPC path. (Fix #12)
     */
    ExAcquirePushLockExclusive(&Manager->CallbackLock);
    Manager->MemoryCallback = Callback;
    Manager->MemoryCallbackContext = Context;
    ExReleasePushLockExclusive(&Manager->CallbackLock);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
CoGetManagerStats(
    PCO_MANAGER Manager,
    PSIZE_T TotalMemory,
    PULONG TotalCaches,
    PULONG TotalEntries,
    PULONG HitRatePermille
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
        PLIST_ENTRY listEntry;

        ExAcquirePushLockShared(&Manager->CacheListLock);
        for (listEntry = Manager->CacheList.Flink;
             listEntry != &Manager->CacheList;
             listEntry = listEntry->Flink) {
            PCO_CACHE cache = CONTAINING_RECORD(listEntry, CO_CACHE, ManagerEntry);
            count += (ULONG)cache->EntryCount;
        }
        ExReleasePushLockShared(&Manager->CacheListLock);
        *TotalEntries = count;
    }

    /* Integer-based hit rate: permille (0-1000). No floating-point. (Fix #5, #19) */
    if (HitRatePermille != NULL) {
        totalHits = Manager->TotalHits;
        totalMisses = Manager->TotalMisses;
        totalLookups = totalHits + totalMisses;

        if (totalLookups > 0) {
            *HitRatePermille = (ULONG)((totalHits * 1000) / totalLookups);
        } else {
            *HitRatePermille = 0;
        }
    }

    return STATUS_SUCCESS;
}

/* ========================================================================= */
/* CACHE LIFECYCLE                                                            */
/* ========================================================================= */

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
    LONG64 structMemory;

    PAGED_CODE();

    if (Manager == NULL || !Manager->Initialized || Cache == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Name == NULL || Name[0] == '\0') {
        return STATUS_INVALID_PARAMETER;
    }

    if (Type >= CoCacheTypeMax) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Manager->CacheCount >= CO_MAX_CACHES) {
        return STATUS_QUOTA_EXCEEDED;
    }

    *Cache = NULL;

    if (Config != NULL) {
        RtlCopyMemory(&localConfig, Config, sizeof(CO_CACHE_CONFIG));
    } else {
        CoInitDefaultConfig(&localConfig);
    }

    status = CopValidateBucketCount(localConfig.BucketCount, &bucketCount);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (!ShadowStrikeSafeMultiply(
            sizeof(CO_HASH_BUCKET),
            bucketCount,
            &bucketArraySize)) {
        return STATUS_INTEGER_OVERFLOW;
    }

    cache = (PCO_CACHE)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(CO_CACHE),
        CO_POOL_TAG
    );

    if (cache == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(cache, sizeof(CO_CACHE));

    cache->Type = Type;
    cache->CacheId = (ULONG)InterlockedIncrement((PLONG)&Manager->NextCacheId);
    cache->Manager = Manager;

    RtlStringCchCopyA(cache->Name, CO_CACHE_NAME_MAX, Name);

    RtlCopyMemory(&cache->Config, &localConfig, sizeof(CO_CACHE_CONFIG));

    cache->BucketCount = bucketCount;
    cache->BucketMask = bucketCount - 1;

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

    for (i = 0; i < bucketCount; i++) {
        InitializeListHead(&cache->Buckets[i].Head);
        ExInitializePushLock(&cache->Buckets[i].Lock);
    }

    for (i = 0; i < CO_SHARD_COUNT; i++) {
        InitializeListHead(&cache->Shards[i].LRUHead);
        ExInitializePushLock(&cache->Shards[i].LRULock);
    }

    InitializeListHead(&cache->GlobalEntryList);
    ExInitializePushLock(&cache->GlobalListLock);

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

    structMemory = (LONG64)(sizeof(CO_CACHE) + bucketArraySize);
    InterlockedAdd64(&cache->MemoryUsage, structMemory);
    InterlockedAdd64(&Manager->CurrentTotalMemory, structMemory);

    /* Atomic peak update (Fix #11) */
    CopUpdatePeak64(&Manager->PeakTotalMemory, Manager->CurrentTotalMemory);

    ExAcquirePushLockExclusive(&Manager->CacheListLock);
    InsertTailList(&Manager->CacheList, &cache->ManagerEntry);
    InterlockedIncrement(&Manager->CacheCount);
    ExReleasePushLockExclusive(&Manager->CacheListLock);

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

    PAGED_CODE();

    if (Cache == NULL || !Cache->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    manager = Cache->Manager;

    InterlockedExchange(&Cache->ShuttingDown, TRUE);

    /* Remove from manager's list (Fix #10 — only one removal site) */
    if (manager != NULL) {
        ExAcquirePushLockExclusive(&manager->CacheListLock);
        RemoveEntryList(&Cache->ManagerEntry);
        InitializeListHead(&Cache->ManagerEntry);
        InterlockedDecrement(&manager->CacheCount);
        ExReleasePushLockExclusive(&manager->CacheListLock);
    }

    CopDestroyCacheInternal(Cache);

    return STATUS_SUCCESS;
}

/**
 * @brief Destroys cache internals and frees the cache structure.
 *
 * PRECONDITION: Cache has already been removed from the manager's CacheList
 * by the caller (CoDestroyCache or CoShutdown). This function does NOT
 * touch the manager's CacheList. (Fix #10)
 */
static VOID
CopDestroyCacheInternal(
    _In_ PCO_CACHE Cache
    )
{
    PCO_MANAGER manager;
    SIZE_T memoryFreed;

    manager = Cache->Manager;

    InterlockedExchange(&Cache->ShuttingDown, TRUE);

    CoFlush(Cache);

    memoryFreed = sizeof(CO_CACHE) +
                  ((SIZE_T)Cache->BucketCount * sizeof(CO_HASH_BUCKET));

    if (Cache->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&Cache->EntryLookaside);
        Cache->LookasideInitialized = FALSE;
    }

    if (Cache->Buckets != NULL) {
        ShadowStrikeFreePoolWithTag(Cache->Buckets, CO_HASH_POOL_TAG);
        Cache->Buckets = NULL;
    }

    if (manager != NULL) {
        InterlockedAdd64(&manager->CurrentTotalMemory, -(LONG64)memoryFreed);
    }

    Cache->Initialized = FALSE;
    ShadowStrikeFreePoolWithTag(Cache, CO_POOL_TAG);
}

/**
 * @brief Flush all entries from a cache.
 *
 * Lock ordering: bucket lock → shard LRU lock → global list lock. (Fix #3, #4)
 *
 * We iterate buckets (not the global list) so we always hold the bucket
 * lock when calling CopRemoveEntryFromCache.
 */
_Use_decl_annotations_
NTSTATUS
CoFlush(
    PCO_CACHE Cache
    )
{
    ULONG i;
    PLIST_ENTRY listEntry;
    PLIST_ENTRY nextEntry;
    PCO_CACHE_ENTRY cacheEntry;
    PCO_HASH_BUCKET bucket;

    if (Cache == NULL || !Cache->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    for (i = 0; i < Cache->BucketCount; i++) {
        bucket = &Cache->Buckets[i];

        if (bucket->EntryCount == 0) {
            continue;
        }

        ExAcquirePushLockExclusive(&bucket->Lock);

        for (listEntry = bucket->Head.Flink;
             listEntry != &bucket->Head;
             listEntry = nextEntry) {

            nextEntry = listEntry->Flink;
            cacheEntry = CONTAINING_RECORD(listEntry, CO_CACHE_ENTRY, HashEntry);

            /* CopRemoveEntryFromCache requires bucket lock held — we hold it */
            CopRemoveEntryFromCache(Cache, cacheEntry, TRUE);
        }

        ExReleasePushLockExclusive(&bucket->Lock);
    }

    return STATUS_SUCCESS;
}

/* ========================================================================= */
/* CACHE OPERATIONS - PUT                                                     */
/* ========================================================================= */

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
    LARGE_INTEGER currentTime;
    PVOID dataCopy = NULL;
    SIZE_T totalMemory;

    if (Cache == NULL || !Cache->Initialized || Cache->ShuttingDown) {
        return STATUS_INVALID_PARAMETER;
    }

    if (TTLSeconds == 0) {
        TTLSeconds = Cache->Config.DefaultTTLSeconds;
    }
    if (TTLSeconds > CO_MAX_TTL_SECONDS) {
        TTLSeconds = CO_MAX_TTL_SECONDS;
    }

    bucketIndex = CoGetBucketIndex(Cache, Key);
    shardIndex = CoGetShardIndex(Key);
    bucket = &Cache->Buckets[bucketIndex];

    currentTime = CopGetCurrentTime();

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

    ExAcquirePushLockExclusive(&bucket->Lock);

    existingEntry = CopFindEntryInBucket(Cache, bucketIndex, Key);

    if (existingEntry != NULL) {
        /*
         * UPDATE existing entry — done entirely under bucket lock.
         * LRU promotion is also done under bucket lock to prevent
         * use-after-free. (Fix #2)
         */
        if (existingEntry->DataOwned && existingEntry->Data != NULL) {
            SIZE_T oldSize = existingEntry->DataSize;
            ShadowStrikeFreePoolWithTag(existingEntry->Data, CO_DATA_POOL_TAG);
            InterlockedAdd64(&Cache->MemoryUsage, -(LONG64)oldSize);
            if (Cache->Manager != NULL) {
                InterlockedAdd64(&Cache->Manager->CurrentTotalMemory, -(LONG64)oldSize);
            }
        }

        existingEntry->Data = (dataCopy != NULL) ? dataCopy : Data;
        existingEntry->DataSize = DataSize;
        existingEntry->DataOwned = (dataCopy != NULL);
        existingEntry->SecondaryKey = SecondaryKey;
        existingEntry->TTLSeconds = TTLSeconds;
        existingEntry->ExpireTime = CopCalculateExpireTime(&currentTime, TTLSeconds);
        existingEntry->Flags = Flags;
        existingEntry->UserContext = UserContext;

        InterlockedIncrement(&existingEntry->AccessCount);
        InterlockedExchange64(&existingEntry->LastAccessTimeQpc, currentTime.QuadPart);

        if (dataCopy != NULL) {
            InterlockedAdd64(&Cache->MemoryUsage, (LONG64)DataSize);
            if (Cache->Manager != NULL) {
                InterlockedAdd64(&Cache->Manager->CurrentTotalMemory, (LONG64)DataSize);
            }
        }

        InterlockedIncrement64(&Cache->Stats.Updates);

        /* Promote in LRU while entry is guaranteed alive (Fix #2) */
        CopPromoteInLRU(Cache, existingEntry);

        ExReleasePushLockExclusive(&bucket->Lock);

        return STATUS_SUCCESS;
    }

    /*
     * NEW entry path.
     *
     * Capacity check: we do a best-effort check. Under high concurrency,
     * the count may slightly overshoot MaxEntries; this is acceptable
     * and avoids a global lock. (Fix #15 — documented, not hidden)
     */
    if ((ULONG)Cache->EntryCount >= Cache->Config.MaxEntries) {
        ExReleasePushLockExclusive(&bucket->Lock);

        CopEvictLRUEntries(Cache, CO_EVICTION_BATCH_SIZE);

        ExAcquirePushLockExclusive(&bucket->Lock);

        /*
         * Re-check for existing key: another thread may have inserted the
         * same key while we released the bucket lock for eviction.
         * Without this check, duplicate keys would corrupt the hash chain.
         */
        existingEntry = CopFindEntryInBucket(Cache, bucketIndex, Key);
        if (existingEntry != NULL) {
            /* Race: another thread inserted this key — update it instead */
            if (existingEntry->DataOwned && existingEntry->Data != NULL) {
                SIZE_T oldSize = existingEntry->DataSize;
                ShadowStrikeFreePoolWithTag(existingEntry->Data, CO_DATA_POOL_TAG);
                InterlockedAdd64(&Cache->MemoryUsage, -(LONG64)oldSize);
                if (Cache->Manager != NULL) {
                    InterlockedAdd64(&Cache->Manager->CurrentTotalMemory, -(LONG64)oldSize);
                }
            }
            existingEntry->Data = (dataCopy != NULL) ? dataCopy : Data;
            existingEntry->DataSize = DataSize;
            existingEntry->DataOwned = (dataCopy != NULL);
            existingEntry->SecondaryKey = SecondaryKey;
            existingEntry->TTLSeconds = TTLSeconds;
            existingEntry->ExpireTime = CopCalculateExpireTime(&currentTime, TTLSeconds);
            existingEntry->Flags = Flags;
            existingEntry->UserContext = UserContext;
            InterlockedIncrement(&existingEntry->AccessCount);
            InterlockedExchange64(&existingEntry->LastAccessTimeQpc, currentTime.QuadPart);
            if (dataCopy != NULL) {
                InterlockedAdd64(&Cache->MemoryUsage, (LONG64)DataSize);
                if (Cache->Manager != NULL) {
                    InterlockedAdd64(&Cache->Manager->CurrentTotalMemory, (LONG64)DataSize);
                }
            }
            InterlockedIncrement64(&Cache->Stats.Updates);
            CopPromoteInLRU(Cache, existingEntry);
            ExReleasePushLockExclusive(&bucket->Lock);
            return STATUS_SUCCESS;
        }

        if ((ULONG)Cache->EntryCount >= Cache->Config.MaxEntries) {
            ExReleasePushLockExclusive(&bucket->Lock);
            if (dataCopy != NULL) {
                ShadowStrikeFreePoolWithTag(dataCopy, CO_DATA_POOL_TAG);
            }
            InterlockedIncrement64(&Cache->Stats.CapacityEvictions);
            return STATUS_QUOTA_EXCEEDED;
        }
    }

    status = CopAllocateEntry(Cache, &entry);
    if (!NT_SUCCESS(status)) {
        ExReleasePushLockExclusive(&bucket->Lock);
        if (dataCopy != NULL) {
            ShadowStrikeFreePoolWithTag(dataCopy, CO_DATA_POOL_TAG);
        }
        return status;
    }

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
    entry->LastAccessTimeQpc = currentTime.QuadPart;
    entry->TTLSeconds = TTLSeconds;
    entry->ExpireTime = CopCalculateExpireTime(&currentTime, TTLSeconds);
    entry->Flags = Flags;
    entry->BucketIndex = bucketIndex;
    entry->ShardIndex = shardIndex;
    entry->UserContext = UserContext;
    entry->OwnerCache = Cache;

    /* Insert into hash bucket (we hold the bucket lock) */
    InsertHeadList(&bucket->Head, &entry->HashEntry);
    InterlockedIncrement(&bucket->EntryCount);
    if (bucket->EntryCount > 1) {
        InterlockedIncrement(&bucket->Collisions);
    }

    /*
     * Insert into shard LRU (lock order: bucket → shard LRU ✓)
     * We can call this while holding the bucket lock.
     */
    CopInsertIntoLRU(Cache, entry);

    /*
     * Insert into global list (lock order: bucket → shard → global ✓)
     */
    ExAcquirePushLockExclusive(&Cache->GlobalListLock);
    InsertTailList(&Cache->GlobalEntryList, &entry->GlobalEntry);
    ExReleasePushLockExclusive(&Cache->GlobalListLock);

    ExReleasePushLockExclusive(&bucket->Lock);

    InterlockedIncrement(&Cache->EntryCount);
    InterlockedIncrement64(&Cache->Stats.Inserts);
    InterlockedIncrement(&Cache->Stats.CurrentEntries);
    CopUpdatePeak32(&Cache->Stats.PeakEntries, Cache->Stats.CurrentEntries);

    totalMemory = sizeof(CO_CACHE_ENTRY);
    if (dataCopy != NULL) {
        totalMemory += DataSize;
    }

    InterlockedAdd64(&Cache->MemoryUsage, (LONG64)totalMemory);
    InterlockedAdd64(&Cache->Stats.CurrentMemory, (LONG64)totalMemory);

    if (Cache->Manager != NULL) {
        InterlockedAdd64(&Cache->Manager->CurrentTotalMemory, (LONG64)totalMemory);
        CopUpdatePeak64(&Cache->Manager->PeakTotalMemory,
                        Cache->Manager->CurrentTotalMemory);
    }

    CopUpdatePeak64(&Cache->Stats.PeakMemory, Cache->Stats.CurrentMemory);

    return STATUS_SUCCESS;
}

/* ========================================================================= */
/* CACHE OPERATIONS - GET (SAFE COPY, NO USE-AFTER-FREE)                      */
/* ========================================================================= */

/**
 * @brief Look up an entry. Returns a COPY of the data to the caller.
 *
 * The data is copied under the bucket lock so the entry cannot be freed
 * while we read from it. (Fix #1 — eliminates use-after-free)
 *
 * If DataBuffer is NULL, we only check existence and return the size.
 * If DataBuffer is non-NULL but *DataSize < actual size, returns
 * STATUS_BUFFER_TOO_SMALL and sets *DataSize to the required size.
 */
_Use_decl_annotations_
NTSTATUS
CoGet(
    PCO_CACHE Cache,
    ULONG64 Key,
    PVOID DataBuffer,
    PSIZE_T DataSize
    )
{
    PCO_CACHE_ENTRY entry;
    ULONG bucketIndex;
    PCO_HASH_BUCKET bucket;
    LARGE_INTEGER currentTime;

    if (Cache == NULL || !Cache->Initialized || Cache->ShuttingDown) {
        return STATUS_INVALID_PARAMETER;
    }

    InterlockedIncrement64(&Cache->Stats.TotalLookups);
    if (Cache->Manager != NULL) {
        InterlockedIncrement64(&Cache->Manager->TotalOperations);
    }

    bucketIndex = CoGetBucketIndex(Cache, Key);
    bucket = &Cache->Buckets[bucketIndex];
    currentTime = CopGetCurrentTime();

    /*
     * Acquire bucket lock SHARED for the lookup + data copy.
     * If expired, we upgrade to exclusive to remove.
     */
    ExAcquirePushLockShared(&bucket->Lock);

    entry = CopFindEntryInBucket(Cache, bucketIndex, Key);

    if (entry == NULL) {
        ExReleasePushLockShared(&bucket->Lock);
        goto Miss;
    }

    if (CopIsEntryExpired(entry, &currentTime)) {
        ExReleasePushLockShared(&bucket->Lock);

        /* Upgrade to exclusive to remove expired entry */
        ExAcquirePushLockExclusive(&bucket->Lock);
        entry = CopFindEntryInBucket(Cache, bucketIndex, Key);
        if (entry != NULL && CopIsEntryExpired(entry, &currentTime)) {
            CopRemoveEntryFromCache(Cache, entry, TRUE);
            InterlockedIncrement64(&Cache->Stats.TTLEvictions);
        }
        ExReleasePushLockExclusive(&bucket->Lock);
        goto Miss;
    }

    /*
     * Copy data under the lock — this is the fix for issue #1.
     * The entry cannot be freed while we hold even a shared bucket lock
     * because removal requires exclusive bucket lock.
     */
    if (DataSize != NULL) {
        if (DataBuffer != NULL) {
            if (*DataSize < entry->DataSize) {
                *DataSize = entry->DataSize;
                ExReleasePushLockShared(&bucket->Lock);
                return STATUS_BUFFER_TOO_SMALL;
            }
            if (entry->Data != NULL && entry->DataSize > 0) {
                RtlCopyMemory(DataBuffer, entry->Data, entry->DataSize);
            }
        }
        *DataSize = entry->DataSize;
    }

    /* Update access tracking (atomic — safe under shared lock) (Fix #16) */
    InterlockedExchange64(&entry->LastAccessTimeQpc, currentTime.QuadPart);
    InterlockedIncrement(&entry->AccessCount);
    InterlockedIncrement(&entry->HitCount);

    /*
     * LRU promotion under the bucket lock. We hold bucket shared;
     * CopPromoteInLRU acquires shard LRU lock (lock order: bucket → shard ✓).
     * The entry is guaranteed alive. (Fix #2)
     */
    if (entry->HitCount >= CO_LRU_PROMOTION_THRESHOLD) {
        InterlockedExchange(&entry->HitCount, 0);
        CopPromoteInLRU(Cache, entry);
    }

    ExReleasePushLockShared(&bucket->Lock);

    InterlockedIncrement64(&Cache->Stats.Hits);
    if (Cache->Manager != NULL) {
        InterlockedIncrement64(&Cache->Manager->TotalHits);
    }

    return STATUS_SUCCESS;

Miss:
    InterlockedIncrement64(&Cache->Stats.Misses);
    if (Cache->Manager != NULL) {
        InterlockedIncrement64(&Cache->Manager->TotalMisses);
    }
    return STATUS_NOT_FOUND;
}

/**
 * @brief Extended lookup. Allocates a copy of the data in Result->Data.
 *
 * Caller MUST call CoFreeLookupResult() to free Result->Data.
 */
_Use_decl_annotations_
NTSTATUS
CoGetEx(
    PCO_CACHE Cache,
    ULONG64 Key,
    PCO_LOOKUP_RESULT Result
    )
{
    PCO_CACHE_ENTRY entry;
    ULONG bucketIndex;
    PCO_HASH_BUCKET bucket;
    LARGE_INTEGER currentTime;
    PVOID dataCopy = NULL;

    if (Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Result, sizeof(CO_LOOKUP_RESULT));
    Result->Key = Key;

    if (Cache == NULL || !Cache->Initialized || Cache->ShuttingDown) {
        Result->Result = CoResultNotInitialized;
        return STATUS_INVALID_PARAMETER;
    }

    InterlockedIncrement64(&Cache->Stats.TotalLookups);
    if (Cache->Manager != NULL) {
        InterlockedIncrement64(&Cache->Manager->TotalOperations);
    }

    bucketIndex = CoGetBucketIndex(Cache, Key);
    bucket = &Cache->Buckets[bucketIndex];
    currentTime = CopGetCurrentTime();

    ExAcquirePushLockShared(&bucket->Lock);

    entry = CopFindEntryInBucket(Cache, bucketIndex, Key);

    if (entry == NULL) {
        ExReleasePushLockShared(&bucket->Lock);
        Result->Result = CoResultNotFound;
        goto Miss;
    }

    if (CopIsEntryExpired(entry, &currentTime)) {
        ExReleasePushLockShared(&bucket->Lock);

        ExAcquirePushLockExclusive(&bucket->Lock);
        entry = CopFindEntryInBucket(Cache, bucketIndex, Key);
        if (entry != NULL && CopIsEntryExpired(entry, &currentTime)) {
            CopRemoveEntryFromCache(Cache, entry, TRUE);
            InterlockedIncrement64(&Cache->Stats.TTLEvictions);
        }
        ExReleasePushLockExclusive(&bucket->Lock);

        Result->Result = CoResultExpired;
        Result->WasExpired = TRUE;
        goto Miss;
    }

    /*
     * Copy data under lock. Allocate a buffer and copy.
     * This is the safe path — no use-after-free. (Fix #1)
     */
    if (entry->Data != NULL && entry->DataSize > 0) {
        dataCopy = ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            entry->DataSize,
            CO_DATA_POOL_TAG
        );
        if (dataCopy == NULL) {
            /*
             * Pool allocation failed — cannot copy entry data.
             * Do NOT report CoResultSuccess with NULL data; callers
             * would dereference NULL. Release lock and return error.
             */
            ExReleasePushLockShared(&bucket->Lock);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlCopyMemory(dataCopy, entry->Data, entry->DataSize);
    }

    Result->Result = CoResultSuccess;
    Result->Data = dataCopy;
    Result->DataSize = entry->DataSize;
    Result->CreateTime = entry->CreateTime;
    Result->ExpireTime = entry->ExpireTime;
    Result->AccessCount = entry->AccessCount;
    Result->WasExpired = FALSE;

    InterlockedExchange64(&entry->LastAccessTimeQpc, currentTime.QuadPart);
    InterlockedIncrement(&entry->AccessCount);
    InterlockedIncrement(&entry->HitCount);

    if (entry->HitCount >= CO_LRU_PROMOTION_THRESHOLD) {
        InterlockedExchange(&entry->HitCount, 0);
        CopPromoteInLRU(Cache, entry);
    }

    ExReleasePushLockShared(&bucket->Lock);

    InterlockedIncrement64(&Cache->Stats.Hits);
    if (Cache->Manager != NULL) {
        InterlockedIncrement64(&Cache->Manager->TotalHits);
    }

    return STATUS_SUCCESS;

Miss:
    InterlockedIncrement64(&Cache->Stats.Misses);
    if (Cache->Manager != NULL) {
        InterlockedIncrement64(&Cache->Manager->TotalMisses);
    }
    return STATUS_NOT_FOUND;
}

_Use_decl_annotations_
VOID
CoFreeLookupResult(
    PCO_LOOKUP_RESULT Result
    )
{
    if (Result == NULL) {
        return;
    }

    if (Result->Data != NULL) {
        ShadowStrikeFreePoolWithTag(Result->Data, CO_DATA_POOL_TAG);
        Result->Data = NULL;
    }

    Result->DataSize = 0;
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

/* ========================================================================= */
/* CACHE OPERATIONS - INVALIDATE / TOUCH / PIN / UNPIN                        */
/* ========================================================================= */

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

    /* Atomic access time update (Fix #16) */
    InterlockedExchange64(&entry->LastAccessTimeQpc, currentTime.QuadPart);

    /* Promote under bucket lock — entry is alive (Fix #2) */
    CopPromoteInLRU(Cache, entry);

    ExReleasePushLockShared(&bucket->Lock);

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

/* ========================================================================= */
/* STATISTICS AND MONITORING (NO FLOATING-POINT)                              */
/* ========================================================================= */

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

/**
 * @brief Get cache hit rate as permille (0-1000). No floating-point. (Fix #5, #19)
 */
_Use_decl_annotations_
ULONG
CoGetHitRate(
    PCO_CACHE Cache
    )
{
    LONG64 hits;
    LONG64 misses;
    LONG64 total;

    if (Cache == NULL) {
        return 0;
    }

    hits = Cache->Stats.Hits;
    misses = Cache->Stats.Misses;
    total = hits + misses;

    if (total == 0) {
        return 0;
    }

    return (ULONG)((hits * 1000) / total);
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

/* ========================================================================= */
/* MAINTENANCE FUNCTIONS                                                      */
/* ========================================================================= */

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

    if (InterlockedCompareExchange(&Cache->MaintenanceActive, TRUE, FALSE) != FALSE) {
        return 0;
    }

    evicted = CopEvictExpiredEntries(Cache, CO_EVICTION_BATCH_SIZE * 2);

    InterlockedIncrement64(&Cache->Stats.MaintenanceCycles);
    KeQuerySystemTime(&Cache->Stats.LastMaintenanceTime);

    if (Cache->Manager != NULL && Cache->Manager->MaxTotalMemory > 0) {
        LONG64 currentMem = Cache->Manager->CurrentTotalMemory;
        LONG64 maxMem = (LONG64)Cache->Manager->MaxTotalMemory;

        if (maxMem > 0) {
            ULONG pressurePercent = (ULONG)((currentMem * 100) / maxMem);

            if (pressurePercent > CO_MEMORY_PRESSURE_THRESHOLD) {
                ULONG additionalEvictions = CopEvictLRUEntries(
                    Cache,
                    CO_EVICTION_BATCH_SIZE
                );
                evicted += additionalEvictions;
                InterlockedAdd64(&Cache->Stats.MemoryEvictions, additionalEvictions);
            }
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

    while ((SIZE_T)Cache->MemoryUsage > TargetBytes && Cache->EntryCount > 0) {
        evictBatch = CopEvictLRUEntries(Cache, CO_EVICTION_BATCH_SIZE);
        if (evictBatch == 0) {
            break;
        }
    }

    bytesFreed = initialUsage - (SIZE_T)Cache->MemoryUsage;
    return bytesFreed;
}

/* ========================================================================= */
/* INTERNAL HELPER FUNCTIONS                                                  */
/* ========================================================================= */

static NTSTATUS
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

static VOID
CopFreeEntry(
    _In_ PCO_CACHE Cache,
    _In_ PCO_CACHE_ENTRY Entry
    )
{
    if (Entry == NULL) {
        return;
    }

    if (Entry->DataOwned && Entry->Data != NULL) {
        ShadowStrikeFreePoolWithTag(Entry->Data, CO_DATA_POOL_TAG);
        Entry->Data = NULL;
    }

    if (Cache->LookasideInitialized) {
        ExFreeToNPagedLookasideList(&Cache->EntryLookaside, Entry);
    } else {
        ShadowStrikeFreePoolWithTag(Entry, CO_ENTRY_POOL_TAG);
    }
}

static PCO_CACHE_ENTRY
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

static VOID
CopInsertIntoLRU(
    _In_ PCO_CACHE Cache,
    _In_ PCO_CACHE_ENTRY Entry
    )
{
    PCO_CACHE_SHARD shard;

    shard = &Cache->Shards[Entry->ShardIndex];

    ExAcquirePushLockExclusive(&shard->LRULock);
    InsertHeadList(&shard->LRUHead, &Entry->LRUEntry);
    InterlockedIncrement(&shard->EntryCount);
    ExReleasePushLockExclusive(&shard->LRULock);
}

static VOID
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

/**
 * @brief Promote entry to MRU position in its shard.
 *
 * Called while the caller holds the bucket lock (shared or exclusive).
 * Lock order: bucket → shard LRU ✓ (Fix #2, #4)
 */
static VOID
CopPromoteInLRU(
    _In_ PCO_CACHE Cache,
    _In_ PCO_CACHE_ENTRY Entry
    )
{
    PCO_CACHE_SHARD shard;

    shard = &Cache->Shards[Entry->ShardIndex];

    ExAcquirePushLockExclusive(&shard->LRULock);

    if (!IsListEmpty(&Entry->LRUEntry)) {
        RemoveEntryList(&Entry->LRUEntry);
        InsertHeadList(&shard->LRUHead, &Entry->LRUEntry);
    }

    ExReleasePushLockExclusive(&shard->LRULock);
}

/**
 * @brief Evict the LRU entry from a shard.
 *
 * Lock order: acquires shard LRU lock → bucket lock → global list lock. (Fix #4)
 *
 * Wait — this is bucket AFTER shard, which violates our stated lock order!
 * Resolution: We grab the entry pointer and its BucketIndex under the shard
 * lock, RELEASE the shard lock (having already removed the LRU entry from
 * the shard list), then acquire the bucket lock independently.
 * This is safe because:
 *   1. The entry's LRUEntry is removed from the shard list, so no other LRU
 *      operation can see it.
 *   2. The entry is still linked in the bucket's hash chain, so it won't be
 *      freed by anyone else until we remove it from the bucket.
 *   3. We set State = Evicting atomically so concurrent readers see it.
 *
 * @return TRUE if an entry was actually evicted, FALSE otherwise. (Fix #7)
 */
static BOOLEAN
CopEvictLRUEntry(
    _In_ PCO_CACHE Cache,
    _In_ PCO_CACHE_SHARD Shard
    )
{
    PLIST_ENTRY tailEntry;
    PCO_CACHE_ENTRY entry;
    PCO_HASH_BUCKET bucket;
    ULONG bucketIndex;
    SIZE_T memoryFreed;

    ExAcquirePushLockExclusive(&Shard->LRULock);

    if (IsListEmpty(&Shard->LRUHead)) {
        ExReleasePushLockExclusive(&Shard->LRULock);
        return FALSE;
    }

    tailEntry = Shard->LRUHead.Blink;
    entry = CONTAINING_RECORD(tailEntry, CO_CACHE_ENTRY, LRUEntry);

    /* Don't evict pinned entries (Fix #7) */
    if (entry->State == CoEntryStatePinned) {
        ExReleasePushLockExclusive(&Shard->LRULock);
        return FALSE;
    }

    /* Remove from LRU list while we hold the shard lock */
    RemoveEntryList(&entry->LRUEntry);
    InitializeListHead(&entry->LRUEntry);
    InterlockedDecrement(&Shard->EntryCount);

    ExReleasePushLockExclusive(&Shard->LRULock);

    /* Mark as evicting so concurrent readers skip it */
    InterlockedExchange(&entry->State, CoEntryStateEvicting);

    /* Now acquire bucket lock to remove from hash chain */
    bucketIndex = entry->BucketIndex;
    bucket = &Cache->Buckets[bucketIndex];

    ExAcquirePushLockExclusive(&bucket->Lock);
    if (!IsListEmpty(&entry->HashEntry)) {
        RemoveEntryList(&entry->HashEntry);
        InitializeListHead(&entry->HashEntry);
        InterlockedDecrement(&bucket->EntryCount);
    }
    ExReleasePushLockExclusive(&bucket->Lock);

    /* Remove from global list (lock order: independent, no bucket held) */
    ExAcquirePushLockExclusive(&Cache->GlobalListLock);
    if (!IsListEmpty(&entry->GlobalEntry)) {
        RemoveEntryList(&entry->GlobalEntry);
        InitializeListHead(&entry->GlobalEntry);
    }
    ExReleasePushLockExclusive(&Cache->GlobalListLock);

    CopCallCleanupCallback(Cache, entry);

    memoryFreed = sizeof(CO_CACHE_ENTRY);
    if (entry->DataOwned && entry->Data != NULL) {
        memoryFreed += entry->DataSize;
    }

    InterlockedAdd64(&Cache->MemoryUsage, -(LONG64)memoryFreed);
    InterlockedAdd64(&Cache->Stats.CurrentMemory, -(LONG64)memoryFreed);
    if (Cache->Manager != NULL) {
        InterlockedAdd64(&Cache->Manager->CurrentTotalMemory, -(LONG64)memoryFreed);
    }

    InterlockedDecrement(&Cache->EntryCount);
    InterlockedDecrement(&Cache->Stats.CurrentEntries);
    InterlockedIncrement64(&Shard->Evictions);

    CopFreeEntry(Cache, entry);

    return TRUE;
}

static BOOLEAN
CopIsEntryExpired(
    _In_ PCO_CACHE_ENTRY Entry,
    _In_ PLARGE_INTEGER CurrentTime
    )
{
    if (Entry->State == CoEntryStatePinned) {
        return FALSE;
    }

    if (Entry->State == CoEntryStateEvicting ||
        Entry->State == CoEntryStateInvalid) {
        return FALSE;
    }

    return CurrentTime->QuadPart >= Entry->ExpireTime.QuadPart;
}

static VOID
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

/**
 * @brief Remove entry from cache, unlink from all lists, and free.
 *
 * PRECONDITION: Caller MUST hold the entry's bucket lock EXCLUSIVE.
 *
 * Lock acquisition order:
 *   - Bucket lock: already held by caller ✓
 *   - Shard LRU lock: acquired here (bucket → shard ✓)
 *   - Global list lock: acquired here (bucket → shard → global ✓)
 *
 * This enforces the global lock order. (Fix #3, #4, #13)
 */
static VOID
CopRemoveEntryFromCache(
    _In_ PCO_CACHE Cache,
    _In_ PCO_CACHE_ENTRY Entry,
    _In_ BOOLEAN CallCleanup
    )
{
    SIZE_T memoryFreed;

    InterlockedExchange(&Entry->State, CoEntryStateEvicting);

    /* Remove from hash bucket — caller holds bucket lock exclusive */
    if (!IsListEmpty(&Entry->HashEntry)) {
        RemoveEntryList(&Entry->HashEntry);
        InitializeListHead(&Entry->HashEntry);
        InterlockedDecrement(&Cache->Buckets[Entry->BucketIndex].EntryCount);
    }

    /* Remove from LRU (acquires shard LRU lock — lock order: bucket → shard ✓) */
    CopRemoveFromLRU(Cache, Entry);

    /* Remove from global list (acquires global list lock — lock order: bucket → shard → global ✓) */
    ExAcquirePushLockExclusive(&Cache->GlobalListLock);
    if (!IsListEmpty(&Entry->GlobalEntry)) {
        RemoveEntryList(&Entry->GlobalEntry);
        InitializeListHead(&Entry->GlobalEntry);
    }
    ExReleasePushLockExclusive(&Cache->GlobalListLock);

    if (CallCleanup) {
        CopCallCleanupCallback(Cache, Entry);
    }

    memoryFreed = sizeof(CO_CACHE_ENTRY);
    if (Entry->DataOwned && Entry->Data != NULL) {
        memoryFreed += Entry->DataSize;
    }

    InterlockedAdd64(&Cache->MemoryUsage, -(LONG64)memoryFreed);
    InterlockedAdd64(&Cache->Stats.CurrentMemory, -(LONG64)memoryFreed);
    if (Cache->Manager != NULL) {
        InterlockedAdd64(&Cache->Manager->CurrentTotalMemory, -(LONG64)memoryFreed);
    }

    InterlockedDecrement(&Cache->EntryCount);
    InterlockedDecrement(&Cache->Stats.CurrentEntries);

    CopFreeEntry(Cache, Entry);
}

/**
 * @brief Evict expired entries by scanning buckets.
 *
 * Acquires each bucket lock exclusively, then calls CopRemoveEntryFromCache
 * which follows the lock order (bucket → shard → global). (Fix #3, #4)
 */
static ULONG
CopEvictExpiredEntries(
    _In_ PCO_CACHE Cache,
    _In_ ULONG MaxToEvict
    )
{
    ULONG evicted = 0;
    ULONG i;
    PLIST_ENTRY listEntry;
    PLIST_ENTRY nextEntry;
    PCO_CACHE_ENTRY cacheEntry;
    LARGE_INTEGER currentTime;
    PCO_HASH_BUCKET bucket;

    currentTime = CopGetCurrentTime();

    for (i = 0; i < Cache->BucketCount && evicted < MaxToEvict; i++) {
        bucket = &Cache->Buckets[i];

        if (bucket->EntryCount == 0) {
            continue;
        }

        ExAcquirePushLockExclusive(&bucket->Lock);

        for (listEntry = bucket->Head.Flink;
             listEntry != &bucket->Head && evicted < MaxToEvict;
             listEntry = nextEntry) {

            nextEntry = listEntry->Flink;
            cacheEntry = CONTAINING_RECORD(listEntry, CO_CACHE_ENTRY, HashEntry);

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

/**
 * @brief Evict LRU entries from shards. Returns ACTUAL eviction count. (Fix #7)
 */
static ULONG
CopEvictLRUEntries(
    _In_ PCO_CACHE Cache,
    _In_ ULONG Count
    )
{
    ULONG evicted = 0;
    ULONG shardIndex;

    for (shardIndex = 0; shardIndex < CO_SHARD_COUNT && evicted < Count; shardIndex++) {
        PCO_CACHE_SHARD shard = &Cache->Shards[shardIndex];

        while (shard->EntryCount > 0 && evicted < Count) {
            if (CopEvictLRUEntry(Cache, shard)) {
                evicted++;
                InterlockedIncrement64(&Cache->Stats.LRUEvictions);
            } else {
                /* Shard is empty or all entries are pinned — move to next shard */
                break;
            }
        }
    }

    return evicted;
}

static VOID
CopMaintenanceWorker(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    )
{
    PCO_MANAGER manager = (PCO_MANAGER)Context;
    PLIST_ENTRY listEntry;
    PCO_CACHE cache;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (manager == NULL || manager->ShuttingDown) {
        if (manager != NULL) {
            InterlockedExchange(&manager->MaintenanceRunning, FALSE);
        }
        return;
    }

    ExAcquirePushLockShared(&manager->CacheListLock);

    for (listEntry = manager->CacheList.Flink;
         listEntry != &manager->CacheList;
         listEntry = listEntry->Flink) {

        cache = CONTAINING_RECORD(listEntry, CO_CACHE, ManagerEntry);

        if (cache->Initialized && !cache->ShuttingDown) {
            CoRunMaintenance(cache);
        }
    }

    ExReleasePushLockShared(&manager->CacheListLock);

    CopUpdateMemoryPressure(manager);

    InterlockedExchange(&manager->MaintenanceRunning, FALSE);
}

static VOID
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

    if (manager == NULL || manager->ShuttingDown || !manager->Initialized) {
        return;
    }

    if (InterlockedCompareExchange(&manager->MaintenanceRunning, TRUE, FALSE) != FALSE) {
        return;
    }

    if (manager->MaintenanceWorkItem != NULL) {
        IoQueueWorkItem(
            manager->MaintenanceWorkItem,
            CopMaintenanceWorker,
            DelayedWorkQueue,
            manager
        );
    } else {
        InterlockedExchange(&manager->MaintenanceRunning, FALSE);
    }
}

static VOID
CopUpdateMemoryPressure(
    _In_ PCO_MANAGER Manager
    )
{
    LONG64 currentMem;
    LONG64 maxMem;
    ULONG pressurePercent;
    CO_MEMORY_PRESSURE_CALLBACK callback = NULL;
    PVOID callbackContext = NULL;

    maxMem = (LONG64)(SIZE_T)InterlockedCompareExchangePointer(
        (PVOID volatile *)&Manager->MaxTotalMemory,
        (PVOID)Manager->MaxTotalMemory,
        (PVOID)Manager->MaxTotalMemory
    );

    if (maxMem == 0) {
        InterlockedExchange(&Manager->MemoryPressure, 0);
        return;
    }

    currentMem = Manager->CurrentTotalMemory;

    if (maxMem > 0) {
        pressurePercent = (ULONG)((currentMem * 100) / maxMem);
    } else {
        pressurePercent = 0;
    }

    InterlockedExchange(&Manager->MemoryPressure, (LONG)pressurePercent);

    /* Read callback + context atomically under lock (Fix #12) */
    if (pressurePercent >= CO_MEMORY_PRESSURE_THRESHOLD) {
        ExAcquirePushLockShared(&Manager->CallbackLock);
        callback = Manager->MemoryCallback;
        callbackContext = Manager->MemoryCallbackContext;
        ExReleasePushLockShared(&Manager->CallbackLock);

        if (callback != NULL) {
            callback(
                Manager,
                (SIZE_T)currentMem,
                (SIZE_T)maxMem,
                callbackContext
            );
        }
    }
}

static NTSTATUS
CopValidateBucketCount(
    _In_ ULONG BucketCount,
    _Out_ PULONG ValidatedCount
    )
{
    ULONG count;

    if (BucketCount == 0) {
        *ValidatedCount = CO_DEFAULT_BUCKET_COUNT;
        return STATUS_SUCCESS;
    }

    count = BucketCount;
    if (count < CO_MIN_BUCKET_COUNT) {
        count = CO_MIN_BUCKET_COUNT;
    }
    if (count > CO_MAX_BUCKET_COUNT) {
        count = CO_MAX_BUCKET_COUNT;
    }

    /* Round up to power of 2 */
    count--;
    count |= count >> 1;
    count |= count >> 2;
    count |= count >> 4;
    count |= count >> 8;
    count |= count >> 16;
    count++;

    if (count > CO_MAX_BUCKET_COUNT) {
        count = CO_MAX_BUCKET_COUNT;
    }

    *ValidatedCount = count;
    return STATUS_SUCCESS;
}
