/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE CACHE OPTIMIZATION ENGINE
 * ============================================================================
 *
 * @file CacheOptimization.h
 * @brief High-performance, lock-optimized caching infrastructure for kernel EDR.
 *
 * Provides enterprise-grade caching with:
 * - Multiple cache types (Process, File Hash, Module, Verdict, IOC, Network)
 * - O(1) hash-based lookups with configurable bucket counts
 * - LRU eviction with aging and TTL expiration
 * - Fine-grained per-bucket locking (reader-writer)
 * - Memory pressure handling with adaptive eviction
 * - Cache sharding for reduced lock contention
 * - Statistics and hit-rate monitoring
 * - Automatic background maintenance
 * - Reference-counted entry access for safe concurrent reads
 *
 * Lock Ordering (MUST be followed everywhere):
 *   1. Bucket lock (per-bucket)
 *   2. Shard LRU lock (per-shard)
 *   3. Global list lock (per-cache)
 *   Never acquire a higher-numbered lock while holding a lower-numbered lock.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_CACHE_OPTIMIZATION_H_
#define _SHADOWSTRIKE_CACHE_OPTIMIZATION_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include <wdm.h>
#include <ntstrsafe.h>

/* ========================================================================= */
/* POOL TAGS                                                                  */
/* ========================================================================= */

#define CO_POOL_TAG             'HCOC'
#define CO_ENTRY_POOL_TAG       'ECOC'
#define CO_DATA_POOL_TAG        'DCOC'
#define CO_HASH_POOL_TAG        'TCOC'

/* ========================================================================= */
/* CONFIGURATION CONSTANTS                                                    */
/* ========================================================================= */

#define CO_DEFAULT_BUCKET_COUNT         4096
#define CO_MAX_BUCKET_COUNT             65536
#define CO_MIN_BUCKET_COUNT             64
#define CO_DEFAULT_MAX_ENTRIES          50000
#define CO_MAX_ENTRIES_LIMIT            1000000
#define CO_DEFAULT_TTL_SECONDS          300
#define CO_MAX_TTL_SECONDS              86400
#define CO_MAINTENANCE_INTERVAL_MS      30000
#define CO_EVICTION_BATCH_SIZE          100
#define CO_LRU_PROMOTION_THRESHOLD      3
#define CO_MEMORY_PRESSURE_THRESHOLD    85
#define CO_MAX_CACHES                   32
#define CO_CACHE_NAME_MAX               32
#define CO_SHARD_COUNT                  16
#define CO_SHARD_MASK                   (CO_SHARD_COUNT - 1)

/* ========================================================================= */
/* ENUMERATIONS                                                               */
/* ========================================================================= */

typedef enum _CO_CACHE_TYPE {
    CoCacheTypeProcessInfo = 0,
    CoCacheTypeFileHash,
    CoCacheTypeModuleInfo,
    CoCacheTypeVerdict,
    CoCacheTypeIOC,
    CoCacheTypeNetworkConnection,
    CoCacheTypeRegistry,
    CoCacheTypeDNS,
    CoCacheTypeCertificate,
    CoCacheTypeWhitelist,
    CoCacheTypeCustom,
    CoCacheTypeMax
} CO_CACHE_TYPE;

typedef enum _CO_ENTRY_STATE {
    CoEntryStateInvalid = 0,
    CoEntryStateValid,
    CoEntryStateExpired,
    CoEntryStateEvicting,
    CoEntryStatePinned
} CO_ENTRY_STATE;

typedef enum _CO_EVICTION_POLICY {
    CoEvictionPolicyLRU = 0,
    CoEvictionPolicyLFU,
    CoEvictionPolicyFIFO,
    CoEvictionPolicyTTL,
    CoEvictionPolicyRandom
} CO_EVICTION_POLICY;

typedef enum _CO_RESULT {
    CoResultSuccess = 0,
    CoResultNotFound,
    CoResultExpired,
    CoResultEvicted,
    CoResultFull,
    CoResultMemoryPressure,
    CoResultInvalidParameter,
    CoResultNotInitialized,
    CoResultAlreadyExists,
    CoResultError
} CO_RESULT;

/* ========================================================================= */
/* FORWARD DECLARATIONS                                                       */
/* ========================================================================= */

typedef struct _CO_CACHE CO_CACHE, *PCO_CACHE;
typedef struct _CO_CACHE_ENTRY CO_CACHE_ENTRY, *PCO_CACHE_ENTRY;
typedef struct _CO_MANAGER CO_MANAGER, *PCO_MANAGER;

/* ========================================================================= */
/* CALLBACK TYPES                                                             */
/* ========================================================================= */

typedef VOID (*CO_ENTRY_CLEANUP_CALLBACK)(
    _In_ PCO_CACHE Cache,
    _In_ ULONG64 Key,
    _In_opt_ PVOID Data,
    _In_ SIZE_T DataSize,
    _In_opt_ PVOID Context
    );

typedef BOOLEAN (*CO_ENTRY_COMPARE_CALLBACK)(
    _In_ ULONG64 Key1,
    _In_ PVOID Data1,
    _In_ ULONG64 Key2,
    _In_ PVOID Data2,
    _In_opt_ PVOID Context
    );

typedef VOID (*CO_MEMORY_PRESSURE_CALLBACK)(
    _In_ PCO_MANAGER Manager,
    _In_ SIZE_T CurrentUsage,
    _In_ SIZE_T MaxUsage,
    _In_opt_ PVOID Context
    );

/* ========================================================================= */
/* STRUCTURES                                                                 */
/* ========================================================================= */

/**
 * @brief Cache entry structure.
 *
 * RefCount semantics:
 *   - Created with RefCount = 1 (hash bucket owns it).
 *   - CoGet/CoGetEx increments RefCount; caller MUST call CoReleaseEntry.
 *   - Eviction/removal sets State = CoEntryStateEvicting and removes from
 *     all lists. When RefCount drops to 0, the entry is freed.
 */
typedef struct _CO_CACHE_ENTRY {
    LIST_ENTRY HashEntry;
    LIST_ENTRY LRUEntry;
    LIST_ENTRY GlobalEntry;

    ULONG64 Key;
    ULONG64 SecondaryKey;
    PVOID Data;
    SIZE_T DataSize;
    BOOLEAN DataOwned;

    volatile LONG State;
    volatile LONG RefCount;
    volatile LONG AccessCount;
    volatile LONG HitCount;

    LARGE_INTEGER CreateTime;
    volatile LONG64 LastAccessTimeQpc;
    LARGE_INTEGER ExpireTime;
    ULONG TTLSeconds;

    ULONG Flags;
    ULONG BucketIndex;
    ULONG ShardIndex;

    PVOID UserContext;

    PCO_CACHE OwnerCache;
} CO_CACHE_ENTRY, *PCO_CACHE_ENTRY;

typedef struct _CO_HASH_BUCKET {
    LIST_ENTRY Head;
    EX_PUSH_LOCK Lock;
    volatile LONG EntryCount;
    volatile LONG Collisions;
} CO_HASH_BUCKET, *PCO_HASH_BUCKET;

/**
 * @brief Cache shard for lock distribution.
 * LRU: head = MRU, tail (LRUHead.Blink) = LRU.
 */
typedef struct _CO_CACHE_SHARD {
    LIST_ENTRY LRUHead;
    EX_PUSH_LOCK LRULock;
    volatile LONG EntryCount;
    volatile LONG64 Hits;
    volatile LONG64 Misses;
    volatile LONG64 Evictions;
} CO_CACHE_SHARD, *PCO_CACHE_SHARD;

typedef struct _CO_CACHE_STATS {
    volatile LONG64 TotalLookups;
    volatile LONG64 Hits;
    volatile LONG64 Misses;
    volatile LONG64 Inserts;
    volatile LONG64 Updates;
    volatile LONG64 Removes;

    volatile LONG64 TTLEvictions;
    volatile LONG64 LRUEvictions;
    volatile LONG64 CapacityEvictions;
    volatile LONG64 MemoryEvictions;

    volatile LONG CurrentEntries;
    volatile LONG PeakEntries;
    volatile LONG64 CurrentMemory;
    volatile LONG64 PeakMemory;

    volatile LONG64 MaintenanceCycles;
    volatile LONG64 EntriesScanned;
    LARGE_INTEGER LastMaintenanceTime;

    volatile LONG64 TotalLookupTimeNs;
    volatile LONG64 TotalInsertTimeNs;
    volatile LONG AvgBucketDepth;
    volatile LONG MaxBucketDepth;
} CO_CACHE_STATS, *PCO_CACHE_STATS;

typedef struct _CO_CACHE_CONFIG {
    ULONG MaxEntries;
    ULONG BucketCount;
    ULONG DefaultTTLSeconds;
    SIZE_T MaxMemoryBytes;
    CO_EVICTION_POLICY EvictionPolicy;
    BOOLEAN UseLookaside;
    BOOLEAN EnableStatistics;
    BOOLEAN EnableTimingStats;
    BOOLEAN CopyDataOnInsert;
    CO_ENTRY_CLEANUP_CALLBACK CleanupCallback;
    PVOID CleanupContext;
} CO_CACHE_CONFIG, *PCO_CACHE_CONFIG;

typedef struct _CO_CACHE {
    CO_CACHE_TYPE Type;
    CHAR Name[CO_CACHE_NAME_MAX];
    ULONG CacheId;

    CO_CACHE_CONFIG Config;

    PCO_HASH_BUCKET Buckets;
    ULONG BucketCount;
    ULONG BucketMask;

    CO_CACHE_SHARD Shards[CO_SHARD_COUNT];

    LIST_ENTRY GlobalEntryList;
    EX_PUSH_LOCK GlobalListLock;
    volatile LONG EntryCount;
    volatile LONG64 MemoryUsage;

    NPAGED_LOOKASIDE_LIST EntryLookaside;
    BOOLEAN LookasideInitialized;

    CO_CACHE_STATS Stats;

    volatile LONG Initialized;
    volatile LONG ShuttingDown;
    volatile LONG MaintenanceActive;

    LIST_ENTRY ManagerEntry;
    PCO_MANAGER Manager;
} CO_CACHE, *PCO_CACHE;

typedef struct _CO_MANAGER {
    volatile LONG Initialized;
    volatile LONG ShuttingDown;

    LIST_ENTRY CacheList;
    EX_PUSH_LOCK CacheListLock;
    volatile LONG CacheCount;
    ULONG NextCacheId;

    SIZE_T MaxTotalMemory;
    volatile LONG64 CurrentTotalMemory;
    volatile LONG64 PeakTotalMemory;

    volatile LONG MemoryPressure;
    CO_MEMORY_PRESSURE_CALLBACK MemoryCallback;
    PVOID MemoryCallbackContext;
    EX_PUSH_LOCK CallbackLock;

    KTIMER MaintenanceTimer;
    KDPC MaintenanceDpc;
    PIO_WORKITEM MaintenanceWorkItem;
    PDEVICE_OBJECT DeviceObject;
    volatile LONG MaintenanceRunning;
    ULONG MaintenanceIntervalMs;

    volatile LONG64 TotalOperations;
    volatile LONG64 TotalHits;
    volatile LONG64 TotalMisses;
    LARGE_INTEGER StartTime;
} CO_MANAGER, *PCO_MANAGER;

/**
 * @brief Lookup result structure.
 *
 * When Result == CoResultSuccess, Data/DataSize point to a copy of the
 * cached data allocated from NonPagedPoolNx with tag CO_DATA_POOL_TAG.
 * Caller MUST free it with CoFreeLookupResult().
 */
typedef struct _CO_LOOKUP_RESULT {
    CO_RESULT Result;
    PVOID Data;
    SIZE_T DataSize;
    ULONG64 Key;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER ExpireTime;
    LONG AccessCount;
    BOOLEAN WasExpired;
} CO_LOOKUP_RESULT, *PCO_LOOKUP_RESULT;

/* ========================================================================= */
/* MANAGER FUNCTIONS                                                          */
/* ========================================================================= */

/**
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
CoInitialize(
    _Out_ PCO_MANAGER* Manager,
    _In_ SIZE_T MaxTotalMemory,
    _In_opt_ PDEVICE_OBJECT DeviceObject
    );

/**
 * @irql PASSIVE_LEVEL
 */
VOID
CoShutdown(
    _Inout_ PCO_MANAGER Manager
    );

/**
 * @irql <= DISPATCH_LEVEL
 */
NTSTATUS
CoSetMemoryLimit(
    _In_ PCO_MANAGER Manager,
    _In_ SIZE_T MaxBytes
    );

/**
 * @irql <= DISPATCH_LEVEL
 */
NTSTATUS
CoRegisterMemoryCallback(
    _In_ PCO_MANAGER Manager,
    _In_ CO_MEMORY_PRESSURE_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

/**
 * @brief Get manager statistics (integer-based, no floating-point).
 *
 * @param HitRatePermille  Receives hit rate as permille (0-1000).
 *                         e.g., 750 = 75.0% hit rate.
 *
 * @irql <= DISPATCH_LEVEL
 */
NTSTATUS
CoGetManagerStats(
    _In_ PCO_MANAGER Manager,
    _Out_opt_ PSIZE_T TotalMemory,
    _Out_opt_ PULONG TotalCaches,
    _Out_opt_ PULONG TotalEntries,
    _Out_opt_ PULONG HitRatePermille
    );

/* ========================================================================= */
/* CACHE LIFECYCLE FUNCTIONS                                                  */
/* ========================================================================= */

/** @irql PASSIVE_LEVEL */
NTSTATUS
CoCreateCache(
    _In_ PCO_MANAGER Manager,
    _In_ CO_CACHE_TYPE Type,
    _In_ PCSTR Name,
    _In_opt_ PCO_CACHE_CONFIG Config,
    _Out_ PCO_CACHE* Cache
    );

/** @irql PASSIVE_LEVEL */
NTSTATUS
CoDestroyCache(
    _In_ PCO_CACHE Cache
    );

/** @irql <= DISPATCH_LEVEL */
NTSTATUS
CoFlush(
    _In_ PCO_CACHE Cache
    );

/* ========================================================================= */
/* CACHE OPERATIONS                                                           */
/* ========================================================================= */

/** @irql <= DISPATCH_LEVEL */
NTSTATUS
CoPut(
    _In_ PCO_CACHE Cache,
    _In_ ULONG64 Key,
    _In_opt_ PVOID Data,
    _In_ SIZE_T DataSize,
    _In_ ULONG TTLSeconds
    );

/** @irql <= DISPATCH_LEVEL */
NTSTATUS
CoPutEx(
    _In_ PCO_CACHE Cache,
    _In_ ULONG64 Key,
    _In_ ULONG64 SecondaryKey,
    _In_opt_ PVOID Data,
    _In_ SIZE_T DataSize,
    _In_ ULONG TTLSeconds,
    _In_ ULONG Flags,
    _In_opt_ PVOID UserContext
    );

/**
 * @brief Look up an entry. Returns a COPY of the data.
 *
 * If DataBuffer is non-NULL, data is copied into it (up to *DataSize bytes).
 * On return, *DataSize contains the actual data size.
 * If DataBuffer is NULL, only checks existence and returns size.
 *
 * @irql <= DISPATCH_LEVEL
 */
NTSTATUS
CoGet(
    _In_ PCO_CACHE Cache,
    _In_ ULONG64 Key,
    _Out_writes_bytes_opt_(*DataSize) PVOID DataBuffer,
    _Inout_opt_ PSIZE_T DataSize
    );

/**
 * @brief Extended lookup. Returns a copy of the data in Result->Data.
 *
 * Caller MUST call CoFreeLookupResult() to free Result->Data.
 *
 * @irql <= DISPATCH_LEVEL
 */
NTSTATUS
CoGetEx(
    _In_ PCO_CACHE Cache,
    _In_ ULONG64 Key,
    _Out_ PCO_LOOKUP_RESULT Result
    );

/**
 * @brief Free data allocated by CoGetEx.
 *
 * @irql <= DISPATCH_LEVEL
 */
VOID
CoFreeLookupResult(
    _Inout_ PCO_LOOKUP_RESULT Result
    );

/** @irql <= DISPATCH_LEVEL */
BOOLEAN
CoContains(
    _In_ PCO_CACHE Cache,
    _In_ ULONG64 Key
    );

/** @irql <= DISPATCH_LEVEL */
NTSTATUS
CoInvalidate(
    _In_ PCO_CACHE Cache,
    _In_ ULONG64 Key
    );

/** @irql <= DISPATCH_LEVEL */
NTSTATUS
CoTouch(
    _In_ PCO_CACHE Cache,
    _In_ ULONG64 Key
    );

/** @irql <= DISPATCH_LEVEL */
NTSTATUS
CoPin(
    _In_ PCO_CACHE Cache,
    _In_ ULONG64 Key
    );

/** @irql <= DISPATCH_LEVEL */
NTSTATUS
CoUnpin(
    _In_ PCO_CACHE Cache,
    _In_ ULONG64 Key
    );

/* ========================================================================= */
/* STATISTICS AND MONITORING                                                  */
/* ========================================================================= */

/** @irql <= DISPATCH_LEVEL */
VOID
CoGetStats(
    _In_ PCO_CACHE Cache,
    _Out_ PCO_CACHE_STATS Stats
    );

/** @irql <= DISPATCH_LEVEL */
VOID
CoResetStats(
    _In_ PCO_CACHE Cache
    );

/**
 * @brief Get cache hit rate as permille (0-1000). No floating-point.
 * @irql <= DISPATCH_LEVEL
 */
ULONG
CoGetHitRate(
    _In_ PCO_CACHE Cache
    );

/** @irql <= DISPATCH_LEVEL */
ULONG
CoGetEntryCount(
    _In_ PCO_CACHE Cache
    );

/** @irql <= DISPATCH_LEVEL */
SIZE_T
CoGetMemoryUsage(
    _In_ PCO_CACHE Cache
    );

/* ========================================================================= */
/* MAINTENANCE FUNCTIONS                                                      */
/* ========================================================================= */

/** @irql <= DISPATCH_LEVEL */
ULONG
CoRunMaintenance(
    _In_ PCO_CACHE Cache
    );

/** @irql <= DISPATCH_LEVEL */
SIZE_T
CoEvictToSize(
    _In_ PCO_CACHE Cache,
    _In_ SIZE_T TargetBytes
    );

/* ========================================================================= */
/* HASH FUNCTION (INLINE)                                                     */
/* ========================================================================= */

FORCEINLINE
ULONG
CoHashKey(
    _In_ ULONG64 Key
    )
{
    ULONG hash = 2166136261u;
    PUCHAR bytes = (PUCHAR)&Key;
    ULONG i;

    for (i = 0; i < sizeof(ULONG64); i++) {
        hash ^= bytes[i];
        hash *= 16777619u;
    }

    return hash;
}

FORCEINLINE
ULONG
CoHashCompoundKey(
    _In_ ULONG64 Key1,
    _In_ ULONG64 Key2
    )
{
    ULONG64 combined = Key1 ^ (Key2 * 0x9E3779B97F4A7C15ULL);
    return CoHashKey(combined);
}

FORCEINLINE
ULONG
CoGetBucketIndex(
    _In_ PCO_CACHE Cache,
    _In_ ULONG64 Key
    )
{
    return CoHashKey(Key) & Cache->BucketMask;
}

FORCEINLINE
ULONG
CoGetShardIndex(
    _In_ ULONG64 Key
    )
{
    return (ULONG)(Key >> 4) & CO_SHARD_MASK;
}

/* ========================================================================= */
/* CONFIGURATION HELPERS                                                      */
/* ========================================================================= */

FORCEINLINE
VOID
CoInitDefaultConfig(
    _Out_ PCO_CACHE_CONFIG Config
    )
{
    RtlZeroMemory(Config, sizeof(CO_CACHE_CONFIG));
    Config->MaxEntries = CO_DEFAULT_MAX_ENTRIES;
    Config->BucketCount = CO_DEFAULT_BUCKET_COUNT;
    Config->DefaultTTLSeconds = CO_DEFAULT_TTL_SECONDS;
    Config->MaxMemoryBytes = 0;
    Config->EvictionPolicy = CoEvictionPolicyLRU;
    Config->UseLookaside = TRUE;
    Config->EnableStatistics = TRUE;
    Config->EnableTimingStats = FALSE;
    Config->CopyDataOnInsert = TRUE;
    Config->CleanupCallback = NULL;
    Config->CleanupContext = NULL;
}

#ifdef __cplusplus
}
#endif

#endif /* _SHADOWSTRIKE_CACHE_OPTIMIZATION_H_ */
