/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE CACHE OPTIMIZATION ENGINE
 * ============================================================================
 *
 * @file CacheOptimization.h
 * @brief High-performance, lock-optimized caching infrastructure for kernel EDR.
 *
 * Provides CrowdStrike Falcon-class caching with:
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
 * Security Guarantees:
 * - All functions validate input parameters
 * - No integer overflows in size calculations
 * - Pool allocations use tagged pools for leak detection
 * - Proper cleanup on all error paths
 * - IRQL constraints strictly enforced
 *
 * Performance Characteristics:
 * - Lookup: O(1) average, O(n) worst case per bucket
 * - Insert: O(1) amortized with LRU eviction
 * - Remove: O(1) average
 * - Memory: Configurable with hard limits
 * - Lock contention: Minimized via sharding
 *
 * MITRE ATT&CK Coverage:
 * - Performance optimization for real-time threat detection
 * - Reduces latency for repeated file/process checks
 * - Enables rapid IOC correlation
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
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

// ============================================================================
// POOL TAGS
// ============================================================================

/**
 * @brief Pool tag for cache manager allocations
 */
#define CO_POOL_TAG             'HCOC'

/**
 * @brief Pool tag for cache entry allocations
 */
#define CO_ENTRY_POOL_TAG       'ECOC'

/**
 * @brief Pool tag for cache data allocations
 */
#define CO_DATA_POOL_TAG        'DCOC'

/**
 * @brief Pool tag for hash table allocations
 */
#define CO_HASH_POOL_TAG        'TCOC'

// ============================================================================
// CONFIGURATION CONSTANTS
// ============================================================================

/**
 * @brief Default hash bucket count (must be power of 2)
 */
#define CO_DEFAULT_BUCKET_COUNT         4096

/**
 * @brief Maximum hash bucket count
 */
#define CO_MAX_BUCKET_COUNT             65536

/**
 * @brief Minimum hash bucket count
 */
#define CO_MIN_BUCKET_COUNT             64

/**
 * @brief Default maximum entries per cache
 */
#define CO_DEFAULT_MAX_ENTRIES          50000

/**
 * @brief Maximum entries limit
 */
#define CO_MAX_ENTRIES_LIMIT            1000000

/**
 * @brief Default TTL in seconds
 */
#define CO_DEFAULT_TTL_SECONDS          300

/**
 * @brief Maximum TTL in seconds (24 hours)
 */
#define CO_MAX_TTL_SECONDS              86400

/**
 * @brief Maintenance timer interval in milliseconds
 */
#define CO_MAINTENANCE_INTERVAL_MS      30000

/**
 * @brief Eviction batch size (entries to evict per cycle)
 */
#define CO_EVICTION_BATCH_SIZE          100

/**
 * @brief LRU promotion threshold (access count before promotion)
 */
#define CO_LRU_PROMOTION_THRESHOLD      3

/**
 * @brief Memory pressure threshold (percentage)
 */
#define CO_MEMORY_PRESSURE_THRESHOLD    85

/**
 * @brief Maximum caches per manager
 */
#define CO_MAX_CACHES                   32

/**
 * @brief Cache name maximum length
 */
#define CO_CACHE_NAME_MAX               32

/**
 * @brief Shard count for reducing lock contention
 */
#define CO_SHARD_COUNT                  16

/**
 * @brief Shard mask for fast modulo
 */
#define CO_SHARD_MASK                   (CO_SHARD_COUNT - 1)

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Cache type classification
 */
typedef enum _CO_CACHE_TYPE {
    CoCacheTypeProcessInfo = 0,     ///< Process metadata cache
    CoCacheTypeFileHash,            ///< File hash cache
    CoCacheTypeModuleInfo,          ///< Loaded module cache
    CoCacheTypeVerdict,             ///< Scan verdict cache
    CoCacheTypeIOC,                 ///< Indicator of Compromise cache
    CoCacheTypeNetworkConnection,   ///< Network connection cache
    CoCacheTypeRegistry,            ///< Registry path cache
    CoCacheTypeDNS,                 ///< DNS resolution cache
    CoCacheTypeCertificate,         ///< Certificate validation cache
    CoCacheTypeWhitelist,           ///< Whitelist lookup cache
    CoCacheTypeCustom,              ///< User-defined cache type
    CoCacheTypeMax
} CO_CACHE_TYPE;

/**
 * @brief Cache entry state
 */
typedef enum _CO_ENTRY_STATE {
    CoEntryStateInvalid = 0,        ///< Entry is invalid
    CoEntryStateValid,              ///< Entry is valid and active
    CoEntryStateExpired,            ///< Entry has expired (TTL)
    CoEntryStateEvicting,           ///< Entry is being evicted
    CoEntryStatePinned              ///< Entry is pinned (no eviction)
} CO_ENTRY_STATE;

/**
 * @brief Eviction policy
 */
typedef enum _CO_EVICTION_POLICY {
    CoEvictionPolicyLRU = 0,        ///< Least Recently Used
    CoEvictionPolicyLFU,            ///< Least Frequently Used
    CoEvictionPolicyFIFO,           ///< First In First Out
    CoEvictionPolicyTTL,            ///< TTL-based only
    CoEvictionPolicyRandom          ///< Random eviction
} CO_EVICTION_POLICY;

/**
 * @brief Cache operation result
 */
typedef enum _CO_RESULT {
    CoResultSuccess = 0,            ///< Operation succeeded
    CoResultNotFound,               ///< Key not found
    CoResultExpired,                ///< Entry was expired
    CoResultEvicted,                ///< Entry was evicted
    CoResultFull,                   ///< Cache is at capacity
    CoResultMemoryPressure,         ///< Memory limit reached
    CoResultInvalidParameter,       ///< Invalid parameter
    CoResultNotInitialized,         ///< Cache not initialized
    CoResultAlreadyExists,          ///< Key already exists
    CoResultError                   ///< Generic error
} CO_RESULT;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

typedef struct _CO_CACHE CO_CACHE, *PCO_CACHE;
typedef struct _CO_CACHE_ENTRY CO_CACHE_ENTRY, *PCO_CACHE_ENTRY;
typedef struct _CO_MANAGER CO_MANAGER, *PCO_MANAGER;

// ============================================================================
// CALLBACK TYPES
// ============================================================================

/**
 * @brief Entry cleanup callback (called when entry is evicted/removed)
 */
typedef VOID (*CO_ENTRY_CLEANUP_CALLBACK)(
    _In_ PCO_CACHE Cache,
    _In_ ULONG64 Key,
    _In_opt_ PVOID Data,
    _In_ SIZE_T DataSize,
    _In_opt_ PVOID Context
    );

/**
 * @brief Entry comparison callback (for custom key comparison)
 */
typedef BOOLEAN (*CO_ENTRY_COMPARE_CALLBACK)(
    _In_ ULONG64 Key1,
    _In_ PVOID Data1,
    _In_ ULONG64 Key2,
    _In_ PVOID Data2,
    _In_opt_ PVOID Context
    );

/**
 * @brief Memory pressure callback
 */
typedef VOID (*CO_MEMORY_PRESSURE_CALLBACK)(
    _In_ PCO_MANAGER Manager,
    _In_ SIZE_T CurrentUsage,
    _In_ SIZE_T MaxUsage,
    _In_opt_ PVOID Context
    );

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Cache entry structure
 */
typedef struct _CO_CACHE_ENTRY {
    //
    // Linkage
    //
    LIST_ENTRY HashEntry;           ///< Hash bucket chain
    LIST_ENTRY LRUEntry;            ///< LRU list linkage
    LIST_ENTRY GlobalEntry;         ///< Global entry list

    //
    // Key and Data
    //
    ULONG64 Key;                    ///< Primary lookup key
    ULONG64 SecondaryKey;           ///< Optional secondary key
    PVOID Data;                     ///< Cached data pointer
    SIZE_T DataSize;                ///< Size of cached data
    BOOLEAN DataOwned;              ///< TRUE if we own the data allocation

    //
    // State
    //
    volatile LONG State;            ///< CO_ENTRY_STATE
    volatile LONG RefCount;         ///< Reference count
    volatile LONG AccessCount;      ///< Total access count
    volatile LONG HitCount;         ///< Hit count since last promotion

    //
    // Timing
    //
    LARGE_INTEGER CreateTime;       ///< Entry creation time
    LARGE_INTEGER LastAccessTime;   ///< Last access time
    LARGE_INTEGER ExpireTime;       ///< Expiration time
    ULONG TTLSeconds;               ///< TTL for this entry

    //
    // Metadata
    //
    ULONG Flags;                    ///< Entry flags
    ULONG BucketIndex;              ///< Hash bucket index (for fast removal)
    ULONG ShardIndex;               ///< Shard index

    //
    // Custom context
    //
    PVOID UserContext;              ///< User-defined context

} CO_CACHE_ENTRY, *PCO_CACHE_ENTRY;

/**
 * @brief Hash bucket structure
 */
typedef struct _CO_HASH_BUCKET {
    LIST_ENTRY Head;                ///< List of entries in bucket
    EX_PUSH_LOCK Lock;              ///< Per-bucket reader-writer lock
    volatile LONG EntryCount;       ///< Entry count in bucket
    volatile LONG Collisions;       ///< Collision count (for monitoring)
} CO_HASH_BUCKET, *PCO_HASH_BUCKET;

/**
 * @brief Cache shard for lock distribution
 */
typedef struct _CO_CACHE_SHARD {
    //
    // LRU management
    //
    LIST_ENTRY LRUHead;             ///< LRU list head (MRU at front)
    LIST_ENTRY LRUTail;             ///< LRU list tail reference
    EX_PUSH_LOCK LRULock;           ///< LRU list lock
    volatile LONG EntryCount;       ///< Entry count in shard

    //
    // Shard statistics
    //
    volatile LONG64 Hits;           ///< Shard hit count
    volatile LONG64 Misses;         ///< Shard miss count
    volatile LONG64 Evictions;      ///< Shard eviction count

} CO_CACHE_SHARD, *PCO_CACHE_SHARD;

/**
 * @brief Cache statistics
 */
typedef struct _CO_CACHE_STATS {
    //
    // Access statistics
    //
    volatile LONG64 TotalLookups;   ///< Total lookup operations
    volatile LONG64 Hits;           ///< Cache hits
    volatile LONG64 Misses;         ///< Cache misses
    volatile LONG64 Inserts;        ///< Total inserts
    volatile LONG64 Updates;        ///< Total updates (existing key)
    volatile LONG64 Removes;        ///< Total explicit removes

    //
    // Eviction statistics
    //
    volatile LONG64 TTLEvictions;   ///< Evictions due to TTL expiry
    volatile LONG64 LRUEvictions;   ///< Evictions due to LRU policy
    volatile LONG64 CapacityEvictions; ///< Evictions due to capacity
    volatile LONG64 MemoryEvictions;///< Evictions due to memory pressure

    //
    // Current state
    //
    volatile LONG CurrentEntries;   ///< Current entry count
    volatile LONG PeakEntries;      ///< Peak entry count
    volatile LONG64 CurrentMemory;  ///< Current memory usage
    volatile LONG64 PeakMemory;     ///< Peak memory usage

    //
    // Maintenance
    //
    volatile LONG64 MaintenanceCycles; ///< Maintenance cycles run
    volatile LONG64 EntriesScanned; ///< Entries scanned in maintenance
    LARGE_INTEGER LastMaintenanceTime; ///< Last maintenance time

    //
    // Performance metrics
    //
    volatile LONG64 TotalLookupTimeNs;  ///< Total lookup time in nanoseconds
    volatile LONG64 TotalInsertTimeNs;  ///< Total insert time in nanoseconds
    volatile LONG AvgBucketDepth;       ///< Average bucket chain depth
    volatile LONG MaxBucketDepth;       ///< Maximum bucket chain depth

} CO_CACHE_STATS, *PCO_CACHE_STATS;

/**
 * @brief Cache configuration
 */
typedef struct _CO_CACHE_CONFIG {
    ULONG MaxEntries;               ///< Maximum entries (0 = default)
    ULONG BucketCount;              ///< Hash bucket count (0 = default)
    ULONG DefaultTTLSeconds;        ///< Default TTL (0 = default)
    SIZE_T MaxMemoryBytes;          ///< Max memory for this cache (0 = unlimited)
    CO_EVICTION_POLICY EvictionPolicy; ///< Eviction policy
    BOOLEAN UseLookaside;           ///< Use lookaside list for entries
    BOOLEAN EnableStatistics;       ///< Enable detailed statistics
    BOOLEAN EnableTimingStats;      ///< Enable timing statistics (performance cost)
    BOOLEAN CopyDataOnInsert;       ///< Copy data on insert (TRUE) or store pointer
    CO_ENTRY_CLEANUP_CALLBACK CleanupCallback; ///< Entry cleanup callback
    PVOID CleanupContext;           ///< Context for cleanup callback
} CO_CACHE_CONFIG, *PCO_CACHE_CONFIG;

/**
 * @brief Cache structure
 */
typedef struct _CO_CACHE {
    //
    // Identity
    //
    CO_CACHE_TYPE Type;             ///< Cache type
    CHAR Name[CO_CACHE_NAME_MAX];   ///< Cache name
    ULONG CacheId;                  ///< Unique cache ID

    //
    // Configuration
    //
    CO_CACHE_CONFIG Config;         ///< Cache configuration

    //
    // Hash table
    //
    PCO_HASH_BUCKET Buckets;        ///< Hash bucket array
    ULONG BucketCount;              ///< Number of buckets
    ULONG BucketMask;               ///< Mask for fast modulo

    //
    // Shards
    //
    CO_CACHE_SHARD Shards[CO_SHARD_COUNT]; ///< Cache shards

    //
    // Global entry tracking
    //
    LIST_ENTRY GlobalEntryList;     ///< All entries (for iteration)
    EX_PUSH_LOCK GlobalListLock;    ///< Global list lock
    volatile LONG EntryCount;       ///< Total entry count
    volatile LONG64 MemoryUsage;    ///< Total memory usage

    //
    // Lookaside list
    //
    NPAGED_LOOKASIDE_LIST EntryLookaside; ///< Entry allocation lookaside
    BOOLEAN LookasideInitialized;   ///< Lookaside list initialized

    //
    // Statistics
    //
    CO_CACHE_STATS Stats;           ///< Cache statistics

    //
    // State
    //
    volatile LONG Initialized;      ///< Initialization flag
    volatile LONG ShuttingDown;     ///< Shutdown in progress
    volatile LONG MaintenanceActive; ///< Maintenance in progress

    //
    // Manager linkage
    //
    LIST_ENTRY ManagerEntry;        ///< Link in manager's cache list
    PCO_MANAGER Manager;            ///< Owning manager

} CO_CACHE, *PCO_CACHE;

/**
 * @brief Cache manager structure
 */
typedef struct _CO_MANAGER {
    //
    // State
    //
    volatile LONG Initialized;      ///< Initialization flag
    volatile LONG ShuttingDown;     ///< Shutdown in progress

    //
    // Cache registry
    //
    LIST_ENTRY CacheList;           ///< List of all caches
    EX_PUSH_LOCK CacheListLock;     ///< Cache list lock
    volatile LONG CacheCount;       ///< Number of caches
    ULONG NextCacheId;              ///< Next cache ID to assign

    //
    // Global memory management
    //
    SIZE_T MaxTotalMemory;          ///< Maximum total memory
    volatile LONG64 CurrentTotalMemory; ///< Current total memory usage
    volatile LONG64 PeakTotalMemory;///< Peak total memory usage

    //
    // Memory pressure handling
    //
    volatile LONG MemoryPressure;   ///< Memory pressure level (0-100)
    CO_MEMORY_PRESSURE_CALLBACK MemoryCallback; ///< Memory pressure callback
    PVOID MemoryCallbackContext;    ///< Context for memory callback

    //
    // Maintenance
    //
    KTIMER MaintenanceTimer;        ///< Maintenance timer
    KDPC MaintenanceDpc;            ///< Maintenance DPC
    PIO_WORKITEM MaintenanceWorkItem; ///< Maintenance work item
    PDEVICE_OBJECT DeviceObject;    ///< Device object for work items
    volatile LONG MaintenanceRunning; ///< Maintenance is running
    ULONG MaintenanceIntervalMs;    ///< Maintenance interval
    KEVENT ShutdownEvent;           ///< Shutdown synchronization event

    //
    // Global statistics
    //
    volatile LONG64 TotalOperations; ///< Total operations across all caches
    volatile LONG64 TotalHits;      ///< Total hits across all caches
    volatile LONG64 TotalMisses;    ///< Total misses across all caches
    LARGE_INTEGER StartTime;        ///< Manager start time

} CO_MANAGER, *PCO_MANAGER;

/**
 * @brief Lookup result structure
 */
typedef struct _CO_LOOKUP_RESULT {
    CO_RESULT Result;               ///< Operation result
    PVOID Data;                     ///< Cached data (if found)
    SIZE_T DataSize;                ///< Data size
    ULONG64 Key;                    ///< Key that was looked up
    LARGE_INTEGER CreateTime;       ///< Entry creation time
    LARGE_INTEGER ExpireTime;       ///< Entry expiration time
    LONG AccessCount;               ///< Entry access count
    BOOLEAN WasExpired;             ///< Entry was expired and removed
} CO_LOOKUP_RESULT, *PCO_LOOKUP_RESULT;

// ============================================================================
// MANAGER FUNCTIONS
// ============================================================================

/**
 * @brief Initialize the cache optimization manager.
 *
 * @param Manager           Receives pointer to new manager
 * @param MaxTotalMemory    Maximum total memory (0 = 256MB default)
 * @param DeviceObject      Device object for work items (optional)
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
CoInitialize(
    _Out_ PCO_MANAGER* Manager,
    _In_ SIZE_T MaxTotalMemory,
    _In_opt_ PDEVICE_OBJECT DeviceObject
    );

/**
 * @brief Shutdown the cache optimization manager.
 *
 * Frees all caches and resources.
 *
 * @param Manager   Manager to shutdown
 *
 * @irql PASSIVE_LEVEL
 */
VOID
CoShutdown(
    _Inout_ PCO_MANAGER Manager
    );

/**
 * @brief Set global memory limit.
 *
 * @param Manager       Manager instance
 * @param MaxBytes      New maximum memory (0 = unlimited)
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql <= DISPATCH_LEVEL
 */
NTSTATUS
CoSetMemoryLimit(
    _In_ PCO_MANAGER Manager,
    _In_ SIZE_T MaxBytes
    );

/**
 * @brief Register memory pressure callback.
 *
 * @param Manager       Manager instance
 * @param Callback      Callback function
 * @param Context       Callback context
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql <= DISPATCH_LEVEL
 */
NTSTATUS
CoRegisterMemoryCallback(
    _In_ PCO_MANAGER Manager,
    _In_ CO_MEMORY_PRESSURE_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

/**
 * @brief Get manager statistics.
 *
 * @param Manager           Manager instance
 * @param TotalMemory       Receives total memory usage
 * @param TotalCaches       Receives cache count
 * @param TotalEntries      Receives total entry count
 * @param HitRate           Receives overall hit rate (0.0-1.0)
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql <= DISPATCH_LEVEL
 */
NTSTATUS
CoGetManagerStats(
    _In_ PCO_MANAGER Manager,
    _Out_opt_ PSIZE_T TotalMemory,
    _Out_opt_ PULONG TotalCaches,
    _Out_opt_ PULONG TotalEntries,
    _Out_opt_ double* HitRate
    );

// ============================================================================
// CACHE LIFECYCLE FUNCTIONS
// ============================================================================

/**
 * @brief Create a new cache.
 *
 * @param Manager       Manager instance
 * @param Type          Cache type
 * @param Name          Cache name (for debugging)
 * @param Config        Cache configuration (NULL = defaults)
 * @param Cache         Receives pointer to new cache
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
CoCreateCache(
    _In_ PCO_MANAGER Manager,
    _In_ CO_CACHE_TYPE Type,
    _In_ PCSTR Name,
    _In_opt_ PCO_CACHE_CONFIG Config,
    _Out_ PCO_CACHE* Cache
    );

/**
 * @brief Destroy a cache.
 *
 * Frees all entries and resources.
 *
 * @param Cache         Cache to destroy
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
CoDestroyCache(
    _In_ PCO_CACHE Cache
    );

/**
 * @brief Flush all entries from a cache.
 *
 * @param Cache         Cache to flush
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql <= DISPATCH_LEVEL
 */
NTSTATUS
CoFlush(
    _In_ PCO_CACHE Cache
    );

// ============================================================================
// CACHE OPERATIONS
// ============================================================================

/**
 * @brief Insert or update an entry in the cache.
 *
 * @param Cache         Cache instance
 * @param Key           Primary key
 * @param Data          Data to cache
 * @param DataSize      Size of data
 * @param TTLSeconds    Entry TTL (0 = use cache default)
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql <= DISPATCH_LEVEL
 */
NTSTATUS
CoPut(
    _In_ PCO_CACHE Cache,
    _In_ ULONG64 Key,
    _In_opt_ PVOID Data,
    _In_ SIZE_T DataSize,
    _In_ ULONG TTLSeconds
    );

/**
 * @brief Insert with extended options.
 *
 * @param Cache         Cache instance
 * @param Key           Primary key
 * @param SecondaryKey  Secondary key (for compound lookups)
 * @param Data          Data to cache
 * @param DataSize      Size of data
 * @param TTLSeconds    Entry TTL (0 = use cache default)
 * @param Flags         Entry flags
 * @param UserContext   User-defined context
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql <= DISPATCH_LEVEL
 */
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
 * @brief Look up an entry in the cache.
 *
 * @param Cache         Cache instance
 * @param Key           Primary key
 * @param Data          Receives data pointer (if found)
 * @param DataSize      Receives data size (if found)
 *
 * @return STATUS_SUCCESS if found, STATUS_NOT_FOUND otherwise
 *
 * @irql <= DISPATCH_LEVEL
 */
NTSTATUS
CoGet(
    _In_ PCO_CACHE Cache,
    _In_ ULONG64 Key,
    _Out_opt_ PVOID* Data,
    _Out_opt_ PSIZE_T DataSize
    );

/**
 * @brief Look up with extended result.
 *
 * @param Cache         Cache instance
 * @param Key           Primary key
 * @param Result        Receives detailed lookup result
 *
 * @return STATUS_SUCCESS if found, error otherwise
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
 * @brief Check if key exists without updating access time.
 *
 * @param Cache         Cache instance
 * @param Key           Primary key
 *
 * @return TRUE if key exists and is valid
 *
 * @irql <= DISPATCH_LEVEL
 */
BOOLEAN
CoContains(
    _In_ PCO_CACHE Cache,
    _In_ ULONG64 Key
    );

/**
 * @brief Remove an entry from the cache.
 *
 * @param Cache         Cache instance
 * @param Key           Primary key
 *
 * @return STATUS_SUCCESS if removed, STATUS_NOT_FOUND if not found
 *
 * @irql <= DISPATCH_LEVEL
 */
NTSTATUS
CoInvalidate(
    _In_ PCO_CACHE Cache,
    _In_ ULONG64 Key
    );

/**
 * @brief Touch an entry (update access time without reading).
 *
 * @param Cache         Cache instance
 * @param Key           Primary key
 *
 * @return STATUS_SUCCESS if found
 *
 * @irql <= DISPATCH_LEVEL
 */
NTSTATUS
CoTouch(
    _In_ PCO_CACHE Cache,
    _In_ ULONG64 Key
    );

/**
 * @brief Pin an entry (prevent eviction).
 *
 * @param Cache         Cache instance
 * @param Key           Primary key
 *
 * @return STATUS_SUCCESS if found and pinned
 *
 * @irql <= DISPATCH_LEVEL
 */
NTSTATUS
CoPin(
    _In_ PCO_CACHE Cache,
    _In_ ULONG64 Key
    );

/**
 * @brief Unpin an entry (allow eviction).
 *
 * @param Cache         Cache instance
 * @param Key           Primary key
 *
 * @return STATUS_SUCCESS if found and unpinned
 *
 * @irql <= DISPATCH_LEVEL
 */
NTSTATUS
CoUnpin(
    _In_ PCO_CACHE Cache,
    _In_ ULONG64 Key
    );

// ============================================================================
// STATISTICS AND MONITORING
// ============================================================================

/**
 * @brief Get cache statistics.
 *
 * @param Cache         Cache instance
 * @param Stats         Receives statistics
 *
 * @irql <= DISPATCH_LEVEL
 */
VOID
CoGetStats(
    _In_ PCO_CACHE Cache,
    _Out_ PCO_CACHE_STATS Stats
    );

/**
 * @brief Reset cache statistics.
 *
 * @param Cache         Cache instance
 *
 * @irql <= DISPATCH_LEVEL
 */
VOID
CoResetStats(
    _In_ PCO_CACHE Cache
    );

/**
 * @brief Get cache hit rate.
 *
 * @param Cache         Cache instance
 *
 * @return Hit rate (0.0 - 1.0)
 *
 * @irql <= DISPATCH_LEVEL
 */
double
CoGetHitRate(
    _In_ PCO_CACHE Cache
    );

/**
 * @brief Get current entry count.
 *
 * @param Cache         Cache instance
 *
 * @return Current entry count
 *
 * @irql <= DISPATCH_LEVEL
 */
ULONG
CoGetEntryCount(
    _In_ PCO_CACHE Cache
    );

/**
 * @brief Get current memory usage.
 *
 * @param Cache         Cache instance
 *
 * @return Memory usage in bytes
 *
 * @irql <= DISPATCH_LEVEL
 */
SIZE_T
CoGetMemoryUsage(
    _In_ PCO_CACHE Cache
    );

// ============================================================================
// MAINTENANCE FUNCTIONS
// ============================================================================

/**
 * @brief Run cache maintenance (evict expired entries).
 *
 * @param Cache         Cache instance
 *
 * @return Number of entries evicted
 *
 * @irql <= DISPATCH_LEVEL
 */
ULONG
CoRunMaintenance(
    _In_ PCO_CACHE Cache
    );

/**
 * @brief Evict entries to reduce memory usage.
 *
 * @param Cache         Cache instance
 * @param TargetBytes   Target memory reduction
 *
 * @return Bytes actually freed
 *
 * @irql <= DISPATCH_LEVEL
 */
SIZE_T
CoEvictToSize(
    _In_ PCO_CACHE Cache,
    _In_ SIZE_T TargetBytes
    );

// ============================================================================
// HASH FUNCTION
// ============================================================================

/**
 * @brief Calculate hash for a key.
 *
 * Uses FNV-1a for good distribution.
 */
FORCEINLINE
ULONG
CoHashKey(
    _In_ ULONG64 Key
    )
{
    //
    // FNV-1a 64-bit to 32-bit hash
    //
    ULONG hash = 2166136261u;
    PUCHAR bytes = (PUCHAR)&Key;
    ULONG i;

    for (i = 0; i < sizeof(ULONG64); i++) {
        hash ^= bytes[i];
        hash *= 16777619u;
    }

    return hash;
}

/**
 * @brief Calculate compound hash for two keys.
 */
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

/**
 * @brief Get bucket index for a key.
 */
FORCEINLINE
ULONG
CoGetBucketIndex(
    _In_ PCO_CACHE Cache,
    _In_ ULONG64 Key
    )
{
    return CoHashKey(Key) & Cache->BucketMask;
}

/**
 * @brief Get shard index for a key.
 */
FORCEINLINE
ULONG
CoGetShardIndex(
    _In_ ULONG64 Key
    )
{
    return (ULONG)(Key >> 4) & CO_SHARD_MASK;
}

// ============================================================================
// CONFIGURATION HELPERS
// ============================================================================

/**
 * @brief Initialize configuration with defaults.
 */
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
    Config->MaxMemoryBytes = 0;  // Unlimited
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

#endif // _SHADOWSTRIKE_CACHE_OPTIMIZATION_H_
