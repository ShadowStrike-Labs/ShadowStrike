/**
 * ============================================================================
 * ShadowStrike NGAV - SCAN CACHE
 * ============================================================================
 *
 * @file ScanCache.h
 * @brief Kernel-mode verdict caching for scan results.
 *
 * Provides O(1) hash-based caching of file scan verdicts to avoid
 * redundant user-mode round-trips for recently scanned files.
 *
 * Features:
 * - Hash-based lookup using file ID + volume serial
 * - TTL-based expiration with configurable timeout
 * - Thread-safe with reader-writer locks
 * - Automatic cleanup of expired entries
 * - Statistics tracking for cache efficiency
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_SCAN_CACHE_H
#define SHADOWSTRIKE_SCAN_CACHE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <fltKernel.h>
#include "../Shared/SharedDefs.h"
#include "../Shared/VerdictTypes.h"

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * @brief Number of hash buckets for the cache.
 * Must be power of 2 for fast modulo via AND.
 */
#define SHADOWSTRIKE_CACHE_BUCKET_COUNT     4096

/**
 * @brief Mask for bucket index calculation.
 */
#define SHADOWSTRIKE_CACHE_BUCKET_MASK      (SHADOWSTRIKE_CACHE_BUCKET_COUNT - 1)

/**
 * @brief Maximum entries in the cache (prevents memory exhaustion).
 */
#define SHADOWSTRIKE_CACHE_MAX_ENTRIES      100000

/**
 * @brief Default TTL in seconds if not configured.
 */
#define SHADOWSTRIKE_CACHE_DEFAULT_TTL      300

/**
 * @brief Cleanup interval in seconds.
 */
#define SHADOWSTRIKE_CACHE_CLEANUP_INTERVAL 60

/**
 * @brief Pool tag for cache allocations.
 */
#define SHADOWSTRIKE_CACHE_POOL_TAG         'hCsS'

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Cache entry key - uniquely identifies a file.
 */
typedef struct _SHADOWSTRIKE_CACHE_KEY {
    /// @brief Volume serial number
    ULONG VolumeSerial;

    /// @brief File ID (from FileInternalInformation)
    UINT64 FileId;

    /// @brief File size at time of scan
    UINT64 FileSize;

    /// @brief Last write time at time of scan
    LARGE_INTEGER LastWriteTime;

} SHADOWSTRIKE_CACHE_KEY, *PSHADOWSTRIKE_CACHE_KEY;

/**
 * @brief Cached verdict entry.
 */
typedef struct _SHADOWSTRIKE_CACHE_ENTRY {
    /// @brief List linkage within bucket
    LIST_ENTRY ListEntry;

    /// @brief Cache key
    SHADOWSTRIKE_CACHE_KEY Key;

    /// @brief Cached verdict
    SHADOWSTRIKE_VERDICT Verdict;

    /// @brief Threat score (0-100)
    UINT8 ThreatScore;

    /// @brief Entry is valid
    BOOLEAN Valid;

    /// @brief Reserved for alignment
    UINT8 Reserved[2];

    /// @brief Time entry was created (100-ns intervals since boot)
    LARGE_INTEGER CreateTime;

    /// @brief Time entry expires
    LARGE_INTEGER ExpireTime;

    /// @brief Hit count for this entry
    volatile LONG HitCount;

} SHADOWSTRIKE_CACHE_ENTRY, *PSHADOWSTRIKE_CACHE_ENTRY;

/**
 * @brief Hash bucket.
 */
typedef struct _SHADOWSTRIKE_CACHE_BUCKET {
    /// @brief Bucket list head
    LIST_ENTRY ListHead;

    /// @brief Bucket lock (reader-writer)
    EX_PUSH_LOCK Lock;

    /// @brief Entry count in this bucket
    volatile LONG EntryCount;

} SHADOWSTRIKE_CACHE_BUCKET, *PSHADOWSTRIKE_CACHE_BUCKET;

/**
 * @brief Cache statistics.
 */
typedef struct _SHADOWSTRIKE_CACHE_STATS {
    /// @brief Total lookups
    volatile LONG64 TotalLookups;

    /// @brief Cache hits
    volatile LONG64 Hits;

    /// @brief Cache misses
    volatile LONG64 Misses;

    /// @brief Entries added
    volatile LONG64 Inserts;

    /// @brief Entries evicted (expired or capacity)
    volatile LONG64 Evictions;

    /// @brief Current entry count
    volatile LONG CurrentEntries;

    /// @brief Peak entry count
    volatile LONG PeakEntries;

    /// @brief Cleanup cycles run
    volatile LONG64 CleanupCycles;

    /// @brief Entries removed by cleanup
    volatile LONG64 CleanupEvictions;

} SHADOWSTRIKE_CACHE_STATS, *PSHADOWSTRIKE_CACHE_STATS;

/**
 * @brief Main cache structure.
 */
typedef struct _SHADOWSTRIKE_SCAN_CACHE {
    /// @brief Hash buckets
    SHADOWSTRIKE_CACHE_BUCKET Buckets[SHADOWSTRIKE_CACHE_BUCKET_COUNT];

    /// @brief Lookaside list for entry allocations
    NPAGED_LOOKASIDE_LIST EntryLookaside;

    /// @brief Lookaside initialized
    BOOLEAN LookasideInitialized;

    /// @brief Cache is initialized
    BOOLEAN Initialized;

    /// @brief Reserved
    BOOLEAN Reserved[6];

    /// @brief TTL in 100-ns intervals
    LARGE_INTEGER TTLInterval;

    /// @brief Statistics
    SHADOWSTRIKE_CACHE_STATS Stats;

    /// @brief Cleanup timer
    KTIMER CleanupTimer;

    /// @brief Cleanup DPC
    KDPC CleanupDpc;

    /// @brief Cleanup work item (legacy style - no DeviceObject required)
    WORK_QUEUE_ITEM CleanupWorkItem;

    /// @brief Work item initialized flag
    BOOLEAN WorkItemInitialized;

    /// @brief Reserved for alignment
    BOOLEAN Reserved2[3];

    /// @brief Cleanup in progress flag
    volatile LONG CleanupInProgress;

} SHADOWSTRIKE_SCAN_CACHE, *PSHADOWSTRIKE_SCAN_CACHE;

/**
 * @brief Lookup result.
 */
typedef struct _SHADOWSTRIKE_CACHE_RESULT {
    /// @brief Entry was found
    BOOLEAN Found;

    /// @brief Verdict (valid if Found == TRUE)
    SHADOWSTRIKE_VERDICT Verdict;

    /// @brief Threat score (valid if Found == TRUE)
    UINT8 ThreatScore;

    /// @brief Reserved
    UINT8 Reserved[2];

    /// @brief Entry hit count
    LONG HitCount;

} SHADOWSTRIKE_CACHE_RESULT, *PSHADOWSTRIKE_CACHE_RESULT;

// ============================================================================
// GLOBAL CACHE INSTANCE
// ============================================================================

/**
 * @brief Global scan cache instance.
 */
extern SHADOWSTRIKE_SCAN_CACHE g_ScanCache;

// ============================================================================
// FUNCTION PROTOTYPES
// ============================================================================

/**
 * @brief Initialize the scan cache.
 *
 * Must be called during DriverEntry before any cache operations.
 *
 * @param TTLSeconds  Cache entry TTL in seconds.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ShadowStrikeCacheInitialize(
    _In_ ULONG TTLSeconds
    );

/**
 * @brief Shutdown the scan cache.
 *
 * Frees all entries and resources. Must be called during driver unload.
 */
VOID
ShadowStrikeCacheShutdown(
    VOID
    );

/**
 * @brief Look up a file in the cache.
 *
 * @param Key     Cache key identifying the file.
 * @param Result  Receives lookup result.
 * @return TRUE if entry was found and is valid, FALSE otherwise.
 */
BOOLEAN
ShadowStrikeCacheLookup(
    _In_ PSHADOWSTRIKE_CACHE_KEY Key,
    _Out_ PSHADOWSTRIKE_CACHE_RESULT Result
    );

/**
 * @brief Insert or update an entry in the cache.
 *
 * @param Key         Cache key identifying the file.
 * @param Verdict     Scan verdict to cache.
 * @param ThreatScore Threat score (0-100).
 * @param TTLSeconds  Entry-specific TTL (0 = use default).
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ShadowStrikeCacheInsert(
    _In_ PSHADOWSTRIKE_CACHE_KEY Key,
    _In_ SHADOWSTRIKE_VERDICT Verdict,
    _In_ UINT8 ThreatScore,
    _In_ ULONG TTLSeconds
    );

/**
 * @brief Remove an entry from the cache.
 *
 * Use when a file is modified to invalidate cached verdict.
 *
 * @param Key  Cache key identifying the file.
 * @return TRUE if entry was found and removed.
 */
BOOLEAN
ShadowStrikeCacheRemove(
    _In_ PSHADOWSTRIKE_CACHE_KEY Key
    );

/**
 * @brief Invalidate all entries for a volume.
 *
 * Use when volume is dismounted.
 *
 * @param VolumeSerial  Volume serial number.
 * @return Number of entries removed.
 */
ULONG
ShadowStrikeCacheInvalidateVolume(
    _In_ ULONG VolumeSerial
    );

/**
 * @brief Clear all entries from the cache.
 */
VOID
ShadowStrikeCacheClear(
    VOID
    );

/**
 * @brief Run cleanup to remove expired entries.
 *
 * Called periodically by timer or manually.
 */
VOID
ShadowStrikeCacheCleanup(
    VOID
    );

/**
 * @brief Get cache statistics.
 *
 * @param Stats  Receives current statistics.
 */
VOID
ShadowStrikeCacheGetStats(
    _Out_ PSHADOWSTRIKE_CACHE_STATS Stats
    );

/**
 * @brief Reset cache statistics.
 */
VOID
ShadowStrikeCacheResetStats(
    VOID
    );

/**
 * @brief Build cache key from file object.
 *
 * @param FltObjects  Filter objects from callback.
 * @param Key         Receives the cache key.
 * @return STATUS_SUCCESS if key was built successfully.
 */
NTSTATUS
ShadowStrikeCacheBuildKey(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PSHADOWSTRIKE_CACHE_KEY Key
    );

/**
 * @brief Calculate hash for cache key.
 *
 * @param Key  Cache key.
 * @return Hash value.
 */
FORCEINLINE
ULONG
ShadowStrikeCacheHash(
    _In_ PSHADOWSTRIKE_CACHE_KEY Key
    )
{
    //
    // FNV-1a hash for good distribution
    //
    ULONG hash = 2166136261u;
    PUCHAR bytes = (PUCHAR)Key;
    SIZE_T i;

    for (i = 0; i < sizeof(SHADOWSTRIKE_CACHE_KEY); i++) {
        hash ^= bytes[i];
        hash *= 16777619u;
    }

    return hash;
}

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_SCAN_CACHE_H
