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
 * SAFETY GUARANTEES:
 * - All operations are IRQL-aware (PASSIVE_LEVEL for paged, APC_LEVEL for locks)
 * - Work item lifecycle properly managed to prevent use-after-free
 * - Shutdown synchronization prevents BSOD during driver unload
 * - No floating-point operations in kernel code
 *
 * @author ShadowStrike Security Team
 * @version 1.2.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_SCAN_CACHE_H
#define SHADOWSTRIKE_SCAN_CACHE_H

#ifdef __cplusplus
extern "C" {
#endif

#pragma warning(push)
#pragma warning(disable:4324)
#include <fltKernel.h>
#pragma warning(pop)
#include "../../Shared/SharedDefs.h"
#include "../../Shared/VerdictTypes.h"

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
 * @brief Maximum TTL in seconds (24 hours) to prevent overflow.
 */
#define SHADOWSTRIKE_CACHE_MAX_TTL          86400

/**
 * @brief Cleanup interval in seconds.
 */
#define SHADOWSTRIKE_CACHE_CLEANUP_INTERVAL 60

/**
 * @brief Pool tag for cache allocations.
 */
#define SHADOWSTRIKE_CACHE_POOL_TAG         'hCsS'

/**
 * @brief Maximum valid verdict value for validation.
 */
#define SHADOWSTRIKE_VERDICT_MAX            Verdict_Timeout

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Cache entry key - uniquely identifies a file.
 *
 * SECURITY/CORRECTNESS: Field order is chosen to eliminate internal
 * compiler-inserted padding bytes. The previous layout
 * `ULONG; UINT64; UINT64; LARGE_INTEGER` produced 4 bytes of internal
 * padding between VolumeSerial and FileId on x64. Hashing/comparing
 * raw struct bytes therefore mixed in uninitialized stack memory,
 * which (a) made the hash non-deterministic for keys that were not
 * pre-zeroed by callers, and (b) could cause false cache misses or
 * (worse) incidental hits across unrelated scans. The new layout
 * places all 8-byte members first, then the 4-byte VolumeSerial,
 * then an explicit, named `Reserved` 4-byte tail so every byte is
 * caller-controlled. Hashing now operates on individual fields and
 * never reads tail padding.
 */
/**
 * @brief Which identity domain a cache key addresses.
 *
 * The cache was born with a single kind of key: NTFS file ID plus size plus
 * last-write time plus volume serial. That key is CONTENT-DERIVED, which is
 * what makes it safe - modifying a file changes the key, so a stale entry can
 * never be matched by the modified file.
 *
 * It has one hard limitation. Every one of those three file-level fields comes
 * from FltQueryInformationFile against the target file object, and in the
 * IRP_MJ_CREATE PRE-operation the file is not open yet, so all three queries
 * fail. ShadowStrikeCacheBuildKey therefore returned STATUS_UNSUCCESSFUL on
 * every create, which meant the create path - the single hottest path in the
 * product, measured at 829,958 operations in a 330 second run - could neither
 * read nor write this cache. The field measurement was cached=0 against
 * total=829958, and it also paid four doomed synchronous information IRPs per
 * create for the privilege.
 *
 * A second kind of key exists to close that gap: volume serial plus a hash of
 * the normalised path, both of which ARE available before the create is issued.
 * A path is not content-derived, so a path key ALONE would be weaker than what
 * it replaces. It is not used alone - see the IdentityWitness fields on
 * SHADOWSTRIKE_CACHE_ENTRY and the post-create verification that consumes
 * them.
 */
typedef enum _SS_CACHE_KEY_KIND {

    /// @brief File ID + size + last-write-time + volume serial. Content-derived.
    /// Zero by construction, so every caller that zero-initialises its key
    /// keeps exactly the behaviour it had before this field carried meaning.
    SsCacheKeyKindIdentity = 0,

    /// @brief Volume serial + normalised-path hash. Available pre-create.
    /// Entries under this kind MUST carry an identity witness.
    SsCacheKeyKindPath = 1,

    /// @brief Bound for validation. Not a usable kind.
    SsCacheKeyKindMax

} SS_CACHE_KEY_KIND;

typedef struct _SHADOWSTRIKE_CACHE_KEY {
    /// @brief File ID (from FileInternalInformation)
    UINT64 FileId;

    /// @brief File size at time of scan
    UINT64 FileSize;

    /// @brief Last write time at time of scan
    LARGE_INTEGER LastWriteTime;

    /// @brief Volume serial number (actual serial, not pointer)
    ULONG VolumeSerial;

    /// @brief Which identity domain this key addresses (SS_CACHE_KEY_KIND).
    ///
    /// MUST be zero-initialized by callers, which yields SsCacheKeyKindIdentity.
    /// It participates in BOTH ShadowStrikeCacheHash and
    /// ShadowStrikeCacheKeyEquals, so a path key can never alias an identity
    /// key even if their remaining bytes coincide.
    ULONG KeyKind;

} SHADOWSTRIKE_CACHE_KEY, *PSHADOWSTRIKE_CACHE_KEY;

//
// Compile-time verification: layout invariants.
// 1) Total struct size remains 32 bytes (ABI stability).
// 2) Size remains a multiple of sizeof(ULONG) (legacy invariant).
// 3) No internal padding between members (sum of member sizes equals
//    sizeof(struct)). This guarantees raw-byte equality of two zeroed
//    structs that differ only by named member values.
//
C_ASSERT(sizeof(SHADOWSTRIKE_CACHE_KEY) == 32);
C_ASSERT(sizeof(SHADOWSTRIKE_CACHE_KEY) % sizeof(ULONG) == 0);
C_ASSERT(sizeof(SHADOWSTRIKE_CACHE_KEY) ==
         (sizeof(UINT64) + sizeof(UINT64) + sizeof(LARGE_INTEGER) +
          sizeof(ULONG) + sizeof(ULONG)));

//
// 4) The discriminator occupies the former tail slot. Pinned because both the
//    hash and the equality test read it by name: if it ever moved or was
//    renamed back to a padding role, path and identity keys would start
//    sharing a namespace silently.
//
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_CACHE_KEY, KeyKind) == 28);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_CACHE_KEY, VolumeSerial) == 24);

/**
 * @brief Cached verdict entry.
 */
typedef struct _SHADOWSTRIKE_CACHE_ENTRY {
    /// @brief List linkage within bucket
    LIST_ENTRY ListEntry;

    /// @brief Cache key
    SHADOWSTRIKE_CACHE_KEY Key;

    /// @brief Cached verdict
    SHADOWSTRIKE_SCAN_VERDICT Verdict;

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

    //
    // IDENTITY WITNESS - what makes a path-keyed entry safe.
    //
    // A path key says nothing about the bytes behind the path, so an entry
    // reached by one records the content identity that was observed when the
    // verdict was produced. The create path hands these three values to its
    // post-operation callback, which CAN query the now-open file, and any
    // disagreement means the path no longer names the file we scanned: the
    // entry is removed and the open is cancelled rather than trusted.
    //
    // Consequence worth stating plainly: a path-keyed hit never grants access
    // on the strength of the path. It only avoids re-scanning bytes we have
    // already judged, and it is revoked before the caller receives a handle.
    //

    /// @brief TRUE once the witness below has been populated.
    BOOLEAN IdentityWitnessed;

    /// @brief Alignment padding.
    BOOLEAN WitnessReserved[3];

    /// @brief NTFS file ID observed when this verdict was produced.
    UINT64 WitnessFileId;

    /// @brief File size observed when this verdict was produced.
    UINT64 WitnessFileSize;

    /// @brief Last-write time observed when this verdict was produced.
    LARGE_INTEGER WitnessLastWriteTime;

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

    /// @brief Cache is initialized (volatile: read by concurrent threads)
    volatile BOOLEAN Initialized;

    /// @brief Shutdown in progress - prevents new work item queuing (volatile: cross-thread signal)
    volatile BOOLEAN ShutdownInProgress;

    /// @brief Reserved
    BOOLEAN Reserved[5];

    /// @brief TTL in 100-ns intervals
    LARGE_INTEGER TTLInterval;

    /// @brief Statistics
    SHADOWSTRIKE_CACHE_STATS Stats;

    /// @brief Cleanup timer ID (managed by TimerManager)
    ULONG CleanupTimerId;

    /// @brief Cleanup in progress flag
    volatile LONG CleanupInProgress;

    /// @brief Active reference count for shutdown synchronization
    volatile LONG ActiveReferences;

    /// @brief Shutdown complete event
    KEVENT ShutdownEvent;

} SHADOWSTRIKE_SCAN_CACHE, *PSHADOWSTRIKE_SCAN_CACHE;

/**
 * @brief Lookup result.
 */
typedef struct _SHADOWSTRIKE_CACHE_RESULT {
    /// @brief Entry was found
    BOOLEAN Found;

    /// @brief Verdict (valid if Found == TRUE)
    SHADOWSTRIKE_SCAN_VERDICT Verdict;

    /// @brief Threat score (valid if Found == TRUE)
    UINT8 ThreatScore;

    /// @brief Reserved
    UINT8 Reserved[2];

    /// @brief Entry hit count
    LONG HitCount;

    /// @brief TRUE if the identity witness below is meaningful.
    /// Always FALSE for an identity-keyed hit, because such a key IS the
    /// identity and needs no separate witness.
    BOOLEAN IdentityWitnessed;

    /// @brief Alignment padding.
    BOOLEAN WitnessReserved[3];

    /// @brief File ID observed when the cached verdict was produced.
    UINT64 WitnessFileId;

    /// @brief File size observed when the cached verdict was produced.
    UINT64 WitnessFileSize;

    /// @brief Last-write time observed when the cached verdict was produced.
    LARGE_INTEGER WitnessLastWriteTime;

} SHADOWSTRIKE_CACHE_RESULT, *PSHADOWSTRIKE_CACHE_RESULT;

// ============================================================================
// GLOBAL CACHE INSTANCE
// ============================================================================

/**
 * @brief Global scan cache instance.
 *
 * Opaque to external consumers. Access only through the public API
 * functions declared in ScanCache.h.
 */

// ============================================================================
// FUNCTION PROTOTYPES
// ============================================================================

/**
 * @brief Initialize the scan cache.
 *
 * Must be called during DriverEntry before any cache operations.
 * Requires a valid device object for work item allocation.
 *
 * @param DeviceObject  Device object for work item allocation.
 * @param TTLSeconds    Cache entry TTL in seconds (clamped to MAX_TTL).
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ShadowStrikeCacheInitialize(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG TTLSeconds
    );

/**
 * @brief Shutdown the scan cache.
 *
 * Frees all entries and resources. Must be called during driver unload.
 * Properly synchronizes with pending DPC/work items to prevent BSOD.
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
 * @param Verdict     Scan verdict to cache (validated against enum range).
 * @param ThreatScore Threat score (0-100).
 * @param TTLSeconds  Entry-specific TTL (0 = use default, clamped to MAX_TTL).
 * @return STATUS_SUCCESS on success, STATUS_INVALID_PARAMETER for invalid verdict.
 */
NTSTATUS
ShadowStrikeCacheInsert(
    _In_ PSHADOWSTRIKE_CACHE_KEY Key,
    _In_ SHADOWSTRIKE_SCAN_VERDICT Verdict,
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
 * @brief Get cache statistics (atomic snapshot).
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
 * @return STATUS_SUCCESS if ALL key fields were populated successfully.
 *         STATUS_UNSUCCESSFUL if any required field could not be obtained.
 */
NTSTATUS
ShadowStrikeCacheBuildKey(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PSHADOWSTRIKE_CACHE_KEY Key
    );

/**
 * @brief Build a PATH-domain cache key, usable before a create completes.
 *
 * Issues no I/O at all, which is the point: ShadowStrikeCacheBuildKey costs
 * three FltQueryInformationFile calls plus one FltQueryVolumeInformation, and
 * on the create path all three of the file-level ones are guaranteed to fail
 * because the file is not open yet.
 *
 * The hash is computed over the UPCASED path because Windows file names are
 * case-insensitive: hashing raw characters would give the same file two keys
 * depending on how the caller happened to spell it, silently halving the hit
 * rate and letting one spelling answer from a stale entry the other refreshed.
 *
 * @param VolumeSerial  Volume serial number. MUST be non-zero - see the body.
 * @param Path          Normalised path, typically NameInfo->Name.
 * @param Key           Receives the key. Zeroed on every path, including error.
 * @return STATUS_SUCCESS, or STATUS_NOT_SUPPORTED when no usable volume serial
 *         is available, or STATUS_INVALID_PARAMETER for a malformed path.
 */
NTSTATUS
ShadowStrikeCacheBuildPathKey(
    _In_ ULONG VolumeSerial,
    _In_ PCUNICODE_STRING Path,
    _Out_ PSHADOWSTRIKE_CACHE_KEY Key
    );

/**
 * @brief Attach the content identity observed for an already-inserted entry.
 *
 * Split from ShadowStrikeCacheInsert deliberately rather than folded into it.
 * The verdict is known at the moment the scan answers, but the identity is only
 * obtainable once the file is open, which on the create path is a different
 * callback. Forcing both into one call would mean either delaying the insert
 * until post-create - losing the verdict if the open fails - or passing an
 * identity that is not yet knowable.
 *
 * A path-keyed entry with no witness is treated as unusable by design, so an
 * insert that is never followed by this call fails safe: the next open re-scans.
 *
 * @param Key            Key of the entry to annotate.
 * @param FileId         Observed NTFS file ID.
 * @param FileSize       Observed file size.
 * @param LastWriteTime  Observed last-write time.
 * @return TRUE if a live entry was found and annotated.
 */
BOOLEAN
ShadowStrikeCacheSetEntryIdentity(
    _In_ PSHADOWSTRIKE_CACHE_KEY Key,
    _In_ UINT64 FileId,
    _In_ UINT64 FileSize,
    _In_ LARGE_INTEGER LastWriteTime
    );

/**
 * @brief Record the identity of a just-scanned file against its path entry.
 *
 * Called from a POST-create callback, where the file is open and its identity
 * is obtainable - which is exactly what the pre-create callback cannot do.
 *
 * @param FltObjects    Filter objects from the post-create callback.
 * @param VolumeSerial  Volume serial used to build the path key.
 * @param Path          Same normalised path used to build the path key.
 * @return STATUS_SUCCESS if the entry was annotated.
 */
NTSTATUS
ShadowStrikeCacheAnnotatePathEntry(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ ULONG VolumeSerial,
    _In_ PCUNICODE_STRING Path
    );

/**
 * @brief Confirm that a path-keyed hit still describes the file now open.
 *
 * This is the whole safety argument for path keying. A path says nothing about
 * the bytes behind it, so a verdict reached through a path key is provisional
 * until the identity observed when that verdict was produced is compared
 * against the file the create actually opened.
 *
 * FAIL-SECURE IN EVERY DIRECTION. Mismatch sets *IdentityMismatch. So does an
 * identity that cannot be read at all, and so does an entry carrying no witness:
 * in each of those cases a scan was skipped on the strength of a claim that
 * could not be substantiated, and the only safe conclusion is that the open must
 * not stand. The stale entry is removed on every one of those paths, so the
 * caller's retry is scanned normally instead of failing a second time.
 *
 * @param FltObjects        Filter objects from the post-create callback.
 * @param VolumeSerial      Volume serial used to build the path key.
 * @param Path              Same normalised path used to build the path key.
 * @param IdentityMismatch  Set TRUE when the caller MUST revoke the open.
 * @return STATUS_SUCCESS when the verification ran to a conclusion.
 */
NTSTATUS
ShadowStrikeCacheVerifyPathEntry(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ ULONG VolumeSerial,
    _In_ PCUNICODE_STRING Path,
    _Out_ PBOOLEAN IdentityMismatch
    );

/**
 * @brief Validate that a verdict value is within valid range.
 *
 * @param Verdict  Verdict value to validate.
 * @return TRUE if valid, FALSE otherwise.
 */
FORCEINLINE
BOOLEAN
ShadowStrikeCacheIsValidVerdict(
    _In_ SHADOWSTRIKE_SCAN_VERDICT Verdict
    )
{
    return (Verdict >= Verdict_Unknown && Verdict <= SHADOWSTRIKE_VERDICT_MAX);
}

/**
 * @brief Determine whether a verdict is safe to persist in the cache.
 *
 * SECURITY: Transient outcomes (Unknown / Error / Timeout) MUST NOT be
 * cached. If a hostile or malformed file forced the user-mode scanner
 * into a transient failure, caching that result would let the same
 * malicious file bypass scanning for the entire TTL window after a
 * single induced failure. Only definitive verdicts are cacheable.
 *
 * @param Verdict  Verdict to evaluate.
 * @return TRUE if the verdict represents a definitive scan result.
 */
FORCEINLINE
BOOLEAN
ShadowStrikeCacheIsCacheableVerdict(
    _In_ SHADOWSTRIKE_SCAN_VERDICT Verdict
    )
{
    return (Verdict == Verdict_Clean ||
            Verdict == Verdict_Malicious ||
            Verdict == Verdict_Suspicious);
}

/**
 * @brief Calculate hash for cache key.
 *
 * Uses FNV-1a hash over the named key members only. Padding/Reserved
 * bytes are intentionally excluded so two keys with identical logical
 * content always hash identically, regardless of whether the caller
 * pre-zeroed the struct. Member order in the hash is fixed and is
 * independent of struct layout for forward compatibility.
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
    ULONG hash = 2166136261u;
    UINT8 buffer[sizeof(UINT64) * 3 + sizeof(ULONG) * 2];
    SIZE_T offset = 0;
    SIZE_T i;

    //
    // Pack significant fields into a contiguous, layout-independent
    // byte stream. This avoids reading any compiler padding and is
    // robust against future layout changes.
    //
    RtlCopyMemory(buffer + offset, &Key->FileId, sizeof(UINT64));
    offset += sizeof(UINT64);
    RtlCopyMemory(buffer + offset, &Key->FileSize, sizeof(UINT64));
    offset += sizeof(UINT64);
    RtlCopyMemory(buffer + offset, &Key->LastWriteTime.QuadPart, sizeof(UINT64));
    offset += sizeof(UINT64);
    RtlCopyMemory(buffer + offset, &Key->VolumeSerial, sizeof(ULONG));
    offset += sizeof(ULONG);
    //
    // The discriminator is hashed, not merely compared. Hashing it spreads the
    // two key kinds across different buckets instead of relying on the equality
    // test alone to separate collided entries.
    //
    RtlCopyMemory(buffer + offset, &Key->KeyKind, sizeof(ULONG));
    offset += sizeof(ULONG);

    for (i = 0; i < offset; i++) {
        hash ^= buffer[i];
        hash *= 16777619u;
    }

    return hash;
}

/**
 * @brief Atomically update peak value using compare-exchange loop.
 *
 * @param Peak    Pointer to peak counter.
 * @param NewVal  New value to compare against peak.
 */
FORCEINLINE
VOID
ShadowStrikeCacheUpdatePeak(
    _Inout_ volatile LONG* Peak,
    _In_ LONG NewVal
    )
{
    LONG current;
    do {
        current = *Peak;
        if (NewVal <= current) {
            break;
        }
    } while (InterlockedCompareExchange(Peak, NewVal, current) != current);
}

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_SCAN_CACHE_H
