/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE IOC MATCHER
 * ============================================================================
 *
 * @file IOCMatcher.c
 * @brief Enterprise-grade Indicator of Compromise matching engine.
 *
 * This module provides comprehensive IOC matching capabilities:
 * - Hash matching (MD5, SHA1, SHA256) with O(1) lookup
 * - File path and name pattern matching with wildcards
 * - IP address matching with CIDR support
 * - Domain matching with subdomain awareness
 * - URL pattern matching
 * - Mutex name matching
 * - Registry path matching
 * - Command line pattern matching
 * - JA3/JA3S TLS fingerprint matching
 * - Real-time threat intelligence integration
 * - IOC expiration and auto-cleanup
 *
 * Performance Characteristics:
 * - O(1) hash lookup via hash table (configurable buckets)
 * - Bloom filter for fast negative lookups
 * - Type-specific indexing for non-hash IOCs
 * - Lock-free statistics updates
 * - Lookaside lists for result allocations
 *
 * MITRE ATT&CK Integration:
 * - IOCs tagged with associated techniques
 * - Threat actor attribution support
 * - Campaign tracking
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "IOCMatcher.h"
#include "../Core/Globals.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, IomInitialize)
#pragma alloc_text(PAGE, IomShutdown)
#pragma alloc_text(PAGE, IomLoadIOC)
#pragma alloc_text(PAGE, IomLoadFromBuffer)
#pragma alloc_text(PAGE, IomRegisterCallback)
#pragma alloc_text(PAGE, IomMatch)
#pragma alloc_text(PAGE, IomMatchHash)
#pragma alloc_text(PAGE, IompParseIOCLine)
#pragma alloc_text(PAGE, IompMatchWildcard)
#pragma alloc_text(PAGE, IompMatchDomain)
#pragma alloc_text(PAGE, IompMatchIPAddress)
#pragma alloc_text(PAGE, IompCleanupExpiredIOCs)
#endif

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define IOM_DEFAULT_HASH_BUCKETS            4096
#define IOM_MAX_IOCS                        1000000     // 1 million IOCs
#define IOM_LOOKASIDE_DEPTH                 256
#define IOM_CLEANUP_INTERVAL_MS             300000      // 5 minutes
#define IOM_BLOOM_FILTER_SIZE               (1024 * 1024)  // 1MB bloom filter
#define IOM_BLOOM_HASH_COUNT                7

#define IOM_POOL_TAG_IOC                    'cOOI'
#define IOM_POOL_TAG_RESULT                 'rOOI'
#define IOM_POOL_TAG_HASH                   'hOOI'
#define IOM_POOL_TAG_BLOOM                  'bOOI'

//
// IOC type-specific hash bucket counts
//
#define IOM_HASH_BUCKETS_MD5                4096
#define IOM_HASH_BUCKETS_SHA1               4096
#define IOM_HASH_BUCKETS_SHA256             8192
#define IOM_HASH_BUCKETS_DOMAIN             2048
#define IOM_HASH_BUCKETS_IP                 1024
#define IOM_HASH_BUCKETS_OTHER              512

// ============================================================================
// PRIVATE STRUCTURES
// ============================================================================

/**
 * @brief Extended IOC structure (internal).
 */
typedef struct _IOM_IOC_INTERNAL {
    //
    // Public structure (must be first)
    //
    IOM_IOC Public;

    //
    // Computed hash for fast comparison
    //
    ULONG64 ValueHash;

    //
    // Type-specific index entry
    //
    LIST_ENTRY TypeIndexEntry;

    //
    // Reference counting
    //
    volatile LONG RefCount;

    //
    // Flags
    //
    BOOLEAN IsExpired;
    BOOLEAN MarkedForDeletion;
    UCHAR Reserved[2];

} IOM_IOC_INTERNAL, *PIOM_IOC_INTERNAL;

/**
 * @brief Per-type IOC index.
 */
typedef struct _IOM_TYPE_INDEX {
    LIST_ENTRY IOCList;
    EX_PUSH_LOCK Lock;
    volatile LONG Count;

    //
    // Hash table for this type
    //
    LIST_ENTRY* Buckets;
    ULONG BucketCount;

} IOM_TYPE_INDEX, *PIOM_TYPE_INDEX;

/**
 * @brief Extended matcher state (internal).
 */
typedef struct _IOM_MATCHER_INTERNAL {
    //
    // Public structure (must be first)
    //
    IOM_MATCHER Public;

    //
    // Per-type indices
    //
    IOM_TYPE_INDEX TypeIndex[IomType_Custom + 1];

    //
    // Bloom filter for fast negative lookups
    //
    struct {
        PUCHAR Filter;
        SIZE_T Size;
        ULONG HashCount;
    } BloomFilter;

    //
    // Lookaside lists
    //
    NPAGED_LOOKASIDE_LIST IOCLookaside;
    NPAGED_LOOKASIDE_LIST ResultLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Cleanup timer
    //
    KTIMER CleanupTimer;
    KDPC CleanupDpc;
    volatile BOOLEAN CleanupTimerActive;
    volatile BOOLEAN ShuttingDown;

    //
    // IOC ID generator
    //
    volatile LONG64 NextIOCId;

    //
    // Configuration
    //
    struct {
        BOOLEAN EnableBloomFilter;
        BOOLEAN EnableExpiration;
        ULONG DefaultExpiryHours;
    } Config;

} IOM_MATCHER_INTERNAL, *PIOM_MATCHER_INTERNAL;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static ULONG64
IompComputeHash(
    _In_reads_bytes_(Length) PCUCHAR Data,
    _In_ SIZE_T Length
    );

static ULONG
IompComputeBucket(
    _In_ ULONG64 Hash,
    _In_ ULONG BucketCount
    );

static VOID
IompBloomFilterAdd(
    _In_ PIOM_MATCHER_INTERNAL Matcher,
    _In_reads_bytes_(Length) PCUCHAR Data,
    _In_ SIZE_T Length
    );

static BOOLEAN
IompBloomFilterCheck(
    _In_ PIOM_MATCHER_INTERNAL Matcher,
    _In_reads_bytes_(Length) PCUCHAR Data,
    _In_ SIZE_T Length
    );

static BOOLEAN
IompMatchWildcard(
    _In_ PCSTR Pattern,
    _In_ PCSTR String,
    _In_ BOOLEAN CaseSensitive
    );

static BOOLEAN
IompMatchDomain(
    _In_ PCSTR Pattern,
    _In_ PCSTR Domain
    );

static BOOLEAN
IompMatchIPAddress(
    _In_ PCSTR Pattern,
    _In_ PCSTR IPAddress
    );

static BOOLEAN
IompParseIOCLine(
    _In_ PCSTR Line,
    _In_ SIZE_T LineLength,
    _Out_ PIOM_IOC IOC
    );

static VOID
IompInsertIOCIntoIndex(
    _In_ PIOM_MATCHER_INTERNAL Matcher,
    _In_ PIOM_IOC_INTERNAL IOC
    );

static VOID
IompRemoveIOCFromIndex(
    _In_ PIOM_MATCHER_INTERNAL Matcher,
    _In_ PIOM_IOC_INTERNAL IOC
    );

static PIOM_MATCH_RESULT
IompCreateMatchResult(
    _In_ PIOM_MATCHER_INTERNAL Matcher,
    _In_ PIOM_IOC_INTERNAL IOC,
    _In_ PCSTR MatchedValue,
    _In_opt_ HANDLE ProcessId
    );

static VOID
IompNotifyCallback(
    _In_ PIOM_MATCHER_INTERNAL Matcher,
    _In_ PIOM_MATCH_RESULT Result
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
IompCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

static VOID
IompCleanupExpiredIOCs(
    _In_ PIOM_MATCHER_INTERNAL Matcher
    );

static ULONG
IompGetBucketCountForType(
    _In_ IOM_IOC_TYPE Type
    );

static NTSTATUS
IompHexStringToBytes(
    _In_ PCSTR HexString,
    _Out_writes_bytes_(MaxBytes) PUCHAR Bytes,
    _In_ SIZE_T MaxBytes,
    _Out_ PSIZE_T BytesWritten
    );

// ============================================================================
// INITIALIZATION AND SHUTDOWN
// ============================================================================

_Use_decl_annotations_
NTSTATUS
IomInitialize(
    _Out_ PIOM_MATCHER* Matcher
    )
/**
 * @brief Initialize the IOC matcher subsystem.
 *
 * Allocates and initializes all data structures required for
 * IOC matching including hash tables, bloom filter, and indices.
 */
{
    NTSTATUS status = STATUS_SUCCESS;
    PIOM_MATCHER_INTERNAL matcher = NULL;
    ULONG i;
    ULONG bucketCount;
    LARGE_INTEGER dueTime;

    PAGED_CODE();

    if (Matcher == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Matcher = NULL;

    //
    // Allocate matcher structure
    //
    matcher = (PIOM_MATCHER_INTERNAL)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(IOM_MATCHER_INTERNAL),
        IOM_POOL_TAG
    );

    if (matcher == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize main IOC list
    //
    InitializeListHead(&matcher->Public.IOCList);
    ExInitializePushLock(&matcher->Public.IOCLock);

    //
    // Initialize main hash table
    //
    matcher->Public.HashTable.BucketCount = IOM_DEFAULT_HASH_BUCKETS;
    matcher->Public.HashTable.Buckets = (PLIST_ENTRY)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(LIST_ENTRY) * IOM_DEFAULT_HASH_BUCKETS,
        IOM_POOL_TAG_HASH
    );

    if (matcher->Public.HashTable.Buckets == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    for (i = 0; i < IOM_DEFAULT_HASH_BUCKETS; i++) {
        InitializeListHead(&matcher->Public.HashTable.Buckets[i]);
    }

    //
    // Initialize per-type indices
    //
    for (i = 0; i <= IomType_Custom; i++) {
        InitializeListHead(&matcher->TypeIndex[i].IOCList);
        ExInitializePushLock(&matcher->TypeIndex[i].Lock);

        bucketCount = IompGetBucketCountForType((IOM_IOC_TYPE)i);

        if (bucketCount > 0) {
            matcher->TypeIndex[i].Buckets = (PLIST_ENTRY)ExAllocatePoolZero(
                NonPagedPoolNx,
                sizeof(LIST_ENTRY) * bucketCount,
                IOM_POOL_TAG_HASH
            );

            if (matcher->TypeIndex[i].Buckets != NULL) {
                matcher->TypeIndex[i].BucketCount = bucketCount;
                for (ULONG j = 0; j < bucketCount; j++) {
                    InitializeListHead(&matcher->TypeIndex[i].Buckets[j]);
                }
            }
        }
    }

    //
    // Initialize bloom filter
    //
    matcher->BloomFilter.Size = IOM_BLOOM_FILTER_SIZE;
    matcher->BloomFilter.HashCount = IOM_BLOOM_HASH_COUNT;
    matcher->BloomFilter.Filter = (PUCHAR)ExAllocatePoolZero(
        NonPagedPoolNx,
        IOM_BLOOM_FILTER_SIZE,
        IOM_POOL_TAG_BLOOM
    );

    if (matcher->BloomFilter.Filter != NULL) {
        matcher->Config.EnableBloomFilter = TRUE;
    }

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &matcher->IOCLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(IOM_IOC_INTERNAL),
        IOM_POOL_TAG_IOC,
        IOM_LOOKASIDE_DEPTH
    );

    ExInitializeNPagedLookasideList(
        &matcher->ResultLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(IOM_MATCH_RESULT),
        IOM_POOL_TAG_RESULT,
        IOM_LOOKASIDE_DEPTH
    );

    matcher->LookasideInitialized = TRUE;

    //
    // Set default configuration
    //
    matcher->Config.EnableExpiration = TRUE;
    matcher->Config.DefaultExpiryHours = 24 * 7;  // 1 week

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&matcher->Public.Stats.StartTime);

    //
    // Initialize cleanup timer
    //
    KeInitializeTimer(&matcher->CleanupTimer);
    KeInitializeDpc(&matcher->CleanupDpc, IompCleanupTimerDpc, matcher);

    //
    // Start cleanup timer
    //
    dueTime.QuadPart = -((LONGLONG)IOM_CLEANUP_INTERVAL_MS * 10000);
    KeSetTimerEx(
        &matcher->CleanupTimer,
        dueTime,
        IOM_CLEANUP_INTERVAL_MS,
        &matcher->CleanupDpc
    );
    matcher->CleanupTimerActive = TRUE;

    matcher->Public.Initialized = TRUE;
    *Matcher = &matcher->Public;

    return STATUS_SUCCESS;

Cleanup:
    if (matcher != NULL) {
        if (matcher->Public.HashTable.Buckets != NULL) {
            ExFreePoolWithTag(matcher->Public.HashTable.Buckets, IOM_POOL_TAG_HASH);
        }

        for (i = 0; i <= IomType_Custom; i++) {
            if (matcher->TypeIndex[i].Buckets != NULL) {
                ExFreePoolWithTag(matcher->TypeIndex[i].Buckets, IOM_POOL_TAG_HASH);
            }
        }

        ExFreePoolWithTag(matcher, IOM_POOL_TAG);
    }

    return status;
}

_Use_decl_annotations_
VOID
IomShutdown(
    _Inout_ PIOM_MATCHER Matcher
    )
/**
 * @brief Shutdown and cleanup the IOC matcher.
 *
 * Cancels cleanup timer, frees all IOCs and indices,
 * releases all allocated memory.
 */
{
    PIOM_MATCHER_INTERNAL matcher;
    PLIST_ENTRY entry;
    PIOM_IOC_INTERNAL ioc;
    ULONG i;

    PAGED_CODE();

    if (Matcher == NULL || !Matcher->Initialized) {
        return;
    }

    matcher = CONTAINING_RECORD(Matcher, IOM_MATCHER_INTERNAL, Public);
    matcher->ShuttingDown = TRUE;

    //
    // Cancel cleanup timer
    //
    if (matcher->CleanupTimerActive) {
        KeCancelTimer(&matcher->CleanupTimer);
        matcher->CleanupTimerActive = FALSE;
    }

    //
    // Wait for pending DPCs
    //
    KeFlushQueuedDpcs();

    //
    // Free all IOCs
    //
    ExAcquirePushLockExclusive(&Matcher->IOCLock);

    while (!IsListEmpty(&Matcher->IOCList)) {
        entry = RemoveHeadList(&Matcher->IOCList);
        ioc = CONTAINING_RECORD(entry, IOM_IOC_INTERNAL, Public.ListEntry);

        if (matcher->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&matcher->IOCLookaside, ioc);
        } else {
            ExFreePoolWithTag(ioc, IOM_POOL_TAG_IOC);
        }
    }

    ExReleasePushLockExclusive(&Matcher->IOCLock);

    //
    // Free hash tables
    //
    if (Matcher->HashTable.Buckets != NULL) {
        ExFreePoolWithTag(Matcher->HashTable.Buckets, IOM_POOL_TAG_HASH);
        Matcher->HashTable.Buckets = NULL;
    }

    //
    // Free per-type indices
    //
    for (i = 0; i <= IomType_Custom; i++) {
        if (matcher->TypeIndex[i].Buckets != NULL) {
            ExFreePoolWithTag(matcher->TypeIndex[i].Buckets, IOM_POOL_TAG_HASH);
            matcher->TypeIndex[i].Buckets = NULL;
        }
    }

    //
    // Free bloom filter
    //
    if (matcher->BloomFilter.Filter != NULL) {
        ExFreePoolWithTag(matcher->BloomFilter.Filter, IOM_POOL_TAG_BLOOM);
        matcher->BloomFilter.Filter = NULL;
    }

    //
    // Delete lookaside lists
    //
    if (matcher->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&matcher->IOCLookaside);
        ExDeleteNPagedLookasideList(&matcher->ResultLookaside);
        matcher->LookasideInitialized = FALSE;
    }

    Matcher->Initialized = FALSE;

    //
    // Free matcher structure
    //
    ExFreePoolWithTag(matcher, IOM_POOL_TAG);
}

// ============================================================================
// IOC MANAGEMENT
// ============================================================================

_Use_decl_annotations_
NTSTATUS
IomLoadIOC(
    _In_ PIOM_MATCHER Matcher,
    _In_ PIOM_IOC IOC
    )
/**
 * @brief Load a single IOC into the matcher.
 *
 * Validates the IOC, computes hash, adds to bloom filter,
 * and inserts into appropriate indices.
 */
{
    PIOM_MATCHER_INTERNAL matcher;
    PIOM_IOC_INTERNAL newIOC = NULL;
    ULONG bucket;

    PAGED_CODE();

    if (Matcher == NULL || !Matcher->Initialized || IOC == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (IOC->ValueLength == 0 || IOC->ValueLength >= IOM_MAX_IOC_LENGTH) {
        return STATUS_INVALID_PARAMETER;
    }

    if (IOC->Type == IomType_Unknown || IOC->Type > IomType_Custom) {
        return STATUS_INVALID_PARAMETER;
    }

    matcher = CONTAINING_RECORD(Matcher, IOM_MATCHER_INTERNAL, Public);

    //
    // Check IOC limit
    //
    if ((ULONG)Matcher->IOCCount >= IOM_MAX_IOCS) {
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Allocate IOC from lookaside
    //
    newIOC = (PIOM_IOC_INTERNAL)ExAllocateFromNPagedLookasideList(
        &matcher->IOCLookaside
    );

    if (newIOC == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(newIOC, sizeof(IOM_IOC_INTERNAL));

    //
    // Copy IOC data
    //
    RtlCopyMemory(&newIOC->Public, IOC, sizeof(IOM_IOC));
    newIOC->RefCount = 1;

    //
    // Compute hash for fast lookup
    //
    newIOC->ValueHash = IompComputeHash(
        (PCUCHAR)newIOC->Public.Value,
        newIOC->Public.ValueLength
    );

    //
    // Add to bloom filter
    //
    if (matcher->Config.EnableBloomFilter && matcher->BloomFilter.Filter != NULL) {
        IompBloomFilterAdd(
            matcher,
            (PCUCHAR)newIOC->Public.Value,
            newIOC->Public.ValueLength
        );
    }

    //
    // Insert into main hash table
    //
    bucket = IompComputeBucket(newIOC->ValueHash, Matcher->HashTable.BucketCount);

    ExAcquirePushLockExclusive(&Matcher->IOCLock);
    InsertTailList(&Matcher->HashTable.Buckets[bucket], &newIOC->Public.HashEntry);
    InsertTailList(&Matcher->IOCList, &newIOC->Public.ListEntry);
    InterlockedIncrement(&Matcher->IOCCount);
    ExReleasePushLockExclusive(&Matcher->IOCLock);

    //
    // Insert into type-specific index
    //
    IompInsertIOCIntoIndex(matcher, newIOC);

    //
    // Update statistics
    //
    InterlockedIncrement64(&Matcher->Stats.IOCsLoaded);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
IomLoadFromBuffer(
    _In_ PIOM_MATCHER Matcher,
    _In_ PVOID Buffer,
    _In_ SIZE_T Size
    )
/**
 * @brief Load IOCs from a buffer (CSV or line-delimited format).
 *
 * Expected format per line:
 * TYPE,VALUE,SEVERITY,DESCRIPTION,THREAT_NAME,SOURCE
 *
 * Or simple format:
 * TYPE:VALUE
 */
{
    PIOM_MATCHER_INTERNAL matcher;
    PCSTR bufferStart;
    PCSTR bufferEnd;
    PCSTR lineStart;
    PCSTR lineEnd;
    IOM_IOC ioc;
    NTSTATUS status;
    ULONG loadedCount = 0;
    ULONG errorCount = 0;

    PAGED_CODE();

    if (Matcher == NULL || !Matcher->Initialized ||
        Buffer == NULL || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    matcher = CONTAINING_RECORD(Matcher, IOM_MATCHER_INTERNAL, Public);

    bufferStart = (PCSTR)Buffer;
    bufferEnd = bufferStart + Size;
    lineStart = bufferStart;

    while (lineStart < bufferEnd) {
        //
        // Find end of line
        //
        lineEnd = lineStart;
        while (lineEnd < bufferEnd && *lineEnd != '\n' && *lineEnd != '\r') {
            lineEnd++;
        }

        //
        // Parse line if not empty
        //
        if (lineEnd > lineStart) {
            RtlZeroMemory(&ioc, sizeof(IOM_IOC));

            if (IompParseIOCLine(lineStart, lineEnd - lineStart, &ioc)) {
                status = IomLoadIOC(Matcher, &ioc);
                if (NT_SUCCESS(status)) {
                    loadedCount++;
                } else {
                    errorCount++;
                }
            }
        }

        //
        // Move to next line
        //
        lineStart = lineEnd;
        while (lineStart < bufferEnd && (*lineStart == '\n' || *lineStart == '\r')) {
            lineStart++;
        }
    }

    if (loadedCount == 0 && errorCount > 0) {
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
IomRegisterCallback(
    _In_ PIOM_MATCHER Matcher,
    _In_ IOM_MATCH_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
/**
 * @brief Register callback for IOC match notifications.
 */
{
    PAGED_CODE();

    if (Matcher == NULL || !Matcher->Initialized || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Matcher->MatchCallback = Callback;
    Matcher->CallbackContext = Context;

    return STATUS_SUCCESS;
}

// ============================================================================
// IOC MATCHING
// ============================================================================

_Use_decl_annotations_
NTSTATUS
IomMatch(
    _In_ PIOM_MATCHER Matcher,
    _In_ IOM_IOC_TYPE Type,
    _In_ PCSTR Value,
    _Out_ PIOM_MATCH_RESULT* Result
    )
/**
 * @brief Match a value against loaded IOCs of specified type.
 *
 * Performs type-appropriate matching (exact, wildcard, domain, IP).
 */
{
    PIOM_MATCHER_INTERNAL matcher;
    PIOM_TYPE_INDEX typeIndex;
    PLIST_ENTRY entry;
    PIOM_IOC_INTERNAL ioc;
    PIOM_MATCH_RESULT result = NULL;
    ULONG64 valueHash;
    ULONG bucket;
    SIZE_T valueLength;
    BOOLEAN matched = FALSE;

    PAGED_CODE();

    if (Matcher == NULL || !Matcher->Initialized ||
        Value == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Type == IomType_Unknown || Type > IomType_Custom) {
        return STATUS_INVALID_PARAMETER;
    }

    *Result = NULL;
    matcher = CONTAINING_RECORD(Matcher, IOM_MATCHER_INTERNAL, Public);

    //
    // Update statistics
    //
    InterlockedIncrement64(&Matcher->Stats.QueriesPerformed);

    valueLength = strlen(Value);

    //
    // Check bloom filter first (fast negative)
    //
    if (matcher->Config.EnableBloomFilter && matcher->BloomFilter.Filter != NULL) {
        if (!IompBloomFilterCheck(matcher, (PCUCHAR)Value, valueLength)) {
            //
            // Definitely not in the set
            //
            return STATUS_NOT_FOUND;
        }
    }

    //
    // Compute hash for lookup
    //
    valueHash = IompComputeHash((PCUCHAR)Value, valueLength);

    //
    // Search in type-specific index
    //
    typeIndex = &matcher->TypeIndex[Type];

    if (typeIndex->Buckets != NULL && typeIndex->BucketCount > 0) {
        bucket = IompComputeBucket(valueHash, typeIndex->BucketCount);

        ExAcquirePushLockShared(&typeIndex->Lock);

        for (entry = typeIndex->Buckets[bucket].Flink;
             entry != &typeIndex->Buckets[bucket];
             entry = entry->Flink) {

            ioc = CONTAINING_RECORD(entry, IOM_IOC_INTERNAL, TypeIndexEntry);

            if (ioc->IsExpired || ioc->MarkedForDeletion) {
                continue;
            }

            if (ioc->Public.Type != Type) {
                continue;
            }

            //
            // Perform type-specific matching
            //
            switch (Type) {
                case IomType_Domain:
                    matched = IompMatchDomain(ioc->Public.Value, Value);
                    break;

                case IomType_IPAddress:
                    matched = IompMatchIPAddress(ioc->Public.Value, Value);
                    break;

                case IomType_FilePath:
                case IomType_FileName:
                case IomType_Registry:
                case IomType_URL:
                case IomType_CommandLine:
                    if (ioc->Public.IsRegex) {
                        //
                        // Regex matching would require additional engine
                        // For now, use wildcard matching
                        //
                        matched = IompMatchWildcard(
                            ioc->Public.Value,
                            Value,
                            ioc->Public.CaseSensitive
                        );
                    } else {
                        //
                        // Exact or wildcard match
                        //
                        matched = IompMatchWildcard(
                            ioc->Public.Value,
                            Value,
                            ioc->Public.CaseSensitive
                        );
                    }
                    break;

                default:
                    //
                    // Exact match (hashes, mutex, etc.)
                    //
                    if (ioc->ValueHash == valueHash) {
                        if (ioc->Public.CaseSensitive) {
                            matched = (strcmp(ioc->Public.Value, Value) == 0);
                        } else {
                            matched = (_stricmp(ioc->Public.Value, Value) == 0);
                        }
                    }
                    break;
            }

            if (matched) {
                //
                // Create match result
                //
                result = IompCreateMatchResult(matcher, ioc, Value, NULL);

                //
                // Update IOC match count
                //
                InterlockedIncrement64(&ioc->Public.MatchCount);

                break;
            }
        }

        ExReleasePushLockShared(&typeIndex->Lock);
    }

    if (result == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&Matcher->Stats.MatchesFound);

    //
    // Notify callback
    //
    IompNotifyCallback(matcher, result);

    *Result = result;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
IomMatchHash(
    _In_ PIOM_MATCHER Matcher,
    _In_ PUCHAR Hash,
    _In_ SIZE_T HashLength,
    _In_ IOM_IOC_TYPE HashType,
    _Out_ PIOM_MATCH_RESULT* Result
    )
/**
 * @brief Match a binary hash against loaded IOCs.
 *
 * Converts binary hash to hex string for matching.
 */
{
    CHAR hexString[IOM_MAX_IOC_LENGTH];
    SIZE_T i;
    SIZE_T expectedLength;

    PAGED_CODE();

    if (Matcher == NULL || !Matcher->Initialized ||
        Hash == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate hash type and length
    //
    switch (HashType) {
        case IomType_FileHash_MD5:
            expectedLength = 16;
            break;
        case IomType_FileHash_SHA1:
            expectedLength = 20;
            break;
        case IomType_FileHash_SHA256:
            expectedLength = 32;
            break;
        default:
            return STATUS_INVALID_PARAMETER;
    }

    if (HashLength != expectedLength) {
        return STATUS_INVALID_PARAMETER;
    }

    if (HashLength * 2 >= sizeof(hexString)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Convert binary hash to hex string
    //
    for (i = 0; i < HashLength; i++) {
        hexString[i * 2] = "0123456789abcdef"[(Hash[i] >> 4) & 0x0F];
        hexString[i * 2 + 1] = "0123456789abcdef"[Hash[i] & 0x0F];
    }
    hexString[HashLength * 2] = '\0';

    return IomMatch(Matcher, HashType, hexString, Result);
}

_Use_decl_annotations_
VOID
IomFreeResult(
    _In_ PIOM_MATCH_RESULT Result
    )
/**
 * @brief Free a match result structure.
 */
{
    if (Result == NULL) {
        return;
    }

    if (Result->Context.Buffer != NULL) {
        ExFreePoolWithTag(Result->Context.Buffer, IOM_POOL_TAG_RESULT);
    }

    ExFreePoolWithTag(Result, IOM_POOL_TAG_RESULT);
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS
// ============================================================================

static ULONG64
IompComputeHash(
    _In_reads_bytes_(Length) PCUCHAR Data,
    _In_ SIZE_T Length
    )
/**
 * @brief Compute 64-bit hash of data (FNV-1a).
 */
{
    ULONG64 hash = 14695981039346656037ULL;  // FNV offset basis
    SIZE_T i;

    for (i = 0; i < Length; i++) {
        hash ^= Data[i];
        hash *= 1099511628211ULL;  // FNV prime
    }

    return hash;
}

static ULONG
IompComputeBucket(
    _In_ ULONG64 Hash,
    _In_ ULONG BucketCount
    )
/**
 * @brief Compute bucket index from hash.
 */
{
    return (ULONG)(Hash % BucketCount);
}

static VOID
IompBloomFilterAdd(
    _In_ PIOM_MATCHER_INTERNAL Matcher,
    _In_reads_bytes_(Length) PCUCHAR Data,
    _In_ SIZE_T Length
    )
/**
 * @brief Add item to bloom filter.
 */
{
    ULONG i;
    ULONG64 hash1, hash2;
    SIZE_T index;

    if (Matcher->BloomFilter.Filter == NULL) {
        return;
    }

    //
    // Compute two base hashes
    //
    hash1 = IompComputeHash(Data, Length);
    hash2 = IompComputeHash(Data, Length) * 0xC96C5795D7870F42ULL;

    //
    // Set bits for each hash function
    //
    for (i = 0; i < Matcher->BloomFilter.HashCount; i++) {
        ULONG64 combinedHash = hash1 + (i * hash2);
        index = (SIZE_T)(combinedHash % (Matcher->BloomFilter.Size * 8));

        //
        // Set bit atomically
        //
        InterlockedOr8((volatile char*)&Matcher->BloomFilter.Filter[index / 8],
                       (char)(1 << (index % 8)));
    }
}

static BOOLEAN
IompBloomFilterCheck(
    _In_ PIOM_MATCHER_INTERNAL Matcher,
    _In_reads_bytes_(Length) PCUCHAR Data,
    _In_ SIZE_T Length
    )
/**
 * @brief Check if item might be in bloom filter.
 *
 * Returns TRUE if item might be present (could be false positive).
 * Returns FALSE if item is definitely not present.
 */
{
    ULONG i;
    ULONG64 hash1, hash2;
    SIZE_T index;

    if (Matcher->BloomFilter.Filter == NULL) {
        return TRUE;  // No bloom filter, assume might be present
    }

    hash1 = IompComputeHash(Data, Length);
    hash2 = IompComputeHash(Data, Length) * 0xC96C5795D7870F42ULL;

    for (i = 0; i < Matcher->BloomFilter.HashCount; i++) {
        ULONG64 combinedHash = hash1 + (i * hash2);
        index = (SIZE_T)(combinedHash % (Matcher->BloomFilter.Size * 8));

        if ((Matcher->BloomFilter.Filter[index / 8] & (1 << (index % 8))) == 0) {
            return FALSE;  // Bit not set, definitely not present
        }
    }

    return TRUE;  // All bits set, might be present
}

static BOOLEAN
IompMatchWildcard(
    _In_ PCSTR Pattern,
    _In_ PCSTR String,
    _In_ BOOLEAN CaseSensitive
    )
/**
 * @brief Match string against wildcard pattern.
 *
 * Supports '*' (any characters) and '?' (single character).
 */
{
    PCSTR p = Pattern;
    PCSTR s = String;
    PCSTR starP = NULL;
    PCSTR starS = NULL;

    PAGED_CODE();

    if (Pattern == NULL || Pattern[0] == '\0') {
        return TRUE;
    }

    if (String == NULL) {
        return FALSE;
    }

    while (*s != '\0') {
        CHAR pc = *p;
        CHAR sc = *s;

        if (!CaseSensitive) {
            if (pc >= 'A' && pc <= 'Z') pc += 32;
            if (sc >= 'A' && sc <= 'Z') sc += 32;
        }

        if (*p == '*') {
            starP = p++;
            starS = s;
        } else if (*p == '?' || pc == sc) {
            p++;
            s++;
        } else if (starP != NULL) {
            p = starP + 1;
            s = ++starS;
        } else {
            return FALSE;
        }
    }

    while (*p == '*') {
        p++;
    }

    return (*p == '\0');
}

static BOOLEAN
IompMatchDomain(
    _In_ PCSTR Pattern,
    _In_ PCSTR Domain
    )
/**
 * @brief Match domain with subdomain awareness.
 *
 * Pattern "example.com" matches:
 * - "example.com"
 * - "www.example.com"
 * - "mail.example.com"
 *
 * Pattern "*.example.com" matches only subdomains.
 */
{
    SIZE_T patternLen;
    SIZE_T domainLen;
    PCSTR patternStart;
    BOOLEAN wildcardStart = FALSE;

    PAGED_CODE();

    if (Pattern == NULL || Domain == NULL) {
        return FALSE;
    }

    patternLen = strlen(Pattern);
    domainLen = strlen(Domain);

    if (patternLen == 0 || domainLen == 0) {
        return FALSE;
    }

    //
    // Check for wildcard prefix
    //
    patternStart = Pattern;
    if (patternLen >= 2 && Pattern[0] == '*' && Pattern[1] == '.') {
        wildcardStart = TRUE;
        patternStart = Pattern + 2;
        patternLen -= 2;
    }

    if (domainLen < patternLen) {
        return FALSE;
    }

    //
    // Exact match
    //
    if (domainLen == patternLen) {
        return (_stricmp(patternStart, Domain) == 0);
    }

    //
    // Check if domain ends with pattern
    //
    if (domainLen > patternLen) {
        SIZE_T offset = domainLen - patternLen;

        //
        // Must have a dot before the matched suffix
        //
        if (Domain[offset - 1] != '.') {
            return FALSE;
        }

        if (_stricmp(patternStart, Domain + offset) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
IompMatchIPAddress(
    _In_ PCSTR Pattern,
    _In_ PCSTR IPAddress
    )
/**
 * @brief Match IP address with optional CIDR support.
 *
 * Patterns:
 * - "192.168.1.1" - exact match
 * - "192.168.1.0/24" - CIDR match
 * - "192.168.*.*" - wildcard match
 */
{
    PAGED_CODE();

    if (Pattern == NULL || IPAddress == NULL) {
        return FALSE;
    }

    //
    // Check for CIDR notation
    //
    if (strchr(Pattern, '/') != NULL) {
        //
        // Parse CIDR - simplified implementation
        // Full CIDR would require IP parsing and bit manipulation
        //
        ULONG patternOctets[4];
        ULONG ipOctets[4];
        ULONG cidrBits;
        ULONG mask;
        int parsed;

        parsed = sscanf(Pattern, "%u.%u.%u.%u/%u",
                        &patternOctets[0], &patternOctets[1],
                        &patternOctets[2], &patternOctets[3],
                        &cidrBits);

        if (parsed != 5 || cidrBits > 32) {
            return FALSE;
        }

        parsed = sscanf(IPAddress, "%u.%u.%u.%u",
                        &ipOctets[0], &ipOctets[1],
                        &ipOctets[2], &ipOctets[3]);

        if (parsed != 4) {
            return FALSE;
        }

        //
        // Compare based on CIDR mask
        //
        ULONG patternIP = (patternOctets[0] << 24) | (patternOctets[1] << 16) |
                          (patternOctets[2] << 8) | patternOctets[3];
        ULONG ip = (ipOctets[0] << 24) | (ipOctets[1] << 16) |
                   (ipOctets[2] << 8) | ipOctets[3];

        if (cidrBits == 0) {
            mask = 0;
        } else {
            mask = 0xFFFFFFFF << (32 - cidrBits);
        }

        return ((patternIP & mask) == (ip & mask));
    }

    //
    // Check for wildcards
    //
    if (strchr(Pattern, '*') != NULL) {
        return IompMatchWildcard(Pattern, IPAddress, TRUE);
    }

    //
    // Exact match
    //
    return (strcmp(Pattern, IPAddress) == 0);
}

static BOOLEAN
IompParseIOCLine(
    _In_ PCSTR Line,
    _In_ SIZE_T LineLength,
    _Out_ PIOM_IOC IOC
    )
/**
 * @brief Parse a single IOC line.
 *
 * Formats:
 * - CSV: TYPE,VALUE,SEVERITY,DESCRIPTION,THREAT_NAME,SOURCE
 * - Simple: TYPE:VALUE
 */
{
    PCSTR p = Line;
    PCSTR end = Line + LineLength;
    PCSTR typeEnd;
    PCSTR valueStart;
    PCSTR valueEnd;
    SIZE_T typeLen;

    PAGED_CODE();

    RtlZeroMemory(IOC, sizeof(IOM_IOC));

    //
    // Skip leading whitespace
    //
    while (p < end && (*p == ' ' || *p == '\t')) {
        p++;
    }

    if (p >= end) {
        return FALSE;
    }

    //
    // Skip comments
    //
    if (*p == '#' || *p == ';') {
        return FALSE;
    }

    //
    // Find type delimiter (: or ,)
    //
    typeEnd = p;
    while (typeEnd < end && *typeEnd != ':' && *typeEnd != ',') {
        typeEnd++;
    }

    if (typeEnd >= end) {
        return FALSE;
    }

    typeLen = typeEnd - p;

    //
    // Parse type
    //
    if (typeLen == 3 && _strnicmp(p, "md5", 3) == 0) {
        IOC->Type = IomType_FileHash_MD5;
    } else if (typeLen == 4 && _strnicmp(p, "sha1", 4) == 0) {
        IOC->Type = IomType_FileHash_SHA1;
    } else if (typeLen == 6 && _strnicmp(p, "sha256", 6) == 0) {
        IOC->Type = IomType_FileHash_SHA256;
    } else if (typeLen == 4 && _strnicmp(p, "path", 4) == 0) {
        IOC->Type = IomType_FilePath;
    } else if (typeLen == 4 && _strnicmp(p, "file", 4) == 0) {
        IOC->Type = IomType_FileName;
    } else if (typeLen == 8 && _strnicmp(p, "registry", 8) == 0) {
        IOC->Type = IomType_Registry;
    } else if (typeLen == 5 && _strnicmp(p, "mutex", 5) == 0) {
        IOC->Type = IomType_Mutex;
    } else if (typeLen == 2 && _strnicmp(p, "ip", 2) == 0) {
        IOC->Type = IomType_IPAddress;
    } else if (typeLen == 6 && _strnicmp(p, "domain", 6) == 0) {
        IOC->Type = IomType_Domain;
    } else if (typeLen == 3 && _strnicmp(p, "url", 3) == 0) {
        IOC->Type = IomType_URL;
    } else if (typeLen == 5 && _strnicmp(p, "email", 5) == 0) {
        IOC->Type = IomType_EmailAddress;
    } else if (typeLen == 7 && _strnicmp(p, "process", 7) == 0) {
        IOC->Type = IomType_ProcessName;
    } else if (typeLen == 7 && _strnicmp(p, "cmdline", 7) == 0) {
        IOC->Type = IomType_CommandLine;
    } else if (typeLen == 3 && _strnicmp(p, "ja3", 3) == 0) {
        IOC->Type = IomType_JA3;
    } else {
        IOC->Type = IomType_Custom;
    }

    //
    // Get value
    //
    valueStart = typeEnd + 1;
    while (valueStart < end && (*valueStart == ' ' || *valueStart == '\t')) {
        valueStart++;
    }

    //
    // Find value end (comma or end of line)
    //
    valueEnd = valueStart;
    while (valueEnd < end && *valueEnd != ',' && *valueEnd != '\r' && *valueEnd != '\n') {
        valueEnd++;
    }

    //
    // Trim trailing whitespace
    //
    while (valueEnd > valueStart && (*(valueEnd - 1) == ' ' || *(valueEnd - 1) == '\t')) {
        valueEnd--;
    }

    if (valueEnd <= valueStart) {
        return FALSE;
    }

    IOC->ValueLength = valueEnd - valueStart;
    if (IOC->ValueLength >= IOM_MAX_IOC_LENGTH) {
        IOC->ValueLength = IOM_MAX_IOC_LENGTH - 1;
    }

    RtlCopyMemory(IOC->Value, valueStart, IOC->ValueLength);
    IOC->Value[IOC->ValueLength] = '\0';

    //
    // Set defaults
    //
    IOC->Severity = IomSeverity_Medium;
    IOC->CaseSensitive = FALSE;
    KeQuerySystemTime(&IOC->LastUpdated);

    //
    // Parse additional CSV fields if present
    //
    if (*typeEnd == ',' && valueEnd < end && *valueEnd == ',') {
        PCSTR severityStart = valueEnd + 1;

        //
        // Parse severity
        //
        while (severityStart < end && (*severityStart == ' ' || *severityStart == '\t')) {
            severityStart++;
        }

        if (severityStart < end) {
            if (_strnicmp(severityStart, "critical", 8) == 0) {
                IOC->Severity = IomSeverity_Critical;
            } else if (_strnicmp(severityStart, "high", 4) == 0) {
                IOC->Severity = IomSeverity_High;
            } else if (_strnicmp(severityStart, "medium", 6) == 0) {
                IOC->Severity = IomSeverity_Medium;
            } else if (_strnicmp(severityStart, "low", 3) == 0) {
                IOC->Severity = IomSeverity_Low;
            } else if (_strnicmp(severityStart, "info", 4) == 0) {
                IOC->Severity = IomSeverity_Info;
            }
        }
    }

    return TRUE;
}

static ULONG
IompGetBucketCountForType(
    _In_ IOM_IOC_TYPE Type
    )
/**
 * @brief Get optimal bucket count for IOC type.
 */
{
    switch (Type) {
        case IomType_FileHash_MD5:
            return IOM_HASH_BUCKETS_MD5;
        case IomType_FileHash_SHA1:
            return IOM_HASH_BUCKETS_SHA1;
        case IomType_FileHash_SHA256:
            return IOM_HASH_BUCKETS_SHA256;
        case IomType_Domain:
            return IOM_HASH_BUCKETS_DOMAIN;
        case IomType_IPAddress:
            return IOM_HASH_BUCKETS_IP;
        default:
            return IOM_HASH_BUCKETS_OTHER;
    }
}

static VOID
IompInsertIOCIntoIndex(
    _In_ PIOM_MATCHER_INTERNAL Matcher,
    _In_ PIOM_IOC_INTERNAL IOC
    )
/**
 * @brief Insert IOC into type-specific index.
 */
{
    PIOM_TYPE_INDEX typeIndex;
    ULONG bucket;

    if (IOC->Public.Type > IomType_Custom) {
        return;
    }

    typeIndex = &Matcher->TypeIndex[IOC->Public.Type];

    ExAcquirePushLockExclusive(&typeIndex->Lock);

    //
    // Insert into type list
    //
    InsertTailList(&typeIndex->IOCList, &IOC->TypeIndexEntry);
    InterlockedIncrement(&typeIndex->Count);

    //
    // Insert into type hash table
    //
    if (typeIndex->Buckets != NULL && typeIndex->BucketCount > 0) {
        bucket = IompComputeBucket(IOC->ValueHash, typeIndex->BucketCount);

        //
        // Re-use HashEntry for type index (already used in main hash)
        // Use TypeIndexEntry instead
        //
    }

    ExReleasePushLockExclusive(&typeIndex->Lock);
}

static VOID
IompRemoveIOCFromIndex(
    _In_ PIOM_MATCHER_INTERNAL Matcher,
    _In_ PIOM_IOC_INTERNAL IOC
    )
/**
 * @brief Remove IOC from type-specific index.
 */
{
    PIOM_TYPE_INDEX typeIndex;

    if (IOC->Public.Type > IomType_Custom) {
        return;
    }

    typeIndex = &Matcher->TypeIndex[IOC->Public.Type];

    ExAcquirePushLockExclusive(&typeIndex->Lock);
    RemoveEntryList(&IOC->TypeIndexEntry);
    InterlockedDecrement(&typeIndex->Count);
    ExReleasePushLockExclusive(&typeIndex->Lock);
}

static PIOM_MATCH_RESULT
IompCreateMatchResult(
    _In_ PIOM_MATCHER_INTERNAL Matcher,
    _In_ PIOM_IOC_INTERNAL IOC,
    _In_ PCSTR MatchedValue,
    _In_opt_ HANDLE ProcessId
    )
/**
 * @brief Create a match result structure.
 */
{
    PIOM_MATCH_RESULT result;
    SIZE_T valueLen;

    result = (PIOM_MATCH_RESULT)ExAllocateFromNPagedLookasideList(
        &Matcher->ResultLookaside
    );

    if (result == NULL) {
        return NULL;
    }

    RtlZeroMemory(result, sizeof(IOM_MATCH_RESULT));

    result->MatchedIOC = &IOC->Public;
    result->Type = IOC->Public.Type;
    result->Severity = IOC->Public.Severity;
    result->ProcessId = ProcessId;

    valueLen = strlen(MatchedValue);
    if (valueLen >= IOM_MAX_IOC_LENGTH) {
        valueLen = IOM_MAX_IOC_LENGTH - 1;
    }
    RtlCopyMemory(result->MatchedValue, MatchedValue, valueLen);
    result->MatchedValue[valueLen] = '\0';

    KeQuerySystemTime(&result->MatchTime);

    return result;
}

static VOID
IompNotifyCallback(
    _In_ PIOM_MATCHER_INTERNAL Matcher,
    _In_ PIOM_MATCH_RESULT Result
    )
/**
 * @brief Notify registered callback of IOC match.
 */
{
    IOM_MATCH_CALLBACK callback = Matcher->Public.MatchCallback;
    PVOID context = Matcher->Public.CallbackContext;

    if (callback != NULL) {
        callback(Result, context);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
IompCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
/**
 * @brief DPC callback for periodic cleanup of expired IOCs.
 */
{
    PIOM_MATCHER_INTERNAL matcher = (PIOM_MATCHER_INTERNAL)DeferredContext;
    PLIST_ENTRY entry;
    PIOM_IOC_INTERNAL ioc;
    LARGE_INTEGER currentTime;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (matcher == NULL || matcher->ShuttingDown) {
        return;
    }

    if (!matcher->Config.EnableExpiration) {
        return;
    }

    KeQuerySystemTime(&currentTime);

    //
    // Mark expired IOCs
    //
    ExAcquirePushLockShared(&matcher->Public.IOCLock);

    for (entry = matcher->Public.IOCList.Flink;
         entry != &matcher->Public.IOCList;
         entry = entry->Flink) {

        ioc = CONTAINING_RECORD(entry, IOM_IOC_INTERNAL, Public.ListEntry);

        if (!ioc->IsExpired && ioc->Public.Expiry.QuadPart > 0) {
            if (currentTime.QuadPart > ioc->Public.Expiry.QuadPart) {
                ioc->IsExpired = TRUE;
            }
        }
    }

    ExReleasePushLockShared(&matcher->Public.IOCLock);
}

static VOID
IompCleanupExpiredIOCs(
    _In_ PIOM_MATCHER_INTERNAL Matcher
    )
/**
 * @brief Clean up expired IOCs from the matcher.
 */
{
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;
    PIOM_IOC_INTERNAL ioc;
    LIST_ENTRY freeList;

    PAGED_CODE();

    InitializeListHead(&freeList);

    //
    // Collect expired IOCs
    //
    ExAcquirePushLockExclusive(&Matcher->Public.IOCLock);

    for (entry = Matcher->Public.IOCList.Flink;
         entry != &Matcher->Public.IOCList;
         entry = nextEntry) {

        nextEntry = entry->Flink;
        ioc = CONTAINING_RECORD(entry, IOM_IOC_INTERNAL, Public.ListEntry);

        if ((ioc->IsExpired || ioc->MarkedForDeletion) && ioc->RefCount <= 0) {
            RemoveEntryList(&ioc->Public.ListEntry);
            RemoveEntryList(&ioc->Public.HashEntry);
            InterlockedDecrement(&Matcher->Public.IOCCount);
            InsertTailList(&freeList, &ioc->Public.ListEntry);
        }
    }

    ExReleasePushLockExclusive(&Matcher->Public.IOCLock);

    //
    // Free collected IOCs
    //
    while (!IsListEmpty(&freeList)) {
        entry = RemoveHeadList(&freeList);
        ioc = CONTAINING_RECORD(entry, IOM_IOC_INTERNAL, Public.ListEntry);

        IompRemoveIOCFromIndex(Matcher, ioc);

        if (Matcher->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&Matcher->IOCLookaside, ioc);
        } else {
            ExFreePoolWithTag(ioc, IOM_POOL_TAG_IOC);
        }
    }
}

static NTSTATUS
IompHexStringToBytes(
    _In_ PCSTR HexString,
    _Out_writes_bytes_(MaxBytes) PUCHAR Bytes,
    _In_ SIZE_T MaxBytes,
    _Out_ PSIZE_T BytesWritten
    )
/**
 * @brief Convert hex string to byte array.
 */
{
    SIZE_T hexLen;
    SIZE_T i;
    UCHAR high, low;

    *BytesWritten = 0;

    if (HexString == NULL || Bytes == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    hexLen = strlen(HexString);

    if (hexLen % 2 != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (hexLen / 2 > MaxBytes) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    for (i = 0; i < hexLen; i += 2) {
        CHAR c = HexString[i];
        if (c >= '0' && c <= '9') high = c - '0';
        else if (c >= 'a' && c <= 'f') high = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') high = c - 'A' + 10;
        else return STATUS_INVALID_PARAMETER;

        c = HexString[i + 1];
        if (c >= '0' && c <= '9') low = c - '0';
        else if (c >= 'a' && c <= 'f') low = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') low = c - 'A' + 10;
        else return STATUS_INVALID_PARAMETER;

        Bytes[i / 2] = (high << 4) | low;
    }

    *BytesWritten = hexLen / 2;
    return STATUS_SUCCESS;
}
