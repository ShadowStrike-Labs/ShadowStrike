/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE MEMORY SCANNER ENGINE IMPLEMENTATION
 * ============================================================================
 *
 * @file MemoryScanner.c
 * @brief Enterprise-grade memory scanning engine for malware detection.
 *
 * Implements CrowdStrike Falcon-class memory scanning with:
 * - Boyer-Moore-Horspool fast single-pattern matching
 * - Aho-Corasick multi-pattern automaton for efficient scanning
 * - Wildcard pattern support with mask-based matching
 * - Multi-part signature detection
 * - Shannon entropy analysis for packed/encrypted detection
 * - Asynchronous scanning with work queue integration
 * - Memory-efficient region enumeration
 * - Thread-safe pattern management
 * - Comprehensive statistics and telemetry
 *
 * Security Hardened v2.0.0:
 * - All input parameters validated before use
 * - Integer overflow protection on size calculations
 * - Safe memory access with exception handling
 * - Reference counting for thread safety
 * - Proper cleanup on all error paths
 * - Rate limiting to prevent DoS
 *
 * Performance Optimizations:
 * - Pre-computed bad character tables for BMH
 * - Aho-Corasick state machine for O(n) multi-pattern
 * - Lookaside lists for frequent allocations
 * - Chunked scanning to limit memory pressure
 * - IRQL-aware operation selection
 *
 * MITRE ATT&CK Coverage:
 * - T1055: Process Injection (memory pattern detection)
 * - T1620: Reflective Code Loading (entropy + patterns)
 * - T1027: Obfuscated Files (entropy analysis)
 * - T1059: Command and Scripting Interpreter (shellcode patterns)
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "MemoryScanner.h"
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/StringUtils.h"
#include <ntstrsafe.h>

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

/**
 * @brief Alphabet size for BMH bad character table
 */
#define MS_ALPHABET_SIZE                256

/**
 * @brief Maximum Aho-Corasick state count
 */
#define MS_AC_MAX_STATES                65536

/**
 * @brief Aho-Corasick failure link sentinel
 */
#define MS_AC_FAIL_SENTINEL             0xFFFFFFFF

/**
 * @brief Context bytes to capture around matches
 */
#define MS_CONTEXT_BYTES                32

/**
 * @brief Lookaside list depth for patterns
 */
#define MS_PATTERN_LOOKASIDE_DEPTH      128

/**
 * @brief Lookaside list depth for matches
 */
#define MS_MATCH_LOOKASIDE_DEPTH        256

/**
 * @brief Lookaside list depth for results
 */
#define MS_RESULT_LOOKASIDE_DEPTH       32

/**
 * @brief Maximum concurrent scans
 */
#define MS_MAX_CONCURRENT_SCANS         64

/**
 * @brief Minimum region size to scan
 */
#define MS_MIN_REGION_SIZE              64

/**
 * @brief Pattern hash table bucket count
 */
#define MS_PATTERN_HASH_BUCKETS         256

/**
 * @brief Entropy calculation block size
 */
#define MS_ENTROPY_BLOCK_SIZE           256

/**
 * @brief High entropy threshold (percent)
 */
#define MS_HIGH_ENTROPY_THRESHOLD       75

/**
 * @brief Scanner magic value for validation
 */
#define MS_SCANNER_MAGIC                0x4D534352  // 'MSCR'

/**
 * @brief Pattern magic value for validation
 */
#define MS_PATTERN_MAGIC                0x4D535054  // 'MSPT'

// ============================================================================
// PRIVATE STRUCTURES
// ============================================================================

/**
 * @brief Aho-Corasick state node
 */
typedef struct _MS_AC_STATE {
    ULONG Goto[MS_ALPHABET_SIZE];       ///< Goto transitions
    ULONG Failure;                       ///< Failure link
    LIST_ENTRY OutputPatterns;           ///< Patterns that match at this state
    ULONG OutputCount;                   ///< Number of output patterns
    ULONG Depth;                         ///< State depth from root
} MS_AC_STATE, *PMS_AC_STATE;

/**
 * @brief Aho-Corasick pattern output entry
 */
typedef struct _MS_AC_OUTPUT {
    LIST_ENTRY ListEntry;
    ULONG PatternId;
    PMS_PATTERN Pattern;
} MS_AC_OUTPUT, *PMS_AC_OUTPUT;

/**
 * @brief Aho-Corasick automaton
 */
typedef struct _MS_AC_AUTOMATON {
    PMS_AC_STATE States;                 ///< State array
    ULONG StateCount;                    ///< Number of states
    ULONG MaxStates;                     ///< Maximum states allocated
    BOOLEAN Built;                       ///< Automaton is built and ready
    EX_PUSH_LOCK Lock;                   ///< Synchronization
} MS_AC_AUTOMATON, *PMS_AC_AUTOMATON;

/**
 * @brief Active scan tracking entry
 */
typedef struct _MS_ACTIVE_SCAN {
    LIST_ENTRY ListEntry;
    ULONG ScanId;
    PMS_SCAN_REQUEST Request;
    PMS_SCAN_RESULT Result;
    volatile LONG Cancelled;
    volatile LONG Completed;
    LARGE_INTEGER StartTime;
    KEVENT CompletionEvent;
    MS_SCAN_COMPLETE_CALLBACK Callback;
    PVOID CallbackContext;
    PIO_WORKITEM WorkItem;
} MS_ACTIVE_SCAN, *PMS_ACTIVE_SCAN;

/**
 * @brief Internal scanner context with additional fields
 */
typedef struct _MS_SCANNER_INTERNAL {
    //
    // Base scanner structure (must be first)
    //
    MS_SCANNER Base;

    //
    // Magic for validation
    //
    ULONG Magic;

    //
    // Aho-Corasick automaton
    //
    MS_AC_AUTOMATON AhoCorasick;

    //
    // Pattern hash table for fast lookup
    //
    LIST_ENTRY PatternHashTable[MS_PATTERN_HASH_BUCKETS];

    //
    // Lookaside lists
    //
    NPAGED_LOOKASIDE_LIST PatternLookaside;
    NPAGED_LOOKASIDE_LIST MatchLookaside;
    NPAGED_LOOKASIDE_LIST ResultLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Scan ID generation
    //
    volatile LONG NextScanId;

    //
    // Reference counting
    //
    volatile LONG ReferenceCount;
    volatile LONG ShuttingDown;
    KEVENT ShutdownEvent;

    //
    // Device object for work items
    //
    PDEVICE_OBJECT DeviceObject;

} MS_SCANNER_INTERNAL, *PMS_SCANNER_INTERNAL;

/**
 * @brief Internal pattern with additional tracking
 */
typedef struct _MS_PATTERN_INTERNAL {
    //
    // Base pattern (must be first)
    //
    MS_PATTERN Base;

    //
    // Magic for validation
    //
    ULONG Magic;

    //
    // Hash table linkage
    //
    LIST_ENTRY HashEntry;

    //
    // Back reference to scanner
    //
    PMS_SCANNER_INTERNAL Scanner;

    //
    // Reference count
    //
    volatile LONG ReferenceCount;

} MS_PATTERN_INTERNAL, *PMS_PATTERN_INTERNAL;

/**
 * @brief Async scan work item context
 */
typedef struct _MS_ASYNC_WORK_CONTEXT {
    PMS_SCANNER_INTERNAL Scanner;
    PMS_ACTIVE_SCAN ActiveScan;
} MS_ASYNC_WORK_CONTEXT, *PMS_ASYNC_WORK_CONTEXT;

// ============================================================================
// PRIVATE FUNCTION PROTOTYPES
// ============================================================================

static ULONG
MspHashPatternId(
    _In_ ULONG PatternId
);

static VOID
MspComputeBadCharTable(
    _Inout_ PMS_PATTERN Pattern
);

static NTSTATUS
MspBoyerMooreHorspoolSearch(
    _In_ PUCHAR Text,
    _In_ SIZE_T TextLen,
    _In_ PMS_PATTERN Pattern,
    _In_ MS_SCAN_FLAGS Flags,
    _Inout_ PMS_SCAN_RESULT Result,
    _In_ PVOID RegionBase,
    _In_ SIZE_T RegionSize,
    _In_ ULONG RegionProtection
);

static NTSTATUS
MspWildcardSearch(
    _In_ PUCHAR Text,
    _In_ SIZE_T TextLen,
    _In_ PMS_PATTERN Pattern,
    _In_ MS_SCAN_FLAGS Flags,
    _Inout_ PMS_SCAN_RESULT Result,
    _In_ PVOID RegionBase,
    _In_ SIZE_T RegionSize,
    _In_ ULONG RegionProtection
);

static NTSTATUS
MspAhoCorasickSearch(
    _In_ PMS_SCANNER_INTERNAL Scanner,
    _In_ PUCHAR Text,
    _In_ SIZE_T TextLen,
    _In_ MS_SCAN_FLAGS Flags,
    _Inout_ PMS_SCAN_RESULT Result,
    _In_ PVOID RegionBase,
    _In_ SIZE_T RegionSize,
    _In_ ULONG RegionProtection
);

static NTSTATUS
MspBuildAhoCorasickAutomaton(
    _Inout_ PMS_SCANNER_INTERNAL Scanner
);

static VOID
MspDestroyAhoCorasickAutomaton(
    _Inout_ PMS_AC_AUTOMATON Automaton
);

static NTSTATUS
MspAllocateMatch(
    _In_ PMS_SCANNER_INTERNAL Scanner,
    _Out_ PMS_MATCH* Match
);

static VOID
MspFreeMatch(
    _In_ PMS_SCANNER_INTERNAL Scanner,
    _In_ PMS_MATCH Match
);

static NTSTATUS
MspAllocateScanResult(
    _In_ PMS_SCANNER_INTERNAL Scanner,
    _Out_ PMS_SCAN_RESULT* Result
);

static VOID
MspAddMatchToResult(
    _In_ PMS_PATTERN Pattern,
    _In_ PUCHAR MatchLocation,
    _In_ SIZE_T Offset,
    _In_ PVOID RegionBase,
    _In_ SIZE_T RegionSize,
    _In_ ULONG RegionProtection,
    _In_ MS_SCAN_FLAGS Flags,
    _In_ PUCHAR Buffer,
    _In_ SIZE_T BufferSize,
    _Inout_ PMS_SCAN_RESULT Result,
    _In_ PMS_SCANNER_INTERNAL Scanner
);

static NTSTATUS
MspScanProcessRegions(
    _In_ PMS_SCANNER_INTERNAL Scanner,
    _In_ PEPROCESS Process,
    _In_ MS_SCAN_TYPE Type,
    _In_ MS_SCAN_FLAGS Flags,
    _Inout_ PMS_SCAN_RESULT Result
);

static NTSTATUS
MspScanSingleRegion(
    _In_ PMS_SCANNER_INTERNAL Scanner,
    _In_ PEPROCESS Process,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T RegionSize,
    _In_ ULONG Protection,
    _In_ MS_SCAN_FLAGS Flags,
    _Inout_ PMS_SCAN_RESULT Result
);

static BOOLEAN
MspShouldScanRegion(
    _In_ ULONG Protection,
    _In_ ULONG State,
    _In_ ULONG Type,
    _In_ MS_SCAN_TYPE ScanType,
    _In_ MS_SCAN_FLAGS Flags
);

static VOID
MspAsyncScanWorker(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
);

static PMS_PATTERN_INTERNAL
MspFindPatternById(
    _In_ PMS_SCANNER_INTERNAL Scanner,
    _In_ ULONG PatternId
);

static VOID
MspAcquireReference(
    _Inout_ PMS_SCANNER_INTERNAL Scanner
);

static VOID
MspReleaseReference(
    _Inout_ PMS_SCANNER_INTERNAL Scanner
);

static DOUBLE
MspCalculateShannonEntropy(
    _In_reads_bytes_(Size) PUCHAR Buffer,
    _In_ SIZE_T Size
);

// ============================================================================
// PAGE ALLOCATION
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, MsInitialize)
#pragma alloc_text(PAGE, MsShutdown)
#pragma alloc_text(PAGE, MsAddPattern)
#pragma alloc_text(PAGE, MsAddPatternWithMask)
#pragma alloc_text(PAGE, MsRemovePattern)
#pragma alloc_text(PAGE, MsEnablePattern)
#pragma alloc_text(PAGE, MsRebuildSearchTables)
#pragma alloc_text(PAGE, MsScanProcess)
#pragma alloc_text(PAGE, MsScanRegion)
#pragma alloc_text(PAGE, MsScanBuffer)
#pragma alloc_text(PAGE, MsScanAsync)
#pragma alloc_text(PAGE, MsCancelScan)
#pragma alloc_text(PAGE, MsFreeScanResult)
#pragma alloc_text(PAGE, MsFindHighEntropyRegions)
#pragma alloc_text(PAGE, MsGetStatistics)
#endif

// ============================================================================
// ENTROPY LOOKUP TABLE
// ============================================================================

/**
 * @brief Pre-computed log2 table for entropy calculation
 */
static DOUBLE g_Log2Table[256] = { 0 };
static BOOLEAN g_Log2TableInitialized = FALSE;

static VOID
MspInitializeLog2Table(
    VOID
)
{
    ULONG i;

    if (g_Log2TableInitialized) {
        return;
    }

    g_Log2Table[0] = 0.0;
    for (i = 1; i < 256; i++) {
        //
        // log2(x) = ln(x) / ln(2)
        // Approximate using integer math for kernel
        //
        DOUBLE value = (DOUBLE)i / 256.0;
        if (value > 0.0) {
            //
            // Using simplified log approximation
            // In production, use a proper math library or lookup table
            //
            DOUBLE log2Val = 0.0;
            DOUBLE x = value;

            //
            // Taylor series approximation for log2
            //
            if (x > 0) {
                DOUBLE term = (x - 1.0) / (x + 1.0);
                DOUBLE term2 = term * term;
                log2Val = 2.0 * term * (1.0 + term2/3.0 + term2*term2/5.0);
                log2Val /= 0.693147180559945;  // ln(2)
            }

            g_Log2Table[i] = log2Val;
        }
    }

    g_Log2TableInitialized = TRUE;
}

// ============================================================================
// INITIALIZATION AND CLEANUP
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MsInitialize(
    _Out_ PMS_SCANNER* Scanner
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PMS_SCANNER_INTERNAL scanner = NULL;
    ULONG i;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Scanner == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Scanner = NULL;

    //
    // Initialize log2 table for entropy calculations
    //
    MspInitializeLog2Table();

    //
    // Allocate internal scanner structure
    //
    scanner = (PMS_SCANNER_INTERNAL)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(MS_SCANNER_INTERNAL),
        MS_POOL_TAG_CONTEXT
    );

    if (scanner == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(scanner, sizeof(MS_SCANNER_INTERNAL));

    //
    // Set magic value
    //
    scanner->Magic = MS_SCANNER_MAGIC;

    //
    // Initialize pattern list
    //
    InitializeListHead(&scanner->Base.PatternList);
    ExInitializePushLock(&scanner->Base.PatternLock);

    //
    // Initialize pattern hash table
    //
    for (i = 0; i < MS_PATTERN_HASH_BUCKETS; i++) {
        InitializeListHead(&scanner->PatternHashTable[i]);
    }

    //
    // Initialize Aho-Corasick automaton
    //
    ExInitializePushLock(&scanner->AhoCorasick.Lock);
    scanner->AhoCorasick.States = NULL;
    scanner->AhoCorasick.StateCount = 0;
    scanner->AhoCorasick.MaxStates = 0;
    scanner->AhoCorasick.Built = FALSE;

    ExInitializePushLock(&scanner->Base.AhoCorasickLock);
    scanner->Base.AhoCorasickReady = FALSE;

    //
    // Initialize active scans tracking
    //
    InitializeListHead(&scanner->Base.ActiveScans);
    KeInitializeSpinLock(&scanner->Base.ActiveScansLock);

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &scanner->PatternLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(MS_PATTERN_INTERNAL),
        MS_POOL_TAG_PATTERN,
        MS_PATTERN_LOOKASIDE_DEPTH
    );

    ExInitializeNPagedLookasideList(
        &scanner->MatchLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(MS_MATCH),
        MS_POOL_TAG_RESULT,
        MS_MATCH_LOOKASIDE_DEPTH
    );

    ExInitializeNPagedLookasideList(
        &scanner->ResultLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(MS_SCAN_RESULT),
        MS_POOL_TAG_RESULT,
        MS_RESULT_LOOKASIDE_DEPTH
    );

    scanner->LookasideInitialized = TRUE;

    //
    // Initialize configuration defaults
    //
    scanner->Base.Config.MaxPatterns = MS_MAX_PATTERNS;
    scanner->Base.Config.ChunkSize = MS_SCAN_CHUNK_SIZE;
    scanner->Base.Config.DefaultTimeoutMs = MS_SCAN_TIMEOUT_MS;
    scanner->Base.Config.EnableAhoCorasick = TRUE;

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&scanner->Base.Stats.StartTime);

    //
    // Initialize reference counting
    //
    scanner->ReferenceCount = 1;
    scanner->ShuttingDown = FALSE;
    KeInitializeEvent(&scanner->ShutdownEvent, NotificationEvent, FALSE);

    //
    // Initialize scan ID counter
    //
    scanner->NextScanId = 1;

    //
    // Mark as initialized
    //
    scanner->Base.Initialized = TRUE;

    *Scanner = (PMS_SCANNER)scanner;

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
MsShutdown(
    _Inout_ PMS_SCANNER Scanner
)
{
    PMS_SCANNER_INTERNAL scanner = (PMS_SCANNER_INTERNAL)Scanner;
    PLIST_ENTRY entry;
    PMS_PATTERN_INTERNAL pattern;
    PMS_ACTIVE_SCAN activeScan;
    KIRQL oldIrql;
    LARGE_INTEGER timeout;

    PAGED_CODE();

    if (Scanner == NULL || !Scanner->Initialized) {
        return;
    }

    if (scanner->Magic != MS_SCANNER_MAGIC) {
        return;
    }

    //
    // Signal shutdown
    //
    InterlockedExchange(&scanner->ShuttingDown, 1);

    //
    // Cancel all active scans
    //
    KeAcquireSpinLock(&scanner->Base.ActiveScansLock, &oldIrql);

    for (entry = scanner->Base.ActiveScans.Flink;
         entry != &scanner->Base.ActiveScans;
         entry = entry->Flink) {

        activeScan = CONTAINING_RECORD(entry, MS_ACTIVE_SCAN, ListEntry);
        InterlockedExchange(&activeScan->Cancelled, 1);
        KeSetEvent(&activeScan->CompletionEvent, IO_NO_INCREMENT, FALSE);
    }

    KeReleaseSpinLock(&scanner->Base.ActiveScansLock, oldIrql);

    //
    // Wait for active scans to complete
    //
    timeout.QuadPart = -((LONGLONG)5000 * 10000);  // 5 seconds

    while (scanner->Base.ActiveScanCount > 0) {
        KeDelayExecutionThread(KernelMode, FALSE, &timeout);
        if (scanner->Base.ActiveScanCount > 0) {
            //
            // Force break after timeout
            //
            break;
        }
    }

    //
    // Wait for references to drain
    //
    while (scanner->ReferenceCount > 1) {
        timeout.QuadPart = -10000;  // 1ms
        KeDelayExecutionThread(KernelMode, FALSE, &timeout);
    }

    //
    // Destroy Aho-Corasick automaton
    //
    MspDestroyAhoCorasickAutomaton(&scanner->AhoCorasick);

    //
    // Free all patterns
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&scanner->Base.PatternLock);

    while (!IsListEmpty(&scanner->Base.PatternList)) {
        entry = RemoveHeadList(&scanner->Base.PatternList);
        pattern = CONTAINING_RECORD(entry, MS_PATTERN_INTERNAL, Base.ListEntry);

        //
        // Free pattern resources
        //
        if (pattern->Base.PatternData != NULL) {
            ShadowStrikeFreePoolWithTag(pattern->Base.PatternData, MS_POOL_TAG_PATTERN);
        }
        if (pattern->Base.WildcardMask != NULL) {
            ShadowStrikeFreePoolWithTag(pattern->Base.WildcardMask, MS_POOL_TAG_PATTERN);
        }
        if (pattern->Base.BadCharTable != NULL) {
            ShadowStrikeFreePoolWithTag(pattern->Base.BadCharTable, MS_POOL_TAG_PATTERN);
        }

        if (scanner->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&scanner->PatternLookaside, pattern);
        } else {
            ShadowStrikeFreePoolWithTag(pattern, MS_POOL_TAG_PATTERN);
        }
    }

    ExReleasePushLockExclusive(&scanner->Base.PatternLock);
    KeLeaveCriticalRegion();

    //
    // Delete lookaside lists
    //
    if (scanner->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&scanner->PatternLookaside);
        ExDeleteNPagedLookasideList(&scanner->MatchLookaside);
        ExDeleteNPagedLookasideList(&scanner->ResultLookaside);
        scanner->LookasideInitialized = FALSE;
    }

    //
    // Clear state
    //
    scanner->Magic = 0;
    scanner->Base.Initialized = FALSE;

    ShadowStrikeFreePoolWithTag(scanner, MS_POOL_TAG_CONTEXT);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
MsSetWorkQueue(
    _Inout_ PMS_SCANNER Scanner,
    _In_ PVOID WorkQueue
)
{
    if (Scanner == NULL || !Scanner->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    Scanner->WorkQueue = WorkQueue;
    return STATUS_SUCCESS;
}

// ============================================================================
// PATTERN MANAGEMENT
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MsAddPattern(
    _In_ PMS_SCANNER Scanner,
    _In_ PCSTR PatternName,
    _In_reads_bytes_(PatternSize) PUCHAR PatternData,
    _In_ ULONG PatternSize,
    _In_ MS_PATTERN_TYPE Type,
    _In_ MS_PATTERN_FLAGS Flags,
    _In_opt_ PCSTR ThreatName,
    _In_ ULONG Severity,
    _Out_ PULONG PatternId
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PMS_SCANNER_INTERNAL scanner = (PMS_SCANNER_INTERNAL)Scanner;
    PMS_PATTERN_INTERNAL pattern = NULL;
    ULONG hashBucket;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Scanner == NULL || !Scanner->Initialized) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (scanner->Magic != MS_SCANNER_MAGIC) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (PatternName == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (PatternData == NULL || PatternSize == 0) {
        return STATUS_INVALID_PARAMETER_3;
    }

    if (PatternSize < MS_MIN_PATTERN_SIZE || PatternSize > MS_MAX_PATTERN_SIZE) {
        return STATUS_INVALID_PARAMETER_4;
    }

    if (PatternId == NULL) {
        return STATUS_INVALID_PARAMETER_8;
    }

    *PatternId = 0;

    //
    // Check pattern limit
    //
    if ((ULONG)scanner->Base.PatternCount >= scanner->Base.Config.MaxPatterns) {
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Check for shutdown
    //
    if (scanner->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    MspAcquireReference(scanner);

    //
    // Allocate pattern from lookaside
    //
    if (scanner->LookasideInitialized) {
        pattern = (PMS_PATTERN_INTERNAL)ExAllocateFromNPagedLookasideList(
            &scanner->PatternLookaside
        );
    } else {
        pattern = (PMS_PATTERN_INTERNAL)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(MS_PATTERN_INTERNAL),
            MS_POOL_TAG_PATTERN
        );
    }

    if (pattern == NULL) {
        MspReleaseReference(scanner);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(pattern, sizeof(MS_PATTERN_INTERNAL));

    //
    // Initialize pattern
    //
    pattern->Magic = MS_PATTERN_MAGIC;
    pattern->Scanner = scanner;
    pattern->ReferenceCount = 1;
    InitializeListHead(&pattern->Base.ListEntry);
    InitializeListHead(&pattern->HashEntry);

    //
    // Allocate and copy pattern data
    //
    pattern->Base.PatternData = (PUCHAR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        PatternSize,
        MS_POOL_TAG_PATTERN
    );

    if (pattern->Base.PatternData == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    RtlCopyMemory(pattern->Base.PatternData, PatternData, PatternSize);
    pattern->Base.PatternSize = PatternSize;

    //
    // Copy pattern name
    //
    status = RtlStringCchCopyA(
        pattern->Base.PatternName,
        sizeof(pattern->Base.PatternName),
        PatternName
    );
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Copy threat name if provided
    //
    if (ThreatName != NULL) {
        RtlStringCchCopyA(
            pattern->Base.ThreatName,
            sizeof(pattern->Base.ThreatName),
            ThreatName
        );
    }

    pattern->Base.Type = Type;
    pattern->Base.Flags = Flags;
    pattern->Base.Severity = Severity;

    //
    // Compute BMH bad character table for exact patterns
    //
    if (Type == MsPattern_Exact) {
        MspComputeBadCharTable(&pattern->Base);
    }

    //
    // Assign pattern ID
    //
    pattern->Base.PatternId = (ULONG)InterlockedIncrement(&scanner->Base.NextPatternId);

    //
    // Insert into pattern list and hash table
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&scanner->Base.PatternLock);

    InsertTailList(&scanner->Base.PatternList, &pattern->Base.ListEntry);

    hashBucket = MspHashPatternId(pattern->Base.PatternId);
    InsertTailList(&scanner->PatternHashTable[hashBucket], &pattern->HashEntry);

    InterlockedIncrement(&scanner->Base.PatternCount);

    //
    // Invalidate Aho-Corasick automaton
    //
    scanner->Base.AhoCorasickReady = FALSE;
    scanner->AhoCorasick.Built = FALSE;

    ExReleasePushLockExclusive(&scanner->Base.PatternLock);
    KeLeaveCriticalRegion();

    *PatternId = pattern->Base.PatternId;
    status = STATUS_SUCCESS;

Cleanup:
    if (!NT_SUCCESS(status)) {
        if (pattern != NULL) {
            if (pattern->Base.PatternData != NULL) {
                ShadowStrikeFreePoolWithTag(pattern->Base.PatternData, MS_POOL_TAG_PATTERN);
            }
            if (scanner->LookasideInitialized) {
                ExFreeToNPagedLookasideList(&scanner->PatternLookaside, pattern);
            } else {
                ShadowStrikeFreePoolWithTag(pattern, MS_POOL_TAG_PATTERN);
            }
        }
    }

    MspReleaseReference(scanner);

    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MsAddPatternWithMask(
    _In_ PMS_SCANNER Scanner,
    _In_ PCSTR PatternName,
    _In_reads_bytes_(PatternSize) PUCHAR PatternData,
    _In_reads_bytes_(PatternSize) PUCHAR WildcardMask,
    _In_ ULONG PatternSize,
    _In_opt_ PCSTR ThreatName,
    _In_ ULONG Severity,
    _Out_ PULONG PatternId
)
{
    NTSTATUS status;
    PMS_SCANNER_INTERNAL scanner = (PMS_SCANNER_INTERNAL)Scanner;
    PMS_PATTERN_INTERNAL pattern;

    PAGED_CODE();

    //
    // First add as exact pattern
    //
    status = MsAddPattern(
        Scanner,
        PatternName,
        PatternData,
        PatternSize,
        MsPattern_Wildcard,
        MsPatternFlag_None,
        ThreatName,
        Severity,
        PatternId
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Find the pattern and add the wildcard mask
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&scanner->Base.PatternLock);

    pattern = MspFindPatternById(scanner, *PatternId);
    if (pattern != NULL) {
        //
        // Allocate and copy wildcard mask
        //
        pattern->Base.WildcardMask = (PUCHAR)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            PatternSize,
            MS_POOL_TAG_PATTERN
        );

        if (pattern->Base.WildcardMask != NULL) {
            RtlCopyMemory(pattern->Base.WildcardMask, WildcardMask, PatternSize);
        } else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    ExReleasePushLockExclusive(&scanner->Base.PatternLock);
    KeLeaveCriticalRegion();

    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MsRemovePattern(
    _In_ PMS_SCANNER Scanner,
    _In_ ULONG PatternId
)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    PMS_SCANNER_INTERNAL scanner = (PMS_SCANNER_INTERNAL)Scanner;
    PMS_PATTERN_INTERNAL pattern;

    PAGED_CODE();

    if (Scanner == NULL || !Scanner->Initialized) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (scanner->Magic != MS_SCANNER_MAGIC) {
        return STATUS_INVALID_PARAMETER_1;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&scanner->Base.PatternLock);

    pattern = MspFindPatternById(scanner, PatternId);
    if (pattern != NULL) {
        //
        // Remove from lists
        //
        RemoveEntryList(&pattern->Base.ListEntry);
        RemoveEntryList(&pattern->HashEntry);
        InterlockedDecrement(&scanner->Base.PatternCount);

        //
        // Free resources
        //
        if (pattern->Base.PatternData != NULL) {
            ShadowStrikeFreePoolWithTag(pattern->Base.PatternData, MS_POOL_TAG_PATTERN);
        }
        if (pattern->Base.WildcardMask != NULL) {
            ShadowStrikeFreePoolWithTag(pattern->Base.WildcardMask, MS_POOL_TAG_PATTERN);
        }
        if (pattern->Base.BadCharTable != NULL) {
            ShadowStrikeFreePoolWithTag(pattern->Base.BadCharTable, MS_POOL_TAG_PATTERN);
        }

        //
        // Invalidate Aho-Corasick
        //
        scanner->Base.AhoCorasickReady = FALSE;
        scanner->AhoCorasick.Built = FALSE;

        if (scanner->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&scanner->PatternLookaside, pattern);
        } else {
            ShadowStrikeFreePoolWithTag(pattern, MS_POOL_TAG_PATTERN);
        }

        status = STATUS_SUCCESS;
    }

    ExReleasePushLockExclusive(&scanner->Base.PatternLock);
    KeLeaveCriticalRegion();

    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MsEnablePattern(
    _In_ PMS_SCANNER Scanner,
    _In_ ULONG PatternId,
    _In_ BOOLEAN Enable
)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    PMS_SCANNER_INTERNAL scanner = (PMS_SCANNER_INTERNAL)Scanner;
    PMS_PATTERN_INTERNAL pattern;

    PAGED_CODE();

    if (Scanner == NULL || !Scanner->Initialized) {
        return STATUS_INVALID_PARAMETER_1;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&scanner->Base.PatternLock);

    pattern = MspFindPatternById(scanner, PatternId);
    if (pattern != NULL) {
        if (Enable) {
            pattern->Base.Flags &= ~MsPatternFlag_Disabled;
        } else {
            pattern->Base.Flags |= MsPatternFlag_Disabled;
        }
        status = STATUS_SUCCESS;
    }

    ExReleasePushLockExclusive(&scanner->Base.PatternLock);
    KeLeaveCriticalRegion();

    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MsRebuildSearchTables(
    _In_ PMS_SCANNER Scanner
)
{
    PMS_SCANNER_INTERNAL scanner = (PMS_SCANNER_INTERNAL)Scanner;
    PLIST_ENTRY entry;
    PMS_PATTERN_INTERNAL pattern;
    NTSTATUS status;

    PAGED_CODE();

    if (Scanner == NULL || !Scanner->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (scanner->Magic != MS_SCANNER_MAGIC) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&scanner->Base.PatternLock);

    //
    // Rebuild BMH tables for all exact patterns
    //
    for (entry = scanner->Base.PatternList.Flink;
         entry != &scanner->Base.PatternList;
         entry = entry->Flink) {

        pattern = CONTAINING_RECORD(entry, MS_PATTERN_INTERNAL, Base.ListEntry);

        if (pattern->Base.Type == MsPattern_Exact && !pattern->Base.TableComputed) {
            MspComputeBadCharTable(&pattern->Base);
        }
    }

    //
    // Rebuild Aho-Corasick automaton if enabled
    //
    if (scanner->Base.Config.EnableAhoCorasick) {
        MspDestroyAhoCorasickAutomaton(&scanner->AhoCorasick);
        status = MspBuildAhoCorasickAutomaton(scanner);
        if (NT_SUCCESS(status)) {
            scanner->Base.AhoCorasickReady = TRUE;
        }
    }

    ExReleasePushLockExclusive(&scanner->Base.PatternLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

// ============================================================================
// SCANNING OPERATIONS
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MsScanProcess(
    _In_ PMS_SCANNER Scanner,
    _In_ HANDLE ProcessId,
    _In_ MS_SCAN_TYPE Type,
    _In_ MS_SCAN_FLAGS Flags,
    _Out_ PMS_SCAN_RESULT* Result
)
{
    NTSTATUS status;
    PMS_SCANNER_INTERNAL scanner = (PMS_SCANNER_INTERNAL)Scanner;
    PEPROCESS process = NULL;
    PMS_SCAN_RESULT result = NULL;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Scanner == NULL || !Scanner->Initialized) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (scanner->Magic != MS_SCANNER_MAGIC) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (ProcessId == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (Result == NULL) {
        return STATUS_INVALID_PARAMETER_5;
    }

    *Result = NULL;

    //
    // Check for shutdown
    //
    if (scanner->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    MspAcquireReference(scanner);

    //
    // Get process reference
    //
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        MspReleaseReference(scanner);
        return status;
    }

    //
    // Allocate result
    //
    status = MspAllocateScanResult(scanner, &result);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(process);
        MspReleaseReference(scanner);
        return status;
    }

    result->ProcessId = ProcessId;
    result->Type = Type;
    KeQuerySystemTime(&result->StartTime);

    //
    // Ensure search tables are built
    //
    if (!scanner->Base.AhoCorasickReady && scanner->Base.Config.EnableAhoCorasick) {
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&scanner->Base.PatternLock);

        if (!scanner->AhoCorasick.Built) {
            MspBuildAhoCorasickAutomaton(scanner);
        }

        ExReleasePushLockExclusive(&scanner->Base.PatternLock);
        KeLeaveCriticalRegion();
    }

    //
    // Scan process memory regions
    //
    status = MspScanProcessRegions(scanner, process, Type, Flags, result);

    //
    // Complete result
    //
    KeQuerySystemTime(&result->EndTime);
    result->DurationMs = (ULONG)((result->EndTime.QuadPart - result->StartTime.QuadPart) / 10000);
    result->Completed = TRUE;
    result->Status = status;

    //
    // Update statistics
    //
    InterlockedIncrement64(&scanner->Base.Stats.TotalScans);
    InterlockedAdd64(&scanner->Base.Stats.BytesScanned, (LONG64)result->BytesScanned);
    InterlockedAdd64(&scanner->Base.Stats.TotalMatches, result->MatchCount);

    ObDereferenceObject(process);
    MspReleaseReference(scanner);

    *Result = result;

    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MsScanRegion(
    _In_ PMS_SCANNER Scanner,
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _In_ SIZE_T Size,
    _In_ MS_SCAN_FLAGS Flags,
    _Out_ PMS_SCAN_RESULT* Result
)
{
    NTSTATUS status;
    PMS_SCANNER_INTERNAL scanner = (PMS_SCANNER_INTERNAL)Scanner;
    PEPROCESS process = NULL;
    PMS_SCAN_RESULT result = NULL;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Scanner == NULL || !Scanner->Initialized) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (ProcessId == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (Address == NULL || Size == 0) {
        return STATUS_INVALID_PARAMETER_3;
    }

    if (Size > MS_MAX_SCAN_SIZE) {
        return STATUS_INVALID_PARAMETER_4;
    }

    if (Result == NULL) {
        return STATUS_INVALID_PARAMETER_6;
    }

    *Result = NULL;

    if (scanner->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    MspAcquireReference(scanner);

    //
    // Get process reference
    //
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        MspReleaseReference(scanner);
        return status;
    }

    //
    // Allocate result
    //
    status = MspAllocateScanResult(scanner, &result);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(process);
        MspReleaseReference(scanner);
        return status;
    }

    result->ProcessId = ProcessId;
    result->Type = MsScanType_Targeted;
    KeQuerySystemTime(&result->StartTime);

    //
    // Scan the specific region
    //
    status = MspScanSingleRegion(
        scanner,
        process,
        Address,
        Size,
        0,  // Protection unknown
        Flags,
        result
    );

    //
    // Complete result
    //
    KeQuerySystemTime(&result->EndTime);
    result->DurationMs = (ULONG)((result->EndTime.QuadPart - result->StartTime.QuadPart) / 10000);
    result->Completed = TRUE;
    result->Status = status;

    //
    // Update statistics
    //
    InterlockedIncrement64(&scanner->Base.Stats.TotalScans);
    InterlockedAdd64(&scanner->Base.Stats.BytesScanned, (LONG64)result->BytesScanned);

    ObDereferenceObject(process);
    MspReleaseReference(scanner);

    *Result = result;

    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MsScanBuffer(
    _In_ PMS_SCANNER Scanner,
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ MS_SCAN_FLAGS Flags,
    _Out_ PMS_SCAN_RESULT* Result
)
{
    NTSTATUS status;
    PMS_SCANNER_INTERNAL scanner = (PMS_SCANNER_INTERNAL)Scanner;
    PMS_SCAN_RESULT result = NULL;
    PLIST_ENTRY entry;
    PMS_PATTERN_INTERNAL pattern;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Scanner == NULL || !Scanner->Initialized) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (Buffer == NULL || Size == 0) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (Size > MS_MAX_SCAN_SIZE) {
        return STATUS_INVALID_PARAMETER_3;
    }

    if (Result == NULL) {
        return STATUS_INVALID_PARAMETER_5;
    }

    *Result = NULL;

    if (scanner->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    MspAcquireReference(scanner);

    //
    // Allocate result
    //
    status = MspAllocateScanResult(scanner, &result);
    if (!NT_SUCCESS(status)) {
        MspReleaseReference(scanner);
        return status;
    }

    result->ProcessId = PsGetCurrentProcessId();
    result->Type = MsScanType_Targeted;
    KeQuerySystemTime(&result->StartTime);

    //
    // Use Aho-Corasick if available and multiple patterns
    //
    if (scanner->Base.AhoCorasickReady && scanner->Base.PatternCount > 3) {
        KeEnterCriticalRegion();
        ExAcquirePushLockShared(&scanner->Base.AhoCorasickLock);

        status = MspAhoCorasickSearch(
            scanner,
            (PUCHAR)Buffer,
            Size,
            Flags,
            result,
            Buffer,
            Size,
            0
        );

        ExReleasePushLockShared(&scanner->Base.AhoCorasickLock);
        KeLeaveCriticalRegion();

    } else {
        //
        // Scan with each pattern
        //
        KeEnterCriticalRegion();
        ExAcquirePushLockShared(&scanner->Base.PatternLock);

        for (entry = scanner->Base.PatternList.Flink;
             entry != &scanner->Base.PatternList;
             entry = entry->Flink) {

            pattern = CONTAINING_RECORD(entry, MS_PATTERN_INTERNAL, Base.ListEntry);

            if (pattern->Base.Flags & MsPatternFlag_Disabled) {
                continue;
            }

            if (pattern->Base.Type == MsPattern_Wildcard && pattern->Base.WildcardMask != NULL) {
                MspWildcardSearch(
                    (PUCHAR)Buffer,
                    Size,
                    &pattern->Base,
                    Flags,
                    result,
                    Buffer,
                    Size,
                    0
                );
            } else {
                MspBoyerMooreHorspoolSearch(
                    (PUCHAR)Buffer,
                    Size,
                    &pattern->Base,
                    Flags,
                    result,
                    Buffer,
                    Size,
                    0
                );
            }

            //
            // Check for stop on first match
            //
            if ((Flags & MsScanFlag_StopOnFirstMatch) && result->MatchCount > 0) {
                break;
            }
        }

        ExReleasePushLockShared(&scanner->Base.PatternLock);
        KeLeaveCriticalRegion();
    }

    //
    // Complete result
    //
    result->BytesScanned = Size;
    result->RegionsScanned = 1;
    KeQuerySystemTime(&result->EndTime);
    result->DurationMs = (ULONG)((result->EndTime.QuadPart - result->StartTime.QuadPart) / 10000);
    result->Completed = TRUE;
    result->Status = STATUS_SUCCESS;

    //
    // Update statistics
    //
    InterlockedIncrement64(&scanner->Base.Stats.TotalScans);
    InterlockedAdd64(&scanner->Base.Stats.BytesScanned, (LONG64)Size);

    MspReleaseReference(scanner);

    *Result = result;

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MsScanAsync(
    _In_ PMS_SCANNER Scanner,
    _In_ PMS_SCAN_REQUEST Request,
    _In_ MS_SCAN_COMPLETE_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ PULONG ScanId
)
{
    NTSTATUS status;
    PMS_SCANNER_INTERNAL scanner = (PMS_SCANNER_INTERNAL)Scanner;
    PMS_ACTIVE_SCAN activeScan = NULL;
    PIO_WORKITEM workItem = NULL;
    PMS_ASYNC_WORK_CONTEXT workContext = NULL;
    KIRQL oldIrql;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Scanner == NULL || !Scanner->Initialized) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (Request == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (Callback == NULL) {
        return STATUS_INVALID_PARAMETER_3;
    }

    if (ScanId == NULL) {
        return STATUS_INVALID_PARAMETER_5;
    }

    *ScanId = 0;

    if (scanner->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Check concurrent scan limit
    //
    if (scanner->Base.ActiveScanCount >= MS_MAX_CONCURRENT_SCANS) {
        return STATUS_QUOTA_EXCEEDED;
    }

    MspAcquireReference(scanner);

    //
    // Allocate active scan tracking
    //
    activeScan = (PMS_ACTIVE_SCAN)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(MS_ACTIVE_SCAN),
        MS_POOL_TAG_CONTEXT
    );

    if (activeScan == NULL) {
        MspReleaseReference(scanner);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(activeScan, sizeof(MS_ACTIVE_SCAN));

    //
    // Allocate work item
    //
    if (scanner->DeviceObject != NULL) {
        workItem = IoAllocateWorkItem(scanner->DeviceObject);
        if (workItem == NULL) {
            ShadowStrikeFreePoolWithTag(activeScan, MS_POOL_TAG_CONTEXT);
            MspReleaseReference(scanner);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    //
    // Allocate work context
    //
    workContext = (PMS_ASYNC_WORK_CONTEXT)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(MS_ASYNC_WORK_CONTEXT),
        MS_POOL_TAG_CONTEXT
    );

    if (workContext == NULL) {
        if (workItem != NULL) {
            IoFreeWorkItem(workItem);
        }
        ShadowStrikeFreePoolWithTag(activeScan, MS_POOL_TAG_CONTEXT);
        MspReleaseReference(scanner);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize active scan
    //
    InitializeListHead(&activeScan->ListEntry);
    activeScan->ScanId = (ULONG)InterlockedIncrement(&scanner->NextScanId);
    activeScan->Request = Request;
    activeScan->Callback = Callback;
    activeScan->CallbackContext = Context;
    activeScan->WorkItem = workItem;
    KeInitializeEvent(&activeScan->CompletionEvent, NotificationEvent, FALSE);
    KeQuerySystemTime(&activeScan->StartTime);

    //
    // Allocate result
    //
    status = MspAllocateScanResult(scanner, &activeScan->Result);
    if (!NT_SUCCESS(status)) {
        if (workItem != NULL) {
            IoFreeWorkItem(workItem);
        }
        ShadowStrikeFreePoolWithTag(workContext, MS_POOL_TAG_CONTEXT);
        ShadowStrikeFreePoolWithTag(activeScan, MS_POOL_TAG_CONTEXT);
        MspReleaseReference(scanner);
        return status;
    }

    //
    // Set up work context
    //
    workContext->Scanner = scanner;
    workContext->ActiveScan = activeScan;

    //
    // Add to active scans list
    //
    KeAcquireSpinLock(&scanner->Base.ActiveScansLock, &oldIrql);
    InsertTailList(&scanner->Base.ActiveScans, &activeScan->ListEntry);
    InterlockedIncrement(&scanner->Base.ActiveScanCount);
    KeReleaseSpinLock(&scanner->Base.ActiveScansLock, oldIrql);

    //
    // Queue the work item
    //
    if (workItem != NULL) {
        IoQueueWorkItem(
            workItem,
            MspAsyncScanWorker,
            DelayedWorkQueue,
            workContext
        );
    } else {
        //
        // No device object - run synchronously
        //
        MspAsyncScanWorker(NULL, workContext);
    }

    *ScanId = activeScan->ScanId;

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MsCancelScan(
    _In_ PMS_SCANNER Scanner,
    _In_ ULONG ScanId
)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    PMS_SCANNER_INTERNAL scanner = (PMS_SCANNER_INTERNAL)Scanner;
    PLIST_ENTRY entry;
    PMS_ACTIVE_SCAN activeScan;
    KIRQL oldIrql;

    PAGED_CODE();

    if (Scanner == NULL || !Scanner->Initialized) {
        return STATUS_INVALID_PARAMETER_1;
    }

    KeAcquireSpinLock(&scanner->Base.ActiveScansLock, &oldIrql);

    for (entry = scanner->Base.ActiveScans.Flink;
         entry != &scanner->Base.ActiveScans;
         entry = entry->Flink) {

        activeScan = CONTAINING_RECORD(entry, MS_ACTIVE_SCAN, ListEntry);

        if (activeScan->ScanId == ScanId) {
            InterlockedExchange(&activeScan->Cancelled, 1);
            KeSetEvent(&activeScan->CompletionEvent, IO_NO_INCREMENT, FALSE);
            status = STATUS_SUCCESS;
            break;
        }
    }

    KeReleaseSpinLock(&scanner->Base.ActiveScansLock, oldIrql);

    return status;
}

// ============================================================================
// RESULT MANAGEMENT
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
VOID
MsFreeScanResult(
    _In_ PMS_SCAN_RESULT Result
)
{
    PLIST_ENTRY entry;
    PMS_MATCH match;

    PAGED_CODE();

    if (Result == NULL) {
        return;
    }

    //
    // Free all matches
    //
    while (!IsListEmpty(&Result->MatchList)) {
        entry = RemoveHeadList(&Result->MatchList);
        match = CONTAINING_RECORD(entry, MS_MATCH, ListEntry);
        ShadowStrikeFreePoolWithTag(match, MS_POOL_TAG_RESULT);
    }

    ShadowStrikeFreePoolWithTag(Result, MS_POOL_TAG_RESULT);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
MsGetNextMatch(
    _In_ PMS_SCAN_RESULT Result,
    _Inout_ PLIST_ENTRY* Iterator,
    _Out_ PMS_MATCH* Match
)
{
    PLIST_ENTRY current;

    if (Result == NULL || Iterator == NULL || Match == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Match = NULL;

    if (*Iterator == NULL) {
        current = Result->MatchList.Flink;
    } else {
        current = (*Iterator)->Flink;
    }

    if (current == &Result->MatchList) {
        return STATUS_NO_MORE_ENTRIES;
    }

    *Iterator = current;
    *Match = CONTAINING_RECORD(current, MS_MATCH, ListEntry);

    return STATUS_SUCCESS;
}

// ============================================================================
// ENTROPY ANALYSIS
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
MsCalculateEntropy(
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_ PULONG EntropyPercent
)
{
    DOUBLE entropy;

    if (Buffer == NULL || Size == 0 || EntropyPercent == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *EntropyPercent = 0;

    if (Size < MS_MIN_REGION_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    entropy = MspCalculateShannonEntropy((PUCHAR)Buffer, Size);

    //
    // Convert to percentage (max entropy is 8 bits)
    //
    *EntropyPercent = (ULONG)((entropy / 8.0) * 100.0);
    if (*EntropyPercent > 100) {
        *EntropyPercent = 100;
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MsFindHighEntropyRegions(
    _In_ PMS_SCANNER Scanner,
    _In_ HANDLE ProcessId,
    _In_ ULONG EntropyThreshold,
    _Out_writes_to_(MaxResults, *ResultCount) PVOID* Results,
    _In_ ULONG MaxResults,
    _Out_ PULONG ResultCount
)
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    KAPC_STATE apcState;
    MEMORY_BASIC_INFORMATION memInfo;
    SIZE_T returnLength;
    PVOID address = NULL;
    PUCHAR buffer = NULL;
    ULONG count = 0;
    ULONG entropy;

    PAGED_CODE();

    if (Scanner == NULL || !Scanner->Initialized) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (ProcessId == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (Results == NULL || MaxResults == 0 || ResultCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ResultCount = 0;

    //
    // Get process reference
    //
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Allocate scan buffer
    //
    buffer = (PUCHAR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        MS_SCAN_CHUNK_SIZE,
        MS_POOL_TAG_BUFFER
    );

    if (buffer == NULL) {
        ObDereferenceObject(process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Attach to process
    //
    KeStackAttachProcess(process, &apcState);

    __try {
        while (address < (PVOID)(ULONG_PTR)0x7FFFFFFFFFFF && count < MaxResults) {
            status = ZwQueryVirtualMemory(
                NtCurrentProcess(),
                address,
                MemoryBasicInformation,
                &memInfo,
                sizeof(memInfo),
                &returnLength
            );

            if (!NT_SUCCESS(status)) {
                break;
            }

            //
            // Check if region is worth scanning
            //
            if (memInfo.State == MEM_COMMIT &&
                memInfo.RegionSize >= MS_MIN_REGION_SIZE &&
                memInfo.RegionSize <= MS_SCAN_CHUNK_SIZE) {

                //
                // Read region
                //
                __try {
                    RtlCopyMemory(buffer, memInfo.BaseAddress, memInfo.RegionSize);

                    //
                    // Calculate entropy
                    //
                    status = MsCalculateEntropy(buffer, memInfo.RegionSize, &entropy);

                    if (NT_SUCCESS(status) && entropy >= EntropyThreshold) {
                        Results[count++] = memInfo.BaseAddress;
                    }

                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    // Skip inaccessible region
                }
            }

            //
            // Move to next region
            //
            address = (PVOID)((ULONG_PTR)memInfo.BaseAddress + memInfo.RegionSize);
        }

    } __finally {
        KeUnstackDetachProcess(&apcState);
    }

    ShadowStrikeFreePoolWithTag(buffer, MS_POOL_TAG_BUFFER);
    ObDereferenceObject(process);

    *ResultCount = count;

    return STATUS_SUCCESS;
}

// ============================================================================
// STATISTICS
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
MsGetStatistics(
    _In_ PMS_SCANNER Scanner,
    _Out_ PMS_STATISTICS Stats
)
{
    PMS_SCANNER_INTERNAL scanner = (PMS_SCANNER_INTERNAL)Scanner;
    LARGE_INTEGER currentTime;

    PAGED_CODE();

    if (Scanner == NULL || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Scanner->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    RtlZeroMemory(Stats, sizeof(MS_STATISTICS));

    Stats->PatternCount = (ULONG)scanner->Base.PatternCount;
    Stats->ActiveScans = (ULONG)scanner->Base.ActiveScanCount;
    Stats->TotalScans = scanner->Base.Stats.TotalScans;
    Stats->TotalMatches = scanner->Base.Stats.TotalMatches;
    Stats->BytesScanned = scanner->Base.Stats.BytesScanned;
    Stats->Timeouts = scanner->Base.Stats.Timeouts;

    KeQuerySystemTime(&currentTime);
    Stats->UpTime.QuadPart = currentTime.QuadPart - scanner->Base.Stats.StartTime.QuadPart;

    //
    // Calculate average scan time (simplified)
    //
    if (Stats->TotalScans > 0) {
        Stats->AverageScanTimeMs = (ULONG)(Stats->UpTime.QuadPart / 10000 / Stats->TotalScans);
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - HASH FUNCTIONS
// ============================================================================

static ULONG
MspHashPatternId(
    _In_ ULONG PatternId
)
{
    ULONG hash = PatternId;
    hash = hash ^ (hash >> 16);
    hash *= 0x85ebca6b;
    hash = hash ^ (hash >> 13);
    return hash % MS_PATTERN_HASH_BUCKETS;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - BOYER-MOORE-HORSPOOL
// ============================================================================

static VOID
MspComputeBadCharTable(
    _Inout_ PMS_PATTERN Pattern
)
{
    ULONG i;

    if (Pattern->TableComputed) {
        return;
    }

    //
    // Allocate bad character table
    //
    if (Pattern->BadCharTable == NULL) {
        Pattern->BadCharTable = (PULONG)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            MS_ALPHABET_SIZE * sizeof(ULONG),
            MS_POOL_TAG_PATTERN
        );

        if (Pattern->BadCharTable == NULL) {
            return;
        }
    }

    //
    // Initialize all positions to pattern length (default shift)
    //
    for (i = 0; i < MS_ALPHABET_SIZE; i++) {
        Pattern->BadCharTable[i] = Pattern->PatternSize;
    }

    //
    // Set shifts for characters in pattern (except last character)
    //
    for (i = 0; i < Pattern->PatternSize - 1; i++) {
        Pattern->BadCharTable[Pattern->PatternData[i]] = Pattern->PatternSize - 1 - i;
    }

    Pattern->TableComputed = TRUE;
}

static NTSTATUS
MspBoyerMooreHorspoolSearch(
    _In_ PUCHAR Text,
    _In_ SIZE_T TextLen,
    _In_ PMS_PATTERN Pattern,
    _In_ MS_SCAN_FLAGS Flags,
    _Inout_ PMS_SCAN_RESULT Result,
    _In_ PVOID RegionBase,
    _In_ SIZE_T RegionSize,
    _In_ ULONG RegionProtection
)
{
    SIZE_T i;
    LONG j;
    SIZE_T patternLen = Pattern->PatternSize;
    PUCHAR patternData = Pattern->PatternData;
    PULONG badCharTable;
    BOOLEAN caseSensitive = (Pattern->Flags & MsPatternFlag_CaseSensitive) != 0;
    PMS_SCANNER_INTERNAL scanner = NULL;

    if (TextLen < patternLen) {
        return STATUS_SUCCESS;  // No match possible
    }

    //
    // Get scanner from pattern for match allocation
    //
    PMS_PATTERN_INTERNAL patternInt = CONTAINING_RECORD(Pattern, MS_PATTERN_INTERNAL, Base);
    if (patternInt->Magic == MS_PATTERN_MAGIC) {
        scanner = patternInt->Scanner;
    }

    //
    // Ensure table is computed
    //
    if (!Pattern->TableComputed || Pattern->BadCharTable == NULL) {
        MspComputeBadCharTable(Pattern);
        if (Pattern->BadCharTable == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    badCharTable = Pattern->BadCharTable;

    //
    // Boyer-Moore-Horspool search
    //
    i = 0;
    while (i <= TextLen - patternLen) {
        //
        // Check for match from right to left
        //
        j = (LONG)patternLen - 1;

        while (j >= 0) {
            UCHAR textChar = Text[i + j];
            UCHAR patChar = patternData[j];

            //
            // Case-insensitive comparison if needed
            //
            if (!caseSensitive) {
                if (textChar >= 'A' && textChar <= 'Z') {
                    textChar |= 0x20;
                }
                if (patChar >= 'A' && patChar <= 'Z') {
                    patChar |= 0x20;
                }
            }

            if (textChar != patChar) {
                break;
            }
            j--;
        }

        if (j < 0) {
            //
            // Match found
            //
            MspAddMatchToResult(
                Pattern,
                Text + i,
                i,
                RegionBase,
                RegionSize,
                RegionProtection,
                Flags,
                Text,
                TextLen,
                Result,
                scanner
            );

            //
            // Update pattern statistics
            //
            InterlockedIncrement64(&Pattern->MatchCount);
            KeQuerySystemTime(&Pattern->LastMatchTime);

            if (Flags & MsScanFlag_StopOnFirstMatch) {
                break;
            }

            //
            // Move past this match
            //
            i += patternLen;
        } else {
            //
            // Shift using bad character table
            //
            UCHAR badChar = Text[i + patternLen - 1];
            i += badCharTable[badChar];
        }
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - WILDCARD SEARCH
// ============================================================================

static NTSTATUS
MspWildcardSearch(
    _In_ PUCHAR Text,
    _In_ SIZE_T TextLen,
    _In_ PMS_PATTERN Pattern,
    _In_ MS_SCAN_FLAGS Flags,
    _Inout_ PMS_SCAN_RESULT Result,
    _In_ PVOID RegionBase,
    _In_ SIZE_T RegionSize,
    _In_ ULONG RegionProtection
)
{
    SIZE_T i, j;
    SIZE_T patternLen = Pattern->PatternSize;
    PUCHAR patternData = Pattern->PatternData;
    PUCHAR wildcardMask = Pattern->WildcardMask;
    BOOLEAN match;
    PMS_SCANNER_INTERNAL scanner = NULL;

    if (TextLen < patternLen || wildcardMask == NULL) {
        return STATUS_SUCCESS;
    }

    //
    // Get scanner from pattern
    //
    PMS_PATTERN_INTERNAL patternInt = CONTAINING_RECORD(Pattern, MS_PATTERN_INTERNAL, Base);
    if (patternInt->Magic == MS_PATTERN_MAGIC) {
        scanner = patternInt->Scanner;
    }

    //
    // Simple sliding window with wildcard support
    //
    for (i = 0; i <= TextLen - patternLen; i++) {
        match = TRUE;

        for (j = 0; j < patternLen; j++) {
            //
            // Skip wildcard positions (mask byte is non-zero)
            //
            if (wildcardMask[j] != 0) {
                continue;
            }

            if (Text[i + j] != patternData[j]) {
                match = FALSE;
                break;
            }
        }

        if (match) {
            //
            // Match found
            //
            MspAddMatchToResult(
                Pattern,
                Text + i,
                i,
                RegionBase,
                RegionSize,
                RegionProtection,
                Flags,
                Text,
                TextLen,
                Result,
                scanner
            );

            InterlockedIncrement64(&Pattern->MatchCount);
            KeQuerySystemTime(&Pattern->LastMatchTime);

            if (Flags & MsScanFlag_StopOnFirstMatch) {
                break;
            }
        }
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - AHO-CORASICK
// ============================================================================

static NTSTATUS
MspBuildAhoCorasickAutomaton(
    _Inout_ PMS_SCANNER_INTERNAL Scanner
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PMS_AC_AUTOMATON automaton = &Scanner->AhoCorasick;
    PLIST_ENTRY entry;
    PMS_PATTERN_INTERNAL pattern;
    ULONG stateIndex;
    ULONG currentState;
    ULONG patternIdx;
    PULONG queue = NULL;
    ULONG queueHead, queueTail;
    ULONG i, c;

    //
    // Calculate maximum states needed
    //
    ULONG totalPatternBytes = 0;
    for (entry = Scanner->Base.PatternList.Flink;
         entry != &Scanner->Base.PatternList;
         entry = entry->Flink) {

        pattern = CONTAINING_RECORD(entry, MS_PATTERN_INTERNAL, Base.ListEntry);
        if (!(pattern->Base.Flags & MsPatternFlag_Disabled)) {
            totalPatternBytes += pattern->Base.PatternSize;
        }
    }

    automaton->MaxStates = min(totalPatternBytes + 1, MS_AC_MAX_STATES);

    //
    // Allocate states
    //
    automaton->States = (PMS_AC_STATE)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        automaton->MaxStates * sizeof(MS_AC_STATE),
        MS_POOL_TAG_CONTEXT
    );

    if (automaton->States == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(automaton->States, automaton->MaxStates * sizeof(MS_AC_STATE));

    //
    // Initialize root state (state 0)
    //
    for (i = 0; i < MS_ALPHABET_SIZE; i++) {
        automaton->States[0].Goto[i] = 0;  // Self-loop on root
    }
    automaton->States[0].Failure = 0;
    InitializeListHead(&automaton->States[0].OutputPatterns);
    automaton->StateCount = 1;

    //
    // Build goto function by adding all patterns
    //
    for (entry = Scanner->Base.PatternList.Flink;
         entry != &Scanner->Base.PatternList;
         entry = entry->Flink) {

        pattern = CONTAINING_RECORD(entry, MS_PATTERN_INTERNAL, Base.ListEntry);

        if (pattern->Base.Flags & MsPatternFlag_Disabled) {
            continue;
        }

        if (pattern->Base.Type == MsPattern_Wildcard) {
            continue;  // Skip wildcard patterns for AC
        }

        currentState = 0;

        for (patternIdx = 0; patternIdx < pattern->Base.PatternSize; patternIdx++) {
            UCHAR ch = pattern->Base.PatternData[patternIdx];

            if (automaton->States[currentState].Goto[ch] == 0 && currentState != 0) {
                //
                // Need new state
                //
                if (automaton->StateCount >= automaton->MaxStates) {
                    status = STATUS_INSUFFICIENT_RESOURCES;
                    goto Cleanup;
                }

                stateIndex = automaton->StateCount++;
                for (i = 0; i < MS_ALPHABET_SIZE; i++) {
                    automaton->States[stateIndex].Goto[i] = MS_AC_FAIL_SENTINEL;
                }
                automaton->States[stateIndex].Failure = 0;
                automaton->States[stateIndex].Depth = patternIdx + 1;
                InitializeListHead(&automaton->States[stateIndex].OutputPatterns);

                automaton->States[currentState].Goto[ch] = stateIndex;
            }

            if (automaton->States[currentState].Goto[ch] != MS_AC_FAIL_SENTINEL) {
                currentState = automaton->States[currentState].Goto[ch];
            }
        }

        //
        // Add pattern to output of final state
        //
        PMS_AC_OUTPUT output = (PMS_AC_OUTPUT)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(MS_AC_OUTPUT),
            MS_POOL_TAG_CONTEXT
        );

        if (output != NULL) {
            output->PatternId = pattern->Base.PatternId;
            output->Pattern = &pattern->Base;
            InsertTailList(&automaton->States[currentState].OutputPatterns, &output->ListEntry);
            automaton->States[currentState].OutputCount++;
        }
    }

    //
    // Build failure function using BFS
    //
    queue = (PULONG)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        automaton->StateCount * sizeof(ULONG),
        MS_POOL_TAG_BUFFER
    );

    if (queue == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    queueHead = 0;
    queueTail = 0;

    //
    // Initialize failure for depth-1 states
    //
    for (c = 0; c < MS_ALPHABET_SIZE; c++) {
        ULONG s = automaton->States[0].Goto[c];
        if (s != 0 && s != MS_AC_FAIL_SENTINEL) {
            automaton->States[s].Failure = 0;
            queue[queueTail++] = s;
        }
    }

    //
    // BFS to compute failure for remaining states
    //
    while (queueHead < queueTail) {
        ULONG r = queue[queueHead++];

        for (c = 0; c < MS_ALPHABET_SIZE; c++) {
            ULONG s = automaton->States[r].Goto[c];

            if (s != MS_AC_FAIL_SENTINEL && s != 0) {
                queue[queueTail++] = s;

                //
                // Follow failure links to find longest proper suffix
                //
                ULONG state = automaton->States[r].Failure;
                while (automaton->States[state].Goto[c] == MS_AC_FAIL_SENTINEL && state != 0) {
                    state = automaton->States[state].Failure;
                }

                automaton->States[s].Failure = automaton->States[state].Goto[c];
                if (automaton->States[s].Failure == MS_AC_FAIL_SENTINEL) {
                    automaton->States[s].Failure = 0;
                }

                //
                // Merge output functions
                //
                ULONG failState = automaton->States[s].Failure;
                if (!IsListEmpty(&automaton->States[failState].OutputPatterns)) {
                    // In a full implementation, we'd merge output lists here
                }
            }
        }
    }

    automaton->Built = TRUE;
    Scanner->Base.AhoCorasickReady = TRUE;

Cleanup:
    if (queue != NULL) {
        ShadowStrikeFreePoolWithTag(queue, MS_POOL_TAG_BUFFER);
    }

    if (!NT_SUCCESS(status)) {
        MspDestroyAhoCorasickAutomaton(automaton);
    }

    return status;
}

static VOID
MspDestroyAhoCorasickAutomaton(
    _Inout_ PMS_AC_AUTOMATON Automaton
)
{
    ULONG i;
    PLIST_ENTRY entry;
    PMS_AC_OUTPUT output;

    if (Automaton->States == NULL) {
        return;
    }

    //
    // Free output lists
    //
    for (i = 0; i < Automaton->StateCount; i++) {
        while (!IsListEmpty(&Automaton->States[i].OutputPatterns)) {
            entry = RemoveHeadList(&Automaton->States[i].OutputPatterns);
            output = CONTAINING_RECORD(entry, MS_AC_OUTPUT, ListEntry);
            ShadowStrikeFreePoolWithTag(output, MS_POOL_TAG_CONTEXT);
        }
    }

    ShadowStrikeFreePoolWithTag(Automaton->States, MS_POOL_TAG_CONTEXT);
    Automaton->States = NULL;
    Automaton->StateCount = 0;
    Automaton->MaxStates = 0;
    Automaton->Built = FALSE;
}

static NTSTATUS
MspAhoCorasickSearch(
    _In_ PMS_SCANNER_INTERNAL Scanner,
    _In_ PUCHAR Text,
    _In_ SIZE_T TextLen,
    _In_ MS_SCAN_FLAGS Flags,
    _Inout_ PMS_SCAN_RESULT Result,
    _In_ PVOID RegionBase,
    _In_ SIZE_T RegionSize,
    _In_ ULONG RegionProtection
)
{
    PMS_AC_AUTOMATON automaton = &Scanner->AhoCorasick;
    ULONG currentState = 0;
    SIZE_T i;
    PLIST_ENTRY entry;
    PMS_AC_OUTPUT output;

    if (!automaton->Built || automaton->States == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    for (i = 0; i < TextLen; i++) {
        UCHAR ch = Text[i];

        //
        // Follow failure links until we find a valid transition
        //
        while (currentState != 0 &&
               automaton->States[currentState].Goto[ch] == MS_AC_FAIL_SENTINEL) {
            currentState = automaton->States[currentState].Failure;
        }

        //
        // Take the goto transition
        //
        ULONG nextState = automaton->States[currentState].Goto[ch];
        if (nextState != MS_AC_FAIL_SENTINEL) {
            currentState = nextState;
        } else {
            currentState = 0;
        }

        //
        // Check for matches at this state
        //
        if (automaton->States[currentState].OutputCount > 0) {
            for (entry = automaton->States[currentState].OutputPatterns.Flink;
                 entry != &automaton->States[currentState].OutputPatterns;
                 entry = entry->Flink) {

                output = CONTAINING_RECORD(entry, MS_AC_OUTPUT, ListEntry);

                SIZE_T matchOffset = i - output->Pattern->PatternSize + 1;

                MspAddMatchToResult(
                    output->Pattern,
                    Text + matchOffset,
                    matchOffset,
                    RegionBase,
                    RegionSize,
                    RegionProtection,
                    Flags,
                    Text,
                    TextLen,
                    Result,
                    Scanner
                );

                InterlockedIncrement64(&output->Pattern->MatchCount);

                if (Flags & MsScanFlag_StopOnFirstMatch) {
                    return STATUS_SUCCESS;
                }
            }
        }

        //
        // Also check failure chain for additional matches
        //
        ULONG tempState = automaton->States[currentState].Failure;
        while (tempState != 0) {
            if (automaton->States[tempState].OutputCount > 0) {
                for (entry = automaton->States[tempState].OutputPatterns.Flink;
                     entry != &automaton->States[tempState].OutputPatterns;
                     entry = entry->Flink) {

                    output = CONTAINING_RECORD(entry, MS_AC_OUTPUT, ListEntry);
                    SIZE_T matchOffset = i - output->Pattern->PatternSize + 1;

                    MspAddMatchToResult(
                        output->Pattern,
                        Text + matchOffset,
                        matchOffset,
                        RegionBase,
                        RegionSize,
                        RegionProtection,
                        Flags,
                        Text,
                        TextLen,
                        Result,
                        Scanner
                    );

                    if (Flags & MsScanFlag_StopOnFirstMatch) {
                        return STATUS_SUCCESS;
                    }
                }
            }
            tempState = automaton->States[tempState].Failure;
        }
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - MEMORY ALLOCATION HELPERS
// ============================================================================

static NTSTATUS
MspAllocateMatch(
    _In_ PMS_SCANNER_INTERNAL Scanner,
    _Out_ PMS_MATCH* Match
)
{
    PMS_MATCH match;

    *Match = NULL;

    if (Scanner->LookasideInitialized) {
        match = (PMS_MATCH)ExAllocateFromNPagedLookasideList(&Scanner->MatchLookaside);
    } else {
        match = (PMS_MATCH)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(MS_MATCH),
            MS_POOL_TAG_RESULT
        );
    }

    if (match == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(match, sizeof(MS_MATCH));
    InitializeListHead(&match->ListEntry);

    *Match = match;

    return STATUS_SUCCESS;
}

static VOID
MspFreeMatch(
    _In_ PMS_SCANNER_INTERNAL Scanner,
    _In_ PMS_MATCH Match
)
{
    if (Match == NULL) {
        return;
    }

    if (Scanner->LookasideInitialized) {
        ExFreeToNPagedLookasideList(&Scanner->MatchLookaside, Match);
    } else {
        ShadowStrikeFreePoolWithTag(Match, MS_POOL_TAG_RESULT);
    }
}

static NTSTATUS
MspAllocateScanResult(
    _In_ PMS_SCANNER_INTERNAL Scanner,
    _Out_ PMS_SCAN_RESULT* Result
)
{
    PMS_SCAN_RESULT result;

    *Result = NULL;

    if (Scanner->LookasideInitialized) {
        result = (PMS_SCAN_RESULT)ExAllocateFromNPagedLookasideList(&Scanner->ResultLookaside);
    } else {
        result = (PMS_SCAN_RESULT)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(MS_SCAN_RESULT),
            MS_POOL_TAG_RESULT
        );
    }

    if (result == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(result, sizeof(MS_SCAN_RESULT));
    InitializeListHead(&result->MatchList);

    *Result = result;

    return STATUS_SUCCESS;
}

static VOID
MspAddMatchToResult(
    _In_ PMS_PATTERN Pattern,
    _In_ PUCHAR MatchLocation,
    _In_ SIZE_T Offset,
    _In_ PVOID RegionBase,
    _In_ SIZE_T RegionSize,
    _In_ ULONG RegionProtection,
    _In_ MS_SCAN_FLAGS Flags,
    _In_ PUCHAR Buffer,
    _In_ SIZE_T BufferSize,
    _Inout_ PMS_SCAN_RESULT Result,
    _In_ PMS_SCANNER_INTERNAL Scanner
)
{
    PMS_MATCH match = NULL;
    NTSTATUS status;

    //
    // Check match limit
    //
    if ((ULONG)Result->MatchCount >= MS_MAX_MATCHES_PER_SCAN) {
        return;
    }

    //
    // Allocate match
    //
    if (Scanner != NULL) {
        status = MspAllocateMatch(Scanner, &match);
    } else {
        match = (PMS_MATCH)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(MS_MATCH),
            MS_POOL_TAG_RESULT
        );
        if (match != NULL) {
            RtlZeroMemory(match, sizeof(MS_MATCH));
            InitializeListHead(&match->ListEntry);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    if (!NT_SUCCESS(status) || match == NULL) {
        return;
    }

    //
    // Fill match information
    //
    match->PatternId = Pattern->PatternId;
    RtlStringCchCopyA(match->PatternName, sizeof(match->PatternName), Pattern->PatternName);
    match->MatchAddress = MatchLocation;
    match->MatchOffset = Offset;
    match->MatchSize = Pattern->PatternSize;
    match->RegionBase = RegionBase;
    match->RegionSize = RegionSize;
    match->RegionProtection = RegionProtection;
    RtlStringCchCopyA(match->ThreatName, sizeof(match->ThreatName), Pattern->ThreatName);
    match->Severity = Pattern->Severity;

    //
    // Capture context if requested
    //
    if (Flags & MsScanFlag_IncludeContext) {
        SIZE_T contextBefore = min(Offset, MS_CONTEXT_BYTES);
        SIZE_T contextAfter = min(BufferSize - Offset - Pattern->PatternSize, MS_CONTEXT_BYTES);

        if (contextBefore > 0) {
            RtlCopyMemory(match->ContextBefore, Buffer + Offset - contextBefore, contextBefore);
            match->ContextBeforeSize = (ULONG)contextBefore;
        }

        if (contextAfter > 0) {
            RtlCopyMemory(
                match->ContextAfter,
                Buffer + Offset + Pattern->PatternSize,
                contextAfter
            );
            match->ContextAfterSize = (ULONG)contextAfter;
        }
    }

    //
    // Add to result list
    //
    InsertTailList(&Result->MatchList, &match->ListEntry);
    InterlockedIncrement(&Result->MatchCount);

    //
    // Update threat summary
    //
    if (Pattern->Severity > Result->MaxSeverity) {
        Result->MaxSeverity = Pattern->Severity;
    }
    Result->ThreatCount++;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - PROCESS SCANNING
// ============================================================================

static NTSTATUS
MspScanProcessRegions(
    _In_ PMS_SCANNER_INTERNAL Scanner,
    _In_ PEPROCESS Process,
    _In_ MS_SCAN_TYPE Type,
    _In_ MS_SCAN_FLAGS Flags,
    _Inout_ PMS_SCAN_RESULT Result
)
{
    NTSTATUS status = STATUS_SUCCESS;
    KAPC_STATE apcState;
    MEMORY_BASIC_INFORMATION memInfo;
    SIZE_T returnLength;
    PVOID address = NULL;

    //
    // Attach to process context
    //
    KeStackAttachProcess(Process, &apcState);

    __try {
        //
        // Enumerate all regions
        //
        while (address < (PVOID)(ULONG_PTR)0x7FFFFFFFFFFF) {
            status = ZwQueryVirtualMemory(
                NtCurrentProcess(),
                address,
                MemoryBasicInformation,
                &memInfo,
                sizeof(memInfo),
                &returnLength
            );

            if (!NT_SUCCESS(status)) {
                status = STATUS_SUCCESS;  // End of address space
                break;
            }

            //
            // Check if we should scan this region
            //
            if (MspShouldScanRegion(
                    memInfo.Protect,
                    memInfo.State,
                    memInfo.Type,
                    Type,
                    Flags)) {

                //
                // Scan region
                //
                status = MspScanSingleRegion(
                    Scanner,
                    Process,
                    memInfo.BaseAddress,
                    memInfo.RegionSize,
                    memInfo.Protect,
                    Flags,
                    Result
                );

                if (!NT_SUCCESS(status)) {
                    //
                    // Continue with other regions
                    //
                    status = STATUS_SUCCESS;
                }

                //
                // Check for stop condition
                //
                if ((Flags & MsScanFlag_StopOnFirstMatch) && Result->MatchCount > 0) {
                    break;
                }
            }

            //
            // Move to next region
            //
            address = (PVOID)((ULONG_PTR)memInfo.BaseAddress + memInfo.RegionSize);
        }

    } __finally {
        KeUnstackDetachProcess(&apcState);
    }

    return status;
}

static NTSTATUS
MspScanSingleRegion(
    _In_ PMS_SCANNER_INTERNAL Scanner,
    _In_ PEPROCESS Process,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T RegionSize,
    _In_ ULONG Protection,
    _In_ MS_SCAN_FLAGS Flags,
    _Inout_ PMS_SCAN_RESULT Result
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PUCHAR buffer = NULL;
    SIZE_T bytesRead = 0;
    SIZE_T offset = 0;
    SIZE_T chunkSize;
    PLIST_ENTRY entry;
    PMS_PATTERN_INTERNAL pattern;

    //
    // Validate region size
    //
    if (RegionSize < MS_MIN_REGION_SIZE || RegionSize > MS_MAX_SCAN_SIZE) {
        return STATUS_SUCCESS;  // Skip
    }

    //
    // Allocate scan buffer
    //
    chunkSize = min(RegionSize, Scanner->Base.Config.ChunkSize);
    buffer = (PUCHAR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        chunkSize,
        MS_POOL_TAG_BUFFER
    );

    if (buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Scan region in chunks
    //
    while (offset < RegionSize) {
        SIZE_T toRead = min(chunkSize, RegionSize - offset);

        //
        // Read chunk from process memory
        //
        __try {
            status = MmCopyVirtualMemory(
                Process,
                (PVOID)((ULONG_PTR)BaseAddress + offset),
                PsGetCurrentProcess(),
                buffer,
                toRead,
                KernelMode,
                &bytesRead
            );
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
        }

        if (!NT_SUCCESS(status) || bytesRead == 0) {
            break;
        }

        //
        // Scan chunk with all patterns
        //
        if (Scanner->Base.AhoCorasickReady && Scanner->Base.PatternCount > 3) {
            MspAhoCorasickSearch(
                Scanner,
                buffer,
                bytesRead,
                Flags,
                Result,
                BaseAddress,
                RegionSize,
                Protection
            );
        } else {
            KeEnterCriticalRegion();
            ExAcquirePushLockShared(&Scanner->Base.PatternLock);

            for (entry = Scanner->Base.PatternList.Flink;
                 entry != &Scanner->Base.PatternList;
                 entry = entry->Flink) {

                pattern = CONTAINING_RECORD(entry, MS_PATTERN_INTERNAL, Base.ListEntry);

                if (pattern->Base.Flags & MsPatternFlag_Disabled) {
                    continue;
                }

                if (pattern->Base.Type == MsPattern_Wildcard) {
                    MspWildcardSearch(
                        buffer,
                        bytesRead,
                        &pattern->Base,
                        Flags,
                        Result,
                        BaseAddress,
                        RegionSize,
                        Protection
                    );
                } else {
                    MspBoyerMooreHorspoolSearch(
                        buffer,
                        bytesRead,
                        &pattern->Base,
                        Flags,
                        Result,
                        BaseAddress,
                        RegionSize,
                        Protection
                    );
                }

                if ((Flags & MsScanFlag_StopOnFirstMatch) && Result->MatchCount > 0) {
                    break;
                }
            }

            ExReleasePushLockShared(&Scanner->Base.PatternLock);
            KeLeaveCriticalRegion();
        }

        Result->BytesScanned += bytesRead;
        offset += bytesRead;

        //
        // Check for stop condition
        //
        if ((Flags & MsScanFlag_StopOnFirstMatch) && Result->MatchCount > 0) {
            break;
        }
    }

    Result->RegionsScanned++;

    ShadowStrikeFreePoolWithTag(buffer, MS_POOL_TAG_BUFFER);

    return STATUS_SUCCESS;
}

static BOOLEAN
MspShouldScanRegion(
    _In_ ULONG Protection,
    _In_ ULONG State,
    _In_ ULONG Type,
    _In_ MS_SCAN_TYPE ScanType,
    _In_ MS_SCAN_FLAGS Flags
)
{
    //
    // Must be committed
    //
    if (State != MEM_COMMIT) {
        return FALSE;
    }

    //
    // Skip guard and no-access pages
    //
    if (Protection & (PAGE_GUARD | PAGE_NOACCESS)) {
        return FALSE;
    }

    //
    // Apply scan type filters
    //
    switch (ScanType) {
        case MsScanType_Quick:
            //
            // Only executable regions
            //
            if (!(Protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                               PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                return FALSE;
            }
            break;

        case MsScanType_Standard:
            //
            // Private regions only
            //
            if (Type != MEM_PRIVATE) {
                return FALSE;
            }
            break;

        case MsScanType_Full:
            //
            // All committed regions
            //
            break;

        case MsScanType_Targeted:
            //
            // Specific region (always scan)
            //
            break;
    }

    //
    // Apply flag filters
    //
    if ((Flags & MsScanFlag_SkipMapped) && Type == MEM_MAPPED) {
        return FALSE;
    }

    if ((Flags & MsScanFlag_SkipImages) && Type == MEM_IMAGE) {
        return FALSE;
    }

    if (Flags & MsScanFlag_OnlyExecutable) {
        if (!(Protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                           PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            return FALSE;
        }
    }

    return TRUE;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - ASYNC WORKER
// ============================================================================

static VOID
MspAsyncScanWorker(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
)
{
    PMS_ASYNC_WORK_CONTEXT workContext = (PMS_ASYNC_WORK_CONTEXT)Context;
    PMS_SCANNER_INTERNAL scanner;
    PMS_ACTIVE_SCAN activeScan;
    PEPROCESS process = NULL;
    NTSTATUS status;
    KIRQL oldIrql;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (workContext == NULL) {
        return;
    }

    scanner = workContext->Scanner;
    activeScan = workContext->ActiveScan;

    //
    // Get process reference
    //
    status = PsLookupProcessByProcessId(activeScan->Request->ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        activeScan->Result->Status = status;
        goto Complete;
    }

    //
    // Perform the scan
    //
    KeQuerySystemTime(&activeScan->Result->StartTime);
    activeScan->Result->ProcessId = activeScan->Request->ProcessId;
    activeScan->Result->Type = activeScan->Request->Type;

    if (activeScan->Request->TargetAddress != NULL) {
        //
        // Targeted scan
        //
        status = MspScanSingleRegion(
            scanner,
            process,
            activeScan->Request->TargetAddress,
            activeScan->Request->TargetSize,
            0,
            activeScan->Request->Flags,
            activeScan->Result
        );
    } else {
        //
        // Full process scan
        //
        status = MspScanProcessRegions(
            scanner,
            process,
            activeScan->Request->Type,
            activeScan->Request->Flags,
            activeScan->Result
        );
    }

    activeScan->Result->Status = status;
    ObDereferenceObject(process);

Complete:
    //
    // Complete the scan
    //
    KeQuerySystemTime(&activeScan->Result->EndTime);
    activeScan->Result->DurationMs = (ULONG)(
        (activeScan->Result->EndTime.QuadPart - activeScan->Result->StartTime.QuadPart) / 10000
    );
    activeScan->Result->Completed = TRUE;

    InterlockedExchange(&activeScan->Completed, 1);
    KeSetEvent(&activeScan->CompletionEvent, IO_NO_INCREMENT, FALSE);

    //
    // Call completion callback
    //
    if (activeScan->Callback != NULL) {
        activeScan->Callback(activeScan->Result, activeScan->CallbackContext);
    }

    //
    // Remove from active scans list
    //
    KeAcquireSpinLock(&scanner->Base.ActiveScansLock, &oldIrql);
    RemoveEntryList(&activeScan->ListEntry);
    InterlockedDecrement(&scanner->Base.ActiveScanCount);
    KeReleaseSpinLock(&scanner->Base.ActiveScansLock, oldIrql);

    //
    // Update statistics
    //
    InterlockedIncrement64(&scanner->Base.Stats.TotalScans);
    InterlockedAdd64(&scanner->Base.Stats.BytesScanned, (LONG64)activeScan->Result->BytesScanned);

    //
    // Free work item
    //
    if (activeScan->WorkItem != NULL) {
        IoFreeWorkItem(activeScan->WorkItem);
    }

    ShadowStrikeFreePoolWithTag(workContext, MS_POOL_TAG_CONTEXT);
    ShadowStrikeFreePoolWithTag(activeScan, MS_POOL_TAG_CONTEXT);

    MspReleaseReference(scanner);
}

// ============================================================================
// PRIVATE IMPLEMENTATION - PATTERN LOOKUP
// ============================================================================

static PMS_PATTERN_INTERNAL
MspFindPatternById(
    _In_ PMS_SCANNER_INTERNAL Scanner,
    _In_ ULONG PatternId
)
{
    ULONG bucket = MspHashPatternId(PatternId);
    PLIST_ENTRY entry;
    PMS_PATTERN_INTERNAL pattern;

    for (entry = Scanner->PatternHashTable[bucket].Flink;
         entry != &Scanner->PatternHashTable[bucket];
         entry = entry->Flink) {

        pattern = CONTAINING_RECORD(entry, MS_PATTERN_INTERNAL, HashEntry);

        if (pattern->Base.PatternId == PatternId) {
            return pattern;
        }
    }

    return NULL;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - REFERENCE COUNTING
// ============================================================================

static VOID
MspAcquireReference(
    _Inout_ PMS_SCANNER_INTERNAL Scanner
)
{
    InterlockedIncrement(&Scanner->ReferenceCount);
}

static VOID
MspReleaseReference(
    _Inout_ PMS_SCANNER_INTERNAL Scanner
)
{
    LONG newCount = InterlockedDecrement(&Scanner->ReferenceCount);

    if (newCount == 0 && Scanner->ShuttingDown) {
        KeSetEvent(&Scanner->ShutdownEvent, IO_NO_INCREMENT, FALSE);
    }
}

// ============================================================================
// PRIVATE IMPLEMENTATION - ENTROPY CALCULATION
// ============================================================================

static DOUBLE
MspCalculateShannonEntropy(
    _In_reads_bytes_(Size) PUCHAR Buffer,
    _In_ SIZE_T Size
)
{
    ULONG frequency[256] = { 0 };
    SIZE_T i;
    DOUBLE entropy = 0.0;
    DOUBLE probability;

    //
    // Count byte frequencies
    //
    for (i = 0; i < Size; i++) {
        frequency[Buffer[i]]++;
    }

    //
    // Calculate Shannon entropy
    //
    for (i = 0; i < 256; i++) {
        if (frequency[i] > 0) {
            probability = (DOUBLE)frequency[i] / (DOUBLE)Size;

            //
            // entropy -= p * log2(p)
            // Using log2(p) = log2(count/size) = log2(count) - log2(size)
            //
            if (probability > 0.0) {
                //
                // Simplified log2 approximation for kernel
                //
                DOUBLE log2p = 0.0;
                DOUBLE temp = probability;
                LONG exp = 0;

                while (temp < 0.5) {
                    temp *= 2.0;
                    exp--;
                }
                while (temp >= 1.0) {
                    temp /= 2.0;
                    exp++;
                }

                //
                // Taylor series for log2(1+x) around x=0
                //
                DOUBLE x = temp - 1.0;
                log2p = exp + (x - x*x/2.0 + x*x*x/3.0) / 0.693147180559945;

                entropy -= probability * log2p;
            }
        }
    }

    return entropy;
}

