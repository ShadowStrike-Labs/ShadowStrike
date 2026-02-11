/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE DATA EXFILTRATION DETECTION
 * ============================================================================
 *
 * @file DataExfiltration.c
 * @brief Enterprise-grade DLP and data exfiltration detection for WFP integration.
 *
 * Architecture decisions:
 * - ALL public APIs run at IRQL PASSIVE_LEVEL. WFP callouts at DISPATCH_LEVEL
 *   must queue work items to call into this module.
 * - Synchronization uses EX_PUSH_LOCK exclusively (no spin locks). Every
 *   acquisition is bracketed by KeEnterCriticalRegion/KeLeaveCriticalRegion.
 * - Transfer contexts are reference-counted. The DPC cleanup timer only
 *   drops a reference; the actual free happens when refcount reaches zero.
 * - Transfer lookup uses a hash table (DX_TRANSFER_HASH_BUCKETS buckets)
 *   for O(1) amortized lookup under lock.
 * - Rundown protection (EX_RUNDOWN_REF) prevents shutdown while in-flight
 *   operations are active.
 * - Pattern match results are stored as value copies (category + sensitivity),
 *   not raw pointers, to avoid dangling references when patterns are removed.
 * - DX_DETECTOR is opaque; internal structure is DX_DETECTOR_INTERNAL.
 * - Alert objects are allocated from the general pool (not lookaside) so
 *   DxFreeAlert can free without needing the detector handle. Transfer and
 *   pattern objects use lookaside lists with proper free-to-lookaside calls.
 *
 * MITRE ATT&CK Coverage (implemented):
 * - T1041: Exfiltration Over C2 Channel (volume + entropy + pattern)
 * - T1567: Exfiltration Over Web Service (cloud storage detection)
 * - T1537: Transfer Data to Cloud Account (cloud storage detection)
 * - T1030: Data Transfer Size Limits (burst + volume threshold)
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "DataExfiltration.h"
#include "../Core/Globals.h"
#include "../Communication/ScanBridge.h"
#include "../Utilities/ProcessUtils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, DxInitialize)
#pragma alloc_text(PAGE, DxShutdown)
#pragma alloc_text(PAGE, DxAddPattern)
#pragma alloc_text(PAGE, DxRemovePattern)
#pragma alloc_text(PAGE, DxAnalyzeTraffic)
#pragma alloc_text(PAGE, DxRecordTransfer)
#pragma alloc_text(PAGE, DxInspectContent)
#pragma alloc_text(PAGE, DxCalculateEntropy)
#pragma alloc_text(PAGE, DxGetAlerts)
#pragma alloc_text(PAGE, DxGetStatistics)
#pragma alloc_text(PAGE, DxRegisterAlertCallback)
#pragma alloc_text(PAGE, DxRegisterBlockCallback)
#pragma alloc_text(PAGE, DxUnregisterCallbacks)
#pragma alloc_text(PAGE, DxFreeAlert)
#endif

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define DX_MAX_ALERTS                       1000
#define DX_MAX_TRANSFERS                    10000
#define DX_TRANSFER_TIMEOUT_MS              300000      // 5 minutes
#define DX_CLEANUP_INTERVAL_MS              60000       // 1 minute
#define DX_LOOKASIDE_DEPTH                  256
#define DX_BURST_THRESHOLD_BYTES            (10 * 1024 * 1024)
#define DX_BURST_WINDOW_MS                  10000
#define DX_TRANSFER_HASH_BUCKETS            128
#define DX_MAX_SUSPICION_SCORE              100
#define DX_POOL_TAG_HASH                    'HXXD'

//
// Fixed-point log2 lookup table (8.8 format, 256 entries).
// log2_table[i] = round(-log2(i/256) * 256) for i in 1..255.
// Entry 0 is unused (probability = 0 contributes 0 to entropy).
//
static const USHORT g_Log2Table[256] = {
       0, 2048, 1792, 1649, 1536, 1446, 1370, 1305,
    1248, 1197, 1152, 1110, 1073, 1038, 1006,  977,
     949,  923,  899,  876,  855,  835,  815,  797,
     780,  763,  747,  732,  718,  704,  690,  677,
     665,  653,  641,  630,  619,  609,  599,  589,
     580,  570,  561,  553,  544,  536,  528,  520,
     512,  505,  497,  490,  483,  476,  470,  463,
     457,  451,  444,  438,  433,  427,  421,  416,
     410,  405,  400,  394,  389,  384,  379,  374,
     370,  365,  360,  356,  351,  347,  342,  338,
     334,  329,  325,  321,  317,  313,  309,  305,
     301,  297,  294,  290,  286,  283,  279,  275,
     272,  268,  265,  261,  258,  255,  251,  248,
     245,  241,  238,  235,  232,  229,  225,  222,
     219,  216,  213,  210,  207,  204,  201,  199,
     196,  193,  190,  187,  185,  182,  179,  176,
     174,  171,  168,  166,  163,  161,  158,  155,
     153,  150,  148,  145,  143,  141,  138,  136,
     133,  131,  128,  126,  124,  121,  119,  117,
     114,  112,  110,  108,  105,  103,  101,   99,
      97,   94,   92,   90,   88,   86,   84,   82,
      79,   77,   75,   73,   71,   69,   67,   65,
      63,   61,   59,   57,   55,   53,   51,   49,
      47,   45,   43,   41,   39,   37,   36,   34,
      32,   30,   28,   26,   24,   23,   21,   19,
      17,   15,   14,   12,   10,    8,    7,    5,
       3,    1,    0,    0,    0,    0,    0,    0,
       0,    0,    0,    0,    0,    0,    0,    0,
       0,    0,    0,    0,    0,    0,    0,    0,
       0,    0,    0,    0,    0,    0,    0,    0,
       0,    0,    0,    0,    0,    0,    0,    0,
       0,    0,    0,    0,    0,    0,    0,    0,
};

//
// Well-known cloud storage domains
//
static const CHAR* g_CloudStorageDomains[] = {
    "dropbox.com",
    "drive.google.com",
    "onedrive.live.com",
    "icloud.com",
    "box.com",
    "mega.nz",
    "mediafire.com",
    "wetransfer.com",
    "sendspace.com",
    "4shared.com",
    "file.io",
    "transfer.sh",
    NULL
};

//
// Personal email domains
//
static const CHAR* g_PersonalEmailDomains[] = {
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "aol.com",
    "mail.com",
    "protonmail.com",
    "tutanota.com",
    "yandex.com",
    "gmx.com",
    "zoho.com",
    NULL
};

//
// Common archive signatures
//
typedef struct _ARCHIVE_SIGNATURE {
    UCHAR Signature[8];
    ULONG SignatureLength;
    BOOLEAN IsEncrypted;
    PCSTR Description;
} ARCHIVE_SIGNATURE;

static const ARCHIVE_SIGNATURE g_ArchiveSignatures[] = {
    { { 0x50, 0x4B, 0x03, 0x04 }, 4, FALSE, "ZIP" },
    { { 0x50, 0x4B, 0x05, 0x06 }, 4, FALSE, "ZIP (empty)" },
    { { 0x50, 0x4B, 0x07, 0x08 }, 4, FALSE, "ZIP (spanned)" },
    { { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07 }, 6, FALSE, "RAR" },
    { { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C }, 6, FALSE, "7Z" },
    { { 0x1F, 0x8B, 0x08 }, 3, FALSE, "GZIP" },
    { { 0x42, 0x5A, 0x68 }, 3, FALSE, "BZIP2" },
    { { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 }, 6, FALSE, "XZ" },
};

// ============================================================================
// PRIVATE STRUCTURES
// ============================================================================

//
// Hash table bucket for transfer contexts.
//
typedef struct _DX_HASH_BUCKET {
    LIST_ENTRY Head;
    EX_PUSH_LOCK Lock;
} DX_HASH_BUCKET, *PDX_HASH_BUCKET;

//
// Full internal detector state. Opaque to consumers.
//
struct _DX_DETECTOR {

    //
    // Initialization state
    //
    volatile LONG Initialized;

    //
    // Rundown protection — prevents shutdown while operations are in flight
    //
    EX_RUNDOWN_REF RundownRef;

    //
    // Pattern database
    //
    LIST_ENTRY PatternList;
    EX_PUSH_LOCK PatternLock;
    volatile LONG PatternCount;
    volatile LONG NextPatternId;

    //
    // Transfer hash table
    //
    PDX_HASH_BUCKET TransferBuckets;
    volatile LONG TransferCount;
    volatile LONG64 NextTransferId;

    //
    // Alerts — protected by push lock, not spin lock
    //
    LIST_ENTRY AlertList;
    EX_PUSH_LOCK AlertLock;
    volatile LONG AlertCount;
    volatile LONG64 NextAlertId;

    //
    // Statistics
    //
    struct {
        volatile LONG64 BytesInspected;
        volatile LONG64 TransfersAnalyzed;
        volatile LONG64 AlertsGenerated;
        volatile LONG64 TransfersBlocked;
        volatile LONG64 PatternMatches;
        LARGE_INTEGER StartTime;
    } Stats;

    //
    // Configuration
    //
    struct {
        SIZE_T VolumeThresholdPerMinute;
        ULONG EntropyThreshold;
        BOOLEAN EnableContentInspection;
        BOOLEAN EnableCloudDetection;
        BOOLEAN BlockOnDetection;
    } Config;

    //
    // Callbacks — protected by push lock
    //
    struct {
        DX_ALERT_CALLBACK AlertCallback;
        PVOID AlertContext;
        DX_BLOCK_CALLBACK BlockCallback;
        PVOID BlockContext;
        EX_PUSH_LOCK Lock;
    } Callbacks;

    //
    // Lookaside lists (pattern + transfer only; alerts use pool)
    //
    NPAGED_LOOKASIDE_LIST PatternLookaside;
    NPAGED_LOOKASIDE_LIST TransferLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Cleanup timer
    //
    KTIMER CleanupTimer;
    KDPC CleanupDpc;
    WORK_QUEUE_ITEM CleanupWorkItem;
    volatile LONG CleanupWorkQueued;
    volatile BOOLEAN ShuttingDown;

    //
    // Pre-computed Base64 lookup table
    //
    UCHAR Base64LookupTable[256];
};

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static ULONG
DxpCalculateShannonEntropy(
    _In_reads_bytes_(DataSize) PUCHAR Data,
    _In_ SIZE_T DataSize
    );

static BOOLEAN
DxpIsBase64Encoded(
    _In_reads_bytes_(DataSize) PUCHAR Data,
    _In_ SIZE_T DataSize
    );

static BOOLEAN
DxpIsCompressedData(
    _In_reads_bytes_(DataSize) PUCHAR Data,
    _In_ SIZE_T DataSize,
    _Out_opt_ PBOOLEAN IsEncrypted
    );

static BOOLEAN
DxpMatchPattern(
    _In_ PDX_PATTERN Pattern,
    _In_reads_bytes_(DataSize) PUCHAR Data,
    _In_ SIZE_T DataSize,
    _Out_opt_ PULONG MatchOffset
    );

static BOOLEAN
DxpIsCloudStorageDestination(
    _In_ PCSTR Hostname
    );

static BOOLEAN
DxpIsPersonalEmailDomain(
    _In_ PCSTR Hostname
    );

static ULONG
DxpHashTransferKey(
    _In_ HANDLE ProcessId,
    _In_reads_bytes_(AddrSize) PVOID RemoteAddress,
    _In_ ULONG AddrSize,
    _In_ USHORT RemotePort
    );

static PDX_TRANSFER_CONTEXT
DxpGetOrCreateTransfer(
    _In_ PDX_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_reads_bytes_(AddrSize) PVOID RemoteAddress,
    _In_ ULONG AddrSize,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6
    );

static VOID
DxpReferenceTransfer(
    _In_ PDX_TRANSFER_CONTEXT Transfer
    );

static VOID
DxpDereferenceTransfer(
    _In_ PDX_DETECTOR Detector,
    _In_ PDX_TRANSFER_CONTEXT Transfer
    );

static NTSTATUS
DxpCreateAlert(
    _In_ PDX_DETECTOR Detector,
    _In_ PDX_TRANSFER_CONTEXT Transfer,
    _In_ DX_EXFIL_TYPE Type,
    _In_ BOOLEAN WasBlocked
    );

static VOID
DxpNotifyAlertCallback(
    _In_ PDX_DETECTOR Detector,
    _In_ PDX_ALERT Alert
    );

static BOOLEAN
DxpShouldBlock(
    _In_ PDX_DETECTOR Detector,
    _In_ PDX_TRANSFER_CONTEXT Transfer
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
DxpCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

static VOID
DxpCleanupWorkRoutine(
    _In_ PVOID Parameter
    );

static VOID
DxpInitializeLookupTables(
    _In_ PDX_DETECTOR Detector
    );

static DX_EXFIL_TYPE
DxpClassifyExfiltration(
    _In_ PDX_TRANSFER_CONTEXT Transfer
    );

static BOOLEAN
DxpCaseInsensitiveCompareA(
    _In_ PCSTR String1,
    _In_ PCSTR String2
    );

static NTSTATUS
DxpValidateRemoteAddress(
    _In_ BOOLEAN IsIPv6,
    _In_ ULONG RemoteAddressSize
    );

// ============================================================================
// INLINE HELPERS — Push Lock with Critical Region
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
static __forceinline VOID
DxpAcquirePushLockShared(
    _Inout_ PEX_PUSH_LOCK Lock
    )
{
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(Lock);
}

_IRQL_requires_max_(APC_LEVEL)
static __forceinline VOID
DxpReleasePushLockShared(
    _Inout_ PEX_PUSH_LOCK Lock
    )
{
    ExReleasePushLockShared(Lock);
    KeLeaveCriticalRegion();
}

_IRQL_requires_max_(APC_LEVEL)
static __forceinline VOID
DxpAcquirePushLockExclusive(
    _Inout_ PEX_PUSH_LOCK Lock
    )
{
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(Lock);
}

_IRQL_requires_max_(APC_LEVEL)
static __forceinline VOID
DxpReleasePushLockExclusive(
    _Inout_ PEX_PUSH_LOCK Lock
    )
{
    ExReleasePushLockExclusive(Lock);
    KeLeaveCriticalRegion();
}

// ============================================================================
// INITIALIZATION AND SHUTDOWN
// ============================================================================

_Use_decl_annotations_
NTSTATUS
DxInitialize(
    _Out_ PDX_DETECTOR* Detector
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PDX_DETECTOR detector = NULL;
    LARGE_INTEGER dueTime;
    ULONG i;

    PAGED_CODE();

    if (Detector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Detector = NULL;

    //
    // Allocate detector structure
    //
    detector = (PDX_DETECTOR)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(DX_DETECTOR),
        DX_POOL_TAG_CONTEXT
    );

    if (detector == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize rundown protection
    //
    ExInitializeRundownProtection(&detector->RundownRef);

    //
    // Initialize pattern list
    //
    InitializeListHead(&detector->PatternList);
    ExInitializePushLock(&detector->PatternLock);

    //
    // Initialize transfer hash table
    //
    detector->TransferBuckets = (PDX_HASH_BUCKET)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(DX_HASH_BUCKET) * DX_TRANSFER_HASH_BUCKETS,
        DX_POOL_TAG_HASH
    );

    if (detector->TransferBuckets == NULL) {
        ExFreePoolWithTag(detector, DX_POOL_TAG_CONTEXT);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (i = 0; i < DX_TRANSFER_HASH_BUCKETS; i++) {
        InitializeListHead(&detector->TransferBuckets[i].Head);
        ExInitializePushLock(&detector->TransferBuckets[i].Lock);
    }

    //
    // Initialize alert list
    //
    InitializeListHead(&detector->AlertList);
    ExInitializePushLock(&detector->AlertLock);

    //
    // Initialize callbacks
    //
    ExInitializePushLock(&detector->Callbacks.Lock);

    //
    // Initialize lookaside lists (pattern + transfer only)
    //
    ExInitializeNPagedLookasideList(
        &detector->PatternLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(DX_PATTERN),
        DX_POOL_TAG_PATTERN,
        DX_LOOKASIDE_DEPTH
    );

    ExInitializeNPagedLookasideList(
        &detector->TransferLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(DX_TRANSFER_CONTEXT),
        DX_POOL_TAG_CONTEXT,
        DX_LOOKASIDE_DEPTH
    );

    detector->LookasideInitialized = TRUE;

    //
    // Initialize lookup tables for fast Base64 detection
    //
    DxpInitializeLookupTables(detector);

    //
    // Set default configuration
    //
    detector->Config.VolumeThresholdPerMinute = (SIZE_T)DX_VOLUME_THRESHOLD_MB * 1024 * 1024;
    detector->Config.EntropyThreshold = DX_ENTROPY_THRESHOLD;
    detector->Config.EnableContentInspection = TRUE;
    detector->Config.EnableCloudDetection = TRUE;
    detector->Config.BlockOnDetection = FALSE;

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&detector->Stats.StartTime);

    //
    // Initialize cleanup timer — DPC queues a work item at PASSIVE_LEVEL
    //
    KeInitializeTimer(&detector->CleanupTimer);
    KeInitializeDpc(&detector->CleanupDpc, DxpCleanupTimerDpc, detector);

    dueTime.QuadPart = -((LONGLONG)DX_CLEANUP_INTERVAL_MS * 10000);
    KeSetTimerEx(
        &detector->CleanupTimer,
        dueTime,
        DX_CLEANUP_INTERVAL_MS,
        &detector->CleanupDpc
    );

    InterlockedExchange(&detector->Initialized, TRUE);
    *Detector = detector;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
DxShutdown(
    _Inout_ PDX_DETECTOR Detector
    )
{
    PLIST_ENTRY entry;
    PDX_PATTERN pattern;
    PDX_TRANSFER_CONTEXT transfer;
    PDX_ALERT alert;
    ULONG i;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized) {
        return;
    }

    //
    // Mark as shutting down and prevent new operations
    //
    InterlockedExchange((volatile LONG*)&Detector->ShuttingDown, TRUE);
    InterlockedExchange(&Detector->Initialized, FALSE);

    //
    // Wait for all in-flight operations to complete
    //
    ExWaitForRundownProtectionRelease(&Detector->RundownRef);

    //
    // Cancel cleanup timer and wait for any pending DPCs/work items
    //
    KeCancelTimer(&Detector->CleanupTimer);
    KeFlushQueuedDpcs();

    //
    // Free all patterns
    //
    DxpAcquirePushLockExclusive(&Detector->PatternLock);

    while (!IsListEmpty(&Detector->PatternList)) {
        entry = RemoveHeadList(&Detector->PatternList);
        pattern = CONTAINING_RECORD(entry, DX_PATTERN, ListEntry);

        if (pattern->Pattern != NULL) {
            ExFreePoolWithTag(pattern->Pattern, DX_POOL_TAG_PATTERN);
        }

        ExFreeToNPagedLookasideList(&Detector->PatternLookaside, pattern);
    }

    DxpReleasePushLockExclusive(&Detector->PatternLock);

    //
    // Free all transfers from hash table
    //
    for (i = 0; i < DX_TRANSFER_HASH_BUCKETS; i++) {
        DxpAcquirePushLockExclusive(&Detector->TransferBuckets[i].Lock);

        while (!IsListEmpty(&Detector->TransferBuckets[i].Head)) {
            entry = RemoveHeadList(&Detector->TransferBuckets[i].Head);
            transfer = CONTAINING_RECORD(entry, DX_TRANSFER_CONTEXT, HashEntry);
            InterlockedDecrement(&Detector->TransferCount);
            ExFreeToNPagedLookasideList(&Detector->TransferLookaside, transfer);
        }

        DxpReleasePushLockExclusive(&Detector->TransferBuckets[i].Lock);
    }

    //
    // Free all alerts
    //
    DxpAcquirePushLockExclusive(&Detector->AlertLock);

    while (!IsListEmpty(&Detector->AlertList)) {
        entry = RemoveHeadList(&Detector->AlertList);
        alert = CONTAINING_RECORD(entry, DX_ALERT, ListEntry);
        InterlockedDecrement(&Detector->AlertCount);
        ExFreePoolWithTag(alert, DX_POOL_TAG_ALERT);
    }

    DxpReleasePushLockExclusive(&Detector->AlertLock);

    //
    // Delete lookaside lists
    //
    if (Detector->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&Detector->PatternLookaside);
        ExDeleteNPagedLookasideList(&Detector->TransferLookaside);
        Detector->LookasideInitialized = FALSE;
    }

    //
    // Free hash table
    //
    if (Detector->TransferBuckets != NULL) {
        ExFreePoolWithTag(Detector->TransferBuckets, DX_POOL_TAG_HASH);
        Detector->TransferBuckets = NULL;
    }

    //
    // Free detector structure
    //
    ExFreePoolWithTag(Detector, DX_POOL_TAG_CONTEXT);
}

// ============================================================================
// PATTERN MANAGEMENT
// ============================================================================

_Use_decl_annotations_
NTSTATUS
DxAddPattern(
    _In_ PDX_DETECTOR Detector,
    _In_ PCSTR PatternName,
    _In_reads_bytes_(PatternSize) PUCHAR Pattern,
    _In_ ULONG PatternSize,
    _In_ ULONG Sensitivity,
    _In_opt_ PCSTR Category,
    _Out_ PULONG PatternId
    )
{
    PDX_PATTERN newPattern = NULL;
    SIZE_T nameLen;
    SIZE_T categoryLen;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized ||
        PatternName == NULL || Pattern == NULL || PatternSize == 0 ||
        PatternId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Sensitivity < 1 || Sensitivity > 4) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Acquire rundown protection
    //
    if (!ExAcquireRundownProtection(&Detector->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    //
    // Check pattern limit
    //
    if ((ULONG)Detector->PatternCount >= DX_MAX_PATTERNS) {
        ExReleaseRundownProtection(&Detector->RundownRef);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Allocate pattern from lookaside
    //
    newPattern = (PDX_PATTERN)ExAllocateFromNPagedLookasideList(
        &Detector->PatternLookaside
    );

    if (newPattern == NULL) {
        ExReleaseRundownProtection(&Detector->RundownRef);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(newPattern, sizeof(DX_PATTERN));

    //
    // Assign pattern ID
    //
    newPattern->PatternId = (ULONG)InterlockedIncrement(&Detector->NextPatternId);

    //
    // Copy pattern name (safe truncation)
    //
    nameLen = strlen(PatternName);
    if (nameLen >= sizeof(newPattern->PatternName)) {
        nameLen = sizeof(newPattern->PatternName) - 1;
    }
    RtlCopyMemory(newPattern->PatternName, PatternName, nameLen);
    newPattern->PatternName[nameLen] = '\0';

    //
    // Allocate and copy pattern data
    //
    newPattern->Pattern = (PUCHAR)ExAllocatePoolZero(
        NonPagedPoolNx,
        PatternSize,
        DX_POOL_TAG_PATTERN
    );

    if (newPattern->Pattern == NULL) {
        ExFreeToNPagedLookasideList(&Detector->PatternLookaside, newPattern);
        ExReleaseRundownProtection(&Detector->RundownRef);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(newPattern->Pattern, Pattern, PatternSize);
    newPattern->PatternSize = PatternSize;
    newPattern->Sensitivity = Sensitivity;
    newPattern->Type = PatternType_Keyword;
    newPattern->RefCount = 1;

    //
    // Copy category
    //
    if (Category != NULL) {
        categoryLen = strlen(Category);
        if (categoryLen >= sizeof(newPattern->Category)) {
            categoryLen = sizeof(newPattern->Category) - 1;
        }
        RtlCopyMemory(newPattern->Category, Category, categoryLen);
        newPattern->Category[categoryLen] = '\0';
    } else {
        RtlCopyMemory(newPattern->Category, "General", 8);
    }

    //
    // Insert into pattern list
    //
    DxpAcquirePushLockExclusive(&Detector->PatternLock);
    InsertTailList(&Detector->PatternList, &newPattern->ListEntry);
    InterlockedIncrement(&Detector->PatternCount);
    DxpReleasePushLockExclusive(&Detector->PatternLock);

    *PatternId = newPattern->PatternId;

    ExReleaseRundownProtection(&Detector->RundownRef);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
DxRemovePattern(
    _In_ PDX_DETECTOR Detector,
    _In_ ULONG PatternId
    )
{
    PLIST_ENTRY entry;
    PDX_PATTERN pattern;
    PDX_PATTERN foundPattern = NULL;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Detector->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    DxpAcquirePushLockExclusive(&Detector->PatternLock);

    for (entry = Detector->PatternList.Flink;
         entry != &Detector->PatternList;
         entry = entry->Flink) {

        pattern = CONTAINING_RECORD(entry, DX_PATTERN, ListEntry);

        if (pattern->PatternId == PatternId) {
            foundPattern = pattern;
            RemoveEntryList(&pattern->ListEntry);
            InterlockedDecrement(&Detector->PatternCount);
            break;
        }
    }

    DxpReleasePushLockExclusive(&Detector->PatternLock);

    if (foundPattern == NULL) {
        ExReleaseRundownProtection(&Detector->RundownRef);
        return STATUS_NOT_FOUND;
    }

    //
    // Free pattern data and pattern object
    //
    if (foundPattern->Pattern != NULL) {
        ExFreePoolWithTag(foundPattern->Pattern, DX_POOL_TAG_PATTERN);
    }

    ExFreeToNPagedLookasideList(&Detector->PatternLookaside, foundPattern);

    ExReleaseRundownProtection(&Detector->RundownRef);
    return STATUS_SUCCESS;
}

// ============================================================================
// TRAFFIC ANALYSIS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
DxAnalyzeTraffic(
    _In_ PDX_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_reads_bytes_(RemoteAddressSize) PVOID RemoteAddress,
    _In_ ULONG RemoteAddressSize,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ SIZE_T DataSize,
    _Out_ PBOOLEAN IsSuspicious,
    _Out_opt_ PBOOLEAN WasBlocked,
    _Out_opt_ PULONG SuspicionScore
    )
{
    PDX_TRANSFER_CONTEXT transfer = NULL;
    DX_INDICATORS indicators = DxIndicator_None;
    NTSTATUS status;
    ULONG entropy = 0;
    ULONG score = 0;
    BOOLEAN isEncrypted = FALSE;
    BOOLEAN blocked = FALSE;
    PLIST_ENTRY entry;
    PDX_PATTERN pattern;
    SIZE_T inspectSize;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized ||
        RemoteAddress == NULL || Data == NULL || DataSize == 0 ||
        IsSuspicious == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate remote address size matches IP version
    //
    status = DxpValidateRemoteAddress(IsIPv6, RemoteAddressSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *IsSuspicious = FALSE;
    if (WasBlocked != NULL) {
        *WasBlocked = FALSE;
    }
    if (SuspicionScore != NULL) {
        *SuspicionScore = 0;
    }

    //
    // Acquire rundown protection
    //
    if (!ExAcquireRundownProtection(&Detector->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    //
    // Cap the inspection size to prevent DoS via large buffers
    //
    inspectSize = DataSize;
    if (inspectSize > DX_MAX_INSPECT_SIZE) {
        inspectSize = DX_MAX_INSPECT_SIZE;
    }

    //
    // Update statistics
    //
    InterlockedAdd64(&Detector->Stats.BytesInspected, (LONG64)DataSize);
    InterlockedIncrement64(&Detector->Stats.TransfersAnalyzed);

    //
    // Get or create transfer context (returns with ref held)
    //
    transfer = DxpGetOrCreateTransfer(
        Detector, ProcessId, RemoteAddress, RemoteAddressSize, RemotePort, IsIPv6
    );
    if (transfer == NULL) {
        ExReleaseRundownProtection(&Detector->RundownRef);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Update transfer statistics (atomic increment for SIZE_T)
    //
    InterlockedAdd64(&transfer->BytesTransferred, (LONG64)DataSize);
    KeQuerySystemTime(&transfer->LastActivityTime);

    //
    // Calculate entropy
    //
    entropy = DxpCalculateShannonEntropy((PUCHAR)Data, inspectSize);
    transfer->Entropy = entropy;

    if (entropy >= Detector->Config.EntropyThreshold) {
        indicators |= DxIndicator_HighEntropy;
        score += 30;
    }

    //
    // Check for compressed/encrypted data
    //
    if (DxpIsCompressedData((PUCHAR)Data, inspectSize, &isEncrypted)) {
        transfer->IsCompressed = TRUE;
        indicators |= DxIndicator_CompressedData;
        score += 10;

        if (isEncrypted) {
            transfer->IsEncrypted = TRUE;
            indicators |= DxIndicator_EncryptedData;
            score += 20;
        }
    }

    //
    // Check for Base64 encoding
    //
    if (DxpIsBase64Encoded((PUCHAR)Data, inspectSize)) {
        transfer->IsEncoded = TRUE;
        indicators |= DxIndicator_EncodedData;
        score += 15;
    }

    //
    // Check for cloud storage destination
    //
    if (Detector->Config.EnableCloudDetection && transfer->Hostname[0] != '\0') {
        if (DxpIsCloudStorageDestination(transfer->Hostname)) {
            indicators |= DxIndicator_CloudUpload;
            score += 25;
        }

        if (DxpIsPersonalEmailDomain(transfer->Hostname)) {
            indicators |= DxIndicator_PersonalEmail;
            score += 20;
        }
    }

    //
    // Check transfer volume
    //
    if ((SIZE_T)transfer->BytesTransferred > Detector->Config.VolumeThresholdPerMinute) {
        indicators |= DxIndicator_HighVolume;
        score += 30;
    }

    //
    // Pattern matching (if content inspection enabled)
    // Match results are stored as value copies (category + sensitivity),
    // not as raw pointers to pattern objects.
    //
    if (Detector->Config.EnableContentInspection) {
        ULONG matchOffset;

        DxpAcquirePushLockShared(&Detector->PatternLock);

        for (entry = Detector->PatternList.Flink;
             entry != &Detector->PatternList;
             entry = entry->Flink) {

            pattern = CONTAINING_RECORD(entry, DX_PATTERN, ListEntry);

            if (DxpMatchPattern(pattern, (PUCHAR)Data, inspectSize, &matchOffset)) {
                InterlockedIncrement(&pattern->MatchCount);
                InterlockedIncrement64(&Detector->Stats.PatternMatches);

                indicators |= DxIndicator_SensitivePattern;

                //
                // Snapshot match info as values (not pointers)
                //
                if (transfer->MatchCount < ARRAYSIZE(transfer->Matches)) {
                    ULONG idx = transfer->MatchCount;
                    RtlCopyMemory(
                        transfer->Matches[idx].Category,
                        pattern->Category,
                        sizeof(transfer->Matches[idx].Category) - 1
                    );
                    transfer->Matches[idx].Category[sizeof(transfer->Matches[idx].Category) - 1] = '\0';
                    transfer->Matches[idx].Sensitivity = pattern->Sensitivity;
                    transfer->Matches[idx].MatchCount = 1;
                    transfer->MatchCount++;
                }

                //
                // Score based on sensitivity
                //
                switch (pattern->Sensitivity) {
                    case 4: score += 50; break;
                    case 3: score += 35; break;
                    case 2: score += 20; break;
                    case 1: score += 10; break;
                }
            }
        }

        DxpReleasePushLockShared(&Detector->PatternLock);
    }

    //
    // Cap score
    //
    if (score > DX_MAX_SUSPICION_SCORE) {
        score = DX_MAX_SUSPICION_SCORE;
    }

    //
    // Store indicators and score
    //
    transfer->Indicators = indicators;
    transfer->SuspicionScore = score;

    //
    // Determine if suspicious
    //
    if (score >= 50) {
        *IsSuspicious = TRUE;

        if (score >= 70) {
            //
            // Check if we should block
            //
            if (Detector->Config.BlockOnDetection && DxpShouldBlock(Detector, transfer)) {
                blocked = TRUE;
                InterlockedIncrement64(&Detector->Stats.TransfersBlocked);
            }

            DX_EXFIL_TYPE exfilType = DxpClassifyExfiltration(transfer);
            DxpCreateAlert(Detector, transfer, exfilType, blocked);
        }
    }

    if (WasBlocked != NULL) {
        *WasBlocked = blocked;
    }
    if (SuspicionScore != NULL) {
        *SuspicionScore = score;
    }

    //
    // Release transfer reference and rundown protection
    //
    DxpDereferenceTransfer(Detector, transfer);
    ExReleaseRundownProtection(&Detector->RundownRef);

    return blocked ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
DxRecordTransfer(
    _In_ PDX_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_reads_bytes_(RemoteAddressSize) PVOID RemoteAddress,
    _In_ ULONG RemoteAddressSize,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6,
    _In_ SIZE_T BytesSent
    )
{
    PDX_TRANSFER_CONTEXT transfer;
    LARGE_INTEGER currentTime;
    NTSTATUS status;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized || RemoteAddress == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = DxpValidateRemoteAddress(IsIPv6, RemoteAddressSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (!ExAcquireRundownProtection(&Detector->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    transfer = DxpGetOrCreateTransfer(
        Detector, ProcessId, RemoteAddress, RemoteAddressSize, RemotePort, IsIPv6
    );
    if (transfer == NULL) {
        ExReleaseRundownProtection(&Detector->RundownRef);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Update transfer statistics (atomic)
    //
    InterlockedAdd64(&transfer->BytesTransferred, (LONG64)BytesSent);
    KeQuerySystemTime(&currentTime);
    transfer->LastActivityTime = currentTime;

    //
    // Calculate bytes per second
    //
    if (transfer->StartTime.QuadPart > 0) {
        LONGLONG elapsedMs = (currentTime.QuadPart - transfer->StartTime.QuadPart) / 10000;
        if (elapsedMs > 0) {
            transfer->BytesPerSecond =
                (SIZE_T)(((LONG64)transfer->BytesTransferred * 1000) / elapsedMs);
        }
    }

    //
    // Check for burst transfer
    //
    if ((SIZE_T)transfer->BytesTransferred > DX_BURST_THRESHOLD_BYTES) {
        LONGLONG burstWindow = (currentTime.QuadPart - transfer->StartTime.QuadPart) / 10000;
        if (burstWindow > 0 && burstWindow < DX_BURST_WINDOW_MS) {
            transfer->Indicators |= DxIndicator_BurstTransfer;
            if (transfer->SuspicionScore < 75) {
                transfer->SuspicionScore = 75;
            }
        }
    }

    //
    // Check volume threshold
    //
    if ((SIZE_T)transfer->BytesTransferred > Detector->Config.VolumeThresholdPerMinute) {
        transfer->Indicators |= DxIndicator_HighVolume;

        if (transfer->SuspicionScore < 50) {
            transfer->SuspicionScore = 50;
        }

        DxpCreateAlert(Detector, transfer, DxExfil_LargeUpload, FALSE);
    }

    DxpDereferenceTransfer(Detector, transfer);
    ExReleaseRundownProtection(&Detector->RundownRef);

    return STATUS_SUCCESS;
}

// ============================================================================
// CONTENT INSPECTION
// ============================================================================

_Use_decl_annotations_
NTSTATUS
DxInspectContent(
    _In_ PDX_DETECTOR Detector,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ SIZE_T DataSize,
    _Out_ PDX_INDICATORS Indicators,
    _Out_writes_to_(MaxMatches, *MatchCount) PDX_PATTERN* Matches,
    _In_ ULONG MaxMatches,
    _Out_ PULONG MatchCount
    )
{
    DX_INDICATORS indicators = DxIndicator_None;
    ULONG entropy;
    BOOLEAN isEncrypted;
    PLIST_ENTRY entry;
    PDX_PATTERN pattern;
    ULONG matchCount = 0;
    ULONG matchOffset;
    SIZE_T inspectSize;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized ||
        Data == NULL || DataSize == 0 ||
        Indicators == NULL || MatchCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Indicators = DxIndicator_None;
    *MatchCount = 0;

    if (!ExAcquireRundownProtection(&Detector->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    //
    // Cap inspection size
    //
    inspectSize = DataSize;
    if (inspectSize > DX_MAX_INSPECT_SIZE) {
        inspectSize = DX_MAX_INSPECT_SIZE;
    }

    //
    // Calculate entropy
    //
    entropy = DxpCalculateShannonEntropy((PUCHAR)Data, inspectSize);
    if (entropy >= Detector->Config.EntropyThreshold) {
        indicators |= DxIndicator_HighEntropy;
    }

    //
    // Check compression/encryption
    //
    if (DxpIsCompressedData((PUCHAR)Data, inspectSize, &isEncrypted)) {
        indicators |= DxIndicator_CompressedData;
        if (isEncrypted) {
            indicators |= DxIndicator_EncryptedData;
        }
    }

    //
    // Check Base64
    //
    if (DxpIsBase64Encoded((PUCHAR)Data, inspectSize)) {
        indicators |= DxIndicator_EncodedData;
    }

    //
    // Pattern matching
    //
    DxpAcquirePushLockShared(&Detector->PatternLock);

    for (entry = Detector->PatternList.Flink;
         entry != &Detector->PatternList;
         entry = entry->Flink) {

        pattern = CONTAINING_RECORD(entry, DX_PATTERN, ListEntry);

        if (DxpMatchPattern(pattern, (PUCHAR)Data, inspectSize, &matchOffset)) {
            indicators |= DxIndicator_SensitivePattern;

            if (Matches != NULL && matchCount < MaxMatches) {
                Matches[matchCount] = pattern;
                matchCount++;
            }

            InterlockedIncrement(&pattern->MatchCount);
            InterlockedIncrement64(&Detector->Stats.PatternMatches);
        }
    }

    DxpReleasePushLockShared(&Detector->PatternLock);

    *Indicators = indicators;
    *MatchCount = matchCount;

    ExReleaseRundownProtection(&Detector->RundownRef);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
DxCalculateEntropy(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ SIZE_T DataSize,
    _Out_ PULONG Entropy
    )
{
    PAGED_CODE();

    if (Data == NULL || DataSize == 0 || Entropy == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Entropy = DxpCalculateShannonEntropy((PUCHAR)Data, DataSize);

    return STATUS_SUCCESS;
}

// ============================================================================
// ALERTS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
DxGetAlerts(
    _In_ PDX_DETECTOR Detector,
    _Out_writes_to_(MaxAlerts, *AlertCount) PDX_ALERT* Alerts,
    _In_ ULONG MaxAlerts,
    _Out_ PULONG AlertCount
    )
{
    PLIST_ENTRY entry;
    PDX_ALERT alert;
    ULONG count = 0;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized ||
        Alerts == NULL || AlertCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *AlertCount = 0;

    if (!ExAcquireRundownProtection(&Detector->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    DxpAcquirePushLockExclusive(&Detector->AlertLock);

    while (!IsListEmpty(&Detector->AlertList) && count < MaxAlerts) {
        entry = RemoveHeadList(&Detector->AlertList);
        alert = CONTAINING_RECORD(entry, DX_ALERT, ListEntry);
        InterlockedDecrement(&Detector->AlertCount);

        Alerts[count++] = alert;
    }

    DxpReleasePushLockExclusive(&Detector->AlertLock);

    *AlertCount = count;

    ExReleaseRundownProtection(&Detector->RundownRef);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
DxFreeAlert(
    _In_ PDX_DETECTOR Detector,
    _In_ PDX_ALERT Alert
    )
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(Detector);

    if (Alert == NULL) {
        return;
    }

    //
    // Alerts are allocated from the general pool with DX_POOL_TAG_ALERT.
    // No UNICODE_STRING buffers — process name is inline WCHAR array.
    //
    ExFreePoolWithTag(Alert, DX_POOL_TAG_ALERT);
}

// ============================================================================
// CALLBACKS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
DxRegisterAlertCallback(
    _In_ PDX_DETECTOR Detector,
    _In_ DX_ALERT_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
{
    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Detector->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    DxpAcquirePushLockExclusive(&Detector->Callbacks.Lock);
    Detector->Callbacks.AlertCallback = Callback;
    Detector->Callbacks.AlertContext = Context;
    DxpReleasePushLockExclusive(&Detector->Callbacks.Lock);

    ExReleaseRundownProtection(&Detector->RundownRef);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
DxRegisterBlockCallback(
    _In_ PDX_DETECTOR Detector,
    _In_ DX_BLOCK_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
{
    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Detector->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    DxpAcquirePushLockExclusive(&Detector->Callbacks.Lock);
    Detector->Callbacks.BlockCallback = Callback;
    Detector->Callbacks.BlockContext = Context;
    DxpReleasePushLockExclusive(&Detector->Callbacks.Lock);

    ExReleaseRundownProtection(&Detector->RundownRef);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
DxUnregisterCallbacks(
    _In_ PDX_DETECTOR Detector
    )
{
    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized) {
        return;
    }

    if (!ExAcquireRundownProtection(&Detector->RundownRef)) {
        return;
    }

    DxpAcquirePushLockExclusive(&Detector->Callbacks.Lock);
    Detector->Callbacks.AlertCallback = NULL;
    Detector->Callbacks.AlertContext = NULL;
    Detector->Callbacks.BlockCallback = NULL;
    Detector->Callbacks.BlockContext = NULL;
    DxpReleasePushLockExclusive(&Detector->Callbacks.Lock);

    ExReleaseRundownProtection(&Detector->RundownRef);
}

// ============================================================================
// STATISTICS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
DxGetStatistics(
    _In_ PDX_DETECTOR Detector,
    _Out_ PDX_STATISTICS Stats
    )
{
    LARGE_INTEGER currentTime;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Stats, sizeof(DX_STATISTICS));

    Stats->BytesInspected = Detector->Stats.BytesInspected;
    Stats->TransfersAnalyzed = Detector->Stats.TransfersAnalyzed;
    Stats->AlertsGenerated = Detector->Stats.AlertsGenerated;
    Stats->TransfersBlocked = Detector->Stats.TransfersBlocked;
    Stats->PatternMatches = Detector->Stats.PatternMatches;
    Stats->ActivePatterns = (ULONG)Detector->PatternCount;

    KeQuerySystemTime(&currentTime);
    Stats->UpTime.QuadPart = currentTime.QuadPart - Detector->Stats.StartTime.QuadPart;

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS
// ============================================================================

static VOID
DxpInitializeLookupTables(
    _In_ PDX_DETECTOR Detector
    )
{
    static const UCHAR base64Alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    ULONG i;

    RtlZeroMemory(Detector->Base64LookupTable, sizeof(Detector->Base64LookupTable));

    for (i = 0; base64Alphabet[i] != '\0'; i++) {
        Detector->Base64LookupTable[base64Alphabet[i]] = 1;
    }

    //
    // Allow whitespace in Base64 streams
    //
    Detector->Base64LookupTable[' '] = 1;
    Detector->Base64LookupTable['\r'] = 1;
    Detector->Base64LookupTable['\n'] = 1;
    Detector->Base64LookupTable['\t'] = 1;
}

/**
 * @brief Calculate Shannon entropy using fixed-point integer arithmetic.
 *
 * Formula: H = -sum(p_i * log2(p_i)) for each byte value i
 * Returns entropy as percentage (0-100) of maximum 8 bits/byte.
 *
 * Uses a precomputed log2 lookup table in 8.8 fixed-point format.
 * For each byte value with frequency f, p = f/N, and we compute
 * -(f/N) * log2(f/N) = (f/N) * (log2(N) - log2(f)).
 * Rearranged for integer math: contribution = f * (log2(N) - log2(f)) / N.
 */
static ULONG
DxpCalculateShannonEntropy(
    _In_reads_bytes_(DataSize) PUCHAR Data,
    _In_ SIZE_T DataSize
    )
{
    ULONG frequency[256] = { 0 };
    SIZE_T i;
    ULONG64 entropyFixed = 0;
    ULONG entropy;

    if (DataSize < 64) {
        return 0;
    }

    //
    // Count byte frequencies
    //
    for (i = 0; i < DataSize; i++) {
        frequency[Data[i]]++;
    }

    //
    // Calculate entropy using fixed-point log2 approximation.
    // We scale probabilities to [0..255] range for table lookup.
    // For each byte value: contribution = freq * log2_table_entry(freq_scaled)
    // where freq_scaled = (freq * 256) / DataSize.
    //
    // The log2_table[k] = round(-log2(k/256) * 256) for k in 1..255.
    // So: H_fixed = sum(freq * log2_table[freq_scaled]) / DataSize
    // And H_percent = H_fixed * 100 / (8 * 256)   [since max entropy = 8 bits, scaled by 256]
    //
    for (i = 0; i < 256; i++) {
        if (frequency[i] > 0) {
            ULONG scaled = (ULONG)((ULONG64)frequency[i] * 256 / DataSize);
            if (scaled == 0) {
                scaled = 1;
            }
            if (scaled > 255) {
                scaled = 255;
            }
            entropyFixed += (ULONG64)frequency[i] * g_Log2Table[scaled];
        }
    }

    //
    // Normalize: entropyFixed is in units of (count * 8.8_fixed).
    // Divide by DataSize to get average per-byte entropy in 8.8 format.
    // Then convert to percentage of 8 bits maximum.
    // H_percent = (entropyFixed / DataSize) * 100 / (8 * 256)
    //           = entropyFixed * 100 / (DataSize * 2048)
    //
    entropy = (ULONG)(entropyFixed * 100 / ((ULONG64)DataSize * 2048));

    if (entropy > 100) {
        entropy = 100;
    }

    return entropy;
}

static BOOLEAN
DxpIsBase64Encoded(
    _In_reads_bytes_(DataSize) PUCHAR Data,
    _In_ SIZE_T DataSize
    )
{
    SIZE_T i;
    SIZE_T validChars = 0;
    SIZE_T alphaChars = 0;
    SIZE_T paddingCount = 0;
    SIZE_T checkLen;

    if (DataSize < 4) {
        return FALSE;
    }

    checkLen = DataSize;
    if (checkLen > 4096) {
        checkLen = 4096;
    }

    for (i = 0; i < checkLen; i++) {
        UCHAR c = Data[i];

        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '+' || c == '/') {
            validChars++;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
                alphaChars++;
            }
        } else if (c == '=') {
            paddingCount++;
            if (paddingCount > 2) {
                return FALSE;
            }
        } else if (c != '\r' && c != '\n' && c != ' ' && c != '\t') {
            if (validChars > 0 && validChars < i) {
                break;
            }
            return FALSE;
        }
    }

    //
    // Need at least 90% valid Base64 characters
    // and a mix of alpha characters (not just numbers)
    //
    if (i > 0 && validChars * 100 / i >= 90 && alphaChars > validChars / 4) {
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN
DxpIsCompressedData(
    _In_reads_bytes_(DataSize) PUCHAR Data,
    _In_ SIZE_T DataSize,
    _Out_opt_ PBOOLEAN IsEncrypted
    )
{
    ULONG i;

    if (IsEncrypted != NULL) {
        *IsEncrypted = FALSE;
    }

    if (DataSize < 6) {
        return FALSE;
    }

    //
    // Check against known archive signatures
    //
    for (i = 0; i < ARRAYSIZE(g_ArchiveSignatures); i++) {
        if (DataSize >= g_ArchiveSignatures[i].SignatureLength) {
            if (RtlCompareMemory(Data, g_ArchiveSignatures[i].Signature,
                                 g_ArchiveSignatures[i].SignatureLength) ==
                g_ArchiveSignatures[i].SignatureLength) {

                if (IsEncrypted != NULL) {
                    *IsEncrypted = g_ArchiveSignatures[i].IsEncrypted;
                }
                return TRUE;
            }
        }
    }

    //
    // Check for encrypted ZIP (flag in local file header).
    // Use RtlCopyMemory for unaligned access safety (ARM compatibility).
    //
    if (DataSize >= 8 && Data[0] == 0x50 && Data[1] == 0x4B &&
        Data[2] == 0x03 && Data[3] == 0x04) {

        USHORT flags = 0;
        RtlCopyMemory(&flags, Data + 6, sizeof(USHORT));
        if (flags & 0x0001) {
            if (IsEncrypted != NULL) {
                *IsEncrypted = TRUE;
            }
        }
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN
DxpMatchPattern(
    _In_ PDX_PATTERN Pattern,
    _In_reads_bytes_(DataSize) PUCHAR Data,
    _In_ SIZE_T DataSize,
    _Out_opt_ PULONG MatchOffset
    )
{
    SIZE_T i, j;
    BOOLEAN found;

    if (MatchOffset != NULL) {
        *MatchOffset = 0;
    }

    if (Pattern->Pattern == NULL || Pattern->PatternSize == 0) {
        return FALSE;
    }

    if (Pattern->PatternSize > DataSize) {
        return FALSE;
    }

    switch (Pattern->Type) {
        case PatternType_Keyword:
            for (i = 0; i <= DataSize - Pattern->PatternSize; i++) {
                found = TRUE;
                for (j = 0; j < Pattern->PatternSize; j++) {
                    if (Data[i + j] != Pattern->Pattern[j]) {
                        found = FALSE;
                        break;
                    }
                }

                if (found) {
                    if (MatchOffset != NULL) {
                        *MatchOffset = (ULONG)i;
                    }
                    return TRUE;
                }
            }
            break;

        case PatternType_FileSignature:
            if (RtlCompareMemory(Data, Pattern->Pattern, Pattern->PatternSize) ==
                Pattern->PatternSize) {
                if (MatchOffset != NULL) {
                    *MatchOffset = 0;
                }
                return TRUE;
            }
            break;

        default:
            //
            // Unknown pattern type — do not match.
            // Only PatternType_Keyword and PatternType_FileSignature are
            // supported in kernel mode.
            //
            break;
    }

    return FALSE;
}

/**
 * @brief Case-insensitive ANSI string comparison (kernel-safe).
 *
 * Replaces _stricmp which is not a documented kernel-mode API.
 */
static BOOLEAN
DxpCaseInsensitiveCompareA(
    _In_ PCSTR String1,
    _In_ PCSTR String2
    )
{
    while (*String1 && *String2) {
        CHAR c1 = *String1;
        CHAR c2 = *String2;

        if (c1 >= 'A' && c1 <= 'Z') c1 += ('a' - 'A');
        if (c2 >= 'A' && c2 <= 'Z') c2 += ('a' - 'A');

        if (c1 != c2) {
            return FALSE;
        }

        String1++;
        String2++;
    }

    return (*String1 == *String2);
}

static BOOLEAN
DxpIsCloudStorageDestination(
    _In_ PCSTR Hostname
    )
{
    ULONG i;
    SIZE_T hostnameLen;
    SIZE_T domainLen;

    if (Hostname == NULL || Hostname[0] == '\0') {
        return FALSE;
    }

    hostnameLen = strlen(Hostname);

    for (i = 0; g_CloudStorageDomains[i] != NULL; i++) {
        domainLen = strlen(g_CloudStorageDomains[i]);

        if (hostnameLen >= domainLen) {
            if (DxpCaseInsensitiveCompareA(
                    Hostname + hostnameLen - domainLen,
                    g_CloudStorageDomains[i])) {
                if (hostnameLen == domainLen ||
                    Hostname[hostnameLen - domainLen - 1] == '.') {
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

static BOOLEAN
DxpIsPersonalEmailDomain(
    _In_ PCSTR Hostname
    )
{
    ULONG i;
    SIZE_T hostnameLen;
    SIZE_T domainLen;

    if (Hostname == NULL || Hostname[0] == '\0') {
        return FALSE;
    }

    hostnameLen = strlen(Hostname);

    for (i = 0; g_PersonalEmailDomains[i] != NULL; i++) {
        domainLen = strlen(g_PersonalEmailDomains[i]);

        if (hostnameLen >= domainLen) {
            if (DxpCaseInsensitiveCompareA(
                    Hostname + hostnameLen - domainLen,
                    g_PersonalEmailDomains[i])) {
                if (hostnameLen == domainLen ||
                    Hostname[hostnameLen - domainLen - 1] == '.') {
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

static NTSTATUS
DxpValidateRemoteAddress(
    _In_ BOOLEAN IsIPv6,
    _In_ ULONG RemoteAddressSize
    )
{
    ULONG expectedSize = IsIPv6 ? sizeof(IN6_ADDR) : sizeof(IN_ADDR);

    if (RemoteAddressSize < expectedSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// TRANSFER HASH TABLE
// ============================================================================

static ULONG
DxpHashTransferKey(
    _In_ HANDLE ProcessId,
    _In_reads_bytes_(AddrSize) PVOID RemoteAddress,
    _In_ ULONG AddrSize,
    _In_ USHORT RemotePort
    )
{
    ULONG hash = 0x811C9DC5;    // FNV-1a offset basis
    PUCHAR addr = (PUCHAR)RemoteAddress;
    ULONG i;
    ULONG_PTR pid = (ULONG_PTR)ProcessId;

    //
    // Hash the PID
    //
    for (i = 0; i < sizeof(ULONG_PTR); i++) {
        hash ^= (UCHAR)(pid & 0xFF);
        hash *= 0x01000193;     // FNV-1a prime
        pid >>= 8;
    }

    //
    // Hash the address
    //
    for (i = 0; i < AddrSize; i++) {
        hash ^= addr[i];
        hash *= 0x01000193;
    }

    //
    // Hash the port
    //
    hash ^= (UCHAR)(RemotePort & 0xFF);
    hash *= 0x01000193;
    hash ^= (UCHAR)((RemotePort >> 8) & 0xFF);
    hash *= 0x01000193;

    return hash % DX_TRANSFER_HASH_BUCKETS;
}

/**
 * @brief Get existing or create new transfer context.
 *
 * Returns with a reference held on the transfer context.
 * Caller MUST call DxpDereferenceTransfer when done.
 *
 * The lock is held across lookup + insert to prevent TOCTOU races.
 */
static PDX_TRANSFER_CONTEXT
DxpGetOrCreateTransfer(
    _In_ PDX_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_reads_bytes_(AddrSize) PVOID RemoteAddress,
    _In_ ULONG AddrSize,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6
    )
{
    ULONG bucket;
    PDX_HASH_BUCKET hashBucket;
    PLIST_ENTRY entry;
    PDX_TRANSFER_CONTEXT transfer;
    PDX_TRANSFER_CONTEXT newTransfer = NULL;
    ULONG expectedAddrSize = IsIPv6 ? sizeof(IN6_ADDR) : sizeof(IN_ADDR);

    bucket = DxpHashTransferKey(ProcessId, RemoteAddress, AddrSize, RemotePort);
    hashBucket = &Detector->TransferBuckets[bucket];

    //
    // Pre-allocate outside the lock to minimize hold time
    //
    if ((ULONG)Detector->TransferCount < DX_MAX_TRANSFERS) {
        newTransfer = (PDX_TRANSFER_CONTEXT)ExAllocateFromNPagedLookasideList(
            &Detector->TransferLookaside
        );
    }

    //
    // Lock the bucket — holds across search + potential insert
    //
    DxpAcquirePushLockExclusive(&hashBucket->Lock);

    //
    // Search for existing transfer
    //
    for (entry = hashBucket->Head.Flink;
         entry != &hashBucket->Head;
         entry = entry->Flink) {

        transfer = CONTAINING_RECORD(entry, DX_TRANSFER_CONTEXT, HashEntry);

        if (transfer->ProcessId == ProcessId &&
            transfer->RemotePort == RemotePort &&
            transfer->IsIPv6 == IsIPv6) {

            PVOID storedAddr = IsIPv6 ?
                (PVOID)&transfer->RemoteAddress.IPv6 :
                (PVOID)&transfer->RemoteAddress.IPv4;

            if (RtlCompareMemory(storedAddr, RemoteAddress, expectedAddrSize) == expectedAddrSize) {
                //
                // Found — take a reference and return
                //
                DxpReferenceTransfer(transfer);

                DxpReleasePushLockExclusive(&hashBucket->Lock);

                //
                // Free pre-allocated entry we don't need
                //
                if (newTransfer != NULL) {
                    ExFreeToNPagedLookasideList(&Detector->TransferLookaside, newTransfer);
                }
                return transfer;
            }
        }
    }

    //
    // Not found — insert new entry (if we have one)
    //
    if (newTransfer == NULL || (ULONG)Detector->TransferCount >= DX_MAX_TRANSFERS) {
        DxpReleasePushLockExclusive(&hashBucket->Lock);
        if (newTransfer != NULL) {
            ExFreeToNPagedLookasideList(&Detector->TransferLookaside, newTransfer);
        }
        return NULL;
    }

    RtlZeroMemory(newTransfer, sizeof(DX_TRANSFER_CONTEXT));

    newTransfer->TransferId = (ULONG64)InterlockedIncrement64(&Detector->NextTransferId);
    newTransfer->ProcessId = ProcessId;
    newTransfer->RemotePort = RemotePort;
    newTransfer->IsIPv6 = IsIPv6;
    newTransfer->RefCount = 2;  // 1 for hash table, 1 for caller

    if (IsIPv6) {
        RtlCopyMemory(&newTransfer->RemoteAddress.IPv6, RemoteAddress, sizeof(IN6_ADDR));
    } else {
        RtlCopyMemory(&newTransfer->RemoteAddress.IPv4, RemoteAddress, sizeof(IN_ADDR));
    }

    KeQuerySystemTime(&newTransfer->StartTime);
    newTransfer->LastActivityTime = newTransfer->StartTime;

    InsertTailList(&hashBucket->Head, &newTransfer->HashEntry);
    InterlockedIncrement(&Detector->TransferCount);

    DxpReleasePushLockExclusive(&hashBucket->Lock);

    return newTransfer;
}

static VOID
DxpReferenceTransfer(
    _In_ PDX_TRANSFER_CONTEXT Transfer
    )
{
    InterlockedIncrement(&Transfer->RefCount);
}

/**
 * @brief Dereference a transfer context.
 *
 * When refcount drops to zero, frees the transfer back to the lookaside list.
 * The hash table ref is the "last" ref — when cleanup removes from the hash
 * table it calls this, and if no in-flight operations hold refs, the object
 * is freed.
 */
static VOID
DxpDereferenceTransfer(
    _In_ PDX_DETECTOR Detector,
    _In_ PDX_TRANSFER_CONTEXT Transfer
    )
{
    LONG newRef = InterlockedDecrement(&Transfer->RefCount);

    NT_ASSERT(newRef >= 0);

    if (newRef == 0) {
        ExFreeToNPagedLookasideList(&Detector->TransferLookaside, Transfer);
    }
}

// ============================================================================
// ALERT CREATION
// ============================================================================

static NTSTATUS
DxpCreateAlert(
    _In_ PDX_DETECTOR Detector,
    _In_ PDX_TRANSFER_CONTEXT Transfer,
    _In_ DX_EXFIL_TYPE Type,
    _In_ BOOLEAN WasBlocked
    )
{
    PDX_ALERT alert;
    LARGE_INTEGER currentTime;
    ULONG i;

    //
    // Check alert limit
    //
    if ((ULONG)Detector->AlertCount >= DX_MAX_ALERTS) {
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Allocate alert from general pool (not lookaside) so DxFreeAlert
    // can free without needing the detector.
    //
    alert = (PDX_ALERT)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(DX_ALERT),
        DX_POOL_TAG_ALERT
    );
    if (alert == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Fill alert details
    //
    alert->AlertId = (ULONG64)InterlockedIncrement64(&Detector->NextAlertId);
    alert->Type = Type;
    alert->Indicators = Transfer->Indicators;
    alert->SeverityScore = Transfer->SuspicionScore;
    alert->ProcessId = Transfer->ProcessId;
    alert->WasBlocked = WasBlocked;

    //
    // Populate process name (best effort, inline buffer)
    //
    alert->ProcessNameLength = 0;
    RtlZeroMemory(alert->ProcessNameBuffer, sizeof(alert->ProcessNameBuffer));

    //
    // Copy destination info
    //
    alert->IsIPv6 = Transfer->IsIPv6;
    alert->RemotePort = Transfer->RemotePort;

    if (Transfer->IsIPv6) {
        RtlCopyMemory(&alert->RemoteAddress.IPv6, &Transfer->RemoteAddress.IPv6, sizeof(IN6_ADDR));
    } else {
        RtlCopyMemory(&alert->RemoteAddress.IPv4, &Transfer->RemoteAddress.IPv4, sizeof(IN_ADDR));
    }

    RtlCopyMemory(alert->Hostname, Transfer->Hostname, sizeof(alert->Hostname) - 1);
    alert->Hostname[sizeof(alert->Hostname) - 1] = '\0';

    //
    // Transfer details
    //
    alert->DataSize = (SIZE_T)Transfer->BytesTransferred;
    alert->TransferStartTime = Transfer->StartTime;

    KeQuerySystemTime(&currentTime);
    alert->AlertTime = currentTime;
    alert->TransferDurationMs = (ULONG)((currentTime.QuadPart - Transfer->StartTime.QuadPart) / 10000);

    //
    // Copy pattern match categories (value snapshots, not pointers)
    //
    for (i = 0; i < Transfer->MatchCount && i < ARRAYSIZE(alert->SensitiveDataFound); i++) {
        RtlCopyMemory(
            alert->SensitiveDataFound[i].Category,
            Transfer->Matches[i].Category,
            sizeof(alert->SensitiveDataFound[i].Category) - 1
        );
        alert->SensitiveDataFound[i].Category[sizeof(alert->SensitiveDataFound[i].Category) - 1] = '\0';
        alert->SensitiveDataFound[i].MatchCount = Transfer->Matches[i].MatchCount;
        alert->CategoryCount++;
    }

    //
    // Queue alert
    //
    DxpAcquirePushLockExclusive(&Detector->AlertLock);
    InsertTailList(&Detector->AlertList, &alert->ListEntry);
    InterlockedIncrement(&Detector->AlertCount);
    DxpReleasePushLockExclusive(&Detector->AlertLock);

    InterlockedIncrement64(&Detector->Stats.AlertsGenerated);

    //
    // Notify callback (under push lock to prevent unload race)
    //
    DxpNotifyAlertCallback(Detector, alert);

    return STATUS_SUCCESS;
}

/**
 * @brief Notify registered alert callback.
 *
 * The callback is invoked while holding the callback push lock shared.
 * This prevents the callback from being unregistered (and potentially
 * the module unloaded) while the call is in flight.
 */
static VOID
DxpNotifyAlertCallback(
    _In_ PDX_DETECTOR Detector,
    _In_ PDX_ALERT Alert
    )
{
    DX_ALERT_CALLBACK callback;
    PVOID context;

    DxpAcquirePushLockShared(&Detector->Callbacks.Lock);

    callback = Detector->Callbacks.AlertCallback;
    context = Detector->Callbacks.AlertContext;

    if (callback != NULL) {
        callback(Alert, context);
    }

    DxpReleasePushLockShared(&Detector->Callbacks.Lock);
}

/**
 * @brief Determine if transfer should be blocked.
 *
 * Block callback is invoked while holding the callback push lock shared,
 * preventing unload race.
 */
static BOOLEAN
DxpShouldBlock(
    _In_ PDX_DETECTOR Detector,
    _In_ PDX_TRANSFER_CONTEXT Transfer
    )
{
    DX_BLOCK_CALLBACK callback;
    PVOID context;
    BOOLEAN shouldBlock = FALSE;

    if (!Detector->Config.BlockOnDetection) {
        return FALSE;
    }

    //
    // High severity always blocks
    //
    if (Transfer->SuspicionScore >= 90) {
        shouldBlock = TRUE;
    }

    //
    // Critical sensitivity pattern match
    //
    if (Transfer->MatchCount > 0) {
        ULONG i;
        for (i = 0; i < Transfer->MatchCount && i < ARRAYSIZE(Transfer->Matches); i++) {
            if (Transfer->Matches[i].Sensitivity == 4) {
                shouldBlock = TRUE;
                break;
            }
        }
    }

    //
    // Consult block callback for final decision (under lock)
    //
    DxpAcquirePushLockShared(&Detector->Callbacks.Lock);

    callback = Detector->Callbacks.BlockCallback;
    context = Detector->Callbacks.BlockContext;

    if (callback != NULL) {
        shouldBlock = callback(Transfer, context);
    }

    DxpReleasePushLockShared(&Detector->Callbacks.Lock);

    return shouldBlock;
}

static DX_EXFIL_TYPE
DxpClassifyExfiltration(
    _In_ PDX_TRANSFER_CONTEXT Transfer
    )
{
    if (Transfer->Indicators & DxIndicator_HighVolume) {
        return DxExfil_LargeUpload;
    }

    if (Transfer->Indicators & DxIndicator_EncryptedData) {
        return DxExfil_EncryptedArchive;
    }

    if (Transfer->Indicators & DxIndicator_EncodedData) {
        return DxExfil_EncodedData;
    }

    if (Transfer->Indicators & DxIndicator_CloudUpload) {
        return DxExfil_CloudStorage;
    }

    if (Transfer->Indicators & DxIndicator_PersonalEmail) {
        return DxExfil_EmailAttachment;
    }

    if (Transfer->Indicators & DxIndicator_SensitivePattern) {
        return DxExfil_SensitiveData;
    }

    return DxExfil_Unknown;
}

// ============================================================================
// CLEANUP TIMER — DPC queues a passive-level work item
// ============================================================================

/**
 * @brief DPC callback — queues a passive-level work item for cleanup.
 *
 * We cannot acquire push locks at DISPATCH_LEVEL, so the DPC simply
 * schedules a work item that runs at PASSIVE_LEVEL.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
DxpCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PDX_DETECTOR detector = (PDX_DETECTOR)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (detector == NULL || detector->ShuttingDown) {
        return;
    }

    //
    // Only queue if not already queued (prevent stacking)
    //
    if (InterlockedCompareExchange(&detector->CleanupWorkQueued, 1, 0) == 0) {
        ExInitializeWorkItem(&detector->CleanupWorkItem, DxpCleanupWorkRoutine, detector);
        ExQueueWorkItem(&detector->CleanupWorkItem, DelayedWorkQueue);
    }
}

/**
 * @brief Work item callback for cleanup — runs at PASSIVE_LEVEL.
 *
 * Iterates hash table buckets, removing and dereferencing stale transfers.
 * Also trims old alerts if the alert queue is more than 75% full.
 */
static VOID
DxpCleanupWorkRoutine(
    _In_ PVOID Parameter
    )
{
    PDX_DETECTOR detector = (PDX_DETECTOR)Parameter;
    ULONG i;
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;
    PDX_TRANSFER_CONTEXT transfer;
    LARGE_INTEGER currentTime;
    LONGLONG timeoutTicks;
    LIST_ENTRY freeList;

    if (detector == NULL || detector->ShuttingDown) {
        InterlockedExchange(&detector->CleanupWorkQueued, 0);
        return;
    }

    //
    // Acquire rundown protection to prevent shutdown during cleanup
    //
    if (!ExAcquireRundownProtection(&detector->RundownRef)) {
        InterlockedExchange(&detector->CleanupWorkQueued, 0);
        return;
    }

    KeQuerySystemTime(&currentTime);
    timeoutTicks = (LONGLONG)DX_TRANSFER_TIMEOUT_MS * 10000;

    InitializeListHead(&freeList);

    //
    // Iterate each hash bucket
    //
    for (i = 0; i < DX_TRANSFER_HASH_BUCKETS; i++) {
        DxpAcquirePushLockExclusive(&detector->TransferBuckets[i].Lock);

        for (entry = detector->TransferBuckets[i].Head.Flink;
             entry != &detector->TransferBuckets[i].Head;
             entry = nextEntry) {

            nextEntry = entry->Flink;
            transfer = CONTAINING_RECORD(entry, DX_TRANSFER_CONTEXT, HashEntry);

            if ((currentTime.QuadPart - transfer->LastActivityTime.QuadPart) > timeoutTicks) {
                RemoveEntryList(&transfer->HashEntry);
                InterlockedDecrement(&detector->TransferCount);
                InsertTailList(&freeList, &transfer->HashEntry);
            }
        }

        DxpReleasePushLockExclusive(&detector->TransferBuckets[i].Lock);
    }

    //
    // Dereference collected transfers (hash table's ref)
    //
    while (!IsListEmpty(&freeList)) {
        entry = RemoveHeadList(&freeList);
        transfer = CONTAINING_RECORD(entry, DX_TRANSFER_CONTEXT, HashEntry);
        DxpDereferenceTransfer(detector, transfer);
    }

    //
    // Trim old alerts if queue is more than 75% full
    //
    if (detector->AlertCount > (LONG)(DX_MAX_ALERTS * 3 / 4)) {
        DxpAcquirePushLockExclusive(&detector->AlertLock);

        while (detector->AlertCount > (LONG)(DX_MAX_ALERTS / 2) &&
               !IsListEmpty(&detector->AlertList)) {

            entry = RemoveHeadList(&detector->AlertList);
            InterlockedDecrement(&detector->AlertCount);

            PDX_ALERT alert = CONTAINING_RECORD(entry, DX_ALERT, ListEntry);
            ExFreePoolWithTag(alert, DX_POOL_TAG_ALERT);
        }

        DxpReleasePushLockExclusive(&detector->AlertLock);
    }

    ExReleaseRundownProtection(&detector->RundownRef);
    InterlockedExchange(&detector->CleanupWorkQueued, 0);
}
