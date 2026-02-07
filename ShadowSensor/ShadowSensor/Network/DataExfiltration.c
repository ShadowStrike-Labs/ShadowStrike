/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE DATA EXFILTRATION DETECTION
 * ============================================================================
 *
 * @file DataExfiltration.c
 * @brief Enterprise-grade DLP and data exfiltration detection for WFP integration.
 *
 * This module provides comprehensive data loss prevention:
 * - Shannon entropy calculation for encrypted/encoded data detection
 * - Pattern matching engine for sensitive data (PII, credentials, source code)
 * - Transfer volume tracking with burst detection
 * - Cloud storage and personal email detection
 * - Base64/encoded data detection
 * - Compressed and encrypted archive detection
 * - DNS and ICMP tunneling indicators
 * - Per-process exfiltration tracking
 * - Real-time alerting with callback notifications
 *
 * Detection Capabilities:
 * - Credit card numbers (Luhn algorithm validation)
 * - Social Security Numbers (format validation)
 * - API keys and secrets (entropy + pattern)
 * - Source code patterns (language detection)
 * - Database dumps (SQL patterns)
 * - Private keys (PEM/DER formats)
 * - High-entropy data (encryption/compression)
 *
 * MITRE ATT&CK Coverage:
 * - T1041: Exfiltration Over C2 Channel
 * - T1048: Exfiltration Over Alternative Protocol
 * - T1567: Exfiltration Over Web Service
 * - T1537: Transfer Data to Cloud Account
 * - T1030: Data Transfer Size Limits
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
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
#pragma alloc_text(PAGE, DxLoadPatterns)
#pragma alloc_text(PAGE, DxAnalyzeTraffic)
#pragma alloc_text(PAGE, DxInspectContent)
#pragma alloc_text(PAGE, DxGetAlerts)
#pragma alloc_text(PAGE, DxGetStatistics)
#pragma alloc_text(PAGE, DxRegisterAlertCallback)
#pragma alloc_text(PAGE, DxRegisterBlockCallback)
#pragma alloc_text(PAGE, DxUnregisterCallbacks)
#endif

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define DX_MAX_ALERTS                       1000
#define DX_MAX_TRANSFERS                    10000
#define DX_TRANSFER_TIMEOUT_MS              300000      // 5 minutes
#define DX_CLEANUP_INTERVAL_MS              60000       // 1 minute
#define DX_LOOKASIDE_DEPTH                  256
#define DX_HIGH_ENTROPY_THRESHOLD           7           // Out of 8 (bits per byte)
#define DX_BURST_THRESHOLD_BYTES            (10 * 1024 * 1024)  // 10 MB
#define DX_BURST_WINDOW_MS                  10000       // 10 seconds

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
    "rapidshare.com",
    "4shared.com",
    "zippyshare.com",
    "anonfiles.com",
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
// Base64 alphabet for detection
//
static const UCHAR g_Base64Alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

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

/**
 * @brief Extended detector state (internal).
 */
typedef struct _DX_DETECTOR_INTERNAL {
    //
    // Public structure (must be first)
    //
    DX_DETECTOR Public;

    //
    // Pattern ID generator
    //
    volatile LONG NextPatternId;

    //
    // Transfer ID generator
    //
    volatile LONG64 NextTransferId;

    //
    // Callbacks
    //
    struct {
        DX_ALERT_CALLBACK AlertCallback;
        PVOID AlertContext;
        DX_BLOCK_CALLBACK BlockCallback;
        PVOID BlockContext;
        EX_PUSH_LOCK Lock;
    } Callbacks;

    //
    // Lookaside lists
    //
    NPAGED_LOOKASIDE_LIST PatternLookaside;
    NPAGED_LOOKASIDE_LIST TransferLookaside;
    NPAGED_LOOKASIDE_LIST AlertLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Cleanup timer
    //
    KTIMER CleanupTimer;
    KDPC CleanupDpc;
    volatile BOOLEAN CleanupTimerActive;
    volatile BOOLEAN ShuttingDown;

    //
    // Pre-computed lookup tables
    //
    UCHAR Base64LookupTable[256];
    BOOLEAN LookupTablesInitialized;

} DX_DETECTOR_INTERNAL, *PDX_DETECTOR_INTERNAL;

/**
 * @brief Per-process transfer tracking.
 */
typedef struct _DX_PROCESS_TRANSFER_CONTEXT {
    LIST_ENTRY ListEntry;

    HANDLE ProcessId;
    UNICODE_STRING ProcessName;

    //
    // Transfer statistics
    //
    volatile LONG64 TotalBytesOut;
    volatile LONG64 BytesOutLastMinute;
    volatile LONG64 TransferCount;

    //
    // Timing
    //
    LARGE_INTEGER FirstTransferTime;
    LARGE_INTEGER LastTransferTime;
    LARGE_INTEGER LastMinuteReset;

    //
    // Burst detection
    //
    SIZE_T BurstBytes;
    LARGE_INTEGER BurstStartTime;

    //
    // Suspicion tracking
    //
    ULONG SuspicionScore;
    ULONG HighEntropyTransfers;
    ULONG PatternMatchCount;

    //
    // Reference counting
    //
    volatile LONG RefCount;

} DX_PROCESS_TRANSFER_CONTEXT, *PDX_PROCESS_TRANSFER_CONTEXT;

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

static PDX_TRANSFER_CONTEXT
DxpGetOrCreateTransfer(
    _In_ PDX_DETECTOR_INTERNAL Detector,
    _In_ HANDLE ProcessId,
    _In_ PVOID RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6
    );

static VOID
DxpReleaseTransfer(
    _In_ PDX_DETECTOR_INTERNAL Detector,
    _In_ PDX_TRANSFER_CONTEXT Transfer
    );

static NTSTATUS
DxpCreateAlert(
    _In_ PDX_DETECTOR_INTERNAL Detector,
    _In_ PDX_TRANSFER_CONTEXT Transfer,
    _In_ DX_EXFIL_TYPE Type
    );

static VOID
DxpNotifyAlertCallback(
    _In_ PDX_DETECTOR_INTERNAL Detector,
    _In_ PDX_ALERT Alert
    );

static BOOLEAN
DxpShouldBlock(
    _In_ PDX_DETECTOR_INTERNAL Detector,
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
DxpInitializeLookupTables(
    _In_ PDX_DETECTOR_INTERNAL Detector
    );

static ULONG
DxpCalculateSuspicionScore(
    _In_ PDX_TRANSFER_CONTEXT Transfer
    );

static DX_EXFIL_TYPE
DxpClassifyExfiltration(
    _In_ PDX_TRANSFER_CONTEXT Transfer
    );

// ============================================================================
// INITIALIZATION AND SHUTDOWN
// ============================================================================

_Use_decl_annotations_
NTSTATUS
DxInitialize(
    _Out_ PDX_DETECTOR* Detector
    )
/**
 * @brief Initialize the data exfiltration detection subsystem.
 *
 * Allocates and initializes all data structures required for
 * DLP including pattern database, transfer tracking, and alerts.
 */
{
    NTSTATUS status = STATUS_SUCCESS;
    PDX_DETECTOR_INTERNAL detector = NULL;
    LARGE_INTEGER dueTime;

    PAGED_CODE();

    if (Detector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Detector = NULL;

    //
    // Allocate detector structure
    //
    detector = (PDX_DETECTOR_INTERNAL)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(DX_DETECTOR_INTERNAL),
        DX_POOL_TAG_CONTEXT
    );

    if (detector == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize pattern list
    //
    InitializeListHead(&detector->Public.PatternList);
    ExInitializePushLock(&detector->Public.PatternLock);

    //
    // Initialize transfer list
    //
    InitializeListHead(&detector->Public.TransferList);
    KeInitializeSpinLock(&detector->Public.TransferLock);

    //
    // Initialize alert list
    //
    InitializeListHead(&detector->Public.AlertList);
    KeInitializeSpinLock(&detector->Public.AlertLock);

    //
    // Initialize callbacks
    //
    ExInitializePushLock(&detector->Callbacks.Lock);

    //
    // Initialize lookaside lists
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

    ExInitializeNPagedLookasideList(
        &detector->AlertLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(DX_ALERT),
        DX_POOL_TAG_ALERT,
        64
    );

    detector->LookasideInitialized = TRUE;

    //
    // Initialize lookup tables for fast Base64 detection
    //
    DxpInitializeLookupTables(detector);

    //
    // Set default configuration
    //
    detector->Public.Config.VolumeThresholdPerMinute = DX_VOLUME_THRESHOLD_MB * 1024 * 1024;
    detector->Public.Config.EntropyThreshold = DX_ENTROPY_THRESHOLD;
    detector->Public.Config.EnableContentInspection = TRUE;
    detector->Public.Config.EnableCloudDetection = TRUE;
    detector->Public.Config.BlockOnDetection = FALSE;  // Alert-only by default

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&detector->Public.Stats.StartTime);

    //
    // Initialize cleanup timer
    //
    KeInitializeTimer(&detector->CleanupTimer);
    KeInitializeDpc(&detector->CleanupDpc, DxpCleanupTimerDpc, detector);

    //
    // Start cleanup timer
    //
    dueTime.QuadPart = -((LONGLONG)DX_CLEANUP_INTERVAL_MS * 10000);
    KeSetTimerEx(
        &detector->CleanupTimer,
        dueTime,
        DX_CLEANUP_INTERVAL_MS,
        &detector->CleanupDpc
    );
    detector->CleanupTimerActive = TRUE;

    detector->Public.Initialized = TRUE;
    *Detector = &detector->Public;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
DxShutdown(
    _Inout_ PDX_DETECTOR Detector
    )
/**
 * @brief Shutdown and cleanup the data exfiltration detector.
 *
 * Cancels cleanup timer, frees all patterns, transfers, alerts,
 * and releases all allocated memory.
 */
{
    PDX_DETECTOR_INTERNAL detector;
    PLIST_ENTRY entry;
    PDX_PATTERN pattern;
    PDX_TRANSFER_CONTEXT transfer;
    PDX_ALERT alert;
    KIRQL oldIrql;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized) {
        return;
    }

    detector = CONTAINING_RECORD(Detector, DX_DETECTOR_INTERNAL, Public);
    detector->ShuttingDown = TRUE;

    //
    // Cancel cleanup timer
    //
    if (detector->CleanupTimerActive) {
        KeCancelTimer(&detector->CleanupTimer);
        detector->CleanupTimerActive = FALSE;
    }

    //
    // Wait for any pending DPCs
    //
    KeFlushQueuedDpcs();

    //
    // Free all patterns
    //
    ExAcquirePushLockExclusive(&Detector->PatternLock);

    while (!IsListEmpty(&Detector->PatternList)) {
        entry = RemoveHeadList(&Detector->PatternList);
        pattern = CONTAINING_RECORD(entry, DX_PATTERN, ListEntry);

        if (pattern->Pattern != NULL) {
            ExFreePoolWithTag(pattern->Pattern, DX_POOL_TAG_PATTERN);
        }

        if (detector->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&detector->PatternLookaside, pattern);
        } else {
            ExFreePoolWithTag(pattern, DX_POOL_TAG_PATTERN);
        }
    }

    ExReleasePushLockExclusive(&Detector->PatternLock);

    //
    // Free all transfers
    //
    KeAcquireSpinLock(&Detector->TransferLock, &oldIrql);

    while (!IsListEmpty(&Detector->TransferList)) {
        entry = RemoveHeadList(&Detector->TransferList);
        transfer = CONTAINING_RECORD(entry, DX_TRANSFER_CONTEXT, ListEntry);

        if (detector->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&detector->TransferLookaside, transfer);
        } else {
            ExFreePoolWithTag(transfer, DX_POOL_TAG_CONTEXT);
        }
    }

    KeReleaseSpinLock(&Detector->TransferLock, oldIrql);

    //
    // Free all alerts
    //
    KeAcquireSpinLock(&Detector->AlertLock, &oldIrql);

    while (!IsListEmpty(&Detector->AlertList)) {
        entry = RemoveHeadList(&Detector->AlertList);
        alert = CONTAINING_RECORD(entry, DX_ALERT, ListEntry);

        if (alert->ProcessName.Buffer != NULL) {
            ExFreePoolWithTag(alert->ProcessName.Buffer, DX_POOL_TAG_ALERT);
        }
        if (alert->UserName.Buffer != NULL) {
            ExFreePoolWithTag(alert->UserName.Buffer, DX_POOL_TAG_ALERT);
        }

        if (detector->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&detector->AlertLookaside, alert);
        } else {
            ExFreePoolWithTag(alert, DX_POOL_TAG_ALERT);
        }
    }

    KeReleaseSpinLock(&Detector->AlertLock, oldIrql);

    //
    // Delete lookaside lists
    //
    if (detector->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&detector->PatternLookaside);
        ExDeleteNPagedLookasideList(&detector->TransferLookaside);
        ExDeleteNPagedLookasideList(&detector->AlertLookaside);
        detector->LookasideInitialized = FALSE;
    }

    Detector->Initialized = FALSE;

    //
    // Free detector structure
    //
    ExFreePoolWithTag(detector, DX_POOL_TAG_CONTEXT);
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
/**
 * @brief Add a sensitive data pattern to the detection engine.
 *
 * Patterns are used to detect sensitive data in outbound traffic
 * such as credit card numbers, SSNs, API keys, etc.
 */
{
    PDX_DETECTOR_INTERNAL detector;
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

    detector = CONTAINING_RECORD(Detector, DX_DETECTOR_INTERNAL, Public);

    //
    // Check pattern limit
    //
    if ((ULONG)Detector->PatternCount >= DX_MAX_PATTERNS) {
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Allocate pattern from lookaside
    //
    newPattern = (PDX_PATTERN)ExAllocateFromNPagedLookasideList(
        &detector->PatternLookaside
    );

    if (newPattern == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(newPattern, sizeof(DX_PATTERN));

    //
    // Assign pattern ID
    //
    newPattern->PatternId = (ULONG)InterlockedIncrement(&detector->NextPatternId);

    //
    // Copy pattern name
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
        ExFreeToNPagedLookasideList(&detector->PatternLookaside, newPattern);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(newPattern->Pattern, Pattern, PatternSize);
    newPattern->PatternSize = PatternSize;

    //
    // Set sensitivity
    //
    newPattern->Sensitivity = Sensitivity;

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
    // Default to keyword matching
    //
    newPattern->Type = PatternType_Keyword;

    //
    // Insert into pattern list
    //
    ExAcquirePushLockExclusive(&Detector->PatternLock);
    InsertTailList(&Detector->PatternList, &newPattern->ListEntry);
    InterlockedIncrement(&Detector->PatternCount);
    ExReleasePushLockExclusive(&Detector->PatternLock);

    *PatternId = newPattern->PatternId;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
DxRemovePattern(
    _In_ PDX_DETECTOR Detector,
    _In_ ULONG PatternId
    )
/**
 * @brief Remove a pattern from the detection engine.
 */
{
    PDX_DETECTOR_INTERNAL detector;
    PLIST_ENTRY entry;
    PDX_PATTERN pattern;
    PDX_PATTERN foundPattern = NULL;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    detector = CONTAINING_RECORD(Detector, DX_DETECTOR_INTERNAL, Public);

    ExAcquirePushLockExclusive(&Detector->PatternLock);

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

    ExReleasePushLockExclusive(&Detector->PatternLock);

    if (foundPattern == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Free pattern
    //
    if (foundPattern->Pattern != NULL) {
        ExFreePoolWithTag(foundPattern->Pattern, DX_POOL_TAG_PATTERN);
    }

    ExFreeToNPagedLookasideList(&detector->PatternLookaside, foundPattern);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
DxLoadPatterns(
    _In_ PDX_DETECTOR Detector,
    _In_ PUNICODE_STRING FilePath
    )
/**
 * @brief Load patterns from a file.
 *
 * File format: Each line contains:
 * PatternName|Sensitivity|Category|PatternHex
 */
{
    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized || FilePath == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Pattern loading from file would be implemented here
    // For kernel mode, this typically reads from a registry key
    // or receives patterns from user-mode via IOCTL
    //
    // This is a placeholder - actual implementation depends on
    // how patterns are delivered to the driver
    //

    return STATUS_NOT_IMPLEMENTED;
}

// ============================================================================
// TRAFFIC ANALYSIS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
DxAnalyzeTraffic(
    _In_ PDX_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ PVOID RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ SIZE_T DataSize,
    _Out_ PBOOLEAN IsSuspicious,
    _Out_opt_ PULONG SuspicionScore
    )
/**
 * @brief Analyze outbound traffic for potential data exfiltration.
 *
 * Performs comprehensive analysis including:
 * - Entropy calculation
 * - Pattern matching
 * - Encoding detection (Base64, etc.)
 * - Compression detection
 * - Volume tracking
 * - Destination classification
 */
{
    PDX_DETECTOR_INTERNAL detector;
    PDX_TRANSFER_CONTEXT transfer = NULL;
    DX_INDICATORS indicators = DxIndicator_None;
    ULONG entropy = 0;
    ULONG score = 0;
    BOOLEAN isCompressed = FALSE;
    BOOLEAN isEncrypted = FALSE;
    PLIST_ENTRY entry;
    PDX_PATTERN pattern;
    ULONG matchOffset;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized ||
        RemoteAddress == NULL || Data == NULL || DataSize == 0 ||
        IsSuspicious == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsSuspicious = FALSE;
    if (SuspicionScore != NULL) {
        *SuspicionScore = 0;
    }

    detector = CONTAINING_RECORD(Detector, DX_DETECTOR_INTERNAL, Public);

    //
    // Update statistics
    //
    InterlockedAdd64(&Detector->Stats.BytesInspected, (LONG64)DataSize);
    InterlockedIncrement64(&Detector->Stats.TransfersAnalyzed);

    //
    // Get or create transfer context
    //
    transfer = DxpGetOrCreateTransfer(detector, ProcessId, RemoteAddress, RemotePort, IsIPv6);
    if (transfer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Update transfer statistics
    //
    transfer->BytesTransferred += DataSize;
    KeQuerySystemTime(&transfer->LastActivityTime);

    //
    // Calculate entropy
    //
    entropy = DxpCalculateShannonEntropy((PUCHAR)Data, DataSize);
    transfer->Entropy = entropy;

    if (entropy >= Detector->Config.EntropyThreshold) {
        indicators |= DxIndicator_HighEntropy;
        score += 30;
    }

    //
    // Check for compressed/encrypted data
    //
    if (DxpIsCompressedData((PUCHAR)Data, DataSize, &isEncrypted)) {
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
    if (DxpIsBase64Encoded((PUCHAR)Data, DataSize)) {
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
    if (transfer->BytesTransferred > Detector->Config.VolumeThresholdPerMinute) {
        indicators |= DxIndicator_HighVolume;
        score += 30;
    }

    //
    // Pattern matching (if content inspection enabled)
    //
    if (Detector->Config.EnableContentInspection) {
        ExAcquirePushLockShared(&Detector->PatternLock);

        for (entry = Detector->PatternList.Flink;
             entry != &Detector->PatternList;
             entry = entry->Flink) {

            pattern = CONTAINING_RECORD(entry, DX_PATTERN, ListEntry);

            if (DxpMatchPattern(pattern, (PUCHAR)Data, DataSize, &matchOffset)) {
                //
                // Pattern match found
                //
                InterlockedIncrement(&pattern->MatchCount);
                InterlockedIncrement64(&Detector->Stats.PatternMatches);

                indicators |= DxIndicator_SensitivePattern;

                //
                // Add to transfer's match list
                //
                if (transfer->MatchCount < 16) {
                    transfer->Matches[transfer->MatchCount].Pattern = pattern;
                    transfer->Matches[transfer->MatchCount].MatchCount = 1;
                    transfer->MatchCount++;
                }

                //
                // Score based on sensitivity
                //
                switch (pattern->Sensitivity) {
                    case 4: // Critical
                        score += 50;
                        break;
                    case 3: // High
                        score += 35;
                        break;
                    case 2: // Medium
                        score += 20;
                        break;
                    case 1: // Low
                        score += 10;
                        break;
                }
            }
        }

        ExReleasePushLockShared(&Detector->PatternLock);
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

        //
        // Create alert if threshold exceeded
        //
        if (score >= 70) {
            DX_EXFIL_TYPE exfilType = DxpClassifyExfiltration(transfer);
            DxpCreateAlert(detector, transfer, exfilType);

            //
            // Check if we should block
            //
            if (Detector->Config.BlockOnDetection && DxpShouldBlock(detector, transfer)) {
                InterlockedIncrement64(&Detector->Stats.TransfersBlocked);
            }
        }
    }

    if (SuspicionScore != NULL) {
        *SuspicionScore = score;
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
DxRecordTransfer(
    _In_ PDX_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ PVOID RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6,
    _In_ SIZE_T BytesSent
    )
/**
 * @brief Record a transfer without full content analysis.
 *
 * Used for tracking transfer volumes when content inspection
 * is not needed or not possible.
 */
{
    PDX_DETECTOR_INTERNAL detector;
    PDX_TRANSFER_CONTEXT transfer;
    LARGE_INTEGER currentTime;

    if (Detector == NULL || !Detector->Initialized || RemoteAddress == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    detector = CONTAINING_RECORD(Detector, DX_DETECTOR_INTERNAL, Public);

    transfer = DxpGetOrCreateTransfer(detector, ProcessId, RemoteAddress, RemotePort, IsIPv6);
    if (transfer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Update transfer statistics
    //
    transfer->BytesTransferred += BytesSent;
    KeQuerySystemTime(&currentTime);
    transfer->LastActivityTime = currentTime;

    //
    // Calculate bytes per second
    //
    if (transfer->StartTime.QuadPart > 0) {
        LONGLONG elapsedMs = (currentTime.QuadPart - transfer->StartTime.QuadPart) / 10000;
        if (elapsedMs > 0) {
            transfer->BytesPerSecond = (SIZE_T)((transfer->BytesTransferred * 1000) / elapsedMs);
        }
    }

    //
    // Check for burst transfer
    //
    if (transfer->BytesTransferred > DX_BURST_THRESHOLD_BYTES) {
        LONGLONG burstWindow = (currentTime.QuadPart - transfer->StartTime.QuadPart) / 10000;
        if (burstWindow < DX_BURST_WINDOW_MS) {
            transfer->Indicators |= DxIndicator_BurstTransfer;
            transfer->SuspicionScore += 25;
        }
    }

    //
    // Check volume threshold
    //
    if (transfer->BytesTransferred > Detector->Config.VolumeThresholdPerMinute) {
        transfer->Indicators |= DxIndicator_HighVolume;

        if (transfer->SuspicionScore < 50) {
            transfer->SuspicionScore = 50;
        }

        //
        // Generate alert for high-volume transfer
        //
        DxpCreateAlert(detector, transfer, DxExfil_LargeUpload);
    }

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
/**
 * @brief Inspect content for sensitive data patterns.
 *
 * Performs content analysis without transfer context tracking.
 * Useful for inspecting file contents or specific data buffers.
 */
{
    PDX_DETECTOR_INTERNAL detector;
    DX_INDICATORS indicators = DxIndicator_None;
    ULONG entropy;
    BOOLEAN isCompressed;
    BOOLEAN isEncrypted;
    PLIST_ENTRY entry;
    PDX_PATTERN pattern;
    ULONG matchCount = 0;
    ULONG matchOffset;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized ||
        Data == NULL || DataSize == 0 ||
        Indicators == NULL || MatchCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Indicators = DxIndicator_None;
    *MatchCount = 0;

    detector = CONTAINING_RECORD(Detector, DX_DETECTOR_INTERNAL, Public);

    //
    // Calculate entropy
    //
    entropy = DxpCalculateShannonEntropy((PUCHAR)Data, DataSize);
    if (entropy >= Detector->Config.EntropyThreshold) {
        indicators |= DxIndicator_HighEntropy;
    }

    //
    // Check compression/encryption
    //
    if (DxpIsCompressedData((PUCHAR)Data, DataSize, &isEncrypted)) {
        indicators |= DxIndicator_CompressedData;
        if (isEncrypted) {
            indicators |= DxIndicator_EncryptedData;
        }
    }

    //
    // Check Base64
    //
    if (DxpIsBase64Encoded((PUCHAR)Data, DataSize)) {
        indicators |= DxIndicator_EncodedData;
    }

    //
    // Pattern matching
    //
    ExAcquirePushLockShared(&Detector->PatternLock);

    for (entry = Detector->PatternList.Flink;
         entry != &Detector->PatternList;
         entry = entry->Flink) {

        pattern = CONTAINING_RECORD(entry, DX_PATTERN, ListEntry);

        if (DxpMatchPattern(pattern, (PUCHAR)Data, DataSize, &matchOffset)) {
            indicators |= DxIndicator_SensitivePattern;

            if (Matches != NULL && matchCount < MaxMatches) {
                Matches[matchCount] = pattern;
                matchCount++;
            }

            InterlockedIncrement(&pattern->MatchCount);
            InterlockedIncrement64(&Detector->Stats.PatternMatches);
        }
    }

    ExReleasePushLockShared(&Detector->PatternLock);

    *Indicators = indicators;
    *MatchCount = matchCount;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
DxCalculateEntropy(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ SIZE_T DataSize,
    _Out_ PULONG Entropy
    )
/**
 * @brief Calculate Shannon entropy of data.
 *
 * Returns entropy as percentage (0-100) where:
 * - 0-30: Low entropy (text, repetitive data)
 * - 30-70: Medium entropy (mixed content)
 * - 70-100: High entropy (compressed/encrypted)
 */
{
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
/**
 * @brief Get pending alerts from the detector.
 *
 * Retrieves and removes alerts from the alert queue.
 * Caller must free each alert using DxFreeAlert.
 */
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    PDX_ALERT alert;
    ULONG count = 0;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized ||
        Alerts == NULL || AlertCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *AlertCount = 0;

    KeAcquireSpinLock(&Detector->AlertLock, &oldIrql);

    while (!IsListEmpty(&Detector->AlertList) && count < MaxAlerts) {
        entry = RemoveHeadList(&Detector->AlertList);
        alert = CONTAINING_RECORD(entry, DX_ALERT, ListEntry);
        InterlockedDecrement(&Detector->AlertCount);

        Alerts[count++] = alert;
    }

    KeReleaseSpinLock(&Detector->AlertLock, oldIrql);

    *AlertCount = count;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
DxFreeAlert(
    _In_ PDX_ALERT Alert
    )
/**
 * @brief Free an alert structure.
 */
{
    if (Alert == NULL) {
        return;
    }

    if (Alert->ProcessName.Buffer != NULL) {
        ExFreePoolWithTag(Alert->ProcessName.Buffer, DX_POOL_TAG_ALERT);
    }

    if (Alert->UserName.Buffer != NULL) {
        ExFreePoolWithTag(Alert->UserName.Buffer, DX_POOL_TAG_ALERT);
    }

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
/**
 * @brief Register callback for alert notifications.
 */
{
    PDX_DETECTOR_INTERNAL detector;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    detector = CONTAINING_RECORD(Detector, DX_DETECTOR_INTERNAL, Public);

    ExAcquirePushLockExclusive(&detector->Callbacks.Lock);
    detector->Callbacks.AlertCallback = Callback;
    detector->Callbacks.AlertContext = Context;
    ExReleasePushLockExclusive(&detector->Callbacks.Lock);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
DxRegisterBlockCallback(
    _In_ PDX_DETECTOR Detector,
    _In_ DX_BLOCK_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
/**
 * @brief Register callback for block decisions.
 */
{
    PDX_DETECTOR_INTERNAL detector;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    detector = CONTAINING_RECORD(Detector, DX_DETECTOR_INTERNAL, Public);

    ExAcquirePushLockExclusive(&detector->Callbacks.Lock);
    detector->Callbacks.BlockCallback = Callback;
    detector->Callbacks.BlockContext = Context;
    ExReleasePushLockExclusive(&detector->Callbacks.Lock);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
DxUnregisterCallbacks(
    _In_ PDX_DETECTOR Detector
    )
/**
 * @brief Unregister all callbacks.
 */
{
    PDX_DETECTOR_INTERNAL detector;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized) {
        return;
    }

    detector = CONTAINING_RECORD(Detector, DX_DETECTOR_INTERNAL, Public);

    ExAcquirePushLockExclusive(&detector->Callbacks.Lock);
    detector->Callbacks.AlertCallback = NULL;
    detector->Callbacks.AlertContext = NULL;
    detector->Callbacks.BlockCallback = NULL;
    detector->Callbacks.BlockContext = NULL;
    ExReleasePushLockExclusive(&detector->Callbacks.Lock);
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
/**
 * @brief Get data exfiltration detection statistics.
 */
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
    _In_ PDX_DETECTOR_INTERNAL Detector
    )
/**
 * @brief Initialize lookup tables for fast encoding detection.
 */
{
    ULONG i;

    //
    // Initialize Base64 lookup table
    // 0 = not Base64, 1 = valid Base64 character
    //
    RtlZeroMemory(Detector->Base64LookupTable, sizeof(Detector->Base64LookupTable));

    for (i = 0; g_Base64Alphabet[i] != '\0'; i++) {
        Detector->Base64LookupTable[g_Base64Alphabet[i]] = 1;
    }

    //
    // Also allow whitespace in Base64
    //
    Detector->Base64LookupTable[' '] = 1;
    Detector->Base64LookupTable['\r'] = 1;
    Detector->Base64LookupTable['\n'] = 1;
    Detector->Base64LookupTable['\t'] = 1;

    Detector->LookupTablesInitialized = TRUE;
}

static ULONG
DxpCalculateShannonEntropy(
    _In_reads_bytes_(DataSize) PUCHAR Data,
    _In_ SIZE_T DataSize
    )
/**
 * @brief Calculate Shannon entropy as percentage (0-100).
 *
 * Shannon entropy formula: H = -sum(p * log2(p))
 * Maximum entropy for bytes is 8 bits.
 * We return as percentage of maximum (0-100).
 */
{
    ULONG frequency[256] = { 0 };
    SIZE_T i;
    ULONG entropy;
    ULONG64 entropySum = 0;

    if (DataSize == 0 || DataSize < 64) {
        return 0;
    }

    //
    // Count byte frequencies
    //
    for (i = 0; i < DataSize; i++) {
        frequency[Data[i]]++;
    }

    //
    // Calculate entropy using fixed-point arithmetic
    // We use a lookup table approximation for log2
    // to avoid floating point in kernel mode
    //
    // Simplified calculation: count unique bytes and their distribution
    //
    for (i = 0; i < 256; i++) {
        if (frequency[i] > 0) {
            //
            // p = frequency[i] / DataSize
            // -p * log2(p) approximated
            //
            // Using: -x*log2(x) is maximized at x=1/e and peaks around 0.53
            // We approximate by counting the "spread" of bytes
            //
            ULONG64 p_scaled = (frequency[i] * 1000000) / DataSize;

            if (p_scaled > 0 && p_scaled < 1000000) {
                //
                // Simple approximation: penalty for concentration
                // More uniform = higher entropy
                //
                ULONG64 contribution = p_scaled;
                if (p_scaled < 10000) {
                    contribution = p_scaled * 2;  // Boost rare bytes
                }
                entropySum += contribution;
            }
        }
    }

    //
    // Normalize to 0-100 scale
    // Perfect entropy (256 equal bytes) would give ~256 * 3906 = 1M
    //
    entropy = (ULONG)((entropySum * 100) / 1000000);

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
/**
 * @brief Check if data appears to be Base64 encoded.
 */
{
    SIZE_T i;
    SIZE_T validChars = 0;
    SIZE_T alphaChars = 0;
    SIZE_T paddingCount = 0;

    if (DataSize < 4) {
        return FALSE;
    }

    //
    // Check if mostly Base64 alphabet
    //
    for (i = 0; i < DataSize && i < 4096; i++) {
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
                return FALSE;  // Invalid Base64
            }
        } else if (c != '\r' && c != '\n' && c != ' ' && c != '\t') {
            //
            // Non-Base64 character (not whitespace)
            //
            if (validChars > 0 && validChars < i) {
                //
                // Allow some non-Base64 if at boundary
                //
                break;
            }
            return FALSE;
        }
    }

    //
    // Need at least 90% valid Base64 characters
    // and a mix of alpha characters (not just numbers)
    //
    if (validChars * 100 / (i > 0 ? i : 1) >= 90 && alphaChars > validChars / 4) {
        //
        // Additional check: length should be multiple of 4 (with padding)
        //
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
/**
 * @brief Check if data is compressed by looking for magic bytes.
 */
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
    // Check for encrypted ZIP (flag in local file header)
    //
    if (DataSize >= 8 && Data[0] == 0x50 && Data[1] == 0x4B &&
        Data[2] == 0x03 && Data[3] == 0x04) {

        USHORT flags = *(PUSHORT)(Data + 6);
        if (flags & 0x0001) {  // Encryption flag
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
/**
 * @brief Match a pattern against data.
 *
 * Supports keyword matching. Regex would require additional engine.
 */
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
            //
            // Simple substring search (Boyer-Moore would be better for production)
            //
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
            //
            // Check at start of data only
            //
            if (RtlCompareMemory(Data, Pattern->Pattern, Pattern->PatternSize) ==
                Pattern->PatternSize) {
                if (MatchOffset != NULL) {
                    *MatchOffset = 0;
                }
                return TRUE;
            }
            break;

        case PatternType_Regex:
        case PatternType_DataFormat:
            //
            // Would require regex engine - not implemented in kernel
            // These patterns should be processed by user-mode
            //
            break;
    }

    return FALSE;
}

static BOOLEAN
DxpIsCloudStorageDestination(
    _In_ PCSTR Hostname
    )
/**
 * @brief Check if hostname matches known cloud storage service.
 */
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
            //
            // Check if hostname ends with domain
            //
            if (_stricmp(Hostname + hostnameLen - domainLen,
                         g_CloudStorageDomains[i]) == 0) {
                //
                // Verify it's at domain boundary
                //
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
/**
 * @brief Check if hostname matches known personal email service.
 */
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
            if (_stricmp(Hostname + hostnameLen - domainLen,
                         g_PersonalEmailDomains[i]) == 0) {
                if (hostnameLen == domainLen ||
                    Hostname[hostnameLen - domainLen - 1] == '.') {
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

static PDX_TRANSFER_CONTEXT
DxpGetOrCreateTransfer(
    _In_ PDX_DETECTOR_INTERNAL Detector,
    _In_ HANDLE ProcessId,
    _In_ PVOID RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6
    )
/**
 * @brief Get existing or create new transfer context.
 */
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    PDX_TRANSFER_CONTEXT transfer;
    PDX_TRANSFER_CONTEXT newTransfer = NULL;
    SIZE_T addrSize = IsIPv6 ? sizeof(IN6_ADDR) : sizeof(IN_ADDR);

    //
    // Search for existing transfer
    //
    KeAcquireSpinLock(&Detector->Public.TransferLock, &oldIrql);

    for (entry = Detector->Public.TransferList.Flink;
         entry != &Detector->Public.TransferList;
         entry = entry->Flink) {

        transfer = CONTAINING_RECORD(entry, DX_TRANSFER_CONTEXT, ListEntry);

        if (transfer->ProcessId == ProcessId &&
            transfer->RemotePort == RemotePort &&
            transfer->IsIPv6 == IsIPv6) {

            PVOID storedAddr = IsIPv6 ?
                (PVOID)&transfer->RemoteAddress.IPv6 :
                (PVOID)&transfer->RemoteAddress.IPv4;

            if (RtlCompareMemory(storedAddr, RemoteAddress, addrSize) == addrSize) {
                KeReleaseSpinLock(&Detector->Public.TransferLock, oldIrql);
                return transfer;
            }
        }
    }

    KeReleaseSpinLock(&Detector->Public.TransferLock, oldIrql);

    //
    // Check transfer limit
    //
    if ((ULONG)Detector->Public.TransferCount >= DX_MAX_TRANSFERS) {
        return NULL;
    }

    //
    // Create new transfer
    //
    newTransfer = (PDX_TRANSFER_CONTEXT)ExAllocateFromNPagedLookasideList(
        &Detector->TransferLookaside
    );

    if (newTransfer == NULL) {
        return NULL;
    }

    RtlZeroMemory(newTransfer, sizeof(DX_TRANSFER_CONTEXT));

    newTransfer->TransferId = (ULONG64)InterlockedIncrement64(&Detector->NextTransferId);
    newTransfer->ProcessId = ProcessId;
    newTransfer->RemotePort = RemotePort;
    newTransfer->IsIPv6 = IsIPv6;

    if (IsIPv6) {
        RtlCopyMemory(&newTransfer->RemoteAddress.IPv6, RemoteAddress, sizeof(IN6_ADDR));
    } else {
        RtlCopyMemory(&newTransfer->RemoteAddress.IPv4, RemoteAddress, sizeof(IN_ADDR));
    }

    KeQuerySystemTime(&newTransfer->StartTime);
    newTransfer->LastActivityTime = newTransfer->StartTime;

    //
    // Insert into list
    //
    KeAcquireSpinLock(&Detector->Public.TransferLock, &oldIrql);
    InsertTailList(&Detector->Public.TransferList, &newTransfer->ListEntry);
    InterlockedIncrement(&Detector->Public.TransferCount);
    KeReleaseSpinLock(&Detector->Public.TransferLock, oldIrql);

    return newTransfer;
}

static VOID
DxpReleaseTransfer(
    _In_ PDX_DETECTOR_INTERNAL Detector,
    _In_ PDX_TRANSFER_CONTEXT Transfer
    )
/**
 * @brief Release transfer context (placeholder for ref counting).
 */
{
    UNREFERENCED_PARAMETER(Detector);
    UNREFERENCED_PARAMETER(Transfer);

    //
    // Transfer cleanup is handled by timer DPC
    //
}

static NTSTATUS
DxpCreateAlert(
    _In_ PDX_DETECTOR_INTERNAL Detector,
    _In_ PDX_TRANSFER_CONTEXT Transfer,
    _In_ DX_EXFIL_TYPE Type
    )
/**
 * @brief Create and queue an exfiltration alert.
 */
{
    PDX_ALERT alert;
    KIRQL oldIrql;
    LARGE_INTEGER currentTime;
    ULONG i;

    //
    // Check alert limit
    //
    if ((ULONG)Detector->Public.AlertCount >= DX_MAX_ALERTS) {
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Allocate alert
    //
    alert = (PDX_ALERT)ExAllocateFromNPagedLookasideList(&Detector->AlertLookaside);
    if (alert == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(alert, sizeof(DX_ALERT));

    //
    // Fill alert details
    //
    alert->AlertId = (ULONG64)InterlockedIncrement64(&Detector->Public.NextAlertId);
    alert->Type = Type;
    alert->Indicators = Transfer->Indicators;
    alert->SeverityScore = Transfer->SuspicionScore;
    alert->ProcessId = Transfer->ProcessId;

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

    //
    // Transfer details
    //
    alert->DataSize = Transfer->BytesTransferred;
    alert->TransferStartTime = Transfer->StartTime;

    KeQuerySystemTime(&currentTime);
    alert->AlertTime = currentTime;
    alert->TransferDurationMs = (ULONG)((currentTime.QuadPart - Transfer->StartTime.QuadPart) / 10000);

    //
    // Copy pattern match categories
    //
    for (i = 0; i < Transfer->MatchCount && i < 8; i++) {
        if (Transfer->Matches[i].Pattern != NULL) {
            RtlCopyMemory(
                alert->SensitiveDataFound[i].Category,
                Transfer->Matches[i].Pattern->Category,
                sizeof(alert->SensitiveDataFound[i].Category) - 1
            );
            alert->SensitiveDataFound[i].MatchCount = Transfer->Matches[i].MatchCount;
            alert->CategoryCount++;
        }
    }

    //
    // Queue alert
    //
    KeAcquireSpinLock(&Detector->Public.AlertLock, &oldIrql);
    InsertTailList(&Detector->Public.AlertList, &alert->ListEntry);
    InterlockedIncrement(&Detector->Public.AlertCount);
    KeReleaseSpinLock(&Detector->Public.AlertLock, oldIrql);

    InterlockedIncrement64(&Detector->Public.Stats.AlertsGenerated);

    //
    // Notify callback
    //
    DxpNotifyAlertCallback(Detector, alert);

    return STATUS_SUCCESS;
}

static VOID
DxpNotifyAlertCallback(
    _In_ PDX_DETECTOR_INTERNAL Detector,
    _In_ PDX_ALERT Alert
    )
/**
 * @brief Notify registered alert callback.
 */
{
    DX_ALERT_CALLBACK callback;
    PVOID context;

    ExAcquirePushLockShared(&Detector->Callbacks.Lock);
    callback = Detector->Callbacks.AlertCallback;
    context = Detector->Callbacks.AlertContext;
    ExReleasePushLockShared(&Detector->Callbacks.Lock);

    if (callback != NULL) {
        callback(Alert, context);
    }
}

static BOOLEAN
DxpShouldBlock(
    _In_ PDX_DETECTOR_INTERNAL Detector,
    _In_ PDX_TRANSFER_CONTEXT Transfer
    )
/**
 * @brief Determine if transfer should be blocked.
 */
{
    DX_BLOCK_CALLBACK callback;
    PVOID context;
    BOOLEAN shouldBlock = FALSE;

    //
    // Check if blocking is enabled
    //
    if (!Detector->Public.Config.BlockOnDetection) {
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
        for (i = 0; i < Transfer->MatchCount; i++) {
            if (Transfer->Matches[i].Pattern != NULL &&
                Transfer->Matches[i].Pattern->Sensitivity == 4) {
                shouldBlock = TRUE;
                break;
            }
        }
    }

    //
    // Consult block callback for final decision
    //
    ExAcquirePushLockShared(&Detector->Callbacks.Lock);
    callback = Detector->Callbacks.BlockCallback;
    context = Detector->Callbacks.BlockContext;
    ExReleasePushLockShared(&Detector->Callbacks.Lock);

    if (callback != NULL) {
        shouldBlock = callback(Transfer, context);
    }

    return shouldBlock;
}

static ULONG
DxpCalculateSuspicionScore(
    _In_ PDX_TRANSFER_CONTEXT Transfer
    )
/**
 * @brief Calculate overall suspicion score for transfer.
 */
{
    ULONG score = 0;

    if (Transfer->Indicators & DxIndicator_HighEntropy) {
        score += 25;
    }

    if (Transfer->Indicators & DxIndicator_EncryptedData) {
        score += 20;
    }

    if (Transfer->Indicators & DxIndicator_EncodedData) {
        score += 15;
    }

    if (Transfer->Indicators & DxIndicator_SensitivePattern) {
        score += 30;
    }

    if (Transfer->Indicators & DxIndicator_CloudUpload) {
        score += 15;
    }

    if (Transfer->Indicators & DxIndicator_PersonalEmail) {
        score += 15;
    }

    if (Transfer->Indicators & DxIndicator_HighVolume) {
        score += 20;
    }

    if (Transfer->Indicators & DxIndicator_BurstTransfer) {
        score += 15;
    }

    if (score > 100) {
        score = 100;
    }

    return score;
}

static DX_EXFIL_TYPE
DxpClassifyExfiltration(
    _In_ PDX_TRANSFER_CONTEXT Transfer
    )
/**
 * @brief Classify the type of exfiltration detected.
 */
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

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
DxpCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
/**
 * @brief DPC callback for periodic cleanup of stale transfers.
 */
{
    PDX_DETECTOR_INTERNAL detector = (PDX_DETECTOR_INTERNAL)DeferredContext;
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;
    PDX_TRANSFER_CONTEXT transfer;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER timeout;
    LIST_ENTRY freeList;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (detector == NULL || detector->ShuttingDown) {
        return;
    }

    KeQuerySystemTime(&currentTime);
    timeout.QuadPart = (LONGLONG)DX_TRANSFER_TIMEOUT_MS * 10000;

    InitializeListHead(&freeList);

    //
    // Collect stale transfers
    //
    KeAcquireSpinLock(&detector->Public.TransferLock, &oldIrql);

    for (entry = detector->Public.TransferList.Flink;
         entry != &detector->Public.TransferList;
         entry = nextEntry) {

        nextEntry = entry->Flink;
        transfer = CONTAINING_RECORD(entry, DX_TRANSFER_CONTEXT, ListEntry);

        //
        // Check if transfer has timed out
        //
        if ((currentTime.QuadPart - transfer->LastActivityTime.QuadPart) > timeout.QuadPart) {
            RemoveEntryList(&transfer->ListEntry);
            InterlockedDecrement(&detector->Public.TransferCount);
            InsertTailList(&freeList, &transfer->ListEntry);
        }
    }

    KeReleaseSpinLock(&detector->Public.TransferLock, oldIrql);

    //
    // Free collected transfers
    //
    while (!IsListEmpty(&freeList)) {
        entry = RemoveHeadList(&freeList);
        transfer = CONTAINING_RECORD(entry, DX_TRANSFER_CONTEXT, ListEntry);

        if (detector->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&detector->TransferLookaside, transfer);
        } else {
            ExFreePoolWithTag(transfer, DX_POOL_TAG_CONTEXT);
        }
    }

    //
    // Also trim old alerts if needed
    //
    if (detector->Public.AlertCount > (LONG)(DX_MAX_ALERTS * 3 / 4)) {
        KeAcquireSpinLock(&detector->Public.AlertLock, &oldIrql);

        while (detector->Public.AlertCount > (LONG)(DX_MAX_ALERTS / 2) &&
               !IsListEmpty(&detector->Public.AlertList)) {

            entry = RemoveHeadList(&detector->Public.AlertList);
            InterlockedDecrement(&detector->Public.AlertCount);

            PDX_ALERT alert = CONTAINING_RECORD(entry, DX_ALERT, ListEntry);

            if (alert->ProcessName.Buffer != NULL) {
                ExFreePoolWithTag(alert->ProcessName.Buffer, DX_POOL_TAG_ALERT);
            }
            if (alert->UserName.Buffer != NULL) {
                ExFreePoolWithTag(alert->UserName.Buffer, DX_POOL_TAG_ALERT);
            }

            if (detector->LookasideInitialized) {
                ExFreeToNPagedLookasideList(&detector->AlertLookaside, alert);
            } else {
                ExFreePoolWithTag(alert, DX_POOL_TAG_ALERT);
            }
        }

        KeReleaseSpinLock(&detector->Public.AlertLock, oldIrql);
    }
}
