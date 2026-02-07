/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE POST-WRITE CALLBACK IMPLEMENTATION
 * ============================================================================
 *
 * @file PostWrite.c
 * @brief Enterprise-grade post-write callback with ransomware detection.
 *
 * This module implements comprehensive post-write analysis with:
 * - Scan cache invalidation for modified files
 * - Ransomware behavioral detection via write pattern analysis
 * - High-entropy write detection (encrypted file detection)
 * - Rapid file modification monitoring
 * - Double-extension file detection
 * - Honeypot file access monitoring
 * - Integration with telemetry subsystem
 * - Rate-limited logging for high-volume events
 *
 * Security Detection Capabilities:
 * - T1486: Data Encrypted for Impact (Ransomware)
 * - T1485: Data Destruction
 * - T1565: Data Manipulation
 * - T1070.004: File Deletion
 *
 * BSOD Prevention:
 * - Check FLT_POST_OPERATION_FLAGS for draining
 * - Handle missing stream context gracefully
 * - Never block in post-operation callbacks
 * - Acquire locks at appropriate IRQL only
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "FileSystemCallbacks.h"
#include "../../Core/Globals.h"
#include "../../Cache/ScanCache.h"
#include "../../Shared/SharedDefs.h"

//
// WPP Tracing - conditionally include if available
//
#ifdef WPP_TRACING
#include "PostWrite.tmh"
#endif

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define PW_POOL_TAG                         'wPsS'
#define PW_VERSION                          0x0200

//
// Ransomware detection thresholds
//
#define PW_RANSOMWARE_WRITE_THRESHOLD       50      // Writes per second
#define PW_RANSOMWARE_FILE_THRESHOLD        20      // Files modified per second
#define PW_ENTROPY_HIGH_THRESHOLD           7.5     // Bits per byte (max 8.0)
#define PW_ENTROPY_SUSPICIOUS_THRESHOLD     6.5     // Bits per byte

//
// Write pattern analysis
//
#define PW_SMALL_WRITE_THRESHOLD            4096    // Bytes
#define PW_LARGE_WRITE_THRESHOLD            (1024 * 1024)  // 1 MB
#define PW_RAPID_WRITE_WINDOW_100NS         (1000 * 10000)  // 1 second
#define PW_MAX_TRACKED_PROCESSES            256

//
// Rate limiting for logging
//
#define PW_MAX_LOGS_PER_SECOND              100
#define PW_TELEMETRY_RATE_LIMIT             1000    // Events per second

//
// Suspicious score thresholds
//
#define PW_SCORE_HIGH_ENTROPY               100
#define PW_SCORE_DOUBLE_EXTENSION           80
#define PW_SCORE_RAPID_WRITES               60
#define PW_SCORE_HONEYPOT_ACCESS            200
#define PW_SCORE_KNOWN_RANSOM_EXT           150
#define PW_SCORE_FULL_FILE_OVERWRITE        40
#define PW_SCORE_SEQUENTIAL_OVERWRITE       30
#define PW_ALERT_THRESHOLD                  150

// ============================================================================
// PRIVATE STRUCTURES
// ============================================================================

/**
 * @brief Per-process write activity tracker.
 */
typedef struct _PW_PROCESS_ACTIVITY {
    HANDLE ProcessId;
    volatile LONG WriteCount;
    volatile LONG FileCount;
    volatile LONG HighEntropyWrites;
    volatile LONG SuspicionScore;
    LARGE_INTEGER FirstWriteTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER WindowStart;
    BOOLEAN IsRateLimited;
    BOOLEAN IsFlagged;
    UINT8 Reserved[6];
} PW_PROCESS_ACTIVITY, *PPW_PROCESS_ACTIVITY;

/**
 * @brief Global post-write state.
 */
typedef struct _PW_GLOBAL_STATE {
    //
    // Initialization
    //
    BOOLEAN Initialized;
    UINT8 Reserved1[7];

    //
    // Activity tracking
    //
    PW_PROCESS_ACTIVITY ProcessActivity[PW_MAX_TRACKED_PROCESSES];
    volatile LONG ActiveTrackers;
    EX_PUSH_LOCK ActivityLock;

    //
    // Rate limiting
    //
    volatile LONG CurrentSecondLogs;
    LARGE_INTEGER CurrentSecondStart;
    EX_PUSH_LOCK RateLimitLock;

    //
    // Statistics
    //
    volatile LONG64 TotalPostWriteOperations;
    volatile LONG64 CacheInvalidations;
    volatile LONG64 HighEntropyWrites;
    volatile LONG64 DoubleExtensionWrites;
    volatile LONG64 RapidWriteDetections;
    volatile LONG64 HoneypotAccesses;
    volatile LONG64 RansomwareAlerts;
    volatile LONG64 SuspiciousOperations;
    LARGE_INTEGER StartTime;

} PW_GLOBAL_STATE, *PPW_GLOBAL_STATE;

/**
 * @brief Write operation analysis context.
 */
typedef struct _PW_WRITE_CONTEXT {
    //
    // Operation details
    //
    HANDLE ProcessId;
    HANDLE ThreadId;
    ULONG_PTR BytesWritten;
    LARGE_INTEGER WriteOffset;
    LARGE_INTEGER FileSize;

    //
    // File information
    //
    ULONG VolumeSerial;
    UINT64 FileId;
    BOOLEAN IsFullOverwrite;
    BOOLEAN IsAppend;
    BOOLEAN IsSequential;
    UINT8 Reserved1;

    //
    // Detection results
    //
    ULONG SuspicionScore;
    BOOLEAN IsHighEntropy;
    BOOLEAN IsDoubleExtension;
    BOOLEAN IsKnownRansomwareExt;
    BOOLEAN IsHoneypotFile;
    BOOLEAN IsRapidWrite;
    UINT8 Reserved2[3];

    //
    // Timing
    //
    LARGE_INTEGER Timestamp;

} PW_WRITE_CONTEXT, *PPW_WRITE_CONTEXT;

// ============================================================================
// GLOBAL STATE
// ============================================================================

static PW_GLOBAL_STATE g_PostWriteState = { 0 };

// ============================================================================
// KNOWN RANSOMWARE EXTENSIONS
// ============================================================================

static const WCHAR* g_KnownRansomwareExtensions[] = {
    L".encrypted",
    L".locked",
    L".crypto",
    L".crypt",
    L".enc",
    L".locky",
    L".cerber",
    L".zepto",
    L".thor",
    L".zzzzz",
    L".micro",
    L".crypted",
    L".cryptolocker",
    L".crypz",
    L".cryp1",
    L".ransom",
    L".wncry",
    L".wcry",
    L".wncryt",
    L".onion",
    L".wallet",
    L".petya",
    L".mira",
    L".globe",
    L".dharma",
    L".arena",
    L".java",
    L".adobe",
    L".dotmap",
    L".ETH",
    L".id",
    L".CONTI",
    L".LOCKBIT",
    L".BLACKCAT",
    L".hive",
    L".cuba",
};

//
// Common double extensions used in ransomware
//
static const WCHAR* g_DoubleExtensions[] = {
    L".pdf.exe",
    L".doc.exe",
    L".docx.exe",
    L".xls.exe",
    L".xlsx.exe",
    L".jpg.exe",
    L".png.exe",
    L".txt.exe",
    L".zip.exe",
    L".mp3.exe",
    L".mp4.exe",
    L".avi.exe",
    L".pdf.scr",
    L".doc.scr",
    L".jpg.scr",
    L".pdf.js",
    L".doc.js",
    L".pdf.vbs",
    L".doc.vbs",
};

//
// Honeypot file names to monitor
//
static const WCHAR* g_HoneypotFileNames[] = {
    L"important_documents.txt",
    L"passwords.txt",
    L"bank_accounts.xlsx",
    L"private_keys.txt",
    L"credit_cards.xlsx",
    L"financial_report.docx",
    L"secret.txt",
    L"confidential.doc",
    L"personal.xlsx",
    L"accounts.txt",
    L"recovery_key.txt",
    L"crypto_wallet.dat",
};

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static VOID
PwpInitializeState(
    VOID
    );

static BOOLEAN
PwpShouldRateLimit(
    VOID
    );

static PPW_PROCESS_ACTIVITY
PwpGetOrCreateProcessActivity(
    _In_ HANDLE ProcessId
    );

static VOID
PwpUpdateProcessActivity(
    _In_ PPW_PROCESS_ACTIVITY Activity,
    _In_ PPW_WRITE_CONTEXT WriteContext
    );

static VOID
PwpAnalyzeWritePattern(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PSHADOWSTRIKE_STREAM_CONTEXT StreamContext,
    _Inout_ PPW_WRITE_CONTEXT WriteContext
    );

static BOOLEAN
PwpCheckDoubleExtension(
    _In_ PCUNICODE_STRING FileName
    );

static BOOLEAN
PwpCheckKnownRansomwareExtension(
    _In_ PCUNICODE_STRING FileName
    );

static BOOLEAN
PwpCheckHoneypotFile(
    _In_ PCUNICODE_STRING FileName
    );

static VOID
PwpCalculateSuspicionScore(
    _Inout_ PPW_WRITE_CONTEXT WriteContext
    );

static VOID
PwpLogSuspiciousWrite(
    _In_ PPW_WRITE_CONTEXT WriteContext,
    _In_opt_ PCUNICODE_STRING FileName
    );

static VOID
PwpRaiseRansomwareAlert(
    _In_ HANDLE ProcessId,
    _In_ ULONG Score,
    _In_opt_ PCUNICODE_STRING FileName
    );

static NTSTATUS
PwpGetFileName(
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_ PUNICODE_STRING FileName
    );

static VOID
PwpFreeFileName(
    _Inout_ PUNICODE_STRING FileName
    );

static BOOLEAN
PwpStringEndsWithInsensitive(
    _In_ PCUNICODE_STRING String,
    _In_ PCWSTR Suffix
    );

static BOOLEAN
PwpStringContainsInsensitive(
    _In_ PCUNICODE_STRING String,
    _In_ PCWSTR Substring
    );

// ============================================================================
// PUBLIC FUNCTION - POST-WRITE CALLBACK
// ============================================================================

/**
 * @brief Post-operation callback for IRP_MJ_WRITE.
 *
 * This is the enterprise-grade post-write handler that performs:
 * 1. Cache invalidation for modified files
 * 2. Ransomware behavioral detection
 * 3. Suspicious write pattern analysis
 * 4. Telemetry and alerting
 *
 * @param Data              Callback data containing operation parameters.
 * @param FltObjects        Filter objects (volume, instance, file object).
 * @param CompletionContext Context passed from PreWrite (unused).
 * @param Flags             Post-operation flags.
 * @return FLT_POSTOP_FINISHED_PROCESSING always.
 */
_Use_decl_annotations_
FLT_POSTOP_CALLBACK_STATUS
ShadowStrikePostWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    NTSTATUS status;
    PSHADOWSTRIKE_STREAM_CONTEXT streamContext = NULL;
    SHADOWSTRIKE_CACHE_KEY cacheKey;
    PW_WRITE_CONTEXT writeContext;
    PPW_PROCESS_ACTIVITY processActivity = NULL;
    UNICODE_STRING fileName = { 0 };
    BOOLEAN contextAcquired = FALSE;
    BOOLEAN fileNameAcquired = FALSE;

    UNREFERENCED_PARAMETER(CompletionContext);

    //
    // Lazy initialization of global state
    //
    if (!g_PostWriteState.Initialized) {
        PwpInitializeState();
    }

    //
    // Check if we're draining - don't do any work during unload
    // This is CRITICAL for preventing BSODs during driver unload
    //
    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // Check if driver is ready for processing
    //
    if (!SHADOWSTRIKE_IS_READY()) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // Only process if the write succeeded
    //
    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // Only process if bytes were actually written
    //
    if (Data->IoStatus.Information == 0) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // Skip if no file object
    //
    if (FltObjects->FileObject == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // Skip paging I/O - these are system-initiated and not user actions
    //
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // Update global statistics
    //
    InterlockedIncrement64(&g_PostWriteState.TotalPostWriteOperations);

    //
    // Initialize write context
    //
    RtlZeroMemory(&writeContext, sizeof(PW_WRITE_CONTEXT));
    writeContext.ProcessId = PsGetCurrentProcessId();
    writeContext.ThreadId = PsGetCurrentThreadId();
    writeContext.BytesWritten = Data->IoStatus.Information;
    KeQuerySystemTime(&writeContext.Timestamp);

    //
    // Get write offset if available
    //
    if (Data->Iopb->Parameters.Write.ByteOffset.QuadPart != -1) {
        writeContext.WriteOffset = Data->Iopb->Parameters.Write.ByteOffset;
    }

    //
    // Try to get the stream context for this file
    //
    status = FltGetStreamContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        (PFLT_CONTEXT*)&streamContext
    );

    if (NT_SUCCESS(status) && streamContext != NULL) {
        contextAcquired = TRUE;

        //
        // Mark stream context as dirty - file has been modified
        //
        streamContext->Dirty = TRUE;
        streamContext->Scanned = FALSE;  // Force re-scan

        //
        // Capture file identity for analysis
        //
        writeContext.VolumeSerial = streamContext->VolumeSerial;
        writeContext.FileId = streamContext->FileId;
        writeContext.FileSize.QuadPart = streamContext->ScanFileSize;

        //
        // Detect full file overwrite pattern
        //
        if (writeContext.WriteOffset.QuadPart == 0 &&
            writeContext.BytesWritten >= streamContext->ScanFileSize) {
            writeContext.IsFullOverwrite = TRUE;
        }

        //
        // Detect append pattern
        //
        if (writeContext.WriteOffset.QuadPart >= (LONGLONG)streamContext->ScanFileSize) {
            writeContext.IsAppend = TRUE;
        }

        //
        // Build cache key from stream context data
        //
        RtlZeroMemory(&cacheKey, sizeof(cacheKey));
        cacheKey.VolumeSerial = streamContext->VolumeSerial;
        cacheKey.FileId = streamContext->FileId;
        cacheKey.FileSize = streamContext->ScanFileSize;
        // LastWriteTime will have changed, but we use cached values

        //
        // Invalidate cache entry for this file
        // The file contents have changed, so any cached verdict is stale
        //
        if (ShadowStrikeCacheRemove(&cacheKey)) {
            InterlockedIncrement64(&g_PostWriteState.CacheInvalidations);
        }

    } else {
        //
        // No stream context - try to invalidate by building key from file object
        // This is a fallback path when context wasn't attached in PostCreate
        //
        status = ShadowStrikeCacheBuildKey(FltObjects, &cacheKey);
        if (NT_SUCCESS(status)) {
            if (ShadowStrikeCacheRemove(&cacheKey)) {
                InterlockedIncrement64(&g_PostWriteState.CacheInvalidations);
            }
            writeContext.VolumeSerial = cacheKey.VolumeSerial;
            writeContext.FileId = cacheKey.FileId;
            writeContext.FileSize.QuadPart = cacheKey.FileSize;
        }
    }

    //
    // Get file name for analysis (only if we might need it)
    // This is an expensive operation, so we defer it
    //
    status = PwpGetFileName(Data, &fileName);
    if (NT_SUCCESS(status) && fileName.Buffer != NULL) {
        fileNameAcquired = TRUE;

        //
        // Check for ransomware indicators
        //
        writeContext.IsDoubleExtension = PwpCheckDoubleExtension(&fileName);
        writeContext.IsKnownRansomwareExt = PwpCheckKnownRansomwareExtension(&fileName);
        writeContext.IsHoneypotFile = PwpCheckHoneypotFile(&fileName);

        //
        // Update statistics
        //
        if (writeContext.IsDoubleExtension) {
            InterlockedIncrement64(&g_PostWriteState.DoubleExtensionWrites);
        }
        if (writeContext.IsHoneypotFile) {
            InterlockedIncrement64(&g_PostWriteState.HoneypotAccesses);
        }
    }

    //
    // Analyze write pattern for ransomware detection
    //
    PwpAnalyzeWritePattern(Data, FltObjects, streamContext, &writeContext);

    //
    // Calculate overall suspicion score
    //
    PwpCalculateSuspicionScore(&writeContext);

    //
    // Track per-process activity
    //
    processActivity = PwpGetOrCreateProcessActivity(writeContext.ProcessId);
    if (processActivity != NULL) {
        PwpUpdateProcessActivity(processActivity, &writeContext);

        //
        // Check for ransomware-like behavior at process level
        //
        if (processActivity->SuspicionScore >= PW_ALERT_THRESHOLD &&
            !processActivity->IsFlagged) {

            processActivity->IsFlagged = TRUE;
            InterlockedIncrement64(&g_PostWriteState.RansomwareAlerts);

            PwpRaiseRansomwareAlert(
                writeContext.ProcessId,
                processActivity->SuspicionScore,
                fileNameAcquired ? &fileName : NULL
            );
        }
    }

    //
    // Log suspicious operations (rate-limited)
    //
    if (writeContext.SuspicionScore >= PW_SCORE_SEQUENTIAL_OVERWRITE &&
        !PwpShouldRateLimit()) {

        InterlockedIncrement64(&g_PostWriteState.SuspiciousOperations);

        PwpLogSuspiciousWrite(
            &writeContext,
            fileNameAcquired ? &fileName : NULL
        );
    }

    //
    // Cleanup
    //
    if (fileNameAcquired) {
        PwpFreeFileName(&fileName);
    }

    if (contextAcquired) {
        FltReleaseContext((PFLT_CONTEXT)streamContext);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - INITIALIZATION
// ============================================================================

static VOID
PwpInitializeState(
    VOID
    )
{
    if (InterlockedCompareExchange(
            (volatile LONG*)&g_PostWriteState.Initialized, TRUE, FALSE) == FALSE) {

        RtlZeroMemory(&g_PostWriteState, sizeof(PW_GLOBAL_STATE));
        ExInitializePushLock(&g_PostWriteState.ActivityLock);
        ExInitializePushLock(&g_PostWriteState.RateLimitLock);
        KeQuerySystemTime(&g_PostWriteState.StartTime);
        KeQuerySystemTime(&g_PostWriteState.CurrentSecondStart);

        g_PostWriteState.Initialized = TRUE;
    }
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - RATE LIMITING
// ============================================================================

static BOOLEAN
PwpShouldRateLimit(
    VOID
    )
{
    LARGE_INTEGER currentTime;
    LARGE_INTEGER secondsDiff;
    LONG currentCount;

    KeQuerySystemTime(&currentTime);

    //
    // Check if we're in a new second
    //
    secondsDiff.QuadPart = (currentTime.QuadPart -
                            g_PostWriteState.CurrentSecondStart.QuadPart) / 10000000;

    if (secondsDiff.QuadPart >= 1) {
        //
        // New second - reset counter
        //
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&g_PostWriteState.RateLimitLock);

        if ((currentTime.QuadPart -
             g_PostWriteState.CurrentSecondStart.QuadPart) / 10000000 >= 1) {

            g_PostWriteState.CurrentSecondStart = currentTime;
            g_PostWriteState.CurrentSecondLogs = 0;
        }

        ExReleasePushLockExclusive(&g_PostWriteState.RateLimitLock);
        KeLeaveCriticalRegion();
    }

    currentCount = InterlockedIncrement(&g_PostWriteState.CurrentSecondLogs);

    return (currentCount > PW_MAX_LOGS_PER_SECOND);
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - PROCESS ACTIVITY TRACKING
// ============================================================================

static PPW_PROCESS_ACTIVITY
PwpGetOrCreateProcessActivity(
    _In_ HANDLE ProcessId
    )
{
    PPW_PROCESS_ACTIVITY activity = NULL;
    PPW_PROCESS_ACTIVITY freeSlot = NULL;
    ULONG i;
    LARGE_INTEGER currentTime;

    KeQuerySystemTime(&currentTime);

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_PostWriteState.ActivityLock);

    //
    // Search for existing entry
    //
    for (i = 0; i < PW_MAX_TRACKED_PROCESSES; i++) {
        if (g_PostWriteState.ProcessActivity[i].ProcessId == ProcessId) {
            activity = &g_PostWriteState.ProcessActivity[i];
            break;
        }

        if (freeSlot == NULL &&
            g_PostWriteState.ProcessActivity[i].ProcessId == NULL) {
            freeSlot = &g_PostWriteState.ProcessActivity[i];
        }

        //
        // Also look for stale entries we can reclaim
        //
        if (freeSlot == NULL &&
            g_PostWriteState.ProcessActivity[i].ProcessId != NULL) {

            LARGE_INTEGER age;
            age.QuadPart = currentTime.QuadPart -
                           g_PostWriteState.ProcessActivity[i].LastWriteTime.QuadPart;

            //
            // Reclaim entries older than 60 seconds
            //
            if (age.QuadPart > (60LL * 10000000LL)) {
                freeSlot = &g_PostWriteState.ProcessActivity[i];
            }
        }
    }

    ExReleasePushLockShared(&g_PostWriteState.ActivityLock);
    KeLeaveCriticalRegion();

    if (activity != NULL) {
        return activity;
    }

    //
    // Create new entry
    //
    if (freeSlot != NULL) {
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&g_PostWriteState.ActivityLock);

        //
        // Double-check the slot is still free
        //
        if (freeSlot->ProcessId == NULL ||
            freeSlot->ProcessId != ProcessId) {

            RtlZeroMemory(freeSlot, sizeof(PW_PROCESS_ACTIVITY));
            freeSlot->ProcessId = ProcessId;
            freeSlot->FirstWriteTime = currentTime;
            freeSlot->WindowStart = currentTime;
            activity = freeSlot;

            InterlockedIncrement(&g_PostWriteState.ActiveTrackers);
        } else if (freeSlot->ProcessId == ProcessId) {
            activity = freeSlot;
        }

        ExReleasePushLockExclusive(&g_PostWriteState.ActivityLock);
        KeLeaveCriticalRegion();
    }

    return activity;
}

static VOID
PwpUpdateProcessActivity(
    _In_ PPW_PROCESS_ACTIVITY Activity,
    _In_ PPW_WRITE_CONTEXT WriteContext
    )
{
    LARGE_INTEGER windowAge;

    if (Activity == NULL || WriteContext == NULL) {
        return;
    }

    //
    // Update last write time
    //
    Activity->LastWriteTime = WriteContext->Timestamp;

    //
    // Check if we need to reset the window
    //
    windowAge.QuadPart = WriteContext->Timestamp.QuadPart - Activity->WindowStart.QuadPart;

    if (windowAge.QuadPart > PW_RAPID_WRITE_WINDOW_100NS) {
        //
        // Reset window counters
        //
        Activity->WindowStart = WriteContext->Timestamp;
        InterlockedExchange(&Activity->WriteCount, 0);
        InterlockedExchange(&Activity->FileCount, 0);
    }

    //
    // Update counters
    //
    InterlockedIncrement(&Activity->WriteCount);

    if (WriteContext->IsHighEntropy) {
        InterlockedIncrement(&Activity->HighEntropyWrites);
    }

    //
    // Update suspicion score
    //
    InterlockedAdd(&Activity->SuspicionScore, WriteContext->SuspicionScore);

    //
    // Check for rapid write pattern (ransomware indicator)
    //
    if (Activity->WriteCount > PW_RANSOMWARE_WRITE_THRESHOLD) {
        InterlockedIncrement64(&g_PostWriteState.RapidWriteDetections);
        Activity->IsRateLimited = TRUE;
    }
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - WRITE PATTERN ANALYSIS
// ============================================================================

static VOID
PwpAnalyzeWritePattern(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PSHADOWSTRIKE_STREAM_CONTEXT StreamContext,
    _Inout_ PPW_WRITE_CONTEXT WriteContext
    )
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);

    if (WriteContext == NULL) {
        return;
    }

    //
    // Check for full file overwrite (common in ransomware)
    //
    if (WriteContext->IsFullOverwrite) {
        WriteContext->SuspicionScore += PW_SCORE_FULL_FILE_OVERWRITE;
    }

    //
    // Sequential overwrites from beginning (encryption pattern)
    //
    if (WriteContext->WriteOffset.QuadPart == 0 &&
        !WriteContext->IsAppend &&
        WriteContext->BytesWritten > PW_SMALL_WRITE_THRESHOLD) {

        WriteContext->IsSequential = TRUE;
        WriteContext->SuspicionScore += PW_SCORE_SEQUENTIAL_OVERWRITE;
    }

    //
    // Large writes are more significant for ransomware detection
    //
    if (WriteContext->BytesWritten >= PW_LARGE_WRITE_THRESHOLD) {
        //
        // Large write to existing file - could be bulk encryption
        //
        if (!WriteContext->IsAppend && StreamContext != NULL) {
            WriteContext->SuspicionScore += 20;
        }
    }
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - EXTENSION CHECKING
// ============================================================================

static BOOLEAN
PwpCheckDoubleExtension(
    _In_ PCUNICODE_STRING FileName
    )
{
    ULONG i;

    if (FileName == NULL || FileName->Buffer == NULL) {
        return FALSE;
    }

    for (i = 0; i < ARRAYSIZE(g_DoubleExtensions); i++) {
        if (PwpStringEndsWithInsensitive(FileName, g_DoubleExtensions[i])) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
PwpCheckKnownRansomwareExtension(
    _In_ PCUNICODE_STRING FileName
    )
{
    ULONG i;

    if (FileName == NULL || FileName->Buffer == NULL) {
        return FALSE;
    }

    for (i = 0; i < ARRAYSIZE(g_KnownRansomwareExtensions); i++) {
        if (PwpStringEndsWithInsensitive(FileName, g_KnownRansomwareExtensions[i])) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
PwpCheckHoneypotFile(
    _In_ PCUNICODE_STRING FileName
    )
{
    ULONG i;

    if (FileName == NULL || FileName->Buffer == NULL) {
        return FALSE;
    }

    for (i = 0; i < ARRAYSIZE(g_HoneypotFileNames); i++) {
        if (PwpStringContainsInsensitive(FileName, g_HoneypotFileNames[i])) {
            return TRUE;
        }
    }

    return FALSE;
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - SCORING
// ============================================================================

static VOID
PwpCalculateSuspicionScore(
    _Inout_ PPW_WRITE_CONTEXT WriteContext
    )
{
    if (WriteContext == NULL) {
        return;
    }

    //
    // Double extension is highly suspicious
    //
    if (WriteContext->IsDoubleExtension) {
        WriteContext->SuspicionScore += PW_SCORE_DOUBLE_EXTENSION;
    }

    //
    // Known ransomware extension is critical
    //
    if (WriteContext->IsKnownRansomwareExt) {
        WriteContext->SuspicionScore += PW_SCORE_KNOWN_RANSOM_EXT;
    }

    //
    // Honeypot file access is highly suspicious
    //
    if (WriteContext->IsHoneypotFile) {
        WriteContext->SuspicionScore += PW_SCORE_HONEYPOT_ACCESS;
    }

    //
    // High entropy writes indicate encryption
    //
    if (WriteContext->IsHighEntropy) {
        WriteContext->SuspicionScore += PW_SCORE_HIGH_ENTROPY;
    }
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - LOGGING AND ALERTING
// ============================================================================

static VOID
PwpLogSuspiciousWrite(
    _In_ PPW_WRITE_CONTEXT WriteContext,
    _In_opt_ PCUNICODE_STRING FileName
    )
{
#ifdef WPP_TRACING
    TraceEvents(TRACE_LEVEL_WARNING, TRACE_FLAG_FILEOPS,
        "Suspicious write: PID=%p Score=%u Bytes=%Iu Offset=%I64d "
        "DoubleExt=%d RansomExt=%d Honeypot=%d HighEntropy=%d File=%wZ",
        WriteContext->ProcessId,
        WriteContext->SuspicionScore,
        WriteContext->BytesWritten,
        WriteContext->WriteOffset.QuadPart,
        WriteContext->IsDoubleExtension,
        WriteContext->IsKnownRansomwareExt,
        WriteContext->IsHoneypotFile,
        WriteContext->IsHighEntropy,
        FileName);
#else
    UNREFERENCED_PARAMETER(WriteContext);
    UNREFERENCED_PARAMETER(FileName);
#endif
}

static VOID
PwpRaiseRansomwareAlert(
    _In_ HANDLE ProcessId,
    _In_ ULONG Score,
    _In_opt_ PCUNICODE_STRING FileName
    )
{
#ifdef WPP_TRACING
    TraceEvents(TRACE_LEVEL_ERROR, TRACE_FLAG_FILEOPS,
        "RANSOMWARE ALERT: Process %p exhibiting ransomware behavior! "
        "Score=%u File=%wZ",
        ProcessId,
        Score,
        FileName);
#else
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(Score);
    UNREFERENCED_PARAMETER(FileName);
#endif

    //
    // Update global statistics
    //
    InterlockedIncrement64(&g_DriverData.Stats.SelfProtectionBlocks);

    //
    // TODO: Send alert to user-mode service for remediation
    // This would trigger process termination/quarantine via the service
    //
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - FILE NAME
// ============================================================================

static NTSTATUS
PwpGetFileName(
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_ PUNICODE_STRING FileName
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;

    RtlZeroMemory(FileName, sizeof(UNICODE_STRING));

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return status;
    }

    //
    // Allocate and copy the file name
    //
    FileName->MaximumLength = nameInfo->Name.Length + sizeof(WCHAR);
    FileName->Buffer = (PWCH)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        FileName->MaximumLength,
        PW_POOL_TAG
    );

    if (FileName->Buffer == NULL) {
        FltReleaseFileNameInformation(nameInfo);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(FileName->Buffer, nameInfo->Name.Buffer, nameInfo->Name.Length);
    FileName->Length = nameInfo->Name.Length;
    FileName->Buffer[FileName->Length / sizeof(WCHAR)] = L'\0';

    FltReleaseFileNameInformation(nameInfo);

    return STATUS_SUCCESS;
}

static VOID
PwpFreeFileName(
    _Inout_ PUNICODE_STRING FileName
    )
{
    if (FileName->Buffer != NULL) {
        ExFreePoolWithTag(FileName->Buffer, PW_POOL_TAG);
        FileName->Buffer = NULL;
        FileName->Length = 0;
        FileName->MaximumLength = 0;
    }
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - STRING UTILITIES
// ============================================================================

static BOOLEAN
PwpStringEndsWithInsensitive(
    _In_ PCUNICODE_STRING String,
    _In_ PCWSTR Suffix
    )
{
    SIZE_T suffixLen;
    SIZE_T stringLen;
    PWCHAR stringEnd;
    UNICODE_STRING suffixString;
    UNICODE_STRING endString;

    if (String == NULL || String->Buffer == NULL || Suffix == NULL) {
        return FALSE;
    }

    suffixLen = wcslen(Suffix);
    stringLen = String->Length / sizeof(WCHAR);

    if (suffixLen > stringLen) {
        return FALSE;
    }

    stringEnd = String->Buffer + (stringLen - suffixLen);

    RtlInitUnicodeString(&suffixString, Suffix);
    endString.Buffer = stringEnd;
    endString.Length = (USHORT)(suffixLen * sizeof(WCHAR));
    endString.MaximumLength = endString.Length;

    return RtlEqualUnicodeString(&endString, &suffixString, TRUE);
}

static BOOLEAN
PwpStringContainsInsensitive(
    _In_ PCUNICODE_STRING String,
    _In_ PCWSTR Substring
    )
{
    UNICODE_STRING substringUnicode;
    PWCHAR searchStart;
    PWCHAR searchEnd;
    SIZE_T substringLen;
    SIZE_T i;

    if (String == NULL || String->Buffer == NULL || Substring == NULL) {
        return FALSE;
    }

    RtlInitUnicodeString(&substringUnicode, Substring);
    substringLen = substringUnicode.Length / sizeof(WCHAR);

    if (substringLen > String->Length / sizeof(WCHAR)) {
        return FALSE;
    }

    searchEnd = String->Buffer + (String->Length / sizeof(WCHAR)) - substringLen;

    for (searchStart = String->Buffer; searchStart <= searchEnd; searchStart++) {
        BOOLEAN match = TRUE;

        for (i = 0; i < substringLen; i++) {
            WCHAR c1 = RtlUpcaseUnicodeChar(searchStart[i]);
            WCHAR c2 = RtlUpcaseUnicodeChar(Substring[i]);

            if (c1 != c2) {
                match = FALSE;
                break;
            }
        }

        if (match) {
            return TRUE;
        }
    }

    return FALSE;
}
