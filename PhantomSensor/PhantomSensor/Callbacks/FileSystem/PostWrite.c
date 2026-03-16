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
 * - Process termination cleanup via notify callback
 * - Time-based suspicion score decay
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
 * - Proper initialization synchronization with memory barriers
 * - Process notify callback for cleanup on process exit
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition - Security Hardened)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#pragma warning(push)
#pragma warning(disable: 4324)  // structure was padded due to alignment specifier (fltKernel.h)
#include "FileSystemCallbacks.h"
#pragma warning(pop)
#include "../../Core/Globals.h"
#include "../../Cache/ScanCache.h"
#include "../../Shared/SharedDefs.h"
#include "../../Communication/CommPort.h"
#include "../../../Shared/MessageTypes.h"
#include "../../Behavioral/BehaviorEngine.h"
#include "../../Exclusions/ExclusionManager.h"
#include "../../Transactions/KtmMonitor.h"
#include "../../ETW/ETWConsumer.h"
#include "../../ETW/ETWProvider.h"
#include "../../Core/DriverEntry.h"

//
// WPP Tracing - conditionally include if available
//
#ifdef WPP_TRACING
#include "PostWrite.tmh"
#endif

// ============================================================================
// COMPILE-TIME ASSERTIONS FOR STRUCTURE ALIGNMENT
// ============================================================================

C_ASSERT(sizeof(SHADOWSTRIKE_STREAM_CONTEXT) % 8 == 0);

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define PW_POOL_TAG                         'wPsS'
#define PW_VERSION                          0x0300

//
// Ransomware detection thresholds
//
#define PW_RANSOMWARE_WRITE_THRESHOLD       50      // Writes per window
#define PW_RANSOMWARE_FILE_THRESHOLD        20      // Unique files per window
#define PW_ENTROPY_HIGH_THRESHOLD_X100      750     // 7.50 bits/byte (scaled by 100)
#define PW_ENTROPY_SUSPICIOUS_THRESHOLD_X100 650    // 6.50 bits/byte (scaled by 100)
#define PW_ENTROPY_SAMPLE_SIZE              256     // Bytes to sample for entropy

//
// Write pattern analysis
//
#define PW_SMALL_WRITE_THRESHOLD            4096    // Bytes
#define PW_LARGE_WRITE_THRESHOLD            (1024 * 1024)  // 1 MB
#define PW_RAPID_WRITE_WINDOW_100NS         (1000LL * 10000LL)  // 1 second
#define PW_MAX_TRACKED_PROCESSES            256
#define PW_MAX_TRACKED_FILES_PER_PROCESS    64

//
// Rate limiting for logging
//
#define PW_MAX_LOGS_PER_SECOND              100
#define PW_TELEMETRY_RATE_LIMIT             1000    // Events per second

//
// Suspicion score thresholds and decay
//
#define PW_SCORE_HIGH_ENTROPY               100
#define PW_SCORE_DOUBLE_EXTENSION           80
#define PW_SCORE_RAPID_WRITES               60
#define PW_SCORE_HONEYPOT_ACCESS            200
#define PW_SCORE_KNOWN_RANSOM_EXT           150
#define PW_SCORE_FULL_FILE_OVERWRITE        40
#define PW_SCORE_SEQUENTIAL_OVERWRITE       30
#define PW_SCORE_LARGE_WRITE_OVERWRITE      20
#define PW_SCORE_RAPID_FILE_MODIFICATIONS   70
#define PW_ALERT_THRESHOLD                  150
#define PW_SCORE_DECAY_PER_SECOND           5       // Score decay rate
#define PW_SCORE_MAX_ACCUMULATION           500     // Cap to prevent overflow

//
// Stale entry timeout
//
#define PW_STALE_ENTRY_TIMEOUT_100NS        (60LL * 10000000LL)  // 60 seconds

// ============================================================================
// ENTROPY LOOKUP TABLE (Pre-computed -log2(p) * 100 for Shannon entropy)
// ============================================================================

//
// This table contains pre-computed values for Shannon entropy calculation.
// Entry i = round(100 * (8 - log2(i))) for i > 0, entry 0 = 0.
// Used as: entropy += (table[scaledCount] * count) / Length
// where scaledCount = (count * 256) / Length.
// This yields SUM(-p*log2(p)*100) = H * 100 (Shannon entropy * 100).
// Result range: 0 (single byte value) to ~800 (perfectly uniform).
//
static const UINT16 g_EntropyTable[257] = {
    0, 800, 700, 642, 600, 568, 542, 519, 500, 483, 468, 454, 442, 430, 419, 409,
    400, 391, 383, 375, 368, 361, 354, 348, 342, 336, 330, 325, 319, 314, 309, 305,
    300, 296, 291, 287, 283, 279, 275, 271, 268, 264, 261, 257, 254, 251, 248, 245,
    242, 239, 236, 233, 230, 227, 225, 222, 219, 217, 214, 212, 209, 207, 205, 202,
    200, 198, 196, 193, 191, 189, 187, 185, 183, 181, 179, 177, 175, 173, 171, 170,
    168, 166, 164, 162, 161, 159, 157, 156, 154, 152, 151, 149, 148, 146, 145, 143,
    142, 140, 139, 137, 136, 134, 133, 131, 130, 129, 127, 126, 125, 123, 122, 121,
    119, 118, 117, 115, 114, 113, 112, 111, 109, 108, 107, 106, 105, 103, 102, 101,
    100, 99, 98, 97, 96, 94, 93, 92, 91, 90, 89, 88, 87, 86, 85, 84,
    83, 82, 81, 80, 79, 78, 77, 76, 75, 74, 73, 72, 71, 71, 70, 69,
    68, 67, 66, 65, 64, 63, 62, 62, 61, 60, 59, 58, 57, 57, 56, 55,
    54, 53, 52, 52, 51, 50, 49, 48, 48, 47, 46, 45, 45, 44, 43, 42,
    42, 41, 40, 39, 39, 38, 37, 36, 36, 35, 34, 33, 33, 32, 31, 31,
    30, 29, 29, 28, 27, 27, 26, 25, 25, 24, 23, 23, 22, 21, 21, 20,
    19, 19, 18, 17, 17, 16, 15, 15, 14, 14, 13, 12, 12, 11, 11, 10,
    9, 9, 8, 8, 7, 6, 6, 5, 5, 4, 3, 3, 2, 2, 1, 1,
    0
};

// ============================================================================
// PRIVATE STRUCTURES
// ============================================================================

/**
 * @brief File ID tracker for unique file counting per process.
 */
typedef struct _PW_FILE_TRACKER {
    UINT64 FileId;
    ULONG VolumeSerial;
} PW_FILE_TRACKER, *PPW_FILE_TRACKER;

/**
 * @brief Per-process write activity tracker.
 */
typedef struct _PW_PROCESS_ACTIVITY {
    HANDLE ProcessId;
    volatile LONG WriteCount;
    volatile LONG UniqueFileCount;
    volatile LONG HighEntropyWrites;
    volatile LONG SuspicionScore;
    volatile LONG RawScore;                 // Score before decay
    LARGE_INTEGER FirstWriteTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER WindowStart;
    LARGE_INTEGER LastScoreUpdate;          // For decay calculation
    BOOLEAN IsRateLimited;
    BOOLEAN IsFlagged;
    BOOLEAN IsActive;                       // Slot is in use
    UINT8 Reserved[5];

    //
    // File tracking for unique file count
    //
    PW_FILE_TRACKER TrackedFiles[PW_MAX_TRACKED_FILES_PER_PROCESS];
    ULONG TrackedFileCount;
    ULONG Reserved2;
} PW_PROCESS_ACTIVITY, *PPW_PROCESS_ACTIVITY;

C_ASSERT(sizeof(PW_PROCESS_ACTIVITY) % 8 == 0);

/**
 * @brief Known extension entry with pre-computed length.
 */
typedef struct _PW_EXTENSION_ENTRY {
    PCWSTR Extension;
    USHORT LengthInBytes;
    USHORT Reserved;
} PW_EXTENSION_ENTRY, *PPW_EXTENSION_ENTRY;

/**
 * @brief Global post-write state.
 */
typedef struct _PW_GLOBAL_STATE {
    //
    // Initialization - use separate flag from state for atomic init
    //
    volatile LONG InitOnce;
    volatile LONG Initialized;
    UINT8 Reserved1[8];

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
    // Process notify callback registration
    //
    BOOLEAN ProcessNotifyRegistered;
    UINT8 Reserved2[7];

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
    volatile LONG64 UniqueFileModifications;
    volatile LONG64 EntropyCalculations;
    LARGE_INTEGER StartTime;

} PW_GLOBAL_STATE, *PPW_GLOBAL_STATE;

C_ASSERT(sizeof(PW_GLOBAL_STATE) % 8 == 0);

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
    LONG SuspicionScore;
    ULONG EntropyX100;              // Entropy * 100 for integer math
    BOOLEAN IsHighEntropy;
    BOOLEAN IsDoubleExtension;
    BOOLEAN IsKnownRansomwareExt;
    BOOLEAN IsHoneypotFile;
    BOOLEAN IsRapidWrite;
    BOOLEAN IsNewUniqueFile;
    UINT8 Reserved2[2];

    //
    // Timing
    //
    LARGE_INTEGER Timestamp;

} PW_WRITE_CONTEXT, *PPW_WRITE_CONTEXT;

C_ASSERT(sizeof(PW_WRITE_CONTEXT) % 8 == 0);

// ============================================================================
// GLOBAL STATE
// ============================================================================

static PW_GLOBAL_STATE g_PostWriteState = { 0 };

// ============================================================================
// KNOWN RANSOMWARE EXTENSIONS (with pre-computed lengths)
// ============================================================================

static PW_EXTENSION_ENTRY g_KnownRansomwareExtensions[] = {
    { L".encrypted",     20, 0 },
    { L".locked",        14, 0 },
    { L".crypto",        14, 0 },
    { L".crypt",         12, 0 },
    { L".enc",            8, 0 },
    { L".locky",         12, 0 },
    { L".cerber",        14, 0 },
    { L".zepto",         12, 0 },
    { L".thor",          10, 0 },
    { L".zzzzz",         12, 0 },
    { L".micro",         12, 0 },
    { L".crypted",       16, 0 },
    { L".cryptolocker",  26, 0 },
    { L".crypz",         12, 0 },
    { L".cryp1",         12, 0 },
    { L".ransom",        14, 0 },
    { L".wncry",         12, 0 },
    { L".wcry",          10, 0 },
    { L".wncryt",        14, 0 },
    { L".onion",         12, 0 },
    { L".wallet",        14, 0 },
    { L".petya",         12, 0 },
    { L".mira",          10, 0 },
    { L".globe",         12, 0 },
    { L".dharma",        14, 0 },
    { L".arena",         12, 0 },
    { L".java",          10, 0 },
    { L".adobe",         12, 0 },
    { L".dotmap",        14, 0 },
    { L".ETH",            8, 0 },
    { L".id",             6, 0 },
    { L".CONTI",         12, 0 },
    { L".LOCKBIT",       16, 0 },
    { L".BLACKCAT",      18, 0 },
    { L".hive",          10, 0 },
    { L".cuba",          10, 0 },
};

#define PW_RANSOMWARE_EXT_COUNT (sizeof(g_KnownRansomwareExtensions) / sizeof(g_KnownRansomwareExtensions[0]))

//
// Common double extensions used in ransomware (with pre-computed lengths)
//
static PW_EXTENSION_ENTRY g_DoubleExtensions[] = {
    { L".pdf.exe",   16, 0 },
    { L".doc.exe",   16, 0 },
    { L".docx.exe",  18, 0 },
    { L".xls.exe",   16, 0 },
    { L".xlsx.exe",  18, 0 },
    { L".jpg.exe",   16, 0 },
    { L".png.exe",   16, 0 },
    { L".txt.exe",   16, 0 },
    { L".zip.exe",   16, 0 },
    { L".mp3.exe",   16, 0 },
    { L".mp4.exe",   16, 0 },
    { L".avi.exe",   16, 0 },
    { L".pdf.scr",   16, 0 },
    { L".doc.scr",   16, 0 },
    { L".jpg.scr",   16, 0 },
    { L".pdf.js",    14, 0 },
    { L".doc.js",    14, 0 },
    { L".pdf.vbs",   16, 0 },
    { L".doc.vbs",   16, 0 },
};

#define PW_DOUBLE_EXT_COUNT (sizeof(g_DoubleExtensions) / sizeof(g_DoubleExtensions[0]))

//
// Honeypot file names to monitor (with pre-computed lengths)
//
static PW_EXTENSION_ENTRY g_HoneypotFileNames[] = {
    { L"important_documents.txt",   44, 0 },
    { L"passwords.txt",             26, 0 },
    { L"bank_accounts.xlsx",        36, 0 },
    { L"private_keys.txt",          32, 0 },
    { L"credit_cards.xlsx",         34, 0 },
    { L"financial_report.docx",     42, 0 },
    { L"secret.txt",                20, 0 },
    { L"confidential.doc",          32, 0 },
    { L"personal.xlsx",             26, 0 },
    { L"accounts.txt",              24, 0 },
    { L"recovery_key.txt",          32, 0 },
    { L"crypto_wallet.dat",         34, 0 },
};

#define PW_HONEYPOT_COUNT (sizeof(g_HoneypotFileNames) / sizeof(g_HoneypotFileNames[0]))

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static VOID
PwpInitializeState(
    VOID
    );

static VOID
PwpProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
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
PwpCleanupProcessActivity(
    _In_ HANDLE ProcessId
    );

static VOID
PwpUpdateProcessActivity(
    _In_ PPW_PROCESS_ACTIVITY Activity,
    _In_ PPW_WRITE_CONTEXT WriteContext
    );

static VOID
PwpApplyScoreDecay(
    _Inout_ PPW_PROCESS_ACTIVITY Activity,
    _In_ PLARGE_INTEGER CurrentTime
    );

static BOOLEAN
PwpTrackUniqueFile(
    _Inout_ PPW_PROCESS_ACTIVITY Activity,
    _In_ UINT64 FileId,
    _In_ ULONG VolumeSerial
    );

static VOID
PwpAnalyzeWritePattern(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PSHADOWSTRIKE_STREAM_CONTEXT StreamContext,
    _Inout_ PPW_WRITE_CONTEXT WriteContext
    );

static ULONG
PwpCalculateEntropy(
    _In_reads_bytes_(Length) PUCHAR Buffer,
    _In_ ULONG Length
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
PwpSendRansomwareEvent(
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
    _In_ PCWSTR Suffix,
    _In_ USHORT SuffixLengthBytes
    );

static BOOLEAN
PwpStringContainsInsensitive(
    _In_ PCUNICODE_STRING String,
    _In_ PCWSTR Substring,
    _In_ USHORT SubstringLengthBytes
    );

// ============================================================================
// PUBLIC FUNCTIONS - INITIALIZATION / CLEANUP
// ============================================================================

/**
 * @brief Initialize post-write monitoring subsystem.
 *
 * Must be called during DriverEntry. Registers process notify callback
 * for proper cleanup on process termination.
 *
 * @return STATUS_SUCCESS or appropriate error code.
 */
NTSTATUS
ShadowStrikePostWriteInitialize(
    VOID
    )
{
    NTSTATUS status;

    PwpInitializeState();

    //
    // Register process notify callback for cleanup
    //
    status = PsSetCreateProcessNotifyRoutineEx(
        PwpProcessNotifyCallback,
        FALSE
    );

    if (NT_SUCCESS(status)) {
        g_PostWriteState.ProcessNotifyRegistered = TRUE;
    } else {
        //
        // Non-fatal - we can still operate without cleanup callback
        // but may have stale entries and PID reuse issues
        //
#ifdef WPP_TRACING
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_FLAG_FILEOPS,
            "PostWrite: Failed to register process notify callback: 0x%08X",
            status);
#endif
        status = STATUS_SUCCESS;
    }

    return status;
}

/**
 * @brief Shutdown post-write monitoring subsystem.
 *
 * Must be called during driver unload.
 */
VOID
ShadowStrikePostWriteShutdown(
    VOID
    )
{
    if (g_PostWriteState.ProcessNotifyRegistered) {
        PsSetCreateProcessNotifyRoutineEx(
            PwpProcessNotifyCallback,
            TRUE  // Remove
        );
        g_PostWriteState.ProcessNotifyRegistered = FALSE;
    }

    //
    // Clear all process activity entries
    //
    if (g_PostWriteState.Initialized) {
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&g_PostWriteState.ActivityLock);

        RtlZeroMemory(
            g_PostWriteState.ProcessActivity,
            sizeof(g_PostWriteState.ProcessActivity)
        );
        g_PostWriteState.ActiveTrackers = 0;

        ExReleasePushLockExclusive(&g_PostWriteState.ActivityLock);
        KeLeaveCriticalRegion();
    }

    InterlockedExchange(&g_PostWriteState.Initialized, FALSE);
    InterlockedExchange(&g_PostWriteState.InitOnce, 0);
}

// ============================================================================
// PUBLIC FUNCTION - POST-WRITE CALLBACK
// ============================================================================

/**
 * @brief Post-operation callback for IRP_MJ_WRITE.
 *
 * This is the enterprise-grade post-write handler that performs:
 * 1. Cache invalidation for modified files
 * 2. Ransomware behavioral detection with entropy analysis
 * 3. Suspicious write pattern analysis
 * 4. Telemetry and alerting with remediation
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
    PVOID writeBuffer = NULL;
    ULONG bytesToAnalyze = 0;

    UNREFERENCED_PARAMETER(CompletionContext);

    //
    // PWR-1 (CRITICAL): Runtime IRQL safety check.
    // Post-write callbacks CAN run at DISPATCH_LEVEL for non-cached I/O.
    // All our analysis requires <= APC_LEVEL (push locks, PagedPool, FltGetStreamContext).
    // Bail immediately if at elevated IRQL to prevent BSOD.
    //
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // Lazy initialization of global state with proper synchronization
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
    // Skip excluded processes (AV engines, backup software, system utilities)
    // This prevents false positives and saves CPU on trusted write paths
    //
    if (ShadowStrikeIsProcessExcluded(PsGetCurrentProcessId(), NULL)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // Update global statistics
    //
    InterlockedIncrement64(&g_PostWriteState.TotalPostWriteOperations);

    //
    // Emit file write event into ETW consumer pipeline for centralized
    // telemetry and cross-source correlation
    //
    {
        PEC_CONSUMER EtwConsumer = ShadowStrikeGetETWConsumer();
        if (EtwConsumer != NULL) {
            EcEmitKernelEvent(
                EtwConsumer,
                &GUID_KERNEL_FILE_PROVIDER,
                EC_EVENTID_FILE_WRITE,
                4, // Information
                0xFFFFFFFFFFFFFFFFULL,
                HandleToULong(PsGetCurrentProcessId()),
                HandleToULong(PsGetCurrentThreadId()),
                NULL, 0);
        }
    }

    //
    // Emit file write event to external ETW provider
    //
    EtwWriteFileEvent(
        EtwEventId_FileWrite,
        HandleToULong(PsGetCurrentProcessId()),
        NULL,   // File path resolved later via stream context
        301,    // Write operation
        (UINT64)Data->IoStatus.Information,
        0, NULL, 0);

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

        //
        // Invalidate cache entry for this file
        //
        if (ShadowStrikeCacheRemove(&cacheKey)) {
            InterlockedIncrement64(&g_PostWriteState.CacheInvalidations);
        }

    } else {
        //
        // No stream context - try to invalidate by building key from file object
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
    // ENTROPY CALCULATION - Analyze write buffer for high entropy (encryption detection)
    // Only do this for non-paging, buffered writes where we can safely access the buffer
    //
    if (Data->Iopb->Parameters.Write.WriteBuffer != NULL &&
        !FlagOn(Data->Iopb->IrpFlags, IRP_NOCACHE) &&
        writeContext.BytesWritten >= 64) {

        //
        // Determine how many bytes to sample for entropy
        //
        bytesToAnalyze = (ULONG)min(writeContext.BytesWritten, PW_ENTROPY_SAMPLE_SIZE);

        //
        // Get the write buffer - handle MDL case
        //
        if (Data->Iopb->Parameters.Write.MdlAddress != NULL) {
            writeBuffer = MmGetSystemAddressForMdlSafe(
                Data->Iopb->Parameters.Write.MdlAddress,
                NormalPagePriority | MdlMappingNoExecute
            );
        } else {
            //
            // FSC-4: In post-op callbacks, the user-mode WriteBuffer may be
            // invalid (freed, paged out, or unmapped). Only MDL-backed buffers
            // are safely accessible. Skip entropy for non-MDL writes rather
            // than relying on __try as a silent failure mechanism.
            //
            writeBuffer = NULL;
        }

        if (writeBuffer != NULL) {
            __try {
                //
                // Calculate entropy using integer math
                //
                writeContext.EntropyX100 = PwpCalculateEntropy(
                    (PUCHAR)writeBuffer,
                    bytesToAnalyze
                );

                InterlockedIncrement64(&g_PostWriteState.EntropyCalculations);

                if (writeContext.EntropyX100 >= PW_ENTROPY_HIGH_THRESHOLD_X100) {
                    writeContext.IsHighEntropy = TRUE;
                    InterlockedIncrement64(&g_PostWriteState.HighEntropyWrites);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                //
                // Buffer access failed - skip entropy check
                //
            }
        }
    }

    //
    // Get file name for analysis
    // Use PagedPool since we're at <= APC_LEVEL
    //
    status = PwpGetFileName(Data, &fileName);
    if (NT_SUCCESS(status) && fileName.Buffer != NULL) {
        fileNameAcquired = TRUE;

        //
        // Check for ransomware indicators using optimized matching
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
    // KTM Transaction Tracking: If this write is within a TxF transaction,
    // record the file operation for ransomware pattern detection.
    // Transacted writes that are later rolled back are a known evasion
    // technique (T1055.013 Process Doppelganging, T1486 ransomware).
    //
    {
        PTXN_PARAMETER_BLOCK txnBlock = IoGetTransactionParameterBlock(FltObjects->FileObject);
        if (txnBlock != NULL && txnBlock->TransactionObject != NULL) {
            PSHADOW_KTM_TRANSACTION ktmTxn = NULL;
            NTSTATUS ktmStatus;
            GUID txnGuid;

            TmGetTransactionId(
                (PKTRANSACTION)txnBlock->TransactionObject,
                &txnGuid
            );

            ktmStatus = ShadowTrackTransaction(
                txnGuid,
                writeContext.ProcessId,
                &ktmTxn
            );

            if (NT_SUCCESS(ktmStatus) && ktmTxn != NULL) {
                if (fileNameAcquired) {
                    ShadowRecordTransactedFileOperation(ktmTxn, &fileName);
                }

                //
                // Enlist in the transaction for commit/rollback notifications.
                // Idempotent — no-op if already enlisted from PreCreate.
                //
                ShadowKtmEnlistInTransaction(
                    FltObjects->Instance,
                    (PKTRANSACTION)txnBlock->TransactionObject,
                    txnGuid,
                    writeContext.ProcessId
                );

                ShadowReleaseKtmTransaction(ktmTxn);
            }
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
    // Track per-process activity with proper synchronization.
    // The activity pointer is into the global array — hold the shared lock
    // during access to prevent PwpCleanupProcessActivity from zeroing the
    // entry concurrently (race between process termination and pending I/O).
    //
    processActivity = PwpGetOrCreateProcessActivity(writeContext.ProcessId);
    if (processActivity != NULL) {
        BOOLEAN shouldAlert = FALSE;
        ULONG alertScore = 0;

        KeEnterCriticalRegion();
        ExAcquirePushLockShared(&g_PostWriteState.ActivityLock);

        //
        // Re-validate: entry may have been cleaned up between
        // PwpGetOrCreateProcessActivity and this lock acquisition
        //
        if (processActivity->IsActive &&
            processActivity->ProcessId == writeContext.ProcessId) {

            //
            // Track unique file modifications
            //
            if (writeContext.FileId != 0) {
                writeContext.IsNewUniqueFile = PwpTrackUniqueFile(
                    processActivity,
                    writeContext.FileId,
                    writeContext.VolumeSerial
                );
                if (writeContext.IsNewUniqueFile) {
                    InterlockedIncrement64(&g_PostWriteState.UniqueFileModifications);
                }
            }

            PwpUpdateProcessActivity(processActivity, &writeContext);

            //
            // Check for ransomware-like behavior at process level
            //
            if (processActivity->SuspicionScore >= PW_ALERT_THRESHOLD &&
                !processActivity->IsFlagged) {

                processActivity->IsFlagged = TRUE;
                alertScore = (ULONG)processActivity->SuspicionScore;
                shouldAlert = TRUE;
                InterlockedIncrement64(&g_PostWriteState.RansomwareAlerts);
            }
        }

        ExReleasePushLockShared(&g_PostWriteState.ActivityLock);
        KeLeaveCriticalRegion();

        //
        // Alert and telemetry OUTSIDE the lock to avoid holding it during
        // CommPort send (which can block on user-mode client).
        //
        if (shouldAlert) {
            BeEngineSubmitEvent(
                BehaviorEvent_RansomwareBehavior,
                BehaviorCategory_Impact,
                HandleToULong(writeContext.ProcessId),
                NULL, 0,
                (UINT32)alertScore,
                TRUE,
                NULL
                );

            PwpRaiseRansomwareAlert(
                writeContext.ProcessId,
                alertScore,
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

/**
 * @brief Initialize global state with proper synchronization.
 *
 * Uses double-checked locking with memory barrier to ensure
 * safe concurrent initialization.
 */
static VOID
PwpInitializeState(
    VOID
    )
{
    //
    // Fast path - already initialized
    //
    if (g_PostWriteState.Initialized) {
        return;
    }

    //
    // Try to claim initialization
    //
    if (InterlockedCompareExchange(&g_PostWriteState.InitOnce, 1, 0) == 0) {
        //
        // We won the race - initialize the state
        // Zero the activity tracking and stats, but NOT InitOnce
        //
        RtlZeroMemory(
            g_PostWriteState.ProcessActivity,
            sizeof(g_PostWriteState.ProcessActivity)
        );
        g_PostWriteState.ActiveTrackers = 0;

        ExInitializePushLock(&g_PostWriteState.ActivityLock);
        ExInitializePushLock(&g_PostWriteState.RateLimitLock);

        g_PostWriteState.CurrentSecondLogs = 0;
        KeQuerySystemTime(&g_PostWriteState.StartTime);
        KeQuerySystemTime(&g_PostWriteState.CurrentSecondStart);

        //
        // Zero statistics
        //
        g_PostWriteState.TotalPostWriteOperations = 0;
        g_PostWriteState.CacheInvalidations = 0;
        g_PostWriteState.HighEntropyWrites = 0;
        g_PostWriteState.DoubleExtensionWrites = 0;
        g_PostWriteState.RapidWriteDetections = 0;
        g_PostWriteState.HoneypotAccesses = 0;
        g_PostWriteState.RansomwareAlerts = 0;
        g_PostWriteState.SuspiciousOperations = 0;
        g_PostWriteState.UniqueFileModifications = 0;
        g_PostWriteState.EntropyCalculations = 0;

        //
        // Memory barrier before publishing initialized flag
        //
        KeMemoryBarrier();
        InterlockedExchange(&g_PostWriteState.Initialized, TRUE);

    } else {
        //
        // Another thread is initializing - spin until complete
        //
        while (!g_PostWriteState.Initialized) {
            YieldProcessor();
        }
        KeMemoryBarrier();
    }
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - PROCESS NOTIFICATION
// ============================================================================

/**
 * @brief Process creation/termination notification callback.
 *
 * Cleans up process activity entries when a process terminates
 * to prevent PID reuse issues and stale data accumulation.
 */
static VOID
PwpProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    UNREFERENCED_PARAMETER(Process);

    //
    // Only interested in process termination
    //
    if (CreateInfo != NULL) {
        return;  // Process creation - ignore
    }

    //
    // Process is terminating - clean up its activity entry
    //
    PwpCleanupProcessActivity(ProcessId);
}

/**
 * @brief Clean up process activity entry for a terminated process.
 */
static VOID
PwpCleanupProcessActivity(
    _In_ HANDLE ProcessId
    )
{
    ULONG i;

    if (!g_PostWriteState.Initialized) {
        return;
    }

    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PostWriteState.ActivityLock);

    for (i = 0; i < PW_MAX_TRACKED_PROCESSES; i++) {
        if (g_PostWriteState.ProcessActivity[i].ProcessId == ProcessId &&
            g_PostWriteState.ProcessActivity[i].IsActive) {

            RtlZeroMemory(
                &g_PostWriteState.ProcessActivity[i],
                sizeof(PW_PROCESS_ACTIVITY)
            );
            InterlockedDecrement(&g_PostWriteState.ActiveTrackers);
            break;
        }
    }

    ExReleasePushLockExclusive(&g_PostWriteState.ActivityLock);
    KeLeaveCriticalRegion();
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

    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

    KeQuerySystemTime(&currentTime);

    //
    // Check if we're in a new second
    //
    secondsDiff.QuadPart = (currentTime.QuadPart -
                            g_PostWriteState.CurrentSecondStart.QuadPart) / 10000000LL;

    if (secondsDiff.QuadPart >= 1) {
        //
        // New second - reset counter
        //
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&g_PostWriteState.RateLimitLock);

        //
        // Double-check under lock
        //
        if ((currentTime.QuadPart -
             g_PostWriteState.CurrentSecondStart.QuadPart) / 10000000LL >= 1) {

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

/**
 * @brief Get or create a process activity tracker.
 *
 * Uses proper synchronization to prevent TOCTOU races.
 * Holds exclusive lock during entire slot allocation.
 */
static PPW_PROCESS_ACTIVITY
PwpGetOrCreateProcessActivity(
    _In_ HANDLE ProcessId
    )
{
    PPW_PROCESS_ACTIVITY activity = NULL;
    ULONG i;
    ULONG freeSlotIndex = (ULONG)-1;
    ULONG staleSlotIndex = (ULONG)-1;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER age;

    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

    if (!g_PostWriteState.Initialized) {
        return NULL;
    }

    KeQuerySystemTime(&currentTime);

    //
    // First, try to find existing entry under shared lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_PostWriteState.ActivityLock);

    for (i = 0; i < PW_MAX_TRACKED_PROCESSES; i++) {
        if (g_PostWriteState.ProcessActivity[i].ProcessId == ProcessId &&
            g_PostWriteState.ProcessActivity[i].IsActive) {
            activity = &g_PostWriteState.ProcessActivity[i];
            break;
        }
    }

    ExReleasePushLockShared(&g_PostWriteState.ActivityLock);
    KeLeaveCriticalRegion();

    if (activity != NULL) {
        return activity;
    }

    //
    // Need to create new entry - acquire exclusive lock
    // and do full search + allocation atomically
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PostWriteState.ActivityLock);

    //
    // Re-check for existing entry (another thread may have created it)
    //
    for (i = 0; i < PW_MAX_TRACKED_PROCESSES; i++) {
        if (g_PostWriteState.ProcessActivity[i].ProcessId == ProcessId &&
            g_PostWriteState.ProcessActivity[i].IsActive) {
            activity = &g_PostWriteState.ProcessActivity[i];
            goto Exit;
        }

        //
        // Track free and stale slots for allocation
        //
        if (!g_PostWriteState.ProcessActivity[i].IsActive) {
            if (freeSlotIndex == (ULONG)-1) {
                freeSlotIndex = i;
            }
        } else if (staleSlotIndex == (ULONG)-1) {
            //
            // Check for stale entry
            //
            age.QuadPart = currentTime.QuadPart -
                           g_PostWriteState.ProcessActivity[i].LastWriteTime.QuadPart;

            if (age.QuadPart > PW_STALE_ENTRY_TIMEOUT_100NS) {
                staleSlotIndex = i;
            }
        }
    }

    //
    // Allocate new slot - prefer free slot over stale
    //
    if (freeSlotIndex != (ULONG)-1) {
        i = freeSlotIndex;
    } else if (staleSlotIndex != (ULONG)-1) {
        i = staleSlotIndex;
    } else {
        //
        // No slots available
        //
        activity = NULL;
        goto Exit;
    }

    //
    // Initialize the new entry
    //
    RtlZeroMemory(&g_PostWriteState.ProcessActivity[i], sizeof(PW_PROCESS_ACTIVITY));
    g_PostWriteState.ProcessActivity[i].ProcessId = ProcessId;
    g_PostWriteState.ProcessActivity[i].IsActive = TRUE;
    g_PostWriteState.ProcessActivity[i].FirstWriteTime = currentTime;
    g_PostWriteState.ProcessActivity[i].LastWriteTime = currentTime;
    g_PostWriteState.ProcessActivity[i].WindowStart = currentTime;
    g_PostWriteState.ProcessActivity[i].LastScoreUpdate = currentTime;

    activity = &g_PostWriteState.ProcessActivity[i];
    InterlockedIncrement(&g_PostWriteState.ActiveTrackers);

Exit:
    ExReleasePushLockExclusive(&g_PostWriteState.ActivityLock);
    KeLeaveCriticalRegion();

    return activity;
}

/**
 * @brief Apply time-based decay to suspicion score.
 */
static VOID
PwpApplyScoreDecay(
    _Inout_ PPW_PROCESS_ACTIVITY Activity,
    _In_ PLARGE_INTEGER CurrentTime
    )
{
    LONGLONG elapsedSeconds;
    LONG decay;
    LONG currentScore;
    LONG newScore;

    elapsedSeconds = (CurrentTime->QuadPart - Activity->LastScoreUpdate.QuadPart) / 10000000LL;

    if (elapsedSeconds > 0) {
        decay = (LONG)(elapsedSeconds * PW_SCORE_DECAY_PER_SECOND);

        do {
            currentScore = Activity->SuspicionScore;
            newScore = currentScore - decay;
            if (newScore < 0) {
                newScore = 0;
            }
        } while (InterlockedCompareExchange(
                     &Activity->SuspicionScore,
                     newScore,
                     currentScore) != currentScore);

        Activity->LastScoreUpdate = *CurrentTime;
    }
}

/**
 * @brief Track unique file modification for a process.
 *
 * @return TRUE if this is a new unique file, FALSE if already tracked.
 */
static BOOLEAN
PwpTrackUniqueFile(
    _Inout_ PPW_PROCESS_ACTIVITY Activity,
    _In_ UINT64 FileId,
    _In_ ULONG VolumeSerial
    )
{
    ULONG i;

    //
    // Check if already tracked
    //
    for (i = 0; i < Activity->TrackedFileCount; i++) {
        if (Activity->TrackedFiles[i].FileId == FileId &&
            Activity->TrackedFiles[i].VolumeSerial == VolumeSerial) {
            return FALSE;  // Already tracked
        }
    }

    //
    // Add to tracking if space available
    //
    if (Activity->TrackedFileCount < PW_MAX_TRACKED_FILES_PER_PROCESS) {
        Activity->TrackedFiles[Activity->TrackedFileCount].FileId = FileId;
        Activity->TrackedFiles[Activity->TrackedFileCount].VolumeSerial = VolumeSerial;
        Activity->TrackedFileCount++;
        InterlockedIncrement(&Activity->UniqueFileCount);
        return TRUE;
    }

    //
    // Tracking buffer full - count as new anyway for detection purposes
    //
    InterlockedIncrement(&Activity->UniqueFileCount);
    return TRUE;
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
    // Apply score decay before adding new score
    //
    PwpApplyScoreDecay(Activity, &WriteContext->Timestamp);

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
        InterlockedExchange(&Activity->UniqueFileCount, 0);
        Activity->TrackedFileCount = 0;
    }

    //
    // Update counters
    //
    InterlockedIncrement(&Activity->WriteCount);

    if (WriteContext->IsHighEntropy) {
        InterlockedIncrement(&Activity->HighEntropyWrites);
    }

    //
    // Update suspicion score with cap
    //
    LONG newRawScore = InterlockedAdd(&Activity->RawScore, WriteContext->SuspicionScore);
    if (newRawScore > PW_SCORE_MAX_ACCUMULATION) {
        InterlockedExchange(&Activity->RawScore, PW_SCORE_MAX_ACCUMULATION);
    }

    //
    // Update decayed score atomically using CAS loop
    //
    {
        LONG oldScore, desired;
        do {
            oldScore = Activity->SuspicionScore;
            desired = oldScore + (LONG)WriteContext->SuspicionScore;
            if (desired > PW_SCORE_MAX_ACCUMULATION) {
                desired = PW_SCORE_MAX_ACCUMULATION;
            }
        } while (InterlockedCompareExchange(
                     &Activity->SuspicionScore,
                     desired,
                     oldScore) != oldScore);
    }

    //
    // Check for rapid write pattern (ransomware indicator)
    //
    if (Activity->WriteCount > PW_RANSOMWARE_WRITE_THRESHOLD) {
        InterlockedIncrement64(&g_PostWriteState.RapidWriteDetections);
        Activity->IsRateLimited = TRUE;
    }

    //
    // Check for rapid unique file modifications
    //
    if (Activity->UniqueFileCount > PW_RANSOMWARE_FILE_THRESHOLD) {
        //
        // Add score for rapid file modifications using CAS loop
        //
        LONG oldScore, desired;
        do {
            oldScore = Activity->SuspicionScore;
            desired = oldScore + PW_SCORE_RAPID_FILE_MODIFICATIONS;
            if (desired > PW_SCORE_MAX_ACCUMULATION) {
                desired = PW_SCORE_MAX_ACCUMULATION;
            }
        } while (InterlockedCompareExchange(
                     &Activity->SuspicionScore,
                     desired,
                     oldScore) != oldScore);
    }
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - ENTROPY CALCULATION
// ============================================================================

/**
 * @brief Calculate Shannon entropy of a buffer using integer math.
 *
 * Uses pre-computed lookup table to avoid floating-point operations
 * in kernel mode. Returns entropy * 100 (e.g., 750 = 7.50 bits/byte).
 *
 * @param Buffer  Buffer to analyze.
 * @param Length  Length of buffer in bytes.
 * @return Entropy value * 100.
 */
static ULONG
PwpCalculateEntropy(
    _In_reads_bytes_(Length) PUCHAR Buffer,
    _In_ ULONG Length
    )
{
    ULONG byteCounts[256] = { 0 };
    ULONG i;
    ULONG entropy = 0;
    ULONG count;

    if (Buffer == NULL || Length == 0) {
        return 0;
    }

    //
    // Count byte frequencies
    //
    for (i = 0; i < Length; i++) {
        byteCounts[Buffer[i]]++;
    }

    //
    // Calculate entropy using lookup table
    // Formula: H = -SUM(p * log2(p)) where p = count/length
    // We scale by 100 for integer precision
    //
    for (i = 0; i < 256; i++) {
        count = byteCounts[i];
        if (count > 0) {
            //
            // Scale count to 0-256 range for table lookup
            // Then scale the result by length ratio
            //
            ULONG scaledCount = (count * 256) / Length;
            if (scaledCount > 256) {
                scaledCount = 256;
            }

            //
            // Get entropy contribution from table and scale by probability
            //
            ULONG contribution = (g_EntropyTable[scaledCount] * count) / Length;
            entropy += contribution;
        }
    }

    //
    // Result is entropy * 100 (max ~800 for 8.0 bits/byte, 0 for single-value data)
    //
    return entropy;
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
            WriteContext->SuspicionScore += PW_SCORE_LARGE_WRITE_OVERWRITE;
        }
    }
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - EXTENSION CHECKING (OPTIMIZED)
// ============================================================================

static BOOLEAN
PwpCheckDoubleExtension(
    _In_ PCUNICODE_STRING FileName
    )
{
    ULONG i;

    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return FALSE;
    }

    for (i = 0; i < PW_DOUBLE_EXT_COUNT; i++) {
        if (PwpStringEndsWithInsensitive(
                FileName,
                g_DoubleExtensions[i].Extension,
                g_DoubleExtensions[i].LengthInBytes)) {
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

    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return FALSE;
    }

    for (i = 0; i < PW_RANSOMWARE_EXT_COUNT; i++) {
        if (PwpStringEndsWithInsensitive(
                FileName,
                g_KnownRansomwareExtensions[i].Extension,
                g_KnownRansomwareExtensions[i].LengthInBytes)) {
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

    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return FALSE;
    }

    for (i = 0; i < PW_HONEYPOT_COUNT; i++) {
        if (PwpStringContainsInsensitive(
                FileName,
                g_HoneypotFileNames[i].Extension,
                g_HoneypotFileNames[i].LengthInBytes)) {
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
        "Suspicious write: PID=%p Score=%d Bytes=%Iu Offset=%I64d "
        "Entropy=%u DoubleExt=%d RansomExt=%d Honeypot=%d HighEntropy=%d File=%wZ",
        WriteContext->ProcessId,
        WriteContext->SuspicionScore,
        WriteContext->BytesWritten,
        WriteContext->WriteOffset.QuadPart,
        WriteContext->EntropyX100,
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
#endif

    //
    // Ransomware alerts tracked locally in g_PostWriteState.RansomwareAlerts
    //

    //
    // Send alert to user-mode service for remediation
    //
    PwpSendRansomwareEvent(ProcessId, Score, FileName);
}

/**
 * @brief Ransomware alert notification payload sent to user-mode.
 */
#pragma pack(push, 1)
typedef struct _PW_RANSOMWARE_ALERT_DATA {
    UINT32 ProcessId;
    UINT32 SuspicionScore;
    UINT32 HighEntropyWrites;
    UINT32 UniqueFileCount;
    UINT32 WriteCount;
    UINT32 FileNameLengthBytes;
    // FileName WCHAR data follows immediately after this structure
} PW_RANSOMWARE_ALERT_DATA, *PPW_RANSOMWARE_ALERT_DATA;
#pragma pack(pop)

/**
 * @brief Send ransomware detection event to user-mode service.
 *
 * Builds a notification message with ransomware alert data and sends it
 * via the existing CommPort infrastructure. The user-mode service receives
 * this as a FilterMessageType_RansomwareAlert and takes remediation action
 * (process termination, quarantine, snapshot rollback, user notification).
 */
static NTSTATUS
PwpSendRansomwareEvent(
    _In_ HANDLE ProcessId,
    _In_ ULONG Score,
    _In_opt_ PCUNICODE_STRING FileName
    )
{
    NTSTATUS status;
    PUCHAR payloadBuf = NULL;
    PPW_RANSOMWARE_ALERT_DATA alertData;
    ULONG fileNameBytes = 0;
    ULONG dataSize;

    if (!SHADOWSTRIKE_USER_MODE_CONNECTED()) {
        return STATUS_PORT_DISCONNECTED;
    }

    if (!g_DriverData.Initialized || g_DriverData.ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Calculate payload size with optional file name
    //
    if (FileName != NULL && FileName->Buffer != NULL && FileName->Length > 0) {
        fileNameBytes = FileName->Length;
        if (fileNameBytes > 520) {
            fileNameBytes = 520;
        }
    }

    dataSize = sizeof(PW_RANSOMWARE_ALERT_DATA) + fileNameBytes;

    //
    // Cap payload to prevent abuse
    //
    if (dataSize > 4096) {
        dataSize = sizeof(PW_RANSOMWARE_ALERT_DATA);
        fileNameBytes = 0;
    }

    payloadBuf = (PUCHAR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        dataSize,
        PW_POOL_TAG
    );

    if (payloadBuf == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Fill ransomware alert payload (header built by batch flush callback)
    //
    alertData = (PPW_RANSOMWARE_ALERT_DATA)payloadBuf;

    alertData->ProcessId = HandleToULong(ProcessId);
    alertData->SuspicionScore = Score;
    alertData->FileNameLengthBytes = fileNameBytes;

    //
    // Include process activity stats if available
    //
    {
        PPW_PROCESS_ACTIVITY activity = NULL;
        ULONG i;

        KeEnterCriticalRegion();
        ExAcquirePushLockShared(&g_PostWriteState.ActivityLock);

        for (i = 0; i < PW_MAX_TRACKED_PROCESSES; i++) {
            if (g_PostWriteState.ProcessActivity[i].ProcessId == ProcessId &&
                g_PostWriteState.ProcessActivity[i].IsActive) {
                activity = &g_PostWriteState.ProcessActivity[i];
                break;
            }
        }

        if (activity != NULL) {
            alertData->HighEntropyWrites = (UINT32)activity->HighEntropyWrites;
            alertData->UniqueFileCount = (UINT32)activity->UniqueFileCount;
            alertData->WriteCount = (UINT32)activity->WriteCount;
        } else {
            alertData->HighEntropyWrites = 0;
            alertData->UniqueFileCount = 0;
            alertData->WriteCount = 0;
        }

        ExReleasePushLockShared(&g_PostWriteState.ActivityLock);
        KeLeaveCriticalRegion();
    }

    //
    // Copy file name if present
    //
    if (fileNameBytes > 0 && FileName != NULL && FileName->Buffer != NULL) {
        PUCHAR dest = payloadBuf + sizeof(PW_RANSOMWARE_ALERT_DATA);
        RtlCopyMemory(dest, FileName->Buffer, fileNameBytes);
    }

    //
    // Route through batch processor for high-throughput delivery.
    // Batch callback builds SHADOWSTRIKE_MESSAGE_HEADER and sends via CommPort.
    // Falls back to direct send if batch processor is unavailable.
    //
    status = ShadowStrikeBatchSendNotification(
        (UINT16)FilterMessageType_RansomwareAlert,
        payloadBuf,
        dataSize
    );

    if (NT_SUCCESS(status)) {
        SHADOWSTRIKE_INC_STAT(MessagesSent);
    } else {
#ifdef WPP_TRACING
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_FLAG_FILEOPS,
            "PostWrite: Failed to send ransomware alert for PID=%p: 0x%08X",
            ProcessId, status);
#endif
    }

    ExFreePoolWithTag(payloadBuf, PW_POOL_TAG);
    return status;
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - FILE NAME (PagedPool)
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

    //
    // Verify IRQL - we need to be at <= APC_LEVEL for paged allocations
    //
    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

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
    // Allocate from PagedPool since we're at <= APC_LEVEL
    // This preserves NonPagedPool for truly non-pageable allocations
    //
    FileName->MaximumLength = nameInfo->Name.Length + sizeof(WCHAR);
    FileName->Buffer = (PWCH)ExAllocatePool2(
        POOL_FLAG_PAGED,
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
// PRIVATE HELPER FUNCTIONS - STRING UTILITIES (OPTIMIZED)
// ============================================================================

/**
 * @brief Check if string ends with suffix (case-insensitive).
 *
 * Uses pre-computed suffix length to avoid wcslen() calls.
 */
static BOOLEAN
PwpStringEndsWithInsensitive(
    _In_ PCUNICODE_STRING String,
    _In_ PCWSTR Suffix,
    _In_ USHORT SuffixLengthBytes
    )
{
    USHORT stringLen;
    PWCHAR stringEnd;
    UNICODE_STRING suffixString;
    UNICODE_STRING endString;

    if (String == NULL || String->Buffer == NULL || Suffix == NULL) {
        return FALSE;
    }

    if (SuffixLengthBytes > String->Length) {
        return FALSE;
    }

    stringLen = String->Length;
    stringEnd = String->Buffer + ((stringLen - SuffixLengthBytes) / sizeof(WCHAR));

    suffixString.Buffer = (PWCH)Suffix;
    suffixString.Length = SuffixLengthBytes;
    suffixString.MaximumLength = SuffixLengthBytes;

    endString.Buffer = stringEnd;
    endString.Length = SuffixLengthBytes;
    endString.MaximumLength = SuffixLengthBytes;

    return RtlEqualUnicodeString(&endString, &suffixString, TRUE);
}

/**
 * @brief Check if string contains substring (case-insensitive).
 *
 * Uses pre-computed substring length to avoid wcslen() calls.
 */
static BOOLEAN
PwpStringContainsInsensitive(
    _In_ PCUNICODE_STRING String,
    _In_ PCWSTR Substring,
    _In_ USHORT SubstringLengthBytes
    )
{
    PWCHAR searchStart;
    PWCHAR searchEnd;
    USHORT substringChars;
    USHORT i;

    if (String == NULL || String->Buffer == NULL || Substring == NULL) {
        return FALSE;
    }

    substringChars = SubstringLengthBytes / sizeof(WCHAR);

    if (SubstringLengthBytes > String->Length) {
        return FALSE;
    }

    searchEnd = String->Buffer + (String->Length / sizeof(WCHAR)) - substringChars;

    for (searchStart = String->Buffer; searchStart <= searchEnd; searchStart++) {
        BOOLEAN match = TRUE;

        for (i = 0; i < substringChars; i++) {
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

// ============================================================================
// PUBLIC FUNCTION - GET STATISTICS
// ============================================================================

/**
 * @brief Get post-write monitoring statistics.
 *
 * @param TotalOperations       Total post-write operations processed.
 * @param CacheInvalidations    Cache entries invalidated.
 * @param HighEntropyWrites     High-entropy writes detected.
 * @param RansomwareAlerts      Ransomware alerts raised.
 * @param ActiveTrackers        Currently active process trackers.
 */
VOID
ShadowStrikePostWriteGetStats(
    _Out_opt_ PLONG64 TotalOperations,
    _Out_opt_ PLONG64 CacheInvalidations,
    _Out_opt_ PLONG64 HighEntropyWrites,
    _Out_opt_ PLONG64 RansomwareAlerts,
    _Out_opt_ PLONG ActiveTrackers
    )
{
    if (TotalOperations != NULL) {
        *TotalOperations = g_PostWriteState.TotalPostWriteOperations;
    }
    if (CacheInvalidations != NULL) {
        *CacheInvalidations = g_PostWriteState.CacheInvalidations;
    }
    if (HighEntropyWrites != NULL) {
        *HighEntropyWrites = g_PostWriteState.HighEntropyWrites;
    }
    if (RansomwareAlerts != NULL) {
        *RansomwareAlerts = g_PostWriteState.RansomwareAlerts;
    }
    if (ActiveTrackers != NULL) {
        *ActiveTrackers = g_PostWriteState.ActiveTrackers;
    }
}
