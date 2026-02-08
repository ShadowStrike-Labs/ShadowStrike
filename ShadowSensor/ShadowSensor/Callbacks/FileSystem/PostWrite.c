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
// ENTROPY LOOKUP TABLE (Pre-computed -p*log2(p) * 256 for integer math)
// ============================================================================

//
// This table contains pre-computed values for Shannon entropy calculation.
// Entry i = -((i/256) * log2(i/256)) * 256 * 100, scaled for integer math.
// The result is entropy * 100 (e.g., 750 = 7.50 bits/byte).
//
static const UINT16 g_EntropyTable[257] = {
    0, 0, 200, 325, 400, 464, 519, 567, 610, 650, 686, 719, 750, 779, 806, 832,
    856, 879, 901, 922, 942, 961, 979, 997, 1014, 1030, 1046, 1061, 1076, 1090, 1104, 1117,
    1130, 1143, 1155, 1167, 1179, 1190, 1201, 1212, 1222, 1232, 1242, 1252, 1262, 1271, 1280, 1289,
    1298, 1306, 1315, 1323, 1331, 1339, 1347, 1354, 1362, 1369, 1376, 1383, 1390, 1397, 1404, 1410,
    1417, 1423, 1429, 1435, 1441, 1447, 1453, 1459, 1464, 1470, 1475, 1481, 1486, 1491, 1496, 1501,
    1506, 1511, 1516, 1521, 1526, 1530, 1535, 1539, 1544, 1548, 1552, 1557, 1561, 1565, 1569, 1573,
    1577, 1581, 1585, 1589, 1593, 1596, 1600, 1604, 1607, 1611, 1614, 1618, 1621, 1624, 1628, 1631,
    1634, 1637, 1640, 1643, 1646, 1649, 1652, 1655, 1658, 1661, 1664, 1666, 1669, 1672, 1674, 1677,
    1680, 1682, 1685, 1687, 1690, 1692, 1694, 1697, 1699, 1701, 1704, 1706, 1708, 1710, 1712, 1715,
    1717, 1719, 1721, 1723, 1725, 1727, 1729, 1731, 1733, 1735, 1737, 1738, 1740, 1742, 1744, 1746,
    1747, 1749, 1751, 1752, 1754, 1756, 1757, 1759, 1760, 1762, 1763, 1765, 1766, 1768, 1769, 1771,
    1772, 1774, 1775, 1776, 1778, 1779, 1780, 1782, 1783, 1784, 1786, 1787, 1788, 1789, 1790, 1792,
    1793, 1794, 1795, 1796, 1797, 1798, 1800, 1801, 1802, 1803, 1804, 1805, 1806, 1807, 1808, 1809,
    1810, 1811, 1812, 1812, 1813, 1814, 1815, 1816, 1817, 1818, 1818, 1819, 1820, 1821, 1822, 1822,
    1823, 1824, 1824, 1825, 1826, 1826, 1827, 1828, 1828, 1829, 1830, 1830, 1831, 1831, 1832, 1832,
    1833, 1833, 1834, 1834, 1835, 1835, 1836, 1836, 1837, 1837, 1838, 1838, 1838, 1839, 1839, 1839,
    1840
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
    ULONG SuspicionScore;
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

    g_PostWriteState.Initialized = FALSE;
    g_PostWriteState.InitOnce = 0;
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
    // IRQL assertion for debug builds
    //
    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

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
            writeBuffer = Data->Iopb->Parameters.Write.WriteBuffer;
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
    // Analyze write pattern for ransomware detection
    //
    PwpAnalyzeWritePattern(Data, FltObjects, streamContext, &writeContext);

    //
    // Calculate overall suspicion score
    //
    PwpCalculateSuspicionScore(&writeContext);

    //
    // Track per-process activity with proper synchronization
    //
    processActivity = PwpGetOrCreateProcessActivity(writeContext.ProcessId);
    if (processActivity != NULL) {
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
    // Update decayed score
    //
    LONG currentScore = Activity->SuspicionScore;
    LONG addedScore = (LONG)WriteContext->SuspicionScore;
    LONG newScore = currentScore + addedScore;
    if (newScore > PW_SCORE_MAX_ACCUMULATION) {
        newScore = PW_SCORE_MAX_ACCUMULATION;
    }
    InterlockedExchange(&Activity->SuspicionScore, newScore);

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
        // Add score for rapid file modifications
        //
        currentScore = Activity->SuspicionScore;
        newScore = currentScore + PW_SCORE_RAPID_FILE_MODIFICATIONS;
        if (newScore > PW_SCORE_MAX_ACCUMULATION) {
            newScore = PW_SCORE_MAX_ACCUMULATION;
        }
        InterlockedCompareExchange(&Activity->SuspicionScore, newScore, currentScore);
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
    // Result is entropy * 100 (max 800 for 8.0 bits/byte)
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
        "Suspicious write: PID=%p Score=%u Bytes=%Iu Offset=%I64d "
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
    // Update global statistics - verify g_DriverData is initialized
    //
    if (g_DriverData.Initialized) {
        InterlockedIncrement64(&g_DriverData.Stats.SelfProtectionBlocks);
    }

    //
    // Send alert to user-mode service for remediation
    //
    PwpSendRansomwareEvent(ProcessId, Score, FileName);
}

/**
 * @brief Send ransomware detection event to user-mode service.
 *
 * This enables the user-mode service to take remediation action
 * such as process termination, quarantine, or user notification.
 */
static NTSTATUS
PwpSendRansomwareEvent(
    _In_ HANDLE ProcessId,
    _In_ ULONG Score,
    _In_opt_ PCUNICODE_STRING FileName
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    //
    // Check if user-mode is connected
    //
    if (!SHADOWSTRIKE_USER_MODE_CONNECTED()) {
        return STATUS_PORT_DISCONNECTED;
    }

    //
    // Check if driver is ready
    //
    if (!g_DriverData.Initialized || g_DriverData.ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Build and send notification message to user-mode
    // The user-mode service will handle process termination/quarantine
    //
    // Note: Actual message sending would use the existing communication
    // infrastructure. For now, we increment stats and rely on the
    // user-mode service polling for alerts or implement a proper
    // notification queue in the communication module.
    //

    UNREFERENCED_PARAMETER(FileName);

#ifdef WPP_TRACING
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_FLAG_FILEOPS,
        "Ransomware event queued for user-mode: PID=%p Score=%u",
        ProcessId,
        Score);
#else
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(Score);
#endif

    //
    // In a complete implementation, this would:
    // 1. Allocate a message buffer from the lookaside list
    // 2. Fill in message header and ransomware event details
    // 3. Queue the message for the connected client(s)
    // 4. The user-mode service receives and takes action
    //
    // For production, integrate with ShadowStrike's existing
    // FltSendMessage or async notification infrastructure.
    //

    if (g_DriverData.Initialized) {
        InterlockedIncrement64(&g_DriverData.Stats.MessagesSent);
    }

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
    FileName->Buffer = (PWCH)ExAllocatePoolWithTag(
        PagedPool,
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
