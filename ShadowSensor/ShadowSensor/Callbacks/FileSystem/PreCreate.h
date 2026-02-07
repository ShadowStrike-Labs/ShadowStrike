/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE PRE-CREATE CALLBACK HEADER
 * ============================================================================
 *
 * @file PreCreate.h
 * @brief Enterprise-grade IRP_MJ_CREATE pre-operation callback for kernel EDR.
 *
 * This module provides comprehensive file access interception and scanning:
 * - On-access malware scanning with cache integration
 * - Alternate Data Stream (ADS) abuse detection
 * - Double/hidden extension detection (e.g., invoice.pdf.exe)
 * - Suspicious path detection (temp, recycle bin, public folders)
 * - Honeypot file access detection
 * - Self-protection enforcement for EDR files
 * - Network file scanning (optional)
 * - Removable media scanning with priority
 * - Ransomware behavior correlation
 * - File reputation integration infrastructure
 * - Exclusion management integration
 * - Synchronous and asynchronous scan support
 *
 * Detection Techniques Covered (MITRE ATT&CK):
 * - T1564.004: NTFS File Attributes (ADS abuse)
 * - T1036.007: Double File Extension
 * - T1036: Masquerading (extension spoofing)
 * - T1204.002: User Execution: Malicious File
 * - T1566.001: Spearphishing Attachment
 * - T1105: Ingress Tool Transfer (download detection)
 * - T1486: Data Encrypted for Impact (ransomware staging)
 * - T1485: Data Destruction (mass file access patterns)
 * - T1083: File and Directory Discovery
 *
 * Integration Points:
 * - ScanCache: Verdict caching for performance
 * - ScanBridge: User-mode scanner communication
 * - ExclusionManager: Path/process/extension exclusions
 * - SelfProtect: EDR file protection enforcement
 * - FileSystemCallbacks: Ransomware detection correlation
 *
 * Performance Characteristics:
 * - O(1) cache lookup for previously scanned files
 * - Early exit for excluded/trusted processes
 * - Configurable scan timeout with fail-open policy
 * - Async scan support for low-priority files
 * - Extension-based scan prioritization
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_PRECREATE_H_
#define _SHADOWSTRIKE_PRECREATE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <fltKernel.h>
#include <ntifs.h>

// ============================================================================
// POOL TAGS
// ============================================================================

#define PC_POOL_TAG                     'CRPP'  // PPRC - PreCreate
#define PC_CONTEXT_TAG                  'xCPC'  // CPCx - Context
#define PC_MESSAGE_TAG                  'gMPC'  // CPMg - Message

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * @brief Maximum file path length to process
 */
#define PC_MAX_PATH_LENGTH              32768

/**
 * @brief Maximum file name length for display/logging
 */
#define PC_MAX_DISPLAY_NAME             512

/**
 * @brief Maximum extension length
 */
#define PC_MAX_EXTENSION_LENGTH         32

/**
 * @brief Default scan timeout in milliseconds
 */
#define PC_DEFAULT_SCAN_TIMEOUT_MS      30000

/**
 * @brief Quick scan timeout for cached/low-priority files
 */
#define PC_QUICK_SCAN_TIMEOUT_MS        5000

/**
 * @brief Maximum concurrent scan requests
 */
#define PC_MAX_CONCURRENT_SCANS         64

/**
 * @brief Maximum pending scan queue depth
 */
#define PC_MAX_PENDING_QUEUE            256

/**
 * @brief Honeypot file name patterns count
 */
#define PC_MAX_HONEYPOT_PATTERNS        32

/**
 * @brief Rate limit for logging (per second)
 */
#define PC_LOG_RATE_LIMIT_PER_SEC       100

// ============================================================================
// ACCESS TYPE CLASSIFICATION
// ============================================================================

/**
 * @brief File access type for scan request classification
 */
typedef enum _PC_ACCESS_TYPE {
    PcAccessUnknown         = 0,
    PcAccessRead            = 1,    ///< Read access (generic scan)
    PcAccessWrite           = 2,    ///< Write access (may create/modify)
    PcAccessExecute         = 3,    ///< Execute access (high priority)
    PcAccessDelete          = 4,    ///< Delete access (self-protection)
    PcAccessRename          = 5,    ///< Rename access (ransomware indicator)
    PcAccessDirectory       = 6     ///< Directory access (enumeration)
} PC_ACCESS_TYPE;

/**
 * @brief Scan priority levels
 */
typedef enum _PC_SCAN_PRIORITY {
    PcPriorityLow           = 0,    ///< Background scan, async OK
    PcPriorityNormal        = 50,   ///< Standard scan priority
    PcPriorityHigh          = 75,   ///< Elevated priority (executables)
    PcPriorityCritical      = 100   ///< Highest priority (immediate threat)
} PC_SCAN_PRIORITY;

/**
 * @brief Pre-create operation result
 */
typedef enum _PC_RESULT {
    PcResultAllow           = 0,    ///< Allow the operation
    PcResultBlock           = 1,    ///< Block the operation
    PcResultPending         = 2,    ///< Scan pending (async)
    PcResultTimeout         = 3,    ///< Scan timed out (fail-open)
    PcResultError           = 4,    ///< Error occurred (fail-open)
    PcResultExcluded        = 5,    ///< Excluded from scanning
    PcResultCached          = 6,    ///< Result from cache
    PcResultSelfProtect     = 7     ///< Blocked by self-protection
} PC_RESULT;

// ============================================================================
// SUSPICIOUS INDICATORS
// ============================================================================

/**
 * @brief Suspicious file indicators detected during pre-create
 */
typedef enum _PC_SUSPICIOUS_FLAGS {
    PcSuspiciousNone            = 0x00000000,
    PcSuspiciousAdsAccess       = 0x00000001,  ///< Alternate data stream access
    PcSuspiciousDoubleExtension = 0x00000002,  ///< Double/hidden extension
    PcSuspiciousTempPath        = 0x00000004,  ///< Suspicious temp path
    PcSuspiciousRecycleBin      = 0x00000008,  ///< Recycle bin access
    PcSuspiciousPublicFolder    = 0x00000010,  ///< Public folder execution
    PcSuspiciousAppData         = 0x00000020,  ///< AppData execution
    PcSuspiciousDownloads       = 0x00000040,  ///< Downloads folder
    PcSuspiciousRemovable       = 0x00000080,  ///< Removable media
    PcSuspiciousNetwork         = 0x00000100,  ///< Network share
    PcSuspiciousHoneypot        = 0x00000200,  ///< Honeypot file access
    PcSuspiciousZoneIdentifier  = 0x00000400,  ///< Zone.Identifier stream
    PcSuspiciousHiddenFile      = 0x00000800,  ///< Hidden file attributes
    PcSuspiciousSystemFile      = 0x00001000,  ///< System file in user path
    PcSuspiciousExecuteNoRead   = 0x00002000,  ///< Execute without read (injection)
    PcSuspiciousWriteExecute    = 0x00004000,  ///< Write + Execute (dropper)
    PcSuspiciousDeleteOnClose   = 0x00008000,  ///< FILE_DELETE_ON_CLOSE
    PcSuspiciousOverwrite       = 0x00010000,  ///< FILE_OVERWRITE access
    PcSuspiciousLongPath        = 0x00020000,  ///< Unusually long path
    PcSuspiciousUnicodeRLO      = 0x00040000,  ///< Unicode RLO character
    PcSuspiciousTrailingSpace   = 0x00080000,  ///< Trailing spaces/dots
    PcSuspiciousReservedName    = 0x00100000   ///< Reserved device name (CON, PRN, etc.)
} PC_SUSPICIOUS_FLAGS;

/**
 * @brief File classification based on extension
 */
typedef enum _PC_FILE_CLASS {
    PcFileClassUnknown      = 0,
    PcFileClassExecutable   = 1,    ///< PE executables (.exe, .dll, .sys)
    PcFileClassScript       = 2,    ///< Script files (.ps1, .vbs, .js)
    PcFileClassDocument     = 3,    ///< Office documents
    PcFileClassArchive      = 4,    ///< Archive files
    PcFileClassMedia        = 5,    ///< Media files (low priority)
    PcFileClassData         = 6,    ///< Data files
    PcFileClassConfig       = 7,    ///< Configuration files
    PcFileClassCertificate  = 8,    ///< Certificate/key files
    PcFileClassDatabase     = 9,    ///< Database files
    PcFileClassBackup       = 10    ///< Backup files (ransomware target)
} PC_FILE_CLASS;

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Pre-create operation context
 *
 * This structure captures all relevant information about a file access
 * operation for analysis, scanning, and correlation.
 */
typedef struct _PC_OPERATION_CONTEXT {
    //
    // Identification
    //
    ULONG Signature;                        ///< Validation signature
    LARGE_INTEGER OperationId;              ///< Unique operation ID

    //
    // Timing
    //
    LARGE_INTEGER StartTime;                ///< Operation start time
    LARGE_INTEGER EndTime;                  ///< Operation end time
    ULONG DurationMs;                       ///< Processing duration

    //
    // Process information
    //
    HANDLE ProcessId;                       ///< Requesting process ID
    HANDLE ThreadId;                        ///< Requesting thread ID
    BOOLEAN IsKernelMode;                   ///< Request from kernel mode
    BOOLEAN IsProtectedProcess;             ///< Our protected process
    BOOLEAN IsExcludedProcess;              ///< Excluded from scanning
    ULONG ProcessSessionId;                 ///< Process session ID

    //
    // File information
    //
    UNICODE_STRING FileName;                ///< Full file path
    WCHAR FileNameBuffer[PC_MAX_DISPLAY_NAME]; ///< Inline buffer
    UNICODE_STRING Extension;               ///< File extension
    WCHAR ExtensionBuffer[PC_MAX_EXTENSION_LENGTH]; ///< Inline buffer
    UNICODE_STRING StreamName;              ///< ADS name if present
    WCHAR StreamNameBuffer[64];             ///< Inline buffer
    PC_FILE_CLASS FileClass;                ///< Classification
    ULONG ScanPriority;                     ///< Scan priority (0-100)

    //
    // Access details
    //
    PC_ACCESS_TYPE AccessType;              ///< Classified access type
    ACCESS_MASK DesiredAccess;              ///< Original desired access
    ULONG CreateOptions;                    ///< Create options
    ULONG CreateDisposition;                ///< Create disposition
    ULONG ShareAccess;                      ///< Share access
    ULONG FileAttributes;                   ///< File attributes
    BOOLEAN IsDirectory;                    ///< Directory flag
    BOOLEAN IsPagingFile;                   ///< Paging file flag
    BOOLEAN IsVolumeOpen;                   ///< Volume open flag

    //
    // Volume information
    //
    BOOLEAN IsNetworkVolume;                ///< Network file system
    BOOLEAN IsRemovableVolume;              ///< Removable media
    FLT_FILESYSTEM_TYPE FileSystemType;     ///< File system type

    //
    // Analysis results
    //
    PC_SUSPICIOUS_FLAGS SuspiciousFlags;    ///< Detected suspicious indicators
    ULONG ThreatScore;                      ///< Calculated threat score (0-100)
    BOOLEAN HasAds;                         ///< Has alternate data stream
    BOOLEAN HasDoubleExtension;             ///< Has double extension
    BOOLEAN IsHoneypotAccess;               ///< Honeypot file touched

    //
    // Scan results
    //
    PC_RESULT Result;                       ///< Final operation result
    BOOLEAN WasCacheHit;                    ///< Result from cache
    BOOLEAN WasScanned;                     ///< Actually scanned
    BOOLEAN ScanTimedOut;                   ///< Scan timed out
    NTSTATUS ScanStatus;                    ///< Scan operation status
    ULONG CacheTTL;                         ///< Cache time-to-live

    //
    // Correlation
    //
    BOOLEAN CorrelatedWithRansomware;       ///< Linked to ransomware activity
    ULONG ProcessFileOpCount;               ///< Process file op counter

} PC_OPERATION_CONTEXT, *PPC_OPERATION_CONTEXT;

#define PC_OPERATION_SIGNATURE          'pOcP'  // PcOp

/**
 * @brief Pre-create configuration options
 */
typedef struct _PC_CONFIG {
    //
    // Scan policy
    //
    BOOLEAN EnableOnAccessScan;             ///< Master scan enable
    BOOLEAN EnableNetworkScan;              ///< Scan network files
    BOOLEAN EnableRemovableScan;            ///< Scan removable media
    BOOLEAN EnableArchiveScan;              ///< Scan inside archives
    BOOLEAN EnableAsyncScan;                ///< Allow async for low priority

    //
    // Threat detection
    //
    BOOLEAN EnableAdsDetection;             ///< Detect ADS abuse
    BOOLEAN EnableDoubleExtDetection;       ///< Detect double extensions
    BOOLEAN EnableHoneypotDetection;        ///< Detect honeypot access
    BOOLEAN EnablePathAnalysis;             ///< Analyze suspicious paths
    BOOLEAN EnableRansomwareCorrelation;    ///< Correlate with ransomware

    //
    // Performance
    //
    ULONG ScanTimeoutMs;                    ///< Scan timeout
    ULONG MaxConcurrentScans;               ///< Max concurrent scans
    ULONG MaxQueueDepth;                    ///< Max pending queue
    BOOLEAN FailOpenOnTimeout;              ///< Allow on timeout
    BOOLEAN FailOpenOnError;                ///< Allow on error

    //
    // Thresholds
    //
    ULONG BlockThreatScore;                 ///< Score to auto-block
    ULONG AlertThreatScore;                 ///< Score to alert

} PC_CONFIG, *PPC_CONFIG;

/**
 * @brief Pre-create statistics
 */
typedef struct _PC_STATISTICS {
    volatile LONG64 TotalOperations;        ///< Total PreCreate calls
    volatile LONG64 OperationsScanned;      ///< Files scanned
    volatile LONG64 OperationsBlocked;      ///< Files blocked
    volatile LONG64 OperationsExcluded;     ///< Files excluded
    volatile LONG64 OperationsCached;       ///< Cache hits
    volatile LONG64 ScanTimeouts;           ///< Scan timeouts
    volatile LONG64 ScanErrors;             ///< Scan errors
    volatile LONG64 SelfProtectBlocks;      ///< Self-protection blocks

    //
    // Threat detection
    //
    volatile LONG64 AdsDetections;          ///< ADS abuse detections
    volatile LONG64 DoubleExtDetections;    ///< Double extension detections
    volatile LONG64 HoneypotDetections;     ///< Honeypot access detections
    volatile LONG64 SuspiciousPathDetections; ///< Suspicious path detections
    volatile LONG64 RansomwareCorrelations; ///< Ransomware correlations

    //
    // By file class
    //
    volatile LONG64 ExecutablesScanned;     ///< Executables scanned
    volatile LONG64 ScriptsScanned;         ///< Scripts scanned
    volatile LONG64 DocumentsScanned;       ///< Documents scanned
    volatile LONG64 ArchivesScanned;        ///< Archives scanned

    //
    // Timing
    //
    LARGE_INTEGER StartTime;                ///< Module start time
    volatile LONG64 TotalScanTimeMs;        ///< Total scan time (for average)
    volatile LONG64 MaxScanTimeMs;          ///< Maximum scan time

} PC_STATISTICS, *PPC_STATISTICS;

/**
 * @brief Honeypot file configuration
 */
typedef struct _PC_HONEYPOT_CONFIG {
    UNICODE_STRING Patterns[PC_MAX_HONEYPOT_PATTERNS];
    ULONG PatternCount;
    BOOLEAN Enabled;
    BOOLEAN AlertOnly;                      ///< Alert but don't block
} PC_HONEYPOT_CONFIG, *PPC_HONEYPOT_CONFIG;

// ============================================================================
// FUNCTION PROTOTYPES - INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the PreCreate callback subsystem.
 *
 * Must be called during driver initialization before registering
 * filesystem callbacks.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
PcInitialize(
    VOID
    );

/**
 * @brief Shutdown the PreCreate callback subsystem.
 *
 * Must be called during driver unload after unregistering callbacks.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
PcShutdown(
    VOID
    );

// ============================================================================
// FUNCTION PROTOTYPES - ANALYSIS
// ============================================================================

/**
 * @brief Analyze a file path for suspicious indicators.
 *
 * @param FileName          Full file path.
 * @param Extension         File extension.
 * @param OutFlags          Receives suspicious flags.
 * @param OutThreatScore    Receives threat score (0-100).
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
PcAnalyzeFilePath(
    _In_ PCUNICODE_STRING FileName,
    _In_opt_ PCUNICODE_STRING Extension,
    _Out_ PC_SUSPICIOUS_FLAGS* OutFlags,
    _Out_ PULONG OutThreatScore
    );

/**
 * @brief Classify a file by its extension.
 *
 * @param Extension         File extension.
 * @param OutClass          Receives file classification.
 * @param OutPriority       Receives scan priority (0-100).
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
PcClassifyFile(
    _In_ PCUNICODE_STRING Extension,
    _Out_ PC_FILE_CLASS* OutClass,
    _Out_ PULONG OutPriority
    );

/**
 * @brief Detect alternate data stream access.
 *
 * @param FileName          Full file path.
 * @param OutStreamName     Receives stream name if present.
 * @param IsAds             Receives TRUE if ADS access.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
PcDetectAdsAccess(
    _In_ PCUNICODE_STRING FileName,
    _Out_opt_ PUNICODE_STRING OutStreamName,
    _Out_ PBOOLEAN IsAds
    );

/**
 * @brief Detect double/hidden file extension.
 *
 * @param FileName          Full file path.
 * @param Extension         Apparent extension.
 * @param OutRealExtension  Receives real extension if hidden.
 * @param IsDouble          Receives TRUE if double extension.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
PcDetectDoubleExtension(
    _In_ PCUNICODE_STRING FileName,
    _In_ PCUNICODE_STRING Extension,
    _Out_opt_ PUNICODE_STRING OutRealExtension,
    _Out_ PBOOLEAN IsDouble
    );

/**
 * @brief Check if file path matches honeypot patterns.
 *
 * @param FileName          Full file path.
 * @param IsHoneypot        Receives TRUE if honeypot match.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
PcCheckHoneypot(
    _In_ PCUNICODE_STRING FileName,
    _Out_ PBOOLEAN IsHoneypot
    );

// ============================================================================
// FUNCTION PROTOTYPES - CONFIGURATION
// ============================================================================

/**
 * @brief Get current PreCreate configuration.
 *
 * @param Config            Receives configuration.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
PcGetConfig(
    _Out_ PPC_CONFIG Config
    );

/**
 * @brief Update PreCreate configuration.
 *
 * @param Config            New configuration.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
PcSetConfig(
    _In_ PPC_CONFIG Config
    );

/**
 * @brief Add a honeypot file pattern.
 *
 * @param Pattern           Pattern to add (supports wildcards).
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
PcAddHoneypotPattern(
    _In_ PCUNICODE_STRING Pattern
    );

/**
 * @brief Clear all honeypot patterns.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
PcClearHoneypotPatterns(
    VOID
    );

// ============================================================================
// FUNCTION PROTOTYPES - STATISTICS
// ============================================================================

/**
 * @brief Get PreCreate statistics.
 *
 * @param Stats             Receives statistics.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
PcGetStatistics(
    _Out_ PPC_STATISTICS Stats
    );

/**
 * @brief Reset PreCreate statistics.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
PcResetStatistics(
    VOID
    );

// ============================================================================
// FUNCTION PROTOTYPES - CORRELATION
// ============================================================================

/**
 * @brief Correlate file access with ransomware behavior.
 *
 * Called to check if current file access is part of ransomware activity.
 *
 * @param ProcessId         Process performing access.
 * @param FileName          File being accessed.
 * @param AccessType        Type of access.
 * @param OutIsCorrelated   Receives TRUE if correlated.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
PcCorrelateRansomware(
    _In_ HANDLE ProcessId,
    _In_ PCUNICODE_STRING FileName,
    _In_ PC_ACCESS_TYPE AccessType,
    _Out_ PBOOLEAN OutIsCorrelated
    );

// ============================================================================
// INLINE HELPERS
// ============================================================================

/**
 * @brief Check if access type indicates execution intent.
 */
FORCEINLINE
BOOLEAN
PcIsExecuteAccess(
    _In_ ACCESS_MASK DesiredAccess
    )
{
    return (DesiredAccess & (FILE_EXECUTE | GENERIC_EXECUTE)) != 0;
}

/**
 * @brief Check if access type indicates write intent.
 */
FORCEINLINE
BOOLEAN
PcIsWriteAccess(
    _In_ ACCESS_MASK DesiredAccess
    )
{
    return (DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA |
                             GENERIC_WRITE | DELETE)) != 0;
}

/**
 * @brief Check if create options indicate delete-on-close.
 */
FORCEINLINE
BOOLEAN
PcIsDeleteOnClose(
    _In_ ULONG CreateOptions
    )
{
    return (CreateOptions & FILE_DELETE_ON_CLOSE) != 0;
}

/**
 * @brief Check if create disposition will overwrite the file.
 */
FORCEINLINE
BOOLEAN
PcIsOverwriteDisposition(
    _In_ ULONG CreateDisposition
    )
{
    return (CreateDisposition == FILE_SUPERSEDE ||
            CreateDisposition == FILE_OVERWRITE ||
            CreateDisposition == FILE_OVERWRITE_IF);
}

/**
 * @brief Calculate threat score contribution from suspicious flags.
 */
FORCEINLINE
ULONG
PcCalculateFlagScore(
    _In_ PC_SUSPICIOUS_FLAGS Flags
    )
{
    ULONG Score = 0;

    if (Flags & PcSuspiciousAdsAccess)          Score += 15;
    if (Flags & PcSuspiciousDoubleExtension)    Score += 25;
    if (Flags & PcSuspiciousTempPath)           Score += 10;
    if (Flags & PcSuspiciousRecycleBin)         Score += 10;
    if (Flags & PcSuspiciousPublicFolder)       Score += 15;
    if (Flags & PcSuspiciousAppData)            Score += 10;
    if (Flags & PcSuspiciousDownloads)          Score += 5;
    if (Flags & PcSuspiciousRemovable)          Score += 10;
    if (Flags & PcSuspiciousNetwork)            Score += 5;
    if (Flags & PcSuspiciousHoneypot)           Score += 40;
    if (Flags & PcSuspiciousZoneIdentifier)     Score += 5;
    if (Flags & PcSuspiciousHiddenFile)         Score += 10;
    if (Flags & PcSuspiciousSystemFile)         Score += 15;
    if (Flags & PcSuspiciousExecuteNoRead)      Score += 20;
    if (Flags & PcSuspiciousWriteExecute)       Score += 20;
    if (Flags & PcSuspiciousDeleteOnClose)      Score += 10;
    if (Flags & PcSuspiciousOverwrite)          Score += 5;
    if (Flags & PcSuspiciousLongPath)           Score += 10;
    if (Flags & PcSuspiciousUnicodeRLO)         Score += 30;
    if (Flags & PcSuspiciousTrailingSpace)      Score += 15;
    if (Flags & PcSuspiciousReservedName)       Score += 20;

    return (Score > 100) ? 100 : Score;
}

#ifdef __cplusplus
}
#endif

#endif // _SHADOWSTRIKE_PRECREATE_H_
