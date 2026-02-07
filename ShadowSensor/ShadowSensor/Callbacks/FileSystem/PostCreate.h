/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE POST-CREATE CALLBACK HEADER
 * ============================================================================
 *
 * @file PostCreate.h
 * @brief Enterprise-grade IRP_MJ_CREATE post-operation callback for kernel EDR.
 *
 * This module provides comprehensive post-create handling and stream context
 * management for file system monitoring:
 * - Stream context attachment and lifecycle management
 * - File attribute caching for performance optimization
 * - Scan verdict correlation between pre-create and post-create
 * - File ID tracking for cache integration
 * - Change detection baseline establishment
 * - Alternate data stream context tracking
 * - Volume context correlation
 * - File classification persistence
 * - Security descriptor caching
 * - Real-time file monitoring setup
 *
 * Context Management:
 * - Stream contexts for per-file-stream state
 * - Stream handle contexts for per-open state
 * - Instance contexts for per-volume state
 * - Proper reference counting and cleanup
 *
 * Integration Points:
 * - ScanCache: Verdict caching correlation
 * - PreCreate: Completion context handling
 * - PostWrite: Change detection baseline
 * - RansomwareDetection: File monitoring setup
 * - TelemetryEvents: File access telemetry
 *
 * Performance Characteristics:
 * - O(1) context lookup via FltGetStreamContext
 * - Lookaside list allocation for contexts
 * - Minimal blocking in post-create path
 * - Efficient file attribute querying
 *
 * MITRE ATT&CK Coverage:
 * - T1486: Data Encrypted for Impact (ransomware baseline)
 * - T1485: Data Destruction (change tracking)
 * - T1564.004: NTFS File Attributes (ADS tracking)
 * - T1070.004: Indicator Removal on Host (file deletion tracking)
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_POSTCREATE_H_
#define _SHADOWSTRIKE_POSTCREATE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <fltKernel.h>
#include <ntifs.h>

// ============================================================================
// POOL TAGS
// ============================================================================

#define POC_POOL_TAG                    'COPP'  // PPOC - PostCreate
#define POC_CONTEXT_TAG                 'xCOC'  // COCx - Context
#define POC_STREAM_TAG                  'tSCP'  // PCSt - Stream
#define POC_HANDLE_TAG                  'hHCP'  // PCHh - Handle

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * @brief Maximum file name length to cache in context
 */
#define POC_MAX_CACHED_NAME             256

/**
 * @brief Maximum extension length to cache
 */
#define POC_MAX_CACHED_EXTENSION        32

/**
 * @brief Stream context signature for validation
 */
#define POC_STREAM_CONTEXT_SIGNATURE    'tXcS'  // ScXt

/**
 * @brief Handle context signature for validation
 */
#define POC_HANDLE_CONTEXT_SIGNATURE    'tXcH'  // HcXt

/**
 * @brief Context allocation lookaside depth
 */
#define POC_CONTEXT_LOOKASIDE_DEPTH     128

/**
 * @brief Maximum pending context operations
 */
#define POC_MAX_PENDING_CONTEXTS        1024

/**
 * @brief Context expiry time for orphaned contexts (30 minutes)
 */
#define POC_CONTEXT_EXPIRY_100NS        (30LL * 60LL * 10000000LL)

/**
 * @brief Rate limit for logging (per second)
 */
#define POC_LOG_RATE_LIMIT_PER_SEC      50

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Post-create operation result
 */
typedef enum _POC_RESULT {
    PocResultSuccess            = 0,    ///< Context attached successfully
    PocResultExisting           = 1,    ///< Used existing context
    PocResultFailed             = 2,    ///< Context attachment failed
    PocResultSkipped            = 3,    ///< Operation skipped (draining, etc.)
    PocResultNoMemory           = 4,    ///< Insufficient resources
    PocResultInvalidObject      = 5     ///< Invalid file object
} POC_RESULT;

/**
 * @brief File tracking flags
 */
typedef enum _POC_TRACKING_FLAGS {
    PocTrackingNone             = 0x00000000,
    PocTrackingScanned          = 0x00000001,   ///< File was scanned
    PocTrackingCached           = 0x00000002,   ///< Verdict is cached
    PocTrackingModified         = 0x00000004,   ///< File has been modified
    PocTrackingDeleted          = 0x00000008,   ///< File marked for deletion
    PocTrackingRenamed          = 0x00000010,   ///< File was renamed
    PocTrackingExecuted         = 0x00000020,   ///< File was executed
    PocTrackingMapped           = 0x00000040,   ///< File was memory mapped
    PocTrackingAds              = 0x00000080,   ///< Has alternate data streams
    PocTrackingEncrypted        = 0x00000100,   ///< File is encrypted (EFS)
    PocTrackingCompressed       = 0x00000200,   ///< File is compressed
    PocTrackingSparse           = 0x00000400,   ///< File is sparse
    PocTrackingHidden           = 0x00000800,   ///< File has hidden attribute
    PocTrackingSystem           = 0x00001000,   ///< File has system attribute
    PocTrackingReadOnly         = 0x00002000,   ///< File is read-only
    PocTrackingTemporary        = 0x00004000,   ///< File is temporary
    PocTrackingNetwork          = 0x00008000,   ///< File is on network
    PocTrackingRemovable        = 0x00010000,   ///< File is on removable media
    PocTrackingRansomwareWatch  = 0x00020000,   ///< Under ransomware monitoring
    PocTrackingHoneypot         = 0x00040000,   ///< Is a honeypot file
    PocTrackingSuspicious       = 0x00080000,   ///< Marked as suspicious
    PocTrackingBlocked          = 0x00100000,   ///< Access was blocked
    PocTrackingQuarantined      = 0x00200000    ///< File was quarantined
} POC_TRACKING_FLAGS;

/**
 * @brief File classification for tracking
 */
typedef enum _POC_FILE_CLASS {
    PocFileClassUnknown         = 0,
    PocFileClassExecutable      = 1,    ///< PE executables
    PocFileClassScript          = 2,    ///< Script files
    PocFileClassDocument        = 3,    ///< Office documents
    PocFileClassArchive         = 4,    ///< Archive files
    PocFileClassMedia           = 5,    ///< Media files
    PocFileClassData            = 6,    ///< Data files
    PocFileClassConfig          = 7,    ///< Configuration files
    PocFileClassCertificate     = 8,    ///< Certificate/key files
    PocFileClassDatabase        = 9,    ///< Database files
    PocFileClassBackup          = 10,   ///< Backup files
    PocFileClassLog             = 11,   ///< Log files
    PocFileClassTemporary       = 12    ///< Temporary files
} POC_FILE_CLASS;

// ============================================================================
// STREAM CONTEXT STRUCTURE
// ============================================================================

/**
 * @brief Enterprise stream context for file tracking.
 *
 * Attached to file streams to track state across operations.
 * Used for change detection, cache correlation, and ransomware monitoring.
 */
typedef struct _SHADOWSTRIKE_STREAM_CONTEXT {
    //
    // Validation
    //
    ULONG Signature;                    ///< POC_STREAM_CONTEXT_SIGNATURE

    //
    // File identification
    //
    LONGLONG FileId;                    ///< File ID (from FileInternalInformation)
    ULONG VolumeSerial;                 ///< Volume serial number
    LONGLONG ScanFileSize;              ///< File size at scan time
    LARGE_INTEGER LastWriteTime;        ///< Last write time at scan
    LARGE_INTEGER CreationTime;         ///< Creation time

    //
    // Cached file name (optional, for logging)
    //
    WCHAR CachedFileName[POC_MAX_CACHED_NAME];
    USHORT CachedFileNameLength;        ///< Length in characters
    WCHAR CachedExtension[POC_MAX_CACHED_EXTENSION];
    USHORT CachedExtensionLength;       ///< Length in characters

    //
    // Classification
    //
    POC_FILE_CLASS FileClass;           ///< File classification
    ULONG FileAttributes;               ///< Cached file attributes

    //
    // Scan state
    //
    BOOLEAN Scanned;                    ///< File was scanned
    BOOLEAN ScanResult;                 ///< Scan result (TRUE = clean)
    LARGE_INTEGER ScanTime;             ///< Time of last scan
    ULONG ScanVerdictTTL;               ///< Verdict cache TTL
    UINT8 ThreatScore;                  ///< Threat score (0-100)
    UINT8 Reserved1[3];                 ///< Alignment

    //
    // Change tracking
    //
    BOOLEAN Dirty;                      ///< File has been modified
    BOOLEAN DeletePending;              ///< Deletion in progress
    BOOLEAN RenamePending;              ///< Rename in progress
    BOOLEAN Closed;                     ///< File has been closed
    volatile LONG OpenCount;            ///< Number of open handles
    volatile LONG WriteCount;           ///< Number of write operations
    volatile LONG ReadCount;            ///< Number of read operations
    LARGE_INTEGER FirstWriteTime;       ///< Time of first write
    LARGE_INTEGER LastModifyTime;       ///< Time of last modification

    //
    // Hash for change detection
    //
    UCHAR ContentHash[32];              ///< SHA-256 hash of content (optional)
    BOOLEAN HashValid;                  ///< Hash is computed
    UINT8 Reserved2[7];                 ///< Alignment

    //
    // Tracking flags
    //
    POC_TRACKING_FLAGS TrackingFlags;   ///< Combined tracking flags

    //
    // Ransomware monitoring
    //
    BOOLEAN RansomwareMonitored;        ///< Under ransomware watch
    UINT8 RansomwareRiskScore;          ///< Ransomware risk (0-100)
    UINT8 Reserved3[2];                 ///< Alignment
    ULONG EntropyScore;                 ///< Content entropy indicator
    ULONG OriginalEntropyScore;         ///< Original entropy before modification

    //
    // Security
    //
    BOOLEAN IsProtectedFile;            ///< Self-protection target
    BOOLEAN IsHoneypotFile;             ///< Honeypot decoy file
    UINT8 Reserved4[2];                 ///< Alignment

    //
    // Timing
    //
    LARGE_INTEGER ContextCreateTime;    ///< When context was created
    LARGE_INTEGER LastAccessTime;       ///< Last access to this context

    //
    // Synchronization
    //
    EX_PUSH_LOCK Lock;                  ///< Context lock

} SHADOWSTRIKE_STREAM_CONTEXT, *PSHADOWSTRIKE_STREAM_CONTEXT;

// ============================================================================
// STREAM HANDLE CONTEXT STRUCTURE
// ============================================================================

/**
 * @brief Per-open handle context.
 *
 * Tracks state for individual file opens (handles).
 */
typedef struct _SHADOWSTRIKE_HANDLE_CONTEXT {
    //
    // Validation
    //
    ULONG Signature;                    ///< POC_HANDLE_CONTEXT_SIGNATURE

    //
    // Handle information
    //
    HANDLE ProcessId;                   ///< Opening process ID
    HANDLE ThreadId;                    ///< Opening thread ID
    ACCESS_MASK DesiredAccess;          ///< Requested access
    ULONG CreateOptions;                ///< Create options
    ULONG ShareAccess;                  ///< Share access

    //
    // State
    //
    BOOLEAN WritePerformed;             ///< Handle wrote to file
    BOOLEAN DeletePerformed;            ///< Handle deleted file
    BOOLEAN RenamePerformed;            ///< Handle renamed file
    BOOLEAN ExecutePerformed;           ///< Handle executed file
    BOOLEAN CloseInProgress;            ///< Close is in progress
    UINT8 Reserved[3];                  ///< Alignment

    //
    // Timing
    //
    LARGE_INTEGER OpenTime;             ///< When handle was opened
    LARGE_INTEGER LastOperationTime;    ///< Last operation time

    //
    // Statistics
    //
    volatile LONG WriteCount;           ///< Writes through this handle
    volatile LONG ReadCount;            ///< Reads through this handle

} SHADOWSTRIKE_HANDLE_CONTEXT, *PSHADOWSTRIKE_HANDLE_CONTEXT;

// ============================================================================
// COMPLETION CONTEXT STRUCTURE
// ============================================================================

/**
 * @brief Pre-create to post-create completion context.
 *
 * Passed from PreCreate to PostCreate to convey scan results.
 */
typedef struct _POC_COMPLETION_CONTEXT {
    //
    // Validation
    //
    ULONG Signature;                    ///< Validation signature
    ULONG Size;                         ///< Structure size

    //
    // Scan results from PreCreate
    //
    BOOLEAN WasScanned;                 ///< File was scanned
    BOOLEAN ScanResult;                 ///< TRUE = clean, FALSE = threat
    UINT8 ThreatScore;                  ///< Threat score (0-100)
    UINT8 Reserved1;                    ///< Alignment
    ULONG CacheTTL;                     ///< Cache time-to-live

    //
    // File classification
    //
    POC_FILE_CLASS FileClass;           ///< Detected file class
    POC_TRACKING_FLAGS SuspicionFlags;  ///< Suspicious indicators

    //
    // Timing
    //
    LARGE_INTEGER PreCreateTime;        ///< PreCreate timestamp
    ULONG ScanDurationMs;               ///< Scan duration

    //
    // Process info
    //
    HANDLE ProcessId;                   ///< Requesting process
    HANDLE ThreadId;                    ///< Requesting thread

} POC_COMPLETION_CONTEXT, *PPOC_COMPLETION_CONTEXT;

#define POC_COMPLETION_SIGNATURE        'pCcP'  // PcCp

// ============================================================================
// POST-CREATE STATE STRUCTURE
// ============================================================================

/**
 * @brief Global PostCreate subsystem state.
 */
typedef struct _POC_GLOBAL_STATE {
    //
    // Initialization
    //
    BOOLEAN Initialized;

    //
    // Context registration
    //
    BOOLEAN StreamContextRegistered;
    BOOLEAN HandleContextRegistered;
    UINT8 Reserved1;

    //
    // Rate limiting
    //
    volatile LONG CurrentSecondLogs;
    LARGE_INTEGER CurrentSecondStart;

    //
    // Statistics
    //
    struct {
        volatile LONG64 TotalPostCreates;
        volatile LONG64 ContextsCreated;
        volatile LONG64 ContextsReused;
        volatile LONG64 ContextsFailed;
        volatile LONG64 ContextsSkipped;
        volatile LONG64 ScannedFiles;
        volatile LONG64 CachedResults;
        volatile LONG64 DirectoriesSkipped;
        volatile LONG64 VolumeOpensSkipped;
        volatile LONG64 DrainingSkipped;
        volatile LONG64 ErrorsHandled;
        LARGE_INTEGER StartTime;
    } Stats;

    //
    // Configuration
    //
    struct {
        BOOLEAN EnableContextCaching;       ///< Cache file names in context
        BOOLEAN EnableChangeTracking;       ///< Track file modifications
        BOOLEAN EnableRansomwareWatch;      ///< Ransomware monitoring
        BOOLEAN EnableHoneypotTracking;     ///< Honeypot file tracking
        BOOLEAN LogContextCreation;         ///< Log context operations
        UINT8 Reserved[3];
    } Config;

    //
    // Shutdown
    //
    volatile BOOLEAN ShutdownRequested;

} POC_GLOBAL_STATE, *PPOC_GLOBAL_STATE;

// ============================================================================
// FUNCTION PROTOTYPES - INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the PostCreate callback subsystem.
 *
 * Must be called during driver initialization before registering callbacks.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
PocInitialize(
    VOID
    );

/**
 * @brief Shutdown the PostCreate callback subsystem.
 *
 * Must be called during driver unload after unregistering callbacks.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
PocShutdown(
    VOID
    );

// ============================================================================
// FUNCTION PROTOTYPES - CONTEXT MANAGEMENT
// ============================================================================

/**
 * @brief Allocate and initialize a stream context.
 *
 * @param FltObjects        Filter objects from callback.
 * @param OutContext        Receives allocated context.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
PocAllocateStreamContext(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PSHADOWSTRIKE_STREAM_CONTEXT* OutContext
    );

/**
 * @brief Get or create stream context for a file.
 *
 * @param FltObjects        Filter objects from callback.
 * @param OutContext        Receives context (existing or new).
 * @param OutCreated        Receives TRUE if context was newly created.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
PocGetOrCreateStreamContext(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PSHADOWSTRIKE_STREAM_CONTEXT* OutContext,
    _Out_opt_ PBOOLEAN OutCreated
    );

/**
 * @brief Update stream context with file information.
 *
 * @param FltObjects        Filter objects from callback.
 * @param Context           Stream context to update.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
PocUpdateStreamContext(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Inout_ PSHADOWSTRIKE_STREAM_CONTEXT Context
    );

/**
 * @brief Apply completion context to stream context.
 *
 * Transfers scan results from PreCreate to stream context.
 *
 * @param StreamContext     Stream context to update.
 * @param CompletionContext Completion context from PreCreate.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
PocApplyCompletionContext(
    _Inout_ PSHADOWSTRIKE_STREAM_CONTEXT StreamContext,
    _In_ PPOC_COMPLETION_CONTEXT CompletionContext
    );

/**
 * @brief Release a stream context reference.
 *
 * @param Context           Context to release.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
PocReleaseStreamContext(
    _In_ PSHADOWSTRIKE_STREAM_CONTEXT Context
    );

// ============================================================================
// FUNCTION PROTOTYPES - COMPLETION CONTEXT
// ============================================================================

/**
 * @brief Allocate a completion context for PreCreate to PostCreate.
 *
 * @param OutContext        Receives allocated context.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
PocAllocateCompletionContext(
    _Out_ PPOC_COMPLETION_CONTEXT* OutContext
    );

/**
 * @brief Free a completion context.
 *
 * @param Context           Context to free.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
PocFreeCompletionContext(
    _In_ PPOC_COMPLETION_CONTEXT Context
    );

// ============================================================================
// FUNCTION PROTOTYPES - UTILITIES
// ============================================================================

/**
 * @brief Query file attributes and cache in context.
 *
 * @param FltObjects        Filter objects from callback.
 * @param Context           Context to update.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
PocQueryFileAttributes(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Inout_ PSHADOWSTRIKE_STREAM_CONTEXT Context
    );

/**
 * @brief Cache file name in stream context.
 *
 * @param NameInfo          File name information.
 * @param Context           Context to update.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
PocCacheFileName(
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _Inout_ PSHADOWSTRIKE_STREAM_CONTEXT Context
    );

/**
 * @brief Classify file based on extension.
 *
 * @param Extension         File extension.
 *
 * @return File classification.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
POC_FILE_CLASS
PocClassifyFileExtension(
    _In_opt_ PCUNICODE_STRING Extension
    );

/**
 * @brief Mark file as modified in context.
 *
 * @param Context           Stream context.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
PocMarkFileModified(
    _Inout_ PSHADOWSTRIKE_STREAM_CONTEXT Context
    );

/**
 * @brief Invalidate scan result for file.
 *
 * Called when file is modified to force re-scan.
 *
 * @param Context           Stream context.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
PocInvalidateScanResult(
    _Inout_ PSHADOWSTRIKE_STREAM_CONTEXT Context
    );

// ============================================================================
// FUNCTION PROTOTYPES - STATISTICS
// ============================================================================

/**
 * @brief Get PostCreate statistics.
 *
 * @param TotalPostCreates      Receives total post-creates.
 * @param ContextsCreated       Receives contexts created.
 * @param ContextsReused        Receives contexts reused.
 * @param ContextsFailed        Receives context failures.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
PocGetStatistics(
    _Out_opt_ PULONG64 TotalPostCreates,
    _Out_opt_ PULONG64 ContextsCreated,
    _Out_opt_ PULONG64 ContextsReused,
    _Out_opt_ PULONG64 ContextsFailed
    );

/**
 * @brief Reset PostCreate statistics.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
PocResetStatistics(
    VOID
    );

// ============================================================================
// INLINE HELPERS
// ============================================================================

/**
 * @brief Validate stream context signature.
 */
FORCEINLINE
BOOLEAN
PocIsValidStreamContext(
    _In_opt_ PSHADOWSTRIKE_STREAM_CONTEXT Context
    )
{
    return (Context != NULL && Context->Signature == POC_STREAM_CONTEXT_SIGNATURE);
}

/**
 * @brief Validate completion context signature.
 */
FORCEINLINE
BOOLEAN
PocIsValidCompletionContext(
    _In_opt_ PPOC_COMPLETION_CONTEXT Context
    )
{
    return (Context != NULL && Context->Signature == POC_COMPLETION_SIGNATURE);
}

/**
 * @brief Check if file needs re-scan based on modification.
 */
FORCEINLINE
BOOLEAN
PocNeedsRescan(
    _In_ PSHADOWSTRIKE_STREAM_CONTEXT Context
    )
{
    if (Context == NULL) {
        return TRUE;
    }

    if (!Context->Scanned) {
        return TRUE;
    }

    if (Context->Dirty) {
        return TRUE;
    }

    return FALSE;
}

/**
 * @brief Check if context is under ransomware monitoring.
 */
FORCEINLINE
BOOLEAN
PocIsRansomwareMonitored(
    _In_ PSHADOWSTRIKE_STREAM_CONTEXT Context
    )
{
    return (Context != NULL && Context->RansomwareMonitored);
}

/**
 * @brief Get file classification from context.
 */
FORCEINLINE
POC_FILE_CLASS
PocGetFileClass(
    _In_ PSHADOWSTRIKE_STREAM_CONTEXT Context
    )
{
    if (Context == NULL) {
        return PocFileClassUnknown;
    }
    return Context->FileClass;
}

#ifdef __cplusplus
}
#endif

#endif // _SHADOWSTRIKE_POSTCREATE_H_
