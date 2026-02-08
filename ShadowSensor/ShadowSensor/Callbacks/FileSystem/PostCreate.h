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
 * - Stream handle context for per-open tracking
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
 * - Lookaside list allocation for performance
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
 * @version 2.1.0 (Enterprise Edition)
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
#define POC_LOOKASIDE_TAG               'lLCP'  // PCLl - Lookaside

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
 * @brief Cryptographic cookie seed for context validation.
 *
 * Combined with context address to create a harder-to-forge signature.
 * This prevents attacks where an attacker with arbitrary kernel write
 * can simply set Signature = POC_*_SIGNATURE to bypass validation.
 */
#define POC_CONTEXT_COOKIE_SEED         0xDEADBEEFCAFEBABEULL

/**
 * @brief Context allocation lookaside depth
 */
#define POC_CONTEXT_LOOKASIDE_DEPTH     128

/**
 * @brief Completion context lookaside depth
 */
#define POC_COMPLETION_LOOKASIDE_DEPTH  64

/**
 * @brief Handle context lookaside depth
 */
#define POC_HANDLE_LOOKASIDE_DEPTH      256

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

/**
 * @brief One second in 100-nanosecond units
 */
#define POC_ONE_SECOND_100NS            10000000LL

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
    // Validation - cryptographic cookie prevents arbitrary kernel write attacks
    //
    ULONG Signature;                    ///< POC_STREAM_CONTEXT_SIGNATURE
    ULONG64 SecurityCookie;             ///< Address-based crypto cookie

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
    // Validation - cryptographic cookie prevents arbitrary kernel write attacks
    //
    ULONG Signature;                    ///< POC_HANDLE_CONTEXT_SIGNATURE
    ULONG64 SecurityCookie;             ///< Address-based crypto cookie

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

    //
    // Synchronization
    //
    EX_PUSH_LOCK Lock;                  ///< Handle context lock

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
    // Validation - cryptographic cookie prevents arbitrary kernel write attacks
    //
    ULONG Signature;                    ///< Validation signature
    ULONG Size;                         ///< Structure size
    ULONG64 SecurityCookie;             ///< Address-based crypto cookie

    //
    // Ownership tracking (prevents double-free)
    //
    volatile LONG OwnershipToken;       ///< 1 = owned, 0 = released

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
    // Initialization (atomic)
    //
    volatile LONG Initialized;
    volatile LONG ShutdownRequested;

    //
    // Context registration
    //
    BOOLEAN StreamContextRegistered;
    BOOLEAN HandleContextRegistered;
    UINT8 Reserved1[2];

    //
    // Lookaside lists
    //
    NPAGED_LOOKASIDE_LIST CompletionContextLookaside;
    NPAGED_LOOKASIDE_LIST HandleContextLookaside;
    BOOLEAN LookasideInitialized;
    UINT8 Reserved2[7];

    //
    // Rate limiting (atomic)
    //
    volatile LONG CurrentSecondLogs;
    volatile LONGLONG CurrentSecondStart;

    //
    // Statistics (all atomic)
    //
    struct {
        volatile LONG64 TotalPostCreates;
        volatile LONG64 ContextsCreated;
        volatile LONG64 ContextsReused;
        volatile LONG64 ContextsFailed;
        volatile LONG64 ContextsSkipped;
        volatile LONG64 HandleContextsCreated;
        volatile LONG64 HandleContextsFailed;
        volatile LONG64 ScannedFiles;
        volatile LONG64 CachedResults;
        volatile LONG64 DirectoriesSkipped;
        volatile LONG64 VolumeOpensSkipped;
        volatile LONG64 DrainingSkipped;
        volatile LONG64 ErrorsHandled;
        volatile LONG64 SignatureMismatches;
        volatile LONG64 InvalidContexts;
        volatile LONG64 DoubleFreeAttempts;
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
        BOOLEAN EnableHandleContexts;       ///< Per-handle tracking
        BOOLEAN LogContextCreation;         ///< Log context operations
        UINT8 Reserved[2];
    } Config;

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
// FUNCTION PROTOTYPES - MAIN CALLBACK
// ============================================================================

/**
 * @brief Post-create callback for IRP_MJ_CREATE.
 *
 * @param Data              Callback data.
 * @param FltObjects        Filter objects.
 * @param CompletionContext Completion context from PreCreate.
 * @param Flags             Post-operation flags.
 *
 * @return FLT_POSTOP_FINISHED_PROCESSING.
 *
 * @irql PASSIVE_LEVEL (post-create is always at PASSIVE)
 */
_IRQL_requires_(PASSIVE_LEVEL)
FLT_POSTOP_CALLBACK_STATUS
ShadowStrikePostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
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
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
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
// FUNCTION PROTOTYPES - HANDLE CONTEXT MANAGEMENT
// ============================================================================

/**
 * @brief Allocate and initialize a handle context.
 *
 * @param Data              Callback data for access info.
 * @param OutContext        Receives allocated context.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
PocAllocateHandleContext(
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_ PSHADOWSTRIKE_HANDLE_CONTEXT* OutContext
    );

/**
 * @brief Get or create handle context for a file open.
 *
 * @param FltObjects        Filter objects from callback.
 * @param Data              Callback data for access info.
 * @param OutContext        Receives context.
 * @param OutCreated        Receives TRUE if newly created.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
PocGetOrCreateHandleContext(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_ PSHADOWSTRIKE_HANDLE_CONTEXT* OutContext,
    _Out_opt_ PBOOLEAN OutCreated
    );

/**
 * @brief Release a handle context reference.
 *
 * @param Context           Context to release.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
PocReleaseHandleContext(
    _In_ PSHADOWSTRIKE_HANDLE_CONTEXT Context
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
 * Thread-safe with double-free protection.
 *
 * @param Context           Context to free (will be NULLed).
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
PocFreeCompletionContext(
    _Inout_ PPOC_COMPLETION_CONTEXT* Context
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
 * @irql <= APC_LEVEL (uses case-insensitive compare)
 */
_IRQL_requires_max_(APC_LEVEL)
POC_FILE_CLASS
PocClassifyFileExtension(
    _In_opt_ PCUNICODE_STRING Extension
    );

/**
 * @brief Mark file as modified in context.
 *
 * @param Context           Stream context.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
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
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
PocInvalidateScanResult(
    _Inout_ PSHADOWSTRIKE_STREAM_CONTEXT Context
    );

// ============================================================================
// FUNCTION PROTOTYPES - STATISTICS
// ============================================================================

/**
 * @brief Get PostCreate statistics (atomic reads).
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
 * @brief Get extended error statistics.
 *
 * @param SignatureMismatches   Receives signature mismatch count.
 * @param InvalidContexts       Receives invalid context count.
 * @param DoubleFreeAttempts    Receives double-free attempt count.
 *
 * @return STATUS_SUCCESS.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
PocGetErrorStatistics(
    _Out_opt_ PULONG64 SignatureMismatches,
    _Out_opt_ PULONG64 InvalidContexts,
    _Out_opt_ PULONG64 DoubleFreeAttempts
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
 * @brief Compute cryptographic cookie for a context address.
 *
 * Combines the context address with a secret seed to create a value
 * that is difficult to forge without knowing both the address and seed.
 * This prevents kernel write attacks from simply setting Signature.
 */
FORCEINLINE
ULONG64
PocComputeSecurityCookie(
    _In_ PVOID ContextAddress
    )
{
    ULONG64 addr = (ULONG64)(ULONG_PTR)ContextAddress;
    //
    // Mix the address with the seed using XOR and rotation
    // This creates a value that depends on both address and seed
    //
    ULONG64 cookie = addr ^ POC_CONTEXT_COOKIE_SEED;
    cookie = (cookie >> 17) | (cookie << 47);  // Rotate right 17
    cookie ^= (addr << 13);
    cookie ^= POC_CONTEXT_COOKIE_SEED;
    return cookie;
}

/**
 * @brief Validate stream context signature and security cookie.
 */
FORCEINLINE
BOOLEAN
PocIsValidStreamContext(
    _In_opt_ PSHADOWSTRIKE_STREAM_CONTEXT Context
    )
{
    if (Context == NULL) {
        return FALSE;
    }
    if (Context->Signature != POC_STREAM_CONTEXT_SIGNATURE) {
        return FALSE;
    }
    //
    // Validate cryptographic cookie matches expected value for this address
    //
    if (Context->SecurityCookie != PocComputeSecurityCookie(Context)) {
        return FALSE;
    }
    return TRUE;
}

/**
 * @brief Validate handle context signature and security cookie.
 */
FORCEINLINE
BOOLEAN
PocIsValidHandleContext(
    _In_opt_ PSHADOWSTRIKE_HANDLE_CONTEXT Context
    )
{
    if (Context == NULL) {
        return FALSE;
    }
    if (Context->Signature != POC_HANDLE_CONTEXT_SIGNATURE) {
        return FALSE;
    }
    //
    // Validate cryptographic cookie matches expected value for this address
    //
    if (Context->SecurityCookie != PocComputeSecurityCookie(Context)) {
        return FALSE;
    }
    return TRUE;
}

/**
 * @brief Validate completion context signature and security cookie.
 */
FORCEINLINE
BOOLEAN
PocIsValidCompletionContext(
    _In_opt_ PPOC_COMPLETION_CONTEXT Context
    )
{
    if (Context == NULL) {
        return FALSE;
    }
    if (Context->Signature != POC_COMPLETION_SIGNATURE) {
        return FALSE;
    }
    if (Context->Size != sizeof(POC_COMPLETION_CONTEXT)) {
        return FALSE;
    }
    //
    // Validate cryptographic cookie matches expected value for this address
    //
    if (Context->SecurityCookie != PocComputeSecurityCookie(Context)) {
        return FALSE;
    }
    return TRUE;
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

/**
 * @brief Atomic read of LONG64 value (safe on 32-bit).
 */
FORCEINLINE
LONG64
PocAtomicRead64(
    _In_ volatile LONG64* Target
    )
{
#ifdef _WIN64
    return *Target;
#else
    return InterlockedCompareExchange64(Target, 0, 0);
#endif
}

/**
 * @brief Atomic read of LONGLONG value (safe on 32-bit).
 */
FORCEINLINE
LONGLONG
PocAtomicReadLongLong(
    _In_ volatile LONGLONG* Target
    )
{
#ifdef _WIN64
    return *Target;
#else
    return (LONGLONG)InterlockedCompareExchange64((volatile LONG64*)Target, 0, 0);
#endif
}

#ifdef __cplusplus
}
#endif

#endif // _SHADOWSTRIKE_POSTCREATE_H_
