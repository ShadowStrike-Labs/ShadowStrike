/**
 * ============================================================================
 * ShadowStrike NGAV - INSTANCE CONTEXT
 * ============================================================================
 *
 * @file InstanceContext.h
 * @brief Instance context definitions and management for per-volume state tracking.
 *
 * Provides instance context management for tracking per-volume configuration,
 * statistics, and state. Instance contexts are attached to each volume that
 * the minifilter attaches to and persist for the lifetime of the attachment.
 *
 * Use Cases:
 * - Per-volume scan statistics (files scanned, blocked, etc.)
 * - Volume-specific configuration overrides
 * - Network volume detection and policy enforcement
 * - Removable media tracking and protection
 * - Volume serial number caching for performance
 * - Filesystem capability detection (FileIDs, streams, etc.)
 *
 * Thread Safety Model:
 * - ERESOURCE protects: VolumeName, VolumeGUIDName, VolumeType, capabilities
 * - Interlocked operations protect: all statistics counters
 * - Policy flags are immutable after initialization (no lock needed for reads)
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_INSTANCE_CONTEXT_H
#define SHADOWSTRIKE_INSTANCE_CONTEXT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <fltKernel.h>
#include <ntddk.h>

// ============================================================================
// POOL TAGS
// ============================================================================

/**
 * @brief Pool tag for instance context allocations: 'iSSx' = ShadowStrike Instance
 */
#define SHADOW_INSTANCE_TAG 'iSSx'

/**
 * @brief Pool tag for instance string buffers
 */
#define SHADOW_INSTANCE_STRING_TAG 'sSSi'

/**
 * @brief Context signature for corruption detection: 'SSiC' = ShadowStrike Instance Context
 *
 * This magic value is validated in all public functions to detect memory corruption
 * or invalid context pointers before dereferencing fields.
 */
#define SHADOW_INSTANCE_CONTEXT_SIGNATURE 'CiSS'

// ============================================================================
// LOGGING MACROS
// ============================================================================

/**
 * @brief Centralized logging macros for consistent debug output.
 *
 * These macros wrap DbgPrintEx and can be fully disabled in production builds.
 * Log levels follow standard kernel conventions:
 * - ERROR: Critical failures that may cause functional problems
 * - WARNING: Non-fatal issues that may indicate problems
 * - INFO: Informational messages for normal operation
 * - TRACE: Verbose debugging output
 */
#if DBG
    #define SHADOW_LOG_ERROR(fmt, ...) \
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, \
                   "[ShadowStrike:InstanceCtx] ERROR: " fmt "\n", ##__VA_ARGS__)

    #define SHADOW_LOG_WARNING(fmt, ...) \
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, \
                   "[ShadowStrike:InstanceCtx] WARN: " fmt "\n", ##__VA_ARGS__)

    #define SHADOW_LOG_INFO(fmt, ...) \
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, \
                   "[ShadowStrike:InstanceCtx] INFO: " fmt "\n", ##__VA_ARGS__)

    #define SHADOW_LOG_TRACE(fmt, ...) \
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, \
                   "[ShadowStrike:InstanceCtx] TRACE: " fmt "\n", ##__VA_ARGS__)
#else
    #define SHADOW_LOG_ERROR(fmt, ...)   ((void)0)
    #define SHADOW_LOG_WARNING(fmt, ...) ((void)0)
    #define SHADOW_LOG_INFO(fmt, ...)    ((void)0)
    #define SHADOW_LOG_TRACE(fmt, ...)   ((void)0)
#endif

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * @brief Maximum volume name length we will cache (in bytes)
 */
#define SHADOW_MAX_VOLUME_NAME_LENGTH 512

/**
 * @brief Maximum GUID name length we will cache (in bytes)
 */
#define SHADOW_MAX_GUID_NAME_LENGTH 128

// ============================================================================
// VOLUME TYPE FLAGS
// ============================================================================

/**
 * @brief Volume type classification flags (can be combined).
 */
typedef enum _SHADOW_VOLUME_TYPE {
    VolumeTypeUnknown       = 0x00000000,
    VolumeTypeFixed         = 0x00000001,  ///< Fixed local disk (C:, D:)
    VolumeTypeRemovable     = 0x00000002,  ///< USB, external HDD
    VolumeTypeNetwork       = 0x00000004,  ///< Network share (SMB/CIFS)
    VolumeTypeCDROM         = 0x00000008,  ///< CD/DVD drive
    VolumeTypeRAMDisk       = 0x00000010,  ///< RAM disk
    VolumeTypeVirtual       = 0x00000020,  ///< Virtual disk (VHD, VHDX)
} SHADOW_VOLUME_TYPE;

// ============================================================================
// FILESYSTEM CAPABILITIES
// ============================================================================

/**
 * @brief Filesystem capability flags queried from volume.
 */
typedef struct _SHADOW_FS_CAPABILITIES {
    BOOLEAN SupportsFileIds;        ///< Supports 64-bit file IDs (NTFS, ReFS)
    BOOLEAN SupportsStreams;        ///< Supports alternate data streams
    BOOLEAN SupportsObjectIds;      ///< Supports object IDs
    BOOLEAN SupportsReparsePoints;  ///< Supports reparse points
    BOOLEAN SupportsSparseFiles;    ///< Supports sparse files
    BOOLEAN SupportsEncryption;     ///< Supports EFS encryption
    BOOLEAN SupportsCompression;    ///< Supports file compression
    BOOLEAN SupportsHardLinks;      ///< Supports hard links
} SHADOW_FS_CAPABILITIES, *PSHADOW_FS_CAPABILITIES;

// ============================================================================
// INSTANCE CONTEXT STRUCTURE
// ============================================================================

/**
 * @brief Per-instance (per-volume) context structure.
 *
 * This structure is allocated by the Filter Manager and associated with
 * each volume instance where the minifilter attaches. It tracks volume-
 * specific state, configuration, and statistics.
 *
 * Thread Safety:
 * - Resource lock protects: VolumeName, VolumeGUIDName, VolumeType,
 *   FilesystemType, DeviceType, Capabilities, IsReadOnly
 * - Interlocked operations protect: all LONGLONG statistics fields
 * - Policy flags (ScanningEnabled, etc.) are set once during init
 *
 * Lifetime: Created during InstanceSetup, destroyed during InstanceTeardown.
 *
 * Memory Management:
 * - Structure allocated by Filter Manager via FltAllocateContext
 * - VolumeName.Buffer separately allocated and freed in cleanup
 * - VolumeGUIDName.Buffer separately allocated and freed in cleanup
 * - Resource must be deleted in cleanup callback
 */
typedef struct _SHADOW_INSTANCE_CONTEXT {

    //
    // Validation & Synchronization
    //

    /// @brief Magic signature for corruption detection (SHADOW_INSTANCE_CONTEXT_SIGNATURE)
    /// MUST be the first field for safe validation before accessing other fields.
    ULONG Signature;

    /// @brief Synchronization lock for thread-safe access
    ERESOURCE Resource;

    /// @brief TRUE if Resource was successfully initialized (CRITICAL for cleanup)
    BOOLEAN ResourceInitialized;

    /// @brief TRUE if context is fully initialized and ready for use
    BOOLEAN Initialized;

    /// @brief Padding for alignment
    BOOLEAN Reserved1[2];

    //
    // Volume Identity
    //

    /// @brief Cached volume name (e.g., "\Device\HarddiskVolume2")
    UNICODE_STRING VolumeName;

    /// @brief Volume GUID name (e.g., "\\?\Volume{guid}")
    UNICODE_STRING VolumeGUIDName;

    /// @brief Volume serial number (from FILE_FS_VOLUME_INFORMATION)
    ULONG VolumeSerialNumber;

    /// @brief Volume type classification flags
    SHADOW_VOLUME_TYPE VolumeType;

    /// @brief File system type (FLT_FSTYPE_NTFS, FLT_FSTYPE_REFS, etc.)
    FLT_FILESYSTEM_TYPE FilesystemType;

    /// @brief Device type (FILE_DEVICE_DISK_FILE_SYSTEM, etc.)
    DEVICE_TYPE DeviceType;

    //
    // Volume Characteristics
    //

    /// @brief TRUE if volume is read-only
    BOOLEAN IsReadOnly;

    /// @brief Padding for alignment
    BOOLEAN Reserved2[3];

    /// @brief Filesystem capabilities (queried once during init)
    SHADOW_FS_CAPABILITIES Capabilities;

    //
    // Policy Configuration (Set once during initialization)
    //

    /// @brief TRUE if scanning is enabled for this volume
    BOOLEAN ScanningEnabled;

    /// @brief TRUE if real-time protection is active
    BOOLEAN RealTimeProtectionEnabled;

    /// @brief TRUE if write protection is enabled (block malware writes)
    BOOLEAN WriteProtectionEnabled;

    /// @brief Reserved for future policy flags
    BOOLEAN PolicyReserved[5];

    //
    // Statistics (All accessed via Interlocked operations)
    //

    /// @brief Total file create operations on this volume
    volatile LONGLONG TotalCreateOperations;

    /// @brief Total files scanned on this volume
    volatile LONGLONG TotalFilesScanned;

    /// @brief Total files blocked on this volume
    volatile LONGLONG TotalFilesBlocked;

    /// @brief Total write operations on this volume
    volatile LONGLONG TotalWriteOperations;

    /// @brief Total clean verdicts on this volume
    volatile LONGLONG TotalCleanVerdicts;

    /// @brief Total malware verdicts on this volume
    volatile LONGLONG TotalMalwareVerdicts;

    /// @brief Total scan errors on this volume
    volatile LONGLONG TotalScanErrors;

    /// @brief Total cache hits on this volume
    volatile LONGLONG TotalCacheHits;

    //
    // Timing and Health
    //

    /// @brief Timestamp when this instance was attached
    LARGE_INTEGER AttachTime;

    /// @brief Last activity timestamp (for idle detection) - accessed via Interlocked
    volatile LONGLONG LastActivityTime;

    /// @brief Cumulative scan time in 100ns units (for average calculation)
    volatile LONGLONG CumulativeScanTime;

} SHADOW_INSTANCE_CONTEXT, *PSHADOW_INSTANCE_CONTEXT;

// ============================================================================
// FUNCTION PROTOTYPES
// ============================================================================

/**
 * @brief Create and initialize instance context.
 *
 * Allocates a new instance context from the Filter Manager and initializes
 * all fields. Must be called during InstanceSetup callback.
 *
 * @param FilterHandle  Filter handle from DriverEntry
 * @param Context       [out] Receives the new context pointer
 *
 * @return STATUS_SUCCESS on success
 *         STATUS_INSUFFICIENT_RESOURCES if allocation fails
 *
 * @note Caller must set the context via FltSetInstanceContext
 * @note Caller must call FltReleaseContext when done
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowCreateInstanceContext(
    _In_ PFLT_FILTER FilterHandle,
    _Outptr_ PSHADOW_INSTANCE_CONTEXT* Context
    );

/**
 * @brief Get instance context for a volume.
 *
 * Retrieves the instance context previously attached to this volume instance.
 * This is a simple wrapper around FltGetInstanceContext.
 *
 * @param Instance  Filter instance
 * @param Context   [out] Receives the context pointer
 *
 * @return STATUS_SUCCESS on success
 *         STATUS_NOT_FOUND if no context is attached
 *
 * @note Caller MUST call FltReleaseContext when done
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowGetInstanceContext(
    _In_ PFLT_INSTANCE Instance,
    _Outptr_ PSHADOW_INSTANCE_CONTEXT* Context
    );

/**
 * @brief Cleanup callback for instance context destruction.
 *
 * Called by Filter Manager when an instance context is being freed
 * (during volume detachment). This is the ONLY place to free resources
 * allocated within the context.
 *
 * CRITICAL: Must delete ERESOURCE to prevent zombie locks.
 *
 * @param Context      The context being freed
 * @param ContextType  Type of context (FLT_INSTANCE_CONTEXT)
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowCleanupInstanceContext(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
    );

/**
 * @brief Initialize volume information in instance context.
 *
 * Queries volume name, GUID, serial number, filesystem type, and capabilities.
 * Must be called after context is created and attached.
 *
 * Thread-safe - acquires exclusive lock internally.
 *
 * @param Context   The context to initialize
 * @param Instance  Filter instance to query
 * @param Volume    Volume object (optional, will be queried if NULL)
 *
 * @return STATUS_SUCCESS on success
 *         STATUS_INSUFFICIENT_RESOURCES if memory allocation fails
 *         Other NTSTATUS codes on query failures
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowInitializeInstanceVolumeInfo(
    _In_ PSHADOW_INSTANCE_CONTEXT Context,
    _In_ PFLT_INSTANCE Instance,
    _In_opt_ PFLT_VOLUME Volume
    );

/**
 * @brief Increment create operation counter.
 *
 * Thread-safe atomic increment of TotalCreateOperations.
 *
 * @param Context  The instance context
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowInstanceIncrementCreateCount(
    _In_ PSHADOW_INSTANCE_CONTEXT Context
    );

/**
 * @brief Increment scanned file counter.
 *
 * Thread-safe atomic increment of TotalFilesScanned.
 *
 * @param Context  The instance context
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowInstanceIncrementScanCount(
    _In_ PSHADOW_INSTANCE_CONTEXT Context
    );

/**
 * @brief Increment blocked file counter.
 *
 * Thread-safe atomic increment of TotalFilesBlocked.
 *
 * @param Context  The instance context
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowInstanceIncrementBlockCount(
    _In_ PSHADOW_INSTANCE_CONTEXT Context
    );

/**
 * @brief Increment write operation counter.
 *
 * Thread-safe atomic increment of TotalWriteOperations.
 *
 * @param Context  The instance context
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowInstanceIncrementWriteCount(
    _In_ PSHADOW_INSTANCE_CONTEXT Context
    );

/**
 * @brief Record scan verdict in instance statistics.
 *
 * Updates verdict counters (clean, malware) and cumulative scan time.
 * Thread-safe - uses atomic operations.
 *
 * @param Context    The instance context
 * @param IsClean    TRUE if clean, FALSE if malware
 * @param ScanTime   Time taken to scan (in 100ns units)
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowInstanceRecordScanVerdict(
    _In_ PSHADOW_INSTANCE_CONTEXT Context,
    _In_ BOOLEAN IsClean,
    _In_ LARGE_INTEGER ScanTime
    );

/**
 * @brief Record scan error in instance statistics.
 *
 * Thread-safe atomic increment of TotalScanErrors.
 *
 * @param Context  The instance context
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowInstanceRecordScanError(
    _In_ PSHADOW_INSTANCE_CONTEXT Context
    );

/**
 * @brief Record cache hit in instance statistics.
 *
 * Thread-safe atomic increment of TotalCacheHits.
 *
 * @param Context  The instance context
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowInstanceRecordCacheHit(
    _In_ PSHADOW_INSTANCE_CONTEXT Context
    );

/**
 * @brief Check if volume is a network volume.
 *
 * Thread-safe - acquires shared lock.
 *
 * @param Context  The instance context
 *
 * @return TRUE if network volume, FALSE otherwise
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
ShadowInstanceIsNetworkVolume(
    _In_ PSHADOW_INSTANCE_CONTEXT Context
    );

/**
 * @brief Check if volume is removable media.
 *
 * Thread-safe - acquires shared lock.
 *
 * @param Context  The instance context
 *
 * @return TRUE if removable media, FALSE otherwise
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
ShadowInstanceIsRemovableMedia(
    _In_ PSHADOW_INSTANCE_CONTEXT Context
    );

/**
 * @brief Check if volume supports file IDs.
 *
 * Thread-safe - acquires shared lock.
 *
 * @param Context  The instance context
 *
 * @return TRUE if file IDs are supported, FALSE otherwise
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
ShadowInstanceSupportsFileIds(
    _In_ PSHADOW_INSTANCE_CONTEXT Context
    );

/**
 * @brief Check if volume supports alternate data streams.
 *
 * Thread-safe - acquires shared lock.
 *
 * @param Context  The instance context
 *
 * @return TRUE if streams are supported, FALSE otherwise
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
ShadowInstanceSupportsStreams(
    _In_ PSHADOW_INSTANCE_CONTEXT Context
    );

/**
 * @brief Get filesystem type for this volume.
 *
 * Thread-safe - acquires shared lock.
 *
 * @param Context  The instance context
 *
 * @return FLT_FILESYSTEM_TYPE value
 */
_IRQL_requires_max_(APC_LEVEL)
FLT_FILESYSTEM_TYPE
ShadowInstanceGetFilesystemType(
    _In_ PSHADOW_INSTANCE_CONTEXT Context
    );

/**
 * @brief Update last activity timestamp.
 *
 * Thread-safe - uses atomic write.
 *
 * @param Context  The instance context
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowInstanceUpdateActivityTime(
    _In_ PSHADOW_INSTANCE_CONTEXT Context
    );

/**
 * @brief Get average scan time for this volume.
 *
 * Thread-safe - uses atomic reads.
 *
 * @param Context  The instance context
 *
 * @return Average scan time in 100ns units, 0 if no scans performed
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
LONGLONG
ShadowInstanceGetAverageScanTime(
    _In_ PSHADOW_INSTANCE_CONTEXT Context
    );

/**
 * @brief Copy volume name to caller buffer.
 *
 * Thread-safe - acquires shared lock. Copies the volume name to
 * caller-provided buffer to avoid holding lock during use.
 *
 * @param Context       The instance context
 * @param Buffer        Caller-provided buffer
 * @param BufferSize    Size of buffer in bytes
 * @param RequiredSize  [out] Receives required size if buffer too small
 *
 * @return STATUS_SUCCESS on success
 *         STATUS_BUFFER_TOO_SMALL if buffer is insufficient
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowInstanceCopyVolumeName(
    _In_ PSHADOW_INSTANCE_CONTEXT Context,
    _Out_writes_bytes_opt_(BufferSize) PWCHAR Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG RequiredSize
    );

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_INSTANCE_CONTEXT_H
