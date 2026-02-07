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
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
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

// ============================================================================
// VOLUME TYPE FLAGS
// ============================================================================

/**
 * @brief Volume type classification flags.
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
// INSTANCE CONTEXT STRUCTURE
// ============================================================================

/**
 * @brief Per-instance (per-volume) context structure.
 *
 * This structure is allocated by the Filter Manager and associated with
 * each volume instance where the minifilter attaches. It tracks volume-
 * specific state, configuration, and statistics.
 *
 * Thread Safety: Protected by the Resource lock. All field access must
 * be synchronized using ExAcquireResourceSharedLite/ExclusiveLite.
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
    // Synchronization
    //

    /// @brief Synchronization lock for thread-safe access
    ERESOURCE Resource;

    /// @brief TRUE if Resource was successfully initialized (CRITICAL for cleanup)
    BOOLEAN ResourceInitialized;

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

    /// @brief File system type (FLT_FSTYPE_NTFS, etc.)
    FLT_FILESYSTEM_TYPE FilesystemType;

    /// @brief Device type (FILE_DEVICE_DISK_FILE_SYSTEM, etc.)
    DEVICE_TYPE DeviceType;

    //
    // Volume Characteristics
    //

    /// @brief TRUE if volume is read-only
    BOOLEAN IsReadOnly;

    /// @brief TRUE if volume supports file IDs (NTFS, ReFS)
    BOOLEAN SupportsFileIds;

    /// @brief TRUE if volume supports alternate data streams
    BOOLEAN SupportsStreams;

    /// @brief TRUE if volume supports object IDs
    BOOLEAN SupportsObjectIds;

    //
    // Policy Configuration
    //

    /// @brief TRUE if scanning is enabled for this volume
    BOOLEAN ScanningEnabled;

    /// @brief TRUE if real-time protection is active
    BOOLEAN RealTimeProtectionEnabled;

    /// @brief TRUE if write protection is enabled (block malware writes)
    BOOLEAN WriteProtectionEnabled;

    /// @brief Reserved for future policy flags
    BOOLEAN Reserved[5];

    //
    // Statistics (Performance Metrics)
    //

    /// @brief Total file create operations on this volume
    LONGLONG TotalCreateOperations;

    /// @brief Total files scanned on this volume
    LONGLONG TotalFilesScanned;

    /// @brief Total files blocked on this volume
    LONGLONG TotalFilesBlocked;

    /// @brief Total write operations on this volume
    LONGLONG TotalWriteOperations;

    /// @brief Total clean verdicts on this volume
    LONGLONG TotalCleanVerdicts;

    /// @brief Total malware verdicts on this volume
    LONGLONG TotalMalwareVerdicts;

    /// @brief Total scan errors on this volume
    LONGLONG TotalScanErrors;

    /// @brief Total cache hits on this volume
    LONGLONG TotalCacheHits;

    //
    // Timing and Health
    //

    /// @brief Timestamp when this instance was attached
    LARGE_INTEGER AttachTime;

    /// @brief Last activity timestamp (for idle detection)
    LARGE_INTEGER LastActivityTime;

    /// @brief Average scan time in 100ns units
    LARGE_INTEGER AverageScanTime;

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
 */
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
VOID
ShadowCleanupInstanceContext(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
    );

/**
 * @brief Initialize volume information in instance context.
 *
 * Queries volume name, GUID, serial number, and characteristics.
 * Must be called after context is created and attached.
 *
 * Thread-safe - acquires exclusive lock internally.
 *
 * @param Context   The context to initialize
 * @param Instance  Filter instance to query
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
ShadowInitializeInstanceVolumeInfo(
    _In_ PSHADOW_INSTANCE_CONTEXT Context,
    _In_ PFLT_INSTANCE Instance
    );

/**
 * @brief Increment create operation counter.
 *
 * Thread-safe atomic increment of TotalCreateOperations.
 *
 * @param Context  The instance context
 */
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
VOID
ShadowInstanceIncrementBlockCount(
    _In_ PSHADOW_INSTANCE_CONTEXT Context
    );

/**
 * @brief Record scan verdict in instance statistics.
 *
 * Updates verdict counters (clean, malware) and average scan time.
 * Thread-safe - uses atomic operations.
 *
 * @param Context    The instance context
 * @param IsClean    TRUE if clean, FALSE if malware
 * @param ScanTime   Time taken to scan (in 100ns units)
 */
VOID
ShadowInstanceRecordScanVerdict(
    _In_ PSHADOW_INSTANCE_CONTEXT Context,
    _In_ BOOLEAN IsClean,
    _In_ LARGE_INTEGER ScanTime
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
BOOLEAN
ShadowInstanceIsRemovableMedia(
    _In_ PSHADOW_INSTANCE_CONTEXT Context
    );

/**
 * @brief Update last activity timestamp.
 *
 * Thread-safe - uses atomic write.
 *
 * @param Context  The instance context
 */
VOID
ShadowInstanceUpdateActivityTime(
    _In_ PSHADOW_INSTANCE_CONTEXT Context
    );

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_INSTANCE_CONTEXT_H
