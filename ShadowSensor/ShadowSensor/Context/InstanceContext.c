/**
 * ============================================================================
 * ShadowStrike NGAV - INSTANCE CONTEXT IMPLEMENTATION
 * ============================================================================
 *
 * @file InstanceContext.c
 * @brief Implementation of instance context management.
 *
 * Handles creation, retrieval, and cleanup of instance contexts with proper
 * thread safety and resource management. Instance contexts track per-volume
 * state, statistics, and configuration.
 *
 * Key Features:
 * - Thread-safe volume information caching
 * - Atomic statistics tracking (scans, blocks, verdicts)
 * - Proper cleanup to prevent BSOD (ExDeleteResourceLite)
 * - Memory leak prevention (string buffer cleanup)
 * - Volume type detection (network, removable, fixed)
 * - File system capability detection
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "InstanceContext.h"
#include "../Core/Globals.h"

// ============================================================================
// PRIVATE HELPER PROTOTYPES
// ============================================================================

NTSTATUS
ShadowQueryVolumeInformation(
    _In_ PFLT_INSTANCE Instance,
    _In_ PSHADOW_INSTANCE_CONTEXT Context
    );

SHADOW_VOLUME_TYPE
ShadowDetermineVolumeType(
    _In_ DEVICE_TYPE DeviceType,
    _In_ FLT_FILESYSTEM_TYPE FsType
    );

// ============================================================================
// PUBLIC FUNCTIONS
// ============================================================================

/**
 * @brief Create and initialize instance context.
 */
NTSTATUS
ShadowCreateInstanceContext(
    _In_ PFLT_FILTER FilterHandle,
    _Outptr_ PSHADOW_INSTANCE_CONTEXT* Context
    )
{
    NTSTATUS status;
    PSHADOW_INSTANCE_CONTEXT ctx = NULL;

    *Context = NULL;

    //
    // Allocate context from Filter Manager
    //
    status = FltAllocateContext(
        FilterHandle,
        FLT_INSTANCE_CONTEXT,
        sizeof(SHADOW_INSTANCE_CONTEXT),
        PagedPool,
        (PFLT_CONTEXT*)&ctx
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Failed to allocate instance context: 0x%X\n", status);
        return status;
    }

    //
    // Zero memory
    //
    RtlZeroMemory(ctx, sizeof(SHADOW_INSTANCE_CONTEXT));

    //
    // Initialize ERESOURCE
    //
    status = ExInitializeResourceLite(&ctx->Resource);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Failed to initialize instance resource: 0x%X\n", status);
        FltReleaseContext(ctx);
        return status;
    }

    //
    // CRITICAL: Mark resource as initialized for safe cleanup
    //
    ctx->ResourceInitialized = TRUE;

    //
    // Initialize timestamps
    //
    KeQuerySystemTime(&ctx->AttachTime);
    ctx->LastActivityTime = ctx->AttachTime;

    //
    // Default policy: Enable scanning on all volumes
    //
    ctx->ScanningEnabled = TRUE;
    ctx->RealTimeProtectionEnabled = TRUE;
    ctx->WriteProtectionEnabled = FALSE;

    *Context = ctx;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] Instance context created successfully\n");

    return STATUS_SUCCESS;
}

/**
 * @brief Get instance context for a volume.
 */
NTSTATUS
ShadowGetInstanceContext(
    _In_ PFLT_INSTANCE Instance,
    _Outptr_ PSHADOW_INSTANCE_CONTEXT* Context
    )
{
    NTSTATUS status;

    *Context = NULL;

    status = FltGetInstanceContext(
        Instance,
        (PFLT_CONTEXT*)Context
    );

    if (!NT_SUCCESS(status)) {
        if (status != STATUS_NOT_FOUND) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike] FltGetInstanceContext failed: 0x%X\n", status);
        }
        return status;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Cleanup callback - called by Filter Manager on instance detach.
 */
VOID
ShadowCleanupInstanceContext(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
    )
{
    PSHADOW_INSTANCE_CONTEXT ctx = (PSHADOW_INSTANCE_CONTEXT)Context;

    UNREFERENCED_PARAMETER(ContextType);

    if (ctx == NULL) {
        return;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] Cleaning up instance context (Volume: %wZ)\n",
               &ctx->VolumeName);

    //
    // CRITICAL: Delete ERESOURCE only if it was successfully initialized
    // Prevents BSOD from deleting uninitialized resources
    //
    if (ctx->ResourceInitialized) {
        ExDeleteResourceLite(&ctx->Resource);
        ctx->ResourceInitialized = FALSE;
    }

    //
    // Free VolumeName buffer if allocated
    //
    if (ctx->VolumeName.Buffer != NULL) {
        ExFreePoolWithTag(ctx->VolumeName.Buffer, SHADOW_INSTANCE_STRING_TAG);
        ctx->VolumeName.Buffer = NULL;
        ctx->VolumeName.Length = 0;
        ctx->VolumeName.MaximumLength = 0;
    }

    //
    // Free VolumeGUIDName buffer if allocated
    //
    if (ctx->VolumeGUIDName.Buffer != NULL) {
        ExFreePoolWithTag(ctx->VolumeGUIDName.Buffer, SHADOW_INSTANCE_STRING_TAG);
        ctx->VolumeGUIDName.Buffer = NULL;
        ctx->VolumeGUIDName.Length = 0;
        ctx->VolumeGUIDName.MaximumLength = 0;
    }

    //
    // Note: The context structure itself is freed by Filter Manager
    // Do NOT call ExFreePoolWithTag on the context pointer
    //
}

/**
 * @brief Initialize volume information in instance context.
 */
NTSTATUS
ShadowInitializeInstanceVolumeInfo(
    _In_ PSHADOW_INSTANCE_CONTEXT Context,
    _In_ PFLT_INSTANCE Instance
    )
{
    NTSTATUS status;
    PFLT_VOLUME volume = NULL;
    FLT_VOLUME_PROPERTIES volumeProps;
    ULONG bytesReturned;

    if (Context == NULL || Instance == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Get volume object
    //
    status = FltGetVolumeFromInstance(Instance, &volume);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] FltGetVolumeFromInstance failed: 0x%X\n", status);
        return status;
    }

    //
    // Query volume properties
    //
    RtlZeroMemory(&volumeProps, sizeof(volumeProps));
    status = FltGetVolumeProperties(
        volume,
        &volumeProps,
        sizeof(volumeProps),
        &bytesReturned
    );

    if (NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW) {
        //
        // Acquire exclusive lock for modification
        //
        KeEnterCriticalRegion();
        ExAcquireResourceExclusiveLite(&Context->Resource, TRUE);

        //
        // Cache device and filesystem type
        //
        Context->DeviceType = volumeProps.DeviceType;
        Context->FilesystemType = volumeProps.FileSystemDriverName.Length > 0 ?
            FLT_FSTYPE_UNKNOWN : FLT_FSTYPE_UNKNOWN;

        //
        // Determine volume type
        //
        Context->VolumeType = ShadowDetermineVolumeType(
            volumeProps.DeviceType,
            Context->FilesystemType
        );

        //
        // Cache volume characteristics
        //
        Context->IsReadOnly = FlagOn(volumeProps.DeviceCharacteristics, FILE_READ_ONLY_DEVICE);
        Context->SupportsFileIds = TRUE;  // Assume NTFS/ReFS for now
        Context->SupportsStreams = TRUE;
        Context->SupportsObjectIds = TRUE;

        //
        // Allocate and copy volume name
        //
        if (volumeProps.RealDeviceName.Length > 0) {
            Context->VolumeName.MaximumLength = volumeProps.RealDeviceName.Length;
            Context->VolumeName.Buffer = (PWCH)ExAllocatePoolWithTag(
                PagedPool,
                volumeProps.RealDeviceName.Length,
                SHADOW_INSTANCE_STRING_TAG
            );

            if (Context->VolumeName.Buffer != NULL) {
                Context->VolumeName.Length = volumeProps.RealDeviceName.Length;
                RtlCopyMemory(
                    Context->VolumeName.Buffer,
                    volumeProps.RealDeviceName.Buffer,
                    volumeProps.RealDeviceName.Length
                );
            }
        }

        ExReleaseResourceLite(&Context->Resource);
        KeLeaveCriticalRegion();
    }

    //
    // Query additional volume information
    //
    status = ShadowQueryVolumeInformation(Instance, Context);

    FltObjectDereference(volume);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Instance initialized: Volume=%wZ, Type=0x%X\n",
               &Context->VolumeName, Context->VolumeType);

    return STATUS_SUCCESS;
}

/**
 * @brief Increment create operation counter (atomic).
 */
VOID
ShadowInstanceIncrementCreateCount(
    _In_ PSHADOW_INSTANCE_CONTEXT Context
    )
{
    if (Context == NULL) {
        return;
    }

    InterlockedIncrement64(&Context->TotalCreateOperations);
    ShadowInstanceUpdateActivityTime(Context);
}

/**
 * @brief Increment scanned file counter (atomic).
 */
VOID
ShadowInstanceIncrementScanCount(
    _In_ PSHADOW_INSTANCE_CONTEXT Context
    )
{
    if (Context == NULL) {
        return;
    }

    InterlockedIncrement64(&Context->TotalFilesScanned);
    ShadowInstanceUpdateActivityTime(Context);
}

/**
 * @brief Increment blocked file counter (atomic).
 */
VOID
ShadowInstanceIncrementBlockCount(
    _In_ PSHADOW_INSTANCE_CONTEXT Context
    )
{
    if (Context == NULL) {
        return;
    }

    InterlockedIncrement64(&Context->TotalFilesBlocked);
    ShadowInstanceUpdateActivityTime(Context);
}

/**
 * @brief Record scan verdict in instance statistics.
 */
VOID
ShadowInstanceRecordScanVerdict(
    _In_ PSHADOW_INSTANCE_CONTEXT Context,
    _In_ BOOLEAN IsClean,
    _In_ LARGE_INTEGER ScanTime
    )
{
    if (Context == NULL) {
        return;
    }

    //
    // Update verdict counters (atomic)
    //
    if (IsClean) {
        InterlockedIncrement64(&Context->TotalCleanVerdicts);
    } else {
        InterlockedIncrement64(&Context->TotalMalwareVerdicts);
    }

    //
    // Update average scan time (simple moving average)
    // Formula: avg = (avg * count + new) / (count + 1)
    //
    LONGLONG totalScans = Context->TotalFilesScanned;
    if (totalScans > 0) {
        LONGLONG currentAvg = Context->AverageScanTime.QuadPart;
        LONGLONG newAvg = (currentAvg * (totalScans - 1) + ScanTime.QuadPart) / totalScans;
        InterlockedExchange64(&Context->AverageScanTime.QuadPart, newAvg);
    } else {
        InterlockedExchange64(&Context->AverageScanTime.QuadPart, ScanTime.QuadPart);
    }

    ShadowInstanceUpdateActivityTime(Context);
}

/**
 * @brief Check if volume is a network volume.
 */
BOOLEAN
ShadowInstanceIsNetworkVolume(
    _In_ PSHADOW_INSTANCE_CONTEXT Context
    )
{
    BOOLEAN isNetwork = FALSE;

    if (Context == NULL) {
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&Context->Resource, TRUE);

    isNetwork = FlagOn(Context->VolumeType, VolumeTypeNetwork);

    ExReleaseResourceLite(&Context->Resource);
    KeLeaveCriticalRegion();

    return isNetwork;
}

/**
 * @brief Check if volume is removable media.
 */
BOOLEAN
ShadowInstanceIsRemovableMedia(
    _In_ PSHADOW_INSTANCE_CONTEXT Context
    )
{
    BOOLEAN isRemovable = FALSE;

    if (Context == NULL) {
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&Context->Resource, TRUE);

    isRemovable = FlagOn(Context->VolumeType, VolumeTypeRemovable);

    ExReleaseResourceLite(&Context->Resource);
    KeLeaveCriticalRegion();

    return isRemovable;
}

/**
 * @brief Update last activity timestamp (atomic).
 */
VOID
ShadowInstanceUpdateActivityTime(
    _In_ PSHADOW_INSTANCE_CONTEXT Context
    )
{
    LARGE_INTEGER currentTime;

    if (Context == NULL) {
        return;
    }

    KeQuerySystemTime(&currentTime);
    InterlockedExchange64(&Context->LastActivityTime.QuadPart, currentTime.QuadPart);
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Query additional volume information (serial number, etc.).
 */
NTSTATUS
ShadowQueryVolumeInformation(
    _In_ PFLT_INSTANCE Instance,
    _In_ PSHADOW_INSTANCE_CONTEXT Context
    )
{
    NTSTATUS status;
    FILE_FS_VOLUME_INFORMATION volumeInfo;
    ULONG bytesReturned;

    //
    // Query volume serial number
    //
    status = FltQueryVolumeInformation(
        Instance,
        &volumeInfo,
        sizeof(volumeInfo),
        FileFsVolumeInformation,
        &bytesReturned
    );

    if (NT_SUCCESS(status)) {
        KeEnterCriticalRegion();
        ExAcquireResourceExclusiveLite(&Context->Resource, TRUE);

        Context->VolumeSerialNumber = volumeInfo.VolumeSerialNumber;

        ExReleaseResourceLite(&Context->Resource);
        KeLeaveCriticalRegion();

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                   "[ShadowStrike] Volume serial: 0x%08X\n",
                   Context->VolumeSerialNumber);
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Determine volume type from device type and filesystem.
 */
SHADOW_VOLUME_TYPE
ShadowDetermineVolumeType(
    _In_ DEVICE_TYPE DeviceType,
    _In_ FLT_FILESYSTEM_TYPE FsType
    )
{
    SHADOW_VOLUME_TYPE volumeType = VolumeTypeUnknown;

    UNREFERENCED_PARAMETER(FsType);

    switch (DeviceType) {
        case FILE_DEVICE_DISK:
        case FILE_DEVICE_DISK_FILE_SYSTEM:
            volumeType = VolumeTypeFixed;
            break;

        case FILE_DEVICE_NETWORK:
        case FILE_DEVICE_NETWORK_FILE_SYSTEM:
            volumeType = VolumeTypeNetwork;
            break;

        case FILE_DEVICE_CD_ROM:
        case FILE_DEVICE_CD_ROM_FILE_SYSTEM:
            volumeType = VolumeTypeCDROM;
            break;

        case FILE_DEVICE_VIRTUAL_DISK:
            volumeType = VolumeTypeVirtual;
            break;

        default:
            // Check if removable via characteristics (done in caller)
            volumeType = VolumeTypeUnknown;
            break;
    }

    return volumeType;
}
