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
 * - Filesystem capability detection via FileFsAttributeInformation
 * - Race-free average scan time calculation
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "InstanceContext.h"
#include "../Core/Globals.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ShadowCreateInstanceContext)
#pragma alloc_text(PAGE, ShadowGetInstanceContext)
#pragma alloc_text(PAGE, ShadowCleanupInstanceContext)
#pragma alloc_text(PAGE, ShadowInitializeInstanceVolumeInfo)
#pragma alloc_text(PAGE, ShadowInstanceIsNetworkVolume)
#pragma alloc_text(PAGE, ShadowInstanceIsRemovableMedia)
#pragma alloc_text(PAGE, ShadowInstanceSupportsFileIds)
#pragma alloc_text(PAGE, ShadowInstanceSupportsStreams)
#pragma alloc_text(PAGE, ShadowInstanceGetFilesystemType)
#pragma alloc_text(PAGE, ShadowInstanceCopyVolumeName)
#pragma alloc_text(PAGE, ShadowpQueryVolumeProperties)
#pragma alloc_text(PAGE, ShadowpQueryFilesystemCapabilities)
#pragma alloc_text(PAGE, ShadowpQueryVolumeSerialNumber)
#pragma alloc_text(PAGE, ShadowpDetermineVolumeType)
#pragma alloc_text(PAGE, ShadowpAllocateAndCopyString)
#endif

// ============================================================================
// PRIVATE HELPER PROTOTYPES
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static
NTSTATUS
ShadowpQueryVolumeProperties(
    _In_ PFLT_VOLUME Volume,
    _Out_ PDEVICE_TYPE DeviceType,
    _Out_ PULONG DeviceCharacteristics,
    _Out_ PFLT_FILESYSTEM_TYPE FilesystemType
    );

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static
NTSTATUS
ShadowpQueryFilesystemCapabilities(
    _In_ PFLT_INSTANCE Instance,
    _Out_ PSHADOW_FS_CAPABILITIES Capabilities
    );

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static
NTSTATUS
ShadowpQueryVolumeSerialNumber(
    _In_ PFLT_INSTANCE Instance,
    _Out_ PULONG SerialNumber
    );

_IRQL_requires_max_(APC_LEVEL)
static
SHADOW_VOLUME_TYPE
ShadowpDetermineVolumeType(
    _In_ DEVICE_TYPE DeviceType,
    _In_ ULONG DeviceCharacteristics,
    _In_ FLT_FILESYSTEM_TYPE FilesystemType
    );

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static
NTSTATUS
ShadowpAllocateAndCopyString(
    _In_ PCUNICODE_STRING Source,
    _Out_ PUNICODE_STRING Destination,
    _In_ ULONG MaxLength
    );

// ============================================================================
// PUBLIC FUNCTIONS
// ============================================================================

/**
 * @brief Create and initialize instance context.
 */
_Use_decl_annotations_
NTSTATUS
ShadowCreateInstanceContext(
    PFLT_FILTER FilterHandle,
    PSHADOW_INSTANCE_CONTEXT* Context
    )
{
    NTSTATUS status;
    PSHADOW_INSTANCE_CONTEXT ctx = NULL;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (FilterHandle == NULL || Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

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
                   "[ShadowStrike] Failed to allocate instance context: 0x%08X\n", status);
        return status;
    }

    //
    // Zero all memory - critical for security (no data leaks from pool)
    //
    RtlZeroMemory(ctx, sizeof(SHADOW_INSTANCE_CONTEXT));

    //
    // Initialize ERESOURCE for synchronization
    //
    status = ExInitializeResourceLite(&ctx->Resource);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Failed to initialize instance resource: 0x%08X\n", status);
        FltReleaseContext(ctx);
        return status;
    }

    //
    // CRITICAL: Mark resource as initialized for safe cleanup
    // This flag MUST be set before any error path that could trigger cleanup
    //
    ctx->ResourceInitialized = TRUE;

    //
    // Initialize timestamps
    //
    KeQuerySystemTime(&ctx->AttachTime);
    InterlockedExchange64(&ctx->LastActivityTime, ctx->AttachTime.QuadPart);

    //
    // Default policy: Enable scanning on all volumes
    // These are set once and never modified, so no lock needed
    //
    ctx->ScanningEnabled = TRUE;
    ctx->RealTimeProtectionEnabled = TRUE;
    ctx->WriteProtectionEnabled = FALSE;

    //
    // Context is not yet fully initialized until volume info is queried
    //
    ctx->Initialized = FALSE;

    *Context = ctx;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] Instance context created successfully\n");

    return STATUS_SUCCESS;
}

/**
 * @brief Get instance context for a volume.
 */
_Use_decl_annotations_
NTSTATUS
ShadowGetInstanceContext(
    PFLT_INSTANCE Instance,
    PSHADOW_INSTANCE_CONTEXT* Context
    )
{
    NTSTATUS status;

    PAGED_CODE();

    if (Instance == NULL || Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Context = NULL;

    status = FltGetInstanceContext(
        Instance,
        (PFLT_CONTEXT*)Context
    );

    if (!NT_SUCCESS(status)) {
        if (status != STATUS_NOT_FOUND) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike] FltGetInstanceContext failed: 0x%08X\n", status);
        }
        return status;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Cleanup callback - called by Filter Manager on instance detach.
 *
 * CRITICAL: This function is the ONLY place where context resources are freed.
 * Filter Manager guarantees this is called exactly once when the context
 * reference count drops to zero.
 */
_Use_decl_annotations_
VOID
ShadowCleanupInstanceContext(
    PFLT_CONTEXT Context,
    FLT_CONTEXT_TYPE ContextType
    )
{
    PSHADOW_INSTANCE_CONTEXT ctx = (PSHADOW_INSTANCE_CONTEXT)Context;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ContextType);

    //
    // Defensive check - Filter Manager should never pass NULL, but verify
    //
    if (ctx == NULL) {
        NT_ASSERT(FALSE);
        return;
    }

    NT_ASSERT(ContextType == FLT_INSTANCE_CONTEXT);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] Cleaning up instance context\n");

    //
    // CRITICAL: Delete ERESOURCE only if it was successfully initialized
    // Calling ExDeleteResourceLite on uninitialized memory = BSOD
    //
    if (ctx->ResourceInitialized) {
        ExDeleteResourceLite(&ctx->Resource);
        ctx->ResourceInitialized = FALSE;
    }

    //
    // Free VolumeName buffer if allocated
    // Use secure zeroing before free to prevent information leakage
    //
    if (ctx->VolumeName.Buffer != NULL) {
        RtlSecureZeroMemory(ctx->VolumeName.Buffer, ctx->VolumeName.MaximumLength);
        ExFreePoolWithTag(ctx->VolumeName.Buffer, SHADOW_INSTANCE_STRING_TAG);
        ctx->VolumeName.Buffer = NULL;
        ctx->VolumeName.Length = 0;
        ctx->VolumeName.MaximumLength = 0;
    }

    //
    // Free VolumeGUIDName buffer if allocated
    //
    if (ctx->VolumeGUIDName.Buffer != NULL) {
        RtlSecureZeroMemory(ctx->VolumeGUIDName.Buffer, ctx->VolumeGUIDName.MaximumLength);
        ExFreePoolWithTag(ctx->VolumeGUIDName.Buffer, SHADOW_INSTANCE_STRING_TAG);
        ctx->VolumeGUIDName.Buffer = NULL;
        ctx->VolumeGUIDName.Length = 0;
        ctx->VolumeGUIDName.MaximumLength = 0;
    }

    //
    // Mark as uninitialized
    //
    ctx->Initialized = FALSE;

    //
    // Note: The context structure itself is freed by Filter Manager
    // Do NOT call ExFreePoolWithTag on the context pointer
    //
}

/**
 * @brief Initialize volume information in instance context.
 */
_Use_decl_annotations_
NTSTATUS
ShadowInitializeInstanceVolumeInfo(
    PSHADOW_INSTANCE_CONTEXT Context,
    PFLT_INSTANCE Instance,
    PFLT_VOLUME Volume
    )
{
    NTSTATUS status;
    PFLT_VOLUME localVolume = NULL;
    BOOLEAN volumeReferenced = FALSE;
    DEVICE_TYPE deviceType = FILE_DEVICE_UNKNOWN;
    ULONG deviceCharacteristics = 0;
    FLT_FILESYSTEM_TYPE fsType = FLT_FSTYPE_UNKNOWN;
    SHADOW_FS_CAPABILITIES capabilities = { 0 };
    SHADOW_VOLUME_TYPE volumeType = VolumeTypeUnknown;
    ULONG serialNumber = 0;
    ULONG returnedLength = 0;
    WCHAR volumeNameBuffer[SHADOW_MAX_VOLUME_NAME_LENGTH / sizeof(WCHAR)];
    UNICODE_STRING volumeName = { 0 };

    PAGED_CODE();

    if (Context == NULL || Instance == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Get volume object if not provided
    //
    if (Volume != NULL) {
        localVolume = Volume;
    } else {
        status = FltGetVolumeFromInstance(Instance, &localVolume);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike] FltGetVolumeFromInstance failed: 0x%08X\n", status);
            return status;
        }
        volumeReferenced = TRUE;
    }

    //
    // Query volume properties (device type, characteristics, filesystem type)
    //
    status = ShadowpQueryVolumeProperties(
        localVolume,
        &deviceType,
        &deviceCharacteristics,
        &fsType
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Failed to query volume properties: 0x%08X\n", status);
        //
        // Continue with defaults - non-fatal for basic operation
        //
    }

    //
    // Query filesystem capabilities
    //
    status = ShadowpQueryFilesystemCapabilities(Instance, &capabilities);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Failed to query filesystem capabilities: 0x%08X\n", status);
        //
        // Default to conservative assumptions (no advanced features)
        //
        RtlZeroMemory(&capabilities, sizeof(capabilities));
    }

    //
    // Query volume serial number
    //
    status = ShadowpQueryVolumeSerialNumber(Instance, &serialNumber);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Failed to query volume serial: 0x%08X\n", status);
        serialNumber = 0;
    }

    //
    // Determine volume type from device characteristics
    //
    volumeType = ShadowpDetermineVolumeType(deviceType, deviceCharacteristics, fsType);

    //
    // Query volume name
    //
    RtlZeroMemory(volumeNameBuffer, sizeof(volumeNameBuffer));
    status = FltGetVolumeName(
        localVolume,
        NULL,
        &returnedLength
    );

    if (status == STATUS_BUFFER_TOO_SMALL && returnedLength > 0) {
        //
        // Cap at our maximum to prevent excessive allocations
        //
        if (returnedLength > SHADOW_MAX_VOLUME_NAME_LENGTH) {
            returnedLength = SHADOW_MAX_VOLUME_NAME_LENGTH;
        }

        volumeName.Buffer = volumeNameBuffer;
        volumeName.MaximumLength = (USHORT)min(returnedLength, sizeof(volumeNameBuffer));
        volumeName.Length = 0;

        status = FltGetVolumeName(
            localVolume,
            &volumeName,
            &returnedLength
        );
    }

    //
    // Now acquire exclusive lock and update context
    //
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&Context->Resource, TRUE);

    //
    // Store queried information
    //
    Context->DeviceType = deviceType;
    Context->FilesystemType = fsType;
    Context->VolumeType = volumeType;
    Context->VolumeSerialNumber = serialNumber;
    Context->IsReadOnly = BooleanFlagOn(deviceCharacteristics, FILE_READ_ONLY_DEVICE);

    //
    // Copy capabilities
    //
    RtlCopyMemory(&Context->Capabilities, &capabilities, sizeof(capabilities));

    //
    // Allocate and copy volume name (under lock)
    //
    if (NT_SUCCESS(status) && volumeName.Length > 0) {
        NTSTATUS copyStatus = ShadowpAllocateAndCopyString(
            &volumeName,
            &Context->VolumeName,
            SHADOW_MAX_VOLUME_NAME_LENGTH
        );

        if (!NT_SUCCESS(copyStatus)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] Failed to copy volume name: 0x%08X\n", copyStatus);
        }
    }

    //
    // Mark context as fully initialized
    //
    Context->Initialized = TRUE;

    ExReleaseResourceLite(&Context->Resource);
    KeLeaveCriticalRegion();

    //
    // Release volume reference if we acquired it
    //
    if (volumeReferenced && localVolume != NULL) {
        FltObjectDereference(localVolume);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Instance initialized: Type=0x%X, FS=%d, Serial=0x%08X\n",
               volumeType, fsType, serialNumber);

    return STATUS_SUCCESS;
}

/**
 * @brief Increment create operation counter (atomic).
 */
_Use_decl_annotations_
VOID
ShadowInstanceIncrementCreateCount(
    PSHADOW_INSTANCE_CONTEXT Context
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
_Use_decl_annotations_
VOID
ShadowInstanceIncrementScanCount(
    PSHADOW_INSTANCE_CONTEXT Context
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
_Use_decl_annotations_
VOID
ShadowInstanceIncrementBlockCount(
    PSHADOW_INSTANCE_CONTEXT Context
    )
{
    if (Context == NULL) {
        return;
    }

    InterlockedIncrement64(&Context->TotalFilesBlocked);
    ShadowInstanceUpdateActivityTime(Context);
}

/**
 * @brief Increment write operation counter (atomic).
 */
_Use_decl_annotations_
VOID
ShadowInstanceIncrementWriteCount(
    PSHADOW_INSTANCE_CONTEXT Context
    )
{
    if (Context == NULL) {
        return;
    }

    InterlockedIncrement64(&Context->TotalWriteOperations);
    ShadowInstanceUpdateActivityTime(Context);
}

/**
 * @brief Record scan verdict in instance statistics.
 *
 * Uses atomic operations exclusively to avoid lock contention on hot path.
 * Average scan time is computed on-demand via ShadowInstanceGetAverageScanTime.
 */
_Use_decl_annotations_
VOID
ShadowInstanceRecordScanVerdict(
    PSHADOW_INSTANCE_CONTEXT Context,
    BOOLEAN IsClean,
    LARGE_INTEGER ScanTime
    )
{
    if (Context == NULL) {
        return;
    }

    //
    // Update verdict counters atomically
    //
    if (IsClean) {
        InterlockedIncrement64(&Context->TotalCleanVerdicts);
    } else {
        InterlockedIncrement64(&Context->TotalMalwareVerdicts);
    }

    //
    // Accumulate scan time atomically
    // Average is computed on-demand to avoid race conditions
    //
    if (ScanTime.QuadPart > 0) {
        InterlockedAdd64(&Context->CumulativeScanTime, ScanTime.QuadPart);
    }

    ShadowInstanceUpdateActivityTime(Context);
}

/**
 * @brief Record scan error in instance statistics.
 */
_Use_decl_annotations_
VOID
ShadowInstanceRecordScanError(
    PSHADOW_INSTANCE_CONTEXT Context
    )
{
    if (Context == NULL) {
        return;
    }

    InterlockedIncrement64(&Context->TotalScanErrors);
    ShadowInstanceUpdateActivityTime(Context);
}

/**
 * @brief Record cache hit in instance statistics.
 */
_Use_decl_annotations_
VOID
ShadowInstanceRecordCacheHit(
    PSHADOW_INSTANCE_CONTEXT Context
    )
{
    if (Context == NULL) {
        return;
    }

    InterlockedIncrement64(&Context->TotalCacheHits);
}

/**
 * @brief Check if volume is a network volume.
 */
_Use_decl_annotations_
BOOLEAN
ShadowInstanceIsNetworkVolume(
    PSHADOW_INSTANCE_CONTEXT Context
    )
{
    BOOLEAN isNetwork = FALSE;

    PAGED_CODE();

    if (Context == NULL) {
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&Context->Resource, TRUE);

    isNetwork = BooleanFlagOn(Context->VolumeType, VolumeTypeNetwork);

    ExReleaseResourceLite(&Context->Resource);
    KeLeaveCriticalRegion();

    return isNetwork;
}

/**
 * @brief Check if volume is removable media.
 */
_Use_decl_annotations_
BOOLEAN
ShadowInstanceIsRemovableMedia(
    PSHADOW_INSTANCE_CONTEXT Context
    )
{
    BOOLEAN isRemovable = FALSE;

    PAGED_CODE();

    if (Context == NULL) {
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&Context->Resource, TRUE);

    isRemovable = BooleanFlagOn(Context->VolumeType, VolumeTypeRemovable);

    ExReleaseResourceLite(&Context->Resource);
    KeLeaveCriticalRegion();

    return isRemovable;
}

/**
 * @brief Check if volume supports file IDs.
 */
_Use_decl_annotations_
BOOLEAN
ShadowInstanceSupportsFileIds(
    PSHADOW_INSTANCE_CONTEXT Context
    )
{
    BOOLEAN supportsFileIds = FALSE;

    PAGED_CODE();

    if (Context == NULL) {
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&Context->Resource, TRUE);

    supportsFileIds = Context->Capabilities.SupportsFileIds;

    ExReleaseResourceLite(&Context->Resource);
    KeLeaveCriticalRegion();

    return supportsFileIds;
}

/**
 * @brief Check if volume supports alternate data streams.
 */
_Use_decl_annotations_
BOOLEAN
ShadowInstanceSupportsStreams(
    PSHADOW_INSTANCE_CONTEXT Context
    )
{
    BOOLEAN supportsStreams = FALSE;

    PAGED_CODE();

    if (Context == NULL) {
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&Context->Resource, TRUE);

    supportsStreams = Context->Capabilities.SupportsStreams;

    ExReleaseResourceLite(&Context->Resource);
    KeLeaveCriticalRegion();

    return supportsStreams;
}

/**
 * @brief Get filesystem type for this volume.
 */
_Use_decl_annotations_
FLT_FILESYSTEM_TYPE
ShadowInstanceGetFilesystemType(
    PSHADOW_INSTANCE_CONTEXT Context
    )
{
    FLT_FILESYSTEM_TYPE fsType = FLT_FSTYPE_UNKNOWN;

    PAGED_CODE();

    if (Context == NULL) {
        return FLT_FSTYPE_UNKNOWN;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&Context->Resource, TRUE);

    fsType = Context->FilesystemType;

    ExReleaseResourceLite(&Context->Resource);
    KeLeaveCriticalRegion();

    return fsType;
}

/**
 * @brief Update last activity timestamp (atomic).
 */
_Use_decl_annotations_
VOID
ShadowInstanceUpdateActivityTime(
    PSHADOW_INSTANCE_CONTEXT Context
    )
{
    LARGE_INTEGER currentTime;

    if (Context == NULL) {
        return;
    }

    KeQuerySystemTime(&currentTime);
    InterlockedExchange64(&Context->LastActivityTime, currentTime.QuadPart);
}

/**
 * @brief Get average scan time for this volume.
 *
 * Computes average on-demand from cumulative time and scan count.
 * This approach avoids race conditions in the recording path.
 */
_Use_decl_annotations_
LONGLONG
ShadowInstanceGetAverageScanTime(
    PSHADOW_INSTANCE_CONTEXT Context
    )
{
    LONGLONG totalScans;
    LONGLONG cumulativeTime;

    if (Context == NULL) {
        return 0;
    }

    //
    // Read both values atomically
    // Order matters: read scans first, then time
    // This gives a conservative (higher) average if races occur
    //
    totalScans = InterlockedCompareExchange64(&Context->TotalFilesScanned, 0, 0);
    cumulativeTime = InterlockedCompareExchange64(&Context->CumulativeScanTime, 0, 0);

    if (totalScans <= 0) {
        return 0;
    }

    return cumulativeTime / totalScans;
}

/**
 * @brief Copy volume name to caller buffer.
 */
_Use_decl_annotations_
NTSTATUS
ShadowInstanceCopyVolumeName(
    PSHADOW_INSTANCE_CONTEXT Context,
    PWCHAR Buffer,
    ULONG BufferSize,
    PULONG RequiredSize
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    USHORT nameLength;

    PAGED_CODE();

    if (Context == NULL || RequiredSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *RequiredSize = 0;

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&Context->Resource, TRUE);

    nameLength = Context->VolumeName.Length;
    *RequiredSize = (ULONG)nameLength + sizeof(WCHAR); // Include null terminator

    if (Buffer == NULL || BufferSize < *RequiredSize) {
        status = STATUS_BUFFER_TOO_SMALL;
    } else if (nameLength > 0 && Context->VolumeName.Buffer != NULL) {
        RtlCopyMemory(Buffer, Context->VolumeName.Buffer, nameLength);
        Buffer[nameLength / sizeof(WCHAR)] = L'\0';
        status = STATUS_SUCCESS;
    } else {
        //
        // No volume name available
        //
        Buffer[0] = L'\0';
        status = STATUS_SUCCESS;
    }

    ExReleaseResourceLite(&Context->Resource);
    KeLeaveCriticalRegion();

    return status;
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Query volume properties from Filter Manager.
 */
static
NTSTATUS
ShadowpQueryVolumeProperties(
    _In_ PFLT_VOLUME Volume,
    _Out_ PDEVICE_TYPE DeviceType,
    _Out_ PULONG DeviceCharacteristics,
    _Out_ PFLT_FILESYSTEM_TYPE FilesystemType
    )
{
    NTSTATUS status;
    FLT_VOLUME_PROPERTIES volumeProps;
    ULONG bytesReturned;

    PAGED_CODE();

    *DeviceType = FILE_DEVICE_UNKNOWN;
    *DeviceCharacteristics = 0;
    *FilesystemType = FLT_FSTYPE_UNKNOWN;

    RtlZeroMemory(&volumeProps, sizeof(volumeProps));

    status = FltGetVolumeProperties(
        Volume,
        &volumeProps,
        sizeof(volumeProps),
        &bytesReturned
    );

    //
    // STATUS_BUFFER_OVERFLOW is expected - we only need fixed fields
    //
    if (NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW) {
        *DeviceType = volumeProps.DeviceType;
        *DeviceCharacteristics = volumeProps.DeviceCharacteristics;

        //
        // Query filesystem type properly via FltGetFileSystemType
        //
        status = FltGetFileSystemType(Volume, FilesystemType);
        if (!NT_SUCCESS(status)) {
            *FilesystemType = FLT_FSTYPE_UNKNOWN;
            //
            // Don't fail the whole operation for this
            //
        }

        return STATUS_SUCCESS;
    }

    return status;
}

/**
 * @brief Query filesystem capabilities from volume.
 *
 * Uses FileFsAttributeInformation to determine actual filesystem features.
 */
static
NTSTATUS
ShadowpQueryFilesystemCapabilities(
    _In_ PFLT_INSTANCE Instance,
    _Out_ PSHADOW_FS_CAPABILITIES Capabilities
    )
{
    NTSTATUS status;
    FILE_FS_ATTRIBUTE_INFORMATION attrInfo;
    ULONG bytesReturned;
    ULONG fsAttributes;

    PAGED_CODE();

    RtlZeroMemory(Capabilities, sizeof(*Capabilities));
    RtlZeroMemory(&attrInfo, sizeof(attrInfo));

    status = FltQueryVolumeInformation(
        Instance,
        NULL,                           // No IRP, use cached info
        &attrInfo,
        sizeof(attrInfo),
        FileFsAttributeInformation
    );

    //
    // STATUS_BUFFER_OVERFLOW is expected - FileSystemName is variable length
    //
    if (NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW) {
        fsAttributes = attrInfo.FileSystemAttributes;

        //
        // Parse filesystem attributes into our capability structure
        // These flags are defined in wdm.h / ntifs.h
        //
        Capabilities->SupportsFileIds =
            BooleanFlagOn(fsAttributes, FILE_SUPPORTS_OPEN_BY_FILE_ID);

        Capabilities->SupportsStreams =
            BooleanFlagOn(fsAttributes, FILE_NAMED_STREAMS);

        Capabilities->SupportsObjectIds =
            BooleanFlagOn(fsAttributes, FILE_SUPPORTS_OBJECT_IDS);

        Capabilities->SupportsReparsePoints =
            BooleanFlagOn(fsAttributes, FILE_SUPPORTS_REPARSE_POINTS);

        Capabilities->SupportsSparseFiles =
            BooleanFlagOn(fsAttributes, FILE_SUPPORTS_SPARSE_FILES);

        Capabilities->SupportsEncryption =
            BooleanFlagOn(fsAttributes, FILE_SUPPORTS_ENCRYPTION);

        Capabilities->SupportsCompression =
            BooleanFlagOn(fsAttributes, FILE_FILE_COMPRESSION);

        Capabilities->SupportsHardLinks =
            BooleanFlagOn(fsAttributes, FILE_SUPPORTS_HARD_LINKS);

        return STATUS_SUCCESS;
    }

    return status;
}

/**
 * @brief Query volume serial number.
 */
static
NTSTATUS
ShadowpQueryVolumeSerialNumber(
    _In_ PFLT_INSTANCE Instance,
    _Out_ PULONG SerialNumber
    )
{
    NTSTATUS status;
    union {
        FILE_FS_VOLUME_INFORMATION VolumeInfo;
        UCHAR Buffer[sizeof(FILE_FS_VOLUME_INFORMATION) + 64 * sizeof(WCHAR)];
    } volumeBuffer;
    ULONG bytesReturned;

    PAGED_CODE();

    *SerialNumber = 0;

    RtlZeroMemory(&volumeBuffer, sizeof(volumeBuffer));

    status = FltQueryVolumeInformation(
        Instance,
        NULL,
        &volumeBuffer.VolumeInfo,
        sizeof(volumeBuffer),
        FileFsVolumeInformation
    );

    if (NT_SUCCESS(status)) {
        *SerialNumber = volumeBuffer.VolumeInfo.VolumeSerialNumber;
    }

    return status;
}

/**
 * @brief Determine volume type from device characteristics.
 *
 * Properly checks FILE_REMOVABLE_MEDIA and other device flags.
 */
static
SHADOW_VOLUME_TYPE
ShadowpDetermineVolumeType(
    _In_ DEVICE_TYPE DeviceType,
    _In_ ULONG DeviceCharacteristics,
    _In_ FLT_FILESYSTEM_TYPE FilesystemType
    )
{
    SHADOW_VOLUME_TYPE volumeType = VolumeTypeUnknown;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(FilesystemType);

    //
    // First check device type
    //
    switch (DeviceType) {
        case FILE_DEVICE_NETWORK:
        case FILE_DEVICE_NETWORK_FILE_SYSTEM:
        case FILE_DEVICE_DFS:
        case FILE_DEVICE_DFS_FILE_SYSTEM:
            volumeType = VolumeTypeNetwork;
            break;

        case FILE_DEVICE_CD_ROM:
        case FILE_DEVICE_CD_ROM_FILE_SYSTEM:
        case FILE_DEVICE_DVD:
            volumeType = VolumeTypeCDROM;
            break;

        case FILE_DEVICE_VIRTUAL_DISK:
            volumeType = VolumeTypeVirtual;
            break;

        case FILE_DEVICE_DISK:
        case FILE_DEVICE_DISK_FILE_SYSTEM:
            //
            // Could be fixed or removable - check characteristics
            //
            if (BooleanFlagOn(DeviceCharacteristics, FILE_REMOVABLE_MEDIA)) {
                volumeType = VolumeTypeRemovable;
            } else if (BooleanFlagOn(DeviceCharacteristics, FILE_FLOPPY_DISKETTE)) {
                volumeType = VolumeTypeRemovable;
            } else {
                volumeType = VolumeTypeFixed;
            }
            break;

        default:
            //
            // Check if removable via characteristics for unknown types
            //
            if (BooleanFlagOn(DeviceCharacteristics, FILE_REMOVABLE_MEDIA)) {
                volumeType = VolumeTypeRemovable;
            } else {
                volumeType = VolumeTypeUnknown;
            }
            break;
    }

    //
    // Check for RAM disk via characteristics
    //
    if (BooleanFlagOn(DeviceCharacteristics, FILE_VIRTUAL_VOLUME)) {
        //
        // Add RAM disk flag if it looks like a virtual volume
        //
        if (DeviceType != FILE_DEVICE_VIRTUAL_DISK) {
            volumeType = (SHADOW_VOLUME_TYPE)(volumeType | VolumeTypeRAMDisk);
        }
    }

    return volumeType;
}

/**
 * @brief Allocate and copy a UNICODE_STRING.
 *
 * Allocates a new buffer for the destination and copies the source.
 * Caller is responsible for freeing Destination->Buffer.
 */
static
NTSTATUS
ShadowpAllocateAndCopyString(
    _In_ PCUNICODE_STRING Source,
    _Out_ PUNICODE_STRING Destination,
    _In_ ULONG MaxLength
    )
{
    USHORT allocationLength;

    PAGED_CODE();

    RtlZeroMemory(Destination, sizeof(*Destination));

    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0) {
        return STATUS_SUCCESS;
    }

    //
    // Cap length to prevent excessive allocations
    //
    allocationLength = (USHORT)min(Source->Length, MaxLength);

    //
    // Allocate buffer with room for null terminator
    //
    Destination->Buffer = (PWCH)ExAllocatePool2(
        POOL_FLAG_PAGED,
        (SIZE_T)allocationLength + sizeof(WCHAR),
        SHADOW_INSTANCE_STRING_TAG
    );

    if (Destination->Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Copy string data
    //
    RtlCopyMemory(Destination->Buffer, Source->Buffer, allocationLength);

    //
    // Null terminate
    //
    Destination->Buffer[allocationLength / sizeof(WCHAR)] = L'\0';

    Destination->Length = allocationLength;
    Destination->MaximumLength = allocationLength + sizeof(WCHAR);

    return STATUS_SUCCESS;
}
