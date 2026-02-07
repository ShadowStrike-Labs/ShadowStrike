/**
 * ============================================================================
 * ShadowStrike NGAV - FILTER REGISTRATION
 * ============================================================================
 *
 * @file FilterRegistration.c
 * @brief Minifilter registration and callback implementations.
 *
 * Contains the FLT_REGISTRATION structure and all file system callback
 * implementations for intercepting I/O operations.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "FilterRegistration.h"
#include "Globals.h"
#include "DriverEntry.h"
#include "StreamContext.h"
#include "../Communication/CommPort.h"
#include "../SelfProtection/SelfProtect.h"
#include "../Shared/SharedDefs.h"
#include "../Shared/MessageProtocol.h"
#include "../Shared/VerdictTypes.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ShadowStrikeInstanceSetup)
#pragma alloc_text(PAGE, ShadowStrikeInstanceQueryTeardown)
#pragma alloc_text(PAGE, ShadowStrikeInstanceTeardownStart)
#pragma alloc_text(PAGE, ShadowStrikeInstanceTeardownComplete)
#endif

// ============================================================================
// CONTEXT DEFINITIONS
// ============================================================================

/**
 * @brief Context registration array.
 */
CONST FLT_CONTEXT_REGISTRATION g_ContextRegistration[] = {

    {
        FLT_STREAM_CONTEXT,                         // ContextType
        0,                                          // Flags
        ShadowCleanupStreamContext,                 // ContextCleanupCallback
        sizeof(SHADOW_STREAM_CONTEXT),              // Size
        SHADOW_CONTEXT_TAG,                         // PoolTag
        NULL,                                       // ContextAllocateCallback
        NULL,                                       // ContextFreeCallback
        NULL                                        // Reserved
    },

    { FLT_CONTEXT_END }
};

// ============================================================================
// OPERATION CALLBACKS
// ============================================================================

/**
 * @brief Operations we're interested in.
 */
CONST FLT_OPERATION_REGISTRATION g_OperationCallbacks[] = {

    //
    // IRP_MJ_CREATE - File open/create operations
    // This is our primary trigger for scanning
    //
    {
        IRP_MJ_CREATE,
        0,                                          // Flags
        ShadowStrikePreCreate,                      // PreOperation
        ShadowStrikePostCreate,                     // PostOperation
        NULL                                        // Reserved
    },

    //
    // IRP_MJ_WRITE - File write operations
    // Track modifications for rescan on close
    //
    {
        IRP_MJ_WRITE,
        0,
        ShadowStrikePreWrite,
        ShadowStrikePostWrite,
        NULL
    },

    //
    // IRP_MJ_SET_INFORMATION - Rename/Delete operations
    // Used for self-protection and monitoring
    //
    {
        IRP_MJ_SET_INFORMATION,
        0,
        ShadowStrikePreSetInformation,
        ShadowStrikePostSetInformation,
        NULL
    },

    //
    // IRP_MJ_CLEANUP - Last handle close
    // Trigger rescan of modified files
    //
    {
        IRP_MJ_CLEANUP,
        0,
        ShadowStrikePreCleanup,
        NULL,                                       // No post-operation needed
        NULL
    },

    //
    // IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION - Execute/Map
    // Critical for catching code execution
    //
    {
        IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
        0,
        ShadowStrikePreAcquireForSectionSync,
        NULL,
        NULL
    },

    { IRP_MJ_OPERATION_END }
};

// ============================================================================
// FILTER REGISTRATION STRUCTURE
// ============================================================================

/**
 * @brief Main filter registration structure.
 */
CONST FLT_REGISTRATION g_FilterRegistration = {

    sizeof(FLT_REGISTRATION),                       // Size
    FLT_REGISTRATION_VERSION,                       // Version
    0,                                              // Flags

    g_ContextRegistration,                          // Context
    g_OperationCallbacks,                           // Operation callbacks

    ShadowStrikeUnload,                             // FilterUnload
    ShadowStrikeInstanceSetup,                      // InstanceSetup
    ShadowStrikeInstanceQueryTeardown,              // InstanceQueryTeardown
    ShadowStrikeInstanceTeardownStart,              // InstanceTeardownStart
    ShadowStrikeInstanceTeardownComplete,           // InstanceTeardownComplete

    NULL,                                           // GenerateFileName
    NULL,                                           // NormalizeNameComponent
    NULL,                                           // NormalizeContextCleanup
    NULL,                                           // TransactionNotification
    NULL,                                           // NormalizeNameComponentEx
    NULL                                            // SectionNotification
};

CONST PFLT_REGISTRATION
ShadowStrikeGetFilterRegistration(
    VOID
    )
{
    return (PFLT_REGISTRATION)&g_FilterRegistration;
}

// ============================================================================
// INSTANCE CALLBACKS
// ============================================================================

NTSTATUS
ShadowStrikeInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN attachToVolume = TRUE;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] InstanceSetup: DevType=%u, FsType=%u\n",
               VolumeDeviceType, VolumeFilesystemType);

    //
    // Determine if we should attach to this volume
    //

    // Skip network redirectors unless configured to scan network files
    if (VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM) {
        if (!g_DriverData.Config.ScanNetworkFiles) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[ShadowStrike] Skipping network volume (disabled)\n");
            attachToVolume = FALSE;
        }
    }

    // Skip CD-ROM unless it's a writable disc
    if (VolumeDeviceType == FILE_DEVICE_CD_ROM ||
        VolumeDeviceType == FILE_DEVICE_CD_ROM_FILE_SYSTEM) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike] Skipping CD-ROM volume\n");
        attachToVolume = FALSE;
    }

    // Skip RAW file system (unformatted volumes)
    if (VolumeFilesystemType == FLT_FSTYPE_RAW) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike] Skipping RAW volume\n");
        attachToVolume = FALSE;
    }

    // Accept common file systems
    switch (VolumeFilesystemType) {
        case FLT_FSTYPE_NTFS:
        case FLT_FSTYPE_REFS:
        case FLT_FSTYPE_FAT:
        case FLT_FSTYPE_EXFAT:
            // Attach to these
            break;

        case FLT_FSTYPE_NPFS:   // Named pipes
        case FLT_FSTYPE_MSFS:   // Mailslots
        case FLT_FSTYPE_CSVFS:  // Cluster shared volumes (skip for now)
            attachToVolume = FALSE;
            break;

        default:
            // Attach to unknown file systems by default
            break;
    }

    if (!attachToVolume) {
        status = STATUS_FLT_DO_NOT_ATTACH;
    }

    return status;
}

NTSTATUS
ShadowStrikeInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] InstanceQueryTeardown\n");

    // Allow teardown - we don't hold any resources that prevent it
    return STATUS_SUCCESS;
}

VOID
ShadowStrikeInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] InstanceTeardownStart\n");
}

VOID
ShadowStrikeInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] InstanceTeardownComplete\n");
}

// ============================================================================
// CONTEXT CLEANUP
// ============================================================================

VOID
ShadowStrikeContextCleanup(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
    )
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(ContextType);

    // Stream context cleanup
    // No additional cleanup needed - memory freed by Filter Manager
}

// ============================================================================
// CONTEXT MANAGEMENT
// ============================================================================

NTSTATUS
ShadowStrikeGetStreamContext(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Outptr_ PSHADOWSTRIKE_STREAM_CONTEXT* Context
    )
{
    NTSTATUS status;
    PSHADOWSTRIKE_STREAM_CONTEXT streamContext = NULL;
    PSHADOWSTRIKE_STREAM_CONTEXT oldContext = NULL;

    *Context = NULL;

    //
    // Try to get existing context
    //
    status = FltGetStreamContext(
        Instance,
        FileObject,
        (PFLT_CONTEXT*)&streamContext
    );

    if (NT_SUCCESS(status)) {
        *Context = streamContext;
        return STATUS_SUCCESS;
    }

    if (status != STATUS_NOT_FOUND) {
        return status;
    }

    //
    // Create new context
    //
    status = ShadowStrikeCreateStreamContext(&streamContext);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Try to set the context
    //
    status = FltSetStreamContext(
        Instance,
        FileObject,
        FLT_SET_CONTEXT_KEEP_IF_EXISTS,
        streamContext,
        (PFLT_CONTEXT*)&oldContext
    );

    if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
        //
        // Another thread beat us - use their context
        //
        FltReleaseContext(streamContext);
        *Context = oldContext;
        return STATUS_SUCCESS;
    }

    if (!NT_SUCCESS(status)) {
        FltReleaseContext(streamContext);
        return status;
    }

    *Context = streamContext;
    return STATUS_SUCCESS;
}

NTSTATUS
ShadowStrikeCreateStreamContext(
    _Outptr_ PSHADOWSTRIKE_STREAM_CONTEXT* Context
    )
{
    NTSTATUS status;
    PSHADOWSTRIKE_STREAM_CONTEXT streamContext = NULL;

    *Context = NULL;

    status = FltAllocateContext(
        g_DriverData.FilterHandle,
        FLT_STREAM_CONTEXT,
        SHADOWSTRIKE_STREAM_CONTEXT_SIZE,
        NonPagedPoolNx,
        (PFLT_CONTEXT*)&streamContext
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(streamContext, SHADOWSTRIKE_STREAM_CONTEXT_SIZE);

    *Context = streamContext;
    return STATUS_SUCCESS;
}

// ============================================================================
// FILE SYSTEM CALLBACKS - IRP_MJ_CREATE
// ============================================================================

FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    BOOLEAN isDirectory = FALSE;
    ULONG createDisposition;

    *CompletionContext = NULL;

    //
    // Quick validation - bail early if not ready
    //
    if (!SHADOWSTRIKE_IS_READY()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!g_DriverData.Config.FilteringEnabled) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Validate parameters
    //
    if (Data == NULL || FltObjects == NULL || FltObjects->FileObject == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Skip kernel-mode requests (paging I/O, etc.)
    //
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Skip directory operations
    //
    createDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;
    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
        isDirectory = TRUE;
    }

    //
    // Increment stats
    //
    SHADOWSTRIKE_INC_STAT(TotalCreateOperations);

    //
    // Get file name for filtering decisions
    //
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );

    if (!NT_SUCCESS(status)) {
        // Can't get name - allow and skip further processing
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Check for self-protection
    // Block write/delete access to protected AV binaries and config files
    //
    if (g_DriverData.Config.SelfProtectionEnabled) {
        ACCESS_MASK desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
        HANDLE requestorPid = PsGetCurrentProcessId();

        //
        // Check if this is a write/delete access to a protected path
        //
        if (ShadowStrikeShouldBlockFileAccess(
                &nameInfo->Name,
                desiredAccess,
                requestorPid,
                FALSE  // Not a delete operation (handled in PreSetInformation)
            )) {
            //
            // Block access to protected file
            //
            FltReleaseFileNameInformation(nameInfo);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] BLOCKED write access to protected file: %wZ\n",
                       &nameInfo->Name);

            return FLT_PREOP_COMPLETE;
        }
    }

    //
    // Pass to post-create for actual scanning
    // We do scanning in post-create because we have file size/attributes there
    //
    *CompletionContext = nameInfo;  // Pass name info to post-op

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
ShadowStrikePostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    PFLT_FILE_NAME_INFORMATION nameInfo = (PFLT_FILE_NAME_INFORMATION)CompletionContext;
    NTSTATUS status;
    BOOLEAN shouldScan = FALSE;
    FILE_STANDARD_INFORMATION fileInfo;
    SHADOWSTRIKE_VERDICT verdict = ShadowStrikeVerdictAllow;

    //
    // Handle draining - just cleanup and return
    //
    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        if (nameInfo != NULL) {
            FltReleaseFileNameInformation(nameInfo);
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // If create failed, nothing to scan
    //
    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        if (nameInfo != NULL) {
            FltReleaseFileNameInformation(nameInfo);
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // Skip if no file object
    //
    if (FltObjects->FileObject == NULL) {
        if (nameInfo != NULL) {
            FltReleaseFileNameInformation(nameInfo);
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    SHADOWSTRIKE_ENTER_OPERATION();

    //
    // Check if this is an executable file
    //
    if (nameInfo != NULL && nameInfo->Extension.Length > 0) {
        // Check extension for executables
        if (RtlCompareUnicodeString(&nameInfo->Extension, &(UNICODE_STRING)RTL_CONSTANT_STRING(L"exe"), TRUE) == 0 ||
            RtlCompareUnicodeString(&nameInfo->Extension, &(UNICODE_STRING)RTL_CONSTANT_STRING(L"dll"), TRUE) == 0 ||
            RtlCompareUnicodeString(&nameInfo->Extension, &(UNICODE_STRING)RTL_CONSTANT_STRING(L"sys"), TRUE) == 0 ||
            RtlCompareUnicodeString(&nameInfo->Extension, &(UNICODE_STRING)RTL_CONSTANT_STRING(L"scr"), TRUE) == 0) {
            shouldScan = TRUE;
        }
    }

    //
    // Get file size
    //
    if (shouldScan) {
        status = FltQueryInformationFile(
            FltObjects->Instance,
            FltObjects->FileObject,
            &fileInfo,
            sizeof(fileInfo),
            FileStandardInformation,
            NULL
        );

        if (NT_SUCCESS(status)) {
            // Check max file size
            if (g_DriverData.Config.MaxScanFileSize > 0 &&
                fileInfo.EndOfFile.QuadPart > (LONGLONG)g_DriverData.Config.MaxScanFileSize) {
                shouldScan = FALSE;
            }

            // Skip directories
            if (fileInfo.Directory) {
                shouldScan = FALSE;
            }
        }
    }

    //
    // Perform scan if needed
    //
    if (shouldScan && g_DriverData.Config.ScanOnOpen && SHADOWSTRIKE_USER_MODE_CONNECTED()) {
        PSHADOWSTRIKE_MESSAGE_HEADER request = NULL;
        SHADOWSTRIKE_SCAN_VERDICT_REPLY reply = {0};
        ULONG requestSize = 0;
        ULONG replySize = sizeof(reply);

        //
        // Build and send scan request
        //
        status = ShadowStrikeBuildFileScanRequest(
            Data,
            FltObjects,
            ShadowStrikeAccessRead,
            &request,
            &requestSize
        );

        if (NT_SUCCESS(status) && request != NULL) {
            status = ShadowStrikeSendScanRequest(
                request,
                requestSize,
                &reply,
                &replySize,
                g_DriverData.Config.ScanTimeoutMs
            );

            if (NT_SUCCESS(status)) {
                verdict = (SHADOWSTRIKE_VERDICT)reply.Verdict;
                SHADOWSTRIKE_INC_STAT(TotalFilesScanned);
            } else if (status == STATUS_TIMEOUT) {
                SHADOWSTRIKE_INC_STAT(ScanTimeouts);
                verdict = g_DriverData.Config.BlockOnTimeout ?
                          ShadowStrikeVerdictBlock : ShadowStrikeVerdictAllow;
            } else {
                SHADOWSTRIKE_INC_STAT(ScanErrors);
                verdict = g_DriverData.Config.BlockOnError ?
                          ShadowStrikeVerdictBlock : ShadowStrikeVerdictAllow;
            }

            ShadowStrikeFreeMessageBuffer(request);
        }

        //
        // Handle verdict
        //
        if (SHADOWSTRIKE_VERDICT_BLOCKS(verdict)) {
            SHADOWSTRIKE_INC_STAT(FilesBlocked);

            // Cancel the create by closing the file and returning access denied
            FltCancelFileOpen(FltObjects->Instance, FltObjects->FileObject);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] BLOCKED: %wZ\n", &nameInfo->Name);
        } else {
            SHADOWSTRIKE_INC_STAT(FilesAllowed);
        }
    }

    SHADOWSTRIKE_LEAVE_OPERATION();

    if (nameInfo != NULL) {
        FltReleaseFileNameInformation(nameInfo);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// ============================================================================
// FILE SYSTEM CALLBACKS - IRP_MJ_WRITE
// ============================================================================

FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    )
{
    *CompletionContext = NULL;

    if (!SHADOWSTRIKE_IS_READY()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Skip kernel-mode writes
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    UNREFERENCED_PARAMETER(FltObjects);

    // Track writes to trigger rescan on close
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
ShadowStrikePostWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    PSHADOWSTRIKE_STREAM_CONTEXT streamContext = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // Mark file as modified in stream context
    //
    status = ShadowStrikeGetStreamContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        &streamContext
    );

    if (NT_SUCCESS(status)) {
        streamContext->Modified = TRUE;
        streamContext->HashValid = FALSE;  // Invalidate cached hash
        FltReleaseContext(streamContext);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// ============================================================================
// FILE SYSTEM CALLBACKS - IRP_MJ_SET_INFORMATION
// ============================================================================

FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    )
{
    FILE_INFORMATION_CLASS fileInfoClass;

    *CompletionContext = NULL;

    if (!SHADOWSTRIKE_IS_READY()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    UNREFERENCED_PARAMETER(FltObjects);

    fileInfoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    //
    // Intercept rename and delete operations
    //
    switch (fileInfoClass) {
        case FileRenameInformation:
        case FileRenameInformationEx:
            // Check self-protection for renames
            if (g_DriverData.Config.SelfProtectionEnabled) {
                PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
                NTSTATUS nameStatus;

                nameStatus = FltGetFileNameInformation(
                    Data,
                    FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                    &nameInfo
                );

                if (NT_SUCCESS(nameStatus)) {
                    FltParseFileNameInformation(nameInfo);

                    //
                    // Block renames of protected files
                    //
                    if (ShadowStrikeShouldBlockFileAccess(
                            &nameInfo->Name,
                            DELETE,  // Rename requires delete access semantically
                            PsGetCurrentProcessId(),
                            FALSE
                        )) {
                        FltReleaseFileNameInformation(nameInfo);
                        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                        Data->IoStatus.Information = 0;

                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                                   "[ShadowStrike] BLOCKED rename of protected file: %wZ\n",
                                   &nameInfo->Name);

                        return FLT_PREOP_COMPLETE;
                    }
                    FltReleaseFileNameInformation(nameInfo);
                }
            }
            break;

        case FileDispositionInformation:
        case FileDispositionInformationEx:
            // Check self-protection for deletes
            if (g_DriverData.Config.SelfProtectionEnabled) {
                PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
                NTSTATUS nameStatus;

                nameStatus = FltGetFileNameInformation(
                    Data,
                    FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                    &nameInfo
                );

                if (NT_SUCCESS(nameStatus)) {
                    FltParseFileNameInformation(nameInfo);

                    //
                    // Block deletion of protected files
                    //
                    if (ShadowStrikeShouldBlockFileAccess(
                            &nameInfo->Name,
                            DELETE,
                            PsGetCurrentProcessId(),
                            TRUE  // This IS a delete operation
                        )) {
                        FltReleaseFileNameInformation(nameInfo);
                        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                        Data->IoStatus.Information = 0;

                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                                   "[ShadowStrike] BLOCKED deletion of protected file: %wZ\n",
                                   &nameInfo->Name);

                        return FLT_PREOP_COMPLETE;
                    }
                    FltReleaseFileNameInformation(nameInfo);
                }
            }
            break;

        default:
            break;
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
ShadowStrikePostSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    // Send notification to user-mode about rename/delete
    // Full implementation in notification path

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// ============================================================================
// FILE SYSTEM CALLBACKS - IRP_MJ_CLEANUP
// ============================================================================

FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    )
{
    PSHADOWSTRIKE_STREAM_CONTEXT streamContext = NULL;
    NTSTATUS status;

    *CompletionContext = NULL;

    if (!SHADOWSTRIKE_IS_READY()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    UNREFERENCED_PARAMETER(Data);

    //
    // Check if file was modified - trigger rescan if needed
    //
    if (g_DriverData.Config.ScanOnWrite) {
        status = FltGetStreamContext(
            FltObjects->Instance,
            FltObjects->FileObject,
            (PFLT_CONTEXT*)&streamContext
        );

        if (NT_SUCCESS(status)) {
            if (streamContext->Modified) {
                // TODO: Queue for rescan
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                           "[ShadowStrike] File modified, needs rescan\n");
            }
            FltReleaseContext(streamContext);
        }
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ============================================================================
// FILE SYSTEM CALLBACKS - SECTION SYNCHRONIZATION
// ============================================================================

FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreAcquireForSectionSync(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    )
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    SHADOWSTRIKE_VERDICT verdict = ShadowStrikeVerdictAllow;

    *CompletionContext = NULL;

    if (!SHADOWSTRIKE_IS_READY()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!g_DriverData.Config.ScanOnExecute) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Check if this is for execute access
    //
    if (Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection != PAGE_EXECUTE &&
        Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection != PAGE_EXECUTE_READ &&
        Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection != PAGE_EXECUTE_READWRITE &&
        Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection != PAGE_EXECUTE_WRITECOPY) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    SHADOWSTRIKE_ENTER_OPERATION();

    //
    // Get file name
    //
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );

    if (!NT_SUCCESS(status)) {
        SHADOWSTRIKE_LEAVE_OPERATION();
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FltParseFileNameInformation(nameInfo);

    //
    // Send scan request for execute
    //
    if (SHADOWSTRIKE_USER_MODE_CONNECTED()) {
        PSHADOWSTRIKE_MESSAGE_HEADER request = NULL;
        SHADOWSTRIKE_SCAN_VERDICT_REPLY reply = {0};
        ULONG requestSize = 0;
        ULONG replySize = sizeof(reply);

        status = ShadowStrikeBuildFileScanRequest(
            Data,
            FltObjects,
            ShadowStrikeAccessExecute,
            &request,
            &requestSize
        );

        if (NT_SUCCESS(status) && request != NULL) {
            status = ShadowStrikeSendScanRequest(
                request,
                requestSize,
                &reply,
                &replySize,
                g_DriverData.Config.ScanTimeoutMs
            );

            if (NT_SUCCESS(status)) {
                verdict = (SHADOWSTRIKE_VERDICT)reply.Verdict;
                SHADOWSTRIKE_INC_STAT(TotalFilesScanned);
            } else if (status == STATUS_TIMEOUT) {
                SHADOWSTRIKE_INC_STAT(ScanTimeouts);
                verdict = g_DriverData.Config.BlockOnTimeout ?
                          ShadowStrikeVerdictBlock : ShadowStrikeVerdictAllow;
            }

            ShadowStrikeFreeMessageBuffer(request);
        }
    }

    FltReleaseFileNameInformation(nameInfo);

    SHADOWSTRIKE_LEAVE_OPERATION();

    //
    // Block execution if verdict says so
    //
    if (SHADOWSTRIKE_VERDICT_BLOCKS(verdict)) {
        SHADOWSTRIKE_INC_STAT(FilesBlocked);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
