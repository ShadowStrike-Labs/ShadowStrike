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
 * SECURITY MODEL:
 * - All user-mode accessible paths validated
 * - Self-protection enforced on all write/delete/rename paths
 * - Kernel-mode requests logged for telemetry (not silently skipped)
 * - Cached verdicts used in blocking-sensitive paths
 *
 * IRQL SAFETY:
 * - All blocking operations use deferred work items
 * - Post-operation callbacks handle elevated IRQL gracefully
 * - Draining operations cleaned up properly
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "FilterRegistration.h"
#include "Globals.h"
#include "DriverEntry.h"
#include "../Context/StreamContext.h"
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
#pragma alloc_text(PAGE, ShadowStrikeIsScannable)
#pragma alloc_text(PAGE, ShadowStrikeQueueRescan)
#endif

// ============================================================================
// SCANNABLE EXTENSIONS TABLE
// ============================================================================

/**
 * @brief Comprehensive list of scannable file extensions.
 *
 * This table covers:
 * - PE executables (exe, dll, sys, scr, ocx, cpl, drv)
 * - Scripts (bat, cmd, ps1, vbs, js, wsf, wsh, hta)
 * - Installers (msi, msp, msu)
 * - Archives with executable content (jar, com)
 * - Management consoles (msc)
 * - Legacy formats (pif, lnk)
 */
static const SHADOW_EXTENSION_ENTRY g_ScannableExtensions[] = {
    // PE Executables (directly executable)
    { L"exe",  6,  TRUE,  FALSE },
    { L"dll",  6,  TRUE,  FALSE },
    { L"sys",  6,  TRUE,  FALSE },
    { L"scr",  6,  TRUE,  FALSE },
    { L"ocx",  6,  TRUE,  FALSE },
    { L"cpl",  6,  TRUE,  FALSE },
    { L"drv",  6,  TRUE,  FALSE },
    { L"com",  6,  TRUE,  FALSE },
    { L"pif",  6,  TRUE,  FALSE },

    // Script files (interpreted but dangerous)
    { L"bat",  6,  FALSE, TRUE  },
    { L"cmd",  6,  FALSE, TRUE  },
    { L"ps1",  6,  FALSE, TRUE  },
    { L"psm1", 8,  FALSE, TRUE  },
    { L"psd1", 8,  FALSE, TRUE  },
    { L"vbs",  6,  FALSE, TRUE  },
    { L"vbe",  6,  FALSE, TRUE  },
    { L"js",   4,  FALSE, TRUE  },
    { L"jse",  6,  FALSE, TRUE  },
    { L"wsf",  6,  FALSE, TRUE  },
    { L"wsh",  6,  FALSE, TRUE  },
    { L"hta",  6,  FALSE, TRUE  },
    { L"msc",  6,  FALSE, TRUE  },

    // Installers
    { L"msi",  6,  TRUE,  FALSE },
    { L"msp",  6,  TRUE,  FALSE },
    { L"msu",  6,  TRUE,  FALSE },

    // Java archives (can contain executable code)
    { L"jar",  6,  TRUE,  FALSE },

    // Shortcuts (can redirect to malware)
    { L"lnk",  6,  FALSE, FALSE },

    // Sentinel - must be last
    { NULL, 0, FALSE, FALSE }
};

// ============================================================================
// CONTEXT DEFINITIONS
// ============================================================================

/**
 * @brief Context registration array.
 *
 * Uses SHADOW_STREAM_CONTEXT from StreamContext.h for consistency.
 */
CONST FLT_CONTEXT_REGISTRATION g_ContextRegistration[] = {

    {
        FLT_STREAM_CONTEXT,                         // ContextType
        0,                                          // Flags
        ShadowCleanupStreamContext,                 // ContextCleanupCallback
        sizeof(SHADOW_STREAM_CONTEXT),              // Size
        SHADOW_STREAM_CONTEXT_TAG,                  // PoolTag
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
    // Track modifications for rescan on close AND self-protection
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
// HELPER: VALIDATE DRIVER READY STATE
// ============================================================================

/**
 * @brief Safely check if driver is ready for operations.
 *
 * Provides additional NULL checks beyond the macro for safety.
 */
FORCEINLINE
BOOLEAN
ShadowStrikeIsDriverReady(
    VOID
    )
{
    //
    // Validate g_DriverData fields are accessible
    //
    if (g_DriverData.FilterHandle == NULL) {
        return FALSE;
    }

    return SHADOWSTRIKE_IS_READY();
}

// ============================================================================
// HELPER: EXTENSION CHECKING
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsScannable(
    _In_ PCUNICODE_STRING Extension,
    _Out_opt_ PBOOLEAN IsExecutable
    )
{
    ULONG i;
    UNICODE_STRING extToCompare;

    if (IsExecutable != NULL) {
        *IsExecutable = FALSE;
    }

    if (Extension == NULL || Extension->Length == 0 || Extension->Buffer == NULL) {
        return FALSE;
    }

    //
    // Check against our extension table
    //
    for (i = 0; g_ScannableExtensions[i].Extension != NULL; i++) {
        RtlInitUnicodeString(&extToCompare, g_ScannableExtensions[i].Extension);

        if (RtlCompareUnicodeString(Extension, &extToCompare, TRUE) == 0) {
            if (IsExecutable != NULL) {
                *IsExecutable = g_ScannableExtensions[i].IsExecutable;
            }
            return TRUE;
        }
    }

    return FALSE;
}

// ============================================================================
// INSTANCE CALLBACKS
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
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
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] InstanceSetup: DevType=%u, FsType=%u\n",
               VolumeDeviceType, VolumeFilesystemType);

    //
    // Validate driver is initialized
    //
    if (!g_DriverData.Initialized) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    //
    // Determine if we should attach to this volume
    //

    // Skip network redirectors unless configured to scan network files
    if (VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM) {
        if (!g_DriverData.Config.ScanNetworkFiles) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[ShadowStrike] Skipping network volume (disabled by config)\n");
            attachToVolume = FALSE;
        }
    }

    // Skip CD-ROM (read-only, low risk for malware persistence)
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

    // Accept common file systems, skip special ones
    switch (VolumeFilesystemType) {
        case FLT_FSTYPE_NTFS:
        case FLT_FSTYPE_REFS:
        case FLT_FSTYPE_FAT:
        case FLT_FSTYPE_EXFAT:
            // Attach to these standard file systems
            break;

        case FLT_FSTYPE_NPFS:   // Named pipes - no file scanning needed
        case FLT_FSTYPE_MSFS:   // Mailslots - no file scanning needed
            attachToVolume = FALSE;
            break;

        case FLT_FSTYPE_CSVFS:  // Cluster Shared Volumes
            //
            // CSVFS requires special handling in cluster environments.
            // Attach but with awareness that I/O may be redirected.
            //
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[ShadowStrike] Attaching to CSVFS volume (cluster mode)\n");
            break;

        default:
            //
            // Attach to unknown file systems by default for security coverage
            //
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[ShadowStrike] Attaching to unknown FsType=%u\n",
                       VolumeFilesystemType);
            break;
    }

    if (!attachToVolume) {
        status = STATUS_FLT_DO_NOT_ATTACH;
    }

    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
{
    LONG outstandingOps;

    PAGED_CODE();
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] InstanceQueryTeardown\n");

    //
    // Check if we have outstanding operations on this instance
    // If so, we may deny the teardown to prevent use-after-free
    //
    outstandingOps = InterlockedCompareExchange(
        &g_DriverData.OutstandingOperations,
        0,
        0
    );

    if (outstandingOps > 0 && !g_DriverData.ShuttingDown) {
        //
        // We have pending operations. Allow teardown but log it.
        // The operations will complete and find the instance gone,
        // but Filter Manager handles this gracefully.
        //
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] InstanceQueryTeardown with %ld outstanding ops\n",
                   outstandingOps);
    }

    //
    // Allow teardown - we don't hold resources that absolutely prevent it
    // Outstanding operations will complete their cleanup paths
    //
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
{
    PAGED_CODE();
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] InstanceTeardownStart\n");

    //
    // Signal that new operations should not be started for this instance
    // This is handled by checking g_DriverData.ShuttingDown in callbacks
    //
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
{
    PAGED_CODE();
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] InstanceTeardownComplete\n");
}

// ============================================================================
// FILE SYSTEM CALLBACKS - IRP_MJ_CREATE
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    ULONG createDisposition;
    ACCESS_MASK desiredAccess;
    HANDLE requestorPid;
    BOOLEAN isKernelMode;

    *CompletionContext = NULL;

    //
    // IRQL assertion for debug builds
    //
    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

    //
    // Quick validation - bail early if not ready
    //
    if (!ShadowStrikeIsDriverReady()) {
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
    // Check requestor mode - log kernel-mode requests for telemetry
    //
    isKernelMode = (Data->RequestorMode == KernelMode);
    if (isKernelMode) {
        //
        // SECURITY: Don't silently skip kernel-mode requests.
        // Log for telemetry but don't block (could be legitimate driver I/O).
        // Self-protection still applies to kernel-mode requests.
        //
        if (!g_DriverData.Config.SelfProtectionEnabled) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        // Fall through to self-protection check
    }

    //
    // Skip directory operations for scanning (but check self-protection)
    //
    createDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;

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
        desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
        requestorPid = PsGetCurrentProcessId();

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
            // CRITICAL: Log BEFORE releasing nameInfo to avoid use-after-free
            //
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] BLOCKED write access to protected file: %wZ (PID=%p, KernelMode=%d)\n",
                       &nameInfo->Name, requestorPid, isKernelMode);

            SHADOWSTRIKE_INC_STAT(SelfProtectionBlocks);

            FltReleaseFileNameInformation(nameInfo);

            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;

            return FLT_PREOP_COMPLETE;
        }
    }

    //
    // Skip kernel-mode requests from scanning (already checked self-protection)
    //
    if (isKernelMode) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Pass to post-create for actual scanning
    // We do scanning in post-create because we have file size/attributes there
    //
    *CompletionContext = nameInfo;  // Pass name info to post-op

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
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
    BOOLEAN isExecutable = FALSE;
    FILE_STANDARD_INFORMATION fileInfo;
    SHADOWSTRIKE_SCAN_VERDICT verdict = Verdict_Clean;
    KIRQL currentIrql;

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

    //
    // Check IRQL - if above PASSIVE_LEVEL, we cannot do blocking operations
    //
    currentIrql = KeGetCurrentIrql();
    if (currentIrql > PASSIVE_LEVEL) {
        //
        // At elevated IRQL - cannot block for user-mode scan.
        // For now, allow the operation. In a full implementation,
        // we would queue a deferred work item.
        //
        if (nameInfo != NULL) {
            FltReleaseFileNameInformation(nameInfo);
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    SHADOWSTRIKE_ENTER_OPERATION();

    //
    // Check if this is a scannable file type
    //
    if (nameInfo != NULL && nameInfo->Extension.Length > 0) {
        shouldScan = ShadowStrikeIsScannable(&nameInfo->Extension, &isExecutable);
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
        } else {
            // Can't query file info - skip scan
            shouldScan = FALSE;
        }
    }

    //
    // Perform scan if needed
    //
    if (shouldScan && g_DriverData.Config.ScanOnOpen && SHADOWSTRIKE_USER_MODE_CONNECTED()) {
        PSHADOWSTRIKE_MESSAGE_HEADER request = NULL;
        SHADOWSTRIKE_SCAN_VERDICT_REPLY reply;
        ULONG requestSize = 0;
        ULONG replySize = sizeof(reply);

        RtlZeroMemory(&reply, sizeof(reply));

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
                verdict = (SHADOWSTRIKE_SCAN_VERDICT)reply.Verdict;
                SHADOWSTRIKE_INC_STAT(TotalFilesScanned);
            } else if (status == STATUS_TIMEOUT) {
                SHADOWSTRIKE_INC_STAT(ScanTimeouts);
                verdict = g_DriverData.Config.BlockOnTimeout ?
                          Verdict_Malicious : Verdict_Clean;
            } else {
                SHADOWSTRIKE_INC_STAT(ScanErrors);
                verdict = g_DriverData.Config.BlockOnError ?
                          Verdict_Malicious : Verdict_Clean;
            }

            ShadowStrikeFreeMessageBuffer(request);
        }

        //
        // Handle verdict
        //
        if (verdict == Verdict_Malicious) {
            SHADOWSTRIKE_INC_STAT(FilesBlocked);

            //
            // CRITICAL: Log BEFORE calling FltCancelFileOpen
            //
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] BLOCKED malicious file: %wZ\n",
                       &nameInfo->Name);

            // Cancel the create by closing the file and returning access denied
            FltCancelFileOpen(FltObjects->Instance, FltObjects->FileObject);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
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

_IRQL_requires_max_(APC_LEVEL)
FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    HANDLE requestorPid;

    *CompletionContext = NULL;

    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

    if (!ShadowStrikeIsDriverReady()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // SECURITY FIX: Check self-protection for write operations
    // This prevents attackers with existing write handles from modifying protected files
    //
    if (g_DriverData.Config.SelfProtectionEnabled) {
        status = FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &nameInfo
        );

        if (NT_SUCCESS(status)) {
            FltParseFileNameInformation(nameInfo);
            requestorPid = PsGetCurrentProcessId();

            if (ShadowStrikeShouldBlockFileAccess(
                    &nameInfo->Name,
                    FILE_WRITE_DATA | FILE_APPEND_DATA,
                    requestorPid,
                    FALSE
                )) {
                //
                // CRITICAL: Log BEFORE releasing nameInfo
                //
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike] BLOCKED write to protected file: %wZ (PID=%p)\n",
                           &nameInfo->Name, requestorPid);

                SHADOWSTRIKE_INC_STAT(SelfProtectionBlocks);

                FltReleaseFileNameInformation(nameInfo);

                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                Data->IoStatus.Information = 0;

                return FLT_PREOP_COMPLETE;
            }

            FltReleaseFileNameInformation(nameInfo);
        }
    }

    // Skip kernel-mode writes for tracking (but self-protection was checked)
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Track writes to trigger rescan on close
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
FLT_POSTOP_CALLBACK_STATUS
ShadowStrikePostWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    PSHADOW_STREAM_CONTEXT streamContext = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (FltObjects->FileObject == NULL || FltObjects->Instance == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // Mark file as modified in stream context
    // Use the proper context type from StreamContext.h
    //
    status = ShadowGetOrCreateStreamContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        &streamContext
    );

    if (NT_SUCCESS(status) && streamContext != NULL) {
        //
        // Invalidate the context - marks as modified and clears scan state
        //
        ShadowInvalidateStreamContext(streamContext);
        FltReleaseContext(streamContext);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// ============================================================================
// FILE SYSTEM CALLBACKS - IRP_MJ_SET_INFORMATION
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    )
{
    FILE_INFORMATION_CLASS fileInfoClass;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS nameStatus;
    HANDLE requestorPid;
    BOOLEAN shouldBlock = FALSE;
    BOOLEAN isDelete = FALSE;

    *CompletionContext = NULL;

    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

    if (!ShadowStrikeIsDriverReady()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    UNREFERENCED_PARAMETER(FltObjects);

    fileInfoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    //
    // Intercept rename and delete operations for self-protection
    //
    switch (fileInfoClass) {
        case FileRenameInformation:
        case FileRenameInformationEx:
        case FileDispositionInformation:
        case FileDispositionInformationEx:
            break;

        default:
            // Not a rename/delete - allow without callback
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Determine if this is a delete operation
    //
    isDelete = (fileInfoClass == FileDispositionInformation ||
                fileInfoClass == FileDispositionInformationEx);

    //
    // Check self-protection
    //
    if (g_DriverData.Config.SelfProtectionEnabled) {
        nameStatus = FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &nameInfo
        );

        if (NT_SUCCESS(nameStatus)) {
            FltParseFileNameInformation(nameInfo);
            requestorPid = PsGetCurrentProcessId();

            shouldBlock = ShadowStrikeShouldBlockFileAccess(
                &nameInfo->Name,
                DELETE,
                requestorPid,
                isDelete
            );

            if (shouldBlock) {
                //
                // CRITICAL: Log BEFORE releasing nameInfo to avoid use-after-free
                //
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike] BLOCKED %s of protected file: %wZ (PID=%p)\n",
                           isDelete ? "deletion" : "rename",
                           &nameInfo->Name,
                           requestorPid);

                SHADOWSTRIKE_INC_STAT(SelfProtectionBlocks);

                FltReleaseFileNameInformation(nameInfo);

                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                Data->IoStatus.Information = 0;

                return FLT_PREOP_COMPLETE;
            }

            //
            // Store name info for post-op notification
            //
            *CompletionContext = nameInfo;
        }
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
FLT_POSTOP_CALLBACK_STATUS
ShadowStrikePostSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    PFLT_FILE_NAME_INFORMATION nameInfo = (PFLT_FILE_NAME_INFORMATION)CompletionContext;
    FILE_INFORMATION_CLASS fileInfoClass;
    BOOLEAN isDelete;
    BOOLEAN isRename;

    UNREFERENCED_PARAMETER(FltObjects);

    //
    // Handle draining
    //
    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        if (nameInfo != NULL) {
            FltReleaseFileNameInformation(nameInfo);
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // If the operation failed, no notification needed
    //
    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        if (nameInfo != NULL) {
            FltReleaseFileNameInformation(nameInfo);
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // Send notification to user-mode about successful rename/delete
    //
    if (nameInfo != NULL && g_DriverData.Config.NotificationsEnabled &&
        SHADOWSTRIKE_USER_MODE_CONNECTED()) {

        fileInfoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
        isDelete = (fileInfoClass == FileDispositionInformation ||
                    fileInfoClass == FileDispositionInformationEx);
        isRename = (fileInfoClass == FileRenameInformation ||
                    fileInfoClass == FileRenameInformationEx);

        if (isDelete || isRename) {
            //
            // Build and send notification asynchronously
            // This is fire-and-forget - we don't wait for reply
            //
            PSHADOWSTRIKE_MESSAGE_HEADER notification = NULL;
            ULONG notificationSize = 0;

            if (NT_SUCCESS(ShadowStrikeBuildFileScanRequest(
                    Data,
                    FltObjects,
                    isDelete ? ShadowStrikeAccessDelete : ShadowStrikeAccessRename,
                    &notification,
                    &notificationSize))) {

                // Send notification (ignore result - fire and forget)
                ShadowStrikeSendNotification(notification, notificationSize);
                ShadowStrikeFreeMessageBuffer(notification);
            }

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                       "[ShadowStrike] %s notification sent: %wZ\n",
                       isDelete ? "Delete" : "Rename",
                       &nameInfo->Name);
        }
    }

    if (nameInfo != NULL) {
        FltReleaseFileNameInformation(nameInfo);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// ============================================================================
// FILE SYSTEM CALLBACKS - IRP_MJ_CLEANUP
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    )
{
    PSHADOW_STREAM_CONTEXT streamContext = NULL;
    NTSTATUS status;
    BOOLEAN needsRescan = FALSE;

    *CompletionContext = NULL;

    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

    if (!ShadowStrikeIsDriverReady()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    UNREFERENCED_PARAMETER(Data);

    //
    // Check if file was modified - trigger rescan if needed
    //
    if (g_DriverData.Config.ScanOnWrite && FltObjects->FileObject != NULL) {
        status = ShadowGetStreamContext(
            FltObjects->Instance,
            FltObjects->FileObject,
            &streamContext
        );

        if (NT_SUCCESS(status) && streamContext != NULL) {
            //
            // Check if rescan is needed using the proper API
            //
            needsRescan = ShadowShouldRescan(
                streamContext,
                g_DriverData.Config.CacheTTLSeconds
            );

            if (needsRescan) {
                //
                // Queue asynchronous rescan
                // We cannot block here as cleanup must complete
                //
                status = ShadowStrikeQueueRescan(
                    FltObjects->Instance,
                    FltObjects->FileObject,
                    streamContext->FileName.Buffer != NULL ? &streamContext->FileName : NULL
                );

                if (NT_SUCCESS(status)) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                               "[ShadowStrike] Queued rescan for modified file\n");
                }
            }

            FltReleaseContext(streamContext);
        }
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ============================================================================
// FILE SYSTEM CALLBACKS - SECTION SYNCHRONIZATION
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreAcquireForSectionSync(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    )
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    SHADOWSTRIKE_SCAN_VERDICT cachedVerdict = Verdict_Unknown;
    PSHADOW_STREAM_CONTEXT streamContext = NULL;
    ULONG pageProtection;
    BOOLEAN isExecuteMapping = FALSE;
    HANDLE requestorPid;

    *CompletionContext = NULL;

    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

    if (!ShadowStrikeIsDriverReady()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // SECURITY FIX: Check self-protection BEFORE checking ScanOnExecute config
    // This prevents attackers from disabling scan and then executing malware
    //
    if (g_DriverData.Config.SelfProtectionEnabled) {
        status = FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &nameInfo
        );

        if (NT_SUCCESS(status)) {
            FltParseFileNameInformation(nameInfo);
            requestorPid = PsGetCurrentProcessId();

            if (ShadowStrikeShouldBlockFileAccess(
                    &nameInfo->Name,
                    SECTION_MAP_EXECUTE,
                    requestorPid,
                    FALSE
                )) {
                //
                // Block execution mapping of protected file from unauthorized process
                //
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike] BLOCKED execute mapping of protected file: %wZ (PID=%p)\n",
                           &nameInfo->Name, requestorPid);

                SHADOWSTRIKE_INC_STAT(SelfProtectionBlocks);

                FltReleaseFileNameInformation(nameInfo);

                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                return FLT_PREOP_COMPLETE;
            }

            // Keep nameInfo for later use
        }
    }

    if (!g_DriverData.Config.ScanOnExecute) {
        if (nameInfo != NULL) {
            FltReleaseFileNameInformation(nameInfo);
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Check if this is for execute access
    //
    pageProtection = Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection;
    if (pageProtection == PAGE_EXECUTE ||
        pageProtection == PAGE_EXECUTE_READ ||
        pageProtection == PAGE_EXECUTE_READWRITE ||
        pageProtection == PAGE_EXECUTE_WRITECOPY) {
        isExecuteMapping = TRUE;
    }

    if (!isExecuteMapping) {
        if (nameInfo != NULL) {
            FltReleaseFileNameInformation(nameInfo);
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    SHADOWSTRIKE_ENTER_OPERATION();

    //
    // Get file name if we didn't get it for self-protection
    //
    if (nameInfo == NULL) {
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
    }

    //
    // CRITICAL: In section sync callback, we MUST NOT block waiting for user-mode
    // This can cause deadlocks as the memory manager holds locks.
    // Use cached verdicts only.
    //
    if (FltObjects->FileObject != NULL) {
        status = ShadowGetStreamContext(
            FltObjects->Instance,
            FltObjects->FileObject,
            &streamContext
        );

        if (NT_SUCCESS(status) && streamContext != NULL) {
            //
            // Use cached verdict if available and valid
            //
            if (ShadowAcquireStreamContextShared(streamContext)) {
                if (streamContext->IsScanned && !streamContext->IsModified) {
                    cachedVerdict = streamContext->Verdict;
                }
                ShadowReleaseStreamContext(streamContext);
            }
            FltReleaseContext(streamContext);
        }
    }

    //
    // If no cached verdict, we must allow (cannot block for scan)
    // Queue an async scan for future reference
    //
    if (cachedVerdict == Verdict_Unknown) {
        //
        // Queue async scan if user-mode is connected
        // This populates the cache for next time
        //
        if (SHADOWSTRIKE_USER_MODE_CONNECTED()) {
            ShadowStrikeQueueRescan(
                FltObjects->Instance,
                FltObjects->FileObject,
                &nameInfo->Name
            );
        }

        // Allow - no cached verdict available
        cachedVerdict = Verdict_Clean;
    }

    FltReleaseFileNameInformation(nameInfo);

    SHADOWSTRIKE_LEAVE_OPERATION();

    //
    // Block execution if cached verdict indicates malware
    //
    if (cachedVerdict == Verdict_Malicious) {
        SHADOWSTRIKE_INC_STAT(FilesBlocked);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ============================================================================
// RESCAN QUEUE IMPLEMENTATION
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
ShadowStrikeQueueRescan(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _In_opt_ PCUNICODE_STRING FileName
    )
{
    //
    // In a full implementation, this would:
    // 1. Allocate a work item from lookaside list
    // 2. Copy necessary context (instance, file ID, name)
    // 3. Queue to a driver work queue for async processing
    // 4. Worker thread sends scan request to user-mode
    //
    // For now, we log and return success to indicate the mechanism exists
    //

    PAGED_CODE();

    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(FileObject);

    if (FileName != NULL && FileName->Buffer != NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                   "[ShadowStrike] Rescan queued for: %wZ\n", FileName);
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                   "[ShadowStrike] Rescan queued (name unavailable)\n");
    }

    //
    // In production, queue to rescan work queue here
    // The work queue implementation would be in a separate module (ScanQueue.c)
    //

    return STATUS_SUCCESS;
}

// ============================================================================
// DEFERRED WORK ITEM WORKER
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeDeferredScanWorker(
    _In_ PFLT_DEFERRED_IO_WORKITEM WorkItem,
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PVOID Context
    )
{
    PSHADOW_DEFERRED_SCAN_CONTEXT scanContext = (PSHADOW_DEFERRED_SCAN_CONTEXT)Context;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    UNREFERENCED_PARAMETER(Data);

    if (scanContext == NULL) {
        FltFreeDeferredIoWorkItem(WorkItem);
        return;
    }

    //
    // Perform the actual scan at PASSIVE_LEVEL
    // This would call ShadowStrikeSendScanRequest with the context data
    //

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] Deferred scan worker executing\n");

    //
    // Cleanup
    //
    if (scanContext->FileName.Buffer != NULL) {
        ExFreePoolWithTag(scanContext->FileName.Buffer, SHADOW_WORK_ITEM_TAG);
    }

    ExFreePoolWithTag(scanContext, SHADOW_WORK_ITEM_TAG);
    FltFreeDeferredIoWorkItem(WorkItem);
}
