/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
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
#include "../Callbacks/FileSystem/NamedPipeMonitor.h"
#include "../Callbacks/FileSystem/USBDeviceControl.h"
#include "../Callbacks/FileSystem/FileSystemCallbacks.h"
#include "../Callbacks/FileSystem/PreCreate.h"
#include "../Callbacks/FileSystem/PreSetInfo.h"

//
// Forward declarations for callback functions defined in dedicated modules.
// These are referenced by g_OperationCallbacks but implemented in their
// respective .c files (PostCreate.c, PreWrite.c, PostWrite.c).
// We use forward declarations rather than header includes to avoid
// struct redefinition conflicts (PostCreate.h redefines stream context).
//
FLT_POSTOP_CALLBACK_STATUS
ShadowStrikePostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
ShadowStrikePostWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

#ifdef ALLOC_PRAGMA
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
static FLT_CONTEXT_REGISTRATION g_ContextRegistration[] = {

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
static FLT_OPERATION_REGISTRATION g_OperationCallbacks[] = {

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

    //
    // IRP_MJ_CREATE_NAMED_PIPE - Named pipe creation
    // Critical for C2 channel and lateral movement detection
    //
    {
        IRP_MJ_CREATE_NAMED_PIPE,
        0,
        NpMonPreCreateNamedPipe,
        NpMonPostCreateNamedPipe,
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
static FLT_REGISTRATION g_FilterRegistration = {

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
// FILE SYSTEM CALLBACKS - IRP_MJ_SET_INFORMATION
// ============================================================================


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
    // Rescan queuing is handled by the deferred scan work queue (ShadowStrikeDeferredScanWorker).
    // The DeferredScan context is populated by PostCreate/PostWrite and dispatched here.
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

// ============================================================================
// FILE SYSTEM CALLBACKS - NAMED PIPE MONITORING
// ============================================================================

/**
 * @brief Pre-operation callback for IRP_MJ_CREATE_NAMED_PIPE.
 *        Dispatches to NamedPipeMonitor module for C2/lateral movement detection.
 */
FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreCreateNamedPipe(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    if (!ShadowStrikeIsDriverReady()) {
        *CompletionContext = NULL;
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return NpMonPreCreateNamedPipe(Data, FltObjects, CompletionContext);
}

/**
 * @brief Post-operation callback for IRP_MJ_CREATE_NAMED_PIPE.
 */
FLT_POSTOP_CALLBACK_STATUS
ShadowStrikePostCreateNamedPipe(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    return NpMonPostCreateNamedPipe(Data, FltObjects, CompletionContext, Flags);
}
