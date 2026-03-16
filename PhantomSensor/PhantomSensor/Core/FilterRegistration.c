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

#include "../Callbacks/FileSystem/PostCreate.h"
#include "FilterRegistration.h"
#include "Globals.h"
#include "DriverEntry.h"
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
#include "../Context/InstanceContext.h"
#include "../Transactions/KtmMonitor.h"

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

    // System/driver files (can install rootkits)
    { L"inf",  6,  FALSE, FALSE },
    { L"reg",  6,  FALSE, FALSE },

    // Scriptlets and advanced scripting
    { L"sct",  6,  FALSE, TRUE  },
    { L"wsc",  6,  FALSE, TRUE  },
    { L"py",   4,  FALSE, TRUE  },

    // Office add-ins (code execution vectors)
    { L"xll",  6,  TRUE,  FALSE },
    { L"wll",  6,  TRUE,  FALSE },

    // Compiled help / ClickOnce (execution vectors)
    { L"chm",  6,  FALSE, FALSE },
    { L"application", 22, TRUE, FALSE },

    // Sentinel - must be last
    { NULL, 0, FALSE, FALSE }
};

// ============================================================================
// CONTEXT DEFINITIONS
// ============================================================================

/**
 * @brief Context registration array.
 *
 * Uses FLT_VARIABLE_SIZED_CONTEXTS because the canonical stream context
 * (SHADOWSTRIKE_STREAM_CONTEXT in PostCreate.h) is ~780 bytes and evolves
 * independently. FltAllocateContext in PostCreate.c specifies the exact
 * size at allocation time.
 *
 * Cleanup callback: ShadowStrikeStreamContextCleanup in FileSystemCallbacks.c
 */

//
// Pool tag for stream contexts
//
#define SHADOWSTRIKE_STREAM_CTX_TAG  'xCSS'

static FLT_CONTEXT_REGISTRATION g_ContextRegistration[] = {

    {
        FLT_STREAM_CONTEXT,                         // ContextType
        0,                                          // Flags
        ShadowStrikeStreamContextCleanup,           // ContextCleanupCallback
        FLT_VARIABLE_SIZED_CONTEXTS,                // Size — PostCreate specifies exact size
        SHADOWSTRIKE_STREAM_CTX_TAG,                // PoolTag
        NULL,                                       // ContextAllocateCallback
        NULL,                                       // ContextFreeCallback
        NULL                                        // Reserved
    },

    {
        FLT_VOLUME_CONTEXT,                         // ContextType
        0,                                          // Flags
        ShadowStrikeVolumeContextCleanup,           // ContextCleanupCallback
        FLT_VARIABLE_SIZED_CONTEXTS,                // Size — FSC specifies exact size
        'xCVS',                                     // PoolTag — SVCx (Volume Context)
        NULL,                                       // ContextAllocateCallback
        NULL,                                       // ContextFreeCallback
        NULL                                        // Reserved
    },

    //
    // Stream Handle Context — per-open-handle tracking (PostCreate.c)
    // Used for per-handle write/delete/rename tracking
    //
    {
        FLT_STREAMHANDLE_CONTEXT,                   // ContextType
        0,                                          // Flags
        NULL,                                       // ContextCleanupCallback (no special cleanup needed)
        FLT_VARIABLE_SIZED_CONTEXTS,                // Size — PostCreate specifies exact size
        'hHCP',                                     // PoolTag — PCHh (Handle Context)
        NULL,                                       // ContextAllocateCallback
        NULL,                                       // ContextFreeCallback
        NULL                                        // Reserved
    },

    //
    // Instance Context — per-instance scan stats, policy, and volume capabilities
    // SHADOW_INSTANCE_CONTEXT: signature validation, ERESOURCE sync,
    // detailed verdict counters, avg scan time, activity timestamps
    //
    {
        FLT_INSTANCE_CONTEXT,                       // ContextType
        0,                                          // Flags
        ShadowCleanupInstanceContext,               // ContextCleanupCallback
        sizeof(SHADOW_INSTANCE_CONTEXT),            // Size — fixed size allocation
        SHADOW_INSTANCE_TAG,                        // PoolTag — 'iSSx'
        NULL,                                       // ContextAllocateCallback
        NULL,                                       // ContextFreeCallback
        NULL                                        // Reserved
    },

    //
    // Transaction Context — per-transaction tracking for KTM commit/rollback
    // SHADOW_KTM_TRANSACTION_CONTEXT: stores transaction GUID + originating PID
    // Set by ShadowKtmEnlistInTransaction, used by ShadowKtmNotificationCallback
    //
    {
        FLT_TRANSACTION_CONTEXT,                    // ContextType
        0,                                          // Flags
        NULL,                                       // ContextCleanupCallback (no dynamic allocs)
        sizeof(SHADOW_KTM_TRANSACTION_CONTEXT),     // Size — fixed size
        SHADOW_KTM_TXN_CTX_TAG,                     // PoolTag — 'kSTc'
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
    // Critical for catching code execution, DLL injection, process hollowing,
    // reflective loading detection via behavioral analysis in PreAcquireSection.c
    //
    {
        IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
        0,
        ShadowStrikePreAcquireSection,
        NULL,
        NULL
    },

    //
    // IRP_MJ_CREATE_NAMED_PIPE - Named pipe creation
    // Critical for C2 channel and lateral movement detection
    // Uses wrapper functions that enforce ShadowStrikeIsDriverReady() guard
    //
    {
        IRP_MJ_CREATE_NAMED_PIPE,
        0,
        ShadowStrikePreCreateNamedPipe,
        ShadowStrikePostCreateNamedPipe,
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
    ShadowKtmNotificationCallback,                  // TransactionNotification
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
    ULONG extLenBytes;
    ULONG tblLenBytes;
    const WCHAR* extBuf;
    const WCHAR* tblBuf;
    ULONG charCount;
    ULONG c;
    BOOLEAN match;

    if (IsExecutable != NULL) {
        *IsExecutable = FALSE;
    }

    if (Extension == NULL || Extension->Length == 0 || Extension->Buffer == NULL) {
        return FALSE;
    }

    extLenBytes = Extension->Length;
    extBuf = Extension->Buffer;

    //
    // DISPATCH-safe comparison: RtlCompareUnicodeString requires <= APC_LEVEL
    // due to pageable NLS tables. Our extension table is pure ASCII, so we use
    // inline case-insensitive comparison that is safe at any IRQL.
    //
    for (i = 0; g_ScannableExtensions[i].Extension != NULL; i++) {

        //
        // Compute table entry length manually (avoid RtlInitUnicodeString
        // which is PASSIVE_LEVEL in some WDK annotations).
        //
        tblBuf = g_ScannableExtensions[i].Extension;
        tblLenBytes = 0;
        while (tblBuf[tblLenBytes / sizeof(WCHAR)] != L'\0') {
            tblLenBytes += sizeof(WCHAR);
        }

        if (extLenBytes != tblLenBytes) {
            continue;
        }

        //
        // Case-insensitive ASCII comparison. All table entries are pure ASCII
        // so upcasing A-Z range is sufficient. Non-ASCII input extensions
        // will never match table entries and correctly return FALSE.
        //
        charCount = extLenBytes / sizeof(WCHAR);
        match = TRUE;
        for (c = 0; c < charCount; c++) {
            WCHAR a = extBuf[c];
            WCHAR b = tblBuf[c];
            if (a >= L'a' && a <= L'z') a -= (L'a' - L'A');
            if (b >= L'a' && b <= L'z') b -= (L'a' - L'A');
            if (a != b) {
                match = FALSE;
                break;
            }
        }

        if (match) {
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
    PSHADOWSTRIKE_STREAM_CONTEXT streamContext = NULL;
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
        status = FltGetStreamContext(
            FltObjects->Instance,
            FltObjects->FileObject,
            (PFLT_CONTEXT*)&streamContext
        );

        if (NT_SUCCESS(status) && streamContext != NULL) {
            //
            // Check if rescan is needed:
            // 1. File was modified (Dirty) since last scan, OR
            // 2. File was never scanned, OR
            // 3. Verdict TTL expired
            //
            if (streamContext->Dirty || !streamContext->Scanned) {
                needsRescan = TRUE;
            } else if (streamContext->ScanVerdictTTL > 0) {
                LARGE_INTEGER now;
                KeQuerySystemTimePrecise(&now);
                LONGLONG elapsedSec = (now.QuadPart - streamContext->ScanTime.QuadPart) / 10000000LL;
                if (elapsedSec > (LONGLONG)streamContext->ScanVerdictTTL) {
                    needsRescan = TRUE;
                }
            }

            if (needsRescan) {
                //
                // Queue asynchronous rescan
                // We cannot block here as cleanup must complete
                //
                UNICODE_STRING cachedName;
                cachedName.Buffer = streamContext->CachedFileName;
                cachedName.Length = streamContext->CachedFileNameLength * sizeof(WCHAR);
                cachedName.MaximumLength = cachedName.Length;

                status = ShadowStrikeQueueRescan(
                    FltObjects->Instance,
                    FltObjects->FileObject,
                    (streamContext->CachedFileNameLength > 0) ? &cachedName : NULL
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
    PSHADOWSTRIKE_STREAM_CONTEXT streamContext = NULL;
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
        status = FltGetStreamContext(
            FltObjects->Instance,
            FltObjects->FileObject,
            (PFLT_CONTEXT*)&streamContext
        );

        if (NT_SUCCESS(status) && streamContext != NULL) {
            //
            // Use cached verdict if available and valid
            // Use push lock for read access
            //
            KeEnterCriticalRegion();
            ExAcquirePushLockShared(&streamContext->Lock);

            if (streamContext->Scanned && !streamContext->Dirty) {
                //
                // Map PostCreate's boolean ScanResult to verdict enum
                //
                if (streamContext->ScanResult) {
                    cachedVerdict = Verdict_Clean;
                } else {
                    cachedVerdict = Verdict_Malicious;
                }
            }

            ExReleasePushLockShared(&streamContext->Lock);
            KeLeaveCriticalRegion();

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
    PFILE_SCAN_REQUEST req = NULL;
    ULONG reqSize;
    USHORT copyLen;
    USHORT pathChars;
    NTSTATUS status;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(FileObject);

    //
    // Validate: must have a connected user-mode agent to receive the request
    //
    if (!SHADOWSTRIKE_USER_MODE_CONNECTED()) {
        return STATUS_PORT_DISCONNECTED;
    }

    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Cap path length to MAX_PATH (260 WCHARs = 520 bytes) to prevent
    // excessive allocation from untrusted file names.
    //
    copyLen = (FileName->Length > 520) ? 520 : FileName->Length;
    pathChars = copyLen / sizeof(WCHAR);

    //
    // Build a FILE_SCAN_REQUEST with the variable-length file path appended.
    // This is the standard scan request protocol — user-mode opens and scans
    // the file independently based on the path we provide.
    //
    reqSize = sizeof(FILE_SCAN_REQUEST) + copyLen;
    req = (PFILE_SCAN_REQUEST)ExAllocatePool2(
        POOL_FLAG_PAGED, reqSize, 'rsQS');
    if (req == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(req, sizeof(FILE_SCAN_REQUEST));
    req->MessageId = SHADOWSTRIKE_NEXT_MESSAGE_ID();
    req->AccessType = (UINT8)ShadowStrikeAccessRead;
    req->Priority = 1;
    req->RequiresReply = 0;
    req->ProcessId = HandleToULong(PsGetCurrentProcessId());
    req->PathLength = pathChars;

    RtlCopyMemory(
        (PUCHAR)req + sizeof(FILE_SCAN_REQUEST),
        FileName->Buffer,
        copyLen);

    //
    // Send via batch processor (fire-and-forget).
    // ShadowStrikeBatchSendNotification routes through BpQueueEvent
    // which is safe and non-blocking. User-mode agent dequeues and
    // performs the actual file scan asynchronously.
    //
    status = ShadowStrikeBatchSendNotification(
        (UINT16)FilterMessageType_ScanRequest,
        req,
        reqSize);

    ExFreePoolWithTag(req, 'rsQS');

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Rescan notification failed: 0x%08X for: %wZ\n",
                   status, FileName);
    }

    return status;
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
    NTSTATUS status;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    UNREFERENCED_PARAMETER(Data);

    if (scanContext == NULL) {
        FltFreeDeferredIoWorkItem(WorkItem);
        return;
    }

    //
    // At PASSIVE_LEVEL we can safely send a scan request to user-mode.
    // Build a lightweight rescan notification using the cached context.
    //
    if (scanContext->FileName.Buffer != NULL &&
        scanContext->FileName.Length > 0 &&
        SHADOWSTRIKE_USER_MODE_CONNECTED()) {

        USHORT copyLen = (scanContext->FileName.Length > 520) ?
                         520 : scanContext->FileName.Length;
        USHORT pathChars = copyLen / sizeof(WCHAR);
        ULONG reqSize = sizeof(FILE_SCAN_REQUEST) + copyLen;

        PFILE_SCAN_REQUEST req = (PFILE_SCAN_REQUEST)ExAllocatePool2(
            POOL_FLAG_PAGED, reqSize, 'dsQS');

        if (req != NULL) {
            RtlZeroMemory(req, sizeof(FILE_SCAN_REQUEST));
            req->MessageId = SHADOWSTRIKE_NEXT_MESSAGE_ID();
            req->AccessType = (UINT8)scanContext->AccessType;
            req->Priority = scanContext->IsExecute ? 0 : 1;
            req->RequiresReply = 0;
            req->ProcessId = HandleToULong(scanContext->ProcessId);
            req->FileSize = (UINT64)scanContext->FileSize.QuadPart;
            req->PathLength = pathChars;

            RtlCopyMemory(
                (PUCHAR)req + sizeof(FILE_SCAN_REQUEST),
                scanContext->FileName.Buffer,
                copyLen);

            status = ShadowStrikeBatchSendNotification(
                (UINT16)FilterMessageType_ScanRequest,
                req,
                reqSize);

            if (!NT_SUCCESS(status)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike] Deferred scan send failed: 0x%08X\n", status);
            }

            ExFreePoolWithTag(req, 'dsQS');
        }
    }

    //
    // Cleanup context resources
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
