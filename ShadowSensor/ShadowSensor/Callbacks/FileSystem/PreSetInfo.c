/**
 * ============================================================================
 * ShadowStrike NGAV - PRE-SET-INFO CALLBACK (SELF-PROTECTION)
 * ============================================================================
 *
 * @file PreSetInfo.c
 * @brief Intercepts FileSetInformation to block renames/deletes of protected files.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "FileSystemCallbacks.h"
#include "../../Core/Globals.h"
#include "../../SelfProtection/SelfProtect.h"

FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    HANDLE requestorPid;
    FILE_INFORMATION_CLASS infoClass;
    BOOLEAN isDelete = FALSE;
    BOOLEAN isRename = FALSE;

    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(FltObjects);

    //
    // Check if driver is ready
    //
    if (!SHADOWSTRIKE_IS_READY()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Fast checks
    if (!g_SelfProtectInitialized || !g_DriverData.Config.SelfProtectionEnabled) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    // We only care about Delete and Rename/Link operations
    switch (infoClass) {
        case FileDispositionInformation:
        case FileDispositionInformationEx:
            isDelete = TRUE;
            break;
        case FileRenameInformation:
        case FileRenameInformationEx:
        case FileLinkInformation:
        case FileLinkInformationEx:
            isRename = TRUE; // Treat rename effectively as a modification/delete of the original path
            break;
        default:
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    SHADOWSTRIKE_ENTER_OPERATION();

    requestorPid = PsGetCurrentProcessId();

    // Get file name
    status = FltGetFileNameInformation(Data,
                                     FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                     &nameInfo);
    if (!NT_SUCCESS(status)) {
        SHADOWSTRIKE_LEAVE_OPERATION();
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        SHADOWSTRIKE_LEAVE_OPERATION();
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Check Self-Protection
    if (ShadowStrikeShouldBlockFileAccess(&nameInfo->Name,
                                        0, // Access mask not relevant for this specific check, we use the op type
                                        requestorPid,
                                        isDelete || isRename)) {

        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;

        SHADOWSTRIKE_INC_STAT(FilesBlocked);

        FltReleaseFileNameInformation(nameInfo);
        SHADOWSTRIKE_LEAVE_OPERATION();
        return FLT_PREOP_COMPLETE;
    }

    FltReleaseFileNameInformation(nameInfo);
    SHADOWSTRIKE_LEAVE_OPERATION();
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
