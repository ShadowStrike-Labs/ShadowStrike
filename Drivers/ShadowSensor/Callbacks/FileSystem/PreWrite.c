/**
 * ============================================================================
 * ShadowStrike NGAV - PRE-WRITE CALLBACK
 * ============================================================================
 *
 * @file PreWrite.c
 * @brief Intercepts writes to invalidate cache entries.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "FileSystemCallbacks.h"
#include "../../Core/Globals.h"
#include "../../SelfProtection/SelfProtect.h"
#include "../../Cache/ScanCache.h"

FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    HANDLE requestorPid;

    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(FltObjects);

    //
    // Check if driver is ready
    //
    if (!SHADOWSTRIKE_IS_READY()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Check Self-Protection first
    //
    if (g_SelfProtectInitialized && g_DriverData.Config.SelfProtectionEnabled) {
        SHADOWSTRIKE_ENTER_OPERATION();

        requestorPid = PsGetCurrentProcessId();

        status = FltGetFileNameInformation(Data,
                                         FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                         &nameInfo);
        if (NT_SUCCESS(status)) {
            status = FltParseFileNameInformation(nameInfo);
            if (NT_SUCCESS(status)) {
                if (ShadowStrikeShouldBlockFileAccess(&nameInfo->Name,
                                                    FILE_WRITE_DATA,
                                                    requestorPid,
                                                    FALSE)) {

                    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                    Data->IoStatus.Information = 0;
                    SHADOWSTRIKE_INC_STAT(FilesBlocked);

                    FltReleaseFileNameInformation(nameInfo);
                    SHADOWSTRIKE_LEAVE_OPERATION();
                    return FLT_PREOP_COMPLETE;
                }
            }
            FltReleaseFileNameInformation(nameInfo);
        }
        SHADOWSTRIKE_LEAVE_OPERATION();
    }

    //
    // Invalidate scan cache for this file
    //
    // If a file is written to, its hash changes, so any previous "SAFE" verdict is invalid.
    //
    {
        SHADOWSTRIKE_CACHE_KEY cacheKey;
        // We can only build key if we have file object
        if (FltObjects->FileObject) {
            if (NT_SUCCESS(ShadowStrikeCacheBuildKey(FltObjects, &cacheKey))) {
                if (ShadowStrikeCacheRemove(&cacheKey)) {
                    // Cache invalidated successfully
                }
            }
        }
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
