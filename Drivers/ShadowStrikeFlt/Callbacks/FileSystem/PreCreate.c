/**
 * ============================================================================
 * ShadowStrike NGAV - PRE-CREATE CALLBACK
 * ============================================================================
 *
 * @file PreCreate.c
 * @brief Implementation of IRP_MJ_CREATE interception.
 *
 * This is the HEART of the on-access scanner.
 * Flow:
 * 1. Validate request (ignore kernel, paging, DASD)
 * 2. Get file name and information
 * 3. Check exclusions (Path, Process, Extension)
 * 4. Check scan cache (Has this file been scanned recently?)
 * 5. If verdict needed:
 *    a. Send synchronous message to user-mode
 *    b. Wait for reply (ALLOW/BLOCK)
 *    c. Enforce verdict
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "FileSystemCallbacks.h"
#include "../../Core/Globals.h"
#include "../../Communication/CommPort.h"
#include "../../Communication/ScanBridge.h"
#include "../../SelfProtection/SelfProtect.h"
#include "../../Cache/ScanCache.h"
#include "../../Exclusions/ExclusionManager.h"

// ============================================================================
// IMPLEMENTATION
// ============================================================================

FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    BOOLEAN isDir = FALSE;
    HANDLE requestorPid = NULL;
    SHADOWSTRIKE_CACHE_KEY cacheKey;
    SHADOWSTRIKE_CACHE_RESULT cacheResult;
    PSHADOWSTRIKE_MESSAGE_HEADER requestMsg = NULL;
    ULONG requestSize = 0;
    SHADOWSTRIKE_SCAN_VERDICT_REPLY replyMsg = {0};
    ULONG replySize = sizeof(SHADOWSTRIKE_SCAN_VERDICT_REPLY);
    SHADOWSTRIKE_ACCESS_TYPE accessType;

    UNREFERENCED_PARAMETER(CompletionContext);

    //
    // 1. FAST FAIL CHECKS
    //

    // Skip if driver is not ready or disabled
    if (!SHADOWSTRIKE_IS_READY() || !g_DriverData.Config.RealTimeScanEnabled) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Skip paging files
    if (Data->Iopb->OperationFlags & SL_OPEN_PAGING_FILE) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Skip kernel mode requests (trust the OS)
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Skip volume opens (no file name usually, or DASD)
    if (FltObjects->FileObject->FileName.Length == 0 && FltObjects->FileObject->RelatedFileObject == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    SHADOWSTRIKE_ENTER_OPERATION();

    //
    // 2. GET IDENTITY
    //

    requestorPid = PsGetCurrentProcessId();

    // Check if process is protected (Don't scan our own operations to prevent loops/deadlocks)
    // Also skip System process
    if (requestorPid == (HANDLE)4 || ShadowStrikeIsProcessProtected(requestorPid)) {
        goto Cleanup;
    }

    //
    // 3. GET FILE NAME
    //

    status = FltGetFileNameInformation(Data,
                                     FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                     &nameInfo);
    if (!NT_SUCCESS(status)) {
        // Can't get name, can't scan. Fail open safely.
        goto Cleanup;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // 4. CHECK DIRECTORY
    //

    // Check if it's a directory open
    // Note: CreateOptions contains FILE_DIRECTORY_FILE
    if (Data->Iopb->Parameters.Create.Options & FILE_DIRECTORY_FILE) {
        isDir = TRUE;
    }

    //
    // 5. EXCLUSION CHECKS
    //
    // Check if file/process is excluded from scanning.
    // This is done BEFORE self-protection to allow performance optimization,
    // but AFTER directory check since we don't scan directories anyway.
    //
    if (!isDir && ShadowStrikeExclusionIsEnabled()) {
        //
        // Check path exclusion (includes extension check internally)
        //
        if (ShadowStrikeIsPathExcluded(&nameInfo->Name, &nameInfo->Extension)) {
            // Path or extension is excluded - skip scanning
            SHADOWSTRIKE_INC_STAT(ExclusionMatches);
            goto Cleanup;
        }

        //
        // Check process exclusion
        // If the requesting process is excluded, skip scanning for this file access.
        //
        if (ShadowStrikeIsProcessExcluded(requestorPid, NULL)) {
            // Requesting process is excluded - skip scanning
            SHADOWSTRIKE_INC_STAT(ExclusionMatches);
            goto Cleanup;
        }
    }

    //
    // 6. SELF PROTECTION CHECK
    //
    // Block access to our protected files if necessary
    //
    if (ShadowStrikeShouldBlockFileAccess(&nameInfo->Name,
                                        Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess,
                                        requestorPid,
                                        FALSE)) { // Not explicitly a delete, though could be DELETE_ON_CLOSE

        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;

        SHADOWSTRIKE_INC_STAT(FilesBlocked);

        FltReleaseFileNameInformation(nameInfo);
        SHADOWSTRIKE_LEAVE_OPERATION();
        return FLT_PREOP_COMPLETE;
    }

    // If it's a directory, we generally don't scan it for malware, but we checked self-protect above.
    if (isDir) {
        goto Cleanup;
    }

    //
    // 6. SCAN REQUEST
    //

    // Only scan if we have a user mode service to talk to
    if (SHADOWSTRIKE_USER_MODE_CONNECTED()) {

        //
        // Build Cache Key
        //
        if (NT_SUCCESS(ShadowStrikeCacheBuildKey(FltObjects, &cacheKey))) {
            //
            // Check Cache
            //
            if (ShadowStrikeCacheLookup(&cacheKey, &cacheResult)) {
                if (cacheResult.Verdict == ShadowStrikeVerdictBlock) {
                    // Cache Hit: BLOCK
                    Data->IoStatus.Status = STATUS_ACCESS_DENIED; // Or STATUS_VIRUS_INFECTED
                    Data->IoStatus.Information = 0;
                    SHADOWSTRIKE_INC_STAT(FilesBlocked);
                    SHADOWSTRIKE_INC_STAT(CacheHits);

                    FltReleaseFileNameInformation(nameInfo);
                    SHADOWSTRIKE_LEAVE_OPERATION();
                    return FLT_PREOP_COMPLETE;
                } else {
                    // Cache Hit: ALLOW
                    SHADOWSTRIKE_INC_STAT(CacheHits);
                    goto Cleanup;
                }
            }
        }

        //
        // Cache Miss: Send to User Mode
        //

        // Determine access type (simplified)
        accessType = ShadowStrikeAccessRead;
        if (Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA)) {
            accessType = ShadowStrikeAccessWrite;
        } else if (Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & (FILE_EXECUTE | GENERIC_EXECUTE)) {
            accessType = ShadowStrikeAccessExecute;
        }

        status = ShadowStrikeBuildFileScanRequest(
            Data,
            FltObjects,
            accessType,
            &requestMsg,
            &requestSize
        );

        if (NT_SUCCESS(status)) {
            //
            // Send Synchronous Request (Wait 30s)
            //
            status = ShadowStrikeSendScanRequest(
                requestMsg,
                requestSize,
                &replyMsg,
                &replySize,
                30000 // 30 seconds timeout
            );

            if (NT_SUCCESS(status)) {
                //
                // Handle Verdict
                //
                if (replyMsg.Verdict == ShadowStrikeVerdictBlock) {
                    // BLOCK
                    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                    Data->IoStatus.Information = 0;
                    SHADOWSTRIKE_INC_STAT(FilesBlocked);

                    // Update Cache
                    ShadowStrikeCacheInsert(&cacheKey, ShadowStrikeVerdictBlock, replyMsg.ThreatScore, replyMsg.CacheTTL);

                    ShadowStrikeFreeMessageBuffer(requestMsg);
                    FltReleaseFileNameInformation(nameInfo);
                    SHADOWSTRIKE_LEAVE_OPERATION();
                    return FLT_PREOP_COMPLETE;
                } else {
                    // ALLOW
                    // Update Cache
                    ShadowStrikeCacheInsert(&cacheKey, ShadowStrikeVerdictSafe, 0, replyMsg.CacheTTL);
                }
            } else {
                // Timeout or Error: Fail Open (Log it)
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                           "[ShadowStrike] Scan timeout/error: 0x%08X. Failing open.\n", status);
            }

            ShadowStrikeFreeMessageBuffer(requestMsg);
        }
    }

Cleanup:
    if (nameInfo) {
        FltReleaseFileNameInformation(nameInfo);
    }

    SHADOWSTRIKE_LEAVE_OPERATION();
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
