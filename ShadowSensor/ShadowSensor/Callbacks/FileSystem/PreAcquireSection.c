/**
 * ============================================================================
 * ShadowStrike NGAV - PRE-ACQUIRE-SECTION CALLBACK
 * ============================================================================
 *
 * @file PreAcquireSection.c
 * @brief Intercepts memory mapping to detect execution.
 *
 * IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION is often sent when a file is
 * about to be mapped as an image (executable). This is a critical interception
 * point for preventing malware execution.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "FileSystemCallbacks.h"
#include "../../Core/Globals.h"
#include "../../Cache/ScanCache.h"
#include "../../Communication/ScanBridge.h"

FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreAcquireSection(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(FltObjects);

    //
    // Check if this is an image mapping request
    //
    if (Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {

        SHADOWSTRIKE_CACHE_KEY cacheKey;
        SHADOWSTRIKE_CACHE_RESULT cacheResult;

        //
        // 1. Fast Fail Checks
        //
        if (!SHADOWSTRIKE_IS_READY() || !g_DriverData.Config.RealTimeScanEnabled) {
             return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        //
        // 2. Check Cache
        //
        if (NT_SUCCESS(ShadowStrikeCacheBuildKey(FltObjects, &cacheKey))) {
            if (ShadowStrikeCacheLookup(&cacheKey, &cacheResult)) {
                if (cacheResult.Verdict == ShadowStrikeVerdictBlock) {
                    //
                    // Known Malware: BLOCK EXECUTION
                    //
                    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                    Data->IoStatus.Information = 0;
                    SHADOWSTRIKE_INC_STAT(FilesBlocked);
                    SHADOWSTRIKE_INC_STAT(CacheHits);

                    return FLT_PREOP_COMPLETE;
                }
            }
        }

        //
        // Note: We do not trigger a new scan here to avoid potential deadlocks
        // during section acquisition. We rely on PreCreate to have populated
        // the cache. If it's a miss here, we allow it (fail-open) for stability.
        //
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
