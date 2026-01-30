/**
 * ============================================================================
 * ShadowStrike NGAV - POST-WRITE CALLBACK
 * ============================================================================
 *
 * @file PostWrite.c
 * @brief Handles post-write logic for cache invalidation.
 *
 * After a successful write operation, this callback:
 * 1. Marks the stream context as dirty (file modified)
 * 2. Invalidates the scan cache entry for this file
 * 3. Clears the "scanned" flag to force re-scan on next access
 *
 * This ensures modified files are re-scanned before execution.
 *
 * BSOD PREVENTION:
 * - Check FLT_POST_OPERATION_FLAGS for draining
 * - Handle missing stream context gracefully
 * - Never block in post-operation callbacks
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "FileSystemCallbacks.h"
#include "../../Core/Globals.h"
#include "../../Cache/ScanCache.h"
#include "../../Shared/SharedDefs.h"

/**
 * @brief Post-operation callback for IRP_MJ_WRITE.
 *
 * Called after the file system completes a write request.
 * If the write succeeded, we mark the file as dirty and invalidate
 * any cached scan verdict since the file contents have changed.
 *
 * @param Data              Callback data containing operation parameters.
 * @param FltObjects        Filter objects (volume, instance, file object).
 * @param CompletionContext Context passed from PreWrite (unused).
 * @param Flags             Post-operation flags.
 * @return FLT_POSTOP_FINISHED_PROCESSING always.
 */
FLT_POSTOP_CALLBACK_STATUS
ShadowStrikePostWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    NTSTATUS status;
    PSHADOWSTRIKE_STREAM_CONTEXT streamContext = NULL;
    SHADOWSTRIKE_CACHE_KEY cacheKey;

    UNREFERENCED_PARAMETER(CompletionContext);

    //
    // Check if we're draining - don't do any work during unload
    //
    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // Check if driver is ready
    //
    if (!SHADOWSTRIKE_IS_READY()) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // Only process if the write succeeded
    //
    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // Only process if bytes were actually written
    //
    if (Data->IoStatus.Information == 0) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // Skip if no file object
    //
    if (FltObjects->FileObject == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // Try to get the stream context for this file
    //
    status = FltGetStreamContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        (PFLT_CONTEXT*)&streamContext
    );

    if (NT_SUCCESS(status) && streamContext != NULL) {
        //
        // Mark stream context as dirty - file has been modified
        //
        streamContext->Dirty = TRUE;
        streamContext->Scanned = FALSE;  // Force re-scan

        //
        // Build cache key from stream context data
        //
        RtlZeroMemory(&cacheKey, sizeof(cacheKey));
        cacheKey.VolumeSerial = streamContext->VolumeSerial;
        cacheKey.FileId = streamContext->FileId;
        cacheKey.FileSize = streamContext->ScanFileSize;
        // LastWriteTime will have changed, but we use cached values

        //
        // Invalidate cache entry for this file
        // The file contents have changed, so any cached verdict is stale
        //
        ShadowStrikeCacheRemove(&cacheKey);

        //
        // Update statistics
        //
        SHADOWSTRIKE_INC_STAT(CacheMisses);  // Next access will be a miss

        FltReleaseContext((PFLT_CONTEXT)streamContext);
    } else {
        //
        // No stream context - try to invalidate by building key from file object
        // This is a fallback path when context wasn't attached in PostCreate
        //
        status = ShadowStrikeCacheBuildKey(FltObjects, &cacheKey);
        if (NT_SUCCESS(status)) {
            ShadowStrikeCacheRemove(&cacheKey);
        }
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}
