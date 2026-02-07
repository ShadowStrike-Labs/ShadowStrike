/**
 * ============================================================================
 * ShadowStrike NGAV - POST-CREATE CALLBACK
 * ============================================================================
 *
 * @file PostCreate.c
 * @brief Handles post-creation logic including stream context attachment.
 *
 * After a file is successfully opened, this callback:
 * 1. Attaches a stream context to track file state
 * 2. Records file attributes for cache correlation
 * 3. Marks file as scanned if PreCreate completed a scan
 *
 * BSOD PREVENTION:
 * - Check FLT_POST_OPERATION_FLAGS for draining
 * - Validate all pointers before use
 * - Handle context allocation failures gracefully
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

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ShadowStrikePostCreate)
#endif

/**
 * @brief Post-operation callback for IRP_MJ_CREATE.
 *
 * Called after the file system completes a create/open request.
 * If the operation succeeded, we attach a stream context to track
 * the file for subsequent operations (writes, etc.).
 *
 * @param Data              Callback data containing operation parameters.
 * @param FltObjects        Filter objects (volume, instance, file object).
 * @param CompletionContext Context passed from PreCreate (scan verdict info).
 * @param Flags             Post-operation flags.
 * @return FLT_POSTOP_FINISHED_PROCESSING always.
 */
FLT_POSTOP_CALLBACK_STATUS
ShadowStrikePostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    NTSTATUS status;
    PSHADOWSTRIKE_STREAM_CONTEXT streamContext = NULL;
    PSHADOWSTRIKE_STREAM_CONTEXT existingContext = NULL;
    FILE_STANDARD_INFORMATION stdInfo;
    FILE_INTERNAL_INFORMATION internalInfo;
    BOOLEAN contextCreated = FALSE;

    PAGED_CODE();

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
    // Only process if the create succeeded
    //
    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // Skip if no file object (shouldn't happen for successful creates)
    //
    if (FltObjects->FileObject == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // Skip directories - we only track files
    //
    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // Skip volume opens
    //
    if (FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // Try to get existing stream context first
    //
    status = FltGetStreamContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        (PFLT_CONTEXT*)&existingContext
    );

    if (NT_SUCCESS(status)) {
        //
        // Context already exists - update it if needed
        // CompletionContext from PreCreate contains scan info
        //
        if (CompletionContext != NULL) {
            //
            // CompletionContext is a pointer to scan verdict info
            // Mark file as scanned
            //
            existingContext->Scanned = TRUE;
            KeQuerySystemTime(&existingContext->ScanTime);
        }

        FltReleaseContext((PFLT_CONTEXT)existingContext);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // No existing context - allocate a new one
    //
    status = FltAllocateContext(
        g_DriverData.FilterHandle,
        FLT_STREAM_CONTEXT,
        sizeof(SHADOWSTRIKE_STREAM_CONTEXT),
        NonPagedPoolNx,
        (PFLT_CONTEXT*)&streamContext
    );

    if (!NT_SUCCESS(status)) {
        //
        // Allocation failed - not fatal, just means we won't track this file
        //
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // Initialize the stream context
    //
    RtlZeroMemory(streamContext, sizeof(SHADOWSTRIKE_STREAM_CONTEXT));

    //
    // Get file size
    //
    status = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &stdInfo,
        sizeof(stdInfo),
        FileStandardInformation,
        NULL
    );

    if (NT_SUCCESS(status)) {
        streamContext->ScanFileSize = stdInfo.EndOfFile.QuadPart;
    }

    //
    // Get file ID for cache correlation
    //
    status = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &internalInfo,
        sizeof(internalInfo),
        FileInternalInformation,
        NULL
    );

    if (NT_SUCCESS(status)) {
        streamContext->FileId = internalInfo.IndexNumber.QuadPart;
    }

    //
    // Get volume serial (approximate using volume pointer)
    //
    if (FltObjects->Volume != NULL) {
        streamContext->VolumeSerial = (ULONG)(ULONG_PTR)FltObjects->Volume;
    }

    //
    // Mark as scanned if PreCreate sent a scan request
    //
    if (CompletionContext != NULL) {
        streamContext->Scanned = TRUE;
        KeQuerySystemTime(&streamContext->ScanTime);
    } else {
        streamContext->Scanned = FALSE;
    }

    //
    // File is clean (not modified since open)
    //
    streamContext->Dirty = FALSE;

    //
    // Attach context to stream
    //
    status = FltSetStreamContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        FLT_SET_CONTEXT_KEEP_IF_EXISTS,
        (PFLT_CONTEXT)streamContext,
        (PFLT_CONTEXT*)&existingContext
    );

    if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
        //
        // Another thread beat us to it - use existing context
        //
        if (existingContext != NULL) {
            FltReleaseContext((PFLT_CONTEXT)existingContext);
        }
        contextCreated = FALSE;
    } else if (!NT_SUCCESS(status)) {
        //
        // Failed to set context - just continue
        //
        contextCreated = FALSE;
    } else {
        contextCreated = TRUE;
    }

    //
    // Release our reference (FltSetStreamContext adds its own if successful)
    //
    FltReleaseContext((PFLT_CONTEXT)streamContext);

    return FLT_POSTOP_FINISHED_PROCESSING;
}
