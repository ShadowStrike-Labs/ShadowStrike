/**
 * ============================================================================
 * ShadowStrike NGAV - STREAM CONTEXT IMPLEMENTATION
 * ============================================================================
 *
 * @file StreamContext.c
 * @brief Implementation of stream context management.
 *
 * Handles creation, retrieval, and cleanup of stream contexts with proper
 * race condition handling, thread safety, and resource management.
 *
 * Key Features:
 * - Race-safe context creation using "Keep if Exists" pattern
 * - Thread-safe access via ERESOURCE locks
 * - Proper cleanup to prevent BSOD (ExDeleteResourceLite)
 * - Memory leak prevention (FileName.Buffer cleanup)
 * - FileID caching for efficient lookups
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "StreamContext.h"
#include "../Core/Globals.h"

// ============================================================================
// PRIVATE HELPER PROTOTYPES
// ============================================================================

NTSTATUS
ShadowAllocateStreamContext(
    _Outptr_ PSHADOW_STREAM_CONTEXT* Context
    );

// ============================================================================
// PUBLIC FUNCTIONS
// ============================================================================

/**
 * @brief Get or create stream context (race-safe implementation).
 */
NTSTATUS
ShadowGetOrSetStreamContext(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Outptr_ PSHADOW_STREAM_CONTEXT* Context
    )
{
    NTSTATUS status;
    PSHADOW_STREAM_CONTEXT newContext = NULL;
    PSHADOW_STREAM_CONTEXT oldContext = NULL;

    *Context = NULL;

    //
    // STEP 1: Try to get existing context
    //
    status = FltGetStreamContext(
        Instance,
        FileObject,
        (PFLT_CONTEXT*)&oldContext
    );

    if (NT_SUCCESS(status)) {
        // Found existing context - return it
        *Context = oldContext;
        return STATUS_SUCCESS;
    }

    if (status != STATUS_NOT_FOUND) {
        // Unexpected error
        return status;
    }

    //
    // STEP 2: No context exists - allocate new one
    //
    status = ShadowAllocateStreamContext(&newContext);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // STEP 3: Try to set the context (race condition handling)
    //
    status = FltSetStreamContext(
        Instance,
        FileObject,
        FLT_SET_CONTEXT_KEEP_IF_EXISTS,
        newContext,
        (PFLT_CONTEXT*)&oldContext
    );

    if (NT_SUCCESS(status)) {
        //
        // We won the race - our context was set successfully
        // CRITICAL: Add reference before initialization to prevent use-after-free
        // if another thread releases the context during initialization
        //
        FltReferenceContext(newContext);
        ShadowInitializeStreamContextFileInfo(newContext, Instance, FileObject);
        *Context = newContext;
        return STATUS_SUCCESS;
    }

    //
    // STEP 4: Handle race condition or error
    //
    if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
        //
        // We lost the race - another thread created the context first
        // Release our unused context and return the winner's context
        //
        FltReleaseContext(newContext);

        if (oldContext != NULL) {
            *Context = oldContext;
            return STATUS_SUCCESS;
        } else {
            // Should not happen with STATUS_FLT_CONTEXT_ALREADY_DEFINED
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike] Context race: oldContext is NULL\n");
            return STATUS_UNSUCCESSFUL;
        }
    }

    //
    // Some other error occurred during FltSetStreamContext
    //
    FltReleaseContext(newContext);
    return status;
}

/**
 * @brief Cleanup callback - called by Filter Manager on context destruction.
 */
VOID
ShadowCleanupStreamContext(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
    )
{
    PSHADOW_STREAM_CONTEXT ctx = (PSHADOW_STREAM_CONTEXT)Context;

    UNREFERENCED_PARAMETER(ContextType);

    if (ctx == NULL) {
        return;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] Cleaning up stream context\n");

    //
    // CRITICAL: Delete ERESOURCE only if it was successfully initialized
    // Prevents BSOD from deleting uninitialized resources
    //
    if (ctx->ResourceInitialized) {
        ExDeleteResourceLite(&ctx->Resource);
        ctx->ResourceInitialized = FALSE;
    }

    //
    // Free FileName buffer if allocated
    //
    if (ctx->FileName.Buffer != NULL) {
        ExFreePoolWithTag(ctx->FileName.Buffer, SHADOW_CONTEXT_STRING_TAG);
        ctx->FileName.Buffer = NULL;
        ctx->FileName.Length = 0;
        ctx->FileName.MaximumLength = 0;
    }

    //
    // Note: The context structure itself is freed by Filter Manager
    // Do NOT call ExFreePoolWithTag on the context pointer
    //
}

/**
 * @brief Invalidate stream context after file modification.
 */
VOID
ShadowInvalidateStreamContext(
    _In_ PSHADOW_STREAM_CONTEXT Context
    )
{
    if (Context == NULL) {
        return;
    }

    //
    // CRITICAL FIX: Use atomic operations to prevent deadlock
    // Previous implementation could deadlock if caller already held the lock
    // Enterprise-grade antivirus products use lock-free atomic updates for
    // modification tracking to avoid deadlocks in complex I/O paths
    //
    InterlockedExchange8((volatile CHAR*)&Context->IsScanned, FALSE);
    InterlockedExchange8((volatile CHAR*)&Context->IsModified, TRUE);
    InterlockedIncrement((volatile LONG*)&Context->WriteCount);
    InterlockedExchange8((volatile CHAR*)&Context->HashValid, FALSE);

    // Note: We preserve the old Verdict for logging/analysis purposes
    // The IsScanned=FALSE flag will trigger rescan
}

/**
 * @brief Set scan verdict and update scan state.
 */
VOID
ShadowSetStreamVerdict(
    _In_ PSHADOW_STREAM_CONTEXT Context,
    _In_ SHADOWSTRIKE_SCAN_VERDICT Verdict
    )
{
    if (Context == NULL) {
        return;
    }

    //
    // Acquire exclusive lock for modification
    //
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&Context->Resource, TRUE);

    Context->Verdict = Verdict;
    Context->IsScanned = TRUE;
    Context->IsModified = FALSE;
    Context->ScanInProgress = FALSE;
    KeQuerySystemTime(&Context->ScanTime);

    ExReleaseResourceLite(&Context->Resource);
    KeLeaveCriticalRegion();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] Set verdict: %d\n", Verdict);
}

/**
 * @brief Check if file needs rescanning.
 */
BOOLEAN
ShadowShouldRescan(
    _In_ PSHADOW_STREAM_CONTEXT Context,
    _In_ ULONG CacheTTL
    )
{
    BOOLEAN shouldRescan = FALSE;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER elapsedTime;

    if (Context == NULL) {
        return TRUE; // No context = needs scan
    }

    //
    // Acquire shared lock for reading
    //
    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&Context->Resource, TRUE);

    //
    // Check 1: Never scanned?
    //
    if (!Context->IsScanned) {
        shouldRescan = TRUE;
        goto cleanup;
    }

    //
    // Check 2: File modified since last scan?
    //
    if (Context->IsModified) {
        shouldRescan = TRUE;
        goto cleanup;
    }

    //
    // Check 3: Scan in progress (avoid re-scan loops)?
    //
    if (Context->ScanInProgress) {
        shouldRescan = FALSE;
        goto cleanup;
    }

    //
    // Check 4: Cache TTL expired?
    //
    if (CacheTTL > 0) {
        KeQuerySystemTime(&currentTime);
        elapsedTime.QuadPart = currentTime.QuadPart - Context->ScanTime.QuadPart;

        // Convert 100-nanosecond units to seconds
        ULONG elapsedSeconds = (ULONG)(elapsedTime.QuadPart / 10000000LL);

        if (elapsedSeconds > CacheTTL) {
            shouldRescan = TRUE;
            goto cleanup;
        }
    }

    // All checks passed - no rescan needed
    shouldRescan = FALSE;

cleanup:
    ExReleaseResourceLite(&Context->Resource);
    KeLeaveCriticalRegion();

    return shouldRescan;
}

/**
 * @brief Initialize file name and FileID in context.
 */
NTSTATUS
ShadowInitializeStreamContextFileInfo(
    _In_ PSHADOW_STREAM_CONTEXT Context,
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    FILE_INTERNAL_INFORMATION fileIdInfo;

    if (Context == NULL || Instance == NULL || FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Get file name
    //
    status = FltGetFileNameInformation(
        NULL,
        FileObject,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );

    if (NT_SUCCESS(status)) {
        FltParseFileNameInformation(nameInfo);

        //
        // Acquire exclusive lock for modification
        //
        KeEnterCriticalRegion();
        ExAcquireResourceExclusiveLite(&Context->Resource, TRUE);

        // Allocate buffer for file name
        if (nameInfo->Name.Length > 0) {
            Context->FileName.MaximumLength = nameInfo->Name.Length;
            Context->FileName.Buffer = (PWCH)ExAllocatePoolWithTag(
                PagedPool,
                nameInfo->Name.Length,
                SHADOW_CONTEXT_STRING_TAG
            );

            if (Context->FileName.Buffer != NULL) {
                RtlCopyUnicodeString(&Context->FileName, &nameInfo->Name);
            }
        }

        ExReleaseResourceLite(&Context->Resource);
        KeLeaveCriticalRegion();

        FltReleaseFileNameInformation(nameInfo);
    }

    //
    // Get File ID (unique 64-bit identifier)
    //
    status = FltQueryInformationFile(
        Instance,
        FileObject,
        &fileIdInfo,
        sizeof(fileIdInfo),
        FileInternalInformation,
        NULL
    );

    if (NT_SUCCESS(status)) {
        KeEnterCriticalRegion();
        ExAcquireResourceExclusiveLite(&Context->Resource, TRUE);

        Context->FileId = fileIdInfo.IndexNumber;

        ExReleaseResourceLite(&Context->Resource);
        KeLeaveCriticalRegion();
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Allocate and initialize a new stream context.
 */
NTSTATUS
ShadowAllocateStreamContext(
    _Outptr_ PSHADOW_STREAM_CONTEXT* Context
    )
{
    NTSTATUS status;
    PSHADOW_STREAM_CONTEXT ctx = NULL;

    *Context = NULL;

    //
    // Allocate context from Filter Manager
    //
    status = FltAllocateContext(
        g_DriverData.FilterHandle,
        FLT_STREAM_CONTEXT,
        sizeof(SHADOW_STREAM_CONTEXT),
        PagedPool,
        (PFLT_CONTEXT*)&ctx
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Failed to allocate stream context: 0x%X\n", status);
        return status;
    }

    //
    // Zero memory
    //
    RtlZeroMemory(ctx, sizeof(SHADOW_STREAM_CONTEXT));

    //
    // Initialize ERESOURCE
    //
    status = ExInitializeResourceLite(&ctx->Resource);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Failed to initialize resource: 0x%X\n", status);
        FltReleaseContext(ctx);
        return status;
    }

    //
    // CRITICAL: Mark resource as initialized for safe cleanup
    //
    ctx->ResourceInitialized = TRUE;

    *Context = ctx;
    return STATUS_SUCCESS;
}
