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
 * - Thread-safe access via ERESOURCE locks with proper IRQL enforcement
 * - Proper cleanup to prevent BSOD (ExDeleteResourceLite)
 * - Memory leak prevention (FileName.Buffer cleanup)
 * - FileID caching for efficient lookups
 * - Defensive programming against corrupted/malicious data
 *
 * CRITICAL FIXES IN THIS VERSION (v2.0.0):
 * -----------------------------------------
 * 1. Fixed FltGetFileNameInformation API misuse (was passing NULL for CallbackData)
 *    - Now uses FltGetFileNameInformationUnsafe which is correct for FileObject-only calls
 * 2. Fixed reference count leak in ShadowGetOrCreateStreamContext
 *    - Removed erroneous FltReferenceContext call after FltSetStreamContext
 * 3. Fixed mixed synchronization (atomics + locks on same fields)
 *    - Now uses consistent ERESOURCE locking for all state fields
 *    - WriteCount remains atomic as it's lock-free by design
 * 4. Added ResourceInitialized checks before all lock acquisitions
 * 5. Added proper IRQL assertions for PASSIVE_LEVEL requirements
 * 6. Added defensive size validation for file name allocations
 * 7. Uses ExAllocatePool2 for modern Windows compatibility
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "StreamContext.h"
#include "../Core/Globals.h"
#include "../Shared/VerdictTypes.h"

// ============================================================================
// COMPILER COMPATIBILITY - ExAllocatePool2 wrapper for older WDK
// ============================================================================

#if !defined(POOL_FLAG_PAGED)
#define POOL_FLAG_PAGED         0x0000000000000100UI64
#define POOL_FLAG_NON_PAGED     0x0000000000000040UI64

//
// Fallback for older WDK versions that don't have ExAllocatePool2
//
#define ShadowAllocatePool(Flags, Size, Tag) \
    ExAllocatePoolWithTag( \
        ((Flags) & POOL_FLAG_PAGED) ? PagedPool : NonPagedPoolNx, \
        (Size), \
        (Tag) \
    )
#else
#define ShadowAllocatePool(Flags, Size, Tag) \
    ExAllocatePool2((Flags), (Size), (Tag))
#endif

// ============================================================================
// PRIVATE HELPER PROTOTYPES
// ============================================================================

static
NTSTATUS
ShadowAllocateStreamContext(
    _Outptr_ PSHADOW_STREAM_CONTEXT* Context
    );

static
VOID
ShadowQueryFileNameUnsafe(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Inout_ PSHADOW_STREAM_CONTEXT Context
    );

static
VOID
ShadowQueryFileId(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Inout_ PSHADOW_STREAM_CONTEXT Context
    );

// ============================================================================
// LOCK HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Acquire stream context lock for shared (read-only) access.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
BOOLEAN
ShadowAcquireStreamContextShared(
    _In_ PSHADOW_STREAM_CONTEXT Context
    )
{
    //
    // IRQL assertion - ERESOURCE can only be acquired at PASSIVE_LEVEL
    //
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    if (Context == NULL) {
        return FALSE;
    }

    //
    // CRITICAL: Check ResourceInitialized before ANY resource operation
    // Acquiring an uninitialized ERESOURCE causes BSOD
    //
    if (!Context->ResourceInitialized) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] CRITICAL: Attempt to acquire uninitialized resource\n");
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&Context->Resource, TRUE);

    return TRUE;
}

/**
 * @brief Acquire stream context lock for exclusive (read-write) access.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
BOOLEAN
ShadowAcquireStreamContextExclusive(
    _In_ PSHADOW_STREAM_CONTEXT Context
    )
{
    //
    // IRQL assertion - ERESOURCE can only be acquired at PASSIVE_LEVEL
    //
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    if (Context == NULL) {
        return FALSE;
    }

    //
    // CRITICAL: Check ResourceInitialized before ANY resource operation
    //
    if (!Context->ResourceInitialized) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] CRITICAL: Attempt to acquire uninitialized resource\n");
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&Context->Resource, TRUE);

    return TRUE;
}

/**
 * @brief Release stream context lock (shared or exclusive).
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowReleaseStreamContext(
    _In_ PSHADOW_STREAM_CONTEXT Context
    )
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    if (Context == NULL || !Context->ResourceInitialized) {
        return;
    }

    ExReleaseResourceLite(&Context->Resource);
    KeLeaveCriticalRegion();
}

// ============================================================================
// CONTEXT MANAGEMENT FUNCTIONS
// ============================================================================

/**
 * @brief Get or create stream context (race-safe implementation).
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowGetOrCreateStreamContext(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Outptr_ PSHADOW_STREAM_CONTEXT* Context
    )
{
    NTSTATUS status;
    PSHADOW_STREAM_CONTEXT newContext = NULL;
    PSHADOW_STREAM_CONTEXT oldContext = NULL;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    //
    // Validate parameters
    //
    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Context = NULL;

    if (Instance == NULL || FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // STEP 1: Try to get existing context
    //
    status = FltGetStreamContext(
        Instance,
        FileObject,
        (PFLT_CONTEXT*)&oldContext
    );

    if (NT_SUCCESS(status)) {
        //
        // Found existing context - return it
        // Reference count is already incremented by FltGetStreamContext
        //
        *Context = oldContext;
        return STATUS_SUCCESS;
    }

    if (status != STATUS_NOT_FOUND) {
        //
        // Unexpected error (e.g., stream contexts not supported)
        //
        return status;
    }

    //
    // STEP 2: No context exists - allocate and initialize new one
    //
    status = ShadowAllocateStreamContext(&newContext);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // STEP 3: Try to set the context (race condition handling)
    //
    // FLT_SET_CONTEXT_KEEP_IF_EXISTS ensures atomicity:
    // - If no context exists, ours is set
    // - If another thread already set one, we get STATUS_FLT_CONTEXT_ALREADY_DEFINED
    //   and oldContext receives the existing context
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
        // SUCCESS: We won the race - our context was set
        //
        // FltSetStreamContext does NOT add a reference for the caller.
        // The Filter Manager holds its own reference. We need to add
        // a reference for the caller (who will call FltReleaseContext).
        //
        // CRITICAL FIX: The original code incorrectly called FltReferenceContext
        // after FltSetStreamContext. When FltSetStreamContext succeeds, the
        // context already has refcount=1 from FltAllocateContext. The Filter
        // Manager's internal reference is separate. We return the context
        // with the allocation reference, which the caller will release.
        //
        // Actually, per WDK docs: When FltSetStreamContext succeeds with
        // KEEP_IF_EXISTS, the caller should NOT call FltReleaseContext on
        // newContext. The Filter Manager now owns the only reference.
        // We need to add a reference for the caller.
        //
        // Wait - let me re-read WDK docs carefully:
        // FltAllocateContext: refcount = 1
        // FltSetStreamContext (success): Filter Manager takes ownership,
        //   but does NOT change refcount. Caller must release if no longer needed.
        //
        // So the context has refcount=1, caller needs it, so we keep that ref.
        // No FltReferenceContext needed. The original bug was ADDING an extra ref.
        //

        //
        // Initialize file info while we hold the context
        //
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
        // FltSetStreamContext already populated oldContext with the existing
        // context (with an added reference for us)
        //
        FltReleaseContext(newContext);  // Release our unused context

        if (oldContext != NULL) {
            *Context = oldContext;
            return STATUS_SUCCESS;
        } else {
            //
            // This should never happen with STATUS_FLT_CONTEXT_ALREADY_DEFINED
            // but handle defensively
            //
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike] BUG: Context race lost but oldContext is NULL\n");
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
 * @brief Get existing stream context (no creation).
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowGetStreamContext(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Outptr_ PSHADOW_STREAM_CONTEXT* Context
    )
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Context = NULL;

    if (Instance == NULL || FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    return FltGetStreamContext(
        Instance,
        FileObject,
        (PFLT_CONTEXT*)Context
    );
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

    //
    // Handle NULL gracefully (defensive programming)
    //
    if (ctx == NULL) {
        return;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] Cleaning up stream context: %wZ\n",
               &ctx->FileName);

    //
    // CRITICAL: Delete ERESOURCE only if it was successfully initialized
    // Deleting an uninitialized ERESOURCE causes BSOD (pool corruption)
    //
    if (ctx->ResourceInitialized) {
        //
        // Ensure no one is holding the resource
        // In a properly designed system, this should never happen during cleanup
        //
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
    // Clear sensitive data
    //
    RtlSecureZeroMemory(ctx->FileHash, sizeof(ctx->FileHash));

    //
    // NOTE: The context structure itself is freed by Filter Manager
    // Do NOT call ExFreePoolWithTag on ctx
    //
}

// ============================================================================
// CONTEXT STATE FUNCTIONS
// ============================================================================

/**
 * @brief Invalidate stream context after file modification.
 *
 * CRITICAL FIX: Uses consistent ERESOURCE locking instead of mixing
 * atomic operations with lock-protected access. The only exception is
 * WriteCount which is designed for lock-free atomic updates.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowInvalidateStreamContext(
    _In_opt_ PSHADOW_STREAM_CONTEXT Context
    )
{
    if (Context == NULL) {
        return;
    }

    //
    // Acquire exclusive lock for all modifications
    // CRITICAL FIX: Original code used InterlockedExchange8 without lock,
    // which caused undefined behavior when mixed with lock-protected reads
    //
    if (!ShadowAcquireStreamContextExclusive(Context)) {
        //
        // Context not initialized - cannot modify safely
        //
        return;
    }

    //
    // Mark as modified and needing rescan
    //
    Context->IsScanned = FALSE;
    Context->IsModified = TRUE;
    Context->HashValid = FALSE;

    //
    // Release lock before atomic operation on WriteCount
    //
    ShadowReleaseStreamContext(Context);

    //
    // WriteCount is the ONLY field that uses atomic operations
    // It's designed for lock-free counting and is never read under lock
    //
    InterlockedIncrement(&Context->WriteCount);
}

/**
 * @brief Set scan verdict and update scan state.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowSetStreamVerdict(
    _In_opt_ PSHADOW_STREAM_CONTEXT Context,
    _In_ SHADOWSTRIKE_SCAN_VERDICT Verdict
    )
{
    if (Context == NULL) {
        return;
    }

    if (!ShadowAcquireStreamContextExclusive(Context)) {
        return;
    }

    Context->Verdict = Verdict;
    Context->IsScanned = TRUE;
    Context->IsModified = FALSE;
    Context->ScanInProgress = FALSE;
    KeQuerySystemTime(&Context->ScanTime);

    ShadowReleaseStreamContext(Context);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] Set verdict: %d for context %p\n", Verdict, Context);
}

/**
 * @brief Mark scan as in progress to prevent re-scan loops.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
BOOLEAN
ShadowMarkScanInProgress(
    _In_opt_ PSHADOW_STREAM_CONTEXT Context
    )
{
    BOOLEAN started = FALSE;

    if (Context == NULL) {
        return FALSE;
    }

    if (!ShadowAcquireStreamContextExclusive(Context)) {
        return FALSE;
    }

    //
    // Only start scan if not already in progress
    //
    if (!Context->ScanInProgress) {
        Context->ScanInProgress = TRUE;
        started = TRUE;
    }

    ShadowReleaseStreamContext(Context);

    return started;
}

/**
 * @brief Check if file needs rescanning.
 */
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ShadowShouldRescan(
    _In_opt_ PSHADOW_STREAM_CONTEXT Context,
    _In_ ULONG CacheTTL
    )
{
    BOOLEAN shouldRescan = FALSE;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER elapsedTime;

    //
    // NULL context = needs scan (defensive)
    //
    if (Context == NULL) {
        return TRUE;
    }

    if (!ShadowAcquireStreamContextShared(Context)) {
        //
        // Cannot acquire lock - assume rescan needed (safe default)
        //
        return TRUE;
    }

    //
    // Check 1: Never scanned?
    //
    if (!Context->IsScanned) {
        shouldRescan = TRUE;
        goto Cleanup;
    }

    //
    // Check 2: File modified since last scan?
    //
    if (Context->IsModified) {
        shouldRescan = TRUE;
        goto Cleanup;
    }

    //
    // Check 3: Scan already in progress?
    // Return FALSE to prevent re-entry
    //
    if (Context->ScanInProgress) {
        shouldRescan = FALSE;
        goto Cleanup;
    }

    //
    // Check 4: Cache TTL expired?
    //
    if (CacheTTL > 0) {
        KeQuerySystemTime(&currentTime);
        elapsedTime.QuadPart = currentTime.QuadPart - Context->ScanTime.QuadPart;

        //
        // Convert 100-nanosecond units to seconds
        // 10,000,000 100-ns units = 1 second
        //
        if (elapsedTime.QuadPart < 0) {
            //
            // Time went backwards (system time change) - force rescan
            //
            shouldRescan = TRUE;
            goto Cleanup;
        }

        ULONG elapsedSeconds = (ULONG)(elapsedTime.QuadPart / 10000000LL);

        if (elapsedSeconds > CacheTTL) {
            shouldRescan = TRUE;
            goto Cleanup;
        }
    }

    //
    // All checks passed - no rescan needed
    //
    shouldRescan = FALSE;

Cleanup:
    ShadowReleaseStreamContext(Context);
    return shouldRescan;
}

/**
 * @brief Initialize file name and FileID in context.
 *
 * CRITICAL FIX: Uses FltGetFileNameInformationUnsafe instead of
 * FltGetFileNameInformation(NULL, ...) which was incorrect API usage.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowInitializeStreamContextFileInfo(
    _In_ PSHADOW_STREAM_CONTEXT Context,
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject
    )
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    if (Context == NULL || Instance == NULL || FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Query file name (uses unsafe API since we only have FileObject)
    //
    ShadowQueryFileNameUnsafe(Instance, FileObject, Context);

    //
    // Query File ID
    //
    ShadowQueryFileId(Instance, FileObject, Context);

    //
    // We return SUCCESS even if individual queries failed
    // Caller can check FileName.Buffer and FileId.QuadPart to verify
    //
    return STATUS_SUCCESS;
}

/**
 * @brief Set cached file hash in context.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowSetStreamContextHash(
    _In_opt_ PSHADOW_STREAM_CONTEXT Context,
    _In_reads_(SHADOW_SHA256_HASH_SIZE) const UCHAR* Hash
    )
{
    if (Context == NULL || Hash == NULL) {
        return;
    }

    if (!ShadowAcquireStreamContextExclusive(Context)) {
        return;
    }

    RtlCopyMemory(Context->FileHash, Hash, SHADOW_SHA256_HASH_SIZE);
    Context->HashValid = TRUE;

    ShadowReleaseStreamContext(Context);
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Allocate and initialize a new stream context.
 */
static
NTSTATUS
ShadowAllocateStreamContext(
    _Outptr_ PSHADOW_STREAM_CONTEXT* Context
    )
{
    NTSTATUS status;
    PSHADOW_STREAM_CONTEXT ctx = NULL;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

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
                   "[ShadowStrike] Failed to allocate stream context: 0x%08X\n", status);
        return status;
    }

    //
    // Zero all memory - critical for security
    //
    RtlZeroMemory(ctx, sizeof(SHADOW_STREAM_CONTEXT));

    //
    // Initialize ERESOURCE lock
    //
    status = ExInitializeResourceLite(&ctx->Resource);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Failed to initialize resource: 0x%08X\n", status);
        FltReleaseContext(ctx);
        return status;
    }

    //
    // CRITICAL: Mark resource as initialized AFTER successful initialization
    // This flag is checked before every lock operation to prevent BSOD
    //
    ctx->ResourceInitialized = TRUE;

    //
    // Initialize default state
    //
    ctx->Verdict = Verdict_Unknown;
    ctx->IsScanned = FALSE;
    ctx->IsModified = FALSE;
    ctx->ScanInProgress = FALSE;
    ctx->HashValid = FALSE;

    *Context = ctx;
    return STATUS_SUCCESS;
}

/**
 * @brief Query file name using the "unsafe" API (for when we only have FileObject).
 *
 * CRITICAL FIX: The original code incorrectly called:
 *   FltGetFileNameInformation(NULL, FileObject, ...)
 *
 * The first parameter is PFLT_CALLBACK_DATA, not optional. When you only
 * have a PFILE_OBJECT (not in a callback context), you MUST use:
 *   FltGetFileNameInformationUnsafe(FileObject, Instance, ...)
 *
 * This function is "unsafe" because it can't guarantee the file object
 * won't be freed during the query, but in our case the caller holds a
 * reference to the file object so it's safe.
 */
static
VOID
ShadowQueryFileNameUnsafe(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Inout_ PSHADOW_STREAM_CONTEXT Context
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PWCH nameBuffer = NULL;
    USHORT allocationSize;

    //
    // CRITICAL FIX: Use FltGetFileNameInformationUnsafe when we only have FileObject
    // The original code passed NULL as the first parameter to FltGetFileNameInformation
    // which caused undefined behavior/BSOD
    //
    status = FltGetFileNameInformationUnsafe(
        FileObject,
        Instance,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                   "[ShadowStrike] FltGetFileNameInformationUnsafe failed: 0x%08X\n", status);
        return;
    }

    //
    // Parse the name information
    //
    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] FltParseFileNameInformation failed: 0x%08X\n", status);
        // Continue anyway - Name field is still valid
    }

    //
    // Validate length before allocation (defensive against corrupted data)
    //
    if (nameInfo->Name.Length == 0 || nameInfo->Name.Length > SHADOW_MAX_FILENAME_LENGTH) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Invalid file name length: %u\n", nameInfo->Name.Length);
        FltReleaseFileNameInformation(nameInfo);
        return;
    }

    //
    // Calculate allocation size (add space for null terminator for safety)
    //
    allocationSize = nameInfo->Name.Length + sizeof(WCHAR);

    //
    // Allocate buffer for file name
    //
    nameBuffer = (PWCH)ShadowAllocatePool(
        POOL_FLAG_PAGED,
        allocationSize,
        SHADOW_CONTEXT_STRING_TAG
    );

    if (nameBuffer == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Failed to allocate file name buffer (%u bytes)\n",
                   allocationSize);
        FltReleaseFileNameInformation(nameInfo);
        return;
    }

    //
    // Acquire exclusive lock for modification
    //
    if (!ShadowAcquireStreamContextExclusive(Context)) {
        ExFreePoolWithTag(nameBuffer, SHADOW_CONTEXT_STRING_TAG);
        FltReleaseFileNameInformation(nameInfo);
        return;
    }

    //
    // Free existing buffer if present (shouldn't happen, but defensive)
    //
    if (Context->FileName.Buffer != NULL) {
        ExFreePoolWithTag(Context->FileName.Buffer, SHADOW_CONTEXT_STRING_TAG);
    }

    //
    // Copy file name to context
    //
    Context->FileName.Buffer = nameBuffer;
    Context->FileName.MaximumLength = allocationSize;
    Context->FileName.Length = nameInfo->Name.Length;

    RtlCopyMemory(
        Context->FileName.Buffer,
        nameInfo->Name.Buffer,
        nameInfo->Name.Length
    );

    //
    // Null-terminate for safety (not required by UNICODE_STRING but helpful for debugging)
    //
    Context->FileName.Buffer[Context->FileName.Length / sizeof(WCHAR)] = L'\0';

    ShadowReleaseStreamContext(Context);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] Cached file name: %wZ\n", &Context->FileName);

    FltReleaseFileNameInformation(nameInfo);
}

/**
 * @brief Query NTFS File ID for the file.
 */
static
VOID
ShadowQueryFileId(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Inout_ PSHADOW_STREAM_CONTEXT Context
    )
{
    NTSTATUS status;
    FILE_INTERNAL_INFORMATION fileIdInfo;
    ULONG bytesReturned;

    RtlZeroMemory(&fileIdInfo, sizeof(fileIdInfo));

    //
    // Query File ID (NTFS unique identifier)
    //
    status = FltQueryInformationFile(
        Instance,
        FileObject,
        &fileIdInfo,
        sizeof(fileIdInfo),
        FileInternalInformation,
        &bytesReturned
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                   "[ShadowStrike] FltQueryInformationFile (FileId) failed: 0x%08X\n", status);
        return;
    }

    if (bytesReturned < sizeof(fileIdInfo)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Incomplete FILE_INTERNAL_INFORMATION returned\n");
        return;
    }

    //
    // Acquire exclusive lock for modification
    //
    if (!ShadowAcquireStreamContextExclusive(Context)) {
        return;
    }

    Context->FileId = fileIdInfo.IndexNumber;

    ShadowReleaseStreamContext(Context);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] Cached FileId: 0x%016llX\n", Context->FileId.QuadPart);
}
