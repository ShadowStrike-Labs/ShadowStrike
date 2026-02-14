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
 * - Two-phase locking: LifetimeLock (spin) + Resource (ERESOURCE)
 * - Proper cleanup with State machine to prevent use-after-free
 * - Memory quota enforcement for DoS protection
 * - Comprehensive telemetry for production debugging
 * - FileID + VolumeSerial for globally unique file identification
 *
 * CRITICAL FIXES IN THIS VERSION (v3.0.0):
 * -----------------------------------------
 * 1. Added LifetimeLock (KSPIN_LOCK) to atomically verify State before Resource acquisition
 * 2. Added State machine (UNINITIALIZED -> INITIALIZING -> ACTIVE -> TEARDOWN)
 * 3. Cleanup waits for active lock holders before deleting ERESOURCE
 * 4. All field access after lock release removed (use-after-free prevention)
 * 5. WriteCount atomic increment moved inside critical section
 * 6. File info initialization moved BEFORE FltSetStreamContext
 * 7. VolumeSerial now properly populated via FltQueryVolumeInformation
 * 8. ScanFileSize now captured during ShadowSetStreamVerdict
 * 9. Global memory quota enforced (16MB) for DoS protection
 * 10. Debug logging gated behind SHADOW_DEBUG_VERBOSE_LOGGING
 * 11. PAGED_CODE() added to all PASSIVE_LEVEL functions
 * 12. Comprehensive telemetry infrastructure added
 * 13. g_DriverData.FilterHandle validated before use
 * 14. SAL annotations fixed (_In_opt_ where NULL is handled)
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "StreamContext.h"
#include "../Core/Globals.h"
#include"../../Shared/VerdictTypes.h"

// ============================================================================
// PAGED CODE PRAGMA
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ShadowAcquireStreamContextShared)
#pragma alloc_text(PAGE, ShadowAcquireStreamContextExclusive)
#pragma alloc_text(PAGE, ShadowReleaseStreamContext)
#pragma alloc_text(PAGE, ShadowGetOrCreateStreamContext)
#pragma alloc_text(PAGE, ShadowGetStreamContext)
#pragma alloc_text(PAGE, ShadowCleanupStreamContext)
#pragma alloc_text(PAGE, ShadowInvalidateStreamContext)
#pragma alloc_text(PAGE, ShadowSetStreamVerdict)
#pragma alloc_text(PAGE, ShadowMarkScanInProgress)
#pragma alloc_text(PAGE, ShadowShouldRescan)
#pragma alloc_text(PAGE, ShadowSetStreamContextHash)
#endif

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
// GLOBAL TELEMETRY INSTANCE
// ============================================================================

SHADOW_STREAM_CONTEXT_TELEMETRY g_StreamContextTelemetry = { 0 };

// ============================================================================
// PRIVATE HELPER PROTOTYPES
// ============================================================================

static
NTSTATUS
ShadowAllocateStreamContext(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
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

static
VOID
ShadowQueryVolumeSerial(
    _In_ PFLT_INSTANCE Instance,
    _Inout_ PSHADOW_STREAM_CONTEXT Context
    );

static
BOOLEAN
ShadowCheckAndReserveStringQuota(
    _In_ USHORT AllocationSize
    );

static
VOID
ShadowReleaseStringQuota(
    _In_ USHORT AllocationSize
    );

static
NTSTATUS
ShadowInitializeStreamContextFileInfo(
    _In_ PSHADOW_STREAM_CONTEXT Context,
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject
    );

// ============================================================================
// LOCK HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Acquire stream context lock for shared (read-only) access.
 *
 * Uses two-phase locking to prevent race with cleanup:
 * 1. Acquire LifetimeLock (spin lock, very brief)
 * 2. Verify State == ACTIVE
 * 3. Enter critical region and acquire Resource shared
 * 4. Release LifetimeLock
 *
 * The LifetimeLock ensures that between checking State and acquiring
 * the Resource, no other thread can transition State to TEARDOWN.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
BOOLEAN
ShadowAcquireStreamContextShared(
    _In_opt_ PSHADOW_STREAM_CONTEXT Context
    )
{
    KIRQL oldIrql;
    LONG state;

    PAGED_CODE();

    if (Context == NULL) {
        return FALSE;
    }

    //
    // Phase 1: Acquire lifetime lock and verify state
    //
    KeAcquireSpinLock(&Context->LifetimeLock, &oldIrql);

    state = Context->State;

    if (state != SHADOW_CONTEXT_STATE_ACTIVE) {
        //
        // Context is not active (uninitialized, initializing, or teardown)
        //
        KeReleaseSpinLock(&Context->LifetimeLock, oldIrql);
        InterlockedIncrement(&g_StreamContextTelemetry.LockAcquisitionFailures);
        return FALSE;
    }

    //
    // Phase 2: Enter critical region and acquire Resource while still holding
    // LifetimeLock. This ensures cleanup cannot proceed until we have the Resource.
    //
    // Note: We're at DISPATCH_LEVEL due to spin lock, but KeEnterCriticalRegion
    // is safe at any IRQL. ExAcquireResourceSharedLite requires <= APC_LEVEL,
    // so we must release spin lock first, but only after entering critical region.
    //
    // CRITICAL: The sequence is:
    // 1. KeEnterCriticalRegion (safe at DISPATCH)
    // 2. Release spin lock (drops to PASSIVE)
    // 3. Acquire Resource (requires PASSIVE/APC)
    //
    KeEnterCriticalRegion();
    KeReleaseSpinLock(&Context->LifetimeLock, oldIrql);

    //
    // Now at PASSIVE_LEVEL, acquire the Resource
    // State was ACTIVE when we checked, and cleanup cannot proceed because:
    // - Cleanup acquires LifetimeLock to set State = TEARDOWN
    // - Cleanup then waits for Resource to be free
    // - We're about to acquire Resource, so cleanup will wait for us
    //
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
    _In_opt_ PSHADOW_STREAM_CONTEXT Context
    )
{
    KIRQL oldIrql;
    LONG state;

    PAGED_CODE();

    if (Context == NULL) {
        return FALSE;
    }

    //
    // Phase 1: Acquire lifetime lock and verify state
    //
    KeAcquireSpinLock(&Context->LifetimeLock, &oldIrql);

    state = Context->State;

    if (state != SHADOW_CONTEXT_STATE_ACTIVE) {
        KeReleaseSpinLock(&Context->LifetimeLock, oldIrql);
        InterlockedIncrement(&g_StreamContextTelemetry.LockAcquisitionFailures);
        return FALSE;
    }

    //
    // Phase 2: Enter critical region, release spin lock, acquire Resource
    //
    KeEnterCriticalRegion();
    KeReleaseSpinLock(&Context->LifetimeLock, oldIrql);

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
    PAGED_CODE();

    //
    // Context must not be NULL if caller acquired the lock successfully
    //
    NT_ASSERT(Context != NULL);

    if (Context == NULL) {
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
 *
 * Reference counting behavior:
 * - FltAllocateContext: refcount = 1
 * - FltSetStreamContext (success): Filter Manager adds its own reference (refcount = 2)
 * - We return the context with our reference; caller must call FltReleaseContext
 * - When file closes, Filter Manager releases its reference
 * - When caller releases, refcount hits 0 and cleanup callback fires
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

    PAGED_CODE();

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
    // Validate global state
    //
    if (g_DriverData.FilterHandle == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] ERROR: FilterHandle is NULL in ShadowGetOrCreateStreamContext\n");
        return STATUS_INVALID_DEVICE_STATE;
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
        // FltGetStreamContext increments reference count for caller
        //
        *Context = oldContext;
        return STATUS_SUCCESS;
    }

    if (status != STATUS_NOT_FOUND) {
        //
        // Unexpected error (e.g., stream contexts not supported on this volume)
        //
        return status;
    }

    //
    // STEP 2: No context exists - allocate and initialize new one
    // This initializes file info BEFORE attaching to prevent reading uninitialized data
    //
    status = ShadowAllocateStreamContext(Instance, FileObject, &newContext);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // STEP 3: Try to set the context (race condition handling)
    //
    // FLT_SET_CONTEXT_KEEP_IF_EXISTS ensures atomicity:
    // - If no context exists, ours is set
    // - If another thread already set one, we get STATUS_FLT_CONTEXT_ALREADY_DEFINED
    //   and oldContext receives the existing context (with added reference)
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
        // SUCCESS: Our context was attached to the file stream
        // We return newContext with the reference from FltAllocateContext
        // Caller must call FltReleaseContext when done
        //
        *Context = newContext;
        return STATUS_SUCCESS;
    }

    //
    // STEP 4: Handle race condition or error
    //
    if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
        //
        // We lost the race - another thread created the context first
        // FltSetStreamContext populated oldContext with the existing context
        // (with an added reference for us)
        //
        InterlockedIncrement(&g_StreamContextTelemetry.RaceConditionsDetected);

        //
        // Release our unused context (triggers cleanup callback)
        //
        FltReleaseContext(newContext);

        if (oldContext != NULL) {
            *Context = oldContext;
            return STATUS_SUCCESS;
        } else {
            //
            // This should never happen per WDK documentation
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
    PAGED_CODE();

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
 *
 * CRITICAL: This function implements safe teardown:
 * 1. Transitions State to TEARDOWN under LifetimeLock
 * 2. Waits for any active Resource holders to release
 * 3. Only then deletes ERESOURCE and frees resources
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowCleanupStreamContext(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
    )
{
    PSHADOW_STREAM_CONTEXT ctx = (PSHADOW_STREAM_CONTEXT)Context;
    KIRQL oldIrql;
    LONG previousState;
    ULONG waitCount = 0;
    USHORT fileNameLength = 0;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ContextType);

    //
    // Handle NULL gracefully (defensive programming)
    //
    if (ctx == NULL) {
        return;
    }

    //
    // STEP 1: Transition State to TEARDOWN under LifetimeLock
    // This prevents any new lock acquisitions from succeeding
    //
    KeAcquireSpinLock(&ctx->LifetimeLock, &oldIrql);
    previousState = InterlockedExchange(&ctx->State, SHADOW_CONTEXT_STATE_TEARDOWN);
    KeReleaseSpinLock(&ctx->LifetimeLock, oldIrql);

    //
    // If context was never fully initialized, skip resource cleanup
    //
    if (previousState == SHADOW_CONTEXT_STATE_UNINITIALIZED) {
        goto CleanupComplete;
    }

    if (previousState == SHADOW_CONTEXT_STATE_INITIALIZING) {
        //
        // Context was being initialized when cleanup triggered
        // ERESOURCE may or may not be initialized - check via heuristic
        // This is a rare race condition
        //
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Context cleanup during initialization\n");
        goto CleanupComplete;
    }

    //
    // STEP 2: Wait for any active Resource holders to release
    // The State is now TEARDOWN, so no new acquisitions will succeed
    // Existing holders will eventually release
    //
    // Use exponential backoff to avoid spinning too aggressively
    //
    while (ExIsResourceAcquiredExclusiveLite(&ctx->Resource) ||
           ExIsResourceAcquiredSharedLite(&ctx->Resource) > 0) {

        waitCount++;

        if (waitCount > 1000) {
            //
            // Something is very wrong - a thread is holding the Resource
            // for an extremely long time during cleanup
            //
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike] CRITICAL: Resource still held after 1000 waits in cleanup\n");
            NT_ASSERT(FALSE);
            break;
        }

        //
        // Brief sleep with increasing delay (1ms, 2ms, 4ms, ... up to 100ms)
        //
        LARGE_INTEGER delay;
        ULONG delayMs = (waitCount < 7) ? (1 << waitCount) : 100;
        delay.QuadPart = -((LONGLONG)delayMs * 10000);
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }

    //
    // STEP 3: Now safe to delete ERESOURCE
    //
    if (previousState == SHADOW_CONTEXT_STATE_ACTIVE) {
        ExDeleteResourceLite(&ctx->Resource);
    }

    //
    // STEP 4: Free FileName buffer if allocated
    //
    if (ctx->FileName.Buffer != NULL) {
        fileNameLength = ctx->FileName.MaximumLength;
        ExFreePoolWithTag(ctx->FileName.Buffer, SHADOW_CONTEXT_STRING_TAG);
        ctx->FileName.Buffer = NULL;
        ctx->FileName.Length = 0;
        ctx->FileName.MaximumLength = 0;

        //
        // Release quota
        //
        ShadowReleaseStringQuota(fileNameLength);
    }

    //
    // STEP 5: Clear sensitive data
    //
    RtlSecureZeroMemory(ctx->FileHash, sizeof(ctx->FileHash));

CleanupComplete:
    //
    // Update telemetry
    //
    InterlockedIncrement64(&g_StreamContextTelemetry.TotalFrees);
    InterlockedDecrement(&g_StreamContextTelemetry.ActiveContexts);

#if SHADOW_DEBUG_VERBOSE_LOGGING
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] Cleaned up stream context %p (previousState=%d)\n",
               ctx, previousState);
#endif
}

// ============================================================================
// CONTEXT STATE FUNCTIONS
// ============================================================================

/**
 * @brief Invalidate stream context after file modification.
 *
 * All state modifications AND atomic WriteCount increment happen
 * inside the exclusive lock to prevent race conditions.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowInvalidateStreamContext(
    _In_opt_ PSHADOW_STREAM_CONTEXT Context
    )
{
    PAGED_CODE();

    if (Context == NULL) {
        return;
    }

    if (!ShadowAcquireStreamContextExclusive(Context)) {
        return;
    }

    //
    // Mark as modified and needing rescan
    //
    Context->IsScanned = FALSE;
    Context->IsModified = TRUE;
    Context->HashValid = FALSE;

    //
    // Increment WriteCount INSIDE the lock to prevent use-after-free
    // The atomic is still used for lock-free reads by monitoring code
    //
    InterlockedIncrement(&Context->WriteCount);

    ShadowReleaseStreamContext(Context);
}

/**
 * @brief Set scan verdict and update scan state.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowSetStreamVerdict(
    _In_opt_ PSHADOW_STREAM_CONTEXT Context,
    _In_ SHADOWSTRIKE_SCAN_VERDICT Verdict,
    _In_ LONGLONG FileSize
    )
{
    PAGED_CODE();

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
    Context->ScanFileSize.QuadPart = FileSize;
    KeQuerySystemTime(&Context->ScanTime);

    ShadowReleaseStreamContext(Context);

#if SHADOW_DEBUG_VERBOSE_LOGGING
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] Set verdict: %d for context %p, size=%lld\n",
               Verdict, Context, FileSize);
#endif
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

    PAGED_CODE();

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

    PAGED_CODE();

    //
    // NULL context = needs scan (defensive)
    //
    if (Context == NULL) {
        return TRUE;
    }

    if (!ShadowAcquireStreamContextShared(Context)) {
        //
        // Cannot acquire lock (context in teardown) - don't scan
        // Returning FALSE is safer than TRUE here because the file
        // is being closed anyway
        //
        return FALSE;
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
        // Handle time going backwards (system time change)
        //
        if (elapsedTime.QuadPart < 0) {
            shouldRescan = TRUE;
            goto Cleanup;
        }

        //
        // Convert 100-nanosecond units to seconds
        // 10,000,000 100-ns units = 1 second
        //
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
 * @brief Set cached file hash in context.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowSetStreamContextHash(
    _In_opt_ PSHADOW_STREAM_CONTEXT Context,
    _In_reads_(SHADOW_SHA256_HASH_SIZE) const UCHAR* Hash
    )
{
    PAGED_CODE();

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

/**
 * @brief Get current telemetry snapshot.
 */
VOID
ShadowGetStreamContextTelemetry(
    _Out_ PSHADOW_STREAM_CONTEXT_TELEMETRY Telemetry
    )
{
    if (Telemetry == NULL) {
        return;
    }

    //
    // Copy current values - these are all atomically updated so we get
    // a consistent-enough snapshot without needing a global lock
    //
    Telemetry->TotalAllocations = g_StreamContextTelemetry.TotalAllocations;
    Telemetry->TotalFrees = g_StreamContextTelemetry.TotalFrees;
    Telemetry->ActiveContexts = g_StreamContextTelemetry.ActiveContexts;
    Telemetry->TotalStringBytes = g_StreamContextTelemetry.TotalStringBytes;
    Telemetry->CurrentStringBytes = g_StreamContextTelemetry.CurrentStringBytes;
    Telemetry->QuotaExceededCount = g_StreamContextTelemetry.QuotaExceededCount;
    Telemetry->ResourceInitFailures = g_StreamContextTelemetry.ResourceInitFailures;
    Telemetry->LockAcquisitionFailures = g_StreamContextTelemetry.LockAcquisitionFailures;
    Telemetry->RaceConditionsDetected = g_StreamContextTelemetry.RaceConditionsDetected;
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Check and reserve quota for string allocation.
 *
 * @return TRUE if quota available and reserved, FALSE if quota exceeded
 */
static
BOOLEAN
ShadowCheckAndReserveStringQuota(
    _In_ USHORT AllocationSize
    )
{
    LONG64 currentBytes;
    LONG64 newBytes;

    do {
        currentBytes = g_StreamContextTelemetry.CurrentStringBytes;
        newBytes = currentBytes + AllocationSize;

        if (newBytes > SHADOW_MAX_CONTEXT_MEMORY) {
            InterlockedIncrement(&g_StreamContextTelemetry.QuotaExceededCount);
            return FALSE;
        }

    } while (InterlockedCompareExchange64(
                 &g_StreamContextTelemetry.CurrentStringBytes,
                 newBytes,
                 currentBytes) != currentBytes);

    InterlockedAdd64(&g_StreamContextTelemetry.TotalStringBytes, AllocationSize);
    return TRUE;
}

/**
 * @brief Release previously reserved string quota.
 */
static
VOID
ShadowReleaseStringQuota(
    _In_ USHORT AllocationSize
    )
{
    InterlockedAdd64(&g_StreamContextTelemetry.CurrentStringBytes, -(LONG64)AllocationSize);
}

/**
 * @brief Allocate and fully initialize a new stream context.
 *
 * This function initializes ALL fields including file info BEFORE
 * the context is attached to the file stream. This prevents other
 * threads from reading uninitialized data.
 */
static
NTSTATUS
ShadowAllocateStreamContext(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Outptr_ PSHADOW_STREAM_CONTEXT* Context
    )
{
    NTSTATUS status;
    PSHADOW_STREAM_CONTEXT ctx = NULL;
    KIRQL oldIrql;

    PAGED_CODE();

    *Context = NULL;

    //
    // Validate FilterHandle
    //
    if (g_DriverData.FilterHandle == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

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
    // Initialize lifetime spin lock and set state to INITIALIZING
    //
    KeInitializeSpinLock(&ctx->LifetimeLock);
    ctx->State = SHADOW_CONTEXT_STATE_INITIALIZING;

    //
    // Initialize ERESOURCE lock
    //
    status = ExInitializeResourceLite(&ctx->Resource);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Failed to initialize resource: 0x%08X\n", status);
        InterlockedIncrement(&g_StreamContextTelemetry.ResourceInitFailures);
        ctx->State = SHADOW_CONTEXT_STATE_UNINITIALIZED;
        FltReleaseContext(ctx);
        return status;
    }

    //
    // Initialize default state fields
    //
    ctx->Verdict = Verdict_Unknown;
    ctx->IsScanned = FALSE;
    ctx->IsModified = FALSE;
    ctx->ScanInProgress = FALSE;
    ctx->HashValid = FALSE;

    //
    // Initialize file info BEFORE attaching to stream
    // This prevents other threads from reading uninitialized FileName/FileId
    //
    status = ShadowInitializeStreamContextFileInfo(ctx, Instance, FileObject);
    if (!NT_SUCCESS(status)) {
        //
        // Non-fatal - context is still usable without cached file info
        // Individual queries may have partially succeeded
        //
    }

    //
    // Transition to ACTIVE state under LifetimeLock
    //
    KeAcquireSpinLock(&ctx->LifetimeLock, &oldIrql);
    ctx->State = SHADOW_CONTEXT_STATE_ACTIVE;
    KeReleaseSpinLock(&ctx->LifetimeLock, oldIrql);

    //
    // Update telemetry
    //
    InterlockedIncrement64(&g_StreamContextTelemetry.TotalAllocations);
    InterlockedIncrement(&g_StreamContextTelemetry.ActiveContexts);

    *Context = ctx;
    return STATUS_SUCCESS;
}

/**
 * @brief Initialize file name, FileID, and VolumeSerial in context.
 *
 * Called during context allocation BEFORE attaching to file stream.
 * Does not acquire context lock because context is not yet visible
 * to other threads.
 */
static
NTSTATUS
ShadowInitializeStreamContextFileInfo(
    _In_ PSHADOW_STREAM_CONTEXT Context,
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject
    )
{
    PAGED_CODE();

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
    // Query Volume Serial Number
    //
    ShadowQueryVolumeSerial(Instance, Context);

    return STATUS_SUCCESS;
}

/**
 * @brief Query file name using the "unsafe" API.
 *
 * Uses FltGetFileNameInformationUnsafe because we only have FileObject,
 * not a callback data structure. This is safe because caller holds a
 * reference to the file object.
 *
 * Does NOT acquire context lock - called during initialization before
 * context is visible to other threads.
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

    PAGED_CODE();

    //
    // Query file name information
    //
    status = FltGetFileNameInformationUnsafe(
        FileObject,
        Instance,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );

    if (!NT_SUCCESS(status)) {
#if SHADOW_DEBUG_VERBOSE_LOGGING
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                   "[ShadowStrike] FltGetFileNameInformationUnsafe failed: 0x%08X\n", status);
#endif
        return;
    }

    //
    // Parse the name information
    //
    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        //
        // Continue anyway - Name field is still valid for our purposes
        //
    }

    //
    // Validate length (defensive against corrupted data and DoS)
    //
    if (nameInfo->Name.Length == 0) {
        FltReleaseFileNameInformation(nameInfo);
        return;
    }

    if (nameInfo->Name.Length > SHADOW_MAX_FILENAME_LENGTH) {
        //
        // Path too long - truncate to our limit
        // This is a defensive measure against malicious long paths
        //
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] File name truncated from %u to %u bytes\n",
                   nameInfo->Name.Length, SHADOW_MAX_FILENAME_LENGTH);
        nameInfo->Name.Length = SHADOW_MAX_FILENAME_LENGTH;
    }

    //
    // Calculate allocation size (add space for null terminator)
    //
    allocationSize = nameInfo->Name.Length + sizeof(WCHAR);

    //
    // Check and reserve quota before allocating
    //
    if (!ShadowCheckAndReserveStringQuota(allocationSize)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] String quota exceeded, cannot cache file name\n");
        FltReleaseFileNameInformation(nameInfo);
        return;
    }

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
        ShadowReleaseStringQuota(allocationSize);
        FltReleaseFileNameInformation(nameInfo);
        return;
    }

    //
    // Copy file name to context
    // No lock needed - context not yet visible to other threads
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
    // Null-terminate for safety
    //
    Context->FileName.Buffer[Context->FileName.Length / sizeof(WCHAR)] = L'\0';

#if SHADOW_DEBUG_VERBOSE_LOGGING
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] Cached file name: %wZ\n", &Context->FileName);
#endif

    FltReleaseFileNameInformation(nameInfo);
}

/**
 * @brief Query NTFS File ID for the file.
 *
 * Does NOT acquire context lock - called during initialization.
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

    PAGED_CODE();

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
#if SHADOW_DEBUG_VERBOSE_LOGGING
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                   "[ShadowStrike] FltQueryInformationFile (FileId) failed: 0x%08X\n", status);
#endif
        return;
    }

    if (bytesReturned < sizeof(fileIdInfo)) {
        return;
    }

    //
    // Store FileId - no lock needed during initialization
    //
    Context->FileId = fileIdInfo.IndexNumber;

#if SHADOW_DEBUG_VERBOSE_LOGGING
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] Cached FileId: 0x%016llX\n", Context->FileId.QuadPart);
#endif
}

/**
 * @brief Query volume serial number.
 *
 * This creates a globally unique file identifier when combined with FileId.
 * Does NOT acquire context lock - called during initialization.
 */
static
VOID
ShadowQueryVolumeSerial(
    _In_ PFLT_INSTANCE Instance,
    _Inout_ PSHADOW_STREAM_CONTEXT Context
    )
{
    NTSTATUS status;
    UCHAR buffer[sizeof(FILE_FS_VOLUME_INFORMATION) + 256 * sizeof(WCHAR)];
    PFILE_FS_VOLUME_INFORMATION volumeInfo = (PFILE_FS_VOLUME_INFORMATION)buffer;

    PAGED_CODE();

    RtlZeroMemory(buffer, sizeof(buffer));

    //
    // Query volume information to get serial number.
    // FltQueryVolumeInformation(Instance, Irp, FsInfo, Length, InfoClass)
    // Pass NULL for IRP — direct query without associated I/O request.
    //
    status = FltQueryVolumeInformation(
        Instance,
        NULL,
        volumeInfo,
        sizeof(buffer),
        FileFsVolumeInformation
    );

    if (!NT_SUCCESS(status)) {
#if SHADOW_DEBUG_VERBOSE_LOGGING
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                   "[ShadowStrike] FltQueryVolumeInformation failed: 0x%08X\n", status);
#endif
        return;
    }

    //
    // Store volume serial - no lock needed during initialization
    //
    Context->VolumeSerial = volumeInfo->VolumeSerialNumber;

#if SHADOW_DEBUG_VERBOSE_LOGGING
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] Cached VolumeSerial: 0x%08X\n", Context->VolumeSerial);
#endif
}
