/**
 * ============================================================================
 * ShadowStrike NGAV - STREAM CONTEXT
 * ============================================================================
 *
 * @file StreamContext.h
 * @brief Stream context definitions and management for per-file state tracking.
 *
 * Provides a robust, thread-safe stream context management system for tracking
 * file state (scan verdicts, modification status, FileID) across I/O operations.
 * Handles race conditions during context creation and ensures proper resource
 * cleanup to prevent BSOD and memory leaks.
 *
 * Thread Safety Model:
 * --------------------
 * - Context lifecycle protected by KSPIN_LOCK (LifetimeLock) for atomicity
 * - Field access protected by ERESOURCE (Resource) for reader/writer semantics
 * - Atomic counters (WriteCount, AllocationCount) use Interlocked* for lock-free updates
 * - Two-phase locking: LifetimeLock (brief) then Resource (extended hold)
 * - ERESOURCE must be acquired at PASSIVE_LEVEL only
 * - LifetimeLock acquired at DISPATCH_LEVEL (spin lock)
 *
 * Memory Model:
 * -------------
 * - Context structure managed by Filter Manager (FltAllocateContext/FltReleaseContext)
 * - FileName.Buffer separately allocated from PagedPool, freed in cleanup callback
 * - ERESOURCE must be deleted in cleanup callback before Filter Manager frees context
 * - Global memory quota enforced to prevent DoS attacks
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_STREAM_CONTEXT_H
#define SHADOWSTRIKE_STREAM_CONTEXT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <fltKernel.h>
#include <ntddk.h>

//
// Forward declaration - actual definition in VerdictTypes.h
// Included by implementation file
//
typedef enum _SHADOWSTRIKE_SCAN_VERDICT SHADOWSTRIKE_SCAN_VERDICT;

// ============================================================================
// POOL TAGS
// ============================================================================

/**
 * @brief Pool tag for stream context allocations: 'xSSc' = ShadowStrike Stream Context
 */
#define SHADOW_STREAM_CONTEXT_TAG 'xSSc'

/**
 * @brief Pool tag for context string buffers: 'sSSc' = ShadowStrike String Context
 */
#define SHADOW_CONTEXT_STRING_TAG 'sSSc'

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * @brief Maximum file name length we will cache (in bytes, including null terminator).
 *        Reduced from 32KB to 2KB for DoS protection while still supporting long paths.
 *        Windows MAX_PATH is 260, but extended paths can reach ~32K. 2KB handles 99%+ of cases.
 */
#define SHADOW_MAX_FILENAME_LENGTH  (2048)

/**
 * @brief SHA-256 hash size in bytes.
 */
#define SHADOW_SHA256_HASH_SIZE     (32)

/**
 * @brief Maximum total memory for stream context string allocations (DoS protection).
 *        16MB global quota prevents resource exhaustion attacks.
 */
#define SHADOW_MAX_CONTEXT_MEMORY   (16 * 1024 * 1024)

/**
 * @brief Context state flags for lifecycle management.
 */
#define SHADOW_CONTEXT_STATE_UNINITIALIZED  0x00000000
#define SHADOW_CONTEXT_STATE_INITIALIZING   0x00000001
#define SHADOW_CONTEXT_STATE_ACTIVE         0x00000002
#define SHADOW_CONTEXT_STATE_TEARDOWN       0x00000003

// ============================================================================
// COMPILE-TIME CONFIGURATION
// ============================================================================

/**
 * @brief Enable verbose debug logging (DISABLE IN PRODUCTION).
 *        When disabled, file paths are not logged to prevent information disclosure.
 */
#ifndef SHADOW_DEBUG_VERBOSE_LOGGING
#define SHADOW_DEBUG_VERBOSE_LOGGING 0
#endif

// ============================================================================
// TELEMETRY STRUCTURE
// ============================================================================

/**
 * @brief Global telemetry counters for stream context operations.
 *        Used for production debugging and performance monitoring.
 */
typedef struct _SHADOW_STREAM_CONTEXT_TELEMETRY {

    /**
     * @brief Total contexts allocated since driver load.
     */
    volatile LONG64 TotalAllocations;

    /**
     * @brief Total contexts freed since driver load.
     */
    volatile LONG64 TotalFrees;

    /**
     * @brief Current active context count.
     */
    volatile LONG ActiveContexts;

    /**
     * @brief Total bytes allocated for file name strings.
     */
    volatile LONG64 TotalStringBytes;

    /**
     * @brief Current bytes allocated for file name strings.
     */
    volatile LONG64 CurrentStringBytes;

    /**
     * @brief Allocation failures due to memory quota.
     */
    volatile LONG QuotaExceededCount;

    /**
     * @brief Resource initialization failures.
     */
    volatile LONG ResourceInitFailures;

    /**
     * @brief Lock acquisition failures (context in teardown).
     */
    volatile LONG LockAcquisitionFailures;

    /**
     * @brief Race conditions detected (context already existed).
     */
    volatile LONG RaceConditionsDetected;

} SHADOW_STREAM_CONTEXT_TELEMETRY, *PSHADOW_STREAM_CONTEXT_TELEMETRY;

/**
 * @brief Global telemetry instance (defined in StreamContext.c).
 */
extern SHADOW_STREAM_CONTEXT_TELEMETRY g_StreamContextTelemetry;

// ============================================================================
// STREAM CONTEXT STRUCTURE
// ============================================================================

/**
 * @brief Per-stream (per-file) context structure.
 *
 * This structure is allocated by the Filter Manager and associated with
 * each file stream. It tracks scan state, verdicts, modification status,
 * and file identity to enable efficient caching and rescan logic.
 *
 * SYNCHRONIZATION RULES (CRITICAL):
 * ---------------------------------
 * 1. LifetimeLock protects State transitions (brief spin lock hold)
 * 2. Resource protects ALL field access (reader/writer lock)
 * 3. Acquisition order: LifetimeLock -> verify State -> Resource
 * 4. WriteCount uses InterlockedIncrement for lock-free atomic updates
 * 5. Resource lock MUST be acquired at IRQL == PASSIVE_LEVEL only
 * 6. LifetimeLock raises to DISPATCH_LEVEL (very brief hold)
 * 7. NEVER access fields without verifying State == ACTIVE first
 *
 * MEMORY MANAGEMENT:
 * ------------------
 * - Structure managed by Filter Manager via FltAllocateContext
 * - FileName.Buffer is separately allocated and freed in cleanup
 * - Resource must be deleted in cleanup callback (ExDeleteResourceLite)
 * - NEVER call ExFreePool on the context pointer itself
 *
 * INITIALIZATION ORDER:
 * ---------------------
 * 1. FltAllocateContext (Filter Manager allocates structure)
 * 2. RtlZeroMemory (zero all fields)
 * 3. KeInitializeSpinLock (initialize lifetime lock)
 * 4. State = INITIALIZING
 * 5. ExInitializeResourceLite (initialize ERESOURCE)
 * 6. Initialize file info (FileName, FileId, VolumeSerial)
 * 7. State = ACTIVE (under LifetimeLock)
 * 8. FltSetStreamContext (attach to file)
 */
typedef struct _SHADOW_STREAM_CONTEXT {

    // =========================================================================
    // Lifecycle Management (MUST BE FIRST for cache line alignment)
    // =========================================================================

    /**
     * @brief Spin lock protecting State transitions.
     *
     * CRITICAL: This lock is held very briefly only during State checks/transitions.
     * It ensures atomicity between checking State and acquiring Resource.
     */
    KSPIN_LOCK LifetimeLock;

    /**
     * @brief Current state of the context lifecycle.
     *
     * Values: UNINITIALIZED, INITIALIZING, ACTIVE, TEARDOWN
     * Transitions are protected by LifetimeLock.
     */
    volatile LONG State;

    /**
     * @brief Reserved padding for alignment to 8-byte boundary.
     */
    ULONG Reserved0;

    // =========================================================================
    // Synchronization
    // =========================================================================

    /**
     * @brief ERESOURCE lock for thread-safe access to all context fields.
     *
     * CRITICAL: Must be initialized with ExInitializeResourceLite before use.
     * CRITICAL: Must be deleted with ExDeleteResourceLite in cleanup callback.
     * CRITICAL: Can only be acquired at IRQL == PASSIVE_LEVEL.
     * CRITICAL: Only acquire when State == ACTIVE (verified under LifetimeLock).
     */
    ERESOURCE Resource;

    // =========================================================================
    // File Identity
    // =========================================================================

    /**
     * @brief Cached file name (normalized path).
     *
     * Populated during context initialization. Buffer is separately allocated
     * from PagedPool and must be freed in cleanup callback.
     */
    UNICODE_STRING FileName;

    /**
     * @brief Unique 64-bit NTFS File ID (stable across renames).
     *
     * Used for cache lookups and file identification. Zero if unavailable.
     */
    LARGE_INTEGER FileId;

    /**
     * @brief Volume serial number for multi-volume disambiguation.
     *
     * Combined with FileId to create globally unique file identifier.
     */
    ULONG VolumeSerial;

    /**
     * @brief Reserved padding for alignment.
     */
    ULONG Reserved2;

    // =========================================================================
    // Scan State
    // =========================================================================

    /**
     * @brief TRUE if file has been scanned at least once.
     *
     * When FALSE, ShadowShouldRescan() returns TRUE.
     */
    BOOLEAN IsScanned;

    /**
     * @brief TRUE if file was written to since last scan.
     *
     * Set to TRUE on write operations. Cleared when scan completes.
     */
    BOOLEAN IsModified;

    /**
     * @brief TRUE if file is currently being scanned.
     *
     * Used to prevent re-scan loops. Set before scan starts, cleared on completion.
     */
    BOOLEAN ScanInProgress;

    /**
     * @brief TRUE if FileHash contains valid data.
     *
     * Invalidated on file modification.
     */
    BOOLEAN HashValid;

    /**
     * @brief Reserved padding for alignment.
     */
    BOOLEAN Reserved3[4];

    /**
     * @brief Last scan verdict (Clean, Malware, Suspicious, etc.).
     *
     * Only valid when IsScanned == TRUE.
     */
    SHADOWSTRIKE_SCAN_VERDICT Verdict;

    /**
     * @brief Timestamp of last successful scan (from KeQuerySystemTime).
     *
     * Used for cache TTL calculations.
     */
    LARGE_INTEGER ScanTime;

    // =========================================================================
    // Modification Tracking
    // =========================================================================

    /**
     * @brief Number of write operations since context creation.
     *
     * Updated atomically with InterlockedIncrement for lock-free counting.
     * This is the ONLY field that uses atomic operations outside the lock.
     * MUST be read/written only via Interlocked* functions.
     */
    volatile LONG WriteCount;

    /**
     * @brief Reserved padding for alignment.
     */
    ULONG Reserved4;

    /**
     * @brief File size at last scan (for change detection).
     *
     * Captured when scan completes. Used with IsModified for robust change detection.
     */
    LARGE_INTEGER ScanFileSize;

    // =========================================================================
    // Hash Cache
    // =========================================================================

    /**
     * @brief Cached SHA-256 hash of file contents.
     *
     * Only valid when HashValid == TRUE. Invalidated on file modification.
     */
    UCHAR FileHash[SHADOW_SHA256_HASH_SIZE];

} SHADOW_STREAM_CONTEXT, *PSHADOW_STREAM_CONTEXT;

// ============================================================================
// LOCK HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Acquire stream context lock for shared (read-only) access.
 *
 * Uses two-phase locking:
 * 1. Acquire LifetimeLock (spin lock, brief)
 * 2. Verify State == ACTIVE
 * 3. Acquire Resource shared
 * 4. Release LifetimeLock
 *
 * CRITICAL: Must be called at IRQL == PASSIVE_LEVEL.
 * CRITICAL: Must call ShadowReleaseStreamContext() to release.
 *
 * @param Context  The context to lock (NULL returns FALSE)
 *
 * @return TRUE if lock acquired successfully
 *         FALSE if context is NULL, not initialized, or in teardown
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
BOOLEAN
ShadowAcquireStreamContextShared(
    _In_opt_ PSHADOW_STREAM_CONTEXT Context
    );

/**
 * @brief Acquire stream context lock for exclusive (read-write) access.
 *
 * Uses two-phase locking:
 * 1. Acquire LifetimeLock (spin lock, brief)
 * 2. Verify State == ACTIVE
 * 3. Acquire Resource exclusive
 * 4. Release LifetimeLock
 *
 * CRITICAL: Must be called at IRQL == PASSIVE_LEVEL.
 * CRITICAL: Must call ShadowReleaseStreamContext() to release.
 *
 * @param Context  The context to lock (NULL returns FALSE)
 *
 * @return TRUE if lock acquired successfully
 *         FALSE if context is NULL, not initialized, or in teardown
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
BOOLEAN
ShadowAcquireStreamContextExclusive(
    _In_opt_ PSHADOW_STREAM_CONTEXT Context
    );

/**
 * @brief Release stream context lock (shared or exclusive).
 *
 * CRITICAL: Must be called after successful ShadowAcquireStreamContext*().
 * CRITICAL: Must be called at IRQL == PASSIVE_LEVEL.
 *
 * @param Context  The context to unlock (must not be NULL if lock was acquired)
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowReleaseStreamContext(
    _In_ PSHADOW_STREAM_CONTEXT Context
    );

// ============================================================================
// CONTEXT MANAGEMENT FUNCTIONS
// ============================================================================

/**
 * @brief Get or create stream context for a file (race-safe).
 *
 * This function implements the "Keep if Exists" pattern to handle race
 * conditions where multiple threads attempt to create a context for the
 * same file simultaneously. It ensures only one context is created and
 * shared across all threads.
 *
 * Algorithm:
 * 1. Try FltGetStreamContext - return if exists
 * 2. Allocate new context via FltAllocateContext
 * 3. Initialize LifetimeLock, State = INITIALIZING
 * 4. Initialize ERESOURCE lock
 * 5. Initialize file info (FileName, FileId, VolumeSerial) BEFORE attachment
 * 6. State = ACTIVE
 * 7. FltSetStreamContext with FLT_SET_CONTEXT_KEEP_IF_EXISTS
 * 8. If race occurred (STATUS_FLT_CONTEXT_ALREADY_DEFINED):
 *    - Release our unused context
 *    - Return the winner's context
 * 9. Otherwise return our new context
 *
 * @param Instance    Filter instance (must not be NULL)
 * @param FileObject  File object (must not be NULL)
 * @param Context     [out] Receives context pointer (caller must call FltReleaseContext)
 *
 * @return STATUS_SUCCESS on success
 *         STATUS_INVALID_PARAMETER if parameters are NULL
 *         STATUS_INSUFFICIENT_RESOURCES if allocation fails or quota exceeded
 *         Other NTSTATUS codes from Filter Manager
 *
 * @note CRITICAL: Caller MUST call FltReleaseContext when done with the context.
 * @note This function must be called at IRQL == PASSIVE_LEVEL.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowGetOrCreateStreamContext(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Outptr_ PSHADOW_STREAM_CONTEXT* Context
    );

/**
 * @brief Get existing stream context for a file (no creation).
 *
 * Simple wrapper around FltGetStreamContext. Use this when you only want
 * to check if a context exists without creating one.
 *
 * @param Instance    Filter instance (must not be NULL)
 * @param FileObject  File object (must not be NULL)
 * @param Context     [out] Receives context pointer if found
 *
 * @return STATUS_SUCCESS if context found
 *         STATUS_NOT_FOUND if no context exists
 *         Other NTSTATUS codes on error
 *
 * @note Caller MUST call FltReleaseContext when done if STATUS_SUCCESS returned.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowGetStreamContext(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Outptr_ PSHADOW_STREAM_CONTEXT* Context
    );

/**
 * @brief Cleanup callback for stream context destruction.
 *
 * Called by Filter Manager when a stream context is being freed.
 * This is the ONLY place to free resources allocated within the context.
 *
 * Cleanup actions:
 * 1. Transition State to TEARDOWN (prevents new lock acquisitions)
 * 2. Wait for any active lock holders to release (spin with backoff)
 * 3. Delete ERESOURCE
 * 4. Free FileName.Buffer
 * 5. Update telemetry
 *
 * CRITICAL: Do NOT call ExFreePool on the context pointer - Filter Manager
 * owns and frees the context structure itself.
 *
 * @param Context      The context being freed (may be NULL - handle gracefully)
 * @param ContextType  Type of context (FLT_STREAM_CONTEXT)
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowCleanupStreamContext(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
    );

// ============================================================================
// CONTEXT STATE FUNCTIONS
// ============================================================================

/**
 * @brief Invalidate stream context after file write.
 *
 * Marks the file as modified and clears scan state to trigger rescan on
 * next access. Thread-safe - acquires exclusive lock internally.
 *
 * Actions:
 * 1. Acquire exclusive lock
 * 2. Set IsModified = TRUE
 * 3. Set IsScanned = FALSE
 * 4. Set HashValid = FALSE
 * 5. Increment WriteCount (atomic, inside lock)
 * 6. Release lock
 *
 * @param Context  The context to invalidate (NULL is handled gracefully)
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowInvalidateStreamContext(
    _In_opt_ PSHADOW_STREAM_CONTEXT Context
    );

/**
 * @brief Set the scan verdict for a stream context.
 *
 * Updates verdict, scan time, file size, and clears modification flags.
 * Thread-safe - acquires exclusive lock internally.
 *
 * Actions:
 * 1. Acquire exclusive lock
 * 2. Set Verdict = provided verdict
 * 3. Set IsScanned = TRUE
 * 4. Set IsModified = FALSE
 * 5. Set ScanInProgress = FALSE
 * 6. Update ScanTime to current time
 * 7. Capture ScanFileSize
 * 8. Release lock
 *
 * @param Context   The context to update (NULL is handled gracefully)
 * @param Verdict   The scan verdict to set
 * @param FileSize  The current file size (captured for change detection)
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowSetStreamVerdict(
    _In_opt_ PSHADOW_STREAM_CONTEXT Context,
    _In_ SHADOWSTRIKE_SCAN_VERDICT Verdict,
    _In_ LONGLONG FileSize
    );

/**
 * @brief Mark scan as in progress to prevent re-scan loops.
 *
 * Thread-safe - acquires exclusive lock internally.
 *
 * @param Context  The context to update
 *
 * @return TRUE if scan was started (caller should proceed with scan)
 *         FALSE if scan was already in progress or context unavailable
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
BOOLEAN
ShadowMarkScanInProgress(
    _In_opt_ PSHADOW_STREAM_CONTEXT Context
    );

/**
 * @brief Check if a file needs rescanning.
 *
 * Returns TRUE if:
 * - Context is NULL (defensive - assume scan needed)
 * - File has never been scanned (IsScanned == FALSE)
 * - File was modified since last scan (IsModified == TRUE)
 * - Cached verdict has expired (based on CacheTTL)
 *
 * Returns FALSE if:
 * - Scan is already in progress (prevents re-entry)
 * - Context is in teardown
 *
 * Thread-safe - acquires shared lock internally.
 *
 * @param Context   The context to check (NULL returns TRUE)
 * @param CacheTTL  Cache time-to-live in seconds (0 = no expiry check)
 *
 * @return TRUE if rescan is needed, FALSE otherwise
 */
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ShadowShouldRescan(
    _In_opt_ PSHADOW_STREAM_CONTEXT Context,
    _In_ ULONG CacheTTL
    );

/**
 * @brief Set cached file hash in context.
 *
 * Thread-safe - acquires exclusive lock internally.
 *
 * @param Context  The context to update
 * @param Hash     SHA-256 hash bytes (SHADOW_SHA256_HASH_SIZE bytes)
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowSetStreamContextHash(
    _In_opt_ PSHADOW_STREAM_CONTEXT Context,
    _In_reads_(SHADOW_SHA256_HASH_SIZE) const UCHAR* Hash
    );

/**
 * @brief Get current telemetry snapshot.
 *
 * Returns a copy of current telemetry counters. Thread-safe.
 *
 * @param Telemetry  [out] Receives telemetry data
 */
VOID
ShadowGetStreamContextTelemetry(
    _Out_ PSHADOW_STREAM_CONTEXT_TELEMETRY Telemetry
    );

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_STREAM_CONTEXT_H
