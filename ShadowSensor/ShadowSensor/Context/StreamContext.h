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
 * - All fields protected by ERESOURCE lock (acquired via Shadow*Lock functions)
 * - Atomic counters (WriteCount) use InterlockedIncrement for lock-free updates
 * - ERESOURCE must be acquired at PASSIVE_LEVEL only
 *
 * Memory Model:
 * - Context structure managed by Filter Manager (FltAllocateContext/FltReleaseContext)
 * - FileName.Buffer separately allocated from PagedPool, freed in cleanup callback
 * - ERESOURCE must be deleted in cleanup callback before Filter Manager frees context
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0
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
 *        Defensive limit to prevent excessive allocations from corrupted data.
 *        MAX_PATH * sizeof(WCHAR) * 2 = 520 * 2 = 1040, rounded up.
 */
#define SHADOW_MAX_FILENAME_LENGTH  (32768)

/**
 * @brief SHA-256 hash size in bytes.
 */
#define SHADOW_SHA256_HASH_SIZE     (32)

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
 * 1. ALL field access MUST be protected by the Resource lock
 * 2. Use ShadowAcquireStreamContextShared() for read-only access
 * 3. Use ShadowAcquireStreamContextExclusive() for modifications
 * 4. WriteCount uses InterlockedIncrement for lock-free atomic updates
 * 5. Resource lock MUST be acquired at IRQL == PASSIVE_LEVEL only
 * 6. NEVER mix atomic and non-atomic access to the same field
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
 * 3. ExInitializeResourceLite (initialize lock)
 * 4. Set ResourceInitialized = TRUE
 * 5. FltSetStreamContext (attach to file)
 * 6. ShadowInitializeStreamContextFileInfo (populate file info)
 */
typedef struct _SHADOW_STREAM_CONTEXT {

    // =========================================================================
    // Synchronization (MUST BE FIRST for alignment)
    // =========================================================================

    /**
     * @brief ERESOURCE lock for thread-safe access to all context fields.
     *
     * CRITICAL: Must be initialized with ExInitializeResourceLite before use.
     * CRITICAL: Must be deleted with ExDeleteResourceLite in cleanup callback.
     * CRITICAL: Can only be acquired at IRQL == PASSIVE_LEVEL.
     */
    ERESOURCE Resource;

    /**
     * @brief TRUE if Resource was successfully initialized.
     *
     * CRITICAL: Must check this before ANY Resource operation to prevent
     * BSOD from operating on uninitialized ERESOURCE. Set to TRUE only
     * after ExInitializeResourceLite succeeds. Set to FALSE in cleanup
     * after ExDeleteResourceLite.
     */
    BOOLEAN ResourceInitialized;

    /**
     * @brief Reserved padding for alignment.
     */
    BOOLEAN Reserved1[7];

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
     * This is the ONLY field that uses atomic operations.
     */
    volatile LONG WriteCount;

    /**
     * @brief Reserved padding for alignment.
     */
    ULONG Reserved4;

    /**
     * @brief File size at last scan (for change detection).
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
 * CRITICAL: Must be called at IRQL == PASSIVE_LEVEL.
 * CRITICAL: Must call ShadowReleaseStreamContext() to release.
 *
 * @param Context  The context to lock (must not be NULL, must be initialized)
 *
 * @return TRUE if lock acquired successfully
 *         FALSE if context is NULL or not initialized (caller should abort)
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
BOOLEAN
ShadowAcquireStreamContextShared(
    _In_ PSHADOW_STREAM_CONTEXT Context
    );

/**
 * @brief Acquire stream context lock for exclusive (read-write) access.
 *
 * CRITICAL: Must be called at IRQL == PASSIVE_LEVEL.
 * CRITICAL: Must call ShadowReleaseStreamContext() to release.
 *
 * @param Context  The context to lock (must not be NULL, must be initialized)
 *
 * @return TRUE if lock acquired successfully
 *         FALSE if context is NULL or not initialized (caller should abort)
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
BOOLEAN
ShadowAcquireStreamContextExclusive(
    _In_ PSHADOW_STREAM_CONTEXT Context
    );

/**
 * @brief Release stream context lock (shared or exclusive).
 *
 * CRITICAL: Must be called after ShadowAcquireStreamContext*().
 * CRITICAL: Must be called at IRQL == PASSIVE_LEVEL.
 *
 * @param Context  The context to unlock
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
 * 3. Initialize ERESOURCE lock
 * 4. FltSetStreamContext with FLT_SET_CONTEXT_KEEP_IF_EXISTS
 * 5. If race occurred (STATUS_FLT_CONTEXT_ALREADY_DEFINED):
 *    - Release our unused context
 *    - Return the winner's context
 * 6. Otherwise initialize file info and return our new context
 *
 * @param Instance    Filter instance (must not be NULL)
 * @param FileObject  File object (must not be NULL)
 * @param Context     [out] Receives context pointer (caller must call FltReleaseContext)
 *
 * @return STATUS_SUCCESS on success
 *         STATUS_INVALID_PARAMETER if parameters are NULL
 *         STATUS_INSUFFICIENT_RESOURCES if allocation fails
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
 * 1. Delete ERESOURCE (if initialized)
 * 2. Free FileName.Buffer (if allocated)
 *
 * CRITICAL: Do NOT call ExFreePool on the context pointer - Filter Manager
 * owns and frees the context structure itself.
 *
 * @param Context      The context being freed (may be NULL - handle gracefully)
 * @param ContextType  Type of context (FLT_STREAM_CONTEXT)
 */
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
 * 1. Set IsModified = TRUE
 * 2. Set IsScanned = FALSE
 * 3. Set HashValid = FALSE
 * 4. Increment WriteCount (atomic)
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
 * Updates verdict, scan time, and clears modification flags.
 * Thread-safe - acquires exclusive lock internally.
 *
 * Actions:
 * 1. Set Verdict = provided verdict
 * 2. Set IsScanned = TRUE
 * 3. Set IsModified = FALSE
 * 4. Set ScanInProgress = FALSE
 * 5. Update ScanTime to current time
 *
 * @param Context  The context to update (NULL is handled gracefully)
 * @param Verdict  The scan verdict to set
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowSetStreamVerdict(
    _In_opt_ PSHADOW_STREAM_CONTEXT Context,
    _In_ SHADOWSTRIKE_SCAN_VERDICT Verdict
    );

/**
 * @brief Mark scan as in progress to prevent re-scan loops.
 *
 * Thread-safe - acquires exclusive lock internally.
 *
 * @param Context  The context to update
 *
 * @return TRUE if scan was started (caller should proceed with scan)
 *         FALSE if scan was already in progress (caller should skip)
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
 * - Scan is already in progress (returns FALSE to prevent re-entry)
 * - Cached verdict has expired (based on CacheTTL)
 *
 * Thread-safe - acquires shared lock internally.
 *
 * @param Context   The context to check (NULL handled gracefully)
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
 * @brief Initialize file name and ID in context.
 *
 * Queries and caches file name (normalized path) and NTFS FileID for
 * efficient lookups. Should be called after context creation and attachment.
 *
 * Thread-safe - acquires exclusive lock internally.
 *
 * @param Context      The context to initialize (must not be NULL)
 * @param Instance     Filter instance for queries (must not be NULL)
 * @param FileObject   File object for queries (must not be NULL)
 *
 * @return STATUS_SUCCESS on success (partial success still returns SUCCESS)
 *         STATUS_INVALID_PARAMETER if any parameter is NULL
 *
 * @note This function continues even if individual queries fail.
 *       Check FileName.Buffer and FileId.QuadPart to verify what was populated.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowInitializeStreamContextFileInfo(
    _In_ PSHADOW_STREAM_CONTEXT Context,
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject
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

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_STREAM_CONTEXT_H
