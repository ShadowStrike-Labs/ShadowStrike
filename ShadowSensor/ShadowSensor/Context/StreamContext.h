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
 * @author ShadowStrike Security Team
 * @version 1.0.0
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
#include "../../Shared/VerdictTypes.h"

// ============================================================================
// POOL TAGS
// ============================================================================

/**
 * @brief Pool tag for stream context allocations: 'cSSx' = ShadowStrike Context
 */
#define SHADOW_CONTEXT_TAG 'cSSx'

/**
 * @brief Pool tag for context string buffers
 */
#define SHADOW_CONTEXT_STRING_TAG 'sSSc'

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
 * Thread Safety: Protected by the Resource lock. All field access must
 * be synchronized using ExAcquireResourceSharedLite/ExclusiveLite.
 *
 * Memory Management:
 * - The structure itself is managed by Filter Manager (via FltAllocateContext)
 * - FileName.Buffer is separately allocated and must be freed in cleanup
 * - Resource must be deleted in cleanup callback
 */
typedef struct _SHADOW_STREAM_CONTEXT {

    //
    // Synchronization
    //

    /// @brief Synchronization lock for thread-safe access to this context
    ERESOURCE Resource;

    //
    // File Identity
    //

    /// @brief Cached file name to avoid repeated FLT queries
    UNICODE_STRING FileName;

    /// @brief Unique 64-bit File ID (NTFS FileId) - stable across renames
    LARGE_INTEGER FileId;

    /// @brief Volume serial number for multi-volume disambiguation
    ULONG VolumeSerial;

    //
    // Scan State
    //

    /// @brief TRUE if file has been scanned at least once
    BOOLEAN IsScanned;

    /// @brief Last scan verdict (Clean, Malware, Suspicious, etc.)
    SHADOWSTRIKE_SCAN_VERDICT Verdict;

    /// @brief Timestamp of last scan (KeQuerySystemTime)
    LARGE_INTEGER ScanTime;

    //
    // Modification Tracking
    //

    /// @brief TRUE if file was written to since last scan
    BOOLEAN IsModified;

    /// @brief Number of write operations performed
    ULONG WriteCount;

    /// @brief Size of file when last scanned
    LARGE_INTEGER ScanFileSize;

    //
    // Hash Cache (Optional)
    //

    /// @brief Cached file hash (SHA256)
    UCHAR FileHash[32];

    /// @brief TRUE if FileHash contains valid data
    BOOLEAN HashValid;

    //
    // Flags
    //

    /// @brief TRUE if file is currently being scanned (prevent re-scan loops)
    BOOLEAN ScanInProgress;

    /// @brief TRUE if Resource was successfully initialized (CRITICAL for cleanup)
    BOOLEAN ResourceInitialized;

    /// @brief Reserved for future use
    BOOLEAN Reserved[5];

} SHADOW_STREAM_CONTEXT, *PSHADOW_STREAM_CONTEXT;

// ============================================================================
// FUNCTION PROTOTYPES
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
 * 2. Allocate new context
 * 3. FltSetStreamContext with FLT_SET_CONTEXT_KEEP_IF_EXISTS
 * 4. If race occurred (STATUS_FLT_CONTEXT_ALREADY_DEFINED):
 *    - Release our unused context
 *    - Return the winner's context
 * 5. Otherwise return our new context
 *
 * @param Instance    Filter instance
 * @param FileObject  File object
 * @param Context     [out] Receives context pointer (caller must release)
 *
 * @return STATUS_SUCCESS on success
 *         STATUS_INSUFFICIENT_RESOURCES if allocation fails
 *         Other NTSTATUS codes from Filter Manager
 *
 * @note Caller MUST call FltReleaseContext when done
 */
NTSTATUS
ShadowGetOrSetStreamContext(
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
 * CRITICAL: Must delete ERESOURCE to prevent zombie locks.
 *
 * @param Context      The context being freed
 * @param ContextType  Type of context (FLT_STREAM_CONTEXT)
 */
VOID
ShadowCleanupStreamContext(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
    );

/**
 * @brief Invalidate stream context after file write.
 *
 * Marks the file as modified and clears scan state to trigger rescan.
 * Thread-safe - acquires exclusive lock.
 *
 * @param Context The context to invalidate
 */
VOID
ShadowInvalidateStreamContext(
    _In_ PSHADOW_STREAM_CONTEXT Context
    );

/**
 * @brief Set the scan verdict for a stream context.
 *
 * Updates verdict, scan time, and clears modification flags.
 * Thread-safe - acquires exclusive lock.
 *
 * @param Context The context to update
 * @param Verdict The scan verdict
 */
VOID
ShadowSetStreamVerdict(
    _In_ PSHADOW_STREAM_CONTEXT Context,
    _In_ SHADOWSTRIKE_SCAN_VERDICT Verdict
    );

/**
 * @brief Check if a file needs rescanning.
 *
 * Returns TRUE if:
 * - File has never been scanned
 * - File was modified since last scan
 * - Cached verdict has expired (TTL-based)
 *
 * Thread-safe - acquires shared lock.
 *
 * @param Context     The context to check
 * @param CacheTTL    Cache time-to-live in seconds (0 = no expiry)
 *
 * @return TRUE if rescan is needed, FALSE otherwise
 */
BOOLEAN
ShadowShouldRescan(
    _In_ PSHADOW_STREAM_CONTEXT Context,
    _In_ ULONG CacheTTL
    );

/**
 * @brief Initialize file name and ID in context.
 *
 * Queries and caches file name and FileID for efficient lookups.
 * Must be called after context creation.
 *
 * Thread-safe - acquires exclusive lock internally.
 *
 * @param Context     The context to initialize
 * @param Instance    Filter instance
 * @param FileObject  File object
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
ShadowInitializeStreamContextFileInfo(
    _In_ PSHADOW_STREAM_CONTEXT Context,
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject
    );

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_STREAM_CONTEXT_H
