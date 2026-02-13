/*++
===============================================================================
ShadowStrike NGAV - RANSOMWARE FILE BACKUP/ROLLBACK ENGINE
===============================================================================

@file FileBackupEngine.h
@brief Pre-write copy-on-write backup engine for ransomware rollback.

Provides automated file backup before destructive write operations to enable
complete rollback when ransomware is detected. Designed for SE Labs / MITRE
ATT&CK T1486 (Data Encrypted for Impact) evaluation with 100% recovery target.

Architecture:
  - PreWrite callback captures original file content before first modification
  - Copy-on-first-write: only the first write per (file, process) pair triggers backup
  - Backups stored in a dedicated directory on the volume root
  - Per-process tracking enables surgical rollback of all changes by a single process
  - LRU eviction ensures bounded disk usage
  - Rollback restores all files modified by a given process to their pre-modification state

Integration Points:
  - ShadowStrikePreWrite → FbePreWriteBackup()
  - ShadowStrikePreSetInformation → FbePreSetInfoBackup()
  - BehaviorEngine ransomware verdict → FbeRollbackProcess()
  - DriverEntry → FbeInitialize() / FbeShutdown()

MITRE ATT&CK Coverage:
  - T1486: Data Encrypted for Impact (ransomware recovery)
  - T1485: Data Destruction (file destruction recovery)
  - T1490: Inhibit System Recovery (shadow copy alternative)

@author ShadowStrike Security Team
@version 1.0.0
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#pragma once

#include <fltKernel.h>

// ============================================================================
// MODULE POOL TAGS
// ============================================================================

#define FBE_POOL_TAG            'eBFS'  // SFBe - File Backup Engine
#define FBE_ENTRY_POOL_TAG      'nBFS'  // SFBn - Backup Entry
#define FBE_PATH_POOL_TAG       'pBFS'  // SFBp - Path Buffer
#define FBE_IO_POOL_TAG         'iBFS'  // SFBi - I/O Buffer
#define FBE_ROLLBACK_POOL_TAG   'rBFS'  // SFBr - Rollback

// ============================================================================
// CONFIGURATION CONSTANTS
// ============================================================================

#define FBE_MAX_BACKUP_SIZE_DEFAULT     ((LONGLONG)10 * 1024 * 1024 * 1024)  // 10 GB
#define FBE_MAX_SINGLE_FILE_SIZE        ((LONGLONG)100 * 1024 * 1024)        // 100 MB
#define FBE_MAX_TRACKED_PROCESSES       1024
#define FBE_MAX_ENTRIES_PER_PROCESS     4096
#define FBE_MAX_TOTAL_ENTRIES           65536
#define FBE_HASH_BUCKET_COUNT           256
#define FBE_IO_BUFFER_SIZE              (64 * 1024)     // 64 KB copy buffer
#define FBE_BACKUP_DIR_NAME             L"\\ShadowStrikeBackup"
#define FBE_BACKUP_DIR_NAME_LEN         (sizeof(FBE_BACKUP_DIR_NAME) - sizeof(WCHAR))
#define FBE_MAX_PATH_LENGTH             520             // chars

// ============================================================================
// BACKUP ENTRY STATES
// ============================================================================

typedef enum _FBE_ENTRY_STATE {
    FbeEntryState_Free = 0,
    FbeEntryState_Pending,          // Backup in progress
    FbeEntryState_Valid,            // Backup complete, can rollback
    FbeEntryState_RolledBack,       // Already rolled back
    FbeEntryState_Evicted,          // LRU evicted
    FbeEntryState_Failed            // Backup failed
} FBE_ENTRY_STATE;

// ============================================================================
// BACKUP OPERATION TYPE
// ============================================================================

typedef enum _FBE_OPERATION_TYPE {
    FbeOp_Write = 0,                // IRP_MJ_WRITE modification
    FbeOp_Rename,                   // FileRenameInformation
    FbeOp_Delete,                   // FileDispositionInformation
    FbeOp_Truncate,                 // FileEndOfFileInformation (size reduction)
    FbeOp_SetAllocation             // FileAllocationInformation
} FBE_OPERATION_TYPE;

// ============================================================================
// ROLLBACK RESULT
// ============================================================================

typedef enum _FBE_ROLLBACK_RESULT {
    FbeRollback_Success = 0,
    FbeRollback_PartialSuccess,     // Some files restored
    FbeRollback_NoBackupsFound,
    FbeRollback_IOError,
    FbeRollback_ShuttingDown,
    FbeRollback_InvalidProcess
} FBE_ROLLBACK_RESULT;

// ============================================================================
// BACKUP ENTRY
// ============================================================================

typedef struct _FBE_BACKUP_ENTRY {

    //
    // Linkage: per-process list and global hash chain
    //
    LIST_ENTRY ProcessLink;         // Links into per-process list
    LIST_ENTRY HashLink;            // Links into hash bucket chain
    LIST_ENTRY LruLink;             // Links into global LRU list

    //
    // State (accessed atomically)
    //
    volatile LONG State;            // FBE_ENTRY_STATE

    //
    // Identity
    //
    HANDLE ProcessId;               // Owning process
    FBE_OPERATION_TYPE OperationType;
    LARGE_INTEGER Timestamp;        // Backup creation time

    //
    // Original file information
    //
    UNICODE_STRING OriginalPath;    // Full normalized path
    WCHAR OriginalPathBuffer[FBE_MAX_PATH_LENGTH];
    LARGE_INTEGER OriginalFileSize;

    //
    // Backup file information
    //
    UNICODE_STRING BackupPath;      // Path to backup copy
    WCHAR BackupPathBuffer[FBE_MAX_PATH_LENGTH];
    LARGE_INTEGER BackupFileSize;

    //
    // Rename tracking (for FbeOp_Rename)
    //
    UNICODE_STRING NewName;
    WCHAR NewNameBuffer[FBE_MAX_PATH_LENGTH];

    //
    // Volume information
    //
    ULONG VolumeSerial;

} FBE_BACKUP_ENTRY, *PFBE_BACKUP_ENTRY;

// ============================================================================
// PER-PROCESS TRACKING
// ============================================================================

typedef struct _FBE_PROCESS_TRACKER {

    LIST_ENTRY Link;                // Links into global process list
    HANDLE ProcessId;

    //
    // Per-process backup entries
    //
    LIST_ENTRY BackupEntries;       // List of FBE_BACKUP_ENTRY.ProcessLink
    volatile LONG EntryCount;
    EX_PUSH_LOCK Lock;

    //
    // Per-process statistics
    //
    volatile LONG64 TotalBytesBackedUp;
    volatile LONG64 FilesBackedUp;
    volatile LONG64 FilesRolledBack;

} FBE_PROCESS_TRACKER, *PFBE_PROCESS_TRACKER;

// ============================================================================
// STATISTICS
// ============================================================================

typedef struct _FBE_STATISTICS {

    volatile LONG64 TotalBackupRequests;
    volatile LONG64 BackupsCreated;
    volatile LONG64 BackupsSkippedDuplicate;    // Already backed up (CoW)
    volatile LONG64 BackupsSkippedSize;         // File too large
    volatile LONG64 BackupsSkippedExtension;    // System file skipped
    volatile LONG64 BackupsFailed;
    volatile LONG64 TotalBytesBackedUp;
    volatile LONG64 TotalBytesRolledBack;
    volatile LONG64 RollbackRequests;
    volatile LONG64 RollbacksSucceeded;
    volatile LONG64 RollbacksFailed;
    volatile LONG64 RollbackFilesRestored;
    volatile LONG64 EntriesEvicted;
    volatile LONG64 CurrentBackupDiskUsage;
    volatile LONG64 PeakBackupDiskUsage;

} FBE_STATISTICS, *PFBE_STATISTICS;

// ============================================================================
// CONFIGURATION
// ============================================================================

typedef struct _FBE_CONFIG {

    LONGLONG MaxTotalBackupSize;        // Maximum total disk usage
    LONGLONG MaxSingleFileSize;         // Maximum single file backup size
    ULONG MaxEntriesPerProcess;         // Max entries per process
    BOOLEAN EnableWriteBackup;          // Backup on IRP_MJ_WRITE
    BOOLEAN EnableRenameBackup;         // Backup on rename
    BOOLEAN EnableDeleteBackup;         // Backup on delete
    BOOLEAN EnableTruncateBackup;       // Backup on truncate

} FBE_CONFIG, *PFBE_CONFIG;

// ============================================================================
// PUBLIC API — LIFECYCLE
// ============================================================================

/**
 * @brief Initialize the file backup engine.
 *
 * Must be called at PASSIVE_LEVEL during driver initialization.
 * Creates backup directory, initializes hash table and tracking structures.
 *
 * @return STATUS_SUCCESS on success.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
FbeInitialize(VOID);

/**
 * @brief Shutdown the file backup engine.
 *
 * Drains outstanding operations, frees all backup entries, 
 * removes backup directory contents. Must be called at PASSIVE_LEVEL.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
FbeShutdown(VOID);

// ============================================================================
// PUBLIC API — BACKUP OPERATIONS
// ============================================================================

/**
 * @brief Create backup before a write operation.
 *
 * Called from ShadowStrikePreWrite. Implements copy-on-first-write:
 * only the first write to a file by a given process triggers a backup.
 *
 * @param[in] Data          Callback data with write parameters.
 * @param[in] FltObjects    Filter objects (instance, volume, file).
 * @param[in] FileName      Normalized file path.
 *
 * @return STATUS_SUCCESS if backup created or already exists.
 *         STATUS_FBE_SKIP if file should not be backed up.
 *         Failure NTSTATUS on I/O error.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
FbePreWriteBackup(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PCUNICODE_STRING FileName
    );

/**
 * @brief Create backup before a set-information operation (rename/delete/truncate).
 *
 * Called from ShadowStrikePreSetInformation.
 *
 * @param[in] Data          Callback data with set-info parameters.
 * @param[in] FltObjects    Filter objects.
 * @param[in] FileName      Normalized file path.
 * @param[in] OpType        Type of operation (rename, delete, truncate).
 *
 * @return STATUS_SUCCESS if backup created or already exists.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
FbePreSetInfoBackup(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PCUNICODE_STRING FileName,
    _In_ FBE_OPERATION_TYPE OpType
    );

// ============================================================================
// PUBLIC API — ROLLBACK OPERATIONS
// ============================================================================

/**
 * @brief Rollback all file modifications made by a specific process.
 *
 * Called when BehaviorEngine issues ransomware verdict. Restores all
 * backed-up files to their original state.
 *
 * @param[in] ProcessId     Process whose changes should be rolled back.
 * @param[out] FilesRestored  Optional: receives count of files restored.
 *
 * @return FBE_ROLLBACK_RESULT indicating outcome.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
FBE_ROLLBACK_RESULT
FbeRollbackProcess(
    _In_ HANDLE ProcessId,
    _Out_opt_ PULONG FilesRestored
    );

/**
 * @brief Commit (discard) backups for a process that has been cleared.
 *
 * Called when a process exits normally or is cleared by scan.
 * Frees backup storage for this process.
 *
 * @param[in] ProcessId     Process whose backups should be discarded.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
FbeCommitProcess(
    _In_ HANDLE ProcessId
    );

// ============================================================================
// PUBLIC API — QUERY
// ============================================================================

/**
 * @brief Get current backup engine statistics.
 *
 * @param[out] Statistics   Receives current statistics snapshot.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
FbeGetStatistics(
    _Out_ PFBE_STATISTICS Statistics
    );

/**
 * @brief Check if a process has any pending backups.
 *
 * @param[in] ProcessId     Process to query.
 *
 * @return TRUE if process has one or more backup entries.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
FbeHasBackups(
    _In_ HANDLE ProcessId
    );

#define STATUS_FBE_SKIP     ((NTSTATUS)0xE0FB0001L)
