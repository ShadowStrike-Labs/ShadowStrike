// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/*++
===============================================================================
ShadowStrike NGAV - RANSOMWARE FILE BACKUP/ROLLBACK ENGINE IMPLEMENTATION
===============================================================================

@file FileBackupEngine.c
@brief Copy-on-first-write backup engine enabling full ransomware rollback.

Implementation Strategy:
  1. PreWrite/PreSetInfo callbacks invoke FbePreWriteBackup/FbePreSetInfoBackup
  2. On first modification by a process, original file content is copied to backup dir
  3. Per-process tracker maintains list of all backed-up files
  4. On ransomware verdict, FbeRollbackProcess restores all files from backup
  5. On clean process exit, FbeCommitProcess discards backups and reclaims space

Copy-on-First-Write Semantics:
  - Hash table keyed by (ProcessId, FilePath) prevents duplicate backups
  - Only the first modification triggers I/O; subsequent writes are no-ops
  - Backup file names use monotonic counter for uniqueness

Storage Management:
  - Total backup size capped at configurable limit (default 10 GB)
  - LRU eviction removes oldest entries when capacity exceeded
  - System/binary files excluded from backup

Performance Safeguards:
  - Backup I/O performed at PASSIVE_LEVEL only
  - Lookaside list for entry allocation
  - EX_PUSH_LOCK per hash bucket for fine-grained concurrency
  - Rundown reference for safe shutdown draining

@author ShadowStrike Security Team
@version 1.0.0
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#include "FileBackupEngine.h"
#include "../../Core/Globals.h"
#include "../../Utilities/FileUtils.h"
#include "../../Behavioral/BehaviorEngine.h"
#include <ntstrsafe.h>

// ============================================================================
// PRIVATE TYPES
// ============================================================================

//
// Hash bucket for (ProcessId, FilePath) -> BackupEntry lookup
//
typedef struct _FBE_HASH_BUCKET {
    LIST_ENTRY      Head;
    EX_PUSH_LOCK    Lock;
    volatile LONG   Count;
} FBE_HASH_BUCKET, *PFBE_HASH_BUCKET;

//
// Global engine state
//
typedef struct _FBE_ENGINE_STATE {

    //
    // Lifecycle
    //
    volatile LONG       State;          // 0=uninit, 1=initializing, 2=ready, 3=shutdown
    EX_RUNDOWN_REF      RundownRef;

    //
    // Hash table: (ProcessId XOR PathHash) -> bucket -> entries
    //
    FBE_HASH_BUCKET     Buckets[FBE_HASH_BUCKET_COUNT];

    //
    // Global LRU list (oldest first)
    //
    LIST_ENTRY          LruHead;
    EX_PUSH_LOCK        LruLock;
    volatile LONG       TotalEntryCount;

    //
    // Per-process tracker table: hash(ProcessId) -> linked list
    //
    FBE_HASH_BUCKET     ProcessBuckets[64];

    //
    // Allocation
    //
    NPAGED_LOOKASIDE_LIST EntryLookaside;
    NPAGED_LOOKASIDE_LIST TrackerLookaside;

    //
    // Backup file naming
    //
    volatile LONG64     NextBackupId;

    //
    // Configuration
    //
    FBE_CONFIG          Config;

    //
    // Statistics
    //
    FBE_STATISTICS      Stats;

} FBE_ENGINE_STATE, *PFBE_ENGINE_STATE;

// ============================================================================
// GLOBAL STATE
// ============================================================================

static FBE_ENGINE_STATE g_FbeState;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static ULONG
FbepHashPath(
    _In_ PCUNICODE_STRING Path
    );

static ULONG
FbepComputeBucketIndex(
    _In_ HANDLE ProcessId,
    _In_ PCUNICODE_STRING FilePath
    );

static ULONG
FbepProcessBucketIndex(
    _In_ HANDLE ProcessId
    );

_IRQL_requires_(PASSIVE_LEVEL)
static PFBE_BACKUP_ENTRY
FbepFindEntry(
    _In_ HANDLE ProcessId,
    _In_ PCUNICODE_STRING FilePath,
    _In_ ULONG BucketIndex
    );

_IRQL_requires_(PASSIVE_LEVEL)
static PFBE_BACKUP_ENTRY
FbepAllocateEntry(VOID);

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
FbepFreeEntry(
    _In_ PFBE_BACKUP_ENTRY Entry
    );

_IRQL_requires_(PASSIVE_LEVEL)
static PFBE_PROCESS_TRACKER
FbepFindOrCreateTracker(
    _In_ HANDLE ProcessId
    );

_IRQL_requires_(PASSIVE_LEVEL)
static PFBE_PROCESS_TRACKER
FbepFindTracker(
    _In_ HANDLE ProcessId
    );

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
FbepFreeTracker(
    _In_ PFBE_PROCESS_TRACKER Tracker
    );

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
FbepCopyFileToBackup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PCUNICODE_STRING SourcePath,
    _In_ PCUNICODE_STRING BackupPath,
    _Out_ PLARGE_INTEGER BytesCopied
    );

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
FbepRestoreFileFromBackup(
    _In_ PFBE_BACKUP_ENTRY Entry
    );

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
FbepDeleteBackupFile(
    _In_ PCUNICODE_STRING BackupPath
    );

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
FbepGenerateBackupPath(
    _In_ PCUNICODE_STRING OriginalPath,
    _Out_ PUNICODE_STRING BackupPath,
    _In_ PWCHAR BackupBuffer,
    _In_ USHORT BackupBufferSize
    );

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
FbepEvictLruEntries(
    _In_ LONGLONG BytesNeeded
    );

static BOOLEAN
FbepShouldBackup(
    _In_ PCUNICODE_STRING FileName
    );

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
FbepGetFileSize(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PLARGE_INTEGER FileSize
    );

_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
FbepEnterOperation(VOID);

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
FbepLeaveOperation(VOID);

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
FbepEnsureBackupDirectory(
    _In_ PCUNICODE_STRING BackupPath
    );

//
// Re-entrancy sentinel: set via IoSetTopLevelIrp during restore I/O
// to prevent PreWrite from backing up our own restore writes.
//
#define FBE_ROLLBACK_SENTINEL   ((PIRP)(ULONG_PTR)0xF8E80118)

// ============================================================================
// SECTION PLACEMENT
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, FbeInitialize)
#pragma alloc_text(PAGE, FbeShutdown)
#pragma alloc_text(PAGE, FbePreWriteBackup)
#pragma alloc_text(PAGE, FbePreSetInfoBackup)
#pragma alloc_text(PAGE, FbeRollbackProcess)
#pragma alloc_text(PAGE, FbeCommitProcess)
#pragma alloc_text(PAGE, FbepFindEntry)
#pragma alloc_text(PAGE, FbepAllocateEntry)
#pragma alloc_text(PAGE, FbepFreeEntry)
#pragma alloc_text(PAGE, FbepFindOrCreateTracker)
#pragma alloc_text(PAGE, FbepFindTracker)
#pragma alloc_text(PAGE, FbepFreeTracker)
#pragma alloc_text(PAGE, FbepCopyFileToBackup)
#pragma alloc_text(PAGE, FbepRestoreFileFromBackup)
#pragma alloc_text(PAGE, FbepDeleteBackupFile)
#pragma alloc_text(PAGE, FbepGenerateBackupPath)
#pragma alloc_text(PAGE, FbepEvictLruEntries)
#pragma alloc_text(PAGE, FbepShouldBackup)
#pragma alloc_text(PAGE, FbepGetFileSize)
#pragma alloc_text(PAGE, FbepEnterOperation)
#pragma alloc_text(PAGE, FbepLeaveOperation)
#pragma alloc_text(PAGE, FbepEnsureBackupDirectory)
#endif

// ============================================================================
// FILE EXTENSION CLASSIFICATION
// ============================================================================

//
// Extensions worth backing up (user data â€” ransomware targets)
//
static const UNICODE_STRING g_BackupExtensions[] = {
    //
    // SORTED ALPHABETICALLY (case-insensitive) for binary search.
    // Do NOT reorder â€” FbepShouldBackup depends on sorted order.
    //
    RTL_CONSTANT_STRING(L".7z"),    RTL_CONSTANT_STRING(L".accdb"),
    RTL_CONSTANT_STRING(L".ai"),    RTL_CONSTANT_STRING(L".avi"),
    RTL_CONSTANT_STRING(L".bak"),   RTL_CONSTANT_STRING(L".bmp"),
    RTL_CONSTANT_STRING(L".c"),     RTL_CONSTANT_STRING(L".cfg"),
    RTL_CONSTANT_STRING(L".conf"),  RTL_CONSTANT_STRING(L".cpp"),
    RTL_CONSTANT_STRING(L".crt"),   RTL_CONSTANT_STRING(L".cs"),
    RTL_CONSTANT_STRING(L".css"),   RTL_CONSTANT_STRING(L".csv"),
    RTL_CONSTANT_STRING(L".db"),    RTL_CONSTANT_STRING(L".dbf"),
    RTL_CONSTANT_STRING(L".doc"),   RTL_CONSTANT_STRING(L".docx"),
    RTL_CONSTANT_STRING(L".dwg"),   RTL_CONSTANT_STRING(L".dxf"),
    RTL_CONSTANT_STRING(L".flac"),  RTL_CONSTANT_STRING(L".gif"),
    RTL_CONSTANT_STRING(L".go"),    RTL_CONSTANT_STRING(L".gz"),
    RTL_CONSTANT_STRING(L".h"),     RTL_CONSTANT_STRING(L".hpp"),
    RTL_CONSTANT_STRING(L".htm"),   RTL_CONSTANT_STRING(L".html"),
    RTL_CONSTANT_STRING(L".ini"),   RTL_CONSTANT_STRING(L".iso"),
    RTL_CONSTANT_STRING(L".java"),  RTL_CONSTANT_STRING(L".jpeg"),
    RTL_CONSTANT_STRING(L".jpg"),   RTL_CONSTANT_STRING(L".js"),
    RTL_CONSTANT_STRING(L".json"),  RTL_CONSTANT_STRING(L".key"),
    RTL_CONSTANT_STRING(L".kt"),    RTL_CONSTANT_STRING(L".log"),
    RTL_CONSTANT_STRING(L".mdb"),   RTL_CONSTANT_STRING(L".mkv"),
    RTL_CONSTANT_STRING(L".mp3"),   RTL_CONSTANT_STRING(L".mp4"),
    RTL_CONSTANT_STRING(L".odp"),   RTL_CONSTANT_STRING(L".ods"),
    RTL_CONSTANT_STRING(L".odt"),   RTL_CONSTANT_STRING(L".p12"),
    RTL_CONSTANT_STRING(L".pdf"),   RTL_CONSTANT_STRING(L".pem"),
    RTL_CONSTANT_STRING(L".pfx"),   RTL_CONSTANT_STRING(L".php"),
    RTL_CONSTANT_STRING(L".png"),   RTL_CONSTANT_STRING(L".ppt"),
    RTL_CONSTANT_STRING(L".pptx"),  RTL_CONSTANT_STRING(L".psd"),
    RTL_CONSTANT_STRING(L".py"),    RTL_CONSTANT_STRING(L".rar"),
    RTL_CONSTANT_STRING(L".rb"),    RTL_CONSTANT_STRING(L".rs"),
    RTL_CONSTANT_STRING(L".rtf"),   RTL_CONSTANT_STRING(L".sldasm"),
    RTL_CONSTANT_STRING(L".sldprt"),RTL_CONSTANT_STRING(L".sql"),
    RTL_CONSTANT_STRING(L".sqlite"),RTL_CONSTANT_STRING(L".step"),
    RTL_CONSTANT_STRING(L".stl"),   RTL_CONSTANT_STRING(L".svg"),
    RTL_CONSTANT_STRING(L".swift"), RTL_CONSTANT_STRING(L".tar"),
    RTL_CONSTANT_STRING(L".tif"),   RTL_CONSTANT_STRING(L".tiff"),
    RTL_CONSTANT_STRING(L".ts"),    RTL_CONSTANT_STRING(L".txt"),
    RTL_CONSTANT_STRING(L".vhd"),   RTL_CONSTANT_STRING(L".vhdx"),
    RTL_CONSTANT_STRING(L".vmdk"),  RTL_CONSTANT_STRING(L".wav"),
    RTL_CONSTANT_STRING(L".xls"),   RTL_CONSTANT_STRING(L".xlsx"),
    RTL_CONSTANT_STRING(L".xml"),   RTL_CONSTANT_STRING(L".yaml"),
    RTL_CONSTANT_STRING(L".yml"),   RTL_CONSTANT_STRING(L".zip"),
};

#define FBE_BACKUP_EXTENSION_COUNT \
    (sizeof(g_BackupExtensions) / sizeof(g_BackupExtensions[0]))

// ============================================================================
// LIFECYCLE IMPLEMENTATION
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
FbeInitialize(VOID)
{
    LONG PreviousState;

    PAGED_CODE();

    PreviousState = InterlockedCompareExchange(&g_FbeState.State, 1, 0);
    if (PreviousState != 0) {
        return (PreviousState == 2) ? STATUS_SUCCESS : STATUS_DEVICE_BUSY;
    }

    //
    // Initialize rundown reference
    //
    ExInitializeRundownProtection(&g_FbeState.RundownRef);

    //
    // Initialize hash buckets
    //
    for (ULONG i = 0; i < FBE_HASH_BUCKET_COUNT; i++) {
        InitializeListHead(&g_FbeState.Buckets[i].Head);
        FltInitializePushLock(&g_FbeState.Buckets[i].Lock);
        g_FbeState.Buckets[i].Count = 0;
    }

    //
    // Initialize process buckets
    //
    for (ULONG i = 0; i < 64; i++) {
        InitializeListHead(&g_FbeState.ProcessBuckets[i].Head);
        FltInitializePushLock(&g_FbeState.ProcessBuckets[i].Lock);
        g_FbeState.ProcessBuckets[i].Count = 0;
    }

    //
    // Initialize LRU list
    //
    InitializeListHead(&g_FbeState.LruHead);
    FltInitializePushLock(&g_FbeState.LruLock);
    g_FbeState.TotalEntryCount = 0;

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &g_FbeState.EntryLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(FBE_BACKUP_ENTRY),
        FBE_ENTRY_POOL_TAG,
        0
        );

    ExInitializeNPagedLookasideList(
        &g_FbeState.TrackerLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(FBE_PROCESS_TRACKER),
        FBE_POOL_TAG,
        0
        );

    //
    // Set default configuration
    //
    g_FbeState.Config.MaxTotalBackupSize = FBE_MAX_BACKUP_SIZE_DEFAULT;
    g_FbeState.Config.MaxSingleFileSize = FBE_MAX_SINGLE_FILE_SIZE;
    g_FbeState.Config.MaxEntriesPerProcess = FBE_MAX_ENTRIES_PER_PROCESS;
    g_FbeState.Config.EnableWriteBackup = TRUE;
    g_FbeState.Config.EnableRenameBackup = TRUE;
    g_FbeState.Config.EnableDeleteBackup = TRUE;
    g_FbeState.Config.EnableTruncateBackup = TRUE;

    //
    // Initialize backup ID counter
    //
    g_FbeState.NextBackupId = 0;

    //
    // Zero statistics
    //
    RtlZeroMemory(&g_FbeState.Stats, sizeof(FBE_STATISTICS));

    //
    // Transition to ready
    //
    InterlockedExchange(&g_FbeState.State, 2);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/FBE] File Backup Engine initialized "
               "(MaxBackup=%lld MB, MaxSingleFile=%lld MB)\n",
               g_FbeState.Config.MaxTotalBackupSize / (1024 * 1024),
               g_FbeState.Config.MaxSingleFileSize / (1024 * 1024));

    return STATUS_SUCCESS;
}


_IRQL_requires_(PASSIVE_LEVEL)
VOID
FbeShutdown(VOID)
{
    LIST_ENTRY *ListEntry;
    PFBE_PROCESS_TRACKER Tracker;

    PAGED_CODE();

    if (InterlockedCompareExchange(&g_FbeState.State, 3, 2) != 2) {
        return;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/FBE] Shutting down File Backup Engine...\n");

    //
    // Wait for outstanding operations to drain
    //
    ExWaitForRundownProtectionRelease(&g_FbeState.RundownRef);

    //
    // Free all process trackers and their entries.
    // Iterate ProcessBuckets (where trackers are actually stored)
    // instead of the never-populated ProcessList.
    //
    for (ULONG BucketIdx = 0; BucketIdx < 64; BucketIdx++) {
        FltAcquirePushLockExclusive(&g_FbeState.ProcessBuckets[BucketIdx].Lock);

        while (!IsListEmpty(&g_FbeState.ProcessBuckets[BucketIdx].Head)) {
            ListEntry = RemoveHeadList(&g_FbeState.ProcessBuckets[BucketIdx].Head);
            Tracker = CONTAINING_RECORD(ListEntry, FBE_PROCESS_TRACKER, Link);

            //
            // Free all entries owned by this tracker
            //
            while (!IsListEmpty(&Tracker->BackupEntries)) {
                LIST_ENTRY *EntryLink = RemoveHeadList(&Tracker->BackupEntries);
                PFBE_BACKUP_ENTRY Entry = CONTAINING_RECORD(
                    EntryLink, FBE_BACKUP_ENTRY, ProcessLink);

                //
                // Remove from LRU (entry may still be linked)
                //
                FltAcquirePushLockExclusive(&g_FbeState.LruLock);
                RemoveEntryList(&Entry->LruLink);
                FltReleasePushLock(&g_FbeState.LruLock);

                //
                // Remove from hash bucket
                //
                ULONG HashBucket = FbepComputeBucketIndex(
                    Entry->ProcessId, &Entry->OriginalPath);
                FltAcquirePushLockExclusive(&g_FbeState.Buckets[HashBucket].Lock);
                RemoveEntryList(&Entry->HashLink);
                InterlockedDecrement(&g_FbeState.Buckets[HashBucket].Count);
                FltReleasePushLock(&g_FbeState.Buckets[HashBucket].Lock);

                //
                // Delete backup file from disk
                //
                if (Entry->State == FbeEntryState_Valid) {
                    FbepDeleteBackupFile(&Entry->BackupPath);
                }

                FbepFreeEntry(Entry);
                InterlockedDecrement(&g_FbeState.TotalEntryCount);
            }

            FbepFreeTracker(Tracker);
        }

        g_FbeState.ProcessBuckets[BucketIdx].Count = 0;
        FltReleasePushLock(&g_FbeState.ProcessBuckets[BucketIdx].Lock);
    }

    //
    // Destroy lookaside lists
    //
    ExDeleteNPagedLookasideList(&g_FbeState.EntryLookaside);
    ExDeleteNPagedLookasideList(&g_FbeState.TrackerLookaside);

    //
    // Cleanup push locks
    //
    for (ULONG i = 0; i < FBE_HASH_BUCKET_COUNT; i++) {
        FltDeletePushLock(&g_FbeState.Buckets[i].Lock);
    }
    for (ULONG i = 0; i < 64; i++) {
        FltDeletePushLock(&g_FbeState.ProcessBuckets[i].Lock);
    }
    FltDeletePushLock(&g_FbeState.LruLock);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/FBE] Shutdown complete. "
               "Created=%lld, Restored=%lld, Evicted=%lld\n",
               g_FbeState.Stats.BackupsCreated,
               g_FbeState.Stats.RollbackFilesRestored,
               g_FbeState.Stats.EntriesEvicted);
}

// ============================================================================
// BACKUP OPERATIONS
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
FbePreWriteBackup(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PCUNICODE_STRING FileName
    )
{
    NTSTATUS Status;
    PFBE_BACKUP_ENTRY Entry;
    PFBE_PROCESS_TRACKER Tracker;
    ULONG BucketIndex;
    HANDLE ProcessId;
    LARGE_INTEGER FileSize;
    LARGE_INTEGER BytesCopied;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(Data);

    //
    // Re-entrancy guard: skip if this write was issued by our own
    // restore path (prevents backing up half-restored files)
    //
    if (IoGetTopLevelIrp() == FBE_ROLLBACK_SENTINEL) {
        return STATUS_FBE_SKIP;
    }

    InterlockedIncrement64(&g_FbeState.Stats.TotalBackupRequests);

    if (!g_FbeState.Config.EnableWriteBackup) {
        return STATUS_FBE_SKIP;
    }

    if (!FbepEnterOperation()) {
        return STATUS_FBE_SKIP;
    }

    //
    // Check if this file type should be backed up
    //
    if (!FbepShouldBackup(FileName)) {
        InterlockedIncrement64(&g_FbeState.Stats.BackupsSkippedExtension);
        FbepLeaveOperation();
        return STATUS_FBE_SKIP;
    }

    ProcessId = PsGetCurrentProcessId();
    BucketIndex = FbepComputeBucketIndex(ProcessId, FileName);

    //
    // Check for existing backup (copy-on-first-write)
    //
    FltAcquirePushLockShared(&g_FbeState.Buckets[BucketIndex].Lock);
    Entry = FbepFindEntry(ProcessId, FileName, BucketIndex);
    FltReleasePushLock(&g_FbeState.Buckets[BucketIndex].Lock);

    if (Entry != NULL) {
        //
        // Already backed up by this process â€” skip
        //
        InterlockedIncrement64(&g_FbeState.Stats.BackupsSkippedDuplicate);
        FbepLeaveOperation();
        return STATUS_SUCCESS;
    }

    //
    // Check capacity limits
    //
    if (g_FbeState.TotalEntryCount >= FBE_MAX_TOTAL_ENTRIES) {
        FbepEvictLruEntries(0);
        if (g_FbeState.TotalEntryCount >= FBE_MAX_TOTAL_ENTRIES) {
            InterlockedIncrement64(&g_FbeState.Stats.BackupsFailed);
            FbepLeaveOperation();
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    //
    // Get file size and validate
    //
    Status = FbepGetFileSize(FltObjects, &FileSize);
    if (!NT_SUCCESS(Status) || FileSize.QuadPart == 0) {
        FbepLeaveOperation();
        return STATUS_FBE_SKIP;
    }

    if (FileSize.QuadPart > g_FbeState.Config.MaxSingleFileSize) {
        InterlockedIncrement64(&g_FbeState.Stats.BackupsSkippedSize);
        FbepLeaveOperation();
        return STATUS_FBE_SKIP;
    }

    //
    // Check total backup size and evict if needed
    //
    if (g_FbeState.Stats.CurrentBackupDiskUsage + FileSize.QuadPart >
        g_FbeState.Config.MaxTotalBackupSize) {
        FbepEvictLruEntries(FileSize.QuadPart);
        if (g_FbeState.Stats.CurrentBackupDiskUsage + FileSize.QuadPart >
            g_FbeState.Config.MaxTotalBackupSize) {
            InterlockedIncrement64(&g_FbeState.Stats.BackupsFailed);
            FbepLeaveOperation();
            return STATUS_DISK_FULL;
        }
    }

    //
    // Allocate backup entry
    //
    Entry = FbepAllocateEntry();
    if (Entry == NULL) {
        InterlockedIncrement64(&g_FbeState.Stats.BackupsFailed);
        FbepLeaveOperation();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize entry fields
    //
    Entry->ProcessId = ProcessId;
    Entry->OperationType = FbeOp_Write;
    KeQuerySystemTime(&Entry->Timestamp);
    Entry->OriginalFileSize = FileSize;
    InterlockedExchange(&Entry->State, FbeEntryState_Pending);

    //
    // Copy original path
    //
    if (FileName->Length >= sizeof(Entry->OriginalPathBuffer)) {
        FbepFreeEntry(Entry);
        FbepLeaveOperation();
        return STATUS_BUFFER_OVERFLOW;
    }

    RtlCopyMemory(Entry->OriginalPathBuffer, FileName->Buffer, FileName->Length);
    Entry->OriginalPath.Buffer = Entry->OriginalPathBuffer;
    Entry->OriginalPath.Length = FileName->Length;
    Entry->OriginalPath.MaximumLength = sizeof(Entry->OriginalPathBuffer);

    //
    // Generate backup path
    //
    Status = FbepGenerateBackupPath(
        FileName,
        &Entry->BackupPath,
        Entry->BackupPathBuffer,
        sizeof(Entry->BackupPathBuffer)
        );

    if (!NT_SUCCESS(Status)) {
        FbepFreeEntry(Entry);
        InterlockedIncrement64(&g_FbeState.Stats.BackupsFailed);
        FbepLeaveOperation();
        return Status;
    }

    //
    // Perform the actual file copy
    //
    BytesCopied.QuadPart = 0;
    Status = FbepCopyFileToBackup(FltObjects, FileName, &Entry->BackupPath, &BytesCopied);

    if (!NT_SUCCESS(Status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/FBE] Backup copy failed for %wZ: 0x%08X\n",
                   FileName, Status);
        FbepFreeEntry(Entry);
        InterlockedIncrement64(&g_FbeState.Stats.BackupsFailed);
        FbepLeaveOperation();
        return Status;
    }

    Entry->BackupFileSize = BytesCopied;
    InterlockedExchange(&Entry->State, FbeEntryState_Valid);

    //
    // Find or create per-process tracker
    //
    Tracker = FbepFindOrCreateTracker(ProcessId);
    if (Tracker == NULL) {
        FbepDeleteBackupFile(&Entry->BackupPath);
        FbepFreeEntry(Entry);
        InterlockedIncrement64(&g_FbeState.Stats.BackupsFailed);
        FbepLeaveOperation();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Check per-process entry limit
    //
    if ((ULONG)Tracker->EntryCount >= g_FbeState.Config.MaxEntriesPerProcess) {
        FbepDeleteBackupFile(&Entry->BackupPath);
        FbepFreeEntry(Entry);
        InterlockedIncrement64(&g_FbeState.Stats.BackupsFailed);
        FbepLeaveOperation();
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Insert into hash bucket (with exclusive lock to prevent duplicate race)
    //
    FltAcquirePushLockExclusive(&g_FbeState.Buckets[BucketIndex].Lock);

    //
    // Re-check for duplicate under exclusive lock (TOCTOU prevention)
    //
    PFBE_BACKUP_ENTRY Existing = FbepFindEntry(ProcessId, FileName, BucketIndex);
    if (Existing != NULL) {
        FltReleasePushLock(&g_FbeState.Buckets[BucketIndex].Lock);
        FbepDeleteBackupFile(&Entry->BackupPath);
        FbepFreeEntry(Entry);
        InterlockedIncrement64(&g_FbeState.Stats.BackupsSkippedDuplicate);
        FbepLeaveOperation();
        return STATUS_SUCCESS;
    }

    InsertTailList(&g_FbeState.Buckets[BucketIndex].Head, &Entry->HashLink);
    InterlockedIncrement(&g_FbeState.Buckets[BucketIndex].Count);
    FltReleasePushLock(&g_FbeState.Buckets[BucketIndex].Lock);

    //
    // Insert into per-process tracker
    //
    FltAcquirePushLockExclusive(&Tracker->Lock);
    InsertTailList(&Tracker->BackupEntries, &Entry->ProcessLink);
    InterlockedIncrement(&Tracker->EntryCount);
    InterlockedAdd64(&Tracker->TotalBytesBackedUp, BytesCopied.QuadPart);
    InterlockedIncrement64(&Tracker->FilesBackedUp);
    FltReleasePushLock(&Tracker->Lock);

    //
    // Insert into LRU list (tail = newest)
    //
    FltAcquirePushLockExclusive(&g_FbeState.LruLock);
    InsertTailList(&g_FbeState.LruHead, &Entry->LruLink);
    FltReleasePushLock(&g_FbeState.LruLock);

    InterlockedIncrement(&g_FbeState.TotalEntryCount);

    //
    // Update statistics
    //
    InterlockedIncrement64(&g_FbeState.Stats.BackupsCreated);
    InterlockedAdd64(&g_FbeState.Stats.TotalBytesBackedUp, BytesCopied.QuadPart);
    InterlockedAdd64(&g_FbeState.Stats.CurrentBackupDiskUsage, BytesCopied.QuadPart);

    LONGLONG CurrentUsage = g_FbeState.Stats.CurrentBackupDiskUsage;
    LONGLONG PeakUsage;
    do {
        PeakUsage = g_FbeState.Stats.PeakBackupDiskUsage;
        if (CurrentUsage <= PeakUsage) break;
    } while (InterlockedCompareExchange64(
        &g_FbeState.Stats.PeakBackupDiskUsage,
        CurrentUsage,
        PeakUsage) != PeakUsage);

    FbepLeaveOperation();
    return STATUS_SUCCESS;
}


_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
FbePreSetInfoBackup(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PCUNICODE_STRING FileName,
    _In_ FBE_OPERATION_TYPE OpType
    )
{
    NTSTATUS Status;
    PFBE_BACKUP_ENTRY Entry;
    PFBE_PROCESS_TRACKER Tracker;
    ULONG BucketIndex;
    HANDLE ProcessId;
    LARGE_INTEGER FileSize;
    LARGE_INTEGER BytesCopied;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(Data);

    //
    // Re-entrancy guard: skip if this I/O was issued by our restore path
    //
    if (IoGetTopLevelIrp() == FBE_ROLLBACK_SENTINEL) {
        return STATUS_FBE_SKIP;
    }

    InterlockedIncrement64(&g_FbeState.Stats.TotalBackupRequests);

    //
    // Validate operation type has backup enabled
    //
    switch (OpType) {
    case FbeOp_Rename:
        if (!g_FbeState.Config.EnableRenameBackup) return STATUS_FBE_SKIP;
        break;
    case FbeOp_Delete:
        if (!g_FbeState.Config.EnableDeleteBackup) return STATUS_FBE_SKIP;
        break;
    case FbeOp_Truncate:
    case FbeOp_SetAllocation:
        if (!g_FbeState.Config.EnableTruncateBackup) return STATUS_FBE_SKIP;
        break;
    default:
        return STATUS_FBE_SKIP;
    }

    if (!FbepEnterOperation()) {
        return STATUS_FBE_SKIP;
    }

    if (!FbepShouldBackup(FileName)) {
        InterlockedIncrement64(&g_FbeState.Stats.BackupsSkippedExtension);
        FbepLeaveOperation();
        return STATUS_FBE_SKIP;
    }

    ProcessId = PsGetCurrentProcessId();
    BucketIndex = FbepComputeBucketIndex(ProcessId, FileName);

    //
    // Check for existing backup
    //
    FltAcquirePushLockShared(&g_FbeState.Buckets[BucketIndex].Lock);
    Entry = FbepFindEntry(ProcessId, FileName, BucketIndex);
    FltReleasePushLock(&g_FbeState.Buckets[BucketIndex].Lock);

    if (Entry != NULL) {
        InterlockedIncrement64(&g_FbeState.Stats.BackupsSkippedDuplicate);
        FbepLeaveOperation();
        return STATUS_SUCCESS;
    }

    //
    // Get file size â€” for delete, file may not exist after so must backup now
    //
    Status = FbepGetFileSize(FltObjects, &FileSize);
    if (!NT_SUCCESS(Status) || FileSize.QuadPart == 0) {
        //
        // For delete operations on zero-length files, still track the entry
        // to enable rollback (recreate empty file)
        //
        if (OpType != FbeOp_Delete) {
            FbepLeaveOperation();
            return STATUS_FBE_SKIP;
        }
        FileSize.QuadPart = 0;
    }

    if (FileSize.QuadPart > g_FbeState.Config.MaxSingleFileSize) {
        InterlockedIncrement64(&g_FbeState.Stats.BackupsSkippedSize);
        FbepLeaveOperation();
        return STATUS_FBE_SKIP;
    }

    //
    // Capacity check and eviction
    //
    if (FileSize.QuadPart > 0 &&
        g_FbeState.Stats.CurrentBackupDiskUsage + FileSize.QuadPart >
        g_FbeState.Config.MaxTotalBackupSize) {
        FbepEvictLruEntries(FileSize.QuadPart);
    }

    if (g_FbeState.TotalEntryCount >= FBE_MAX_TOTAL_ENTRIES) {
        FbepEvictLruEntries(0);
        if (g_FbeState.TotalEntryCount >= FBE_MAX_TOTAL_ENTRIES) {
            InterlockedIncrement64(&g_FbeState.Stats.BackupsFailed);
            FbepLeaveOperation();
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    //
    // Allocate and initialize entry
    //
    Entry = FbepAllocateEntry();
    if (Entry == NULL) {
        InterlockedIncrement64(&g_FbeState.Stats.BackupsFailed);
        FbepLeaveOperation();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Entry->ProcessId = ProcessId;
    Entry->OperationType = OpType;
    KeQuerySystemTime(&Entry->Timestamp);
    Entry->OriginalFileSize = FileSize;
    InterlockedExchange(&Entry->State, FbeEntryState_Pending);

    //
    // Copy original path
    //
    if (FileName->Length >= sizeof(Entry->OriginalPathBuffer)) {
        FbepFreeEntry(Entry);
        FbepLeaveOperation();
        return STATUS_BUFFER_OVERFLOW;
    }

    RtlCopyMemory(Entry->OriginalPathBuffer, FileName->Buffer, FileName->Length);
    Entry->OriginalPath.Buffer = Entry->OriginalPathBuffer;
    Entry->OriginalPath.Length = FileName->Length;
    Entry->OriginalPath.MaximumLength = sizeof(Entry->OriginalPathBuffer);

    //
    // Generate backup path
    //
    Status = FbepGenerateBackupPath(
        FileName,
        &Entry->BackupPath,
        Entry->BackupPathBuffer,
        sizeof(Entry->BackupPathBuffer)
        );

    if (!NT_SUCCESS(Status)) {
        FbepFreeEntry(Entry);
        InterlockedIncrement64(&g_FbeState.Stats.BackupsFailed);
        FbepLeaveOperation();
        return Status;
    }

    //
    // Copy file content to backup (if file has content)
    //
    BytesCopied.QuadPart = 0;
    if (FileSize.QuadPart > 0) {
        Status = FbepCopyFileToBackup(FltObjects, FileName, &Entry->BackupPath, &BytesCopied);
        if (!NT_SUCCESS(Status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike/FBE] SetInfo backup copy failed for %wZ: 0x%08X\n",
                       FileName, Status);
            FbepFreeEntry(Entry);
            InterlockedIncrement64(&g_FbeState.Stats.BackupsFailed);
            FbepLeaveOperation();
            return Status;
        }
    }

    Entry->BackupFileSize = BytesCopied;
    InterlockedExchange(&Entry->State, FbeEntryState_Valid);

    //
    // Insert into tracking structures (same pattern as PreWrite)
    //
    Tracker = FbepFindOrCreateTracker(ProcessId);
    if (Tracker == NULL) {
        if (BytesCopied.QuadPart > 0) {
            FbepDeleteBackupFile(&Entry->BackupPath);
        }
        FbepFreeEntry(Entry);
        InterlockedIncrement64(&g_FbeState.Stats.BackupsFailed);
        FbepLeaveOperation();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if ((ULONG)Tracker->EntryCount >= g_FbeState.Config.MaxEntriesPerProcess) {
        if (BytesCopied.QuadPart > 0) {
            FbepDeleteBackupFile(&Entry->BackupPath);
        }
        FbepFreeEntry(Entry);
        InterlockedIncrement64(&g_FbeState.Stats.BackupsFailed);
        FbepLeaveOperation();
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Insert into hash bucket with duplicate check
    //
    FltAcquirePushLockExclusive(&g_FbeState.Buckets[BucketIndex].Lock);

    PFBE_BACKUP_ENTRY Existing = FbepFindEntry(ProcessId, FileName, BucketIndex);
    if (Existing != NULL) {
        FltReleasePushLock(&g_FbeState.Buckets[BucketIndex].Lock);
        if (BytesCopied.QuadPart > 0) {
            FbepDeleteBackupFile(&Entry->BackupPath);
        }
        FbepFreeEntry(Entry);
        InterlockedIncrement64(&g_FbeState.Stats.BackupsSkippedDuplicate);
        FbepLeaveOperation();
        return STATUS_SUCCESS;
    }

    InsertTailList(&g_FbeState.Buckets[BucketIndex].Head, &Entry->HashLink);
    InterlockedIncrement(&g_FbeState.Buckets[BucketIndex].Count);
    FltReleasePushLock(&g_FbeState.Buckets[BucketIndex].Lock);

    FltAcquirePushLockExclusive(&Tracker->Lock);
    InsertTailList(&Tracker->BackupEntries, &Entry->ProcessLink);
    InterlockedIncrement(&Tracker->EntryCount);
    InterlockedAdd64(&Tracker->TotalBytesBackedUp, BytesCopied.QuadPart);
    InterlockedIncrement64(&Tracker->FilesBackedUp);
    FltReleasePushLock(&Tracker->Lock);

    FltAcquirePushLockExclusive(&g_FbeState.LruLock);
    InsertTailList(&g_FbeState.LruHead, &Entry->LruLink);
    FltReleasePushLock(&g_FbeState.LruLock);

    InterlockedIncrement(&g_FbeState.TotalEntryCount);
    InterlockedIncrement64(&g_FbeState.Stats.BackupsCreated);
    InterlockedAdd64(&g_FbeState.Stats.TotalBytesBackedUp, BytesCopied.QuadPart);
    InterlockedAdd64(&g_FbeState.Stats.CurrentBackupDiskUsage, BytesCopied.QuadPart);

    FbepLeaveOperation();
    return STATUS_SUCCESS;
}

// ============================================================================
// ROLLBACK OPERATIONS
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
FBE_ROLLBACK_RESULT
FbeRollbackProcess(
    _In_ HANDLE ProcessId,
    _Out_opt_ PULONG FilesRestored
    )
{
    PFBE_PROCESS_TRACKER Tracker;
    LIST_ENTRY *ListEntry;
    ULONG Restored = 0;
    ULONG Failed = 0;
    NTSTATUS Status;

    PAGED_CODE();

    if (FilesRestored != NULL) {
        *FilesRestored = 0;
    }

    InterlockedIncrement64(&g_FbeState.Stats.RollbackRequests);

    if (!FbepEnterOperation()) {
        return FbeRollback_ShuttingDown;
    }

    Tracker = FbepFindTracker(ProcessId);
    if (Tracker == NULL) {
        FbepLeaveOperation();
        return FbeRollback_NoBackupsFound;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[ShadowStrike/FBE] RANSOMWARE ROLLBACK: Restoring %ld files "
               "for PID=%lu (%lld bytes backed up)\n",
               Tracker->EntryCount,
               HandleToULong(ProcessId),
               Tracker->TotalBytesBackedUp);

    //
    // Submit ransomware rollback event to BehaviorEngine for kill-chain correlation.
    //
    (VOID)BeEngineSubmitEvent(
        BehaviorEvent_FileRollbackStarted,
        BehaviorCategory_Impact,
        HandleToULong(ProcessId),
        NULL, 0,
        90,
        FALSE,
        NULL
        );

    //
    // Two-phase rollback: collect entries under lock, process without lock.
    // This prevents use-after-free if FbeCommitProcess runs concurrently
    // and modifies the list while we hold a captured Blink pointer.
    //

    //
    // Phase 1: Claim entries by CAS'ing their state to Pending.
    // Collect pointers into a stack/pool buffer.
    //
    #define FBE_ROLLBACK_STACK_BATCH    64
    PFBE_BACKUP_ENTRY StackBatch[FBE_ROLLBACK_STACK_BATCH];
    PFBE_BACKUP_ENTRY *RollbackBatch = StackBatch;
    ULONG BatchCapacity = FBE_ROLLBACK_STACK_BATCH;
    ULONG ClaimedCount = 0;
    BOOLEAN UsedPoolAlloc = FALSE;

    //
    // If the process has more entries than stack buffer, allocate from pool
    //
    if ((ULONG)Tracker->EntryCount > FBE_ROLLBACK_STACK_BATCH) {
        ULONG AllocCount = min((ULONG)Tracker->EntryCount, FBE_MAX_ENTRIES_PER_PROCESS);
        ULONG AllocSize = AllocCount * sizeof(PFBE_BACKUP_ENTRY);

        if (AllocSize <= 64 * 1024) {
            RollbackBatch = (PFBE_BACKUP_ENTRY *)ExAllocatePool2(
                POOL_FLAG_NON_PAGED, AllocSize, FBE_ROLLBACK_POOL_TAG);
            if (RollbackBatch != NULL) {
                BatchCapacity = AllocCount;
                UsedPoolAlloc = TRUE;
            } else {
                RollbackBatch = StackBatch;
            }
        }
    }

    FltAcquirePushLockShared(&Tracker->Lock);

    for (ListEntry = Tracker->BackupEntries.Blink;
         ListEntry != &Tracker->BackupEntries && ClaimedCount < BatchCapacity;
         ListEntry = ListEntry->Blink) {

        PFBE_BACKUP_ENTRY Entry = CONTAINING_RECORD(
            ListEntry, FBE_BACKUP_ENTRY, ProcessLink);

        if (InterlockedCompareExchange(&Entry->State,
                                       FbeEntryState_Pending,
                                       FbeEntryState_Valid) == FbeEntryState_Valid) {
            RollbackBatch[ClaimedCount++] = Entry;
        }
    }

    FltReleasePushLock(&Tracker->Lock);

    //
    // Phase 2: Restore files without holding any lock.
    // Process in reverse (newest first) to undo rename chains correctly.
    //
    for (ULONG i = 0; i < ClaimedCount; i++) {
        PFBE_BACKUP_ENTRY Entry = RollbackBatch[i];

        Status = FbepRestoreFileFromBackup(Entry);
        if (NT_SUCCESS(Status)) {
            InterlockedExchange(&Entry->State, FbeEntryState_RolledBack);
            Restored++;
            InterlockedIncrement64(&g_FbeState.Stats.RollbackFilesRestored);
            InterlockedAdd64(&g_FbeState.Stats.TotalBytesRolledBack,
                             Entry->BackupFileSize.QuadPart);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[ShadowStrike/FBE] Restored: %wZ (%lld bytes)\n",
                       &Entry->OriginalPath,
                       Entry->BackupFileSize.QuadPart);
        } else {
            //
            // Revert state so retry is possible
            //
            InterlockedExchange(&Entry->State, FbeEntryState_Valid);
            Failed++;

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike/FBE] RESTORE FAILED: %wZ (0x%08X)\n",
                       &Entry->OriginalPath, Status);
        }
    }

    if (UsedPoolAlloc) {
        ExFreePoolWithTag(RollbackBatch, FBE_ROLLBACK_POOL_TAG);
    }

    if (FilesRestored != NULL) {
        *FilesRestored = Restored;
    }

    if (Restored > 0 && Failed == 0) {
        InterlockedIncrement64(&g_FbeState.Stats.RollbacksSucceeded);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike/FBE] ROLLBACK COMPLETE: %lu files restored for PID=%lu\n",
                   Restored, HandleToULong(ProcessId));
        FbepLeaveOperation();
        return FbeRollback_Success;
    } else if (Restored > 0 && Failed > 0) {
        InterlockedIncrement64(&g_FbeState.Stats.RollbacksFailed);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike/FBE] ROLLBACK PARTIAL: %lu restored, %lu failed for PID=%lu\n",
                   Restored, Failed, HandleToULong(ProcessId));
        FbepLeaveOperation();
        return FbeRollback_PartialSuccess;
    } else {
        InterlockedIncrement64(&g_FbeState.Stats.RollbacksFailed);
        FbepLeaveOperation();
        return FbeRollback_IOError;
    }
}


_IRQL_requires_(PASSIVE_LEVEL)
VOID
FbeCommitProcess(
    _In_ HANDLE ProcessId
    )
{
    PFBE_PROCESS_TRACKER Tracker;
    LIST_ENTRY *ListEntry;
    ULONG BucketIndex;

    PAGED_CODE();

    if (!FbepEnterOperation()) {
        return;
    }

    Tracker = FbepFindTracker(ProcessId);
    if (Tracker == NULL) {
        FbepLeaveOperation();
        return;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike/FBE] Committing (discarding) %ld backups for PID=%lu\n",
               Tracker->EntryCount, HandleToULong(ProcessId));

    //
    // Remove all entries from this process
    //
    FltAcquirePushLockExclusive(&Tracker->Lock);

    while (!IsListEmpty(&Tracker->BackupEntries)) {
        ListEntry = RemoveHeadList(&Tracker->BackupEntries);
        PFBE_BACKUP_ENTRY Entry = CONTAINING_RECORD(
            ListEntry, FBE_BACKUP_ENTRY, ProcessLink);

        FltReleasePushLock(&Tracker->Lock);

        //
        // Remove from hash bucket
        //
        BucketIndex = FbepComputeBucketIndex(Entry->ProcessId, &Entry->OriginalPath);
        FltAcquirePushLockExclusive(&g_FbeState.Buckets[BucketIndex].Lock);
        RemoveEntryList(&Entry->HashLink);
        InterlockedDecrement(&g_FbeState.Buckets[BucketIndex].Count);
        FltReleasePushLock(&g_FbeState.Buckets[BucketIndex].Lock);

        //
        // Remove from LRU
        //
        FltAcquirePushLockExclusive(&g_FbeState.LruLock);
        RemoveEntryList(&Entry->LruLink);
        FltReleasePushLock(&g_FbeState.LruLock);

        InterlockedDecrement(&g_FbeState.TotalEntryCount);

        //
        // Delete backup file and free entry
        //
        if (Entry->State == FbeEntryState_Valid) {
            InterlockedAdd64(&g_FbeState.Stats.CurrentBackupDiskUsage,
                             -Entry->BackupFileSize.QuadPart);
            FbepDeleteBackupFile(&Entry->BackupPath);
        }

        FbepFreeEntry(Entry);

        FltAcquirePushLockExclusive(&Tracker->Lock);
    }

    Tracker->EntryCount = 0;
    FltReleasePushLock(&Tracker->Lock);

    //
    // Remove tracker from process bucket
    //
    ULONG ProcBucket = FbepProcessBucketIndex(ProcessId);
    FltAcquirePushLockExclusive(&g_FbeState.ProcessBuckets[ProcBucket].Lock);
    RemoveEntryList(&Tracker->Link);
    InterlockedDecrement(&g_FbeState.ProcessBuckets[ProcBucket].Count);
    FltReleasePushLock(&g_FbeState.ProcessBuckets[ProcBucket].Lock);

    FbepFreeTracker(Tracker);

    FbepLeaveOperation();
}

// ============================================================================
// QUERY OPERATIONS
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
VOID
FbeGetStatistics(
    _Out_ PFBE_STATISTICS Statistics
    )
{
    RtlCopyMemory(Statistics, &g_FbeState.Stats, sizeof(FBE_STATISTICS));
}


_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
FbeHasBackups(
    _In_ HANDLE ProcessId
    )
{
    ULONG ProcBucket = FbepProcessBucketIndex(ProcessId);
    BOOLEAN Found = FALSE;

    FltAcquirePushLockShared(&g_FbeState.ProcessBuckets[ProcBucket].Lock);

    LIST_ENTRY *ListEntry = g_FbeState.ProcessBuckets[ProcBucket].Head.Flink;
    while (ListEntry != &g_FbeState.ProcessBuckets[ProcBucket].Head) {
        PFBE_PROCESS_TRACKER Tracker = CONTAINING_RECORD(
            ListEntry, FBE_PROCESS_TRACKER, Link);
        if (Tracker->ProcessId == ProcessId && Tracker->EntryCount > 0) {
            Found = TRUE;
            break;
        }
        ListEntry = ListEntry->Flink;
    }

    FltReleasePushLock(&g_FbeState.ProcessBuckets[ProcBucket].Lock);
    return Found;
}

// ============================================================================
// PRIVATE â€” HASHING
// ============================================================================

static ULONG
FbepHashPath(
    _In_ PCUNICODE_STRING Path
    )
{
    ULONG Hash = 5381;
    USHORT Length = Path->Length / sizeof(WCHAR);

    for (USHORT i = 0; i < Length; i++) {
        WCHAR Ch = RtlUpcaseUnicodeChar(Path->Buffer[i]);
        Hash = ((Hash << 5) + Hash) + (ULONG)Ch;
    }

    return Hash;
}


static ULONG
FbepComputeBucketIndex(
    _In_ HANDLE ProcessId,
    _In_ PCUNICODE_STRING FilePath
    )
{
    ULONG PathHash = FbepHashPath(FilePath);
    ULONG PidHash = HandleToULong(ProcessId);
    return (PathHash ^ PidHash) % FBE_HASH_BUCKET_COUNT;
}


static ULONG
FbepProcessBucketIndex(
    _In_ HANDLE ProcessId
    )
{
    return (HandleToULong(ProcessId) >> 2) % 64;
}

// ============================================================================
// PRIVATE â€” ENTRY MANAGEMENT
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
static PFBE_BACKUP_ENTRY
FbepFindEntry(
    _In_ HANDLE ProcessId,
    _In_ PCUNICODE_STRING FilePath,
    _In_ ULONG BucketIndex
    )
{
    LIST_ENTRY *ListEntry;

    for (ListEntry = g_FbeState.Buckets[BucketIndex].Head.Flink;
         ListEntry != &g_FbeState.Buckets[BucketIndex].Head;
         ListEntry = ListEntry->Flink) {

        PFBE_BACKUP_ENTRY Entry = CONTAINING_RECORD(
            ListEntry, FBE_BACKUP_ENTRY, HashLink);

        if (Entry->ProcessId == ProcessId &&
            Entry->OriginalPath.Length == FilePath->Length &&
            RtlEqualUnicodeString(&Entry->OriginalPath, FilePath, TRUE)) {

            LONG EntryState = ReadAcquire(&Entry->State);
            if (EntryState == FbeEntryState_Valid ||
                EntryState == FbeEntryState_Pending) {
                return Entry;
            }
        }
    }

    return NULL;
}


_IRQL_requires_(PASSIVE_LEVEL)
static PFBE_BACKUP_ENTRY
FbepAllocateEntry(VOID)
{
    PFBE_BACKUP_ENTRY Entry;

    Entry = (PFBE_BACKUP_ENTRY)ExAllocateFromNPagedLookasideList(
        &g_FbeState.EntryLookaside);

    if (Entry != NULL) {
        RtlZeroMemory(Entry, sizeof(FBE_BACKUP_ENTRY));
        InitializeListHead(&Entry->ProcessLink);
        InitializeListHead(&Entry->HashLink);
        InitializeListHead(&Entry->LruLink);
    }

    return Entry;
}


_IRQL_requires_(PASSIVE_LEVEL)
static VOID
FbepFreeEntry(
    _In_ PFBE_BACKUP_ENTRY Entry
    )
{
    ExFreeToNPagedLookasideList(&g_FbeState.EntryLookaside, Entry);
}

// ============================================================================
// PRIVATE â€” PROCESS TRACKER MANAGEMENT
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
static PFBE_PROCESS_TRACKER
FbepFindOrCreateTracker(
    _In_ HANDLE ProcessId
    )
{
    PFBE_PROCESS_TRACKER Tracker;
    ULONG ProcBucket = FbepProcessBucketIndex(ProcessId);
    LIST_ENTRY *ListEntry;

    //
    // Search existing under shared lock
    //
    FltAcquirePushLockShared(&g_FbeState.ProcessBuckets[ProcBucket].Lock);

    for (ListEntry = g_FbeState.ProcessBuckets[ProcBucket].Head.Flink;
         ListEntry != &g_FbeState.ProcessBuckets[ProcBucket].Head;
         ListEntry = ListEntry->Flink) {

        Tracker = CONTAINING_RECORD(ListEntry, FBE_PROCESS_TRACKER, Link);
        if (Tracker->ProcessId == ProcessId) {
            FltReleasePushLock(&g_FbeState.ProcessBuckets[ProcBucket].Lock);
            return Tracker;
        }
    }

    FltReleasePushLock(&g_FbeState.ProcessBuckets[ProcBucket].Lock);

    //
    // Not found â€” allocate new tracker
    //
    Tracker = (PFBE_PROCESS_TRACKER)ExAllocateFromNPagedLookasideList(
        &g_FbeState.TrackerLookaside);

    if (Tracker == NULL) {
        return NULL;
    }

    RtlZeroMemory(Tracker, sizeof(FBE_PROCESS_TRACKER));
    Tracker->ProcessId = ProcessId;
    InitializeListHead(&Tracker->BackupEntries);
    FltInitializePushLock(&Tracker->Lock);
    InitializeListHead(&Tracker->Link);

    //
    // Insert under exclusive lock with duplicate check
    //
    FltAcquirePushLockExclusive(&g_FbeState.ProcessBuckets[ProcBucket].Lock);

    for (ListEntry = g_FbeState.ProcessBuckets[ProcBucket].Head.Flink;
         ListEntry != &g_FbeState.ProcessBuckets[ProcBucket].Head;
         ListEntry = ListEntry->Flink) {

        PFBE_PROCESS_TRACKER Existing = CONTAINING_RECORD(
            ListEntry, FBE_PROCESS_TRACKER, Link);

        if (Existing->ProcessId == ProcessId) {
            FltReleasePushLock(&g_FbeState.ProcessBuckets[ProcBucket].Lock);
            FltDeletePushLock(&Tracker->Lock);
            ExFreeToNPagedLookasideList(&g_FbeState.TrackerLookaside, Tracker);
            return Existing;
        }
    }

    InsertTailList(&g_FbeState.ProcessBuckets[ProcBucket].Head, &Tracker->Link);
    InterlockedIncrement(&g_FbeState.ProcessBuckets[ProcBucket].Count);

    FltReleasePushLock(&g_FbeState.ProcessBuckets[ProcBucket].Lock);

    return Tracker;
}


_IRQL_requires_(PASSIVE_LEVEL)
static PFBE_PROCESS_TRACKER
FbepFindTracker(
    _In_ HANDLE ProcessId
    )
{
    ULONG ProcBucket = FbepProcessBucketIndex(ProcessId);
    LIST_ENTRY *ListEntry;

    FltAcquirePushLockShared(&g_FbeState.ProcessBuckets[ProcBucket].Lock);

    for (ListEntry = g_FbeState.ProcessBuckets[ProcBucket].Head.Flink;
         ListEntry != &g_FbeState.ProcessBuckets[ProcBucket].Head;
         ListEntry = ListEntry->Flink) {

        PFBE_PROCESS_TRACKER Tracker = CONTAINING_RECORD(
            ListEntry, FBE_PROCESS_TRACKER, Link);

        if (Tracker->ProcessId == ProcessId) {
            FltReleasePushLock(&g_FbeState.ProcessBuckets[ProcBucket].Lock);
            return Tracker;
        }
    }

    FltReleasePushLock(&g_FbeState.ProcessBuckets[ProcBucket].Lock);
    return NULL;
}


_IRQL_requires_(PASSIVE_LEVEL)
static VOID
FbepFreeTracker(
    _In_ PFBE_PROCESS_TRACKER Tracker
    )
{
    FltDeletePushLock(&Tracker->Lock);
    ExFreeToNPagedLookasideList(&g_FbeState.TrackerLookaside, Tracker);
}

// ============================================================================
// PRIVATE â€” FILE I/O OPERATIONS
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
FbepCopyFileToBackup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PCUNICODE_STRING SourcePath,
    _In_ PCUNICODE_STRING BackupPath,
    _Out_ PLARGE_INTEGER BytesCopied
    )
{
    NTSTATUS Status;
    HANDLE BackupHandle = NULL;
    PFILE_OBJECT BackupFileObject = NULL;
    IO_STATUS_BLOCK IoStatus;
    OBJECT_ATTRIBUTES ObjAttrs;
    PVOID CopyBuffer = NULL;
    LARGE_INTEGER Offset;
    LARGE_INTEGER FileSize;
    ULONG BytesRead;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(SourcePath);

    BytesCopied->QuadPart = 0;

    //
    // Get source file size
    //
    Status = FbepGetFileSize(FltObjects, &FileSize);
    if (!NT_SUCCESS(Status) || FileSize.QuadPart == 0) {
        return STATUS_SUCCESS;
    }

    //
    // Allocate copy buffer
    //
    CopyBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, FBE_IO_BUFFER_SIZE, FBE_IO_POOL_TAG);
    if (CopyBuffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Create backup file
    //
    InitializeObjectAttributes(
        &ObjAttrs,
        (PUNICODE_STRING)BackupPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
        );

    Status = FltCreateFileEx(
        g_DriverData.FilterHandle,
        FltObjects->Instance,
        &BackupHandle,
        &BackupFileObject,
        GENERIC_WRITE | SYNCHRONIZE,
        &ObjAttrs,
        &IoStatus,
        NULL,
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
        0,                              // No sharing during write
        FILE_CREATE,                    // Fail if exists
        FILE_NON_DIRECTORY_FILE |
            FILE_WRITE_THROUGH |
            FILE_SYNCHRONOUS_IO_NONALERT |
            FILE_NO_INTERMEDIATE_BUFFERING,
        NULL,
        0,
        IO_IGNORE_SHARE_ACCESS_CHECK
        );

    if (!NT_SUCCESS(Status)) {
        //
        // If directory doesn't exist, create it and retry
        //
        if (Status == STATUS_OBJECT_PATH_NOT_FOUND) {
            Status = FbepEnsureBackupDirectory(BackupPath);
            if (NT_SUCCESS(Status)) {
                Status = FltCreateFileEx(
                    g_DriverData.FilterHandle,
                    FltObjects->Instance,
                    &BackupHandle,
                    &BackupFileObject,
                    GENERIC_WRITE | SYNCHRONIZE,
                    &ObjAttrs,
                    &IoStatus,
                    NULL,
                    FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
                    0,
                    FILE_CREATE,
                    FILE_NON_DIRECTORY_FILE |
                        FILE_WRITE_THROUGH |
                        FILE_SYNCHRONOUS_IO_NONALERT |
                        FILE_NO_INTERMEDIATE_BUFFERING,
                    NULL,
                    0,
                    IO_IGNORE_SHARE_ACCESS_CHECK
                    );
            }
        }

        //
        // If FILE_CREATE fails because file exists, try SUPERSEDE
        //
        if (Status == STATUS_OBJECT_NAME_COLLISION) {
            Status = FltCreateFileEx(
                g_DriverData.FilterHandle,
                FltObjects->Instance,
                &BackupHandle,
                &BackupFileObject,
                GENERIC_WRITE | SYNCHRONIZE,
                &ObjAttrs,
                &IoStatus,
                NULL,
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
                0,
                FILE_SUPERSEDE,
                FILE_NON_DIRECTORY_FILE |
                    FILE_WRITE_THROUGH |
                    FILE_SYNCHRONOUS_IO_NONALERT |
                    FILE_NO_INTERMEDIATE_BUFFERING,
                NULL,
                0,
                IO_IGNORE_SHARE_ACCESS_CHECK
                );
        }

        if (!NT_SUCCESS(Status)) {
            ExFreePoolWithTag(CopyBuffer, FBE_IO_POOL_TAG);
            return Status;
        }
    }

    //
    // Copy file content in chunks
    //
    Offset.QuadPart = 0;

    while (Offset.QuadPart < FileSize.QuadPart) {

        ULONG ReadSize = FBE_IO_BUFFER_SIZE;
        if (FileSize.QuadPart - Offset.QuadPart < (LONGLONG)ReadSize) {
            ReadSize = (ULONG)(FileSize.QuadPart - Offset.QuadPart);
        }

        //
        // Align read size for non-buffered I/O
        //
        ULONG AlignedReadSize = (ReadSize + 511) & ~511u;
        if (AlignedReadSize > FBE_IO_BUFFER_SIZE) {
            AlignedReadSize = FBE_IO_BUFFER_SIZE;
        }

        //
        // Read from source using FltReadFile
        //
        Status = FltReadFile(
            FltObjects->Instance,
            FltObjects->FileObject,
            &Offset,
            AlignedReadSize,
            CopyBuffer,
            FLTFL_IO_OPERATION_NON_CACHED |
                FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
            &BytesRead,
            NULL,
            NULL
            );

        if (!NT_SUCCESS(Status)) {
            //
            // End of file is acceptable
            //
            if (Status == STATUS_END_OF_FILE) {
                Status = STATUS_SUCCESS;
                break;
            }
            goto Cleanup;
        }

        if (BytesRead == 0) {
            break;
        }

        //
        // Write to backup file
        //
        ULONG AlignedWriteSize = (BytesRead + 511) & ~511u;

        Status = FltWriteFile(
            FltObjects->Instance,
            BackupFileObject,
            &Offset,
            AlignedWriteSize,
            CopyBuffer,
            FLTFL_IO_OPERATION_NON_CACHED |
                FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
            NULL,
            NULL,
            NULL
            );

        if (!NT_SUCCESS(Status)) {
            goto Cleanup;
        }

        Offset.QuadPart += BytesRead;
    }

    //
    // Report actual file bytes backed up, not aligned I/O offset.
    // Non-buffered writes pad to sector boundary; Offset may exceed FileSize.
    // Using FileSize ensures CurrentBackupDiskUsage is accurate.
    //
    BytesCopied->QuadPart = min(Offset.QuadPart, FileSize.QuadPart);
    Status = STATUS_SUCCESS;

Cleanup:
    if (BackupFileObject != NULL) {
        ObDereferenceObject(BackupFileObject);
    }

    if (BackupHandle != NULL) {
        FltClose(BackupHandle);
    }

    if (CopyBuffer != NULL) {
        ExFreePoolWithTag(CopyBuffer, FBE_IO_POOL_TAG);
    }

    if (!NT_SUCCESS(Status) && BytesCopied->QuadPart == 0) {
        FbepDeleteBackupFile(BackupPath);
    }

    return Status;
}


_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
FbepRestoreFileFromBackup(
    _In_ PFBE_BACKUP_ENTRY Entry
    )
{
    NTSTATUS Status;
    HANDLE SourceHandle = NULL;
    PFILE_OBJECT SourceFileObject = NULL;
    HANDLE TargetHandle = NULL;
    PFILE_OBJECT TargetFileObject = NULL;
    IO_STATUS_BLOCK IoStatus;
    OBJECT_ATTRIBUTES ObjAttrs;
    PVOID CopyBuffer = NULL;
    LARGE_INTEGER Offset;
    ULONG BytesRead;

    PAGED_CODE();

    //
    // Set re-entrancy sentinel to prevent PreWrite from backing up
    // our restore writes (per-thread via TEB TopLevelIrp).
    //
    PIRP SavedTopLevelIrp = IoGetTopLevelIrp();
    IoSetTopLevelIrp(FBE_ROLLBACK_SENTINEL);

    CopyBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, FBE_IO_BUFFER_SIZE, FBE_IO_POOL_TAG);
    if (CopyBuffer == NULL) {
        IoSetTopLevelIrp(SavedTopLevelIrp);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Open backup file for reading
    //
    InitializeObjectAttributes(
        &ObjAttrs,
        &Entry->BackupPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
        );

    Status = FltCreateFileEx(
        g_DriverData.FilterHandle,
        NULL,
        &SourceHandle,
        &SourceFileObject,
        GENERIC_READ | SYNCHRONIZE,
        &ObjAttrs,
        &IoStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE |
            FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0,
        IO_IGNORE_SHARE_ACCESS_CHECK
        );

    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(CopyBuffer, FBE_IO_POOL_TAG);
        IoSetTopLevelIrp(SavedTopLevelIrp);
        return Status;
    }

    //
    // Create/overwrite original file
    //
    InitializeObjectAttributes(
        &ObjAttrs,
        &Entry->OriginalPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
        );

    Status = FltCreateFileEx(
        g_DriverData.FilterHandle,
        NULL,
        &TargetHandle,
        &TargetFileObject,
        GENERIC_WRITE | SYNCHRONIZE | DELETE,
        &ObjAttrs,
        &IoStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OVERWRITE_IF,  // Overwrite (preserves ACLs) if exists, create if deleted
        FILE_NON_DIRECTORY_FILE |
            FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0,
        IO_IGNORE_SHARE_ACCESS_CHECK
        );

    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    //
    // Copy backup content back to original location.
    // Limit to OriginalFileSize to exclude non-buffered write padding.
    //
    Offset.QuadPart = 0;

    while (Offset.QuadPart < Entry->OriginalFileSize.QuadPart) {

        ULONG ReadSize = FBE_IO_BUFFER_SIZE;
        LONGLONG Remaining = Entry->OriginalFileSize.QuadPart - Offset.QuadPart;
        if (Remaining < (LONGLONG)ReadSize) {
            ReadSize = (ULONG)Remaining;
        }

        Status = FltReadFile(
            NULL,
            SourceFileObject,
            &Offset,
            ReadSize,
            CopyBuffer,
            0,
            &BytesRead,
            NULL,
            NULL
            );

        if (!NT_SUCCESS(Status) || BytesRead == 0) {
            if (Status == STATUS_END_OF_FILE) {
                Status = STATUS_SUCCESS;
            }
            break;
        }

        //
        // Clamp write to remaining original size
        //
        ULONG WriteSize = BytesRead;
        if (Offset.QuadPart + WriteSize > Entry->OriginalFileSize.QuadPart) {
            WriteSize = (ULONG)(Entry->OriginalFileSize.QuadPart - Offset.QuadPart);
        }

        Status = FltWriteFile(
            NULL,
            TargetFileObject,
            &Offset,
            WriteSize,
            CopyBuffer,
            0,
            NULL,
            NULL,
            NULL
            );

        if (!NT_SUCCESS(Status)) {
            break;
        }

        Offset.QuadPart += WriteSize;
    }

    //
    // Set exact file size to match original (remove any alignment padding)
    //
    if (NT_SUCCESS(Status) && TargetFileObject != NULL) {
        FILE_END_OF_FILE_INFORMATION EofInfo;
        EofInfo.EndOfFile = Entry->OriginalFileSize;
        FltSetInformationFile(
            NULL,
            TargetFileObject,
            &EofInfo,
            sizeof(EofInfo),
            FileEndOfFileInformation
            );
    }

Cleanup:
    if (TargetFileObject != NULL) {
        ObDereferenceObject(TargetFileObject);
    }
    if (TargetHandle != NULL) {
        FltClose(TargetHandle);
    }
    if (SourceFileObject != NULL) {
        ObDereferenceObject(SourceFileObject);
    }
    if (SourceHandle != NULL) {
        FltClose(SourceHandle);
    }
    if (CopyBuffer != NULL) {
        ExFreePoolWithTag(CopyBuffer, FBE_IO_POOL_TAG);
    }

    //
    // Restore TopLevelIrp to prevent sentinel from leaking to caller
    //
    IoSetTopLevelIrp(SavedTopLevelIrp);

    return Status;
}


_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
FbepDeleteBackupFile(
    _In_ PCUNICODE_STRING BackupPath
    )
{
    NTSTATUS Status;
    HANDLE FileHandle = NULL;
    IO_STATUS_BLOCK IoStatus;
    OBJECT_ATTRIBUTES ObjAttrs;
    FILE_DISPOSITION_INFORMATION DispositionInfo;

    PAGED_CODE();

    InitializeObjectAttributes(
        &ObjAttrs,
        (PUNICODE_STRING)BackupPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
        );

    Status = FltCreateFileEx(
        g_DriverData.FilterHandle,
        NULL,
        &FileHandle,
        NULL,
        DELETE | SYNCHRONIZE,
        &ObjAttrs,
        &IoStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0,
        IO_IGNORE_SHARE_ACCESS_CHECK
        );

    if (!NT_SUCCESS(Status)) {
        //
        // File already deleted or path gone â€” not an error during cleanup
        //
        if (Status == STATUS_OBJECT_NAME_NOT_FOUND ||
            Status == STATUS_OBJECT_PATH_NOT_FOUND) {
            return STATUS_SUCCESS;
        }
        return Status;
    }

    DispositionInfo.DeleteFile = TRUE;
    Status = ZwSetInformationFile(
        FileHandle,
        &IoStatus,
        &DispositionInfo,
        sizeof(DispositionInfo),
        FileDispositionInformation
        );

    FltClose(FileHandle);
    return Status;
}

// ============================================================================
// PRIVATE â€” PATH GENERATION
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
FbepGenerateBackupPath(
    _In_ PCUNICODE_STRING OriginalPath,
    _Out_ PUNICODE_STRING BackupPath,
    _In_ PWCHAR BackupBuffer,
    _In_ USHORT BackupBufferSize
    )
{
    NTSTATUS Status;
    LONG64 BackupId;
    UNICODE_STRING Result;

    PAGED_CODE();

    //
    // Extract volume prefix from original path.
    // Expected formats from FltGetFileNameInformation (normalized):
    //   \Device\HarddiskVolume1\path  (standard local)
    //   \Device\CdRom0\path           (optical)
    //   \Device\Mup\server\share\path (network redirector â€” NOT supported)
    //   \Device\LanmanRedirector\...  (network â€” NOT supported)
    //
    // Strategy: find the 3rd backslash to isolate the volume device name.
    // Reject network paths (Mup, LanmanRedirector) where local backup
    // is nonsensical and the 3rd slash wouldn't give a correct volume.
    //
    USHORT OrigLen = OriginalPath->Length / sizeof(WCHAR);
    USHORT SlashCount = 0;
    USHORT VolumeEnd = 0;

    //
    // Reject paths that are too short to contain a valid volume prefix
    // (minimum: \Device\X\ = 10 chars)
    //
    if (OrigLen < 10) {
        return STATUS_INVALID_PARAMETER;
    }

    for (USHORT i = 0; i < OrigLen; i++) {
        if (OriginalPath->Buffer[i] == L'\\') {
            SlashCount++;
            if (SlashCount == 3) {
                VolumeEnd = i;
                break;
            }
        }
    }

    //
    // Validate we found a proper volume prefix
    //
    if (VolumeEnd == 0 || VolumeEnd < 8) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Reject network redirector paths where local backup doesn't make sense.
    // \Device\Mup\...  or \Device\LanmanRedirector\...
    //
    {
        UNICODE_STRING VolumePrefix;
        VolumePrefix.Buffer = OriginalPath->Buffer;
        VolumePrefix.Length = VolumeEnd * sizeof(WCHAR);
        VolumePrefix.MaximumLength = VolumePrefix.Length;

        UNICODE_STRING MupPrefix = RTL_CONSTANT_STRING(L"\\Device\\Mup");
        UNICODE_STRING LanmanPrefix = RTL_CONSTANT_STRING(L"\\Device\\LanmanRedirector");

        if (RtlEqualUnicodeString(&VolumePrefix, &MupPrefix, TRUE) ||
            RtlEqualUnicodeString(&VolumePrefix, &LanmanPrefix, TRUE)) {
            return STATUS_NOT_SUPPORTED;
        }
    }

    BackupId = InterlockedIncrement64(&g_FbeState.NextBackupId);

    Result.Buffer = BackupBuffer;
    Result.Length = 0;
    Result.MaximumLength = BackupBufferSize;

    //
    // Build: <VolumePrefix>\ShadowStrikeBackup\<BackupId>.bak
    //
    Status = RtlUnicodeStringPrintf(
        &Result,
        L"%.*s" FBE_BACKUP_DIR_NAME L"\\%I64u.bak",
        VolumeEnd,
        OriginalPath->Buffer,
        (ULONGLONG)BackupId
        );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    BackupPath->Buffer = BackupBuffer;
    BackupPath->Length = Result.Length;
    BackupPath->MaximumLength = BackupBufferSize;

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE â€” FILE SIZE QUERY
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
FbepGetFileSize(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PLARGE_INTEGER FileSize
    )
{
    NTSTATUS Status;
    FILE_STANDARD_INFORMATION FileInfo;

    PAGED_CODE();

    FileSize->QuadPart = 0;

    Status = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &FileInfo,
        sizeof(FileInfo),
        FileStandardInformation,
        NULL
        );

    if (NT_SUCCESS(Status)) {
        FileSize->QuadPart = FileInfo.EndOfFile.QuadPart;
    }

    return Status;
}

// ============================================================================
// PRIVATE â€” EXTENSION CLASSIFICATION
// ============================================================================

static BOOLEAN
FbepShouldBackup(
    _In_ PCUNICODE_STRING FileName
    )
{
    USHORT Length = FileName->Length / sizeof(WCHAR);
    USHORT DotPos = 0;
    UNICODE_STRING Extension;

    //
    // Find last dot for extension
    //
    for (USHORT i = Length; i > 0; i--) {
        if (FileName->Buffer[i - 1] == L'.') {
            DotPos = i - 1;
            break;
        }
        if (FileName->Buffer[i - 1] == L'\\') {
            break;
        }
    }

    if (DotPos == 0) {
        //
        // No extension â€” don't backup by default
        // (reduces noise from temp files, streams, etc.)
        //
        return FALSE;
    }

    Extension.Buffer = &FileName->Buffer[DotPos];
    Extension.Length = (Length - DotPos) * sizeof(WCHAR);
    Extension.MaximumLength = Extension.Length;

    //
    // Binary search over sorted g_BackupExtensions array.
    // O(log n) instead of O(n) â€” critical for hot PreWrite path.
    //
    LONG Lo = 0;
    LONG Hi = (LONG)FBE_BACKUP_EXTENSION_COUNT - 1;

    while (Lo <= Hi) {
        LONG Mid = Lo + (Hi - Lo) / 2;
        LONG Cmp = RtlCompareUnicodeString(&Extension, &g_BackupExtensions[Mid], TRUE);
        if (Cmp == 0) {
            return TRUE;
        } else if (Cmp < 0) {
            Hi = Mid - 1;
        } else {
            Lo = Mid + 1;
        }
    }

    return FALSE;
}

// ============================================================================
// PRIVATE â€” LRU EVICTION
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
FbepEvictLruEntries(
    _In_ LONGLONG BytesNeeded
    )
{
    PFBE_BACKUP_ENTRY Entry;
    LIST_ENTRY *ListEntry;
    ULONG Evicted = 0;
    ULONG MaxEvict = 128;   // Safety cap per eviction pass

    PAGED_CODE();

    FltAcquirePushLockExclusive(&g_FbeState.LruLock);

    while (!IsListEmpty(&g_FbeState.LruHead) && Evicted < MaxEvict) {

        //
        // Check if we've freed enough space.
        // Re-checked EVERY iteration (including after lock reacquire) to
        // prevent over-eviction when concurrent inserts/commits change counts.
        //
        if (BytesNeeded > 0 &&
            g_FbeState.Stats.CurrentBackupDiskUsage + BytesNeeded <=
            g_FbeState.Config.MaxTotalBackupSize &&
            g_FbeState.TotalEntryCount < FBE_MAX_TOTAL_ENTRIES) {
            break;
        }

        if (BytesNeeded == 0 && g_FbeState.TotalEntryCount < FBE_MAX_TOTAL_ENTRIES) {
            break;
        }

        ListEntry = RemoveHeadList(&g_FbeState.LruHead);
        Entry = CONTAINING_RECORD(ListEntry, FBE_BACKUP_ENTRY, LruLink);

        //
        // Mark as evicted under LRU lock to prevent concurrent rollback
        // from claiming this entry via CAS on State.
        //
        // FSC-6: Lock ordering note â€” we release LruLock before acquiring
        // BucketLock/TrackerLock, which is the opposite of the insert path.
        // This is safe because:
        // 1. State=Evicted prevents concurrent rollback (CAS check)
        // 2. Hash lookup finds entry but State=Evicted causes skip
        // 3. EntryCount decrement is eventually consistent
        //
        LONG PrevState = InterlockedExchange(&Entry->State, FbeEntryState_Evicted);

        //
        // Release LRU lock during I/O (file delete may block)
        //
        FltReleasePushLock(&g_FbeState.LruLock);

        //
        // Remove from hash bucket
        //
        ULONG BucketIndex = FbepComputeBucketIndex(Entry->ProcessId, &Entry->OriginalPath);
        FltAcquirePushLockExclusive(&g_FbeState.Buckets[BucketIndex].Lock);
        RemoveEntryList(&Entry->HashLink);
        InterlockedDecrement(&g_FbeState.Buckets[BucketIndex].Count);
        FltReleasePushLock(&g_FbeState.Buckets[BucketIndex].Lock);

        //
        // Remove from process tracker
        //
        PFBE_PROCESS_TRACKER Tracker = FbepFindTracker(Entry->ProcessId);
        if (Tracker != NULL) {
            FltAcquirePushLockExclusive(&Tracker->Lock);
            RemoveEntryList(&Entry->ProcessLink);
            InterlockedDecrement(&Tracker->EntryCount);
            FltReleasePushLock(&Tracker->Lock);
        }

        InterlockedDecrement(&g_FbeState.TotalEntryCount);

        //
        // Delete backup file and update accounting
        //
        if (PrevState == FbeEntryState_Valid) {
            InterlockedAdd64(&g_FbeState.Stats.CurrentBackupDiskUsage,
                             -Entry->BackupFileSize.QuadPart);
            FbepDeleteBackupFile(&Entry->BackupPath);
        }

        InterlockedIncrement64(&g_FbeState.Stats.EntriesEvicted);

        FbepFreeEntry(Entry);
        Evicted++;

        //
        // Re-acquire LRU lock for next iteration.
        // Capacity is re-checked at loop top to prevent over-eviction.
        //
        FltAcquirePushLockExclusive(&g_FbeState.LruLock);
    }

    FltReleasePushLock(&g_FbeState.LruLock);

    if (Evicted > 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                   "[ShadowStrike/FBE] Evicted %lu LRU backup entries\n",
                   Evicted);
    }
}

// ============================================================================
// PRIVATE â€” LIFECYCLE HELPERS
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
FbepEnterOperation(VOID)
{
    if (g_FbeState.State != 2) {
        return FALSE;
    }

    return ExAcquireRundownProtection(&g_FbeState.RundownRef);
}


_IRQL_requires_(PASSIVE_LEVEL)
static VOID
FbepLeaveOperation(VOID)
{
    ExReleaseRundownProtection(&g_FbeState.RundownRef);
}

// ============================================================================
// PRIVATE â€” DIRECTORY MANAGEMENT
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
FbepEnsureBackupDirectory(
    _In_ PCUNICODE_STRING BackupPath
    )
{
    NTSTATUS Status;
    HANDLE DirHandle;
    IO_STATUS_BLOCK IoStatus;
    OBJECT_ATTRIBUTES ObjAttrs;
    UNICODE_STRING DirPath;
    USHORT LastSlash = 0;
    PACL Dacl = NULL;

    PAGED_CODE();

    if (BackupPath->Length == 0 || BackupPath->Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Extract directory portion from full backup path
    // e.g., \Device\HarddiskVolume1\ShadowStrikeBackup\123.bak
    //     â†’ \Device\HarddiskVolume1\ShadowStrikeBackup
    //
    for (USHORT i = BackupPath->Length / sizeof(WCHAR); i > 0; i--) {
        if (BackupPath->Buffer[i - 1] == L'\\') {
            LastSlash = i - 1;
            break;
        }
    }

    if (LastSlash == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    DirPath.Buffer = BackupPath->Buffer;
    DirPath.Length = LastSlash * sizeof(WCHAR);
    DirPath.MaximumLength = DirPath.Length;

    //
    // Build a restrictive security descriptor for the backup directory.
    // Only LOCAL_SYSTEM has access â€” this prevents ransomware running as
    // user/admin from enumerating or encrypting backup files.
    //
    // SD layout: absolute SD on stack, ACL from pool
    //   - Protected DACL (SE_DACL_PROTECTED) â€” no parent inheritance
    //   - Single ACE: SYSTEM gets FILE_ALL_ACCESS with inheritance
    //
    SECURITY_DESCRIPTOR Sd;
    BOOLEAN SdValid = FALSE;

    {
        SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
        UCHAR SystemSidBuf[SECURITY_MAX_SID_SIZE];
        PSID SystemSid = (PSID)SystemSidBuf;

        RtlInitializeSid(SystemSid, &NtAuthority, 1);
        *RtlSubAuthoritySid(SystemSid, 0) = SECURITY_LOCAL_SYSTEM_RID;

        ULONG SidLength = RtlLengthSid(SystemSid);
        ULONG AceSize = FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + SidLength;
        ULONG AclSize = sizeof(ACL) + AceSize;

        //
        // Align ACL to ULONG boundary (required by ACL structure)
        //
        AclSize = (AclSize + sizeof(ULONG) - 1) & ~(sizeof(ULONG) - 1);

        Dacl = (PACL)ExAllocatePool2(POOL_FLAG_PAGED, AclSize, FBE_POOL_TAG);
        if (Dacl != NULL) {
            Status = RtlCreateAcl(Dacl, AclSize, ACL_REVISION);
            if (NT_SUCCESS(Status)) {
                Status = RtlAddAccessAllowedAceEx(
                    Dacl,
                    ACL_REVISION,
                    OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
                    FILE_ALL_ACCESS,
                    SystemSid
                    );
            }

            if (NT_SUCCESS(Status)) {
                Status = RtlCreateSecurityDescriptor(
                    &Sd, SECURITY_DESCRIPTOR_REVISION);
            }

            if (NT_SUCCESS(Status)) {
                Status = RtlSetDaclSecurityDescriptor(
                    &Sd, TRUE, Dacl, FALSE);
            }

            if (NT_SUCCESS(Status)) {
                //
                // SE_DACL_PROTECTED prevents ACL inheritance from parent dir.
                // Without this, parent dir ACEs get merged and users may gain access.
                //
                Sd.Control |= SE_DACL_PROTECTED;
                SdValid = TRUE;
            } else {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike/FBE] Failed to build backup dir SD: 0x%08X\n",
                           Status);
            }
        }
    }

    InitializeObjectAttributes(
        &ObjAttrs,
        &DirPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        SdValid ? &Sd : NULL
        );

    //
    // FILE_OPEN_IF: creates if missing, opens if exists.
    // Security descriptor is applied only on creation (FILE_CREATED).
    //
    Status = FltCreateFile(
        g_DriverData.FilterHandle,
        NULL,
        &DirHandle,
        FILE_LIST_DIRECTORY | SYNCHRONIZE,
        &ObjAttrs,
        &IoStatus,
        NULL,
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN_IF,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0,
        0
        );

    if (NT_SUCCESS(Status)) {
        FltClose(DirHandle);
    }

    if (Dacl != NULL) {
        ExFreePoolWithTag(Dacl, FBE_POOL_TAG);
    }

    return Status;
}
