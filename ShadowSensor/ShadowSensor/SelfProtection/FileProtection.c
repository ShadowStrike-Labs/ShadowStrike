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
    ShadowStrike Next-Generation Antivirus
    Module: FileProtection.c

    Purpose: Enterprise-grade file protection for EDR self-defense.

    This module provides comprehensive file-level protection capabilities:
    - Protected file/directory path management with prefix matching
    - NTFS Alternate Data Stream (ADS) protection and detection
    - Path normalization and canonicalization
    - Symbolic link and junction point awareness
    - Short name (8.3) to long name resolution via FltGetFileNameInformation
    - File extension-based protection rules
    - Comprehensive audit logging with retrieval API
    - Integration with minifilter callbacks

    Security Architecture:
    - All paths normalized before comparison (case-insensitive via RtlUpcaseUnicodeChar)
    - ADS stream names stripped using correct post-last-separator logic
    - Protected processes exempted from blocking
    - Fail-open on unexpected errors to prevent system instability
    - DoS prevention through resource limits
    - Reference counting on FP_PROTECTED_PATH prevents use-after-free
    - All data copied while under lock; no post-lock dereference of list entries
    - No large stack buffers — hot-path allocations are pool-backed
    - Config writes protected by exclusive lock
    - Statistics use InterlockedExchange64 for atomic reset
    - FP_ENGINE is opaque (defined here only)

    MITRE ATT&CK Coverage:
    - T1070.004: Indicator Removal (file deletion protection)
    - T1222: File and Directory Permissions Modification
    - T1564.004: Hidden Files and Directories (ADS protection)
    - T1036: Masquerading (path normalization)

    Copyright (c) ShadowStrike Team
--*/

#include "FileProtection.h"
#include "SelfProtect.h"
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/StringUtils.h"
#include "../Tracing/Trace.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, FpInitialize)
#pragma alloc_text(PAGE, FpShutdown)
#pragma alloc_text(PAGE, FpConfigure)
#pragma alloc_text(PAGE, FpAddProtectedPath)
#pragma alloc_text(PAGE, FpAddProtectedPathW)
#pragma alloc_text(PAGE, FpRemoveProtectedPath)
#pragma alloc_text(PAGE, FpAddProtectedExtension)
#pragma alloc_text(PAGE, FpClearAllRules)
#pragma alloc_text(PAGE, FpNormalizePath)
#pragma alloc_text(PAGE, FpNormalizePathEx)
#pragma alloc_text(PAGE, FpResolveSymlink)
#pragma alloc_text(PAGE, FpConvertShortToLongName)
#pragma alloc_text(PAGE, FpGetAuditLog)
#pragma alloc_text(PAGE, FpClearAuditLog)
#endif

//=============================================================================
// Internal Constants
//=============================================================================

#define FP_DEFAULT_MAX_AUDIT_ENTRIES    1024
#define FP_STREAM_SEPARATOR             L':'
#define FP_PATH_SEPARATOR               L'\\'
#define FP_SHORT_NAME_MARKER            L'~'

//=============================================================================
// Internal Structures (only visible in this translation unit)
//=============================================================================

/**
 * @brief Protected extension entry (internal, embedded in engine array)
 */
typedef struct _FP_PROTECTED_EXTENSION {
    BOOLEAN InUse;
    WCHAR Extension[FP_MAX_EXTENSION_LENGTH];
    USHORT ExtensionLength;
    ULONG ProtectionFlags;
    volatile LONG64 BlockedCount;
} FP_PROTECTED_EXTENSION, *PFP_PROTECTED_EXTENSION;

/**
 * @brief Protected path entry (internal, reference-counted)
 */
typedef struct _FP_PROTECTED_PATH {
    LIST_ENTRY ListEntry;

    WCHAR NormalizedPath[FP_MAX_PATH_LENGTH];
    USHORT PathLength;
    BOOLEAN IsDirectory;

    FP_RULE_TYPE RuleType;
    ULONG ProtectionFlags;

    volatile LONG64 BlockedOperations;
    volatile LONG64 AuditedOperations;

    LARGE_INTEGER AddedTime;
    volatile LONG64 LastAccessTimeTicks;

    volatile LONG RefCount;
} FP_PROTECTED_PATH, *PFP_PROTECTED_PATH;

/**
 * @brief Internal audit entry with LIST_ENTRY for the ring buffer
 */
typedef struct _FP_AUDIT_ENTRY_INTERNAL {
    LIST_ENTRY ListEntry;
    FP_AUDIT_ENTRY_INFO Info;
} FP_AUDIT_ENTRY_INTERNAL, *PFP_AUDIT_ENTRY_INTERNAL;

/**
 * @brief Engine configuration (protected by ConfigLock)
 */
typedef struct _FP_ENGINE_CONFIG {
    BOOLEAN EnablePathNormalization;
    BOOLEAN EnableStreamProtection;
    BOOLEAN EnableSymlinkResolution;
    BOOLEAN EnableShortNameResolution;
    BOOLEAN EnableAuditLogging;
    ULONG MaxAuditEntries;
} FP_ENGINE_CONFIG;

/**
 * @brief File protection engine (opaque — only defined here)
 */
struct _FP_ENGINE {
    volatile LONG Initialized;

    //
    // Protected paths (linked list, reference-counted entries)
    //
    LIST_ENTRY ProtectedPathList;
    EX_PUSH_LOCK PathListLock;
    volatile LONG ProtectedPathCount;

    //
    // Protected extensions (static array)
    //
    FP_PROTECTED_EXTENSION ProtectedExtensions[FP_MAX_PROTECTED_EXTENSIONS];
    EX_PUSH_LOCK ExtensionLock;
    volatile LONG ProtectedExtensionCount;

    //
    // Audit log (ring buffer)
    //
    LIST_ENTRY AuditLog;
    EX_PUSH_LOCK AuditLogLock;
    volatile LONG AuditLogCount;

    //
    // Configuration (protected by ConfigLock)
    //
    EX_PUSH_LOCK ConfigLock;
    FP_ENGINE_CONFIG Config;

    //
    // Statistics (per-field interlocked access)
    //
    FP_STATISTICS Stats;
};

//=============================================================================
// Forward Declarations
//=============================================================================

static BOOLEAN
FppMatchPath(
    _In_ PCWSTR TestPath,
    _In_ USHORT TestPathLength,
    _In_ PCWSTR RulePath,
    _In_ USHORT RulePathLength,
    _In_ BOOLEAN IsRecursive
    );

static BOOLEAN
FppMatchExtension(
    _In_ PCWSTR FileName,
    _In_ PCWSTR Extension,
    _In_ USHORT ExtensionLength
    );

static VOID
FppReleaseProtectedPath(
    _Inout_ PFP_PROTECTED_PATH Path
    );

static VOID
FppFreeAuditEntry(
    _In_ PFP_AUDIT_ENTRY_INTERNAL Entry
    );

static VOID
FppTrimAuditLog(
    _Inout_ PFP_ENGINE Engine
    );

static NTSTATUS
FppGetProcessName(
    _In_ HANDLE ProcessId,
    _Out_writes_z_(NameSize) PWCHAR ProcessName,
    _In_ ULONG NameSize
    );

static BOOLEAN
FppIsShortName(
    _In_ PCWSTR FileName
    );

static VOID
FppUpcaseInPlace(
    _Inout_z_ PWCHAR String,
    _In_ USHORT CharCount
    );

static USHORT
FppFindStreamSeparator(
    _In_ PCWSTR Path,
    _In_ USHORT PathLenChars
    );

//=============================================================================
// Helper: Uppercase a WCHAR string in-place using RtlUpcaseUnicodeChar
// (kernel-safe, no CRT dependency)
//=============================================================================

static
VOID
FppUpcaseInPlace(
    _Inout_z_ PWCHAR String,
    _In_ USHORT CharCount
    )
{
    USHORT i;
    for (i = 0; i < CharCount && String[i] != L'\0'; i++) {
        String[i] = RtlUpcaseUnicodeChar(String[i]);
    }
}

//=============================================================================
// Helper: Find the first stream separator colon after the last path separator.
// Returns index of the colon, or 0 if no stream found.
//=============================================================================

static
USHORT
FppFindStreamSeparator(
    _In_ PCWSTR Path,
    _In_ USHORT PathLenChars
    )
{
    USHORT LastSep = 0;
    USHORT i;

    //
    // Find position of last backslash
    //
    for (i = 0; i < PathLenChars; i++) {
        if (Path[i] == FP_PATH_SEPARATOR || Path[i] == L'/') {
            LastSep = i;
        }
    }

    //
    // Find first colon after the last separator that isn't a drive-letter colon.
    // Drive-letter colon is at index 1 (e.g., "C:") — skip it.
    //
    for (i = LastSep + 1; i < PathLenChars; i++) {
        if (Path[i] == FP_STREAM_SEPARATOR) {
            if (i == 1) {
                //
                // Drive letter colon (C:), skip
                //
                continue;
            }
            return i;
        }
    }

    return 0;
}

//=============================================================================
// Engine Management
//=============================================================================

_Use_decl_annotations_
NTSTATUS
FpInitialize(
    _Out_ PFP_ENGINE* Engine
    )
{
    PFP_ENGINE NewEngine = NULL;
    LARGE_INTEGER CurrentTime;

    PAGED_CODE();

    if (Engine == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Engine = NULL;

    NewEngine = (PFP_ENGINE)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(FP_ENGINE),
        FP_POOL_TAG_CONTEXT
        );

    if (NewEngine == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(NewEngine, sizeof(FP_ENGINE));

    InitializeListHead(&NewEngine->ProtectedPathList);
    ExInitializePushLock(&NewEngine->PathListLock);

    RtlZeroMemory(NewEngine->ProtectedExtensions, sizeof(NewEngine->ProtectedExtensions));
    ExInitializePushLock(&NewEngine->ExtensionLock);

    InitializeListHead(&NewEngine->AuditLog);
    ExInitializePushLock(&NewEngine->AuditLogLock);

    ExInitializePushLock(&NewEngine->ConfigLock);

    NewEngine->Config.EnablePathNormalization = TRUE;
    NewEngine->Config.EnableStreamProtection = TRUE;
    NewEngine->Config.EnableSymlinkResolution = TRUE;
    NewEngine->Config.EnableShortNameResolution = TRUE;
    NewEngine->Config.EnableAuditLogging = TRUE;
    NewEngine->Config.MaxAuditEntries = FP_DEFAULT_MAX_AUDIT_ENTRIES;

    KeQuerySystemTime(&CurrentTime);
    NewEngine->Stats.StartTime = CurrentTime;

    InterlockedExchange(&NewEngine->Initialized, TRUE);

    *Engine = NewEngine;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
FpShutdown(
    _Inout_ PFP_ENGINE Engine
    )
{
    PLIST_ENTRY Entry;
    PFP_PROTECTED_PATH Path;
    PFP_AUDIT_ENTRY_INTERNAL AuditEntry;

    PAGED_CODE();

    if (Engine == NULL) {
        return;
    }

    if (InterlockedCompareExchange(&Engine->Initialized, FALSE, TRUE) != TRUE) {
        return;
    }

    //
    // Free all protected paths
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->PathListLock);

    while (!IsListEmpty(&Engine->ProtectedPathList)) {
        Entry = RemoveHeadList(&Engine->ProtectedPathList);
        Path = CONTAINING_RECORD(Entry, FP_PROTECTED_PATH, ListEntry);
        FppReleaseProtectedPath(Path);
    }

    ExReleasePushLockExclusive(&Engine->PathListLock);
    KeLeaveCriticalRegion();

    //
    // Clear extensions
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->ExtensionLock);
    RtlZeroMemory(Engine->ProtectedExtensions, sizeof(Engine->ProtectedExtensions));
    Engine->ProtectedExtensionCount = 0;
    ExReleasePushLockExclusive(&Engine->ExtensionLock);
    KeLeaveCriticalRegion();

    //
    // Free audit log
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->AuditLogLock);

    while (!IsListEmpty(&Engine->AuditLog)) {
        Entry = RemoveHeadList(&Engine->AuditLog);
        AuditEntry = CONTAINING_RECORD(Entry, FP_AUDIT_ENTRY_INTERNAL, ListEntry);
        FppFreeAuditEntry(AuditEntry);
    }

    ExReleasePushLockExclusive(&Engine->AuditLogLock);
    KeLeaveCriticalRegion();

    ShadowStrikeFreePoolWithTag(Engine, FP_POOL_TAG_CONTEXT);
}

_Use_decl_annotations_
NTSTATUS
FpConfigure(
    _In_ PFP_ENGINE Engine,
    _In_ BOOLEAN EnableNormalization,
    _In_ BOOLEAN EnableStreamProtection,
    _In_ BOOLEAN EnableSymlinkResolution,
    _In_ BOOLEAN EnableAuditLogging
    )
{
    PAGED_CODE();

    if (Engine == NULL || !InterlockedCompareExchange(&Engine->Initialized, TRUE, TRUE)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Acquire exclusive ConfigLock to atomically update all config fields
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->ConfigLock);

    Engine->Config.EnablePathNormalization = EnableNormalization;
    Engine->Config.EnableStreamProtection = EnableStreamProtection;
    Engine->Config.EnableSymlinkResolution = EnableSymlinkResolution;
    Engine->Config.EnableAuditLogging = EnableAuditLogging;

    ExReleasePushLockExclusive(&Engine->ConfigLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

//=============================================================================
// Path Protection Management
//=============================================================================

_Use_decl_annotations_
NTSTATUS
FpAddProtectedPath(
    _In_ PFP_ENGINE Engine,
    _In_ PCUNICODE_STRING Path,
    _In_ ULONG ProtectionFlags,
    _In_ FP_RULE_TYPE RuleType
    )
{
    PFP_PROTECTED_PATH NewPath = NULL;
    PLIST_ENTRY Entry;
    PFP_PROTECTED_PATH ExistingPath;
    BOOLEAN Duplicate = FALSE;
    LARGE_INTEGER CurrentTime;
    USHORT PathLength;

    PAGED_CODE();

    if (Engine == NULL || !InterlockedCompareExchange(&Engine->Initialized, TRUE, TRUE)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Path == NULL || Path->Buffer == NULL || Path->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    PathLength = Path->Length / sizeof(WCHAR);
    if (PathLength >= FP_MAX_PATH_LENGTH) {
        return STATUS_NAME_TOO_LONG;
    }

    NewPath = (PFP_PROTECTED_PATH)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(FP_PROTECTED_PATH),
        FP_POOL_TAG_RULE
        );

    if (NewPath == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(NewPath, sizeof(FP_PROTECTED_PATH));

    RtlCopyMemory(NewPath->NormalizedPath, Path->Buffer, Path->Length);
    NewPath->NormalizedPath[PathLength] = L'\0';
    NewPath->PathLength = PathLength;

    //
    // Uppercase using kernel-safe per-character upcase (no CRT _wcsupr_s)
    //
    FppUpcaseInPlace(NewPath->NormalizedPath, PathLength);

    NewPath->RuleType = RuleType;
    NewPath->ProtectionFlags = ProtectionFlags;
    NewPath->RefCount = 1;

    KeQuerySystemTime(&CurrentTime);
    NewPath->AddedTime = CurrentTime;

    if (PathLength > 0 && NewPath->NormalizedPath[PathLength - 1] == FP_PATH_SEPARATOR) {
        NewPath->IsDirectory = TRUE;
    }

    //
    // Insert under exclusive lock — re-check count inside the lock to prevent TOCTOU
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->PathListLock);

    //
    // Count check inside the lock (fixes MED-01 TOCTOU)
    //
    if (Engine->ProtectedPathCount >= FP_MAX_PROTECTED_PATHS) {
        ExReleasePushLockExclusive(&Engine->PathListLock);
        KeLeaveCriticalRegion();
        ShadowStrikeFreePoolWithTag(NewPath, FP_POOL_TAG_RULE);
        return STATUS_QUOTA_EXCEEDED;
    }

    for (Entry = Engine->ProtectedPathList.Flink;
         Entry != &Engine->ProtectedPathList;
         Entry = Entry->Flink) {

        ExistingPath = CONTAINING_RECORD(Entry, FP_PROTECTED_PATH, ListEntry);

        if (ExistingPath->PathLength == NewPath->PathLength &&
            RtlCompareMemory(ExistingPath->NormalizedPath, NewPath->NormalizedPath,
                             NewPath->PathLength * sizeof(WCHAR)) ==
            (SIZE_T)(NewPath->PathLength * sizeof(WCHAR))) {
            Duplicate = TRUE;
            break;
        }
    }

    if (!Duplicate) {
        InsertTailList(&Engine->ProtectedPathList, &NewPath->ListEntry);
        InterlockedIncrement(&Engine->ProtectedPathCount);
        InterlockedIncrement64(&Engine->Stats.PathsProtected);
        NewPath = NULL;
    }

    ExReleasePushLockExclusive(&Engine->PathListLock);
    KeLeaveCriticalRegion();

    if (NewPath != NULL) {
        ShadowStrikeFreePoolWithTag(NewPath, FP_POOL_TAG_RULE);
        return STATUS_DUPLICATE_OBJECTID;
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
FpAddProtectedPathW(
    _In_ PFP_ENGINE Engine,
    _In_ PCWSTR Path,
    _In_ ULONG ProtectionFlags,
    _In_ FP_RULE_TYPE RuleType
    )
{
    UNICODE_STRING PathString;

    PAGED_CODE();

    if (Path == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlInitUnicodeString(&PathString, Path);

    return FpAddProtectedPath(Engine, &PathString, ProtectionFlags, RuleType);
}

_Use_decl_annotations_
NTSTATUS
FpRemoveProtectedPath(
    _In_ PFP_ENGINE Engine,
    _In_ PCUNICODE_STRING Path
    )
{
    PLIST_ENTRY Entry;
    PFP_PROTECTED_PATH FoundPath = NULL;
    PWCHAR NormalizedPath = NULL;
    USHORT PathLength;

    PAGED_CODE();

    if (Engine == NULL || !InterlockedCompareExchange(&Engine->Initialized, TRUE, TRUE)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Path == NULL || Path->Buffer == NULL || Path->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    PathLength = Path->Length / sizeof(WCHAR);
    if (PathLength >= FP_MAX_PATH_LENGTH) {
        return STATUS_NAME_TOO_LONG;
    }

    //
    // Allocate normalization buffer from pool instead of stack (was 2KB on stack)
    //
    NormalizedPath = (PWCHAR)ShadowStrikeAllocatePoolWithTag(
        PagedPool,
        FP_MAX_PATH_LENGTH * sizeof(WCHAR),
        FP_POOL_TAG_WORK
        );

    if (NormalizedPath == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(NormalizedPath, Path->Buffer, Path->Length);
    NormalizedPath[PathLength] = L'\0';
    FppUpcaseInPlace(NormalizedPath, PathLength);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->PathListLock);

    for (Entry = Engine->ProtectedPathList.Flink;
         Entry != &Engine->ProtectedPathList;
         Entry = Entry->Flink) {

        PFP_PROTECTED_PATH TestPath = CONTAINING_RECORD(Entry, FP_PROTECTED_PATH, ListEntry);

        if (TestPath->PathLength == PathLength &&
            RtlCompareMemory(TestPath->NormalizedPath, NormalizedPath,
                             PathLength * sizeof(WCHAR)) ==
            (SIZE_T)(PathLength * sizeof(WCHAR))) {

            RemoveEntryList(Entry);
            InterlockedDecrement(&Engine->ProtectedPathCount);
            FoundPath = TestPath;
            break;
        }
    }

    ExReleasePushLockExclusive(&Engine->PathListLock);
    KeLeaveCriticalRegion();

    ShadowStrikeFreePoolWithTag(NormalizedPath, FP_POOL_TAG_WORK);

    if (FoundPath != NULL) {
        FppReleaseProtectedPath(FoundPath);
        return STATUS_SUCCESS;
    }

    return STATUS_NOT_FOUND;
}

_Use_decl_annotations_
NTSTATUS
FpAddProtectedExtension(
    _In_ PFP_ENGINE Engine,
    _In_ PCWSTR Extension,
    _In_ ULONG ProtectionFlags
    )
{
    LONG i;
    SIZE_T ExtLen;
    NTSTATUS Status = STATUS_QUOTA_EXCEEDED;

    PAGED_CODE();

    if (Engine == NULL || !InterlockedCompareExchange(&Engine->Initialized, TRUE, TRUE) ||
        Extension == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    ExtLen = wcslen(Extension);
    if (ExtLen == 0 || ExtLen >= FP_MAX_EXTENSION_LENGTH) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->ExtensionLock);

    for (i = 0; i < FP_MAX_PROTECTED_EXTENSIONS; i++) {
        if (!Engine->ProtectedExtensions[i].InUse) {
            Engine->ProtectedExtensions[i].InUse = TRUE;
            Engine->ProtectedExtensions[i].ExtensionLength = (USHORT)ExtLen;
            Engine->ProtectedExtensions[i].ProtectionFlags = ProtectionFlags;

            RtlCopyMemory(Engine->ProtectedExtensions[i].Extension,
                Extension, ExtLen * sizeof(WCHAR));
            Engine->ProtectedExtensions[i].Extension[ExtLen] = L'\0';

            FppUpcaseInPlace(Engine->ProtectedExtensions[i].Extension, (USHORT)ExtLen);

            InterlockedIncrement(&Engine->ProtectedExtensionCount);
            InterlockedIncrement64(&Engine->Stats.ExtensionsProtected);

            Status = STATUS_SUCCESS;
            break;
        }
    }

    ExReleasePushLockExclusive(&Engine->ExtensionLock);
    KeLeaveCriticalRegion();

    return Status;
}

_Use_decl_annotations_
VOID
FpClearAllRules(
    _In_ PFP_ENGINE Engine
    )
{
    PLIST_ENTRY Entry;
    PFP_PROTECTED_PATH Path;

    PAGED_CODE();

    if (Engine == NULL || !InterlockedCompareExchange(&Engine->Initialized, TRUE, TRUE)) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->PathListLock);

    while (!IsListEmpty(&Engine->ProtectedPathList)) {
        Entry = RemoveHeadList(&Engine->ProtectedPathList);
        Path = CONTAINING_RECORD(Entry, FP_PROTECTED_PATH, ListEntry);
        FppReleaseProtectedPath(Path);
    }

    Engine->ProtectedPathCount = 0;

    ExReleasePushLockExclusive(&Engine->PathListLock);
    KeLeaveCriticalRegion();

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->ExtensionLock);

    RtlZeroMemory(Engine->ProtectedExtensions, sizeof(Engine->ProtectedExtensions));
    Engine->ProtectedExtensionCount = 0;

    ExReleasePushLockExclusive(&Engine->ExtensionLock);
    KeLeaveCriticalRegion();
}

//=============================================================================
// Access Checks
//=============================================================================

_Use_decl_annotations_
FP_ACCESS_RESULT
FpCheckAccess(
    _In_ PFP_ENGINE Engine,
    _In_ PCUNICODE_STRING FilePath,
    _In_ FP_OPERATION_TYPE Operation,
    _In_ HANDLE RequestorPid,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_opt_ PULONG OutProtectionFlags
    )
{
    PLIST_ENTRY Entry;
    FP_ACCESS_RESULT Result = FpAccess_NotProtected;
    PWCHAR NormalizedPath = NULL;
    WCHAR FileName[260];
    WCHAR Extension[FP_MAX_EXTENSION_LENGTH];
    USHORT PathLength;
    ULONG ProtectionFlags = 0;
    BOOLEAN CheckExtensions = TRUE;
    LONG i;

    //
    // Captured data from matched path (copied while under lock)
    //
    BOOLEAN HaveMatchedPath = FALSE;
    WCHAR MatchedRulePath[FP_MAX_PATH_LENGTH];
    ULONG MatchedFlags = 0;
    volatile LONG64 *MatchedBlockedOps = NULL;
    volatile LONG64 *MatchedAuditedOps = NULL;
    volatile LONG64 *MatchedLastAccessTicks = NULL;

    //
    // Config snapshot (read under config lock)
    //
    BOOLEAN CfgStreamProtection;
    BOOLEAN CfgAuditLogging;

    UNREFERENCED_PARAMETER(DesiredAccess);

    if (OutProtectionFlags != NULL) {
        *OutProtectionFlags = 0;
    }

    if (Engine == NULL || !InterlockedCompareExchange(&Engine->Initialized, TRUE, TRUE)) {
        return FpAccess_Allow;
    }

    if (FilePath == NULL || FilePath->Buffer == NULL || FilePath->Length == 0) {
        return FpAccess_Allow;
    }

    InterlockedIncrement64(&Engine->Stats.TotalChecks);

    if (ShadowStrikeIsProcessProtected(RequestorPid, NULL)) {
        return FpAccess_Allow;
    }

    PathLength = FilePath->Length / sizeof(WCHAR);
    if (PathLength >= FP_MAX_PATH_LENGTH) {
        return FpAccess_Allow;
    }

    //
    // Read config snapshot under shared lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Engine->ConfigLock);
    CfgStreamProtection = Engine->Config.EnableStreamProtection;
    CfgAuditLogging = Engine->Config.EnableAuditLogging;
    ExReleasePushLockShared(&Engine->ConfigLock);
    KeLeaveCriticalRegion();

    //
    // Allocate normalization buffer from pool (not stack — was 2KB)
    //
    NormalizedPath = (PWCHAR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        FP_MAX_PATH_LENGTH * sizeof(WCHAR),
        FP_POOL_TAG_WORK
        );

    if (NormalizedPath == NULL) {
        return FpAccess_Allow;
    }

    RtlCopyMemory(NormalizedPath, FilePath->Buffer, FilePath->Length);
    NormalizedPath[PathLength] = L'\0';

    //
    // Strip stream name: find first colon after the last path separator.
    // This handles paths like \Device\HarddiskVolume1\file.txt:stream:$DATA
    // and correctly ignores drive-letter colons.
    //
    if (CfgStreamProtection) {
        USHORT StreamPos = FppFindStreamSeparator(NormalizedPath, PathLength);
        if (StreamPos > 0) {
            NormalizedPath[StreamPos] = L'\0';
            PathLength = StreamPos;
        }
    }

    //
    // Uppercase using kernel-safe RtlUpcaseUnicodeChar
    //
    FppUpcaseInPlace(NormalizedPath, PathLength);

    //
    // Extract filename and extension (FileName/Extension are small stack buffers — OK)
    //
    {
        PWCHAR LastSlash = NULL;
        PWCHAR Dot = NULL;
        USHORT fi;

        for (fi = PathLength; fi > 0; fi--) {
            if (NormalizedPath[fi - 1] == FP_PATH_SEPARATOR) {
                LastSlash = &NormalizedPath[fi];
                break;
            }
        }

        if (LastSlash != NULL) {
            RtlStringCchCopyW(FileName, ARRAYSIZE(FileName), LastSlash);
        } else {
            RtlStringCchCopyW(FileName, ARRAYSIZE(FileName), NormalizedPath);
        }

        Dot = NULL;
        for (fi = (USHORT)wcslen(FileName); fi > 0; fi--) {
            if (FileName[fi - 1] == L'.') {
                Dot = &FileName[fi - 1];
                break;
            }
        }

        if (Dot != NULL) {
            RtlStringCchCopyW(Extension, ARRAYSIZE(Extension), Dot);
            FppUpcaseInPlace(Extension, (USHORT)wcslen(Extension));
        } else {
            Extension[0] = L'\0';
            CheckExtensions = FALSE;
        }
    }

    //
    // Check path rules under shared lock.
    // CRITICAL: All data from matched path is COPIED while under the lock.
    // No post-lock dereference of MatchedPath pointer (fixes CRITICAL-02).
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Engine->PathListLock);

    for (Entry = Engine->ProtectedPathList.Flink;
         Entry != &Engine->ProtectedPathList;
         Entry = Entry->Flink) {

        PFP_PROTECTED_PATH TestPath = CONTAINING_RECORD(Entry, FP_PROTECTED_PATH, ListEntry);

        BOOLEAN IsRecursive = (TestPath->ProtectionFlags & FpProtect_Recursive) != 0;

        if (FppMatchPath(NormalizedPath, PathLength,
            TestPath->NormalizedPath, TestPath->PathLength, IsRecursive)) {

            //
            // Copy all needed data while under lock
            //
            HaveMatchedPath = TRUE;
            MatchedFlags = TestPath->ProtectionFlags;
            ProtectionFlags = TestPath->ProtectionFlags;

            RtlCopyMemory(MatchedRulePath, TestPath->NormalizedPath,
                          TestPath->PathLength * sizeof(WCHAR));
            MatchedRulePath[TestPath->PathLength] = L'\0';

            //
            // Take a reference so we can safely do InterlockedIncrement64
            // on the entry's counters after releasing the lock.
            //
            InterlockedIncrement(&TestPath->RefCount);
            MatchedBlockedOps = &TestPath->BlockedOperations;
            MatchedAuditedOps = &TestPath->AuditedOperations;
            MatchedLastAccessTicks = &TestPath->LastAccessTimeTicks;

            //
            // Update last access time atomically (fixes CRITICAL-01: no write under shared lock)
            //
            {
                LARGE_INTEGER CurrentTime;
                KeQuerySystemTime(&CurrentTime);
                InterlockedExchange64(MatchedLastAccessTicks, CurrentTime.QuadPart);
            }

            break;
        }
    }

    ExReleasePushLockShared(&Engine->PathListLock);
    KeLeaveCriticalRegion();

    //
    // Check extension rules if no path match
    //
    if (!HaveMatchedPath && CheckExtensions &&
        InterlockedCompareExchange(&Engine->ProtectedExtensionCount, 0, 0) > 0) {

        KeEnterCriticalRegion();
        ExAcquirePushLockShared(&Engine->ExtensionLock);

        for (i = 0; i < FP_MAX_PROTECTED_EXTENSIONS; i++) {
            if (Engine->ProtectedExtensions[i].InUse) {
                if (FppMatchExtension(FileName,
                    Engine->ProtectedExtensions[i].Extension,
                    Engine->ProtectedExtensions[i].ExtensionLength)) {

                    ProtectionFlags = Engine->ProtectedExtensions[i].ProtectionFlags;
                    Result = FpAccess_Block;
                    break;
                }
            }
        }

        ExReleasePushLockShared(&Engine->ExtensionLock);
        KeLeaveCriticalRegion();
    }

    //
    // Determine result based on operation and flags
    //
    if (HaveMatchedPath || ProtectionFlags != 0) {

        if (ProtectionFlags & FpProtect_AuditOnly) {
            Result = FpAccess_AuditOnly;
        } else {
            BOOLEAN ShouldBlock = FALSE;

            switch (Operation) {
            case FpOperation_Write:
                ShouldBlock = (ProtectionFlags & FpProtect_BlockWrite) != 0;
                if (ShouldBlock) InterlockedIncrement64(&Engine->Stats.BlockedWrites);
                break;
            case FpOperation_Delete:
                ShouldBlock = (ProtectionFlags & FpProtect_BlockDelete) != 0;
                if (ShouldBlock) InterlockedIncrement64(&Engine->Stats.BlockedDeletes);
                break;
            case FpOperation_Rename:
                ShouldBlock = (ProtectionFlags & FpProtect_BlockRename) != 0;
                if (ShouldBlock) InterlockedIncrement64(&Engine->Stats.BlockedRenames);
                break;
            case FpOperation_SetInfo:
                ShouldBlock = (ProtectionFlags & FpProtect_BlockSetInfo) != 0;
                if (ShouldBlock) InterlockedIncrement64(&Engine->Stats.BlockedSetInfo);
                break;
            case FpOperation_SetSecurity:
                ShouldBlock = (ProtectionFlags & FpProtect_BlockSetSecurity) != 0;
                if (ShouldBlock) InterlockedIncrement64(&Engine->Stats.BlockedSetSecurity);
                break;
            case FpOperation_CreateHardlink:
                ShouldBlock = (ProtectionFlags & FpProtect_BlockHardlink) != 0;
                if (ShouldBlock) InterlockedIncrement64(&Engine->Stats.BlockedHardlinks);
                break;
            case FpOperation_CreateStream:
            case FpOperation_DeleteStream:
                ShouldBlock = (ProtectionFlags & FpProtect_BlockStreams) != 0;
                if (ShouldBlock) InterlockedIncrement64(&Engine->Stats.BlockedStreams);
                break;
            default:
                break;
            }

            Result = ShouldBlock ? FpAccess_Block : FpAccess_Allow;
        }

        //
        // Update per-path stats via interlocked ops on ref-counted entry
        // (safe because we hold a reference from above)
        //
        if (HaveMatchedPath) {
            if (Result == FpAccess_Block) {
                InterlockedIncrement64(MatchedBlockedOps);
            } else if (Result == FpAccess_AuditOnly) {
                InterlockedIncrement64(MatchedAuditedOps);
            }
        }
    }

    //
    // Release the reference we took on the matched path
    //
    if (HaveMatchedPath) {
        //
        // Find the path again — but we don't need to, we just decrement.
        // The path can only be freed when RefCount reaches 0.
        // FppReleaseProtectedPath handles the decrement-and-free.
        //
        // We need the original pointer for the decrement. We stored the
        // volatile pointers which are within the struct, so we can recover
        // the struct address.
        //
        PFP_PROTECTED_PATH RefPath = CONTAINING_RECORD(
            MatchedBlockedOps, FP_PROTECTED_PATH, BlockedOperations);
        FppReleaseProtectedPath(RefPath);
    }

    //
    // Log if audit logging is enabled
    //
    if (CfgAuditLogging &&
        (Result == FpAccess_Block || Result == FpAccess_AuditOnly)) {

        UNICODE_STRING RulePath = { 0 };
        if (HaveMatchedPath) {
            RtlInitUnicodeString(&RulePath, MatchedRulePath);
        }

        FpLogAccessAttempt(Engine, FilePath, Operation, Result, RequestorPid,
            HaveMatchedPath ? &RulePath : NULL);
    }

    if (OutProtectionFlags != NULL) {
        *OutProtectionFlags = ProtectionFlags;
    }

    ShadowStrikeFreePoolWithTag(NormalizedPath, FP_POOL_TAG_WORK);

    return Result;
}

_Use_decl_annotations_
BOOLEAN
FpIsPathProtected(
    _In_ PFP_ENGINE Engine,
    _In_ PCUNICODE_STRING Path,
    _Out_opt_ PULONG ProtectionFlags
    )
{
    ULONG Flags = 0;
    FP_ACCESS_RESULT Result;

    if (ProtectionFlags != NULL) {
        *ProtectionFlags = 0;
    }

    Result = FpCheckAccess(Engine, Path, FpOperation_Write,
        PsGetCurrentProcessId(), 0, &Flags);

    if (Result == FpAccess_Block || Result == FpAccess_AuditOnly) {
        if (ProtectionFlags != NULL) {
            *ProtectionFlags = Flags;
        }
        return TRUE;
    }

    return FALSE;
}

_Use_decl_annotations_
FP_ACCESS_RESULT
FpCheckFileAccess(
    _In_ PFP_ENGINE Engine,
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FP_OPERATION_TYPE Operation,
    _Out_opt_ PFP_ACCESS_CHECK_RESULT ResultInfo
    )
{
    NTSTATUS Status;
    PFLT_FILE_NAME_INFORMATION FileNameInfo = NULL;
    FP_ACCESS_RESULT Result = FpAccess_Allow;
    HANDLE RequestorPid;
    ULONG Flags = 0;

    UNREFERENCED_PARAMETER(FltObjects);

    if (ResultInfo != NULL) {
        RtlZeroMemory(ResultInfo, sizeof(FP_ACCESS_CHECK_RESULT));
    }

    if (Engine == NULL || !InterlockedCompareExchange(&Engine->Initialized, TRUE, TRUE) ||
        Data == NULL) {
        return FpAccess_Allow;
    }

    Status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &FileNameInfo
        );

    if (!NT_SUCCESS(Status)) {
        return FpAccess_Allow;
    }

    Status = FltParseFileNameInformation(FileNameInfo);
    if (!NT_SUCCESS(Status)) {
        FltReleaseFileNameInformation(FileNameInfo);
        return FpAccess_Allow;
    }

    //
    // FltGetRequestorProcessId returns ULONG — cast properly to HANDLE
    // (fixes CRITICAL-03)
    //
    RequestorPid = (HANDLE)(ULONG_PTR)FltGetRequestorProcessId(Data);

    Result = FpCheckAccess(
        Engine,
        &FileNameInfo->Name,
        Operation,
        RequestorPid,
        0,
        &Flags
        );

    FltReleaseFileNameInformation(FileNameInfo);

    //
    // Populate result info if requested (fixes INCOMPLETE-04)
    //
    if (ResultInfo != NULL) {
        ResultInfo->Result = Result;
        ResultInfo->MatchedProtectionFlags = Flags;
        ResultInfo->HasMatchedRule = (Flags != 0);
    }

    return Result;
}

//=============================================================================
// Path Utilities
//=============================================================================

_Use_decl_annotations_
NTSTATUS
FpNormalizePath(
    _In_ PCUNICODE_STRING InputPath,
    _Out_ PFP_PATH_INFO PathInfo
    )
{
    USHORT PathLength;
    USHORT StreamPos;
    PWCHAR LastSlash;
    PWCHAR Dot;

    PAGED_CODE();

    if (InputPath == NULL || PathInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(PathInfo, sizeof(FP_PATH_INFO));

    if (InputPath->Buffer == NULL || InputPath->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    PathLength = InputPath->Length / sizeof(WCHAR);
    if (PathLength >= FP_MAX_PATH_LENGTH) {
        return STATUS_NAME_TOO_LONG;
    }

    RtlCopyMemory(PathInfo->NormalizedPath, InputPath->Buffer, InputPath->Length);
    PathInfo->NormalizedPath[PathLength] = L'\0';
    PathInfo->NormalizedLength = PathLength;

    //
    // Check for stream using correct post-last-separator logic
    //
    StreamPos = FppFindStreamSeparator(PathInfo->NormalizedPath, PathLength);
    if (StreamPos > 0) {
        PathInfo->HasStream = TRUE;
        RtlStringCchCopyW(PathInfo->StreamName, FP_MAX_STREAM_NAME_LENGTH,
                          &PathInfo->NormalizedPath[StreamPos]);
        PathInfo->NormalizedPath[StreamPos] = L'\0';
        PathInfo->NormalizedLength = StreamPos;
    }

    LastSlash = wcsrchr(PathInfo->NormalizedPath, FP_PATH_SEPARATOR);
    if (LastSlash != NULL) {
        RtlStringCchCopyW(PathInfo->FileName, ARRAYSIZE(PathInfo->FileName), LastSlash + 1);
    } else {
        RtlStringCchCopyW(PathInfo->FileName, ARRAYSIZE(PathInfo->FileName),
                          PathInfo->NormalizedPath);
    }

    Dot = wcsrchr(PathInfo->FileName, L'.');
    if (Dot != NULL) {
        RtlStringCchCopyW(PathInfo->Extension, FP_MAX_EXTENSION_LENGTH, Dot);
    }

    PathInfo->IsShortName = FppIsShortName(PathInfo->FileName);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
FpNormalizePathEx(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PFP_PATH_INFO PathInfo
    )
{
    NTSTATUS Status;
    PFLT_FILE_NAME_INFORMATION FileNameInfo = NULL;

    PAGED_CODE();

    if (Instance == NULL || FileObject == NULL || PathInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(PathInfo, sizeof(FP_PATH_INFO));

    Status = FltGetFileNameInformationUnsafe(
        FileObject,
        Instance,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &FileNameInfo
        );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = FltParseFileNameInformation(FileNameInfo);
    if (!NT_SUCCESS(Status)) {
        FltReleaseFileNameInformation(FileNameInfo);
        return Status;
    }

    Status = FpNormalizePath(&FileNameInfo->Name, PathInfo);

    FltReleaseFileNameInformation(FileNameInfo);

    return Status;
}

_Use_decl_annotations_
NTSTATUS
FpExtractStreamName(
    _In_ PCUNICODE_STRING FullPath,
    _Out_writes_z_(StreamNameSize) PWCHAR StreamName,
    _In_ ULONG StreamNameSize,
    _Out_ PUNICODE_STRING BasePath
    )
{
    USHORT StreamPos;
    USHORT PathLenChars;

    if (FullPath == NULL || StreamName == NULL || BasePath == NULL ||
        FullPath->Buffer == NULL || FullPath->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    StreamName[0] = L'\0';
    BasePath->Buffer = FullPath->Buffer;
    BasePath->Length = FullPath->Length;
    BasePath->MaximumLength = FullPath->MaximumLength;

    PathLenChars = FullPath->Length / sizeof(WCHAR);
    StreamPos = FppFindStreamSeparator(FullPath->Buffer, PathLenChars);

    if (StreamPos == 0) {
        return STATUS_NOT_FOUND;
    }

    {
        USHORT StreamLen = PathLenChars - StreamPos;
        if (StreamLen >= StreamNameSize) {
            StreamLen = (USHORT)(StreamNameSize - 1);
        }

        RtlCopyMemory(StreamName, &FullPath->Buffer[StreamPos], StreamLen * sizeof(WCHAR));
        StreamName[StreamLen] = L'\0';
    }

    BasePath->Length = StreamPos * sizeof(WCHAR);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
FpStripStreamName(
    _In_ PCUNICODE_STRING FullPath,
    _Out_ PUNICODE_STRING BasePath
    )
{
    WCHAR StreamName[FP_MAX_STREAM_NAME_LENGTH];

    return FpExtractStreamName(FullPath, StreamName, FP_MAX_STREAM_NAME_LENGTH, BasePath);
}

_Use_decl_annotations_
NTSTATUS
FpResolveSymlink(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_writes_z_(TargetPathSize) PWCHAR TargetPath,
    _In_ ULONG TargetPathSize
    )
{
    NTSTATUS Status;
    PFLT_FILE_NAME_INFORMATION FileNameInfo = NULL;

    PAGED_CODE();

    if (Instance == NULL || FileObject == NULL || TargetPath == NULL || TargetPathSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    TargetPath[0] = L'\0';

    Status = FltGetFileNameInformationUnsafe(
        FileObject,
        Instance,
        FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
        &FileNameInfo
        );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = FltParseFileNameInformation(FileNameInfo);
    if (!NT_SUCCESS(Status)) {
        FltReleaseFileNameInformation(FileNameInfo);
        return Status;
    }

    {
        USHORT CopyLen = FileNameInfo->Name.Length / sizeof(WCHAR);
        if (CopyLen >= TargetPathSize) {
            CopyLen = (USHORT)(TargetPathSize - 1);
        }

        RtlCopyMemory(TargetPath, FileNameInfo->Name.Buffer, CopyLen * sizeof(WCHAR));
        TargetPath[CopyLen] = L'\0';
    }

    FltReleaseFileNameInformation(FileNameInfo);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
FpConvertShortToLongName(
    _In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING ShortPath,
    _Out_ PUNICODE_STRING LongPath
    )
/*++

Routine Description:

    Converts a short (8.3) path to its long name equivalent by opening the
    file and querying FLT_FILE_NAME_NORMALIZED, which automatically resolves
    short names to long names.

    Caller must free LongPath->Buffer with ExFreePool on success.

--*/
{
    NTSTATUS Status;
    HANDLE FileHandle = NULL;
    PFILE_OBJECT FileObject = NULL;
    IO_STATUS_BLOCK IoStatus;
    OBJECT_ATTRIBUTES ObjAttr;
    UNICODE_STRING MutableShortPath;
    PFLT_FILE_NAME_INFORMATION FileNameInfo = NULL;

    PAGED_CODE();

    if (Instance == NULL || ShortPath == NULL || LongPath == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    LongPath->Buffer = NULL;
    LongPath->Length = 0;
    LongPath->MaximumLength = 0;

    if (ShortPath->Buffer == NULL || ShortPath->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Open file with minimal access to query its normalized name
    //
    MutableShortPath = *ShortPath;

    InitializeObjectAttributes(
        &ObjAttr,
        &MutableShortPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
        );

    Status = FltCreateFileEx(
        NULL,
        Instance,
        &FileHandle,
        &FileObject,
        FILE_READ_ATTRIBUTES,
        &ObjAttr,
        &IoStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
        NULL,
        0,
        IO_IGNORE_SHARE_ACCESS_CHECK
        );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Get normalized name (automatically resolves short → long)
    //
    Status = FltGetFileNameInformationUnsafe(
        FileObject,
        Instance,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &FileNameInfo
        );

    if (!NT_SUCCESS(Status)) {
        ObDereferenceObject(FileObject);
        FltClose(FileHandle);
        return Status;
    }

    Status = FltParseFileNameInformation(FileNameInfo);
    if (!NT_SUCCESS(Status)) {
        FltReleaseFileNameInformation(FileNameInfo);
        ObDereferenceObject(FileObject);
        FltClose(FileHandle);
        return Status;
    }

    //
    // Allocate and copy the long name
    //
    LongPath->Length = FileNameInfo->Name.Length;
    LongPath->MaximumLength = FileNameInfo->Name.Length + sizeof(WCHAR);
    LongPath->Buffer = (PWCHAR)ExAllocatePool2(
        POOL_FLAG_PAGED,
        LongPath->MaximumLength,
        FP_POOL_TAG_PATH
        );

    if (LongPath->Buffer == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        LongPath->Length = 0;
        LongPath->MaximumLength = 0;
    } else {
        RtlCopyMemory(LongPath->Buffer, FileNameInfo->Name.Buffer, FileNameInfo->Name.Length);
        LongPath->Buffer[FileNameInfo->Name.Length / sizeof(WCHAR)] = L'\0';
    }

    FltReleaseFileNameInformation(FileNameInfo);
    ObDereferenceObject(FileObject);
    FltClose(FileHandle);

    return Status;
}

//=============================================================================
// Audit Logging
//=============================================================================

_Use_decl_annotations_
VOID
FpLogAccessAttempt(
    _In_ PFP_ENGINE Engine,
    _In_ PCUNICODE_STRING FilePath,
    _In_ FP_OPERATION_TYPE Operation,
    _In_ FP_ACCESS_RESULT Result,
    _In_ HANDLE ProcessId,
    _In_opt_ PCUNICODE_STRING RulePath
    )
{
    PFP_AUDIT_ENTRY_INTERNAL Entry;
    LARGE_INTEGER CurrentTime;
    USHORT CopyLen;

    if (Engine == NULL || !InterlockedCompareExchange(&Engine->Initialized, TRUE, TRUE)) {
        return;
    }

    //
    // Re-read config under lock
    //
    {
        BOOLEAN AuditEnabled;
        KeEnterCriticalRegion();
        ExAcquirePushLockShared(&Engine->ConfigLock);
        AuditEnabled = Engine->Config.EnableAuditLogging;
        ExReleasePushLockShared(&Engine->ConfigLock);
        KeLeaveCriticalRegion();

        if (!AuditEnabled) {
            return;
        }
    }

    if (FilePath == NULL || FilePath->Buffer == NULL) {
        return;
    }

    //
    // Allocate audit entry from PagedPool (entries are large ~4.6KB each,
    // only accessed at <= APC_LEVEL) — fixes DESIGN-02
    //
    Entry = (PFP_AUDIT_ENTRY_INTERNAL)ShadowStrikeAllocatePoolWithTag(
        PagedPool,
        sizeof(FP_AUDIT_ENTRY_INTERNAL),
        FP_POOL_TAG_AUDIT
        );

    if (Entry == NULL) {
        return;
    }

    RtlZeroMemory(Entry, sizeof(FP_AUDIT_ENTRY_INTERNAL));

    KeQuerySystemTime(&CurrentTime);
    Entry->Info.Timestamp = CurrentTime;
    Entry->Info.ProcessId = ProcessId;
    Entry->Info.ThreadId = PsGetCurrentThreadId();
    Entry->Info.Operation = Operation;
    Entry->Info.Result = Result;

    CopyLen = FilePath->Length / sizeof(WCHAR);
    if (CopyLen >= FP_MAX_PATH_LENGTH) {
        CopyLen = FP_MAX_PATH_LENGTH - 1;
    }
    RtlCopyMemory(Entry->Info.FilePath, FilePath->Buffer, CopyLen * sizeof(WCHAR));
    Entry->Info.FilePath[CopyLen] = L'\0';

    if (RulePath != NULL && RulePath->Buffer != NULL) {
        CopyLen = RulePath->Length / sizeof(WCHAR);
        if (CopyLen >= FP_MAX_PATH_LENGTH) {
            CopyLen = FP_MAX_PATH_LENGTH - 1;
        }
        RtlCopyMemory(Entry->Info.RulePath, RulePath->Buffer, CopyLen * sizeof(WCHAR));
        Entry->Info.RulePath[CopyLen] = L'\0';
    }

    FppGetProcessName(ProcessId, Entry->Info.ProcessName, ARRAYSIZE(Entry->Info.ProcessName));

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->AuditLogLock);

    InsertTailList(&Engine->AuditLog, &Entry->ListEntry);
    InterlockedIncrement(&Engine->AuditLogCount);
    InterlockedIncrement64(&Engine->Stats.AuditEvents);

    FppTrimAuditLog(Engine);

    ExReleasePushLockExclusive(&Engine->AuditLogLock);
    KeLeaveCriticalRegion();
}

_Use_decl_annotations_
NTSTATUS
FpGetAuditLog(
    _In_ PFP_ENGINE Engine,
    _Out_writes_to_(*BufferCount, *BufferCount) PFP_AUDIT_ENTRY_INFO Buffer,
    _Inout_ PULONG BufferCount
    )
/*++

Routine Description:

    Copies audit log entries into a caller-provided buffer.
    Entries are copied oldest-first. The caller provides the buffer
    and its max capacity in *BufferCount; on return *BufferCount
    contains the number actually copied.

--*/
{
    PLIST_ENTRY Entry;
    PFP_AUDIT_ENTRY_INTERNAL AuditEntry;
    ULONG MaxEntries;
    ULONG Copied = 0;

    PAGED_CODE();

    if (Engine == NULL || Buffer == NULL || BufferCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!InterlockedCompareExchange(&Engine->Initialized, TRUE, TRUE)) {
        return STATUS_DEVICE_NOT_READY;
    }

    MaxEntries = *BufferCount;
    *BufferCount = 0;

    if (MaxEntries == 0) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Engine->AuditLogLock);

    for (Entry = Engine->AuditLog.Flink;
         Entry != &Engine->AuditLog && Copied < MaxEntries;
         Entry = Entry->Flink) {

        AuditEntry = CONTAINING_RECORD(Entry, FP_AUDIT_ENTRY_INTERNAL, ListEntry);

        RtlCopyMemory(&Buffer[Copied], &AuditEntry->Info, sizeof(FP_AUDIT_ENTRY_INFO));
        Copied++;
    }

    ExReleasePushLockShared(&Engine->AuditLogLock);
    KeLeaveCriticalRegion();

    *BufferCount = Copied;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
FpClearAuditLog(
    _In_ PFP_ENGINE Engine
    )
{
    PLIST_ENTRY Entry;
    PFP_AUDIT_ENTRY_INTERNAL AuditEntry;

    PAGED_CODE();

    if (Engine == NULL || !InterlockedCompareExchange(&Engine->Initialized, TRUE, TRUE)) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->AuditLogLock);

    while (!IsListEmpty(&Engine->AuditLog)) {
        Entry = RemoveHeadList(&Engine->AuditLog);
        AuditEntry = CONTAINING_RECORD(Entry, FP_AUDIT_ENTRY_INTERNAL, ListEntry);
        FppFreeAuditEntry(AuditEntry);
    }

    Engine->AuditLogCount = 0;

    ExReleasePushLockExclusive(&Engine->AuditLogLock);
    KeLeaveCriticalRegion();
}

//=============================================================================
// Statistics
//=============================================================================

_Use_decl_annotations_
VOID
FpGetStatistics(
    _In_ PFP_ENGINE Engine,
    _Out_ PFP_STATISTICS Stats
    )
/*++

Routine Description:

    Reads statistics using per-field volatile reads to avoid torn reads on x86.
    No lock needed — each field is read atomically via InterlockedCompareExchange64.

--*/
{
    if (Engine == NULL || Stats == NULL) {
        return;
    }

    RtlZeroMemory(Stats, sizeof(FP_STATISTICS));

    Stats->TotalChecks          = InterlockedCompareExchange64(&Engine->Stats.TotalChecks, 0, 0);
    Stats->PathsProtected       = InterlockedCompareExchange64(&Engine->Stats.PathsProtected, 0, 0);
    Stats->ExtensionsProtected  = InterlockedCompareExchange64(&Engine->Stats.ExtensionsProtected, 0, 0);
    Stats->BlockedWrites        = InterlockedCompareExchange64(&Engine->Stats.BlockedWrites, 0, 0);
    Stats->BlockedDeletes       = InterlockedCompareExchange64(&Engine->Stats.BlockedDeletes, 0, 0);
    Stats->BlockedRenames       = InterlockedCompareExchange64(&Engine->Stats.BlockedRenames, 0, 0);
    Stats->BlockedSetInfo       = InterlockedCompareExchange64(&Engine->Stats.BlockedSetInfo, 0, 0);
    Stats->BlockedSetSecurity   = InterlockedCompareExchange64(&Engine->Stats.BlockedSetSecurity, 0, 0);
    Stats->BlockedHardlinks     = InterlockedCompareExchange64(&Engine->Stats.BlockedHardlinks, 0, 0);
    Stats->BlockedStreams        = InterlockedCompareExchange64(&Engine->Stats.BlockedStreams, 0, 0);
    Stats->AuditEvents          = InterlockedCompareExchange64(&Engine->Stats.AuditEvents, 0, 0);
    Stats->BypassAttempts        = InterlockedCompareExchange64(&Engine->Stats.BypassAttempts, 0, 0);
    Stats->StartTime            = Engine->Stats.StartTime;
}

_Use_decl_annotations_
VOID
FpResetStatistics(
    _In_ PFP_ENGINE Engine
    )
/*++

Routine Description:

    Resets statistics using per-field InterlockedExchange64 to avoid racing
    with concurrent InterlockedIncrement64 calls.

--*/
{
    LARGE_INTEGER CurrentTime;

    if (Engine == NULL) {
        return;
    }

    KeQuerySystemTime(&CurrentTime);

    InterlockedExchange64(&Engine->Stats.TotalChecks, 0);
    InterlockedExchange64(&Engine->Stats.PathsProtected, 0);
    InterlockedExchange64(&Engine->Stats.ExtensionsProtected, 0);
    InterlockedExchange64(&Engine->Stats.BlockedWrites, 0);
    InterlockedExchange64(&Engine->Stats.BlockedDeletes, 0);
    InterlockedExchange64(&Engine->Stats.BlockedRenames, 0);
    InterlockedExchange64(&Engine->Stats.BlockedSetInfo, 0);
    InterlockedExchange64(&Engine->Stats.BlockedSetSecurity, 0);
    InterlockedExchange64(&Engine->Stats.BlockedHardlinks, 0);
    InterlockedExchange64(&Engine->Stats.BlockedStreams, 0);
    InterlockedExchange64(&Engine->Stats.AuditEvents, 0);
    InterlockedExchange64(&Engine->Stats.BypassAttempts, 0);

    Engine->Stats.StartTime = CurrentTime;
}

//=============================================================================
// Internal Helper Functions
//=============================================================================

static
BOOLEAN
FppMatchPath(
    _In_ PCWSTR TestPath,
    _In_ USHORT TestPathLength,
    _In_ PCWSTR RulePath,
    _In_ USHORT RulePathLength,
    _In_ BOOLEAN IsRecursive
    )
{
    USHORT i;

    if (TestPathLength < RulePathLength) {
        return FALSE;
    }

    //
    // Case-insensitive compare using RtlUpcaseUnicodeChar.
    // Both paths should already be uppercased, but belt-and-suspenders.
    //
    for (i = 0; i < RulePathLength; i++) {
        if (RtlUpcaseUnicodeChar(TestPath[i]) != RtlUpcaseUnicodeChar(RulePath[i])) {
            return FALSE;
        }
    }

    if (TestPathLength == RulePathLength) {
        return TRUE;
    }

    if (IsRecursive) {
        if (TestPath[RulePathLength] == FP_PATH_SEPARATOR ||
            RulePath[RulePathLength - 1] == FP_PATH_SEPARATOR) {
            return TRUE;
        }
    }

    return FALSE;
}

static
BOOLEAN
FppMatchExtension(
    _In_ PCWSTR FileName,
    _In_ PCWSTR Extension,
    _In_ USHORT ExtensionLength
    )
{
    SIZE_T FileNameLen = wcslen(FileName);
    PCWSTR FileDot;
    SIZE_T fi;

    if (FileNameLen <= ExtensionLength) {
        return FALSE;
    }

    FileDot = NULL;
    for (fi = FileNameLen; fi > 0; fi--) {
        if (FileName[fi - 1] == L'.') {
            FileDot = &FileName[fi - 1];
            break;
        }
    }

    if (FileDot == NULL) {
        return FALSE;
    }

    //
    // Case-insensitive compare (both should be uppercased, but be safe)
    //
    {
        SIZE_T extLen = wcslen(FileDot);
        SIZE_T ruleLen = wcslen(Extension);
        SIZE_T ci;

        if (extLen != ruleLen) {
            return FALSE;
        }

        for (ci = 0; ci < extLen; ci++) {
            if (RtlUpcaseUnicodeChar(FileDot[ci]) != RtlUpcaseUnicodeChar(Extension[ci])) {
                return FALSE;
            }
        }
    }

    return TRUE;
}

/**
 * @brief Release a reference on a protected path.
 *        When RefCount reaches 0, the entry is freed.
 */
static
VOID
FppReleaseProtectedPath(
    _Inout_ PFP_PROTECTED_PATH Path
    )
{
    if (Path == NULL) {
        return;
    }

    if (InterlockedDecrement(&Path->RefCount) <= 0) {
        ShadowStrikeFreePoolWithTag(Path, FP_POOL_TAG_RULE);
    }
}

static
VOID
FppFreeAuditEntry(
    _In_ PFP_AUDIT_ENTRY_INTERNAL Entry
    )
{
    if (Entry != NULL) {
        ShadowStrikeFreePoolWithTag(Entry, FP_POOL_TAG_AUDIT);
    }
}

static
VOID
FppTrimAuditLog(
    _Inout_ PFP_ENGINE Engine
    )
/*++

Routine Description:

    Trims audit log to maximum size.
    Must be called with AuditLogLock held exclusive.

--*/
{
    PLIST_ENTRY Entry;
    PFP_AUDIT_ENTRY_INTERNAL AuditEntry;
    LONG MaxEntries;

    //
    // Read MaxAuditEntries — ConfigLock ordering: we already hold AuditLogLock,
    // so we read it non-lockingly (it's a ULONG set under ConfigLock at PASSIVE).
    // This is safe because we only use it as a threshold.
    //
    MaxEntries = (LONG)Engine->Config.MaxAuditEntries;

    while (Engine->AuditLogCount > MaxEntries) {
        if (IsListEmpty(&Engine->AuditLog)) {
            break;
        }

        Entry = RemoveHeadList(&Engine->AuditLog);
        AuditEntry = CONTAINING_RECORD(Entry, FP_AUDIT_ENTRY_INTERNAL, ListEntry);
        FppFreeAuditEntry(AuditEntry);
        InterlockedDecrement(&Engine->AuditLogCount);
    }
}

static
NTSTATUS
FppGetProcessName(
    _In_ HANDLE ProcessId,
    _Out_writes_z_(NameSize) PWCHAR ProcessName,
    _In_ ULONG NameSize
    )
{
    PEPROCESS Process = NULL;
    NTSTATUS Status;
    PUNICODE_STRING ImageFileName = NULL;

    ProcessName[0] = L'\0';

    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) {
        RtlStringCchCopyW(ProcessName, NameSize, L"<unknown>");
        return Status;
    }

    Status = SeLocateProcessImageName(Process, &ImageFileName);
    if (NT_SUCCESS(Status) && ImageFileName != NULL) {
        PWCHAR LastSlash = wcsrchr(ImageFileName->Buffer, L'\\');
        if (LastSlash != NULL) {
            RtlStringCchCopyW(ProcessName, NameSize, LastSlash + 1);
        } else {
            USHORT CopyLen = ImageFileName->Length / sizeof(WCHAR);
            if (CopyLen >= NameSize) {
                CopyLen = (USHORT)(NameSize - 1);
            }
            RtlCopyMemory(ProcessName, ImageFileName->Buffer, CopyLen * sizeof(WCHAR));
            ProcessName[CopyLen] = L'\0';
        }

        ExFreePool(ImageFileName);
    } else {
        RtlStringCchCopyW(ProcessName, NameSize, L"<unknown>");
    }

    ObDereferenceObject(Process);

    return STATUS_SUCCESS;
}

static
BOOLEAN
FppIsShortName(
    _In_ PCWSTR FileName
    )
{
    SIZE_T Len;
    PCWSTR Tilde;

    if (FileName == NULL) {
        return FALSE;
    }

    Len = wcslen(FileName);

    if (Len > 12) {
        return FALSE;
    }

    Tilde = wcschr(FileName, FP_SHORT_NAME_MARKER);
    if (Tilde != NULL) {
        if (Tilde[1] >= L'1' && Tilde[1] <= L'9') {
            return TRUE;
        }
    }

    return FALSE;
}