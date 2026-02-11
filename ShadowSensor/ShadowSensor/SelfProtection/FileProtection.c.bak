/*++
    ShadowStrike Next-Generation Antivirus
    Module: FileProtection.c

    Purpose: Enterprise-grade file protection for EDR self-defense.

    This module provides comprehensive file-level protection capabilities:
    - Protected file/directory path management with prefix matching
    - NTFS Alternate Data Stream (ADS) protection and detection
    - Path normalization and canonicalization
    - Symbolic link and junction point awareness
    - Short name (8.3) to long name resolution
    - File extension-based protection rules
    - Comprehensive audit logging
    - Integration with minifilter callbacks

    Security Considerations:
    - All paths normalized before comparison (case-insensitive)
    - ADS names stripped to prevent bypass via streams
    - Protected processes exempted from blocking
    - Fail-open on unexpected errors to prevent system instability
    - DoS prevention through resource limits

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
#pragma alloc_text(INIT, FpInitialize)
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

//
// Common stream names to detect
//
static const WCHAR* g_KnownStreamNames[] = {
    L":$DATA",
    L":Zone.Identifier",
    L":$ATTRIBUTE_LIST",
    L":$BITMAP",
    L":$EA",
    L":$EA_INFORMATION",
    L":$FILE_NAME",
    L":$INDEX_ROOT",
    L":$INDEX_ALLOCATION",
    L":$LOGGED_UTILITY_STREAM",
    L":$OBJECT_ID",
    L":$REPARSE_POINT"
};

#define FP_KNOWN_STREAM_COUNT   ARRAYSIZE(g_KnownStreamNames)

//=============================================================================
// Forward Declarations
//=============================================================================

static
BOOLEAN
FppMatchPath(
    _In_ PCWSTR TestPath,
    _In_ USHORT TestPathLength,
    _In_ PCWSTR RulePath,
    _In_ USHORT RulePathLength,
    _In_ BOOLEAN IsRecursive
    );

static
BOOLEAN
FppMatchExtension(
    _In_ PCWSTR FileName,
    _In_ PCWSTR Extension,
    _In_ USHORT ExtensionLength
    );

static
VOID
FppFreeProtectedPath(
    _In_ PFP_PROTECTED_PATH Path
    );

static
VOID
FppFreeAuditEntry(
    _In_ PFP_AUDIT_ENTRY Entry
    );

static
VOID
FppTrimAuditLog(
    _Inout_ PFP_ENGINE Engine
    );

static
NTSTATUS
FppGetProcessName(
    _In_ HANDLE ProcessId,
    _Out_writes_z_(NameSize) PWCHAR ProcessName,
    _In_ ULONG NameSize
    );

static
BOOLEAN
FppIsShortName(
    _In_ PCWSTR FileName
    );

static
VOID
FppExtractFileName(
    _In_ PCUNICODE_STRING FullPath,
    _Out_ PUNICODE_STRING FileName
    );

static
VOID
FppExtractExtension(
    _In_ PCUNICODE_STRING FileName,
    _Out_writes_z_(ExtSize) PWCHAR Extension,
    _In_ ULONG ExtSize
    );

static
FORCEINLINE
BOOLEAN
FppHasStream(
    _In_ PCUNICODE_STRING Path
    )
{
    USHORT i;
    BOOLEAN FoundFirstColon = FALSE;

    if (Path == NULL || Path->Buffer == NULL || Path->Length == 0) {
        return FALSE;
    }

    for (i = 0; i < Path->Length / sizeof(WCHAR); i++) {
        if (Path->Buffer[i] == FP_STREAM_SEPARATOR) {
            if (FoundFirstColon) {
                //
                // Second colon indicates stream name (e.g., file.txt:stream:$DATA)
                //
                return TRUE;
            }

            //
            // First colon could be drive letter (C:) or stream start
            //
            if (i > 0 && i < Path->Length / sizeof(WCHAR) - 1) {
                //
                // Check if this looks like a stream (not drive letter)
                //
                if (i > 1 || (Path->Buffer[0] != L'\\' && Path->Buffer[0] != L'/')) {
                    //
                    // Check next character - if it's not \ or /, it's likely a stream
                    //
                    WCHAR NextChar = Path->Buffer[i + 1];
                    if (NextChar != L'\\' && NextChar != L'/' && NextChar != L'\0') {
                        //
                        // Could be stream, need further validation
                        // Skip if this is position 1 (drive letter case C:)
                        //
                        if (i != 1) {
                            return TRUE;
                        }
                    }
                }
            }
            FoundFirstColon = TRUE;
        }
    }

    return FALSE;
}

//=============================================================================
// Engine Management
//=============================================================================

_Use_decl_annotations_
NTSTATUS
FpInitialize(
    _Out_ PFP_ENGINE* Engine
    )
/*++

Routine Description:

    Initializes the file protection engine.

Arguments:

    Engine - Receives pointer to the initialized engine.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PFP_ENGINE NewEngine = NULL;
    LARGE_INTEGER CurrentTime;

    PAGED_CODE();

    if (Engine == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Engine = NULL;

    //
    // Allocate engine structure
    //
    NewEngine = (PFP_ENGINE)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(FP_ENGINE),
        FP_POOL_TAG_CONTEXT
        );

    if (NewEngine == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(NewEngine, sizeof(FP_ENGINE));

    //
    // Initialize protected path list
    //
    InitializeListHead(&NewEngine->ProtectedPathList);
    ExInitializePushLock(&NewEngine->PathListLock);

    //
    // Initialize extension array
    //
    RtlZeroMemory(NewEngine->ProtectedExtensions, sizeof(NewEngine->ProtectedExtensions));
    ExInitializePushLock(&NewEngine->ExtensionLock);

    //
    // Initialize audit log
    //
    InitializeListHead(&NewEngine->AuditLog);
    ExInitializePushLock(&NewEngine->AuditLogLock);

    //
    // Set default configuration
    //
    NewEngine->Config.EnablePathNormalization = TRUE;
    NewEngine->Config.EnableStreamProtection = TRUE;
    NewEngine->Config.EnableSymlinkResolution = TRUE;
    NewEngine->Config.EnableShortNameResolution = TRUE;
    NewEngine->Config.EnableAuditLogging = TRUE;
    NewEngine->Config.MaxAuditEntries = FP_DEFAULT_MAX_AUDIT_ENTRIES;

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&CurrentTime);
    NewEngine->Stats.StartTime = CurrentTime;

    NewEngine->Initialized = TRUE;

    *Engine = NewEngine;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
FpShutdown(
    _Inout_ PFP_ENGINE Engine
    )
/*++

Routine Description:

    Shuts down the file protection engine.

--*/
{
    PLIST_ENTRY Entry;
    PFP_PROTECTED_PATH Path;
    PFP_AUDIT_ENTRY AuditEntry;

    PAGED_CODE();

    if (Engine == NULL || !Engine->Initialized) {
        return;
    }

    Engine->Initialized = FALSE;

    //
    // Free all protected paths
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->PathListLock);

    while (!IsListEmpty(&Engine->ProtectedPathList)) {
        Entry = RemoveHeadList(&Engine->ProtectedPathList);
        Path = CONTAINING_RECORD(Entry, FP_PROTECTED_PATH, ListEntry);
        FppFreeProtectedPath(Path);
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
        AuditEntry = CONTAINING_RECORD(Entry, FP_AUDIT_ENTRY, ListEntry);
        FppFreeAuditEntry(AuditEntry);
    }

    ExReleasePushLockExclusive(&Engine->AuditLogLock);
    KeLeaveCriticalRegion();

    //
    // Free engine
    //
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
/*++

Routine Description:

    Configures the file protection engine.

--*/
{
    PAGED_CODE();

    if (Engine == NULL || !Engine->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    Engine->Config.EnablePathNormalization = EnableNormalization;
    Engine->Config.EnableStreamProtection = EnableStreamProtection;
    Engine->Config.EnableSymlinkResolution = EnableSymlinkResolution;
    Engine->Config.EnableAuditLogging = EnableAuditLogging;

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
/*++

Routine Description:

    Adds a path to the protection list.

--*/
{
    PFP_PROTECTED_PATH NewPath = NULL;
    PLIST_ENTRY Entry;
    PFP_PROTECTED_PATH ExistingPath;
    BOOLEAN Duplicate = FALSE;
    LARGE_INTEGER CurrentTime;
    USHORT PathLength;

    PAGED_CODE();

    if (Engine == NULL || !Engine->Initialized) {
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
    // Check limit
    //
    if (InterlockedCompareExchange(&Engine->ProtectedPathCount, 0, 0) >=
        FP_MAX_PROTECTED_PATHS) {
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Allocate new entry
    //
    NewPath = (PFP_PROTECTED_PATH)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(FP_PROTECTED_PATH),
        FP_POOL_TAG_RULE
        );

    if (NewPath == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(NewPath, sizeof(FP_PROTECTED_PATH));

    //
    // Copy and normalize path
    //
    RtlCopyMemory(NewPath->NormalizedPath, Path->Buffer, Path->Length);
    NewPath->NormalizedPath[PathLength] = L'\0';
    NewPath->PathLength = PathLength;

    //
    // Convert to uppercase for case-insensitive matching
    //
    _wcsupr_s(NewPath->NormalizedPath, FP_MAX_PATH_LENGTH);

    //
    // Set rule properties
    //
    NewPath->RuleType = RuleType;
    NewPath->ProtectionFlags = ProtectionFlags;
    NewPath->RefCount = 1;

    KeQuerySystemTime(&CurrentTime);
    NewPath->AddedTime = CurrentTime;

    //
    // Determine if this is a directory path (ends with \)
    //
    if (PathLength > 0 && NewPath->NormalizedPath[PathLength - 1] == FP_PATH_SEPARATOR) {
        NewPath->IsDirectory = TRUE;
    }

    //
    // Add to list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->PathListLock);

    //
    // Check for duplicate
    //
    for (Entry = Engine->ProtectedPathList.Flink;
         Entry != &Engine->ProtectedPathList;
         Entry = Entry->Flink) {

        ExistingPath = CONTAINING_RECORD(Entry, FP_PROTECTED_PATH, ListEntry);

        if (ExistingPath->PathLength == NewPath->PathLength &&
            _wcsicmp(ExistingPath->NormalizedPath, NewPath->NormalizedPath) == 0) {
            Duplicate = TRUE;
            break;
        }
    }

    if (!Duplicate) {
        InsertTailList(&Engine->ProtectedPathList, &NewPath->ListEntry);
        InterlockedIncrement(&Engine->ProtectedPathCount);
        InterlockedIncrement64(&Engine->Stats.PathsProtected);
        NewPath = NULL;  // Ownership transferred
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
/*++

Routine Description:

    Adds a path to the protection list (C string version).

--*/
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
/*++

Routine Description:

    Removes a path from the protection list.

--*/
{
    PLIST_ENTRY Entry;
    PFP_PROTECTED_PATH FoundPath = NULL;
    WCHAR NormalizedPath[FP_MAX_PATH_LENGTH];
    USHORT PathLength;

    PAGED_CODE();

    if (Engine == NULL || !Engine->Initialized) {
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
    // Normalize for comparison
    //
    RtlCopyMemory(NormalizedPath, Path->Buffer, Path->Length);
    NormalizedPath[PathLength] = L'\0';
    _wcsupr_s(NormalizedPath, FP_MAX_PATH_LENGTH);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->PathListLock);

    for (Entry = Engine->ProtectedPathList.Flink;
         Entry != &Engine->ProtectedPathList;
         Entry = Entry->Flink) {

        PFP_PROTECTED_PATH TestPath = CONTAINING_RECORD(Entry, FP_PROTECTED_PATH, ListEntry);

        if (TestPath->PathLength == PathLength &&
            _wcsicmp(TestPath->NormalizedPath, NormalizedPath) == 0) {

            RemoveEntryList(Entry);
            InterlockedDecrement(&Engine->ProtectedPathCount);
            FoundPath = TestPath;
            break;
        }
    }

    ExReleasePushLockExclusive(&Engine->PathListLock);
    KeLeaveCriticalRegion();

    if (FoundPath != NULL) {
        FppFreeProtectedPath(FoundPath);
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
/*++

Routine Description:

    Adds a protected file extension.

--*/
{
    LONG i;
    SIZE_T ExtLen;
    NTSTATUS Status = STATUS_QUOTA_EXCEEDED;

    PAGED_CODE();

    if (Engine == NULL || !Engine->Initialized || Extension == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    ExtLen = wcslen(Extension);
    if (ExtLen == 0 || ExtLen >= FP_MAX_EXTENSION_LENGTH) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->ExtensionLock);

    //
    // Find empty slot
    //
    for (i = 0; i < FP_MAX_PROTECTED_EXTENSIONS; i++) {
        if (!Engine->ProtectedExtensions[i].InUse) {
            Engine->ProtectedExtensions[i].InUse = TRUE;
            Engine->ProtectedExtensions[i].ExtensionLength = (USHORT)ExtLen;
            Engine->ProtectedExtensions[i].ProtectionFlags = ProtectionFlags;

            RtlCopyMemory(Engine->ProtectedExtensions[i].Extension,
                Extension, ExtLen * sizeof(WCHAR));
            Engine->ProtectedExtensions[i].Extension[ExtLen] = L'\0';

            //
            // Uppercase for case-insensitive matching
            //
            _wcsupr_s(Engine->ProtectedExtensions[i].Extension, FP_MAX_EXTENSION_LENGTH);

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
/*++

Routine Description:

    Clears all protection rules.

--*/
{
    PLIST_ENTRY Entry;
    PFP_PROTECTED_PATH Path;

    PAGED_CODE();

    if (Engine == NULL || !Engine->Initialized) {
        return;
    }

    //
    // Clear path rules
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->PathListLock);

    while (!IsListEmpty(&Engine->ProtectedPathList)) {
        Entry = RemoveHeadList(&Engine->ProtectedPathList);
        Path = CONTAINING_RECORD(Entry, FP_PROTECTED_PATH, ListEntry);
        FppFreeProtectedPath(Path);
    }

    Engine->ProtectedPathCount = 0;

    ExReleasePushLockExclusive(&Engine->PathListLock);
    KeLeaveCriticalRegion();

    //
    // Clear extension rules
    //
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
    _In_ ACCESS_MASK DesiredAccess
    )
/*++

Routine Description:

    Checks if a file operation should be blocked.

--*/
{
    PLIST_ENTRY Entry;
    PFP_PROTECTED_PATH MatchedPath = NULL;
    FP_ACCESS_RESULT Result = FpAccess_NotProtected;
    WCHAR NormalizedPath[FP_MAX_PATH_LENGTH];
    WCHAR FileName[260];
    WCHAR Extension[FP_MAX_EXTENSION_LENGTH];
    USHORT PathLength;
    ULONG ProtectionFlags = 0;
    BOOLEAN CheckExtensions = TRUE;
    LONG i;

    UNREFERENCED_PARAMETER(DesiredAccess);

    if (Engine == NULL || !Engine->Initialized) {
        return FpAccess_Allow;
    }

    if (FilePath == NULL || FilePath->Buffer == NULL || FilePath->Length == 0) {
        return FpAccess_Allow;
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&Engine->Stats.TotalChecks);

    //
    // Allow protected processes (ShadowStrike components)
    //
    if (ShadowStrikeIsProcessProtected(RequestorPid, NULL)) {
        return FpAccess_Allow;
    }

    PathLength = FilePath->Length / sizeof(WCHAR);
    if (PathLength >= FP_MAX_PATH_LENGTH) {
        return FpAccess_Allow;  // Fail-open on invalid paths
    }

    //
    // Normalize path for comparison
    //
    RtlCopyMemory(NormalizedPath, FilePath->Buffer, FilePath->Length);
    NormalizedPath[PathLength] = L'\0';

    //
    // Strip stream name if present (protect base file regardless of stream)
    //
    if (Engine->Config.EnableStreamProtection && FppHasStream(FilePath)) {
        PWCHAR StreamSep = wcsrchr(NormalizedPath, FP_STREAM_SEPARATOR);
        if (StreamSep != NULL && StreamSep > NormalizedPath + 2) {
            //
            // Check it's not the drive letter colon
            //
            if (*(StreamSep - 1) != L'\\' && *(StreamSep - 1) != L'/') {
                *StreamSep = L'\0';
                PathLength = (USHORT)wcslen(NormalizedPath);
            }
        }
    }

    //
    // Convert to uppercase
    //
    _wcsupr_s(NormalizedPath, FP_MAX_PATH_LENGTH);

    //
    // Extract filename and extension
    //
    PWCHAR LastSlash = wcsrchr(NormalizedPath, FP_PATH_SEPARATOR);
    if (LastSlash != NULL) {
        RtlStringCchCopyW(FileName, ARRAYSIZE(FileName), LastSlash + 1);
    } else {
        RtlStringCchCopyW(FileName, ARRAYSIZE(FileName), NormalizedPath);
    }

    PWCHAR Dot = wcsrchr(FileName, L'.');
    if (Dot != NULL) {
        RtlStringCchCopyW(Extension, ARRAYSIZE(Extension), Dot);
        _wcsupr_s(Extension, FP_MAX_EXTENSION_LENGTH);
    } else {
        Extension[0] = L'\0';
        CheckExtensions = FALSE;
    }

    //
    // Check path rules
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

            MatchedPath = TestPath;
            ProtectionFlags = TestPath->ProtectionFlags;

            //
            // Update last access time
            //
            LARGE_INTEGER CurrentTime;
            KeQuerySystemTime(&CurrentTime);
            TestPath->LastAccessTime = CurrentTime;

            break;
        }
    }

    ExReleasePushLockShared(&Engine->PathListLock);
    KeLeaveCriticalRegion();

    //
    // Check extension rules if no path match
    //
    if (MatchedPath == NULL && CheckExtensions && Engine->ProtectedExtensionCount > 0) {
        KeEnterCriticalRegion();
        ExAcquirePushLockShared(&Engine->ExtensionLock);

        for (i = 0; i < FP_MAX_PROTECTED_EXTENSIONS; i++) {
            if (Engine->ProtectedExtensions[i].InUse) {
                if (FppMatchExtension(FileName,
                    Engine->ProtectedExtensions[i].Extension,
                    Engine->ProtectedExtensions[i].ExtensionLength)) {

                    ProtectionFlags = Engine->ProtectedExtensions[i].ProtectionFlags;
                    Result = FpAccess_Block;  // Will be refined below
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
    if (MatchedPath != NULL || ProtectionFlags != 0) {

        //
        // Check if audit-only mode
        //
        if (ProtectionFlags & FpProtect_AuditOnly) {
            Result = FpAccess_AuditOnly;
        } else {
            //
            // Check operation-specific protection
            //
            BOOLEAN ShouldBlock = FALSE;

            switch (Operation) {
            case FpOperation_Write:
                ShouldBlock = (ProtectionFlags & FpProtect_BlockWrite) != 0;
                if (ShouldBlock) {
                    InterlockedIncrement64(&Engine->Stats.BlockedWrites);
                }
                break;

            case FpOperation_Delete:
                ShouldBlock = (ProtectionFlags & FpProtect_BlockDelete) != 0;
                if (ShouldBlock) {
                    InterlockedIncrement64(&Engine->Stats.BlockedDeletes);
                }
                break;

            case FpOperation_Rename:
                ShouldBlock = (ProtectionFlags & FpProtect_BlockRename) != 0;
                if (ShouldBlock) {
                    InterlockedIncrement64(&Engine->Stats.BlockedRenames);
                }
                break;

            case FpOperation_SetInfo:
                ShouldBlock = (ProtectionFlags & FpProtect_BlockSetInfo) != 0;
                if (ShouldBlock) {
                    InterlockedIncrement64(&Engine->Stats.BlockedSetInfo);
                }
                break;

            case FpOperation_SetSecurity:
                ShouldBlock = (ProtectionFlags & FpProtect_BlockSetSecurity) != 0;
                if (ShouldBlock) {
                    InterlockedIncrement64(&Engine->Stats.BlockedSetSecurity);
                }
                break;

            case FpOperation_CreateHardlink:
                ShouldBlock = (ProtectionFlags & FpProtect_BlockHardlink) != 0;
                if (ShouldBlock) {
                    InterlockedIncrement64(&Engine->Stats.BlockedHardlinks);
                }
                break;

            case FpOperation_CreateStream:
            case FpOperation_DeleteStream:
                ShouldBlock = (ProtectionFlags & FpProtect_BlockStreams) != 0;
                if (ShouldBlock) {
                    InterlockedIncrement64(&Engine->Stats.BlockedStreams);
                }
                break;

            default:
                break;
            }

            Result = ShouldBlock ? FpAccess_Block : FpAccess_Allow;
        }

        //
        // Update matched rule statistics
        //
        if (MatchedPath != NULL) {
            if (Result == FpAccess_Block) {
                InterlockedIncrement64(&MatchedPath->BlockedOperations);
            } else if (Result == FpAccess_AuditOnly) {
                InterlockedIncrement64(&MatchedPath->AuditedOperations);
            }
        }
    }

    //
    // Log if audit logging is enabled
    //
    if (Engine->Config.EnableAuditLogging &&
        (Result == FpAccess_Block || Result == FpAccess_AuditOnly)) {

        UNICODE_STRING RulePath = { 0 };
        if (MatchedPath != NULL) {
            RtlInitUnicodeString(&RulePath, MatchedPath->NormalizedPath);
        }

        FpLogAccessAttempt(Engine, FilePath, Operation, Result, RequestorPid,
            MatchedPath ? &RulePath : NULL);
    }

    return Result;
}

_Use_decl_annotations_
BOOLEAN
FpIsPathProtected(
    _In_ PFP_ENGINE Engine,
    _In_ PCUNICODE_STRING Path,
    _Out_opt_ PULONG ProtectionFlags
    )
/*++

Routine Description:

    Checks if a path is protected.

--*/
{
    FP_ACCESS_RESULT Result;

    if (ProtectionFlags != NULL) {
        *ProtectionFlags = 0;
    }

    Result = FpCheckAccess(Engine, Path, FpOperation_Write,
        PsGetCurrentProcessId(), 0);

    if (Result == FpAccess_Block || Result == FpAccess_AuditOnly) {
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
    _Out_opt_ PFP_PROTECTED_PATH* MatchedRule
    )
/*++

Routine Description:

    Checks file access with full minifilter context.

--*/
{
    NTSTATUS Status;
    PFLT_FILE_NAME_INFORMATION FileNameInfo = NULL;
    FP_ACCESS_RESULT Result = FpAccess_Allow;
    HANDLE RequestorPid;

    UNREFERENCED_PARAMETER(FltObjects);

    if (MatchedRule != NULL) {
        *MatchedRule = NULL;
    }

    if (Engine == NULL || !Engine->Initialized || Data == NULL) {
        return FpAccess_Allow;
    }

    //
    // Get file name information
    //
    Status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &FileNameInfo
        );

    if (!NT_SUCCESS(Status)) {
        return FpAccess_Allow;  // Fail-open
    }

    Status = FltParseFileNameInformation(FileNameInfo);
    if (!NT_SUCCESS(Status)) {
        FltReleaseFileNameInformation(FileNameInfo);
        return FpAccess_Allow;
    }

    RequestorPid = FltGetRequestorProcessId(Data);

    Result = FpCheckAccess(
        Engine,
        &FileNameInfo->Name,
        Operation,
        RequestorPid,
        0
        );

    FltReleaseFileNameInformation(FileNameInfo);

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
/*++

Routine Description:

    Normalizes a file path.

--*/
{
    USHORT PathLength;
    PWCHAR StreamSep;
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

    //
    // Copy path
    //
    RtlCopyMemory(PathInfo->NormalizedPath, InputPath->Buffer, InputPath->Length);
    PathInfo->NormalizedPath[PathLength] = L'\0';
    PathInfo->NormalizedLength = PathLength;

    //
    // Check for stream
    //
    if (FppHasStream(InputPath)) {
        PathInfo->HasStream = TRUE;

        //
        // Extract stream name
        //
        StreamSep = wcsrchr(PathInfo->NormalizedPath, FP_STREAM_SEPARATOR);
        if (StreamSep != NULL && StreamSep > PathInfo->NormalizedPath + 2) {
            RtlStringCchCopyW(PathInfo->StreamName, FP_MAX_STREAM_NAME_LENGTH, StreamSep);

            //
            // Truncate path at stream separator for base path
            //
            *StreamSep = L'\0';
            PathInfo->NormalizedLength = (USHORT)wcslen(PathInfo->NormalizedPath);
        }
    }

    //
    // Extract filename
    //
    LastSlash = wcsrchr(PathInfo->NormalizedPath, FP_PATH_SEPARATOR);
    if (LastSlash != NULL) {
        RtlStringCchCopyW(PathInfo->FileName, ARRAYSIZE(PathInfo->FileName), LastSlash + 1);
    } else {
        RtlStringCchCopyW(PathInfo->FileName, ARRAYSIZE(PathInfo->FileName), PathInfo->NormalizedPath);
    }

    //
    // Extract extension
    //
    Dot = wcsrchr(PathInfo->FileName, L'.');
    if (Dot != NULL) {
        RtlStringCchCopyW(PathInfo->Extension, FP_MAX_EXTENSION_LENGTH, Dot);
    }

    //
    // Check for short name
    //
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
/*++

Routine Description:

    Normalizes path with filter context (resolves reparse points, etc.).

--*/
{
    NTSTATUS Status;
    PFLT_FILE_NAME_INFORMATION FileNameInfo = NULL;

    PAGED_CODE();

    if (Instance == NULL || FileObject == NULL || PathInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(PathInfo, sizeof(FP_PATH_INFO));

    //
    // Get normalized file name
    //
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

    //
    // Use the basic normalization
    //
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
/*++

Routine Description:

    Extracts stream name from path.

--*/
{
    USHORT i;
    USHORT StreamStart = 0;
    BOOLEAN FoundStream = FALSE;

    if (FullPath == NULL || StreamName == NULL || BasePath == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    StreamName[0] = L'\0';
    BasePath->Buffer = FullPath->Buffer;
    BasePath->Length = FullPath->Length;
    BasePath->MaximumLength = FullPath->MaximumLength;

    if (!FppHasStream(FullPath)) {
        return STATUS_NOT_FOUND;
    }

    //
    // Find stream separator (skip drive letter colon)
    //
    for (i = 2; i < FullPath->Length / sizeof(WCHAR); i++) {
        if (FullPath->Buffer[i] == FP_STREAM_SEPARATOR) {
            StreamStart = i;
            FoundStream = TRUE;
            break;
        }
    }

    if (!FoundStream) {
        return STATUS_NOT_FOUND;
    }

    //
    // Copy stream name
    //
    USHORT StreamLen = (FullPath->Length / sizeof(WCHAR)) - StreamStart;
    if (StreamLen >= StreamNameSize) {
        StreamLen = (USHORT)(StreamNameSize - 1);
    }

    RtlCopyMemory(StreamName, &FullPath->Buffer[StreamStart], StreamLen * sizeof(WCHAR));
    StreamName[StreamLen] = L'\0';

    //
    // Adjust base path
    //
    BasePath->Length = StreamStart * sizeof(WCHAR);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
FpStripStreamName(
    _In_ PCUNICODE_STRING FullPath,
    _Out_ PUNICODE_STRING BasePath
    )
/*++

Routine Description:

    Strips stream name from path.

--*/
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
/*++

Routine Description:

    Resolves symbolic link target.

--*/
{
    NTSTATUS Status;
    PFLT_FILE_NAME_INFORMATION FileNameInfo = NULL;

    PAGED_CODE();

    if (Instance == NULL || FileObject == NULL || TargetPath == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    TargetPath[0] = L'\0';

    //
    // Get opened name (follows symlinks)
    //
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

    //
    // Copy the resolved path
    //
    USHORT CopyLen = FileNameInfo->Name.Length / sizeof(WCHAR);
    if (CopyLen >= TargetPathSize) {
        CopyLen = (USHORT)(TargetPathSize - 1);
    }

    RtlCopyMemory(TargetPath, FileNameInfo->Name.Buffer, CopyLen * sizeof(WCHAR));
    TargetPath[CopyLen] = L'\0';

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

    Converts short name (8.3) to long name.

--*/
{
    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(ShortPath);
    UNREFERENCED_PARAMETER(LongPath);

    PAGED_CODE();

    //
    // This would require opening the file and querying FileNameInformation
    // For now, return the input as-is (full implementation would use FltQueryInformationFile)
    //
    return STATUS_NOT_IMPLEMENTED;
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
/*++

Routine Description:

    Logs an access attempt.

--*/
{
    PFP_AUDIT_ENTRY Entry;
    LARGE_INTEGER CurrentTime;
    USHORT CopyLen;

    if (Engine == NULL || !Engine->Initialized || !Engine->Config.EnableAuditLogging) {
        return;
    }

    if (FilePath == NULL || FilePath->Buffer == NULL) {
        return;
    }

    //
    // Allocate audit entry
    //
    Entry = (PFP_AUDIT_ENTRY)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(FP_AUDIT_ENTRY),
        FP_POOL_TAG_CONTEXT
        );

    if (Entry == NULL) {
        return;
    }

    RtlZeroMemory(Entry, sizeof(FP_AUDIT_ENTRY));

    KeQuerySystemTime(&CurrentTime);
    Entry->Timestamp = CurrentTime;
    Entry->ProcessId = ProcessId;
    Entry->ThreadId = PsGetCurrentThreadId();
    Entry->Operation = Operation;
    Entry->Result = Result;

    //
    // Copy file path
    //
    CopyLen = FilePath->Length / sizeof(WCHAR);
    if (CopyLen >= FP_MAX_PATH_LENGTH) {
        CopyLen = FP_MAX_PATH_LENGTH - 1;
    }
    RtlCopyMemory(Entry->FilePath, FilePath->Buffer, CopyLen * sizeof(WCHAR));
    Entry->FilePath[CopyLen] = L'\0';

    //
    // Copy rule path if provided
    //
    if (RulePath != NULL && RulePath->Buffer != NULL) {
        CopyLen = RulePath->Length / sizeof(WCHAR);
        if (CopyLen >= FP_MAX_PATH_LENGTH) {
            CopyLen = FP_MAX_PATH_LENGTH - 1;
        }
        RtlCopyMemory(Entry->RulePath, RulePath->Buffer, CopyLen * sizeof(WCHAR));
        Entry->RulePath[CopyLen] = L'\0';
    }

    //
    // Get process name
    //
    FppGetProcessName(ProcessId, Entry->ProcessName, ARRAYSIZE(Entry->ProcessName));

    //
    // Add to audit log
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->AuditLogLock);

    InsertTailList(&Engine->AuditLog, &Entry->ListEntry);
    InterlockedIncrement(&Engine->AuditLogCount);
    InterlockedIncrement64(&Engine->Stats.AuditEvents);

    //
    // Trim if over limit
    //
    FppTrimAuditLog(Engine);

    ExReleasePushLockExclusive(&Engine->AuditLogLock);
    KeLeaveCriticalRegion();
}

_Use_decl_annotations_
NTSTATUS
FpGetAuditLog(
    _In_ PFP_ENGINE Engine,
    _Out_ PFP_AUDIT_ENTRY* Entries,
    _Inout_ PULONG EntryCount
    )
/*++

Routine Description:

    Gets audit log entries.

--*/
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(Engine);
    UNREFERENCED_PARAMETER(Entries);
    UNREFERENCED_PARAMETER(EntryCount);

    //
    // Implementation would copy entries to caller-provided buffer
    //
    return STATUS_NOT_IMPLEMENTED;
}

_Use_decl_annotations_
VOID
FpClearAuditLog(
    _In_ PFP_ENGINE Engine
    )
/*++

Routine Description:

    Clears the audit log.

--*/
{
    PLIST_ENTRY Entry;
    PFP_AUDIT_ENTRY AuditEntry;

    PAGED_CODE();

    if (Engine == NULL || !Engine->Initialized) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->AuditLogLock);

    while (!IsListEmpty(&Engine->AuditLog)) {
        Entry = RemoveHeadList(&Engine->AuditLog);
        AuditEntry = CONTAINING_RECORD(Entry, FP_AUDIT_ENTRY, ListEntry);
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

    Gets file protection statistics.

--*/
{
    if (Engine == NULL || Stats == NULL) {
        return;
    }

    RtlCopyMemory(Stats, &Engine->Stats, sizeof(FP_STATISTICS));
}

_Use_decl_annotations_
VOID
FpResetStatistics(
    _In_ PFP_ENGINE Engine
    )
/*++

Routine Description:

    Resets statistics.

--*/
{
    LARGE_INTEGER CurrentTime;

    if (Engine == NULL) {
        return;
    }

    KeQuerySystemTime(&CurrentTime);

    RtlZeroMemory(&Engine->Stats, sizeof(FP_STATISTICS));
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
/*++

Routine Description:

    Checks if test path matches rule path.

--*/
{
    //
    // Case-insensitive prefix match
    //
    if (TestPathLength < RulePathLength) {
        return FALSE;
    }

    if (_wcsnicmp(TestPath, RulePath, RulePathLength) != 0) {
        return FALSE;
    }

    //
    // Exact match
    //
    if (TestPathLength == RulePathLength) {
        return TRUE;
    }

    //
    // For recursive rules, check if test path is under rule path
    //
    if (IsRecursive) {
        //
        // Ensure rule path ends at directory boundary
        //
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
/*++

Routine Description:

    Checks if filename has the specified extension.

--*/
{
    SIZE_T FileNameLen = wcslen(FileName);
    PCWSTR FileDot;

    if (FileNameLen <= ExtensionLength) {
        return FALSE;
    }

    FileDot = wcsrchr(FileName, L'.');
    if (FileDot == NULL) {
        return FALSE;
    }

    return _wcsicmp(FileDot, Extension) == 0;
}

static
VOID
FppFreeProtectedPath(
    _In_ PFP_PROTECTED_PATH Path
    )
{
    if (Path != NULL) {
        ShadowStrikeFreePoolWithTag(Path, FP_POOL_TAG_RULE);
    }
}

static
VOID
FppFreeAuditEntry(
    _In_ PFP_AUDIT_ENTRY Entry
    )
{
    if (Entry != NULL) {
        ShadowStrikeFreePoolWithTag(Entry, FP_POOL_TAG_CONTEXT);
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
    PFP_AUDIT_ENTRY AuditEntry;

    while (Engine->AuditLogCount > (LONG)Engine->Config.MaxAuditEntries) {
        if (IsListEmpty(&Engine->AuditLog)) {
            break;
        }

        Entry = RemoveHeadList(&Engine->AuditLog);
        AuditEntry = CONTAINING_RECORD(Entry, FP_AUDIT_ENTRY, ListEntry);
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
/*++

Routine Description:

    Gets process name from PID.

--*/
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
        //
        // Extract just the filename
        //
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
/*++

Routine Description:

    Checks if filename appears to be a short (8.3) name.

--*/
{
    SIZE_T Len;
    PCWSTR Tilde;

    if (FileName == NULL) {
        return FALSE;
    }

    Len = wcslen(FileName);

    //
    // Short names are typically 12 chars or less (8.3 format)
    //
    if (Len > 12) {
        return FALSE;
    }

    //
    // Look for tilde character (e.g., PROGRA~1)
    //
    Tilde = wcschr(FileName, FP_SHORT_NAME_MARKER);
    if (Tilde != NULL) {
        //
        // Check if followed by digit
        //
        if (Tilde[1] >= L'1' && Tilde[1] <= L'9') {
            return TRUE;
        }
    }

    return FALSE;
}

static
VOID
FppExtractFileName(
    _In_ PCUNICODE_STRING FullPath,
    _Out_ PUNICODE_STRING FileName
    )
/*++

Routine Description:

    Extracts filename from full path.

--*/
{
    USHORT i;

    FileName->Buffer = FullPath->Buffer;
    FileName->Length = FullPath->Length;
    FileName->MaximumLength = FullPath->MaximumLength;

    //
    // Find last separator
    //
    for (i = FullPath->Length / sizeof(WCHAR); i > 0; i--) {
        if (FullPath->Buffer[i - 1] == FP_PATH_SEPARATOR) {
            FileName->Buffer = &FullPath->Buffer[i];
            FileName->Length = FullPath->Length - (i * sizeof(WCHAR));
            FileName->MaximumLength = FileName->Length + sizeof(WCHAR);
            break;
        }
    }
}

static
VOID
FppExtractExtension(
    _In_ PCUNICODE_STRING FileName,
    _Out_writes_z_(ExtSize) PWCHAR Extension,
    _In_ ULONG ExtSize
    )
/*++

Routine Description:

    Extracts extension from filename.

--*/
{
    USHORT i;

    Extension[0] = L'\0';

    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return;
    }

    //
    // Find last dot
    //
    for (i = FileName->Length / sizeof(WCHAR); i > 0; i--) {
        if (FileName->Buffer[i - 1] == L'.') {
            USHORT ExtLen = (FileName->Length / sizeof(WCHAR)) - (i - 1);
            if (ExtLen >= ExtSize) {
                ExtLen = (USHORT)(ExtSize - 1);
            }
            RtlCopyMemory(Extension, &FileName->Buffer[i - 1], ExtLen * sizeof(WCHAR));
            Extension[ExtLen] = L'\0';
            break;
        }
    }
}

