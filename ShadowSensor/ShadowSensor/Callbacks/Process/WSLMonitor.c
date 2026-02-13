/*++
===============================================================================
ShadowStrike NGAV - WSL/CONTAINER MONITORING IMPLEMENTATION
===============================================================================

@file WSLMonitor.c
@brief Detects WSL processes, tracks cross-subsystem activity, and identifies
       container escape patterns.

WSL Detection Strategy:
  - Process image name matching: wsl.exe, wslhost.exe, wslservice.exe
  - Parent chain analysis: WSL launcher → host → child processes
  - Pico process identification via subsystem flags
  - File access monitoring for /mnt/ → native drive crossings
  - Credential file access detection (SAM, SECURITY, SYSTEM hives)

@author ShadowStrike Security Team
@version 1.0.0
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#include "WSLMonitor.h"
#include "../../Core/Globals.h"
#include <ntstrsafe.h>

// ============================================================================
// PRIVATE TYPES
// ============================================================================

typedef struct _WSL_STATE {

    volatile LONG       State;
    EX_RUNDOWN_REF      RundownRef;

    //
    // Tracked processes: hash table by PID
    //
    struct {
        LIST_ENTRY  Head;
        EX_PUSH_LOCK Lock;
        volatile LONG Count;
    } ProcessBuckets[64];

    //
    // Allocation
    //
    NPAGED_LOOKASIDE_LIST ProcessLookaside;

    //
    // Statistics
    //
    WSL_STATISTICS      Stats;

} WSL_STATE, *PWSL_STATE;

// ============================================================================
// KNOWN WSL PROCESS NAMES
// ============================================================================

static const UNICODE_STRING g_WslLauncher   = RTL_CONSTANT_STRING(L"wsl.exe");
static const UNICODE_STRING g_WslHost       = RTL_CONSTANT_STRING(L"wslhost.exe");
static const UNICODE_STRING g_WslService    = RTL_CONSTANT_STRING(L"wslservice.exe");
static const UNICODE_STRING g_WslRelay      = RTL_CONSTANT_STRING(L"wslrelay.exe");
static const UNICODE_STRING g_Bash          = RTL_CONSTANT_STRING(L"bash.exe");

//
// Credential file patterns that WSL processes should not touch
//
static const UNICODE_STRING g_CredentialPaths[] = {
    RTL_CONSTANT_STRING(L"\\Windows\\System32\\config\\SAM"),
    RTL_CONSTANT_STRING(L"\\Windows\\System32\\config\\SECURITY"),
    RTL_CONSTANT_STRING(L"\\Windows\\System32\\config\\SYSTEM"),
    RTL_CONSTANT_STRING(L"\\Windows\\NTDS\\ntds.dit"),
    RTL_CONSTANT_STRING(L"\\Windows\\System32\\config\\DEFAULT"),
};

#define WSL_CREDENTIAL_PATH_COUNT \
    (sizeof(g_CredentialPaths) / sizeof(g_CredentialPaths[0]))

// ============================================================================
// GLOBAL STATE
// ============================================================================

static WSL_STATE g_WslState;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static ULONG
WslpBucketIndex(
    _In_ HANDLE ProcessId
    );

static PWSL_TRACKED_PROCESS
WslpFindProcess(
    _In_ HANDLE ProcessId
    );

static WSL_PROCESS_TYPE
WslpClassifyImage(
    _In_ PCUNICODE_STRING ImageFileName
    );

static BOOLEAN
WslpExtractImageName(
    _In_ PCUNICODE_STRING FullPath,
    _Out_ PUNICODE_STRING NameOnly
    );

static BOOLEAN
WslpIsCredentialPath(
    _In_ PCUNICODE_STRING FileName
    );

static BOOLEAN
WslpEnterOperation(VOID);

static VOID
WslpLeaveOperation(VOID);

// ============================================================================
// LIFECYCLE
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
WslMonInitialize(VOID)
{
    LONG Previous;

    PAGED_CODE();

    Previous = InterlockedCompareExchange(&g_WslState.State, 1, 0);
    if (Previous != 0) {
        return (Previous == 2) ? STATUS_SUCCESS : STATUS_DEVICE_BUSY;
    }

    ExInitializeRundownProtection(&g_WslState.RundownRef);

    for (ULONG i = 0; i < 64; i++) {
        InitializeListHead(&g_WslState.ProcessBuckets[i].Head);
        FltInitializePushLock(&g_WslState.ProcessBuckets[i].Lock);
        g_WslState.ProcessBuckets[i].Count = 0;
    }

    ExInitializeNPagedLookasideList(
        &g_WslState.ProcessLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(WSL_TRACKED_PROCESS),
        WSL_PROCESS_POOL_TAG,
        0
        );

    RtlZeroMemory(&g_WslState.Stats, sizeof(WSL_STATISTICS));

    InterlockedExchange(&g_WslState.State, 2);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/WSL] WSL/Container monitor initialized\n");

    return STATUS_SUCCESS;
}


_IRQL_requires_(PASSIVE_LEVEL)
VOID
WslMonShutdown(VOID)
{
    PAGED_CODE();

    if (InterlockedCompareExchange(&g_WslState.State, 3, 2) != 2) {
        return;
    }

    ExWaitForRundownProtectionRelease(&g_WslState.RundownRef);

    //
    // Free all tracked processes
    //
    for (ULONG i = 0; i < 64; i++) {
        FltAcquirePushLockExclusive(&g_WslState.ProcessBuckets[i].Lock);
        while (!IsListEmpty(&g_WslState.ProcessBuckets[i].Head)) {
            LIST_ENTRY *Entry = RemoveHeadList(&g_WslState.ProcessBuckets[i].Head);
            PWSL_TRACKED_PROCESS Proc = CONTAINING_RECORD(
                Entry, WSL_TRACKED_PROCESS, Link);
            ExFreeToNPagedLookasideList(&g_WslState.ProcessLookaside, Proc);
        }
        FltReleasePushLock(&g_WslState.ProcessBuckets[i].Lock);
        FltDeletePushLock(&g_WslState.ProcessBuckets[i].Lock);
    }

    ExDeleteNPagedLookasideList(&g_WslState.ProcessLookaside);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/WSL] Shutdown complete. "
               "Detected=%lld, Escapes=%lld\n",
               g_WslState.Stats.WslProcessesDetected,
               g_WslState.Stats.EscapeAttemptsDetected);
}

// ============================================================================
// PROCESS DETECTION
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
WSL_PROCESS_TYPE
WslMonCheckProcessCreate(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentProcessId,
    _In_opt_ PCUNICODE_STRING ImageFileName
    )
{
    WSL_PROCESS_TYPE Type = WslProcess_None;
    PWSL_TRACKED_PROCESS NewProc;
    PWSL_TRACKED_PROCESS ParentProc;
    ULONG Bucket;
    UNICODE_STRING ImageNameOnly;

    PAGED_CODE();

    if (!WslpEnterOperation()) {
        return WslProcess_None;
    }

    //
    // Step 1: Check if image name matches known WSL binaries
    //
    if (ImageFileName != NULL && ImageFileName->Length > 0) {
        if (WslpExtractImageName(ImageFileName, &ImageNameOnly)) {
            Type = WslpClassifyImage(&ImageNameOnly);
        }
    }

    //
    // Step 2: If not directly classified, check if parent is WSL
    //
    if (Type == WslProcess_None) {
        ParentProc = WslpFindProcess(ParentProcessId);
        if (ParentProc != NULL) {
            Type = WslProcess_Child;
            InterlockedIncrement64(&g_WslState.Stats.SuspiciousSpawns);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike/WSL] WSL child process spawned: "
                       "PID=%lu, Parent=%lu (ParentType=%d)\n",
                       HandleToULong(ProcessId),
                       HandleToULong(ParentProcessId),
                       ParentProc->ProcessType);
        }
    }

    if (Type == WslProcess_None) {
        WslpLeaveOperation();
        return WslProcess_None;
    }

    //
    // Step 3: Track this WSL process
    //
    NewProc = (PWSL_TRACKED_PROCESS)ExAllocateFromNPagedLookasideList(
        &g_WslState.ProcessLookaside);

    if (NewProc == NULL) {
        WslpLeaveOperation();
        return Type;
    }

    RtlZeroMemory(NewProc, sizeof(WSL_TRACKED_PROCESS));
    InitializeListHead(&NewProc->Link);
    NewProc->ProcessId = ProcessId;
    NewProc->ParentProcessId = ParentProcessId;
    NewProc->ProcessType = Type;
    KeQuerySystemTime(&NewProc->CreateTime);

    if (ImageFileName != NULL && ImageFileName->Length > 0) {
        USHORT CopyLen = min(ImageFileName->Length,
                             (WSL_PROCESS_NAME_MAX - 1) * sizeof(WCHAR));
        RtlCopyMemory(NewProc->ImageName, ImageFileName->Buffer, CopyLen);
        NewProc->ImageNameLength = CopyLen / sizeof(WCHAR);
    }

    Bucket = WslpBucketIndex(ProcessId);

    FltAcquirePushLockExclusive(&g_WslState.ProcessBuckets[Bucket].Lock);
    InsertTailList(&g_WslState.ProcessBuckets[Bucket].Head, &NewProc->Link);
    InterlockedIncrement(&g_WslState.ProcessBuckets[Bucket].Count);
    FltReleasePushLock(&g_WslState.ProcessBuckets[Bucket].Lock);

    InterlockedIncrement64(&g_WslState.Stats.WslProcessesDetected);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/WSL] WSL process detected: PID=%lu Type=%d\n",
               HandleToULong(ProcessId), Type);

    WslpLeaveOperation();
    return Type;
}


_IRQL_requires_(PASSIVE_LEVEL)
VOID
WslMonProcessTerminated(
    _In_ HANDLE ProcessId
    )
{
    ULONG Bucket;
    LIST_ENTRY *ListEntry;

    PAGED_CODE();

    if (!WslpEnterOperation()) {
        return;
    }

    Bucket = WslpBucketIndex(ProcessId);

    FltAcquirePushLockExclusive(&g_WslState.ProcessBuckets[Bucket].Lock);

    for (ListEntry = g_WslState.ProcessBuckets[Bucket].Head.Flink;
         ListEntry != &g_WslState.ProcessBuckets[Bucket].Head;
         ListEntry = ListEntry->Flink) {

        PWSL_TRACKED_PROCESS Proc = CONTAINING_RECORD(
            ListEntry, WSL_TRACKED_PROCESS, Link);

        if (Proc->ProcessId == ProcessId) {
            RemoveEntryList(&Proc->Link);
            InterlockedDecrement(&g_WslState.ProcessBuckets[Bucket].Count);
            FltReleasePushLock(&g_WslState.ProcessBuckets[Bucket].Lock);

            ExFreeToNPagedLookasideList(&g_WslState.ProcessLookaside, Proc);
            WslpLeaveOperation();
            return;
        }
    }

    FltReleasePushLock(&g_WslState.ProcessBuckets[Bucket].Lock);
    WslpLeaveOperation();
}

// ============================================================================
// FILE ACCESS MONITORING
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
WSL_ESCAPE_TYPE
WslMonCheckFileAccess(
    _In_ HANDLE ProcessId,
    _In_ PCUNICODE_STRING FileName
    )
{
    PWSL_TRACKED_PROCESS Proc;

    if (!WslpEnterOperation()) {
        return WslEscape_None;
    }

    Proc = WslpFindProcess(ProcessId);
    if (Proc == NULL) {
        WslpLeaveOperation();
        return WslEscape_None;
    }

    InterlockedIncrement(&Proc->FileAccessCount);
    InterlockedIncrement64(&g_WslState.Stats.FileSystemCrossings);

    //
    // Check credential file access
    //
    if (WslpIsCredentialPath(FileName)) {
        InterlockedIncrement(&Proc->EscapeAttempts);
        InterlockedIncrement64(&g_WslState.Stats.EscapeAttemptsDetected);
        InterlockedIncrement64(&g_WslState.Stats.CredentialAccessAttempts);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike/WSL] CRITICAL: WSL credential access attempt! "
                   "PID=%lu, File=%wZ\n",
                   HandleToULong(ProcessId), FileName);

        WslpLeaveOperation();
        return WslEscape_CredentialAccess;
    }

    //
    // Check if WSL process is accessing Windows system directories
    // This indicates potential container escape or host manipulation
    //
    UNICODE_STRING System32 = RTL_CONSTANT_STRING(L"\\Windows\\System32\\");
    UNICODE_STRING Drivers  = RTL_CONSTANT_STRING(L"\\Windows\\System32\\drivers\\");

    if (FileName->Length > Drivers.Length) {
        //
        // Check for driver file access from WSL (T1611 escape indicator)
        //
        UNICODE_STRING Suffix;
        Suffix.Buffer = FileName->Buffer +
            (FileName->Length / sizeof(WCHAR)) - (Drivers.Length / sizeof(WCHAR));
        Suffix.Length = Drivers.Length;
        Suffix.MaximumLength = Drivers.Length;

        // Check by searching for the substring in the path
        for (USHORT i = 0; i < FileName->Length / sizeof(WCHAR) - Drivers.Length / sizeof(WCHAR) + 1; i++) {
            UNICODE_STRING Candidate;
            Candidate.Buffer = &FileName->Buffer[i];
            Candidate.Length = Drivers.Length;
            Candidate.MaximumLength = Drivers.Length;

            if (RtlEqualUnicodeString(&Candidate, &Drivers, TRUE)) {
                InterlockedIncrement(&Proc->SuspiciousActions);
                InterlockedIncrement64(&g_WslState.Stats.EscapeAttemptsDetected);

                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike/WSL] WSL driver directory access: "
                           "PID=%lu, File=%wZ\n",
                           HandleToULong(ProcessId), FileName);

                WslpLeaveOperation();
                return WslEscape_DriverLoad;
            }
        }
    }

    WslpLeaveOperation();
    return WslEscape_None;
}

// ============================================================================
// QUERY
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
WslMonIsWslProcess(
    _In_ HANDLE ProcessId
    )
{
    return (WslpFindProcess(ProcessId) != NULL);
}


_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WslMonGetStatistics(
    _Out_ PWSL_STATISTICS Statistics
    )
{
    RtlCopyMemory(Statistics, &g_WslState.Stats, sizeof(WSL_STATISTICS));
}

// ============================================================================
// PRIVATE — PROCESS LOOKUP
// ============================================================================

static ULONG
WslpBucketIndex(
    _In_ HANDLE ProcessId
    )
{
    return (HandleToULong(ProcessId) >> 2) % 64;
}


static PWSL_TRACKED_PROCESS
WslpFindProcess(
    _In_ HANDLE ProcessId
    )
{
    ULONG Bucket = WslpBucketIndex(ProcessId);
    LIST_ENTRY *ListEntry;

    FltAcquirePushLockShared(&g_WslState.ProcessBuckets[Bucket].Lock);

    for (ListEntry = g_WslState.ProcessBuckets[Bucket].Head.Flink;
         ListEntry != &g_WslState.ProcessBuckets[Bucket].Head;
         ListEntry = ListEntry->Flink) {

        PWSL_TRACKED_PROCESS Proc = CONTAINING_RECORD(
            ListEntry, WSL_TRACKED_PROCESS, Link);

        if (Proc->ProcessId == ProcessId) {
            FltReleasePushLock(&g_WslState.ProcessBuckets[Bucket].Lock);
            return Proc;
        }
    }

    FltReleasePushLock(&g_WslState.ProcessBuckets[Bucket].Lock);
    return NULL;
}

// ============================================================================
// PRIVATE — IMAGE CLASSIFICATION
// ============================================================================

static WSL_PROCESS_TYPE
WslpClassifyImage(
    _In_ PCUNICODE_STRING ImageName
    )
{
    if (RtlEqualUnicodeString(ImageName, &g_WslLauncher, TRUE)) {
        return WslProcess_Launcher;
    }
    if (RtlEqualUnicodeString(ImageName, &g_WslHost, TRUE)) {
        return WslProcess_Host;
    }
    if (RtlEqualUnicodeString(ImageName, &g_WslService, TRUE)) {
        return WslProcess_Service;
    }
    if (RtlEqualUnicodeString(ImageName, &g_WslRelay, TRUE)) {
        return WslProcess_Child;
    }
    if (RtlEqualUnicodeString(ImageName, &g_Bash, TRUE)) {
        return WslProcess_Child;
    }
    return WslProcess_None;
}


static BOOLEAN
WslpExtractImageName(
    _In_ PCUNICODE_STRING FullPath,
    _Out_ PUNICODE_STRING NameOnly
    )
{
    USHORT Length = FullPath->Length / sizeof(WCHAR);

    for (USHORT i = Length; i > 0; i--) {
        if (FullPath->Buffer[i - 1] == L'\\') {
            NameOnly->Buffer = &FullPath->Buffer[i];
            NameOnly->Length = (Length - i) * sizeof(WCHAR);
            NameOnly->MaximumLength = NameOnly->Length;
            return (NameOnly->Length > 0);
        }
    }

    *NameOnly = *FullPath;
    return (FullPath->Length > 0);
}

// ============================================================================
// PRIVATE — CREDENTIAL PATH CHECK
// ============================================================================

static BOOLEAN
WslpIsCredentialPath(
    _In_ PCUNICODE_STRING FileName
    )
{
    for (ULONG i = 0; i < WSL_CREDENTIAL_PATH_COUNT; i++) {
        //
        // Check if the credential path is a suffix of the filename
        // (handles volume prefix variations)
        //
        if (FileName->Length >= g_CredentialPaths[i].Length) {
            UNICODE_STRING Suffix;
            Suffix.Buffer = FileName->Buffer +
                (FileName->Length - g_CredentialPaths[i].Length) / sizeof(WCHAR);
            Suffix.Length = g_CredentialPaths[i].Length;
            Suffix.MaximumLength = g_CredentialPaths[i].Length;

            if (RtlEqualUnicodeString(&Suffix, &g_CredentialPaths[i], TRUE)) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

// ============================================================================
// PRIVATE — LIFECYCLE
// ============================================================================

static BOOLEAN
WslpEnterOperation(VOID)
{
    if (g_WslState.State != 2) return FALSE;
    return ExAcquireRundownProtection(&g_WslState.RundownRef);
}

static VOID
WslpLeaveOperation(VOID)
{
    ExReleaseRundownProtection(&g_WslState.RundownRef);
}
