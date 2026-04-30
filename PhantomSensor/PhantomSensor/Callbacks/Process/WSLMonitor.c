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
ShadowStrike NGAV - WSL/CONTAINER MONITORING IMPLEMENTATION
===============================================================================

@file WSLMonitor.c
@brief Detects WSL processes, tracks cross-subsystem activity, and identifies
       container escape patterns.

WSL Detection Strategy:
  - Process image name matching: wsl.exe, wslhost.exe, wslservice.exe
  - Parent chain analysis: WSL launcher -> host -> child processes
  - Pico process identification via subsystem flags
  - File access monitoring for /mnt/ -> native drive crossings
  - Credential file access detection (SAM, SECURITY, SYSTEM hives)
  - Native escape target detection (cmd.exe, powershell.exe from WSL context)

Security Hardening (WSL-1 through WSL-15):
  - Lock-safe process lookups (pointer valid only while lock held)
  - Rundown protection on all public query APIs
  - Capacity enforcement against pool exhaustion
  - Duplicate PID insertion guard
  - bash.exe false positive elimination via parent-chain-only detection
  - Case-insensitive path substring search for System32/drivers detection

@author ShadowStrike Security Team
@version 2.0.0
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#include "WSLMonitor.h"
#include "../../Core/Globals.h"
#include "../../Behavioral/BehaviorEngine.h"
#include <ntstrsafe.h>

// ============================================================================
// PRIVATE TYPES
// ============================================================================

typedef struct _WSL_STATE {

    volatile LONG       State;
    EX_RUNDOWN_REF      RundownRef;

    //
    // Tracked processes: hash table by PID (64 buckets).
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
    // Global capacity tracking to prevent NonPagedPool exhaustion under
    // attack (WSL-5). Checked against WSL_MAX_TRACKED_PROCESSES.
    //
    volatile LONG TotalTrackedCount;

    //
    // Statistics
    //
    WSL_STATISTICS      Stats;

} WSL_STATE, *PWSL_STATE;

// ============================================================================
// KNOWN WSL PROCESS NAMES
// ============================================================================

//
// Note: bash.exe is intentionally excluded from direct classification.
// It appears in both WSL and non-WSL contexts (Git Bash, Cygwin, MSYS2).
// WSL-spawned bash is detected through parent chain analysis instead (WSL-11).
//
static const UNICODE_STRING g_WslLauncher   = RTL_CONSTANT_STRING(L"wsl.exe");
static const UNICODE_STRING g_WslHost       = RTL_CONSTANT_STRING(L"wslhost.exe");
static const UNICODE_STRING g_WslService    = RTL_CONSTANT_STRING(L"wslservice.exe");
static const UNICODE_STRING g_WslRelay      = RTL_CONSTANT_STRING(L"wslrelay.exe");

//
// Native Windows executables that indicate container-to-host escape when
// spawned from a WSL process context (T1611: Escape to Host).
//
static const UNICODE_STRING g_NativeEscapeTargets[] = {
    RTL_CONSTANT_STRING(L"cmd.exe"),
    RTL_CONSTANT_STRING(L"powershell.exe"),
    RTL_CONSTANT_STRING(L"pwsh.exe"),
    RTL_CONSTANT_STRING(L"mshta.exe"),
    RTL_CONSTANT_STRING(L"wscript.exe"),
    RTL_CONSTANT_STRING(L"cscript.exe"),
    RTL_CONSTANT_STRING(L"regsvr32.exe"),
    RTL_CONSTANT_STRING(L"rundll32.exe"),
    RTL_CONSTANT_STRING(L"certutil.exe"),
    RTL_CONSTANT_STRING(L"bitsadmin.exe"),
};

#define WSL_NATIVE_ESCAPE_TARGET_COUNT \
    (sizeof(g_NativeEscapeTargets) / sizeof(g_NativeEscapeTargets[0]))

//
// Credential file patterns that WSL processes should not touch.
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

//
// Path substrings for system directory access detection.
//
static const UNICODE_STRING g_DriversDir  = RTL_CONSTANT_STRING(L"\\drivers\\");
static const UNICODE_STRING g_System32Dir = RTL_CONSTANT_STRING(L"\\System32\\");

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

//
// Returns pointer valid ONLY while caller holds the bucket lock.
// Caller MUST hold ProcessBuckets[BucketIndex].Lock (shared or exclusive).
//
static PWSL_TRACKED_PROCESS
WslpFindProcessLocked(
    _In_ HANDLE ProcessId,
    _In_ ULONG BucketIndex
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
WslpPathContainsCI(
    _In_ PCUNICODE_STRING Path,
    _In_ PCUNICODE_STRING Substring
    );

static BOOLEAN
WslpIsNativeEscapeTarget(
    _In_ PCUNICODE_STRING ImageName
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

    g_WslState.TotalTrackedCount = 0;
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
    LONG freedCount = 0;

    PAGED_CODE();

    if (InterlockedCompareExchange(&g_WslState.State, 3, 2) != 2) {
        return;
    }

    ExWaitForRundownProtectionRelease(&g_WslState.RundownRef);

    //
    // All operations have drained. No concurrent access is possible, so
    // lock acquisition is unnecessary during cleanup (WSL-15).
    //
    for (ULONG i = 0; i < 64; i++) {
        while (!IsListEmpty(&g_WslState.ProcessBuckets[i].Head)) {
            LIST_ENTRY *Entry = RemoveHeadList(&g_WslState.ProcessBuckets[i].Head);
            PWSL_TRACKED_PROCESS Proc = CONTAINING_RECORD(
                Entry, WSL_TRACKED_PROCESS, Link);
            ExFreeToNPagedLookasideList(&g_WslState.ProcessLookaside, Proc);
            freedCount++;
        }
        FltDeletePushLock(&g_WslState.ProcessBuckets[i].Lock);
    }

    ExDeleteNPagedLookasideList(&g_WslState.ProcessLookaside);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/WSL] Shutdown complete. "
               "Detected=%lld, Escapes=%lld, Freed=%ld\n",
               g_WslState.Stats.WslProcessesDetected,
               g_WslState.Stats.EscapeAttemptsDetected,
               freedCount);
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
    WSL_PROCESS_TYPE ParentType = WslProcess_None;
    PWSL_TRACKED_PROCESS NewProc;
    ULONG Bucket;
    ULONG ParentBucket;
    UNICODE_STRING ImageNameOnly = { 0 };
    BOOLEAN hasImageName = FALSE;

    PAGED_CODE();

    if (!WslpEnterOperation()) {
        return WslProcess_None;
    }

    //
    // Step 1: Extract and classify the image name against known WSL binaries.
    //
    if (ImageFileName != NULL &&
        ImageFileName->Buffer != NULL &&
        ImageFileName->Length > 0) {

        if (WslpExtractImageName(ImageFileName, &ImageNameOnly)) {
            Type = WslpClassifyImage(&ImageNameOnly);
            hasImageName = TRUE;
        }
    }

    //
    // Step 2: If not directly classified, check if the parent is a tracked
    // WSL process. This also detects bash.exe from WSL context (without
    // false-positiving on Git Bash, Cygwin, etc.) and native escape targets.
    //
    // Lock the parent bucket to prevent use-after-free during ProcessType
    // read (WSL-3 fix). The pointer is valid only while the lock is held.
    //
    if (Type == WslProcess_None) {
        ParentBucket = WslpBucketIndex(ParentProcessId);

        FltAcquirePushLockShared(&g_WslState.ProcessBuckets[ParentBucket].Lock);
        {
            PWSL_TRACKED_PROCESS ParentProc =
                WslpFindProcessLocked(ParentProcessId, ParentBucket);

            if (ParentProc != NULL) {
                ParentType = ParentProc->ProcessType;
                Type = WslProcess_Child;
            }
        }
        FltReleasePushLock(&g_WslState.ProcessBuckets[ParentBucket].Lock);

        if (Type == WslProcess_Child) {
            InterlockedIncrement64(&g_WslState.Stats.SuspiciousSpawns);

            //
            // Check for native Windows executable escape (T1611).
            // A WSL-tracked parent spawning cmd.exe, powershell.exe, etc.
            // indicates potential container-to-host breakout.
            //
            if (hasImageName && WslpIsNativeEscapeTarget(&ImageNameOnly)) {
                InterlockedIncrement64(&g_WslState.Stats.EscapeAttemptsDetected);

                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike/WSL] ESCAPE: WSL->native process creation! "
                           "PID=%lu, Parent=%lu (ParentType=%d), Image=%wZ\n",
                           HandleToULong(ProcessId),
                           HandleToULong(ParentProcessId),
                           ParentType,
                           ImageFileName);

                //
                // Submit WSL container escape event to BehaviorEngine.
                //
                (VOID)BeEngineSubmitEvent(
                    BehaviorEvent_WslContainerEscape,
                    BehaviorCategory_DefenseEvasion,
                    HandleToULong(ProcessId),
                    NULL, 0,
                    80,
                    FALSE,
                    NULL
                    );
            } else {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                           "[ShadowStrike/WSL] WSL child process spawned: "
                           "PID=%lu, Parent=%lu (ParentType=%d)\n",
                           HandleToULong(ProcessId),
                           HandleToULong(ParentProcessId),
                           ParentType);
            }
        }
    }

    if (Type == WslProcess_None) {
        WslpLeaveOperation();
        return WslProcess_None;
    }

    //
    // Step 3: Enforce capacity limit to prevent NonPagedPool exhaustion
    // under attack. An adversary spawning thousands of WSL processes would
    // otherwise cause unbounded memory consumption (WSL-5).
    //
    if (InterlockedCompareExchange(
            &g_WslState.TotalTrackedCount, 0, 0) >= WSL_MAX_TRACKED_PROCESSES) {

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/WSL] Capacity limit reached (%d). "
                   "PID=%lu not tracked (Type=%d)\n",
                   WSL_MAX_TRACKED_PROCESSES,
                   HandleToULong(ProcessId), Type);

        WslpLeaveOperation();
        return Type;
    }

    //
    // Step 4: Allocate and populate tracking entry.
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

    if (ImageFileName != NULL &&
        ImageFileName->Buffer != NULL &&
        ImageFileName->Length > 0) {

        USHORT CopyLen = min(ImageFileName->Length,
                             (WSL_PROCESS_NAME_MAX - 1) * sizeof(WCHAR));
        RtlCopyMemory(NewProc->ImageName, ImageFileName->Buffer, CopyLen);
        NewProc->ImageNameLength = CopyLen / sizeof(WCHAR);
    }

    //
    // Step 5: Insert into hash table under exclusive lock.
    // Guard against duplicate insertion from rapid PID reuse (WSL-13).
    //
    Bucket = WslpBucketIndex(ProcessId);

    FltAcquirePushLockExclusive(&g_WslState.ProcessBuckets[Bucket].Lock);
    {
        PWSL_TRACKED_PROCESS Existing = WslpFindProcessLocked(ProcessId, Bucket);
        if (Existing != NULL) {
            //
            // Duplicate PID already tracked. This can happen with rapid
            // process creation/termination where the termination callback
            // hasn't fired yet. Discard the new entry.
            //
            FltReleasePushLock(&g_WslState.ProcessBuckets[Bucket].Lock);
            ExFreeToNPagedLookasideList(&g_WslState.ProcessLookaside, NewProc);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                       "[ShadowStrike/WSL] Duplicate PID=%lu, skipping insert\n",
                       HandleToULong(ProcessId));

            WslpLeaveOperation();
            return Type;
        }

        InsertTailList(&g_WslState.ProcessBuckets[Bucket].Head, &NewProc->Link);
        InterlockedIncrement(&g_WslState.ProcessBuckets[Bucket].Count);
    }
    FltReleasePushLock(&g_WslState.ProcessBuckets[Bucket].Lock);

    InterlockedIncrement(&g_WslState.TotalTrackedCount);
    InterlockedIncrement64(&g_WslState.Stats.WslProcessesDetected);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/WSL] WSL process tracked: PID=%lu Type=%d (Total=%ld)\n",
               HandleToULong(ProcessId), Type,
               InterlockedCompareExchange(&g_WslState.TotalTrackedCount, 0, 0));

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
    PWSL_TRACKED_PROCESS Found = NULL;

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
            Found = Proc;
            break;
        }
    }

    FltReleasePushLock(&g_WslState.ProcessBuckets[Bucket].Lock);

    //
    // Free the detached entry outside the lock. The entry is no longer
    // reachable from the list, so no concurrent access is possible.
    //
    if (Found != NULL) {
        InterlockedDecrement(&g_WslState.TotalTrackedCount);
        ExFreeToNPagedLookasideList(&g_WslState.ProcessLookaside, Found);
    }

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
    ULONG Bucket;
    WSL_ESCAPE_TYPE Result = WslEscape_None;

    //
    // Defensive validation â€” FileName may have NULL Buffer on malformed
    // IRP_MJ_CREATE requests or volume opens (WSL-14).
    //
    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return WslEscape_None;
    }

    if (!WslpEnterOperation()) {
        return WslEscape_None;
    }

    //
    // Hold the bucket lock for the duration of all process field accesses
    // to prevent use-after-free if the process terminates concurrently.
    // InterlockedIncrement on process fields is atomic, but the pointer
    // itself must remain valid (WSL-3 fix).
    //
    Bucket = WslpBucketIndex(ProcessId);

    FltAcquirePushLockShared(&g_WslState.ProcessBuckets[Bucket].Lock);
    {
        PWSL_TRACKED_PROCESS Proc = WslpFindProcessLocked(ProcessId, Bucket);

        if (Proc == NULL) {
            FltReleasePushLock(&g_WslState.ProcessBuckets[Bucket].Lock);
            WslpLeaveOperation();
            return WslEscape_None;
        }

        //
        // Track all file accesses from WSL processes for profiling.
        //
        InterlockedIncrement(&Proc->FileAccessCount);
        InterlockedIncrement64(&g_WslState.Stats.FileSystemCrossings);

        //
        // Priority 1: Credential file access (T1003 â€” OS Credential Dumping).
        // This is the highest severity because it indicates direct credential
        // theft attempts from WSL context.
        //
        if (WslpIsCredentialPath(FileName)) {
            InterlockedIncrement(&Proc->EscapeAttempts);
            InterlockedIncrement64(&g_WslState.Stats.EscapeAttemptsDetected);
            InterlockedIncrement64(&g_WslState.Stats.CredentialAccessAttempts);
            Result = WslEscape_CredentialAccess;

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike/WSL] CRITICAL: WSL credential access attempt! "
                       "PID=%lu, File=%wZ\n",
                       HandleToULong(ProcessId), FileName);

            //
            // Submit WSL credential access event to BehaviorEngine.
            //
            (VOID)BeEngineSubmitEvent(
                BehaviorEvent_WslCredentialAccess,
                BehaviorCategory_CredentialAccess,
                HandleToULong(ProcessId),
                NULL, 0,
                85,
                FALSE,
                NULL
                );
        }

        //
        // Priority 2: Driver directory access (T1611 â€” Escape to Host).
        // WSL processes accessing \drivers\ may be attempting to load
        // or manipulate kernel-mode drivers.
        //
        if (Result == WslEscape_None) {
            if (WslpPathContainsCI(FileName, &g_DriversDir)) {
                InterlockedIncrement(&Proc->SuspiciousActions);
                InterlockedIncrement64(&g_WslState.Stats.EscapeAttemptsDetected);
                Result = WslEscape_DriverLoad;

                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike/WSL] WSL driver directory access: "
                           "PID=%lu, File=%wZ\n",
                           HandleToULong(ProcessId), FileName);

                //
                // Submit WSL driver access event to BehaviorEngine.
                //
                (VOID)BeEngineSubmitEvent(
                    BehaviorEvent_WslDriverAccess,
                    BehaviorCategory_DefenseEvasion,
                    HandleToULong(ProcessId),
                    NULL, 0,
                    60,
                    FALSE,
                    NULL
                    );
            }
        }

        //
        // Priority 3: System32 access (T1611 â€” general system manipulation).
        // WSL processes accessing \System32\ may be tampering with system
        // binaries, DLLs, or configuration files (WSL-12 fix).
        //
        if (Result == WslEscape_None) {
            if (WslpPathContainsCI(FileName, &g_System32Dir)) {
                InterlockedIncrement(&Proc->SuspiciousActions);
                Result = WslEscape_FileSystemAccess;

                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                           "[ShadowStrike/WSL] WSL System32 access: "
                           "PID=%lu, File=%wZ\n",
                           HandleToULong(ProcessId), FileName);
            }
        }
    }
    FltReleasePushLock(&g_WslState.ProcessBuckets[Bucket].Lock);

    WslpLeaveOperation();
    return Result;
}

// ============================================================================
// QUERY
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
WslMonIsWslProcess(
    _In_ HANDLE ProcessId
    )
{
    ULONG Bucket;
    BOOLEAN Found;

    //
    // Rundown protection ensures the hash table and push locks are valid
    // (WSL-4 fix). Without this, a call during/after shutdown would access
    // deleted push locks â†’ BSOD.
    //
    if (!WslpEnterOperation()) {
        return FALSE;
    }

    Bucket = WslpBucketIndex(ProcessId);

    FltAcquirePushLockShared(&g_WslState.ProcessBuckets[Bucket].Lock);
    Found = (WslpFindProcessLocked(ProcessId, Bucket) != NULL);
    FltReleasePushLock(&g_WslState.ProcessBuckets[Bucket].Lock);

    WslpLeaveOperation();
    return Found;
}


_IRQL_requires_max_(APC_LEVEL)
VOID
WslMonGetStatistics(
    _Out_ PWSL_STATISTICS Statistics
    )
{
    //
    // Rundown protection ensures stats are in a consistent state (WSL-8 fix).
    // If the module has shut down, return zeroed stats.
    //
    if (!WslpEnterOperation()) {
        RtlZeroMemory(Statistics, sizeof(WSL_STATISTICS));
        return;
    }

    RtlCopyMemory(Statistics, &g_WslState.Stats, sizeof(WSL_STATISTICS));

    WslpLeaveOperation();
}

// ============================================================================
// PRIVATE â€” PROCESS LOOKUP
// ============================================================================

static ULONG
WslpBucketIndex(
    _In_ HANDLE ProcessId
    )
{
    return (HandleToULong(ProcessId) >> 2) % 64;
}


//
// Searches for a tracked process within a specific bucket.
// CALLER MUST HOLD ProcessBuckets[BucketIndex].Lock (shared or exclusive).
// The returned pointer is valid ONLY while the lock is held.
//
static PWSL_TRACKED_PROCESS
WslpFindProcessLocked(
    _In_ HANDLE ProcessId,
    _In_ ULONG BucketIndex
    )
{
    LIST_ENTRY *ListEntry;

    for (ListEntry = g_WslState.ProcessBuckets[BucketIndex].Head.Flink;
         ListEntry != &g_WslState.ProcessBuckets[BucketIndex].Head;
         ListEntry = ListEntry->Flink) {

        PWSL_TRACKED_PROCESS Proc = CONTAINING_RECORD(
            ListEntry, WSL_TRACKED_PROCESS, Link);

        if (Proc->ProcessId == ProcessId) {
            return Proc;
        }
    }

    return NULL;
}

// ============================================================================
// PRIVATE â€” IMAGE CLASSIFICATION
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
    //
    // bash.exe intentionally NOT classified here. It appears in Git Bash,
    // Cygwin, MSYS2, and other non-WSL contexts. WSL-spawned bash is
    // detected through parent chain analysis in WslMonCheckProcessCreate
    // step 2, which only classifies bash as WSL if its parent is already
    // tracked as a WSL process (WSL-11 fix).
    //
    return WslProcess_None;
}


static BOOLEAN
WslpExtractImageName(
    _In_ PCUNICODE_STRING FullPath,
    _Out_ PUNICODE_STRING NameOnly
    )
{
    USHORT Length;

    if (FullPath->Buffer == NULL || FullPath->Length == 0) {
        NameOnly->Buffer = NULL;
        NameOnly->Length = 0;
        NameOnly->MaximumLength = 0;
        return FALSE;
    }

    Length = FullPath->Length / sizeof(WCHAR);

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
// PRIVATE â€” CREDENTIAL PATH CHECK
// ============================================================================

static BOOLEAN
WslpIsCredentialPath(
    _In_ PCUNICODE_STRING FileName
    )
{
    for (ULONG i = 0; i < WSL_CREDENTIAL_PATH_COUNT; i++) {
        //
        // Check if the credential path is a suffix of the filename
        // (handles volume prefix variations like \Device\HarddiskVolume3\...).
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
// PRIVATE â€” PATH SUBSTRING SEARCH
// ============================================================================

//
// Case-insensitive substring search within a UNICODE_STRING path.
// Replaces the previous O(n) loop of RtlEqualUnicodeString calls with
// a direct character comparison approach (WSL-6 fix).
//
static BOOLEAN
WslpPathContainsCI(
    _In_ PCUNICODE_STRING Path,
    _In_ PCUNICODE_STRING Substring
    )
{
    USHORT pathChars;
    USHORT subChars;
    USHORT limit;

    if (Path->Buffer == NULL || Substring->Buffer == NULL) {
        return FALSE;
    }

    pathChars = Path->Length / sizeof(WCHAR);
    subChars = Substring->Length / sizeof(WCHAR);

    if (subChars == 0 || pathChars < subChars) {
        return FALSE;
    }

    //
    // Maximum starting position for a valid match. Since pathChars and
    // subChars are derived from UNICODE_STRING.Length (USHORT / 2), the
    // maximum value of limit is 32766, which fits safely in USHORT.
    //
    limit = pathChars - subChars;

    for (USHORT i = 0; i <= limit; i++) {
        BOOLEAN match = TRUE;

        for (USHORT j = 0; j < subChars; j++) {
            if (RtlUpcaseUnicodeChar(Path->Buffer[i + j]) !=
                RtlUpcaseUnicodeChar(Substring->Buffer[j])) {
                match = FALSE;
                break;
            }
        }

        if (match) {
            return TRUE;
        }
    }

    return FALSE;
}

// ============================================================================
// PRIVATE â€” NATIVE ESCAPE TARGET DETECTION
// ============================================================================

//
// Checks if the given image name matches a known native Windows executable
// that would be suspicious if spawned from a WSL process context (T1611).
//
static BOOLEAN
WslpIsNativeEscapeTarget(
    _In_ PCUNICODE_STRING ImageName
    )
{
    for (ULONG i = 0; i < WSL_NATIVE_ESCAPE_TARGET_COUNT; i++) {
        if (RtlEqualUnicodeString(ImageName, &g_NativeEscapeTargets[i], TRUE)) {
            return TRUE;
        }
    }
    return FALSE;
}

// ============================================================================
// PRIVATE â€” LIFECYCLE
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
