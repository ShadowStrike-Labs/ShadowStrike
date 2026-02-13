/*++
    ShadowStrike Next-Generation Antivirus
    Module: ClipboardMonitor.c - Kernel-side clipboard abuse detection

    Purpose: Heuristic detection of clipboard data theft patterns by analyzing
    process creation (command lines, image names) and file write patterns.
    Direct clipboard interception is impossible from kernel mode (clipboard
    is a user-mode construct in csrss.exe), but we can detect the behavioral
    fingerprints of clipboard-stealing malware and tools.

    MITRE ATT&CK: T1115 (Clipboard Data)

    Copyright (c) ShadowStrike Team
--*/

#include "ClipboardMonitor.h"
#include "../../Core/Globals.h"
#include "../../Utilities/MemoryUtils.h"
#include <ntstrsafe.h>

// ============================================================================
// Private Constants
// ============================================================================

#define CBMON_INIT_UNINITIALIZED    0
#define CBMON_INIT_INITIALIZING     1
#define CBMON_INIT_READY            2
#define CBMON_INIT_SHUTDOWN         3

//
// Per-process clipboard suspicion tracking
//
#define CBMON_PROCESS_HASH_BUCKETS  256
#define CBMON_MAX_TRACKED_PROCESSES 2048
#define CBMON_TEMP_WRITE_THRESHOLD  10      // Rapid writes in window
#define CBMON_TEMP_WRITE_WINDOW_MS  5000    // 5-second window

// ============================================================================
// Private Structures
// ============================================================================

typedef struct _CBMON_PROCESS_ENTRY {
    LIST_ENTRY Link;
    HANDLE ProcessId;
    ULONG Indicators;              // CBMON_INDICATOR bitmask
    volatile LONG TempFileWrites;  // Counter within time window
    LARGE_INTEGER WindowStart;     // Start of current counting window
    BOOLEAN Flagged;               // Already reported
} CBMON_PROCESS_ENTRY, *PCBMON_PROCESS_ENTRY;

typedef struct _CBMON_STATE {
    volatile LONG InitState;
    EX_RUNDOWN_REF RundownRef;
    NPAGED_LOOKASIDE_LIST EntryLookaside;

    // Per-PID tracking hash table
    LIST_ENTRY ProcessBuckets[CBMON_PROCESS_HASH_BUCKETS];
    EX_PUSH_LOCK BucketLocks[CBMON_PROCESS_HASH_BUCKETS];
    volatile LONG TrackedCount;

    CBMON_STATISTICS Stats;
} CBMON_STATE;

static CBMON_STATE g_CbState;

// ============================================================================
// Known Clipboard Command-Line Patterns (case-insensitive matching)
// ============================================================================

static const WCHAR* g_ClipboardCmdPatterns[] = {
    L"Get-Clipboard",
    L"Set-Clipboard",
    L"clip.exe",
    L"[System.Windows.Forms.Clipboard]",
    L"win32_clipboard",
    L"xclip",
    L"xsel",
    L"pbcopy",
    L"ClipboardData",
    L"GetClipboardData",
    L"OpenClipboard",
    L"OleGetClipboard",
    L"Add-Type.*Clipboard",
};

#define CBMON_CMD_PATTERN_COUNT  (sizeof(g_ClipboardCmdPatterns) / sizeof(g_ClipboardCmdPatterns[0]))

// ============================================================================
// Known Clipboard Stealer Image Names (filename only, case-insensitive)
// ============================================================================

static const WCHAR* g_ClipboardStealerNames[] = {
    L"cliplogger",
    L"clipstealer",
    L"clipgrab",
    L"clipboard_monitor",
    L"clipboardspy",
    L"clipsvc_exploit",
};

#define CBMON_STEALER_NAME_COUNT  (sizeof(g_ClipboardStealerNames) / sizeof(g_ClipboardStealerNames[0]))

// ============================================================================
// Forward Declarations
// ============================================================================

static ULONG CbMonpHashPid(_In_ HANDLE ProcessId);

static PCBMON_PROCESS_ENTRY CbMonpLookupProcess(
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN CreateIfMissing
    );

static BOOLEAN CbMonpContainsPatternCI(
    _In_ PCUNICODE_STRING Haystack,
    _In_ PCWSTR Needle
    );

static BOOLEAN CbMonpIsTempPath(
    _In_ PCUNICODE_STRING FileName
    );

static PCWSTR CbMonpExtractFileName(
    _In_ PCUNICODE_STRING FullPath
    );

// ============================================================================
// Public API
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
CbMonInitialize(VOID)
{
    LONG prev;

    prev = InterlockedCompareExchange(&g_CbState.InitState,
                                       CBMON_INIT_INITIALIZING,
                                       CBMON_INIT_UNINITIALIZED);
    if (prev != CBMON_INIT_UNINITIALIZED) {
        return (prev == CBMON_INIT_READY) ? STATUS_SUCCESS : STATUS_DEVICE_BUSY;
    }

    ExInitializeRundownProtection(&g_CbState.RundownRef);

    ExInitializeNPagedLookasideList(
        &g_CbState.EntryLookaside,
        NULL, NULL,
        POOL_NX_ALLOCATION,
        sizeof(CBMON_PROCESS_ENTRY),
        CBMON_POOL_TAG,
        0
        );

    for (ULONG i = 0; i < CBMON_PROCESS_HASH_BUCKETS; i++) {
        InitializeListHead(&g_CbState.ProcessBuckets[i]);
        FltInitializePushLock(&g_CbState.BucketLocks[i]);
    }

    g_CbState.TrackedCount = 0;
    RtlZeroMemory(&g_CbState.Stats, sizeof(CBMON_STATISTICS));

    InterlockedExchange(&g_CbState.InitState, CBMON_INIT_READY);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[ShadowStrike/ClipboardMonitor] Initialized with %u cmd patterns, %u stealer names\n",
        (ULONG)CBMON_CMD_PATTERN_COUNT,
        (ULONG)CBMON_STEALER_NAME_COUNT);

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
CbMonShutdown(VOID)
{
    LONG prev;

    prev = InterlockedCompareExchange(&g_CbState.InitState,
                                       CBMON_INIT_SHUTDOWN,
                                       CBMON_INIT_READY);
    if (prev != CBMON_INIT_READY) {
        return;
    }

    ExWaitForRundownProtectionRelease(&g_CbState.RundownRef);

    //
    // Free all tracked process entries
    //
    for (ULONG i = 0; i < CBMON_PROCESS_HASH_BUCKETS; i++) {
        while (!IsListEmpty(&g_CbState.ProcessBuckets[i])) {
            PLIST_ENTRY entry = RemoveHeadList(&g_CbState.ProcessBuckets[i]);
            PCBMON_PROCESS_ENTRY procEntry = CONTAINING_RECORD(
                entry, CBMON_PROCESS_ENTRY, Link);
            ExFreeToNPagedLookasideList(&g_CbState.EntryLookaside, procEntry);
        }
        FltDeletePushLock(&g_CbState.BucketLocks[i]);
    }

    ExDeleteNPagedLookasideList(&g_CbState.EntryLookaside);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[ShadowStrike/ClipboardMonitor] Shutdown complete "
        "(checked=%lld, suspicious=%lld)\n",
        g_CbState.Stats.TotalProcessesChecked,
        g_CbState.Stats.SuspiciousDetections);
}

_IRQL_requires_(PASSIVE_LEVEL)
ULONG
CbMonCheckProcessCreate(
    _In_ HANDLE ProcessId,
    _In_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    ULONG indicators = CbIndicator_None;
    PCUNICODE_STRING cmdLine;
    PCUNICODE_STRING imageName;

    if (g_CbState.InitState != CBMON_INIT_READY) {
        return CbIndicator_None;
    }

    if (!ExAcquireRundownProtection(&g_CbState.RundownRef)) {
        return CbIndicator_None;
    }

    InterlockedIncrement64(&g_CbState.Stats.TotalProcessesChecked);

    cmdLine = CreateInfo->CommandLine;
    imageName = CreateInfo->ImageFileName;

    //
    // Check command line for clipboard-related patterns
    //
    if (cmdLine != NULL && cmdLine->Length > 0) {
        for (ULONG i = 0; i < CBMON_CMD_PATTERN_COUNT; i++) {
            if (CbMonpContainsPatternCI(cmdLine, g_ClipboardCmdPatterns[i])) {
                indicators |= CbIndicator_ClipboardCommandLine;
                InterlockedIncrement64(&g_CbState.Stats.CommandLineMatches);

                //
                // Check for encoded clipboard commands (double evasion layer)
                //
                if (CbMonpContainsPatternCI(cmdLine, L"-enc") ||
                    CbMonpContainsPatternCI(cmdLine, L"-EncodedCommand")) {
                    indicators |= CbIndicator_EncodedClipboardCmd;
                }

                break;
            }
        }
    }

    //
    // Check image name against known clipboard stealers
    //
    if (imageName != NULL && imageName->Length > 0) {
        PCWSTR fileName = CbMonpExtractFileName(imageName);
        if (fileName != NULL) {
            for (ULONG i = 0; i < CBMON_STEALER_NAME_COUNT; i++) {
                UNICODE_STRING pattern;
                RtlInitUnicodeString(&pattern, g_ClipboardStealerNames[i]);

                //
                // Case-insensitive substring check in filename
                //
                UNICODE_STRING fileNameStr;
                RtlInitUnicodeString(&fileNameStr, fileName);

                if (CbMonpContainsPatternCI(&fileNameStr, g_ClipboardStealerNames[i])) {
                    indicators |= CbIndicator_KnownStealerImage;
                    break;
                }
            }
        }
    }

    //
    // If any indicator found, track this process for further monitoring
    //
    if (indicators != CbIndicator_None) {
        PCBMON_PROCESS_ENTRY entry = CbMonpLookupProcess(ProcessId, TRUE);
        if (entry != NULL) {
            entry->Indicators |= indicators;
        }

        InterlockedIncrement64(&g_CbState.Stats.SuspiciousDetections);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[ShadowStrike/ClipboardMonitor] T1115 indicator: PID=%lu, flags=0x%08X\n",
            HandleToULong(ProcessId),
            indicators);
    }

    ExReleaseRundownProtection(&g_CbState.RundownRef);
    return indicators;
}

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
CbMonCheckFileWrite(
    _In_ HANDLE ProcessId,
    _In_ PCUNICODE_STRING FileName
    )
{
    PCBMON_PROCESS_ENTRY entry;
    LARGE_INTEGER now;
    BOOLEAN suspicious = FALSE;

    if (g_CbState.InitState != CBMON_INIT_READY) {
        return FALSE;
    }

    if (!ExAcquireRundownProtection(&g_CbState.RundownRef)) {
        return FALSE;
    }

    //
    // Only check processes that already have clipboard indicators
    //
    entry = CbMonpLookupProcess(ProcessId, FALSE);
    if (entry == NULL || entry->Indicators == CbIndicator_None) {
        ExReleaseRundownProtection(&g_CbState.RundownRef);
        return FALSE;
    }

    //
    // Check if writing to temp/appdata paths (clipboard dump targets)
    //
    if (!CbMonpIsTempPath(FileName)) {
        ExReleaseRundownProtection(&g_CbState.RundownRef);
        return FALSE;
    }

    //
    // Track rapid temp file writes within time window
    //
    KeQuerySystemTime(&now);

    {
        LONGLONG elapsedMs = (now.QuadPart - entry->WindowStart.QuadPart) / 10000;

        if (elapsedMs > CBMON_TEMP_WRITE_WINDOW_MS || entry->WindowStart.QuadPart == 0) {
            //
            // Reset window
            //
            entry->WindowStart = now;
            InterlockedExchange(&entry->TempFileWrites, 1);
        } else {
            LONG count = InterlockedIncrement(&entry->TempFileWrites);

            if (count >= CBMON_TEMP_WRITE_THRESHOLD && !entry->Flagged) {
                entry->Indicators |= CbIndicator_RapidTempFileWrites;
                entry->Flagged = TRUE;
                suspicious = TRUE;

                InterlockedIncrement64(&g_CbState.Stats.FileWriteMatches);

                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "[ShadowStrike/ClipboardMonitor] T1115 rapid temp writes: "
                    "PID=%lu, count=%ld, file=%wZ\n",
                    HandleToULong(ProcessId),
                    count,
                    FileName);
            }
        }
    }

    ExReleaseRundownProtection(&g_CbState.RundownRef);
    return suspicious;
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
CbMonGetStatistics(
    _Out_ PCBMON_STATISTICS Stats
    )
{
    if (Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Stats->TotalProcessesChecked = g_CbState.Stats.TotalProcessesChecked;
    Stats->SuspiciousDetections = g_CbState.Stats.SuspiciousDetections;
    Stats->CommandLineMatches = g_CbState.Stats.CommandLineMatches;
    Stats->FileWriteMatches = g_CbState.Stats.FileWriteMatches;
    Stats->CrossProcessMatches = g_CbState.Stats.CrossProcessMatches;

    return STATUS_SUCCESS;
}

// ============================================================================
// Private Helpers
// ============================================================================

static ULONG
CbMonpHashPid(
    _In_ HANDLE ProcessId
    )
{
    ULONG_PTR pid = (ULONG_PTR)ProcessId;
    pid ^= (pid >> 16);
    pid *= 0x45d9f3b;
    pid ^= (pid >> 16);
    return (ULONG)(pid & (CBMON_PROCESS_HASH_BUCKETS - 1));
}

static PCBMON_PROCESS_ENTRY
CbMonpLookupProcess(
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN CreateIfMissing
    )
{
    ULONG bucket = CbMonpHashPid(ProcessId);
    PLIST_ENTRY listHead = &g_CbState.ProcessBuckets[bucket];
    PLIST_ENTRY entry;
    PCBMON_PROCESS_ENTRY procEntry = NULL;

    KeEnterCriticalRegion();
    FltAcquirePushLockShared(&g_CbState.BucketLocks[bucket]);

    for (entry = listHead->Flink; entry != listHead; entry = entry->Flink) {
        PCBMON_PROCESS_ENTRY candidate = CONTAINING_RECORD(
            entry, CBMON_PROCESS_ENTRY, Link);
        if (candidate->ProcessId == ProcessId) {
            procEntry = candidate;
            break;
        }
    }

    FltReleasePushLock(&g_CbState.BucketLocks[bucket]);
    KeLeaveCriticalRegion();

    if (procEntry == NULL && CreateIfMissing) {
        //
        // Cap tracked processes to prevent resource exhaustion
        //
        if (g_CbState.TrackedCount >= CBMON_MAX_TRACKED_PROCESSES) {
            return NULL;
        }

        procEntry = (PCBMON_PROCESS_ENTRY)ExAllocateFromNPagedLookasideList(
            &g_CbState.EntryLookaside);

        if (procEntry == NULL) {
            return NULL;
        }

        RtlZeroMemory(procEntry, sizeof(CBMON_PROCESS_ENTRY));
        procEntry->ProcessId = ProcessId;

        KeEnterCriticalRegion();
        FltAcquirePushLockExclusive(&g_CbState.BucketLocks[bucket]);

        //
        // TOCTOU: re-check under exclusive lock
        //
        {
            PLIST_ENTRY check;
            for (check = listHead->Flink; check != listHead; check = check->Flink) {
                PCBMON_PROCESS_ENTRY existing = CONTAINING_RECORD(
                    check, CBMON_PROCESS_ENTRY, Link);
                if (existing->ProcessId == ProcessId) {
                    //
                    // Another thread inserted — use existing, free ours
                    //
                    FltReleasePushLock(&g_CbState.BucketLocks[bucket]);
                    KeLeaveCriticalRegion();
                    ExFreeToNPagedLookasideList(&g_CbState.EntryLookaside, procEntry);
                    return existing;
                }
            }
        }

        InsertTailList(listHead, &procEntry->Link);
        InterlockedIncrement(&g_CbState.TrackedCount);

        FltReleasePushLock(&g_CbState.BucketLocks[bucket]);
        KeLeaveCriticalRegion();
    }

    return procEntry;
}

static BOOLEAN
CbMonpContainsPatternCI(
    _In_ PCUNICODE_STRING Haystack,
    _In_ PCWSTR Needle
    )
{
    UNICODE_STRING needleStr;
    USHORT needleChars;
    USHORT haystackChars;
    USHORT limit;

    if (Haystack == NULL || Haystack->Buffer == NULL || Haystack->Length == 0) {
        return FALSE;
    }

    RtlInitUnicodeString(&needleStr, Needle);
    needleChars = needleStr.Length / sizeof(WCHAR);
    haystackChars = Haystack->Length / sizeof(WCHAR);

    if (needleChars == 0 || needleChars > haystackChars) {
        return FALSE;
    }

    limit = haystackChars - needleChars;

    for (USHORT i = 0; i <= limit; i++) {
        BOOLEAN match = TRUE;

        for (USHORT j = 0; j < needleChars; j++) {
            WCHAR h = RtlUpcaseUnicodeChar(Haystack->Buffer[i + j]);
            WCHAR n = RtlUpcaseUnicodeChar(needleStr.Buffer[j]);

            if (h != n) {
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

static BOOLEAN
CbMonpIsTempPath(
    _In_ PCUNICODE_STRING FileName
    )
{
    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return FALSE;
    }

    //
    // Check for common temp/appdata paths where clipboard dumps land
    //
    static const WCHAR* tempPatterns[] = {
        L"\\Temp\\",
        L"\\AppData\\Local\\Temp\\",
        L"\\AppData\\Roaming\\",
        L"\\Local Settings\\Temp\\",
        L"\\$Recycle.Bin\\",
    };

    for (ULONG i = 0; i < sizeof(tempPatterns) / sizeof(tempPatterns[0]); i++) {
        if (CbMonpContainsPatternCI(FileName, tempPatterns[i])) {
            return TRUE;
        }
    }

    return FALSE;
}

static PCWSTR
CbMonpExtractFileName(
    _In_ PCUNICODE_STRING FullPath
    )
{
    if (FullPath == NULL || FullPath->Buffer == NULL || FullPath->Length == 0) {
        return NULL;
    }

    USHORT chars = FullPath->Length / sizeof(WCHAR);

    for (USHORT i = chars; i > 0; i--) {
        if (FullPath->Buffer[i - 1] == L'\\') {
            return &FullPath->Buffer[i];
        }
    }

    return FullPath->Buffer;
}
