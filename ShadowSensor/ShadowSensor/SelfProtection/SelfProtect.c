/**
 * ============================================================================
 * ShadowStrike NGAV - SELF-PROTECTION IMPLEMENTATION
 * ============================================================================
 *
 * @file SelfProtect.c
 * @brief Self-protection against malware termination and tampering.
 *
 * CRITICAL SECURITY MODULE - This prevents malware from:
 * 1. Terminating our service process
 * 2. Injecting code into our process
 * 3. Modifying our binaries on disk
 * 4. Tampering with our registry keys
 *
 * Without ELAM, this is our primary defense. Handle with extreme care.
 *
 * IRQL SAFETY:
 * - ObCallbacks run at IRQL <= DISPATCH_LEVEL.
 * - All data accessed from callbacks is protected by EX_SPIN_LOCK
 *   (ExAcquireSpinLockShared/Exclusive), safe at DISPATCH_LEVEL.
 * - Push locks are NOT used anywhere in this module.
 * - Paged functions (Init/Shutdown/Protect/Unprotect/Add*/Remove*) assert
 *   PAGED_CODE() and run at PASSIVE_LEVEL.
 *
 * LIFECYCLE:
 * - volatile LONG g_SelfProtectInitialized / g_SelfProtectShuttingDown
 * - volatile LONG g_SelfProtectActiveOps + KEVENT g_SelfProtectDrainEvent
 * - Shutdown: signal shutdown -> wait for drain -> free resources
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "SelfProtect.h"
#include "../Core/Globals.h"
#include "../Shared/SharedDefs.h"
#include "../Utilities/MemoryUtils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ShadowStrikeInitializeSelfProtection)
#pragma alloc_text(PAGE, ShadowStrikeShutdownSelfProtection)
#pragma alloc_text(PAGE, ShadowStrikeProtectProcess)
#pragma alloc_text(PAGE, ShadowStrikeUnprotectProcess)
#pragma alloc_text(PAGE, ShadowStrikeAddProtectedPath)
#pragma alloc_text(PAGE, ShadowStrikeRemoveProtectedPath)
#pragma alloc_text(PAGE, ShadowStrikeAddProtectedRegistryKey)
#pragma alloc_text(PAGE, ShadowStrikeRemoveProtectedRegistryKey)
#endif

// ============================================================================
// GLOBAL STATE
// ============================================================================

//
// Lifecycle control:
//   Initialized=1 means all structures are valid.
//   ShuttingDown=1 means no new operations should start.
//   ActiveOps counts in-flight callback operations; DrainEvent is signaled
//   when ActiveOps reaches 0 after ShuttingDown is set.
//
static volatile LONG  g_SelfProtectInitialized = 0;
static volatile LONG  g_SelfProtectShuttingDown = 0;
static volatile LONG  g_SelfProtectActiveOps = 0;
static KEVENT         g_SelfProtectDrainEvent;

//
// Protected process list.
// EX_SPIN_LOCK provides reader/writer semantics safe at DISPATCH_LEVEL.
//
static LIST_ENTRY     g_ProtectedProcessList;
static EX_SPIN_LOCK   g_ProtectedProcessLock;
static volatile LONG  g_ProtectedProcessCount = 0;

//
// Protected file paths (static array).
//
static SHADOWSTRIKE_PROTECTED_PATH g_ProtectedPaths[SHADOWSTRIKE_MAX_PROTECTED_PATHS];
static EX_SPIN_LOCK   g_ProtectedPathLock;

//
// Protected registry keys (static array).
//
static SHADOWSTRIKE_PROTECTED_REGKEY g_ProtectedRegKeys[SHADOWSTRIKE_MAX_PROTECTED_REGKEYS];
static EX_SPIN_LOCK   g_ProtectedRegKeyLock;

//
// Statistics — updated via InterlockedIncrement64, snapshot under spin lock.
//
static SHADOWSTRIKE_SELFPROTECT_STATS g_SelfProtectStats;
static EX_SPIN_LOCK   g_SelfProtectStatsLock;

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

/**
 * @brief Enter an active operation. Returns FALSE if shutdown is in progress.
 */
static
BOOLEAN
SspEnterOperation(
    VOID
    )
{
    if (ReadNoFence(&g_SelfProtectShuttingDown)) {
        return FALSE;
    }
    InterlockedIncrement(&g_SelfProtectActiveOps);
    //
    // Re-check after incrementing to close the race where shutdown
    // was signaled between the first check and the increment.
    //
    if (ReadNoFence(&g_SelfProtectShuttingDown)) {
        if (InterlockedDecrement(&g_SelfProtectActiveOps) == 0) {
            KeSetEvent(&g_SelfProtectDrainEvent, IO_NO_INCREMENT, FALSE);
        }
        return FALSE;
    }
    return TRUE;
}

/**
 * @brief Leave an active operation. Signals drain event if last out.
 */
static
VOID
SspLeaveOperation(
    VOID
    )
{
    if (InterlockedDecrement(&g_SelfProtectActiveOps) == 0) {
        if (ReadNoFence(&g_SelfProtectShuttingDown)) {
            KeSetEvent(&g_SelfProtectDrainEvent, IO_NO_INCREMENT, FALSE);
        }
    }
}

/**
 * @brief Safely measure a PCWSTR with a maximum character count.
 * @return STATUS_SUCCESS and length in *OutCch, or error.
 */
static
NTSTATUS
SspSafeStringLength(
    _In_ PCWSTR String,
    _In_ SIZE_T MaxCch,
    _Out_ SIZE_T* OutCch
    )
{
    NTSTATUS status;

    *OutCch = 0;

    __try {
        status = RtlStringCchLengthW(String, MaxCch, OutCch);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        *OutCch = 0;
    }

    return status;
}

/**
 * @brief Strip access rights for a process handle operation.
 * Factors out duplicated logic between CREATE and DUPLICATE operations.
 */
static
VOID
SspStripProcessAccess(
    _Inout_ PACCESS_MASK DesiredAccess,
    _In_ ULONG ProtectionFlags
    )
{
    ACCESS_MASK original = *DesiredAccess;
    ACCESS_MASK stripped = original;

    if (ProtectionFlags & ProtectionFlagBlockTerminate) {
        stripped &= ~PROCESS_TERMINATE;
    }
    if (ProtectionFlags & ProtectionFlagBlockVMWrite) {
        stripped &= ~(PROCESS_VM_WRITE | PROCESS_VM_OPERATION);
    }
    if (ProtectionFlags & ProtectionFlagBlockInject) {
        stripped &= ~PROCESS_CREATE_THREAD;
    }
    if (ProtectionFlags & ProtectionFlagBlockSuspend) {
        stripped &= ~PROCESS_SUSPEND_RESUME;
    }

    if (stripped != original) {
        *DesiredAccess = stripped;
        InterlockedIncrement64(&g_SelfProtectStats.HandleStrips);

        if ((original & PROCESS_TERMINATE) && !(stripped & PROCESS_TERMINATE)) {
            InterlockedIncrement64(&g_SelfProtectStats.ProcessTerminateBlocks);
        }
        if ((original & PROCESS_VM_WRITE) && !(stripped & PROCESS_VM_WRITE)) {
            InterlockedIncrement64(&g_SelfProtectStats.VMWriteBlocks);
        }
    }
}

/**
 * @brief Strip access rights for a thread handle operation.
 */
static
VOID
SspStripThreadAccess(
    _Inout_ PACCESS_MASK DesiredAccess
    )
{
    ACCESS_MASK original = *DesiredAccess;
    ACCESS_MASK stripped = original & ~SHADOWSTRIKE_DANGEROUS_THREAD_ACCESS;

    if (stripped != original) {
        *DesiredAccess = stripped;
        InterlockedIncrement64(&g_SelfProtectStats.HandleStrips);
        InterlockedIncrement64(&g_SelfProtectStats.ThreadInjectBlocks);
    }
}

/**
 * @brief Prefix-match a UNICODE_STRING against a stored WCHAR path.
 * Case-insensitive. Used for both file paths and registry keys.
 */
static
BOOLEAN
SspPrefixMatch(
    _In_ PCUNICODE_STRING TestPath,
    _In_ PCWCH Prefix,
    _In_ USHORT PrefixCch
    )
{
    UNICODE_STRING prefixStr;
    UNICODE_STRING testPrefix;

    if (PrefixCch == 0) {
        return FALSE;
    }

    prefixStr.Buffer = (PWCH)Prefix;
    prefixStr.Length = PrefixCch * sizeof(WCHAR);
    prefixStr.MaximumLength = prefixStr.Length;

    if (TestPath->Length < prefixStr.Length) {
        return FALSE;
    }

    testPrefix.Buffer = TestPath->Buffer;
    testPrefix.Length = prefixStr.Length;
    testPrefix.MaximumLength = prefixStr.Length;

    return (RtlCompareUnicodeString(&testPrefix, &prefixStr, TRUE) == 0);
}

// ============================================================================
// INITIALIZATION / SHUTDOWN
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeInitializeSelfProtection(
    VOID
    )
{
    PAGED_CODE();

    if (InterlockedCompareExchange(&g_SelfProtectInitialized, 0, 0) != 0) {
        return STATUS_SUCCESS;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Initializing self-protection subsystem\n");

    //
    // Zero all static arrays and stats
    //
    RtlZeroMemory(g_ProtectedPaths, sizeof(g_ProtectedPaths));
    RtlZeroMemory(g_ProtectedRegKeys, sizeof(g_ProtectedRegKeys));
    RtlZeroMemory(&g_SelfProtectStats, sizeof(g_SelfProtectStats));

    //
    // Initialize process list
    //
    InitializeListHead(&g_ProtectedProcessList);
    g_ProtectedProcessCount = 0;

    //
    // Initialize spin locks (EX_SPIN_LOCK = 0 initial state)
    //
    g_ProtectedProcessLock = 0;
    g_ProtectedPathLock = 0;
    g_ProtectedRegKeyLock = 0;
    g_SelfProtectStatsLock = 0;

    //
    // Initialize lifecycle
    //
    InterlockedExchange(&g_SelfProtectShuttingDown, 0);
    InterlockedExchange(&g_SelfProtectActiveOps, 0);
    KeInitializeEvent(&g_SelfProtectDrainEvent, NotificationEvent, FALSE);

    //
    // Mark initialized — publish with full barrier
    //
    InterlockedExchange(&g_SelfProtectInitialized, 1);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Self-protection initialized\n");

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeShutdownSelfProtection(
    VOID
    )
{
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;
    PSHADOWSTRIKE_PROTECTED_PROCESS_ENTRY processEntry;
    KIRQL oldIrql;
    LARGE_INTEGER timeout;

    PAGED_CODE();

    if (InterlockedCompareExchange(&g_SelfProtectInitialized, 0, 0) == 0) {
        return;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Shutting down self-protection\n");

    //
    // Phase 1: Signal shutdown — no new operations will start
    //
    InterlockedExchange(&g_SelfProtectShuttingDown, 1);

    //
    // Phase 2: Wait for in-flight operations to drain
    //
    if (ReadNoFence(&g_SelfProtectActiveOps) > 0) {
        timeout.QuadPart = -50000000LL;  // 5 seconds
        KeWaitForSingleObject(
            &g_SelfProtectDrainEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout
        );
    }

    //
    // Phase 3: Free all protected process entries
    // At this point no callback is accessing our data.
    //
    oldIrql = ExAcquireSpinLockExclusive(&g_ProtectedProcessLock);

    for (entry = g_ProtectedProcessList.Flink;
         entry != &g_ProtectedProcessList;
         entry = nextEntry) {

        nextEntry = entry->Flink;

        processEntry = CONTAINING_RECORD(
            entry,
            SHADOWSTRIKE_PROTECTED_PROCESS_ENTRY,
            ListEntry
        );

        RemoveEntryList(entry);

        if (processEntry->Process != NULL) {
            ObDereferenceObject(processEntry->Process);
            processEntry->Process = NULL;
        }

        ShadowStrikeFreePoolWithTag(processEntry, SSSP_POOL_TAG_PROCESS);
    }

    g_ProtectedProcessCount = 0;

    ExReleaseSpinLockExclusive(&g_ProtectedProcessLock, oldIrql);

    //
    // Phase 4: Clear paths and registry keys under their locks
    //
    oldIrql = ExAcquireSpinLockExclusive(&g_ProtectedPathLock);
    RtlZeroMemory(g_ProtectedPaths, sizeof(g_ProtectedPaths));
    ExReleaseSpinLockExclusive(&g_ProtectedPathLock, oldIrql);

    oldIrql = ExAcquireSpinLockExclusive(&g_ProtectedRegKeyLock);
    RtlZeroMemory(g_ProtectedRegKeys, sizeof(g_ProtectedRegKeys));
    ExReleaseSpinLockExclusive(&g_ProtectedRegKeyLock, oldIrql);

    //
    // Phase 5: Mark uninitialized
    //
    InterlockedExchange(&g_SelfProtectInitialized, 0);

    //
    // Log final stats (safe — no concurrent access after drain)
    //
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Self-protection stats: HandleStrips=%lld, TermBlocks=%lld, "
               "FileBlocks=%lld, RegBlocks=%lld\n",
               g_SelfProtectStats.HandleStrips,
               g_SelfProtectStats.ProcessTerminateBlocks,
               g_SelfProtectStats.FileWriteBlocks + g_SelfProtectStats.FileDeleteBlocks,
               g_SelfProtectStats.RegistryBlocks);
}

// ============================================================================
// PROTECTED PROCESS MANAGEMENT
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeProtectProcess(
    _In_ HANDLE ProcessId,
    _In_ ULONG Flags,
    _In_opt_ PCWSTR ImagePath
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PSHADOWSTRIKE_PROTECTED_PROCESS_ENTRY newEntry = NULL;
    PEPROCESS process = NULL;
    KIRQL oldIrql;
    BOOLEAN duplicate = FALSE;
    SIZE_T copyLen = 0;
    LARGE_INTEGER createTime;

    PAGED_CODE();

    if (ProcessId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ReadNoFence(&g_SelfProtectInitialized)) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (ReadNoFence(&g_ProtectedProcessCount) >= SHADOWSTRIKE_MAX_PROTECTED_PROCESSES) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Max protected processes reached\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Get process object reference
    //
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Failed to lookup process %p: 0x%08X\n",
                   ProcessId, status);
        return status;
    }

    //
    // Capture create time for PID-reuse protection
    //
    createTime.QuadPart = PsGetProcessCreateTimeQuadPart(process);

    //
    // Safely measure ImagePath if provided
    //
    if (ImagePath != NULL) {
        status = SspSafeStringLength(ImagePath, 260, &copyLen);
        if (!NT_SUCCESS(status)) {
            copyLen = 0;
        }
        if (copyLen > 259) {
            copyLen = 259;
        }
    }

    //
    // Allocate entry (NonPagedPoolNx — accessed from DISPATCH_LEVEL callbacks)
    //
    newEntry = (PSHADOWSTRIKE_PROTECTED_PROCESS_ENTRY)ShadowStrikeAllocatePoolWithTag(
        NonPagedPool,
        sizeof(SHADOWSTRIKE_PROTECTED_PROCESS_ENTRY),
        SSSP_POOL_TAG_PROCESS
    );

    if (newEntry == NULL) {
        ObDereferenceObject(process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize entry (allocation is zeroed by ShadowStrikeAllocatePoolWithTag)
    //
    newEntry->ProcessId = ProcessId;
    newEntry->Process = process;
    newEntry->CreateTime = createTime;
    newEntry->Flags = Flags;
    KeQuerySystemTime(&newEntry->RegistrationTime);

    if (ImagePath != NULL && copyLen > 0) {
        RtlCopyMemory(newEntry->ImagePath, ImagePath, copyLen * sizeof(WCHAR));
        newEntry->ImagePath[copyLen] = L'\0';
    }

    //
    // Insert under exclusive spin lock — check for duplicates
    //
    oldIrql = ExAcquireSpinLockExclusive(&g_ProtectedProcessLock);

    {
        PLIST_ENTRY listEntry;

        for (listEntry = g_ProtectedProcessList.Flink;
             listEntry != &g_ProtectedProcessList;
             listEntry = listEntry->Flink) {

            PSHADOWSTRIKE_PROTECTED_PROCESS_ENTRY existing = CONTAINING_RECORD(
                listEntry,
                SHADOWSTRIKE_PROTECTED_PROCESS_ENTRY,
                ListEntry
            );

            if (existing->ProcessId == ProcessId &&
                existing->CreateTime.QuadPart == createTime.QuadPart) {
                duplicate = TRUE;
                break;
            }
        }

        if (!duplicate) {
            InsertTailList(&g_ProtectedProcessList, &newEntry->ListEntry);
            g_ProtectedProcessCount++;
        }
    }

    ExReleaseSpinLockExclusive(&g_ProtectedProcessLock, oldIrql);

    if (duplicate) {
        ObDereferenceObject(process);
        ShadowStrikeFreePoolWithTag(newEntry, SSSP_POOL_TAG_PROCESS);
        return STATUS_OBJECT_NAME_COLLISION;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Protected process registered: PID=%p, Flags=0x%X\n",
               ProcessId, Flags);

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeUnprotectProcess(
    _In_ HANDLE ProcessId
    )
{
    PSHADOWSTRIKE_PROTECTED_PROCESS_ENTRY found = NULL;
    KIRQL oldIrql;

    PAGED_CODE();

    if (!ReadNoFence(&g_SelfProtectInitialized) || ProcessId == NULL) {
        return;
    }

    oldIrql = ExAcquireSpinLockExclusive(&g_ProtectedProcessLock);

    {
        PLIST_ENTRY listEntry;

        for (listEntry = g_ProtectedProcessList.Flink;
             listEntry != &g_ProtectedProcessList;
             listEntry = listEntry->Flink) {

            PSHADOWSTRIKE_PROTECTED_PROCESS_ENTRY processEntry = CONTAINING_RECORD(
                listEntry,
                SHADOWSTRIKE_PROTECTED_PROCESS_ENTRY,
                ListEntry
            );

            if (processEntry->ProcessId == ProcessId) {
                RemoveEntryList(listEntry);
                g_ProtectedProcessCount--;
                found = processEntry;
                break;
            }
        }
    }

    ExReleaseSpinLockExclusive(&g_ProtectedProcessLock, oldIrql);

    //
    // Dereference and free OUTSIDE the spin lock
    //
    if (found != NULL) {
        if (found->Process != NULL) {
            ObDereferenceObject(found->Process);
        }
        ShadowStrikeFreePoolWithTag(found, SSSP_POOL_TAG_PROCESS);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike] Process unprotected: PID=%p\n", ProcessId);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsProcessProtected(
    _In_ HANDLE ProcessId,
    _Out_opt_ PULONG OutFlags
    )
{
    BOOLEAN isProtected = FALSE;
    ULONG flags = 0;
    KIRQL oldIrql;

    if (!ReadNoFence(&g_SelfProtectInitialized) || ProcessId == NULL) {
        if (OutFlags) *OutFlags = 0;
        return FALSE;
    }

    oldIrql = ExAcquireSpinLockShared(&g_ProtectedProcessLock);

    {
        PLIST_ENTRY listEntry;

        for (listEntry = g_ProtectedProcessList.Flink;
             listEntry != &g_ProtectedProcessList;
             listEntry = listEntry->Flink) {

            PSHADOWSTRIKE_PROTECTED_PROCESS_ENTRY processEntry = CONTAINING_RECORD(
                listEntry,
                SHADOWSTRIKE_PROTECTED_PROCESS_ENTRY,
                ListEntry
            );

            if (processEntry->ProcessId == ProcessId) {
                isProtected = TRUE;
                flags = processEntry->Flags;
                break;
            }
        }
    }

    ExReleaseSpinLockShared(&g_ProtectedProcessLock, oldIrql);

    if (OutFlags) *OutFlags = flags;
    return isProtected;
}

// ============================================================================
// PROTECTED PATH MANAGEMENT
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeAddProtectedPath(
    _In_ PCWSTR Path,
    _In_ ULONG Flags
    )
{
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    SIZE_T pathLen = 0;
    KIRQL oldIrql;
    LONG i;

    PAGED_CODE();

    if (Path == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ReadNoFence(&g_SelfProtectInitialized)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Safe string length measurement
    //
    status = SspSafeStringLength(Path, SHADOWSTRIKE_MAX_PROTECTED_PATH_LENGTH, &pathLen);
    if (!NT_SUCCESS(status) || pathLen == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    status = STATUS_INSUFFICIENT_RESOURCES;

    oldIrql = ExAcquireSpinLockExclusive(&g_ProtectedPathLock);

    for (i = 0; i < SHADOWSTRIKE_MAX_PROTECTED_PATHS; i++) {
        if (!g_ProtectedPaths[i].InUse) {
            g_ProtectedPaths[i].PathLength = (USHORT)pathLen;
            g_ProtectedPaths[i].Flags = Flags;
            RtlCopyMemory(g_ProtectedPaths[i].Path, Path, pathLen * sizeof(WCHAR));
            g_ProtectedPaths[i].Path[pathLen] = L'\0';
            //
            // Set InUse LAST to ensure all fields are visible before
            // a concurrent reader sees InUse=TRUE.
            //
            g_ProtectedPaths[i].InUse = TRUE;
            status = STATUS_SUCCESS;
            break;
        }
    }

    ExReleaseSpinLockExclusive(&g_ProtectedPathLock, oldIrql);

    if (NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike] Protected path added: %ws\n", Path);
    }

    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeRemoveProtectedPath(
    _In_ PCWSTR Path
    )
{
    NTSTATUS status = STATUS_NOT_FOUND;
    SIZE_T pathLen = 0;
    KIRQL oldIrql;
    LONG i;

    PAGED_CODE();

    if (Path == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ReadNoFence(&g_SelfProtectInitialized)) {
        return STATUS_DEVICE_NOT_READY;
    }

    status = SspSafeStringLength(Path, SHADOWSTRIKE_MAX_PROTECTED_PATH_LENGTH, &pathLen);
    if (!NT_SUCCESS(status) || pathLen == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    status = STATUS_NOT_FOUND;

    oldIrql = ExAcquireSpinLockExclusive(&g_ProtectedPathLock);

    for (i = 0; i < SHADOWSTRIKE_MAX_PROTECTED_PATHS; i++) {
        if (g_ProtectedPaths[i].InUse &&
            g_ProtectedPaths[i].PathLength == (USHORT)pathLen) {

            UNICODE_STRING stored;
            UNICODE_STRING input;

            stored.Buffer = g_ProtectedPaths[i].Path;
            stored.Length = (USHORT)(pathLen * sizeof(WCHAR));
            stored.MaximumLength = stored.Length;

            input.Buffer = (PWCH)Path;
            input.Length = stored.Length;
            input.MaximumLength = stored.Length;

            if (RtlCompareUnicodeString(&stored, &input, TRUE) == 0) {
                g_ProtectedPaths[i].InUse = FALSE;
                RtlZeroMemory(g_ProtectedPaths[i].Path,
                              sizeof(g_ProtectedPaths[i].Path));
                g_ProtectedPaths[i].PathLength = 0;
                g_ProtectedPaths[i].Flags = 0;
                status = STATUS_SUCCESS;
                break;
            }
        }
    }

    ExReleaseSpinLockExclusive(&g_ProtectedPathLock, oldIrql);

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsPathProtected(
    _In_ PCUNICODE_STRING Path
    )
{
    BOOLEAN isProtected = FALSE;
    KIRQL oldIrql;
    LONG i;

    if (!ReadNoFence(&g_SelfProtectInitialized) ||
        Path == NULL || Path->Buffer == NULL || Path->Length == 0) {
        return FALSE;
    }

    oldIrql = ExAcquireSpinLockShared(&g_ProtectedPathLock);

    for (i = 0; i < SHADOWSTRIKE_MAX_PROTECTED_PATHS; i++) {
        if (g_ProtectedPaths[i].InUse) {
            if (SspPrefixMatch(Path,
                               g_ProtectedPaths[i].Path,
                               g_ProtectedPaths[i].PathLength)) {
                isProtected = TRUE;
                break;
            }
        }
    }

    ExReleaseSpinLockShared(&g_ProtectedPathLock, oldIrql);

    return isProtected;
}

// ============================================================================
// PROTECTED REGISTRY KEY MANAGEMENT
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeAddProtectedRegistryKey(
    _In_ PCWSTR KeyPath,
    _In_ ULONG Flags
    )
{
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    SIZE_T pathLen = 0;
    KIRQL oldIrql;
    LONG i;

    PAGED_CODE();

    if (KeyPath == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ReadNoFence(&g_SelfProtectInitialized)) {
        return STATUS_DEVICE_NOT_READY;
    }

    status = SspSafeStringLength(KeyPath, SHADOWSTRIKE_MAX_PROTECTED_PATH_LENGTH, &pathLen);
    if (!NT_SUCCESS(status) || pathLen == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    status = STATUS_INSUFFICIENT_RESOURCES;

    oldIrql = ExAcquireSpinLockExclusive(&g_ProtectedRegKeyLock);

    for (i = 0; i < SHADOWSTRIKE_MAX_PROTECTED_REGKEYS; i++) {
        if (!g_ProtectedRegKeys[i].InUse) {
            g_ProtectedRegKeys[i].KeyPathLength = (USHORT)pathLen;
            g_ProtectedRegKeys[i].Flags = Flags;
            RtlCopyMemory(g_ProtectedRegKeys[i].KeyPath, KeyPath, pathLen * sizeof(WCHAR));
            g_ProtectedRegKeys[i].KeyPath[pathLen] = L'\0';
            g_ProtectedRegKeys[i].InUse = TRUE;
            status = STATUS_SUCCESS;
            break;
        }
    }

    ExReleaseSpinLockExclusive(&g_ProtectedRegKeyLock, oldIrql);

    if (NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike] Protected registry key added: %ws\n", KeyPath);
    }

    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeRemoveProtectedRegistryKey(
    _In_ PCWSTR KeyPath
    )
{
    NTSTATUS status = STATUS_NOT_FOUND;
    SIZE_T pathLen = 0;
    KIRQL oldIrql;
    LONG i;

    PAGED_CODE();

    if (KeyPath == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ReadNoFence(&g_SelfProtectInitialized)) {
        return STATUS_DEVICE_NOT_READY;
    }

    status = SspSafeStringLength(KeyPath, SHADOWSTRIKE_MAX_PROTECTED_PATH_LENGTH, &pathLen);
    if (!NT_SUCCESS(status) || pathLen == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    status = STATUS_NOT_FOUND;

    oldIrql = ExAcquireSpinLockExclusive(&g_ProtectedRegKeyLock);

    for (i = 0; i < SHADOWSTRIKE_MAX_PROTECTED_REGKEYS; i++) {
        if (g_ProtectedRegKeys[i].InUse &&
            g_ProtectedRegKeys[i].KeyPathLength == (USHORT)pathLen) {

            UNICODE_STRING stored;
            UNICODE_STRING input;

            stored.Buffer = g_ProtectedRegKeys[i].KeyPath;
            stored.Length = (USHORT)(pathLen * sizeof(WCHAR));
            stored.MaximumLength = stored.Length;

            input.Buffer = (PWCH)KeyPath;
            input.Length = stored.Length;
            input.MaximumLength = stored.Length;

            if (RtlCompareUnicodeString(&stored, &input, TRUE) == 0) {
                g_ProtectedRegKeys[i].InUse = FALSE;
                RtlZeroMemory(g_ProtectedRegKeys[i].KeyPath,
                              sizeof(g_ProtectedRegKeys[i].KeyPath));
                g_ProtectedRegKeys[i].KeyPathLength = 0;
                g_ProtectedRegKeys[i].Flags = 0;
                status = STATUS_SUCCESS;
                break;
            }
        }
    }

    ExReleaseSpinLockExclusive(&g_ProtectedRegKeyLock, oldIrql);

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsRegistryKeyProtected(
    _In_ PCUNICODE_STRING KeyPath
    )
{
    BOOLEAN isProtected = FALSE;
    KIRQL oldIrql;
    LONG i;

    if (!ReadNoFence(&g_SelfProtectInitialized) ||
        KeyPath == NULL || KeyPath->Buffer == NULL || KeyPath->Length == 0) {
        return FALSE;
    }

    oldIrql = ExAcquireSpinLockShared(&g_ProtectedRegKeyLock);

    for (i = 0; i < SHADOWSTRIKE_MAX_PROTECTED_REGKEYS; i++) {
        if (g_ProtectedRegKeys[i].InUse) {
            if (SspPrefixMatch(KeyPath,
                               g_ProtectedRegKeys[i].KeyPath,
                               g_ProtectedRegKeys[i].KeyPathLength)) {
                isProtected = TRUE;
                break;
            }
        }
    }

    ExReleaseSpinLockShared(&g_ProtectedRegKeyLock, oldIrql);

    return isProtected;
}

// ============================================================================
// OBJECT CALLBACK - HANDLE PROTECTION
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
OB_PREOP_CALLBACK_STATUS
ShadowStrikeObjectPreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    HANDLE targetProcessId = NULL;
    HANDLE callerProcessId = NULL;
    ULONG targetFlags = 0;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation == NULL || OperationInformation->Object == NULL) {
        return OB_PREOP_SUCCESS;
    }

    if (!ReadNoFence(&g_SelfProtectInitialized) ||
        ReadNoFence(&g_SelfProtectShuttingDown)) {
        return OB_PREOP_SUCCESS;
    }

    if (!g_DriverData.Config.SelfProtectionEnabled) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Skip kernel-mode callers (trusted)
    //
    if (OperationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Enter active operation (drain-safe)
    //
    if (!SspEnterOperation()) {
        return OB_PREOP_SUCCESS;
    }

    callerProcessId = PsGetCurrentProcessId();

    //
    // Handle process objects
    //
    if (OperationInformation->ObjectType == *PsProcessType) {
        PEPROCESS targetProcess = (PEPROCESS)OperationInformation->Object;
        targetProcessId = PsGetProcessId(targetProcess);

        if (callerProcessId == targetProcessId) {
            goto Exit;
        }

        if (!ShadowStrikeIsProcessProtected(targetProcessId, &targetFlags)) {
            goto Exit;
        }

        //
        // Allow trusted (protected) callers
        //
        if (ShadowStrikeIsProcessProtected(callerProcessId, NULL)) {
            goto Exit;
        }

        //
        // Strip dangerous access rights
        //
        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
            SspStripProcessAccess(
                &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess,
                targetFlags
            );
        } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            SspStripProcessAccess(
                &OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess,
                targetFlags
            );
        }

    //
    // Handle thread objects
    //
    } else if (OperationInformation->ObjectType == *PsThreadType) {
        PETHREAD targetThread = (PETHREAD)OperationInformation->Object;
        PEPROCESS ownerProcess = IoThreadToProcess(targetThread);

        if (ownerProcess == NULL) {
            goto Exit;
        }

        targetProcessId = PsGetProcessId(ownerProcess);

        if (callerProcessId == targetProcessId) {
            goto Exit;
        }

        if (!ShadowStrikeIsProcessProtected(targetProcessId, &targetFlags)) {
            goto Exit;
        }

        if (ShadowStrikeIsProcessProtected(callerProcessId, NULL)) {
            goto Exit;
        }

        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
            SspStripThreadAccess(
                &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess
            );
        } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            SspStripThreadAccess(
                &OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess
            );
        }
    }

Exit:
    SspLeaveOperation();
    return OB_PREOP_SUCCESS;
}

// ============================================================================
// FILE ACCESS PROTECTION
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeShouldBlockFileAccess(
    _In_ PCUNICODE_STRING FilePath,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ HANDLE RequestorPid,
    _In_ BOOLEAN IsDelete
    )
{
    if (!ReadNoFence(&g_SelfProtectInitialized) ||
        ReadNoFence(&g_SelfProtectShuttingDown)) {
        return FALSE;
    }

    if (!g_DriverData.Config.SelfProtectionEnabled) {
        return FALSE;
    }

    if (FilePath == NULL || FilePath->Buffer == NULL || FilePath->Length == 0) {
        return FALSE;
    }

    if (!SspEnterOperation()) {
        return FALSE;
    }

    //
    // Allow protected processes to modify their own files
    //
    if (ShadowStrikeIsProcessProtected(RequestorPid, NULL)) {
        SspLeaveOperation();
        return FALSE;
    }

    if (!ShadowStrikeIsPathProtected(FilePath)) {
        SspLeaveOperation();
        return FALSE;
    }

    if (IsDelete) {
        InterlockedIncrement64(&g_SelfProtectStats.FileDeleteBlocks);
        SspLeaveOperation();

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] BLOCKED delete of protected file by PID %p: %wZ\n",
                   RequestorPid, FilePath);
        return TRUE;
    }

    if (DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE | WRITE_DAC | WRITE_OWNER)) {
        InterlockedIncrement64(&g_SelfProtectStats.FileWriteBlocks);
        SspLeaveOperation();

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] BLOCKED write to protected file by PID %p: %wZ\n",
                   RequestorPid, FilePath);
        return TRUE;
    }

    SspLeaveOperation();
    return FALSE;
}

// ============================================================================
// REGISTRY ACCESS PROTECTION
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeShouldBlockRegistryAccess(
    _In_ PCUNICODE_STRING KeyPath,
    _In_ REG_NOTIFY_CLASS Operation,
    _In_ HANDLE RequestorPid
    )
{
    if (!ReadNoFence(&g_SelfProtectInitialized) ||
        ReadNoFence(&g_SelfProtectShuttingDown)) {
        return FALSE;
    }

    if (!g_DriverData.Config.SelfProtectionEnabled) {
        return FALSE;
    }

    if (KeyPath == NULL || KeyPath->Buffer == NULL || KeyPath->Length == 0) {
        return FALSE;
    }

    if (!SspEnterOperation()) {
        return FALSE;
    }

    if (ShadowStrikeIsProcessProtected(RequestorPid, NULL)) {
        SspLeaveOperation();
        return FALSE;
    }

    if (!ShadowStrikeIsRegistryKeyProtected(KeyPath)) {
        SspLeaveOperation();
        return FALSE;
    }

    switch (Operation) {
        case RegNtPreDeleteKey:
        case RegNtPreSetValueKey:
        case RegNtPreDeleteValueKey:
        case RegNtPreRenameKey:
        case RegNtPreSetKeySecurity:
            InterlockedIncrement64(&g_SelfProtectStats.RegistryBlocks);
            SspLeaveOperation();

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] BLOCKED registry change by PID %p: %wZ (op=%d)\n",
                       RequestorPid, KeyPath, Operation);
            return TRUE;

        default:
            break;
    }

    SspLeaveOperation();
    return FALSE;
}

// ============================================================================
// STATISTICS
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeGetSelfProtectStats(
    _Out_ PSHADOWSTRIKE_SELFPROTECT_STATS Stats
    )
{
    KIRQL oldIrql;

    if (Stats == NULL) {
        return;
    }

    RtlZeroMemory(Stats, sizeof(*Stats));

    if (!ReadNoFence(&g_SelfProtectInitialized)) {
        return;
    }

    //
    // Snapshot all stats atomically under spin lock to prevent torn reads.
    //
    oldIrql = ExAcquireSpinLockShared(&g_SelfProtectStatsLock);

    Stats->HandleStrips = g_SelfProtectStats.HandleStrips;
    Stats->ProcessTerminateBlocks = g_SelfProtectStats.ProcessTerminateBlocks;
    Stats->VMWriteBlocks = g_SelfProtectStats.VMWriteBlocks;
    Stats->ThreadInjectBlocks = g_SelfProtectStats.ThreadInjectBlocks;
    Stats->FileWriteBlocks = g_SelfProtectStats.FileWriteBlocks;
    Stats->FileDeleteBlocks = g_SelfProtectStats.FileDeleteBlocks;
    Stats->RegistryBlocks = g_SelfProtectStats.RegistryBlocks;

    ExReleaseSpinLockShared(&g_SelfProtectStatsLock, oldIrql);
}
