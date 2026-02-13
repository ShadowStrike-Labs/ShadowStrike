/*++
    ShadowStrike Next-Generation Antivirus
    Module: AmsiBypassDetector.c - Kernel-side AMSI bypass detection

    This module detects AMSI bypass attempts by:
    1. Recording amsi.dll base address per-process via ImageNotify
    2. Loading a clean amsi.dll baseline from System32 at init
    3. Comparing critical function prologues (AmsiScanBuffer, etc.)
       against the clean baseline on demand
    4. Monitoring memory protection changes on amsi.dll .text section
    5. Detecting known patch patterns (ret, mov eax E_INVALIDARG, nop sled)

    Design follows the same pattern as NtdllIntegrity module.

    Copyright (c) ShadowStrike Team
--*/

#include "AmsiBypassDetector.h"
#include "../../Core/Globals.h"
#include "../../Shared/BehaviorTypes.h"
#include <ntstrsafe.h>

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

//
// Known AMSI function names and their common patch signatures
//
typedef struct _ABD_CRITICAL_FUNCTION {
    CHAR Name[ABD_FUNCTION_NAME_MAX];
    ULONG RvaOffset;                    // Resolved at runtime from export table
    BOOLEAN Resolved;
} ABD_CRITICAL_FUNCTION, *PABD_CRITICAL_FUNCTION;

//
// Patch signatures that indicate AMSI bypass
//
// Pattern 1: "mov eax, 0x80070057; ret" (E_INVALIDARG) — most common AmsiScanBuffer patch
static const UCHAR g_PatchSig_MovEaxInvalidArg[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

// Pattern 2: "xor eax, eax; ret" — return S_OK (AMSI_RESULT_CLEAN)
static const UCHAR g_PatchSig_XorEaxRet[] = { 0x31, 0xC0, 0xC3 };
static const UCHAR g_PatchSig_XorEaxRet2[] = { 0x33, 0xC0, 0xC3 };

// Pattern 3: "ret" — immediate return
static const UCHAR g_PatchSig_Ret[] = { 0xC3 };

// Pattern 4: NOP sled (≥4 NOPs) — common in hook overwrite
static const UCHAR g_PatchSig_NopSled[] = { 0x90, 0x90, 0x90, 0x90 };

// Pattern 5: "mov eax, 0; ret" — return S_OK explicitly
static const UCHAR g_PatchSig_MovEaxZeroRet[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 };

typedef struct _ABD_PATCH_SIGNATURE {
    const UCHAR *Bytes;
    ULONG Length;
    ABD_BYPASS_TYPE BypassType;
} ABD_PATCH_SIGNATURE;

static const ABD_PATCH_SIGNATURE g_PatchSignatures[] = {
    { g_PatchSig_MovEaxInvalidArg,  sizeof(g_PatchSig_MovEaxInvalidArg),  AbdBypass_PatchAmsiScanBuffer },
    { g_PatchSig_XorEaxRet,         sizeof(g_PatchSig_XorEaxRet),         AbdBypass_PatchAmsiScanBuffer },
    { g_PatchSig_XorEaxRet2,        sizeof(g_PatchSig_XorEaxRet2),        AbdBypass_PatchAmsiScanBuffer },
    { g_PatchSig_Ret,               sizeof(g_PatchSig_Ret),               AbdBypass_PatchAmsiScanBuffer },
    { g_PatchSig_NopSled,           sizeof(g_PatchSig_NopSled),           AbdBypass_InlineHook },
    { g_PatchSig_MovEaxZeroRet,     sizeof(g_PatchSig_MovEaxZeroRet),     AbdBypass_PatchAmsiScanBuffer },
};

//
// amsi.dll filename for matching in ImageNotify
//
static const WCHAR g_AmsiDllName[] = L"amsi.dll";
static const USHORT g_AmsiDllNameLen = sizeof(g_AmsiDllName) - sizeof(WCHAR);

//
// Critical AMSI export names
//
static const CHAR* g_CriticalExportNames[] = {
    "AmsiScanBuffer",
    "AmsiScanString",
    "AmsiOpenSession",
    "AmsiInitialize",
    "AmsiCloseSession",
    "AmsiUninitialize",
};

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

/**
 * @brief Per-process amsi.dll tracking entry.
 */
typedef struct _ABD_PROCESS_ENTRY {
    LIST_ENTRY ListEntry;
    HANDLE ProcessId;
    PVOID AmsiBase;                     // Base address of amsi.dll
    SIZE_T AmsiSize;                    // Size of amsi.dll mapping
    LARGE_INTEGER LoadTime;             // When amsi.dll was loaded
    LARGE_INTEGER LastScanTime;         // Last integrity scan time
    BOOLEAN IsPatched;                  // Cached detection result
    ABD_BYPASS_TYPE LastDetectedBypass;
    volatile LONG ReferenceCount;
} ABD_PROCESS_ENTRY, *PABD_PROCESS_ENTRY;

/**
 * @brief Global detector state.
 */
typedef struct _ABD_DETECTOR_STATE {
    volatile LONG State;
    EX_RUNDOWN_REF RundownRef;

    //
    // Clean baseline — amsi.dll loaded from \SystemRoot\System32\amsi.dll
    //
    PVOID CleanAmsiCopy;                // Mapped clean copy of amsi.dll
    SIZE_T CleanAmsiSize;

    //
    // Critical function offsets in clean baseline
    //
    ABD_CRITICAL_FUNCTION CriticalFunctions[ABD_MAX_CRITICAL_FUNCTIONS];
    ULONG CriticalFunctionCount;

    //
    // Per-process tracking
    //
    LIST_ENTRY ProcessList;
    EX_PUSH_LOCK ProcessLock;
    volatile LONG ProcessCount;

    //
    // Lookaside for process entries
    //
    NPAGED_LOOKASIDE_LIST ProcessLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Statistics
    //
    ABD_STATISTICS Stats;

} ABD_DETECTOR_STATE, *PABD_DETECTOR_STATE;

static ABD_DETECTOR_STATE g_AbdState;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static NTSTATUS
AbdpLoadCleanBaseline(
    VOID
    );

static NTSTATUS
AbdpResolveExports(
    VOID
    );

static PABD_PROCESS_ENTRY
AbdpFindProcess(
    _In_ HANDLE ProcessId
    );

static PABD_PROCESS_ENTRY
AbdpTrackProcess(
    _In_ HANDLE ProcessId,
    _In_ PVOID AmsiBase,
    _In_ SIZE_T AmsiSize
    );

static VOID
AbdpRemoveProcess(
    _In_ HANDLE ProcessId
    );

static BOOLEAN
AbdpIsAmsiDll(
    _In_ PUNICODE_STRING ImageName
    );

static BOOLEAN
AbdpCheckPrologueForPatch(
    _In_ const UCHAR *CurrentPrologue,
    _In_ ULONG PrologueSize,
    _Out_ PABD_BYPASS_TYPE BypassType
    );

static NTSTATUS
AbdpReadProcessMemory(
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size
    );

static ULONG
AbdpFindExportRva(
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _In_ PCSTR ExportName
    );

static ULONG
AbdpRvaToFileOffset(
    _In_ PIMAGE_SECTION_HEADER Sections,
    _In_ ULONG NumberOfSections,
    _In_ ULONG Rva
    );

// ============================================================================
// LIFECYCLE
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
AbdInitialize(
    VOID
    )
{
    NTSTATUS status;
    LONG prevState;

    prevState = InterlockedCompareExchange(
        &g_AbdState.State,
        ABD_STATE_INITIALIZING,
        ABD_STATE_UNINITIALIZED
    );

    if (prevState != ABD_STATE_UNINITIALIZED) {
        return STATUS_ALREADY_INITIALIZED;
    }

    RtlZeroMemory(&g_AbdState.Stats, sizeof(ABD_STATISTICS));
    InitializeListHead(&g_AbdState.ProcessList);
    ExInitializePushLock(&g_AbdState.ProcessLock);
    g_AbdState.ProcessCount = 0;

    //
    // Initialize lookaside list
    //
    ExInitializeNPagedLookasideList(
        &g_AbdState.ProcessLookaside,
        NULL, NULL,
        POOL_NX_ALLOCATION,
        sizeof(ABD_PROCESS_ENTRY),
        ABD_POOL_TAG_PROC,
        0
    );
    g_AbdState.LookasideInitialized = TRUE;

    //
    // Initialize rundown protection
    //
    ExInitializeRundownProtection(&g_AbdState.RundownRef);

    //
    // Load clean amsi.dll baseline from System32
    //
    status = AbdpLoadCleanBaseline();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] AMSI Bypass Detector: Failed to load clean baseline: 0x%08X\n"
                   "[ShadowStrike] AMSI bypass detection will use signature-only mode.\n",
                   status);
        //
        // Non-fatal: we can still detect bypasses via patch signature matching
        // without baseline comparison (slightly lower fidelity)
        //
    }

    //
    // Resolve critical export RVAs from clean baseline
    //
    if (g_AbdState.CleanAmsiCopy != NULL) {
        AbdpResolveExports();
    }

    MemoryBarrier();
    InterlockedExchange(&g_AbdState.State, ABD_STATE_READY);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] AMSI Bypass Detector initialized "
               "(baseline=%s, functions=%u, signatures=%u)\n",
               g_AbdState.CleanAmsiCopy ? "loaded" : "unavailable",
               g_AbdState.CriticalFunctionCount,
               (ULONG)ARRAYSIZE(g_PatchSignatures));

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
AbdShutdown(
    VOID
    )
{
    LONG prevState;

    prevState = InterlockedCompareExchange(
        &g_AbdState.State,
        ABD_STATE_SHUTTING_DOWN,
        ABD_STATE_READY
    );

    if (prevState != ABD_STATE_READY) {
        return;
    }

    ExWaitForRundownProtectionRelease(&g_AbdState.RundownRef);

    //
    // Free all process entries
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_AbdState.ProcessLock);
    while (!IsListEmpty(&g_AbdState.ProcessList)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_AbdState.ProcessList);
        PABD_PROCESS_ENTRY proc = CONTAINING_RECORD(entry, ABD_PROCESS_ENTRY, ListEntry);
        ExFreeToNPagedLookasideList(&g_AbdState.ProcessLookaside, proc);
    }
    g_AbdState.ProcessCount = 0;
    ExReleasePushLockExclusive(&g_AbdState.ProcessLock);
    KeLeaveCriticalRegion();

    //
    // Free clean baseline
    //
    if (g_AbdState.CleanAmsiCopy != NULL) {
        ExFreePoolWithTag(g_AbdState.CleanAmsiCopy, ABD_POOL_TAG_BASELINE);
        g_AbdState.CleanAmsiCopy = NULL;
    }

    //
    // Destroy lookaside
    //
    if (g_AbdState.LookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_AbdState.ProcessLookaside);
        g_AbdState.LookasideInitialized = FALSE;
    }

    InterlockedExchange(&g_AbdState.State, ABD_STATE_UNINITIALIZED);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] AMSI Bypass Detector shutdown "
               "(monitored=%lld, bypasses=%lld)\n",
               g_AbdState.Stats.ProcessesMonitored,
               g_AbdState.Stats.BypassesDetected);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
AbdIsActive(
    VOID
    )
{
    return (ReadAcquire(&g_AbdState.State) == ABD_STATE_READY);
}

// ============================================================================
// IMAGE LOAD INTEGRATION
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
VOID
AbdNotifyImageLoad(
    _In_ HANDLE ProcessId,
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _In_ PUNICODE_STRING ImageName
    )
{
    if (!AbdIsActive()) {
        return;
    }

    if (!ExAcquireRundownProtection(&g_AbdState.RundownRef)) {
        return;
    }

    //
    // Check if this is amsi.dll
    //
    if (AbdpIsAmsiDll(ImageName)) {
        AbdpTrackProcess(ProcessId, ImageBase, ImageSize);
        InterlockedIncrement64(&g_AbdState.Stats.AmsiLoadsObserved);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                   "[ShadowStrike] amsi.dll loaded in PID %lu at %p (size=0x%IX)\n",
                   HandleToUlong(ProcessId), ImageBase, ImageSize);
    }

    ExReleaseRundownProtection(&g_AbdState.RundownRef);
}

// ============================================================================
// INTEGRITY SCAN
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
AbdScanProcess(
    _In_ HANDLE ProcessId,
    _Out_ PABD_DETECTION Detection
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PABD_PROCESS_ENTRY procEntry;
    UCHAR currentPrologue[ABD_PROLOGUE_SIZE];

    RtlZeroMemory(Detection, sizeof(ABD_DETECTION));
    Detection->BypassType = AbdBypass_None;

    if (!AbdIsActive()) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (!ExAcquireRundownProtection(&g_AbdState.RundownRef)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Find tracked process
    //
    procEntry = AbdpFindProcess(ProcessId);
    if (procEntry == NULL) {
        ExReleaseRundownProtection(&g_AbdState.RundownRef);
        return STATUS_NOT_FOUND;
    }

    InterlockedIncrement64(&g_AbdState.Stats.ScansPerformed);

    //
    // Scan each critical function
    //
    for (ULONG i = 0; i < g_AbdState.CriticalFunctionCount; i++) {
        ABD_CRITICAL_FUNCTION *func = &g_AbdState.CriticalFunctions[i];
        ABD_BYPASS_TYPE bypassType;
        PVOID functionAddress;

        if (!func->Resolved || func->RvaOffset == 0) {
            continue;
        }

        functionAddress = (PVOID)((ULONG_PTR)procEntry->AmsiBase + func->RvaOffset);

        //
        // Read current function prologue from process memory
        //
        status = AbdpReadProcessMemory(
            ProcessId,
            functionAddress,
            currentPrologue,
            ABD_PROLOGUE_SIZE
        );

        if (!NT_SUCCESS(status)) {
            continue;
        }

        //
        // Method 1: Check against known patch signatures
        //
        if (AbdpCheckPrologueForPatch(currentPrologue, ABD_PROLOGUE_SIZE, &bypassType)) {
            Detection->BypassType = bypassType;
            Detection->ProcessId = ProcessId;
            Detection->TargetAddress = functionAddress;
            RtlCopyMemory(Detection->CurrentBytes, currentPrologue, ABD_PROLOGUE_SIZE);
            KeQuerySystemTimePrecise(&Detection->DetectionTime);

            RtlStringCbCopyA(
                Detection->FunctionName,
                sizeof(Detection->FunctionName),
                func->Name
            );

            //
            // Copy original bytes from clean baseline
            //
            if (g_AbdState.CleanAmsiCopy != NULL &&
                func->RvaOffset + ABD_PROLOGUE_SIZE <= g_AbdState.CleanAmsiSize) {
                RtlCopyMemory(
                    Detection->OriginalBytes,
                    (PUCHAR)g_AbdState.CleanAmsiCopy + func->RvaOffset,
                    ABD_PROLOGUE_SIZE
                );
            }

            procEntry->IsPatched = TRUE;
            procEntry->LastDetectedBypass = bypassType;

            InterlockedIncrement64(&g_AbdState.Stats.BypassesDetected);
            InterlockedIncrement64(&g_AbdState.Stats.PatchDetections);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] AMSI BYPASS DETECTED in PID %lu: "
                       "%s patched (type=%d) at %p\n",
                       HandleToUlong(ProcessId),
                       func->Name,
                       (int)bypassType,
                       functionAddress);

            break;  // One detection per scan is sufficient
        }

        //
        // Method 2: Compare against clean baseline (if available)
        //
        if (g_AbdState.CleanAmsiCopy != NULL &&
            func->RvaOffset + ABD_PROLOGUE_SIZE <= g_AbdState.CleanAmsiSize) {

            const UCHAR *cleanPrologue =
                (const UCHAR *)g_AbdState.CleanAmsiCopy + func->RvaOffset;

            if (RtlCompareMemory(currentPrologue, cleanPrologue, ABD_PROLOGUE_SIZE)
                != ABD_PROLOGUE_SIZE) {
                //
                // Prologue differs from clean baseline — may be hooked
                //
                Detection->BypassType = AbdBypass_InlineHook;
                Detection->ProcessId = ProcessId;
                Detection->TargetAddress = functionAddress;
                RtlCopyMemory(Detection->CurrentBytes, currentPrologue, ABD_PROLOGUE_SIZE);
                RtlCopyMemory(Detection->OriginalBytes, cleanPrologue, ABD_PROLOGUE_SIZE);
                KeQuerySystemTimePrecise(&Detection->DetectionTime);

                RtlStringCbCopyA(
                    Detection->FunctionName,
                    sizeof(Detection->FunctionName),
                    func->Name
                );

                procEntry->IsPatched = TRUE;
                procEntry->LastDetectedBypass = AbdBypass_InlineHook;

                InterlockedIncrement64(&g_AbdState.Stats.BypassesDetected);
                InterlockedIncrement64(&g_AbdState.Stats.PatchDetections);

                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike] AMSI HOOK DETECTED in PID %lu: "
                           "%s modified at %p (baseline mismatch)\n",
                           HandleToUlong(ProcessId),
                           func->Name,
                           functionAddress);

                break;
            }
        }
    }

    KeQuerySystemTimePrecise(&procEntry->LastScanTime);
    ExReleaseRundownProtection(&g_AbdState.RundownRef);

    return STATUS_SUCCESS;
}

// ============================================================================
// MEMORY PROTECTION CHANGE DETECTION
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
AbdCheckProtectionChange(
    _In_ HANDLE ProcessId,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T RegionSize,
    _In_ ULONG OldProtection,
    _In_ ULONG NewProtection
    )
{
    PABD_PROCESS_ENTRY procEntry;
    ULONG_PTR regionStart;
    ULONG_PTR regionEnd;
    ULONG_PTR amsiStart;
    ULONG_PTR amsiEnd;

    if (!AbdIsActive()) {
        return FALSE;
    }

    if (!ExAcquireRundownProtection(&g_AbdState.RundownRef)) {
        return FALSE;
    }

    procEntry = AbdpFindProcess(ProcessId);
    if (procEntry == NULL) {
        ExReleaseRundownProtection(&g_AbdState.RundownRef);
        return FALSE;
    }

    //
    // Check if the protection change overlaps with amsi.dll memory range
    //
    regionStart = (ULONG_PTR)BaseAddress;
    regionEnd = regionStart + RegionSize;
    amsiStart = (ULONG_PTR)procEntry->AmsiBase;
    amsiEnd = amsiStart + procEntry->AmsiSize;

    if (regionStart < amsiEnd && regionEnd > amsiStart) {
        //
        // Protection change targets amsi.dll region.
        // Check if this makes the .text section writable (bypass indicator).
        //
        BOOLEAN wasWritable = (OldProtection & (PAGE_READWRITE | PAGE_WRITECOPY |
                                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        BOOLEAN isWritable = (NewProtection & (PAGE_READWRITE | PAGE_WRITECOPY |
                               PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

        if (!wasWritable && isWritable) {
            //
            // amsi.dll text section made writable — strong bypass indicator
            //
            InterlockedIncrement64(&g_AbdState.Stats.BypassesDetected);
            InterlockedIncrement64(&g_AbdState.Stats.ProtectionChangeDetections);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] AMSI BYPASS INDICATOR in PID %lu: "
                       "amsi.dll region at %p made writable (0x%X -> 0x%X)\n",
                       HandleToUlong(ProcessId), BaseAddress,
                       OldProtection, NewProtection);

            ExReleaseRundownProtection(&g_AbdState.RundownRef);
            return TRUE;
        }
    }

    ExReleaseRundownProtection(&g_AbdState.RundownRef);
    return FALSE;
}

// ============================================================================
// STATISTICS
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
AbdGetStatistics(
    _Out_ PABD_STATISTICS Stats
    )
{
    Stats->ProcessesMonitored     = ReadNoFence64((PLONG64)&g_AbdState.Stats.ProcessesMonitored);
    Stats->AmsiLoadsObserved      = ReadNoFence64((PLONG64)&g_AbdState.Stats.AmsiLoadsObserved);
    Stats->BypassesDetected       = ReadNoFence64((PLONG64)&g_AbdState.Stats.BypassesDetected);
    Stats->PatchDetections        = ReadNoFence64((PLONG64)&g_AbdState.Stats.PatchDetections);
    Stats->ProtectionChangeDetections = ReadNoFence64((PLONG64)&g_AbdState.Stats.ProtectionChangeDetections);
    Stats->EtwPatchDetections     = ReadNoFence64((PLONG64)&g_AbdState.Stats.EtwPatchDetections);
    Stats->ScansPerformed         = ReadNoFence64((PLONG64)&g_AbdState.Stats.ScansPerformed);
}

// ============================================================================
// PRIVATE — BASELINE LOADING
// ============================================================================

/**
 * @brief Load clean amsi.dll from \SystemRoot\System32\amsi.dll into kernel memory.
 */
static NTSTATUS
AbdpLoadCleanBaseline(
    VOID
    )
{
    NTSTATUS status;
    UNICODE_STRING amsiPath;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatus;
    HANDLE fileHandle = NULL;
    FILE_STANDARD_INFORMATION fileInfo;
    PVOID buffer = NULL;
    LARGE_INTEGER readOffset;

    RtlInitUnicodeString(&amsiPath, L"\\SystemRoot\\System32\\amsi.dll");

    InitializeObjectAttributes(
        &objAttr,
        &amsiPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    status = ZwOpenFile(
        &fileHandle,
        FILE_READ_DATA | SYNCHRONIZE,
        &objAttr,
        &ioStatus,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Get file size
    //
    status = ZwQueryInformationFile(
        fileHandle,
        &ioStatus,
        &fileInfo,
        sizeof(fileInfo),
        FileStandardInformation
    );

    if (!NT_SUCCESS(status)) {
        ZwClose(fileHandle);
        return status;
    }

    //
    // Sanity check size — amsi.dll should be < 1MB
    //
    if (fileInfo.EndOfFile.QuadPart == 0 ||
        fileInfo.EndOfFile.QuadPart > (1024 * 1024)) {
        ZwClose(fileHandle);
        return STATUS_FILE_TOO_LARGE;
    }

    //
    // Allocate and read
    //
    buffer = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        (SIZE_T)fileInfo.EndOfFile.QuadPart,
        ABD_POOL_TAG_BASELINE
    );

    if (buffer == NULL) {
        ZwClose(fileHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    readOffset.QuadPart = 0;
    status = ZwReadFile(
        fileHandle,
        NULL, NULL, NULL,
        &ioStatus,
        buffer,
        (ULONG)fileInfo.EndOfFile.QuadPart,
        &readOffset,
        NULL
    );

    ZwClose(fileHandle);

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buffer, ABD_POOL_TAG_BASELINE);
        return status;
    }

    //
    // Validate PE header
    //
    if (fileInfo.EndOfFile.QuadPart < 64) {
        ExFreePoolWithTag(buffer, ABD_POOL_TAG_BASELINE);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        ExFreePoolWithTag(buffer, ABD_POOL_TAG_BASELINE);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if ((ULONG)dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) >
        (ULONG)fileInfo.EndOfFile.QuadPart) {
        ExFreePoolWithTag(buffer, ABD_POOL_TAG_BASELINE);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(
        (PUCHAR)buffer + dosHeader->e_lfanew
    );

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        ExFreePoolWithTag(buffer, ABD_POOL_TAG_BASELINE);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    g_AbdState.CleanAmsiCopy = buffer;
    g_AbdState.CleanAmsiSize = (SIZE_T)fileInfo.EndOfFile.QuadPart;

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE — EXPORT RESOLUTION
// ============================================================================

/**
 * @brief Resolve critical function RVAs from clean baseline PE exports.
 */
static NTSTATUS
AbdpResolveExports(
    VOID
    )
{
    ULONG resolved = 0;

    if (g_AbdState.CleanAmsiCopy == NULL) {
        return STATUS_NOT_FOUND;
    }

    for (ULONG i = 0; i < ARRAYSIZE(g_CriticalExportNames); i++) {
        if (i >= ABD_MAX_CRITICAL_FUNCTIONS) {
            break;
        }

        ULONG rva = AbdpFindExportRva(
            g_AbdState.CleanAmsiCopy,
            g_AbdState.CleanAmsiSize,
            g_CriticalExportNames[i]
        );

        ABD_CRITICAL_FUNCTION *func = &g_AbdState.CriticalFunctions[resolved];

        RtlStringCbCopyA(func->Name, sizeof(func->Name), g_CriticalExportNames[i]);
        func->RvaOffset = rva;
        func->Resolved = (rva != 0);

        if (func->Resolved) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                       "[ShadowStrike] AMSI export resolved: %s -> RVA 0x%X\n",
                       g_CriticalExportNames[i], rva);
        }

        resolved++;
    }

    g_AbdState.CriticalFunctionCount = resolved;
    return STATUS_SUCCESS;
}

/**
 * @brief Find an export's RVA from a PE image in memory.
 */
static ULONG
AbdpFindExportRva(
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _In_ PCSTR ExportName
    )
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS64 ntHeaders;
    PIMAGE_EXPORT_DIRECTORY exportDir;
    ULONG exportDirRva;
    ULONG exportDirSize;
    PULONG addressOfFunctions;
    PULONG addressOfNames;
    PUSHORT addressOfNameOrdinals;
    ULONG i;

    if (ImageBase == NULL || ImageSize < sizeof(IMAGE_DOS_HEADER)) {
        return 0;
    }

    dosHeader = (PIMAGE_DOS_HEADER)ImageBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    if ((ULONG)dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > ImageSize) {
        return 0;
    }

    ntHeaders = (PIMAGE_NT_HEADERS64)((PUCHAR)ImageBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    if (ntHeaders->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) {
        return 0;
    }

    exportDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    exportDirSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    if (exportDirRva == 0 || exportDirSize == 0) {
        return 0;
    }

    //
    // For on-disk PE, we need to convert RVA to file offset.
    // Walk sections to find the one containing the export directory.
    //
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);
    ULONG numSections = ntHeaders->FileHeader.NumberOfSections;

    //
    // Helper: convert RVA to file offset
    //
    #define RVA_TO_OFFSET(rva) AbdpRvaToFileOffset(sections, numSections, (rva))

    ULONG exportDirOffset = RVA_TO_OFFSET(exportDirRva);
    if (exportDirOffset == 0 || exportDirOffset + sizeof(IMAGE_EXPORT_DIRECTORY) > ImageSize) {
        return 0;
    }

    exportDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ImageBase + exportDirOffset);

    if (exportDir->NumberOfNames == 0) {
        return 0;
    }

    ULONG namesOffset = RVA_TO_OFFSET(exportDir->AddressOfNames);
    ULONG ordinalsOffset = RVA_TO_OFFSET(exportDir->AddressOfNameOrdinals);
    ULONG functionsOffset = RVA_TO_OFFSET(exportDir->AddressOfFunctions);

    if (namesOffset == 0 || ordinalsOffset == 0 || functionsOffset == 0) {
        return 0;
    }

    if (namesOffset + exportDir->NumberOfNames * sizeof(ULONG) > ImageSize ||
        ordinalsOffset + exportDir->NumberOfNames * sizeof(USHORT) > ImageSize ||
        functionsOffset + exportDir->NumberOfFunctions * sizeof(ULONG) > ImageSize) {
        return 0;
    }

    addressOfNames = (PULONG)((PUCHAR)ImageBase + namesOffset);
    addressOfNameOrdinals = (PUSHORT)((PUCHAR)ImageBase + ordinalsOffset);
    addressOfFunctions = (PULONG)((PUCHAR)ImageBase + functionsOffset);

    for (i = 0; i < exportDir->NumberOfNames; i++) {
        ULONG nameOffset = RVA_TO_OFFSET(addressOfNames[i]);
        if (nameOffset == 0 || nameOffset >= ImageSize) {
            continue;
        }

        PCSTR currentName = (PCSTR)((PUCHAR)ImageBase + nameOffset);

        //
        // Bounds check the string
        //
        SIZE_T maxLen = ImageSize - nameOffset;
        SIZE_T nameLen = strnlen(currentName, maxLen);
        if (nameLen == maxLen) {
            continue;
        }

        if (strcmp(currentName, ExportName) == 0) {
            USHORT ordinal = addressOfNameOrdinals[i];
            if (ordinal < exportDir->NumberOfFunctions) {
                return addressOfFunctions[ordinal];
            }
        }
    }

    #undef RVA_TO_OFFSET

    return 0;
}

/**
 * @brief Convert RVA to file offset using section headers.
 */
static ULONG
AbdpRvaToFileOffset(
    _In_ PIMAGE_SECTION_HEADER Sections,
    _In_ ULONG NumberOfSections,
    _In_ ULONG Rva
    )
{
    for (ULONG i = 0; i < NumberOfSections; i++) {
        if (Rva >= Sections[i].VirtualAddress &&
            Rva < Sections[i].VirtualAddress + Sections[i].SizeOfRawData) {
            return Rva - Sections[i].VirtualAddress + Sections[i].PointerToRawData;
        }
    }
    return 0;
}

// ============================================================================
// PRIVATE — PROCESS TRACKING
// ============================================================================

static BOOLEAN
AbdpIsAmsiDll(
    _In_ PUNICODE_STRING ImageName
    )
{
    USHORT nameChars;
    USHORT matchChars;

    if (ImageName == NULL || ImageName->Buffer == NULL || ImageName->Length == 0) {
        return FALSE;
    }

    nameChars = ImageName->Length / sizeof(WCHAR);
    matchChars = g_AmsiDllNameLen / sizeof(WCHAR);

    //
    // Check if path ends with \amsi.dll (case-insensitive)
    //
    if (nameChars < matchChars + 1) {  // +1 for backslash
        return FALSE;
    }

    PCWSTR suffix = &ImageName->Buffer[nameChars - matchChars];
    if (_wcsnicmp(suffix, g_AmsiDllName, matchChars) != 0) {
        return FALSE;
    }

    //
    // Verify preceded by path separator
    //
    if (ImageName->Buffer[nameChars - matchChars - 1] != L'\\') {
        return FALSE;
    }

    return TRUE;
}

static PABD_PROCESS_ENTRY
AbdpFindProcess(
    _In_ HANDLE ProcessId
    )
{
    PABD_PROCESS_ENTRY entry = NULL;
    PLIST_ENTRY listEntry;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_AbdState.ProcessLock);

    for (listEntry = g_AbdState.ProcessList.Flink;
         listEntry != &g_AbdState.ProcessList;
         listEntry = listEntry->Flink) {

        PABD_PROCESS_ENTRY current = CONTAINING_RECORD(
            listEntry, ABD_PROCESS_ENTRY, ListEntry
        );

        if (current->ProcessId == ProcessId) {
            entry = current;
            break;
        }
    }

    ExReleasePushLockShared(&g_AbdState.ProcessLock);
    KeLeaveCriticalRegion();

    return entry;
}

static PABD_PROCESS_ENTRY
AbdpTrackProcess(
    _In_ HANDLE ProcessId,
    _In_ PVOID AmsiBase,
    _In_ SIZE_T AmsiSize
    )
{
    PABD_PROCESS_ENTRY entry;

    //
    // Check if already tracked
    //
    entry = AbdpFindProcess(ProcessId);
    if (entry != NULL) {
        //
        // Update base address (amsi.dll may be reloaded)
        //
        entry->AmsiBase = AmsiBase;
        entry->AmsiSize = AmsiSize;
        entry->IsPatched = FALSE;
        entry->LastDetectedBypass = AbdBypass_None;
        return entry;
    }

    //
    // Check capacity
    //
    if (InterlockedCompareExchange(&g_AbdState.ProcessCount, 0, 0)
        >= ABD_MAX_TRACKED_PROCESSES) {
        return NULL;
    }

    entry = (PABD_PROCESS_ENTRY)ExAllocateFromNPagedLookasideList(
        &g_AbdState.ProcessLookaside
    );

    if (entry == NULL) {
        return NULL;
    }

    RtlZeroMemory(entry, sizeof(ABD_PROCESS_ENTRY));
    entry->ProcessId = ProcessId;
    entry->AmsiBase = AmsiBase;
    entry->AmsiSize = AmsiSize;
    entry->ReferenceCount = 1;
    KeQuerySystemTimePrecise(&entry->LoadTime);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_AbdState.ProcessLock);
    InsertTailList(&g_AbdState.ProcessList, &entry->ListEntry);
    InterlockedIncrement(&g_AbdState.ProcessCount);
    ExReleasePushLockExclusive(&g_AbdState.ProcessLock);
    KeLeaveCriticalRegion();

    InterlockedIncrement64(&g_AbdState.Stats.ProcessesMonitored);

    return entry;
}

// ============================================================================
// PRIVATE — PATCH DETECTION
// ============================================================================

static BOOLEAN
AbdpCheckPrologueForPatch(
    _In_ const UCHAR *CurrentPrologue,
    _In_ ULONG PrologueSize,
    _Out_ PABD_BYPASS_TYPE BypassType
    )
{
    *BypassType = AbdBypass_None;

    for (ULONG i = 0; i < ARRAYSIZE(g_PatchSignatures); i++) {
        if (g_PatchSignatures[i].Length <= PrologueSize) {
            if (RtlCompareMemory(
                    CurrentPrologue,
                    g_PatchSignatures[i].Bytes,
                    g_PatchSignatures[i].Length
                ) == g_PatchSignatures[i].Length) {

                *BypassType = g_PatchSignatures[i].BypassType;
                return TRUE;
            }
        }
    }

    return FALSE;
}

// ============================================================================
// PRIVATE — PROCESS MEMORY READING
// ============================================================================

/**
 * @brief Read memory from a target process.
 *
 * Attaches to the target process via KeStackAttachProcess,
 * then performs a safe copy from the target address.
 */
static NTSTATUS
AbdpReadProcessMemory(
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size
    )
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    KAPC_STATE apcState;

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    KeStackAttachProcess(process, &apcState);

    __try {
        ProbeForRead(Address, Size, 1);
        RtlCopyMemory(Buffer, Address, Size);
        status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);

    return status;
}
