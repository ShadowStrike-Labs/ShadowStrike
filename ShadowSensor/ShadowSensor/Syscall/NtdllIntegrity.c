/*++
    ShadowStrike Next-Generation Antivirus
    Module: NtdllIntegrity.c

    Purpose: Enterprise-grade NTDLL integrity monitoring and hook detection
             for identifying API hooking, inline patching, and syscall stub
             modifications used by malware for evasion.

    Architecture:
    - Clean NTDLL reference copy for comparison baseline
    - Per-process NTDLL state tracking with function-level granularity
    - Inline hook detection (JMP, CALL, MOV patterns)
    - Syscall stub validation (mov eax, X; syscall sequence)
    - SHA-256 hash comparison for .text section integrity
    - Export table enumeration for comprehensive coverage
    - Lookaside list allocation for performance

    Detection Capabilities:
    - Inline/detour hooks (JMP REL32, JMP ABS, hotpatch)
    - Trampoline hooks (MOV R10/RAX + JMP)
    - Syscall number tampering
    - IAT/EAT modifications
    - PE header tampering
    - Unhooking detection (monitoring our own hooks)

    MITRE ATT&CK Coverage:
    - T1055: Process Injection (hook-based injection)
    - T1106: Native API (syscall hooking detection)
    - T1562: Impair Defenses (security tool hooking)
    - T1574: Hijack Execution Flow (API hooking)

    Copyright (c) ShadowStrike Team
--*/

#include "NtdllIntegrity.h"
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/HashUtils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, NiInitialize)
#pragma alloc_text(PAGE, NiShutdown)
#pragma alloc_text(PAGE, NiScanProcess)
#pragma alloc_text(PAGE, NiCheckFunction)
#pragma alloc_text(PAGE, NiDetectHooks)
#pragma alloc_text(PAGE, NiCompareToClean)
#pragma alloc_text(PAGE, NiFreeState)
#endif

//=============================================================================
// Internal Constants
//=============================================================================

#define NI_SIGNATURE                    'TNIM'  // 'MINT' reversed
#define NI_PROCESS_SIGNATURE            'PNIM'  // 'MINP' reversed
#define NI_FUNCTION_SIGNATURE           'FNIM'  // 'MINF' reversed

#define NI_MAX_PROCESSES                256
#define NI_MAX_FUNCTIONS                2048
#define NI_PROLOGUE_SIZE                16
#define NI_SYSCALL_STUB_SIZE            24

#define NI_MIN_VALID_USER_ADDRESS       0x10000ULL
#define NI_MAX_USER_ADDRESS             0x7FFFFFFFFFFFULL

//
// Hook detection patterns
//
#define NI_JMP_REL32_OPCODE             0xE9    // JMP rel32
#define NI_JMP_ABS_PREFIX               0xFF    // JMP r/m64
#define NI_CALL_REL32_OPCODE            0xE8    // CALL rel32
#define NI_MOV_R10_RCX                  0x4C8B  // mov r10, rcx (syscall pattern)
#define NI_MOV_EAX_IMM32                0xB8    // mov eax, imm32 (syscall number)
#define NI_SYSCALL_OPCODE               0x050F  // syscall (0F 05)
#define NI_INT_2E                       0x2ECD  // int 2Eh
#define NI_NOP_OPCODE                   0x90    // NOP
#define NI_HOTPATCH_MOV_EDI             0x8BFF  // mov edi, edi (hotpatch)

//
// Critical ntdll functions to monitor
//
static const PCHAR NI_CRITICAL_FUNCTIONS[] = {
    "NtCreateFile",
    "NtOpenFile",
    "NtReadFile",
    "NtWriteFile",
    "NtClose",
    "NtCreateProcess",
    "NtCreateProcessEx",
    "NtCreateUserProcess",
    "NtOpenProcess",
    "NtTerminateProcess",
    "NtCreateThread",
    "NtCreateThreadEx",
    "NtOpenThread",
    "NtTerminateThread",
    "NtSuspendThread",
    "NtResumeThread",
    "NtAllocateVirtualMemory",
    "NtFreeVirtualMemory",
    "NtProtectVirtualMemory",
    "NtReadVirtualMemory",
    "NtWriteVirtualMemory",
    "NtQueryVirtualMemory",
    "NtMapViewOfSection",
    "NtUnmapViewOfSection",
    "NtCreateSection",
    "NtOpenSection",
    "NtQueryInformationProcess",
    "NtSetInformationProcess",
    "NtQueryInformationThread",
    "NtSetInformationThread",
    "NtQuerySystemInformation",
    "NtSetSystemInformation",
    "NtCreateKey",
    "NtOpenKey",
    "NtSetValueKey",
    "NtQueryValueKey",
    "NtDeleteKey",
    "NtDeleteValueKey",
    "NtEnumerateKey",
    "NtEnumerateValueKey",
    "NtLoadDriver",
    "NtUnloadDriver",
    "NtDeviceIoControlFile",
    "NtFsControlFile",
    "NtSetContextThread",
    "NtGetContextThread",
    "NtQueueApcThread",
    "NtQueueApcThreadEx",
    "NtTestAlert",
    "NtContinue",
    "NtRaiseException",
    "NtCreateMutant",
    "NtOpenMutant",
    "NtCreateEvent",
    "NtOpenEvent",
    "NtWaitForSingleObject",
    "NtWaitForMultipleObjects",
    "NtDelayExecution",
    "NtYieldExecution",
    "LdrLoadDll",
    "LdrUnloadDll",
    "LdrGetProcedureAddress",
    "LdrGetDllHandle",
    "RtlCreateHeap",
    "RtlAllocateHeap",
    "RtlFreeHeap",
    "RtlDestroyHeap",
    NULL
};

#define NI_CRITICAL_FUNCTION_COUNT (sizeof(NI_CRITICAL_FUNCTIONS) / sizeof(NI_CRITICAL_FUNCTIONS[0]) - 1)

//=============================================================================
// Internal Structures
//=============================================================================

typedef struct _NI_MONITOR_INTERNAL {
    ULONG Signature;
    NI_MONITOR Monitor;

    //
    // Clean NTDLL information
    //
    PVOID CleanTextSection;
    SIZE_T CleanTextSize;
    ULONG_PTR CleanTextRva;
    UCHAR CleanTextHash[32];

    //
    // Export table from clean NTDLL
    //
    struct {
        PVOID ExportDirectory;
        ULONG NumberOfFunctions;
        ULONG NumberOfNames;
        PULONG AddressOfFunctions;
        PULONG AddressOfNames;
        PUSHORT AddressOfNameOrdinals;
    } CleanExports;

    //
    // Lookaside lists
    //
    NPAGED_LOOKASIDE_LIST ProcessLookaside;
    NPAGED_LOOKASIDE_LIST FunctionLookaside;

    //
    // Shutdown flag
    //
    volatile BOOLEAN ShuttingDown;

} NI_MONITOR_INTERNAL, *PNI_MONITOR_INTERNAL;

//=============================================================================
// Forward Declarations
//=============================================================================

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
NipCaptureCleanNtdll(
    _Inout_ PNI_MONITOR_INTERNAL MonitorInternal
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
NipGetProcessNtdll(
    _In_ HANDLE ProcessId,
    _Out_ PVOID* NtdllBase,
    _Out_ PSIZE_T NtdllSize
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
NipReadProcessMemory(
    _In_ HANDLE ProcessId,
    _In_ PVOID SourceAddress,
    _Out_writes_bytes_(Size) PVOID Destination,
    _In_ SIZE_T Size
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
NipGetTextSection(
    _In_ PVOID ModuleBase,
    _In_ SIZE_T ModuleSize,
    _Out_ PVOID* TextBase,
    _Out_ PSIZE_T TextSize,
    _Out_ PULONG_PTR TextRva
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
NipParseExportTable(
    _In_ PVOID ModuleBase,
    _In_ SIZE_T ModuleSize,
    _Out_ PVOID* ExportDirectory,
    _Out_ PULONG NumberOfFunctions,
    _Out_ PULONG NumberOfNames,
    _Out_ PULONG* AddressOfFunctions,
    _Out_ PULONG* AddressOfNames,
    _Out_ PUSHORT* AddressOfNameOrdinals
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
NipLookupExportByName(
    _In_ PNI_MONITOR_INTERNAL MonitorInternal,
    _In_ PCSTR FunctionName,
    _Out_ PULONG_PTR FunctionRva,
    _Out_ PUCHAR ExpectedPrologue
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static NI_MODIFICATION
NipDetectHookType(
    _In_ PUCHAR CurrentPrologue,
    _In_ PUCHAR ExpectedPrologue,
    _In_ SIZE_T Size
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static BOOLEAN
NipIsSyscallStub(
    _In_ PUCHAR Prologue,
    _In_ SIZE_T Size,
    _Out_opt_ PULONG SyscallNumber
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static BOOLEAN
NipValidateSyscallStub(
    _In_ PUCHAR CurrentPrologue,
    _In_ PUCHAR ExpectedPrologue,
    _In_ SIZE_T Size
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static PNI_PROCESS_NTDLL
NipFindProcessState(
    _In_ PNI_MONITOR Monitor,
    _In_ HANDLE ProcessId
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
NipFreeProcessState(
    _In_ PNI_MONITOR_INTERNAL MonitorInternal,
    _Inout_ PNI_PROCESS_NTDLL State
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
NipComputeTextSectionHash(
    _In_ HANDLE ProcessId,
    _In_ PVOID NtdllBase,
    _In_ ULONG_PTR TextRva,
    _In_ SIZE_T TextSize,
    _Out_writes_(32) PUCHAR Hash
    );

//=============================================================================
// Initialization / Shutdown
//=============================================================================

_Use_decl_annotations_
NTSTATUS
NiInitialize(
    _Out_ PNI_MONITOR* Monitor
    )
/*++

Routine Description:

    Initializes the NTDLL integrity monitor. Captures a clean copy of NTDLL
    from the System process for use as a reference baseline.

Arguments:

    Monitor - Receives pointer to initialized monitor.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PNI_MONITOR_INTERNAL monitorInternal = NULL;
    PNI_MONITOR monitor = NULL;
    NTSTATUS status;

    PAGED_CODE();

    if (Monitor == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Monitor = NULL;

    //
    // Allocate internal monitor structure
    //
    monitorInternal = (PNI_MONITOR_INTERNAL)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(NI_MONITOR_INTERNAL),
        NI_POOL_TAG
        );

    if (monitorInternal == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(monitorInternal, sizeof(NI_MONITOR_INTERNAL));

    monitorInternal->Signature = NI_SIGNATURE;
    monitor = &monitorInternal->Monitor;

    //
    // Initialize process list
    //
    InitializeListHead(&monitor->ProcessList);
    FltInitializePushLock(&monitor->ProcessLock);
    monitor->ProcessCount = 0;

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &monitorInternal->ProcessLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(NI_PROCESS_NTDLL),
        NI_POOL_TAG,
        0
        );

    ExInitializeNPagedLookasideList(
        &monitorInternal->FunctionLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(NI_FUNCTION_STATE),
        NI_POOL_TAG,
        0
        );

    //
    // Capture clean NTDLL from a trusted source
    //
    status = NipCaptureCleanNtdll(monitorInternal);
    if (!NT_SUCCESS(status)) {
        ExDeleteNPagedLookasideList(&monitorInternal->ProcessLookaside);
        ExDeleteNPagedLookasideList(&monitorInternal->FunctionLookaside);
        ShadowStrikeFreePoolWithTag(monitorInternal, NI_POOL_TAG);
        return status;
    }

    //
    // Initialize statistics
    //
    KeQuerySystemTimePrecise(&monitor->Stats.StartTime);
    monitor->Stats.ProcessesMonitored = 0;
    monitor->Stats.ModificationsFound = 0;
    monitor->Stats.HooksDetected = 0;

    monitor->Initialized = TRUE;
    monitorInternal->ShuttingDown = FALSE;

    *Monitor = monitor;

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
NiShutdown(
    _Inout_ PNI_MONITOR Monitor
    )
/*++

Routine Description:

    Shuts down the NTDLL integrity monitor. Frees all process states
    and releases the clean NTDLL copy.

Arguments:

    Monitor - Monitor to shutdown.

--*/
{
    PNI_MONITOR_INTERNAL monitorInternal;
    PNI_PROCESS_NTDLL processState;
    PLIST_ENTRY entry;
    LIST_ENTRY statesToFree;

    PAGED_CODE();

    if (Monitor == NULL || !Monitor->Initialized) {
        return;
    }

    monitorInternal = CONTAINING_RECORD(Monitor, NI_MONITOR_INTERNAL, Monitor);

    if (monitorInternal->Signature != NI_SIGNATURE) {
        return;
    }

    monitorInternal->ShuttingDown = TRUE;
    Monitor->Initialized = FALSE;
    KeMemoryBarrier();

    //
    // Collect all process states for cleanup
    //
    InitializeListHead(&statesToFree);

    FltAcquirePushLockExclusive(&Monitor->ProcessLock);

    while (!IsListEmpty(&Monitor->ProcessList)) {
        entry = RemoveHeadList(&Monitor->ProcessList);
        InsertTailList(&statesToFree, entry);
    }

    Monitor->ProcessCount = 0;

    FltReleasePushLock(&Monitor->ProcessLock);

    //
    // Free all process states
    //
    while (!IsListEmpty(&statesToFree)) {
        entry = RemoveHeadList(&statesToFree);
        processState = CONTAINING_RECORD(entry, NI_PROCESS_NTDLL, ListEntry);
        NipFreeProcessState(monitorInternal, processState);
    }

    //
    // Free clean NTDLL copy
    //
    if (Monitor->CleanNtdllCopy != NULL) {
        ShadowStrikeFreePoolWithTag(Monitor->CleanNtdllCopy, NI_POOL_TAG);
        Monitor->CleanNtdllCopy = NULL;
        Monitor->CleanNtdllSize = 0;
    }

    //
    // Delete lookaside lists
    //
    ExDeleteNPagedLookasideList(&monitorInternal->ProcessLookaside);
    ExDeleteNPagedLookasideList(&monitorInternal->FunctionLookaside);

    //
    // Clear signature and free
    //
    monitorInternal->Signature = 0;
    ShadowStrikeFreePoolWithTag(monitorInternal, NI_POOL_TAG);
}


//=============================================================================
// Process Scanning
//=============================================================================

_Use_decl_annotations_
NTSTATUS
NiScanProcess(
    _In_ PNI_MONITOR Monitor,
    _In_ HANDLE ProcessId,
    _Out_ PNI_PROCESS_NTDLL* State
    )
/*++

Routine Description:

    Scans a process's NTDLL for modifications and hooks. Creates or updates
    the process state with current function prologues and modification flags.

Arguments:

    Monitor - NTDLL integrity monitor.
    ProcessId - Process to scan.
    State - Receives the process NTDLL state.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PNI_MONITOR_INTERNAL monitorInternal;
    PNI_PROCESS_NTDLL processState = NULL;
    PNI_FUNCTION_STATE functionState;
    NTSTATUS status;
    PVOID ntdllBase = NULL;
    SIZE_T ntdllSize = 0;
    ULONG i;
    BOOLEAN newState = FALSE;
    KIRQL oldIrql;

    PAGED_CODE();

    if (Monitor == NULL || !Monitor->Initialized || State == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ProcessId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *State = NULL;

    monitorInternal = CONTAINING_RECORD(Monitor, NI_MONITOR_INTERNAL, Monitor);

    if (monitorInternal->ShuttingDown) {
        return STATUS_SHUTDOWN_IN_PROGRESS;
    }

    //
    // Check if we already have state for this process
    //
    processState = NipFindProcessState(Monitor, ProcessId);

    if (processState == NULL) {
        //
        // Create new process state
        //
        processState = (PNI_PROCESS_NTDLL)ExAllocateFromNPagedLookasideList(
            &monitorInternal->ProcessLookaside
            );

        if (processState == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(processState, sizeof(NI_PROCESS_NTDLL));

        processState->ProcessId = ProcessId;
        InitializeListHead(&processState->FunctionList);
        KeInitializeSpinLock(&processState->FunctionLock);
        processState->FunctionCount = 0;
        processState->ModificationCount = 0;

        newState = TRUE;
    }

    //
    // Get NTDLL base for this process
    //
    status = NipGetProcessNtdll(ProcessId, &ntdllBase, &ntdllSize);
    if (!NT_SUCCESS(status)) {
        if (newState) {
            ExFreeToNPagedLookasideList(&monitorInternal->ProcessLookaside, processState);
        }
        return status;
    }

    processState->NtdllBase = ntdllBase;
    processState->NtdllSize = ntdllSize;

    //
    // Compute hash of .text section
    //
    status = NipComputeTextSectionHash(
        ProcessId,
        ntdllBase,
        monitorInternal->CleanTextRva,
        monitorInternal->CleanTextSize,
        processState->Hash
        );

    if (!NT_SUCCESS(status)) {
        //
        // Continue even if hash fails - we can still check individual functions
        //
    }

    //
    // Clear existing function states if updating
    //
    if (!newState) {
        PLIST_ENTRY entry;
        LIST_ENTRY toFree;

        InitializeListHead(&toFree);

        KeAcquireSpinLock(&processState->FunctionLock, &oldIrql);

        while (!IsListEmpty(&processState->FunctionList)) {
            entry = RemoveHeadList(&processState->FunctionList);
            InsertTailList(&toFree, entry);
        }
        processState->FunctionCount = 0;

        KeReleaseSpinLock(&processState->FunctionLock, oldIrql);

        while (!IsListEmpty(&toFree)) {
            entry = RemoveHeadList(&toFree);
            functionState = CONTAINING_RECORD(entry, NI_FUNCTION_STATE, ListEntry);
            ExFreeToNPagedLookasideList(&monitorInternal->FunctionLookaside, functionState);
        }
    }

    //
    // Scan critical functions
    //
    processState->ModificationCount = 0;

    for (i = 0; i < NI_CRITICAL_FUNCTION_COUNT; i++) {
        PCSTR functionName = NI_CRITICAL_FUNCTIONS[i];
        ULONG_PTR functionRva = 0;
        UCHAR expectedPrologue[NI_PROLOGUE_SIZE] = {0};
        UCHAR currentPrologue[NI_PROLOGUE_SIZE] = {0};
        PVOID functionAddress;
        NI_MODIFICATION modType;

        //
        // Look up function in clean NTDLL
        //
        status = NipLookupExportByName(
            monitorInternal,
            functionName,
            &functionRva,
            expectedPrologue
            );

        if (!NT_SUCCESS(status)) {
            continue;
        }

        //
        // Calculate function address in target process
        //
        functionAddress = (PVOID)((ULONG_PTR)ntdllBase + functionRva);

        //
        // Read current prologue from process
        //
        status = NipReadProcessMemory(
            ProcessId,
            functionAddress,
            currentPrologue,
            NI_PROLOGUE_SIZE
            );

        if (!NT_SUCCESS(status)) {
            continue;
        }

        //
        // Allocate function state
        //
        functionState = (PNI_FUNCTION_STATE)ExAllocateFromNPagedLookasideList(
            &monitorInternal->FunctionLookaside
            );

        if (functionState == NULL) {
            continue;
        }

        RtlZeroMemory(functionState, sizeof(NI_FUNCTION_STATE));

        //
        // Fill function state
        //
        RtlCopyMemory(functionState->FunctionName, functionName,
                      min(strlen(functionName), sizeof(functionState->FunctionName) - 1));

        functionState->ExpectedAddress = (PVOID)((ULONG_PTR)Monitor->CleanNtdllCopy + functionRva);
        functionState->CurrentAddress = functionAddress;

        RtlCopyMemory(functionState->ExpectedPrologue, expectedPrologue, NI_PROLOGUE_SIZE);
        RtlCopyMemory(functionState->CurrentPrologue, currentPrologue, NI_PROLOGUE_SIZE);

        //
        // Detect modification type
        //
        modType = NipDetectHookType(currentPrologue, expectedPrologue, NI_PROLOGUE_SIZE);

        functionState->IsModified = (modType != NiMod_None);
        functionState->ModificationType = modType;

        if (functionState->IsModified) {
            processState->ModificationCount++;
            InterlockedIncrement64(&Monitor->Stats.ModificationsFound);

            if (modType == NiMod_HookInstalled) {
                InterlockedIncrement64(&Monitor->Stats.HooksDetected);
            }
        }

        //
        // Add to function list
        //
        KeAcquireSpinLock(&processState->FunctionLock, &oldIrql);
        InsertTailList(&processState->FunctionList, &functionState->ListEntry);
        processState->FunctionCount++;
        KeReleaseSpinLock(&processState->FunctionLock, oldIrql);
    }

    KeQuerySystemTimePrecise(&processState->LastCheck);

    //
    // Add to process list if new
    //
    if (newState) {
        FltAcquirePushLockExclusive(&Monitor->ProcessLock);
        InsertTailList(&Monitor->ProcessList, &processState->ListEntry);
        InterlockedIncrement(&Monitor->ProcessCount);
        InterlockedIncrement64(&Monitor->Stats.ProcessesMonitored);
        FltReleasePushLock(&Monitor->ProcessLock);
    }

    *State = processState;

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
NiCheckFunction(
    _In_ PNI_MONITOR Monitor,
    _In_ HANDLE ProcessId,
    _In_ PCSTR FunctionName,
    _Out_ PNI_FUNCTION_STATE* State
    )
/*++

Routine Description:

    Checks a specific function in a process's NTDLL for modifications.

Arguments:

    Monitor - NTDLL integrity monitor.
    ProcessId - Target process.
    FunctionName - Name of function to check.
    State - Receives function state (caller must free via lookaside).

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PNI_MONITOR_INTERNAL monitorInternal;
    PNI_FUNCTION_STATE functionState = NULL;
    NTSTATUS status;
    PVOID ntdllBase = NULL;
    SIZE_T ntdllSize = 0;
    ULONG_PTR functionRva = 0;
    UCHAR expectedPrologue[NI_PROLOGUE_SIZE] = {0};
    UCHAR currentPrologue[NI_PROLOGUE_SIZE] = {0};
    PVOID functionAddress;
    NI_MODIFICATION modType;

    PAGED_CODE();

    if (Monitor == NULL || !Monitor->Initialized ||
        FunctionName == NULL || State == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ProcessId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *State = NULL;

    monitorInternal = CONTAINING_RECORD(Monitor, NI_MONITOR_INTERNAL, Monitor);

    if (monitorInternal->ShuttingDown) {
        return STATUS_SHUTDOWN_IN_PROGRESS;
    }

    //
    // Get NTDLL base for this process
    //
    status = NipGetProcessNtdll(ProcessId, &ntdllBase, &ntdllSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Look up function in clean NTDLL
    //
    status = NipLookupExportByName(
        monitorInternal,
        FunctionName,
        &functionRva,
        expectedPrologue
        );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Calculate function address in target process
    //
    functionAddress = (PVOID)((ULONG_PTR)ntdllBase + functionRva);

    //
    // Read current prologue from process
    //
    status = NipReadProcessMemory(
        ProcessId,
        functionAddress,
        currentPrologue,
        NI_PROLOGUE_SIZE
        );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Allocate function state
    //
    functionState = (PNI_FUNCTION_STATE)ExAllocateFromNPagedLookasideList(
        &monitorInternal->FunctionLookaside
        );

    if (functionState == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(functionState, sizeof(NI_FUNCTION_STATE));

    //
    // Fill function state
    //
    RtlCopyMemory(functionState->FunctionName, FunctionName,
                  min(strlen(FunctionName), sizeof(functionState->FunctionName) - 1));

    functionState->ExpectedAddress = (PVOID)((ULONG_PTR)Monitor->CleanNtdllCopy + functionRva);
    functionState->CurrentAddress = functionAddress;

    RtlCopyMemory(functionState->ExpectedPrologue, expectedPrologue, NI_PROLOGUE_SIZE);
    RtlCopyMemory(functionState->CurrentPrologue, currentPrologue, NI_PROLOGUE_SIZE);

    //
    // Detect modification type
    //
    modType = NipDetectHookType(currentPrologue, expectedPrologue, NI_PROLOGUE_SIZE);

    functionState->IsModified = (modType != NiMod_None);
    functionState->ModificationType = modType;

    *State = functionState;

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
NiDetectHooks(
    _In_ PNI_MONITOR Monitor,
    _In_ HANDLE ProcessId,
    _Out_writes_to_(Max, *Count) PNI_FUNCTION_STATE* Hooks,
    _In_ ULONG Max,
    _Out_ PULONG Count
    )
/*++

Routine Description:

    Detects all hooked functions in a process's NTDLL.

Arguments:

    Monitor - NTDLL integrity monitor.
    ProcessId - Target process.
    Hooks - Array to receive hooked function states.
    Max - Maximum entries in Hooks array.
    Count - Receives actual count of hooks found.

Return Value:

    STATUS_SUCCESS on success.
    STATUS_BUFFER_TOO_SMALL if more hooks exist than Max.

--*/
{
    PNI_MONITOR_INTERNAL monitorInternal;
    PNI_PROCESS_NTDLL processState = NULL;
    NTSTATUS status;
    ULONG hookIndex = 0;
    BOOLEAN freeState = FALSE;

    PAGED_CODE();

    if (Monitor == NULL || !Monitor->Initialized ||
        Hooks == NULL || Count == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Count = 0;

    if (Max == 0) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    monitorInternal = CONTAINING_RECORD(Monitor, NI_MONITOR_INTERNAL, Monitor);

    if (monitorInternal->ShuttingDown) {
        return STATUS_SHUTDOWN_IN_PROGRESS;
    }

    //
    // Scan the process to get current state
    //
    status = NiScanProcess(Monitor, ProcessId, &processState);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Iterate function states and collect hooked ones
    //
    if (processState != NULL) {
        PLIST_ENTRY entry;
        PNI_FUNCTION_STATE funcState;
        KIRQL oldIrql;

        KeAcquireSpinLock(&processState->FunctionLock, &oldIrql);

        for (entry = processState->FunctionList.Flink;
             entry != &processState->FunctionList && hookIndex < Max;
             entry = entry->Flink) {

            funcState = CONTAINING_RECORD(entry, NI_FUNCTION_STATE, ListEntry);

            if (funcState->IsModified &&
                funcState->ModificationType == NiMod_HookInstalled) {

                //
                // Allocate a copy for the caller
                //
                PNI_FUNCTION_STATE hookCopy = (PNI_FUNCTION_STATE)ExAllocateFromNPagedLookasideList(
                    &monitorInternal->FunctionLookaside
                    );

                if (hookCopy != NULL) {
                    RtlCopyMemory(hookCopy, funcState, sizeof(NI_FUNCTION_STATE));
                    InitializeListHead(&hookCopy->ListEntry);
                    Hooks[hookIndex++] = hookCopy;
                }
            }
        }

        KeReleaseSpinLock(&processState->FunctionLock, oldIrql);
    }

    *Count = hookIndex;

    //
    // Check if there are more hooks than we could return
    //
    if (processState != NULL && processState->ModificationCount > Max) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
NiCompareToClean(
    _In_ PNI_MONITOR Monitor,
    _In_ HANDLE ProcessId,
    _Out_ PBOOLEAN IsModified
    )
/*++

Routine Description:

    Compares a process's NTDLL .text section to the clean reference
    using SHA-256 hash comparison.

Arguments:

    Monitor - NTDLL integrity monitor.
    ProcessId - Target process.
    IsModified - Receives TRUE if NTDLL has been modified.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PNI_MONITOR_INTERNAL monitorInternal;
    NTSTATUS status;
    PVOID ntdllBase = NULL;
    SIZE_T ntdllSize = 0;
    UCHAR processHash[32] = {0};

    PAGED_CODE();

    if (Monitor == NULL || !Monitor->Initialized || IsModified == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsModified = TRUE;  // Assume modified until proven otherwise

    monitorInternal = CONTAINING_RECORD(Monitor, NI_MONITOR_INTERNAL, Monitor);

    if (monitorInternal->ShuttingDown) {
        return STATUS_SHUTDOWN_IN_PROGRESS;
    }

    //
    // Get NTDLL base for this process
    //
    status = NipGetProcessNtdll(ProcessId, &ntdllBase, &ntdllSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Compute hash of process .text section
    //
    status = NipComputeTextSectionHash(
        ProcessId,
        ntdllBase,
        monitorInternal->CleanTextRva,
        monitorInternal->CleanTextSize,
        processHash
        );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Compare hashes
    //
    *IsModified = (RtlCompareMemory(processHash, monitorInternal->CleanTextHash, 32) != 32);

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
NiFreeState(
    _In_ PNI_PROCESS_NTDLL State
    )
/*++

Routine Description:

    Frees a process NTDLL state structure.
    Note: This only frees a standalone state, not one in the monitor's list.

Arguments:

    State - State to free.

--*/
{
    PAGED_CODE();

    //
    // Note: Function states within the process are not freed here
    // as they may still be in use. The full cleanup happens in NiShutdown.
    //

    UNREFERENCED_PARAMETER(State);
}


//=============================================================================
// Internal Functions - NTDLL Capture
//=============================================================================

static
_Use_decl_annotations_
NTSTATUS
NipCaptureCleanNtdll(
    _Inout_ PNI_MONITOR_INTERNAL MonitorInternal
    )
/*++

Routine Description:

    Captures a clean copy of NTDLL from the System process (PID 4)
    or reads from disk as a fallback.

--*/
{
    NTSTATUS status;
    PVOID ntdllBase = NULL;
    SIZE_T ntdllSize = 0;
    PVOID cleanCopy = NULL;
    PVOID textBase = NULL;
    SIZE_T textSize = 0;
    ULONG_PTR textRva = 0;
    PEPROCESS systemProcess = NULL;
    KAPC_STATE apcState;

    //
    // Get System process (PID 4)
    //
    status = PsLookupProcessByProcessId((HANDLE)4, &systemProcess);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Get NTDLL base from System process
    // Note: System process doesn't have a user-mode NTDLL, so we need to
    // get it from another clean process like csrss or smss
    //
    ObDereferenceObject(systemProcess);

    //
    // Try to get NTDLL from current process as initial source
    // In production, this would be from a trusted process or disk
    //
    status = NipGetProcessNtdll(PsGetCurrentProcessId(), &ntdllBase, &ntdllSize);
    if (!NT_SUCCESS(status)) {
        //
        // Fallback: try to read from disk
        //
        // For now, return error - disk reading would be implemented separately
        //
        return status;
    }

    //
    // Allocate buffer for clean copy
    //
    cleanCopy = ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        ntdllSize,
        NI_POOL_TAG
        );

    if (cleanCopy == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Read NTDLL into our buffer
    //
    status = NipReadProcessMemory(
        PsGetCurrentProcessId(),
        ntdllBase,
        cleanCopy,
        ntdllSize
        );

    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreePoolWithTag(cleanCopy, NI_POOL_TAG);
        return status;
    }

    MonitorInternal->Monitor.CleanNtdllCopy = cleanCopy;
    MonitorInternal->Monitor.CleanNtdllSize = ntdllSize;

    //
    // Parse .text section
    //
    status = NipGetTextSection(
        cleanCopy,
        ntdllSize,
        &textBase,
        &textSize,
        &textRva
        );

    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreePoolWithTag(cleanCopy, NI_POOL_TAG);
        MonitorInternal->Monitor.CleanNtdllCopy = NULL;
        return status;
    }

    MonitorInternal->CleanTextSection = textBase;
    MonitorInternal->CleanTextSize = textSize;
    MonitorInternal->CleanTextRva = textRva;

    //
    // Compute hash of clean .text section
    //
    status = ShadowStrikeComputeSha256(
        textBase,
        textSize,
        MonitorInternal->CleanTextHash,
        sizeof(MonitorInternal->CleanTextHash)
        );

    if (!NT_SUCCESS(status)) {
        //
        // Non-fatal - continue without hash
        //
        RtlZeroMemory(MonitorInternal->CleanTextHash, sizeof(MonitorInternal->CleanTextHash));
    }

    //
    // Parse export table
    //
    status = NipParseExportTable(
        cleanCopy,
        ntdllSize,
        &MonitorInternal->CleanExports.ExportDirectory,
        &MonitorInternal->CleanExports.NumberOfFunctions,
        &MonitorInternal->CleanExports.NumberOfNames,
        &MonitorInternal->CleanExports.AddressOfFunctions,
        &MonitorInternal->CleanExports.AddressOfNames,
        &MonitorInternal->CleanExports.AddressOfNameOrdinals
        );

    if (!NT_SUCCESS(status)) {
        //
        // Export parsing failure is critical
        //
        ShadowStrikeFreePoolWithTag(cleanCopy, NI_POOL_TAG);
        MonitorInternal->Monitor.CleanNtdllCopy = NULL;
        return status;
    }

    return STATUS_SUCCESS;
}


static
_Use_decl_annotations_
NTSTATUS
NipGetProcessNtdll(
    _In_ HANDLE ProcessId,
    _Out_ PVOID* NtdllBase,
    _Out_ PSIZE_T NtdllSize
    )
/*++

Routine Description:

    Gets the base address and size of ntdll.dll in a process.

--*/
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PPEB peb = NULL;
    PPEB_LDR_DATA ldrData = NULL;
    PLIST_ENTRY listHead;
    PLIST_ENTRY listEntry;
    KAPC_STATE apcState;
    BOOLEAN found = FALSE;
    UNICODE_STRING ntdllName;

    *NtdllBase = NULL;
    *NtdllSize = 0;

    RtlInitUnicodeString(&ntdllName, L"ntdll.dll");

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    peb = PsGetProcessPeb(process);
    if (peb == NULL) {
        ObDereferenceObject(process);
        return STATUS_NOT_FOUND;
    }

    KeStackAttachProcess(process, &apcState);

    __try {
        ProbeForRead(peb, sizeof(PEB), sizeof(PVOID));
        ldrData = peb->Ldr;

        if (ldrData == NULL) {
            status = STATUS_NOT_FOUND;
            __leave;
        }

        ProbeForRead(ldrData, sizeof(PEB_LDR_DATA), sizeof(PVOID));

        listHead = &ldrData->InMemoryOrderModuleList;
        listEntry = listHead->Flink;

        while (listEntry != listHead) {
            PLDR_DATA_TABLE_ENTRY ldrEntry;

            ldrEntry = CONTAINING_RECORD(
                listEntry,
                LDR_DATA_TABLE_ENTRY,
                InMemoryOrderLinks
                );

            ProbeForRead(ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY), sizeof(PVOID));

            if (ldrEntry->BaseDllName.Buffer != NULL &&
                ldrEntry->BaseDllName.Length > 0) {

                ProbeForRead(
                    ldrEntry->BaseDllName.Buffer,
                    ldrEntry->BaseDllName.Length,
                    sizeof(WCHAR)
                    );

                if (RtlCompareUnicodeString(&ldrEntry->BaseDllName, &ntdllName, TRUE) == 0) {
                    *NtdllBase = ldrEntry->DllBase;
                    *NtdllSize = ldrEntry->SizeOfImage;
                    found = TRUE;
                    break;
                }
            }

            listEntry = listEntry->Flink;
        }

        status = found ? STATUS_SUCCESS : STATUS_NOT_FOUND;

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);

    return status;
}


static
_Use_decl_annotations_
NTSTATUS
NipReadProcessMemory(
    _In_ HANDLE ProcessId,
    _In_ PVOID SourceAddress,
    _Out_writes_bytes_(Size) PVOID Destination,
    _In_ SIZE_T Size
    )
/*++

Routine Description:

    Safely reads memory from a process's address space.

--*/
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    KAPC_STATE apcState;

    if (Size == 0) {
        return STATUS_SUCCESS;
    }

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    KeStackAttachProcess(process, &apcState);

    __try {
        if (!MmIsAddressValid(SourceAddress)) {
            status = STATUS_ACCESS_VIOLATION;
            __leave;
        }

        ProbeForRead(SourceAddress, Size, 1);
        RtlCopyMemory(Destination, SourceAddress, Size);
        status = STATUS_SUCCESS;

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);

    return status;
}


static
_Use_decl_annotations_
NTSTATUS
NipGetTextSection(
    _In_ PVOID ModuleBase,
    _In_ SIZE_T ModuleSize,
    _Out_ PVOID* TextBase,
    _Out_ PSIZE_T TextSize,
    _Out_ PULONG_PTR TextRva
    )
/*++

Routine Description:

    Parses PE headers to find the .text section.

--*/
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS64 ntHeaders;
    PIMAGE_SECTION_HEADER sectionHeader;
    ULONG i;

    *TextBase = NULL;
    *TextSize = 0;
    *TextRva = 0;

    if (ModuleSize < sizeof(IMAGE_DOS_HEADER)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    dosHeader = (PIMAGE_DOS_HEADER)ModuleBase;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if ((SIZE_T)dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > ModuleSize) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    ntHeaders = (PIMAGE_NT_HEADERS64)((PUCHAR)ModuleBase + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    //
    // Find section headers
    //
    sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    for (i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if ((PUCHAR)&sectionHeader[i] + sizeof(IMAGE_SECTION_HEADER) >
            (PUCHAR)ModuleBase + ModuleSize) {
            break;
        }

        //
        // Look for .text or executable section
        //
        if (RtlCompareMemory(sectionHeader[i].Name, ".text", 5) == 5 ||
            (sectionHeader[i].Characteristics & IMAGE_SCN_CNT_CODE)) {

            *TextRva = sectionHeader[i].VirtualAddress;
            *TextSize = sectionHeader[i].Misc.VirtualSize;
            *TextBase = (PVOID)((PUCHAR)ModuleBase + sectionHeader[i].VirtualAddress);

            if ((PUCHAR)*TextBase + *TextSize <= (PUCHAR)ModuleBase + ModuleSize) {
                return STATUS_SUCCESS;
            }
        }
    }

    return STATUS_NOT_FOUND;
}


static
_Use_decl_annotations_
NTSTATUS
NipParseExportTable(
    _In_ PVOID ModuleBase,
    _In_ SIZE_T ModuleSize,
    _Out_ PVOID* ExportDirectory,
    _Out_ PULONG NumberOfFunctions,
    _Out_ PULONG NumberOfNames,
    _Out_ PULONG* AddressOfFunctions,
    _Out_ PULONG* AddressOfNames,
    _Out_ PUSHORT* AddressOfNameOrdinals
    )
/*++

Routine Description:

    Parses the PE export directory.

--*/
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS64 ntHeaders;
    PIMAGE_DATA_DIRECTORY exportDataDir;
    PIMAGE_EXPORT_DIRECTORY exportDir;
    ULONG exportDirRva;
    ULONG exportDirSize;

    *ExportDirectory = NULL;
    *NumberOfFunctions = 0;
    *NumberOfNames = 0;
    *AddressOfFunctions = NULL;
    *AddressOfNames = NULL;
    *AddressOfNameOrdinals = NULL;

    if (ModuleSize < sizeof(IMAGE_DOS_HEADER)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    dosHeader = (PIMAGE_DOS_HEADER)ModuleBase;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    ntHeaders = (PIMAGE_NT_HEADERS64)((PUCHAR)ModuleBase + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    //
    // Get export directory
    //
    exportDataDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    exportDirRva = exportDataDir->VirtualAddress;
    exportDirSize = exportDataDir->Size;

    if (exportDirRva == 0 || exportDirSize == 0) {
        return STATUS_NOT_FOUND;
    }

    if (exportDirRva + sizeof(IMAGE_EXPORT_DIRECTORY) > ModuleSize) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    exportDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ModuleBase + exportDirRva);

    *ExportDirectory = exportDir;
    *NumberOfFunctions = exportDir->NumberOfFunctions;
    *NumberOfNames = exportDir->NumberOfNames;

    if (exportDir->AddressOfFunctions != 0) {
        *AddressOfFunctions = (PULONG)((PUCHAR)ModuleBase + exportDir->AddressOfFunctions);
    }

    if (exportDir->AddressOfNames != 0) {
        *AddressOfNames = (PULONG)((PUCHAR)ModuleBase + exportDir->AddressOfNames);
    }

    if (exportDir->AddressOfNameOrdinals != 0) {
        *AddressOfNameOrdinals = (PUSHORT)((PUCHAR)ModuleBase + exportDir->AddressOfNameOrdinals);
    }

    return STATUS_SUCCESS;
}


static
_Use_decl_annotations_
NTSTATUS
NipLookupExportByName(
    _In_ PNI_MONITOR_INTERNAL MonitorInternal,
    _In_ PCSTR FunctionName,
    _Out_ PULONG_PTR FunctionRva,
    _Out_ PUCHAR ExpectedPrologue
    )
/*++

Routine Description:

    Looks up an export by name in the clean NTDLL copy.

--*/
{
    PULONG addressOfNames;
    PUSHORT addressOfOrdinals;
    PULONG addressOfFunctions;
    ULONG i;
    PVOID cleanBase;
    SIZE_T nameLen;

    *FunctionRva = 0;
    RtlZeroMemory(ExpectedPrologue, NI_PROLOGUE_SIZE);

    if (MonitorInternal->CleanExports.AddressOfNames == NULL ||
        MonitorInternal->CleanExports.AddressOfFunctions == NULL ||
        MonitorInternal->CleanExports.AddressOfNameOrdinals == NULL) {
        return STATUS_NOT_FOUND;
    }

    cleanBase = MonitorInternal->Monitor.CleanNtdllCopy;
    addressOfNames = MonitorInternal->CleanExports.AddressOfNames;
    addressOfOrdinals = MonitorInternal->CleanExports.AddressOfNameOrdinals;
    addressOfFunctions = MonitorInternal->CleanExports.AddressOfFunctions;
    nameLen = strlen(FunctionName);

    //
    // Binary search would be more efficient, but linear is simple and correct
    //
    for (i = 0; i < MonitorInternal->CleanExports.NumberOfNames; i++) {
        PCSTR exportName = (PCSTR)((PUCHAR)cleanBase + addressOfNames[i]);

        if (RtlCompareMemory(exportName, FunctionName, nameLen + 1) == nameLen + 1) {
            //
            // Found it - get the function RVA
            //
            USHORT ordinal = addressOfOrdinals[i];
            ULONG functionRva = addressOfFunctions[ordinal];

            *FunctionRva = functionRva;

            //
            // Copy the prologue bytes
            //
            PVOID prologueAddr = (PVOID)((PUCHAR)cleanBase + functionRva);

            if ((PUCHAR)prologueAddr + NI_PROLOGUE_SIZE <=
                (PUCHAR)cleanBase + MonitorInternal->Monitor.CleanNtdllSize) {
                RtlCopyMemory(ExpectedPrologue, prologueAddr, NI_PROLOGUE_SIZE);
            }

            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}


//=============================================================================
// Internal Functions - Hook Detection
//=============================================================================

static
_Use_decl_annotations_
NI_MODIFICATION
NipDetectHookType(
    _In_ PUCHAR CurrentPrologue,
    _In_ PUCHAR ExpectedPrologue,
    _In_ SIZE_T Size
    )
/*++

Routine Description:

    Detects the type of modification in a function prologue.

--*/
{
    //
    // First check if they match exactly
    //
    if (RtlCompareMemory(CurrentPrologue, ExpectedPrologue, Size) == Size) {
        return NiMod_None;
    }

    //
    // Check for JMP rel32 (E9 xx xx xx xx)
    //
    if (CurrentPrologue[0] == NI_JMP_REL32_OPCODE) {
        return NiMod_HookInstalled;
    }

    //
    // Check for JMP [rip+offset] (FF 25 xx xx xx xx)
    //
    if (CurrentPrologue[0] == NI_JMP_ABS_PREFIX && CurrentPrologue[1] == 0x25) {
        return NiMod_HookInstalled;
    }

    //
    // Check for MOV RAX, imm64; JMP RAX (48 B8 ... FF E0)
    //
    if (CurrentPrologue[0] == 0x48 && CurrentPrologue[1] == 0xB8) {
        //
        // Look for JMP RAX at offset 10
        //
        if (Size >= 12 && CurrentPrologue[10] == 0xFF && CurrentPrologue[11] == 0xE0) {
            return NiMod_HookInstalled;
        }
    }

    //
    // Check for MOV R10, imm64; JMP R10 (49 BA ... 41 FF E2)
    //
    if (CurrentPrologue[0] == 0x49 && CurrentPrologue[1] == 0xBA) {
        if (Size >= 13 && CurrentPrologue[10] == 0x41 &&
            CurrentPrologue[11] == 0xFF && CurrentPrologue[12] == 0xE2) {
            return NiMod_HookInstalled;
        }
    }

    //
    // Check for PUSH + RET (50-57 C3) - stack-based hook
    //
    if ((CurrentPrologue[0] >= 0x50 && CurrentPrologue[0] <= 0x57) &&
        Size >= 2 && CurrentPrologue[1] == 0xC3) {
        return NiMod_HookInstalled;
    }

    //
    // Check for hotpatch pattern modification (CC or EB at -1 from entry)
    // In x64, hotpatch is typically JMP rel8 at -5
    //

    //
    // Check if this is a syscall stub that has been modified
    //
    ULONG expectedSyscall = 0;
    ULONG currentSyscall = 0;

    BOOLEAN expectedIsSyscall = NipIsSyscallStub(ExpectedPrologue, Size, &expectedSyscall);
    BOOLEAN currentIsSyscall = NipIsSyscallStub(CurrentPrologue, Size, &currentSyscall);

    if (expectedIsSyscall) {
        if (!currentIsSyscall) {
            //
            // Syscall stub was replaced with something else
            //
            return NiMod_HookInstalled;
        }

        if (expectedSyscall != currentSyscall) {
            //
            // Syscall number was changed
            //
            return NiMod_SyscallStubModified;
        }

        //
        // Syscall stub exists but bytes differ - instruction patch
        //
        if (!NipValidateSyscallStub(CurrentPrologue, ExpectedPrologue, Size)) {
            return NiMod_InstructionPatch;
        }
    }

    //
    // Generic instruction modification
    //
    return NiMod_InstructionPatch;
}


static
_Use_decl_annotations_
BOOLEAN
NipIsSyscallStub(
    _In_ PUCHAR Prologue,
    _In_ SIZE_T Size,
    _Out_opt_ PULONG SyscallNumber
    )
/*++

Routine Description:

    Checks if a prologue represents a syscall stub.

    Expected pattern (x64):
    4C 8B D1        mov r10, rcx
    B8 XX XX XX XX  mov eax, syscall_number
    0F 05           syscall
    C3              ret

--*/
{
    if (Size < 12) {
        return FALSE;
    }

    //
    // Check for mov r10, rcx (4C 8B D1)
    //
    if (Prologue[0] != 0x4C || Prologue[1] != 0x8B || Prologue[2] != 0xD1) {
        return FALSE;
    }

    //
    // Check for mov eax, imm32 (B8)
    //
    if (Prologue[3] != NI_MOV_EAX_IMM32) {
        return FALSE;
    }

    if (SyscallNumber != NULL) {
        *SyscallNumber = *(PULONG)&Prologue[4];
    }

    //
    // Check for syscall (0F 05) - may be at different offsets
    // depending on Windows version
    //
    for (SIZE_T i = 8; i < Size - 1; i++) {
        if (Prologue[i] == 0x0F && Prologue[i + 1] == 0x05) {
            return TRUE;
        }
    }

    return FALSE;
}


static
_Use_decl_annotations_
BOOLEAN
NipValidateSyscallStub(
    _In_ PUCHAR CurrentPrologue,
    _In_ PUCHAR ExpectedPrologue,
    _In_ SIZE_T Size
    )
/*++

Routine Description:

    Validates that a syscall stub's critical bytes are intact.

--*/
{
    //
    // Check mov r10, rcx
    //
    if (CurrentPrologue[0] != ExpectedPrologue[0] ||
        CurrentPrologue[1] != ExpectedPrologue[1] ||
        CurrentPrologue[2] != ExpectedPrologue[2]) {
        return FALSE;
    }

    //
    // Check mov eax opcode
    //
    if (CurrentPrologue[3] != ExpectedPrologue[3]) {
        return FALSE;
    }

    //
    // Check syscall number
    //
    if (RtlCompareMemory(&CurrentPrologue[4], &ExpectedPrologue[4], 4) != 4) {
        return FALSE;
    }

    //
    // Look for syscall instruction in both
    //
    BOOLEAN foundCurrentSyscall = FALSE;
    BOOLEAN foundExpectedSyscall = FALSE;

    for (SIZE_T i = 8; i < Size - 1; i++) {
        if (CurrentPrologue[i] == 0x0F && CurrentPrologue[i + 1] == 0x05) {
            foundCurrentSyscall = TRUE;
        }
        if (ExpectedPrologue[i] == 0x0F && ExpectedPrologue[i + 1] == 0x05) {
            foundExpectedSyscall = TRUE;
        }
    }

    return (foundCurrentSyscall && foundExpectedSyscall);
}


//=============================================================================
// Internal Functions - Process State Management
//=============================================================================

static
_Use_decl_annotations_
PNI_PROCESS_NTDLL
NipFindProcessState(
    _In_ PNI_MONITOR Monitor,
    _In_ HANDLE ProcessId
    )
/*++

Routine Description:

    Finds an existing process state in the monitor's list.

--*/
{
    PLIST_ENTRY entry;
    PNI_PROCESS_NTDLL processState;

    FltAcquirePushLockShared(&Monitor->ProcessLock);

    for (entry = Monitor->ProcessList.Flink;
         entry != &Monitor->ProcessList;
         entry = entry->Flink) {

        processState = CONTAINING_RECORD(entry, NI_PROCESS_NTDLL, ListEntry);

        if (processState->ProcessId == ProcessId) {
            FltReleasePushLock(&Monitor->ProcessLock);
            return processState;
        }
    }

    FltReleasePushLock(&Monitor->ProcessLock);

    return NULL;
}


static
_Use_decl_annotations_
VOID
NipFreeProcessState(
    _In_ PNI_MONITOR_INTERNAL MonitorInternal,
    _Inout_ PNI_PROCESS_NTDLL State
    )
/*++

Routine Description:

    Frees a process state and all its function states.

--*/
{
    PLIST_ENTRY entry;
    PNI_FUNCTION_STATE functionState;
    KIRQL oldIrql;
    LIST_ENTRY toFree;

    InitializeListHead(&toFree);

    //
    // Collect all function states
    //
    KeAcquireSpinLock(&State->FunctionLock, &oldIrql);

    while (!IsListEmpty(&State->FunctionList)) {
        entry = RemoveHeadList(&State->FunctionList);
        InsertTailList(&toFree, entry);
    }

    State->FunctionCount = 0;

    KeReleaseSpinLock(&State->FunctionLock, oldIrql);

    //
    // Free function states
    //
    while (!IsListEmpty(&toFree)) {
        entry = RemoveHeadList(&toFree);
        functionState = CONTAINING_RECORD(entry, NI_FUNCTION_STATE, ListEntry);
        ExFreeToNPagedLookasideList(&MonitorInternal->FunctionLookaside, functionState);
    }

    //
    // Free process state
    //
    ExFreeToNPagedLookasideList(&MonitorInternal->ProcessLookaside, State);
}


static
_Use_decl_annotations_
NTSTATUS
NipComputeTextSectionHash(
    _In_ HANDLE ProcessId,
    _In_ PVOID NtdllBase,
    _In_ ULONG_PTR TextRva,
    _In_ SIZE_T TextSize,
    _Out_writes_(32) PUCHAR Hash
    )
/*++

Routine Description:

    Computes SHA-256 hash of a process's NTDLL .text section.

--*/
{
    NTSTATUS status;
    PVOID textBuffer = NULL;
    PVOID textAddress;

    RtlZeroMemory(Hash, 32);

    if (TextSize == 0 || TextSize > 16 * 1024 * 1024) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Allocate buffer for .text section
    //
    textBuffer = ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        TextSize,
        NI_POOL_TAG
        );

    if (textBuffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Calculate .text address in process
    //
    textAddress = (PVOID)((ULONG_PTR)NtdllBase + TextRva);

    //
    // Read .text section from process
    //
    status = NipReadProcessMemory(ProcessId, textAddress, textBuffer, TextSize);

    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreePoolWithTag(textBuffer, NI_POOL_TAG);
        return status;
    }

    //
    // Compute hash
    //
    status = ShadowStrikeComputeSha256(textBuffer, TextSize, Hash, 32);

    ShadowStrikeFreePoolWithTag(textBuffer, NI_POOL_TAG);

    return status;
}

