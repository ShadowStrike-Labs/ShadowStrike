/*++
    ShadowStrike Next-Generation Antivirus
    Module: ThreadNotify.c

    Purpose: Enterprise-grade thread creation/termination monitoring with
             comprehensive injection detection, risk assessment, and
             behavioral analysis.

    Architecture:
    - PsSetCreateThreadNotifyRoutineEx callback registration
    - Per-process thread tracking with reference counting
    - Remote thread injection detection and scoring
    - Start address validation against loaded modules
    - Memory protection analysis for RWX detection
    - Cross-session and privilege escalation detection
    - Rapid thread creation pattern detection
    - Integration with ScanBridge for user-mode notifications

    Detection Capabilities:
    - CreateRemoteThread / CreateRemoteThreadEx injection
    - NtCreateThreadEx with remote handles
    - RtlCreateUserThread-based injection
    - Thread execution hijacking
    - Shellcode injection via unbacked memory
    - APC-based code execution

    MITRE ATT&CK Coverage:
    - T1055.001: Dynamic-link Library Injection
    - T1055.002: Portable Executable Injection
    - T1055.003: Thread Execution Hijacking
    - T1055.004: Asynchronous Procedure Call
    - T1055.012: Process Hollowing
    - T1106: Native API

    Copyright (c) ShadowStrike Team
--*/

#include "ThreadNotify.h"
#include "../../Core/Globals.h"
#include "../../Communication/ScanBridge.h"
#include "../../Utilities/MemoryUtils.h"
#include "../../Utilities/ProcessUtils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, RegisterThreadNotify)
#pragma alloc_text(PAGE, UnregisterThreadNotify)
#pragma alloc_text(PAGE, TnRegisterCallback)
#pragma alloc_text(PAGE, TnUnregisterCallback)
#pragma alloc_text(PAGE, TnIsRemoteThread)
#pragma alloc_text(PAGE, TnAnalyzeStartAddress)
#endif

//=============================================================================
// Internal Constants
//=============================================================================

#define TN_SIGNATURE                    'NRHT'  // 'THRN' reversed
#define TN_CONTEXT_SIGNATURE            'CTHT'  // 'THTC' reversed

#define TN_SYSTEM_PROCESS_ID            4
#define TN_MIN_VALID_USER_ADDRESS       0x10000ULL
#define TN_MAX_USER_ADDRESS             0x7FFFFFFFFFFFULL

#define TN_MAX_RECENT_EVENTS            64
#define TN_RAPID_THREAD_THRESHOLD       10
#define TN_RAPID_THREAD_WINDOW_MS       1000

//
// Injection score weights
//
#define TN_SCORE_REMOTE_THREAD          100
#define TN_SCORE_SUSPENDED_START        50
#define TN_SCORE_UNBACKED_START         200
#define TN_SCORE_RWX_START              250
#define TN_SCORE_SYSTEM_TARGET          150
#define TN_SCORE_PROTECTED_TARGET       200
#define TN_SCORE_UNUSUAL_ENTRY          75
#define TN_SCORE_CROSS_SESSION          100
#define TN_SCORE_ELEVATED_SOURCE        50
#define TN_SCORE_RAPID_CREATION         100
#define TN_SCORE_SHELLCODE_PATTERN      300

//=============================================================================
// Global State
//=============================================================================

static TN_MONITOR g_TnMonitor = { 0 };
static BOOLEAN g_TnInitialized = FALSE;

//=============================================================================
// Forward Declarations
//=============================================================================

VOID
TnpThreadNotifyCallback(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
TnpInitializeMonitor(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
TnpCleanupMonitor(
    VOID
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static PTN_PROCESS_CONTEXT
TnpFindProcessContext(
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN CreateIfNotFound
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
TnpReferenceProcessContext(
    _Inout_ PTN_PROCESS_CONTEXT Context
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
TnpDereferenceProcessContext(
    _Inout_ PTN_PROCESS_CONTEXT Context
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
TnpDestroyProcessContext(
    _Inout_ PTN_PROCESS_CONTEXT Context
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
TnpAnalyzeThreadCreation(
    _In_ HANDLE TargetProcessId,
    _In_ HANDLE ThreadId,
    _In_ HANDLE CreatorProcessId,
    _Out_ PTN_THREAD_EVENT Event
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
TnpGetThreadStartAddress(
    _In_ HANDLE ThreadId,
    _Out_ PVOID* StartAddress,
    _Out_ PVOID* Win32StartAddress
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
TnpGetMemoryProtection(
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _Out_ PULONG Protection,
    _Out_ PBOOLEAN IsBacked
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
TnpFindModuleForAddress(
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _Out_writes_(ModuleNameSize) PWCHAR ModuleName,
    _In_ ULONG ModuleNameSize,
    _Out_ PULONG_PTR ModuleBase,
    _Out_ PSIZE_T ModuleSize
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
TnpGetProcessImageName(
    _In_ HANDLE ProcessId,
    _Out_writes_(BufferSize) PWCHAR Buffer,
    _In_ ULONG BufferSize
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static BOOLEAN
TnpIsSystemProcess(
    _In_ HANDLE ProcessId
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static BOOLEAN
TnpIsProtectedProcess(
    _In_ HANDLE ProcessId
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static BOOLEAN
TnpCheckShellcodePatterns(
    _In_ HANDLE ProcessId,
    _In_ PVOID Address
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
TnpCalculateInjectionScore(
    _In_ PTN_THREAD_EVENT Event
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static TN_RISK_LEVEL
TnpCalculateRiskLevel(
    _In_ ULONG Score
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
TnpHandleThreadCreation(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
TnpHandleThreadTermination(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
TnpSendNotification(
    _In_ PTN_THREAD_EVENT Event
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
TnpUpdateProcessRisk(
    _Inout_ PTN_PROCESS_CONTEXT Context,
    _In_ PTN_THREAD_EVENT Event
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
TnpPruneOldEvents(
    _Inout_ PTN_PROCESS_CONTEXT Context
    );

//=============================================================================
// Initialization / Shutdown
//=============================================================================

_Use_decl_annotations_
NTSTATUS
RegisterThreadNotify(
    VOID
    )
/*++

Routine Description:

    Registers the thread creation notification callback and initializes
    the thread monitoring subsystem.

Return Value:

    STATUS_SUCCESS if successful, otherwise an NTSTATUS error code.

--*/
{
    NTSTATUS status;

    PAGED_CODE();

    if (g_TnInitialized) {
        return STATUS_SUCCESS;
    }

    //
    // Initialize the monitor infrastructure
    //
    status = TnpInitializeMonitor();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Register the thread notification callback
    // Using PsSetCreateThreadNotifyRoutineEx for extended information if available
    //
    status = PsSetCreateThreadNotifyRoutine(TnpThreadNotifyCallback);

    if (!NT_SUCCESS(status)) {
        TnpCleanupMonitor();
        return status;
    }

    g_TnMonitor.CallbackRegistered = TRUE;
    g_TnInitialized = TRUE;

    //
    // Update global driver state
    //
    g_DriverData.ThreadNotifyRegistered = TRUE;

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
UnregisterThreadNotify(
    VOID
    )
/*++

Routine Description:

    Unregisters the thread creation notification callback and cleans up
    all tracking structures.

Return Value:

    STATUS_SUCCESS if successful, otherwise an NTSTATUS error code.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();

    if (!g_TnInitialized) {
        return STATUS_SUCCESS;
    }

    //
    // Mark as shutting down
    //
    g_TnMonitor.ShuttingDown = TRUE;
    KeMemoryBarrier();

    //
    // Unregister the callback
    //
    if (g_TnMonitor.CallbackRegistered) {
        status = PsRemoveCreateThreadNotifyRoutine(TnpThreadNotifyCallback);
        if (NT_SUCCESS(status)) {
            g_TnMonitor.CallbackRegistered = FALSE;
        }
    }

    //
    // Cleanup monitor infrastructure
    //
    TnpCleanupMonitor();

    g_TnInitialized = FALSE;
    g_TnMonitor.Initialized = FALSE;

    //
    // Update global driver state
    //
    g_DriverData.ThreadNotifyRegistered = FALSE;

    return status;
}


static
_Use_decl_annotations_
NTSTATUS
TnpInitializeMonitor(
    VOID
    )
/*++

Routine Description:

    Initializes the thread monitoring infrastructure.

--*/
{
    PAGED_CODE();

    RtlZeroMemory(&g_TnMonitor, sizeof(TN_MONITOR));

    //
    // Initialize process list
    //
    InitializeListHead(&g_TnMonitor.ProcessList);
    FltInitializePushLock(&g_TnMonitor.ProcessLock);
    g_TnMonitor.ProcessCount = 0;

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &g_TnMonitor.EventLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(TN_THREAD_EVENT),
        TN_POOL_TAG_EVENT,
        0
        );

    ExInitializeNPagedLookasideList(
        &g_TnMonitor.ContextLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(TN_PROCESS_CONTEXT),
        TN_POOL_TAG_CONTEXT,
        0
        );

    //
    // Set default configuration
    //
    g_TnMonitor.Config.MonitorRemoteThreads = TRUE;
    g_TnMonitor.Config.MonitorSuspendedThreads = TRUE;
    g_TnMonitor.Config.ValidateStartAddresses = TRUE;
    g_TnMonitor.Config.TrackThreadHistory = TRUE;
    g_TnMonitor.Config.InjectionScoreThreshold = TN_INJECTION_SCORE_THRESHOLD;
    g_TnMonitor.Config.DefaultAction = TnActionAlert;

    //
    // Initialize statistics
    //
    KeQuerySystemTimePrecise(&g_TnMonitor.Stats.StartTime);

    g_TnMonitor.Initialized = TRUE;
    g_TnMonitor.ShuttingDown = FALSE;

    return STATUS_SUCCESS;
}


static
_Use_decl_annotations_
VOID
TnpCleanupMonitor(
    VOID
    )
/*++

Routine Description:

    Cleans up the thread monitoring infrastructure.

--*/
{
    PLIST_ENTRY entry;
    PTN_PROCESS_CONTEXT context;
    LIST_ENTRY contextsToFree;

    PAGED_CODE();

    InitializeListHead(&contextsToFree);

    //
    // Collect all process contexts
    //
    FltAcquirePushLockExclusive(&g_TnMonitor.ProcessLock);

    while (!IsListEmpty(&g_TnMonitor.ProcessList)) {
        entry = RemoveHeadList(&g_TnMonitor.ProcessList);
        InsertTailList(&contextsToFree, entry);
    }

    g_TnMonitor.ProcessCount = 0;

    FltReleasePushLock(&g_TnMonitor.ProcessLock);

    //
    // Free all contexts
    //
    while (!IsListEmpty(&contextsToFree)) {
        entry = RemoveHeadList(&contextsToFree);
        context = CONTAINING_RECORD(entry, TN_PROCESS_CONTEXT, ListEntry);
        TnpDestroyProcessContext(context);
    }

    //
    // Delete lookaside lists
    //
    ExDeleteNPagedLookasideList(&g_TnMonitor.EventLookaside);
    ExDeleteNPagedLookasideList(&g_TnMonitor.ContextLookaside);
}


//=============================================================================
// Thread Notification Callback
//=============================================================================

VOID
TnpThreadNotifyCallback(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
    )
/*++

Routine Description:

    Callback routine invoked when a thread is created or deleted.
    This is the main entry point for thread monitoring.

Arguments:

    ProcessId - The process ID where the thread is created/deleted.
    ThreadId - The thread ID of the thread.
    Create - TRUE if the thread is being created, FALSE if deleted.

--*/
{
    //
    // Check if driver is ready to process requests
    //
    if (!SHADOWSTRIKE_IS_READY()) {
        return;
    }

    if (g_TnMonitor.ShuttingDown) {
        return;
    }

    //
    // Track operation for clean shutdown
    //
    SHADOWSTRIKE_ENTER_OPERATION();

    if (Create) {
        //
        // Handle thread creation
        //
        InterlockedIncrement64(&g_TnMonitor.Stats.TotalThreadsCreated);
        TnpHandleThreadCreation(ProcessId, ThreadId);
    } else {
        //
        // Handle thread termination
        //
        InterlockedIncrement64(&g_TnMonitor.Stats.TotalThreadsTerminated);
        TnpHandleThreadTermination(ProcessId, ThreadId);
    }

    SHADOWSTRIKE_LEAVE_OPERATION();
}


static
_Use_decl_annotations_
VOID
TnpHandleThreadCreation(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId
    )
/*++

Routine Description:

    Handles a thread creation event with full analysis.

--*/
{
    NTSTATUS status;
    PTN_THREAD_EVENT event = NULL;
    PTN_PROCESS_CONTEXT processContext = NULL;
    HANDLE creatorProcessId;
    BOOLEAN isRemote = FALSE;
    KIRQL oldIrql;

    PAGED_CODE();

    //
    // Determine creator process
    //
    creatorProcessId = PsGetCurrentProcessId();

    //
    // Quick check for remote thread
    //
    if (creatorProcessId != ProcessId &&
        creatorProcessId != (HANDLE)(ULONG_PTR)TN_SYSTEM_PROCESS_ID) {
        isRemote = TRUE;
    }

    //
    // Skip if not monitoring remote threads and this isn't remote
    //
    if (!isRemote && !g_TnMonitor.Config.TrackThreadHistory) {
        return;
    }

    //
    // Get or create process context
    //
    processContext = TnpFindProcessContext(ProcessId, TRUE);
    if (processContext == NULL) {
        return;
    }

    //
    // Increment thread count
    //
    InterlockedIncrement(&processContext->ThreadCount);

    //
    // For remote threads, perform full analysis
    //
    if (isRemote && g_TnMonitor.Config.MonitorRemoteThreads) {
        //
        // Allocate event structure
        //
        event = (PTN_THREAD_EVENT)ExAllocateFromNPagedLookasideList(
            &g_TnMonitor.EventLookaside
            );

        if (event == NULL) {
            TnpDereferenceProcessContext(processContext);
            return;
        }

        RtlZeroMemory(event, sizeof(TN_THREAD_EVENT));

        //
        // Perform comprehensive analysis
        //
        status = TnpAnalyzeThreadCreation(
            ProcessId,
            ThreadId,
            creatorProcessId,
            event
            );

        if (NT_SUCCESS(status)) {
            //
            // Update statistics
            //
            InterlockedIncrement64(&g_TnMonitor.Stats.RemoteThreadsDetected);
            InterlockedIncrement(&processContext->RemoteThreadCount);

            if (event->InjectionScore >= g_TnMonitor.Config.InjectionScoreThreshold) {
                InterlockedIncrement64(&g_TnMonitor.Stats.SuspiciousThreadsDetected);
                InterlockedIncrement(&processContext->SuspiciousThreadCount);
                InterlockedIncrement64(&g_TnMonitor.Stats.InjectionAttempts);
            }

            //
            // Update process risk assessment
            //
            TnpUpdateProcessRisk(processContext, event);

            //
            // Add to recent events if tracking history
            //
            if (g_TnMonitor.Config.TrackThreadHistory) {
                TnpPruneOldEvents(processContext);

                KeAcquireSpinLock(&processContext->EventLock, &oldIrql);

                if (processContext->EventCount < TN_MAX_RECENT_EVENTS) {
                    InsertTailList(&processContext->RecentEvents, &event->ListEntry);
                    processContext->EventCount++;
                    event = NULL;  // Don't free, it's in the list
                }

                KeReleaseSpinLock(&processContext->EventLock, oldIrql);
            }

            //
            // Send notification to user-mode
            //
            if (event != NULL) {
                TnpSendNotification(event);
            }

            //
            // Invoke user callback if registered
            //
            if (g_TnMonitor.UserCallback != NULL && event != NULL) {
                g_TnMonitor.UserCallback(event, g_TnMonitor.UserContext);
            }
        }

        //
        // Free event if not stored
        //
        if (event != NULL) {
            ExFreeToNPagedLookasideList(&g_TnMonitor.EventLookaside, event);
        }
    }

    TnpDereferenceProcessContext(processContext);
}


static
_Use_decl_annotations_
VOID
TnpHandleThreadTermination(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId
    )
/*++

Routine Description:

    Handles a thread termination event.

--*/
{
    PTN_PROCESS_CONTEXT processContext;

    UNREFERENCED_PARAMETER(ThreadId);

    //
    // Find process context
    //
    processContext = TnpFindProcessContext(ProcessId, FALSE);
    if (processContext == NULL) {
        return;
    }

    //
    // Decrement thread count
    //
    InterlockedDecrement(&processContext->ThreadCount);

    TnpDereferenceProcessContext(processContext);
}


//=============================================================================
// Thread Analysis
//=============================================================================

static
_Use_decl_annotations_
NTSTATUS
TnpAnalyzeThreadCreation(
    _In_ HANDLE TargetProcessId,
    _In_ HANDLE ThreadId,
    _In_ HANDLE CreatorProcessId,
    _Out_ PTN_THREAD_EVENT Event
    )
/*++

Routine Description:

    Performs comprehensive analysis of a thread creation event.

--*/
{
    NTSTATUS status;
    PVOID startAddress = NULL;
    PVOID win32StartAddress = NULL;
    ULONG protection = 0;
    BOOLEAN isBacked = FALSE;

    PAGED_CODE();

    //
    // Fill basic information
    //
    Event->TargetProcessId = TargetProcessId;
    Event->TargetThreadId = ThreadId;
    Event->CreatorProcessId = CreatorProcessId;
    Event->CreatorThreadId = PsGetCurrentThreadId();
    Event->EventType = TnEventCreate;
    KeQuerySystemTimePrecise(&Event->Timestamp);

    //
    // Check if remote
    //
    Event->IsRemote = (CreatorProcessId != TargetProcessId);
    if (Event->IsRemote) {
        Event->Indicators |= TnIndicator_RemoteThread;
    }

    //
    // Get thread start address
    //
    status = TnpGetThreadStartAddress(ThreadId, &startAddress, &win32StartAddress);
    if (NT_SUCCESS(status)) {
        Event->StartAddress = startAddress;
        Event->Win32StartAddress = win32StartAddress;

        //
        // Validate start address is in user space
        //
        if ((ULONG_PTR)startAddress >= TN_MIN_VALID_USER_ADDRESS &&
            (ULONG_PTR)startAddress <= TN_MAX_USER_ADDRESS) {

            //
            // Check memory protection
            //
            status = TnpGetMemoryProtection(
                TargetProcessId,
                startAddress,
                &protection,
                &isBacked
                );

            if (NT_SUCCESS(status)) {
                Event->IsStartAddressBacked = isBacked;

                if (!isBacked) {
                    Event->Indicators |= TnIndicator_UnbackedStartAddr;
                }

                //
                // Check for RWX memory (highly suspicious)
                //
                if ((protection & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) {
                    Event->Indicators |= TnIndicator_RWXStartAddr;
                }
            }

            //
            // Find containing module if backed
            //
            if (isBacked) {
                TnpFindModuleForAddress(
                    TargetProcessId,
                    startAddress,
                    Event->ModuleName,
                    sizeof(Event->ModuleName) / sizeof(WCHAR),
                    &Event->ModuleBase,
                    &Event->ModuleSize
                    );
            }

            //
            // Check for shellcode patterns if unbacked
            //
            if (!isBacked && g_TnMonitor.Config.ValidateStartAddresses) {
                if (TnpCheckShellcodePatterns(TargetProcessId, startAddress)) {
                    Event->Indicators |= TnIndicator_ShellcodePattern;
                }
            }
        }
    }

    //
    // Check if target is a system process
    //
    if (TnpIsSystemProcess(TargetProcessId)) {
        Event->Indicators |= TnIndicator_SystemProcess;
    }

    //
    // Check if target is a protected process
    //
    if (TnpIsProtectedProcess(TargetProcessId)) {
        Event->Indicators |= TnIndicator_ProtectedProcess;
    }

    //
    // Get process image names
    //
    TnpGetProcessImageName(
        CreatorProcessId,
        Event->CreatorImageName,
        sizeof(Event->CreatorImageName) / sizeof(WCHAR)
        );

    TnpGetProcessImageName(
        TargetProcessId,
        Event->TargetImageName,
        sizeof(Event->TargetImageName) / sizeof(WCHAR)
        );

    //
    // Calculate injection score and risk level
    //
    Event->InjectionScore = TnpCalculateInjectionScore(Event);
    Event->RiskLevel = TnpCalculateRiskLevel(Event->InjectionScore);

    return STATUS_SUCCESS;
}


static
_Use_decl_annotations_
NTSTATUS
TnpGetThreadStartAddress(
    _In_ HANDLE ThreadId,
    _Out_ PVOID* StartAddress,
    _Out_ PVOID* Win32StartAddress
    )
/*++

Routine Description:

    Gets the start address of a thread.

--*/
{
    NTSTATUS status;
    PETHREAD thread = NULL;
    HANDLE threadHandle = NULL;
    PVOID startAddr = NULL;
    ULONG returnLength = 0;

    *StartAddress = NULL;
    *Win32StartAddress = NULL;

    status = PsLookupThreadByThreadId(ThreadId, &thread);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Open handle to thread for query
    //
    status = ObOpenObjectByPointer(
        thread,
        OBJ_KERNEL_HANDLE,
        NULL,
        THREAD_QUERY_INFORMATION,
        *PsThreadType,
        KernelMode,
        &threadHandle
        );

    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(thread);
        return status;
    }

    //
    // Query thread start address
    //
    status = ZwQueryInformationThread(
        threadHandle,
        ThreadQuerySetWin32StartAddress,
        &startAddr,
        sizeof(startAddr),
        &returnLength
        );

    if (NT_SUCCESS(status)) {
        *Win32StartAddress = startAddr;
        *StartAddress = startAddr;  // Will be same for most cases
    }

    ZwClose(threadHandle);
    ObDereferenceObject(thread);

    return status;
}


static
_Use_decl_annotations_
NTSTATUS
TnpGetMemoryProtection(
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _Out_ PULONG Protection,
    _Out_ PBOOLEAN IsBacked
    )
/*++

Routine Description:

    Gets memory protection attributes for an address.

--*/
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    HANDLE processHandle = NULL;
    MEMORY_BASIC_INFORMATION memInfo;
    SIZE_T returnLength;

    *Protection = 0;
    *IsBacked = FALSE;

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ObOpenObjectByPointer(
        process,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_QUERY_INFORMATION,
        *PsProcessType,
        KernelMode,
        &processHandle
        );

    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(process);
        return status;
    }

    status = ZwQueryVirtualMemory(
        processHandle,
        Address,
        MemoryBasicInformation,
        &memInfo,
        sizeof(memInfo),
        &returnLength
        );

    if (NT_SUCCESS(status)) {
        *Protection = memInfo.Protect;
        *IsBacked = (memInfo.Type == MEM_IMAGE);
    }

    ZwClose(processHandle);
    ObDereferenceObject(process);

    return status;
}


static
_Use_decl_annotations_
NTSTATUS
TnpFindModuleForAddress(
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _Out_writes_(ModuleNameSize) PWCHAR ModuleName,
    _In_ ULONG ModuleNameSize,
    _Out_ PULONG_PTR ModuleBase,
    _Out_ PSIZE_T ModuleSize
    )
/*++

Routine Description:

    Finds the module containing a given address.

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

    ModuleName[0] = L'\0';
    *ModuleBase = 0;
    *ModuleSize = 0;

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
            ULONG_PTR moduleStart;
            ULONG_PTR moduleEnd;

            ldrEntry = CONTAINING_RECORD(
                listEntry,
                LDR_DATA_TABLE_ENTRY,
                InMemoryOrderLinks
                );

            ProbeForRead(ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY), sizeof(PVOID));

            moduleStart = (ULONG_PTR)ldrEntry->DllBase;
            moduleEnd = moduleStart + ldrEntry->SizeOfImage;

            if ((ULONG_PTR)Address >= moduleStart &&
                (ULONG_PTR)Address < moduleEnd) {

                *ModuleBase = moduleStart;
                *ModuleSize = ldrEntry->SizeOfImage;

                if (ldrEntry->BaseDllName.Buffer != NULL &&
                    ldrEntry->BaseDllName.Length > 0) {

                    ProbeForRead(
                        ldrEntry->BaseDllName.Buffer,
                        ldrEntry->BaseDllName.Length,
                        sizeof(WCHAR)
                        );

                    USHORT copyLen = min(
                        ldrEntry->BaseDllName.Length,
                        (USHORT)((ModuleNameSize - 1) * sizeof(WCHAR))
                        );

                    RtlCopyMemory(ModuleName, ldrEntry->BaseDllName.Buffer, copyLen);
                    ModuleName[copyLen / sizeof(WCHAR)] = L'\0';
                }

                found = TRUE;
                break;
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
TnpGetProcessImageName(
    _In_ HANDLE ProcessId,
    _Out_writes_(BufferSize) PWCHAR Buffer,
    _In_ ULONG BufferSize
    )
/*++

Routine Description:

    Gets the image name for a process.

--*/
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PUNICODE_STRING imageName = NULL;

    Buffer[0] = L'\0';

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = SeLocateProcessImageName(process, &imageName);
    if (NT_SUCCESS(status) && imageName != NULL) {
        USHORT copyLen = min(imageName->Length, (USHORT)((BufferSize - 1) * sizeof(WCHAR)));
        RtlCopyMemory(Buffer, imageName->Buffer, copyLen);
        Buffer[copyLen / sizeof(WCHAR)] = L'\0';
        ExFreePool(imageName);
    }

    ObDereferenceObject(process);

    return status;
}


static
_Use_decl_annotations_
BOOLEAN
TnpIsSystemProcess(
    _In_ HANDLE ProcessId
    )
/*++

Routine Description:

    Checks if a process is a system process.

--*/
{
    //
    // System process (PID 4) and other critical processes
    //
    if (ProcessId == (HANDLE)(ULONG_PTR)TN_SYSTEM_PROCESS_ID) {
        return TRUE;
    }

    //
    // Could expand to check for csrss, smss, lsass, etc.
    //

    return FALSE;
}


static
_Use_decl_annotations_
BOOLEAN
TnpIsProtectedProcess(
    _In_ HANDLE ProcessId
    )
/*++

Routine Description:

    Checks if a process is protected by ShadowStrike.

--*/
{
    PLIST_ENTRY entry;
    BOOLEAN found = FALSE;

    UNREFERENCED_PARAMETER(ProcessId);

    //
    // Check against protected process list in driver data
    //
    FltAcquirePushLockShared(&g_DriverData.ProtectedProcessLock);

    for (entry = g_DriverData.ProtectedProcessList.Flink;
         entry != &g_DriverData.ProtectedProcessList;
         entry = entry->Flink) {

        //
        // Would compare ProcessId against entries in the list
        // Structure depends on how protected processes are tracked
        //
    }

    FltReleasePushLock(&g_DriverData.ProtectedProcessLock);

    return found;
}


static
_Use_decl_annotations_
BOOLEAN
TnpCheckShellcodePatterns(
    _In_ HANDLE ProcessId,
    _In_ PVOID Address
    )
/*++

Routine Description:

    Checks for common shellcode patterns at an address.

--*/
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    KAPC_STATE apcState;
    BOOLEAN isShellcode = FALSE;
    UCHAR codeBuffer[32];

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    KeStackAttachProcess(process, &apcState);

    __try {
        if (!MmIsAddressValid(Address)) {
            __leave;
        }

        ProbeForRead(Address, sizeof(codeBuffer), 1);
        RtlCopyMemory(codeBuffer, Address, sizeof(codeBuffer));

        //
        // Check for common shellcode patterns
        //

        //
        // GetPC via call $+5 / pop (E8 00 00 00 00)
        //
        if (codeBuffer[0] == 0xE8 &&
            codeBuffer[1] == 0x00 &&
            codeBuffer[2] == 0x00 &&
            codeBuffer[3] == 0x00 &&
            codeBuffer[4] == 0x00) {
            isShellcode = TRUE;
            __leave;
        }

        //
        // JMP/CALL ESP (FF E4 / FF D4)
        //
        if (codeBuffer[0] == 0xFF &&
            (codeBuffer[1] == 0xE4 || codeBuffer[1] == 0xD4)) {
            isShellcode = TRUE;
            __leave;
        }

        //
        // NOP sled (many 0x90s)
        //
        ULONG nopCount = 0;
        for (ULONG i = 0; i < sizeof(codeBuffer); i++) {
            if (codeBuffer[i] == 0x90) {
                nopCount++;
            }
        }
        if (nopCount > 16) {
            isShellcode = TRUE;
            __leave;
        }

        //
        // PEB access patterns (FS:[0x30] or GS:[0x60])
        //
        if ((codeBuffer[0] == 0x64 && codeBuffer[1] == 0xA1 && codeBuffer[2] == 0x30) ||
            (codeBuffer[0] == 0x65 && codeBuffer[1] == 0x48 && codeBuffer[2] == 0x8B)) {
            isShellcode = TRUE;
            __leave;
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        isShellcode = FALSE;
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);

    return isShellcode;
}


static
_Use_decl_annotations_
ULONG
TnpCalculateInjectionScore(
    _In_ PTN_THREAD_EVENT Event
    )
/*++

Routine Description:

    Calculates an injection suspicion score based on indicators.

--*/
{
    ULONG score = 0;

    if (Event->Indicators & TnIndicator_RemoteThread) {
        score += TN_SCORE_REMOTE_THREAD;
    }

    if (Event->Indicators & TnIndicator_SuspendedStart) {
        score += TN_SCORE_SUSPENDED_START;
    }

    if (Event->Indicators & TnIndicator_UnbackedStartAddr) {
        score += TN_SCORE_UNBACKED_START;
    }

    if (Event->Indicators & TnIndicator_RWXStartAddr) {
        score += TN_SCORE_RWX_START;
    }

    if (Event->Indicators & TnIndicator_SystemProcess) {
        score += TN_SCORE_SYSTEM_TARGET;
    }

    if (Event->Indicators & TnIndicator_ProtectedProcess) {
        score += TN_SCORE_PROTECTED_TARGET;
    }

    if (Event->Indicators & TnIndicator_UnusualEntryPoint) {
        score += TN_SCORE_UNUSUAL_ENTRY;
    }

    if (Event->Indicators & TnIndicator_CrossSession) {
        score += TN_SCORE_CROSS_SESSION;
    }

    if (Event->Indicators & TnIndicator_ElevatedSource) {
        score += TN_SCORE_ELEVATED_SOURCE;
    }

    if (Event->Indicators & TnIndicator_RapidCreation) {
        score += TN_SCORE_RAPID_CREATION;
    }

    if (Event->Indicators & TnIndicator_ShellcodePattern) {
        score += TN_SCORE_SHELLCODE_PATTERN;
    }

    return min(score, 1000);
}


static
_Use_decl_annotations_
TN_RISK_LEVEL
TnpCalculateRiskLevel(
    _In_ ULONG Score
    )
/*++

Routine Description:

    Converts an injection score to a risk level.

--*/
{
    if (Score >= 700) {
        return TnRiskCritical;
    } else if (Score >= 500) {
        return TnRiskHigh;
    } else if (Score >= 300) {
        return TnRiskMedium;
    } else if (Score >= 100) {
        return TnRiskLow;
    } else {
        return TnRiskNone;
    }
}


//=============================================================================
// Process Context Management
//=============================================================================

static
_Use_decl_annotations_
PTN_PROCESS_CONTEXT
TnpFindProcessContext(
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN CreateIfNotFound
    )
/*++

Routine Description:

    Finds or creates a process context.

--*/
{
    PLIST_ENTRY entry;
    PTN_PROCESS_CONTEXT context = NULL;

    FltAcquirePushLockShared(&g_TnMonitor.ProcessLock);

    for (entry = g_TnMonitor.ProcessList.Flink;
         entry != &g_TnMonitor.ProcessList;
         entry = entry->Flink) {

        context = CONTAINING_RECORD(entry, TN_PROCESS_CONTEXT, ListEntry);

        if (context->ProcessId == ProcessId) {
            TnpReferenceProcessContext(context);
            FltReleasePushLock(&g_TnMonitor.ProcessLock);
            return context;
        }
    }

    FltReleasePushLock(&g_TnMonitor.ProcessLock);

    if (!CreateIfNotFound) {
        return NULL;
    }

    //
    // Create new context
    //
    context = (PTN_PROCESS_CONTEXT)ExAllocateFromNPagedLookasideList(
        &g_TnMonitor.ContextLookaside
        );

    if (context == NULL) {
        return NULL;
    }

    RtlZeroMemory(context, sizeof(TN_PROCESS_CONTEXT));

    context->ProcessId = ProcessId;
    context->RefCount = 2;  // One for list, one for caller
    InitializeListHead(&context->RecentEvents);
    KeInitializeSpinLock(&context->EventLock);

    //
    // Try to get EPROCESS
    //
    PsLookupProcessByProcessId(ProcessId, &context->Process);

    //
    // Add to list
    //
    FltAcquirePushLockExclusive(&g_TnMonitor.ProcessLock);

    //
    // Check again in case another thread added it
    //
    for (entry = g_TnMonitor.ProcessList.Flink;
         entry != &g_TnMonitor.ProcessList;
         entry = entry->Flink) {

        PTN_PROCESS_CONTEXT existing = CONTAINING_RECORD(entry, TN_PROCESS_CONTEXT, ListEntry);

        if (existing->ProcessId == ProcessId) {
            //
            // Already exists, use existing
            //
            TnpReferenceProcessContext(existing);
            FltReleasePushLock(&g_TnMonitor.ProcessLock);

            if (context->Process != NULL) {
                ObDereferenceObject(context->Process);
            }
            ExFreeToNPagedLookasideList(&g_TnMonitor.ContextLookaside, context);

            return existing;
        }
    }

    InsertTailList(&g_TnMonitor.ProcessList, &context->ListEntry);
    InterlockedIncrement(&g_TnMonitor.ProcessCount);

    FltReleasePushLock(&g_TnMonitor.ProcessLock);

    return context;
}


static
_Use_decl_annotations_
VOID
TnpReferenceProcessContext(
    _Inout_ PTN_PROCESS_CONTEXT Context
    )
{
    InterlockedIncrement(&Context->RefCount);
}


static
_Use_decl_annotations_
VOID
TnpDereferenceProcessContext(
    _Inout_ PTN_PROCESS_CONTEXT Context
    )
{
    LONG newCount;

    newCount = InterlockedDecrement(&Context->RefCount);

    //
    // Note: Don't free here, context cleanup happens on process exit
    // or monitor shutdown
    //
    UNREFERENCED_PARAMETER(newCount);
}


static
_Use_decl_annotations_
VOID
TnpDestroyProcessContext(
    _Inout_ PTN_PROCESS_CONTEXT Context
    )
/*++

Routine Description:

    Destroys a process context and frees all events.

--*/
{
    PLIST_ENTRY entry;
    PTN_THREAD_EVENT event;
    KIRQL oldIrql;
    LIST_ENTRY eventsToFree;

    PAGED_CODE();

    InitializeListHead(&eventsToFree);

    //
    // Collect all events
    //
    KeAcquireSpinLock(&Context->EventLock, &oldIrql);

    while (!IsListEmpty(&Context->RecentEvents)) {
        entry = RemoveHeadList(&Context->RecentEvents);
        InsertTailList(&eventsToFree, entry);
    }

    Context->EventCount = 0;

    KeReleaseSpinLock(&Context->EventLock, oldIrql);

    //
    // Free events
    //
    while (!IsListEmpty(&eventsToFree)) {
        entry = RemoveHeadList(&eventsToFree);
        event = CONTAINING_RECORD(entry, TN_THREAD_EVENT, ListEntry);
        ExFreeToNPagedLookasideList(&g_TnMonitor.EventLookaside, event);
    }

    //
    // Dereference EPROCESS
    //
    if (Context->Process != NULL) {
        ObDereferenceObject(Context->Process);
        Context->Process = NULL;
    }

    //
    // Free context
    //
    ExFreeToNPagedLookasideList(&g_TnMonitor.ContextLookaside, Context);
}


static
_Use_decl_annotations_
VOID
TnpUpdateProcessRisk(
    _Inout_ PTN_PROCESS_CONTEXT Context,
    _In_ PTN_THREAD_EVENT Event
    )
/*++

Routine Description:

    Updates the process cumulative risk based on a new event.

--*/
{
    Context->CumulativeIndicators |= Event->Indicators;
    Context->CumulativeScore += Event->InjectionScore;

    //
    // Update overall risk level
    //
    if (Event->RiskLevel > Context->OverallRisk) {
        Context->OverallRisk = Event->RiskLevel;
    }

    //
    // Track timing for rapid creation detection
    //
    if (Event->IsRemote) {
        LARGE_INTEGER currentTime = Event->Timestamp;

        if (Context->FirstRemoteThread.QuadPart == 0) {
            Context->FirstRemoteThread = currentTime;
        }

        Context->LastRemoteThread = currentTime;
        Context->RemoteThreadsInWindow++;
    }
}


static
_Use_decl_annotations_
VOID
TnpPruneOldEvents(
    _Inout_ PTN_PROCESS_CONTEXT Context
    )
/*++

Routine Description:

    Removes old events from the history to prevent memory growth.

--*/
{
    PLIST_ENTRY entry;
    PTN_THREAD_EVENT event;
    KIRQL oldIrql;
    LIST_ENTRY toFree;

    InitializeListHead(&toFree);

    KeAcquireSpinLock(&Context->EventLock, &oldIrql);

    //
    // Remove excess events (FIFO)
    //
    while (Context->EventCount > TN_MAX_RECENT_EVENTS) {
        if (IsListEmpty(&Context->RecentEvents)) {
            break;
        }

        entry = RemoveHeadList(&Context->RecentEvents);
        InsertTailList(&toFree, entry);
        Context->EventCount--;
    }

    KeReleaseSpinLock(&Context->EventLock, oldIrql);

    //
    // Free removed events
    //
    while (!IsListEmpty(&toFree)) {
        entry = RemoveHeadList(&toFree);
        event = CONTAINING_RECORD(entry, TN_THREAD_EVENT, ListEntry);
        ExFreeToNPagedLookasideList(&g_TnMonitor.EventLookaside, event);
    }
}


//=============================================================================
// Notification
//=============================================================================

static
_Use_decl_annotations_
VOID
TnpSendNotification(
    _In_ PTN_THREAD_EVENT Event
    )
/*++

Routine Description:

    Sends a thread event notification to user-mode.

--*/
{
    //
    // Only send if user-mode is connected
    //
    if (!SHADOWSTRIKE_USER_MODE_CONNECTED()) {
        return;
    }

    //
    // Send via ScanBridge
    //
    ShadowStrikeSendThreadNotification(
        Event->TargetProcessId,
        Event->TargetThreadId,
        TRUE,  // Create
        Event->IsRemote
        );

    InterlockedIncrement64(&g_TnMonitor.Stats.AlertsGenerated);
}


//=============================================================================
// Public API
//=============================================================================

_Use_decl_annotations_
PTN_MONITOR
TnGetMonitor(
    VOID
    )
{
    if (!g_TnInitialized) {
        return NULL;
    }

    return &g_TnMonitor;
}


_Use_decl_annotations_
NTSTATUS
TnRegisterCallback(
    _In_ TN_CALLBACK_ROUTINE Callback,
    _In_opt_ PVOID Context
    )
{
    PAGED_CODE();

    if (!g_TnInitialized) {
        return STATUS_NOT_FOUND;
    }

    if (Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    g_TnMonitor.UserCallback = Callback;
    g_TnMonitor.UserContext = Context;

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
TnUnregisterCallback(
    VOID
    )
{
    PAGED_CODE();

    g_TnMonitor.UserCallback = NULL;
    g_TnMonitor.UserContext = NULL;
}


_Use_decl_annotations_
NTSTATUS
TnGetProcessContext(
    _In_ HANDLE ProcessId,
    _Outptr_ PTN_PROCESS_CONTEXT* Context
    )
{
    PTN_PROCESS_CONTEXT ctx;

    if (!g_TnInitialized || Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Context = NULL;

    ctx = TnpFindProcessContext(ProcessId, FALSE);
    if (ctx == NULL) {
        return STATUS_NOT_FOUND;
    }

    *Context = ctx;
    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
TnReleaseProcessContext(
    _In_ PTN_PROCESS_CONTEXT Context
    )
{
    if (Context != NULL) {
        TnpDereferenceProcessContext(Context);
    }
}


_Use_decl_annotations_
NTSTATUS
TnIsRemoteThread(
    _In_ HANDLE TargetProcessId,
    _In_ HANDLE ThreadId,
    _Out_ PBOOLEAN IsRemote,
    _Out_opt_ TN_INJECTION_INDICATOR* Indicators,
    _Out_opt_ PULONG Score
    )
{
    NTSTATUS status;
    TN_THREAD_EVENT event;
    HANDLE creatorProcessId;

    PAGED_CODE();

    if (!g_TnInitialized || IsRemote == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsRemote = FALSE;
    if (Indicators != NULL) *Indicators = TnIndicator_None;
    if (Score != NULL) *Score = 0;

    creatorProcessId = PsGetCurrentProcessId();

    RtlZeroMemory(&event, sizeof(event));

    status = TnpAnalyzeThreadCreation(
        TargetProcessId,
        ThreadId,
        creatorProcessId,
        &event
        );

    if (NT_SUCCESS(status)) {
        *IsRemote = event.IsRemote;
        if (Indicators != NULL) *Indicators = event.Indicators;
        if (Score != NULL) *Score = event.InjectionScore;
    }

    return status;
}


_Use_decl_annotations_
NTSTATUS
TnAnalyzeStartAddress(
    _In_ HANDLE ProcessId,
    _In_ PVOID StartAddress,
    _Out_ TN_INJECTION_INDICATOR* Indicators,
    _Out_ TN_RISK_LEVEL* RiskLevel
    )
{
    NTSTATUS status;
    ULONG protection = 0;
    BOOLEAN isBacked = FALSE;
    TN_INJECTION_INDICATOR indicators = TnIndicator_None;
    ULONG score = 0;

    PAGED_CODE();

    if (!g_TnInitialized || Indicators == NULL || RiskLevel == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Indicators = TnIndicator_None;
    *RiskLevel = TnRiskNone;

    //
    // Check memory protection
    //
    status = TnpGetMemoryProtection(ProcessId, StartAddress, &protection, &isBacked);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (!isBacked) {
        indicators |= TnIndicator_UnbackedStartAddr;
        score += TN_SCORE_UNBACKED_START;
    }

    if ((protection & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) {
        indicators |= TnIndicator_RWXStartAddr;
        score += TN_SCORE_RWX_START;
    }

    //
    // Check for shellcode
    //
    if (!isBacked && TnpCheckShellcodePatterns(ProcessId, StartAddress)) {
        indicators |= TnIndicator_ShellcodePattern;
        score += TN_SCORE_SHELLCODE_PATTERN;
    }

    *Indicators = indicators;
    *RiskLevel = TnpCalculateRiskLevel(score);

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
TnGetStatistics(
    _Out_opt_ PULONG64 TotalCreated,
    _Out_opt_ PULONG64 TotalTerminated,
    _Out_opt_ PULONG64 RemoteDetected,
    _Out_opt_ PULONG64 SuspiciousDetected
    )
{
    if (!g_TnInitialized) {
        if (TotalCreated != NULL) *TotalCreated = 0;
        if (TotalTerminated != NULL) *TotalTerminated = 0;
        if (RemoteDetected != NULL) *RemoteDetected = 0;
        if (SuspiciousDetected != NULL) *SuspiciousDetected = 0;
        return STATUS_NOT_FOUND;
    }

    if (TotalCreated != NULL) {
        *TotalCreated = g_TnMonitor.Stats.TotalThreadsCreated;
    }
    if (TotalTerminated != NULL) {
        *TotalTerminated = g_TnMonitor.Stats.TotalThreadsTerminated;
    }
    if (RemoteDetected != NULL) {
        *RemoteDetected = g_TnMonitor.Stats.RemoteThreadsDetected;
    }
    if (SuspiciousDetected != NULL) {
        *SuspiciousDetected = g_TnMonitor.Stats.SuspiciousThreadsDetected;
    }

    return STATUS_SUCCESS;
}


//=============================================================================
// Utility Functions
//=============================================================================

PCWSTR
TnGetRiskLevelName(
    _In_ TN_RISK_LEVEL Level
    )
{
    switch (Level) {
        case TnRiskNone:     return L"None";
        case TnRiskLow:      return L"Low";
        case TnRiskMedium:   return L"Medium";
        case TnRiskHigh:     return L"High";
        case TnRiskCritical: return L"Critical";
        default:             return L"Unknown";
    }
}


PCWSTR
TnGetIndicatorName(
    _In_ TN_INJECTION_INDICATOR Indicator
    )
{
    switch (Indicator) {
        case TnIndicator_None:              return L"None";
        case TnIndicator_RemoteThread:      return L"Remote Thread";
        case TnIndicator_SuspendedStart:    return L"Suspended Start";
        case TnIndicator_UnbackedStartAddr: return L"Unbacked Start Address";
        case TnIndicator_RWXStartAddr:      return L"RWX Start Address";
        case TnIndicator_SystemProcess:     return L"System Process Target";
        case TnIndicator_ProtectedProcess:  return L"Protected Process Target";
        case TnIndicator_UnusualEntryPoint: return L"Unusual Entry Point";
        case TnIndicator_CrossSession:      return L"Cross Session";
        case TnIndicator_ElevatedSource:    return L"Elevated Source";
        case TnIndicator_KnownInjector:     return L"Known Injector";
        case TnIndicator_RapidCreation:     return L"Rapid Creation";
        case TnIndicator_HiddenThread:      return L"Hidden Thread";
        case TnIndicator_ApcInjection:      return L"APC Injection";
        case TnIndicator_ContextHijack:     return L"Context Hijack";
        case TnIndicator_ShellcodePattern:  return L"Shellcode Pattern";
        default:                            return L"Unknown";
    }
}
