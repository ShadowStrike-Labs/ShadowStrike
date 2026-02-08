/*++
    ShadowStrike Next-Generation Antivirus
    Module: ThreadNotify.c

    Purpose: Enterprise-grade thread creation/termination monitoring with
             comprehensive injection detection, risk assessment, and
             behavioral analysis.

    Architecture:
    - PsSetCreateThreadNotifyRoutine callback registration
    - Per-process thread tracking with proper reference counting
    - Remote thread injection detection and scoring
    - Start address validation against loaded modules
    - Memory protection analysis for RWX detection
    - Cross-session and privilege escalation detection
    - Rapid thread creation pattern detection
    - Integration with ScanBridge for user-mode notifications
    - Proper cleanup on process termination

    Detection Capabilities:
    - CreateRemoteThread / CreateRemoteThreadEx injection
    - NtCreateThreadEx with remote handles
    - RtlCreateUserThread-based injection
    - Thread execution hijacking
    - Shellcode injection via unbacked memory
    - APC-based code execution
    - Cross-session thread injection
    - Rapid thread creation attacks

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
#pragma alloc_text(PAGE, TnNotifyProcessTermination)
#endif

//=============================================================================
// Internal Constants
//=============================================================================

#define TN_SYSTEM_PROCESS_ID            4
#define TN_MIN_VALID_USER_ADDRESS       0x10000ULL
#define TN_MAX_USER_ADDRESS             0x7FFFFFFFFFFFULL

#define TN_MAX_RECENT_EVENTS            64

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

//
// System process name hashes (FNV-1a) for fast comparison
//
#define TN_HASH_SYSTEM                  0x6E3A8D45
#define TN_HASH_CSRSS                   0x7C2B9F12
#define TN_HASH_SMSS                    0x5D1A8E34
#define TN_HASH_LSASS                   0x4F3C7D56
#define TN_HASH_SERVICES                0x8E4B6C78
#define TN_HASH_WININIT                 0x9F5D7E9A
#define TN_HASH_WINLOGON                0xAE6E8FAB
#define TN_HASH_SVCHOST                 0xBF7F9FBC

//=============================================================================
// Global State
//=============================================================================

static TN_MONITOR g_TnMonitor = { 0 };

//=============================================================================
// Forward Declarations
//=============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
VOID
TnpThreadNotifyCallback(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
    );

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
TnpInitializeMonitor(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
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
static PTN_PROCESS_CONTEXT
TnpFindProcessContextNoCreate(
    _In_ HANDLE ProcessId
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

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
TnpDestroyProcessContext(
    _Inout_ PTN_PROCESS_CONTEXT Context
    );

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
TnpRemoveProcessContextFromList(
    _In_ HANDLE ProcessId
    );

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
TnpAnalyzeThreadCreation(
    _In_ HANDLE TargetProcessId,
    _In_ HANDLE ThreadId,
    _In_ HANDLE CreatorProcessId,
    _Out_ PTN_THREAD_EVENT Event
    );

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
TnpGetThreadStartAddress(
    _In_ HANDLE ThreadId,
    _Out_ PVOID* StartAddress,
    _Out_ PVOID* Win32StartAddress
    );

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
TnpGetMemoryProtection(
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _Out_ PULONG Protection,
    _Out_ PBOOLEAN IsBacked
    );

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
TnpFindModuleForAddress(
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _Out_writes_(ModuleNameSize) PWCHAR ModuleName,
    _In_ ULONG ModuleNameSize,
    _Out_ PULONG_PTR ModuleBase,
    _Out_ PSIZE_T ModuleSize
    );

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
TnpGetProcessImageName(
    _In_ HANDLE ProcessId,
    _Out_writes_(BufferSize) PWCHAR Buffer,
    _In_ ULONG BufferSize
    );

_IRQL_requires_(PASSIVE_LEVEL)
static ULONG
TnpGetProcessSessionId(
    _In_ HANDLE ProcessId
    );

_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
TnpIsSystemProcess(
    _In_ HANDLE ProcessId
    );

_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
TnpIsProtectedProcess(
    _In_ HANDLE ProcessId
    );

_IRQL_requires_(PASSIVE_LEVEL)
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

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
TnpHandleThreadCreation(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId
    );

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
TnpHandleThreadTermination(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId
    );

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
TnpSendNotification(
    _In_ PTN_THREAD_EVENT Event
    );

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
TnpInvokeUserCallback(
    _In_ PTN_THREAD_EVENT Event
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
TnpUpdateProcessRisk(
    _Inout_ PTN_PROCESS_CONTEXT Context,
    _In_ PTN_THREAD_EVENT Event
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
TnpCheckRapidCreation(
    _Inout_ PTN_PROCESS_CONTEXT Context,
    _In_ PLARGE_INTEGER CurrentTime
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
TnpPruneOldEvents(
    _Inout_ PTN_PROCESS_CONTEXT Context
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
TnpHashProcessName(
    _In_ PCWSTR Name
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
TnpValidateProcessContext(
    _In_ PTN_PROCESS_CONTEXT Context
    );

//=============================================================================
// Inline Helpers
//=============================================================================

FORCEINLINE
BOOLEAN
TnpIsInitialized(
    VOID
    )
{
    return (InterlockedCompareExchange(&g_TnMonitor.InitState,
                                       TnStateInitialized,
                                       TnStateInitialized) == TnStateInitialized);
}

FORCEINLINE
BOOLEAN
TnpIsShuttingDown(
    VOID
    )
{
    LONG state = InterlockedCompareExchange(&g_TnMonitor.InitState, 0, 0);
    return (state == TnStateShuttingDown || state == TnStateShutdown);
}

FORCEINLINE
ULONG
TnpSafeAddScore(
    _In_ ULONG Current,
    _In_ ULONG Addition
    )
{
    ULONG result = Current + Addition;
    if (result < Current) {
        return MAXULONG;
    }
    return result;
}

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
    LONG previousState;

    PAGED_CODE();

    //
    // Atomic state transition: Uninitialized -> Initializing
    //
    previousState = InterlockedCompareExchange(
        &g_TnMonitor.InitState,
        TnStateInitializing,
        TnStateUninitialized
        );

    if (previousState != TnStateUninitialized) {
        if (previousState == TnStateInitialized) {
            return STATUS_SUCCESS;
        }
        return STATUS_DEVICE_BUSY;
    }

    //
    // Initialize the monitor infrastructure
    //
    status = TnpInitializeMonitor();
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&g_TnMonitor.InitState, TnStateUninitialized);
        return status;
    }

    //
    // Register the thread notification callback
    //
    status = PsSetCreateThreadNotifyRoutine(TnpThreadNotifyCallback);
    if (!NT_SUCCESS(status)) {
        TnpCleanupMonitor();
        InterlockedExchange(&g_TnMonitor.InitState, TnStateUninitialized);
        return status;
    }

    g_TnMonitor.CallbackRegistered = TRUE;

    //
    // Transition to initialized state
    //
    InterlockedExchange(&g_TnMonitor.InitState, TnStateInitialized);

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
    LONG previousState;

    PAGED_CODE();

    //
    // Atomic state transition: Initialized -> ShuttingDown
    //
    previousState = InterlockedCompareExchange(
        &g_TnMonitor.InitState,
        TnStateShuttingDown,
        TnStateInitialized
        );

    if (previousState != TnStateInitialized) {
        if (previousState == TnStateUninitialized ||
            previousState == TnStateShutdown) {
            return STATUS_SUCCESS;
        }
        return STATUS_DEVICE_BUSY;
    }

    //
    // Memory barrier to ensure all CPUs see the shutdown state
    //
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

    //
    // Transition to shutdown state
    //
    InterlockedExchange(&g_TnMonitor.InitState, TnStateShutdown);

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
    ExInitializePushLock(&g_TnMonitor.ProcessLock);
    g_TnMonitor.ProcessCount = 0;

    //
    // Initialize callback lock
    //
    ExInitializePushLock(&g_TnMonitor.CallbackLock);
    g_TnMonitor.CallbackEntry = NULL;

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &g_TnMonitor.EventLookaside,
        NULL,
        NULL,
        POOL_NX_OPTIN,
        sizeof(TN_THREAD_EVENT),
        TN_POOL_TAG_EVENT,
        0
        );

    ExInitializeNPagedLookasideList(
        &g_TnMonitor.ContextLookaside,
        NULL,
        NULL,
        POOL_NX_OPTIN,
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
    g_TnMonitor.Config.DetectCrossSession = TRUE;
    g_TnMonitor.Config.DetectRapidCreation = TRUE;
    g_TnMonitor.Config.InjectionScoreThreshold = TN_INJECTION_SCORE_THRESHOLD;
    g_TnMonitor.Config.DefaultAction = TnActionAlert;

    //
    // Initialize statistics
    //
    KeQuerySystemTimePrecise(&g_TnMonitor.Stats.StartTime);

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
    PTN_CALLBACK_ENTRY callbackEntry;

    PAGED_CODE();

    InitializeListHead(&contextsToFree);

    //
    // Free callback entry if present
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_TnMonitor.CallbackLock);

    callbackEntry = g_TnMonitor.CallbackEntry;
    g_TnMonitor.CallbackEntry = NULL;

    ExReleasePushLockExclusive(&g_TnMonitor.CallbackLock);
    KeLeaveCriticalRegion();

    if (callbackEntry != NULL) {
        ExFreePoolWithTag(callbackEntry, TN_POOL_TAG);
    }

    //
    // Collect all process contexts
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_TnMonitor.ProcessLock);

    while (!IsListEmpty(&g_TnMonitor.ProcessList)) {
        entry = RemoveHeadList(&g_TnMonitor.ProcessList);
        context = CONTAINING_RECORD(entry, TN_PROCESS_CONTEXT, ListEntry);

        //
        // Mark as destroying to prevent concurrent access
        //
        InterlockedExchange(&context->Destroying, TRUE);
        InsertTailList(&contextsToFree, entry);
    }

    g_TnMonitor.ProcessCount = 0;

    ExReleasePushLockExclusive(&g_TnMonitor.ProcessLock);
    KeLeaveCriticalRegion();

    //
    // Free all contexts outside the lock
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

_Use_decl_annotations_
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
    PAGED_CODE();

    //
    // Check if driver is ready to process requests
    //
    if (!SHADOWSTRIKE_IS_READY()) {
        return;
    }

    if (!TnpIsInitialized() || TnpIsShuttingDown()) {
        return;
    }

    //
    // Validate parameters
    //
    if (ProcessId == NULL || ThreadId == NULL) {
        return;
    }

    //
    // Track operation for clean shutdown
    //
    SHADOWSTRIKE_ENTER_OPERATION();

    if (Create) {
        InterlockedIncrement64(&g_TnMonitor.Stats.TotalThreadsCreated);
        TnpHandleThreadCreation(ProcessId, ThreadId);
    } else {
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
    BOOLEAN eventStoredInList = FALSE;

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
    // Validate context
    //
    if (!TnpValidateProcessContext(processContext)) {
        TnpDereferenceProcessContext(processContext);
        return;
    }

    //
    // Increment thread count with underflow protection
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
            // CRITICAL FIX: Send notifications BEFORE potentially storing in list
            // This ensures all suspicious events trigger alerts
            //
            TnpSendNotification(event);
            TnpInvokeUserCallback(event);

            //
            // Add to recent events if tracking history
            //
            if (g_TnMonitor.Config.TrackThreadHistory) {
                TnpPruneOldEvents(processContext);

                KeAcquireSpinLock(&processContext->EventLock, &oldIrql);

                if (processContext->EventCount < TN_MAX_RECENT_EVENTS &&
                    !processContext->Destroying) {
                    InsertTailList(&processContext->RecentEvents, &event->ListEntry);
                    processContext->EventCount++;
                    eventStoredInList = TRUE;
                }

                KeReleaseSpinLock(&processContext->EventLock, oldIrql);
            }
        }

        //
        // Free event if not stored in list
        //
        if (!eventStoredInList && event != NULL) {
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
    LONG newCount;

    UNREFERENCED_PARAMETER(ThreadId);

    //
    // Find process context (don't create if not found)
    //
    processContext = TnpFindProcessContextNoCreate(ProcessId);
    if (processContext == NULL) {
        return;
    }

    //
    // Decrement thread count with underflow protection
    //
    newCount = InterlockedDecrement(&processContext->ThreadCount);
    if (newCount < 0) {
        //
        // Underflow detected - thread existed before we started tracking
        // Clamp to zero
        //
        InterlockedCompareExchange(&processContext->ThreadCount, 0, newCount);
    }

    TnpDereferenceProcessContext(processContext);
}


//=============================================================================
// Process Termination Cleanup
//=============================================================================

_Use_decl_annotations_
VOID
TnNotifyProcessTermination(
    _In_ HANDLE ProcessId
    )
/*++

Routine Description:

    Called by process notify callback to clean up thread tracking state
    for a terminating process.

--*/
{
    PAGED_CODE();

    if (!TnpIsInitialized()) {
        return;
    }

    TnpRemoveProcessContextFromList(ProcessId);
}


static
_Use_decl_annotations_
VOID
TnpRemoveProcessContextFromList(
    _In_ HANDLE ProcessId
    )
/*++

Routine Description:

    Removes a process context from the global list and schedules destruction.

--*/
{
    PLIST_ENTRY entry;
    PTN_PROCESS_CONTEXT context = NULL;
    BOOLEAN found = FALSE;

    PAGED_CODE();

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_TnMonitor.ProcessLock);

    for (entry = g_TnMonitor.ProcessList.Flink;
         entry != &g_TnMonitor.ProcessList;
         entry = entry->Flink) {

        context = CONTAINING_RECORD(entry, TN_PROCESS_CONTEXT, ListEntry);

        if (context->ProcessId == ProcessId) {
            //
            // Mark as destroying
            //
            InterlockedExchange(&context->Destroying, TRUE);

            //
            // Remove from list
            //
            RemoveEntryList(entry);
            InterlockedDecrement(&g_TnMonitor.ProcessCount);
            found = TRUE;
            break;
        }
    }

    ExReleasePushLockExclusive(&g_TnMonitor.ProcessLock);
    KeLeaveCriticalRegion();

    //
    // Dereference outside the lock (this removes the "list" reference)
    //
    if (found && context != NULL) {
        TnpDereferenceProcessContext(context);
    }
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
    ULONG creatorSessionId;
    ULONG targetSessionId;

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
    // Get session IDs for cross-session detection
    //
    if (g_TnMonitor.Config.DetectCrossSession) {
        creatorSessionId = TnpGetProcessSessionId(CreatorProcessId);
        targetSessionId = TnpGetProcessSessionId(TargetProcessId);

        Event->CreatorSessionId = creatorSessionId;
        Event->TargetSessionId = targetSessionId;

        if (Event->IsRemote && creatorSessionId != targetSessionId) {
            Event->Indicators |= TnIndicator_CrossSession;
            InterlockedIncrement64(&g_TnMonitor.Stats.CrossSessionDetected);
        }
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

    //
    // Validate ThreadId
    //
    if (ThreadId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

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
        *StartAddress = startAddr;
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

    //
    // Validate ProcessId
    //
    if (ProcessId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

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
    Includes loop bounds to prevent infinite loops from corrupted lists.

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
    ULONG iterationCount = 0;

    ModuleName[0] = L'\0';
    *ModuleBase = 0;
    *ModuleSize = 0;

    if (ProcessId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

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

        //
        // SECURITY FIX: Bounded loop to prevent DoS from corrupted lists
        //
        while (listEntry != listHead &&
               iterationCount < TN_MAX_MODULE_WALK_ITERATIONS) {

            PLDR_DATA_TABLE_ENTRY ldrEntry;
            ULONG_PTR moduleStart;
            ULONG_PTR moduleEnd;

            iterationCount++;

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

        if (iterationCount >= TN_MAX_MODULE_WALK_ITERATIONS) {
            //
            // Possible corrupted list - log and return error
            //
            status = STATUS_DATA_ERROR;
        } else {
            status = found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
        }

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

    if (ProcessId == NULL || BufferSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

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
ULONG
TnpGetProcessSessionId(
    _In_ HANDLE ProcessId
    )
/*++

Routine Description:

    Gets the session ID for a process.

--*/
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    ULONG sessionId = 0;

    if (ProcessId == NULL) {
        return 0;
    }

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (NT_SUCCESS(status)) {
        sessionId = PsGetProcessSessionId(process);
        ObDereferenceObject(process);
    }

    return sessionId;
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
    Uses image name comparison for critical system processes.

--*/
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PUNICODE_STRING imageName = NULL;
    BOOLEAN isSystem = FALSE;
    WCHAR nameBuffer[64];
    ULONG hash;

    //
    // System process (PID 4)
    //
    if (ProcessId == (HANDLE)(ULONG_PTR)TN_SYSTEM_PROCESS_ID) {
        return TRUE;
    }

    if (ProcessId == NULL) {
        return FALSE;
    }

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    //
    // Check if running as SYSTEM
    //
    if (PsIsSystemProcess(process)) {
        ObDereferenceObject(process);
        return TRUE;
    }

    //
    // Get image name and check against known system process names
    //
    status = SeLocateProcessImageName(process, &imageName);
    if (NT_SUCCESS(status) && imageName != NULL && imageName->Buffer != NULL) {
        //
        // Extract just the filename
        //
        PWCHAR fileName = imageName->Buffer;
        PWCHAR lastSlash = wcsrchr(imageName->Buffer, L'\\');
        if (lastSlash != NULL) {
            fileName = lastSlash + 1;
        }

        //
        // Copy to local buffer for safe manipulation
        //
        SIZE_T len = wcslen(fileName);
        if (len < ARRAYSIZE(nameBuffer)) {
            RtlCopyMemory(nameBuffer, fileName, (len + 1) * sizeof(WCHAR));

            //
            // Convert to lowercase for comparison
            //
            _wcslwr(nameBuffer);

            //
            // Check against known system processes
            //
            if (wcscmp(nameBuffer, L"csrss.exe") == 0 ||
                wcscmp(nameBuffer, L"smss.exe") == 0 ||
                wcscmp(nameBuffer, L"lsass.exe") == 0 ||
                wcscmp(nameBuffer, L"services.exe") == 0 ||
                wcscmp(nameBuffer, L"wininit.exe") == 0 ||
                wcscmp(nameBuffer, L"winlogon.exe") == 0 ||
                wcscmp(nameBuffer, L"lsaiso.exe") == 0 ||
                wcscmp(nameBuffer, L"spoolsv.exe") == 0 ||
                wcscmp(nameBuffer, L"dwm.exe") == 0) {
                isSystem = TRUE;
            }
        }

        ExFreePool(imageName);
    }

    ObDereferenceObject(process);

    return isSystem;
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

    if (ProcessId == NULL) {
        return FALSE;
    }

    //
    // Check against protected process list in driver data
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_DriverData.ProtectedProcessLock);

    for (entry = g_DriverData.ProtectedProcessList.Flink;
         entry != &g_DriverData.ProtectedProcessList;
         entry = entry->Flink) {

        PPROTECTED_PROCESS_ENTRY protectedEntry =
            CONTAINING_RECORD(entry, PROTECTED_PROCESS_ENTRY, ListEntry);

        if (protectedEntry->ProcessId == ProcessId) {
            found = TRUE;
            break;
        }
    }

    ExReleasePushLockShared(&g_DriverData.ProtectedProcessLock);
    KeLeaveCriticalRegion();

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
    NOTE: This is a heuristic detection that can be bypassed by
    sophisticated attackers. It serves as a first-pass filter.

--*/
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    KAPC_STATE apcState;
    BOOLEAN isShellcode = FALSE;
    UCHAR codeBuffer[64];  // Increased buffer for better detection

    if (ProcessId == NULL || Address == NULL) {
        return FALSE;
    }

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    KeStackAttachProcess(process, &apcState);

    __try {
        //
        // SECURITY FIX: Removed MmIsAddressValid - rely on SEH
        // MmIsAddressValid is fundamentally unsafe for security decisions
        //

        ProbeForRead(Address, sizeof(codeBuffer), 1);
        RtlCopyMemory(codeBuffer, Address, sizeof(codeBuffer));

        //
        // Check for common shellcode patterns
        //

        //
        // Pattern 1: GetPC via call $+5 / pop (E8 00 00 00 00 5x)
        //
        if (codeBuffer[0] == 0xE8 &&
            codeBuffer[1] == 0x00 &&
            codeBuffer[2] == 0x00 &&
            codeBuffer[3] == 0x00 &&
            codeBuffer[4] == 0x00 &&
            (codeBuffer[5] >= 0x58 && codeBuffer[5] <= 0x5F)) {
            isShellcode = TRUE;
            __leave;
        }

        //
        // Pattern 2: JMP/CALL ESP (FF E4 / FF D4)
        //
        if (codeBuffer[0] == 0xFF &&
            (codeBuffer[1] == 0xE4 || codeBuffer[1] == 0xD4)) {
            isShellcode = TRUE;
            __leave;
        }

        //
        // Pattern 3: JMP/CALL EAX (FF E0 / FF D0)
        //
        if (codeBuffer[0] == 0xFF &&
            (codeBuffer[1] == 0xE0 || codeBuffer[1] == 0xD0)) {
            isShellcode = TRUE;
            __leave;
        }

        //
        // Pattern 4: NOP sled detection (many consecutive NOPs)
        //
        ULONG nopCount = 0;
        for (ULONG i = 0; i < sizeof(codeBuffer); i++) {
            if (codeBuffer[i] == 0x90) {
                nopCount++;
            }
        }
        if (nopCount > 20) {  // More than 20 NOPs is suspicious
            isShellcode = TRUE;
            __leave;
        }

        //
        // Pattern 5: x86 PEB access (FS:[0x30])
        //
        if (codeBuffer[0] == 0x64 &&
            codeBuffer[1] == 0xA1 &&
            codeBuffer[2] == 0x30 &&
            codeBuffer[3] == 0x00 &&
            codeBuffer[4] == 0x00 &&
            codeBuffer[5] == 0x00) {
            isShellcode = TRUE;
            __leave;
        }

        //
        // Pattern 6: x64 PEB access (GS:[0x60])
        //
        if (codeBuffer[0] == 0x65 &&
            codeBuffer[1] == 0x48 &&
            codeBuffer[2] == 0x8B &&
            (codeBuffer[3] == 0x04 || codeBuffer[3] == 0x0C) &&
            codeBuffer[4] == 0x25 &&
            codeBuffer[5] == 0x60) {
            isShellcode = TRUE;
            __leave;
        }

        //
        // Pattern 7: LEA-based GetPC (48 8D 05 / E8 followed by add/sub)
        //
        if (codeBuffer[0] == 0x48 &&
            codeBuffer[1] == 0x8D &&
            codeBuffer[2] == 0x05) {
            // Relative LEA in x64 - check if followed by suspicious ops
            if (codeBuffer[7] == 0x48 && codeBuffer[8] == 0x83) {
                isShellcode = TRUE;
                __leave;
            }
        }

        //
        // Pattern 8: XOR reg, reg followed by PUSH/POP sequence
        //
        if ((codeBuffer[0] == 0x31 || codeBuffer[0] == 0x33) &&
            (codeBuffer[1] & 0xC0) == 0xC0) {  // XOR reg, reg
            ULONG pushCount = 0;
            for (ULONG i = 2; i < 16; i++) {
                if (codeBuffer[i] >= 0x50 && codeBuffer[i] <= 0x57) {
                    pushCount++;
                }
            }
            if (pushCount >= 4) {
                isShellcode = TRUE;
                __leave;
            }
        }

        //
        // Pattern 9: SYSCALL/SYSENTER direct invocation
        //
        for (ULONG i = 0; i < sizeof(codeBuffer) - 1; i++) {
            if ((codeBuffer[i] == 0x0F && codeBuffer[i+1] == 0x05) ||  // SYSCALL
                (codeBuffer[i] == 0x0F && codeBuffer[i+1] == 0x34)) {  // SYSENTER
                isShellcode = TRUE;
                __leave;
            }
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
        score = TnpSafeAddScore(score, TN_SCORE_REMOTE_THREAD);
    }

    if (Event->Indicators & TnIndicator_SuspendedStart) {
        score = TnpSafeAddScore(score, TN_SCORE_SUSPENDED_START);
    }

    if (Event->Indicators & TnIndicator_UnbackedStartAddr) {
        score = TnpSafeAddScore(score, TN_SCORE_UNBACKED_START);
    }

    if (Event->Indicators & TnIndicator_RWXStartAddr) {
        score = TnpSafeAddScore(score, TN_SCORE_RWX_START);
    }

    if (Event->Indicators & TnIndicator_SystemProcess) {
        score = TnpSafeAddScore(score, TN_SCORE_SYSTEM_TARGET);
    }

    if (Event->Indicators & TnIndicator_ProtectedProcess) {
        score = TnpSafeAddScore(score, TN_SCORE_PROTECTED_TARGET);
    }

    if (Event->Indicators & TnIndicator_UnusualEntryPoint) {
        score = TnpSafeAddScore(score, TN_SCORE_UNUSUAL_ENTRY);
    }

    if (Event->Indicators & TnIndicator_CrossSession) {
        score = TnpSafeAddScore(score, TN_SCORE_CROSS_SESSION);
    }

    if (Event->Indicators & TnIndicator_ElevatedSource) {
        score = TnpSafeAddScore(score, TN_SCORE_ELEVATED_SOURCE);
    }

    if (Event->Indicators & TnIndicator_RapidCreation) {
        score = TnpSafeAddScore(score, TN_SCORE_RAPID_CREATION);
    }

    if (Event->Indicators & TnIndicator_ShellcodePattern) {
        score = TnpSafeAddScore(score, TN_SCORE_SHELLCODE_PATTERN);
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
BOOLEAN
TnpValidateProcessContext(
    _In_ PTN_PROCESS_CONTEXT Context
    )
/*++

Routine Description:

    Validates a process context structure.

--*/
{
    if (Context == NULL) {
        return FALSE;
    }

    if (Context->Signature != TN_PROCESS_CONTEXT_SIGNATURE) {
        return FALSE;
    }

    if (Context->Destroying) {
        return FALSE;
    }

    return TRUE;
}


static
_Use_decl_annotations_
PTN_PROCESS_CONTEXT
TnpFindProcessContextNoCreate(
    _In_ HANDLE ProcessId
    )
/*++

Routine Description:

    Finds a process context without creating one if not found.

--*/
{
    PLIST_ENTRY entry;
    PTN_PROCESS_CONTEXT context = NULL;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_TnMonitor.ProcessLock);

    for (entry = g_TnMonitor.ProcessList.Flink;
         entry != &g_TnMonitor.ProcessList;
         entry = entry->Flink) {

        context = CONTAINING_RECORD(entry, TN_PROCESS_CONTEXT, ListEntry);

        if (context->ProcessId == ProcessId && !context->Destroying) {
            TnpReferenceProcessContext(context);
            ExReleasePushLockShared(&g_TnMonitor.ProcessLock);
            KeLeaveCriticalRegion();
            return context;
        }
    }

    ExReleasePushLockShared(&g_TnMonitor.ProcessLock);
    KeLeaveCriticalRegion();

    return NULL;
}


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
    PTN_PROCESS_CONTEXT newContext = NULL;
    NTSTATUS status;

    //
    // First try shared lock for lookup
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_TnMonitor.ProcessLock);

    for (entry = g_TnMonitor.ProcessList.Flink;
         entry != &g_TnMonitor.ProcessList;
         entry = entry->Flink) {

        context = CONTAINING_RECORD(entry, TN_PROCESS_CONTEXT, ListEntry);

        if (context->ProcessId == ProcessId && !context->Destroying) {
            TnpReferenceProcessContext(context);
            ExReleasePushLockShared(&g_TnMonitor.ProcessLock);
            KeLeaveCriticalRegion();
            return context;
        }
    }

    ExReleasePushLockShared(&g_TnMonitor.ProcessLock);
    KeLeaveCriticalRegion();

    if (!CreateIfNotFound) {
        return NULL;
    }

    //
    // Check process limit before allocating
    //
    if (g_TnMonitor.ProcessCount >= TN_MAX_TRACKED_PROCESSES) {
        return NULL;
    }

    //
    // Allocate new context
    //
    newContext = (PTN_PROCESS_CONTEXT)ExAllocateFromNPagedLookasideList(
        &g_TnMonitor.ContextLookaside
        );

    if (newContext == NULL) {
        return NULL;
    }

    RtlZeroMemory(newContext, sizeof(TN_PROCESS_CONTEXT));

    newContext->Signature = TN_PROCESS_CONTEXT_SIGNATURE;
    newContext->ProcessId = ProcessId;
    newContext->RefCount = 2;  // One for list, one for caller
    newContext->Destroying = FALSE;
    InitializeListHead(&newContext->RecentEvents);
    KeInitializeSpinLock(&newContext->EventLock);

    //
    // Try to get EPROCESS and session ID
    //
    status = PsLookupProcessByProcessId(ProcessId, &newContext->Process);
    if (NT_SUCCESS(status)) {
        newContext->SessionId = PsGetProcessSessionId(newContext->Process);
    }

    //
    // Acquire exclusive lock to add to list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_TnMonitor.ProcessLock);

    //
    // Check again in case another thread added it
    //
    for (entry = g_TnMonitor.ProcessList.Flink;
         entry != &g_TnMonitor.ProcessList;
         entry = entry->Flink) {

        PTN_PROCESS_CONTEXT existing = CONTAINING_RECORD(entry, TN_PROCESS_CONTEXT, ListEntry);

        if (existing->ProcessId == ProcessId && !existing->Destroying) {
            //
            // Already exists, use existing
            //
            TnpReferenceProcessContext(existing);
            ExReleasePushLockExclusive(&g_TnMonitor.ProcessLock);
            KeLeaveCriticalRegion();

            if (newContext->Process != NULL) {
                ObDereferenceObject(newContext->Process);
            }
            ExFreeToNPagedLookasideList(&g_TnMonitor.ContextLookaside, newContext);

            return existing;
        }
    }

    //
    // Re-check process limit under exclusive lock
    //
    if (g_TnMonitor.ProcessCount >= TN_MAX_TRACKED_PROCESSES) {
        ExReleasePushLockExclusive(&g_TnMonitor.ProcessLock);
        KeLeaveCriticalRegion();

        if (newContext->Process != NULL) {
            ObDereferenceObject(newContext->Process);
        }
        ExFreeToNPagedLookasideList(&g_TnMonitor.ContextLookaside, newContext);
        return NULL;
    }

    InsertTailList(&g_TnMonitor.ProcessList, &newContext->ListEntry);
    InterlockedIncrement(&g_TnMonitor.ProcessCount);

    ExReleasePushLockExclusive(&g_TnMonitor.ProcessLock);
    KeLeaveCriticalRegion();

    return newContext;
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
/*++

Routine Description:

    Decrements reference count and destroys context when it reaches zero.

--*/
{
    LONG newCount;

    if (Context == NULL) {
        return;
    }

    newCount = InterlockedDecrement(&Context->RefCount);

    if (newCount == 0) {
        //
        // Context is no longer referenced - destroy it
        // Note: Context should already be removed from list at this point
        //
        TnpDestroyProcessContext(Context);
    } else if (newCount < 0) {
        //
        // Bug detection - this should never happen
        //
        NT_ASSERT(FALSE);
    }
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

    if (Context == NULL) {
        return;
    }

    //
    // Mark as destroying
    //
    InterlockedExchange(&Context->Destroying, TRUE);

    InitializeListHead(&eventsToFree);

    //
    // Collect all events under spinlock
    //
    KeAcquireSpinLock(&Context->EventLock, &oldIrql);

    while (!IsListEmpty(&Context->RecentEvents)) {
        entry = RemoveHeadList(&Context->RecentEvents);
        InsertTailList(&eventsToFree, entry);
    }

    Context->EventCount = 0;

    KeReleaseSpinLock(&Context->EventLock, oldIrql);

    //
    // Free events outside spinlock
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
    // Invalidate signature
    //
    Context->Signature = 0;

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
    Includes overflow protection and rapid creation detection.

--*/
{
    ULONG currentScore;
    ULONG newScore;

    Context->CumulativeIndicators |= Event->Indicators;

    //
    // Safe score addition with overflow protection
    //
    do {
        currentScore = Context->CumulativeScore;
        newScore = TnpSafeAddScore(currentScore, Event->InjectionScore);
    } while (InterlockedCompareExchange(
                (PLONG)&Context->CumulativeScore,
                newScore,
                currentScore) != (LONG)currentScore);

    //
    // Update overall risk level
    //
    if (Event->RiskLevel > Context->OverallRisk) {
        Context->OverallRisk = Event->RiskLevel;
    }

    //
    // Check for rapid creation pattern
    //
    if (Event->IsRemote && g_TnMonitor.Config.DetectRapidCreation) {
        if (TnpCheckRapidCreation(Context, &Event->Timestamp)) {
            //
            // Update event indicators
            //
            Event->Indicators |= TnIndicator_RapidCreation;
            Event->InjectionScore = TnpCalculateInjectionScore(Event);
            Event->RiskLevel = TnpCalculateRiskLevel(Event->InjectionScore);

            InterlockedIncrement64(&g_TnMonitor.Stats.RapidCreationDetected);
        }

        Context->LastRemoteThread = Event->Timestamp;
    }
}


static
_Use_decl_annotations_
BOOLEAN
TnpCheckRapidCreation(
    _Inout_ PTN_PROCESS_CONTEXT Context,
    _In_ PLARGE_INTEGER CurrentTime
    )
/*++

Routine Description:

    Checks if threads are being created rapidly (potential attack).

--*/
{
    LARGE_INTEGER windowStart;
    LONG threadsInWindow;

    //
    // Calculate window start time
    //
    windowStart.QuadPart = CurrentTime->QuadPart - TN_RAPID_THREAD_WINDOW_100NS;

    //
    // Check if we need to reset the window
    //
    if (Context->WindowStart.QuadPart < windowStart.QuadPart ||
        Context->WindowStart.QuadPart == 0) {
        //
        // Start new window
        //
        Context->WindowStart = *CurrentTime;
        InterlockedExchange(&Context->RemoteThreadsInWindow, 1);
        return FALSE;
    }

    //
    // Increment count in current window
    //
    threadsInWindow = InterlockedIncrement(&Context->RemoteThreadsInWindow);

    //
    // Check threshold
    //
    return (threadsInWindow >= TN_RAPID_THREAD_THRESHOLD);
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
    while (Context->EventCount >= TN_MAX_RECENT_EVENTS) {
        if (IsListEmpty(&Context->RecentEvents)) {
            break;
        }

        entry = RemoveHeadList(&Context->RecentEvents);
        InsertTailList(&toFree, entry);
        Context->EventCount--;
    }

    KeReleaseSpinLock(&Context->EventLock, oldIrql);

    //
    // Free removed events outside spinlock
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
    PAGED_CODE();

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


static
_Use_decl_annotations_
VOID
TnpInvokeUserCallback(
    _In_ PTN_THREAD_EVENT Event
    )
/*++

Routine Description:

    Safely invokes the user callback with proper synchronization.

--*/
{
    PTN_CALLBACK_ENTRY callbackEntry;
    TN_CALLBACK_ROUTINE callback;
    PVOID context;

    PAGED_CODE();

    //
    // SECURITY FIX: Safe callback invocation with reference counting
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_TnMonitor.CallbackLock);

    callbackEntry = g_TnMonitor.CallbackEntry;
    if (callbackEntry != NULL) {
        InterlockedIncrement(&callbackEntry->RefCount);
    }

    ExReleasePushLockShared(&g_TnMonitor.CallbackLock);
    KeLeaveCriticalRegion();

    if (callbackEntry == NULL) {
        return;
    }

    //
    // Invoke callback outside the lock
    //
    callback = callbackEntry->Callback;
    context = callbackEntry->Context;

    if (callback != NULL) {
        callback(Event, context);
    }

    //
    // Release reference
    //
    InterlockedDecrement(&callbackEntry->RefCount);
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
    if (!TnpIsInitialized()) {
        return NULL;
    }

    return &g_TnMonitor;
}


_Use_decl_annotations_
BOOLEAN
TnIsReady(
    VOID
    )
{
    return TnpIsInitialized() && !TnpIsShuttingDown();
}


_Use_decl_annotations_
NTSTATUS
TnRegisterCallback(
    _In_ TN_CALLBACK_ROUTINE Callback,
    _In_opt_ PVOID Context
    )
{
    PTN_CALLBACK_ENTRY newEntry;
    PTN_CALLBACK_ENTRY oldEntry;

    PAGED_CODE();

    if (!TnpIsInitialized()) {
        return STATUS_NOT_FOUND;
    }

    if (Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Allocate new callback entry
    //
    newEntry = (PTN_CALLBACK_ENTRY)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(TN_CALLBACK_ENTRY),
        TN_POOL_TAG
        );

    if (newEntry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    newEntry->Callback = Callback;
    newEntry->Context = Context;
    newEntry->RefCount = 1;

    //
    // Swap with existing entry
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_TnMonitor.CallbackLock);

    oldEntry = g_TnMonitor.CallbackEntry;
    g_TnMonitor.CallbackEntry = newEntry;

    ExReleasePushLockExclusive(&g_TnMonitor.CallbackLock);
    KeLeaveCriticalRegion();

    //
    // Wait for old entry references to drain and free
    //
    if (oldEntry != NULL) {
        while (oldEntry->RefCount > 0) {
            YieldProcessor();
        }
        ExFreePoolWithTag(oldEntry, TN_POOL_TAG);
    }

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
TnUnregisterCallback(
    VOID
    )
{
    PTN_CALLBACK_ENTRY oldEntry;

    PAGED_CODE();

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_TnMonitor.CallbackLock);

    oldEntry = g_TnMonitor.CallbackEntry;
    g_TnMonitor.CallbackEntry = NULL;

    ExReleasePushLockExclusive(&g_TnMonitor.CallbackLock);
    KeLeaveCriticalRegion();

    if (oldEntry != NULL) {
        //
        // Wait for references to drain
        //
        while (oldEntry->RefCount > 0) {
            YieldProcessor();
        }
        ExFreePoolWithTag(oldEntry, TN_POOL_TAG);
    }
}


_Use_decl_annotations_
NTSTATUS
TnGetProcessContext(
    _In_ HANDLE ProcessId,
    _Outptr_ PTN_PROCESS_CONTEXT* Context
    )
{
    PTN_PROCESS_CONTEXT ctx;

    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Context = NULL;

    if (!TnpIsInitialized()) {
        return STATUS_NOT_FOUND;
    }

    if (ProcessId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    ctx = TnpFindProcessContextNoCreate(ProcessId);
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

    if (IsRemote == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsRemote = FALSE;
    if (Indicators != NULL) *Indicators = TnIndicator_None;
    if (Score != NULL) *Score = 0;

    if (!TnpIsInitialized()) {
        return STATUS_NOT_FOUND;
    }

    if (TargetProcessId == NULL || ThreadId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

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

    if (Indicators == NULL || RiskLevel == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Indicators = TnIndicator_None;
    *RiskLevel = TnRiskNone;

    if (!TnpIsInitialized()) {
        return STATUS_NOT_FOUND;
    }

    if (ProcessId == NULL || StartAddress == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Check memory protection
    //
    status = TnpGetMemoryProtection(ProcessId, StartAddress, &protection, &isBacked);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (!isBacked) {
        indicators |= TnIndicator_UnbackedStartAddr;
        score = TnpSafeAddScore(score, TN_SCORE_UNBACKED_START);
    }

    if ((protection & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) {
        indicators |= TnIndicator_RWXStartAddr;
        score = TnpSafeAddScore(score, TN_SCORE_RWX_START);
    }

    //
    // Check for shellcode
    //
    if (!isBacked && TnpCheckShellcodePatterns(ProcessId, StartAddress)) {
        indicators |= TnIndicator_ShellcodePattern;
        score = TnpSafeAddScore(score, TN_SCORE_SHELLCODE_PATTERN);
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
    if (!TnpIsInitialized()) {
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

_Use_decl_annotations_
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


_Use_decl_annotations_
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
