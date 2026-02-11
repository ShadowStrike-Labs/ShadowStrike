/*++
    ShadowStrike Next-Generation Antivirus
    Module: AntiDebug.c - Anti-debugging detection & alerting implementation

    Architecture:
    - All synchronization via EX_PUSH_LOCK (IRQL <= APC_LEVEL).
    - EX_RUNDOWN_REF drains all in-flight API calls before shutdown.
    - Periodic detection runs in a work item (queued by a DPC timer).
    - Events are stored as internal ADB_EVENT nodes on a capped list.
    - Callers receive ADB_EVENT_INFO value-type copies (no internal pointers).
    - Detect-and-alert model only. This module does NOT and CANNOT block
      kernel debugger attachment.

    Copyright (c) ShadowStrike Team
--*/

#include "AntiDebug.h"
#include <ntifs.h>       // PsGetProcessImageFileName
#include <ntstrsafe.h>
#include <intrin.h>

// ============================================================================
// INTERNAL TYPES
// ============================================================================

//
// Internal event node — lives on Protector->EventList.
// Never returned to callers. Contains LIST_ENTRY linkage.
//
typedef struct _ADB_EVENT {
    LIST_ENTRY          ListEntry;
    ADB_DEBUG_ATTEMPT   Type;
    HANDLE              ProcessId;
    WCHAR               ProcessName[ADB_MAX_PROCESS_NAME];
    USHORT              ProcessNameLength;
    CHAR                Details[ADB_MAX_DETAIL_LENGTH];
    LARGE_INTEGER       Timestamp;
    BOOLEAN             WasBlocked;
} ADB_EVENT, *PADB_EVENT;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static VOID AdbpTimerDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

static
IO_WORKITEM_ROUTINE AdbpPeriodicCheckWorker;

static BOOLEAN AdbpDetectKernelDebugger(VOID);
static BOOLEAN AdbpDetectHypervisor(VOID);
static BOOLEAN AdbpDetectDriverVerifier(_In_ PADB_PROTECTOR Protector);
static BOOLEAN AdbpDetectUserDebugger(VOID);
static BOOLEAN AdbpDetectCrashDumpConfig(VOID);

static VOID AdbpRecordEvent(
    _In_ PADB_PROTECTOR Protector,
    _In_ ADB_DEBUG_ATTEMPT Type,
    _In_opt_ PCCH Details
    );

static VOID AdbpSnapshotEvent(
    _In_ PADB_EVENT Source,
    _Out_ PADB_EVENT_INFO Dest
    );

static VOID AdbpFreeEventList(
    _Inout_ PLIST_ENTRY ListHead
    );

static VOID AdbpEvictOldestEventsLocked(
    _In_ PADB_PROTECTOR Protector,
    _In_ ULONG TargetCount,
    _Inout_ PLIST_ENTRY FreeList
    );

// ============================================================================
// AdbInitialize
// ============================================================================

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
AdbInitialize(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PADB_PROTECTOR *Protector
    )
{
    PADB_PROTECTOR Ctx = NULL;

    if (Protector == NULL || DeviceObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Protector = NULL;

    Ctx = (PADB_PROTECTOR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(ADB_PROTECTOR),
        ADB_POOL_TAG_CTX
        );
    if (Ctx == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // ExAllocatePool2 zero-initializes, so all fields start at 0/NULL/FALSE.

    Ctx->DeviceObject = DeviceObject;
    ExInitializeRundownProtection(&Ctx->RundownRef);
    ExInitializePushLock(&Ctx->EventLock);
    ExInitializePushLock(&Ctx->CallbackLock);
    InitializeListHead(&Ctx->EventList);

    // Allocate work item for periodic checks
    Ctx->CheckWorkItem = IoAllocateWorkItem(DeviceObject);
    if (Ctx->CheckWorkItem == NULL) {
        ExFreePoolWithTag(Ctx, ADB_POOL_TAG_CTX);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Initialize timer and DPC
    KeInitializeTimer(&Ctx->CheckTimer);
    KeInitializeDpc(&Ctx->CheckDpc, AdbpTimerDpcRoutine, Ctx);

    // Run initial detection synchronously
    InterlockedExchange(&Ctx->KernelDebuggerPresent,
                        AdbpDetectKernelDebugger() ? 1 : 0);
    InterlockedExchange(&Ctx->HypervisorPresent,
                        AdbpDetectHypervisor() ? 1 : 0);
    InterlockedExchange(&Ctx->VerifierEnabled,
                        AdbpDetectDriverVerifier(Ctx) ? 1 : 0);
    InterlockedExchange(&Ctx->CrashDumpEnabled,
                        AdbpDetectCrashDumpConfig() ? 1 : 0);

    KeQuerySystemTimePrecise(&Ctx->Stats.StartTime);
    Ctx->Stats.KernelDebuggerPresent = (BOOLEAN)Ctx->KernelDebuggerPresent;
    Ctx->Stats.HypervisorPresent = (BOOLEAN)Ctx->HypervisorPresent;
    Ctx->Stats.VerifierEnabled = (BOOLEAN)Ctx->VerifierEnabled;

    // Record initial detections as events
    if (Ctx->KernelDebuggerPresent) {
        AdbpRecordEvent(Ctx, AdbAttemptKernelDebugger,
                        "Kernel debugger detected at initialization");
    }
    if (Ctx->HypervisorPresent) {
        AdbpRecordEvent(Ctx, AdbAttemptHypervisor,
                        "Hypervisor detected at initialization");
    }
    if (Ctx->VerifierEnabled) {
        AdbpRecordEvent(Ctx, AdbAttemptDriverVerifier,
                        "Driver Verifier enabled at initialization");
    }
    if (Ctx->CrashDumpEnabled) {
        AdbpRecordEvent(Ctx, AdbAttemptMemoryDump,
                        "Complete memory dump enabled at initialization");
    }

    // Start periodic timer
    InterlockedExchange(&Ctx->TimerActive, 1);
    {
        LARGE_INTEGER DueTime;
        DueTime.QuadPart = -(LONGLONG)ADB_CHECK_INTERVAL_SEC * 10000000LL;
        KeSetTimerEx(&Ctx->CheckTimer, DueTime,
                     ADB_CHECK_INTERVAL_SEC * 1000, &Ctx->CheckDpc);
    }

    // Mark initialized last — after all fields are set
    InterlockedExchange(&Ctx->Initialized, 1);

    *Protector = Ctx;
    return STATUS_SUCCESS;
}

// ============================================================================
// AdbShutdown
// ============================================================================

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
AdbShutdown(
    _Inout_ PADB_PROTECTOR Protector
    )
{
    LIST_ENTRY FreeList;

    if (Protector == NULL) {
        return;
    }

    // Idempotent shutdown
    if (InterlockedExchange(&Protector->Initialized, 0) == 0) {
        return;
    }

    // Signal shutdown to the periodic worker
    InterlockedExchange(&Protector->ShutdownRequested, 1);

    // Cancel the periodic timer
    InterlockedExchange(&Protector->TimerActive, 0);
    KeCancelTimer(&Protector->CheckTimer);

    //
    // KeFlushQueuedDpcs ensures the DPC has finished executing.
    // After this, no new work items will be queued because
    // ShutdownRequested == 1 and TimerActive == 0.
    //
    KeFlushQueuedDpcs();

    //
    // Wait for all in-flight API calls to drain.
    // After this returns, no thread is inside any public API.
    //
    ExWaitForRundownProtectionRelease(&Protector->RundownRef);

    // Free the work item
    if (Protector->CheckWorkItem != NULL) {
        IoFreeWorkItem(Protector->CheckWorkItem);
        Protector->CheckWorkItem = NULL;
    }

    // Drain and free all events — no lock needed, we're fully drained
    InitializeListHead(&FreeList);
    while (!IsListEmpty(&Protector->EventList)) {
        PLIST_ENTRY Entry = RemoveHeadList(&Protector->EventList);
        InsertTailList(&FreeList, Entry);
    }
    AdbpFreeEventList(&FreeList);

    ExFreePoolWithTag(Protector, ADB_POOL_TAG_CTX);
}

// ============================================================================
// AdbRegisterCallback
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
AdbRegisterCallback(
    _In_ PADB_PROTECTOR Protector,
    _In_opt_ PADB_DEBUG_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
{
    if (Protector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ADB_ACQUIRE_RUNDOWN(Protector)) {
        return STATUS_DELETE_PENDING;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Protector->CallbackLock);

    Protector->UserCallback = Callback;
    Protector->CallbackContext = Context;

    ExReleasePushLockExclusive(&Protector->CallbackLock);
    KeLeaveCriticalRegion();

    ADB_RELEASE_RUNDOWN(Protector);
    return STATUS_SUCCESS;
}

// ============================================================================
// AdbCheckForDebugger
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
AdbCheckForDebugger(
    _In_ PADB_PROTECTOR Protector,
    _Out_ PBOOLEAN DebuggerPresent
    )
{
    BOOLEAN PreviousState;
    BOOLEAN CurrentState;

    if (Protector == NULL || DebuggerPresent == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *DebuggerPresent = FALSE;

    if (!ADB_ACQUIRE_RUNDOWN(Protector)) {
        return STATUS_DELETE_PENDING;
    }

    PreviousState = (BOOLEAN)InterlockedCompareExchange(
        &Protector->KernelDebuggerPresent, 0, 0);

    CurrentState = AdbpDetectKernelDebugger();

    // Update state atomically
    InterlockedExchange(&Protector->KernelDebuggerPresent,
                        CurrentState ? 1 : 0);

    // Record transition event (newly detected)
    if (CurrentState && !PreviousState) {
        AdbpRecordEvent(Protector, AdbAttemptKernelDebugger,
                        "Kernel debugger newly detected");
    }

    // Also check for user-mode debugger on our process
    if (AdbpDetectUserDebugger()) {
        if (CurrentState == FALSE) {
            // Only log if kernel debugger wasn't already the trigger
            AdbpRecordEvent(Protector, AdbAttemptUserDebugger,
                            "User-mode debugger detected on driver process");
        }
        CurrentState = TRUE;
    }

    *DebuggerPresent = CurrentState;

    ADB_RELEASE_RUNDOWN(Protector);
    return STATUS_SUCCESS;
}

// ============================================================================
// AdbCheckForHypervisor
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
AdbCheckForHypervisor(
    _In_ PADB_PROTECTOR Protector,
    _Out_ PBOOLEAN HypervisorPresent
    )
{
    BOOLEAN PreviousState;
    BOOLEAN CurrentState;

    if (Protector == NULL || HypervisorPresent == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *HypervisorPresent = FALSE;

    if (!ADB_ACQUIRE_RUNDOWN(Protector)) {
        return STATUS_DELETE_PENDING;
    }

    PreviousState = (BOOLEAN)InterlockedCompareExchange(
        &Protector->HypervisorPresent, 0, 0);

    CurrentState = AdbpDetectHypervisor();
    InterlockedExchange(&Protector->HypervisorPresent,
                        CurrentState ? 1 : 0);

    if (CurrentState && !PreviousState) {
        AdbpRecordEvent(Protector, AdbAttemptHypervisor,
                        "Hypervisor newly detected");
    }

    *HypervisorPresent = CurrentState;

    ADB_RELEASE_RUNDOWN(Protector);
    return STATUS_SUCCESS;
}

// ============================================================================
// AdbGetEvents — returns value-type copies into caller-provided array
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
AdbGetEvents(
    _In_ PADB_PROTECTOR Protector,
    _Out_writes_to_(MaxEvents, *ReturnedCount) PADB_EVENT_INFO EventArray,
    _In_ ULONG MaxEvents,
    _Out_ PULONG ReturnedCount
    )
{
    ULONG Copied = 0;
    PLIST_ENTRY Entry;

    if (Protector == NULL || EventArray == NULL ||
        MaxEvents == 0 || ReturnedCount == NULL) {
        if (ReturnedCount != NULL) *ReturnedCount = 0;
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnedCount = 0;

    if (!ADB_ACQUIRE_RUNDOWN(Protector)) {
        return STATUS_DELETE_PENDING;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Protector->EventLock);

    for (Entry = Protector->EventList.Flink;
         Entry != &Protector->EventList && Copied < MaxEvents;
         Entry = Entry->Flink)
    {
        PADB_EVENT Evt = CONTAINING_RECORD(Entry, ADB_EVENT, ListEntry);
        AdbpSnapshotEvent(Evt, &EventArray[Copied]);
        Copied++;
    }

    ExReleasePushLockShared(&Protector->EventLock);
    KeLeaveCriticalRegion();

    *ReturnedCount = Copied;

    ADB_RELEASE_RUNDOWN(Protector);
    return STATUS_SUCCESS;
}

// ============================================================================
// AdbGetStatistics
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
AdbGetStatistics(
    _In_ PADB_PROTECTOR Protector,
    _Out_ PADB_STATISTICS Stats
    )
{
    if (Protector == NULL || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ADB_ACQUIRE_RUNDOWN(Protector)) {
        return STATUS_DELETE_PENDING;
    }

    Stats->TotalDetections = InterlockedCompareExchange64(
        &Protector->Stats.TotalDetections, 0, 0);
    Stats->CallbackInvocations = InterlockedCompareExchange64(
        &Protector->Stats.CallbackInvocations, 0, 0);
    Stats->CurrentEventCount = InterlockedCompareExchange(
        &Protector->EventCount, 0, 0);
    Stats->KernelDebuggerPresent = (BOOLEAN)InterlockedCompareExchange(
        &Protector->KernelDebuggerPresent, 0, 0);
    Stats->HypervisorPresent = (BOOLEAN)InterlockedCompareExchange(
        &Protector->HypervisorPresent, 0, 0);
    Stats->VerifierEnabled = (BOOLEAN)InterlockedCompareExchange(
        &Protector->VerifierEnabled, 0, 0);
    Stats->LastCheckTime = Protector->Stats.LastCheckTime;
    Stats->StartTime = Protector->Stats.StartTime;

    ADB_RELEASE_RUNDOWN(Protector);
    return STATUS_SUCCESS;
}

// ============================================================================
// AdbClearEvents — removes and frees all events
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
AdbClearEvents(
    _In_ PADB_PROTECTOR Protector
    )
{
    LIST_ENTRY FreeList;

    if (Protector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ADB_ACQUIRE_RUNDOWN(Protector)) {
        return STATUS_DELETE_PENDING;
    }

    InitializeListHead(&FreeList);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Protector->EventLock);

    // Move all events to FreeList
    while (!IsListEmpty(&Protector->EventList)) {
        PLIST_ENTRY Entry = RemoveHeadList(&Protector->EventList);
        InsertTailList(&FreeList, Entry);
    }
    InterlockedExchange(&Protector->EventCount, 0);

    ExReleasePushLockExclusive(&Protector->EventLock);
    KeLeaveCriticalRegion();

    // Free outside the lock
    AdbpFreeEventList(&FreeList);

    ADB_RELEASE_RUNDOWN(Protector);
    return STATUS_SUCCESS;
}

// ============================================================================
// INTERNAL: Record an event
// ============================================================================

static VOID
AdbpRecordEvent(
    _In_ PADB_PROTECTOR Protector,
    _In_ ADB_DEBUG_ATTEMPT Type,
    _In_opt_ PCCH Details
    )
{
    PADB_EVENT Evt;
    LIST_ENTRY FreeList;
    PADB_DEBUG_CALLBACK CallbackFn = NULL;
    PVOID CallbackCtx = NULL;
    ADB_EVENT_INFO SnapForCallback;

    // Pre-allocate before taking any locks
    Evt = (PADB_EVENT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(ADB_EVENT),
        ADB_POOL_TAG_EVENT
        );
    if (Evt == NULL) {
        // Cannot record — increment counter anyway
        InterlockedIncrement64(&Protector->Stats.TotalDetections);
        return;
    }

    // Fill event fields
    Evt->Type = Type;
    Evt->ProcessId = PsGetCurrentProcessId();
    Evt->ProcessNameLength = 0;
    Evt->ProcessName[0] = L'\0';
    Evt->WasBlocked = FALSE;
    KeQuerySystemTimePrecise(&Evt->Timestamp);

    if (Details != NULL) {
        RtlStringCchCopyA(Evt->Details, ADB_MAX_DETAIL_LENGTH, Details);
    } else {
        Evt->Details[0] = '\0';
    }

    // Get current process name if possible
    {
        PEPROCESS Process = PsGetCurrentProcess();
        if (Process != NULL) {
            PUCHAR ImageName = PsGetProcessImageFileName(Process);
            if (ImageName != NULL) {
                //
                // PsGetProcessImageFileName returns a narrow string (max 15 chars).
                // Convert to wide for the event.
                //
                ANSI_STRING Ansi;
                UNICODE_STRING Wide;
                RtlInitAnsiString(&Ansi, (PCSZ)ImageName);
                Wide.Buffer = Evt->ProcessName;
                Wide.Length = 0;
                Wide.MaximumLength = sizeof(Evt->ProcessName) - sizeof(WCHAR);
                if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&Wide, &Ansi, FALSE))) {
                    Evt->ProcessNameLength = Wide.Length / sizeof(WCHAR);
                    Evt->ProcessName[Evt->ProcessNameLength] = L'\0';
                }
            }
        }
    }

    InitializeListHead(&FreeList);

    //
    // Snapshot the event BEFORE inserting into the list.
    // Once inserted, another thread could evict and free it.
    //
    AdbpSnapshotEvent(Evt, &SnapForCallback);

    // Insert into event list under exclusive lock
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Protector->EventLock);

    InsertTailList(&Protector->EventList, &Evt->ListEntry);
    InterlockedIncrement(&Protector->EventCount);

    // Evict oldest if over cap
    if (Protector->EventCount > ADB_MAX_EVENTS) {
        AdbpEvictOldestEventsLocked(
            Protector,
            ADB_MAX_EVENTS,
            &FreeList
            );
    }

    ExReleasePushLockExclusive(&Protector->EventLock);
    KeLeaveCriticalRegion();

    // Free evicted events outside the lock
    AdbpFreeEventList(&FreeList);

    InterlockedIncrement64(&Protector->Stats.TotalDetections);

    // Invoke callback if registered (read under callback lock, call outside)
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Protector->CallbackLock);
    CallbackFn = Protector->UserCallback;
    CallbackCtx = Protector->CallbackContext;
    ExReleasePushLockShared(&Protector->CallbackLock);
    KeLeaveCriticalRegion();

    if (CallbackFn != NULL) {
        // SnapForCallback was taken before the event was visible to other threads
        CallbackFn(Type, &SnapForCallback, CallbackCtx);
        InterlockedIncrement64(&Protector->Stats.CallbackInvocations);
    }
}

// ============================================================================
// INTERNAL: Snapshot event to caller value type
// ============================================================================

static VOID
AdbpSnapshotEvent(
    _In_ PADB_EVENT Source,
    _Out_ PADB_EVENT_INFO Dest
    )
{
    Dest->Type = Source->Type;
    Dest->ProcessId = Source->ProcessId;
    Dest->ProcessNameLength = Source->ProcessNameLength;
    Dest->Timestamp = Source->Timestamp;
    Dest->WasBlocked = Source->WasBlocked;

    RtlCopyMemory(Dest->ProcessName, Source->ProcessName,
                   (SIZE_T)(Source->ProcessNameLength + 1) * sizeof(WCHAR));
    // Null-terminate just in case
    Dest->ProcessName[ADB_MAX_PROCESS_NAME - 1] = L'\0';

    RtlCopyMemory(Dest->Details, Source->Details, ADB_MAX_DETAIL_LENGTH);
    Dest->Details[ADB_MAX_DETAIL_LENGTH - 1] = '\0';
}

// ============================================================================
// INTERNAL: Free a list of events
// ============================================================================

static VOID
AdbpFreeEventList(
    _Inout_ PLIST_ENTRY ListHead
    )
{
    while (!IsListEmpty(ListHead)) {
        PLIST_ENTRY Entry = RemoveHeadList(ListHead);
        PADB_EVENT Evt = CONTAINING_RECORD(Entry, ADB_EVENT, ListEntry);
        ExFreePoolWithTag(Evt, ADB_POOL_TAG_EVENT);
    }
}

// ============================================================================
// INTERNAL: Evict oldest events to reach TargetCount
// Caller MUST hold EventLock exclusive.
// Evicted events are moved to FreeList for freeing outside the lock.
// ============================================================================

static VOID
AdbpEvictOldestEventsLocked(
    _In_ PADB_PROTECTOR Protector,
    _In_ ULONG TargetCount,
    _Inout_ PLIST_ENTRY FreeList
    )
{
    while (Protector->EventCount > (LONG)TargetCount &&
           !IsListEmpty(&Protector->EventList))
    {
        PLIST_ENTRY Entry = RemoveHeadList(&Protector->EventList);
        InsertTailList(FreeList, Entry);
        InterlockedDecrement(&Protector->EventCount);
    }
}

// ============================================================================
// INTERNAL: Detection — Kernel debugger
// ============================================================================

static BOOLEAN
AdbpDetectKernelDebugger(VOID)
{
    //
    // KD_DEBUGGER_ENABLED is a kernel-exported pointer to a BOOLEAN.
    // KD_DEBUGGER_NOT_PRESENT is also exported.
    // Both are safe to read at any IRQL.
    //
    if (KD_DEBUGGER_ENABLED != NULL && *KD_DEBUGGER_ENABLED) {
        if (KD_DEBUGGER_NOT_PRESENT == NULL || !(*KD_DEBUGGER_NOT_PRESENT)) {
            return TRUE;
        }
    }

    return FALSE;
}

// ============================================================================
// INTERNAL: Detection — User-mode debugger
// ============================================================================

static BOOLEAN
AdbpDetectUserDebugger(VOID)
{
    //
    // Check if the current process has a debug port.
    // This detects user-mode debuggers attached to a process that is
    // calling into our driver. Not directly applicable to the driver
    // process itself, but useful telemetry.
    //
    // We cannot call NtQueryInformationProcess from kernel mode directly
    // for the System process. Instead check the EPROCESS debug port.
    // However, the offset is undocumented and version-dependent, so we
    // skip this for safety in a production driver.
    //
    // For production: use PsSetCreateProcessNotifyRoutineEx to watch
    // for debugger attachment to protected processes.
    //

    return FALSE;
}

// ============================================================================
// INTERNAL: Detection — Hypervisor
// ============================================================================

static BOOLEAN
AdbpDetectHypervisor(VOID)
{
    int CpuInfo[4] = {0};

    //
    // CPUID leaf 1, ECX bit 31 = Hypervisor Present.
    // __cpuid is safe at PASSIVE_LEVEL and DISPATCH_LEVEL on x86/x64.
    //
    __cpuid(CpuInfo, 1);

    if (CpuInfo[2] & (1 << 31)) {
        return TRUE;
    }

    return FALSE;
}

// ============================================================================
// INTERNAL: Detection — Driver Verifier
// ============================================================================

static BOOLEAN
AdbpDetectDriverVerifier(
    _In_ PADB_PROTECTOR Protector
    )
{
    ULONG VerifierFlags = 0;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(Protector);

    //
    // MmIsVerifierEnabled returns the verifier level.
    // It's safe to call at PASSIVE_LEVEL.
    //
    Status = MmIsVerifierEnabled(&VerifierFlags);
    if (NT_SUCCESS(Status) && VerifierFlags != 0) {
        return TRUE;
    }

    return FALSE;
}

// ============================================================================
// INTERNAL: Detection — Crash dump configuration
//
// Checks if crash dump settings have been modified to allow full memory dumps,
// which an attacker could use to extract driver memory.
// ============================================================================

static BOOLEAN
AdbpDetectCrashDumpConfig(VOID)
{
    NTSTATUS Status;
    HANDLE KeyHandle = NULL;
    OBJECT_ATTRIBUTES ObjAttrs;
    UNICODE_STRING KeyPath;
    UNICODE_STRING ValueName;
    UCHAR ValueBuffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION ValueInfo =
        (PKEY_VALUE_PARTIAL_INFORMATION)ValueBuffer;
    ULONG ResultLength = 0;
    ULONG DumpType = 0;

    RtlInitUnicodeString(&KeyPath,
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\CrashControl");

    InitializeObjectAttributes(&ObjAttrs, &KeyPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    Status = ZwOpenKey(&KeyHandle, KEY_READ, &ObjAttrs);
    if (!NT_SUCCESS(Status)) {
        return FALSE;
    }

    RtlInitUnicodeString(&ValueName, L"CrashDumpEnabled");

    Status = ZwQueryValueKey(
        KeyHandle,
        &ValueName,
        KeyValuePartialInformation,
        ValueInfo,
        sizeof(ValueBuffer),
        &ResultLength
        );

    ZwClose(KeyHandle);

    if (!NT_SUCCESS(Status) ||
        ValueInfo->Type != REG_DWORD ||
        ValueInfo->DataLength < sizeof(ULONG)) {
        return FALSE;
    }

    DumpType = *(PULONG)ValueInfo->Data;

    //
    // CrashDumpEnabled values:
    //   0 = None
    //   1 = Complete memory dump (security risk — contains all kernel memory)
    //   2 = Kernel memory dump
    //   3 = Small memory dump (minidump)
    //   7 = Automatic memory dump
    //
    // Flag complete memory dump (type 1) as suspicious.
    //
    if (DumpType == 1) {
        return TRUE;
    }

    return FALSE;
}

// ============================================================================
// TIMER DPC — only queues the work item, does NO event processing
// ============================================================================

static VOID
AdbpTimerDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PADB_PROTECTOR Protector = (PADB_PROTECTOR)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (Protector == NULL) {
        return;
    }

    // Don't queue if shutdown is requested or timer is deactivated
    if (Protector->ShutdownRequested || !Protector->TimerActive) {
        return;
    }

    //
    // Queue the work item to run at PASSIVE_LEVEL.
    // The work item does the actual detection work.
    // IoQueueWorkItem is safe to call at DISPATCH_LEVEL.
    //
    if (Protector->CheckWorkItem != NULL) {
        IoQueueWorkItem(
            Protector->CheckWorkItem,
            AdbpPeriodicCheckWorker,
            DelayedWorkQueue,
            Protector
            );
    }
}

// ============================================================================
// PERIODIC CHECK WORKER — runs at PASSIVE_LEVEL
// ============================================================================

static VOID
AdbpPeriodicCheckWorker(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    )
{
    PADB_PROTECTOR Protector = (PADB_PROTECTOR)Context;
    BOOLEAN PrevKd, PrevHv, PrevVf, PrevDump;
    BOOLEAN CurrKd, CurrHv, CurrVf, CurrDump;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Protector == NULL || Protector->ShutdownRequested) {
        return;
    }

    //
    // Acquire rundown protection so shutdown waits for us.
    // If shutdown has started, bail immediately.
    //
    if (!ADB_ACQUIRE_RUNDOWN(Protector)) {
        return;
    }

    // Read previous state
    PrevKd = (BOOLEAN)InterlockedCompareExchange(
        &Protector->KernelDebuggerPresent, 0, 0);
    PrevHv = (BOOLEAN)InterlockedCompareExchange(
        &Protector->HypervisorPresent, 0, 0);
    PrevVf = (BOOLEAN)InterlockedCompareExchange(
        &Protector->VerifierEnabled, 0, 0);
    PrevDump = (BOOLEAN)InterlockedCompareExchange(
        &Protector->CrashDumpEnabled, 0, 0);

    // Run detections
    CurrKd = AdbpDetectKernelDebugger();
    CurrHv = AdbpDetectHypervisor();
    CurrVf = AdbpDetectDriverVerifier(Protector);
    CurrDump = AdbpDetectCrashDumpConfig();

    // Update state atomically
    InterlockedExchange(&Protector->KernelDebuggerPresent, CurrKd ? 1 : 0);
    InterlockedExchange(&Protector->HypervisorPresent, CurrHv ? 1 : 0);
    InterlockedExchange(&Protector->VerifierEnabled, CurrVf ? 1 : 0);
    InterlockedExchange(&Protector->CrashDumpEnabled, CurrDump ? 1 : 0);

    // Record transition events only (FALSE → TRUE)
    if (CurrKd && !PrevKd) {
        AdbpRecordEvent(Protector, AdbAttemptKernelDebugger,
                        "Kernel debugger attached (periodic check)");
    }
    if (CurrHv && !PrevHv) {
        AdbpRecordEvent(Protector, AdbAttemptHypervisor,
                        "Hypervisor detected (periodic check)");
    }
    if (CurrVf && !PrevVf) {
        AdbpRecordEvent(Protector, AdbAttemptDriverVerifier,
                        "Driver Verifier enabled (periodic check)");
    }
    if (CurrDump && !PrevDump) {
        AdbpRecordEvent(Protector, AdbAttemptMemoryDump,
                        "Complete memory dump enabled — security risk");
    }

    // Update statistics snapshot
    Protector->Stats.KernelDebuggerPresent = CurrKd;
    Protector->Stats.HypervisorPresent = CurrHv;
    Protector->Stats.VerifierEnabled = CurrVf;
    KeQuerySystemTimePrecise(&Protector->Stats.LastCheckTime);

    ADB_RELEASE_RUNDOWN(Protector);
}

// ============================================================================
// END OF FILE
// ============================================================================