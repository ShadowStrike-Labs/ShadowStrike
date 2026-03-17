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
    ShadowStrike Next-Generation Antivirus
    Module: AntiDebug.c - Anti-debugging detection & alerting implementation

    Architecture:
    - All synchronization via EX_PUSH_LOCK (IRQL <= APC_LEVEL).
    - EX_RUNDOWN_REF drains all in-flight API calls before shutdown.
    - Periodic detection runs in a system thread (DPC signals KEVENT to wake).
    - Events are stored as internal ADB_EVENT nodes on a capped list.
    - Callers receive ADB_EVENT_INFO value-type copies (no internal pointers).
    - Detect-and-alert model only. This module does NOT and CANNOT block
      kernel debugger attachment.

    Copyright (c) ShadowStrike Team
--*/

#include "AntiDebug.h"
#include "../Behavioral/BehaviorEngine.h"
#include "../Sync/TimerManager.h"
#include "../Core/DriverEntry.h"
#include "../ETW/TelemetryEvents.h"
#include <ntifs.h>
#include <ntstrsafe.h>
#include <intrin.h>

// ============================================================================
// WDK KERNEL-MODE MISSING DECLARATIONS
// ============================================================================

NTKERNELAPI
PCHAR
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
    );

#ifndef ProcessDebugPort
#define ProcessDebugPort 7
#endif

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

// ============================================================================
// INTERNAL TYPES
// ============================================================================

//
// Internal event node â€” lives on Protector->EventList.
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

static VOID AdbpCheckTimerCallback(
    _In_ ULONG TimerId,
    _In_opt_ PVOID Context
    );

static VOID AdbpPeriodicCheckThread(
    _In_ PVOID StartContext
    );

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
    _Out_ PADB_PROTECTOR *Protector
    )
{
    PADB_PROTECTOR Ctx = NULL;
    NTSTATUS Status;
    HANDLE ThreadHandle = NULL;

    if (Protector == NULL) {
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

    ExInitializeRundownProtection(&Ctx->RundownRef);
    ExInitializePushLock(&Ctx->EventLock);
    ExInitializePushLock(&Ctx->CallbackLock);
    InitializeListHead(&Ctx->EventList);
    KeInitializeEvent(&Ctx->CheckWakeEvent, SynchronizationEvent, FALSE);

    // CheckTimerId initialized to 0 (TM_INVALID_TIMER_ID) by ExAllocatePool2

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
    Ctx->Stats.KernelDebuggerPresent = (Ctx->KernelDebuggerPresent != 0);
    Ctx->Stats.HypervisorPresent = (Ctx->HypervisorPresent != 0);
    Ctx->Stats.VerifierEnabled = (Ctx->VerifierEnabled != 0);

    // Record initial detections as events
    if (Ctx->KernelDebuggerPresent) {
        AdbpRecordEvent(Ctx, AdbAttemptKernelDebugger,
                        "Kernel debugger detected at initialization");
        (VOID)BeEngineSubmitEvent(
            BehaviorEvent_DebuggerEvasion,
            BehaviorCategory_DefenseEvasion,
            HandleToULong(PsGetCurrentProcessId()),
            NULL, 0, 70, FALSE, NULL);
        (VOID)TeLogEvasionAttempt(
            Evasion_DebugEvasion,
            HandleToULong(PsGetCurrentProcessId()),
            L"PhantomSensor", "KernelDebugger", 70);
    }
    if (Ctx->HypervisorPresent) {
        AdbpRecordEvent(Ctx, AdbAttemptHypervisor,
                        "Hypervisor detected at initialization");
        (VOID)BeEngineSubmitEvent(
            BehaviorEvent_VirtualizationEvasion,
            BehaviorCategory_DefenseEvasion,
            HandleToULong(PsGetCurrentProcessId()),
            NULL, 0, 50, FALSE, NULL);
        (VOID)TeLogEvasionAttempt(
            Evasion_VMEvasion,
            HandleToULong(PsGetCurrentProcessId()),
            L"PhantomSensor", "Hypervisor", 50);
    }
    if (Ctx->VerifierEnabled) {
        AdbpRecordEvent(Ctx, AdbAttemptDriverVerifier,
                        "Driver Verifier enabled at initialization");
        (VOID)BeEngineSubmitEvent(
            BehaviorEvent_DebuggerEvasion,
            BehaviorCategory_DefenseEvasion,
            HandleToULong(PsGetCurrentProcessId()),
            NULL, 0, 40, FALSE, NULL);
        (VOID)TeLogEvasionAttempt(
            Evasion_DebugEvasion,
            HandleToULong(PsGetCurrentProcessId()),
            L"PhantomSensor", "DriverVerifier", 40);
    }
    if (Ctx->CrashDumpEnabled) {
        AdbpRecordEvent(Ctx, AdbAttemptMemoryDump,
                        "Complete memory dump enabled at initialization");
        (VOID)BeEngineSubmitEvent(
            BehaviorEvent_DebuggerEvasion,
            BehaviorCategory_DefenseEvasion,
            HandleToULong(PsGetCurrentProcessId()),
            NULL, 0, 55, FALSE, NULL);
        (VOID)TeLogEvasionAttempt(
            Evasion_DebugEvasion,
            HandleToULong(PsGetCurrentProcessId()),
            L"CrashControl", "CrashDumpEnabled", 55);
    }

    // Create periodic check system thread
    Status = PsCreateSystemThread(
        &ThreadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        AdbpPeriodicCheckThread,
        Ctx
        );
    if (!NT_SUCCESS(Status)) {
        //
        // Drain event list before freeing context to prevent pool leak.
        //
        while (!IsListEmpty(&Ctx->EventList)) {
            PLIST_ENTRY Entry = RemoveHeadList(&Ctx->EventList);
            PADB_EVENT Evt = CONTAINING_RECORD(Entry, ADB_EVENT, ListEntry);
            ExFreePoolWithTag(Evt, ADB_POOL_TAG_EVENT);
        }
        ExFreePoolWithTag(Ctx, ADB_POOL_TAG_CTX);
        return Status;
    }

    Status = ObReferenceObjectByHandle(
        ThreadHandle,
        THREAD_ALL_ACCESS,
        *PsThreadType,
        KernelMode,
        (PVOID*)&Ctx->CheckThread,
        NULL
        );

    if (!NT_SUCCESS(Status)) {
        //
        // Thread is already running but we have no PETHREAD to wait on.
        // Signal shutdown, wait on the handle (still valid), then clean up.
        //
        InterlockedExchange(&Ctx->ShutdownRequested, 1);
        KeSetEvent(&Ctx->CheckWakeEvent, IO_NO_INCREMENT, FALSE);
        ZwWaitForSingleObject(ThreadHandle, FALSE, NULL);
        ZwClose(ThreadHandle);
        //
        // Thread has exited â€” drain event list before freeing context.
        //
        while (!IsListEmpty(&Ctx->EventList)) {
            PLIST_ENTRY Entry = RemoveHeadList(&Ctx->EventList);
            PADB_EVENT Evt = CONTAINING_RECORD(Entry, ADB_EVENT, ListEntry);
            ExFreePoolWithTag(Evt, ADB_POOL_TAG_EVENT);
        }
        ExFreePoolWithTag(Ctx, ADB_POOL_TAG_CTX);
        return Status;
    }

    ZwClose(ThreadHandle);

    // Start periodic timer via TimerManager
    {
        PTM_MANAGER tmMgr = ShadowStrikeGetTimerManager();
        if (tmMgr) {
            TM_TIMER_OPTIONS opts = { 0 };
            opts.Flags = TmFlag_WorkItemCallback | TmFlag_Coalescable;
            opts.ToleranceMs = 5000;
            Status = TmCreatePeriodic(tmMgr, ADB_CHECK_INTERVAL_SEC * 1000,
                                      AdbpCheckTimerCallback, Ctx,
                                      &opts, &Ctx->CheckTimerId);
            if (NT_SUCCESS(Status)) {
                InterlockedExchange(&Ctx->TimerActive, 1);
            }
        }
    }

    // Mark initialized last â€” after all fields are set
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

    // Cancel the periodic timer via TimerManager
    InterlockedExchange(&Protector->TimerActive, 0);
    {
        PTM_MANAGER tmMgr = ShadowStrikeGetTimerManager();
        if (tmMgr && Protector->CheckTimerId != TM_INVALID_TIMER_ID) {
            TmCancel(tmMgr, Protector->CheckTimerId, TRUE);
            Protector->CheckTimerId = TM_INVALID_TIMER_ID;
        }
    }

    //
    // Wake the check thread and wait for it to exit.
    // The thread checks ShutdownRequested and terminates.
    //
    KeSetEvent(&Protector->CheckWakeEvent, IO_NO_INCREMENT, FALSE);
    if (Protector->CheckThread != NULL) {
        KeWaitForSingleObject(
            Protector->CheckThread,
            Executive,
            KernelMode,
            FALSE,
            NULL
            );
        ObDereferenceObject(Protector->CheckThread);
        Protector->CheckThread = NULL;
    }

    //
    // Wait for all in-flight API calls to drain.
    // After this returns, no thread is inside any public API.
    //
    ExWaitForRundownProtectionRelease(&Protector->RundownRef);

    // Drain and free all events â€” no lock needed, we're fully drained
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

    PreviousState = (InterlockedCompareExchange(
        &Protector->KernelDebuggerPresent, 0, 0) != 0);

    CurrentState = AdbpDetectKernelDebugger();

    // Update state atomically
    InterlockedExchange(&Protector->KernelDebuggerPresent,
                        CurrentState ? 1 : 0);

    // Record transition event (newly detected)
    if (CurrentState && !PreviousState) {
        AdbpRecordEvent(Protector, AdbAttemptKernelDebugger,
                        "Kernel debugger newly detected");
        (VOID)BeEngineSubmitEvent(
            BehaviorEvent_DebuggerEvasion,
            BehaviorCategory_DefenseEvasion,
            HandleToULong(PsGetCurrentProcessId()),
            NULL, 0, 70, FALSE, NULL);
        (VOID)TeLogEvasionAttempt(
            Evasion_DebugEvasion,
            HandleToULong(PsGetCurrentProcessId()),
            L"PhantomSensor", "KernelDebugger", 70);
    }

    // Also check for user-mode debugger on our process
    if (AdbpDetectUserDebugger()) {
        if (CurrentState == FALSE) {
            // Only log if kernel debugger wasn't already the trigger
            AdbpRecordEvent(Protector, AdbAttemptUserDebugger,
                            "User-mode debugger detected on driver process");
            (VOID)BeEngineSubmitEvent(
                BehaviorEvent_DebuggerEvasion,
                BehaviorCategory_DefenseEvasion,
                HandleToULong(PsGetCurrentProcessId()),
                NULL, 0, 60, FALSE, NULL);
            (VOID)TeLogEvasionAttempt(
                Evasion_DebugEvasion,
                HandleToULong(PsGetCurrentProcessId()),
                L"PhantomSensor", "UserDebugger", 60);
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

    PreviousState = (InterlockedCompareExchange(
        &Protector->HypervisorPresent, 0, 0) != 0);

    CurrentState = AdbpDetectHypervisor();
    InterlockedExchange(&Protector->HypervisorPresent,
                        CurrentState ? 1 : 0);

    if (CurrentState && !PreviousState) {
        AdbpRecordEvent(Protector, AdbAttemptHypervisor,
                        "Hypervisor newly detected");
        (VOID)BeEngineSubmitEvent(
            BehaviorEvent_VirtualizationEvasion,
            BehaviorCategory_DefenseEvasion,
            HandleToULong(PsGetCurrentProcessId()),
            NULL, 0, 50, FALSE, NULL);
        (VOID)TeLogEvasionAttempt(
            Evasion_VMEvasion,
            HandleToULong(PsGetCurrentProcessId()),
            L"PhantomSensor", "Hypervisor", 50);
    }

    *HypervisorPresent = CurrentState;

    ADB_RELEASE_RUNDOWN(Protector);
    return STATUS_SUCCESS;
}

// ============================================================================
// AdbGetEvents â€” returns value-type copies into caller-provided array
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
    Stats->KernelDebuggerPresent = (InterlockedCompareExchange(
        &Protector->KernelDebuggerPresent, 0, 0) != 0);
    Stats->HypervisorPresent = (InterlockedCompareExchange(
        &Protector->HypervisorPresent, 0, 0) != 0);
    Stats->VerifierEnabled = (InterlockedCompareExchange(
        &Protector->VerifierEnabled, 0, 0) != 0);
    Stats->LastCheckTime = Protector->Stats.LastCheckTime;
    Stats->StartTime = Protector->Stats.StartTime;

    ADB_RELEASE_RUNDOWN(Protector);
    return STATUS_SUCCESS;
}

// ============================================================================
// AdbClearEvents â€” removes and frees all events
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
        POOL_FLAG_PAGED,
        sizeof(ADB_EVENT),
        ADB_POOL_TAG_EVENT
        );
    if (Evt == NULL) {
        // Cannot record â€” increment counter anyway
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
            PCHAR ImageName = PsGetProcessImageFileName(Process);
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
// INTERNAL: Detection â€” Kernel debugger
// ============================================================================

static BOOLEAN
AdbpDetectKernelDebugger(VOID)
{
    //
    // KD_DEBUGGER_ENABLED expands to *KdDebuggerEnabled (already dereferenced).
    // KD_DEBUGGER_NOT_PRESENT expands to *KdDebuggerNotPresent.
    // Both are safe to read at any IRQL.
    //
    if (KD_DEBUGGER_ENABLED && !KD_DEBUGGER_NOT_PRESENT) {
        return TRUE;
    }

    return FALSE;
}

// ============================================================================
// INTERNAL: Detection â€” User-mode debugger
// ============================================================================

static BOOLEAN
AdbpDetectUserDebugger(VOID)
{
    NTSTATUS Status;
    HANDLE DebugPort = NULL;

    //
    // System process (PID 4) cannot have a user-mode debugger.
    // When called from periodic check thread, this is always PID 4.
    // When called via IOCTL from user-mode service, this checks
    // whether the calling process has a debugger attached.
    //
    if (PsGetProcessId(PsGetCurrentProcess()) == (HANDLE)(ULONG_PTR)4) {
        return FALSE;
    }

    //
    // Query ProcessDebugPort (info class 7). Returns non-zero port handle
    // if a user-mode debugger is attached to the calling process.
    //
    Status = ZwQueryInformationProcess(
        NtCurrentProcess(),
        (PROCESSINFOCLASS)ProcessDebugPort,
        &DebugPort,
        sizeof(DebugPort),
        NULL
        );

    if (NT_SUCCESS(Status) && DebugPort != NULL) {
        return TRUE;
    }

    return FALSE;
}

// ============================================================================
// INTERNAL: Detection â€” Hypervisor
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
// INTERNAL: Detection â€” Driver Verifier
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
// INTERNAL: Detection â€” Crash dump configuration
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
    //   1 = Complete memory dump (security risk â€” contains all kernel memory)
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
// TIMER CALLBACK â€” signals the system thread to wake, does NO event processing
// ============================================================================

static VOID
AdbpCheckTimerCallback(
    _In_ ULONG TimerId,
    _In_opt_ PVOID Context
    )
{
    PADB_PROTECTOR Protector = (PADB_PROTECTOR)Context;

    UNREFERENCED_PARAMETER(TimerId);

    if (Protector && !Protector->ShutdownRequested) {
        KeSetEvent(&Protector->CheckWakeEvent, IO_NO_INCREMENT, FALSE);
    }
}

// ============================================================================
// PERIODIC CHECK THREAD â€” runs at PASSIVE_LEVEL, waits on wake event
// ============================================================================

static VOID
AdbpPeriodicCheckThread(
    _In_ PVOID StartContext
    )
{
    PADB_PROTECTOR Protector = (PADB_PROTECTOR)StartContext;
    LARGE_INTEGER Timeout;
    BOOLEAN PrevKd, PrevHv, PrevVf, PrevDump;
    BOOLEAN CurrKd, CurrHv, CurrVf, CurrDump;

    Timeout.QuadPart = -(LONGLONG)ADB_CHECK_INTERVAL_SEC * 10000000LL;

    while (!Protector->ShutdownRequested) {

        KeWaitForSingleObject(
            &Protector->CheckWakeEvent,
            Executive,
            KernelMode,
            FALSE,
            &Timeout
            );

        if (Protector->ShutdownRequested) {
            break;
        }

        if (!ADB_ACQUIRE_RUNDOWN(Protector)) {
            break;
        }

        // Read previous state
        PrevKd = (InterlockedCompareExchange(
            &Protector->KernelDebuggerPresent, 0, 0) != 0);
        PrevHv = (InterlockedCompareExchange(
            &Protector->HypervisorPresent, 0, 0) != 0);
        PrevVf = (InterlockedCompareExchange(
            &Protector->VerifierEnabled, 0, 0) != 0);
        PrevDump = (InterlockedCompareExchange(
            &Protector->CrashDumpEnabled, 0, 0) != 0);

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

        // Record transition events only (FALSE -> TRUE)
        // Report to BehaviorEngine + TelemetryEvents for full pipeline coverage
        if (CurrKd && !PrevKd) {
            AdbpRecordEvent(Protector, AdbAttemptKernelDebugger,
                            "Kernel debugger attached (periodic check)");
            (VOID)BeEngineSubmitEvent(
                BehaviorEvent_DebuggerEvasion,
                BehaviorCategory_DefenseEvasion,
                HandleToULong(PsGetCurrentProcessId()),
                NULL, 0, 70, FALSE, NULL);
            (VOID)TeLogEvasionAttempt(
                Evasion_DebugEvasion,
                HandleToULong(PsGetCurrentProcessId()),
                L"PhantomSensor", "KernelDebugger", 70);
        }
        if (CurrHv && !PrevHv) {
            AdbpRecordEvent(Protector, AdbAttemptHypervisor,
                            "Hypervisor detected (periodic check)");
            (VOID)BeEngineSubmitEvent(
                BehaviorEvent_VirtualizationEvasion,
                BehaviorCategory_DefenseEvasion,
                HandleToULong(PsGetCurrentProcessId()),
                NULL, 0, 50, FALSE, NULL);
            (VOID)TeLogEvasionAttempt(
                Evasion_VMEvasion,
                HandleToULong(PsGetCurrentProcessId()),
                L"PhantomSensor", "Hypervisor", 50);
        }
        if (CurrVf && !PrevVf) {
            AdbpRecordEvent(Protector, AdbAttemptDriverVerifier,
                            "Driver Verifier enabled (periodic check)");
            (VOID)BeEngineSubmitEvent(
                BehaviorEvent_DebuggerEvasion,
                BehaviorCategory_DefenseEvasion,
                HandleToULong(PsGetCurrentProcessId()),
                NULL, 0, 40, FALSE, NULL);
            (VOID)TeLogEvasionAttempt(
                Evasion_DebugEvasion,
                HandleToULong(PsGetCurrentProcessId()),
                L"PhantomSensor", "DriverVerifier", 40);
        }
        if (CurrDump && !PrevDump) {
            AdbpRecordEvent(Protector, AdbAttemptMemoryDump,
                            "Complete memory dump enabled (periodic check)");
            (VOID)BeEngineSubmitEvent(
                BehaviorEvent_DebuggerEvasion,
                BehaviorCategory_DefenseEvasion,
                HandleToULong(PsGetCurrentProcessId()),
                NULL, 0, 55, FALSE, NULL);
            (VOID)TeLogEvasionAttempt(
                Evasion_DebugEvasion,
                HandleToULong(PsGetCurrentProcessId()),
                L"CrashControl", "CrashDumpEnabled", 55);
        }

        // Update statistics snapshot
        Protector->Stats.KernelDebuggerPresent = CurrKd;
        Protector->Stats.HypervisorPresent = CurrHv;
        Protector->Stats.VerifierEnabled = CurrVf;
        KeQuerySystemTimePrecise(&Protector->Stats.LastCheckTime);

        ADB_RELEASE_RUNDOWN(Protector);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

// ============================================================================
// END OF FILE
// ============================================================================
