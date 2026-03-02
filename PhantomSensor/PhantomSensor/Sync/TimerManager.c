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
    Module: TimerManager.c

    Purpose: Enterprise-grade centralized timer management for periodic tasks,
             timeouts, and scheduled work in the kernel driver.

    Architecture:
    - High-resolution timer support via KeSetCoalescableTimer
    - Timer wheel for efficient deadline-miss detection
    - One-shot and periodic timers with reference counting
    - Timer coalescing for power efficiency on mobile endpoints
    - Thread-safe operations with proper IRQL management
    - WorkItemCallback timers execute at PASSIVE_LEVEL via IoQueueWorkItem
    - Comprehensive statistics for performance monitoring

    Reference Counting Model:
      - Timer starts with RefCount=2: 1 for the TimerList, 1 for creation.
      - TmpFindTimerById adds +1 (caller must TmpDereferenceTimer).
      - TmCancel removes from TimerList (releases the list reference),
        then releases the find reference. The creation reference is released
        separately: if auto-start failed we call TmCancel internally, otherwise
        the caller is responsible via explicit TmCancel.
      - Auto-delete one-shot: TmpFireTimer releases both the list reference
        and the creation reference (2 derefs). The DPC/WorkItem caller
        still holds its own ref, so neither deref hits 0. The caller's
        deref then hits 0 → TmpDestroyTimer frees the memory.
      - TmpDestroyTimer is called when RefCount reaches 0.

    Context Ownership:
      - If Options->ContextSize > 0, the data at Options->Context is COPIED
        into a driver-owned allocation. The timer frees it on destruction.
      - If ContextSize == 0, Context is a caller-owned opaque pointer. The
        caller must ensure it remains valid for the timer's lifetime.

    MITRE ATT&CK Coverage:
    - T1497: Virtualization/Sandbox Evasion (timing analysis)
    - T1082: System Information Discovery (scheduled enumeration)

    Copyright (c) ShadowStrike 
--*/

#include "TimerManager.h"
#include "../Utilities/MemoryUtils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, TmInitialize)
#pragma alloc_text(PAGE, TmShutdown)
#endif

//=============================================================================
// Internal Constants
//=============================================================================

#define TM_TIMER_SIGNATURE          'RMIT'  // 'TIMR' reversed
#define TM_WHEEL_TICK_INTERVAL_MS   10      // 10ms wheel tick

//=============================================================================
// Internal Structures
//=============================================================================

typedef struct _TM_TIMER_INTERNAL {
    //
    // Signature for debug validation (never used for control flow decisions
    // after timer destruction — only checked while timer is referenced)
    //
    ULONG Signature;

    //
    // Public timer structure
    //
    TM_TIMER Timer;

    //
    // Back-reference to manager
    //
    PTM_MANAGER Manager;

    //
    // Work item for WorkItemCallback mode (pre-allocated at create time)
    //
    PIO_WORKITEM WorkItem;

    //
    // Wheel slot index (for fast removal)
    //
    ULONG WheelSlotIndex;

    //
    // Flags
    //
    volatile LONG DeletionPending;      // LONG for interlocked ops
    volatile LONG InWheelSlot;          // Track whether we're in the wheel

} TM_TIMER_INTERNAL, *PTM_TIMER_INTERNAL;

//=============================================================================
// Forward Declarations
//=============================================================================

static KDEFERRED_ROUTINE TmpTimerDpcRoutine;
static KDEFERRED_ROUTINE TmpWheelDpcRoutine;
static IO_WORKITEM_ROUTINE TmpWorkItemRoutine;

_IRQL_requires_max_(DISPATCH_LEVEL)
static PTM_TIMER_INTERNAL
TmpFindTimerById(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG TimerId
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
TmpReferenceTimer(
    _Inout_ PTM_TIMER_INTERNAL TimerInternal
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
TmpDereferenceTimer(
    _Inout_ PTM_TIMER_INTERNAL TimerInternal
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
TmpInsertTimerIntoWheel(
    _In_ PTM_MANAGER Manager,
    _Inout_ PTM_TIMER_INTERNAL TimerInternal
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
TmpRemoveTimerFromWheel(
    _In_ PTM_MANAGER Manager,
    _Inout_ PTM_TIMER_INTERNAL TimerInternal
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static NTSTATUS
TmpCreateTimerInternal(
    _In_ PTM_MANAGER Manager,
    _In_ TM_TIMER_TYPE Type,
    _In_ PLARGE_INTEGER DueTime,
    _In_ ULONG PeriodMs,
    _In_ TM_TIMER_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _In_opt_ PTM_TIMER_OPTIONS Options,
    _Out_ PULONG TimerId
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
TmpDestroyTimer(
    _Inout_ PTM_TIMER_INTERNAL TimerInternal
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
TmpFireTimer(
    _Inout_ PTM_TIMER_INTERNAL TimerInternal
    );

_IRQL_requires_(DISPATCH_LEVEL)
static VOID
TmpProcessWheelSlot(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG SlotIndex
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static NTSTATUS
TmpStartTimerInternal(
    _In_ PTM_MANAGER Manager,
    _Inout_ PTM_TIMER_INTERNAL TimerInternal
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
TmpStopTimerInternal(
    _In_ PTM_MANAGER Manager,
    _Inout_ PTM_TIMER_INTERNAL TimerInternal
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
TmpAllocateTimerId(
    _In_ PTM_MANAGER Manager
    );

//=============================================================================
// Helper: Generate timer ID that never returns 0
//=============================================================================

static
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
TmpAllocateTimerId(
    _In_ PTM_MANAGER Manager
    )
{
    LONG id;
    do {
        id = InterlockedIncrement(&Manager->NextTimerId);
        if (id == 0) {
            // Wrapped — skip 0 (invalid sentinel)
            id = InterlockedIncrement(&Manager->NextTimerId);
        }
    } while (id == 0);
    return (ULONG)id;
}

//=============================================================================
// Initialization / Shutdown
//=============================================================================

_Use_decl_annotations_
NTSTATUS
TmInitialize(
    _In_opt_ PDEVICE_OBJECT DeviceObject,
    _Out_ PTM_MANAGER* Manager
    )
/*++

Routine Description:

    Initializes the timer manager subsystem. Allocates the manager structure,
    initializes the timer wheel, and starts the wheel timer.

Arguments:

    DeviceObject - Device object for IoAllocateWorkItem (needed for
                   TmFlag_WorkItemCallback). May be NULL if work items
                   are not used.
    Manager      - Receives pointer to initialized timer manager.

Return Value:

    STATUS_SUCCESS on success.
    STATUS_INSUFFICIENT_RESOURCES if allocation fails.

IRQL:

    PASSIVE_LEVEL

--*/
{
    PTM_MANAGER mgr = NULL;
    ULONG i;
    LARGE_INTEGER dueTime;

    PAGED_CODE();

    if (Manager == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Manager = NULL;

    //
    // Allocate the manager structure from non-paged pool
    // (required for DPC and spinlock operations)
    //
    mgr = (PTM_MANAGER)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(TM_MANAGER),
        TM_POOL_TAG_CONTEXT
        );

    if (mgr == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(mgr, sizeof(TM_MANAGER));

    //
    // Store device object for WorkItem support
    //
    mgr->DeviceObject = DeviceObject;

    //
    // Initialize the timer list
    //
    InitializeListHead(&mgr->TimerList);
    KeInitializeSpinLock(&mgr->TimerListLock);
    mgr->TimerCount = 0;

    //
    // Initialize timer wheel slots
    //
    for (i = 0; i < TM_WHEEL_SIZE; i++) {
        InitializeListHead(&mgr->Wheel[i].TimerList);
        KeInitializeSpinLock(&mgr->Wheel[i].Lock);
        mgr->Wheel[i].TimerCount = 0;
    }

    mgr->CurrentSlot = 0;

    //
    // Initialize wheel timer and DPC
    //
    KeInitializeTimer(&mgr->WheelTimer);
    KeInitializeDpc(&mgr->WheelDpc, TmpWheelDpcRoutine, mgr);

    //
    // Initialize ID generation - start at 1 (0 is invalid)
    //
    mgr->NextTimerId = 0; // First InterlockedIncrement yields 1

    //
    // Initialize statistics
    //
    KeQuerySystemTimePrecise(&mgr->Stats.StartTime);

    //
    // Set default configuration
    //
    mgr->Config.DefaultToleranceMs = TM_DEFAULT_TOLERANCE_MS;
    mgr->Config.EnableCoalescing = TRUE;
    mgr->Config.EnableHighResolution = FALSE;

    //
    // Initialize work item drain support
    //
    mgr->PendingWorkItems = 0;
    KeInitializeEvent(&mgr->AllWorkItemsDrained, NotificationEvent, TRUE);

    //
    // Start the wheel timer - runs every TM_WHEEL_RESOLUTION_MS
    //
    dueTime.QuadPart = TM_MS_TO_RELATIVE(TM_WHEEL_RESOLUTION_MS);
    KeSetTimerEx(
        &mgr->WheelTimer,
        dueTime,
        TM_WHEEL_RESOLUTION_MS,
        &mgr->WheelDpc
        );

    //
    // Mark as initialized LAST (after all setup is done)
    //
    InterlockedExchange(&mgr->Initialized, 1);

    *Manager = mgr;

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
TmShutdown(
    _Inout_ PTM_MANAGER Manager
    )
/*++

Routine Description:

    Shuts down the timer manager. Cancels all pending timers, stops the
    wheel timer, and frees all resources.

Arguments:

    Manager - Timer manager to shutdown.

IRQL:

    PASSIVE_LEVEL

--*/
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    PTM_TIMER_INTERNAL timerInternal;
    LIST_ENTRY timersToFree;
    ULONG slotIndex;

    PAGED_CODE();

    if (Manager == NULL) {
        return;
    }

    //
    // Atomically transition Initialized 1→0. Only one caller proceeds.
    //
    if (InterlockedCompareExchange(&Manager->Initialized, 0, 1) != 1) {
        return;
    }

    //
    // Signal shutdown
    //
    InterlockedExchange(&Manager->ShuttingDown, 1);
    KeMemoryBarrier();

    //
    // Cancel the wheel timer and wait for its DPC to drain
    //
    KeCancelTimer(&Manager->WheelTimer);
    KeFlushQueuedDpcs();

    //
    // Build list of timers to free (can't free while holding lock)
    //
    InitializeListHead(&timersToFree);

    //
    // Cancel all timers and move to local free list
    //
    KeAcquireSpinLock(&Manager->TimerListLock, &oldIrql);

    while (!IsListEmpty(&Manager->TimerList)) {
        entry = RemoveHeadList(&Manager->TimerList);
        timerInternal = CONTAINING_RECORD(entry, TM_TIMER_INTERNAL, Timer.ListEntry);

        //
        // Cancel the kernel timer
        //
        KeCancelTimer(&timerInternal->Timer.KernelTimer);

        //
        // Mark as cancelled
        //
        InterlockedExchange(&timerInternal->Timer.State, (LONG)TmTimerState_Cancelled);
        InterlockedExchange(&timerInternal->DeletionPending, 1);

        //
        // Add to local free list (reuse ListEntry since we removed from TimerList)
        //
        InsertTailList(&timersToFree, &timerInternal->Timer.ListEntry);
    }

    Manager->TimerCount = 0;
    KeReleaseSpinLock(&Manager->TimerListLock, oldIrql);

    //
    // Clean out all wheel slots
    //
    for (slotIndex = 0; slotIndex < TM_WHEEL_SIZE; slotIndex++) {
        KeAcquireSpinLock(&Manager->Wheel[slotIndex].Lock, &oldIrql);
        InitializeListHead(&Manager->Wheel[slotIndex].TimerList);
        Manager->Wheel[slotIndex].TimerCount = 0;
        KeReleaseSpinLock(&Manager->Wheel[slotIndex].Lock, oldIrql);
    }

    //
    // Wait for any in-flight DPCs to complete.
    // NOTE: KeFlushQueuedDpcs only drains DPCs — it does NOT wait for
    // work items that those DPCs may have queued via IoQueueWorkItem.
    //
    KeFlushQueuedDpcs();

    //
    // Wait for all in-flight work items to complete. DPCs increment
    // PendingWorkItems before IoQueueWorkItem; TmpWorkItemRoutine
    // decrements and signals AllWorkItemsDrained when it reaches 0.
    // Without this, IoFreeWorkItem on an active work item → BSOD.
    //
    if (Manager->PendingWorkItems > 0) {
        LARGE_INTEGER drainTimeout;
        drainTimeout.QuadPart = TM_SEC_TO_RELATIVE(10);
        KeWaitForSingleObject(
            &Manager->AllWorkItemsDrained,
            Executive,
            KernelMode,
            FALSE,
            &drainTimeout
            );
    }

    //
    // Now free all timers directly (bypass refcount — we own everything)
    //
    while (!IsListEmpty(&timersToFree)) {
        entry = RemoveHeadList(&timersToFree);
        timerInternal = CONTAINING_RECORD(entry, TM_TIMER_INTERNAL, Timer.ListEntry);

        //
        // Signal cancel event if anyone is waiting
        //
        KeSetEvent(&timerInternal->Timer.CancelEvent, IO_NO_INCREMENT, FALSE);

        //
        // Free work item if allocated
        //
        if (timerInternal->WorkItem != NULL) {
            IoFreeWorkItem(timerInternal->WorkItem);
            timerInternal->WorkItem = NULL;
        }

        //
        // Free context if we own it (ContextSize > 0 means we copied it)
        //
        if (timerInternal->Timer.Context != NULL &&
            timerInternal->Timer.ContextSize > 0) {
            ShadowStrikeFreePoolWithTag(
                timerInternal->Timer.Context,
                TM_POOL_TAG_CONTEXT
                );
        }

        //
        // Free timer structure
        //
        timerInternal->Signature = 0;
        ShadowStrikeFreePoolWithTag(timerInternal, TM_POOL_TAG_TIMER);
    }

    //
    // Free the manager
    //
    ShadowStrikeFreePoolWithTag(Manager, TM_POOL_TAG_CONTEXT);
}


//=============================================================================
// Timer Creation
//=============================================================================

_Use_decl_annotations_
NTSTATUS
TmCreateOneShot(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG DelayMs,
    _In_ TM_TIMER_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _In_opt_ PTM_TIMER_OPTIONS Options,
    _Out_ PULONG TimerId
    )
{
    LARGE_INTEGER dueTime;

    if (Manager == NULL || Callback == NULL || TimerId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Manager->Initialized || Manager->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (DelayMs < TM_MIN_PERIOD_MS || DelayMs > TM_MAX_PERIOD_MS) {
        return STATUS_INVALID_PARAMETER;
    }

    dueTime.QuadPart = TM_MS_TO_RELATIVE(DelayMs);

    return TmpCreateTimerInternal(
        Manager,
        TmTimerType_OneShot,
        &dueTime,
        0,
        Callback,
        Context,
        Options,
        TimerId
        );
}


_Use_decl_annotations_
NTSTATUS
TmCreatePeriodic(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG PeriodMs,
    _In_ TM_TIMER_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _In_opt_ PTM_TIMER_OPTIONS Options,
    _Out_ PULONG TimerId
    )
{
    LARGE_INTEGER dueTime;

    if (Manager == NULL || Callback == NULL || TimerId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Manager->Initialized || Manager->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (PeriodMs < TM_MIN_PERIOD_MS || PeriodMs > TM_MAX_PERIOD_MS) {
        return STATUS_INVALID_PARAMETER;
    }

    dueTime.QuadPart = TM_MS_TO_RELATIVE(PeriodMs);

    return TmpCreateTimerInternal(
        Manager,
        TmTimerType_Periodic,
        &dueTime,
        PeriodMs,
        Callback,
        Context,
        Options,
        TimerId
        );
}


_Use_decl_annotations_
NTSTATUS
TmCreateAbsolute(
    _In_ PTM_MANAGER Manager,
    _In_ PLARGE_INTEGER DueTime,
    _In_opt_ ULONG PeriodMs,
    _In_ TM_TIMER_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _In_opt_ PTM_TIMER_OPTIONS Options,
    _Out_ PULONG TimerId
    )
{
    TM_TIMER_TYPE type;

    if (Manager == NULL || DueTime == NULL ||
        Callback == NULL || TimerId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Manager->Initialized || Manager->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (PeriodMs != 0 && (PeriodMs < TM_MIN_PERIOD_MS || PeriodMs > TM_MAX_PERIOD_MS)) {
        return STATUS_INVALID_PARAMETER;
    }

    type = (PeriodMs > 0) ? TmTimerType_Periodic : TmTimerType_OneShot;

    return TmpCreateTimerInternal(
        Manager,
        type,
        DueTime,
        PeriodMs,
        Callback,
        Context,
        Options,
        TimerId
        );
}


//=============================================================================
// Timer Control
//=============================================================================

_Use_decl_annotations_
NTSTATUS
TmStart(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG TimerId
    )
/*++

Routine Description:

    Starts a timer that was created but not yet active.

--*/
{
    PTM_TIMER_INTERNAL timerInternal;
    NTSTATUS status;

    if (Manager == NULL || TimerId == TM_INVALID_TIMER_ID) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Manager->Initialized || Manager->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    timerInternal = TmpFindTimerById(Manager, TimerId);
    if (timerInternal == NULL) {
        return STATUS_NOT_FOUND;
    }

    status = TmpStartTimerInternal(Manager, timerInternal);

    TmpDereferenceTimer(timerInternal);

    return status;
}


_Use_decl_annotations_
NTSTATUS
TmStop(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG TimerId
    )
/*++

Routine Description:

    Stops (pauses) a timer without destroying it. Timer can be restarted.

--*/
{
    PTM_TIMER_INTERNAL timerInternal;

    if (Manager == NULL || TimerId == TM_INVALID_TIMER_ID) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Manager->Initialized || Manager->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    timerInternal = TmpFindTimerById(Manager, TimerId);
    if (timerInternal == NULL) {
        return STATUS_NOT_FOUND;
    }

    TmpStopTimerInternal(Manager, timerInternal);

    TmpDereferenceTimer(timerInternal);

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
TmCancel(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG TimerId,
    _In_ BOOLEAN Wait
    )
/*++

Routine Description:

    Cancels and destroys a timer.

    Wait=TRUE: If the timer is currently in Firing state, wait at
    PASSIVE_LEVEL for the callback to complete before returning.

    Reference counting:
    - TmpFindTimerById adds +1 (find ref).
    - We remove from TimerList (releases the list ref via deref).
    - We release the find ref.
    - When refcount hits 0, TmpDestroyTimer frees the memory.

--*/
{
    PTM_TIMER_INTERNAL timerInternal;
    KIRQL oldIrql;
    LONG prevState;
    BOOLEAN needWait = FALSE;

    if (Manager == NULL || TimerId == TM_INVALID_TIMER_ID) {
        return STATUS_INVALID_PARAMETER;
    }

    timerInternal = TmpFindTimerById(Manager, TimerId);
    if (timerInternal == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Mark deletion pending atomically (prevents double-cancel)
    //
    if (InterlockedCompareExchange(&timerInternal->DeletionPending, 1, 0) != 0) {
        // Already being deleted by another thread
        TmpDereferenceTimer(timerInternal);
        return STATUS_SUCCESS;
    }

    //
    // Set cancel requested
    //
    InterlockedExchange(&timerInternal->Timer.CancelRequested, 1);

    //
    // Capture previous state BEFORE we transition to Cancelled.
    // This is critical: if state was Firing, we know callback is in-flight.
    //
    prevState = InterlockedExchange(&timerInternal->Timer.State,
                                    (LONG)TmTimerState_Cancelled);

    if (Wait && prevState == (LONG)TmTimerState_Firing) {
        needWait = TRUE;
    }

    //
    // Cancel the kernel timer (harmless if already fired/cancelled)
    //
    KeCancelTimer(&timerInternal->Timer.KernelTimer);

    //
    // Remove from wheel
    //
    TmpRemoveTimerFromWheel(Manager, timerInternal);

    //
    // Remove from global list (releases list reference)
    //
    KeAcquireSpinLock(&Manager->TimerListLock, &oldIrql);
    RemoveEntryList(&timerInternal->Timer.ListEntry);
    InitializeListHead(&timerInternal->Timer.ListEntry);
    InterlockedDecrement(&Manager->TimerCount);
    KeReleaseSpinLock(&Manager->TimerListLock, oldIrql);

    //
    // Update statistics
    //
    InterlockedIncrement64(&Manager->Stats.TimersCancelled);

    //
    // If callback is in-flight and caller wants to wait, do so now.
    // CancelEvent is signaled by TmpFireTimer after callback returns.
    //
    if (needWait && KeGetCurrentIrql() == PASSIVE_LEVEL) {
        LARGE_INTEGER timeout;
        timeout.QuadPart = TM_SEC_TO_RELATIVE(5); // 5 second max wait
        KeWaitForSingleObject(
            &timerInternal->Timer.CancelEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout
            );
    }

    //
    // Signal cancel event for any other waiters
    //
    KeSetEvent(&timerInternal->Timer.CancelEvent, IO_NO_INCREMENT, FALSE);

    //
    // Release list reference (timer was in list, now removed)
    //
    TmpDereferenceTimer(timerInternal);

    //
    // Release find reference
    //
    TmpDereferenceTimer(timerInternal);

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
TmReset(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG TimerId
    )
/*++

Routine Description:

    Resets a timer — stops it and starts it again with same parameters.
    Uses direct internal calls on the found timer, avoiding triple-lookup.

--*/
{
    PTM_TIMER_INTERNAL timerInternal;
    NTSTATUS status;

    if (Manager == NULL || TimerId == TM_INVALID_TIMER_ID) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Manager->Initialized || Manager->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    timerInternal = TmpFindTimerById(Manager, TimerId);
    if (timerInternal == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Stop directly on the found object (no second Find)
    //
    TmpStopTimerInternal(Manager, timerInternal);

    //
    // Start directly on the found object (no third Find)
    //
    status = TmpStartTimerInternal(Manager, timerInternal);

    TmpDereferenceTimer(timerInternal);

    return status;
}


_Use_decl_annotations_
NTSTATUS
TmSetPeriod(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG TimerId,
    _In_ ULONG NewPeriodMs
    )
/*++

Routine Description:

    Modifies the period of a periodic timer. Stops, updates, restarts.
    Uses direct internal calls, avoiding triple-lookup.

--*/
{
    PTM_TIMER_INTERNAL timerInternal;
    BOOLEAN wasActive;

    if (Manager == NULL || TimerId == TM_INVALID_TIMER_ID) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Manager->Initialized || Manager->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (NewPeriodMs < TM_MIN_PERIOD_MS || NewPeriodMs > TM_MAX_PERIOD_MS) {
        return STATUS_INVALID_PARAMETER;
    }

    timerInternal = TmpFindTimerById(Manager, TimerId);
    if (timerInternal == NULL) {
        return STATUS_NOT_FOUND;
    }

    if (timerInternal->Timer.Type != TmTimerType_Periodic) {
        TmpDereferenceTimer(timerInternal);
        return STATUS_INVALID_PARAMETER;
    }

    wasActive = (InterlockedCompareExchange(&timerInternal->Timer.State,
                 (LONG)TmTimerState_Active, (LONG)TmTimerState_Active)
                 == (LONG)TmTimerState_Active);

    if (wasActive) {
        TmpStopTimerInternal(Manager, timerInternal);
    }

    //
    // Update period
    //
    timerInternal->Timer.Period.QuadPart = TM_MS_TO_RELATIVE(NewPeriodMs);
    timerInternal->Timer.DueTime.QuadPart = TM_MS_TO_RELATIVE(NewPeriodMs);

    if (wasActive) {
        TmpStartTimerInternal(Manager, timerInternal);
    }

    TmpDereferenceTimer(timerInternal);

    return STATUS_SUCCESS;
}


//=============================================================================
// Timer Query
//=============================================================================

_Use_decl_annotations_
NTSTATUS
TmGetState(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG TimerId,
    _Out_ PLONG State
    )
{
    PTM_TIMER_INTERNAL timerInternal;

    if (Manager == NULL || TimerId == TM_INVALID_TIMER_ID || State == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Manager->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    timerInternal = TmpFindTimerById(Manager, TimerId);
    if (timerInternal == NULL) {
        return STATUS_NOT_FOUND;
    }

    *State = timerInternal->Timer.State;

    TmpDereferenceTimer(timerInternal);

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
TmGetRemaining(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG TimerId,
    _Out_ PLARGE_INTEGER Remaining
    )
{
    PTM_TIMER_INTERNAL timerInternal;
    LARGE_INTEGER currentTime;

    if (Manager == NULL || TimerId == TM_INVALID_TIMER_ID || Remaining == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Manager->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    timerInternal = TmpFindTimerById(Manager, TimerId);
    if (timerInternal == NULL) {
        return STATUS_NOT_FOUND;
    }

    if (timerInternal->Timer.State != (LONG)TmTimerState_Active) {
        Remaining->QuadPart = 0;
        TmpDereferenceTimer(timerInternal);
        return STATUS_SUCCESS;
    }

    KeQuerySystemTimePrecise(&currentTime);
    Remaining->QuadPart = timerInternal->Timer.NextFireTime.QuadPart -
                          currentTime.QuadPart;

    if (Remaining->QuadPart < 0) {
        Remaining->QuadPart = 0;
    }

    TmpDereferenceTimer(timerInternal);

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
BOOLEAN
TmIsActive(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG TimerId
    )
{
    PTM_TIMER_INTERNAL timerInternal;
    BOOLEAN isActive;
    LONG state;

    if (Manager == NULL || !Manager->Initialized ||
        TimerId == TM_INVALID_TIMER_ID) {
        return FALSE;
    }

    timerInternal = TmpFindTimerById(Manager, TimerId);
    if (timerInternal == NULL) {
        return FALSE;
    }

    state = timerInternal->Timer.State;
    isActive = (state == (LONG)TmTimerState_Active ||
                state == (LONG)TmTimerState_Firing);

    TmpDereferenceTimer(timerInternal);

    return isActive;
}


//=============================================================================
// Bulk Operations
//=============================================================================

_Use_decl_annotations_
VOID
TmCancelAll(
    _In_ PTM_MANAGER Manager,
    _In_ BOOLEAN Wait
    )
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    PTM_TIMER_INTERNAL timerInternal;
    ULONG timerIds[64];
    ULONG count;
    ULONG i;

    if (Manager == NULL || !Manager->Initialized) {
        return;
    }

    //
    // Iterate in batches — TmCancel modifies the list so we can't
    // cancel while iterating.
    //
    do {
        count = 0;

        KeAcquireSpinLock(&Manager->TimerListLock, &oldIrql);

        for (entry = Manager->TimerList.Flink;
             entry != &Manager->TimerList && count < ARRAYSIZE(timerIds);
             entry = entry->Flink) {

            timerInternal = CONTAINING_RECORD(entry, TM_TIMER_INTERNAL,
                                              Timer.ListEntry);

            if (!timerInternal->DeletionPending) {
                timerIds[count++] = timerInternal->Timer.TimerId;
            }
        }

        KeReleaseSpinLock(&Manager->TimerListLock, oldIrql);

        for (i = 0; i < count; i++) {
            TmCancel(Manager, timerIds[i], Wait);
        }

    } while (count > 0);
}


_Use_decl_annotations_
VOID
TmCancelGroup(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG CoalesceGroup,
    _In_ BOOLEAN Wait
    )
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    PTM_TIMER_INTERNAL timerInternal;
    ULONG timerIds[64];
    ULONG count;
    ULONG i;

    if (Manager == NULL || !Manager->Initialized) {
        return;
    }

    do {
        count = 0;

        KeAcquireSpinLock(&Manager->TimerListLock, &oldIrql);

        for (entry = Manager->TimerList.Flink;
             entry != &Manager->TimerList && count < ARRAYSIZE(timerIds);
             entry = entry->Flink) {

            timerInternal = CONTAINING_RECORD(entry, TM_TIMER_INTERNAL,
                                              Timer.ListEntry);

            if (!timerInternal->DeletionPending &&
                timerInternal->Timer.CoalesceGroup == CoalesceGroup) {
                timerIds[count++] = timerInternal->Timer.TimerId;
            }
        }

        KeReleaseSpinLock(&Manager->TimerListLock, oldIrql);

        for (i = 0; i < count; i++) {
            TmCancel(Manager, timerIds[i], Wait);
        }

    } while (count > 0);
}


//=============================================================================
// Statistics
//=============================================================================

_Use_decl_annotations_
NTSTATUS
TmGetStatistics(
    _In_ PTM_MANAGER Manager,
    _Out_ PTM_STATISTICS Stats
    )
{
    LARGE_INTEGER currentTime;

    if (Manager == NULL || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Manager->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    RtlZeroMemory(Stats, sizeof(TM_STATISTICS));

    Stats->ActiveTimers = (ULONG)Manager->TimerCount;
    Stats->TimersCreated = (ULONG64)Manager->Stats.TimersCreated;
    Stats->TimersFired = (ULONG64)Manager->Stats.TimersFired;
    Stats->TimersCancelled = (ULONG64)Manager->Stats.TimersCancelled;
    Stats->TimersMissed = (ULONG64)Manager->Stats.TimersMissed;
    Stats->CoalescedTimers = (ULONG64)Manager->Stats.CoalescedTimers;

    KeQuerySystemTimePrecise(&currentTime);
    Stats->UpTime.QuadPart = currentTime.QuadPart -
                             Manager->Stats.StartTime.QuadPart;

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
TmResetStatistics(
    _Inout_ PTM_MANAGER Manager
    )
{
    if (Manager == NULL || !Manager->Initialized) {
        return;
    }

    InterlockedExchange64(&Manager->Stats.TimersCreated, 0);
    InterlockedExchange64(&Manager->Stats.TimersFired, 0);
    InterlockedExchange64(&Manager->Stats.TimersCancelled, 0);
    InterlockedExchange64(&Manager->Stats.TimersMissed, 0);
    InterlockedExchange64(&Manager->Stats.CoalescedTimers, 0);

    KeQuerySystemTimePrecise(&Manager->Stats.StartTime);
}


//=============================================================================
// Internal Functions
//=============================================================================

static
_Use_decl_annotations_
NTSTATUS
TmpCreateTimerInternal(
    _In_ PTM_MANAGER Manager,
    _In_ TM_TIMER_TYPE Type,
    _In_ PLARGE_INTEGER DueTime,
    _In_ ULONG PeriodMs,
    _In_ TM_TIMER_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _In_opt_ PTM_TIMER_OPTIONS Options,
    _Out_ PULONG TimerId
    )
/*++

Routine Description:

    Internal timer creation routine. Allocates the internal structure,
    copies context if specified, pre-allocates a WorkItem if needed,
    and optionally auto-starts the timer.

--*/
{
    PTM_TIMER_INTERNAL timerInternal = NULL;
    KIRQL oldIrql;
    NTSTATUS status = STATUS_SUCCESS;
    PVOID contextCopy = NULL;
    LONG currentCount;

    *TimerId = TM_INVALID_TIMER_ID;

    //
    // Check timer limit atomically
    //
    do {
        currentCount = Manager->TimerCount;
        if (currentCount >= TM_MAX_TIMERS) {
            return STATUS_QUOTA_EXCEEDED;
        }
    } while (InterlockedCompareExchange(&Manager->TimerCount,
             currentCount + 1, currentCount) != currentCount);

    //
    // Allocate timer structure
    //
    timerInternal = (PTM_TIMER_INTERNAL)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(TM_TIMER_INTERNAL),
        TM_POOL_TAG_TIMER
        );

    if (timerInternal == NULL) {
        InterlockedDecrement(&Manager->TimerCount);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(timerInternal, sizeof(TM_TIMER_INTERNAL));

    //
    // Copy context if provided and size specified (we take ownership)
    //
    if (Options != NULL && Options->Context != NULL && Options->ContextSize > 0) {
        contextCopy = ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            Options->ContextSize,
            TM_POOL_TAG_CONTEXT
            );

        if (contextCopy == NULL) {
            ShadowStrikeFreePoolWithTag(timerInternal, TM_POOL_TAG_TIMER);
            InterlockedDecrement(&Manager->TimerCount);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(contextCopy, Options->Context, Options->ContextSize);
        timerInternal->Timer.Context = contextCopy;
        timerInternal->Timer.ContextSize = Options->ContextSize;
    }
    else {
        // Caller owns Context lifetime (ContextSize = 0)
        timerInternal->Timer.Context = Context;
        timerInternal->Timer.ContextSize = 0;
    }

    //
    // Pre-allocate work item if WorkItemCallback is requested
    //
    if (Options != NULL && (Options->Flags & TmFlag_WorkItemCallback)) {
        if (Manager->DeviceObject == NULL) {
            // Can't use WorkItemCallback without a device object
            if (contextCopy != NULL) {
                ShadowStrikeFreePoolWithTag(contextCopy, TM_POOL_TAG_CONTEXT);
            }
            ShadowStrikeFreePoolWithTag(timerInternal, TM_POOL_TAG_TIMER);
            InterlockedDecrement(&Manager->TimerCount);
            return STATUS_INVALID_PARAMETER;
        }

        timerInternal->WorkItem = IoAllocateWorkItem(Manager->DeviceObject);
        if (timerInternal->WorkItem == NULL) {
            if (contextCopy != NULL) {
                ShadowStrikeFreePoolWithTag(contextCopy, TM_POOL_TAG_CONTEXT);
            }
            ShadowStrikeFreePoolWithTag(timerInternal, TM_POOL_TAG_TIMER);
            InterlockedDecrement(&Manager->TimerCount);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    //
    // Initialize signature and back-reference
    //
    timerInternal->Signature = TM_TIMER_SIGNATURE;
    timerInternal->Manager = Manager;

    //
    // Initialize kernel timer and DPC
    //
    KeInitializeTimer(&timerInternal->Timer.KernelTimer);
    KeInitializeDpc(&timerInternal->Timer.TimerDpc, TmpTimerDpcRoutine,
                    timerInternal);

    //
    // Generate unique timer ID (never 0)
    //
    timerInternal->Timer.TimerId = TmpAllocateTimerId(Manager);

    //
    // Set timer properties
    //
    timerInternal->Timer.Type = Type;
    timerInternal->Timer.DueTime = *DueTime;
    timerInternal->Timer.Period.QuadPart =
        (PeriodMs > 0) ? TM_MS_TO_RELATIVE(PeriodMs) : 0;
    timerInternal->Timer.Callback = Callback;
    timerInternal->Timer.State = (LONG)TmTimerState_Created;

    //
    // Apply options
    //
    if (Options != NULL) {
        timerInternal->Timer.Flags = Options->Flags;
        timerInternal->Timer.ToleranceMs = Options->ToleranceMs;
        timerInternal->Timer.CoalesceGroup = Options->CoalesceGroup;

        if (Options->Name != NULL) {
            RtlStringCchCopyA(
                timerInternal->Timer.Name,
                TM_TIMER_NAME_MAX,
                Options->Name
                );
        }
    }
    else {
        timerInternal->Timer.Flags = TmFlag_Coalescable;
        timerInternal->Timer.ToleranceMs = Manager->Config.DefaultToleranceMs;
        timerInternal->Timer.CoalesceGroup = 0;
    }

    //
    // Initialize synchronization
    //
    KeInitializeEvent(&timerInternal->Timer.CancelEvent,
                      NotificationEvent, FALSE);

    //
    // Set initial reference count: 1 for TimerList, 1 for creation
    //
    timerInternal->Timer.RefCount = 2;

    //
    // Initialize statistics
    //
    KeQuerySystemTimePrecise(&timerInternal->Timer.CreationTime);

    //
    // Initialize list entries
    //
    InitializeListHead(&timerInternal->Timer.ListEntry);
    InitializeListHead(&timerInternal->Timer.WheelEntry);

    //
    // Insert into global timer list
    // (TimerCount was already atomically reserved above)
    //
    KeAcquireSpinLock(&Manager->TimerListLock, &oldIrql);
    InsertTailList(&Manager->TimerList, &timerInternal->Timer.ListEntry);
    KeReleaseSpinLock(&Manager->TimerListLock, oldIrql);

    //
    // Update statistics
    //
    InterlockedIncrement64(&Manager->Stats.TimersCreated);

    *TimerId = timerInternal->Timer.TimerId;

    //
    // Auto-start if not using manual start (Synchronized flag)
    //
    if (!(timerInternal->Timer.Flags & TmFlag_Synchronized)) {
        status = TmpStartTimerInternal(Manager, timerInternal);
        if (!NT_SUCCESS(status)) {
            TmCancel(Manager, timerInternal->Timer.TimerId, FALSE);
            *TimerId = TM_INVALID_TIMER_ID;
            return status;
        }
    }

    return STATUS_SUCCESS;
}


static
_Use_decl_annotations_
PTM_TIMER_INTERNAL
TmpFindTimerById(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG TimerId
    )
/*++

Routine Description:

    Finds a timer by ID and returns it with incremented reference count.
    Caller MUST call TmpDereferenceTimer when done.

--*/
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    PTM_TIMER_INTERNAL timerInternal;
    PTM_TIMER_INTERNAL result = NULL;

    KeAcquireSpinLock(&Manager->TimerListLock, &oldIrql);

    for (entry = Manager->TimerList.Flink;
         entry != &Manager->TimerList;
         entry = entry->Flink) {

        timerInternal = CONTAINING_RECORD(entry, TM_TIMER_INTERNAL,
                                          Timer.ListEntry);

        if (timerInternal->Timer.TimerId == TimerId &&
            !timerInternal->DeletionPending) {
            TmpReferenceTimer(timerInternal);
            result = timerInternal;
            break;
        }
    }

    KeReleaseSpinLock(&Manager->TimerListLock, oldIrql);

    return result;
}


static
_Use_decl_annotations_
VOID
TmpReferenceTimer(
    _Inout_ PTM_TIMER_INTERNAL TimerInternal
    )
{
    LONG newRef = InterlockedIncrement(&TimerInternal->Timer.RefCount);
    NT_ASSERT(newRef >= 2); // New value >= 2 means old value was >= 1
    UNREFERENCED_PARAMETER(newRef);
}


static
_Use_decl_annotations_
VOID
TmpDereferenceTimer(
    _Inout_ PTM_TIMER_INTERNAL TimerInternal
    )
{
    LONG newCount;

    newCount = InterlockedDecrement(&TimerInternal->Timer.RefCount);
    NT_ASSERT(newCount >= 0);

    if (newCount == 0) {
        TmpDestroyTimer(TimerInternal);
    }
}


static
_Use_decl_annotations_
VOID
TmpDestroyTimer(
    _Inout_ PTM_TIMER_INTERNAL TimerInternal
    )
/*++

Routine Description:

    Frees timer resources. Called when reference count reaches zero.
    At this point, the timer is no longer in any list.

--*/
{
    //
    // Ensure kernel timer is cancelled
    //
    KeCancelTimer(&TimerInternal->Timer.KernelTimer);

    //
    // Free work item if allocated
    //
    if (TimerInternal->WorkItem != NULL) {
        IoFreeWorkItem(TimerInternal->WorkItem);
        TimerInternal->WorkItem = NULL;
    }

    //
    // Free copied context if we own it (ContextSize > 0)
    //
    if (TimerInternal->Timer.Context != NULL &&
        TimerInternal->Timer.ContextSize > 0) {
        ShadowStrikeFreePoolWithTag(
            TimerInternal->Timer.Context,
            TM_POOL_TAG_CONTEXT
            );
    }

    //
    // Clear signature and free
    //
    TimerInternal->Signature = 0;
    ShadowStrikeFreePoolWithTag(TimerInternal, TM_POOL_TAG_TIMER);
}


//=============================================================================
// Internal: Start / Stop (operate on already-found timer, no re-lookup)
//=============================================================================

static
_Use_decl_annotations_
NTSTATUS
TmpStartTimerInternal(
    _In_ PTM_MANAGER Manager,
    _Inout_ PTM_TIMER_INTERNAL TimerInternal
    )
/*++

Routine Description:

    Starts a timer. Called with a reference already held.
    Uses InterlockedCompareExchange for state transition.

--*/
{
    ULONG tolerableDelayMs;
    LONG prevState;

    //
    // Atomically transition Created → Active
    //
    prevState = InterlockedCompareExchange(
        &TimerInternal->Timer.State,
        (LONG)TmTimerState_Active,
        (LONG)TmTimerState_Created
        );

    if (prevState != (LONG)TmTimerState_Created) {
        return STATUS_INVALID_STATE_TRANSITION;
    }

    //
    // Calculate next fire time
    //
    KeQuerySystemTimePrecise(&TimerInternal->Timer.NextFireTime);
    // DueTime is negative (relative), so subtract to get absolute future time
    TimerInternal->Timer.NextFireTime.QuadPart -=
        TimerInternal->Timer.DueTime.QuadPart;

    //
    // Set the kernel timer
    //
    if ((TimerInternal->Timer.Flags & TmFlag_Coalescable) &&
        Manager->Config.EnableCoalescing) {

        tolerableDelayMs = TimerInternal->Timer.ToleranceMs;
        if (tolerableDelayMs == 0) {
            tolerableDelayMs = Manager->Config.DefaultToleranceMs;
        }

        KeSetCoalescableTimer(
            &TimerInternal->Timer.KernelTimer,
            TimerInternal->Timer.DueTime,
            (TimerInternal->Timer.Type == TmTimerType_Periodic) ?
                (ULONG)(TimerInternal->Timer.Period.QuadPart / -10000LL) : 0,
            tolerableDelayMs,
            &TimerInternal->Timer.TimerDpc
            );

        InterlockedIncrement64(&Manager->Stats.CoalescedTimers);
    }
    else {
        KeSetTimerEx(
            &TimerInternal->Timer.KernelTimer,
            TimerInternal->Timer.DueTime,
            (TimerInternal->Timer.Type == TmTimerType_Periodic) ?
                (LONG)(TimerInternal->Timer.Period.QuadPart / -10000LL) : 0,
            &TimerInternal->Timer.TimerDpc
            );
    }

    //
    // Insert into timer wheel for deadline tracking
    //
    TmpInsertTimerIntoWheel(Manager, TimerInternal);

    return STATUS_SUCCESS;
}


static
_Use_decl_annotations_
VOID
TmpStopTimerInternal(
    _In_ PTM_MANAGER Manager,
    _Inout_ PTM_TIMER_INTERNAL TimerInternal
    )
/*++

Routine Description:

    Stops a timer. Called with a reference already held.
    Transitions state back to Created so it can be restarted.

--*/
{
    //
    // Cancel the kernel timer
    //
    KeCancelTimer(&TimerInternal->Timer.KernelTimer);

    //
    // Remove from wheel
    //
    TmpRemoveTimerFromWheel(Manager, TimerInternal);

    //
    // Transition to Created (can be restarted)
    //
    InterlockedExchange(&TimerInternal->Timer.State,
                        (LONG)TmTimerState_Created);
}


//=============================================================================
// Timer Wheel
//=============================================================================

static
_Use_decl_annotations_
VOID
TmpInsertTimerIntoWheel(
    _In_ PTM_MANAGER Manager,
    _Inout_ PTM_TIMER_INTERNAL TimerInternal
    )
{
    KIRQL oldIrql;
    ULONG slotIndex;
    LARGE_INTEGER currentTime;
    LONGLONG ticksUntilFire;
    ULONG slotsUntilFire;

    KeQuerySystemTimePrecise(&currentTime);
    ticksUntilFire = TimerInternal->Timer.NextFireTime.QuadPart -
                     currentTime.QuadPart;

    if (ticksUntilFire <= 0) {
        slotIndex = (ULONG)Manager->CurrentSlot & TM_WHEEL_MASK;
    }
    else {
        slotsUntilFire = (ULONG)((ticksUntilFire / 10000LL) /
                          TM_WHEEL_RESOLUTION_MS);

        if (slotsUntilFire >= TM_WHEEL_SIZE) {
            slotsUntilFire = TM_WHEEL_SIZE - 1;
        }

        slotIndex = ((ULONG)Manager->CurrentSlot + slotsUntilFire) &
                    TM_WHEEL_MASK;
    }

    TimerInternal->WheelSlotIndex = slotIndex;

    KeAcquireSpinLock(&Manager->Wheel[slotIndex].Lock, &oldIrql);
    InsertTailList(&Manager->Wheel[slotIndex].TimerList,
                   &TimerInternal->Timer.WheelEntry);
    InterlockedIncrement(&Manager->Wheel[slotIndex].TimerCount);
    InterlockedExchange(&TimerInternal->InWheelSlot, 1);
    KeReleaseSpinLock(&Manager->Wheel[slotIndex].Lock, oldIrql);
}


static
_Use_decl_annotations_
VOID
TmpRemoveTimerFromWheel(
    _In_ PTM_MANAGER Manager,
    _Inout_ PTM_TIMER_INTERNAL TimerInternal
    )
{
    KIRQL oldIrql;
    ULONG slotIndex;

    //
    // Only remove if we're actually in a wheel slot
    //
    if (InterlockedCompareExchange(&TimerInternal->InWheelSlot, 0, 1) != 1) {
        return;
    }

    slotIndex = TimerInternal->WheelSlotIndex;

    if (slotIndex < TM_WHEEL_SIZE) {
        KeAcquireSpinLock(&Manager->Wheel[slotIndex].Lock, &oldIrql);

        //
        // Check that WheelEntry is still linked (not already removed)
        //
        if (!IsListEmpty(&TimerInternal->Timer.WheelEntry)) {
            RemoveEntryList(&TimerInternal->Timer.WheelEntry);
            InitializeListHead(&TimerInternal->Timer.WheelEntry);
            InterlockedDecrement(&Manager->Wheel[slotIndex].TimerCount);
        }

        KeReleaseSpinLock(&Manager->Wheel[slotIndex].Lock, oldIrql);
    }
}


//=============================================================================
// Timer Firing
//=============================================================================

static
_Use_decl_annotations_
VOID
TmpFireTimer(
    _Inout_ PTM_TIMER_INTERNAL TimerInternal
    )
/*++

Routine Description:

    Fires the timer callback. Handles state transitions and auto-delete.

    Reference counting for auto-delete one-shot:
      Before DPC/WorkItem calls us: RefCount = 3 (list + creation + caller)
      We release list ref and creation ref (2 derefs) → RefCount = 1 (caller)
      Caller releases its ref → RefCount = 0 → TmpDestroyTimer.
      Both our derefs are safe because the caller's ref keeps RefCount ≥ 1.

--*/
{
    PTM_MANAGER manager;
    LARGE_INTEGER currentTime;
    KIRQL oldIrql;

    manager = TimerInternal->Manager;

    //
    // Check for cancellation or shutdown
    //
    if (TimerInternal->Timer.CancelRequested || manager->ShuttingDown) {
        KeSetEvent(&TimerInternal->Timer.CancelEvent,
                   IO_NO_INCREMENT, FALSE);
        return;
    }

    //
    // Transition to firing state
    //
    InterlockedExchange(&TimerInternal->Timer.State,
                        (LONG)TmTimerState_Firing);

    //
    // Update statistics
    //
    KeQuerySystemTimePrecise(&currentTime);
    TimerInternal->Timer.LastFireTime = currentTime;
    InterlockedIncrement64(&TimerInternal->Timer.FireCount);
    InterlockedIncrement64(&manager->Stats.TimersFired);

    //
    // Invoke callback
    //
    if (TimerInternal->Timer.Callback != NULL) {
        TimerInternal->Timer.Callback(
            TimerInternal->Timer.TimerId,
            TimerInternal->Timer.Context
            );
    }

    //
    // Handle post-fire state transition
    //
    if (TimerInternal->Timer.CancelRequested) {
        InterlockedExchange(&TimerInternal->Timer.State,
                            (LONG)TmTimerState_Cancelled);
        KeSetEvent(&TimerInternal->Timer.CancelEvent,
                   IO_NO_INCREMENT, FALSE);
    }
    else if (TimerInternal->Timer.Type == TmTimerType_OneShot) {
        InterlockedExchange(&TimerInternal->Timer.State,
                            (LONG)TmTimerState_Expired);

        //
        // Auto-delete: remove from list, release list ref + creation ref.
        // Caller (DPC/WorkItem) still holds a ref, so these won't hit 0.
        //
        if (TimerInternal->Timer.Flags & TmFlag_AutoDelete) {
            InterlockedExchange(&TimerInternal->DeletionPending, 1);

            // Remove from TimerList
            KeAcquireSpinLock(&manager->TimerListLock, &oldIrql);
            RemoveEntryList(&TimerInternal->Timer.ListEntry);
            InitializeListHead(&TimerInternal->Timer.ListEntry);
            InterlockedDecrement(&manager->TimerCount);
            KeReleaseSpinLock(&manager->TimerListLock, oldIrql);

            // Remove from wheel
            TmpRemoveTimerFromWheel(manager, TimerInternal);

            // Release list reference (RefCount 3→2, safe: caller holds ref)
            TmpDereferenceTimer(TimerInternal);

            // Release creation reference (RefCount 2→1, safe: caller holds ref)
            TmpDereferenceTimer(TimerInternal);
        }
    }
    else if (TimerInternal->Timer.Type == TmTimerType_Periodic) {
        //
        // Calculate next fire time and re-insert into wheel
        // Period is negative (relative), so subtract to add time
        //
        TimerInternal->Timer.NextFireTime.QuadPart =
            currentTime.QuadPart - TimerInternal->Timer.Period.QuadPart;

        InterlockedExchange(&TimerInternal->Timer.State,
                            (LONG)TmTimerState_Active);

        TmpRemoveTimerFromWheel(manager, TimerInternal);
        TmpInsertTimerIntoWheel(manager, TimerInternal);
    }

    //
    // Signal cancel event so anyone waiting on TmCancel can proceed
    //
    KeSetEvent(&TimerInternal->Timer.CancelEvent,
               IO_NO_INCREMENT, FALSE);
}


//=============================================================================
// DPC Routines
//=============================================================================

_Use_decl_annotations_
static
VOID
TmpTimerDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
/*++

Routine Description:

    DPC routine called when a kernel timer fires. Runs at DISPATCH_LEVEL.

    If TmFlag_WorkItemCallback is set and a WorkItem was pre-allocated,
    queues the work item for PASSIVE_LEVEL execution (work item routine
    is responsible for releasing the DPC reference). Otherwise, fires
    the callback directly at DISPATCH_LEVEL.

    Always releases its DPC reference. For auto-delete one-shots,
    TmpFireTimer releases list + creation refs (both safe because our
    DPC ref keeps RefCount ≥ 1), then our deref hits 0 → destroy.

--*/
{
    PTM_TIMER_INTERNAL timerInternal;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    timerInternal = (PTM_TIMER_INTERNAL)DeferredContext;

    if (timerInternal == NULL) {
        return;
    }

    //
    // Add reference for this DPC execution
    //
    TmpReferenceTimer(timerInternal);

    //
    // If manager is shutting down, do not queue work items or fire.
    // TmShutdown will handle cleanup. Release our DPC ref and bail.
    //
    if (timerInternal->Manager->ShuttingDown) {
        TmpDereferenceTimer(timerInternal);
        return;
    }

    //
    // Route to work item for PASSIVE_LEVEL execution if requested.
    // Increment PendingWorkItems BEFORE IoQueueWorkItem so TmShutdown
    // knows to wait. TmpWorkItemRoutine will decrement and signal.
    //
    if ((timerInternal->Timer.Flags & TmFlag_WorkItemCallback) &&
        timerInternal->WorkItem != NULL) {

        InterlockedIncrement(&timerInternal->Manager->PendingWorkItems);
        KeClearEvent(&timerInternal->Manager->AllWorkItemsDrained);

        IoQueueWorkItem(
            timerInternal->WorkItem,
            TmpWorkItemRoutine,
            DelayedWorkQueue,
            timerInternal
            );
        return;
    }

    //
    // Execute at DPC level
    //
    TmpFireTimer(timerInternal);

    //
    // Always release DPC reference
    //
    TmpDereferenceTimer(timerInternal);
}


_Use_decl_annotations_
static
VOID
TmpWheelDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
/*++

Routine Description:

    Wheel DPC - advances the slot counter and processes the current slot
    to detect missed timer deadlines.

    CurrentSlot is a LONG managed via InterlockedIncrement. We mask
    with TM_WHEEL_MASK to get the actual slot index. The raw value
    grows monotonically but we only ever use (value & TM_WHEEL_MASK).

--*/
{
    PTM_MANAGER manager;
    ULONG slotIndex;
    LONG rawSlot;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    manager = (PTM_MANAGER)DeferredContext;

    if (manager == NULL || manager->ShuttingDown || !manager->Initialized) {
        return;
    }

    //
    // Advance wheel slot atomically. Use mask to get slot index.
    // The raw value may wrap (LONG_MAX → negative) but & TM_WHEEL_MASK
    // always produces a valid index 0..TM_WHEEL_SIZE-1.
    //
    rawSlot = InterlockedIncrement(&manager->CurrentSlot);
    slotIndex = (ULONG)rawSlot & TM_WHEEL_MASK;

    //
    // Process expired timers in current slot
    //
    TmpProcessWheelSlot(manager, slotIndex);
}


static
_Use_decl_annotations_
VOID
TmpProcessWheelSlot(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG SlotIndex
    )
/*++

Routine Description:

    Processes all timers in a wheel slot to detect missed deadlines.
    This is a monitoring/statistics function — actual timer firing is
    done by the kernel timer DPC (TmpTimerDpcRoutine).

--*/
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    PLIST_ENTRY next;
    PTM_TIMER_INTERNAL timerInternal;
    LARGE_INTEGER currentTime;

    if (SlotIndex >= TM_WHEEL_SIZE) {
        return;
    }

    KeQuerySystemTimePrecise(&currentTime);

    KeAcquireSpinLock(&Manager->Wheel[SlotIndex].Lock, &oldIrql);

    for (entry = Manager->Wheel[SlotIndex].TimerList.Flink;
         entry != &Manager->Wheel[SlotIndex].TimerList;
         entry = next) {

        next = entry->Flink;
        timerInternal = CONTAINING_RECORD(entry, TM_TIMER_INTERNAL,
                                          Timer.WheelEntry);

        //
        // Check if timer has missed its deadline
        //
        if (timerInternal->Timer.State == (LONG)TmTimerState_Active &&
            timerInternal->Timer.NextFireTime.QuadPart <
            currentTime.QuadPart) {
            InterlockedIncrement64(&Manager->Stats.TimersMissed);
        }
    }

    KeReleaseSpinLock(&Manager->Wheel[SlotIndex].Lock, oldIrql);
}


//=============================================================================
// Work Item Routine (PASSIVE_LEVEL callback execution)
//=============================================================================

_Use_decl_annotations_
static
VOID
TmpWorkItemRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    )
/*++

Routine Description:

    Work item routine for timers with TmFlag_WorkItemCallback.
    Executes callback at PASSIVE_LEVEL, then releases the DPC reference.

--*/
{
    PTM_TIMER_INTERNAL timerInternal;
    PTM_MANAGER manager;

    UNREFERENCED_PARAMETER(DeviceObject);

    timerInternal = (PTM_TIMER_INTERNAL)Context;

    if (timerInternal == NULL) {
        return;
    }

    //
    // Save manager pointer before TmpDereferenceTimer — the deref may
    // hit RefCount=0 and free timerInternal, making timerInternal->Manager
    // a use-after-free. Manager itself is safe because TmShutdown is
    // blocked on AllWorkItemsDrained until we signal it below.
    //
    manager = timerInternal->Manager;

    TmpFireTimer(timerInternal);

    //
    // Release the reference that was added by the DPC routine
    //
    TmpDereferenceTimer(timerInternal);

    //
    // Decrement pending work item count. If this was the last in-flight
    // work item, signal AllWorkItemsDrained so TmShutdown can proceed
    // safely with IoFreeWorkItem / memory deallocation.
    //
    if (InterlockedDecrement(&manager->PendingWorkItems) == 0) {
        KeSetEvent(&manager->AllWorkItemsDrained,
                   IO_NO_INCREMENT, FALSE);
    }
}
