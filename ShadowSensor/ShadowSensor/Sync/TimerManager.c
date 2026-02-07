/*++
    ShadowStrike Next-Generation Antivirus
    Module: TimerManager.c

    Purpose: Enterprise-grade centralized timer management for periodic tasks,
             timeouts, and scheduled work in the kernel driver.

    Architecture:
    - High-resolution timer support via KeSetCoalescableTimer
    - Timer wheel for efficient O(1) timeout management
    - One-shot and periodic timers with reference counting
    - Timer coalescing for power efficiency on mobile endpoints
    - Thread-safe operations with proper IRQL management
    - Comprehensive statistics for performance monitoring

    MITRE ATT&CK Coverage:
    - T1497: Virtualization/Sandbox Evasion (timing analysis)
    - T1082: System Information Discovery (scheduled enumeration)

    Copyright (c) ShadowStrike Team
--*/

#include "TimerManager.h"
#include "../Utilities/MemoryUtils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, TmInitialize)
#pragma alloc_text(PAGE, TmShutdown)
#endif

//=============================================================================
// Internal Constants
//=============================================================================

#define TM_TIMER_SIGNATURE          'RMIT'  // 'TIMR' reversed
#define TM_MANAGER_SIGNATURE        'RGMT'  // 'TMGR' reversed
#define TM_INVALID_TIMER_ID         0
#define TM_WHEEL_TICK_INTERVAL_MS   10      // 10ms wheel tick
#define TM_MAX_DPC_TIME_US          50      // Max 50us in DPC before yielding

//=============================================================================
// Internal Structures
//=============================================================================

typedef struct _TM_TIMER_INTERNAL {
    //
    // Signature for validation
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
    // Work item for WorkItemCallback mode
    //
    PIO_WORKITEM WorkItem;

    //
    // Wheel slot index (for fast removal)
    //
    ULONG WheelSlotIndex;

    //
    // Deletion pending flag
    //
    volatile BOOLEAN DeletionPending;

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

//=============================================================================
// Initialization / Shutdown
//=============================================================================

_Use_decl_annotations_
NTSTATUS
TmInitialize(
    _Out_ PTM_MANAGER* Manager
    )
/*++

Routine Description:

    Initializes the timer manager subsystem. Allocates the manager structure,
    initializes the timer wheel, and starts the wheel timer for processing
    timer expirations.

Arguments:

    Manager - Receives pointer to initialized timer manager.

Return Value:

    STATUS_SUCCESS on success.
    STATUS_INSUFFICIENT_RESOURCES if allocation fails.

IRQL:

    PASSIVE_LEVEL

--*/
{
    PTM_MANAGER manager = NULL;
    NTSTATUS status = STATUS_SUCCESS;
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
    manager = (PTM_MANAGER)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(TM_MANAGER),
        TM_POOL_TAG_CONTEXT
        );

    if (manager == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(manager, sizeof(TM_MANAGER));

    //
    // Initialize the timer list
    //
    InitializeListHead(&manager->TimerList);
    KeInitializeSpinLock(&manager->TimerListLock);
    manager->TimerCount = 0;

    //
    // Initialize timer wheel slots
    //
    for (i = 0; i < TM_WHEEL_SIZE; i++) {
        InitializeListHead(&manager->Wheel[i].TimerList);
        KeInitializeSpinLock(&manager->Wheel[i].Lock);
        manager->Wheel[i].TimerCount = 0;
    }

    manager->CurrentSlot = 0;

    //
    // Initialize wheel timer and DPC
    //
    KeInitializeTimer(&manager->WheelTimer);
    KeInitializeDpc(&manager->WheelDpc, TmpWheelDpcRoutine, manager);

    //
    // Initialize ID generation - start at 1 (0 is invalid)
    //
    manager->NextTimerId = 1;

    //
    // Initialize statistics
    //
    KeQuerySystemTimePrecise(&manager->Stats.StartTime);
    manager->Stats.TimersCreated = 0;
    manager->Stats.TimersFired = 0;
    manager->Stats.TimersCancelled = 0;
    manager->Stats.TimersMissed = 0;
    manager->Stats.CoalescedTimers = 0;

    //
    // Set default configuration
    //
    manager->Config.DefaultToleranceMs = TM_DEFAULT_TOLERANCE_MS;
    manager->Config.EnableCoalescing = TRUE;
    manager->Config.EnableHighResolution = FALSE;

    //
    // Mark as initialized before starting the wheel timer
    //
    manager->Initialized = TRUE;
    manager->ShuttingDown = FALSE;

    //
    // Start the wheel timer - runs every TM_WHEEL_RESOLUTION_MS
    //
    dueTime.QuadPart = TM_MS_TO_RELATIVE(TM_WHEEL_RESOLUTION_MS);
    KeSetTimerEx(
        &manager->WheelTimer,
        dueTime,
        TM_WHEEL_RESOLUTION_MS,
        &manager->WheelDpc
        );

    *Manager = manager;

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

Return Value:

    None.

IRQL:

    PASSIVE_LEVEL

--*/
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    PTM_TIMER_INTERNAL timerInternal;
    LIST_ENTRY timersToFree;

    PAGED_CODE();

    if (Manager == NULL || !Manager->Initialized) {
        return;
    }

    //
    // Signal shutdown
    //
    Manager->ShuttingDown = TRUE;
    KeMemoryBarrier();

    //
    // Cancel the wheel timer
    //
    KeCancelTimer(&manager->WheelTimer);
    KeFlushQueuedDpcs();

    //
    // Build list of timers to free (can't free while holding lock)
    //
    InitializeListHead(&timersToFree);

    //
    // Cancel all timers
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
        timerInternal->Timer.State = TmTimerState_Cancelled;

        //
        // Add to free list
        //
        InsertTailList(&timersToFree, &timerInternal->Timer.ListEntry);
    }

    Manager->TimerCount = 0;
    KeReleaseSpinLock(&Manager->TimerListLock, oldIrql);

    //
    // Wait for any in-flight DPCs to complete
    //
    KeFlushQueuedDpcs();

    //
    // Now free all timers
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
        // Free context if we own it
        //
        if (timerInternal->Timer.Context != NULL &&
            timerInternal->Timer.ContextSize > 0) {
            ShadowStrikeFreePoolWithTag(
                timerInternal->Timer.Context,
                TM_POOL_TAG_CONTEXT
                );
        }

        //
        // Clear signature and free
        //
        timerInternal->Signature = 0;
        ShadowStrikeFreePoolWithTag(timerInternal, TM_POOL_TAG_TIMER);
    }

    //
    // Mark as uninitialized
    //
    Manager->Initialized = FALSE;

    //
    // Free the manager
    //
    ShadowStrikeFreePoolWithTag(Manager, TM_POOL_TAG_CONTEXT);
}


_Use_decl_annotations_
NTSTATUS
TmSetWorkQueue(
    _Inout_ PTM_MANAGER Manager,
    _In_ PVOID WorkQueue
    )
/*++

Routine Description:

    Sets the work queue to use for timers with WorkItemCallback flag.

Arguments:

    Manager - Timer manager.
    WorkQueue - Async work queue manager (PAWQ_MANAGER).

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    if (Manager == NULL || !Manager->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    Manager->WorkQueue = WorkQueue;

    return STATUS_SUCCESS;
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
/*++

Routine Description:

    Creates a one-shot timer that fires once after the specified delay.

Arguments:

    Manager - Timer manager.
    DelayMs - Delay in milliseconds before timer fires.
    Callback - Function to call when timer fires.
    Context - Optional context passed to callback.
    Options - Optional timer options.
    TimerId - Receives the timer ID.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    LARGE_INTEGER dueTime;

    if (Manager == NULL || !Manager->Initialized || Callback == NULL || TimerId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (DelayMs < TM_MIN_PERIOD_MS || DelayMs > TM_MAX_PERIOD_MS) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Calculate relative due time
    //
    dueTime.QuadPart = TM_MS_TO_RELATIVE(DelayMs);

    return TmpCreateTimerInternal(
        Manager,
        TmTimerType_OneShot,
        &dueTime,
        0,  // No period for one-shot
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
/*++

Routine Description:

    Creates a periodic timer that fires repeatedly at the specified interval.

Arguments:

    Manager - Timer manager.
    PeriodMs - Period in milliseconds between firings.
    Callback - Function to call when timer fires.
    Context - Optional context passed to callback.
    Options - Optional timer options.
    TimerId - Receives the timer ID.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    LARGE_INTEGER dueTime;

    if (Manager == NULL || !Manager->Initialized || Callback == NULL || TimerId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (PeriodMs < TM_MIN_PERIOD_MS || PeriodMs > TM_MAX_PERIOD_MS) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // First firing after one period
    //
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
/*++

Routine Description:

    Creates a timer with an absolute due time.

Arguments:

    Manager - Timer manager.
    DueTime - Absolute time when timer should fire.
    PeriodMs - Optional period for periodic timers (0 for one-shot).
    Callback - Function to call when timer fires.
    Context - Optional context passed to callback.
    Options - Optional timer options.
    TimerId - Receives the timer ID.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    TM_TIMER_TYPE type;

    if (Manager == NULL || !Manager->Initialized ||
        DueTime == NULL || Callback == NULL || TimerId == NULL) {
        return STATUS_INVALID_PARAMETER;
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

Arguments:

    Manager - Timer manager.
    TimerId - Timer to start.

Return Value:

    STATUS_SUCCESS on success.
    STATUS_NOT_FOUND if timer doesn't exist.

--*/
{
    PTM_TIMER_INTERNAL timerInternal;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG tolerableDelayMs;

    if (Manager == NULL || !Manager->Initialized || TimerId == TM_INVALID_TIMER_ID) {
        return STATUS_INVALID_PARAMETER;
    }

    timerInternal = TmpFindTimerById(Manager, TimerId);
    if (timerInternal == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Can only start timers in Created state
    //
    if (timerInternal->Timer.State != TmTimerState_Created) {
        TmpDereferenceTimer(timerInternal);
        return STATUS_INVALID_STATE_TRANSITION;
    }

    //
    // Transition to Active
    //
    timerInternal->Timer.State = TmTimerState_Active;

    //
    // Calculate next fire time
    //
    KeQuerySystemTimePrecise(&timerInternal->Timer.NextFireTime);
    timerInternal->Timer.NextFireTime.QuadPart -= timerInternal->Timer.DueTime.QuadPart;

    //
    // Set the kernel timer
    //
    if ((timerInternal->Timer.Flags & TmFlag_Coalescable) && Manager->Config.EnableCoalescing) {
        //
        // Use coalescable timer for power efficiency
        //
        tolerableDelayMs = timerInternal->Timer.ToleranceMs;
        if (tolerableDelayMs == 0) {
            tolerableDelayMs = Manager->Config.DefaultToleranceMs;
        }

        KeSetCoalescableTimer(
            &timerInternal->Timer.KernelTimer,
            timerInternal->Timer.DueTime,
            (timerInternal->Timer.Type == TmTimerType_Periodic) ?
                (ULONG)(timerInternal->Timer.Period.QuadPart / -10000LL) : 0,
            tolerableDelayMs,
            &timerInternal->Timer.TimerDpc
            );

        InterlockedIncrement64(&Manager->Stats.CoalescedTimers);
    }
    else {
        //
        // High-resolution timer
        //
        KeSetTimerEx(
            &timerInternal->Timer.KernelTimer,
            timerInternal->Timer.DueTime,
            (timerInternal->Timer.Type == TmTimerType_Periodic) ?
                (LONG)(timerInternal->Timer.Period.QuadPart / -10000LL) : 0,
            &timerInternal->Timer.TimerDpc
            );
    }

    //
    // Insert into timer wheel for deadline tracking
    //
    TmpInsertTimerIntoWheel(Manager, timerInternal);

    TmpDereferenceTimer(timerInternal);

    return STATUS_SUCCESS;
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

Arguments:

    Manager - Timer manager.
    TimerId - Timer to stop.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PTM_TIMER_INTERNAL timerInternal;

    if (Manager == NULL || !Manager->Initialized || TimerId == TM_INVALID_TIMER_ID) {
        return STATUS_INVALID_PARAMETER;
    }

    timerInternal = TmpFindTimerById(Manager, TimerId);
    if (timerInternal == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Cancel the kernel timer
    //
    KeCancelTimer(&timerInternal->Timer.KernelTimer);

    //
    // Remove from wheel
    //
    TmpRemoveTimerFromWheel(Manager, timerInternal);

    //
    // Transition to Created (can be restarted)
    //
    timerInternal->Timer.State = TmTimerState_Created;

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

Arguments:

    Manager - Timer manager.
    TimerId - Timer to cancel.
    Wait - If TRUE, waits for any in-progress callback to complete.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PTM_TIMER_INTERNAL timerInternal;
    KIRQL oldIrql;
    BOOLEAN wasActive;

    if (Manager == NULL || !Manager->Initialized || TimerId == TM_INVALID_TIMER_ID) {
        return STATUS_INVALID_PARAMETER;
    }

    timerInternal = TmpFindTimerById(Manager, TimerId);
    if (timerInternal == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Mark as cancelled
    //
    timerInternal->Timer.CancelRequested = TRUE;
    timerInternal->Timer.State = TmTimerState_Cancelled;
    timerInternal->DeletionPending = TRUE;

    //
    // Cancel the kernel timer
    //
    wasActive = KeCancelTimer(&timerInternal->Timer.KernelTimer);

    //
    // Remove from wheel
    //
    TmpRemoveTimerFromWheel(Manager, timerInternal);

    //
    // Remove from global list
    //
    KeAcquireSpinLock(&Manager->TimerListLock, &oldIrql);
    RemoveEntryList(&timerInternal->Timer.ListEntry);
    InterlockedDecrement(&Manager->TimerCount);
    KeReleaseSpinLock(&Manager->TimerListLock, oldIrql);

    //
    // Signal cancel event
    //
    KeSetEvent(&timerInternal->Timer.CancelEvent, IO_NO_INCREMENT, FALSE);

    //
    // Update statistics
    //
    InterlockedIncrement64(&Manager->Stats.TimersCancelled);

    if (Wait && timerInternal->Timer.State == TmTimerState_Firing) {
        //
        // Wait for callback to complete - the cancel event will be signaled
        // This is safe at PASSIVE_LEVEL only
        //
        if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
            KeWaitForSingleObject(
                &timerInternal->Timer.CancelEvent,
                Executive,
                KernelMode,
                FALSE,
                NULL
                );
        }
    }

    //
    // Release our find reference - timer will be freed when refcount hits 0
    //
    TmpDereferenceTimer(timerInternal);

    //
    // Release creation reference
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

    Resets a timer to fire again with its original parameters.

Arguments:

    Manager - Timer manager.
    TimerId - Timer to reset.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PTM_TIMER_INTERNAL timerInternal;
    NTSTATUS status;

    if (Manager == NULL || !Manager->Initialized || TimerId == TM_INVALID_TIMER_ID) {
        return STATUS_INVALID_PARAMETER;
    }

    timerInternal = TmpFindTimerById(Manager, TimerId);
    if (timerInternal == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Stop then start
    //
    status = TmStop(Manager, TimerId);
    if (NT_SUCCESS(status)) {
        status = TmStart(Manager, TimerId);
    }

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

    Modifies the period of a periodic timer.

Arguments:

    Manager - Timer manager.
    TimerId - Timer to modify.
    NewPeriodMs - New period in milliseconds.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PTM_TIMER_INTERNAL timerInternal;
    BOOLEAN wasActive;

    if (Manager == NULL || !Manager->Initialized || TimerId == TM_INVALID_TIMER_ID) {
        return STATUS_INVALID_PARAMETER;
    }

    if (NewPeriodMs < TM_MIN_PERIOD_MS || NewPeriodMs > TM_MAX_PERIOD_MS) {
        return STATUS_INVALID_PARAMETER;
    }

    timerInternal = TmpFindTimerById(Manager, TimerId);
    if (timerInternal == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Only periodic timers can have period changed
    //
    if (timerInternal->Timer.Type != TmTimerType_Periodic) {
        TmpDereferenceTimer(timerInternal);
        return STATUS_INVALID_PARAMETER;
    }

    wasActive = (timerInternal->Timer.State == TmTimerState_Active);

    //
    // Stop if active
    //
    if (wasActive) {
        TmStop(Manager, TimerId);
    }

    //
    // Update period
    //
    timerInternal->Timer.Period.QuadPart = TM_MS_TO_RELATIVE(NewPeriodMs);
    timerInternal->Timer.DueTime.QuadPart = TM_MS_TO_RELATIVE(NewPeriodMs);

    //
    // Restart if was active
    //
    if (wasActive) {
        TmStart(Manager, TimerId);
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
    _Out_ PTM_TIMER_STATE State
    )
{
    PTM_TIMER_INTERNAL timerInternal;

    if (Manager == NULL || !Manager->Initialized ||
        TimerId == TM_INVALID_TIMER_ID || State == NULL) {
        return STATUS_INVALID_PARAMETER;
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

    if (Manager == NULL || !Manager->Initialized ||
        TimerId == TM_INVALID_TIMER_ID || Remaining == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    timerInternal = TmpFindTimerById(Manager, TimerId);
    if (timerInternal == NULL) {
        return STATUS_NOT_FOUND;
    }

    if (timerInternal->Timer.State != TmTimerState_Active) {
        Remaining->QuadPart = 0;
        TmpDereferenceTimer(timerInternal);
        return STATUS_SUCCESS;
    }

    KeQuerySystemTimePrecise(&currentTime);
    Remaining->QuadPart = timerInternal->Timer.NextFireTime.QuadPart - currentTime.QuadPart;

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

    if (Manager == NULL || !Manager->Initialized || TimerId == TM_INVALID_TIMER_ID) {
        return FALSE;
    }

    timerInternal = TmpFindTimerById(Manager, TimerId);
    if (timerInternal == NULL) {
        return FALSE;
    }

    isActive = (timerInternal->Timer.State == TmTimerState_Active ||
                timerInternal->Timer.State == TmTimerState_Firing);

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
    ULONG count = 0;
    ULONG i;

    if (Manager == NULL || !Manager->Initialized) {
        return;
    }

    //
    // Collect timer IDs (can't cancel while iterating due to list modification)
    //
    do {
        count = 0;

        KeAcquireSpinLock(&Manager->TimerListLock, &oldIrql);

        for (entry = Manager->TimerList.Flink;
             entry != &Manager->TimerList && count < ARRAYSIZE(timerIds);
             entry = entry->Flink) {

            timerInternal = CONTAINING_RECORD(entry, TM_TIMER_INTERNAL, Timer.ListEntry);

            if (!timerInternal->DeletionPending) {
                timerIds[count++] = timerInternal->Timer.TimerId;
            }
        }

        KeReleaseSpinLock(&Manager->TimerListLock, oldIrql);

        //
        // Cancel collected timers
        //
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
    ULONG count = 0;
    ULONG i;

    if (Manager == NULL || !Manager->Initialized) {
        return;
    }

    //
    // Collect timer IDs in the specified group
    //
    do {
        count = 0;

        KeAcquireSpinLock(&Manager->TimerListLock, &oldIrql);

        for (entry = Manager->TimerList.Flink;
             entry != &Manager->TimerList && count < ARRAYSIZE(timerIds);
             entry = entry->Flink) {

            timerInternal = CONTAINING_RECORD(entry, TM_TIMER_INTERNAL, Timer.ListEntry);

            if (!timerInternal->DeletionPending &&
                timerInternal->Timer.CoalesceGroup == CoalesceGroup) {
                timerIds[count++] = timerInternal->Timer.TimerId;
            }
        }

        KeReleaseSpinLock(&Manager->TimerListLock, oldIrql);

        //
        // Cancel collected timers
        //
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

    if (Manager == NULL || !Manager->Initialized || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Stats, sizeof(TM_STATISTICS));

    Stats->ActiveTimers = (ULONG)Manager->TimerCount;
    Stats->TimersCreated = Manager->Stats.TimersCreated;
    Stats->TimersFired = Manager->Stats.TimersFired;
    Stats->TimersCancelled = Manager->Stats.TimersCancelled;
    Stats->TimersMissed = Manager->Stats.TimersMissed;
    Stats->CoalescedTimers = Manager->Stats.CoalescedTimers;

    KeQuerySystemTimePrecise(&currentTime);
    Stats->UpTime.QuadPart = currentTime.QuadPart - Manager->Stats.StartTime.QuadPart;

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

    Internal timer creation routine.

--*/
{
    PTM_TIMER_INTERNAL timerInternal = NULL;
    KIRQL oldIrql;
    NTSTATUS status = STATUS_SUCCESS;
    PVOID contextCopy = NULL;

    *TimerId = TM_INVALID_TIMER_ID;

    //
    // Check timer limit
    //
    if (Manager->TimerCount >= TM_MAX_TIMERS) {
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Allocate timer structure
    //
    timerInternal = (PTM_TIMER_INTERNAL)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(TM_TIMER_INTERNAL),
        TM_POOL_TAG_TIMER
        );

    if (timerInternal == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(timerInternal, sizeof(TM_TIMER_INTERNAL));

    //
    // Copy context if provided and size specified
    //
    if (Options != NULL && Options->Context != NULL && Options->ContextSize > 0) {
        contextCopy = ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            Options->ContextSize,
            TM_POOL_TAG_CONTEXT
            );

        if (contextCopy == NULL) {
            ShadowStrikeFreePoolWithTag(timerInternal, TM_POOL_TAG_TIMER);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(contextCopy, Options->Context, Options->ContextSize);
        timerInternal->Timer.Context = contextCopy;
        timerInternal->Timer.ContextSize = Options->ContextSize;
    }
    else {
        timerInternal->Timer.Context = Context;
        timerInternal->Timer.ContextSize = 0;
    }

    //
    // Initialize signature
    //
    timerInternal->Signature = TM_TIMER_SIGNATURE;
    timerInternal->Manager = Manager;
    timerInternal->DeletionPending = FALSE;

    //
    // Initialize kernel timer and DPC
    //
    KeInitializeTimer(&timerInternal->Timer.KernelTimer);
    KeInitializeDpc(&timerInternal->Timer.TimerDpc, TmpTimerDpcRoutine, timerInternal);

    //
    // Generate timer ID
    //
    timerInternal->Timer.TimerId = (ULONG)InterlockedIncrement(&Manager->NextTimerId);

    //
    // Set timer properties
    //
    timerInternal->Timer.Type = Type;
    timerInternal->Timer.DueTime = *DueTime;
    timerInternal->Timer.Period.QuadPart = (PeriodMs > 0) ? TM_MS_TO_RELATIVE(PeriodMs) : 0;
    timerInternal->Timer.Callback = Callback;
    timerInternal->Timer.State = TmTimerState_Created;

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
                sizeof(timerInternal->Timer.Name),
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
    KeInitializeEvent(&timerInternal->Timer.CancelEvent, NotificationEvent, FALSE);
    timerInternal->Timer.CancelRequested = FALSE;

    //
    // Set initial reference count (1 for creation, 1 for being in list)
    //
    timerInternal->Timer.RefCount = 2;

    //
    // Initialize statistics
    //
    timerInternal->Timer.FireCount = 0;
    KeQuerySystemTimePrecise(&timerInternal->Timer.CreationTime);

    //
    // Initialize list entries
    //
    InitializeListHead(&timerInternal->Timer.ListEntry);
    InitializeListHead(&timerInternal->Timer.WheelEntry);

    //
    // Insert into global timer list
    //
    KeAcquireSpinLock(&Manager->TimerListLock, &oldIrql);
    InsertTailList(&Manager->TimerList, &timerInternal->Timer.ListEntry);
    InterlockedIncrement(&Manager->TimerCount);
    KeReleaseSpinLock(&Manager->TimerListLock, oldIrql);

    //
    // Update statistics
    //
    InterlockedIncrement64(&Manager->Stats.TimersCreated);

    *TimerId = timerInternal->Timer.TimerId;

    //
    // Auto-start if not using manual start
    //
    if (!(timerInternal->Timer.Flags & TmFlag_Synchronized)) {
        status = TmStart(Manager, timerInternal->Timer.TimerId);
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

        timerInternal = CONTAINING_RECORD(entry, TM_TIMER_INTERNAL, Timer.ListEntry);

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
    InterlockedIncrement(&TimerInternal->Timer.RefCount);
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

    if (newCount == 0) {
        //
        // Last reference - safe to free
        //
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

--*/
{
    //
    // Free work item if allocated
    //
    if (TimerInternal->WorkItem != NULL) {
        IoFreeWorkItem(TimerInternal->WorkItem);
        TimerInternal->WorkItem = NULL;
    }

    //
    // Free copied context if we own it
    //
    if (TimerInternal->Timer.Context != NULL &&
        TimerInternal->Timer.ContextSize > 0) {
        ShadowStrikeFreePoolWithTag(
            TimerInternal->Timer.Context,
            TM_POOL_TAG_CONTEXT
            );
    }

    //
    // Clear signature
    //
    TimerInternal->Signature = 0;

    //
    // Free timer structure
    //
    ShadowStrikeFreePoolWithTag(TimerInternal, TM_POOL_TAG_TIMER);
}


static
_Use_decl_annotations_
VOID
TmpInsertTimerIntoWheel(
    _In_ PTM_MANAGER Manager,
    _Inout_ PTM_TIMER_INTERNAL TimerInternal
    )
/*++

Routine Description:

    Inserts timer into the timer wheel for deadline tracking.

--*/
{
    KIRQL oldIrql;
    ULONG slotIndex;
    LARGE_INTEGER currentTime;
    LONGLONG ticksUntilFire;
    ULONG slotsUntilFire;

    //
    // Calculate which wheel slot this timer belongs in
    //
    KeQuerySystemTimePrecise(&currentTime);
    ticksUntilFire = TimerInternal->Timer.NextFireTime.QuadPart - currentTime.QuadPart;

    if (ticksUntilFire <= 0) {
        //
        // Already expired - put in current slot
        //
        slotIndex = Manager->CurrentSlot;
    }
    else {
        //
        // Convert ticks to milliseconds, then to slots
        //
        slotsUntilFire = (ULONG)((ticksUntilFire / 10000LL) / TM_WHEEL_RESOLUTION_MS);

        if (slotsUntilFire >= TM_WHEEL_SIZE) {
            //
            // Too far in future - will be re-inserted when wheel advances
            //
            slotsUntilFire = TM_WHEEL_SIZE - 1;
        }

        slotIndex = (Manager->CurrentSlot + slotsUntilFire) % TM_WHEEL_SIZE;
    }

    TimerInternal->WheelSlotIndex = slotIndex;

    KeAcquireSpinLock(&Manager->Wheel[slotIndex].Lock, &oldIrql);
    InsertTailList(&Manager->Wheel[slotIndex].TimerList, &TimerInternal->Timer.WheelEntry);
    InterlockedIncrement(&Manager->Wheel[slotIndex].TimerCount);
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

    slotIndex = TimerInternal->WheelSlotIndex;

    if (slotIndex < TM_WHEEL_SIZE) {
        KeAcquireSpinLock(&Manager->Wheel[slotIndex].Lock, &oldIrql);

        if (!IsListEmpty(&TimerInternal->Timer.WheelEntry)) {
            RemoveEntryList(&TimerInternal->Timer.WheelEntry);
            InitializeListHead(&TimerInternal->Timer.WheelEntry);
            InterlockedDecrement(&Manager->Wheel[slotIndex].TimerCount);
        }

        KeReleaseSpinLock(&Manager->Wheel[slotIndex].Lock, oldIrql);
    }
}


static
_Use_decl_annotations_
VOID
TmpFireTimer(
    _Inout_ PTM_TIMER_INTERNAL TimerInternal
    )
/*++

Routine Description:

    Fires the timer callback.

--*/
{
    PTM_MANAGER manager;
    LARGE_INTEGER currentTime;

    manager = TimerInternal->Manager;

    //
    // Check for cancellation
    //
    if (TimerInternal->Timer.CancelRequested || manager->ShuttingDown) {
        return;
    }

    //
    // Transition to firing state
    //
    TimerInternal->Timer.State = TmTimerState_Firing;

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
        TimerInternal->Timer.State = TmTimerState_Cancelled;
        KeSetEvent(&TimerInternal->Timer.CancelEvent, IO_NO_INCREMENT, FALSE);
    }
    else if (TimerInternal->Timer.Type == TmTimerType_OneShot) {
        TimerInternal->Timer.State = TmTimerState_Expired;

        //
        // Auto-delete one-shot timers with AutoDelete flag
        //
        if (TimerInternal->Timer.Flags & TmFlag_AutoDelete) {
            TimerInternal->DeletionPending = TRUE;
            TmpDereferenceTimer(TimerInternal);
        }
    }
    else if (TimerInternal->Timer.Type == TmTimerType_Periodic) {
        //
        // Calculate next fire time and re-insert into wheel
        //
        TimerInternal->Timer.NextFireTime.QuadPart =
            currentTime.QuadPart - TimerInternal->Timer.Period.QuadPart;
        TimerInternal->Timer.State = TmTimerState_Active;

        TmpRemoveTimerFromWheel(manager, TimerInternal);
        TmpInsertTimerIntoWheel(manager, TimerInternal);
    }
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

    DPC routine called when a kernel timer fires.

--*/
{
    PTM_TIMER_INTERNAL timerInternal;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    timerInternal = (PTM_TIMER_INTERNAL)DeferredContext;

    if (timerInternal == NULL ||
        timerInternal->Signature != TM_TIMER_SIGNATURE) {
        return;
    }

    //
    // Add reference for callback
    //
    TmpReferenceTimer(timerInternal);

    //
    // Check if this should be executed via work item
    //
    if (timerInternal->Timer.Flags & TmFlag_WorkItemCallback) {
        //
        // Queue work item for PASSIVE_LEVEL execution
        // For now, execute at DPC level - would need work item allocation
        //
        TmpFireTimer(timerInternal);
    }
    else {
        //
        // Execute at DPC level
        //
        TmpFireTimer(timerInternal);
    }

    //
    // Release callback reference
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

    DPC routine for timer wheel processing. Called periodically to advance
    the wheel and check for missed timers.

--*/
{
    PTM_MANAGER manager;
    ULONG currentSlot;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    manager = (PTM_MANAGER)DeferredContext;

    if (manager == NULL || manager->ShuttingDown || !manager->Initialized) {
        return;
    }

    //
    // Advance wheel slot
    //
    currentSlot = InterlockedIncrement((LONG*)&manager->CurrentSlot) % TM_WHEEL_SIZE;
    manager->CurrentSlot = currentSlot;

    //
    // Process expired timers in current slot
    //
    TmpProcessWheelSlot(manager, currentSlot);
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

--*/
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    PLIST_ENTRY next;
    PTM_TIMER_INTERNAL timerInternal;
    LARGE_INTEGER currentTime;

    KeQuerySystemTimePrecise(&currentTime);

    KeAcquireSpinLock(&Manager->Wheel[SlotIndex].Lock, &oldIrql);

    for (entry = Manager->Wheel[SlotIndex].TimerList.Flink;
         entry != &Manager->Wheel[SlotIndex].TimerList;
         entry = next) {

        next = entry->Flink;
        timerInternal = CONTAINING_RECORD(entry, TM_TIMER_INTERNAL, Timer.WheelEntry);

        //
        // Check if timer has missed its deadline (wasn't fired by kernel timer)
        //
        if (timerInternal->Timer.State == TmTimerState_Active &&
            timerInternal->Timer.NextFireTime.QuadPart < currentTime.QuadPart) {

            //
            // Deadline missed - log and update statistics
            //
            InterlockedIncrement64(&Manager->Stats.TimersMissed);
        }
    }

    KeReleaseSpinLock(&Manager->Wheel[SlotIndex].Lock, oldIrql);
}


_Use_decl_annotations_
static
VOID
TmpWorkItemRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    )
/*++

Routine Description:

    Work item routine for timers with WorkItemCallback flag.
    Executes callback at PASSIVE_LEVEL.

--*/
{
    PTM_TIMER_INTERNAL timerInternal;

    UNREFERENCED_PARAMETER(DeviceObject);

    timerInternal = (PTM_TIMER_INTERNAL)Context;

    if (timerInternal == NULL ||
        timerInternal->Signature != TM_TIMER_SIGNATURE) {
        return;
    }

    TmpFireTimer(timerInternal);

    TmpDereferenceTimer(timerInternal);
}
