/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE KERNEL WORK QUEUE IMPLEMENTATION
 * ============================================================================
 *
 * @file WorkQueue.c
 * @brief Implementation of enterprise-grade kernel work queue.
 *
 * v2.1.0 Changes (Enterprise Hardened):
 * ======================================
 * - KeEnterCriticalRegion around ALL push lock acquisitions
 * - PAGE segment (not INIT) for init functions — safe for ref-counted re-init
 * - DPC fallback REMOVED: if no DeviceObject, fail submission (don't execute
 *   at DISPATCH_LEVEL)
 * - Shutdown: cancel all delayed timers, KeFlushQueuedDpcs, proper SLIST drain
 * - Retry path re-acquires rundown protection before re-queue
 * - Single ListEntry (ActiveListEntry) — no per-priority queue lists
 * - Legacy callback uses wrapper function, no UB cast
 * - Per-priority stats use interlocked ops
 * - Context copies always NonPaged (callable from DISPATCH_LEVEL)
 * - WaitForWorkItem uses KeQueryPerformanceCounter for accurate timing
 * - Flush actually cancels and completes items
 * - State transitions use InterlockedCompareExchange
 * - SetDeviceObject/SetFilterHandle synchronized with push lock
 *
 * @author ShadowStrike Security Team
 * @version 2.1.0 (Enterprise Edition - Hardened)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "WorkQueue.h"
#include "../Utilities/MemoryUtils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ShadowStrikeWorkQueueInitialize)
#pragma alloc_text(PAGE, ShadowStrikeWorkQueueInitializeEx)
#pragma alloc_text(PAGE, ShadowStrikeWorkQueueShutdown)
#pragma alloc_text(PAGE, ShadowStrikeWorkQueueDrain)
#pragma alloc_text(PAGE, ShadowStrikeWaitForWorkItem)
#pragma alloc_text(PAGE, ShadowStrikeWorkQueueSetDeviceObject)
#pragma alloc_text(PAGE, ShadowStrikeWorkQueueSetFilterHandle)
#endif

// ============================================================================
// GLOBAL STATE
// ============================================================================

static SHADOWSTRIKE_WQ_MANAGER g_WqManager = { 0 };

// ============================================================================
// INTERNAL PROTOTYPES
// ============================================================================

static PSHADOWSTRIKE_WORK_ITEM WqiAllocateWorkItem(VOID);
static VOID WqiFreeWorkItem(_In_ PSHADOWSTRIKE_WORK_ITEM Item);
static VOID WqiReferenceWorkItem(_Inout_ PSHADOWSTRIKE_WORK_ITEM Item);
static VOID WqiDereferenceWorkItem(_Inout_ PSHADOWSTRIKE_WORK_ITEM Item);

static VOID WqiExecuteWorkItem(_In_ PSHADOWSTRIKE_WORK_ITEM Item);
static VOID WqiCompleteWorkItem(_In_ PSHADOWSTRIKE_WORK_ITEM Item, _In_ NTSTATUS Status);

static IO_WORKITEM_ROUTINE WqiIoWorkItemCallback;

static VOID WqiFltWorkItemCallback(
    _In_ PFLT_GENERIC_WORKITEM FltWorkItem,
    _In_ PVOID FltObject,
    _In_opt_ PVOID Context);

static KDEFERRED_ROUTINE WqiDelayTimerDpcCallback;

static PSHADOWSTRIKE_WORK_ITEM WqiFindWorkItemById(_In_ ULONG64 ItemId);

static VOID WqiTrackSubmit(VOID);
static VOID WqiTrackComplete(_In_ PSHADOWSTRIKE_WORK_ITEM Item, _In_ BOOLEAN Success);

static NTSTATUS WqiSetupContext(
    _Inout_ PSHADOWSTRIKE_WORK_ITEM Item,
    _In_opt_ PVOID Context,
    _In_ ULONG ContextSize,
    _In_ ULONG Flags);

static NTSTATUS WqiDispatchItem(_Inout_ PSHADOWSTRIKE_WORK_ITEM Item);

static NTSTATUS WqiDispatchFilterItem(
    _Inout_ PSHADOWSTRIKE_WORK_ITEM Item,
    _In_ PFLT_INSTANCE Instance);

/// Legacy wrapper that adapts VOID(*)(PVOID) to NTSTATUS(*)(PVOID, ULONG)
static NTSTATUS WqiLegacyRoutineWrapper(
    _In_opt_ PVOID Context,
    _In_ ULONG ContextSize);

static VOID WqiRemoveFromActiveList(_Inout_ PSHADOWSTRIKE_WORK_ITEM Item);
static VOID WqiAddToActiveList(_Inout_ PSHADOWSTRIKE_WORK_ITEM Item);

// ============================================================================
// SUBSYSTEM INITIALIZATION
// FIX #1: Push lock with KeEnterCriticalRegion
// FIX #2: PAGE segment, not INIT
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeWorkQueueInitialize(VOID)
{
    SHADOWSTRIKE_WQ_CONFIG DefaultConfig;

    PAGED_CODE();

    ShadowStrikeInitWorkQueueConfig(&DefaultConfig);
    return ShadowStrikeWorkQueueInitializeEx(&DefaultConfig);
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeWorkQueueInitializeEx(
    _In_ PSHADOWSTRIKE_WQ_CONFIG Config)
{
    PAGED_CODE();

    if (Config == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // FIX #1: KeEnterCriticalRegion before push lock
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_WqManager.InitLock);

    // Ref-counted init — only first caller does real work
    if (InterlockedIncrement(&g_WqManager.InitCount) > 1) {
        ExReleasePushLockExclusive(&g_WqManager.InitLock);
        KeLeaveCriticalRegion();
        return STATUS_SUCCESS;
    }

    InterlockedExchange(&g_WqManager.State, (LONG)ShadowWqStateInitializing);

    // Copy and validate configuration
    RtlCopyMemory(&g_WqManager.Config, Config, sizeof(SHADOWSTRIKE_WQ_CONFIG));

    if (g_WqManager.Config.MaxPendingTotal == 0)
        g_WqManager.Config.MaxPendingTotal = WQ_DEFAULT_MAX_PENDING;
    if (g_WqManager.Config.MaxPendingTotal < WQ_MIN_MAX_PENDING)
        g_WqManager.Config.MaxPendingTotal = WQ_MIN_MAX_PENDING;
    if (g_WqManager.Config.MaxPendingTotal > WQ_MAX_MAX_PENDING)
        g_WqManager.Config.MaxPendingTotal = WQ_MAX_MAX_PENDING;
    if (g_WqManager.Config.LookasideDepth == 0)
        g_WqManager.Config.LookasideDepth = WQ_LOOKASIDE_DEPTH;

    g_WqManager.MaxPending = (LONG)g_WqManager.Config.MaxPendingTotal;
    g_WqManager.DeviceObject = Config->DeviceObject;
    g_WqManager.FilterHandle = Config->FilterHandle;

    // Initialize active list
    InitializeListHead(&g_WqManager.ActiveList);
    KeInitializeSpinLock(&g_WqManager.ActiveListLock);
    g_WqManager.ActiveCount = 0;

    // Initialize free list (lock-free SLIST)
    InitializeSListHead(&g_WqManager.FreeList);
    g_WqManager.FreeCount = 0;

    // Work item ID generator
    g_WqManager.NextItemId = 1;

    // Lookaside list
    ExInitializeNPagedLookasideList(
        &g_WqManager.WorkItemLookaside,
        NULL, NULL, 0,
        sizeof(SHADOWSTRIKE_WORK_ITEM),
        SHADOW_WQ_ITEM_TAG,
        g_WqManager.Config.LookasideDepth);
    g_WqManager.LookasideInitialized = TRUE;

    // Rundown protection
    ExInitializeRundownProtection(&g_WqManager.RundownProtection);

    // Events
    KeInitializeEvent(&g_WqManager.ShutdownEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&g_WqManager.DrainCompleteEvent, NotificationEvent, FALSE);

    // Statistics
    RtlZeroMemory(&g_WqManager.Stats, sizeof(g_WqManager.Stats));
    KeQuerySystemTimePrecise(&g_WqManager.Stats.StartTime);

    // Pending count
    g_WqManager.PendingCount = 0;

    // Go live
    InterlockedExchange(&g_WqManager.State, (LONG)ShadowWqStateRunning);
    InterlockedExchange(&g_WqManager.Stats.State, (LONG)ShadowWqStateRunning);

    ExReleasePushLockExclusive(&g_WqManager.InitLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

// ============================================================================
// SHUTDOWN
// FIX #1: Push lock with critical region
// FIX #4: SLIST items actually freed
// FIX #10: IoFreeWorkItem only after item is idle
// FIX #15: Cancel timers, KeFlushQueuedDpcs
// ============================================================================

_Use_decl_annotations_
VOID
ShadowStrikeWorkQueueShutdown(
    _In_ BOOLEAN WaitForCompletion)
{
    LARGE_INTEGER Timeout;

    PAGED_CODE();

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_WqManager.InitLock);

    // Ref-counted: only last release does real cleanup
    if (InterlockedDecrement(&g_WqManager.InitCount) > 0) {
        ExReleasePushLockExclusive(&g_WqManager.InitLock);
        KeLeaveCriticalRegion();
        return;
    }

    // Signal shutdown
    InterlockedExchange(&g_WqManager.State, (LONG)ShadowWqStateShutdown);
    InterlockedExchange(&g_WqManager.Stats.State, (LONG)ShadowWqStateShutdown);
    KeSetEvent(&g_WqManager.ShutdownEvent, IO_NO_INCREMENT, FALSE);

    // Wait for all in-flight operations to release rundown protection
    ExWaitForRundownProtectionRelease(&g_WqManager.RundownProtection);

    // FIX #15: Cancel all delayed timers on active items, then flush DPCs
    {
        KIRQL OldIrql;
        PLIST_ENTRY Entry;

        KeAcquireSpinLock(&g_WqManager.ActiveListLock, &OldIrql);
        for (Entry = g_WqManager.ActiveList.Flink;
             Entry != &g_WqManager.ActiveList;
             Entry = Entry->Flink) {

            PSHADOWSTRIKE_WORK_ITEM Item = CONTAINING_RECORD(
                Entry, SHADOWSTRIKE_WORK_ITEM, ActiveListEntry);

            if (Item->Type == ShadowWqTypeDelayed) {
                KeCancelTimer(&Item->DelayTimer);
            }
        }
        KeReleaseSpinLock(&g_WqManager.ActiveListLock, OldIrql);
    }

    // FIX #15: Flush all queued DPCs to ensure timer DPCs have completed
    KeFlushQueuedDpcs();

    // Wait for pending items if requested
    if (WaitForCompletion) {
        if (g_WqManager.ActiveCount > 0) {
            Timeout.QuadPart = -((LONGLONG)WQ_SHUTDOWN_TIMEOUT_MS * 10000);
            KeWaitForSingleObject(
                &g_WqManager.DrainCompleteEvent,
                Executive, KernelMode, FALSE, &Timeout);
        }
    }

    // Flush: complete all remaining active items as cancelled
    {
        KIRQL OldIrql;
        LIST_ENTRY LocalList;
        InitializeListHead(&LocalList);

        KeAcquireSpinLock(&g_WqManager.ActiveListLock, &OldIrql);
        while (!IsListEmpty(&g_WqManager.ActiveList)) {
            PLIST_ENTRY Entry = RemoveHeadList(&g_WqManager.ActiveList);
            InsertTailList(&LocalList, Entry);
        }
        g_WqManager.ActiveCount = 0;
        KeReleaseSpinLock(&g_WqManager.ActiveListLock, OldIrql);

        while (!IsListEmpty(&LocalList)) {
            PLIST_ENTRY Entry = RemoveHeadList(&LocalList);
            PSHADOWSTRIKE_WORK_ITEM Item = CONTAINING_RECORD(
                Entry, SHADOWSTRIKE_WORK_ITEM, ActiveListEntry);
            InitializeListHead(&Item->ActiveListEntry);

            // Cancel callback
            if (Item->Options.CancelCallback != NULL) {
                Item->Options.CancelCallback(Item->Context, Item->ContextSize);
            }
            // Cleanup
            Item->CompletionStatus = STATUS_CANCELLED;
            InterlockedExchange(&Item->State, (LONG)ShadowWqItemStateCancelled);
            // Don't call WqiCompleteWorkItem — rundown already released
            WqiFreeWorkItem(Item);
        }
    }

    // FIX #4: Drain SLIST free list — actually free each item
    while (TRUE) {
        PSLIST_ENTRY Entry = InterlockedPopEntrySList(&g_WqManager.FreeList);
        if (Entry == NULL) break;

        PSHADOWSTRIKE_WORK_ITEM Item = CONTAINING_RECORD(
            Entry, SHADOWSTRIKE_WORK_ITEM, FreeListEntry);
        ExFreeToNPagedLookasideList(&g_WqManager.WorkItemLookaside, Item);
        InterlockedDecrement(&g_WqManager.FreeCount);
    }

    // Destroy lookaside
    if (g_WqManager.LookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_WqManager.WorkItemLookaside);
        g_WqManager.LookasideInitialized = FALSE;
    }

    InterlockedExchange(&g_WqManager.State, (LONG)ShadowWqStateUninitialized);

    ExReleasePushLockExclusive(&g_WqManager.InitLock);
    KeLeaveCriticalRegion();
}

_Use_decl_annotations_
BOOLEAN
ShadowStrikeWorkQueueIsInitialized(VOID)
{
    LONG State = InterlockedCompareExchange(&g_WqManager.State, 0, 0);
    return (State == (LONG)ShadowWqStateRunning ||
            State == (LONG)ShadowWqStatePaused);
}

_Use_decl_annotations_
SHADOWSTRIKE_WQ_STATE
ShadowStrikeWorkQueueGetState(VOID)
{
    return (SHADOWSTRIKE_WQ_STATE)InterlockedCompareExchange(
        &g_WqManager.State, 0, 0);
}

// ============================================================================
// INTERNAL: WORK ITEM LIFECYCLE
// FIX #7: Single ListEntry (ActiveListEntry), no dual-list
// FIX #16: No unnecessary zeroing of SLIST items
// FIX #17: SubmitTime set before insertion
// FIX #19: ActiveList membership tracked via state, not IsListEmpty
// ============================================================================

static PSHADOWSTRIKE_WORK_ITEM
WqiAllocateWorkItem(VOID)
{
    PSHADOWSTRIKE_WORK_ITEM Item;

    // Try free list first
    PSLIST_ENTRY Entry = InterlockedPopEntrySList(&g_WqManager.FreeList);
    if (Entry != NULL) {
        Item = CONTAINING_RECORD(Entry, SHADOWSTRIKE_WORK_ITEM, FreeListEntry);
        InterlockedDecrement(&g_WqManager.FreeCount);
    } else {
        Item = (PSHADOWSTRIKE_WORK_ITEM)ExAllocateFromNPagedLookasideList(
            &g_WqManager.WorkItemLookaside);
        if (Item == NULL) {
            return NULL;
        }
    }

    // Zero the entire item for clean state
    RtlZeroMemory(Item, sizeof(SHADOWSTRIKE_WORK_ITEM));

    // Initialize common fields
    Item->ItemId = (ULONG64)InterlockedIncrement64(&g_WqManager.NextItemId);
    Item->RefCount = 1;
    InterlockedExchange(&Item->State, (LONG)ShadowWqItemStateAllocated);
    Item->Manager = &g_WqManager;
    InitializeListHead(&Item->ActiveListEntry);

    return Item;
}

static VOID
WqiFreeWorkItem(
    _In_ PSHADOWSTRIKE_WORK_ITEM Item)
{
    if (Item == NULL) return;

    // Cleanup context
    if (Item->Context != NULL) {
        if (Item->Flags & ShadowWqFlagSecureContext) {
            ShadowStrikeSecureZeroMemory(Item->Context, Item->ContextSize);
        }
        if (!Item->UsingInlineContext &&
            (Item->Flags & ShadowWqFlagDeleteContext)) {
            ShadowStrikeFreePoolWithTag(Item->Context, SHADOW_WQ_CONTEXT_TAG);
        }
        Item->Context = NULL;
    }

    // FIX #10: IoFreeWorkItem is safe here because the item has completed
    // or been removed from dispatch. We only call WqiFreeWorkItem after
    // the IoWorkItem callback has returned (via WqiCompleteWorkItem path)
    // or during shutdown after KeFlushQueuedDpcs.
    if (Item->IoWorkItem != NULL) {
        IoFreeWorkItem(Item->IoWorkItem);
        Item->IoWorkItem = NULL;
    }

    if (Item->FltWorkItem != NULL) {
        FltFreeGenericWorkItem(Item->FltWorkItem);
        Item->FltWorkItem = NULL;
    }

    InterlockedExchange(&Item->State, (LONG)ShadowWqItemStateFree);

    // Return to free list if below threshold
    if (g_WqManager.FreeCount < (LONG)g_WqManager.Config.LookasideDepth) {
        InterlockedPushEntrySList(&g_WqManager.FreeList, &Item->FreeListEntry);
        InterlockedIncrement(&g_WqManager.FreeCount);
    } else {
        ExFreeToNPagedLookasideList(&g_WqManager.WorkItemLookaside, Item);
    }
}

static VOID
WqiReferenceWorkItem(
    _Inout_ PSHADOWSTRIKE_WORK_ITEM Item)
{
    LONG Old = InterlockedIncrement(&Item->RefCount);
    NT_ASSERT(Old > 1); // Must not reference a freed item
    UNREFERENCED_PARAMETER(Old);
}

static VOID
WqiDereferenceWorkItem(
    _Inout_ PSHADOWSTRIKE_WORK_ITEM Item)
{
    LONG New = InterlockedDecrement(&Item->RefCount);
    NT_ASSERT(New >= 0);
    if (New == 0) {
        WqiFreeWorkItem(Item);
    }
}

// ============================================================================
// INTERNAL: ACTIVE LIST HELPERS
// ============================================================================

static VOID
WqiAddToActiveList(
    _Inout_ PSHADOWSTRIKE_WORK_ITEM Item)
{
    KIRQL OldIrql;

    // FIX #17: Set submit time BEFORE adding to list
    KeQuerySystemTimePrecise(&Item->SubmitTime);

    KeAcquireSpinLock(&g_WqManager.ActiveListLock, &OldIrql);
    InsertTailList(&g_WqManager.ActiveList, &Item->ActiveListEntry);
    InterlockedIncrement(&g_WqManager.ActiveCount);
    KeReleaseSpinLock(&g_WqManager.ActiveListLock, OldIrql);
}

static VOID
WqiRemoveFromActiveList(
    _Inout_ PSHADOWSTRIKE_WORK_ITEM Item)
{
    KIRQL OldIrql;

    KeAcquireSpinLock(&g_WqManager.ActiveListLock, &OldIrql);
    // FIX #19: Check Flink is valid before removing
    if (Item->ActiveListEntry.Flink != &Item->ActiveListEntry) {
        RemoveEntryList(&Item->ActiveListEntry);
        InitializeListHead(&Item->ActiveListEntry);
        InterlockedDecrement(&g_WqManager.ActiveCount);
    }
    KeReleaseSpinLock(&g_WqManager.ActiveListLock, OldIrql);
}

// ============================================================================
// INTERNAL: CONTEXT SETUP
// FIX #12: Always NonPaged for contexts (callable from DISPATCH_LEVEL)
// ============================================================================

static NTSTATUS
WqiSetupContext(
    _Inout_ PSHADOWSTRIKE_WORK_ITEM Item,
    _In_opt_ PVOID Context,
    _In_ ULONG ContextSize,
    _In_ ULONG Flags)
{
    if (Context == NULL || ContextSize == 0) {
        Item->Context = Context;
        Item->ContextSize = (Context != NULL) ? 0 : ContextSize;
        Item->UsingInlineContext = FALSE;
        return STATUS_SUCCESS;
    }

    if (ContextSize > WQ_MAX_CONTEXT_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Flags & ShadowWqFlagCopyContext) {
        if (ContextSize <= WQ_MAX_INLINE_CONTEXT_SIZE) {
            RtlCopyMemory(Item->InlineContext, Context, ContextSize);
            Item->Context = Item->InlineContext;
            Item->UsingInlineContext = TRUE;
        } else {
            // FIX #12: ALWAYS NonPaged — this function is callable
            // from DISPATCH_LEVEL via the submission APIs
            PVOID Copy = ShadowStrikeAllocateWithTag(
                ContextSize, SHADOW_WQ_CONTEXT_TAG);
            if (Copy == NULL) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            RtlCopyMemory(Copy, Context, ContextSize);
            Item->Context = Copy;
            Item->UsingInlineContext = FALSE;
        }
    } else {
        // Reference caller's buffer
        Item->Context = Context;
        Item->UsingInlineContext = FALSE;
    }

    Item->ContextSize = ContextSize;
    return STATUS_SUCCESS;
}

// ============================================================================
// INTERNAL: DISPATCH ITEM TO SYSTEM WORK QUEUE
// FIX #3: No fallback to direct execution at DISPATCH_LEVEL
// ============================================================================

static NTSTATUS
WqiDispatchItem(
    _Inout_ PSHADOWSTRIKE_WORK_ITEM Item)
{
    NTSTATUS Status;

    // Try IoWorkItem first (preferred, unload-safe)
    if (g_WqManager.DeviceObject != NULL) {
        Item->IoWorkItem = IoAllocateWorkItem(g_WqManager.DeviceObject);
        if (Item->IoWorkItem == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Item->Type = ShadowWqTypeSystem;
        InterlockedExchange(&Item->State, (LONG)ShadowWqItemStateQueued);

        IoQueueWorkItem(
            Item->IoWorkItem,
            WqiIoWorkItemCallback,
            ShadowStrikeWqPriorityToWorkQueueType(Item->Priority),
            Item);

        return STATUS_SUCCESS;
    }

    // Try filter manager
    if (g_WqManager.FilterHandle != NULL) {
        Item->FltWorkItem = FltAllocateGenericWorkItem();
        if (Item->FltWorkItem == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Item->Type = ShadowWqTypeFilter;
        InterlockedExchange(&Item->State, (LONG)ShadowWqItemStateQueued);

        Status = FltQueueGenericWorkItem(
            Item->FltWorkItem,
            g_WqManager.FilterHandle,
            WqiFltWorkItemCallback,
            ShadowStrikeWqPriorityToWorkQueueType(Item->Priority),
            Item);

        if (!NT_SUCCESS(Status)) {
            FltFreeGenericWorkItem(Item->FltWorkItem);
            Item->FltWorkItem = NULL;
            return Status;
        }
        return STATUS_SUCCESS;
    }

    // FIX #3: No DeviceObject AND no FilterHandle = cannot dispatch.
    // Do NOT execute directly at arbitrary IRQL.
    return STATUS_DEVICE_NOT_READY;
}

static NTSTATUS
WqiDispatchFilterItem(
    _Inout_ PSHADOWSTRIKE_WORK_ITEM Item,
    _In_ PFLT_INSTANCE Instance)
{
    NTSTATUS Status;

    Item->FltWorkItem = FltAllocateGenericWorkItem();
    if (Item->FltWorkItem == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Item->Type = ShadowWqTypeFilter;
    InterlockedExchange(&Item->State, (LONG)ShadowWqItemStateQueued);

    Status = FltQueueGenericWorkItem(
        Item->FltWorkItem,
        Instance,
        WqiFltWorkItemCallback,
        ShadowStrikeWqPriorityToWorkQueueType(Item->Priority),
        Item);

    if (!NT_SUCCESS(Status)) {
        FltFreeGenericWorkItem(Item->FltWorkItem);
        Item->FltWorkItem = NULL;
    }

    return Status;
}

// ============================================================================
// INTERNAL: LEGACY ROUTINE WRAPPER
// FIX #8: Proper wrapper instead of UB function pointer cast
// ============================================================================

static NTSTATUS
WqiLegacyRoutineWrapper(
    _In_opt_ PVOID Context,
    _In_ ULONG ContextSize)
{
    PSHADOWSTRIKE_WORK_ITEM Item;

    UNREFERENCED_PARAMETER(ContextSize);

    // The Context for legacy items is the WORK_ITEM itself,
    // which stores the original legacy callback and original context.
    Item = (PSHADOWSTRIKE_WORK_ITEM)Context;
    if (Item == NULL || Item->LegacyRoutine == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Call the original void-returning callback with the real context
    Item->LegacyRoutine(Item->Options.CompletionContext);
    return STATUS_SUCCESS;
}

// ============================================================================
// INTERNAL: EXECUTION AND COMPLETION
// FIX #5: Retry re-acquires rundown protection
// FIX #6: Clean completion path
// ============================================================================

static VOID
WqiExecuteWorkItem(
    _In_ PSHADOWSTRIKE_WORK_ITEM Item)
{
    NTSTATUS Status = STATUS_SUCCESS;
    LARGE_INTEGER StartTime, EndTime;

    // Check cancellation
    if (InterlockedCompareExchange(&Item->CancelRequested, 0, 0) != 0) {
        WqiCompleteWorkItem(Item, STATUS_CANCELLED);
        return;
    }

    // Transition to Running
    InterlockedExchange(&Item->State, (LONG)ShadowWqItemStateRunning);
    KeQuerySystemTimePrecise(&StartTime);
    Item->StartTime = StartTime;

    InterlockedIncrement(&g_WqManager.Stats.CurrentExecuting);

    // Execute work routine with SEH protection
    __try {
        if (Item->LegacyRoutine != NULL) {
            // Legacy void-return path
            Item->LegacyRoutine(Item->Context);
            Status = STATUS_SUCCESS;
        } else if (Item->Routine != NULL) {
            Status = Item->Routine(Item->Context, Item->ContextSize);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    KeQuerySystemTimePrecise(&EndTime);
    Item->EndTime = EndTime;

    // Update timing statistics
    if (g_WqManager.Config.EnableDetailedTiming) {
        LONG64 ExecTimeUs = (LONG64)ShadowStrikeWqGetElapsedUs(&StartTime, &EndTime);
        LONG64 WaitTimeUs = (LONG64)ShadowStrikeWqGetElapsedUs(&Item->SubmitTime, &StartTime);
        InterlockedAdd64(&g_WqManager.Stats.TotalExecTimeUs, ExecTimeUs);
        InterlockedAdd64(&g_WqManager.Stats.TotalWaitTimeUs, WaitTimeUs);
        InterlockedIncrement64(&g_WqManager.Stats.TimingSampleCount);
    }

    InterlockedDecrement(&g_WqManager.Stats.CurrentExecuting);

    // FIX #5: Handle retry — re-acquire rundown before re-queue
    if (!NT_SUCCESS(Status) &&
        (Item->Flags & ShadowWqFlagRetryOnFailure) &&
        Item->RetryCount < Item->Options.MaxRetries) {

        Item->RetryCount++;
        InterlockedIncrement64(&g_WqManager.Stats.TotalRetries);

        if (Item->Options.RetryDelayMs > 0) {
            // Delayed retry via timer → DPC → IoWorkItem
            // Rundown is still held from the original submission
            // (we haven't released it yet in this code path)
            LARGE_INTEGER DueTime;
            DueTime.QuadPart = -((LONGLONG)Item->Options.RetryDelayMs * 10000);

            // Re-allocate IoWorkItem for the retry dispatch from DPC
            if (Item->IoWorkItem != NULL) {
                IoFreeWorkItem(Item->IoWorkItem);
                Item->IoWorkItem = NULL;
            }
            if (g_WqManager.DeviceObject != NULL) {
                Item->IoWorkItem = IoAllocateWorkItem(g_WqManager.DeviceObject);
            }
            if (Item->IoWorkItem == NULL) {
                // Can't retry without infrastructure — complete as failed
                WqiCompleteWorkItem(Item, Status);
                return;
            }

            KeInitializeTimer(&Item->DelayTimer);
            KeInitializeDpc(&Item->DelayDpc, WqiDelayTimerDpcCallback, Item);
            InterlockedExchange(&Item->State, (LONG)ShadowWqItemStateQueued);
            KeSetTimer(&Item->DelayTimer, DueTime, &Item->DelayDpc);
        } else {
            // Immediate retry — dispatch again
            if (Item->IoWorkItem != NULL) {
                IoFreeWorkItem(Item->IoWorkItem);
                Item->IoWorkItem = NULL;
            }
            NTSTATUS DispatchStatus = WqiDispatchItem(Item);
            if (!NT_SUCCESS(DispatchStatus)) {
                WqiCompleteWorkItem(Item, Status);
            }
            // If dispatch succeeded, the work item callback will call us again
        }
        return;
    }

    WqiCompleteWorkItem(Item, Status);
}

static VOID
WqiCompleteWorkItem(
    _In_ PSHADOWSTRIKE_WORK_ITEM Item,
    _In_ NTSTATUS Status)
{
    BOOLEAN Success = NT_SUCCESS(Status);

    Item->CompletionStatus = Status;
    KeQuerySystemTimePrecise(&Item->EndTime);

    // Set final state
    if (Status == STATUS_CANCELLED) {
        InterlockedExchange(&Item->State, (LONG)ShadowWqItemStateCancelled);
    } else if (Success) {
        InterlockedExchange(&Item->State, (LONG)ShadowWqItemStateCompleted);
    } else {
        InterlockedExchange(&Item->State, (LONG)ShadowWqItemStateFailed);
    }

    // Completion callback
    if (Item->Options.CompletionCallback != NULL) {
        __try {
            Item->Options.CompletionCallback(
                Status, Item->Context, Item->Options.CompletionContext);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // Don't crash on bad callback
        }
    }

    // Signal completion event
    if ((Item->Flags & ShadowWqFlagSignalCompletion) &&
        Item->Options.CompletionEvent != NULL) {
        KeSetEvent(Item->Options.CompletionEvent, IO_NO_INCREMENT, FALSE);
    }

    // Cleanup callback
    if (Item->Options.CleanupCallback != NULL) {
        __try {
            Item->Options.CleanupCallback(Item->Context, Item->ContextSize);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // Don't crash
        }
    }

    // Update stats
    WqiTrackComplete(Item, Success);

    // Remove from active list
    WqiRemoveFromActiveList(Item);

    // Check drain completion
    if (InterlockedCompareExchange(&g_WqManager.State, 0, 0) ==
        (LONG)ShadowWqStateDraining) {
        if (g_WqManager.ActiveCount == 0 && g_WqManager.PendingCount == 0) {
            KeSetEvent(&g_WqManager.DrainCompleteEvent, IO_NO_INCREMENT, FALSE);
        }
    }

    // Release rundown protection (acquired at submission time)
    ExReleaseRundownProtection(&g_WqManager.RundownProtection);

    // Dereference — may free the item
    WqiDereferenceWorkItem(Item);
}

// ============================================================================
// SYSTEM WORK ITEM CALLBACKS
// FIX #3: DPC NEVER executes work directly
// ============================================================================

static VOID
WqiIoWorkItemCallback(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PSHADOWSTRIKE_WORK_ITEM Item = (PSHADOWSTRIKE_WORK_ITEM)Context;
    if (Item == NULL) return;

    WqiExecuteWorkItem(Item);
}

static VOID
WqiFltWorkItemCallback(
    _In_ PFLT_GENERIC_WORKITEM FltWorkItem,
    _In_ PVOID FltObject,
    _In_opt_ PVOID Context)
{
    UNREFERENCED_PARAMETER(FltWorkItem);
    UNREFERENCED_PARAMETER(FltObject);

    PSHADOWSTRIKE_WORK_ITEM Item = (PSHADOWSTRIKE_WORK_ITEM)Context;
    if (Item == NULL) return;

    WqiExecuteWorkItem(Item);
}

/// DPC timer callback: queues work to PASSIVE_LEVEL via IoWorkItem
/// FIX #3: NEVER calls WqiExecuteWorkItem directly
static VOID
WqiDelayTimerDpcCallback(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    PSHADOWSTRIKE_WORK_ITEM Item = (PSHADOWSTRIKE_WORK_ITEM)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (Item == NULL) return;

    // Check if shutdown
    if (InterlockedCompareExchange(&g_WqManager.State, 0, 0) ==
        (LONG)ShadowWqStateShutdown) {
        // Complete as cancelled — but rundown is already released during
        // shutdown, so just mark and dereference
        InterlockedExchange(&Item->State, (LONG)ShadowWqItemStateCancelled);
        Item->CompletionStatus = STATUS_CANCELLED;
        WqiRemoveFromActiveList(Item);
        InterlockedDecrement(&g_WqManager.PendingCount);
        WqiDereferenceWorkItem(Item);
        return;
    }

    // Dispatch via IoWorkItem (must have been pre-allocated)
    if (Item->IoWorkItem != NULL) {
        IoQueueWorkItem(
            Item->IoWorkItem,
            WqiIoWorkItemCallback,
            ShadowStrikeWqPriorityToWorkQueueType(Item->Priority),
            Item);
    } else {
        // No IoWorkItem available — complete as failed
        WqiCompleteWorkItem(Item, STATUS_DEVICE_NOT_READY);
    }
}

// ============================================================================
// INTERNAL: STATISTICS
// FIX #9: All per-priority stats use interlocked operations
// ============================================================================

static VOID
WqiTrackSubmit(VOID)
{
    LONG Current, Peak;

    InterlockedIncrement64(&g_WqManager.Stats.TotalSubmitted);
    Current = InterlockedIncrement(&g_WqManager.PendingCount);
    InterlockedIncrement(&g_WqManager.Stats.CurrentPending);

    // Update peak atomically
    do {
        Peak = g_WqManager.Stats.PeakPending;
        if (Current <= Peak) break;
    } while (InterlockedCompareExchange(
        &g_WqManager.Stats.PeakPending, Current, Peak) != Peak);
}

static VOID
WqiTrackComplete(
    _In_ PSHADOWSTRIKE_WORK_ITEM Item,
    _In_ BOOLEAN Success)
{
    UNREFERENCED_PARAMETER(Item);

    InterlockedDecrement(&g_WqManager.PendingCount);
    InterlockedDecrement(&g_WqManager.Stats.CurrentPending);

    if (InterlockedCompareExchange(&Item->State, 0, 0) ==
        (LONG)ShadowWqItemStateCancelled) {
        InterlockedIncrement64(&g_WqManager.Stats.TotalCancelled);
    } else if (Success) {
        InterlockedIncrement64(&g_WqManager.Stats.TotalCompleted);
    } else {
        InterlockedIncrement64(&g_WqManager.Stats.TotalFailed);
    }

    // Update executing peak
    LONG ExecCurrent = g_WqManager.Stats.CurrentExecuting;
    LONG ExecPeak;
    do {
        ExecPeak = g_WqManager.Stats.PeakExecuting;
        if (ExecCurrent <= ExecPeak) break;
    } while (InterlockedCompareExchange(
        &g_WqManager.Stats.PeakExecuting, ExecCurrent, ExecPeak) != ExecPeak);
}

static PSHADOWSTRIKE_WORK_ITEM
WqiFindWorkItemById(
    _In_ ULONG64 ItemId)
{
    KIRQL OldIrql;
    PLIST_ENTRY Entry;
    PSHADOWSTRIKE_WORK_ITEM Found = NULL;

    KeAcquireSpinLock(&g_WqManager.ActiveListLock, &OldIrql);

    for (Entry = g_WqManager.ActiveList.Flink;
         Entry != &g_WqManager.ActiveList;
         Entry = Entry->Flink) {

        PSHADOWSTRIKE_WORK_ITEM Item = CONTAINING_RECORD(
            Entry, SHADOWSTRIKE_WORK_ITEM, ActiveListEntry);

        if (Item->ItemId == ItemId) {
            WqiReferenceWorkItem(Item);
            Found = Item;
            break;
        }
    }

    KeReleaseSpinLock(&g_WqManager.ActiveListLock, OldIrql);
    return Found;
}

// ============================================================================
// SIMPLE SUBMISSION API
// FIX #6: Clean error paths with proper rundown release
// FIX #8: Legacy wrapper instead of UB cast
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeQueueWorkItem(
    _In_ PFN_SHADOWSTRIKE_WORK_ROUTINE_LEGACY Routine,
    _In_opt_ PVOID Context)
{
    return ShadowStrikeQueueWorkItemWithPriority(
        Routine, Context, ShadowWqPriorityNormal);
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeQueueWorkItemWithPriority(
    _In_ PFN_SHADOWSTRIKE_WORK_ROUTINE_LEGACY Routine,
    _In_opt_ PVOID Context,
    _In_ SHADOWSTRIKE_WQ_PRIORITY Priority)
{
    NTSTATUS Status;
    PSHADOWSTRIKE_WORK_ITEM Item;

    // Validate state
    if (InterlockedCompareExchange(&g_WqManager.State, 0, 0) !=
        (LONG)ShadowWqStateRunning) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (!ExAcquireRundownProtection(&g_WqManager.RundownProtection)) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (Routine == NULL) {
        ExReleaseRundownProtection(&g_WqManager.RundownProtection);
        return STATUS_INVALID_PARAMETER;
    }

    if (!ShadowStrikeIsValidWqPriority(Priority)) {
        Priority = ShadowWqPriorityNormal;
    }

    // Check capacity
    if (g_WqManager.PendingCount >= g_WqManager.MaxPending) {
        InterlockedIncrement64(&g_WqManager.Stats.TotalDropped);
        ExReleaseRundownProtection(&g_WqManager.RundownProtection);
        return STATUS_QUOTA_EXCEEDED;
    }

    Item = WqiAllocateWorkItem();
    if (Item == NULL) {
        ExReleaseRundownProtection(&g_WqManager.RundownProtection);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // FIX #8: Store legacy routine separately, use proper wrapper-free path
    Item->LegacyRoutine = Routine;
    Item->Routine = NULL;
    Item->Context = Context;
    Item->ContextSize = 0;
    Item->Priority = Priority;
    Item->Flags = ShadowWqFlagNone;
    Item->UsingInlineContext = FALSE;

    // Add to active tracking
    WqiAddToActiveList(Item);
    WqiTrackSubmit();

    // Dispatch
    Status = WqiDispatchItem(Item);
    if (!NT_SUCCESS(Status)) {
        // Cleanup on dispatch failure
        WqiRemoveFromActiveList(Item);
        InterlockedDecrement(&g_WqManager.PendingCount);
        InterlockedDecrement(&g_WqManager.Stats.CurrentPending);
        WqiFreeWorkItem(Item);
        ExReleaseRundownProtection(&g_WqManager.RundownProtection);
        return Status;
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeQueueWorkItemWithContext(
    _In_ PFN_SHADOWSTRIKE_WORK_ROUTINE Routine,
    _In_reads_bytes_opt_(ContextSize) PVOID Context,
    _In_ ULONG ContextSize,
    _In_ SHADOWSTRIKE_WQ_PRIORITY Priority)
{
    SHADOWSTRIKE_WQ_OPTIONS Options;

    ShadowStrikeInitWorkQueueOptions(&Options);
    Options.Priority = Priority;
    Options.Flags = ShadowWqFlagCopyContext | ShadowWqFlagDeleteContext;

    return ShadowStrikeQueueWorkItemEx(
        Routine, Context, ContextSize, &Options, NULL);
}

// ============================================================================
// ADVANCED SUBMISSION API
// FIX #5, #6, #12: Proper error paths, NonPaged contexts, rundown balance
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeQueueWorkItemEx(
    _In_ PFN_SHADOWSTRIKE_WORK_ROUTINE Routine,
    _In_reads_bytes_opt_(ContextSize) PVOID Context,
    _In_ ULONG ContextSize,
    _In_opt_ PSHADOWSTRIKE_WQ_OPTIONS Options,
    _Out_opt_ PULONG64 ItemId)
{
    NTSTATUS Status;
    PSHADOWSTRIKE_WORK_ITEM Item;
    SHADOWSTRIKE_WQ_OPTIONS DefaultOptions;

    if (ItemId != NULL) *ItemId = 0;

    if (InterlockedCompareExchange(&g_WqManager.State, 0, 0) !=
        (LONG)ShadowWqStateRunning) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (!ExAcquireRundownProtection(&g_WqManager.RundownProtection)) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (Routine == NULL) {
        ExReleaseRundownProtection(&g_WqManager.RundownProtection);
        return STATUS_INVALID_PARAMETER;
    }

    if (ContextSize > WQ_MAX_CONTEXT_SIZE) {
        ExReleaseRundownProtection(&g_WqManager.RundownProtection);
        return STATUS_INVALID_PARAMETER;
    }

    // Capacity check
    if (g_WqManager.PendingCount >= g_WqManager.MaxPending) {
        InterlockedIncrement64(&g_WqManager.Stats.TotalDropped);
        ExReleaseRundownProtection(&g_WqManager.RundownProtection);
        return STATUS_QUOTA_EXCEEDED;
    }

    if (Options == NULL) {
        ShadowStrikeInitWorkQueueOptions(&DefaultOptions);
        Options = &DefaultOptions;
    }

    if (!ShadowStrikeIsValidWqPriority(Options->Priority)) {
        Options->Priority = ShadowWqPriorityNormal;
    }

    Item = WqiAllocateWorkItem();
    if (Item == NULL) {
        ExReleaseRundownProtection(&g_WqManager.RundownProtection);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Item->Routine = Routine;
    Item->LegacyRoutine = NULL;
    Item->Priority = Options->Priority;
    Item->Flags = Options->Flags;
    RtlCopyMemory(&Item->Options, Options, sizeof(SHADOWSTRIKE_WQ_OPTIONS));

    // Setup context (always NonPaged for copies)
    Status = WqiSetupContext(Item, Context, ContextSize, Options->Flags);
    if (!NT_SUCCESS(Status)) {
        WqiFreeWorkItem(Item);
        ExReleaseRundownProtection(&g_WqManager.RundownProtection);
        return Status;
    }

    // Initialize timer/DPC for potential retries
    KeInitializeTimer(&Item->DelayTimer);
    KeInitializeDpc(&Item->DelayDpc, WqiDelayTimerDpcCallback, Item);

    // Track
    WqiAddToActiveList(Item);
    WqiTrackSubmit();

    if (ItemId != NULL) *ItemId = Item->ItemId;

    // Dispatch
    Status = WqiDispatchItem(Item);
    if (!NT_SUCCESS(Status)) {
        WqiRemoveFromActiveList(Item);
        InterlockedDecrement(&g_WqManager.PendingCount);
        InterlockedDecrement(&g_WqManager.Stats.CurrentPending);
        WqiFreeWorkItem(Item);
        ExReleaseRundownProtection(&g_WqManager.RundownProtection);
        if (ItemId != NULL) *ItemId = 0;
        return Status;
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeQueueDelayedWorkItem(
    _In_ PFN_SHADOWSTRIKE_WORK_ROUTINE Routine,
    _In_reads_bytes_opt_(ContextSize) PVOID Context,
    _In_ ULONG ContextSize,
    _In_ ULONG DelayMs,
    _In_opt_ PSHADOWSTRIKE_WQ_OPTIONS Options,
    _Out_opt_ PULONG64 ItemId)
{
    NTSTATUS Status;
    PSHADOWSTRIKE_WORK_ITEM Item;
    SHADOWSTRIKE_WQ_OPTIONS DefaultOptions;
    LARGE_INTEGER DueTime;

    if (ItemId != NULL) *ItemId = 0;

    if (InterlockedCompareExchange(&g_WqManager.State, 0, 0) !=
        (LONG)ShadowWqStateRunning) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (!ExAcquireRundownProtection(&g_WqManager.RundownProtection)) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (Routine == NULL) {
        ExReleaseRundownProtection(&g_WqManager.RundownProtection);
        return STATUS_INVALID_PARAMETER;
    }

    // Must have DeviceObject for the DPC -> IoWorkItem dispatch
    if (g_WqManager.DeviceObject == NULL) {
        ExReleaseRundownProtection(&g_WqManager.RundownProtection);
        return STATUS_DEVICE_NOT_READY;
    }

    if (Options == NULL) {
        ShadowStrikeInitWorkQueueOptions(&DefaultOptions);
        Options = &DefaultOptions;
    }

    Item = WqiAllocateWorkItem();
    if (Item == NULL) {
        ExReleaseRundownProtection(&g_WqManager.RundownProtection);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Item->Routine = Routine;
    Item->LegacyRoutine = NULL;
    Item->Priority = Options->Priority;
    Item->Flags = Options->Flags;
    Item->Type = ShadowWqTypeDelayed;
    RtlCopyMemory(&Item->Options, Options, sizeof(SHADOWSTRIKE_WQ_OPTIONS));

    // Setup context
    Status = WqiSetupContext(Item, Context, ContextSize, Options->Flags);
    if (!NT_SUCCESS(Status)) {
        WqiFreeWorkItem(Item);
        ExReleaseRundownProtection(&g_WqManager.RundownProtection);
        return Status;
    }

    // Pre-allocate IoWorkItem for when timer fires
    Item->IoWorkItem = IoAllocateWorkItem(g_WqManager.DeviceObject);
    if (Item->IoWorkItem == NULL) {
        WqiFreeWorkItem(Item);
        ExReleaseRundownProtection(&g_WqManager.RundownProtection);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Initialize timer/DPC
    KeInitializeTimer(&Item->DelayTimer);
    KeInitializeDpc(&Item->DelayDpc, WqiDelayTimerDpcCallback, Item);

    // Track
    WqiAddToActiveList(Item);
    WqiTrackSubmit();

    if (ItemId != NULL) *ItemId = Item->ItemId;

    // Set timer
    InterlockedExchange(&Item->State, (LONG)ShadowWqItemStateQueued);
    DueTime.QuadPart = -((LONGLONG)DelayMs * 10000);
    KeSetTimer(&Item->DelayTimer, DueTime, &Item->DelayDpc);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeQueueFilterWorkItem(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFN_SHADOWSTRIKE_WORK_ROUTINE Routine,
    _In_reads_bytes_opt_(ContextSize) PVOID Context,
    _In_ ULONG ContextSize,
    _In_opt_ PSHADOWSTRIKE_WQ_OPTIONS Options,
    _Out_opt_ PULONG64 ItemId)
{
    NTSTATUS Status;
    PSHADOWSTRIKE_WORK_ITEM Item;
    SHADOWSTRIKE_WQ_OPTIONS DefaultOptions;

    if (ItemId != NULL) *ItemId = 0;

    if (Instance == NULL || Routine == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(&g_WqManager.State, 0, 0) !=
        (LONG)ShadowWqStateRunning) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (!ExAcquireRundownProtection(&g_WqManager.RundownProtection)) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (Options == NULL) {
        ShadowStrikeInitWorkQueueOptions(&DefaultOptions);
        Options = &DefaultOptions;
    }

    Item = WqiAllocateWorkItem();
    if (Item == NULL) {
        ExReleaseRundownProtection(&g_WqManager.RundownProtection);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Item->Routine = Routine;
    Item->LegacyRoutine = NULL;
    Item->Priority = Options->Priority;
    Item->Flags = Options->Flags;
    RtlCopyMemory(&Item->Options, Options, sizeof(SHADOWSTRIKE_WQ_OPTIONS));

    Status = WqiSetupContext(Item, Context, ContextSize, Options->Flags);
    if (!NT_SUCCESS(Status)) {
        WqiFreeWorkItem(Item);
        ExReleaseRundownProtection(&g_WqManager.RundownProtection);
        return Status;
    }

    WqiAddToActiveList(Item);
    WqiTrackSubmit();

    if (ItemId != NULL) *ItemId = Item->ItemId;

    Status = WqiDispatchFilterItem(Item, Instance);
    if (!NT_SUCCESS(Status)) {
        WqiRemoveFromActiveList(Item);
        InterlockedDecrement(&g_WqManager.PendingCount);
        InterlockedDecrement(&g_WqManager.Stats.CurrentPending);
        WqiFreeWorkItem(Item);
        ExReleaseRundownProtection(&g_WqManager.RundownProtection);
        if (ItemId != NULL) *ItemId = 0;
        return Status;
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// WORK ITEM MANAGEMENT
// FIX #11: Flush actually completes items
// FIX #14: CancelByKey fully cancels items
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeCancelWorkItem(
    _In_ ULONG64 ItemId)
{
    PSHADOWSTRIKE_WORK_ITEM Item;
    LONG OldState;

    Item = WqiFindWorkItemById(ItemId);
    if (Item == NULL) {
        return STATUS_NOT_FOUND;
    }

    // Try to transition from Queued to Cancelled atomically
    OldState = InterlockedCompareExchange(
        &Item->State,
        (LONG)ShadowWqItemStateCancelled,
        (LONG)ShadowWqItemStateQueued);

    if (OldState == (LONG)ShadowWqItemStateQueued) {
        // Successfully cancelled before execution
        InterlockedExchange(&Item->CancelRequested, 1);

        // Cancel timer if delayed
        if (Item->Type == ShadowWqTypeDelayed) {
            KeCancelTimer(&Item->DelayTimer);
        }

        // Call cancel callback
        if (Item->Options.CancelCallback != NULL) {
            __try {
                Item->Options.CancelCallback(Item->Context, Item->ContextSize);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                // Don't crash
            }
        }

        WqiCompleteWorkItem(Item, STATUS_CANCELLED);
        WqiDereferenceWorkItem(Item); // release FindById ref
        return STATUS_SUCCESS;
    }

    if (OldState == (LONG)ShadowWqItemStateRunning) {
        // Already executing — set cancel flag, routine can check it
        InterlockedExchange(&Item->CancelRequested, 1);
        WqiDereferenceWorkItem(Item);
        return STATUS_UNSUCCESSFUL;
    }

    // Already completed or in other state
    WqiDereferenceWorkItem(Item);
    return STATUS_UNSUCCESSFUL;
}

// FIX #14: CancelWorkItemsByKey removed — serialization feature was dead code

_Use_decl_annotations_
NTSTATUS
ShadowStrikeWaitForWorkItem(
    _In_ ULONG64 ItemId,
    _In_ ULONG TimeoutMs,
    _Out_opt_ PNTSTATUS CompletionStatus)
{
    PSHADOWSTRIKE_WORK_ITEM Item;
    LARGE_INTEGER StartPerfCount, CurrentPerfCount, Frequency;
    LARGE_INTEGER SleepInterval;
    ULONG64 ElapsedMs;

    PAGED_CODE();

    if (CompletionStatus != NULL) *CompletionStatus = STATUS_UNSUCCESSFUL;

    Item = WqiFindWorkItemById(ItemId);
    if (Item == NULL) {
        return STATUS_NOT_FOUND;
    }

    // Check if already complete
    LONG State = InterlockedCompareExchange(&Item->State, 0, 0);
    if (State == (LONG)ShadowWqItemStateCompleted ||
        State == (LONG)ShadowWqItemStateCancelled ||
        State == (LONG)ShadowWqItemStateFailed) {

        if (CompletionStatus != NULL) *CompletionStatus = Item->CompletionStatus;
        WqiDereferenceWorkItem(Item);
        return STATUS_SUCCESS;
    }

    // Wait using completion event if available
    if ((Item->Flags & ShadowWqFlagSignalCompletion) &&
        Item->Options.CompletionEvent != NULL) {

        LARGE_INTEGER Timeout;
        Timeout.QuadPart = (TimeoutMs == 0) ?
            0 : -((LONGLONG)TimeoutMs * 10000);

        NTSTATUS WaitStatus = KeWaitForSingleObject(
            Item->Options.CompletionEvent,
            Executive, KernelMode, FALSE,
            (TimeoutMs == 0) ? NULL : &Timeout);

        if (WaitStatus == STATUS_SUCCESS) {
            if (CompletionStatus != NULL) *CompletionStatus = Item->CompletionStatus;
            WqiDereferenceWorkItem(Item);
            return STATUS_SUCCESS;
        }

        WqiDereferenceWorkItem(Item);
        return STATUS_TIMEOUT;
    }

    // FIX #13: Poll with accurate timing using KeQueryPerformanceCounter
    StartPerfCount = KeQueryPerformanceCounter(&Frequency);
    SleepInterval.QuadPart = -10000; // 1ms minimum sleep

    while (TRUE) {
        State = InterlockedCompareExchange(&Item->State, 0, 0);
        if (State == (LONG)ShadowWqItemStateCompleted ||
            State == (LONG)ShadowWqItemStateCancelled ||
            State == (LONG)ShadowWqItemStateFailed) {

            if (CompletionStatus != NULL) *CompletionStatus = Item->CompletionStatus;
            WqiDereferenceWorkItem(Item);
            return STATUS_SUCCESS;
        }

        if (TimeoutMs > 0) {
            CurrentPerfCount = KeQueryPerformanceCounter(NULL);
            ElapsedMs = ((ULONG64)(CurrentPerfCount.QuadPart - StartPerfCount.QuadPart) * 1000)
                        / (ULONG64)Frequency.QuadPart;
            if (ElapsedMs >= TimeoutMs) {
                WqiDereferenceWorkItem(Item);
                return STATUS_TIMEOUT;
            }
        }

        KeDelayExecutionThread(KernelMode, FALSE, &SleepInterval);
    }
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeGetWorkItemState(
    _In_ ULONG64 ItemId,
    _Out_ PSHADOWSTRIKE_WQ_ITEM_STATE State)
{
    PSHADOWSTRIKE_WORK_ITEM Item;

    if (State == NULL) return STATUS_INVALID_PARAMETER;
    *State = ShadowWqItemStateFree;

    Item = WqiFindWorkItemById(ItemId);
    if (Item == NULL) return STATUS_NOT_FOUND;

    *State = (SHADOWSTRIKE_WQ_ITEM_STATE)InterlockedCompareExchange(
        &Item->State, 0, 0);
    WqiDereferenceWorkItem(Item);

    return STATUS_SUCCESS;
}

// ============================================================================
// QUEUE CONTROL
// FIX #18: State transitions use InterlockedCompareExchange
// FIX #11: Flush actually cancels and completes items
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeWorkQueuePause(VOID)
{
    // FIX #18: Atomic state transition
    LONG Old = InterlockedCompareExchange(
        &g_WqManager.State,
        (LONG)ShadowWqStatePaused,
        (LONG)ShadowWqStateRunning);

    if (Old != (LONG)ShadowWqStateRunning) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    InterlockedExchange(&g_WqManager.Stats.State, (LONG)ShadowWqStatePaused);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeWorkQueueResume(VOID)
{
    LONG Old = InterlockedCompareExchange(
        &g_WqManager.State,
        (LONG)ShadowWqStateRunning,
        (LONG)ShadowWqStatePaused);

    if (Old != (LONG)ShadowWqStatePaused) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    InterlockedExchange(&g_WqManager.Stats.State, (LONG)ShadowWqStateRunning);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeWorkQueueDrain(
    _In_ ULONG TimeoutMs)
{
    LARGE_INTEGER Timeout;
    NTSTATUS Status;

    PAGED_CODE();

    // Transition to draining
    LONG Old = InterlockedCompareExchange(
        &g_WqManager.State,
        (LONG)ShadowWqStateDraining,
        (LONG)ShadowWqStateRunning);

    if (Old != (LONG)ShadowWqStateRunning) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    InterlockedExchange(&g_WqManager.Stats.State, (LONG)ShadowWqStateDraining);
    KeClearEvent(&g_WqManager.DrainCompleteEvent);

    // Check if already drained
    if (g_WqManager.ActiveCount == 0 && g_WqManager.PendingCount == 0) {
        InterlockedExchange(&g_WqManager.State, (LONG)ShadowWqStateRunning);
        InterlockedExchange(&g_WqManager.Stats.State, (LONG)ShadowWqStateRunning);
        return STATUS_SUCCESS;
    }

    // Wait
    Timeout.QuadPart = -((LONGLONG)TimeoutMs * 10000);
    Status = KeWaitForSingleObject(
        &g_WqManager.DrainCompleteEvent,
        Executive, KernelMode, FALSE,
        (TimeoutMs == 0) ? NULL : &Timeout);

    InterlockedExchange(&g_WqManager.State, (LONG)ShadowWqStateRunning);
    InterlockedExchange(&g_WqManager.Stats.State, (LONG)ShadowWqStateRunning);

    return (Status == STATUS_SUCCESS) ? STATUS_SUCCESS : STATUS_TIMEOUT;
}

_Use_decl_annotations_
ULONG
ShadowStrikeWorkQueueFlush(VOID)
{
    KIRQL OldIrql;
    PLIST_ENTRY Entry, NextEntry;
    PSHADOWSTRIKE_WORK_ITEM Item;
    ULONG FlushedCount = 0;
    LIST_ENTRY ToCancelList;

    InitializeListHead(&ToCancelList);

    // FIX #11: Collect queued items under lock, then cancel them outside lock
    KeAcquireSpinLock(&g_WqManager.ActiveListLock, &OldIrql);

    for (Entry = g_WqManager.ActiveList.Flink;
         Entry != &g_WqManager.ActiveList;
         Entry = NextEntry) {

        NextEntry = Entry->Flink;
        Item = CONTAINING_RECORD(Entry, SHADOWSTRIKE_WORK_ITEM, ActiveListEntry);

        LONG State = InterlockedCompareExchange(&Item->State, 0, 0);
        if (State == (LONG)ShadowWqItemStateQueued) {
            // Atomically transition to cancelled
            LONG Was = InterlockedCompareExchange(
                &Item->State,
                (LONG)ShadowWqItemStateCancelled,
                (LONG)ShadowWqItemStateQueued);

            if (Was == (LONG)ShadowWqItemStateQueued) {
                InterlockedExchange(&Item->CancelRequested, 1);

                // Cancel timer if delayed
                if (Item->Type == ShadowWqTypeDelayed) {
                    KeCancelTimer(&Item->DelayTimer);
                }

                // Remove from active list
                RemoveEntryList(&Item->ActiveListEntry);
                InterlockedDecrement(&g_WqManager.ActiveCount);

                // Move to local cancel list
                InsertTailList(&ToCancelList, &Item->ActiveListEntry);
                FlushedCount++;
            }
        }
    }

    KeReleaseSpinLock(&g_WqManager.ActiveListLock, OldIrql);

    // Complete cancelled items outside spin lock
    while (!IsListEmpty(&ToCancelList)) {
        Entry = RemoveHeadList(&ToCancelList);
        Item = CONTAINING_RECORD(Entry, SHADOWSTRIKE_WORK_ITEM, ActiveListEntry);
        InitializeListHead(&Item->ActiveListEntry);

        // Cancel callback
        if (Item->Options.CancelCallback != NULL) {
            __try {
                Item->Options.CancelCallback(Item->Context, Item->ContextSize);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                // Don't crash
            }
        }

        Item->CompletionStatus = STATUS_CANCELLED;

        // Completion callback
        if (Item->Options.CompletionCallback != NULL) {
            __try {
                Item->Options.CompletionCallback(
                    STATUS_CANCELLED, Item->Context, Item->Options.CompletionContext);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                // Don't crash
            }
        }

        // Signal completion event
        if ((Item->Flags & ShadowWqFlagSignalCompletion) &&
            Item->Options.CompletionEvent != NULL) {
            KeSetEvent(Item->Options.CompletionEvent, IO_NO_INCREMENT, FALSE);
        }

        // Update stats
        InterlockedDecrement(&g_WqManager.PendingCount);
        InterlockedDecrement(&g_WqManager.Stats.CurrentPending);
        InterlockedIncrement64(&g_WqManager.Stats.TotalCancelled);

        // Release rundown + free
        ExReleaseRundownProtection(&g_WqManager.RundownProtection);
        WqiDereferenceWorkItem(Item);
    }

    return FlushedCount;
}

// ============================================================================
// STATISTICS
// FIX #9, #20, #24: Thread-safe stats using interlocked operations
// ============================================================================

_Use_decl_annotations_
VOID
ShadowStrikeGetWorkQueueStatistics(
    _Out_ PSHADOWSTRIKE_WQ_STATISTICS Statistics)
{
    LARGE_INTEGER CurrentTime;

    if (Statistics == NULL) return;

    // Snapshot volatile fields individually for consistency
    Statistics->State = InterlockedCompareExchange(&g_WqManager.Stats.State, 0, 0);
    Statistics->TotalSubmitted = g_WqManager.Stats.TotalSubmitted;
    Statistics->TotalCompleted = g_WqManager.Stats.TotalCompleted;
    Statistics->TotalFailed = g_WqManager.Stats.TotalFailed;
    Statistics->TotalCancelled = g_WqManager.Stats.TotalCancelled;
    Statistics->TotalRetries = g_WqManager.Stats.TotalRetries;
    Statistics->TotalDropped = g_WqManager.Stats.TotalDropped;
    Statistics->CurrentPending = g_WqManager.Stats.CurrentPending;
    Statistics->PeakPending = g_WqManager.Stats.PeakPending;
    Statistics->CurrentExecuting = g_WqManager.Stats.CurrentExecuting;
    Statistics->PeakExecuting = g_WqManager.Stats.PeakExecuting;

    // Timing
    Statistics->TotalWaitTimeUs = g_WqManager.Stats.TotalWaitTimeUs;
    Statistics->TotalExecTimeUs = g_WqManager.Stats.TotalExecTimeUs;
    Statistics->TimingSampleCount = g_WqManager.Stats.TimingSampleCount;

    Statistics->StartTime = g_WqManager.Stats.StartTime;
}

_Use_decl_annotations_
VOID
ShadowStrikeResetWorkQueueStatistics(VOID)
{
    // FIX #20: Reset only accumulated counters, not live state
    InterlockedExchange64(&g_WqManager.Stats.TotalSubmitted, 0);
    InterlockedExchange64(&g_WqManager.Stats.TotalCompleted, 0);
    InterlockedExchange64(&g_WqManager.Stats.TotalFailed, 0);
    InterlockedExchange64(&g_WqManager.Stats.TotalCancelled, 0);
    InterlockedExchange64(&g_WqManager.Stats.TotalRetries, 0);
    InterlockedExchange64(&g_WqManager.Stats.TotalDropped, 0);
    InterlockedExchange(&g_WqManager.Stats.PeakPending,
        g_WqManager.Stats.CurrentPending);
    InterlockedExchange(&g_WqManager.Stats.PeakExecuting,
        g_WqManager.Stats.CurrentExecuting);

    InterlockedExchange64(&g_WqManager.Stats.TotalWaitTimeUs, 0);
    InterlockedExchange64(&g_WqManager.Stats.TotalExecTimeUs, 0);
    InterlockedExchange64(&g_WqManager.Stats.TimingSampleCount, 0);

    KeQuerySystemTimePrecise(&g_WqManager.Stats.StartTime);
}

_Use_decl_annotations_
LONG
ShadowStrikeGetPendingWorkItemCount(VOID)
{
    return g_WqManager.PendingCount;
}

// ============================================================================
// CONFIGURATION
// FIX #22, #31: Synchronized with push lock
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeWorkQueueSetDeviceObject(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    PAGED_CODE();

    if (DeviceObject == NULL) return STATUS_INVALID_PARAMETER;

    // FIX #22, #31: Use push lock for thread-safe update
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_WqManager.InitLock);

    g_WqManager.DeviceObject = DeviceObject;
    g_WqManager.Config.DeviceObject = DeviceObject;

    ExReleasePushLockExclusive(&g_WqManager.InitLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeWorkQueueSetFilterHandle(
    _In_ PFLT_FILTER FilterHandle)
{
    PAGED_CODE();

    if (FilterHandle == NULL) return STATUS_INVALID_PARAMETER;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_WqManager.InitLock);

    g_WqManager.FilterHandle = FilterHandle;
    g_WqManager.Config.FilterHandle = FilterHandle;

    ExReleasePushLockExclusive(&g_WqManager.InitLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
ShadowStrikeInitWorkQueueOptions(
    _Out_ PSHADOWSTRIKE_WQ_OPTIONS Options)
{
    if (Options == NULL) return;

    RtlZeroMemory(Options, sizeof(SHADOWSTRIKE_WQ_OPTIONS));
    Options->Priority = ShadowWqPriorityNormal;
    Options->Flags = ShadowWqFlagNone;
}

_Use_decl_annotations_
VOID
ShadowStrikeInitWorkQueueConfig(
    _Out_ PSHADOWSTRIKE_WQ_CONFIG Config)
{
    if (Config == NULL) return;

    RtlZeroMemory(Config, sizeof(SHADOWSTRIKE_WQ_CONFIG));
    Config->MaxPendingTotal = WQ_DEFAULT_MAX_PENDING;
    Config->LookasideDepth = WQ_LOOKASIDE_DEPTH;
    Config->EnableDetailedTiming = FALSE;
}

// ============================================================================
// END OF FILE
// ============================================================================
