/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE KERNEL WORK QUEUE IMPLEMENTATION
 * ============================================================================
 *
 * @file WorkQueue.c
 * @brief Implementation of enterprise-grade kernel work queue.
 *
 * This implementation provides:
 * - Thread-safe work item management with lock-free operations where possible
 * - Priority-based scheduling with per-priority queues
 * - IoWorkItem integration for safe driver unload
 * - FltQueueGenericWorkItem for filter manager operations
 * - Rundown protection for clean shutdown
 * - Comprehensive statistics and timing
 * - Lookaside list for efficient work item allocation
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "WorkQueue.h"
#include "../Utilities/MemoryUtils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, ShadowStrikeWorkQueueInitialize)
#pragma alloc_text(INIT, ShadowStrikeWorkQueueInitializeEx)
#pragma alloc_text(PAGE, ShadowStrikeWorkQueueShutdown)
#pragma alloc_text(PAGE, ShadowStrikeWorkQueueDrain)
#pragma alloc_text(PAGE, ShadowStrikeWaitForWorkItem)
#pragma alloc_text(PAGE, ShadowStrikeWorkQueueSetDeviceObject)
#pragma alloc_text(PAGE, ShadowStrikeWorkQueueSetFilterHandle)
#endif

// ============================================================================
// GLOBAL STATE
// ============================================================================

/**
 * @brief Global work queue manager (Meyers' singleton)
 */
static SHADOWSTRIKE_WQ_MANAGER g_WqManager = { 0 };

// ============================================================================
// INTERNAL FUNCTION PROTOTYPES
// ============================================================================

static
PSHADOWSTRIKE_WORK_ITEM
WqiAllocateWorkItem(
    VOID
    );

static
VOID
WqiFreeWorkItem(
    _In_ PSHADOWSTRIKE_WORK_ITEM Item
    );

static
VOID
WqiReferenceWorkItem(
    _Inout_ PSHADOWSTRIKE_WORK_ITEM Item
    );

static
VOID
WqiDereferenceWorkItem(
    _Inout_ PSHADOWSTRIKE_WORK_ITEM Item
    );

static
NTSTATUS
WqiEnqueueItem(
    _In_ PSHADOWSTRIKE_WORK_ITEM Item
    );

static
VOID
WqiExecuteWorkItem(
    _In_ PSHADOWSTRIKE_WORK_ITEM Item
    );

static
VOID
WqiCompleteWorkItem(
    _In_ PSHADOWSTRIKE_WORK_ITEM Item,
    _In_ NTSTATUS Status
    );

static
IO_WORKITEM_ROUTINE WqiIoWorkItemCallback;

static
VOID
WqiFltWorkItemCallback(
    _In_ PFLT_GENERIC_WORKITEM FltWorkItem,
    _In_ PVOID FltObject,
    _In_opt_ PVOID Context
    );

static
KDEFERRED_ROUTINE WqiDelayTimerDpcCallback;

static
VOID
WqiUpdateStatisticsOnSubmit(
    _In_ SHADOWSTRIKE_WQ_PRIORITY Priority
    );

static
VOID
WqiUpdateStatisticsOnComplete(
    _In_ PSHADOWSTRIKE_WORK_ITEM Item,
    _In_ BOOLEAN Success
    );

static
PSHADOWSTRIKE_WORK_ITEM
WqiFindWorkItemById(
    _In_ ULONG64 ItemId
    );

// ============================================================================
// SUBSYSTEM INITIALIZATION
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeWorkQueueInitialize(
    VOID
    )
{
    SHADOWSTRIKE_WQ_CONFIG DefaultConfig;

    PAGED_CODE();

    ShadowStrikeInitWorkQueueConfig(&DefaultConfig);
    return ShadowStrikeWorkQueueInitializeEx(&DefaultConfig);
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeWorkQueueInitializeEx(
    _In_ PSHADOWSTRIKE_WQ_CONFIG Config
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG i;

    PAGED_CODE();

    if (Config == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Thread-safe initialization with push lock
    //
    ExAcquirePushLockExclusive(&g_WqManager.InitLock);

    //
    // Check if already initialized (reference counting)
    //
    if (InterlockedIncrement(&g_WqManager.InitCount) > 1) {
        ExReleasePushLockExclusive(&g_WqManager.InitLock);
        return STATUS_SUCCESS;
    }

    //
    // Set state to initializing
    //
    g_WqManager.State = ShadowWqStateInitializing;

    //
    // Copy configuration
    //
    RtlCopyMemory(&g_WqManager.Config, Config, sizeof(SHADOWSTRIKE_WQ_CONFIG));

    //
    // Validate and apply defaults
    //
    if (g_WqManager.Config.MaxPendingTotal == 0) {
        g_WqManager.Config.MaxPendingTotal = WQ_DEFAULT_MAX_PENDING;
    }
    if (g_WqManager.Config.MaxPendingTotal < WQ_MIN_MAX_PENDING) {
        g_WqManager.Config.MaxPendingTotal = WQ_MIN_MAX_PENDING;
    }
    if (g_WqManager.Config.MaxPendingTotal > WQ_MAX_MAX_PENDING) {
        g_WqManager.Config.MaxPendingTotal = WQ_MAX_MAX_PENDING;
    }

    if (g_WqManager.Config.MaxPendingPerPriority == 0) {
        g_WqManager.Config.MaxPendingPerPriority =
            g_WqManager.Config.MaxPendingTotal / ShadowWqPriorityCount;
    }

    if (g_WqManager.Config.LookasideDepth == 0) {
        g_WqManager.Config.LookasideDepth = WQ_LOOKASIDE_DEPTH;
    }

    //
    // Store device/filter handles
    //
    g_WqManager.DeviceObject = Config->DeviceObject;
    g_WqManager.FilterHandle = Config->FilterHandle;

    //
    // Initialize priority queues
    //
    for (i = 0; i < ShadowWqPriorityCount; i++) {
        InitializeListHead(&g_WqManager.Queues[i].Head);
        KeInitializeSpinLock(&g_WqManager.Queues[i].Lock);
        g_WqManager.Queues[i].Count = 0;
        g_WqManager.Queues[i].PeakCount = 0;
        g_WqManager.Queues[i].MaxItems = g_WqManager.Config.MaxPendingPerPriority;
        g_WqManager.Queues[i].TotalEnqueued = 0;
        g_WqManager.Queues[i].TotalDequeued = 0;
        g_WqManager.Queues[i].TotalDropped = 0;
    }

    //
    // Initialize free list (lock-free SLIST)
    //
    InitializeSListHead(&g_WqManager.FreeList);
    g_WqManager.FreeCount = 0;

    //
    // Initialize active list
    //
    InitializeListHead(&g_WqManager.ActiveList);
    KeInitializeSpinLock(&g_WqManager.ActiveListLock);
    g_WqManager.ActiveCount = 0;

    //
    // Initialize work item ID generator
    //
    g_WqManager.NextItemId = 1;

    //
    // Initialize lookaside list for work items
    //
    ExInitializeNPagedLookasideList(
        &g_WqManager.WorkItemLookaside,
        NULL,   // Allocate function
        NULL,   // Free function
        0,      // Flags
        sizeof(SHADOWSTRIKE_WORK_ITEM),
        SHADOW_WQ_ITEM_TAG,
        g_WqManager.Config.LookasideDepth
    );
    g_WqManager.LookasideInitialized = TRUE;

    //
    // Initialize rundown protection
    //
    ExInitializeRundownProtection(&g_WqManager.RundownProtection);

    //
    // Initialize events
    //
    KeInitializeEvent(&g_WqManager.ShutdownEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&g_WqManager.DrainCompleteEvent, NotificationEvent, FALSE);

    //
    // Initialize serialization support
    //
    InitializeListHead(&g_WqManager.Serialization.ActiveKeys);
    KeInitializeSpinLock(&g_WqManager.Serialization.Lock);

    //
    // Initialize statistics
    //
    RtlZeroMemory(&g_WqManager.Stats, sizeof(g_WqManager.Stats));
    KeQuerySystemTimePrecise(&g_WqManager.Stats.StartTime);

    //
    // Initialize timing
    //
    g_WqManager.Timing.TotalWaitTime = 0;
    g_WqManager.Timing.TotalExecTime = 0;
    g_WqManager.Timing.SampleCount = 0;

    //
    // Set state to running
    //
    g_WqManager.State = ShadowWqStateRunning;
    g_WqManager.Stats.State = ShadowWqStateRunning;

    ExReleasePushLockExclusive(&g_WqManager.InitLock);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
ShadowStrikeWorkQueueShutdown(
    _In_ BOOLEAN WaitForCompletion
    )
{
    LARGE_INTEGER Timeout;
    ULONG i;

    PAGED_CODE();

    ExAcquirePushLockExclusive(&g_WqManager.InitLock);

    //
    // Reference counting - only cleanup when last reference released
    //
    if (InterlockedDecrement(&g_WqManager.InitCount) > 0) {
        ExReleasePushLockExclusive(&g_WqManager.InitLock);
        return;
    }

    //
    // Set state to shutting down
    //
    g_WqManager.State = ShadowWqStateShutdown;
    g_WqManager.Stats.State = ShadowWqStateShutdown;

    //
    // Signal shutdown event
    //
    KeSetEvent(&g_WqManager.ShutdownEvent, IO_NO_INCREMENT, FALSE);

    //
    // Wait for rundown protection to complete
    //
    ExWaitForRundownProtectionRelease(&g_WqManager.RundownProtection);

    //
    // If waiting for completion, wait for pending items
    //
    if (WaitForCompletion) {
        if (g_WqManager.ActiveCount > 0 ||
            g_WqManager.Stats.CurrentPending > 0) {

            Timeout.QuadPart = -((LONGLONG)WQ_SHUTDOWN_TIMEOUT_MS * 10000);
            KeWaitForSingleObject(
                &g_WqManager.DrainCompleteEvent,
                Executive,
                KernelMode,
                FALSE,
                &Timeout
            );
        }
    }

    //
    // Flush all queues
    //
    ShadowStrikeWorkQueueFlush();

    //
    // Cleanup lookaside list
    //
    if (g_WqManager.LookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_WqManager.WorkItemLookaside);
        g_WqManager.LookasideInitialized = FALSE;
    }

    //
    // Free any remaining items in free list
    //
    while (TRUE) {
        PSLIST_ENTRY Entry = InterlockedPopEntrySList(&g_WqManager.FreeList);
        if (Entry == NULL) {
            break;
        }
        // Items in free list are already freed via lookaside
    }

    g_WqManager.State = ShadowWqStateUninitialized;

    ExReleasePushLockExclusive(&g_WqManager.InitLock);
}

_Use_decl_annotations_
BOOLEAN
ShadowStrikeWorkQueueIsInitialized(
    VOID
    )
{
    return (g_WqManager.State == ShadowWqStateRunning ||
            g_WqManager.State == ShadowWqStatePaused);
}

_Use_decl_annotations_
SHADOWSTRIKE_WQ_STATE
ShadowStrikeWorkQueueGetState(
    VOID
    )
{
    return g_WqManager.State;
}

// ============================================================================
// INTERNAL WORK ITEM MANAGEMENT
// ============================================================================

/**
 * @brief Allocate a work item from lookaside list
 */
static
PSHADOWSTRIKE_WORK_ITEM
WqiAllocateWorkItem(
    VOID
    )
{
    PSHADOWSTRIKE_WORK_ITEM Item;

    //
    // Try to get from free list first
    //
    PSLIST_ENTRY Entry = InterlockedPopEntrySList(&g_WqManager.FreeList);
    if (Entry != NULL) {
        Item = CONTAINING_RECORD(Entry, SHADOWSTRIKE_WORK_ITEM, FreeListEntry);
        InterlockedDecrement(&g_WqManager.FreeCount);
        RtlZeroMemory(Item, sizeof(SHADOWSTRIKE_WORK_ITEM));
    } else {
        //
        // Allocate from lookaside
        //
        Item = (PSHADOWSTRIKE_WORK_ITEM)ExAllocateFromNPagedLookasideList(
            &g_WqManager.WorkItemLookaside
        );

        if (Item == NULL) {
            return NULL;
        }

        RtlZeroMemory(Item, sizeof(SHADOWSTRIKE_WORK_ITEM));
    }

    //
    // Initialize common fields
    //
    Item->ItemId = InterlockedIncrement64(&g_WqManager.NextItemId);
    Item->RefCount = 1;
    Item->State = ShadowWqItemStateAllocated;
    Item->Manager = &g_WqManager;
    InitializeListHead(&Item->ListEntry);

    return Item;
}

/**
 * @brief Free a work item back to lookaside list
 */
static
VOID
WqiFreeWorkItem(
    _In_ PSHADOWSTRIKE_WORK_ITEM Item
    )
{
    if (Item == NULL) {
        return;
    }

    //
    // Cleanup context if we own it
    //
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

    //
    // Free IoWorkItem if allocated
    //
    if (Item->IoWorkItem != NULL) {
        IoFreeWorkItem(Item->IoWorkItem);
        Item->IoWorkItem = NULL;
    }

    //
    // Free FltWorkItem if allocated
    //
    if (Item->FltWorkItem != NULL) {
        FltFreeGenericWorkItem(Item->FltWorkItem);
        Item->FltWorkItem = NULL;
    }

    //
    // Mark as free
    //
    Item->State = ShadowWqItemStateFree;

    //
    // Return to free list if not too many
    //
    if (g_WqManager.FreeCount < (LONG)g_WqManager.Config.LookasideDepth) {
        InterlockedPushEntrySList(
            &g_WqManager.FreeList,
            &Item->FreeListEntry
        );
        InterlockedIncrement(&g_WqManager.FreeCount);
    } else {
        //
        // Return to lookaside
        //
        ExFreeToNPagedLookasideList(&g_WqManager.WorkItemLookaside, Item);
    }
}

/**
 * @brief Reference a work item
 */
static
VOID
WqiReferenceWorkItem(
    _Inout_ PSHADOWSTRIKE_WORK_ITEM Item
    )
{
    InterlockedIncrement(&Item->RefCount);
}

/**
 * @brief Dereference a work item, freeing if count reaches zero
 */
static
VOID
WqiDereferenceWorkItem(
    _Inout_ PSHADOWSTRIKE_WORK_ITEM Item
    )
{
    if (InterlockedDecrement(&Item->RefCount) == 0) {
        WqiFreeWorkItem(Item);
    }
}

/**
 * @brief Enqueue a work item to appropriate priority queue
 */
static
NTSTATUS
WqiEnqueueItem(
    _In_ PSHADOWSTRIKE_WORK_ITEM Item
    )
{
    KIRQL OldIrql;
    PSHADOWSTRIKE_WQ_PRIORITY_QUEUE Queue;
    LONG Current;
    LONG Peak;

    if (!ShadowStrikeIsValidWqPriority(Item->Priority)) {
        return STATUS_INVALID_PARAMETER;
    }

    Queue = &g_WqManager.Queues[Item->Priority];

    //
    // Check queue capacity
    //
    if (Queue->Count >= (LONG)Queue->MaxItems) {
        InterlockedIncrement64(&Queue->TotalDropped);
        InterlockedIncrement64(&g_WqManager.Stats.TotalDropped);
        InterlockedIncrement64(&g_WqManager.Stats.QueueFullEvents);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Add to queue
    //
    KeAcquireSpinLock(&Queue->Lock, &OldIrql);

    //
    // Double-check capacity under lock
    //
    if (Queue->Count >= (LONG)Queue->MaxItems) {
        KeReleaseSpinLock(&Queue->Lock, OldIrql);
        InterlockedIncrement64(&Queue->TotalDropped);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Insert based on importance
    //
    if (Item->Flags & ShadowWqFlagHighImportance) {
        InsertHeadList(&Queue->Head, &Item->ListEntry);
    } else {
        InsertTailList(&Queue->Head, &Item->ListEntry);
    }

    Current = InterlockedIncrement(&Queue->Count);
    InterlockedIncrement64(&Queue->TotalEnqueued);

    KeReleaseSpinLock(&Queue->Lock, OldIrql);

    //
    // Update peak
    //
    do {
        Peak = Queue->PeakCount;
        if (Current <= Peak) {
            break;
        }
    } while (InterlockedCompareExchange(&Queue->PeakCount, Current, Peak) != Peak);

    //
    // Update state
    //
    Item->State = ShadowWqItemStateQueued;
    KeQuerySystemTimePrecise(&Item->SubmitTime);

    return STATUS_SUCCESS;
}

/**
 * @brief Execute a work item
 */
static
VOID
WqiExecuteWorkItem(
    _In_ PSHADOWSTRIKE_WORK_ITEM Item
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    LARGE_INTEGER StartTime;
    LARGE_INTEGER EndTime;

    //
    // Check for cancellation
    //
    if (Item->CancelRequested) {
        WqiCompleteWorkItem(Item, STATUS_CANCELLED);
        return;
    }

    //
    // Update state
    //
    Item->State = ShadowWqItemStateRunning;
    KeQuerySystemTimePrecise(&StartTime);
    Item->StartTime = StartTime;

    //
    // Update statistics
    //
    InterlockedIncrement(&g_WqManager.Stats.CurrentExecuting);

    //
    // Execute the work routine
    //
    __try {
        if (Item->Routine != NULL) {
            Status = Item->Routine(Item->Context, Item->ContextSize);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    //
    // Record end time
    //
    KeQuerySystemTimePrecise(&EndTime);
    Item->EndTime = EndTime;

    //
    // Update timing statistics
    //
    if (g_WqManager.Config.EnableDetailedTiming) {
        LONG64 ExecTime = (EndTime.QuadPart - StartTime.QuadPart) / 10; // microseconds
        LONG64 WaitTime = (StartTime.QuadPart - Item->SubmitTime.QuadPart) / 10;

        InterlockedAdd64(&g_WqManager.Timing.TotalExecTime, ExecTime);
        InterlockedAdd64(&g_WqManager.Timing.TotalWaitTime, WaitTime);
        InterlockedIncrement64(&g_WqManager.Timing.SampleCount);
    }

    InterlockedDecrement(&g_WqManager.Stats.CurrentExecuting);

    //
    // Handle retry on failure
    //
    if (!NT_SUCCESS(Status) &&
        (Item->Flags & ShadowWqFlagRetryOnFailure) &&
        Item->RetryCount < Item->Options.MaxRetries) {

        Item->RetryCount++;
        InterlockedIncrement64(&g_WqManager.Stats.TotalRetries);

        //
        // Re-queue with delay if specified
        //
        if (Item->Options.RetryDelayMs > 0) {
            // Queue delayed retry
            LARGE_INTEGER DueTime;
            DueTime.QuadPart = -((LONGLONG)Item->Options.RetryDelayMs * 10000);
            KeSetTimer(&Item->DelayTimer, DueTime, &Item->DelayDpc);
        } else {
            // Immediate retry
            WqiEnqueueItem(Item);
        }
        return;
    }

    //
    // Complete the work item
    //
    WqiCompleteWorkItem(Item, Status);
}

/**
 * @brief Complete a work item
 */
static
VOID
WqiCompleteWorkItem(
    _In_ PSHADOWSTRIKE_WORK_ITEM Item,
    _In_ NTSTATUS Status
    )
{
    KIRQL OldIrql;
    BOOLEAN Success = NT_SUCCESS(Status);

    //
    // Record completion status
    //
    Item->CompletionStatus = Status;
    KeQuerySystemTimePrecise(&Item->EndTime);

    //
    // Set final state
    //
    if (Status == STATUS_CANCELLED) {
        Item->State = ShadowWqItemStateCancelled;
    } else if (Success) {
        Item->State = ShadowWqItemStateCompleted;
    } else {
        Item->State = ShadowWqItemStateFailed;
    }

    //
    // Call completion callback
    //
    if (Item->Options.CompletionCallback != NULL) {
        Item->Options.CompletionCallback(
            Status,
            Item->Context,
            Item->Options.CompletionContext
        );
    }

    //
    // Signal completion event
    //
    if ((Item->Flags & ShadowWqFlagSignalCompletion) &&
        Item->Options.CompletionEvent != NULL) {
        KeSetEvent(Item->Options.CompletionEvent, IO_NO_INCREMENT, FALSE);
    }

    //
    // Call cleanup callback
    //
    if (Item->Options.CleanupCallback != NULL) {
        Item->Options.CleanupCallback(Item->Context, Item->ContextSize);
    }

    //
    // Update statistics
    //
    WqiUpdateStatisticsOnComplete(Item, Success);

    //
    // Remove from active list
    //
    KeAcquireSpinLock(&g_WqManager.ActiveListLock, &OldIrql);
    if (!IsListEmpty(&Item->ListEntry)) {
        RemoveEntryList(&Item->ListEntry);
        InitializeListHead(&Item->ListEntry);
        InterlockedDecrement(&g_WqManager.ActiveCount);
    }
    KeReleaseSpinLock(&g_WqManager.ActiveListLock, OldIrql);

    //
    // Check if we should signal drain complete
    //
    if (g_WqManager.State == ShadowWqStateDraining) {
        if (g_WqManager.ActiveCount == 0 &&
            g_WqManager.Stats.CurrentPending == 0) {
            KeSetEvent(&g_WqManager.DrainCompleteEvent, IO_NO_INCREMENT, FALSE);
        }
    }

    //
    // Release rundown protection
    //
    ExReleaseRundownProtection(&g_WqManager.RundownProtection);

    //
    // Dereference work item (may free it)
    //
    WqiDereferenceWorkItem(Item);
}

// ============================================================================
// SYSTEM WORK ITEM CALLBACKS
// ============================================================================

/**
 * @brief IoWorkItem callback routine
 */
static
VOID
WqiIoWorkItemCallback(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    )
{
    PSHADOWSTRIKE_WORK_ITEM Item = (PSHADOWSTRIKE_WORK_ITEM)Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Item == NULL) {
        return;
    }

    WqiExecuteWorkItem(Item);
}

/**
 * @brief FltGenericWorkItem callback routine
 */
static
VOID
WqiFltWorkItemCallback(
    _In_ PFLT_GENERIC_WORKITEM FltWorkItem,
    _In_ PVOID FltObject,
    _In_opt_ PVOID Context
    )
{
    PSHADOWSTRIKE_WORK_ITEM Item = (PSHADOWSTRIKE_WORK_ITEM)Context;

    UNREFERENCED_PARAMETER(FltWorkItem);
    UNREFERENCED_PARAMETER(FltObject);

    if (Item == NULL) {
        return;
    }

    WqiExecuteWorkItem(Item);
}

/**
 * @brief Delay timer DPC callback
 */
static
VOID
WqiDelayTimerDpcCallback(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PSHADOWSTRIKE_WORK_ITEM Item = (PSHADOWSTRIKE_WORK_ITEM)DeferredContext;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (Item == NULL) {
        return;
    }

    //
    // Now queue the actual work item for execution
    //
    if (g_WqManager.DeviceObject != NULL && Item->IoWorkItem != NULL) {
        IoQueueWorkItem(
            Item->IoWorkItem,
            WqiIoWorkItemCallback,
            ShadowStrikeWqPriorityToWorkQueueType(Item->Priority),
            Item
        );
    } else {
        //
        // Fallback: execute directly (not recommended)
        //
        WqiExecuteWorkItem(Item);
    }
}

// ============================================================================
// STATISTICS HELPERS
// ============================================================================

/**
 * @brief Update statistics when submitting
 */
static
VOID
WqiUpdateStatisticsOnSubmit(
    _In_ SHADOWSTRIKE_WQ_PRIORITY Priority
    )
{
    LONG Current;
    LONG Peak;

    InterlockedIncrement64(&g_WqManager.Stats.TotalSubmitted);
    Current = InterlockedIncrement(&g_WqManager.Stats.CurrentPending);

    //
    // Update peak
    //
    do {
        Peak = g_WqManager.Stats.PeakPending;
        if (Current <= Peak) {
            break;
        }
    } while (InterlockedCompareExchange(
        &g_WqManager.Stats.PeakPending, Current, Peak) != Peak);

    //
    // Per-priority stats
    //
    if (ShadowStrikeIsValidWqPriority(Priority)) {
        g_WqManager.Stats.PerPriority[Priority].Submitted++;
        g_WqManager.Stats.PerPriority[Priority].Pending++;
    }
}

/**
 * @brief Update statistics when completing
 */
static
VOID
WqiUpdateStatisticsOnComplete(
    _In_ PSHADOWSTRIKE_WORK_ITEM Item,
    _In_ BOOLEAN Success
    )
{
    InterlockedDecrement(&g_WqManager.Stats.CurrentPending);

    if (Item->State == ShadowWqItemStateCancelled) {
        InterlockedIncrement64(&g_WqManager.Stats.TotalCancelled);
    } else if (Success) {
        InterlockedIncrement64(&g_WqManager.Stats.TotalCompleted);
    } else {
        InterlockedIncrement64(&g_WqManager.Stats.TotalFailed);
    }

    //
    // Per-priority stats
    //
    if (ShadowStrikeIsValidWqPriority(Item->Priority)) {
        g_WqManager.Stats.PerPriority[Item->Priority].Completed++;
        if (g_WqManager.Stats.PerPriority[Item->Priority].Pending > 0) {
            g_WqManager.Stats.PerPriority[Item->Priority].Pending--;
        }
    }
}

/**
 * @brief Find work item by ID
 */
static
PSHADOWSTRIKE_WORK_ITEM
WqiFindWorkItemById(
    _In_ ULONG64 ItemId
    )
{
    KIRQL OldIrql;
    PLIST_ENTRY Entry;
    PSHADOWSTRIKE_WORK_ITEM Item;
    PSHADOWSTRIKE_WORK_ITEM Found = NULL;

    KeAcquireSpinLock(&g_WqManager.ActiveListLock, &OldIrql);

    for (Entry = g_WqManager.ActiveList.Flink;
         Entry != &g_WqManager.ActiveList;
         Entry = Entry->Flink) {

        Item = CONTAINING_RECORD(Entry, SHADOWSTRIKE_WORK_ITEM, ListEntry);
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
// WORK ITEM SUBMISSION - SIMPLE API
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeQueueWorkItem(
    _In_ PFN_SHADOWSTRIKE_WORK_ROUTINE_LEGACY Routine,
    _In_opt_ PVOID Context
    )
{
    return ShadowStrikeQueueWorkItemWithPriority(
        Routine,
        Context,
        ShadowWqPriorityNormal
    );
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeQueueWorkItemWithPriority(
    _In_ PFN_SHADOWSTRIKE_WORK_ROUTINE_LEGACY Routine,
    _In_opt_ PVOID Context,
    _In_ SHADOWSTRIKE_WQ_PRIORITY Priority
    )
{
    NTSTATUS Status;
    PSHADOWSTRIKE_WORK_ITEM Item;
    KIRQL OldIrql;

    //
    // Validate state
    //
    if (g_WqManager.State != ShadowWqStateRunning) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Acquire rundown protection
    //
    if (!ExAcquireRundownProtection(&g_WqManager.RundownProtection)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Validate parameters
    //
    if (Routine == NULL) {
        ExReleaseRundownProtection(&g_WqManager.RundownProtection);
        return STATUS_INVALID_PARAMETER;
    }

    if (!ShadowStrikeIsValidWqPriority(Priority)) {
        Priority = ShadowWqPriorityNormal;
    }

    //
    // Allocate work item
    //
    Item = WqiAllocateWorkItem();
    if (Item == NULL) {
        ExReleaseRundownProtection(&g_WqManager.RundownProtection);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Setup work item (legacy wrapper)
    //
    Item->Routine = (PFN_SHADOWSTRIKE_WORK_ROUTINE)Routine;
    Item->Context = Context;
    Item->ContextSize = 0;
    Item->Priority = Priority;
    Item->Flags = ShadowWqFlagNone;
    Item->UsingInlineContext = FALSE;

    //
    // Add to active list
    //
    KeAcquireSpinLock(&g_WqManager.ActiveListLock, &OldIrql);
    InsertTailList(&g_WqManager.ActiveList, &Item->ListEntry);
    InterlockedIncrement(&g_WqManager.ActiveCount);
    KeReleaseSpinLock(&g_WqManager.ActiveListLock, OldIrql);

    //
    // Update statistics
    //
    WqiUpdateStatisticsOnSubmit(Priority);

    //
    // Queue the work item
    //
    if (g_WqManager.DeviceObject != NULL) {
        //
        // Use IoWorkItem (preferred)
        //
        Item->IoWorkItem = IoAllocateWorkItem(g_WqManager.DeviceObject);
        if (Item->IoWorkItem == NULL) {
            WqiCompleteWorkItem(Item, STATUS_INSUFFICIENT_RESOURCES);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Item->Type = ShadowWqTypeSystem;
        Item->State = ShadowWqItemStateQueued;

        IoQueueWorkItem(
            Item->IoWorkItem,
            WqiIoWorkItemCallback,
            ShadowStrikeWqPriorityToWorkQueueType(Priority),
            Item
        );

        Status = STATUS_SUCCESS;
    } else {
        //
        // Fallback: Use filter work item if available
        //
        if (g_WqManager.FilterHandle != NULL) {
            Item->FltWorkItem = FltAllocateGenericWorkItem();
            if (Item->FltWorkItem != NULL) {
                Item->Type = ShadowWqTypeFilter;
                Item->State = ShadowWqItemStateQueued;

                Status = FltQueueGenericWorkItem(
                    Item->FltWorkItem,
                    g_WqManager.FilterHandle,
                    WqiFltWorkItemCallback,
                    (Priority >= ShadowWqPriorityHigh) ?
                        CriticalWorkQueue : DelayedWorkQueue,
                    Item
                );

                if (!NT_SUCCESS(Status)) {
                    FltFreeGenericWorkItem(Item->FltWorkItem);
                    Item->FltWorkItem = NULL;
                }
            } else {
                Status = STATUS_INSUFFICIENT_RESOURCES;
            }
        } else {
            //
            // Last resort: Execute synchronously at PASSIVE_LEVEL
            // This is NOT recommended but provides fallback
            //
            if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
                WqiExecuteWorkItem(Item);
                Status = STATUS_SUCCESS;
            } else {
                //
                // Cannot execute at elevated IRQL without proper infrastructure
                //
                WqiCompleteWorkItem(Item, STATUS_UNSUCCESSFUL);
                Status = STATUS_UNSUCCESSFUL;
            }
        }
    }

    return Status;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeQueueWorkItemWithContext(
    _In_ PFN_SHADOWSTRIKE_WORK_ROUTINE Routine,
    _In_reads_bytes_opt_(ContextSize) PVOID Context,
    _In_ ULONG ContextSize,
    _In_ SHADOWSTRIKE_WQ_PRIORITY Priority
    )
{
    SHADOWSTRIKE_WQ_OPTIONS Options;

    ShadowStrikeInitWorkQueueOptions(&Options);
    Options.Priority = Priority;
    Options.Flags = ShadowWqFlagCopyContext | ShadowWqFlagDeleteContext;

    return ShadowStrikeQueueWorkItemEx(
        Routine,
        Context,
        ContextSize,
        &Options,
        NULL
    );
}

// ============================================================================
// WORK ITEM SUBMISSION - ADVANCED API
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeQueueWorkItemEx(
    _In_ PFN_SHADOWSTRIKE_WORK_ROUTINE Routine,
    _In_reads_bytes_opt_(ContextSize) PVOID Context,
    _In_ ULONG ContextSize,
    _In_opt_ PSHADOWSTRIKE_WQ_OPTIONS Options,
    _Out_opt_ PULONG64 ItemId
    )
{
    NTSTATUS Status;
    PSHADOWSTRIKE_WORK_ITEM Item;
    SHADOWSTRIKE_WQ_OPTIONS DefaultOptions;
    KIRQL OldIrql;
    PVOID ContextCopy = NULL;

    if (ItemId != NULL) {
        *ItemId = 0;
    }

    //
    // Validate state
    //
    if (g_WqManager.State != ShadowWqStateRunning) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Acquire rundown protection
    //
    if (!ExAcquireRundownProtection(&g_WqManager.RundownProtection)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Validate parameters
    //
    if (Routine == NULL) {
        ExReleaseRundownProtection(&g_WqManager.RundownProtection);
        return STATUS_INVALID_PARAMETER;
    }

    if (ContextSize > WQ_MAX_CONTEXT_SIZE) {
        ExReleaseRundownProtection(&g_WqManager.RundownProtection);
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Use default options if not provided
    //
    if (Options == NULL) {
        ShadowStrikeInitWorkQueueOptions(&DefaultOptions);
        Options = &DefaultOptions;
    }

    //
    // Validate priority
    //
    if (!ShadowStrikeIsValidWqPriority(Options->Priority)) {
        Options->Priority = ShadowWqPriorityNormal;
    }

    //
    // Allocate work item
    //
    Item = WqiAllocateWorkItem();
    if (Item == NULL) {
        ExReleaseRundownProtection(&g_WqManager.RundownProtection);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Setup work item
    //
    Item->Routine = Routine;
    Item->Priority = Options->Priority;
    Item->Flags = Options->Flags;
    RtlCopyMemory(&Item->Options, Options, sizeof(SHADOWSTRIKE_WQ_OPTIONS));

    //
    // Handle context
    //
    if (Context != NULL && ContextSize > 0) {
        if (Options->Flags & ShadowWqFlagCopyContext) {
            //
            // Copy context
            //
            if (ContextSize <= WQ_MAX_INLINE_CONTEXT_SIZE) {
                //
                // Use inline context
                //
                RtlCopyMemory(Item->InlineContext, Context, ContextSize);
                Item->Context = Item->InlineContext;
                Item->UsingInlineContext = TRUE;
            } else {
                //
                // Allocate external context
                //
                if (Options->Flags & ShadowWqFlagNonPagedContext) {
                    ContextCopy = ShadowStrikeAllocateWithTag(
                        ContextSize,
                        SHADOW_WQ_CONTEXT_TAG
                    );
                } else {
                    ContextCopy = ShadowStrikeAllocatePagedWithTag(
                        ContextSize,
                        SHADOW_WQ_CONTEXT_TAG
                    );
                }

                if (ContextCopy == NULL) {
                    WqiFreeWorkItem(Item);
                    ExReleaseRundownProtection(&g_WqManager.RundownProtection);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                RtlCopyMemory(ContextCopy, Context, ContextSize);
                Item->Context = ContextCopy;
                Item->UsingInlineContext = FALSE;
            }
        } else {
            //
            // Reference caller's context
            //
            Item->Context = Context;
            Item->UsingInlineContext = FALSE;
        }
        Item->ContextSize = ContextSize;
    } else {
        Item->Context = Context;
        Item->ContextSize = 0;
        Item->UsingInlineContext = FALSE;
    }

    //
    // Initialize timer/DPC for delayed or retry scenarios
    //
    KeInitializeTimer(&Item->DelayTimer);
    KeInitializeDpc(&Item->DelayDpc, WqiDelayTimerDpcCallback, Item);

    //
    // Add to active list
    //
    KeAcquireSpinLock(&g_WqManager.ActiveListLock, &OldIrql);
    InsertTailList(&g_WqManager.ActiveList, &Item->ListEntry);
    InterlockedIncrement(&g_WqManager.ActiveCount);
    KeReleaseSpinLock(&g_WqManager.ActiveListLock, OldIrql);

    //
    // Update statistics
    //
    WqiUpdateStatisticsOnSubmit(Item->Priority);

    //
    // Return item ID
    //
    if (ItemId != NULL) {
        *ItemId = Item->ItemId;
    }

    //
    // Queue the work item
    //
    if (g_WqManager.DeviceObject != NULL) {
        Item->IoWorkItem = IoAllocateWorkItem(g_WqManager.DeviceObject);
        if (Item->IoWorkItem == NULL) {
            WqiCompleteWorkItem(Item, STATUS_INSUFFICIENT_RESOURCES);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Item->Type = ShadowWqTypeSystem;
        Item->State = ShadowWqItemStateQueued;

        IoQueueWorkItem(
            Item->IoWorkItem,
            WqiIoWorkItemCallback,
            ShadowStrikeWqPriorityToWorkQueueType(Item->Priority),
            Item
        );

        Status = STATUS_SUCCESS;
    } else if (g_WqManager.FilterHandle != NULL) {
        Item->FltWorkItem = FltAllocateGenericWorkItem();
        if (Item->FltWorkItem != NULL) {
            Item->Type = ShadowWqTypeFilter;
            Item->State = ShadowWqItemStateQueued;

            Status = FltQueueGenericWorkItem(
                Item->FltWorkItem,
                g_WqManager.FilterHandle,
                WqiFltWorkItemCallback,
                (Item->Priority >= ShadowWqPriorityHigh) ?
                    CriticalWorkQueue : DelayedWorkQueue,
                Item
            );

            if (!NT_SUCCESS(Status)) {
                FltFreeGenericWorkItem(Item->FltWorkItem);
                Item->FltWorkItem = NULL;
                WqiCompleteWorkItem(Item, Status);
            }
        } else {
            WqiCompleteWorkItem(Item, STATUS_INSUFFICIENT_RESOURCES);
            Status = STATUS_INSUFFICIENT_RESOURCES;
        }
    } else {
        //
        // No work item infrastructure available
        //
        if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
            WqiExecuteWorkItem(Item);
            Status = STATUS_SUCCESS;
        } else {
            WqiCompleteWorkItem(Item, STATUS_UNSUCCESSFUL);
            Status = STATUS_UNSUCCESSFUL;
        }
    }

    return Status;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeQueueDelayedWorkItem(
    _In_ PFN_SHADOWSTRIKE_WORK_ROUTINE Routine,
    _In_reads_bytes_opt_(ContextSize) PVOID Context,
    _In_ ULONG ContextSize,
    _In_ ULONG DelayMs,
    _In_opt_ PSHADOWSTRIKE_WQ_OPTIONS Options,
    _Out_opt_ PULONG64 ItemId
    )
{
    NTSTATUS Status;
    PSHADOWSTRIKE_WORK_ITEM Item;
    SHADOWSTRIKE_WQ_OPTIONS DefaultOptions;
    KIRQL OldIrql;
    LARGE_INTEGER DueTime;

    if (ItemId != NULL) {
        *ItemId = 0;
    }

    //
    // Validate state
    //
    if (g_WqManager.State != ShadowWqStateRunning) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Acquire rundown protection
    //
    if (!ExAcquireRundownProtection(&g_WqManager.RundownProtection)) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (Routine == NULL) {
        ExReleaseRundownProtection(&g_WqManager.RundownProtection);
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Use default options if not provided
    //
    if (Options == NULL) {
        ShadowStrikeInitWorkQueueOptions(&DefaultOptions);
        Options = &DefaultOptions;
    }

    //
    // Allocate work item
    //
    Item = WqiAllocateWorkItem();
    if (Item == NULL) {
        ExReleaseRundownProtection(&g_WqManager.RundownProtection);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Setup work item
    //
    Item->Routine = Routine;
    Item->Context = Context;
    Item->ContextSize = ContextSize;
    Item->Priority = Options->Priority;
    Item->Flags = Options->Flags;
    Item->Type = ShadowWqTypeDelayed;
    RtlCopyMemory(&Item->Options, Options, sizeof(SHADOWSTRIKE_WQ_OPTIONS));

    //
    // Handle context copy if needed
    //
    if ((Options->Flags & ShadowWqFlagCopyContext) &&
        Context != NULL && ContextSize > 0) {

        if (ContextSize <= WQ_MAX_INLINE_CONTEXT_SIZE) {
            RtlCopyMemory(Item->InlineContext, Context, ContextSize);
            Item->Context = Item->InlineContext;
            Item->UsingInlineContext = TRUE;
        } else {
            PVOID ContextCopy = ShadowStrikeAllocateWithTag(
                ContextSize,
                SHADOW_WQ_CONTEXT_TAG
            );
            if (ContextCopy == NULL) {
                WqiFreeWorkItem(Item);
                ExReleaseRundownProtection(&g_WqManager.RundownProtection);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            RtlCopyMemory(ContextCopy, Context, ContextSize);
            Item->Context = ContextCopy;
            Item->UsingInlineContext = FALSE;
        }
    }

    //
    // Allocate IoWorkItem for when timer fires
    //
    if (g_WqManager.DeviceObject != NULL) {
        Item->IoWorkItem = IoAllocateWorkItem(g_WqManager.DeviceObject);
        if (Item->IoWorkItem == NULL) {
            WqiFreeWorkItem(Item);
            ExReleaseRundownProtection(&g_WqManager.RundownProtection);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    //
    // Initialize timer and DPC
    //
    KeInitializeTimer(&Item->DelayTimer);
    KeInitializeDpc(&Item->DelayDpc, WqiDelayTimerDpcCallback, Item);

    //
    // Add to active list
    //
    KeAcquireSpinLock(&g_WqManager.ActiveListLock, &OldIrql);
    InsertTailList(&g_WqManager.ActiveList, &Item->ListEntry);
    InterlockedIncrement(&g_WqManager.ActiveCount);
    KeReleaseSpinLock(&g_WqManager.ActiveListLock, OldIrql);

    //
    // Update statistics
    //
    WqiUpdateStatisticsOnSubmit(Item->Priority);

    //
    // Return item ID
    //
    if (ItemId != NULL) {
        *ItemId = Item->ItemId;
    }

    //
    // Set the timer
    //
    DueTime.QuadPart = -((LONGLONG)DelayMs * 10000);
    Item->State = ShadowWqItemStateQueued;
    KeQuerySystemTimePrecise(&Item->SubmitTime);

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
    _Out_opt_ PULONG64 ItemId
    )
{
    NTSTATUS Status;
    PSHADOWSTRIKE_WORK_ITEM Item;
    SHADOWSTRIKE_WQ_OPTIONS DefaultOptions;
    KIRQL OldIrql;

    if (ItemId != NULL) {
        *ItemId = 0;
    }

    if (Instance == NULL || Routine == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate state
    //
    if (g_WqManager.State != ShadowWqStateRunning) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Acquire rundown protection
    //
    if (!ExAcquireRundownProtection(&g_WqManager.RundownProtection)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Use default options if not provided
    //
    if (Options == NULL) {
        ShadowStrikeInitWorkQueueOptions(&DefaultOptions);
        Options = &DefaultOptions;
    }

    //
    // Allocate work item
    //
    Item = WqiAllocateWorkItem();
    if (Item == NULL) {
        ExReleaseRundownProtection(&g_WqManager.RundownProtection);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Allocate filter work item
    //
    Item->FltWorkItem = FltAllocateGenericWorkItem();
    if (Item->FltWorkItem == NULL) {
        WqiFreeWorkItem(Item);
        ExReleaseRundownProtection(&g_WqManager.RundownProtection);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Setup work item
    //
    Item->Routine = Routine;
    Item->Context = Context;
    Item->ContextSize = ContextSize;
    Item->Priority = Options->Priority;
    Item->Flags = Options->Flags;
    Item->Type = ShadowWqTypeFilter;
    RtlCopyMemory(&Item->Options, Options, sizeof(SHADOWSTRIKE_WQ_OPTIONS));

    //
    // Handle context copy
    //
    if ((Options->Flags & ShadowWqFlagCopyContext) &&
        Context != NULL && ContextSize > 0) {

        if (ContextSize <= WQ_MAX_INLINE_CONTEXT_SIZE) {
            RtlCopyMemory(Item->InlineContext, Context, ContextSize);
            Item->Context = Item->InlineContext;
            Item->UsingInlineContext = TRUE;
        } else {
            PVOID ContextCopy = ShadowStrikeAllocateWithTag(
                ContextSize,
                SHADOW_WQ_CONTEXT_TAG
            );
            if (ContextCopy == NULL) {
                FltFreeGenericWorkItem(Item->FltWorkItem);
                WqiFreeWorkItem(Item);
                ExReleaseRundownProtection(&g_WqManager.RundownProtection);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            RtlCopyMemory(ContextCopy, Context, ContextSize);
            Item->Context = ContextCopy;
            Item->UsingInlineContext = FALSE;
        }
    }

    //
    // Add to active list
    //
    KeAcquireSpinLock(&g_WqManager.ActiveListLock, &OldIrql);
    InsertTailList(&g_WqManager.ActiveList, &Item->ListEntry);
    InterlockedIncrement(&g_WqManager.ActiveCount);
    KeReleaseSpinLock(&g_WqManager.ActiveListLock, OldIrql);

    //
    // Update statistics
    //
    WqiUpdateStatisticsOnSubmit(Item->Priority);

    //
    // Return item ID
    //
    if (ItemId != NULL) {
        *ItemId = Item->ItemId;
    }

    //
    // Queue via filter manager
    //
    Item->State = ShadowWqItemStateQueued;
    KeQuerySystemTimePrecise(&Item->SubmitTime);

    Status = FltQueueGenericWorkItem(
        Item->FltWorkItem,
        Instance,
        WqiFltWorkItemCallback,
        (Item->Priority >= ShadowWqPriorityHigh) ?
            CriticalWorkQueue : DelayedWorkQueue,
        Item
    );

    if (!NT_SUCCESS(Status)) {
        WqiCompleteWorkItem(Item, Status);
    }

    return Status;
}

// ============================================================================
// WORK ITEM MANAGEMENT
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeCancelWorkItem(
    _In_ ULONG64 ItemId
    )
{
    PSHADOWSTRIKE_WORK_ITEM Item;
    SHADOWSTRIKE_WQ_ITEM_STATE OldState;

    Item = WqiFindWorkItemById(ItemId);
    if (Item == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Try to cancel
    //
    OldState = (SHADOWSTRIKE_WQ_ITEM_STATE)InterlockedCompareExchange(
        (PLONG)&Item->State,
        ShadowWqItemStateCancelled,
        ShadowWqItemStateQueued
    );

    if (OldState == ShadowWqItemStateQueued) {
        //
        // Successfully cancelled before execution
        //
        Item->CancelRequested = TRUE;

        //
        // Cancel timer if delayed
        //
        if (Item->Type == ShadowWqTypeDelayed) {
            KeCancelTimer(&Item->DelayTimer);
        }

        //
        // Call cancel callback
        //
        if (Item->Options.CancelCallback != NULL) {
            Item->Options.CancelCallback(Item->Context, Item->ContextSize);
        }

        WqiCompleteWorkItem(Item, STATUS_CANCELLED);
        WqiDereferenceWorkItem(Item);
        return STATUS_SUCCESS;
    }

    if (OldState == ShadowWqItemStateRunning) {
        //
        // Already executing - request cancellation
        //
        Item->CancelRequested = TRUE;
        WqiDereferenceWorkItem(Item);
        return STATUS_UNSUCCESSFUL;
    }

    //
    // Already completed or in other state
    //
    WqiDereferenceWorkItem(Item);
    return STATUS_UNSUCCESSFUL;
}

_Use_decl_annotations_
ULONG
ShadowStrikeCancelWorkItemsByKey(
    _In_ ULONG64 SerializationKey
    )
{
    KIRQL OldIrql;
    PLIST_ENTRY Entry;
    PSHADOWSTRIKE_WORK_ITEM Item;
    ULONG CancelledCount = 0;
    LIST_ENTRY ToCancelList;

    InitializeListHead(&ToCancelList);

    //
    // Find all items with matching key
    //
    KeAcquireSpinLock(&g_WqManager.ActiveListLock, &OldIrql);

    for (Entry = g_WqManager.ActiveList.Flink;
         Entry != &g_WqManager.ActiveList;
         Entry = Entry->Flink) {

        Item = CONTAINING_RECORD(Entry, SHADOWSTRIKE_WORK_ITEM, ListEntry);

        if (Item->Options.SerializationKey == SerializationKey &&
            Item->State == ShadowWqItemStateQueued) {

            Item->CancelRequested = TRUE;
            CancelledCount++;
        }
    }

    KeReleaseSpinLock(&g_WqManager.ActiveListLock, OldIrql);

    return CancelledCount;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeWaitForWorkItem(
    _In_ ULONG64 ItemId,
    _In_ ULONG TimeoutMs,
    _Out_opt_ PNTSTATUS Status
    )
{
    PSHADOWSTRIKE_WORK_ITEM Item;
    LARGE_INTEGER Timeout;
    NTSTATUS WaitStatus;
    KEVENT CompletionEvent;

    PAGED_CODE();

    if (Status != NULL) {
        *Status = STATUS_UNSUCCESSFUL;
    }

    Item = WqiFindWorkItemById(ItemId);
    if (Item == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Check if already complete
    //
    if (Item->State == ShadowWqItemStateCompleted ||
        Item->State == ShadowWqItemStateCancelled ||
        Item->State == ShadowWqItemStateFailed) {

        if (Status != NULL) {
            *Status = Item->CompletionStatus;
        }
        WqiDereferenceWorkItem(Item);
        return STATUS_SUCCESS;
    }

    //
    // Need to wait - check if completion event is set
    //
    if (Item->Options.CompletionEvent != NULL) {
        Timeout.QuadPart = (TimeoutMs == 0) ?
            MAXLONGLONG : -((LONGLONG)TimeoutMs * 10000);

        WaitStatus = KeWaitForSingleObject(
            Item->Options.CompletionEvent,
            Executive,
            KernelMode,
            FALSE,
            (TimeoutMs == 0) ? NULL : &Timeout
        );

        if (WaitStatus == STATUS_SUCCESS) {
            if (Status != NULL) {
                *Status = Item->CompletionStatus;
            }
            WqiDereferenceWorkItem(Item);
            return STATUS_SUCCESS;
        }

        WqiDereferenceWorkItem(Item);
        return STATUS_TIMEOUT;
    }

    //
    // No completion event - poll with sleep
    //
    Timeout.QuadPart = -10000; // 1ms
    ULONG Elapsed = 0;

    while (Item->State != ShadowWqItemStateCompleted &&
           Item->State != ShadowWqItemStateCancelled &&
           Item->State != ShadowWqItemStateFailed) {

        if (TimeoutMs > 0 && Elapsed >= TimeoutMs) {
            WqiDereferenceWorkItem(Item);
            return STATUS_TIMEOUT;
        }

        KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
        Elapsed++;
    }

    if (Status != NULL) {
        *Status = Item->CompletionStatus;
    }

    WqiDereferenceWorkItem(Item);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeGetWorkItemState(
    _In_ ULONG64 ItemId,
    _Out_ PSHADOWSTRIKE_WQ_ITEM_STATE State
    )
{
    PSHADOWSTRIKE_WORK_ITEM Item;

    if (State == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *State = ShadowWqItemStateFree;

    Item = WqiFindWorkItemById(ItemId);
    if (Item == NULL) {
        return STATUS_NOT_FOUND;
    }

    *State = Item->State;
    WqiDereferenceWorkItem(Item);

    return STATUS_SUCCESS;
}

// ============================================================================
// QUEUE CONTROL
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeWorkQueuePause(
    VOID
    )
{
    if (g_WqManager.State != ShadowWqStateRunning) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    g_WqManager.State = ShadowWqStatePaused;
    g_WqManager.Stats.State = ShadowWqStatePaused;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeWorkQueueResume(
    VOID
    )
{
    if (g_WqManager.State != ShadowWqStatePaused) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    g_WqManager.State = ShadowWqStateRunning;
    g_WqManager.Stats.State = ShadowWqStateRunning;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeWorkQueueDrain(
    _In_ ULONG TimeoutMs
    )
{
    LARGE_INTEGER Timeout;
    NTSTATUS Status;

    PAGED_CODE();

    //
    // Set draining state
    //
    g_WqManager.State = ShadowWqStateDraining;
    g_WqManager.Stats.State = ShadowWqStateDraining;

    //
    // Reset drain complete event
    //
    KeClearEvent(&g_WqManager.DrainCompleteEvent);

    //
    // Check if already drained
    //
    if (g_WqManager.ActiveCount == 0 &&
        g_WqManager.Stats.CurrentPending == 0) {

        g_WqManager.State = ShadowWqStateRunning;
        g_WqManager.Stats.State = ShadowWqStateRunning;
        return STATUS_SUCCESS;
    }

    //
    // Wait for drain
    //
    Timeout.QuadPart = -((LONGLONG)TimeoutMs * 10000);

    Status = KeWaitForSingleObject(
        &g_WqManager.DrainCompleteEvent,
        Executive,
        KernelMode,
        FALSE,
        (TimeoutMs == 0) ? NULL : &Timeout
    );

    g_WqManager.State = ShadowWqStateRunning;
    g_WqManager.Stats.State = ShadowWqStateRunning;

    return (Status == STATUS_SUCCESS) ? STATUS_SUCCESS : STATUS_TIMEOUT;
}

_Use_decl_annotations_
ULONG
ShadowStrikeWorkQueueFlush(
    VOID
    )
{
    KIRQL OldIrql;
    PLIST_ENTRY Entry;
    PLIST_ENTRY NextEntry;
    PSHADOWSTRIKE_WORK_ITEM Item;
    ULONG FlushedCount = 0;

    //
    // Iterate through all priority queues
    //
    for (ULONG i = 0; i < ShadowWqPriorityCount; i++) {
        PSHADOWSTRIKE_WQ_PRIORITY_QUEUE Queue = &g_WqManager.Queues[i];

        KeAcquireSpinLock(&Queue->Lock, &OldIrql);

        for (Entry = Queue->Head.Flink;
             Entry != &Queue->Head;
             Entry = NextEntry) {

            NextEntry = Entry->Flink;
            Item = CONTAINING_RECORD(Entry, SHADOWSTRIKE_WORK_ITEM, ListEntry);

            if (Item->State == ShadowWqItemStateQueued) {
                Item->CancelRequested = TRUE;
                FlushedCount++;
            }
        }

        KeReleaseSpinLock(&Queue->Lock, OldIrql);
    }

    return FlushedCount;
}

// ============================================================================
// STATISTICS
// ============================================================================

_Use_decl_annotations_
VOID
ShadowStrikeGetWorkQueueStatistics(
    _Out_ PSHADOWSTRIKE_WQ_STATISTICS Statistics
    )
{
    LARGE_INTEGER CurrentTime;

    if (Statistics == NULL) {
        return;
    }

    RtlCopyMemory(Statistics, &g_WqManager.Stats, sizeof(SHADOWSTRIKE_WQ_STATISTICS));

    //
    // Calculate uptime
    //
    KeQuerySystemTimePrecise(&CurrentTime);
    Statistics->Uptime.QuadPart =
        CurrentTime.QuadPart - g_WqManager.Stats.StartTime.QuadPart;

    //
    // Calculate averages
    //
    if (g_WqManager.Timing.SampleCount > 0) {
        Statistics->AverageWaitTimeUs =
            (ULONG64)(g_WqManager.Timing.TotalWaitTime /
                      g_WqManager.Timing.SampleCount);
        Statistics->AverageExecTimeUs =
            (ULONG64)(g_WqManager.Timing.TotalExecTime /
                      g_WqManager.Timing.SampleCount);
    }

    //
    // Get per-priority pending counts
    //
    for (ULONG i = 0; i < ShadowWqPriorityCount; i++) {
        Statistics->PerPriority[i].Pending = g_WqManager.Queues[i].Count;
        Statistics->PerPriority[i].Peak = g_WqManager.Queues[i].PeakCount;
    }
}

_Use_decl_annotations_
VOID
ShadowStrikeResetWorkQueueStatistics(
    VOID
    )
{
    LONG CurrentPending = g_WqManager.Stats.CurrentPending;
    LONG CurrentExecuting = g_WqManager.Stats.CurrentExecuting;
    SHADOWSTRIKE_WQ_STATE CurrentState = g_WqManager.Stats.State;

    RtlZeroMemory(&g_WqManager.Stats, sizeof(SHADOWSTRIKE_WQ_STATISTICS));

    //
    // Preserve current values
    //
    g_WqManager.Stats.CurrentPending = CurrentPending;
    g_WqManager.Stats.CurrentExecuting = CurrentExecuting;
    g_WqManager.Stats.State = CurrentState;

    //
    // Reset start time
    //
    KeQuerySystemTimePrecise(&g_WqManager.Stats.StartTime);

    //
    // Reset timing
    //
    g_WqManager.Timing.TotalWaitTime = 0;
    g_WqManager.Timing.TotalExecTime = 0;
    g_WqManager.Timing.SampleCount = 0;
}

_Use_decl_annotations_
LONG
ShadowStrikeGetPendingWorkItemCount(
    VOID
    )
{
    return g_WqManager.Stats.CurrentPending;
}

_Use_decl_annotations_
LONG
ShadowStrikeGetPendingWorkItemCountByPriority(
    _In_ SHADOWSTRIKE_WQ_PRIORITY Priority
    )
{
    if (!ShadowStrikeIsValidWqPriority(Priority)) {
        return 0;
    }

    return g_WqManager.Queues[Priority].Count;
}

// ============================================================================
// CONFIGURATION
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeWorkQueueSetDeviceObject(
    _In_ PDEVICE_OBJECT DeviceObject
    )
{
    PAGED_CODE();

    if (DeviceObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    g_WqManager.DeviceObject = DeviceObject;
    g_WqManager.Config.DeviceObject = DeviceObject;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeWorkQueueSetFilterHandle(
    _In_ PFLT_FILTER FilterHandle
    )
{
    PAGED_CODE();

    if (FilterHandle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    g_WqManager.FilterHandle = FilterHandle;
    g_WqManager.Config.FilterHandle = FilterHandle;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
ShadowStrikeInitWorkQueueOptions(
    _Out_ PSHADOWSTRIKE_WQ_OPTIONS Options
    )
{
    if (Options == NULL) {
        return;
    }

    RtlZeroMemory(Options, sizeof(SHADOWSTRIKE_WQ_OPTIONS));
    Options->Priority = ShadowWqPriorityNormal;
    Options->Flags = ShadowWqFlagNone;
    Options->TimeoutMs = WQ_DEFAULT_TIMEOUT_MS;
}

_Use_decl_annotations_
VOID
ShadowStrikeInitWorkQueueConfig(
    _Out_ PSHADOWSTRIKE_WQ_CONFIG Config
    )
{
    if (Config == NULL) {
        return;
    }

    RtlZeroMemory(Config, sizeof(SHADOWSTRIKE_WQ_CONFIG));
    Config->MaxPendingTotal = WQ_DEFAULT_MAX_PENDING;
    Config->MaxPendingPerPriority = WQ_DEFAULT_MAX_PENDING / ShadowWqPriorityCount;
    Config->DefaultTimeoutMs = WQ_DEFAULT_TIMEOUT_MS;
    Config->LookasideDepth = WQ_LOOKASIDE_DEPTH;
    Config->EnableStatistics = TRUE;
    Config->EnableDetailedTiming = FALSE;
}
