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
/**
 * ============================================================================
 * ShadowStrike NGAV - MESSAGE QUEUE IMPLEMENTATION
 * ============================================================================
 *
 * @file MessageQueue.c
 * @brief Asynchronous message queue for kernel<->user communication.
 *
 * Enterprise-grade message queue implementation for high-throughput,
 * low-latency kernel-to-user-mode communication.
 *
 * Key Design Decisions:
 * - Reference-counted pending completions prevent use-after-free
 * - Response data copied into completion structure under lock
 * - Atomic slot reservation prevents queue depth race conditions
 * - Explicit allocation source tracking prevents pool corruption
 * - Proper shutdown sequencing waits for all outstanding operations
 *
 * Thread Safety:
 * - Per-priority spinlocks minimize contention
 * - Lock ordering: Priority locks acquired in ascending order
 * - Statistics use interlocked operations (no locks)
 * - Pending completions protected by dedicated spinlock with refcount
 *
 * IRQL Requirements:
 * - MqInitialize/MqShutdown: PASSIVE_LEVEL
 * - MqEnqueueMessage: <= DISPATCH_LEVEL
 * - MqDequeueMessage: PASSIVE_LEVEL (may wait)
 * - MqCompleteMessage: <= DISPATCH_LEVEL
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "MessageQueue.h"

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

//
// Timing constants
//
#define MQ_WORKER_POLL_INTERVAL_MS      10
#define MQ_COMPLETION_TIMEOUT_DEFAULT   30000   // 30 seconds
#define MQ_SHUTDOWN_COMPLETION_WAIT_MS  10000   // 10 seconds max wait for completions

//
// Lookaside threshold - messages <= this size use lookaside
//
#define MQ_LOOKASIDE_THRESHOLD          1024

// ============================================================================
// PENDING COMPLETION STRUCTURE (REFERENCE-COUNTED)
// ============================================================================

/**
 * @brief Completion state values.
 */
typedef enum _MQ_COMPLETION_STATE {
    MqCompletionState_Pending = 0,      // Waiting for response
    MqCompletionState_Completed = 1,    // Response received
    MqCompletionState_TimedOut = 2,     // Timed out
    MqCompletionState_Cancelled = 3,    // Cancelled (shutdown)
    MqCompletionState_Detached = 4      // Waiter gave up, completion orphaned
} MQ_COMPLETION_STATE;

/**
 * @brief Reference-counted pending completion structure.
 *
 * Lifetime management:
 * - Created with RefCount=2 (one for waiter, one for list)
 * - Waiter releases its reference when done waiting
 * - MqCompleteMessage or cleanup releases list reference
 * - Structure freed when RefCount reaches 0
 *
 * Response buffer:
 * - ResponseData is dynamically allocated at completion time
 * - This avoids embedding 64KB per completion from nonpaged pool
 * - The waiter copies from ResponseData after the event is signaled
 */
typedef struct _MQ_PENDING_COMPLETION {
    // Validation
    UINT32 Magic;
    UINT32 Reserved1;

    // List membership
    LIST_ENTRY ListEntry;

    // Identification
    UINT64 CompletionId;
    UINT64 MessageId;
    UINT64 EnqueueTime;

    // Reference counting for safe lifetime management
    volatile LONG RefCount;

    // State (atomic)
    volatile LONG State;

    // Completion event
    KEVENT CompletionEvent;

    // Result
    volatile NTSTATUS CompletionStatus;

    // Response buffer - dynamically allocated based on actual response size
    // to avoid wasting 64KB of nonpaged pool per blocking message.
    // ResponseBufferSize: max size the waiter can accept (set at creation)
    // ResponseSize: actual bytes written by completer (set at completion)
    UINT32 ResponseBufferSize;
    volatile UINT32 ResponseSize;
    PUINT8 ResponseData;    // Dynamically allocated, NULL until response arrives
} MQ_PENDING_COMPLETION, *PMQ_PENDING_COMPLETION;

// ============================================================================
// GLOBAL STATE
// ============================================================================

/**
 * @brief Global message queue state.
 */
static MESSAGE_QUEUE_GLOBALS g_MqGlobals = {0};

/**
 * @brief Pending completion list and synchronization.
 */
static LIST_ENTRY g_PendingCompletionList;
static KSPIN_LOCK g_PendingCompletionLock;
static volatile LONG g_PendingCompletionCount = 0;

/**
 * @brief Lookaside list for pending completions.
 */
static NPAGED_LOOKASIDE_LIST g_PendingCompletionLookaside;
static BOOLEAN g_PendingCompletionLookasideInitialized = FALSE;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static PQUEUED_MESSAGE
MqpAllocateMessage(
    _In_ UINT32 DataSize
    );

static VOID
MqpFreeMessageInternal(
    _In_ PQUEUED_MESSAGE Message
    );

static NTSTATUS
MqpEnqueueToPriorityQueue(
    _In_ PQUEUED_MESSAGE Message
    );

static PQUEUED_MESSAGE
MqpDequeueFromPriorityQueues(
    VOID
    );

static PMQ_PENDING_COMPLETION
MqpAllocatePendingCompletion(
    VOID
    );

static VOID
MqpReleasePendingCompletion(
    _In_ PMQ_PENDING_COMPLETION Completion
    );

static PMQ_PENDING_COMPLETION
MqpFindAndReferencePendingCompletion(
    _In_ UINT64 MessageId
    );

static VOID
MqpDetachPendingCompletion(
    _In_ PMQ_PENDING_COMPLETION Completion
    );

static VOID
MqpCleanupExpiredCompletions(
    VOID
    );

static VOID
MqpUpdateFlowControl(
    _In_ LONG CurrentDepth
    );

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
MqpWorkerThread(
    _In_ PVOID Context
    );

/**
 * @brief Get current time in milliseconds.
 */
FORCEINLINE
UINT64
MqpGetCurrentTimeMs(
    VOID
    )
{
    LARGE_INTEGER time;
    KeQuerySystemTime(&time);
    return (UINT64)(time.QuadPart / 10000);  // 100ns -> ms
}

/**
 * @brief Check if subsystem is in running state.
 */
FORCEINLINE
BOOLEAN
MqpIsRunning(
    VOID
    )
{
    //
    // Simple volatile read — a CAS-as-read here would interfere with
    // shutdown transitions by rewriting MqState_Running back.
    //
    return (ReadNoFence((volatile LONG*)&g_MqGlobals.State) == MqState_Running);
}

// ============================================================================
// INITIALIZATION AND SHUTDOWN
// ============================================================================

/**
 * @brief Initialize the message queue subsystem.
 *
 * Thread-safe initialization using atomic state transitions.
 * All resources allocated atomically - either all succeed or none.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MqInitialize(
    VOID
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE threadHandle = NULL;
    LONG previousState;
    ULONG i;

    PAGED_CODE();

    //
    // Atomic state transition: Uninitialized -> Initializing
    //
    previousState = InterlockedCompareExchange(
        &g_MqGlobals.State,
        MqState_Initializing,
        MqState_Uninitialized
    );

    if (previousState != MqState_Uninitialized) {
        if (previousState == MqState_Running) {
            return STATUS_ALREADY_REGISTERED;
        }
        return STATUS_DEVICE_BUSY;  // Initialization in progress
    }

    //
    // Zero out global state (except State which we just set)
    //
    {
        LONG savedState = g_MqGlobals.State;
        RtlZeroMemory(&g_MqGlobals, sizeof(g_MqGlobals));
        g_MqGlobals.State = savedState;
    }

    //
    // Initialize default configuration
    //
    g_MqGlobals.MaxQueueDepth = MQ_DEFAULT_MAX_QUEUE_DEPTH;
    g_MqGlobals.MaxMessageSize = MQ_DEFAULT_MAX_MESSAGE_SIZE;
    g_MqGlobals.BatchSize = MQ_DEFAULT_BATCH_SIZE;
    g_MqGlobals.BatchTimeoutMs = MQ_DEFAULT_BATCH_TIMEOUT_MS;
    g_MqGlobals.HighWaterMark = MQ_DEFAULT_HIGH_WATER_MARK;
    g_MqGlobals.LowWaterMark = MQ_DEFAULT_LOW_WATER_MARK;

    //
    // Initialize priority queues
    //
    for (i = 0; i < MessagePriority_Max; i++) {
        InitializeListHead(&g_MqGlobals.Queues[i].MessageList);
        KeInitializeSpinLock(&g_MqGlobals.Queues[i].Lock);
        g_MqGlobals.Queues[i].Count = 0;
        g_MqGlobals.Queues[i].PeakCount = 0;
    }

    //
    // Initialize batch lock
    //
    KeInitializeSpinLock(&g_MqGlobals.BatchLock);

    //
    // Initialize events
    //
    KeInitializeEvent(&g_MqGlobals.MessageAvailableEvent, SynchronizationEvent, FALSE);
    KeInitializeEvent(&g_MqGlobals.BatchReadyEvent, SynchronizationEvent, FALSE);
    KeInitializeEvent(&g_MqGlobals.HighWaterMarkEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&g_MqGlobals.SpaceAvailableEvent, NotificationEvent, TRUE);  // Initially signaled (space available)
    KeInitializeEvent(&g_MqGlobals.AllCompletionsReleasedEvent, NotificationEvent, TRUE);  // Initially signaled

    //
    // Initialize message lookaside list
    //
    ExInitializeNPagedLookasideList(
        &g_MqGlobals.MessageLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        MQ_MESSAGE_ALLOC_SIZE(MQ_LOOKASIDE_THRESHOLD),
        MQ_POOL_TAG_MESSAGE,
        0
    );
    g_MqGlobals.MessageLookasideInitialized = TRUE;

    //
    // Initialize pending completion list and lookaside
    //
    InitializeListHead(&g_PendingCompletionList);
    KeInitializeSpinLock(&g_PendingCompletionLock);
    g_PendingCompletionCount = 0;

    ExInitializeNPagedLookasideList(
        &g_PendingCompletionLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(MQ_PENDING_COMPLETION),
        MQ_POOL_TAG_COMPLETION,
        0
    );
    g_PendingCompletionLookasideInitialized = TRUE;

    //
    // Initialize worker thread control
    //
    KeInitializeEvent(&g_MqGlobals.WorkerStopEvent, NotificationEvent, FALSE);
    g_MqGlobals.WorkerStopping = FALSE;

    //
    // Create worker thread
    //
    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    status = PsCreateSystemThread(
        &threadHandle,
        THREAD_ALL_ACCESS,
        &objAttr,
        NULL,
        NULL,
        MqpWorkerThread,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        MQ_LOG_ERROR("Failed to create worker thread: 0x%08X", status);
        goto Cleanup;
    }

    //
    // Get thread object reference
    //
    status = ObReferenceObjectByHandle(
        threadHandle,
        THREAD_ALL_ACCESS,
        *PsThreadType,
        KernelMode,
        (PVOID*)&g_MqGlobals.WorkerThread,
        NULL
    );

    ZwClose(threadHandle);
    threadHandle = NULL;

    if (!NT_SUCCESS(status)) {
        MQ_LOG_ERROR("Failed to reference worker thread: 0x%08X", status);
        //
        // Signal thread to stop - it will exit on its own
        //
        InterlockedExchange(&g_MqGlobals.WorkerStopping, TRUE);
        KeSetEvent(&g_MqGlobals.WorkerStopEvent, IO_NO_INCREMENT, FALSE);
        goto Cleanup;
    }

    //
    // Transition to running state
    //
    InterlockedExchange(&g_MqGlobals.State, MqState_Running);

    MQ_LOG_INFO("Message queue initialized (depth=%d, msgSize=%d)",
                g_MqGlobals.MaxQueueDepth, g_MqGlobals.MaxMessageSize);

    return STATUS_SUCCESS;

Cleanup:
    //
    // Cleanup on failure
    //
    if (g_MqGlobals.MessageLookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_MqGlobals.MessageLookaside);
        g_MqGlobals.MessageLookasideInitialized = FALSE;
    }

    if (g_PendingCompletionLookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_PendingCompletionLookaside);
        g_PendingCompletionLookasideInitialized = FALSE;
    }

    InterlockedExchange(&g_MqGlobals.State, MqState_Uninitialized);

    return status;
}

/**
 * @brief Shutdown the message queue subsystem.
 *
 * Proper shutdown sequence:
 * 1. Transition to ShuttingDown state (reject new operations)
 * 2. Stop worker thread (wait indefinitely - it MUST stop)
 * 3. Cancel all pending completions
 * 4. Wait for all completion references to be released
 * 5. Drain message queues
 * 6. Delete lookaside lists
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
MqShutdown(
    VOID
    )
{
    ULONG i;
    PLIST_ENTRY entry;
    PMQ_PENDING_COMPLETION completion;
    KIRQL oldIrql;
    LARGE_INTEGER timeout;
    NTSTATUS waitStatus;

    PAGED_CODE();

    //
    // Atomic state transition: Running -> ShuttingDown
    //
    if (InterlockedCompareExchange(&g_MqGlobals.State, MqState_ShuttingDown, MqState_Running) != MqState_Running) {
        return;  // Not running or already shutting down
    }

    MQ_LOG_INFO("Shutting down message queue...");

    //
    // Signal worker thread to stop
    //
    InterlockedExchange(&g_MqGlobals.WorkerStopping, TRUE);
    KeSetEvent(&g_MqGlobals.WorkerStopEvent, IO_NO_INCREMENT, FALSE);
    KeSetEvent(&g_MqGlobals.MessageAvailableEvent, IO_NO_INCREMENT, FALSE);

    //
    // Wait for worker thread to exit (indefinitely - it MUST stop)
    // The worker checks WorkerStopping flag and will exit promptly
    //
    if (g_MqGlobals.WorkerThread != NULL) {
        waitStatus = KeWaitForSingleObject(
            g_MqGlobals.WorkerThread,
            Executive,
            KernelMode,
            FALSE,
            NULL  // Infinite wait - worker MUST exit
        );

        if (waitStatus != STATUS_SUCCESS) {
            //
            // This should never happen with infinite wait
            // Log but continue cleanup
            //
            MQ_LOG_ERROR("Unexpected wait result for worker thread: 0x%08X", waitStatus);
        }

        ObDereferenceObject(g_MqGlobals.WorkerThread);
        g_MqGlobals.WorkerThread = NULL;
    }

    //
    // Cancel all pending completions and release list references.
    // Completions whose waiter already released are collected into
    // a local list for deferred freeing outside the spinlock.
    //
    {
        LIST_ENTRY orphanedCompletions;
        PLIST_ENTRY orphanEntry;
        PMQ_PENDING_COMPLETION orphanCompletion;

        InitializeListHead(&orphanedCompletions);

        KeAcquireSpinLock(&g_PendingCompletionLock, &oldIrql);

        while (!IsListEmpty(&g_PendingCompletionList)) {
            entry = RemoveHeadList(&g_PendingCompletionList);
            completion = CONTAINING_RECORD(entry, MQ_PENDING_COMPLETION, ListEntry);
            InitializeListHead(&completion->ListEntry);
            InterlockedDecrement(&g_PendingCompletionCount);

            //
            // Mark as cancelled and signal waiter
            //
            InterlockedExchange(&completion->State, MqCompletionState_Cancelled);
            completion->CompletionStatus = STATUS_CANCELLED;
            KeSetEvent(&completion->CompletionEvent, IO_NO_INCREMENT, FALSE);

            //
            // Release list's reference (waiter still has one).
            // If refcount hits 0, waiter already released — collect for deferred free.
            //
            if (InterlockedDecrement(&completion->RefCount) == 0) {
                completion->Magic = 0;
                InsertTailList(&orphanedCompletions, &completion->ListEntry);
            }
        }

        //
        // Track that we need to wait for outstanding completions
        //
        if (g_MqGlobals.OutstandingCompletions > 0) {
            KeClearEvent(&g_MqGlobals.AllCompletionsReleasedEvent);
        }

        KeReleaseSpinLock(&g_PendingCompletionLock, oldIrql);

        //
        // Free orphaned completions outside the spinlock
        //
        while (!IsListEmpty(&orphanedCompletions)) {
            orphanEntry = RemoveHeadList(&orphanedCompletions);
            orphanCompletion = CONTAINING_RECORD(orphanEntry, MQ_PENDING_COMPLETION, ListEntry);

            if (orphanCompletion->ResponseData != NULL) {
                ExFreePoolWithTag(orphanCompletion->ResponseData, MQ_POOL_TAG_MESSAGE);
                orphanCompletion->ResponseData = NULL;
            }

            if (InterlockedDecrement(&g_MqGlobals.OutstandingCompletions) == 0) {
                KeSetEvent(&g_MqGlobals.AllCompletionsReleasedEvent, IO_NO_INCREMENT, FALSE);
            }

            if (g_PendingCompletionLookasideInitialized) {
                ExFreeToNPagedLookasideList(&g_PendingCompletionLookaside, orphanCompletion);
            }
        }
    }

    //
    // Wait for all outstanding completions to be released
    // This ensures waiters have finished copying response data
    //
    if (g_MqGlobals.OutstandingCompletions > 0) {
        timeout.QuadPart = -(LONGLONG)MQ_SHUTDOWN_COMPLETION_WAIT_MS * 10000LL;
        waitStatus = KeWaitForSingleObject(
            &g_MqGlobals.AllCompletionsReleasedEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout
        );

        if (waitStatus == STATUS_TIMEOUT) {
            MQ_LOG_WARNING("Timeout waiting for %d outstanding completions",
                          g_MqGlobals.OutstandingCompletions);
        }
    }

    //
    // Drain all priority queues
    // Collect messages to a local list under lock, then free outside lock.
    //
    {
        LIST_ENTRY drainList;
        PLIST_ENTRY drainEntry;
        PQUEUED_MESSAGE drainMessage;

        InitializeListHead(&drainList);

        for (i = 0; i < MessagePriority_Max; i++) {
            KeAcquireSpinLock(&g_MqGlobals.Queues[i].Lock, &oldIrql);

            while (!IsListEmpty(&g_MqGlobals.Queues[i].MessageList)) {
                entry = RemoveHeadList(&g_MqGlobals.Queues[i].MessageList);
                InterlockedDecrement(&g_MqGlobals.Queues[i].Count);
                InsertTailList(&drainList, entry);
            }

            KeReleaseSpinLock(&g_MqGlobals.Queues[i].Lock, oldIrql);
        }

        //
        // Now free all collected messages outside any spinlock
        //
        while (!IsListEmpty(&drainList)) {
            drainEntry = RemoveHeadList(&drainList);
            drainMessage = CONTAINING_RECORD(drainEntry, QUEUED_MESSAGE, ListEntry);
            MqpFreeMessageInternal(drainMessage);
        }
    }

    g_MqGlobals.TotalMessageCount = 0;

    //
    // Free batch buffer if allocated
    //
    if (g_MqGlobals.CurrentBatch != NULL) {
        ExFreePoolWithTag(g_MqGlobals.CurrentBatch, MQ_POOL_TAG_BATCH);
        g_MqGlobals.CurrentBatch = NULL;
    }

    //
    // Delete lookaside lists
    // Safe now because all references have been released
    //
    if (g_MqGlobals.MessageLookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_MqGlobals.MessageLookaside);
        g_MqGlobals.MessageLookasideInitialized = FALSE;
    }

    if (g_PendingCompletionLookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_PendingCompletionLookaside);
        g_PendingCompletionLookasideInitialized = FALSE;
    }

    MQ_LOG_INFO("Final stats: Enqueued=%llu, Dequeued=%llu, Dropped=%llu",
               (unsigned long long)g_MqGlobals.TotalMessagesEnqueued,
               (unsigned long long)g_MqGlobals.TotalMessagesDequeued,
               (unsigned long long)g_MqGlobals.TotalMessagesDropped);

    //
    // Transition to shutdown state
    //
    InterlockedExchange(&g_MqGlobals.State, MqState_Shutdown);

    MQ_LOG_INFO("Message queue shutdown complete");
}

/**
 * @brief Configure the message queue parameters.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
MqConfigure(
    _In_ UINT32 MaxQueueDepth,
    _In_ UINT32 MaxMessageSize,
    _In_ UINT32 BatchSize,
    _In_ UINT32 BatchTimeoutMs
    )
{
    //
    // Validate parameters
    //
    if (MaxQueueDepth == 0 || MaxQueueDepth > MQ_MAX_QUEUE_DEPTH_LIMIT) {
        return STATUS_INVALID_PARAMETER;
    }

    if (MaxMessageSize == 0 || MaxMessageSize > MQ_MAX_MESSAGE_SIZE_LIMIT) {
        return STATUS_INVALID_PARAMETER;
    }

    if (BatchSize < MQ_MIN_BATCH_SIZE || BatchSize > MQ_MAX_BATCH_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Update configuration atomically
    //
    InterlockedExchange(&g_MqGlobals.MaxQueueDepth, (LONG)MaxQueueDepth);
    InterlockedExchange(&g_MqGlobals.MaxMessageSize, (LONG)MaxMessageSize);
    InterlockedExchange(&g_MqGlobals.BatchSize, (LONG)BatchSize);
    InterlockedExchange(&g_MqGlobals.BatchTimeoutMs, (LONG)BatchTimeoutMs);

    //
    // Update water marks (80% / 50% of new depth)
    //
    InterlockedExchange(&g_MqGlobals.HighWaterMark, (LONG)((MaxQueueDepth * 80) / 100));
    InterlockedExchange(&g_MqGlobals.LowWaterMark, (LONG)((MaxQueueDepth * 50) / 100));

    MQ_LOG_INFO("Reconfigured: depth=%u, msgSize=%u, batch=%u",
               MaxQueueDepth, MaxMessageSize, BatchSize);

    return STATUS_SUCCESS;
}

// ============================================================================
// MESSAGE OPERATIONS
// ============================================================================

/**
 * @brief Enqueue a message with atomic slot reservation.
 *
 * Uses InterlockedCompareExchange loop to atomically reserve a queue slot,
 * preventing the TOCTOU race where multiple threads could exceed MaxQueueDepth.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
MqEnqueueMessage(
    _In_ SHADOWSTRIKE_MESSAGE_TYPE MessageType,
    _In_reads_bytes_(MessageSize) PVOID MessageData,
    _In_ UINT32 MessageSize,
    _In_ MESSAGE_PRIORITY Priority,
    _In_ UINT32 Flags,
    _Out_opt_ PUINT64 MessageId
    )
{
    PQUEUED_MESSAGE message = NULL;
    NTSTATUS status;
    LONG currentDepth;
    LONG newDepth;
    LONG maxDepth;

    //
    // Initialize output
    //
    if (MessageId != NULL) {
        *MessageId = 0;
    }

    //
    // Validate state
    //
    if (!MqpIsRunning()) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Validate parameters
    //
    if (MessageData == NULL && MessageSize > 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (MessageSize > (UINT32)g_MqGlobals.MaxMessageSize) {
        return STATUS_BUFFER_OVERFLOW;
    }

    if (Priority >= MessagePriority_Max) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Atomic slot reservation using CAS loop
    // High/Critical priority messages bypass the limit
    //
    maxDepth = g_MqGlobals.MaxQueueDepth;

    if (Priority >= MessagePriority_High) {
        //
        // High priority - always succeeds, just increment
        //
        InterlockedIncrement(&g_MqGlobals.TotalMessageCount);
    } else {
        //
        // Normal/Low priority - must reserve slot atomically
        //
        do {
            currentDepth = g_MqGlobals.TotalMessageCount;
            if (currentDepth >= maxDepth) {
                InterlockedIncrement64(&g_MqGlobals.TotalMessagesDropped);
                return STATUS_DEVICE_BUSY;
            }
            newDepth = currentDepth + 1;
        } while (InterlockedCompareExchange(&g_MqGlobals.TotalMessageCount, newDepth, currentDepth) != currentDepth);
    }

    //
    // Allocate message structure
    //
    message = MqpAllocateMessage(MessageSize);
    if (message == NULL) {
        //
        // Release reserved slot
        //
        InterlockedDecrement(&g_MqGlobals.TotalMessageCount);
        InterlockedIncrement64(&g_MqGlobals.TotalMessagesDropped);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Fill message structure
    //
    message->MessageId = (UINT64)InterlockedIncrement64(&g_MqGlobals.NextMessageId);
    message->EnqueueTime = MqpGetCurrentTimeMs();
    message->MessageType = MessageType;
    message->Priority = Priority;
    message->MessageSize = MessageSize;
    message->Flags = Flags;
    message->ProcessId = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
    message->ThreadId = (UINT32)(ULONG_PTR)PsGetCurrentThreadId();
    message->CompletionId = 0;

    //
    // Copy message data
    //
    if (MessageSize > 0 && MessageData != NULL) {
        RtlCopyMemory(message->Data, MessageData, MessageSize);
    }

    //
    // Enqueue to appropriate priority queue
    // Note: TotalMessageCount already incremented above
    //
    status = MqpEnqueueToPriorityQueue(message);
    if (!NT_SUCCESS(status)) {
        MqpFreeMessageInternal(message);
        InterlockedDecrement(&g_MqGlobals.TotalMessageCount);
        return status;
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&g_MqGlobals.TotalMessagesEnqueued);
    InterlockedAdd64(&g_MqGlobals.TotalBytesEnqueued, MessageSize);

    //
    // Update flow control state
    //
    MqpUpdateFlowControl(g_MqGlobals.TotalMessageCount);

    //
    // Update peak count
    //
    {
        LONG depth = g_MqGlobals.TotalMessageCount;
        LONG peak = g_MqGlobals.PeakMessageCount;
        while (depth > peak) {
            LONG oldPeak = InterlockedCompareExchange(&g_MqGlobals.PeakMessageCount, depth, peak);
            if (oldPeak == peak) break;
            peak = oldPeak;
        }
    }

    //
    // Signal message available
    //
    KeSetEvent(&g_MqGlobals.MessageAvailableEvent, IO_NO_INCREMENT, FALSE);

    //
    // Return message ID
    //
    if (MessageId != NULL) {
        *MessageId = message->MessageId;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Enqueue a blocking message and wait for response.
 *
 * Key safety features:
 * - Completion structure is reference-counted
 * - Response data copied INTO completion structure under lock
 * - Caller copies from completion structure after wait (safe - we hold reference)
 * - On timeout/cancel, completion is detached so MqCompleteMessage is safe
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MqEnqueueMessageAndWait(
    _In_ SHADOWSTRIKE_MESSAGE_TYPE MessageType,
    _In_reads_bytes_(MessageSize) PVOID MessageData,
    _In_ UINT32 MessageSize,
    _In_ MESSAGE_PRIORITY Priority,
    _Out_writes_bytes_to_(ResponseBufferSize, *ResponseSize) PVOID ResponseBuffer,
    _In_ UINT32 ResponseBufferSize,
    _Out_ PUINT32 ResponseSize,
    _In_ UINT32 TimeoutMs
    )
{
    PQUEUED_MESSAGE message = NULL;
    PMQ_PENDING_COMPLETION pendingCompletion = NULL;
    NTSTATUS status;
    LARGE_INTEGER timeout;
    KIRQL oldIrql;
    LONG currentDepth;
    LONG newDepth;
    LONG maxDepth;
    MQ_COMPLETION_STATE completionState;

    PAGED_CODE();

    //
    // Initialize outputs
    //
    *ResponseSize = 0;

    //
    // Validate state
    //
    if (!MqpIsRunning()) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Validate parameters
    //
    if (MessageData == NULL && MessageSize > 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ResponseBuffer == NULL || ResponseBufferSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ResponseBufferSize > MQ_MAX_RESPONSE_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (MessageSize > (UINT32)g_MqGlobals.MaxMessageSize) {
        return STATUS_BUFFER_OVERFLOW;
    }

    if (Priority >= MessagePriority_Max) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Check pending completion limit
    //
    if (g_PendingCompletionCount >= MQ_MAX_PENDING_COMPLETIONS) {
        return STATUS_TOO_MANY_COMMANDS;
    }

    //
    // Allocate pending completion structure
    //
    pendingCompletion = MqpAllocatePendingCompletion();
    if (pendingCompletion == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Reserve queue slot atomically
    //
    maxDepth = g_MqGlobals.MaxQueueDepth;

    if (Priority >= MessagePriority_High) {
        InterlockedIncrement(&g_MqGlobals.TotalMessageCount);
    } else {
        do {
            currentDepth = g_MqGlobals.TotalMessageCount;
            if (currentDepth >= maxDepth) {
                MqpReleasePendingCompletion(pendingCompletion);
                MqpReleasePendingCompletion(pendingCompletion);  // Release both refs
                InterlockedIncrement64(&g_MqGlobals.TotalMessagesDropped);
                return STATUS_DEVICE_BUSY;
            }
            newDepth = currentDepth + 1;
        } while (InterlockedCompareExchange(&g_MqGlobals.TotalMessageCount, newDepth, currentDepth) != currentDepth);
    }

    //
    // Allocate message
    //
    message = MqpAllocateMessage(MessageSize);
    if (message == NULL) {
        InterlockedDecrement(&g_MqGlobals.TotalMessageCount);
        MqpReleasePendingCompletion(pendingCompletion);
        MqpReleasePendingCompletion(pendingCompletion);
        InterlockedIncrement64(&g_MqGlobals.TotalMessagesDropped);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize pending completion
    // Created with RefCount=2 (one for waiter, one for list)
    //
    pendingCompletion->CompletionId = (UINT64)InterlockedIncrement64(&g_MqGlobals.NextCompletionId);
    pendingCompletion->MessageId = (UINT64)InterlockedIncrement64(&g_MqGlobals.NextMessageId);
    pendingCompletion->EnqueueTime = MqpGetCurrentTimeMs();
    pendingCompletion->ResponseBufferSize = ResponseBufferSize;

    //
    // Fill message structure
    //
    message->MessageId = pendingCompletion->MessageId;
    message->EnqueueTime = pendingCompletion->EnqueueTime;
    message->MessageType = MessageType;
    message->Priority = Priority;
    message->MessageSize = MessageSize;
    message->Flags = MQ_MSG_FLAG_BLOCKING;
    message->ProcessId = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
    message->ThreadId = (UINT32)(ULONG_PTR)PsGetCurrentThreadId();
    message->CompletionId = pendingCompletion->CompletionId;

    //
    // Copy message data
    //
    if (MessageSize > 0 && MessageData != NULL) {
        RtlCopyMemory(message->Data, MessageData, MessageSize);
    }

    //
    // Add pending completion to tracking list
    //
    KeAcquireSpinLock(&g_PendingCompletionLock, &oldIrql);
    InsertTailList(&g_PendingCompletionList, &pendingCompletion->ListEntry);
    InterlockedIncrement(&g_PendingCompletionCount);
    InterlockedIncrement(&g_MqGlobals.OutstandingCompletions);
    KeClearEvent(&g_MqGlobals.AllCompletionsReleasedEvent);
    KeReleaseSpinLock(&g_PendingCompletionLock, oldIrql);

    //
    // Enqueue message (TotalMessageCount already incremented)
    //
    status = MqpEnqueueToPriorityQueue(message);
    if (!NT_SUCCESS(status)) {
        //
        // Remove pending completion on failure
        //
        MqpDetachPendingCompletion(pendingCompletion);
        MqpReleasePendingCompletion(pendingCompletion);  // Release waiter's ref
        MqpFreeMessageInternal(message);
        InterlockedDecrement(&g_MqGlobals.TotalMessageCount);
        return status;
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&g_MqGlobals.TotalMessagesEnqueued);
    InterlockedAdd64(&g_MqGlobals.TotalBytesEnqueued, MessageSize);

    //
    // Signal message available
    //
    KeSetEvent(&g_MqGlobals.MessageAvailableEvent, IO_NO_INCREMENT, FALSE);

    //
    // Wait for completion
    //
    if (TimeoutMs == 0) {
        status = KeWaitForSingleObject(
            &pendingCompletion->CompletionEvent,
            Executive,
            KernelMode,
            FALSE,
            NULL
        );
    } else {
        timeout.QuadPart = -(LONGLONG)TimeoutMs * 10000LL;
        status = KeWaitForSingleObject(
            &pendingCompletion->CompletionEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout
        );
    }

    //
    // Handle wait result.
    // Read the completion state atomically. Using ReadNoFence on the
    // volatile LONG is sufficient here — the KeWaitForSingleObject
    // return already provides the acquire barrier.
    //
    completionState = (MQ_COMPLETION_STATE)ReadNoFence(&pendingCompletion->State);

    if (status == STATUS_SUCCESS && completionState == MqCompletionState_Completed) {
        //
        // Success - copy response from completion structure
        // Safe because we still hold our reference
        //
        UINT32 copySize = min(pendingCompletion->ResponseSize, ResponseBufferSize);
        if (copySize > 0) {
            RtlCopyMemory(ResponseBuffer, pendingCompletion->ResponseData, copySize);
        }
        *ResponseSize = copySize;
        status = pendingCompletion->CompletionStatus;
    } else if (status == STATUS_TIMEOUT || completionState == MqCompletionState_TimedOut) {
        //
        // Timeout - detach completion so MqCompleteMessage won't access it
        //
        MqpDetachPendingCompletion(pendingCompletion);
        MQ_LOG_WARNING("Blocking message timeout (id=%llu, timeout=%ums)",
                      (unsigned long long)pendingCompletion->MessageId, TimeoutMs);
        status = STATUS_TIMEOUT;
    } else if (completionState == MqCompletionState_Cancelled) {
        //
        // Cancelled (shutdown)
        //
        status = STATUS_CANCELLED;
    } else {
        //
        // Other failure
        //
        MqpDetachPendingCompletion(pendingCompletion);
        MQ_LOG_WARNING("Wait failed for message id=%llu: 0x%08X",
                      (unsigned long long)pendingCompletion->MessageId, status);
    }

    //
    // Release waiter's reference
    //
    MqpReleasePendingCompletion(pendingCompletion);

    return status;
}

/**
 * @brief Dequeue a single message.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MqDequeueMessage(
    _Out_ PQUEUED_MESSAGE* Message,
    _In_ UINT32 TimeoutMs
    )
{
    PQUEUED_MESSAGE message = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    LARGE_INTEGER timeout;

    PAGED_CODE();

    //
    // Initialize output
    //
    *Message = NULL;

    //
    // Validate state
    //
    if (!MqpIsRunning()) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Try to dequeue immediately
    //
    message = MqpDequeueFromPriorityQueues();
    if (message != NULL) {
        *Message = message;
        InterlockedIncrement64(&g_MqGlobals.TotalMessagesDequeued);
        InterlockedAdd64(&g_MqGlobals.TotalBytesDequeued, message->MessageSize);
        return STATUS_SUCCESS;
    }

    //
    // If no wait requested, return immediately
    //
    if (TimeoutMs == 0) {
        return STATUS_NO_MORE_ENTRIES;
    }

    //
    // Wait for message available
    //
    if (TimeoutMs == MAXULONG) {
        status = KeWaitForSingleObject(
            &g_MqGlobals.MessageAvailableEvent,
            Executive,
            KernelMode,
            FALSE,
            NULL
        );
    } else {
        timeout.QuadPart = -(LONGLONG)TimeoutMs * 10000LL;
        status = KeWaitForSingleObject(
            &g_MqGlobals.MessageAvailableEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout
        );
    }

    if (status == STATUS_TIMEOUT) {
        return STATUS_TIMEOUT;
    }

    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Check if shutting down
    //
    if (!MqpIsRunning()) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Try to dequeue again
    //
    message = MqpDequeueFromPriorityQueues();
    if (message == NULL) {
        return STATUS_NO_MORE_ENTRIES;
    }

    *Message = message;
    InterlockedIncrement64(&g_MqGlobals.TotalMessagesDequeued);
    InterlockedAdd64(&g_MqGlobals.TotalBytesDequeued, message->MessageSize);

    //
    // Update flow control
    //
    MqpUpdateFlowControl(g_MqGlobals.TotalMessageCount);

    return STATUS_SUCCESS;
}

/**
 * @brief Dequeue a batch of messages.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MqDequeueBatch(
    _Out_writes_to_(MaxMessages, *MessageCount) PQUEUED_MESSAGE* Messages,
    _In_ UINT32 MaxMessages,
    _Out_ PUINT32 MessageCount,
    _In_ UINT32 TimeoutMs
    )
{
    UINT32 count = 0;
    PQUEUED_MESSAGE message;
    NTSTATUS status;

    PAGED_CODE();

    //
    // Initialize output
    //
    *MessageCount = 0;

    //
    // Validate parameters
    //
    if (Messages == NULL || MaxMessages == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate state
    //
    if (!MqpIsRunning()) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Dequeue first message (may wait)
    //
    status = MqDequeueMessage(&Messages[0], TimeoutMs);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    count = 1;

    //
    // Dequeue remaining messages without waiting
    //
    while (count < MaxMessages) {
        message = MqpDequeueFromPriorityQueues();
        if (message == NULL) {
            break;
        }

        Messages[count] = message;
        count++;

        InterlockedIncrement64(&g_MqGlobals.TotalMessagesDequeued);
        InterlockedAdd64(&g_MqGlobals.TotalBytesDequeued, message->MessageSize);
    }

    *MessageCount = count;

    if (count > 1) {
        InterlockedIncrement64(&g_MqGlobals.TotalBatchesSent);
    }

    //
    // Update flow control
    //
    MqpUpdateFlowControl(g_MqGlobals.TotalMessageCount);

    return STATUS_SUCCESS;
}

/**
 * @brief Free a dequeued message.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
MqFreeMessage(
    _In_opt_ PQUEUED_MESSAGE Message
    )
{
    if (Message != NULL && MQ_IS_VALID_MESSAGE(Message)) {
        MqpFreeMessageInternal(Message);
    }
}

/**
 * @brief Complete a blocking message with response.
 *
 * Thread-safe completion:
 * - Finds and references completion under lock
 * - Copies response data under lock
 * - Signals waiter
 * - Releases reference
 *
 * If waiter has already timed out/cancelled, completion is detached
 * and this function returns STATUS_NOT_FOUND.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
MqCompleteMessage(
    _In_ UINT64 MessageId,
    _In_ NTSTATUS Status,
    _In_reads_bytes_opt_(ResponseSize) PVOID ResponseData,
    _In_ UINT32 ResponseSize
    )
{
    PMQ_PENDING_COMPLETION completion;
    UINT32 copySize;
    LONG previousState;
    KIRQL oldIrql;

    //
    // Validate response size
    //
    if (ResponseSize > MQ_MAX_RESPONSE_SIZE) {
        return STATUS_BUFFER_OVERFLOW;
    }

    //
    // Find and reference completion
    // This acquires lock, finds entry, adds reference, releases lock
    //
    completion = MqpFindAndReferencePendingCompletion(MessageId);
    if (completion == NULL) {
        MQ_LOG_WARNING("CompleteMessage: id=%llu not found", (unsigned long long)MessageId);
        return STATUS_NOT_FOUND;
    }

    //
    // Atomically transition state: Pending -> Completed
    // If already not pending (timeout/cancel/detached), fail
    //
    previousState = InterlockedCompareExchange(
        &completion->State,
        MqCompletionState_Completed,
        MqCompletionState_Pending
    );

    if (previousState != MqCompletionState_Pending) {
        //
        // Already completed/timed out/cancelled
        //
        MqpReleasePendingCompletion(completion);
        return STATUS_ALREADY_COMPLETE;
    }

    //
    // Dynamically allocate response buffer and copy response data.
    // This avoids embedding 64KB in every completion structure.
    //
    if (ResponseData != NULL && ResponseSize > 0) {
        copySize = min(ResponseSize, completion->ResponseBufferSize);
        copySize = min(copySize, MQ_MAX_RESPONSE_SIZE);

        PUINT8 responseBuf = (PUINT8)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, copySize, MQ_POOL_TAG_MESSAGE);

        if (responseBuf != NULL) {
            RtlCopyMemory(responseBuf, ResponseData, copySize);

            KeAcquireSpinLock(&g_PendingCompletionLock, &oldIrql);
            completion->ResponseData = responseBuf;
            completion->ResponseSize = copySize;
            completion->CompletionStatus = Status;
            KeReleaseSpinLock(&g_PendingCompletionLock, oldIrql);
        } else {
            //
            // Allocation failed — complete with error status but no response data
            //
            MQ_LOG_ERROR("Failed to allocate %u byte response buffer for message %llu",
                         copySize, (unsigned long long)MessageId);
            KeAcquireSpinLock(&g_PendingCompletionLock, &oldIrql);
            completion->ResponseData = NULL;
            completion->ResponseSize = 0;
            completion->CompletionStatus = STATUS_INSUFFICIENT_RESOURCES;
            KeReleaseSpinLock(&g_PendingCompletionLock, oldIrql);
        }
    } else {
        KeAcquireSpinLock(&g_PendingCompletionLock, &oldIrql);
        completion->ResponseSize = 0;
        completion->CompletionStatus = Status;
        KeReleaseSpinLock(&g_PendingCompletionLock, oldIrql);
    }

    //
    // Signal completion event
    //
    KeSetEvent(&completion->CompletionEvent, IO_NO_INCREMENT, FALSE);

    //
    // Release our reference
    //
    MqpReleasePendingCompletion(completion);

    return STATUS_SUCCESS;
}

// ============================================================================
// FLOW CONTROL
// ============================================================================

/**
 * @brief Update flow control state atomically.
 */
static VOID
MqpUpdateFlowControl(
    _In_ LONG CurrentDepth
    )
{
    LONG highWaterMark = g_MqGlobals.HighWaterMark;
    LONG lowWaterMark = g_MqGlobals.LowWaterMark;

    if (CurrentDepth >= highWaterMark) {
        //
        // At or above high water mark - activate flow control
        //
        if (InterlockedCompareExchange(&g_MqGlobals.FlowControlActive,
                                       MQ_FLOW_CONTROL_ACTIVE,
                                       MQ_FLOW_CONTROL_INACTIVE) == MQ_FLOW_CONTROL_INACTIVE) {
            g_MqGlobals.LastFlowControlTime = MqpGetCurrentTimeMs();
            KeSetEvent(&g_MqGlobals.HighWaterMarkEvent, IO_NO_INCREMENT, FALSE);
            KeClearEvent(&g_MqGlobals.SpaceAvailableEvent);
            MQ_LOG_WARNING("High water mark reached: %d messages", CurrentDepth);
        }
    } else if (CurrentDepth <= lowWaterMark) {
        //
        // At or below low water mark - deactivate flow control
        //
        if (InterlockedCompareExchange(&g_MqGlobals.FlowControlActive,
                                       MQ_FLOW_CONTROL_INACTIVE,
                                       MQ_FLOW_CONTROL_ACTIVE) == MQ_FLOW_CONTROL_ACTIVE) {
            KeClearEvent(&g_MqGlobals.HighWaterMarkEvent);
            KeSetEvent(&g_MqGlobals.SpaceAvailableEvent, IO_NO_INCREMENT, FALSE);
            MQ_LOG_INFO("Low water mark reached: %d messages, flow control released", CurrentDepth);
        }
    }
}

/**
 * @brief Check if queue is at high water mark.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
MqIsHighWaterMark(
    VOID
    )
{
    return (g_MqGlobals.FlowControlActive == MQ_FLOW_CONTROL_ACTIVE);
}

/**
 * @brief Check if queue is at low water mark.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
MqIsLowWaterMark(
    VOID
    )
{
    return (g_MqGlobals.FlowControlActive == MQ_FLOW_CONTROL_INACTIVE &&
            g_MqGlobals.TotalMessageCount <= g_MqGlobals.LowWaterMark);
}

/**
 * @brief Get current queue depth.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
UINT32
MqGetQueueDepth(
    VOID
    )
{
    LONG depth = g_MqGlobals.TotalMessageCount;
    return (depth > 0) ? (UINT32)depth : 0;
}

/**
 * @brief Wait for queue space.
 *
 * Waits for SpaceAvailableEvent which is signaled when queue drops
 * below low water mark.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MqWaitForSpace(
    _In_ UINT32 TimeoutMs
    )
{
    LARGE_INTEGER timeout;
    NTSTATUS status;

    PAGED_CODE();

    //
    // If not at high water mark, space is available
    //
    if (g_MqGlobals.FlowControlActive != MQ_FLOW_CONTROL_ACTIVE) {
        return STATUS_SUCCESS;
    }

    if (TimeoutMs == 0) {
        return STATUS_DEVICE_BUSY;
    }

    //
    // Wait for SpaceAvailableEvent (signaled when below low water mark)
    //
    if (TimeoutMs == MAXULONG) {
        status = KeWaitForSingleObject(
            &g_MqGlobals.SpaceAvailableEvent,
            Executive,
            KernelMode,
            FALSE,
            NULL
        );
    } else {
        timeout.QuadPart = -(LONGLONG)TimeoutMs * 10000LL;
        status = KeWaitForSingleObject(
            &g_MqGlobals.SpaceAvailableEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout
        );
    }

    if (status == STATUS_TIMEOUT) {
        return STATUS_DEVICE_BUSY;
    }

    return status;
}

/**
 * @brief Flush all queued messages.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MqFlush(
    _In_ BOOLEAN Wait
    )
{
    LARGE_INTEGER pollInterval;
    ULONG maxWaitIterations = 100;  // 1 second max

    PAGED_CODE();

    if (!Wait) {
        return STATUS_SUCCESS;
    }

    //
    // Wait for queue to drain
    //
    pollInterval.QuadPart = -100000LL;  // 10ms

    while (g_MqGlobals.TotalMessageCount > 0 && maxWaitIterations > 0) {
        KeDelayExecutionThread(KernelMode, FALSE, &pollInterval);
        maxWaitIterations--;
    }

    //
    // Return appropriate status
    //
    if (g_MqGlobals.TotalMessageCount > 0) {
        return STATUS_TIMEOUT;
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// STATISTICS
// ============================================================================

/**
 * @brief Get message queue statistics.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
MqGetStatistics(
    _Out_ PUINT64 TotalEnqueued,
    _Out_ PUINT64 TotalDequeued,
    _Out_ PUINT64 TotalDropped,
    _Out_ PUINT32 CurrentDepth,
    _Out_ PUINT32 PeakDepth
    )
{
    if (TotalEnqueued == NULL || TotalDequeued == NULL || TotalDropped == NULL ||
        CurrentDepth == NULL || PeakDepth == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *TotalEnqueued = (UINT64)g_MqGlobals.TotalMessagesEnqueued;
    *TotalDequeued = (UINT64)g_MqGlobals.TotalMessagesDequeued;
    *TotalDropped = (UINT64)g_MqGlobals.TotalMessagesDropped;
    *CurrentDepth = (UINT32)max(0, g_MqGlobals.TotalMessageCount);
    *PeakDepth = (UINT32)max(0, g_MqGlobals.PeakMessageCount);

    return STATUS_SUCCESS;
}

/**
 * @brief Reset statistics counters.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
MqResetStatistics(
    VOID
    )
{
    ULONG i;

    InterlockedExchange64(&g_MqGlobals.TotalMessagesEnqueued, 0);
    InterlockedExchange64(&g_MqGlobals.TotalMessagesDequeued, 0);
    InterlockedExchange64(&g_MqGlobals.TotalMessagesDropped, 0);
    InterlockedExchange64(&g_MqGlobals.TotalBatchesSent, 0);
    InterlockedExchange64(&g_MqGlobals.TotalBytesEnqueued, 0);
    InterlockedExchange64(&g_MqGlobals.TotalBytesDequeued, 0);
    InterlockedExchange(&g_MqGlobals.PeakMessageCount, g_MqGlobals.TotalMessageCount);

    for (i = 0; i < MessagePriority_Max; i++) {
        InterlockedExchange(&g_MqGlobals.Queues[i].PeakCount, g_MqGlobals.Queues[i].Count);
    }
}

// ============================================================================
// EVENTS
// ============================================================================

/**
 * @brief Wait for message available.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MqWaitForMessageAvailable(
    _In_ UINT32 TimeoutMs
    )
{
    LARGE_INTEGER timeout;
    NTSTATUS status;

    PAGED_CODE();

    if (!MqpIsRunning()) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (TimeoutMs == 0) {
        //
        // Non-blocking check
        //
        if (g_MqGlobals.TotalMessageCount > 0) {
            return STATUS_SUCCESS;
        }
        return STATUS_TIMEOUT;
    }

    if (TimeoutMs == MAXULONG) {
        status = KeWaitForSingleObject(
            &g_MqGlobals.MessageAvailableEvent,
            Executive,
            KernelMode,
            FALSE,
            NULL
        );
    } else {
        timeout.QuadPart = -(LONGLONG)TimeoutMs * 10000LL;
        status = KeWaitForSingleObject(
            &g_MqGlobals.MessageAvailableEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout
        );
    }

    return status;
}

/**
 * @brief Get event for message available notification.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
PKEVENT
MqGetMessageAvailableEvent(
    VOID
    )
{
    return &g_MqGlobals.MessageAvailableEvent;
}

/**
 * @brief Get event for batch ready notification.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
PKEVENT
MqGetBatchReadyEvent(
    VOID
    )
{
    return &g_MqGlobals.BatchReadyEvent;
}

/**
 * @brief Get event for high water mark notification.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
PKEVENT
MqGetHighWaterMarkEvent(
    VOID
    )
{
    return &g_MqGlobals.HighWaterMarkEvent;
}

// ============================================================================
// INTERNAL HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Allocate a message structure with overflow protection.
 *
 * Uses lookaside list for small messages, direct pool for large ones.
 * Allocation source is explicitly tracked for safe deallocation.
 */
static PQUEUED_MESSAGE
MqpAllocateMessage(
    _In_ UINT32 DataSize
    )
{
    PQUEUED_MESSAGE message = NULL;
    SIZE_T allocSize;

    //
    // Verify subsystem is initialized
    //
    if (!g_MqGlobals.MessageLookasideInitialized) {
        return NULL;
    }

    //
    // Calculate allocation size with overflow check
    //
    allocSize = MqCalculateMessageAllocSize(DataSize);
    if (allocSize == 0) {
        //
        // Overflow detected
        //
        return NULL;
    }

    //
    // Use lookaside for small messages
    //
    if (DataSize <= MQ_LOOKASIDE_THRESHOLD) {
        message = (PQUEUED_MESSAGE)ExAllocateFromNPagedLookasideList(&g_MqGlobals.MessageLookaside);
        if (message != NULL) {
            RtlZeroMemory(message, MQ_MESSAGE_ALLOC_SIZE(MQ_LOOKASIDE_THRESHOLD));
            message->AllocSource = MqAllocSource_Lookaside;
        }
    } else {
        //
        // Direct allocation for larger messages
        //
        message = (PQUEUED_MESSAGE)ExAllocatePool2(POOL_FLAG_NON_PAGED, allocSize, MQ_POOL_TAG_MESSAGE);
        if (message != NULL) {
            message->AllocSource = MqAllocSource_Pool;
        }
    }

    if (message != NULL) {
        message->Magic = MQ_MESSAGE_MAGIC;
        InitializeListHead(&message->ListEntry);
    }

    return message;
}

/**
 * @brief Free a message structure using tracked allocation source.
 */
static VOID
MqpFreeMessageInternal(
    _In_ PQUEUED_MESSAGE Message
    )
{
    //
    // Validate message
    //
    if (Message == NULL || Message->Magic != MQ_MESSAGE_MAGIC) {
        return;
    }

    //
    // Invalidate magic to detect double-free
    //
    Message->Magic = 0;

    //
    // Free based on recorded allocation source
    //
    switch (Message->AllocSource) {
    case MqAllocSource_Lookaside:
        if (g_MqGlobals.MessageLookasideInitialized) {
            ExFreeToNPagedLookasideList(&g_MqGlobals.MessageLookaside, Message);
        }
        break;

    case MqAllocSource_Pool:
        ExFreePoolWithTag(Message, MQ_POOL_TAG_MESSAGE);
        break;

    default:
        //
        // Invalid allocation source - corruption detected
        // Cannot safely free, leak is better than corruption
        //
        MQ_LOG_ERROR("Invalid message allocation source: %d", Message->AllocSource);
        break;
    }
}

/**
 * @brief Enqueue message to priority queue.
 *
 * Note: TotalMessageCount must already be incremented by caller
 * to implement atomic slot reservation.
 */
static NTSTATUS
MqpEnqueueToPriorityQueue(
    _In_ PQUEUED_MESSAGE Message
    )
{
    PPRIORITY_QUEUE queue;
    KIRQL oldIrql;
    LONG newCount;

    if (Message->Priority >= MessagePriority_Max) {
        return STATUS_INVALID_PARAMETER;
    }

    queue = &g_MqGlobals.Queues[Message->Priority];

    KeAcquireSpinLock(&queue->Lock, &oldIrql);

    InsertTailList(&queue->MessageList, &Message->ListEntry);

    newCount = InterlockedIncrement(&queue->Count);
    if (newCount > queue->PeakCount) {
        InterlockedExchange(&queue->PeakCount, newCount);
    }

    KeReleaseSpinLock(&queue->Lock, oldIrql);

    return STATUS_SUCCESS;
}

/**
 * @brief Dequeue highest priority message.
 *
 * Decrements TotalMessageCount when message is dequeued.
 */
static PQUEUED_MESSAGE
MqpDequeueFromPriorityQueues(
    VOID
    )
{
    PQUEUED_MESSAGE message = NULL;
    PPRIORITY_QUEUE queue;
    PLIST_ENTRY entry;
    KIRQL oldIrql;
    LONG priority;

    //
    // Check queues in descending priority order
    //
    for (priority = MessagePriority_Max - 1; priority >= 0; priority--) {
        queue = &g_MqGlobals.Queues[priority];

        //
        // Quick check without lock
        //
        if (queue->Count == 0) {
            continue;
        }

        KeAcquireSpinLock(&queue->Lock, &oldIrql);

        if (!IsListEmpty(&queue->MessageList)) {
            entry = RemoveHeadList(&queue->MessageList);
            message = CONTAINING_RECORD(entry, QUEUED_MESSAGE, ListEntry);
            InitializeListHead(&message->ListEntry);  // Prevent double-remove
            InterlockedDecrement(&queue->Count);
        }

        KeReleaseSpinLock(&queue->Lock, oldIrql);

        if (message != NULL) {
            InterlockedDecrement(&g_MqGlobals.TotalMessageCount);
            break;
        }
    }

    return message;
}

/**
 * @brief Allocate pending completion structure.
 *
 * Created with RefCount=2:
 * - One reference for the waiter
 * - One reference for the list
 */
static PMQ_PENDING_COMPLETION
MqpAllocatePendingCompletion(
    VOID
    )
{
    PMQ_PENDING_COMPLETION completion;

    if (!g_PendingCompletionLookasideInitialized) {
        return NULL;
    }

    completion = (PMQ_PENDING_COMPLETION)ExAllocateFromNPagedLookasideList(&g_PendingCompletionLookaside);
    if (completion != NULL) {
        RtlZeroMemory(completion, sizeof(MQ_PENDING_COMPLETION));
        completion->Magic = MQ_COMPLETION_MAGIC;
        completion->RefCount = 2;  // Waiter + List
        completion->State = MqCompletionState_Pending;
        KeInitializeEvent(&completion->CompletionEvent, NotificationEvent, FALSE);
        InitializeListHead(&completion->ListEntry);
    }

    return completion;
}

/**
 * @brief Release a reference to pending completion.
 *
 * When RefCount reaches 0, the structure is freed.
 */
static VOID
MqpReleasePendingCompletion(
    _In_ PMQ_PENDING_COMPLETION Completion
    )
{
    LONG newRefCount;

    if (Completion == NULL || Completion->Magic != MQ_COMPLETION_MAGIC) {
        return;
    }

    newRefCount = InterlockedDecrement(&Completion->RefCount);

    if (newRefCount == 0) {
        //
        // Last reference - free response buffer and the structure
        //
        Completion->Magic = 0;  // Invalidate

        if (Completion->ResponseData != NULL) {
            ExFreePoolWithTag(Completion->ResponseData, MQ_POOL_TAG_MESSAGE);
            Completion->ResponseData = NULL;
        }

        //
        // Update outstanding completion count
        //
        if (InterlockedDecrement(&g_MqGlobals.OutstandingCompletions) == 0) {
            KeSetEvent(&g_MqGlobals.AllCompletionsReleasedEvent, IO_NO_INCREMENT, FALSE);
        }

        if (g_PendingCompletionLookasideInitialized) {
            ExFreeToNPagedLookasideList(&g_PendingCompletionLookaside, Completion);
        }
    } else if (newRefCount < 0) {
        //
        // Underflow - bug in reference counting
        //
        MQ_LOG_ERROR("Completion refcount underflow!");
    }
}

/**
 * @brief Find pending completion by message ID and add reference.
 *
 * Searches under lock, adds reference if found, then releases lock.
 * Caller must call MqpReleasePendingCompletion when done.
 *
 * Returns NULL if not found or already completed/detached.
 */
static PMQ_PENDING_COMPLETION
MqpFindAndReferencePendingCompletion(
    _In_ UINT64 MessageId
    )
{
    PMQ_PENDING_COMPLETION completion = NULL;
    PMQ_PENDING_COMPLETION found = NULL;
    PLIST_ENTRY entry;
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_PendingCompletionLock, &oldIrql);

    for (entry = g_PendingCompletionList.Flink;
         entry != &g_PendingCompletionList;
         entry = entry->Flink)
    {
        completion = CONTAINING_RECORD(entry, MQ_PENDING_COMPLETION, ListEntry);
        if (completion->MessageId == MessageId &&
            completion->State == MqCompletionState_Pending) {
            //
            // Found - add reference while holding lock
            //
            InterlockedIncrement(&completion->RefCount);
            found = completion;
            break;
        }
    }

    KeReleaseSpinLock(&g_PendingCompletionLock, oldIrql);

    return found;
}

/**
 * @brief Detach pending completion from list.
 *
 * Called when waiter times out or is cancelled.
 * Removes from list and releases list's reference.
 * After detach, MqCompleteMessage will not find this completion.
 */
static VOID
MqpDetachPendingCompletion(
    _In_ PMQ_PENDING_COMPLETION Completion
    )
{
    KIRQL oldIrql;
    BOOLEAN wasInList = FALSE;

    if (Completion == NULL) {
        return;
    }

    KeAcquireSpinLock(&g_PendingCompletionLock, &oldIrql);

    //
    // Mark as detached
    //
    InterlockedExchange(&Completion->State, MqCompletionState_Detached);

    //
    // Remove from list if still there
    //
    if (!IsListEmpty(&Completion->ListEntry)) {
        RemoveEntryList(&Completion->ListEntry);
        InitializeListHead(&Completion->ListEntry);
        InterlockedDecrement(&g_PendingCompletionCount);
        wasInList = TRUE;
    }

    KeReleaseSpinLock(&g_PendingCompletionLock, oldIrql);

    //
    // Release list's reference if we removed from list
    //
    if (wasInList) {
        MqpReleasePendingCompletion(Completion);
    }
}

/**
 * @brief Clean up expired pending completions.
 *
 * Called periodically by worker thread to timeout stale blocking messages.
 */
static VOID
MqpCleanupExpiredCompletions(
    VOID
    )
{
    PMQ_PENDING_COMPLETION completion;
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;
    KIRQL oldIrql;
    UINT64 currentTime = MqpGetCurrentTimeMs();
    UINT64 timeout = MQ_COMPLETION_TIMEOUT_DEFAULT;
    LONG previousState;
    LIST_ENTRY expiredList;
    PLIST_ENTRY expiredEntry;
    PMQ_PENDING_COMPLETION expiredCompletion;

    InitializeListHead(&expiredList);

    KeAcquireSpinLock(&g_PendingCompletionLock, &oldIrql);

    for (entry = g_PendingCompletionList.Flink;
         entry != &g_PendingCompletionList;
         entry = nextEntry)
    {
        nextEntry = entry->Flink;
        completion = CONTAINING_RECORD(entry, MQ_PENDING_COMPLETION, ListEntry);

        //
        // Check if expired
        //
        if ((currentTime - completion->EnqueueTime) > timeout) {
            //
            // Try to transition to TimedOut state
            //
            previousState = InterlockedCompareExchange(
                &completion->State,
                MqCompletionState_TimedOut,
                MqCompletionState_Pending
            );

            if (previousState == MqCompletionState_Pending) {
                //
                // Successfully transitioned — signal timeout, then remove from
                // the global list and collect for deferred reference release.
                //
                completion->CompletionStatus = STATUS_TIMEOUT;
                KeSetEvent(&completion->CompletionEvent, IO_NO_INCREMENT, FALSE);

                RemoveEntryList(&completion->ListEntry);
                InterlockedDecrement(&g_PendingCompletionCount);
                InsertTailList(&expiredList, &completion->ListEntry);

                MQ_LOG_WARNING("Expired pending completion: id=%llu, age=%llums",
                              (unsigned long long)completion->MessageId,
                              (unsigned long long)(currentTime - completion->EnqueueTime));
            }
        }
    }

    KeReleaseSpinLock(&g_PendingCompletionLock, oldIrql);

    //
    // Release list references outside the spinlock.
    // The waiter still holds its own reference and will free when done.
    //
    while (!IsListEmpty(&expiredList)) {
        expiredEntry = RemoveHeadList(&expiredList);
        expiredCompletion = CONTAINING_RECORD(expiredEntry, MQ_PENDING_COMPLETION, ListEntry);
        InitializeListHead(&expiredCompletion->ListEntry);
        MqpReleasePendingCompletion(expiredCompletion);
    }
}

/**
 * @brief Worker thread for maintenance operations.
 */
_IRQL_requires_(PASSIVE_LEVEL)
static VOID
MqpWorkerThread(
    _In_ PVOID Context
    )
{
    NTSTATUS status;
    LARGE_INTEGER pollInterval;
    ULONG iterationCount = 0;

    UNREFERENCED_PARAMETER(Context);

    PAGED_CODE();

    MQ_LOG_INFO("Worker thread started");

    pollInterval.QuadPart = -(LONGLONG)MQ_WORKER_POLL_INTERVAL_MS * 10000LL;

    while (!g_MqGlobals.WorkerStopping) {
        //
        // Wait for stop event or poll timeout
        //
        status = KeWaitForSingleObject(
            &g_MqGlobals.WorkerStopEvent,
            Executive,
            KernelMode,
            FALSE,
            &pollInterval
        );

        if (status == STATUS_SUCCESS || g_MqGlobals.WorkerStopping) {
            //
            // Stop event signaled
            //
            break;
        }

        //
        // Periodic maintenance (every second)
        //
        iterationCount++;
        if (iterationCount >= 100) {  // 100 * 10ms = 1 second
            iterationCount = 0;

            //
            // Clean up expired completions
            //
            MqpCleanupExpiredCompletions();

            //
            // Log statistics if at high water mark (debug only)
            //
            #if MQ_DEBUG_OUTPUT
            if (g_MqGlobals.FlowControlActive == MQ_FLOW_CONTROL_ACTIVE) {
                MQ_LOG_WARNING("High load: depth=%d, enqueued=%llu, dropped=%llu",
                              g_MqGlobals.TotalMessageCount,
                              (unsigned long long)g_MqGlobals.TotalMessagesEnqueued,
                              (unsigned long long)g_MqGlobals.TotalMessagesDropped);
            }
            #endif
        }
    }

    MQ_LOG_INFO("Worker thread exiting");

    PsTerminateSystemThread(STATUS_SUCCESS);
}
