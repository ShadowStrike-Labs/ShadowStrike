/**
 * ============================================================================
 * ShadowStrike NGAV - MESSAGE QUEUE IMPLEMENTATION
 * ============================================================================
 *
 * @file MessageQueue.c
 * @brief Asynchronous message queue for kernel<->user communication.
 *
 * Enterprise-grade, lock-free (where possible) message queue implementation
 * for high-throughput, low-latency kernel-to-user-mode communication.
 *
 * Features:
 * - Priority-based message ordering (4 priority levels)
 * - Lock-free statistics counters
 * - Efficient batch coalescing for throughput optimization
 * - Flow control with high/low water marks
 * - Completion tracking for blocking messages
 * - Per-priority lookaside lists for memory efficiency
 * - BSOD-safe resource management with RAII patterns
 *
 * Thread Safety:
 * - Per-priority spinlocks minimize contention
 * - Lock ordering: Priority locks acquired in ascending order to prevent deadlock
 * - Statistics use interlocked operations (no locks)
 * - Batch operations protected by dedicated batch lock
 *
 * IRQL Requirements:
 * - MqInitialize/MqShutdown: PASSIVE_LEVEL
 * - MqEnqueueMessage: <= DISPATCH_LEVEL
 * - MqDequeueMessage: PASSIVE_LEVEL (may wait)
 * - MqCompleteMessage: <= DISPATCH_LEVEL
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "MessageQueue.h"
#include "../Core/Globals.h"
#include "../../Shared/SharedDefs.h"
#include "../../Shared/ErrorCodes.h"

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

//
// Internal pool tags for tracking allocations
//
#define MQ_TAG_GLOBALS      'GqMs'
#define MQ_TAG_MESSAGE      'MqMs'
#define MQ_TAG_BATCH        'BqMs'
#define MQ_TAG_PENDING      'PqMs'

//
// Limits for safety
//
#define MQ_MAX_QUEUE_DEPTH_LIMIT        1000000
#define MQ_MAX_MESSAGE_SIZE_LIMIT       (1024 * 1024)   // 1MB
#define MQ_MIN_BATCH_SIZE               1
#define MQ_MAX_BATCH_SIZE               1000
#define MQ_MAX_PENDING_COMPLETIONS      50000

//
// Timing
//
#define MQ_WORKER_POLL_INTERVAL_MS      10
#define MQ_COMPLETION_TIMEOUT_DEFAULT   30000

// ============================================================================
// PENDING COMPLETION TRACKING
// ============================================================================

/**
 * @brief Entry for tracking pending blocking messages awaiting completion.
 *
 * When a blocking message is enqueued, we create a pending completion entry
 * that holds the completion event and response buffer pointers. When the
 * user-mode service sends a response, we look up this entry by MessageId
 * and signal completion.
 */
typedef struct _MQ_PENDING_COMPLETION {
    LIST_ENTRY ListEntry;
    UINT64 MessageId;
    KEVENT CompletionEvent;
    volatile NTSTATUS CompletionStatus;
    PVOID ResponseBuffer;
    UINT32 ResponseBufferSize;
    volatile UINT32 ResponseSize;
    UINT64 EnqueueTime;
    volatile BOOLEAN Completed;
    BOOLEAN Cancelled;
    UINT8 Reserved[6];
} MQ_PENDING_COMPLETION, *PMQ_PENDING_COMPLETION;

// ============================================================================
// GLOBAL STATE
// ============================================================================

/**
 * @brief Global message queue state.
 */
static MESSAGE_QUEUE_GLOBALS g_MqGlobals = {0};

/**
 * @brief Pending completion list for blocking messages.
 */
static LIST_ENTRY g_PendingCompletionList;
static KSPIN_LOCK g_PendingCompletionLock;
static volatile LONG g_PendingCompletionCount = 0;
static NPAGED_LOOKASIDE_LIST g_PendingCompletionLookaside;

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
MqpFreePendingCompletion(
    _In_ PMQ_PENDING_COMPLETION Completion
    );

static PMQ_PENDING_COMPLETION
MqpFindPendingCompletion(
    _In_ UINT64 MessageId
    );

static VOID
MqpRemovePendingCompletion(
    _In_ PMQ_PENDING_COMPLETION Completion
    );

static VOID
MqpCleanupExpiredCompletions(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
MqpWorkerThread(
    _In_ PVOID Context
    );

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

// ============================================================================
// INITIALIZATION AND SHUTDOWN
// ============================================================================

/**
 * @brief Initialize the message queue subsystem.
 *
 * Must be called at PASSIVE_LEVEL during driver initialization.
 * Allocates all required resources and initializes synchronization objects.
 *
 * @return STATUS_SUCCESS on success, error code on failure.
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
    ULONG i;

    PAGED_CODE();

    //
    // Check if already initialized
    //
    if (g_MqGlobals.Initialized) {
        return STATUS_ALREADY_REGISTERED;
    }

    //
    // Zero out global state
    //
    RtlZeroMemory(&g_MqGlobals, sizeof(g_MqGlobals));

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

    //
    // Initialize message lookaside list
    // We allocate enough for a typical message plus some overhead
    //
    ExInitializeNPagedLookasideList(
        &g_MqGlobals.MessageLookaside,
        NULL,   // Allocate function (use default)
        NULL,   // Free function (use default)
        POOL_NX_ALLOCATION,
        MQ_MESSAGE_ALLOC_SIZE(1024),  // Typical small message
        MQ_TAG_MESSAGE,
        0       // Depth (let system manage)
    );

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
        MQ_TAG_PENDING,
        0
    );

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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike/MQ] Failed to create worker thread: 0x%08X\n", status);
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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike/MQ] Failed to reference worker thread: 0x%08X\n", status);
        g_MqGlobals.WorkerStopping = TRUE;
        KeSetEvent(&g_MqGlobals.WorkerStopEvent, IO_NO_INCREMENT, FALSE);
        goto Cleanup;
    }

    //
    // Mark as initialized
    //
    g_MqGlobals.Initialized = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MQ] Message queue initialized (depth=%u, msgSize=%u)\n",
               g_MqGlobals.MaxQueueDepth, g_MqGlobals.MaxMessageSize);

    return STATUS_SUCCESS;

Cleanup:
    //
    // Cleanup on failure
    //
    ExDeleteNPagedLookasideList(&g_MqGlobals.MessageLookaside);
    ExDeleteNPagedLookasideList(&g_PendingCompletionLookaside);

    RtlZeroMemory(&g_MqGlobals, sizeof(g_MqGlobals));

    return status;
}

/**
 * @brief Shutdown the message queue subsystem.
 *
 * Drains all pending messages, completes outstanding blocking requests
 * with STATUS_CANCELLED, and releases all resources.
 *
 * Must be called at PASSIVE_LEVEL during driver unload.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
MqShutdown(
    VOID
    )
{
    ULONG i;
    PLIST_ENTRY entry;
    PQUEUED_MESSAGE message;
    PMQ_PENDING_COMPLETION completion;
    KIRQL oldIrql;
    LARGE_INTEGER timeout;

    PAGED_CODE();

    if (!g_MqGlobals.Initialized) {
        return;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MQ] Shutting down message queue...\n");

    //
    // Signal worker thread to stop
    //
    g_MqGlobals.WorkerStopping = TRUE;
    KeSetEvent(&g_MqGlobals.WorkerStopEvent, IO_NO_INCREMENT, FALSE);
    KeSetEvent(&g_MqGlobals.MessageAvailableEvent, IO_NO_INCREMENT, FALSE);

    //
    // Wait for worker thread to exit (max 5 seconds)
    //
    if (g_MqGlobals.WorkerThread != NULL) {
        timeout.QuadPart = -50000000LL;  // 5 seconds
        KeWaitForSingleObject(
            g_MqGlobals.WorkerThread,
            Executive,
            KernelMode,
            FALSE,
            &timeout
        );

        ObDereferenceObject(g_MqGlobals.WorkerThread);
        g_MqGlobals.WorkerThread = NULL;
    }

    //
    // Cancel all pending completions
    //
    KeAcquireSpinLock(&g_PendingCompletionLock, &oldIrql);

    while (!IsListEmpty(&g_PendingCompletionList)) {
        entry = RemoveHeadList(&g_PendingCompletionList);
        completion = CONTAINING_RECORD(entry, MQ_PENDING_COMPLETION, ListEntry);

        completion->CompletionStatus = STATUS_CANCELLED;
        completion->Cancelled = TRUE;
        KeSetEvent(&completion->CompletionEvent, IO_NO_INCREMENT, FALSE);
    }

    KeReleaseSpinLock(&g_PendingCompletionLock, oldIrql);

    //
    // Give pending completions time to wake up (100ms)
    //
    timeout.QuadPart = -1000000LL;
    KeDelayExecutionThread(KernelMode, FALSE, &timeout);

    //
    // Drain all priority queues
    //
    for (i = 0; i < MessagePriority_Max; i++) {
        KeAcquireSpinLock(&g_MqGlobals.Queues[i].Lock, &oldIrql);

        while (!IsListEmpty(&g_MqGlobals.Queues[i].MessageList)) {
            entry = RemoveHeadList(&g_MqGlobals.Queues[i].MessageList);
            message = CONTAINING_RECORD(entry, QUEUED_MESSAGE, ListEntry);

            //
            // If blocking message, signal completion with cancelled status
            //
            if (MQ_IS_BLOCKING_MESSAGE(message) && message->CompletionEvent != NULL) {
                if (message->CompletionStatus != NULL) {
                    *message->CompletionStatus = STATUS_CANCELLED;
                }
                KeSetEvent(message->CompletionEvent, IO_NO_INCREMENT, FALSE);
            }

            MqpFreeMessageInternal(message);
        }

        g_MqGlobals.Queues[i].Count = 0;

        KeReleaseSpinLock(&g_MqGlobals.Queues[i].Lock, oldIrql);
    }

    g_MqGlobals.TotalMessageCount = 0;

    //
    // Free batch buffer if allocated
    //
    if (g_MqGlobals.CurrentBatch != NULL) {
        ExFreePoolWithTag(g_MqGlobals.CurrentBatch, MQ_TAG_BATCH);
        g_MqGlobals.CurrentBatch = NULL;
    }

    //
    // Delete lookaside lists
    //
    ExDeleteNPagedLookasideList(&g_MqGlobals.MessageLookaside);
    ExDeleteNPagedLookasideList(&g_PendingCompletionLookaside);

    //
    // Log final statistics
    //
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MQ] Final stats: Enqueued=%llu, Dequeued=%llu, Dropped=%llu\n",
               g_MqGlobals.TotalMessagesEnqueued,
               g_MqGlobals.TotalMessagesDequeued,
               g_MqGlobals.TotalMessagesDropped);

    //
    // Clear state
    //
    g_MqGlobals.Initialized = FALSE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MQ] Message queue shutdown complete\n");
}

/**
 * @brief Configure the message queue parameters.
 *
 * Can be called at runtime to adjust queue parameters. Will not affect
 * messages already in the queue.
 *
 * @param MaxQueueDepth Maximum total messages across all priority queues.
 * @param MaxMessageSize Maximum size of a single message.
 * @param BatchSize Number of messages to batch for delivery.
 * @param BatchTimeoutMs Maximum time to wait before flushing a batch.
 *
 * @return STATUS_SUCCESS or STATUS_INVALID_PARAMETER.
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
    // Update configuration atomically where possible
    //
    InterlockedExchange((volatile LONG*)&g_MqGlobals.MaxQueueDepth, MaxQueueDepth);
    InterlockedExchange((volatile LONG*)&g_MqGlobals.MaxMessageSize, MaxMessageSize);
    InterlockedExchange((volatile LONG*)&g_MqGlobals.BatchSize, BatchSize);
    InterlockedExchange((volatile LONG*)&g_MqGlobals.BatchTimeoutMs, BatchTimeoutMs);

    //
    // Update water marks (80% / 50% of new depth)
    //
    InterlockedExchange((volatile LONG*)&g_MqGlobals.HighWaterMark, (MaxQueueDepth * 80) / 100);
    InterlockedExchange((volatile LONG*)&g_MqGlobals.LowWaterMark, (MaxQueueDepth * 50) / 100);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MQ] Reconfigured: depth=%u, msgSize=%u, batch=%u\n",
               MaxQueueDepth, MaxMessageSize, BatchSize);

    return STATUS_SUCCESS;
}

// ============================================================================
// MESSAGE OPERATIONS
// ============================================================================

/**
 * @brief Enqueue a message to the appropriate priority queue.
 *
 * This is the core message enqueue function. Messages are placed in the
 * appropriate priority queue and the consumer is signaled.
 *
 * @param MessageType Type of message being enqueued.
 * @param MessageData Pointer to message payload data.
 * @param MessageSize Size of message payload in bytes.
 * @param Priority Priority level for the message.
 * @param Flags Message flags (blocking, notify-only, etc.).
 * @param MessageId Optional output for the assigned message ID.
 *
 * @return STATUS_SUCCESS, STATUS_INSUFFICIENT_RESOURCES, or STATUS_DEVICE_BUSY.
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

    //
    // Initialize output
    //
    if (MessageId != NULL) {
        *MessageId = 0;
    }

    //
    // Validate state
    //
    if (!g_MqGlobals.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Validate parameters
    //
    if (MessageData == NULL && MessageSize > 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (MessageSize > g_MqGlobals.MaxMessageSize) {
        return STATUS_BUFFER_OVERFLOW;
    }

    if (Priority >= MessagePriority_Max) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Check queue depth (unless high priority which bypasses check)
    //
    currentDepth = g_MqGlobals.TotalMessageCount;
    if (currentDepth >= (LONG)g_MqGlobals.MaxQueueDepth) {
        if (Priority < MessagePriority_High) {
            InterlockedIncrement64(&g_MqGlobals.TotalMessagesDropped);
            return STATUS_DEVICE_BUSY;
        }
        // High/Critical priority messages always get through
    }

    //
    // Allocate message structure
    //
    message = MqpAllocateMessage(MessageSize);
    if (message == NULL) {
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
    message->CompletionEvent = NULL;
    message->CompletionStatus = NULL;
    message->ResponseBuffer = NULL;
    message->ResponseBufferSize = 0;
    message->ResponseSize = NULL;

    //
    // Copy message data
    //
    if (MessageSize > 0 && MessageData != NULL) {
        RtlCopyMemory(message->Data, MessageData, MessageSize);
    }

    //
    // Enqueue to appropriate priority queue
    //
    status = MqpEnqueueToPriorityQueue(message);
    if (!NT_SUCCESS(status)) {
        MqpFreeMessageInternal(message);
        return status;
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&g_MqGlobals.TotalMessagesEnqueued);
    InterlockedAdd64(&g_MqGlobals.TotalBytesEnqueued, MessageSize);

    //
    // Check high water mark
    //
    currentDepth = g_MqGlobals.TotalMessageCount;
    if (currentDepth >= (LONG)g_MqGlobals.HighWaterMark && !g_MqGlobals.FlowControlActive) {
        g_MqGlobals.FlowControlActive = TRUE;
        g_MqGlobals.LastFlowControlTime = MqpGetCurrentTimeMs();
        KeSetEvent(&g_MqGlobals.HighWaterMarkEvent, IO_NO_INCREMENT, FALSE);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MQ] High water mark reached: %d messages\n", currentDepth);
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
 * This function enqueues a message that requires a response from user-mode.
 * The calling thread blocks until either:
 * - A response is received via MqCompleteMessage()
 * - The timeout expires
 * - The queue is shut down
 *
 * IMPORTANT: Cannot be called at IRQL > PASSIVE_LEVEL as it waits.
 *
 * @param MessageType Type of message being enqueued.
 * @param MessageData Pointer to message payload data.
 * @param MessageSize Size of message payload in bytes.
 * @param Priority Priority level for the message.
 * @param ResponseBuffer Buffer to receive the response.
 * @param ResponseBufferSize Size of response buffer in bytes.
 * @param ResponseSize Receives actual response size.
 * @param TimeoutMs Timeout in milliseconds (0 = infinite).
 *
 * @return STATUS_SUCCESS, STATUS_TIMEOUT, STATUS_CANCELLED, etc.
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

    PAGED_CODE();

    //
    // Initialize outputs
    //
    *ResponseSize = 0;

    //
    // Validate state
    //
    if (!g_MqGlobals.Initialized) {
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

    if (MessageSize > g_MqGlobals.MaxMessageSize) {
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
    // Allocate message
    //
    message = MqpAllocateMessage(MessageSize);
    if (message == NULL) {
        MqpFreePendingCompletion(pendingCompletion);
        InterlockedIncrement64(&g_MqGlobals.TotalMessagesDropped);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize pending completion
    //
    pendingCompletion->MessageId = (UINT64)InterlockedIncrement64(&g_MqGlobals.NextMessageId);
    KeInitializeEvent(&pendingCompletion->CompletionEvent, NotificationEvent, FALSE);
    pendingCompletion->CompletionStatus = STATUS_PENDING;
    pendingCompletion->ResponseBuffer = ResponseBuffer;
    pendingCompletion->ResponseBufferSize = ResponseBufferSize;
    pendingCompletion->ResponseSize = 0;
    pendingCompletion->EnqueueTime = MqpGetCurrentTimeMs();
    pendingCompletion->Completed = FALSE;
    pendingCompletion->Cancelled = FALSE;

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
    message->CompletionEvent = &pendingCompletion->CompletionEvent;
    message->CompletionStatus = &pendingCompletion->CompletionStatus;
    message->ResponseBuffer = ResponseBuffer;
    message->ResponseBufferSize = ResponseBufferSize;
    message->ResponseSize = &pendingCompletion->ResponseSize;

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
    KeReleaseSpinLock(&g_PendingCompletionLock, oldIrql);

    //
    // Enqueue message
    //
    status = MqpEnqueueToPriorityQueue(message);
    if (!NT_SUCCESS(status)) {
        //
        // Remove pending completion on failure
        //
        KeAcquireSpinLock(&g_PendingCompletionLock, &oldIrql);
        RemoveEntryList(&pendingCompletion->ListEntry);
        InterlockedDecrement(&g_PendingCompletionCount);
        KeReleaseSpinLock(&g_PendingCompletionLock, oldIrql);

        MqpFreePendingCompletion(pendingCompletion);
        MqpFreeMessageInternal(message);
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
        //
        // Infinite wait
        //
        status = KeWaitForSingleObject(
            &pendingCompletion->CompletionEvent,
            Executive,
            KernelMode,
            FALSE,
            NULL
        );
    } else {
        //
        // Timed wait (negative value = relative)
        //
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
    // Handle wait result
    //
    if (status == STATUS_SUCCESS) {
        //
        // Completion was signaled - get result
        //
        status = pendingCompletion->CompletionStatus;
        *ResponseSize = pendingCompletion->ResponseSize;
    } else if (status == STATUS_TIMEOUT) {
        //
        // Timeout - mark as timed out
        //
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MQ] Blocking message timeout (id=%llu, timeout=%ums)\n",
                   pendingCompletion->MessageId, TimeoutMs);
        status = STATUS_TIMEOUT;
    } else {
        //
        // Other wait failure (e.g., thread alerted)
        //
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MQ] Wait failed for message id=%llu: 0x%08X\n",
                   pendingCompletion->MessageId, status);
    }

    //
    // Remove from pending list and free
    //
    MqpRemovePendingCompletion(pendingCompletion);
    MqpFreePendingCompletion(pendingCompletion);

    return status;
}

/**
 * @brief Dequeue a single message from the queue.
 *
 * Dequeues the highest priority message available. Priority order is:
 * Critical > High > Normal > Low.
 *
 * @param Message Receives pointer to dequeued message. Caller must free
 *                with MqFreeMessage() when done.
 * @param TimeoutMs Timeout in milliseconds (0 = no wait).
 *
 * @return STATUS_SUCCESS, STATUS_TIMEOUT, or error code.
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
    if (!g_MqGlobals.Initialized) {
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
    // Try to dequeue again
    //
    message = MqpDequeueFromPriorityQueues();
    if (message == NULL) {
        //
        // Spurious wakeup - event was signaled but no message
        // (could happen during shutdown or race condition)
        //
        return STATUS_NO_MORE_ENTRIES;
    }

    *Message = message;
    InterlockedIncrement64(&g_MqGlobals.TotalMessagesDequeued);
    InterlockedAdd64(&g_MqGlobals.TotalBytesDequeued, message->MessageSize);

    //
    // Check low water mark - reset flow control
    //
    if (g_MqGlobals.FlowControlActive) {
        LONG depth = g_MqGlobals.TotalMessageCount;
        if (depth <= (LONG)g_MqGlobals.LowWaterMark) {
            g_MqGlobals.FlowControlActive = FALSE;
            KeClearEvent(&g_MqGlobals.HighWaterMarkEvent);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[ShadowStrike/MQ] Low water mark reached: %d messages, flow control released\n", depth);
        }
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Dequeue a batch of messages.
 *
 * Efficiently dequeues up to MaxMessages in a single operation.
 * Messages are returned in priority order (highest first).
 *
 * @param Messages Array to receive message pointers.
 * @param MaxMessages Maximum messages to dequeue.
 * @param MessageCount Receives actual number dequeued.
 * @param TimeoutMs Timeout for first message (0 = no wait).
 *
 * @return STATUS_SUCCESS or error code.
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
    if (!g_MqGlobals.Initialized) {
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

    //
    // Update batch statistics
    //
    if (count > 1) {
        InterlockedIncrement64(&g_MqGlobals.TotalBatchesSent);
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Free a dequeued message.
 *
 * Must be called to release a message obtained from MqDequeueMessage
 * or MqDequeueBatch.
 *
 * @param Message Message to free.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
MqFreeMessage(
    _In_ PQUEUED_MESSAGE Message
    )
{
    if (Message != NULL) {
        MqpFreeMessageInternal(Message);
    }
}

/**
 * @brief Complete a blocking message with response data.
 *
 * Called by the consumer (typically CommPort message handler) when
 * a response is received from user-mode for a blocking message.
 *
 * @param MessageId ID of the message being completed.
 * @param Status Completion status.
 * @param ResponseData Response data to copy to waiting thread.
 * @param ResponseSize Size of response data.
 *
 * @return STATUS_SUCCESS or STATUS_NOT_FOUND if MessageId not found.
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

    //
    // Find pending completion
    //
    completion = MqpFindPendingCompletion(MessageId);
    if (completion == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MQ] CompleteMessage: id=%llu not found\n", MessageId);
        return STATUS_NOT_FOUND;
    }

    //
    // Check if already completed
    //
    if (completion->Completed || completion->Cancelled) {
        return STATUS_ALREADY_COMPLETE;
    }

    //
    // Copy response data
    //
    if (ResponseData != NULL && ResponseSize > 0 && completion->ResponseBuffer != NULL) {
        copySize = min(ResponseSize, completion->ResponseBufferSize);
        RtlCopyMemory(completion->ResponseBuffer, ResponseData, copySize);
        completion->ResponseSize = copySize;
    } else {
        completion->ResponseSize = 0;
    }

    //
    // Set completion status
    //
    completion->CompletionStatus = Status;
    completion->Completed = TRUE;

    //
    // Signal completion event
    //
    KeSetEvent(&completion->CompletionEvent, IO_NO_INCREMENT, FALSE);

    return STATUS_SUCCESS;
}

// ============================================================================
// FLOW CONTROL
// ============================================================================

/**
 * @brief Check if queue is at high water mark.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
MqIsHighWaterMark(
    VOID
    )
{
    return g_MqGlobals.FlowControlActive;
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
    return (!g_MqGlobals.FlowControlActive &&
            g_MqGlobals.TotalMessageCount <= (LONG)g_MqGlobals.LowWaterMark);
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
 * @brief Wait for queue space to become available.
 *
 * Blocks until the queue drops below the high water mark or timeout.
 *
 * @param TimeoutMs Timeout in milliseconds.
 * @return STATUS_SUCCESS if space available, STATUS_TIMEOUT otherwise.
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

    if (!g_MqGlobals.FlowControlActive) {
        return STATUS_SUCCESS;
    }

    if (TimeoutMs == 0) {
        return STATUS_DEVICE_BUSY;
    }

    timeout.QuadPart = -(LONGLONG)TimeoutMs * 10000LL;

    //
    // Wait for flow control to be released
    // (HighWaterMarkEvent is cleared when we go below low water mark)
    //
    status = KeWaitForSingleObject(
        &g_MqGlobals.HighWaterMarkEvent,
        Executive,
        KernelMode,
        FALSE,
        &timeout
    );

    if (status == STATUS_TIMEOUT) {
        return STATUS_DEVICE_BUSY;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Flush all queued messages.
 *
 * @param Wait TRUE to wait for completion.
 * @return STATUS_SUCCESS.
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
 * @brief Allocate a message structure.
 *
 * Uses lookaside list for small messages, direct pool for large ones.
 */
static PQUEUED_MESSAGE
MqpAllocateMessage(
    _In_ UINT32 DataSize
    )
{
    PQUEUED_MESSAGE message;
    SIZE_T allocSize = MQ_MESSAGE_ALLOC_SIZE(DataSize);

    //
    // Use lookaside for typical small messages
    //
    if (allocSize <= MQ_MESSAGE_ALLOC_SIZE(1024)) {
        message = (PQUEUED_MESSAGE)ExAllocateFromNPagedLookasideList(&g_MqGlobals.MessageLookaside);
    } else {
        //
        // Direct allocation for larger messages
        //
        message = (PQUEUED_MESSAGE)ExAllocatePoolZero(NonPagedPoolNx, allocSize, MQ_TAG_MESSAGE);
    }

    if (message != NULL) {
        RtlZeroMemory(message, allocSize);
        InitializeListHead(&message->ListEntry);
    }

    return message;
}

/**
 * @brief Free a message structure.
 */
static VOID
MqpFreeMessageInternal(
    _In_ PQUEUED_MESSAGE Message
    )
{
    SIZE_T allocSize = MQ_MESSAGE_ALLOC_SIZE(Message->MessageSize);

    if (allocSize <= MQ_MESSAGE_ALLOC_SIZE(1024)) {
        ExFreeToNPagedLookasideList(&g_MqGlobals.MessageLookaside, Message);
    } else {
        ExFreePoolWithTag(Message, MQ_TAG_MESSAGE);
    }
}

/**
 * @brief Enqueue message to appropriate priority queue.
 */
static NTSTATUS
MqpEnqueueToPriorityQueue(
    _In_ PQUEUED_MESSAGE Message
    )
{
    PPRIORITY_QUEUE queue;
    KIRQL oldIrql;
    LONG newCount;
    LONG totalCount;

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

    //
    // Update total count
    //
    totalCount = InterlockedIncrement(&g_MqGlobals.TotalMessageCount);
    if (totalCount > g_MqGlobals.PeakMessageCount) {
        InterlockedExchange(&g_MqGlobals.PeakMessageCount, totalCount);
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Dequeue highest priority message.
 *
 * Checks queues in priority order: Critical, High, Normal, Low.
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
 */
static PMQ_PENDING_COMPLETION
MqpAllocatePendingCompletion(
    VOID
    )
{
    PMQ_PENDING_COMPLETION completion;

    completion = (PMQ_PENDING_COMPLETION)ExAllocateFromNPagedLookasideList(&g_PendingCompletionLookaside);
    if (completion != NULL) {
        RtlZeroMemory(completion, sizeof(MQ_PENDING_COMPLETION));
        InitializeListHead(&completion->ListEntry);
    }

    return completion;
}

/**
 * @brief Free pending completion structure.
 */
static VOID
MqpFreePendingCompletion(
    _In_ PMQ_PENDING_COMPLETION Completion
    )
{
    ExFreeToNPagedLookasideList(&g_PendingCompletionLookaside, Completion);
}

/**
 * @brief Find pending completion by message ID.
 */
static PMQ_PENDING_COMPLETION
MqpFindPendingCompletion(
    _In_ UINT64 MessageId
    )
{
    PMQ_PENDING_COMPLETION completion = NULL;
    PLIST_ENTRY entry;
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_PendingCompletionLock, &oldIrql);

    for (entry = g_PendingCompletionList.Flink;
         entry != &g_PendingCompletionList;
         entry = entry->Flink)
    {
        completion = CONTAINING_RECORD(entry, MQ_PENDING_COMPLETION, ListEntry);
        if (completion->MessageId == MessageId) {
            break;
        }
        completion = NULL;
    }

    KeReleaseSpinLock(&g_PendingCompletionLock, oldIrql);

    return completion;
}

/**
 * @brief Remove pending completion from tracking list.
 */
static VOID
MqpRemovePendingCompletion(
    _In_ PMQ_PENDING_COMPLETION Completion
    )
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_PendingCompletionLock, &oldIrql);

    if (!IsListEmpty(&Completion->ListEntry)) {
        RemoveEntryList(&Completion->ListEntry);
        InterlockedDecrement(&g_PendingCompletionCount);
        InitializeListHead(&Completion->ListEntry);
    }

    KeReleaseSpinLock(&g_PendingCompletionLock, oldIrql);
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

    KeAcquireSpinLock(&g_PendingCompletionLock, &oldIrql);

    for (entry = g_PendingCompletionList.Flink;
         entry != &g_PendingCompletionList;
         entry = nextEntry)
    {
        nextEntry = entry->Flink;
        completion = CONTAINING_RECORD(entry, MQ_PENDING_COMPLETION, ListEntry);

        //
        // Check if expired (30 second default)
        //
        if ((currentTime - completion->EnqueueTime) > timeout) {
            if (!completion->Completed && !completion->Cancelled) {
                //
                // Mark as timed out and signal
                //
                completion->CompletionStatus = STATUS_TIMEOUT;
                completion->Cancelled = TRUE;
                KeSetEvent(&completion->CompletionEvent, IO_NO_INCREMENT, FALSE);

                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike/MQ] Expired pending completion: id=%llu, age=%llums\n",
                           completion->MessageId, currentTime - completion->EnqueueTime);
            }
        }
    }

    KeReleaseSpinLock(&g_PendingCompletionLock, oldIrql);
}

/**
 * @brief Worker thread for maintenance operations.
 *
 * Periodically:
 * - Cleans up expired pending completions
 * - Flushes batch buffer on timeout
 * - Monitors queue health
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

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MQ] Worker thread started\n");

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

        if (status == STATUS_SUCCESS) {
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
            // Log statistics if at high water mark
            //
            if (g_MqGlobals.FlowControlActive) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike/MQ] High load: depth=%d, enqueued=%llu, dropped=%llu\n",
                           g_MqGlobals.TotalMessageCount,
                           g_MqGlobals.TotalMessagesEnqueued,
                           g_MqGlobals.TotalMessagesDropped);
            }
        }
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MQ] Worker thread exiting\n");

    PsTerminateSystemThread(STATUS_SUCCESS);
}