/**
 * ============================================================================
 * ShadowStrike NGAV - MESSAGE QUEUE
 * ============================================================================
 *
 * @file MessageQueue.h
 * @brief Asynchronous message queue for kernel<->user communication.
 *
 * This module provides a high-performance, thread-safe message queue for
 * asynchronous communication between the kernel driver and user-mode service.
 *
 * Features:
 * - Lock-free operations where possible
 * - Priority-based message ordering
 * - Batched message delivery
 * - Overflow protection with atomic slot reservation
 * - Statistics and monitoring
 * - Reference-counted blocking message completions
 *
 * Thread Safety:
 * - Per-priority spinlocks minimize contention
 * - Lock ordering: Priority locks acquired in ascending order to prevent deadlock
 * - Statistics use interlocked operations (no locks)
 * - Blocking message completions are reference-counted for safe lifetime management
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

#ifndef SHADOWSTRIKE_MESSAGE_QUEUE_H
#define SHADOWSTRIKE_MESSAGE_QUEUE_H

#include <fltKernel.h>
#include "../../Shared/MessageTypes.h"
#include "../../Shared/BehaviorTypes.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// BUILD CONFIGURATION
// ============================================================================

/**
 * @brief Debug output control.
 *
 * Define MQ_DEBUG_OUTPUT=1 in debug builds to enable diagnostic logging.
 * Production builds MUST NOT define this to prevent information disclosure.
 */
#ifndef MQ_DEBUG_OUTPUT
#if DBG
#define MQ_DEBUG_OUTPUT 1
#else
#define MQ_DEBUG_OUTPUT 0
#endif
#endif

#if MQ_DEBUG_OUTPUT
#define MQ_LOG_ERROR(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[ShadowStrike/MQ] " fmt "\n", ##__VA_ARGS__)
#define MQ_LOG_WARNING(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "[ShadowStrike/MQ] " fmt "\n", ##__VA_ARGS__)
#define MQ_LOG_INFO(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[ShadowStrike/MQ] " fmt "\n", ##__VA_ARGS__)
#define MQ_LOG_TRACE(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "[ShadowStrike/MQ] " fmt "\n", ##__VA_ARGS__)
#else
#define MQ_LOG_ERROR(fmt, ...)   ((void)0)
#define MQ_LOG_WARNING(fmt, ...) ((void)0)
#define MQ_LOG_INFO(fmt, ...)    ((void)0)
#define MQ_LOG_TRACE(fmt, ...)   ((void)0)
#endif

// ============================================================================
// MESSAGE QUEUE CONFIGURATION
// ============================================================================

/**
 * @brief Pool tags for memory allocation tracking.
 */
#define MQ_POOL_TAG_GENERAL     'qMsS'
#define MQ_POOL_TAG_MESSAGE     'mMsS'
#define MQ_POOL_TAG_BATCH       'bMsS'
#define MQ_POOL_TAG_COMPLETION  'cMsS'

/**
 * @brief Default configuration values.
 */
#define MQ_DEFAULT_MAX_QUEUE_DEPTH      100000
#define MQ_DEFAULT_MAX_MESSAGE_SIZE     (64 * 1024)  // 64KB
#define MQ_DEFAULT_BATCH_SIZE           100
#define MQ_DEFAULT_BATCH_TIMEOUT_MS     100
#define MQ_DEFAULT_HIGH_WATER_MARK      80000
#define MQ_DEFAULT_LOW_WATER_MARK       50000

/**
 * @brief Safety limits.
 */
#define MQ_MAX_QUEUE_DEPTH_LIMIT        1000000
#define MQ_MAX_MESSAGE_SIZE_LIMIT       (1024 * 1024)   // 1MB absolute max
#define MQ_MIN_BATCH_SIZE               1
#define MQ_MAX_BATCH_SIZE               1000
#define MQ_MAX_PENDING_COMPLETIONS      50000
#define MQ_MAX_RESPONSE_SIZE            (64 * 1024)     // 64KB max response

/**
 * @brief Message priorities.
 */
typedef enum _MESSAGE_PRIORITY {
    MessagePriority_Low = 0,
    MessagePriority_Normal = 1,
    MessagePriority_High = 2,
    MessagePriority_Critical = 3,
    MessagePriority_Max
} MESSAGE_PRIORITY;

// ============================================================================
// MESSAGE STRUCTURES
// ============================================================================

/**
 * @brief Allocation source tracking for safe deallocation.
 */
typedef enum _MQ_ALLOC_SOURCE {
    MqAllocSource_Invalid = 0,
    MqAllocSource_Lookaside = 1,
    MqAllocSource_Pool = 2
} MQ_ALLOC_SOURCE;

/**
 * @brief Magic value for allocation validation.
 */
#define MQ_MESSAGE_MAGIC        0x51534D53  // 'SMSQ'
#define MQ_COMPLETION_MAGIC     0x504D4F43  // 'COMP'

/**
 * @brief Queued message entry.
 *
 * Represents a message in the priority queue. Messages are allocated from
 * either a lookaside list (small messages) or pool (large messages).
 * The AllocSource field tracks the allocation source for safe deallocation.
 */
typedef struct _QUEUED_MESSAGE {
    // Allocation tracking (MUST be first for validation)
    UINT32 Magic;
    MQ_ALLOC_SOURCE AllocSource;

    LIST_ENTRY ListEntry;

    // Message identification
    UINT64 MessageId;
    UINT64 EnqueueTime;

    // Message metadata
    SHADOWSTRIKE_MESSAGE_TYPE MessageType;
    MESSAGE_PRIORITY Priority;
    UINT32 MessageSize;
    UINT32 Flags;

    // Source info
    UINT32 ProcessId;
    UINT32 ThreadId;

    // For blocking messages: ID to look up completion structure
    // The completion structure is reference-counted and managed separately
    UINT64 CompletionId;

    // Message data follows (flexible array)
    UINT8 Data[ANYSIZE_ARRAY];
} QUEUED_MESSAGE, *PQUEUED_MESSAGE;

// Message flags
#define MQ_MSG_FLAG_BLOCKING              0x00000001  // Requires response
#define MQ_MSG_FLAG_HIGH_PRIORITY         0x00000002  // Skip queue on high load
#define MQ_MSG_FLAG_NOTIFY_ONLY           0x00000004  // No response needed
#define MQ_MSG_FLAG_BATCHED               0x00000008  // Can be batched
#define MQ_MSG_FLAG_COMPLETED             0x00000010  // Processing complete
#define MQ_MSG_FLAG_TIMED_OUT             0x00000020  // Timed out

/**
 * @brief Message batch for efficient delivery.
 */
typedef struct _MESSAGE_BATCH {
    UINT64 BatchId;
    UINT64 CreateTime;
    UINT32 MessageCount;
    UINT32 TotalSize;
    UINT32 Flags;
    UINT32 Reserved;
    // Variable: Messages follow
} MESSAGE_BATCH, *PMESSAGE_BATCH;

// ============================================================================
// MESSAGE QUEUE STATE
// ============================================================================

/**
 * @brief Per-priority queue.
 */
typedef struct _PRIORITY_QUEUE {
    LIST_ENTRY MessageList;
    KSPIN_LOCK Lock;
    volatile LONG Count;
    volatile LONG PeakCount;
} PRIORITY_QUEUE, *PPRIORITY_QUEUE;

/**
 * @brief Flow control state values for atomic operations.
 */
#define MQ_FLOW_CONTROL_INACTIVE    0
#define MQ_FLOW_CONTROL_ACTIVE      1

/**
 * @brief Subsystem state values.
 */
typedef enum _MQ_STATE {
    MqState_Uninitialized = 0,
    MqState_Initializing = 1,
    MqState_Running = 2,
    MqState_ShuttingDown = 3,
    MqState_Shutdown = 4
} MQ_STATE;

/**
 * @brief Message queue global state.
 */
typedef struct _MESSAGE_QUEUE_GLOBALS {
    // Initialization state (atomic)
    volatile LONG State;
    UINT8 Reserved1[4];

    // Configuration (updated atomically)
    volatile LONG MaxQueueDepth;
    volatile LONG MaxMessageSize;
    volatile LONG BatchSize;
    volatile LONG BatchTimeoutMs;
    volatile LONG HighWaterMark;
    volatile LONG LowWaterMark;

    // Priority queues
    PRIORITY_QUEUE Queues[MessagePriority_Max];
    volatile LONG TotalMessageCount;
    volatile LONG PeakMessageCount;

    // Message ID generator
    volatile LONG64 NextMessageId;

    // Completion ID generator (separate from message ID)
    volatile LONG64 NextCompletionId;

    // Batch buffer
    PMESSAGE_BATCH CurrentBatch;
    KSPIN_LOCK BatchLock;
    UINT64 BatchStartTime;

    // Consumer notification
    KEVENT MessageAvailableEvent;
    KEVENT BatchReadyEvent;
    KEVENT HighWaterMarkEvent;      // Signaled when AT high water mark
    KEVENT SpaceAvailableEvent;     // Signaled when BELOW low water mark

    // Lookaside list for messages
    NPAGED_LOOKASIDE_LIST MessageLookaside;
    BOOLEAN MessageLookasideInitialized;
    UINT8 Reserved2[7];

    // Statistics
    volatile LONG64 TotalMessagesEnqueued;
    volatile LONG64 TotalMessagesDequeued;
    volatile LONG64 TotalMessagesDropped;
    volatile LONG64 TotalBatchesSent;
    volatile LONG64 TotalBytesEnqueued;
    volatile LONG64 TotalBytesDequeued;

    // Flow control state (atomic: 0=inactive, 1=active)
    volatile LONG FlowControlActive;
    UINT8 Reserved3[4];
    UINT64 LastFlowControlTime;

    // Worker thread
    PETHREAD WorkerThread;
    KEVENT WorkerStopEvent;
    volatile LONG WorkerStopping;
    UINT8 Reserved4[4];

    // Outstanding completion tracking for safe shutdown
    volatile LONG OutstandingCompletions;
    KEVENT AllCompletionsReleasedEvent;
} MESSAGE_QUEUE_GLOBALS, *PMESSAGE_QUEUE_GLOBALS;

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the message queue.
 *
 * Must be called at PASSIVE_LEVEL before any other MQ functions.
 * Thread-safe: Uses atomic state transition.
 *
 * @return STATUS_SUCCESS on success.
 * @return STATUS_ALREADY_REGISTERED if already initialized.
 * @return STATUS_INSUFFICIENT_RESOURCES on allocation failure.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MqInitialize(VOID);

/**
 * @brief Shutdown the message queue.
 *
 * Drains all pending messages, cancels outstanding blocking requests,
 * and releases all resources. Waits for all outstanding completions
 * to be released before freeing memory.
 *
 * Must be called at PASSIVE_LEVEL during driver unload.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
MqShutdown(VOID);

/**
 * @brief Configure the message queue.
 *
 * Can be called at runtime to adjust queue parameters.
 * Changes take effect for new messages only.
 *
 * @param MaxQueueDepth Maximum queue depth (1 to MQ_MAX_QUEUE_DEPTH_LIMIT).
 * @param MaxMessageSize Maximum message size (1 to MQ_MAX_MESSAGE_SIZE_LIMIT).
 * @param BatchSize Batch size for delivery (MQ_MIN_BATCH_SIZE to MQ_MAX_BATCH_SIZE).
 * @param BatchTimeoutMs Batch timeout in milliseconds.
 * @return STATUS_SUCCESS on success.
 * @return STATUS_INVALID_PARAMETER if parameters out of range.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
MqConfigure(
    _In_ UINT32 MaxQueueDepth,
    _In_ UINT32 MaxMessageSize,
    _In_ UINT32 BatchSize,
    _In_ UINT32 BatchTimeoutMs
    );

// ============================================================================
// PUBLIC API - MESSAGE OPERATIONS
// ============================================================================

/**
 * @brief Enqueue a message.
 *
 * Adds a message to the appropriate priority queue. Uses atomic slot
 * reservation to enforce queue depth limits.
 *
 * @param MessageType Message type.
 * @param MessageData Message data (kernel-mode pointer).
 * @param MessageSize Message data size.
 * @param Priority Message priority.
 * @param Flags Message flags.
 * @param MessageId Output message ID (optional).
 * @return STATUS_SUCCESS on success.
 * @return STATUS_DEVICE_NOT_READY if not initialized.
 * @return STATUS_DEVICE_BUSY if queue full (non-high-priority).
 * @return STATUS_INSUFFICIENT_RESOURCES on allocation failure.
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
    );

/**
 * @brief Enqueue blocking message and wait for response.
 *
 * Enqueues a message that requires a response from user-mode.
 * The calling thread blocks until response received, timeout, or shutdown.
 *
 * Response data is copied into the caller's buffer under lock protection
 * to prevent race conditions.
 *
 * IMPORTANT: Must be called at PASSIVE_LEVEL only.
 *
 * @param MessageType Message type.
 * @param MessageData Message data (kernel-mode pointer).
 * @param MessageSize Message data size.
 * @param Priority Message priority.
 * @param ResponseBuffer Buffer for response (kernel-mode pointer).
 * @param ResponseBufferSize Response buffer size (max MQ_MAX_RESPONSE_SIZE).
 * @param ResponseSize Actual response size.
 * @param TimeoutMs Timeout in milliseconds (0 = infinite).
 * @return STATUS_SUCCESS on success.
 * @return STATUS_TIMEOUT if timeout expired.
 * @return STATUS_CANCELLED if shutdown in progress.
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
    );

/**
 * @brief Dequeue a single message.
 *
 * Dequeues the highest priority message available.
 * Caller must free with MqFreeMessage().
 *
 * @param Message Output message pointer.
 * @param TimeoutMs Timeout in milliseconds (0 = no wait).
 * @return STATUS_SUCCESS if message dequeued.
 * @return STATUS_TIMEOUT if timeout expired.
 * @return STATUS_NO_MORE_ENTRIES if no message and no wait.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MqDequeueMessage(
    _Out_ PQUEUED_MESSAGE* Message,
    _In_ UINT32 TimeoutMs
    );

/**
 * @brief Dequeue a batch of messages.
 *
 * Efficiently dequeues up to MaxMessages in a single operation.
 *
 * @param Messages Output array of message pointers.
 * @param MaxMessages Maximum messages to dequeue.
 * @param MessageCount Actual messages dequeued.
 * @param TimeoutMs Timeout for first message (0 = no wait).
 * @return STATUS_SUCCESS on success.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MqDequeueBatch(
    _Out_writes_to_(MaxMessages, *MessageCount) PQUEUED_MESSAGE* Messages,
    _In_ UINT32 MaxMessages,
    _Out_ PUINT32 MessageCount,
    _In_ UINT32 TimeoutMs
    );

/**
 * @brief Free a dequeued message.
 *
 * Must be called to release a message obtained from MqDequeueMessage
 * or MqDequeueBatch. Safe to call with NULL.
 *
 * @param Message Message to free (may be NULL).
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
MqFreeMessage(
    _In_opt_ PQUEUED_MESSAGE Message
    );

/**
 * @brief Complete a blocking message with response.
 *
 * Called by the consumer when a response is received from user-mode
 * for a blocking message. Response data is copied under lock protection.
 *
 * IMPORTANT: ResponseData must be a kernel-mode pointer. If completing
 * from an IOCTL handler, the caller must first copy user-mode data to
 * a kernel buffer with proper validation (ProbeForRead, try/except).
 *
 * @param MessageId Message ID from the dequeued message.
 * @param Status Completion status.
 * @param ResponseData Response data (kernel-mode pointer, may be NULL).
 * @param ResponseSize Response data size.
 * @return STATUS_SUCCESS on success.
 * @return STATUS_NOT_FOUND if MessageId not found or already completed.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
MqCompleteMessage(
    _In_ UINT64 MessageId,
    _In_ NTSTATUS Status,
    _In_reads_bytes_opt_(ResponseSize) PVOID ResponseData,
    _In_ UINT32 ResponseSize
    );

// ============================================================================
// PUBLIC API - FLOW CONTROL
// ============================================================================

/**
 * @brief Check if queue is at high water mark.
 * @return TRUE if at high water mark.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
MqIsHighWaterMark(VOID);

/**
 * @brief Check if queue is at low water mark.
 * @return TRUE if at low water mark.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
MqIsLowWaterMark(VOID);

/**
 * @brief Get current queue depth.
 * @return Current queue depth.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
UINT32
MqGetQueueDepth(VOID);

/**
 * @brief Wait for queue space.
 *
 * Blocks until queue drops below low water mark or timeout.
 *
 * @param TimeoutMs Timeout in milliseconds.
 * @return STATUS_SUCCESS if space available.
 * @return STATUS_DEVICE_BUSY if timeout expired while still at high water.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MqWaitForSpace(
    _In_ UINT32 TimeoutMs
    );

/**
 * @brief Flush all queued messages.
 *
 * @param Wait TRUE to wait for queue to drain.
 * @return STATUS_SUCCESS if queue drained.
 * @return STATUS_TIMEOUT if Wait=TRUE and queue didn't drain in time.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MqFlush(
    _In_ BOOLEAN Wait
    );

// ============================================================================
// PUBLIC API - STATISTICS
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
    );

/**
 * @brief Reset statistics.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
MqResetStatistics(VOID);

// ============================================================================
// PUBLIC API - EVENTS (READ-ONLY ACCESS)
// ============================================================================

/**
 * @brief Wait for message available.
 *
 * Waits for the message available event. This is the safe way to wait
 * for messages - callers should use this instead of accessing events directly.
 *
 * @param TimeoutMs Timeout in milliseconds (0 = no wait, MAXULONG = infinite).
 * @return STATUS_SUCCESS if message available.
 * @return STATUS_TIMEOUT if timeout expired.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MqWaitForMessageAvailable(
    _In_ UINT32 TimeoutMs
    );

/**
 * @brief Get event for message available notification.
 *
 * WARNING: Returned event is for WAITING ONLY. Callers must NOT
 * signal or clear this event. Prefer using MqWaitForMessageAvailable().
 *
 * @return Event object pointer.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
PKEVENT
MqGetMessageAvailableEvent(VOID);

/**
 * @brief Get event for batch ready notification.
 *
 * WARNING: Returned event is for WAITING ONLY.
 *
 * @return Event object pointer.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
PKEVENT
MqGetBatchReadyEvent(VOID);

/**
 * @brief Get event for high water mark notification.
 *
 * WARNING: Returned event is for WAITING ONLY.
 *
 * @return Event object pointer.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
PKEVENT
MqGetHighWaterMarkEvent(VOID);

// ============================================================================
// HELPER MACROS
// ============================================================================

/**
 * @brief Calculate message allocation size with overflow check.
 *
 * Returns 0 on overflow, which will cause allocation to fail safely.
 */
FORCEINLINE
SIZE_T
MqCalculateMessageAllocSize(
    _In_ UINT32 DataSize
    )
{
    SIZE_T baseSize = FIELD_OFFSET(QUEUED_MESSAGE, Data);
    SIZE_T totalSize;

    // Check for overflow
    if (DataSize > (SIZE_T)(-1) - baseSize) {
        return 0;  // Overflow - return 0 to cause allocation failure
    }

    totalSize = baseSize + (SIZE_T)DataSize;
    return totalSize;
}

/**
 * @brief Legacy macro for compatibility (prefer MqCalculateMessageAllocSize).
 */
#define MQ_MESSAGE_ALLOC_SIZE(dataSize) \
    ((SIZE_T)(FIELD_OFFSET(QUEUED_MESSAGE, Data) + (SIZE_T)(dataSize)))

/**
 * @brief Check if message is blocking.
 */
#define MQ_IS_BLOCKING_MESSAGE(msg) \
    (((msg)->Flags & MQ_MSG_FLAG_BLOCKING) != 0)

/**
 * @brief Check if message can be batched.
 */
#define MQ_CAN_BATCH_MESSAGE(msg) \
    (((msg)->Flags & MQ_MSG_FLAG_BATCHED) != 0)

/**
 * @brief Validate message magic.
 */
#define MQ_IS_VALID_MESSAGE(msg) \
    ((msg) != NULL && (msg)->Magic == MQ_MESSAGE_MAGIC)

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_MESSAGE_QUEUE_H
