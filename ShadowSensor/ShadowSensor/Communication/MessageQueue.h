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
 * - Overflow protection
 * - Statistics and monitoring
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#pragma once

#include <fltKernel.h>
#include "../../Shared/MessageTypes.h"
#include "../../Shared/BehaviorTypes.h"

// ============================================================================
// MESSAGE QUEUE CONFIGURATION
// ============================================================================

/**
 * @brief Pool tags.
 */
#define MQ_POOL_TAG_GENERAL     'qMsS'
#define MQ_POOL_TAG_MESSAGE     'mMsS'
#define MQ_POOL_TAG_BATCH       'bMsS'

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
 * @brief Queued message entry.
 */
typedef struct _QUEUED_MESSAGE {
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
    
    // Completion (for blocking messages)
    KEVENT* CompletionEvent;
    NTSTATUS* CompletionStatus;
    PVOID ResponseBuffer;
    UINT32 ResponseBufferSize;
    UINT32* ResponseSize;
    
    // Message data follows
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
 * @brief Message queue global state.
 */
typedef struct _MESSAGE_QUEUE_GLOBALS {
    // Initialization state
    BOOLEAN Initialized;
    UINT8 Reserved1[3];
    
    // Configuration
    UINT32 MaxQueueDepth;
    UINT32 MaxMessageSize;
    UINT32 BatchSize;
    UINT32 BatchTimeoutMs;
    UINT32 HighWaterMark;
    UINT32 LowWaterMark;
    
    // Priority queues
    PRIORITY_QUEUE Queues[MessagePriority_Max];
    volatile LONG TotalMessageCount;
    volatile LONG PeakMessageCount;
    
    // Message ID generator
    volatile LONG64 NextMessageId;
    
    // Batch buffer
    PMESSAGE_BATCH CurrentBatch;
    KSPIN_LOCK BatchLock;
    UINT64 BatchStartTime;
    
    // Consumer notification
    KEVENT MessageAvailableEvent;
    KEVENT BatchReadyEvent;
    KEVENT HighWaterMarkEvent;
    
    // Lookaside list
    NPAGED_LOOKASIDE_LIST MessageLookaside;
    
    // Statistics
    volatile LONG64 TotalMessagesEnqueued;
    volatile LONG64 TotalMessagesDequeued;
    volatile LONG64 TotalMessagesDropped;
    volatile LONG64 TotalBatchesSent;
    volatile LONG64 TotalBytesEnqueued;
    volatile LONG64 TotalBytesDequeued;
    
    // Flow control state
    BOOLEAN FlowControlActive;
    UINT8 Reserved2[3];
    UINT64 LastFlowControlTime;
    
    // Worker thread
    PETHREAD WorkerThread;
    KEVENT WorkerStopEvent;
    BOOLEAN WorkerStopping;
    UINT8 Reserved3[7];
} MESSAGE_QUEUE_GLOBALS, *PMESSAGE_QUEUE_GLOBALS;

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the message queue.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
MqInitialize(VOID);

/**
 * @brief Shutdown the message queue.
 */
VOID
MqShutdown(VOID);

/**
 * @brief Configure the message queue.
 * @param MaxQueueDepth Maximum queue depth.
 * @param MaxMessageSize Maximum message size.
 * @param BatchSize Batch size for delivery.
 * @param BatchTimeoutMs Batch timeout in milliseconds.
 * @return STATUS_SUCCESS on success.
 */
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
 * @param MessageType Message type.
 * @param MessageData Message data.
 * @param MessageSize Message data size.
 * @param Priority Message priority.
 * @param Flags Message flags.
 * @param MessageId Output message ID.
 * @return STATUS_SUCCESS on success.
 */
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
 * @param MessageType Message type.
 * @param MessageData Message data.
 * @param MessageSize Message data size.
 * @param Priority Message priority.
 * @param ResponseBuffer Buffer for response.
 * @param ResponseBufferSize Response buffer size.
 * @param ResponseSize Actual response size.
 * @param TimeoutMs Timeout in milliseconds (0 = infinite).
 * @return STATUS_SUCCESS on success.
 */
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
 * @param Message Output message (caller frees with MqFreeMessage).
 * @param TimeoutMs Timeout in milliseconds (0 = no wait).
 * @return STATUS_SUCCESS if message dequeued, STATUS_TIMEOUT if timeout.
 */
NTSTATUS
MqDequeueMessage(
    _Out_ PQUEUED_MESSAGE* Message,
    _In_ UINT32 TimeoutMs
    );

/**
 * @brief Dequeue a batch of messages.
 * @param Messages Output array of messages.
 * @param MaxMessages Maximum messages to dequeue.
 * @param MessageCount Actual messages dequeued.
 * @param TimeoutMs Timeout in milliseconds.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
MqDequeueBatch(
    _Out_writes_to_(MaxMessages, *MessageCount) PQUEUED_MESSAGE* Messages,
    _In_ UINT32 MaxMessages,
    _Out_ PUINT32 MessageCount,
    _In_ UINT32 TimeoutMs
    );

/**
 * @brief Free a dequeued message.
 * @param Message Message to free.
 */
VOID
MqFreeMessage(
    _In_ PQUEUED_MESSAGE Message
    );

/**
 * @brief Complete a blocking message with response.
 * @param MessageId Message ID.
 * @param Status Completion status.
 * @param ResponseData Response data.
 * @param ResponseSize Response data size.
 * @return STATUS_SUCCESS on success.
 */
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
BOOLEAN
MqIsHighWaterMark(VOID);

/**
 * @brief Check if queue is at low water mark (after high).
 * @return TRUE if at low water mark.
 */
BOOLEAN
MqIsLowWaterMark(VOID);

/**
 * @brief Get current queue depth.
 * @return Current queue depth.
 */
UINT32
MqGetQueueDepth(VOID);

/**
 * @brief Wait for queue space.
 * @param TimeoutMs Timeout in milliseconds.
 * @return STATUS_SUCCESS if space available.
 */
NTSTATUS
MqWaitForSpace(
    _In_ UINT32 TimeoutMs
    );

/**
 * @brief Flush all queued messages.
 * @param Wait TRUE to wait for completion.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
MqFlush(
    _In_ BOOLEAN Wait
    );

// ============================================================================
// PUBLIC API - STATISTICS
// ============================================================================

/**
 * @brief Get message queue statistics.
 * @param TotalEnqueued Output total enqueued.
 * @param TotalDequeued Output total dequeued.
 * @param TotalDropped Output total dropped.
 * @param CurrentDepth Output current depth.
 * @param PeakDepth Output peak depth.
 * @return STATUS_SUCCESS on success.
 */
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
VOID
MqResetStatistics(VOID);

// ============================================================================
// PUBLIC API - EVENTS
// ============================================================================

/**
 * @brief Get event for message available notification.
 * @return Event object.
 */
PKEVENT
MqGetMessageAvailableEvent(VOID);

/**
 * @brief Get event for batch ready notification.
 * @return Event object.
 */
PKEVENT
MqGetBatchReadyEvent(VOID);

/**
 * @brief Get event for high water mark notification.
 * @return Event object.
 */
PKEVENT
MqGetHighWaterMarkEvent(VOID);

// ============================================================================
// HELPER MACROS
// ============================================================================

/**
 * @brief Calculate message allocation size.
 */
#define MQ_MESSAGE_ALLOC_SIZE(dataSize) \
    (FIELD_OFFSET(QUEUED_MESSAGE, Data) + (dataSize))

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

#endif // SHADOWSTRIKE_MESSAGE_QUEUE_H
