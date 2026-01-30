/**
 * ============================================================================
 * ShadowStrike NGAV - COMMUNICATION PORT
 * ============================================================================
 *
 * @file CommPort.h
 * @brief Filter Manager communication port declarations.
 *
 * Handles creation and management of the communication port for
 * kernel-to-user-mode messaging.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_COMM_PORT_H
#define SHADOWSTRIKE_COMM_PORT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <fltKernel.h>
#include "../Shared/SharedDefs.h"
#include "../Shared/MessageProtocol.h"

// ============================================================================
// PORT CREATION AND DESTRUCTION
// ============================================================================

/**
 * @brief Create the server communication port.
 *
 * Creates L"\\ShadowStrikePort" for user-mode connections.
 *
 * @param FilterHandle  Handle from FltRegisterFilter.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ShadowStrikeCreateCommunicationPort(
    _In_ PFLT_FILTER FilterHandle
    );

/**
 * @brief Close the server communication port.
 *
 * Disconnects all clients and closes the port.
 */
VOID
ShadowStrikeCloseCommunicationPort(
    VOID
    );

// ============================================================================
// CONNECTION CALLBACKS
// ============================================================================

/**
 * @brief Client connection callback.
 *
 * Called when user-mode service connects to the port.
 * Validates the connection and allocates client context.
 *
 * @param ClientPort              Client port handle.
 * @param ServerPortCookie        Server context (unused).
 * @param ConnectionContext       Client-supplied context.
 * @param SizeOfContext           Size of ConnectionContext.
 * @param ConnectionPortCookie    Receives client cookie.
 * @return STATUS_SUCCESS to accept, error to reject.
 */
NTSTATUS
ShadowStrikeConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionPortCookie
    );

/**
 * @brief Client disconnection callback.
 *
 * Called when user-mode service disconnects.
 * Cleans up client context and decrements connection count.
 *
 * @param ConnectionCookie  Client cookie from connect callback.
 */
VOID
ShadowStrikeDisconnectNotify(
    _In_opt_ PVOID ConnectionCookie
    );

/**
 * @brief Message received callback.
 *
 * Called when user-mode sends a message (control commands, replies).
 *
 * @param PortCookie     Client cookie.
 * @param InputBuffer    Message from user-mode.
 * @param InputBufferLength  Size of input buffer.
 * @param OutputBuffer   Reply buffer.
 * @param OutputBufferLength  Size of output buffer.
 * @param ReturnOutputBufferLength  Receives actual reply size.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ShadowStrikeMessageNotify(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

// ============================================================================
// MESSAGE SENDING
// ============================================================================

/**
 * @brief Send a scan request to user-mode and wait for reply.
 *
 * This is a blocking call that waits for user-mode to scan a file
 * and return a verdict.
 *
 * @param Request      Pointer to the scan request structure.
 * @param RequestSize  Size of the request including variable data.
 * @param Reply        Receives the verdict reply.
 * @param ReplySize    On input, size of reply buffer. On output, actual size.
 * @param TimeoutMs    Maximum wait time in milliseconds.
 * @return STATUS_SUCCESS on success, STATUS_TIMEOUT on timeout.
 */
NTSTATUS
ShadowStrikeSendScanRequest(
    _In_reads_bytes_(RequestSize) PSHADOWSTRIKE_MESSAGE_HEADER Request,
    _In_ ULONG RequestSize,
    _Out_writes_bytes_to_(*ReplySize, *ReplySize) PSHADOWSTRIKE_SCAN_VERDICT_REPLY Reply,
    _Inout_ PULONG ReplySize,
    _In_ ULONG TimeoutMs
    );

/**
 * @brief Send a notification to user-mode (no reply expected).
 *
 * Fire-and-forget message for monitoring/logging purposes.
 *
 * @param Notification  Pointer to the notification message.
 * @param Size          Size of the notification.
 * @return STATUS_SUCCESS if queued successfully.
 */
NTSTATUS
ShadowStrikeSendNotification(
    _In_reads_bytes_(Size) PSHADOWSTRIKE_MESSAGE_HEADER Notification,
    _In_ ULONG Size
    );

/**
 * @brief Send process notification to user-mode.
 *
 * @param Notification  Process notification structure.
 * @param Size          Size of the notification.
 * @param RequireReply  TRUE if verdict is needed.
 * @param Reply         Receives verdict reply if RequireReply is TRUE.
 * @param ReplySize     Size of reply buffer.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ShadowStrikeSendProcessNotification(
    _In_reads_bytes_(Size) PSHADOWSTRIKE_PROCESS_NOTIFICATION Notification,
    _In_ ULONG Size,
    _In_ BOOLEAN RequireReply,
    _Out_writes_bytes_opt_(*ReplySize) PSHADOWSTRIKE_PROCESS_VERDICT_REPLY Reply,
    _Inout_opt_ PULONG ReplySize
    );

// ============================================================================
// CONNECTION STATE QUERIES
// ============================================================================

/**
 * @brief Check if any user-mode client is connected.
 *
 * @return TRUE if at least one client is connected.
 */
BOOLEAN
ShadowStrikeIsUserModeConnected(
    VOID
    );

/**
 * @brief Get connected client count.
 *
 * @return Number of connected clients.
 */
LONG
ShadowStrikeGetConnectedClientCount(
    VOID
    );

/**
 * @brief Get primary scanner client port.
 *
 * @return Client port handle of primary scanner, or NULL.
 */
PFLT_PORT
ShadowStrikeGetPrimaryScannerPort(
    VOID
    );

// ============================================================================
// CLIENT MANAGEMENT
// ============================================================================

/**
 * @brief Find client slot by process ID.
 *
 * @param ProcessId  Process ID to search for.
 * @return Index of client slot, or -1 if not found.
 */
LONG
ShadowStrikeFindClientByProcessId(
    _In_ HANDLE ProcessId
    );

/**
 * @brief Validate client connection is still active.
 *
 * @param ClientIndex  Index of client slot.
 * @return TRUE if client is connected and valid.
 */
BOOLEAN
ShadowStrikeValidateClient(
    _In_ LONG ClientIndex
    );

// ============================================================================
// MESSAGE BUFFER ALLOCATION
// ============================================================================

/**
 * @brief Allocate message buffer from lookaside list.
 *
 * @param Size  Minimum size required.
 * @return Pointer to buffer, or NULL on failure.
 */
PVOID
ShadowStrikeAllocateMessageBuffer(
    _In_ SIZE_T Size
    );

/**
 * @brief Free message buffer to lookaside list.
 *
 * @param Buffer  Buffer to free.
 */
VOID
ShadowStrikeFreeMessageBuffer(
    _In_ PVOID Buffer
    );

// ============================================================================
// MESSAGE CONSTRUCTION HELPERS
// ============================================================================

/**
 * @brief Initialize message header with common fields.
 *
 * @param Header       Header to initialize.
 * @param MessageType  Type of message.
 * @param DataSize     Size of payload data.
 */
VOID
ShadowStrikeInitMessageHeader(
    _Out_ PSHADOWSTRIKE_MESSAGE_HEADER Header,
    _In_ SHADOWSTRIKE_MESSAGE_TYPE MessageType,
    _In_ ULONG DataSize
    );

/**
 * @brief Build file scan request from callback data.
 *
 * @param Data         Callback data from filter operation.
 * @param FltObjects   Filter objects.
 * @param AccessType   Type of file access.
 * @param Request      Receives the built request.
 * @param RequestSize  Receives actual request size.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ShadowStrikeBuildFileScanRequest(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ SHADOWSTRIKE_FILE_ACCESS_TYPE AccessType,
    _Out_ PSHADOWSTRIKE_MESSAGE_HEADER* Request,
    _Out_ PULONG RequestSize
    );

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_COMM_PORT_H
