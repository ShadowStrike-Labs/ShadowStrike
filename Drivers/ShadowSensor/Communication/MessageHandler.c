/**
 * ============================================================================
 * ShadowStrike NGAV - MESSAGE HANDLER IMPLEMENTATION
 * ============================================================================
 *
 * @file MessageHandler.c
 * @brief Implementation of message dispatching logic.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "MessageHandler.h"
#include "../Shared/MessageTypes.h"
#include "../Shared/MessageProtocol.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ShadowStrikeProcessUserMessage)
#endif

NTSTATUS
ShadowStrikeProcessUserMessage(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_opt_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PFILTER_MESSAGE_HEADER Header = (PFILTER_MESSAGE_HEADER)InputBuffer;
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferSize);

    *ReturnOutputBufferLength = 0;

    //
    // Basic Validation
    //
    if (InputBuffer == NULL || InputBufferSize < sizeof(FILTER_MESSAGE_HEADER)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Check Magic and Version
    //
    if (Header->Magic != SHADOWSTRIKE_MESSAGE_MAGIC) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Dispatch based on MessageType
    //
    switch (Header->MessageType) {
        case FilterMessageType_Ping:
            // Heartbeat from user-mode
            break;

        case FilterMessageType_ConfigUpdate:
            // Update configuration
            // TODO: Implement config update logic
            break;

        case FilterMessageType_ScanVerdict:
            // Reply to a scan request (usually handled via FilterReplyMessage, not here)
            // But if async, might come here.
            break;

        default:
            Status = STATUS_INVALID_PARAMETER;
            break;
    }

    return Status;
}
