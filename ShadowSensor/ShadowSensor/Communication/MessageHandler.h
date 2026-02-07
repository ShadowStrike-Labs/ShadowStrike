/**
 * ============================================================================
 * ShadowStrike NGAV - MESSAGE HANDLER HEADER
 * ============================================================================
 *
 * @file MessageHandler.h
 * @brief Enterprise-grade message dispatch and routing for user-mode messages.
 *
 * Provides:
 * - Subsystem handler registration
 * - Message validation and dispatch
 * - Protected process management
 * - Configuration/policy updates
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_MESSAGE_HANDLER_H_
#define _SHADOWSTRIKE_MESSAGE_HANDLER_H_

#include <fltKernel.h>
#include "../Core/Globals.h"
#include "../../Shared/MessageTypes.h"

// ============================================================================
// INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the message handler subsystem.
 *
 * Must be called during driver initialization before any messages are processed.
 *
 * @return STATUS_SUCCESS or error code.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MhInitialize(
    VOID
    );

/**
 * @brief Shutdown the message handler subsystem.
 *
 * Releases all resources and clears protected process list.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
MhShutdown(
    VOID
    );

// ============================================================================
// HANDLER REGISTRATION
// ============================================================================

/**
 * @brief Message handler callback function type.
 */
typedef NTSTATUS
(*PMH_MESSAGE_HANDLER_CALLBACK)(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PVOID Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

/**
 * @brief Register a message handler callback.
 *
 * @param MessageType Message type to handle.
 * @param Callback Handler callback function.
 * @param Context Optional context passed to callback.
 *
 * @return STATUS_SUCCESS or error code.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MhRegisterHandler(
    _In_ SHADOWSTRIKE_MESSAGE_TYPE MessageType,
    _In_ PMH_MESSAGE_HANDLER_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

/**
 * @brief Unregister a message handler.
 *
 * @param MessageType Message type to unregister.
 *
 * @return STATUS_SUCCESS or error code.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MhUnregisterHandler(
    _In_ SHADOWSTRIKE_MESSAGE_TYPE MessageType
    );

// ============================================================================
// MESSAGE PROCESSING
// ============================================================================

/**
 * @brief Process a message from user-mode.
 *
 * Main entry point for handling messages received from user-mode via
 * the communication port.
 *
 * @param ClientContext Client port context.
 * @param InputBuffer Input message buffer.
 * @param InputBufferSize Size of input buffer.
 * @param OutputBuffer Optional output buffer for reply.
 * @param OutputBufferSize Size of output buffer.
 * @param ReturnOutputBufferLength Size actually written to output buffer.
 *
 * @return STATUS_SUCCESS or error code.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeProcessUserMessage(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_opt_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

// ============================================================================
// PROTECTED PROCESS MANAGEMENT
// ============================================================================

/**
 * @brief Check if a process is protected.
 *
 * @param ProcessId Process ID to check.
 *
 * @return TRUE if protected, FALSE otherwise.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
MhIsProcessProtected(
    _In_ UINT32 ProcessId
    );

/**
 * @brief Get protection flags for a process.
 *
 * @param ProcessId Process ID to check.
 * @param Flags Receives protection flags if protected.
 *
 * @return STATUS_SUCCESS if found, STATUS_NOT_FOUND otherwise.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
MhGetProcessProtectionFlags(
    _In_ UINT32 ProcessId,
    _Out_ PUINT32 Flags
    );

/**
 * @brief Remove a protected process.
 *
 * Called when a protected process terminates.
 *
 * @param ProcessId Process ID to remove.
 *
 * @return STATUS_SUCCESS if removed, STATUS_NOT_FOUND otherwise.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
MhUnprotectProcess(
    _In_ UINT32 ProcessId
    );

#endif // _SHADOWSTRIKE_MESSAGE_HANDLER_H_
