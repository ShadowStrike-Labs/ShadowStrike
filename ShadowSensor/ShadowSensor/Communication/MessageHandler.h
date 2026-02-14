/**
 * ============================================================================
 * ShadowStrike NGAV - MESSAGE HANDLER HEADER
 * ============================================================================
 *
 * @file MessageHandler.h
 * @brief Enterprise-grade message dispatch and routing for user-mode messages.
 *
 * Provides:
 * - Subsystem handler registration with safe callback invocation
 * - Message validation and dispatch with full SEH protection
 * - Protected process management with proper synchronization
 * - Configuration/policy updates with authorization checks
 *
 * Thread Safety:
 * - All public APIs are thread-safe
 * - Handler registration uses EX_PUSH_LOCK
 * - Protected process list uses EX_PUSH_LOCK
 * - All operations respect IRQL requirements
 *
 * Security:
 * - All user-mode buffers are probed and protected with SEH
 * - Authorization checks for privileged operations
 * - Input validation on all parameters
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_MESSAGE_HANDLER_H_
#define _SHADOWSTRIKE_MESSAGE_HANDLER_H_

#include <fltKernel.h>
#include "../Core/Globals.h"
#include "../../Shared/MessageTypes.h"
#include "../../Shared/MessageProtocol.h"

// ============================================================================
// COMPILE-TIME VALIDATIONS
// ============================================================================

C_ASSERT(sizeof(SS_MESSAGE_HEADER) <= 64);
C_ASSERT(sizeof(SHADOWSTRIKE_GENERIC_REPLY) <= 32);
C_ASSERT(MAX_PROCESS_NAME_LENGTH <= 520);

// ============================================================================
// CONSTANTS
// ============================================================================

#define MH_MAX_HANDLERS                 64
#define MH_MAX_PROTECTED_PROCESSES      256

// ============================================================================
// INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the message handler subsystem.
 *
 * Must be called during driver initialization before any messages are processed.
 * Thread-safe: Uses interlocked operations to prevent double initialization.
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
 * Must not be called while messages are being processed.
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
 *
 * Callbacks are invoked at PASSIVE_LEVEL with all buffers already validated.
 * The callback MUST NOT block indefinitely.
 *
 * @param ClientContext Client port context (validated, non-NULL).
 * @param Header Message header (validated, kernel memory).
 * @param PayloadBuffer Pointer to payload (may be NULL if PayloadSize is 0).
 * @param PayloadSize Size of payload in bytes.
 * @param OutputBuffer Output buffer for reply (may be NULL).
 * @param OutputBufferSize Size of output buffer.
 * @param ReturnOutputBufferLength Receives bytes written to output.
 *
 * @return NTSTATUS result.
 */
typedef NTSTATUS
(*PMH_MESSAGE_HANDLER_CALLBACK)(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

/**
 * @brief Register a message handler callback.
 *
 * The callback will be invoked for messages of the specified type.
 * Only one handler can be registered per message type.
 *
 * @param MessageType Message type to handle (must be < MH_MAX_HANDLERS).
 * @param Callback Handler callback function (must not be NULL).
 * @param Context Optional context passed to callback.
 *
 * @return STATUS_SUCCESS on success.
 * @return STATUS_INVALID_PARAMETER if Callback is NULL or MessageType invalid.
 * @return STATUS_ALREADY_REGISTERED if handler already exists.
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
 * Waits for any in-flight callbacks to complete before returning.
 *
 * @param MessageType Message type to unregister.
 *
 * @return STATUS_SUCCESS on success.
 * @return STATUS_INVALID_PARAMETER if MessageType invalid.
 * @return STATUS_NOT_FOUND if no handler registered.
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
 * the communication port. Performs full validation including:
 * - Buffer probing (ProbeForRead/ProbeForWrite)
 * - SEH protection for all user buffer access
 * - Message header validation
 * - Authorization checks for privileged operations
 *
 * @param ClientContext Client port context (must not be NULL).
 * @param InputBuffer Input message buffer (user-mode address).
 * @param InputBufferSize Size of input buffer.
 * @param OutputBuffer Optional output buffer for reply (user-mode address).
 * @param OutputBufferSize Size of output buffer.
 * @param ReturnOutputBufferLength Receives size written to output (must not be NULL).
 *
 * @return STATUS_SUCCESS or error code.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeProcessUserMessage(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_reads_bytes_(InputBufferSize) PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

// ============================================================================
// PROTECTED PROCESS MANAGEMENT
// ============================================================================

/**
 * @brief Check if a process is protected.
 *
 * This function is safe to call from any IRQL <= APC_LEVEL.
 * Uses shared lock for concurrent read access.
 *
 * @param ProcessId Process ID to check (0 returns FALSE).
 *
 * @return TRUE if protected, FALSE otherwise.
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
MhIsProcessProtected(
    _In_ UINT32 ProcessId
    );

/**
 * @brief Get protection flags for a process.
 *
 * @param ProcessId Process ID to check (0 returns STATUS_INVALID_PARAMETER).
 * @param Flags Receives protection flags if protected (must not be NULL).
 *
 * @return STATUS_SUCCESS if found.
 * @return STATUS_INVALID_PARAMETER if ProcessId is 0 or Flags is NULL.
 * @return STATUS_NOT_FOUND if not protected.
 */
_IRQL_requires_max_(APC_LEVEL)
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
 * @param ProcessId Process ID to remove (0 returns STATUS_INVALID_PARAMETER).
 *
 * @return STATUS_SUCCESS if removed.
 * @return STATUS_INVALID_PARAMETER if ProcessId is 0.
 * @return STATUS_NOT_FOUND if not in list.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
MhUnprotectProcess(
    _In_ UINT32 ProcessId
    );

/**
 * @brief Check if caller is authorized for privileged operations.
 *
 * Verifies the calling process is:
 * - Running as SYSTEM, or
 * - A registered protected ShadowStrike service process
 *
 * @param ClientContext Client connection context.
 *
 * @return TRUE if authorized, FALSE otherwise.
 */
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
MhIsCallerAuthorized(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext
    );

#endif // _SHADOWSTRIKE_MESSAGE_HANDLER_H_
