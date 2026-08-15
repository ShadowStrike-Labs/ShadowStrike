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
 * ShadowStrike NGAV - COMMUNICATION PORT
 * ============================================================================
 *
 * @file CommPort.h
 * @brief Filter Manager communication port declarations.
 *
 * Handles creation and management of the communication port for
 * kernel-to-user-mode messaging with full reference counting,
 * client authentication, and enterprise-grade security.
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_COMM_PORT_H
#define SHADOWSTRIKE_COMM_PORT_H

#ifdef __cplusplus
extern "C" {
#endif

#pragma warning(push)
#pragma warning(disable:4324)
#include <fltKernel.h>
#pragma warning(pop)
#include "../../Shared/SharedDefs.h"
#include "../../Shared/MessageProtocol.h"

// ============================================================================
// CLIENT CAPABILITY FLAGS
// ============================================================================

/**
 * @brief Client capability and permission flags.
 *
 * Controls what operations each connected client is authorized to perform.
 */
typedef enum _SHADOWSTRIKE_CLIENT_CAPABILITY {
    /// No capabilities (invalid client)
    ShadowStrikeCapNone                 = 0x00000000,

    /// Can receive and reply to scan requests
    ShadowStrikeCapScanFiles            = 0x00000001,

    /// Can receive process notifications
    ShadowStrikeCapProcessNotify        = 0x00000002,

    /// Can receive image load notifications
    ShadowStrikeCapImageNotify          = 0x00000004,

    /// Can receive registry notifications
    ShadowStrikeCapRegistryNotify       = 0x00000008,

    /// Can query driver status
    ShadowStrikeCapQueryStatus          = 0x00000010,

    /// Can update driver policy (requires elevated verification)
    ShadowStrikeCapUpdatePolicy         = 0x00000020,

    /// Can enable/disable filtering (requires elevated verification)
    ShadowStrikeCapControlFiltering     = 0x00000040,

    /// Can register protected processes
    ShadowStrikeCapProtectProcess       = 0x00000080,

    /// Is a verified ShadowStrike service binary
    ShadowStrikeCapVerifiedService      = 0x80000000,

    /// Default capabilities for verified service
    ShadowStrikeCapServiceDefault       = (ShadowStrikeCapScanFiles |
                                           ShadowStrikeCapProcessNotify |
                                           ShadowStrikeCapImageNotify |
                                           ShadowStrikeCapRegistryNotify |
                                           ShadowStrikeCapQueryStatus |
                                           ShadowStrikeCapUpdatePolicy |
                                           ShadowStrikeCapControlFiltering |
                                           ShadowStrikeCapProtectProcess |
                                           ShadowStrikeCapVerifiedService),

    /// Minimal capabilities for unverified clients
    ShadowStrikeCapMinimal              = (ShadowStrikeCapQueryStatus)

} SHADOWSTRIKE_CLIENT_CAPABILITY;

// ============================================================================
// CLIENT PORT REFERENCE STRUCTURE
// ============================================================================

/**
 * @brief Extended client port context with reference counting.
 *
 * This structure provides safe access to client ports by maintaining
 * a reference count that prevents use-after-free during message sends.
 */
typedef struct _SHADOWSTRIKE_CLIENT_PORT_REF {
    /// Client port handle (NULL if disconnected)
    PFLT_PORT ClientPort;

    /// Client process ID
    HANDLE ClientProcessId;

    /// Connection timestamp
    LARGE_INTEGER ConnectedTime;

    /// Reference count for safe access. The accepted connection owns one
    /// baseline reference until BeginClientDisconnect claims it exactly once.
    volatile LONG ReferenceCount;

    /// Client is being disconnected (no new references allowed). The 0->1
    /// transition is also the exactly-once baseline-reference claim.
    volatile LONG Disconnecting;

    /// Nonzero generation identifying this specific reuse of the slot.
    /// Preserved when the rest of the slot is reset.
    ULONG_PTR ConnectionGeneration;

    /// Exactly-once finalization state (idle, claimed/queued, or running).
    /// A slot is reusable only after its completion event is signaled.
    volatile LONG FinalizationState;

    /// Owns this accepted connection's contribution to ConnectedClients.
    /// BeginClientDisconnect retires it exactly once with the baseline.
    volatile LONG ConnectionCounted;

    /// Owns the per-slot primary-scanner PID publication and any paired KEX
    /// readiness increment. Retired exactly once by BeginClientDisconnect.
    volatile LONG ScannerPublicationsActive;

    /// Work item preallocated before the connection is accepted. A final
    /// release at APC_LEVEL can therefore defer PASSIVE-only teardown without
    /// depending on a teardown-time allocation.
    PFLT_GENERIC_WORKITEM FinalizationWorkItem;

    /// Immutable identity check for the canonical ClientPort owner. This is
    /// never passed to FltCloseClientPort; only &ClientPort is closed.
    PFLT_PORT FinalizationExpectedPort;

    /// Client capabilities/permissions
    ULONG Capabilities;

    /// Is primary scanner connection
    BOOLEAN IsPrimaryScanner;

    /// Client image path hash (for verification)
    UCHAR ImagePathHash[32];

    /// Messages sent to this client
    volatile LONG64 MessagesSent;

    /// Replies received from this client
    volatile LONG64 RepliesReceived;

    /// Slot index (for self-reference)
    LONG SlotIndex;

    /// Per-session AES-256-GCM encryption key (32 bytes, derived at connection time)
    UCHAR SessionKey[32];

    /// Session nonce prefix (4 bytes, sent to client in key exchange)
    UCHAR SessionNoncePrefix[4];

    /// Monotonic nonce counter for this session (combined with prefix for unique nonces)
    volatile LONG64 NonceCounter;

    /// Whether encryption has been established for this client.
    /// Access only through interlocked operations because KEX completion,
    /// senders, and disconnect finalization execute concurrently.
    volatile LONG EncryptionEstablished;

} SHADOWSTRIKE_CLIENT_PORT_REF, *PSHADOWSTRIKE_CLIENT_PORT_REF;

// ============================================================================
// MESSAGE BUFFER HEADER (for allocation tracking)
// ============================================================================

/**
 * @brief Header prepended to all message allocations.
 *
 * Tracks allocation source to ensure correct deallocation method.
 */
typedef struct _SHADOWSTRIKE_MESSAGE_BUFFER_HEADER {
    /// Magic for validation
    ULONG Magic;

    /// Allocation source (1 = lookaside, 2 = pool)
    ULONG AllocationSource;

    /// Requested size
    SIZE_T RequestedSize;

    /// Actual allocated size
    SIZE_T AllocatedSize;

} SHADOWSTRIKE_MESSAGE_BUFFER_HEADER, *PSHADOWSTRIKE_MESSAGE_BUFFER_HEADER;

#define SHADOWSTRIKE_BUFFER_MAGIC           0x53534642  // "SSFB"
#define SHADOWSTRIKE_ALLOC_LOOKASIDE        1
#define SHADOWSTRIKE_ALLOC_POOL             2

// ============================================================================
// PORT CREATION AND DESTRUCTION
// ============================================================================

/**
 * @brief Create the server communication port.
 *
 * Creates L"\\ShadowStrikePort" for user-mode connections.
 * Must be called at PASSIVE_LEVEL.
 *
 * @param FilterHandle  Handle from FltRegisterFilter.
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeCreateCommunicationPort(
    _In_ PFLT_FILTER FilterHandle
    );

/**
 * @brief Close the server communication port.
 *
 * Disconnects all clients and closes the port.
 * Waits for all outstanding references to drain.
 * Must be called at PASSIVE_LEVEL.
 *
 * @irql PASSIVE_LEVEL
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
 * Validates the connection, authenticates the client, and allocates context.
 *
 * @param ClientPort              Client port handle.
 * @param ServerPortCookie        Server context (unused).
 * @param ConnectionContext       Client-supplied context (user-mode buffer).
 * @param SizeOfContext           Size of ConnectionContext.
 * @param ConnectionPortCookie    Receives client cookie.
 * @return STATUS_SUCCESS to accept, error to reject.
 *
 * @irql PASSIVE_LEVEL
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
 * Marks client as disconnecting and waits for references to drain.
 *
 * @param ConnectionCookie  Client cookie from connect callback.
 *
 * @irql PASSIVE_LEVEL
 */
VOID
ShadowStrikeDisconnectNotify(
    _In_opt_ PVOID ConnectionCookie
    );

/**
 * @brief Message received callback.
 *
 * Called when user-mode sends a message (control commands, replies).
 * All user-mode buffers are properly validated with try/except.
 *
 * @param PortCookie     Client cookie.
 * @param InputBuffer    Message from user-mode (user-mode pointer).
 * @param InputBufferLength  Size of input buffer.
 * @param OutputBuffer   Reply buffer (user-mode pointer).
 * @param OutputBufferLength  Size of output buffer.
 * @param ReturnOutputBufferLength  Receives actual reply size.
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
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
// MESSAGE SENDING (Thread-Safe with Reference Counting)
// ============================================================================

/**
 * @brief Send a scan request to user-mode and wait for reply.
 *
 * This is a blocking call that waits for user-mode to scan a file
 * and return a verdict. Uses reference counting for safe client access.
 *
 * @param Request      Pointer to the scan request structure.
 * @param RequestSize  Size of the request including variable data.
 * @param Reply        Receives the verdict reply.
 * @param ReplySize    On input, size of reply buffer. On output, actual size.
 * @param TimeoutMs    Maximum wait time in milliseconds.
 * @return STATUS_SUCCESS on success, STATUS_TIMEOUT on timeout.
 *
 * @irql PASSIVE_LEVEL
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
 * Uses zero-timeout to avoid blocking.
 *
 * @param Notification  Pointer to the notification message.
 * @param Size          Size of the notification.
 * @return STATUS_SUCCESS if sent successfully.
 *
 * @irql <= APC_LEVEL
 */
NTSTATUS
ShadowStrikeSendNotification(
    _In_reads_bytes_(Size) PSHADOWSTRIKE_MESSAGE_HEADER Notification,
    _In_ ULONG Size
    );

/**
 * @brief Hard ceiling on how long a process notification may wait for a verdict.
 *
 * The caller supplies the budget (see ReplyTimeoutMs below) because only the
 * caller knows what its callback owes the kernel. This ceiling exists because
 * the previous implementation did NOT take a budget: it read
 * g_DriverData.Config.ScanTimeoutMs, a FILE-scan timeout that user mode sets by
 * policy, defaulting to 30000 ms and accepted up to
 * SHADOWSTRIKE_MAX_SCAN_TIMEOUT_MS (300000 ms). A process-creation callback
 * blocks the thread that called CreateProcess, so inheriting a five-minute
 * file-scan budget there is not a tuning question but a freeze.
 *
 * 1000 ms is a chosen bound, not a measured one, and it is deliberately looser
 * than any caller should ask for: PC_SCAN_TIMEOUT_EXECUTE_MS (500) is what the
 * file pre-execution gate allows for the same class of decision. The ceiling is
 * enforced here, at the single chokepoint, so a future caller cannot reintroduce
 * an unbounded wait by picking the wrong constant.
 */
#define SHADOWSTRIKE_PROCESS_REPLY_TIMEOUT_MAX_MS   1000

/**
 * @brief Send process notification to user-mode.
 *
 * @param Notification    Pre-built notification buffer.
 * @param Size            Total size of notification in bytes.
 * @param RequireReply    If TRUE, wait for verdict reply.
 * @param Reply           Output verdict reply buffer (optional).
 * @param ReplySize       In/out reply buffer size (optional). On return it holds
 *                        the number of bytes a reply actually delivered, and it
 *                        is written ONLY when a reply genuinely arrived - so the
 *                        caller must not read the verdict without checking both
 *                        the returned status and this length.
 * @param ReplyTimeoutMs  How long to wait for the verdict, in milliseconds.
 *                        Required (must be non-zero) when RequireReply is TRUE
 *                        and ignored otherwise; there is deliberately no
 *                        "0 means default" behaviour, because a caller that
 *                        forgets to state its budget must fail loudly rather
 *                        than silently inherit someone else's. Clamped to
 *                        SHADOWSTRIKE_PROCESS_REPLY_TIMEOUT_MAX_MS, and further
 *                        to 250 ms during boot phase.
 * @return STATUS_SUCCESS if sent successfully. STATUS_TIMEOUT if no reply
 *         arrived within the budget - a documented FltSendMessage success code,
 *         so callers must test for it by name and must NOT treat NT_SUCCESS as
 *         proof that Reply was written.
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeSendProcessNotification(
    _In_reads_bytes_(Size) PSHADOWSTRIKE_PROCESS_NOTIFICATION Notification,
    _In_ ULONG Size,
    _In_ BOOLEAN RequireReply,
    _Out_writes_bytes_opt_(*ReplySize) PSHADOWSTRIKE_PROCESS_VERDICT_REPLY Reply,
    _Inout_opt_ PULONG ReplySize,
    _In_ ULONG ReplyTimeoutMs
    );

// ============================================================================
// CONNECTION STATE QUERIES
// ============================================================================

/**
 * @brief Check if any user-mode client is connected.
 *
 * @return TRUE if at least one client is connected.
 *
 * @irql Any
 */
BOOLEAN
ShadowStrikeIsUserModeConnected(
    VOID
    );

/**
 * @brief Check if a key-exchange-complete primary scanner is connected.
 *
 * Authoritative readiness signal for the verdict-blocking scan path. Returns
 * TRUE only when at least one primary-scanner connection has completed its key
 * exchange (IsPrimaryScanner && EncryptionEstablished) and can therefore
 * decrypt and reply to scan requests. Lock-free (Interlocked load of
 * g_DriverData.PrimaryScannersReady), so it is safe to call from the scan
 * readiness gate without acquiring ClientPortLock.
 *
 * @return TRUE if a usable primary scanner is connected, FALSE otherwise.
 *
 * @irql <= DISPATCH_LEVEL
 */
BOOLEAN
ShadowStrikeIsPrimaryScannerConnected(
    VOID
    );

/**
 * @brief Get connected client count.
 *
 * @return Number of connected clients.
 *
 * @irql Any
 */
LONG
ShadowStrikeGetConnectedClientCount(
    VOID
    );

// ============================================================================
// CLIENT PORT REFERENCE MANAGEMENT
// ============================================================================

/**
 * @brief [DEPRECATED] Get the primary scanner port handle.
 *
 * Returns the raw PFLT_PORT without reference increment.
 * DEPRECATED: Use ShadowStrikeAcquirePrimaryScannerPort() for safe,
 * reference-counted access. This function exists only for backward
 * compatibility and has zero external callers.
 *
 * @return PFLT_PORT if connected, NULL otherwise.
 *
 * @irql <= APC_LEVEL
 */
PFLT_PORT
ShadowStrikeGetPrimaryScannerPort(
    VOID
    );

/**
 * @brief Acquire reference to primary scanner port.
 *
 * Returns a referenced client port that is safe to use for sending.
 * Caller MUST call ShadowStrikeReleaseClientPort when done.
 *
 * @param ClientRef     Receives pointer to client reference structure.
 * @param AllowFallback When TRUE and no primary scanner is connected, falls
 *                      back to the first connected client (fire-and-forget
 *                      telemetry/notification paths only). When FALSE, only a
 *                      real primary scanner is acceptable — REQUIRED for the
 *                      verdict-blocking scan transport so synchronous scans are
 *                      never routed to a non-scanner client (which would block
 *                      and freeze the system).
 * @return STATUS_SUCCESS if port acquired, error otherwise.
 *
 * @irql <= APC_LEVEL
 */
NTSTATUS
ShadowStrikeAcquirePrimaryScannerPort(
    _Out_ PSHADOWSTRIKE_CLIENT_PORT_REF* ClientRef,
    _In_ BOOLEAN AllowFallback
    );

/**
 * @brief Release reference to client port.
 *
 * Decrements reference count. If this is the last reference and the client is
 * disconnecting, claims PASSIVE teardown synchronously or queues the slot's
 * preallocated finalization work item when called at APC_LEVEL.
 *
 * @param ClientRef  Client reference to release.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowStrikeReleaseClientPort(
    _In_ PSHADOWSTRIKE_CLIENT_PORT_REF ClientRef
    );

// ============================================================================
// CLIENT MANAGEMENT
// ============================================================================

/**
 * @brief Find client slot by process ID.
 *
 * @param ProcessId  Process ID to search for.
 * @return Index of client slot, or -1 if not found.
 *
 * @irql <= APC_LEVEL
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
 *
 * @irql <= APC_LEVEL
 */
BOOLEAN
ShadowStrikeValidateClient(
    _In_ LONG ClientIndex
    );

/**
 * @brief Check if client has required capability.
 *
 * @param ClientIndex  Index of client slot.
 * @param Capability   Required capability flag.
 * @return TRUE if client has the capability.
 *
 * @irql <= APC_LEVEL
 */
BOOLEAN
ShadowStrikeClientHasCapability(
    _In_ LONG ClientIndex,
    _In_ SHADOWSTRIKE_CLIENT_CAPABILITY Capability
    );

// ============================================================================
// MESSAGE BUFFER ALLOCATION (with tracking)
// ============================================================================

/**
 * @brief Allocate message buffer with source tracking.
 *
 * @param Size  Minimum size required.
 * @return Pointer to buffer (after header), or NULL on failure.
 *
 * @irql <= DISPATCH_LEVEL
 */
PVOID
ShadowStrikeAllocateMessageBuffer(
    _In_ ULONG Size
    );

/**
 * @brief Free message buffer (auto-detects allocation source).
 *
 * @param Buffer  Buffer to free (pointer returned from allocate).
 *
 * @irql <= DISPATCH_LEVEL
 */
VOID
ShadowStrikeFreeMessageBuffer(
    _In_opt_ PVOID Buffer
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
 *
 * @irql <= DISPATCH_LEVEL
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
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeBuildFileScanRequest(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ SHADOWSTRIKE_FILE_ACCESS_TYPE AccessType,
    _Out_ PSHADOWSTRIKE_MESSAGE_HEADER* Request,
    _Out_ PULONG RequestSize
    );

// ============================================================================
// CLIENT VERIFICATION
// ============================================================================

/**
 * @brief Verify connecting client is authorized.
 *
 * Checks process image path, code signature, and other
 * security attributes to determine client capabilities.
 *
 * @param ClientProcessId  Process ID of connecting client.
 * @param Capabilities     Receives client capability flags.
 * @param ImageHash        Receives hash of client image path.
 * @return STATUS_SUCCESS if client is authorized.
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeVerifyClient(
    _In_ HANDLE ClientProcessId,
    _Out_ PULONG Capabilities,
    _Out_writes_bytes_(32) PUCHAR ImageHash
    );

// ============================================================================
// PROTECTED PROCESS MANAGEMENT
// ============================================================================

/**
 * @brief Register a process for self-protection.
 *
 * @param ProcessId        Process ID to protect.
 * @param ProtectionFlags  Protection level flags.
 * @param ProcessName      Optional process name for logging.
 * @return STATUS_SUCCESS if registered.
 *
 * @irql PASSIVE_LEVEL
 */
/**
 * @brief Test whether a PID is the connected ShadowStrike scanner service.
 *
 * The file callbacks use this to exempt an accepted primary scanner's OWN
 * file I/O from the synchronous user-mode scan round trip, which would
 * otherwise recurse into PreCreate -> SbSendScanRequest and exhaust the
 * scanner worker pool. Multiple overlapping/reconnecting primary slots are
 * represented independently; PID 0/unknown never matches.
 *
 * @param ProcessId  Process ID to test; NULL means unknown.
 * @return TRUE if ProcessId belongs to any accepted primary scanner slot.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsScannerProcess(
    _In_ HANDLE ProcessId
    );

NTSTATUS
ShadowStrikeRegisterProtectedProcess(
    _In_ ULONG ProcessId,
    _In_ ULONG ProtectionFlags,
    _In_opt_ PCWSTR ProcessName
    );

/**
 * @brief Unregister a protected process.
 *
 * @param ProcessId  Process ID to unprotect.
 * @return STATUS_SUCCESS if unregistered.
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeUnregisterProtectedProcess(
    _In_ ULONG ProcessId
    );

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_COMM_PORT_H
