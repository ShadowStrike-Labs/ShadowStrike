/**
 * ============================================================================
 * ShadowStrike NGAV - MESSAGE HANDLER IMPLEMENTATION
 * ============================================================================
 *
 * @file MessageHandler.c
 * @brief Enterprise-grade message dispatching and routing logic.
 *
 * This module handles all incoming messages from user-mode and routes them
 * to the appropriate subsystem handlers. It provides:
 *
 * - Message validation (magic, version, size bounds)
 * - Subsystem registration and callback dispatch
 * - Configuration updates with validation
 * - Policy management
 * - Protected process registration
 * - Statistics and status queries
 * - Scan verdict processing
 *
 * Thread Safety:
 * - Handler registration protected by EX_PUSH_LOCK
 * - Configuration updates protected by driver config lock
 * - Statistics use interlocked operations
 *
 * IRQL:
 * - Message processing: PASSIVE_LEVEL (may touch paged memory)
 * - Handler registration: PASSIVE_LEVEL
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "MessageHandler.h"
#include "MessageQueue.h"
#include "../../Shared/MessageTypes.h"
#include "../../Shared/MessageProtocol.h"
#include "../../Shared/ErrorCodes.h"
#include "../Core/Globals.h"

// ============================================================================
// CONSTANTS
// ============================================================================

#define MH_TAG                          'hMsS'
#define MH_MAX_HANDLERS                 64
#define MH_MAX_PROTECTED_PROCESSES      256

// ============================================================================
// TYPES
// ============================================================================

/**
 * @brief Message handler callback function type.
 *
 * @param ClientContext Client port context.
 * @param Header Message header.
 * @param PayloadBuffer Pointer to payload (after header).
 * @param PayloadSize Size of payload.
 * @param OutputBuffer Optional output buffer for reply.
 * @param OutputBufferSize Size of output buffer.
 * @param ReturnOutputBufferLength Size written to output buffer.
 * @return NTSTATUS result.
 */
typedef NTSTATUS
(*PMH_MESSAGE_HANDLER_CALLBACK)(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PFILTER_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

/**
 * @brief Registered message handler entry.
 */
typedef struct _MH_HANDLER_ENTRY {
    BOOLEAN Registered;
    UINT8 Reserved1[3];
    SHADOWSTRIKE_MESSAGE_TYPE MessageType;
    PMH_MESSAGE_HANDLER_CALLBACK Callback;
    PVOID Context;
    volatile LONG64 InvocationCount;
    volatile LONG64 ErrorCount;
} MH_HANDLER_ENTRY, *PMH_HANDLER_ENTRY;

/**
 * @brief Protected process entry.
 */
typedef struct _MH_PROTECTED_PROCESS {
    LIST_ENTRY ListEntry;
    UINT32 ProcessId;
    UINT32 ProtectionFlags;
    LARGE_INTEGER RegistrationTime;
    WCHAR ProcessName[MAX_PROCESS_NAME_LENGTH];
} MH_PROTECTED_PROCESS, *PMH_PROTECTED_PROCESS;

/**
 * @brief Message handler global state.
 */
typedef struct _MH_GLOBALS {
    BOOLEAN Initialized;
    UINT8 Reserved[7];
    
    // Handler table
    MH_HANDLER_ENTRY Handlers[MH_MAX_HANDLERS];
    EX_PUSH_LOCK HandlersLock;
    
    // Protected processes
    LIST_ENTRY ProtectedProcessList;
    EX_PUSH_LOCK ProtectedProcessLock;
    volatile LONG ProtectedProcessCount;
    NPAGED_LOOKASIDE_LIST ProtectedProcessLookaside;
    
    // Statistics
    volatile LONG64 TotalMessagesProcessed;
    volatile LONG64 TotalMessagesSucceeded;
    volatile LONG64 TotalMessagesFailed;
    volatile LONG64 TotalInvalidMessages;
    volatile LONG64 TotalUnhandledMessages;
} MH_GLOBALS, *PMH_GLOBALS;

// ============================================================================
// GLOBALS
// ============================================================================

static MH_GLOBALS g_MhGlobals = {0};

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static NTSTATUS
MhpValidateMessageHeader(
    _In_reads_bytes_(BufferSize) PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PFILTER_MESSAGE_HEADER* Header,
    _Out_ PVOID* Payload,
    _Out_ PULONG PayloadSize
    );

static NTSTATUS
MhpHandleHeartbeat(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PFILTER_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

static NTSTATUS
MhpHandleConfigUpdate(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PFILTER_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

static NTSTATUS
MhpHandlePolicyUpdate(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PFILTER_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

static NTSTATUS
MhpHandleDriverStatusQuery(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PFILTER_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

static NTSTATUS
MhpHandleProtectedProcessRegister(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PFILTER_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

static NTSTATUS
MhpHandleScanVerdict(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PFILTER_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

static NTSTATUS
MhpHandleEnableFiltering(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PFILTER_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

static NTSTATUS
MhpHandleDisableFiltering(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PFILTER_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

// ============================================================================
// PAGE ALLOCATION
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, MhInitialize)
#pragma alloc_text(PAGE, MhShutdown)
#pragma alloc_text(PAGE, ShadowStrikeProcessUserMessage)
#pragma alloc_text(PAGE, MhpHandleHeartbeat)
#pragma alloc_text(PAGE, MhpHandleConfigUpdate)
#pragma alloc_text(PAGE, MhpHandlePolicyUpdate)
#pragma alloc_text(PAGE, MhpHandleDriverStatusQuery)
#pragma alloc_text(PAGE, MhpHandleProtectedProcessRegister)
#pragma alloc_text(PAGE, MhpHandleScanVerdict)
#pragma alloc_text(PAGE, MhpHandleEnableFiltering)
#pragma alloc_text(PAGE, MhpHandleDisableFiltering)
#endif

// ============================================================================
// INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the message handler subsystem.
 *
 * @return STATUS_SUCCESS on success.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MhInitialize(
    VOID
    )
{
    PAGED_CODE();

    if (g_MhGlobals.Initialized) {
        return STATUS_ALREADY_REGISTERED;
    }

    RtlZeroMemory(&g_MhGlobals, sizeof(g_MhGlobals));

    //
    // Initialize locks
    //
    ExInitializePushLock(&g_MhGlobals.HandlersLock);
    ExInitializePushLock(&g_MhGlobals.ProtectedProcessLock);

    //
    // Initialize protected process list
    //
    InitializeListHead(&g_MhGlobals.ProtectedProcessList);
    g_MhGlobals.ProtectedProcessCount = 0;

    ExInitializeNPagedLookasideList(
        &g_MhGlobals.ProtectedProcessLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(MH_PROTECTED_PROCESS),
        MH_TAG,
        0
    );

    //
    // Register built-in handlers
    //
    MhRegisterHandler(FilterMessageType_Heartbeat, MhpHandleHeartbeat, NULL);
    MhRegisterHandler(FilterMessageType_ConfigUpdate, MhpHandleConfigUpdate, NULL);
    MhRegisterHandler(FilterMessageType_UpdatePolicy, MhpHandlePolicyUpdate, NULL);
    MhRegisterHandler(FilterMessageType_QueryDriverStatus, MhpHandleDriverStatusQuery, NULL);
    MhRegisterHandler(FilterMessageType_RegisterProtectedProcess, MhpHandleProtectedProcessRegister, NULL);
    MhRegisterHandler(FilterMessageType_ScanVerdict, MhpHandleScanVerdict, NULL);
    MhRegisterHandler(FilterMessageType_EnableFiltering, MhpHandleEnableFiltering, NULL);
    MhRegisterHandler(FilterMessageType_DisableFiltering, MhpHandleDisableFiltering, NULL);

    g_MhGlobals.Initialized = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MH] Message handler initialized\n");

    return STATUS_SUCCESS;
}

/**
 * @brief Shutdown the message handler subsystem.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
MhShutdown(
    VOID
    )
{
    PLIST_ENTRY entry;
    PMH_PROTECTED_PROCESS protectedProcess;

    PAGED_CODE();

    if (!g_MhGlobals.Initialized) {
        return;
    }

    //
    // Clear protected process list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_MhGlobals.ProtectedProcessLock);

    while (!IsListEmpty(&g_MhGlobals.ProtectedProcessList)) {
        entry = RemoveHeadList(&g_MhGlobals.ProtectedProcessList);
        protectedProcess = CONTAINING_RECORD(entry, MH_PROTECTED_PROCESS, ListEntry);
        ExFreeToNPagedLookasideList(&g_MhGlobals.ProtectedProcessLookaside, protectedProcess);
    }
    g_MhGlobals.ProtectedProcessCount = 0;

    ExReleasePushLockExclusive(&g_MhGlobals.ProtectedProcessLock);
    KeLeaveCriticalRegion();

    //
    // Delete lookaside
    //
    ExDeleteNPagedLookasideList(&g_MhGlobals.ProtectedProcessLookaside);

    //
    // Log final statistics
    //
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MH] Shutdown - Processed=%llu, Succeeded=%llu, Failed=%llu, Invalid=%llu\n",
               g_MhGlobals.TotalMessagesProcessed,
               g_MhGlobals.TotalMessagesSucceeded,
               g_MhGlobals.TotalMessagesFailed,
               g_MhGlobals.TotalInvalidMessages);

    g_MhGlobals.Initialized = FALSE;
}

// ============================================================================
// HANDLER REGISTRATION
// ============================================================================

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
    )
{
    ULONG slot;

    PAGED_CODE();

    if (Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (MessageType >= MH_MAX_HANDLERS) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_MhGlobals.HandlersLock);

    slot = (ULONG)MessageType;

    if (g_MhGlobals.Handlers[slot].Registered) {
        ExReleasePushLockExclusive(&g_MhGlobals.HandlersLock);
        KeLeaveCriticalRegion();
        return STATUS_ALREADY_REGISTERED;
    }

    g_MhGlobals.Handlers[slot].MessageType = MessageType;
    g_MhGlobals.Handlers[slot].Callback = Callback;
    g_MhGlobals.Handlers[slot].Context = Context;
    g_MhGlobals.Handlers[slot].InvocationCount = 0;
    g_MhGlobals.Handlers[slot].ErrorCount = 0;
    g_MhGlobals.Handlers[slot].Registered = TRUE;

    ExReleasePushLockExclusive(&g_MhGlobals.HandlersLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

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
    )
{
    ULONG slot;

    PAGED_CODE();

    if (MessageType >= MH_MAX_HANDLERS) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_MhGlobals.HandlersLock);

    slot = (ULONG)MessageType;

    if (!g_MhGlobals.Handlers[slot].Registered) {
        ExReleasePushLockExclusive(&g_MhGlobals.HandlersLock);
        KeLeaveCriticalRegion();
        return STATUS_NOT_FOUND;
    }

    g_MhGlobals.Handlers[slot].Registered = FALSE;
    g_MhGlobals.Handlers[slot].Callback = NULL;
    g_MhGlobals.Handlers[slot].Context = NULL;

    ExReleasePushLockExclusive(&g_MhGlobals.HandlersLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

// ============================================================================
// MAIN MESSAGE PROCESSING
// ============================================================================

/**
 * @brief Process a message from user-mode.
 *
 * Main entry point for handling messages received from user-mode via
 * the communication port. Validates the message, looks up the handler,
 * and dispatches to the appropriate callback.
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
    )
{
    NTSTATUS status;
    PFILTER_MESSAGE_HEADER header = NULL;
    PVOID payload = NULL;
    ULONG payloadSize = 0;
    PMH_HANDLER_ENTRY handler = NULL;
    ULONG slot;

    PAGED_CODE();

    //
    // Initialize output
    //
    *ReturnOutputBufferLength = 0;

    //
    // Update statistics
    //
    InterlockedIncrement64(&g_MhGlobals.TotalMessagesProcessed);

    //
    // Validate message
    //
    status = MhpValidateMessageHeader(
        InputBuffer,
        InputBufferSize,
        &header,
        &payload,
        &payloadSize
    );

    if (!NT_SUCCESS(status)) {
        InterlockedIncrement64(&g_MhGlobals.TotalInvalidMessages);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MH] Invalid message received: 0x%08X\n", status);
        return status;
    }

    //
    // Look up handler
    //
    slot = (ULONG)header->MessageType;
    if (slot >= MH_MAX_HANDLERS) {
        InterlockedIncrement64(&g_MhGlobals.TotalUnhandledMessages);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MH] Message type out of range: %u\n", header->MessageType);
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_MhGlobals.HandlersLock);

    handler = &g_MhGlobals.Handlers[slot];
    if (!handler->Registered || handler->Callback == NULL) {
        ExReleasePushLockShared(&g_MhGlobals.HandlersLock);
        KeLeaveCriticalRegion();

        InterlockedIncrement64(&g_MhGlobals.TotalUnhandledMessages);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                   "[ShadowStrike/MH] No handler for message type: %u\n", header->MessageType);
        return STATUS_SUCCESS;  // Not an error - just no handler
    }

    //
    // Call handler (under shared lock for safety)
    //
    InterlockedIncrement64(&handler->InvocationCount);

    status = handler->Callback(
        ClientContext,
        header,
        payload,
        payloadSize,
        OutputBuffer,
        OutputBufferSize,
        ReturnOutputBufferLength
    );

    if (!NT_SUCCESS(status)) {
        InterlockedIncrement64(&handler->ErrorCount);
    }

    ExReleasePushLockShared(&g_MhGlobals.HandlersLock);
    KeLeaveCriticalRegion();

    //
    // Update statistics
    //
    if (NT_SUCCESS(status)) {
        InterlockedIncrement64(&g_MhGlobals.TotalMessagesSucceeded);
    } else {
        InterlockedIncrement64(&g_MhGlobals.TotalMessagesFailed);
    }

    return status;
}

// ============================================================================
// VALIDATION
// ============================================================================

/**
 * @brief Validate message header and extract payload pointer.
 */
static NTSTATUS
MhpValidateMessageHeader(
    _In_reads_bytes_(BufferSize) PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PFILTER_MESSAGE_HEADER* Header,
    _Out_ PVOID* Payload,
    _Out_ PULONG PayloadSize
    )
{
    PFILTER_MESSAGE_HEADER hdr;

    *Header = NULL;
    *Payload = NULL;
    *PayloadSize = 0;

    //
    // Basic null and size checks
    //
    if (Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (BufferSize < sizeof(FILTER_MESSAGE_HEADER)) {
        return SHADOWSTRIKE_ERROR_BUFFER_TOO_SMALL;
    }

    hdr = (PFILTER_MESSAGE_HEADER)Buffer;

    //
    // Validate magic
    //
    if (hdr->Magic != SHADOWSTRIKE_MESSAGE_MAGIC) {
        return SHADOWSTRIKE_ERROR_INVALID_MESSAGE;
    }

    //
    // Validate version
    //
    if (hdr->Version != SHADOWSTRIKE_PROTOCOL_VERSION) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MH] Version mismatch: got %u, expected %u\n",
                   hdr->Version, SHADOWSTRIKE_PROTOCOL_VERSION);
        return SHADOWSTRIKE_ERROR_VERSION_MISMATCH;
    }

    //
    // Validate sizes
    //
    if (hdr->TotalSize > BufferSize) {
        return SHADOWSTRIKE_ERROR_BUFFER_TOO_SMALL;
    }

    if (hdr->DataSize > (BufferSize - sizeof(FILTER_MESSAGE_HEADER))) {
        return SHADOWSTRIKE_ERROR_INVALID_MESSAGE;
    }

    //
    // Extract payload
    //
    *Header = hdr;

    if (hdr->DataSize > 0) {
        *Payload = (PUCHAR)Buffer + sizeof(FILTER_MESSAGE_HEADER);
        *PayloadSize = hdr->DataSize;
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// BUILT-IN HANDLERS
// ============================================================================

/**
 * @brief Handle heartbeat message.
 */
static NTSTATUS
MhpHandleHeartbeat(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PFILTER_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PSHADOWSTRIKE_GENERIC_REPLY reply;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);
    UNREFERENCED_PARAMETER(PayloadBuffer);
    UNREFERENCED_PARAMETER(PayloadSize);

    *ReturnOutputBufferLength = 0;

    //
    // Send simple acknowledgment reply if buffer provided
    //
    if (OutputBuffer != NULL && OutputBufferSize >= sizeof(SHADOWSTRIKE_GENERIC_REPLY)) {
        reply = (PSHADOWSTRIKE_GENERIC_REPLY)OutputBuffer;
        reply->MessageId = Header->MessageId;
        reply->Status = 0;  // Success
        reply->Reserved = 0;
        *ReturnOutputBufferLength = sizeof(SHADOWSTRIKE_GENERIC_REPLY);
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Handle configuration update message.
 */
static NTSTATUS
MhpHandleConfigUpdate(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PFILTER_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PSHADOWSTRIKE_GENERIC_REPLY reply;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);
    UNREFERENCED_PARAMETER(Header);
    UNREFERENCED_PARAMETER(PayloadBuffer);
    UNREFERENCED_PARAMETER(PayloadSize);

    *ReturnOutputBufferLength = 0;

    //
    // ConfigUpdate is typically handled via PolicyUpdate
    // This is a legacy/compatibility handler
    //

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MH] ConfigUpdate received (use PolicyUpdate for new clients)\n");

    if (OutputBuffer != NULL && OutputBufferSize >= sizeof(SHADOWSTRIKE_GENERIC_REPLY)) {
        reply = (PSHADOWSTRIKE_GENERIC_REPLY)OutputBuffer;
        reply->MessageId = Header->MessageId;
        reply->Status = 0;
        reply->Reserved = 0;
        *ReturnOutputBufferLength = sizeof(SHADOWSTRIKE_GENERIC_REPLY);
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Handle policy update message.
 */
static NTSTATUS
MhpHandlePolicyUpdate(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PFILTER_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PSHADOWSTRIKE_POLICY_UPDATE policy;
    PSHADOWSTRIKE_GENERIC_REPLY reply;
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);

    *ReturnOutputBufferLength = 0;

    //
    // Validate payload
    //
    if (PayloadBuffer == NULL || PayloadSize < sizeof(SHADOWSTRIKE_POLICY_UPDATE)) {
        return STATUS_INVALID_PARAMETER;
    }

    policy = (PSHADOWSTRIKE_POLICY_UPDATE)PayloadBuffer;

    //
    // Validate policy values
    //
    if (policy->ScanTimeoutMs < SHADOWSTRIKE_MIN_SCAN_TIMEOUT_MS ||
        policy->ScanTimeoutMs > SHADOWSTRIKE_MAX_SCAN_TIMEOUT_MS) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MH] Invalid scan timeout: %u\n", policy->ScanTimeoutMs);
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Apply policy to driver configuration
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ConfigLock);

    g_DriverData.Config.ScanOnOpen = policy->ScanOnOpen;
    g_DriverData.Config.ScanOnExecute = policy->ScanOnExecute;
    g_DriverData.Config.ScanOnWrite = policy->ScanOnWrite;
    g_DriverData.Config.NotificationsEnabled = policy->EnableNotifications;
    g_DriverData.Config.BlockOnTimeout = policy->BlockOnTimeout;
    g_DriverData.Config.BlockOnError = policy->BlockOnError;
    g_DriverData.Config.ScanNetworkFiles = policy->ScanNetworkFiles;
    g_DriverData.Config.ScanRemovableMedia = policy->ScanRemovableMedia;
    g_DriverData.Config.MaxScanFileSize = policy->MaxScanFileSize;
    g_DriverData.Config.ScanTimeoutMs = policy->ScanTimeoutMs;
    g_DriverData.Config.CacheTTLSeconds = policy->CacheTTLSeconds;
    g_DriverData.Config.MaxPendingRequests = policy->MaxPendingRequests;

    ExReleasePushLockExclusive(&g_DriverData.ConfigLock);
    KeLeaveCriticalRegion();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MH] Policy updated: ScanOnOpen=%d, ScanOnExec=%d, Timeout=%u\n",
               policy->ScanOnOpen, policy->ScanOnExecute, policy->ScanTimeoutMs);

    //
    // Send reply
    //
    if (OutputBuffer != NULL && OutputBufferSize >= sizeof(SHADOWSTRIKE_GENERIC_REPLY)) {
        reply = (PSHADOWSTRIKE_GENERIC_REPLY)OutputBuffer;
        reply->MessageId = Header->MessageId;
        reply->Status = (UINT32)status;
        reply->Reserved = 0;
        *ReturnOutputBufferLength = sizeof(SHADOWSTRIKE_GENERIC_REPLY);
    }

    return status;
}

/**
 * @brief Handle driver status query.
 */
static NTSTATUS
MhpHandleDriverStatusQuery(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PFILTER_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PSHADOWSTRIKE_DRIVER_STATUS driverStatus;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);
    UNREFERENCED_PARAMETER(Header);
    UNREFERENCED_PARAMETER(PayloadBuffer);
    UNREFERENCED_PARAMETER(PayloadSize);

    *ReturnOutputBufferLength = 0;

    //
    // Validate output buffer
    //
    if (OutputBuffer == NULL || OutputBufferSize < sizeof(SHADOWSTRIKE_DRIVER_STATUS)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    driverStatus = (PSHADOWSTRIKE_DRIVER_STATUS)OutputBuffer;
    RtlZeroMemory(driverStatus, sizeof(SHADOWSTRIKE_DRIVER_STATUS));

    //
    // Fill driver status
    //
    driverStatus->VersionMajor = SHADOWSTRIKE_VERSION_MAJOR;
    driverStatus->VersionMinor = SHADOWSTRIKE_VERSION_MINOR;
    driverStatus->VersionBuild = SHADOWSTRIKE_VERSION_BUILD;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_DriverData.ConfigLock);

    driverStatus->FilteringActive = g_DriverData.Config.FilteringEnabled && g_DriverData.FilteringStarted;
    driverStatus->ScanOnOpenEnabled = g_DriverData.Config.ScanOnOpen;
    driverStatus->ScanOnExecuteEnabled = g_DriverData.Config.ScanOnExecute;
    driverStatus->ScanOnWriteEnabled = g_DriverData.Config.ScanOnWrite;
    driverStatus->NotificationsEnabled = g_DriverData.Config.NotificationsEnabled;

    ExReleasePushLockShared(&g_DriverData.ConfigLock);
    KeLeaveCriticalRegion();

    driverStatus->TotalFilesScanned = (UINT64)g_DriverData.Stats.TotalFilesScanned;
    driverStatus->FilesBlocked = (UINT64)g_DriverData.Stats.FilesBlocked;
    driverStatus->CacheHits = (UINT64)g_DriverData.Stats.CacheHits;
    driverStatus->CacheMisses = (UINT64)g_DriverData.Stats.CacheMisses;
    driverStatus->PendingRequests = g_DriverData.Stats.PendingRequests;
    driverStatus->PeakPendingRequests = g_DriverData.Stats.PeakPendingRequests;
    driverStatus->ConnectedClients = g_DriverData.ConnectedClients;

    *ReturnOutputBufferLength = sizeof(SHADOWSTRIKE_DRIVER_STATUS);

    return STATUS_SUCCESS;
}

/**
 * @brief Handle protected process registration.
 */
static NTSTATUS
MhpHandleProtectedProcessRegister(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PFILTER_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PSHADOWSTRIKE_PROTECTED_PROCESS request;
    PSHADOWSTRIKE_GENERIC_REPLY reply;
    PMH_PROTECTED_PROCESS newEntry;
    PLIST_ENTRY entry;
    PMH_PROTECTED_PROCESS existingEntry;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN found = FALSE;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);

    *ReturnOutputBufferLength = 0;

    //
    // Validate payload
    //
    if (PayloadBuffer == NULL || PayloadSize < sizeof(SHADOWSTRIKE_PROTECTED_PROCESS)) {
        return STATUS_INVALID_PARAMETER;
    }

    request = (PSHADOWSTRIKE_PROTECTED_PROCESS)PayloadBuffer;

    //
    // Validate process ID
    //
    if (request->ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Check limit
    //
    if (g_MhGlobals.ProtectedProcessCount >= MH_MAX_PROTECTED_PROCESSES) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MH] Max protected processes reached (%d)\n",
                   MH_MAX_PROTECTED_PROCESSES);
        return SHADOWSTRIKE_ERROR_MAX_PROTECTED;
    }

    //
    // Check if already registered
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_MhGlobals.ProtectedProcessLock);

    for (entry = g_MhGlobals.ProtectedProcessList.Flink;
         entry != &g_MhGlobals.ProtectedProcessList;
         entry = entry->Flink)
    {
        existingEntry = CONTAINING_RECORD(entry, MH_PROTECTED_PROCESS, ListEntry);
        if (existingEntry->ProcessId == request->ProcessId) {
            //
            // Update existing entry
            //
            existingEntry->ProtectionFlags = request->ProtectionFlags;
            RtlCopyMemory(existingEntry->ProcessName, request->ProcessName,
                          sizeof(existingEntry->ProcessName));
            found = TRUE;
            break;
        }
    }

    if (!found) {
        //
        // Allocate new entry
        //
        newEntry = (PMH_PROTECTED_PROCESS)ExAllocateFromNPagedLookasideList(
            &g_MhGlobals.ProtectedProcessLookaside);

        if (newEntry == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
        } else {
            RtlZeroMemory(newEntry, sizeof(MH_PROTECTED_PROCESS));
            newEntry->ProcessId = request->ProcessId;
            newEntry->ProtectionFlags = request->ProtectionFlags;
            KeQuerySystemTime(&newEntry->RegistrationTime);
            RtlCopyMemory(newEntry->ProcessName, request->ProcessName,
                          sizeof(newEntry->ProcessName));

            InsertTailList(&g_MhGlobals.ProtectedProcessList, &newEntry->ListEntry);
            InterlockedIncrement(&g_MhGlobals.ProtectedProcessCount);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[ShadowStrike/MH] Protected process registered: PID=%u, Flags=0x%08X\n",
                       request->ProcessId, request->ProtectionFlags);
        }
    }

    ExReleasePushLockExclusive(&g_MhGlobals.ProtectedProcessLock);
    KeLeaveCriticalRegion();

    //
    // Also add to driver's protected process list for self-protection callbacks
    //
    // (This would integrate with the object callback protection)
    //

    //
    // Send reply
    //
    if (OutputBuffer != NULL && OutputBufferSize >= sizeof(SHADOWSTRIKE_GENERIC_REPLY)) {
        reply = (PSHADOWSTRIKE_GENERIC_REPLY)OutputBuffer;
        reply->MessageId = Header->MessageId;
        reply->Status = (UINT32)status;
        reply->Reserved = 0;
        *ReturnOutputBufferLength = sizeof(SHADOWSTRIKE_GENERIC_REPLY);
    }

    return status;
}

/**
 * @brief Handle scan verdict message (response to a scan request).
 */
static NTSTATUS
MhpHandleScanVerdict(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PFILTER_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PSHADOWSTRIKE_SCAN_VERDICT_REPLY verdict;
    NTSTATUS status;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferSize);

    *ReturnOutputBufferLength = 0;

    //
    // Validate payload
    //
    if (PayloadBuffer == NULL || PayloadSize < sizeof(SHADOWSTRIKE_SCAN_VERDICT_REPLY)) {
        return STATUS_INVALID_PARAMETER;
    }

    verdict = (PSHADOWSTRIKE_SCAN_VERDICT_REPLY)PayloadBuffer;

    //
    // Route to MessageQueue completion mechanism
    // This completes the blocking message waiting for this verdict
    //
    status = MqCompleteMessage(
        verdict->MessageId,
        STATUS_SUCCESS,
        verdict,
        PayloadSize
    );

    if (!NT_SUCCESS(status) && status != STATUS_NOT_FOUND) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MH] Failed to complete scan verdict: id=%llu, status=0x%08X\n",
                   verdict->MessageId, status);
    }

    //
    // Update statistics
    //
    SHADOWSTRIKE_INC_STAT(RepliesReceived);

    return STATUS_SUCCESS;
}

/**
 * @brief Handle enable filtering command.
 */
static NTSTATUS
MhpHandleEnableFiltering(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PFILTER_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PSHADOWSTRIKE_GENERIC_REPLY reply;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);
    UNREFERENCED_PARAMETER(PayloadBuffer);
    UNREFERENCED_PARAMETER(PayloadSize);

    *ReturnOutputBufferLength = 0;

    //
    // Enable filtering
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ConfigLock);

    g_DriverData.Config.FilteringEnabled = TRUE;

    ExReleasePushLockExclusive(&g_DriverData.ConfigLock);
    KeLeaveCriticalRegion();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MH] Filtering enabled\n");

    //
    // Send reply
    //
    if (OutputBuffer != NULL && OutputBufferSize >= sizeof(SHADOWSTRIKE_GENERIC_REPLY)) {
        reply = (PSHADOWSTRIKE_GENERIC_REPLY)OutputBuffer;
        reply->MessageId = Header->MessageId;
        reply->Status = 0;
        reply->Reserved = 0;
        *ReturnOutputBufferLength = sizeof(SHADOWSTRIKE_GENERIC_REPLY);
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Handle disable filtering command.
 */
static NTSTATUS
MhpHandleDisableFiltering(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PFILTER_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PSHADOWSTRIKE_GENERIC_REPLY reply;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);
    UNREFERENCED_PARAMETER(PayloadBuffer);
    UNREFERENCED_PARAMETER(PayloadSize);

    *ReturnOutputBufferLength = 0;

    //
    // Disable filtering
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ConfigLock);

    g_DriverData.Config.FilteringEnabled = FALSE;

    ExReleasePushLockExclusive(&g_DriverData.ConfigLock);
    KeLeaveCriticalRegion();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MH] Filtering disabled\n");

    //
    // Send reply
    //
    if (OutputBuffer != NULL && OutputBufferSize >= sizeof(SHADOWSTRIKE_GENERIC_REPLY)) {
        reply = (PSHADOWSTRIKE_GENERIC_REPLY)OutputBuffer;
        reply->MessageId = Header->MessageId;
        reply->Status = 0;
        reply->Reserved = 0;
        *ReturnOutputBufferLength = sizeof(SHADOWSTRIKE_GENERIC_REPLY);
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// PROTECTED PROCESS QUERIES
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
    )
{
    PLIST_ENTRY entry;
    PMH_PROTECTED_PROCESS protectedProcess;
    BOOLEAN found = FALSE;

    if (ProcessId == 0) {
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_MhGlobals.ProtectedProcessLock);

    for (entry = g_MhGlobals.ProtectedProcessList.Flink;
         entry != &g_MhGlobals.ProtectedProcessList;
         entry = entry->Flink)
    {
        protectedProcess = CONTAINING_RECORD(entry, MH_PROTECTED_PROCESS, ListEntry);
        if (protectedProcess->ProcessId == ProcessId) {
            found = TRUE;
            break;
        }
    }

    ExReleasePushLockShared(&g_MhGlobals.ProtectedProcessLock);
    KeLeaveCriticalRegion();

    return found;
}

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
    )
{
    PLIST_ENTRY entry;
    PMH_PROTECTED_PROCESS protectedProcess;
    NTSTATUS status = STATUS_NOT_FOUND;

    *Flags = 0;

    if (ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_MhGlobals.ProtectedProcessLock);

    for (entry = g_MhGlobals.ProtectedProcessList.Flink;
         entry != &g_MhGlobals.ProtectedProcessList;
         entry = entry->Flink)
    {
        protectedProcess = CONTAINING_RECORD(entry, MH_PROTECTED_PROCESS, ListEntry);
        if (protectedProcess->ProcessId == ProcessId) {
            *Flags = protectedProcess->ProtectionFlags;
            status = STATUS_SUCCESS;
            break;
        }
    }

    ExReleasePushLockShared(&g_MhGlobals.ProtectedProcessLock);
    KeLeaveCriticalRegion();

    return status;
}

/**
 * @brief Remove a protected process (e.g., on process termination).
 *
 * @param ProcessId Process ID to remove.
 *
 * @return STATUS_SUCCESS if removed, STATUS_NOT_FOUND otherwise.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
MhUnprotectProcess(
    _In_ UINT32 ProcessId
    )
{
    PLIST_ENTRY entry;
    PMH_PROTECTED_PROCESS protectedProcess;
    NTSTATUS status = STATUS_NOT_FOUND;

    if (ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_MhGlobals.ProtectedProcessLock);

    for (entry = g_MhGlobals.ProtectedProcessList.Flink;
         entry != &g_MhGlobals.ProtectedProcessList;
         entry = entry->Flink)
    {
        protectedProcess = CONTAINING_RECORD(entry, MH_PROTECTED_PROCESS, ListEntry);
        if (protectedProcess->ProcessId == ProcessId) {
            RemoveEntryList(&protectedProcess->ListEntry);
            ExFreeToNPagedLookasideList(&g_MhGlobals.ProtectedProcessLookaside, protectedProcess);
            InterlockedDecrement(&g_MhGlobals.ProtectedProcessCount);
            status = STATUS_SUCCESS;

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[ShadowStrike/MH] Protected process removed: PID=%u\n", ProcessId);
            break;
        }
    }

    ExReleasePushLockExclusive(&g_MhGlobals.ProtectedProcessLock);
    KeLeaveCriticalRegion();

    return status;
}
