/**
 * ============================================================================
 * ShadowStrike NGAV - COMMUNICATION PORT
 * ============================================================================
 *
 * @file CommPort.c
 * @brief Filter Manager communication port implementation.
 *
 * Implements the kernel-to-user-mode communication channel using
 * Filter Manager communication ports.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "CommPort.h"
#include "../Core/Globals.h"
#include "../Shared/SharedDefs.h"
#include "../Shared/PortName.h"
#include "../Shared/MessageTypes.h"
#include "../Shared/ErrorCodes.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ShadowStrikeCreateCommunicationPort)
#pragma alloc_text(PAGE, ShadowStrikeCloseCommunicationPort)
#pragma alloc_text(PAGE, ShadowStrikeConnectNotify)
#pragma alloc_text(PAGE, ShadowStrikeDisconnectNotify)
#endif

// ============================================================================
// PORT CREATION AND DESTRUCTION
// ============================================================================

NTSTATUS
ShadowStrikeCreateCommunicationPort(
    _In_ PFLT_FILTER FilterHandle
    )
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING portName;

    PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Creating communication port: %ws\n",
               SHADOWSTRIKE_PORT_NAME);

    //
    // Create security descriptor that allows admin access
    //
    status = FltBuildDefaultSecurityDescriptor(
        &securityDescriptor,
        FLT_PORT_ALL_ACCESS
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] FltBuildDefaultSecurityDescriptor failed: 0x%08X\n",
                   status);
        return status;
    }

    RtlInitUnicodeString(&portName, SHADOWSTRIKE_PORT_NAME);

    InitializeObjectAttributes(
        &objectAttributes,
        &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        securityDescriptor
    );

    //
    // Create the server port
    //
    status = FltCreateCommunicationPort(
        FilterHandle,
        &g_DriverData.ServerPort,
        &objectAttributes,
        NULL,                               // ServerPortCookie
        ShadowStrikeConnectNotify,          // ConnectNotifyCallback
        ShadowStrikeDisconnectNotify,       // DisconnectNotifyCallback
        ShadowStrikeMessageNotify,          // MessageNotifyCallback
        SHADOWSTRIKE_PORT_MAX_CONNECTIONS   // MaxConnections
    );

    FltFreeSecurityDescriptor(securityDescriptor);

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] FltCreateCommunicationPort failed: 0x%08X\n",
                   status);
        g_DriverData.ServerPort = NULL;
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Communication port created successfully\n");

    return STATUS_SUCCESS;
}

VOID
ShadowStrikeCloseCommunicationPort(
    VOID
    )
{
    LONG i;

    PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Closing communication port\n");

    //
    // Close all client ports first
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ClientPortLock);

    for (i = 0; i < SHADOWSTRIKE_MAX_CONNECTIONS; i++) {
        if (g_DriverData.ClientPorts[i].ClientPort != NULL) {
            FltCloseClientPort(
                g_DriverData.FilterHandle,
                &g_DriverData.ClientPorts[i].ClientPort
            );
            g_DriverData.ClientPorts[i].ClientPort = NULL;
            g_DriverData.ClientPorts[i].ClientProcessId = NULL;
        }
    }

    g_DriverData.ConnectedClients = 0;

    ExReleasePushLockExclusive(&g_DriverData.ClientPortLock);
    KeLeaveCriticalRegion();

    //
    // Close the server port
    //
    if (g_DriverData.ServerPort != NULL) {
        FltCloseCommunicationPort(g_DriverData.ServerPort);
        g_DriverData.ServerPort = NULL;
    }
}

// ============================================================================
// CONNECTION CALLBACKS
// ============================================================================

NTSTATUS
ShadowStrikeConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionPortCookie
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    LONG slotIndex = -1;
    LONG i;
    HANDLE clientProcessId;
    BOOLEAN isPrimaryScanner = FALSE;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(ServerPortCookie);

    *ConnectionPortCookie = NULL;

    //
    // Get client process ID
    //
    clientProcessId = PsGetCurrentProcessId();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Client connecting: PID=%p\n", clientProcessId);

    //
    // Validate connection context if provided
    //
    if (ConnectionContext != NULL && SizeOfContext >= sizeof(UINT32)) {
        // First DWORD could be a connection type indicator
        UINT32 connectionType = *(PUINT32)ConnectionContext;
        if (connectionType == 1) {
            isPrimaryScanner = TRUE;
        }
    }

    //
    // Find available slot
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ClientPortLock);

    // Check if already at max connections
    if (g_DriverData.ConnectedClients >= SHADOWSTRIKE_MAX_CONNECTIONS) {
        ExReleasePushLockExclusive(&g_DriverData.ClientPortLock);
        KeLeaveCriticalRegion();

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Connection rejected: max connections reached\n");
        return STATUS_CONNECTION_COUNT_LIMIT;
    }

    // Find empty slot
    for (i = 0; i < SHADOWSTRIKE_MAX_CONNECTIONS; i++) {
        if (g_DriverData.ClientPorts[i].ClientPort == NULL) {
            slotIndex = i;
            break;
        }
    }

    if (slotIndex < 0) {
        ExReleasePushLockExclusive(&g_DriverData.ClientPortLock);
        KeLeaveCriticalRegion();

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] No available client slots\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize client slot
    //
    RtlZeroMemory(&g_DriverData.ClientPorts[slotIndex], sizeof(SHADOWSTRIKE_CLIENT_PORT));
    g_DriverData.ClientPorts[slotIndex].ClientPort = ClientPort;
    g_DriverData.ClientPorts[slotIndex].ClientProcessId = clientProcessId;
    g_DriverData.ClientPorts[slotIndex].IsPrimaryScanner = isPrimaryScanner;
    KeQuerySystemTime(&g_DriverData.ClientPorts[slotIndex].ConnectedTime);

    InterlockedIncrement(&g_DriverData.ConnectedClients);

    ExReleasePushLockExclusive(&g_DriverData.ClientPortLock);
    KeLeaveCriticalRegion();

    //
    // Return slot index as cookie for disconnect
    //
    *ConnectionPortCookie = (PVOID)(ULONG_PTR)(slotIndex + 1);  // +1 to avoid NULL

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Client connected: slot=%ld, primary=%d, total=%ld\n",
               slotIndex, isPrimaryScanner, g_DriverData.ConnectedClients);

    return status;
}

VOID
ShadowStrikeDisconnectNotify(
    _In_opt_ PVOID ConnectionCookie
    )
{
    LONG slotIndex;

    PAGED_CODE();

    if (ConnectionCookie == NULL) {
        return;
    }

    slotIndex = (LONG)(ULONG_PTR)ConnectionCookie - 1;  // -1 to reverse +1 from connect

    if (slotIndex < 0 || slotIndex >= SHADOWSTRIKE_MAX_CONNECTIONS) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Invalid disconnect cookie: %p\n", ConnectionCookie);
        return;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Client disconnecting: slot=%ld\n", slotIndex);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ClientPortLock);

    if (g_DriverData.ClientPorts[slotIndex].ClientPort != NULL) {
        //
        // Close the client port
        //
        FltCloseClientPort(
            g_DriverData.FilterHandle,
            &g_DriverData.ClientPorts[slotIndex].ClientPort
        );

        g_DriverData.ClientPorts[slotIndex].ClientPort = NULL;
        g_DriverData.ClientPorts[slotIndex].ClientProcessId = NULL;

        InterlockedDecrement(&g_DriverData.ConnectedClients);
    }

    ExReleasePushLockExclusive(&g_DriverData.ClientPortLock);
    KeLeaveCriticalRegion();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Client disconnected, remaining=%ld\n",
               g_DriverData.ConnectedClients);
}

// ============================================================================
// MESSAGE HANDLING
// ============================================================================

NTSTATUS
ShadowStrikeMessageNotify(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PSHADOWSTRIKE_MESSAGE_HEADER header;
    LONG slotIndex;

    *ReturnOutputBufferLength = 0;

    //
    // Validate parameters
    //
    if (InputBuffer == NULL || InputBufferLength < sizeof(SHADOWSTRIKE_MESSAGE_HEADER)) {
        return STATUS_INVALID_PARAMETER;
    }

    header = (PSHADOWSTRIKE_MESSAGE_HEADER)InputBuffer;

    //
    // Validate message header
    //
    if (!SHADOWSTRIKE_VALID_MESSAGE_HEADER(header)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Invalid message header from user-mode\n");
        return STATUS_INVALID_PARAMETER;
    }

    slotIndex = (LONG)(ULONG_PTR)PortCookie - 1;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] Message received: type=%u, id=%llu, slot=%ld\n",
               header->MessageType, header->MessageId, slotIndex);

    //
    // Dispatch based on message type
    //
    switch (header->MessageType) {

        case ShadowStrikeMessageQueryDriverStatus: {
            //
            // Return driver status
            //
            if (OutputBuffer == NULL ||
                OutputBufferLength < sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + sizeof(SHADOWSTRIKE_DRIVER_STATUS)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            PSHADOWSTRIKE_MESSAGE_HEADER replyHeader = (PSHADOWSTRIKE_MESSAGE_HEADER)OutputBuffer;
            PSHADOWSTRIKE_DRIVER_STATUS driverStatus =
                (PSHADOWSTRIKE_DRIVER_STATUS)((PUCHAR)OutputBuffer + sizeof(SHADOWSTRIKE_MESSAGE_HEADER));

            ShadowStrikeInitMessageHeader(
                replyHeader,
                ShadowStrikeMessageQueryDriverStatus,
                sizeof(SHADOWSTRIKE_DRIVER_STATUS)
            );

            RtlZeroMemory(driverStatus, sizeof(SHADOWSTRIKE_DRIVER_STATUS));
            driverStatus->VersionMajor = SHADOWSTRIKE_VERSION_MAJOR;
            driverStatus->VersionMinor = SHADOWSTRIKE_VERSION_MINOR;
            driverStatus->VersionBuild = SHADOWSTRIKE_VERSION_BUILD;
            driverStatus->FilteringActive = g_DriverData.FilteringStarted;
            driverStatus->ScanOnOpenEnabled = g_DriverData.Config.ScanOnOpen;
            driverStatus->ScanOnExecuteEnabled = g_DriverData.Config.ScanOnExecute;
            driverStatus->ScanOnWriteEnabled = g_DriverData.Config.ScanOnWrite;
            driverStatus->NotificationsEnabled = g_DriverData.Config.NotificationsEnabled;
            driverStatus->TotalFilesScanned = g_DriverData.Stats.TotalFilesScanned;
            driverStatus->FilesBlocked = g_DriverData.Stats.FilesBlocked;
            driverStatus->PendingRequests = g_DriverData.Stats.PendingRequests;
            driverStatus->PeakPendingRequests = g_DriverData.Stats.PeakPendingRequests;
            driverStatus->CacheHits = g_DriverData.Stats.CacheHits;
            driverStatus->CacheMisses = g_DriverData.Stats.CacheMisses;
            driverStatus->ConnectedClients = g_DriverData.ConnectedClients;

            *ReturnOutputBufferLength = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + sizeof(SHADOWSTRIKE_DRIVER_STATUS);
            break;
        }

        case ShadowStrikeMessageUpdatePolicy: {
            //
            // Update driver policy
            //
            if (InputBufferLength < sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + sizeof(SHADOWSTRIKE_POLICY_UPDATE)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            PSHADOWSTRIKE_POLICY_UPDATE policy =
                (PSHADOWSTRIKE_POLICY_UPDATE)((PUCHAR)InputBuffer + sizeof(SHADOWSTRIKE_MESSAGE_HEADER));

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

            ExReleasePushLockExclusive(&g_DriverData.ConfigLock);
            KeLeaveCriticalRegion();

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[ShadowStrike] Policy updated\n");
            break;
        }

        case ShadowStrikeMessageEnableFiltering: {
            g_DriverData.Config.FilteringEnabled = TRUE;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[ShadowStrike] Filtering enabled\n");
            break;
        }

        case ShadowStrikeMessageDisableFiltering: {
            g_DriverData.Config.FilteringEnabled = FALSE;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[ShadowStrike] Filtering disabled\n");
            break;
        }

        case ShadowStrikeMessageRegisterProtectedProcess: {
            //
            // Register a process for self-protection
            //
            if (InputBufferLength < sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + sizeof(SHADOWSTRIKE_PROTECTED_PROCESS)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            // TODO: Add to protected process list
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[ShadowStrike] Protected process registration received\n");
            break;
        }

        case ShadowStrikeMessageHeartbeat: {
            //
            // Heartbeat - just acknowledge
            //
            if (OutputBuffer != NULL && OutputBufferLength >= sizeof(SHADOWSTRIKE_GENERIC_REPLY)) {
                PSHADOWSTRIKE_GENERIC_REPLY reply = (PSHADOWSTRIKE_GENERIC_REPLY)OutputBuffer;
                reply->MessageId = header->MessageId;
                reply->Status = 0;
                reply->Reserved = 0;
                *ReturnOutputBufferLength = sizeof(SHADOWSTRIKE_GENERIC_REPLY);
            }
            break;
        }

        case ShadowStrikeMessageScanVerdict: {
            //
            // This is a reply to a scan request - handled via FltSendMessage reply
            //
            SHADOWSTRIKE_INC_STAT(RepliesReceived);
            break;
        }

        default:
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] Unknown message type: %u\n", header->MessageType);
            status = STATUS_INVALID_PARAMETER;
            break;
    }

    return status;
}

// ============================================================================
// MESSAGE SENDING
// ============================================================================

NTSTATUS
ShadowStrikeSendScanRequest(
    _In_reads_bytes_(RequestSize) PSHADOWSTRIKE_MESSAGE_HEADER Request,
    _In_ ULONG RequestSize,
    _Out_writes_bytes_to_(*ReplySize, *ReplySize) PSHADOWSTRIKE_SCAN_VERDICT_REPLY Reply,
    _Inout_ PULONG ReplySize,
    _In_ ULONG TimeoutMs
    )
{
    NTSTATUS status;
    PFLT_PORT clientPort = NULL;
    LARGE_INTEGER timeout;
    LONG pendingCount;

    //
    // Validate parameters
    //
    if (Request == NULL || Reply == NULL || ReplySize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Check if user-mode is connected
    //
    if (!ShadowStrikeIsUserModeConnected()) {
        return SHADOWSTRIKE_ERROR_PORT_NOT_CONNECTED;
    }

    //
    // Check pending request limit
    //
    pendingCount = InterlockedIncrement(&g_DriverData.Stats.PendingRequests);
    if (pendingCount > g_DriverData.Stats.PeakPendingRequests) {
        InterlockedExchange(&g_DriverData.Stats.PeakPendingRequests, pendingCount);
    }

    if ((ULONG)pendingCount > g_DriverData.Config.MaxPendingRequests) {
        InterlockedDecrement(&g_DriverData.Stats.PendingRequests);
        SHADOWSTRIKE_INC_STAT(MessagesDropped);
        return SHADOWSTRIKE_ERROR_QUEUE_FULL;
    }

    //
    // Get primary scanner port
    //
    clientPort = ShadowStrikeGetPrimaryScannerPort();
    if (clientPort == NULL) {
        InterlockedDecrement(&g_DriverData.Stats.PendingRequests);
        return SHADOWSTRIKE_ERROR_PORT_NOT_CONNECTED;
    }

    //
    // Calculate timeout (negative = relative)
    //
    timeout.QuadPart = -(LONGLONG)TimeoutMs * 10000LL;

    //
    // Send message and wait for reply
    //
    status = FltSendMessage(
        g_DriverData.FilterHandle,
        &clientPort,
        Request,
        RequestSize,
        Reply,
        ReplySize,
        &timeout
    );

    InterlockedDecrement(&g_DriverData.Stats.PendingRequests);

    if (NT_SUCCESS(status)) {
        SHADOWSTRIKE_INC_STAT(MessagesSent);
        SHADOWSTRIKE_INC_STAT(RepliesReceived);
    } else if (status == STATUS_TIMEOUT) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Scan request timeout (id=%llu)\n",
                   Request->MessageId);
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] FltSendMessage failed: 0x%08X\n", status);
    }

    return status;
}

NTSTATUS
ShadowStrikeSendNotification(
    _In_reads_bytes_(Size) PSHADOWSTRIKE_MESSAGE_HEADER Notification,
    _In_ ULONG Size
    )
{
    NTSTATUS status;
    PFLT_PORT clientPort = NULL;
    ULONG replySize = 0;

    if (!g_DriverData.Config.NotificationsEnabled) {
        return STATUS_SUCCESS;
    }

    if (!ShadowStrikeIsUserModeConnected()) {
        return SHADOWSTRIKE_ERROR_PORT_NOT_CONNECTED;
    }

    clientPort = ShadowStrikeGetPrimaryScannerPort();
    if (clientPort == NULL) {
        return SHADOWSTRIKE_ERROR_PORT_NOT_CONNECTED;
    }

    //
    // Send without waiting for reply (NULL timeout = no wait for reply)
    //
    status = FltSendMessage(
        g_DriverData.FilterHandle,
        &clientPort,
        Notification,
        Size,
        NULL,
        &replySize,
        NULL
    );

    if (NT_SUCCESS(status)) {
        SHADOWSTRIKE_INC_STAT(MessagesSent);
    }

    return status;
}

NTSTATUS
ShadowStrikeSendProcessNotification(
    _In_reads_bytes_(Size) PSHADOWSTRIKE_PROCESS_NOTIFICATION Notification,
    _In_ ULONG Size,
    _In_ BOOLEAN RequireReply,
    _Out_writes_bytes_opt_(*ReplySize) PSHADOWSTRIKE_PROCESS_VERDICT_REPLY Reply,
    _Inout_opt_ PULONG ReplySize
    )
{
    NTSTATUS status;
    PFLT_PORT clientPort = NULL;
    LARGE_INTEGER timeout;
    LONG pendingCount;
    PSHADOWSTRIKE_MESSAGE_HEADER header = NULL;
    ULONG totalSize;
    ULONG replyBufferSize = 0;

    //
    // Validate parameters
    //
    if (Notification == NULL || Size < sizeof(SHADOWSTRIKE_PROCESS_NOTIFICATION)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (RequireReply && (Reply == NULL || ReplySize == NULL)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Check if notifications are enabled
    //
    if (!g_DriverData.Config.NotificationsEnabled) {
        return STATUS_SUCCESS;
    }

    //
    // Check if user-mode is connected
    //
    if (!ShadowStrikeIsUserModeConnected()) {
        return SHADOWSTRIKE_ERROR_PORT_NOT_CONNECTED;
    }

    //
    // Get primary scanner port
    //
    clientPort = ShadowStrikeGetPrimaryScannerPort();
    if (clientPort == NULL) {
        return SHADOWSTRIKE_ERROR_PORT_NOT_CONNECTED;
    }

    //
    // Calculate total message size (header + notification data)
    //
    totalSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + Size;

    //
    // Allocate message buffer
    //
    header = (PSHADOWSTRIKE_MESSAGE_HEADER)ShadowStrikeAllocateMessageBuffer(totalSize);
    if (header == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize message header
    //
    ShadowStrikeInitMessageHeader(
        header,
        ShadowStrikeMessageProcessNotify,
        Size
    );

    //
    // Copy notification data after header
    //
    RtlCopyMemory(
        (PUCHAR)header + sizeof(SHADOWSTRIKE_MESSAGE_HEADER),
        Notification,
        Size
    );

    //
    // Update pending request count if waiting for reply
    //
    if (RequireReply) {
        pendingCount = InterlockedIncrement(&g_DriverData.Stats.PendingRequests);
        if (pendingCount > g_DriverData.Stats.PeakPendingRequests) {
            InterlockedExchange(&g_DriverData.Stats.PeakPendingRequests, pendingCount);
        }

        //
        // Check pending request limit
        //
        if ((ULONG)pendingCount > g_DriverData.Config.MaxPendingRequests) {
            InterlockedDecrement(&g_DriverData.Stats.PendingRequests);
            ShadowStrikeFreeMessageBuffer(header);
            SHADOWSTRIKE_INC_STAT(MessagesDropped);
            return SHADOWSTRIKE_ERROR_QUEUE_FULL;
        }

        //
        // Set timeout (default 30 seconds for process decisions)
        //
        timeout.QuadPart = -(LONGLONG)g_DriverData.Config.ScanTimeoutMs * 10000LL;
        replyBufferSize = *ReplySize;

        //
        // Send message and wait for reply
        //
        status = FltSendMessage(
            g_DriverData.FilterHandle,
            &clientPort,
            header,
            totalSize,
            Reply,
            &replyBufferSize,
            &timeout
        );

        InterlockedDecrement(&g_DriverData.Stats.PendingRequests);

        if (NT_SUCCESS(status)) {
            SHADOWSTRIKE_INC_STAT(MessagesSent);
            SHADOWSTRIKE_INC_STAT(RepliesReceived);
            *ReplySize = replyBufferSize;

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                       "[ShadowStrike] Process notification sent, verdict received (id=%llu)\n",
                       header->MessageId);
        } else if (status == STATUS_TIMEOUT) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] Process notification timeout (id=%llu, pid=%u)\n",
                       header->MessageId, Notification->ProcessId);
            SHADOWSTRIKE_INC_STAT(Timeouts);
        } else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike] Process notification failed: 0x%08X (pid=%u)\n",
                       status, Notification->ProcessId);
        }
    } else {
        //
        // Fire-and-forget notification (no reply expected)
        //
        status = FltSendMessage(
            g_DriverData.FilterHandle,
            &clientPort,
            header,
            totalSize,
            NULL,
            &replyBufferSize,
            NULL  // No timeout = don't wait for reply
        );

        if (NT_SUCCESS(status)) {
            SHADOWSTRIKE_INC_STAT(MessagesSent);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                       "[ShadowStrike] Process notification sent (id=%llu, pid=%u)\n",
                       header->MessageId, Notification->ProcessId);
        } else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] Process notification send failed: 0x%08X\n", status);
        }
    }

    //
    // Free message buffer
    //
    ShadowStrikeFreeMessageBuffer(header);

    return status;
}

// ============================================================================
// CONNECTION STATE QUERIES
// ============================================================================

BOOLEAN
ShadowStrikeIsUserModeConnected(
    VOID
    )
{
    return (g_DriverData.ConnectedClients > 0);
}

LONG
ShadowStrikeGetConnectedClientCount(
    VOID
    )
{
    return g_DriverData.ConnectedClients;
}

PFLT_PORT
ShadowStrikeGetPrimaryScannerPort(
    VOID
    )
{
    PFLT_PORT port = NULL;
    LONG i;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_DriverData.ClientPortLock);

    // First try to find primary scanner
    for (i = 0; i < SHADOWSTRIKE_MAX_CONNECTIONS; i++) {
        if (g_DriverData.ClientPorts[i].ClientPort != NULL &&
            g_DriverData.ClientPorts[i].IsPrimaryScanner) {
            port = g_DriverData.ClientPorts[i].ClientPort;
            break;
        }
    }

    // Fall back to first connected client
    if (port == NULL) {
        for (i = 0; i < SHADOWSTRIKE_MAX_CONNECTIONS; i++) {
            if (g_DriverData.ClientPorts[i].ClientPort != NULL) {
                port = g_DriverData.ClientPorts[i].ClientPort;
                break;
            }
        }
    }

    ExReleasePushLockShared(&g_DriverData.ClientPortLock);
    KeLeaveCriticalRegion();

    return port;
}

// ============================================================================
// CLIENT MANAGEMENT
// ============================================================================

LONG
ShadowStrikeFindClientByProcessId(
    _In_ HANDLE ProcessId
    )
{
    LONG result = -1;
    LONG i;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_DriverData.ClientPortLock);

    for (i = 0; i < SHADOWSTRIKE_MAX_CONNECTIONS; i++) {
        if (g_DriverData.ClientPorts[i].ClientPort != NULL &&
            g_DriverData.ClientPorts[i].ClientProcessId == ProcessId) {
            result = i;
            break;
        }
    }

    ExReleasePushLockShared(&g_DriverData.ClientPortLock);
    KeLeaveCriticalRegion();

    return result;
}

BOOLEAN
ShadowStrikeValidateClient(
    _In_ LONG ClientIndex
    )
{
    BOOLEAN valid = FALSE;

    if (ClientIndex < 0 || ClientIndex >= SHADOWSTRIKE_MAX_CONNECTIONS) {
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_DriverData.ClientPortLock);

    valid = (g_DriverData.ClientPorts[ClientIndex].ClientPort != NULL);

    ExReleasePushLockShared(&g_DriverData.ClientPortLock);
    KeLeaveCriticalRegion();

    return valid;
}

// ============================================================================
// MESSAGE BUFFER ALLOCATION
// ============================================================================

PVOID
ShadowStrikeAllocateMessageBuffer(
    _In_ SIZE_T Size
    )
{
    PVOID buffer = NULL;

    if (Size <= SHADOWSTRIKE_MAX_MESSAGE_SIZE && g_DriverData.LookasideInitialized) {
        buffer = ExAllocateFromNPagedLookasideList(&g_DriverData.MessageLookaside);
    } else {
        buffer = ExAllocatePoolZero(
            NonPagedPoolNx,
            Size,
            SHADOWSTRIKE_POOL_TAG
        );
    }

    return buffer;
}

VOID
ShadowStrikeFreeMessageBuffer(
    _In_ PVOID Buffer
    )
{
    if (Buffer == NULL) {
        return;
    }

    if (g_DriverData.LookasideInitialized) {
        ExFreeToNPagedLookasideList(&g_DriverData.MessageLookaside, Buffer);
    } else {
        ExFreePoolWithTag(Buffer, SHADOWSTRIKE_POOL_TAG);
    }
}

// ============================================================================
// GENERIC MESSAGE SENDING
// ============================================================================

/**
 * @brief Send a message to user-mode via the communication port.
 *
 * This is the core message sending function used by all notification
 * and scan request functions. It handles client port selection, timeout
 * management, and statistics tracking.
 *
 * @param InputBuffer       Message to send.
 * @param InputBufferSize   Size of the input message.
 * @param OutputBuffer      Optional buffer for reply (NULL for fire-and-forget).
 * @param OutputBufferSize  Size of output buffer / receives actual reply size.
 * @param Timeout           Optional timeout (NULL for no wait, negative for relative).
 * @return STATUS_SUCCESS on success, STATUS_TIMEOUT on timeout, or error.
 */
NTSTATUS
ShadowStrikeSendMessage(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_opt_ PVOID OutputBuffer,
    _Inout_opt_ PULONG OutputBufferSize,
    _In_opt_ PLARGE_INTEGER Timeout
    )
{
    NTSTATUS status;
    PFLT_PORT clientPort = NULL;
    ULONG replySize = 0;
    LONG pendingCount;

    //
    // Validate parameters
    //
    if (InputBuffer == NULL || InputBufferSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Check if driver is ready
    //
    if (!SHADOWSTRIKE_IS_READY()) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Check if user-mode is connected
    //
    if (!ShadowStrikeIsUserModeConnected()) {
        return SHADOWSTRIKE_ERROR_PORT_NOT_CONNECTED;
    }

    //
    // Get primary scanner port
    //
    clientPort = ShadowStrikeGetPrimaryScannerPort();
    if (clientPort == NULL) {
        return SHADOWSTRIKE_ERROR_PORT_NOT_CONNECTED;
    }

    //
    // Track pending requests if expecting a reply
    //
    if (OutputBuffer != NULL && OutputBufferSize != NULL) {
        pendingCount = InterlockedIncrement(&g_DriverData.Stats.PendingRequests);
        if (pendingCount > g_DriverData.Stats.PeakPendingRequests) {
            InterlockedExchange(&g_DriverData.Stats.PeakPendingRequests, pendingCount);
        }

        //
        // Check pending request limit
        //
        if ((ULONG)pendingCount > g_DriverData.Config.MaxPendingRequests) {
            InterlockedDecrement(&g_DriverData.Stats.PendingRequests);
            SHADOWSTRIKE_INC_STAT(MessagesDropped);
            return SHADOWSTRIKE_ERROR_QUEUE_FULL;
        }

        replySize = *OutputBufferSize;
    }

    //
    // Send message via Filter Manager
    //
    status = FltSendMessage(
        g_DriverData.FilterHandle,
        &clientPort,
        InputBuffer,
        InputBufferSize,
        OutputBuffer,
        OutputBuffer ? &replySize : NULL,
        Timeout
    );

    //
    // Update pending count if we were tracking
    //
    if (OutputBuffer != NULL && OutputBufferSize != NULL) {
        InterlockedDecrement(&g_DriverData.Stats.PendingRequests);
        *OutputBufferSize = replySize;
    }

    //
    // Update statistics based on result
    //
    if (NT_SUCCESS(status)) {
        SHADOWSTRIKE_INC_STAT(MessagesSent);
        if (OutputBuffer != NULL) {
            SHADOWSTRIKE_INC_STAT(RepliesReceived);
        }
    } else if (status == STATUS_TIMEOUT) {
        SHADOWSTRIKE_INC_STAT(ScanTimeouts);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] ShadowStrikeSendMessage timeout\n");
    } else if (status == STATUS_PORT_DISCONNECTED) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] ShadowStrikeSendMessage: port disconnected\n");
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] ShadowStrikeSendMessage failed: 0x%08X\n", status);
    }

    return status;
}

// ============================================================================
// MESSAGE CONSTRUCTION HELPERS
// ============================================================================

VOID
ShadowStrikeInitMessageHeader(
    _Out_ PSHADOWSTRIKE_MESSAGE_HEADER Header,
    _In_ SHADOWSTRIKE_MESSAGE_TYPE MessageType,
    _In_ ULONG DataSize
    )
{
    LARGE_INTEGER timestamp;

    RtlZeroMemory(Header, sizeof(SHADOWSTRIKE_MESSAGE_HEADER));

    KeQuerySystemTime(&timestamp);

    Header->Magic = SHADOWSTRIKE_MESSAGE_MAGIC;
    Header->Version = SHADOWSTRIKE_PROTOCOL_VERSION;
    Header->MessageType = (UINT16)MessageType;
    Header->MessageId = SHADOWSTRIKE_NEXT_MESSAGE_ID();
    Header->TotalSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + DataSize;
    Header->DataSize = DataSize;
    Header->Timestamp = timestamp.QuadPart;
    Header->Flags = 0;
    Header->Reserved = 0;
}

NTSTATUS
ShadowStrikeBuildFileScanRequest(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ SHADOWSTRIKE_FILE_ACCESS_TYPE AccessType,
    _Out_ PSHADOWSTRIKE_MESSAGE_HEADER* Request,
    _Out_ PULONG RequestSize
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PSHADOWSTRIKE_MESSAGE_HEADER header = NULL;
    PSHADOWSTRIKE_FILE_SCAN_REQUEST scanRequest = NULL;
    ULONG totalSize;
    PWCHAR variableData;
    PEPROCESS process;
    UNICODE_STRING processName = {0};

    *Request = NULL;
    *RequestSize = 0;

    UNREFERENCED_PARAMETER(FltObjects);

    //
    // Get file name
    //
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    FltParseFileNameInformation(nameInfo);

    //
    // Get process name (simplified - just use process ID for now)
    //
    process = IoThreadToProcess(Data->Thread);
    // TODO: Get actual process name from EPROCESS

    //
    // Calculate total message size
    //
    totalSize = SHADOWSTRIKE_FILE_SCAN_REQUEST_SIZE(
        nameInfo->Name.Length / sizeof(WCHAR),
        processName.Length / sizeof(WCHAR)
    );

    //
    // Allocate message buffer
    //
    header = (PSHADOWSTRIKE_MESSAGE_HEADER)ShadowStrikeAllocateMessageBuffer(totalSize);
    if (header == NULL) {
        FltReleaseFileNameInformation(nameInfo);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize header
    //
    ShadowStrikeInitMessageHeader(
        header,
        (AccessType == ShadowStrikeAccessExecute) ?
            ShadowStrikeMessageFileScanOnExecute : ShadowStrikeMessageFileScanOnOpen,
        totalSize - sizeof(SHADOWSTRIKE_MESSAGE_HEADER)
    );

    //
    // Fill scan request
    //
    scanRequest = (PSHADOWSTRIKE_FILE_SCAN_REQUEST)((PUCHAR)header + sizeof(SHADOWSTRIKE_MESSAGE_HEADER));

    scanRequest->MessageId = header->MessageId;
    scanRequest->AccessType = (UINT8)AccessType;
    scanRequest->Disposition = 0;
    scanRequest->Priority = (UINT8)ShadowStrikePriorityNormal;
    scanRequest->RequiresReply = 1;
    scanRequest->ProcessId = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
    scanRequest->ThreadId = (UINT32)(ULONG_PTR)PsGetCurrentThreadId();
    scanRequest->ParentProcessId = 0;  // TODO
    scanRequest->SessionId = 0;  // TODO
    scanRequest->FileSize = 0;  // Set in post-create
    scanRequest->FileAttributes = 0;
    scanRequest->DesiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    scanRequest->ShareAccess = Data->Iopb->Parameters.Create.ShareAccess;
    scanRequest->CreateOptions = Data->Iopb->Parameters.Create.Options;
    scanRequest->VolumeSerial = 0;
    scanRequest->FileId = 0;
    scanRequest->IsDirectory = FALSE;
    scanRequest->IsNetworkFile = FALSE;
    scanRequest->IsRemovableMedia = FALSE;
    scanRequest->HasADS = FALSE;
    scanRequest->PathLength = nameInfo->Name.Length / sizeof(WCHAR);
    scanRequest->ProcessNameLength = processName.Length / sizeof(WCHAR);

    //
    // Copy variable-length data
    //
    variableData = (PWCHAR)((PUCHAR)scanRequest + sizeof(SHADOWSTRIKE_FILE_SCAN_REQUEST));

    // Copy file path
    if (nameInfo->Name.Length > 0) {
        RtlCopyMemory(variableData, nameInfo->Name.Buffer, nameInfo->Name.Length);
        variableData += nameInfo->Name.Length / sizeof(WCHAR);
    }

    // Copy process name
    if (processName.Length > 0) {
        RtlCopyMemory(variableData, processName.Buffer, processName.Length);
    }

    FltReleaseFileNameInformation(nameInfo);

    *Request = header;
    *RequestSize = totalSize;

    return STATUS_SUCCESS;
}
