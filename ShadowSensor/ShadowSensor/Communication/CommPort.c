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
 * @file CommPort.c
 * @brief Filter Manager communication port implementation.
 *
 * Implements the kernel-to-user-mode communication channel using
 * Filter Manager communication ports with:
 * - Reference counting for safe client port access
 * - Client authentication and capability-based authorization
 * - Proper user-mode buffer validation with try/except
 * - Protected process registration
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "CommPort.h"
#include "../Core/Globals.h"
#include "../../Shared/SharedDefs.h"
#include "../../Shared/PortName.h"
#include "../../Shared/MessageTypes.h"
#include "../../Shared/ErrorCodes.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ShadowStrikeCreateCommunicationPort)
#pragma alloc_text(PAGE, ShadowStrikeCloseCommunicationPort)
#pragma alloc_text(PAGE, ShadowStrikeConnectNotify)
#pragma alloc_text(PAGE, ShadowStrikeDisconnectNotify)
#pragma alloc_text(PAGE, ShadowStrikeMessageNotify)
#pragma alloc_text(PAGE, ShadowStrikeVerifyClient)
#pragma alloc_text(PAGE, ShadowStrikeRegisterProtectedProcess)
#pragma alloc_text(PAGE, ShadowStrikeUnregisterProtectedProcess)
#pragma alloc_text(PAGE, ShadowStrikeBuildFileScanRequest)
#endif

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

/**
 * @brief Protected process entry for self-protection list.
 */
typedef struct _SHADOWSTRIKE_PROTECTED_PROCESS_ENTRY {
    LIST_ENTRY ListEntry;
    ULONG ProcessId;
    ULONG ProtectionFlags;
    WCHAR ProcessName[MAX_PROCESS_NAME_LENGTH];
} SHADOWSTRIKE_PROTECTED_PROCESS_ENTRY, *PSHADOWSTRIKE_PROTECTED_PROCESS_ENTRY;

// ============================================================================
// EXTENDED CLIENT PORT ARRAY
// ============================================================================

/**
 * @brief Extended client port storage with reference counting.
 *
 * This replaces the simple SHADOWSTRIKE_CLIENT_PORT in globals with
 * the reference-counted version.
 */
static SHADOWSTRIKE_CLIENT_PORT_REF g_ClientPortRefs[SHADOWSTRIKE_MAX_CONNECTIONS];

// ============================================================================
// INTERNAL HELPER DECLARATIONS
// ============================================================================

static NTSTATUS
ShadowStrikeValidateInputBuffer(
    _In_reads_bytes_(BufferLength) PVOID Buffer,
    _In_ ULONG BufferLength,
    _Out_ PSHADOWSTRIKE_MESSAGE_HEADER* Header
    );

static NTSTATUS
ShadowStrikeHandleQueryDriverStatus(
    _In_ PSHADOWSTRIKE_MESSAGE_HEADER InputHeader,
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnLength
    );

static NTSTATUS
ShadowStrikeHandleUpdatePolicy(
    _In_ LONG ClientIndex,
    _In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength
    );

static NTSTATUS
ShadowStrikeHandleEnableDisableFiltering(
    _In_ LONG ClientIndex,
    _In_ BOOLEAN Enable
    );

static NTSTATUS
ShadowStrikeHandleRegisterProtectedProcess(
    _In_ LONG ClientIndex,
    _In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength
    );

static NTSTATUS
ShadowStrikeHandleHeartbeat(
    _In_ PSHADOWSTRIKE_MESSAGE_HEADER InputHeader,
    _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnLength
    );

static NTSTATUS
ShadowStrikeGetProcessImagePath(
    _In_ HANDLE ProcessId,
    _Out_writes_bytes_(BufferSize) PWCHAR Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG ActualLength
    );

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
    LONG i;

    PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Creating communication port: %ws\n",
               SHADOWSTRIKE_PORT_NAME);

    //
    // Initialize client port reference array
    //
    RtlZeroMemory(g_ClientPortRefs, sizeof(g_ClientPortRefs));
    for (i = 0; i < SHADOWSTRIKE_MAX_CONNECTIONS; i++) {
        g_ClientPortRefs[i].SlotIndex = i;
    }

    //
    // Create security descriptor that allows admin access only
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
    LONG waitCount;
    LARGE_INTEGER waitInterval;

    PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Closing communication port\n");

    //
    // Mark all clients as disconnecting and wait for references to drain
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ClientPortLock);

    for (i = 0; i < SHADOWSTRIKE_MAX_CONNECTIONS; i++) {
        if (g_ClientPortRefs[i].ClientPort != NULL) {
            //
            // Mark as disconnecting - no new references can be acquired
            //
            InterlockedExchange(&g_ClientPortRefs[i].Disconnecting, 1);
        }
    }

    ExReleasePushLockExclusive(&g_DriverData.ClientPortLock);
    KeLeaveCriticalRegion();

    //
    // Wait for all outstanding references to drain (with timeout)
    //
    waitInterval.QuadPart = -10000LL * 100;  // 100ms intervals
    waitCount = 0;

    for (i = 0; i < SHADOWSTRIKE_MAX_CONNECTIONS; i++) {
        while (g_ClientPortRefs[i].ReferenceCount > 0 && waitCount < 50) {
            KeDelayExecutionThread(KernelMode, FALSE, &waitInterval);
            waitCount++;
        }

        if (g_ClientPortRefs[i].ReferenceCount > 0) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] Warning: Client slot %ld still has %ld references\n",
                       i, g_ClientPortRefs[i].ReferenceCount);
        }
    }

    //
    // Now close all client ports under lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ClientPortLock);

    for (i = 0; i < SHADOWSTRIKE_MAX_CONNECTIONS; i++) {
        if (g_ClientPortRefs[i].ClientPort != NULL) {
            FltCloseClientPort(
                g_DriverData.FilterHandle,
                &g_ClientPortRefs[i].ClientPort
            );
            RtlZeroMemory(&g_ClientPortRefs[i], sizeof(SHADOWSTRIKE_CLIENT_PORT_REF));
            g_ClientPortRefs[i].SlotIndex = i;
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

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Communication port closed\n");
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
    ULONG capabilities = 0;
    UCHAR imageHash[32] = {0};
    UINT32 connectionType = 0;

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
    // Verify client and determine capabilities
    //
    status = ShadowStrikeVerifyClient(clientProcessId, &capabilities, imageHash);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Client verification failed: 0x%08X\n", status);
        //
        // For development, allow with minimal capabilities
        // In production, this should return STATUS_ACCESS_DENIED
        //
        capabilities = ShadowStrikeCapMinimal;
        RtlZeroMemory(imageHash, sizeof(imageHash));
    }

    //
    // Safely read connection context from user-mode with try/except
    //
    if (ConnectionContext != NULL && SizeOfContext >= sizeof(UINT32)) {
        __try {
            //
            // Probe the user-mode buffer for read access
            //
            ProbeForRead(ConnectionContext, SizeOfContext, sizeof(UINT32));

            connectionType = *(PUINT32)ConnectionContext;
            if (connectionType == 1) {
                isPrimaryScanner = TRUE;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] Exception reading connection context\n");
            //
            // Invalid user buffer - reject connection
            //
            return STATUS_INVALID_PARAMETER;
        }
    }

    //
    // Find available slot under lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ClientPortLock);

    //
    // Check if already at max connections
    //
    if (g_DriverData.ConnectedClients >= SHADOWSTRIKE_MAX_CONNECTIONS) {
        ExReleasePushLockExclusive(&g_DriverData.ClientPortLock);
        KeLeaveCriticalRegion();

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Connection rejected: max connections reached\n");
        return STATUS_CONNECTION_COUNT_LIMIT;
    }

    //
    // Find empty slot
    //
    for (i = 0; i < SHADOWSTRIKE_MAX_CONNECTIONS; i++) {
        if (g_ClientPortRefs[i].ClientPort == NULL &&
            g_ClientPortRefs[i].Disconnecting == 0) {
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
    // Initialize client slot with reference count of 1 (for the connection itself)
    //
    RtlZeroMemory(&g_ClientPortRefs[slotIndex], sizeof(SHADOWSTRIKE_CLIENT_PORT_REF));
    g_ClientPortRefs[slotIndex].ClientPort = ClientPort;
    g_ClientPortRefs[slotIndex].ClientProcessId = clientProcessId;
    g_ClientPortRefs[slotIndex].IsPrimaryScanner = isPrimaryScanner;
    g_ClientPortRefs[slotIndex].Capabilities = capabilities;
    g_ClientPortRefs[slotIndex].ReferenceCount = 1;  // Initial reference for connection
    g_ClientPortRefs[slotIndex].Disconnecting = 0;
    g_ClientPortRefs[slotIndex].SlotIndex = slotIndex;
    RtlCopyMemory(g_ClientPortRefs[slotIndex].ImagePathHash, imageHash, sizeof(imageHash));
    KeQuerySystemTime(&g_ClientPortRefs[slotIndex].ConnectedTime);

    //
    // Update global connected count
    //
    g_DriverData.ConnectedClients++;

    ExReleasePushLockExclusive(&g_DriverData.ClientPortLock);
    KeLeaveCriticalRegion();

    //
    // Return slot index as cookie (add 1 to avoid NULL)
    //
    *ConnectionPortCookie = (PVOID)(ULONG_PTR)(slotIndex + 1);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Client connected: slot=%ld, primary=%d, caps=0x%08X, total=%ld\n",
               slotIndex, isPrimaryScanner, capabilities, g_DriverData.ConnectedClients);

    return status;
}

VOID
ShadowStrikeDisconnectNotify(
    _In_opt_ PVOID ConnectionCookie
    )
{
    LONG slotIndex;
    LARGE_INTEGER waitInterval;
    LONG waitCount = 0;

    PAGED_CODE();

    if (ConnectionCookie == NULL) {
        return;
    }

    slotIndex = (LONG)(ULONG_PTR)ConnectionCookie - 1;

    if (slotIndex < 0 || slotIndex >= SHADOWSTRIKE_MAX_CONNECTIONS) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Invalid disconnect cookie: %p\n", ConnectionCookie);
        return;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Client disconnecting: slot=%ld\n", slotIndex);

    //
    // Mark as disconnecting - prevents new references from being acquired
    //
    InterlockedExchange(&g_ClientPortRefs[slotIndex].Disconnecting, 1);

    //
    // Decrement the initial connection reference
    //
    InterlockedDecrement(&g_ClientPortRefs[slotIndex].ReferenceCount);

    //
    // Wait for all outstanding references to drain
    //
    waitInterval.QuadPart = -10000LL * 50;  // 50ms intervals

    while (g_ClientPortRefs[slotIndex].ReferenceCount > 0 && waitCount < 100) {
        KeDelayExecutionThread(KernelMode, FALSE, &waitInterval);
        waitCount++;
    }

    if (g_ClientPortRefs[slotIndex].ReferenceCount > 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Warning: Client slot %ld still has %ld references after timeout\n",
                   slotIndex, g_ClientPortRefs[slotIndex].ReferenceCount);
    }

    //
    // Now safe to close the port
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ClientPortLock);

    if (g_ClientPortRefs[slotIndex].ClientPort != NULL) {
        FltCloseClientPort(
            g_DriverData.FilterHandle,
            &g_ClientPortRefs[slotIndex].ClientPort
        );

        //
        // Clear the slot but preserve slot index
        //
        RtlZeroMemory(&g_ClientPortRefs[slotIndex], sizeof(SHADOWSTRIKE_CLIENT_PORT_REF));
        g_ClientPortRefs[slotIndex].SlotIndex = slotIndex;

        if (g_DriverData.ConnectedClients > 0) {
            g_DriverData.ConnectedClients--;
        }
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
    SHADOWSTRIKE_MESSAGE_HEADER localHeader;
    PSHADOWSTRIKE_MESSAGE_HEADER header = NULL;
    LONG slotIndex;

    PAGED_CODE();

    *ReturnOutputBufferLength = 0;

    //
    // Validate slot index from cookie
    //
    if (PortCookie == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    slotIndex = (LONG)(ULONG_PTR)PortCookie - 1;
    if (slotIndex < 0 || slotIndex >= SHADOWSTRIKE_MAX_CONNECTIONS) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate input buffer size
    //
    if (InputBuffer == NULL || InputBufferLength < sizeof(SHADOWSTRIKE_MESSAGE_HEADER)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Safely copy message header from user-mode buffer
    //
    __try {
        ProbeForRead(InputBuffer, InputBufferLength, sizeof(UINT32));
        RtlCopyMemory(&localHeader, InputBuffer, sizeof(SHADOWSTRIKE_MESSAGE_HEADER));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Exception reading input buffer\n");
        return STATUS_INVALID_USER_BUFFER;
    }

    header = &localHeader;

    //
    // Validate message header
    //
    if (!SHADOWSTRIKE_VALID_MESSAGE_HEADER(header)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Invalid message header (magic=0x%08X, version=%u)\n",
                   header->Magic, header->Version);
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate that TotalSize matches actual buffer length
    //
    if (header->TotalSize > InputBufferLength) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Message size mismatch: header=%u, buffer=%u\n",
                   header->TotalSize, InputBufferLength);
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate DataSize consistency
    //
    if (header->DataSize > header->TotalSize - sizeof(SHADOWSTRIKE_MESSAGE_HEADER)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] DataSize exceeds available space\n");
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] Message received: type=%u, id=%llu, slot=%ld\n",
               header->MessageType, header->MessageId, slotIndex);

    //
    // Dispatch based on message type with capability checks
    //
    switch (header->MessageType) {

        case ShadowStrikeMessageQueryDriverStatus:
            //
            // Query status - requires QueryStatus capability
            //
            if (!ShadowStrikeClientHasCapability(slotIndex, ShadowStrikeCapQueryStatus)) {
                status = STATUS_ACCESS_DENIED;
                break;
            }
            status = ShadowStrikeHandleQueryDriverStatus(
                header,
                OutputBuffer,
                OutputBufferLength,
                ReturnOutputBufferLength
            );
            break;

        case ShadowStrikeMessageUpdatePolicy:
            //
            // Update policy - requires UpdatePolicy capability
            //
            if (!ShadowStrikeClientHasCapability(slotIndex, ShadowStrikeCapUpdatePolicy)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike] Policy update denied - insufficient capability\n");
                status = STATUS_ACCESS_DENIED;
                break;
            }
            status = ShadowStrikeHandleUpdatePolicy(slotIndex, InputBuffer, InputBufferLength);
            break;

        case ShadowStrikeMessageEnableFiltering:
            //
            // Enable filtering - requires ControlFiltering capability
            //
            if (!ShadowStrikeClientHasCapability(slotIndex, ShadowStrikeCapControlFiltering)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike] Enable filtering denied - insufficient capability\n");
                status = STATUS_ACCESS_DENIED;
                break;
            }
            status = ShadowStrikeHandleEnableDisableFiltering(slotIndex, TRUE);
            break;

        case ShadowStrikeMessageDisableFiltering:
            //
            // Disable filtering - requires ControlFiltering capability
            //
            if (!ShadowStrikeClientHasCapability(slotIndex, ShadowStrikeCapControlFiltering)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike] Disable filtering denied - insufficient capability\n");
                status = STATUS_ACCESS_DENIED;
                break;
            }
            status = ShadowStrikeHandleEnableDisableFiltering(slotIndex, FALSE);
            break;

        case ShadowStrikeMessageRegisterProtectedProcess:
            //
            // Register protected process - requires ProtectProcess capability
            //
            if (!ShadowStrikeClientHasCapability(slotIndex, ShadowStrikeCapProtectProcess)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike] Protected process registration denied\n");
                status = STATUS_ACCESS_DENIED;
                break;
            }
            status = ShadowStrikeHandleRegisterProtectedProcess(
                slotIndex,
                InputBuffer,
                InputBufferLength
            );
            break;

        case ShadowStrikeMessageHeartbeat:
            status = ShadowStrikeHandleHeartbeat(
                header,
                OutputBuffer,
                OutputBufferLength,
                ReturnOutputBufferLength
            );
            break;

        case ShadowStrikeMessageScanVerdict:
            //
            // Scan verdict reply - handled via FltSendMessage reply mechanism
            //
            SHADOWSTRIKE_INC_STAT(RepliesReceived);
            break;

        default:
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] Unknown message type: %u\n", header->MessageType);
            status = STATUS_INVALID_PARAMETER;
            break;
    }

    return status;
}

// ============================================================================
// MESSAGE TYPE HANDLERS
// ============================================================================

static NTSTATUS
ShadowStrikeHandleQueryDriverStatus(
    _In_ PSHADOWSTRIKE_MESSAGE_HEADER InputHeader,
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnLength
    )
{
    SHADOWSTRIKE_MESSAGE_HEADER replyHeader;
    SHADOWSTRIKE_DRIVER_STATUS driverStatus;
    ULONG requiredSize;

    PAGED_CODE();

    *ReturnLength = 0;
    requiredSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + sizeof(SHADOWSTRIKE_DRIVER_STATUS);

    if (OutputBuffer == NULL || OutputBufferLength < requiredSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Build reply header
    //
    ShadowStrikeInitMessageHeader(
        &replyHeader,
        ShadowStrikeMessageQueryDriverStatus,
        sizeof(SHADOWSTRIKE_DRIVER_STATUS)
    );
    replyHeader.MessageId = InputHeader->MessageId;  // Correlation

    //
    // Build driver status
    //
    RtlZeroMemory(&driverStatus, sizeof(SHADOWSTRIKE_DRIVER_STATUS));
    driverStatus.VersionMajor = SHADOWSTRIKE_VERSION_MAJOR;
    driverStatus.VersionMinor = SHADOWSTRIKE_VERSION_MINOR;
    driverStatus.VersionBuild = SHADOWSTRIKE_VERSION_BUILD;
    driverStatus.FilteringActive = g_DriverData.FilteringStarted;
    driverStatus.ScanOnOpenEnabled = g_DriverData.Config.ScanOnOpen;
    driverStatus.ScanOnExecuteEnabled = g_DriverData.Config.ScanOnExecute;
    driverStatus.ScanOnWriteEnabled = g_DriverData.Config.ScanOnWrite;
    driverStatus.NotificationsEnabled = g_DriverData.Config.NotificationsEnabled;
    driverStatus.TotalFilesScanned = g_DriverData.Stats.TotalFilesScanned;
    driverStatus.FilesBlocked = g_DriverData.Stats.FilesBlocked;
    driverStatus.PendingRequests = g_DriverData.Stats.PendingRequests;
    driverStatus.PeakPendingRequests = g_DriverData.Stats.PeakPendingRequests;
    driverStatus.CacheHits = g_DriverData.Stats.CacheHits;
    driverStatus.CacheMisses = g_DriverData.Stats.CacheMisses;
    driverStatus.ConnectedClients = g_DriverData.ConnectedClients;

    //
    // Copy to user buffer with try/except
    //
    __try {
        ProbeForWrite(OutputBuffer, requiredSize, sizeof(UINT32));
        RtlCopyMemory(OutputBuffer, &replyHeader, sizeof(SHADOWSTRIKE_MESSAGE_HEADER));
        RtlCopyMemory(
            (PUCHAR)OutputBuffer + sizeof(SHADOWSTRIKE_MESSAGE_HEADER),
            &driverStatus,
            sizeof(SHADOWSTRIKE_DRIVER_STATUS)
        );
        *ReturnLength = requiredSize;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_INVALID_USER_BUFFER;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
ShadowStrikeHandleUpdatePolicy(
    _In_ LONG ClientIndex,
    _In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength
    )
{
    SHADOWSTRIKE_POLICY_UPDATE localPolicy;
    ULONG requiredSize;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(ClientIndex);

    requiredSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + sizeof(SHADOWSTRIKE_POLICY_UPDATE);
    if (InputBufferLength < requiredSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Safely copy policy from user buffer
    //
    __try {
        ProbeForRead(InputBuffer, InputBufferLength, sizeof(UINT32));
        RtlCopyMemory(
            &localPolicy,
            (PUCHAR)InputBuffer + sizeof(SHADOWSTRIKE_MESSAGE_HEADER),
            sizeof(SHADOWSTRIKE_POLICY_UPDATE)
        );
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_INVALID_USER_BUFFER;
    }

    //
    // Validate policy values before applying
    //
    if (localPolicy.ScanTimeoutMs < SHADOWSTRIKE_MIN_SCAN_TIMEOUT_MS ||
        localPolicy.ScanTimeoutMs > SHADOWSTRIKE_MAX_SCAN_TIMEOUT_MS) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Apply policy under lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ConfigLock);

    g_DriverData.Config.ScanOnOpen = localPolicy.ScanOnOpen;
    g_DriverData.Config.ScanOnExecute = localPolicy.ScanOnExecute;
    g_DriverData.Config.ScanOnWrite = localPolicy.ScanOnWrite;
    g_DriverData.Config.NotificationsEnabled = localPolicy.EnableNotifications;
    g_DriverData.Config.BlockOnTimeout = localPolicy.BlockOnTimeout;
    g_DriverData.Config.BlockOnError = localPolicy.BlockOnError;
    g_DriverData.Config.ScanNetworkFiles = localPolicy.ScanNetworkFiles;
    g_DriverData.Config.ScanRemovableMedia = localPolicy.ScanRemovableMedia;
    g_DriverData.Config.MaxScanFileSize = localPolicy.MaxScanFileSize;
    g_DriverData.Config.ScanTimeoutMs = localPolicy.ScanTimeoutMs;
    g_DriverData.Config.CacheTTLSeconds = localPolicy.CacheTTLSeconds;

    if (localPolicy.MaxPendingRequests > 0 &&
        localPolicy.MaxPendingRequests <= SHADOWSTRIKE_DEFAULT_MAX_PENDING) {
        g_DriverData.Config.MaxPendingRequests = localPolicy.MaxPendingRequests;
    }

    ExReleasePushLockExclusive(&g_DriverData.ConfigLock);
    KeLeaveCriticalRegion();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Policy updated by authorized client\n");

    return STATUS_SUCCESS;
}

static NTSTATUS
ShadowStrikeHandleEnableDisableFiltering(
    _In_ LONG ClientIndex,
    _In_ BOOLEAN Enable
    )
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(ClientIndex);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ConfigLock);

    g_DriverData.Config.FilteringEnabled = Enable;

    ExReleasePushLockExclusive(&g_DriverData.ConfigLock);
    KeLeaveCriticalRegion();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Filtering %s by authorized client\n",
               Enable ? "enabled" : "disabled");

    return STATUS_SUCCESS;
}

static NTSTATUS
ShadowStrikeHandleRegisterProtectedProcess(
    _In_ LONG ClientIndex,
    _In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength
    )
{
    SHADOWSTRIKE_PROTECTED_PROCESS localProtectedProcess;
    ULONG requiredSize;
    NTSTATUS status;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(ClientIndex);

    requiredSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + sizeof(SHADOWSTRIKE_PROTECTED_PROCESS);
    if (InputBufferLength < requiredSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Safely copy protected process info from user buffer
    //
    __try {
        ProbeForRead(InputBuffer, InputBufferLength, sizeof(UINT32));
        RtlCopyMemory(
            &localProtectedProcess,
            (PUCHAR)InputBuffer + sizeof(SHADOWSTRIKE_MESSAGE_HEADER),
            sizeof(SHADOWSTRIKE_PROTECTED_PROCESS)
        );
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_INVALID_USER_BUFFER;
    }

    //
    // Validate process ID
    //
    if (localProtectedProcess.ProcessId == 0 || localProtectedProcess.ProcessId == 4) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Ensure process name is null-terminated
    //
    localProtectedProcess.ProcessName[MAX_PROCESS_NAME_LENGTH - 1] = L'\0';

    //
    // Register the protected process
    //
    status = ShadowStrikeRegisterProtectedProcess(
        localProtectedProcess.ProcessId,
        localProtectedProcess.ProtectionFlags,
        localProtectedProcess.ProcessName
    );

    return status;
}

static NTSTATUS
ShadowStrikeHandleHeartbeat(
    _In_ PSHADOWSTRIKE_MESSAGE_HEADER InputHeader,
    _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnLength
    )
{
    SHADOWSTRIKE_GENERIC_REPLY reply;

    PAGED_CODE();

    *ReturnLength = 0;

    if (OutputBuffer == NULL || OutputBufferLength < sizeof(SHADOWSTRIKE_GENERIC_REPLY)) {
        return STATUS_SUCCESS;  // Heartbeat can succeed without reply
    }

    RtlZeroMemory(&reply, sizeof(reply));
    reply.MessageId = InputHeader->MessageId;
    reply.Status = 0;

    __try {
        ProbeForWrite(OutputBuffer, sizeof(SHADOWSTRIKE_GENERIC_REPLY), sizeof(UINT32));
        RtlCopyMemory(OutputBuffer, &reply, sizeof(SHADOWSTRIKE_GENERIC_REPLY));
        *ReturnLength = sizeof(SHADOWSTRIKE_GENERIC_REPLY);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_INVALID_USER_BUFFER;
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// MESSAGE SENDING WITH REFERENCE COUNTING
// ============================================================================

NTSTATUS
ShadowStrikeAcquirePrimaryScannerPort(
    _Out_ PSHADOWSTRIKE_CLIENT_PORT_REF* ClientRef
    )
{
    LONG i;
    LONG targetSlot = -1;
    LONG oldRefCount;

    *ClientRef = NULL;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_DriverData.ClientPortLock);

    //
    // First try to find primary scanner
    //
    for (i = 0; i < SHADOWSTRIKE_MAX_CONNECTIONS; i++) {
        if (g_ClientPortRefs[i].ClientPort != NULL &&
            g_ClientPortRefs[i].Disconnecting == 0 &&
            g_ClientPortRefs[i].IsPrimaryScanner) {
            targetSlot = i;
            break;
        }
    }

    //
    // Fall back to first connected client
    //
    if (targetSlot < 0) {
        for (i = 0; i < SHADOWSTRIKE_MAX_CONNECTIONS; i++) {
            if (g_ClientPortRefs[i].ClientPort != NULL &&
                g_ClientPortRefs[i].Disconnecting == 0) {
                targetSlot = i;
                break;
            }
        }
    }

    if (targetSlot < 0) {
        ExReleasePushLockShared(&g_DriverData.ClientPortLock);
        KeLeaveCriticalRegion();
        return SHADOWSTRIKE_ERROR_PORT_NOT_CONNECTED;
    }

    //
    // Atomically increment reference count if not disconnecting
    //
    if (g_ClientPortRefs[targetSlot].Disconnecting != 0) {
        ExReleasePushLockShared(&g_DriverData.ClientPortLock);
        KeLeaveCriticalRegion();
        return SHADOWSTRIKE_ERROR_CLIENT_DISCONNECTED;
    }

    oldRefCount = InterlockedIncrement(&g_ClientPortRefs[targetSlot].ReferenceCount);
    if (oldRefCount <= 0) {
        //
        // Reference count was already at 0 or negative - undo and fail
        //
        InterlockedDecrement(&g_ClientPortRefs[targetSlot].ReferenceCount);
        ExReleasePushLockShared(&g_DriverData.ClientPortLock);
        KeLeaveCriticalRegion();
        return SHADOWSTRIKE_ERROR_CLIENT_DISCONNECTED;
    }

    *ClientRef = &g_ClientPortRefs[targetSlot];

    ExReleasePushLockShared(&g_DriverData.ClientPortLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

VOID
ShadowStrikeReleaseClientPort(
    _In_ PSHADOWSTRIKE_CLIENT_PORT_REF ClientRef
    )
{
    if (ClientRef == NULL) {
        return;
    }

    InterlockedDecrement(&ClientRef->ReferenceCount);
}

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
    PSHADOWSTRIKE_CLIENT_PORT_REF clientRef = NULL;
    PFLT_PORT clientPort;
    LARGE_INTEGER timeout;
    LONG pendingCount;
    ULONG replySize;

    //
    // Validate parameters
    //
    if (Request == NULL || Reply == NULL || ReplySize == NULL || *ReplySize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Check pending request limit before acquiring port
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
    // Acquire reference to client port
    //
    status = ShadowStrikeAcquirePrimaryScannerPort(&clientRef);
    if (!NT_SUCCESS(status)) {
        InterlockedDecrement(&g_DriverData.Stats.PendingRequests);
        return status;
    }

    clientPort = clientRef->ClientPort;
    replySize = *ReplySize;

    //
    // Calculate timeout (negative = relative time in 100ns units)
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
        &replySize,
        &timeout
    );

    //
    // Release client reference
    //
    ShadowStrikeReleaseClientPort(clientRef);

    InterlockedDecrement(&g_DriverData.Stats.PendingRequests);

    if (NT_SUCCESS(status)) {
        SHADOWSTRIKE_INC_STAT(MessagesSent);
        SHADOWSTRIKE_INC_STAT(RepliesReceived);
        InterlockedIncrement64(&clientRef->MessagesSent);
        InterlockedIncrement64(&clientRef->RepliesReceived);
        *ReplySize = replySize;
    } else if (status == STATUS_TIMEOUT) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Scan request timeout (id=%llu)\n",
                   Request->MessageId);
        SHADOWSTRIKE_INC_STAT(ScanTimeouts);
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
    PSHADOWSTRIKE_CLIENT_PORT_REF clientRef = NULL;
    PFLT_PORT clientPort;
    LARGE_INTEGER timeout;

    if (!g_DriverData.Config.NotificationsEnabled) {
        return STATUS_SUCCESS;
    }

    //
    // Acquire reference to client port
    //
    status = ShadowStrikeAcquirePrimaryScannerPort(&clientRef);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    clientPort = clientRef->ClientPort;

    //
    // Use zero timeout for fire-and-forget (returns immediately)
    //
    timeout.QuadPart = 0;

    status = FltSendMessage(
        g_DriverData.FilterHandle,
        &clientPort,
        Notification,
        Size,
        NULL,
        NULL,
        &timeout
    );

    ShadowStrikeReleaseClientPort(clientRef);

    if (NT_SUCCESS(status)) {
        SHADOWSTRIKE_INC_STAT(MessagesSent);
        InterlockedIncrement64(&clientRef->MessagesSent);
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
    PSHADOWSTRIKE_CLIENT_PORT_REF clientRef = NULL;
    PFLT_PORT clientPort;
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

    if (!g_DriverData.Config.NotificationsEnabled) {
        return STATUS_SUCCESS;
    }

    //
    // Acquire reference to client port
    //
    status = ShadowStrikeAcquirePrimaryScannerPort(&clientRef);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    clientPort = clientRef->ClientPort;

    //
    // Calculate total message size
    //
    totalSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + Size;

    //
    // Allocate message buffer
    //
    header = (PSHADOWSTRIKE_MESSAGE_HEADER)ShadowStrikeAllocateMessageBuffer(totalSize);
    if (header == NULL) {
        ShadowStrikeReleaseClientPort(clientRef);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize header and copy notification
    //
    ShadowStrikeInitMessageHeader(header, ShadowStrikeMessageProcessNotify, Size);
    RtlCopyMemory((PUCHAR)header + sizeof(SHADOWSTRIKE_MESSAGE_HEADER), Notification, Size);

    if (RequireReply) {
        //
        // Track pending requests
        //
        pendingCount = InterlockedIncrement(&g_DriverData.Stats.PendingRequests);
        if (pendingCount > g_DriverData.Stats.PeakPendingRequests) {
            InterlockedExchange(&g_DriverData.Stats.PeakPendingRequests, pendingCount);
        }

        if ((ULONG)pendingCount > g_DriverData.Config.MaxPendingRequests) {
            InterlockedDecrement(&g_DriverData.Stats.PendingRequests);
            ShadowStrikeFreeMessageBuffer(header);
            ShadowStrikeReleaseClientPort(clientRef);
            SHADOWSTRIKE_INC_STAT(MessagesDropped);
            return SHADOWSTRIKE_ERROR_QUEUE_FULL;
        }

        replyBufferSize = *ReplySize;
        timeout.QuadPart = -(LONGLONG)g_DriverData.Config.ScanTimeoutMs * 10000LL;

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
        } else if (status == STATUS_TIMEOUT) {
            SHADOWSTRIKE_INC_STAT(ScanTimeouts);
        }
    } else {
        //
        // Fire-and-forget with zero timeout
        //
        timeout.QuadPart = 0;

        status = FltSendMessage(
            g_DriverData.FilterHandle,
            &clientPort,
            header,
            totalSize,
            NULL,
            NULL,
            &timeout
        );

        if (NT_SUCCESS(status)) {
            SHADOWSTRIKE_INC_STAT(MessagesSent);
        }
    }

    ShadowStrikeFreeMessageBuffer(header);
    ShadowStrikeReleaseClientPort(clientRef);

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
    //
    // Read with memory barrier for visibility
    //
    return (InterlockedCompareExchange(&g_DriverData.ConnectedClients, 0, 0) > 0);
}

LONG
ShadowStrikeGetConnectedClientCount(
    VOID
    )
{
    return InterlockedCompareExchange(&g_DriverData.ConnectedClients, 0, 0);
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
        if (g_ClientPortRefs[i].ClientPort != NULL &&
            g_ClientPortRefs[i].ClientProcessId == ProcessId) {
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

    valid = (g_ClientPortRefs[ClientIndex].ClientPort != NULL &&
             g_ClientPortRefs[ClientIndex].Disconnecting == 0);

    ExReleasePushLockShared(&g_DriverData.ClientPortLock);
    KeLeaveCriticalRegion();

    return valid;
}

BOOLEAN
ShadowStrikeClientHasCapability(
    _In_ LONG ClientIndex,
    _In_ SHADOWSTRIKE_CLIENT_CAPABILITY Capability
    )
{
    BOOLEAN hasCapability = FALSE;

    if (ClientIndex < 0 || ClientIndex >= SHADOWSTRIKE_MAX_CONNECTIONS) {
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_DriverData.ClientPortLock);

    if (g_ClientPortRefs[ClientIndex].ClientPort != NULL) {
        hasCapability = ((g_ClientPortRefs[ClientIndex].Capabilities & (ULONG)Capability) != 0);
    }

    ExReleasePushLockShared(&g_DriverData.ClientPortLock);
    KeLeaveCriticalRegion();

    return hasCapability;
}

// ============================================================================
// MESSAGE BUFFER ALLOCATION WITH TRACKING
// ============================================================================

PVOID
ShadowStrikeAllocateMessageBuffer(
    _In_ SIZE_T Size
    )
{
    PSHADOWSTRIKE_MESSAGE_BUFFER_HEADER header = NULL;
    SIZE_T totalSize;
    SIZE_T lookasideMaxPayload;

    if (Size == 0) {
        return NULL;
    }

    totalSize = sizeof(SHADOWSTRIKE_MESSAGE_BUFFER_HEADER) + Size;

    //
    // Calculate max payload that fits in lookaside
    //
    lookasideMaxPayload = SHADOWSTRIKE_MAX_MESSAGE_SIZE - sizeof(SHADOWSTRIKE_MESSAGE_BUFFER_HEADER);

    if (Size <= lookasideMaxPayload && g_DriverData.LookasideInitialized) {
        //
        // Allocate from lookaside list
        //
        header = (PSHADOWSTRIKE_MESSAGE_BUFFER_HEADER)
            ExAllocateFromNPagedLookasideList(&g_DriverData.MessageLookaside);

        if (header != NULL) {
            header->Magic = SHADOWSTRIKE_BUFFER_MAGIC;
            header->AllocationSource = SHADOWSTRIKE_ALLOC_LOOKASIDE;
            header->RequestedSize = Size;
            header->AllocatedSize = SHADOWSTRIKE_MAX_MESSAGE_SIZE;
            return (PVOID)(header + 1);
        }
    }

    //
    // Allocate from pool (either too large or lookaside failed)
    //
    header = (PSHADOWSTRIKE_MESSAGE_BUFFER_HEADER)ExAllocatePoolZero(
        NonPagedPoolNx,
        totalSize,
        SHADOWSTRIKE_POOL_TAG
    );

    if (header != NULL) {
        header->Magic = SHADOWSTRIKE_BUFFER_MAGIC;
        header->AllocationSource = SHADOWSTRIKE_ALLOC_POOL;
        header->RequestedSize = Size;
        header->AllocatedSize = totalSize;
        return (PVOID)(header + 1);
    }

    return NULL;
}

VOID
ShadowStrikeFreeMessageBuffer(
    _In_opt_ PVOID Buffer
    )
{
    PSHADOWSTRIKE_MESSAGE_BUFFER_HEADER header;

    if (Buffer == NULL) {
        return;
    }

    //
    // Get header from buffer pointer
    //
    header = ((PSHADOWSTRIKE_MESSAGE_BUFFER_HEADER)Buffer) - 1;

    //
    // Validate magic to catch corruption
    //
    if (header->Magic != SHADOWSTRIKE_BUFFER_MAGIC) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] ERROR: Invalid buffer magic in free (0x%08X)\n",
                   header->Magic);
        //
        // Do not free - this is a bug indicator
        //
        return;
    }

    //
    // Clear magic to detect double-free
    //
    header->Magic = 0;

    //
    // Free based on allocation source
    //
    if (header->AllocationSource == SHADOWSTRIKE_ALLOC_LOOKASIDE) {
        if (g_DriverData.LookasideInitialized) {
            ExFreeToNPagedLookasideList(&g_DriverData.MessageLookaside, header);
        } else {
            //
            // Lookaside was deleted - fall back to pool free
            // This can happen during driver unload
            //
            ExFreePoolWithTag(header, SHADOWSTRIKE_POOL_TAG);
        }
    } else if (header->AllocationSource == SHADOWSTRIKE_ALLOC_POOL) {
        ExFreePoolWithTag(header, SHADOWSTRIKE_POOL_TAG);
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] ERROR: Unknown allocation source %u\n",
                   header->AllocationSource);
    }
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
    WCHAR processImagePath[MAX_PROCESS_NAME_LENGTH];
    ULONG processNameLength = 0;
    PUNICODE_STRING processImageName = NULL;

    PAGED_CODE();

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

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return status;
    }

    //
    // Get process image name
    //
    RtlZeroMemory(processImagePath, sizeof(processImagePath));
    process = IoThreadToProcess(Data->Thread);

    if (process != NULL) {
        status = SeLocateProcessImageName(process, &processImageName);
        if (NT_SUCCESS(status) && processImageName != NULL) {
            //
            // Extract just the file name portion
            //
            PWCHAR lastSlash = processImageName->Buffer;
            PWCHAR p = processImageName->Buffer;
            ULONG i;

            for (i = 0; i < processImageName->Length / sizeof(WCHAR); i++) {
                if (p[i] == L'\\' || p[i] == L'/') {
                    lastSlash = &p[i + 1];
                }
            }

            processNameLength = (ULONG)wcslen(lastSlash);
            if (processNameLength >= MAX_PROCESS_NAME_LENGTH) {
                processNameLength = MAX_PROCESS_NAME_LENGTH - 1;
            }
            RtlCopyMemory(processImagePath, lastSlash, processNameLength * sizeof(WCHAR));

            ExFreePool(processImageName);
        }
    }

    //
    // Calculate total message size
    //
    totalSize = SHADOWSTRIKE_FILE_SCAN_REQUEST_SIZE(
        nameInfo->Name.Length / sizeof(WCHAR),
        processNameLength
    );

    //
    // Cap total size
    //
    if (totalSize > SHADOWSTRIKE_MAX_MESSAGE_SIZE) {
        FltReleaseFileNameInformation(nameInfo);
        return STATUS_BUFFER_OVERFLOW;
    }

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

    //
    // Get parent process ID
    //
    if (process != NULL) {
        scanRequest->ParentProcessId = (UINT32)(ULONG_PTR)PsGetProcessInheritedFromUniqueProcessId(process);
    } else {
        scanRequest->ParentProcessId = 0;
    }

    //
    // Get session ID
    //
    scanRequest->SessionId = PsGetCurrentProcessSessionId();

    scanRequest->FileSize = 0;  // Set in post-create if needed
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
    scanRequest->PathLength = (UINT16)(nameInfo->Name.Length / sizeof(WCHAR));
    scanRequest->ProcessNameLength = (UINT16)processNameLength;

    //
    // Copy variable-length data
    //
    variableData = (PWCHAR)((PUCHAR)scanRequest + sizeof(SHADOWSTRIKE_FILE_SCAN_REQUEST));

    if (nameInfo->Name.Length > 0) {
        RtlCopyMemory(variableData, nameInfo->Name.Buffer, nameInfo->Name.Length);
        variableData += nameInfo->Name.Length / sizeof(WCHAR);
    }

    if (processNameLength > 0) {
        RtlCopyMemory(variableData, processImagePath, processNameLength * sizeof(WCHAR));
    }

    FltReleaseFileNameInformation(nameInfo);

    *Request = header;
    *RequestSize = totalSize;

    return STATUS_SUCCESS;
}

// ============================================================================
// CLIENT VERIFICATION
// ============================================================================

NTSTATUS
ShadowStrikeVerifyClient(
    _In_ HANDLE ClientProcessId,
    _Out_ PULONG Capabilities,
    _Out_writes_bytes_(32) PUCHAR ImageHash
    )
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PUNICODE_STRING imageName = NULL;
    BOOLEAN isVerified = FALSE;

    PAGED_CODE();

    *Capabilities = ShadowStrikeCapMinimal;
    RtlZeroMemory(ImageHash, 32);

    //
    // Get process object
    //
    status = PsLookupProcessByProcessId(ClientProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Get process image name
    //
    status = SeLocateProcessImageName(process, &imageName);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(process);
        return status;
    }

    //
    // Verification logic:
    // In production, this would check:
    // 1. Process image path matches expected ShadowStrike service path
    // 2. Image is code-signed with ShadowStrike certificate
    // 3. Image hash matches known-good hash
    // 4. Process is running as SYSTEM or appropriate service account
    //
    // For now, we check if the image name contains "ShadowStrike"
    //
    if (imageName->Buffer != NULL && imageName->Length > 0) {
        UNICODE_STRING searchString;
        RtlInitUnicodeString(&searchString, L"ShadowStrike");

        //
        // Simple substring check (case-insensitive would be better)
        //
        if (wcsstr(imageName->Buffer, L"ShadowStrike") != NULL ||
            wcsstr(imageName->Buffer, L"shadowstrike") != NULL) {
            isVerified = TRUE;
        }

        //
        // Compute simple hash of image path for tracking
        // In production, use SHA-256
        //
        ULONG hash = 0;
        for (USHORT i = 0; i < imageName->Length / sizeof(WCHAR); i++) {
            hash = hash * 31 + imageName->Buffer[i];
        }
        RtlCopyMemory(ImageHash, &hash, sizeof(hash));
    }

    ExFreePool(imageName);
    ObDereferenceObject(process);

    if (isVerified) {
        *Capabilities = ShadowStrikeCapServiceDefault;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike] Client verified with full capabilities\n");
    } else {
        *Capabilities = ShadowStrikeCapMinimal;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Client not verified - minimal capabilities\n");
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// PROTECTED PROCESS MANAGEMENT
// ============================================================================

NTSTATUS
ShadowStrikeRegisterProtectedProcess(
    _In_ ULONG ProcessId,
    _In_ ULONG ProtectionFlags,
    _In_opt_ PCWSTR ProcessName
    )
{
    PSHADOWSTRIKE_PROTECTED_PROCESS_ENTRY entry = NULL;
    PLIST_ENTRY listEntry;
    BOOLEAN alreadyExists = FALSE;

    PAGED_CODE();

    //
    // Validate process ID
    //
    if (ProcessId == 0 || ProcessId == 4) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Check limit
    //
    if (g_DriverData.ProtectedProcessCount >= 64) {
        return SHADOWSTRIKE_ERROR_MAX_PROTECTED;
    }

    //
    // Check if already protected
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_DriverData.ProtectedProcessLock);

    for (listEntry = g_DriverData.ProtectedProcessList.Flink;
         listEntry != &g_DriverData.ProtectedProcessList;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_PROTECTED_PROCESS_ENTRY, ListEntry);
        if (entry->ProcessId == ProcessId) {
            alreadyExists = TRUE;
            break;
        }
    }

    ExReleasePushLockShared(&g_DriverData.ProtectedProcessLock);
    KeLeaveCriticalRegion();

    if (alreadyExists) {
        return STATUS_OBJECTID_EXISTS;
    }

    //
    // Allocate new entry
    //
    entry = (PSHADOWSTRIKE_PROTECTED_PROCESS_ENTRY)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(SHADOWSTRIKE_PROTECTED_PROCESS_ENTRY),
        SHADOWSTRIKE_POOL_TAG
    );

    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    entry->ProcessId = ProcessId;
    entry->ProtectionFlags = ProtectionFlags;

    if (ProcessName != NULL) {
        SIZE_T nameLen = wcslen(ProcessName);
        if (nameLen >= MAX_PROCESS_NAME_LENGTH) {
            nameLen = MAX_PROCESS_NAME_LENGTH - 1;
        }
        RtlCopyMemory(entry->ProcessName, ProcessName, nameLen * sizeof(WCHAR));
        entry->ProcessName[nameLen] = L'\0';
    }

    //
    // Add to list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ProtectedProcessLock);

    InsertTailList(&g_DriverData.ProtectedProcessList, &entry->ListEntry);
    InterlockedIncrement(&g_DriverData.ProtectedProcessCount);

    ExReleasePushLockExclusive(&g_DriverData.ProtectedProcessLock);
    KeLeaveCriticalRegion();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Protected process registered: PID=%u, flags=0x%08X\n",
               ProcessId, ProtectionFlags);

    return STATUS_SUCCESS;
}

NTSTATUS
ShadowStrikeUnregisterProtectedProcess(
    _In_ ULONG ProcessId
    )
{
    PLIST_ENTRY listEntry;
    PSHADOWSTRIKE_PROTECTED_PROCESS_ENTRY entry = NULL;
    PSHADOWSTRIKE_PROTECTED_PROCESS_ENTRY foundEntry = NULL;

    PAGED_CODE();

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ProtectedProcessLock);

    for (listEntry = g_DriverData.ProtectedProcessList.Flink;
         listEntry != &g_DriverData.ProtectedProcessList;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_PROTECTED_PROCESS_ENTRY, ListEntry);
        if (entry->ProcessId == ProcessId) {
            foundEntry = entry;
            RemoveEntryList(&entry->ListEntry);
            InterlockedDecrement(&g_DriverData.ProtectedProcessCount);
            break;
        }
    }

    ExReleasePushLockExclusive(&g_DriverData.ProtectedProcessLock);
    KeLeaveCriticalRegion();

    if (foundEntry != NULL) {
        ExFreePoolWithTag(foundEntry, SHADOWSTRIKE_POOL_TAG);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike] Protected process unregistered: PID=%u\n", ProcessId);
        return STATUS_SUCCESS;
    }

    return SHADOWSTRIKE_ERROR_NOT_PROTECTED;
}
