/**
 * ============================================================================
 * ShadowStrike NGAV - SCAN BRIDGE IMPLEMENTATION
 * ============================================================================
 *
 * @file ScanBridge.c
 * @brief Bridge functions for sending scan-related notifications to user-mode.
 *
 * This file provides convenience wrappers for sending various notification
 * types (process, thread, image, registry) to the user-mode service.
 *
 * NOTE: ShadowStrikeBuildFileScanRequest is defined in CommPort.c to avoid
 * duplicate symbol errors. This file uses ShadowStrikeSendMessage from
 * CommPort.c for all message sending operations.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "ScanBridge.h"
#include "CommPort.h"
#include "../Core/Globals.h"
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/FileUtils.h"
#include "../Utilities/ProcessUtils.h"
#include "../Utilities/StringUtils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ShadowStrikeSendProcessNotification)
#pragma alloc_text(PAGE, ShadowStrikeSendThreadNotification)
#pragma alloc_text(PAGE, ShadowStrikeSendImageNotification)
#pragma alloc_text(PAGE, ShadowStrikeSendRegistryNotification)
#endif

// ============================================================================
// PROCESS NOTIFICATION
// ============================================================================

NTSTATUS
ShadowStrikeSendProcessNotification(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentId,
    _In_ BOOLEAN Create,
    _In_ PUNICODE_STRING ImageName,
    _In_opt_ PUNICODE_STRING CommandLine
    )
{
    NTSTATUS status;
    PSHADOWSTRIKE_MESSAGE_HEADER header = NULL;
    PSHADOWSTRIKE_PROCESS_NOTIFICATION notification = NULL;
    ULONG totalSize = 0;
    ULONG imageNameLen = ImageName ? ImageName->Length : 0;
    ULONG cmdLineLen = CommandLine ? CommandLine->Length : 0;

    PAGED_CODE();

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
    // Calculate total message size
    //
    totalSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) +
                sizeof(SHADOWSTRIKE_PROCESS_NOTIFICATION) +
                imageNameLen + sizeof(WCHAR) +
                cmdLineLen + sizeof(WCHAR);

    if (totalSize > SHADOWSTRIKE_MAX_MESSAGE_SIZE) {
        totalSize = SHADOWSTRIKE_MAX_MESSAGE_SIZE;
    }

    //
    // Allocate message buffer from lookaside list
    //
    header = (PSHADOWSTRIKE_MESSAGE_HEADER)ShadowStrikeAllocateMessageBuffer(totalSize);
    if (header == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize header
    //
    ShadowStrikeInitMessageHeader(
        header,
        ShadowStrikeMessageProcessNotify,
        totalSize - sizeof(SHADOWSTRIKE_MESSAGE_HEADER)
    );

    //
    // Fill notification payload
    //
    notification = (PSHADOWSTRIKE_PROCESS_NOTIFICATION)((PUCHAR)header + sizeof(SHADOWSTRIKE_MESSAGE_HEADER));
    notification->ProcessId = HandleToULong(ProcessId);
    notification->ParentProcessId = HandleToULong(ParentId);
    notification->CreatingProcessId = HandleToULong(PsGetCurrentProcessId());
    notification->CreatingThreadId = HandleToULong(PsGetCurrentThreadId());
    notification->Create = Create;
    notification->ImagePathLength = (UINT16)imageNameLen;
    notification->CommandLineLength = (UINT16)cmdLineLen;

    //
    // Copy variable-length strings
    //
    PUCHAR stringPtr = (PUCHAR)(notification + 1);
    ULONG remaining = totalSize - (ULONG)((PUCHAR)stringPtr - (PUCHAR)header);

    if (ImageName && imageNameLen > 0 && remaining >= imageNameLen) {
        RtlCopyMemory(stringPtr, ImageName->Buffer, imageNameLen);
        stringPtr += imageNameLen;
        remaining -= imageNameLen;
    }

    if (CommandLine && cmdLineLen > 0 && remaining >= cmdLineLen) {
        RtlCopyMemory(stringPtr, CommandLine->Buffer, cmdLineLen);
    }

    //
    // Send fire-and-forget notification (no reply expected)
    //
    status = ShadowStrikeSendMessage(
        header,
        totalSize,
        NULL,
        NULL,
        NULL
    );

    //
    // Free message buffer back to lookaside list
    //
    ShadowStrikeFreeMessageBuffer(header);

    return status;
}

// ============================================================================
// THREAD NOTIFICATION
// ============================================================================

NTSTATUS
ShadowStrikeSendThreadNotification(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create,
    _In_ BOOLEAN IsRemote
    )
{
    NTSTATUS status;
    PSHADOWSTRIKE_MESSAGE_HEADER header = NULL;
    PSHADOWSTRIKE_THREAD_NOTIFICATION notification = NULL;
    ULONG totalSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) +
                      sizeof(SHADOWSTRIKE_THREAD_NOTIFICATION);

    PAGED_CODE();

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
    // Allocate message buffer
    //
    header = (PSHADOWSTRIKE_MESSAGE_HEADER)ShadowStrikeAllocateMessageBuffer(totalSize);
    if (header == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize header
    //
    ShadowStrikeInitMessageHeader(
        header,
        ShadowStrikeMessageThreadNotify,
        sizeof(SHADOWSTRIKE_THREAD_NOTIFICATION)
    );

    //
    // Fill notification payload
    //
    notification = (PSHADOWSTRIKE_THREAD_NOTIFICATION)((PUCHAR)header + sizeof(SHADOWSTRIKE_MESSAGE_HEADER));
    notification->ProcessId = HandleToULong(ProcessId);
    notification->ThreadId = HandleToULong(ThreadId);
    notification->CreatorProcessId = HandleToULong(PsGetCurrentProcessId());
    notification->CreatorThreadId = HandleToULong(PsGetCurrentThreadId());
    notification->IsRemote = IsRemote;

    //
    // Send notification
    //
    status = ShadowStrikeSendMessage(
        header,
        totalSize,
        NULL,
        NULL,
        NULL
    );

    ShadowStrikeFreeMessageBuffer(header);

    return status;
}

// ============================================================================
// IMAGE LOAD NOTIFICATION
// ============================================================================

NTSTATUS
ShadowStrikeSendImageNotification(
    _In_ HANDLE ProcessId,
    _In_ PUNICODE_STRING FullImageName,
    _In_ PIMAGE_INFO ImageInfo
    )
{
    NTSTATUS status;
    PSHADOWSTRIKE_MESSAGE_HEADER header = NULL;
    PSHADOWSTRIKE_IMAGE_NOTIFICATION notification = NULL;
    ULONG imageNameLen = FullImageName ? FullImageName->Length : 0;
    ULONG totalSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) +
                      sizeof(SHADOWSTRIKE_IMAGE_NOTIFICATION) +
                      imageNameLen + sizeof(WCHAR);

    PAGED_CODE();

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

    if (totalSize > SHADOWSTRIKE_MAX_MESSAGE_SIZE) {
        totalSize = SHADOWSTRIKE_MAX_MESSAGE_SIZE;
    }

    //
    // Allocate message buffer
    //
    header = (PSHADOWSTRIKE_MESSAGE_HEADER)ShadowStrikeAllocateMessageBuffer(totalSize);
    if (header == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize header
    //
    ShadowStrikeInitMessageHeader(
        header,
        ShadowStrikeMessageImageLoad,
        totalSize - sizeof(SHADOWSTRIKE_MESSAGE_HEADER)
    );

    //
    // Fill notification payload
    //
    notification = (PSHADOWSTRIKE_IMAGE_NOTIFICATION)((PUCHAR)header + sizeof(SHADOWSTRIKE_MESSAGE_HEADER));
    notification->ProcessId = HandleToULong(ProcessId);
    notification->ImageBase = (UINT64)ImageInfo->ImageBase;
    notification->ImageSize = (UINT64)ImageInfo->ImageSize;
    notification->IsSystemImage = (BOOLEAN)ImageInfo->SystemModeImage;

    //
    // Get signature information from extended info if available
    //
    if (ImageInfo->ExtendedInfoPresent) {
        PIMAGE_INFO_EX imageInfoEx = CONTAINING_RECORD(ImageInfo, IMAGE_INFO_EX, ImageInfo);
        notification->SignatureLevel = imageInfoEx->ImageSignatureLevel;
        notification->SignatureType = imageInfoEx->ImageSignatureType;
    } else {
        notification->SignatureLevel = 0;
        notification->SignatureType = 0;
    }

    notification->ImageNameLength = (UINT16)imageNameLen;

    //
    // Copy image name
    //
    PUCHAR stringPtr = (PUCHAR)(notification + 1);
    if (FullImageName && imageNameLen > 0) {
        RtlCopyMemory(stringPtr, FullImageName->Buffer, imageNameLen);
    }

    //
    // Send notification
    //
    status = ShadowStrikeSendMessage(
        header,
        totalSize,
        NULL,
        NULL,
        NULL
    );

    ShadowStrikeFreeMessageBuffer(header);

    return status;
}

// ============================================================================
// REGISTRY NOTIFICATION
// ============================================================================

NTSTATUS
ShadowStrikeSendRegistryNotification(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ UINT8 Operation,
    _In_ PUNICODE_STRING KeyPath,
    _In_opt_ PUNICODE_STRING ValueName,
    _In_opt_ PVOID Data,
    _In_ ULONG DataSize,
    _In_ ULONG DataType
    )
{
    NTSTATUS status;
    PSHADOWSTRIKE_MESSAGE_HEADER header = NULL;
    PSHADOWSTRIKE_REGISTRY_NOTIFICATION notification = NULL;
    ULONG keyPathLen = KeyPath ? KeyPath->Length : 0;
    ULONG valueNameLen = ValueName ? ValueName->Length : 0;

    PAGED_CODE();

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
    // Limit captured data size to prevent huge messages
    //
    ULONG safeDataSize = (Data && DataSize > 0) ? DataSize : 0;
    if (safeDataSize > MAX_REGISTRY_DATA_SIZE) {
        safeDataSize = MAX_REGISTRY_DATA_SIZE;
    }

    ULONG totalSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) +
                      sizeof(SHADOWSTRIKE_REGISTRY_NOTIFICATION) +
                      keyPathLen + sizeof(WCHAR) +
                      valueNameLen + sizeof(WCHAR) +
                      safeDataSize;

    if (totalSize > SHADOWSTRIKE_MAX_MESSAGE_SIZE) {
        totalSize = SHADOWSTRIKE_MAX_MESSAGE_SIZE;
    }

    //
    // Allocate message buffer
    //
    header = (PSHADOWSTRIKE_MESSAGE_HEADER)ShadowStrikeAllocateMessageBuffer(totalSize);
    if (header == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize header
    //
    ShadowStrikeInitMessageHeader(
        header,
        ShadowStrikeMessageRegistryNotify,
        totalSize - sizeof(SHADOWSTRIKE_MESSAGE_HEADER)
    );

    //
    // Fill notification payload
    //
    notification = (PSHADOWSTRIKE_REGISTRY_NOTIFICATION)((PUCHAR)header + sizeof(SHADOWSTRIKE_MESSAGE_HEADER));
    notification->ProcessId = HandleToULong(ProcessId);
    notification->ThreadId = HandleToULong(ThreadId);
    notification->Operation = Operation;
    notification->KeyPathLength = (UINT16)keyPathLen;
    notification->ValueNameLength = (UINT16)valueNameLen;
    notification->DataSize = safeDataSize;
    notification->DataType = DataType;

    //
    // Copy variable-length data
    //
    PUCHAR stringPtr = (PUCHAR)(notification + 1);
    ULONG remaining = totalSize - (ULONG)((PUCHAR)stringPtr - (PUCHAR)header);

    // Copy key path
    if (KeyPath && keyPathLen > 0 && remaining >= keyPathLen) {
        RtlCopyMemory(stringPtr, KeyPath->Buffer, keyPathLen);
        stringPtr += keyPathLen;
        remaining -= keyPathLen;
    }

    // Copy value name
    if (ValueName && valueNameLen > 0 && remaining >= valueNameLen) {
        RtlCopyMemory(stringPtr, ValueName->Buffer, valueNameLen);
        stringPtr += valueNameLen;
        remaining -= valueNameLen;
    }

    // Copy data (with exception handling for potentially invalid user pointers)
    if (Data && safeDataSize > 0 && remaining >= safeDataSize) {
        __try {
            RtlCopyMemory(stringPtr, Data, safeDataSize);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // Failed to copy data, zero it out
            RtlZeroMemory(stringPtr, safeDataSize);
            notification->DataSize = 0;
        }
    }

    //
    // Send notification
    //
    status = ShadowStrikeSendMessage(
        header,
        totalSize,
        NULL,
        NULL,
        NULL
    );

    ShadowStrikeFreeMessageBuffer(header);

    return status;
}
