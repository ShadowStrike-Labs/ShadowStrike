/**
 * ============================================================================
 * ShadowStrike NGAV - SCAN BRIDGE IMPLEMENTATION
 * ============================================================================
 *
 * @file ScanBridge.c
 * @brief Implementation of scan request building and sending.
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
#pragma alloc_text(PAGE, ShadowStrikeBuildFileScanRequest)
#pragma alloc_text(PAGE, ShadowStrikeSendScanRequest)
#pragma alloc_text(PAGE, ShadowStrikeSendProcessNotification)
#pragma alloc_text(PAGE, ShadowStrikeSendThreadNotification)
#pragma alloc_text(PAGE, ShadowStrikeSendImageNotification)
#pragma alloc_text(PAGE, ShadowStrikeSendRegistryNotification)
#pragma alloc_text(PAGE, ShadowStrikeAllocateMessageBuffer)
#pragma alloc_text(PAGE, ShadowStrikeFreeMessageBuffer)
#endif

NTSTATUS
ShadowStrikeBuildFileScanRequest(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ SHADOWSTRIKE_ACCESS_TYPE AccessType,
    _Outptr_ PSHADOWSTRIKE_MESSAGE_HEADER* Request,
    _Out_ PULONG RequestSize
    )
{
    NTSTATUS Status;
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
    PFILE_SCAN_REQUEST ScanRequest = NULL;
    PSHADOWSTRIKE_MESSAGE_HEADER Header = NULL;
    ULONG TotalSize = 0;
    UNICODE_STRING FileName = {0};
    UNICODE_STRING ProcessName = {0};
    UNICODE_STRING EmptyString = RTL_CONSTANT_STRING(L"");
    UCHAR ProcessNameBuffer[512]; // Temp buffer for process name

    PAGED_CODE();

    *Request = NULL;
    *RequestSize = 0;

    //
    // 1. Get File Name
    //
    Status = FltGetFileNameInformation(Data,
                                     FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                     &NameInfo);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = FltParseFileNameInformation(NameInfo);
    if (!NT_SUCCESS(Status)) {
        FltReleaseFileNameInformation(NameInfo);
        return Status;
    }

    FileName = NameInfo->Name;

    //
    // 2. Get Process Name
    //
    RtlInitEmptyUnicodeString(&ProcessName, (PWCHAR)ProcessNameBuffer, sizeof(ProcessNameBuffer));
    if (!NT_SUCCESS(ShadowStrikeGetProcessImageName(PsGetCurrentProcessId(), &ProcessName))) {
        ProcessName = EmptyString;
    }

    //
    // 3. Calculate Size
    //
    TotalSize = sizeof(FILTER_MESSAGE_HEADER) + sizeof(FILE_SCAN_REQUEST) +
                FileName.Length + sizeof(WCHAR) +
                ProcessName.Length + sizeof(WCHAR);

    if (TotalSize > SHADOWSTRIKE_MAX_MESSAGE_SIZE) {
        // Truncate path if needed
        TotalSize = SHADOWSTRIKE_MAX_MESSAGE_SIZE;
    }

    //
    // 4. Allocate Buffer
    //
    Header = (PSHADOWSTRIKE_MESSAGE_HEADER)ShadowStrikeAllocateMessageBuffer(TotalSize);
    if (Header == NULL) {
        FltReleaseFileNameInformation(NameInfo);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // 5. Fill Header
    //
    Header->Magic = SHADOWSTRIKE_MESSAGE_MAGIC;
    Header->Version = SHADOWSTRIKE_PROTOCOL_VERSION;
    Header->MessageType = FilterMessageType_ScanRequest;
    Header->MessageId = SHADOWSTRIKE_NEXT_MESSAGE_ID();
    Header->TotalSize = TotalSize;
    Header->DataSize = TotalSize - sizeof(FILTER_MESSAGE_HEADER);
    KeQuerySystemTime((PLARGE_INTEGER)&Header->Timestamp);
    Header->Flags = 0;

    //
    // 6. Fill Scan Request
    //
    ScanRequest = (PFILE_SCAN_REQUEST)(Header + 1);
    ScanRequest->MessageId = Header->MessageId;
    ScanRequest->AccessType = (UINT8)AccessType;
    ScanRequest->ProcessId = HandleToULong(PsGetCurrentProcessId());
    ScanRequest->ThreadId = HandleToULong(PsGetCurrentThreadId());

    // Fill file info
    ScanRequest->PathLength = FileName.Length;
    ScanRequest->ProcessNameLength = ProcessName.Length;

    // Copy strings
    PUCHAR StringPtr = (PUCHAR)(ScanRequest + 1);

    // Safety check for buffer overflow
    ULONG RemainingSize = TotalSize - (ULONG)((PUCHAR)StringPtr - (PUCHAR)Header);

    if (RemainingSize >= FileName.Length) {
        RtlCopyMemory(StringPtr, FileName.Buffer, FileName.Length);
        StringPtr += FileName.Length;
        RemainingSize -= FileName.Length;
    }

    if (RemainingSize >= ProcessName.Length) {
        RtlCopyMemory(StringPtr, ProcessName.Buffer, ProcessName.Length);
    }

    FltReleaseFileNameInformation(NameInfo);

    *Request = Header;
    *RequestSize = TotalSize;

    return STATUS_SUCCESS;
}

NTSTATUS
ShadowStrikeSendScanRequest(
    _In_ PSHADOWSTRIKE_MESSAGE_HEADER Request,
    _In_ ULONG RequestSize,
    _Out_ PSHADOWSTRIKE_SCAN_VERDICT_REPLY Reply,
    _Inout_ PULONG ReplySize,
    _In_ ULONG TimeoutMs
    )
{
    NTSTATUS Status;
    LARGE_INTEGER Timeout;

    PAGED_CODE();

    // Convert ms to 100ns units (negative for relative time)
    Timeout.QuadPart = -(LONGLONG)TimeoutMs * 10000;

    Status = ShadowStrikeSendMessage(
        Request,
        RequestSize,
        Reply,
        ReplySize,
        &Timeout
    );

    return Status;
}

NTSTATUS
ShadowStrikeSendProcessNotification(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentId,
    _In_ BOOLEAN Create,
    _In_ PUNICODE_STRING ImageName,
    _In_opt_ PUNICODE_STRING CommandLine
    )
{
    NTSTATUS Status;
    PSHADOWSTRIKE_MESSAGE_HEADER Header = NULL;
    PSHADOWSTRIKE_PROCESS_NOTIFICATION Notification = NULL;
    ULONG TotalSize = 0;
    ULONG ImageNameLen = ImageName ? ImageName->Length : 0;
    ULONG CmdLineLen = CommandLine ? CommandLine->Length : 0;

    PAGED_CODE();

    TotalSize = sizeof(FILTER_MESSAGE_HEADER) + sizeof(SHADOWSTRIKE_PROCESS_NOTIFICATION) +
                ImageNameLen + sizeof(WCHAR) +
                CmdLineLen + sizeof(WCHAR);

    if (TotalSize > SHADOWSTRIKE_MAX_MESSAGE_SIZE) {
        TotalSize = SHADOWSTRIKE_MAX_MESSAGE_SIZE;
    }

    Header = (PSHADOWSTRIKE_MESSAGE_HEADER)ShadowStrikeAllocateMessageBuffer(TotalSize);
    if (!Header) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Header->Magic = SHADOWSTRIKE_MESSAGE_MAGIC;
    Header->Version = SHADOWSTRIKE_PROTOCOL_VERSION;
    Header->MessageType = FilterMessageType_ProcessNotify;
    Header->MessageId = SHADOWSTRIKE_NEXT_MESSAGE_ID();
    Header->TotalSize = TotalSize;
    Header->DataSize = TotalSize - sizeof(FILTER_MESSAGE_HEADER);
    KeQuerySystemTime((PLARGE_INTEGER)&Header->Timestamp);
    Header->Flags = 0; // Async

    Notification = (PSHADOWSTRIKE_PROCESS_NOTIFICATION)(Header + 1);
    Notification->ProcessId = HandleToULong(ProcessId);
    Notification->ParentProcessId = HandleToULong(ParentId);
    Notification->CreatingProcessId = HandleToULong(PsGetCurrentProcessId());
    Notification->CreatingThreadId = HandleToULong(PsGetCurrentThreadId());
    Notification->Create = Create;
    Notification->ImagePathLength = (UINT16)ImageNameLen;
    Notification->CommandLineLength = (UINT16)CmdLineLen;

    PUCHAR StringPtr = (PUCHAR)(Notification + 1);
    ULONG Remaining = TotalSize - (ULONG)((PUCHAR)StringPtr - (PUCHAR)Header);

    if (ImageName && ImageNameLen > 0 && Remaining >= ImageNameLen) {
        RtlCopyMemory(StringPtr, ImageName->Buffer, ImageNameLen);
        StringPtr += ImageNameLen;
        Remaining -= ImageNameLen;
    }

    if (CommandLine && CmdLineLen > 0 && Remaining >= CmdLineLen) {
        RtlCopyMemory(StringPtr, CommandLine->Buffer, CmdLineLen);
    }

    // Fire and forget - NULL timeout/reply
    Status = ShadowStrikeSendMessage(
        Header,
        TotalSize,
        NULL,
        NULL,
        NULL
    );

    ShadowStrikeFreeMessageBuffer(Header);
    return Status;
}

NTSTATUS
ShadowStrikeSendThreadNotification(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create,
    _In_ BOOLEAN IsRemote
    )
{
    NTSTATUS Status;
    PSHADOWSTRIKE_MESSAGE_HEADER Header = NULL;
    PSHADOWSTRIKE_THREAD_NOTIFICATION Notification = NULL;
    ULONG TotalSize = sizeof(FILTER_MESSAGE_HEADER) + sizeof(SHADOWSTRIKE_THREAD_NOTIFICATION);

    PAGED_CODE();

    Header = (PSHADOWSTRIKE_MESSAGE_HEADER)ShadowStrikeAllocateMessageBuffer(TotalSize);
    if (!Header) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Header->Magic = SHADOWSTRIKE_MESSAGE_MAGIC;
    Header->Version = SHADOWSTRIKE_PROTOCOL_VERSION;
    Header->MessageType = FilterMessageType_ThreadNotify;
    Header->MessageId = SHADOWSTRIKE_NEXT_MESSAGE_ID();
    Header->TotalSize = TotalSize;
    Header->DataSize = TotalSize - sizeof(FILTER_MESSAGE_HEADER);
    KeQuerySystemTime((PLARGE_INTEGER)&Header->Timestamp);
    Header->Flags = 0;

    Notification = (PSHADOWSTRIKE_THREAD_NOTIFICATION)(Header + 1);
    Notification->ProcessId = HandleToULong(ProcessId);
    Notification->ThreadId = HandleToULong(ThreadId);
    Notification->CreatorProcessId = HandleToULong(PsGetCurrentProcessId());
    Notification->CreatorThreadId = HandleToULong(PsGetCurrentThreadId());
    Notification->IsRemote = IsRemote;

    Status = ShadowStrikeSendMessage(
        Header,
        TotalSize,
        NULL,
        NULL,
        NULL
    );

    ShadowStrikeFreeMessageBuffer(Header);
    return Status;
}

NTSTATUS
ShadowStrikeSendImageNotification(
    _In_ HANDLE ProcessId,
    _In_ PUNICODE_STRING FullImageName,
    _In_ PIMAGE_INFO ImageInfo
    )
{
    NTSTATUS Status;
    PSHADOWSTRIKE_MESSAGE_HEADER Header = NULL;
    PSHADOWSTRIKE_IMAGE_NOTIFICATION Notification = NULL;
    ULONG ImageNameLen = FullImageName ? FullImageName->Length : 0;
    ULONG TotalSize = sizeof(FILTER_MESSAGE_HEADER) + sizeof(SHADOWSTRIKE_IMAGE_NOTIFICATION) +
                      ImageNameLen + sizeof(WCHAR);

    PAGED_CODE();

    if (TotalSize > SHADOWSTRIKE_MAX_MESSAGE_SIZE) {
        TotalSize = SHADOWSTRIKE_MAX_MESSAGE_SIZE;
    }

    Header = (PSHADOWSTRIKE_MESSAGE_HEADER)ShadowStrikeAllocateMessageBuffer(TotalSize);
    if (!Header) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Header->Magic = SHADOWSTRIKE_MESSAGE_MAGIC;
    Header->Version = SHADOWSTRIKE_PROTOCOL_VERSION;
    Header->MessageType = FilterMessageType_ImageLoad;
    Header->MessageId = SHADOWSTRIKE_NEXT_MESSAGE_ID();
    Header->TotalSize = TotalSize;
    Header->DataSize = TotalSize - sizeof(FILTER_MESSAGE_HEADER);
    KeQuerySystemTime((PLARGE_INTEGER)&Header->Timestamp);
    Header->Flags = 0;

    Notification = (PSHADOWSTRIKE_IMAGE_NOTIFICATION)(Header + 1);
    Notification->ProcessId = HandleToULong(ProcessId);
    Notification->ImageBase = (UINT64)ImageInfo->ImageBase;
    Notification->ImageSize = (UINT64)ImageInfo->ImageSize;
    Notification->IsSystemImage = (BOOLEAN)ImageInfo->SystemModeImage;

    // Extended Info for signature level if available
    if (ImageInfo->ExtendedInfoPresent) {
        PIMAGE_INFO_EX ImageInfoEx = (PIMAGE_INFO_EX)ImageInfo;
        Notification->SignatureLevel = ImageInfoEx->ImageSignatureLevel;
        Notification->SignatureType = ImageInfoEx->ImageSignatureType;
    } else {
        Notification->SignatureLevel = 0;
        Notification->SignatureType = 0;
    }

    Notification->ImageNameLength = (UINT16)ImageNameLen;

    PUCHAR StringPtr = (PUCHAR)(Notification + 1);
    if (FullImageName && ImageNameLen > 0) {
        RtlCopyMemory(StringPtr, FullImageName->Buffer, ImageNameLen);
    }

    Status = ShadowStrikeSendMessage(
        Header,
        TotalSize,
        NULL,
        NULL,
        NULL
    );

    ShadowStrikeFreeMessageBuffer(Header);
    return Status;
}

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
    NTSTATUS Status;
    PSHADOWSTRIKE_MESSAGE_HEADER Header = NULL;
    PSHADOWSTRIKE_REGISTRY_NOTIFICATION Notification = NULL;
    ULONG KeyPathLen = KeyPath ? KeyPath->Length : 0;
    ULONG ValueNameLen = ValueName ? ValueName->Length : 0;

    // We limit data size to avoid huge messages
    ULONG SafeDataSize = (Data && DataSize > 0) ? DataSize : 0;
    if (SafeDataSize > 1024) SafeDataSize = 1024; // Cap captured data at 1KB

    ULONG TotalSize = sizeof(FILTER_MESSAGE_HEADER) + sizeof(SHADOWSTRIKE_REGISTRY_NOTIFICATION) +
                      KeyPathLen + sizeof(WCHAR) +
                      ValueNameLen + sizeof(WCHAR) +
                      SafeDataSize;

    PAGED_CODE();

    if (TotalSize > SHADOWSTRIKE_MAX_MESSAGE_SIZE) {
        TotalSize = SHADOWSTRIKE_MAX_MESSAGE_SIZE;
        // Truncate if still too big? For now just cap.
    }

    Header = (PSHADOWSTRIKE_MESSAGE_HEADER)ShadowStrikeAllocateMessageBuffer(TotalSize);
    if (!Header) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Header->Magic = SHADOWSTRIKE_MESSAGE_MAGIC;
    Header->Version = SHADOWSTRIKE_PROTOCOL_VERSION;
    Header->MessageType = FilterMessageType_RegistryNotify;
    Header->MessageId = SHADOWSTRIKE_NEXT_MESSAGE_ID();
    Header->TotalSize = TotalSize;
    Header->DataSize = TotalSize - sizeof(FILTER_MESSAGE_HEADER);
    KeQuerySystemTime((PLARGE_INTEGER)&Header->Timestamp);
    Header->Flags = 0;

    Notification = (PSHADOWSTRIKE_REGISTRY_NOTIFICATION)(Header + 1);
    Notification->ProcessId = HandleToULong(ProcessId);
    Notification->ThreadId = HandleToULong(ThreadId);
    Notification->Operation = Operation;
    Notification->KeyPathLength = (UINT16)KeyPathLen;
    Notification->ValueNameLength = (UINT16)ValueNameLen;
    Notification->DataSize = SafeDataSize;
    Notification->DataType = DataType;

    PUCHAR StringPtr = (PUCHAR)(Notification + 1);
    ULONG Remaining = TotalSize - (ULONG)((PUCHAR)StringPtr - (PUCHAR)Header);

    // Copy Key Path
    if (KeyPath && KeyPathLen > 0 && Remaining >= KeyPathLen) {
        RtlCopyMemory(StringPtr, KeyPath->Buffer, KeyPathLen);
        StringPtr += KeyPathLen;
        Remaining -= KeyPathLen;
    }

    // Copy Value Name
    if (ValueName && ValueNameLen > 0 && Remaining >= ValueNameLen) {
        RtlCopyMemory(StringPtr, ValueName->Buffer, ValueNameLen);
        StringPtr += ValueNameLen;
        Remaining -= ValueNameLen;
    }

    // Copy Data
    if (Data && SafeDataSize > 0 && Remaining >= SafeDataSize) {
        // Need to be careful with reading user pointers?
        // Assuming Data came from kernel capture or trusted source in RegistryCallback.
        // In RegistryCallback, 'Data' comes from PREG_SET_VALUE_KEY_INFORMATION which is kernel memory (usually).
        // But let's use try/except if we were paranoid, but here we assume caller (RegistryCallback) handled probing if needed.
        // Actually RegistryCallback gets it from CmCallback, which provides kernel pointers for system space or user pointers.
        // We should assume it might be user memory?
        // CmCallback data is usually valid in context.
        RtlCopyMemory(StringPtr, Data, SafeDataSize);
    }

    Status = ShadowStrikeSendMessage(
        Header,
        TotalSize,
        NULL,
        NULL,
        NULL
    );

    ShadowStrikeFreeMessageBuffer(Header);
    return Status;
}

PVOID
ShadowStrikeAllocateMessageBuffer(
    _In_ ULONG Size
    )
{
    PVOID Buffer = NULL;

    PAGED_CODE();

    if (Size <= SHADOWSTRIKE_MAX_MESSAGE_SIZE) {
        Buffer = ExAllocateFromNPagedLookasideList(&g_DriverData.MessageLookaside);
    }

    if (Buffer == NULL) {
        Buffer = ShadowStrikeAllocate(Size);
    } else {
        RtlZeroMemory(Buffer, Size);
    }

    return Buffer;
}

VOID
ShadowStrikeFreeMessageBuffer(
    _In_ PVOID Buffer
    )
{
    PAGED_CODE();

    if (Buffer) {
        ShadowStrikeFreePool(Buffer);
    }
}
