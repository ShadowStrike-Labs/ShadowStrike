#pragma once

#include <fltKernel.h>
#include "../Shared/MessageProtocol.h"
#include "../Shared/VerdictTypes.h"
#include "../Shared/MessageTypes.h"

//
// Access types for scan request
//
typedef enum _SHADOWSTRIKE_ACCESS_TYPE {
    ShadowStrikeAccessRead = 1,
    ShadowStrikeAccessWrite,
    ShadowStrikeAccessExecute,
    ShadowStrikeAccessCreate,
    ShadowStrikeAccessRename,
    ShadowStrikeAccessDelete
} SHADOWSTRIKE_ACCESS_TYPE;

//
// Function Prototypes
//

NTSTATUS
ShadowStrikeBuildFileScanRequest(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ SHADOWSTRIKE_ACCESS_TYPE AccessType,
    _Outptr_ PSHADOWSTRIKE_MESSAGE_HEADER* Request,
    _Out_ PULONG RequestSize
    );

NTSTATUS
ShadowStrikeSendScanRequest(
    _In_ PSHADOWSTRIKE_MESSAGE_HEADER Request,
    _In_ ULONG RequestSize,
    _Out_ PSHADOWSTRIKE_SCAN_VERDICT_REPLY Reply,
    _Inout_ PULONG ReplySize,
    _In_ ULONG TimeoutMs
    );

NTSTATUS
ShadowStrikeSendProcessNotification(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentId,
    _In_ BOOLEAN Create,
    _In_ PUNICODE_STRING ImageName,
    _In_opt_ PUNICODE_STRING CommandLine
    );

NTSTATUS
ShadowStrikeSendThreadNotification(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create,
    _In_ BOOLEAN IsRemote
    );

NTSTATUS
ShadowStrikeSendImageNotification(
    _In_ HANDLE ProcessId,
    _In_ PUNICODE_STRING FullImageName,
    _In_ PIMAGE_INFO ImageInfo
    );

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
    );

PVOID
ShadowStrikeAllocateMessageBuffer(
    _In_ ULONG Size
    );

VOID
ShadowStrikeFreeMessageBuffer(
    _In_ PVOID Buffer
    );

// Helper from ScanBridge.c to handle generic sending
NTSTATUS
ShadowStrikeSendMessage(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_opt_ PVOID OutputBuffer,
    _Inout_opt_ PULONG OutputBufferSize,
    _In_opt_ PLARGE_INTEGER Timeout
    );
