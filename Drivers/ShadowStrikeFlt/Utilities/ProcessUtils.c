/**
 * ============================================================================
 * ShadowStrike NGAV - PROCESS UTILITIES
 * ============================================================================
 *
 * @file ProcessUtils.c
 * @brief Implementation of process information retrieval.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "ProcessUtils.h"
#include "MemoryUtils.h"

//
// Typedef for ZwQueryInformationProcess
//
typedef NTSTATUS (NTAPI *ZWQUERYINFORMATIONPROCESS)(
    _In_      HANDLE           ProcessHandle,
    _In_      PROCESSINFOCLASS ProcessInformationClass,
    _Out_     PVOID            ProcessInformation,
    _In_      ULONG            ProcessInformationLength,
    _Out_opt_ PULONG           ReturnLength
    );

//
// Globals
//
ZWQUERYINFORMATIONPROCESS ZwQueryInformationProcess = NULL;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ShadowStrikeGetProcessImageName)
#pragma alloc_text(PAGE, ShadowStrikeGetProcessIdFromHandle)
#endif

//
// Helper to get ZwQueryInformationProcess address
//
NTSTATUS
InitZwQueryInformationProcess()
{
    UNICODE_STRING RoutineName;
    RtlInitUnicodeString(&RoutineName, L"ZwQueryInformationProcess");

    ZwQueryInformationProcess = (ZWQUERYINFORMATIONPROCESS)MmGetSystemRoutineAddress(&RoutineName);

    if (ZwQueryInformationProcess == NULL) {
        return STATUS_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
ShadowStrikeGetProcessImageName(
    _In_ HANDLE ProcessId,
    _Out_ PUNICODE_STRING ProcessName
    )
{
    NTSTATUS Status;
    HANDLE ProcessHandle = NULL;
    PEPROCESS ProcessObject = NULL;
    ULONG ReturnLength = 0;
    PUNICODE_STRING ImageName = NULL;
    UCHAR Buffer[512]; // Initial buffer
    PVOID ProcessInfoBuffer = Buffer;
    ULONG ProcessInfoLen = sizeof(Buffer);
    OBJECT_ATTRIBUTES ObjectAttributes;
    CLIENT_ID ClientId;

    PAGED_CODE();

    if (ZwQueryInformationProcess == NULL) {
        Status = InitZwQueryInformationProcess();
        if (!NT_SUCCESS(Status)) {
            return Status;
        }
    }

    //
    // Get handle to process
    //
    InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    ClientId.UniqueProcess = ProcessId;
    ClientId.UniqueThread = NULL;

    Status = ZwOpenProcess(&ProcessHandle, PROCESS_QUERY_LIMITED_INFORMATION, &ObjectAttributes, &ClientId);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Query for ProcessImageFileName (27)
    //
    Status = ZwQueryInformationProcess(ProcessHandle,
                                     ProcessImageFileName,
                                     ProcessInfoBuffer,
                                     ProcessInfoLen,
                                     &ReturnLength);

    if (Status == STATUS_INFO_LENGTH_MISMATCH) {
        // Allocate larger buffer
        ProcessInfoLen = ReturnLength;
        ProcessInfoBuffer = ShadowStrikeAllocatePaged(ProcessInfoLen);
        if (ProcessInfoBuffer == NULL) {
            ZwClose(ProcessHandle);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Status = ZwQueryInformationProcess(ProcessHandle,
                                         ProcessImageFileName,
                                         ProcessInfoBuffer,
                                         ProcessInfoLen,
                                         &ReturnLength);
    }

    if (NT_SUCCESS(Status)) {
        ImageName = (PUNICODE_STRING)ProcessInfoBuffer;

        //
        // Deep copy the string to the caller's structure
        //
        Status = STATUS_BUFFER_TOO_SMALL;
        if (ProcessName->MaximumLength >= ImageName->Length) {
             RtlCopyUnicodeString(ProcessName, ImageName);
             Status = STATUS_SUCCESS;
        }
    }

    if (ProcessInfoBuffer != Buffer) {
        ShadowStrikeFreePool(ProcessInfoBuffer);
    }

    ZwClose(ProcessHandle);
    return Status;
}

NTSTATUS
ShadowStrikeGetProcessIdFromHandle(
    _In_ HANDLE ProcessHandle,
    _Out_ PHANDLE ProcessId
    )
{
    NTSTATUS Status;
    PROCESS_BASIC_INFORMATION BasicInfo;
    ULONG ReturnLength;

    PAGED_CODE();

    if (ZwQueryInformationProcess == NULL) {
        Status = InitZwQueryInformationProcess();
        if (!NT_SUCCESS(Status)) {
            return Status;
        }
    }

    Status = ZwQueryInformationProcess(ProcessHandle,
                                     ProcessBasicInformation,
                                     &BasicInfo,
                                     sizeof(BasicInfo),
                                     &ReturnLength);

    if (NT_SUCCESS(Status)) {
        *ProcessId = (HANDLE)BasicInfo.UniqueProcessId;
    }

    return Status;
}

BOOLEAN
ShadowStrikeIsProcessTerminating(
    _In_ PEPROCESS Process
    )
{
    // Check if process flags indicate termination
    // This is often version dependent, so be careful.
    // Usually checking signal state involves undocumented offsets or just PsGetProcessExitStatus
    // For now we assume false as we don't have safe way to check without offsets.
    UNREFERENCED_PARAMETER(Process);
    return FALSE;
}
