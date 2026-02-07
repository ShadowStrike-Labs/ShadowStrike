/**
 * ============================================================================
 * ShadowStrike NGAV - FILE UTILITIES
 * ============================================================================
 *
 * @file FileUtils.c
 * @brief Implementation of file information retrieval helpers.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "FileUtils.h"
#include "StringUtils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ShadowStrikeGetFileName)
#pragma alloc_text(PAGE, ShadowStrikeGetFileId)
#pragma alloc_text(PAGE, ShadowStrikeGetFileSize)
#endif

NTSTATUS
ShadowStrikeGetFileName(
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_ PUNICODE_STRING FileName
    )
{
    NTSTATUS Status;
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;

    PAGED_CODE();

    //
    // Get the name information
    // FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT
    //
    Status = FltGetFileNameInformation(Data,
                                     FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                     &NameInfo);

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Parse the name
    //
    Status = FltParseFileNameInformation(NameInfo);
    if (!NT_SUCCESS(Status)) {
        FltReleaseFileNameInformation(NameInfo);
        return Status;
    }

    //
    // Copy to output string
    //
    Status = ShadowStrikeCopyUnicodeString(FileName, &NameInfo->Name);

    FltReleaseFileNameInformation(NameInfo);

    return Status;
}

NTSTATUS
ShadowStrikeGetFileId(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PULONG64 FileId
    )
{
    NTSTATUS Status;
    FILE_INTERNAL_INFORMATION FileInternalInfo;
    ULONG ReturnLength;

    PAGED_CODE();

    Status = FltQueryInformationFile(Instance,
                                   FileObject,
                                   &FileInternalInfo,
                                   sizeof(FILE_INTERNAL_INFORMATION),
                                   FileInternalInformation,
                                   &ReturnLength);

    if (NT_SUCCESS(Status)) {
        *FileId = FileInternalInfo.IndexNumber.QuadPart;
    }

    return Status;
}

NTSTATUS
ShadowStrikeGetFileSize(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PLONGLONG FileSize
    )
{
    NTSTATUS Status;
    FILE_STANDARD_INFORMATION FileStandardInfo;
    ULONG ReturnLength;

    PAGED_CODE();

    Status = FltQueryInformationFile(Instance,
                                   FileObject,
                                   &FileStandardInfo,
                                   sizeof(FILE_STANDARD_INFORMATION),
                                   FileStandardInformation,
                                   &ReturnLength);

    if (NT_SUCCESS(Status)) {
        *FileSize = FileStandardInfo.EndOfFile.QuadPart;
    }

    return Status;
}
