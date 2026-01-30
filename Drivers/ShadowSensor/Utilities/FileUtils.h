/**
 * ============================================================================
 * ShadowStrike NGAV - FILE UTILITIES
 * ============================================================================
 *
 * @file FileUtils.h
 * @brief Helper functions for file information retrieval.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_FILE_UTILS_H_
#define _SHADOWSTRIKE_FILE_UTILS_H_

#include <fltKernel.h>

//
// Function Prototypes
//

NTSTATUS
ShadowStrikeGetFileName(
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_ PUNICODE_STRING FileName
    );

NTSTATUS
ShadowStrikeGetFileId(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PULONG64 FileId
    );

NTSTATUS
ShadowStrikeGetFileSize(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PLONGLONG FileSize
    );

#endif // _SHADOWSTRIKE_FILE_UTILS_H_
