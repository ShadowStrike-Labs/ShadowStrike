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
/*++
    ShadowStrike Next-Generation Antivirus
    Module: FileProtection.h

    Purpose: Enterprise-grade file protection for EDR self-defense.

    This module provides comprehensive file-level protection capabilities:
    - Protected file/directory path management
    - NTFS Alternate Data Stream (ADS) protection
    - Path normalization and canonicalization
    - Symbolic link and junction point resolution
    - Short name (8.3) to long name resolution
    - File extension-based protection rules
    - Comprehensive audit logging
    - Integration with minifilter callbacks

    Security Considerations:
    - All paths are normalized before comparison
    - Case-insensitive matching for Windows compatibility
    - ADS names are stripped to prevent bypass
    - Symbolic links resolved to prevent bypass
    - Short names resolved via FltGetFileNameInformation(NORMALIZED)
    - Opaque engine struct prevents direct internal access
    - Reference counting on protected paths prevents use-after-free
    - All stack buffers eliminated from hot paths (pool-allocated)

    MITRE ATT&CK Coverage:
    - T1070.004: Indicator Removal (file deletion protection)
    - T1222: File and Directory Permissions Modification
    - T1564.004: Hidden Files and Directories (ADS protection)
    - T1036: Masquerading (path normalization)

    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntifs.h>
#include <fltKernel.h>
#include <ntstrsafe.h>

//=============================================================================
// Constants
//=============================================================================

#define FP_POOL_TAG_CONTEXT     'CFPF'
#define FP_POOL_TAG_PATH        'PFPF'
#define FP_POOL_TAG_RULE        'RFPF'
#define FP_POOL_TAG_AUDIT       'AFPF'
#define FP_POOL_TAG_WORK        'WFPF'

#define FP_MAX_PROTECTED_PATHS          64
#define FP_MAX_PATH_LENGTH              1024
#define FP_MAX_STREAM_NAME_LENGTH       256
#define FP_MAX_EXTENSION_LENGTH         32
#define FP_MAX_PROTECTED_EXTENSIONS     32
#define FP_MAX_AUDIT_ENTRIES            1024

//=============================================================================
// Enumerations
//=============================================================================

typedef enum _FP_RULE_TYPE {
    FpRuleType_Path = 0,
    FpRuleType_Extension,
    FpRuleType_FileName,
    FpRuleType_Pattern,
    FpRuleType_Count
} FP_RULE_TYPE;

typedef enum _FP_PROTECTION_FLAGS {
    FpProtect_None              = 0x00000000,

    //
    // Operation protection
    //
    FpProtect_BlockWrite        = 0x00000001,
    FpProtect_BlockDelete       = 0x00000002,
    FpProtect_BlockRename       = 0x00000004,
    FpProtect_BlockSetInfo      = 0x00000008,
    FpProtect_BlockSetSecurity  = 0x00000010,
    FpProtect_BlockHardlink     = 0x00000020,
    FpProtect_BlockStreams       = 0x00000040,
    FpProtect_BlockExecute      = 0x00000080,

    //
    // Protection scope
    //
    FpProtect_Recursive         = 0x00000100,
    FpProtect_IncludeStreams    = 0x00000200,
    FpProtect_FollowLinks       = 0x00000400,

    //
    // Audit flags
    //
    FpProtect_AuditOnly         = 0x00001000,
    FpProtect_AlertOnAccess     = 0x00002000,

    //
    // Convenience combinations
    //
    FpProtect_ReadOnly          = FpProtect_BlockWrite | FpProtect_BlockDelete |
                                  FpProtect_BlockRename | FpProtect_BlockSetInfo,

    FpProtect_Full              = FpProtect_BlockWrite | FpProtect_BlockDelete |
                                  FpProtect_BlockRename | FpProtect_BlockSetInfo |
                                  FpProtect_BlockSetSecurity | FpProtect_BlockHardlink |
                                  FpProtect_BlockStreams | FpProtect_Recursive |
                                  FpProtect_IncludeStreams

} FP_PROTECTION_FLAGS;

typedef enum _FP_OPERATION_TYPE {
    FpOperation_Read = 0,
    FpOperation_Write,
    FpOperation_Delete,
    FpOperation_Rename,
    FpOperation_SetInfo,
    FpOperation_SetSecurity,
    FpOperation_CreateHardlink,
    FpOperation_CreateStream,
    FpOperation_DeleteStream,
    FpOperation_Execute,
    FpOperation_Count
} FP_OPERATION_TYPE;

typedef enum _FP_ACCESS_RESULT {
    FpAccess_Allow = 0,
    FpAccess_Block,
    FpAccess_AuditOnly,
    FpAccess_NotProtected
} FP_ACCESS_RESULT;

//=============================================================================
// Public Structures (no internal pointers exposed)
//=============================================================================

/**
 * @brief Public audit log entry for consumption by callers.
 *        No LIST_ENTRY or kernel pointers — safe for user-mode copy.
 */
typedef struct _FP_AUDIT_ENTRY_INFO {
    LARGE_INTEGER Timestamp;
    HANDLE ProcessId;
    HANDLE ThreadId;
    FP_OPERATION_TYPE Operation;
    FP_ACCESS_RESULT Result;
    WCHAR ProcessName[260];
    WCHAR FilePath[FP_MAX_PATH_LENGTH];
    WCHAR RulePath[FP_MAX_PATH_LENGTH];
} FP_AUDIT_ENTRY_INFO, *PFP_AUDIT_ENTRY_INFO;

/**
 * @brief Path analysis result
 */
typedef struct _FP_PATH_INFO {
    WCHAR NormalizedPath[FP_MAX_PATH_LENGTH];
    USHORT NormalizedLength;

    WCHAR FileName[260];
    WCHAR Extension[FP_MAX_EXTENSION_LENGTH];
    WCHAR StreamName[FP_MAX_STREAM_NAME_LENGTH];

    BOOLEAN IsDirectory;
    BOOLEAN HasStream;
    BOOLEAN IsSymlink;
    BOOLEAN IsJunction;
    BOOLEAN IsReparsePoint;
    BOOLEAN IsShortName;

    WCHAR VolumeName[64];
    ULONG VolumeSerialNumber;
} FP_PATH_INFO, *PFP_PATH_INFO;

/**
 * @brief File protection statistics (public, safe to copy)
 */
typedef struct _FP_STATISTICS {
    volatile LONG64 TotalChecks;
    volatile LONG64 PathsProtected;
    volatile LONG64 ExtensionsProtected;

    volatile LONG64 BlockedWrites;
    volatile LONG64 BlockedDeletes;
    volatile LONG64 BlockedRenames;
    volatile LONG64 BlockedSetInfo;
    volatile LONG64 BlockedSetSecurity;
    volatile LONG64 BlockedHardlinks;
    volatile LONG64 BlockedStreams;

    volatile LONG64 AuditEvents;
    volatile LONG64 BypassAttempts;

    LARGE_INTEGER StartTime;
} FP_STATISTICS, *PFP_STATISTICS;

/**
 * @brief Access check result with matched rule info.
 *        Returned by FpCheckFileAccess — contains copies, no dangling pointers.
 */
typedef struct _FP_ACCESS_CHECK_RESULT {
    FP_ACCESS_RESULT Result;
    ULONG MatchedProtectionFlags;
    WCHAR MatchedRulePath[FP_MAX_PATH_LENGTH];
    BOOLEAN HasMatchedRule;
} FP_ACCESS_CHECK_RESULT, *PFP_ACCESS_CHECK_RESULT;

//=============================================================================
// Opaque Engine Type
//=============================================================================

/**
 * @brief Opaque file protection engine handle.
 *        Internal layout is defined only in FileProtection.c.
 */
typedef struct _FP_ENGINE FP_ENGINE, *PFP_ENGINE;

//=============================================================================
// Function Prototypes - Engine Management
//=============================================================================

/**
 * @brief Initialize the file protection engine.
 * @note  Placed in PAGE section (safe to call after DriverEntry).
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
FpInitialize(
    _Out_ PFP_ENGINE* Engine
    );

/**
 * @brief Shutdown the file protection engine and free all resources.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
FpShutdown(
    _Inout_ PFP_ENGINE Engine
    );

/**
 * @brief Configure the file protection engine.
 *        Thread-safe — uses internal synchronization.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
FpConfigure(
    _In_ PFP_ENGINE Engine,
    _In_ BOOLEAN EnableNormalization,
    _In_ BOOLEAN EnableStreamProtection,
    _In_ BOOLEAN EnableSymlinkResolution,
    _In_ BOOLEAN EnableAuditLogging
    );

//=============================================================================
// Function Prototypes - Path Protection
//=============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
FpAddProtectedPath(
    _In_ PFP_ENGINE Engine,
    _In_ PCUNICODE_STRING Path,
    _In_ ULONG ProtectionFlags,
    _In_ FP_RULE_TYPE RuleType
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
FpAddProtectedPathW(
    _In_ PFP_ENGINE Engine,
    _In_ PCWSTR Path,
    _In_ ULONG ProtectionFlags,
    _In_ FP_RULE_TYPE RuleType
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
FpRemoveProtectedPath(
    _In_ PFP_ENGINE Engine,
    _In_ PCUNICODE_STRING Path
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
FpAddProtectedExtension(
    _In_ PFP_ENGINE Engine,
    _In_ PCWSTR Extension,
    _In_ ULONG ProtectionFlags
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
FpClearAllRules(
    _In_ PFP_ENGINE Engine
    );

//=============================================================================
// Function Prototypes - Access Checks
//=============================================================================

/**
 * @brief Check if a file operation should be blocked.
 *        All path data is copied under lock — no dangling references.
 */
_IRQL_requires_max_(APC_LEVEL)
FP_ACCESS_RESULT
FpCheckAccess(
    _In_ PFP_ENGINE Engine,
    _In_ PCUNICODE_STRING FilePath,
    _In_ FP_OPERATION_TYPE Operation,
    _In_ HANDLE RequestorPid,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_opt_ PULONG OutProtectionFlags
    );

/**
 * @brief Check if a path is in the protection list.
 *        Populates ProtectionFlags if matched.
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
FpIsPathProtected(
    _In_ PFP_ENGINE Engine,
    _In_ PCUNICODE_STRING Path,
    _Out_opt_ PULONG ProtectionFlags
    );

/**
 * @brief Check file access with full minifilter context.
 *        Returns result info with copied matched rule (no dangling pointers).
 */
_IRQL_requires_max_(APC_LEVEL)
FP_ACCESS_RESULT
FpCheckFileAccess(
    _In_ PFP_ENGINE Engine,
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FP_OPERATION_TYPE Operation,
    _Out_opt_ PFP_ACCESS_CHECK_RESULT ResultInfo
    );

//=============================================================================
// Function Prototypes - Path Utilities
//=============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
FpNormalizePath(
    _In_ PCUNICODE_STRING InputPath,
    _Out_ PFP_PATH_INFO PathInfo
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
FpNormalizePathEx(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PFP_PATH_INFO PathInfo
    );

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
FpExtractStreamName(
    _In_ PCUNICODE_STRING FullPath,
    _Out_writes_z_(StreamNameSize) PWCHAR StreamName,
    _In_ ULONG StreamNameSize,
    _Out_ PUNICODE_STRING BasePath
    );

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
FpStripStreamName(
    _In_ PCUNICODE_STRING FullPath,
    _Out_ PUNICODE_STRING BasePath
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
FpResolveSymlink(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_writes_z_(TargetPathSize) PWCHAR TargetPath,
    _In_ ULONG TargetPathSize
    );

/**
 * @brief Convert short name (8.3) to long name using FltGetFileNameInformation.
 *        Caller must free LongPath->Buffer with ExFreePool.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
FpConvertShortToLongName(
    _In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING ShortPath,
    _Out_ PUNICODE_STRING LongPath
    );

//=============================================================================
// Function Prototypes - Audit Logging
//=============================================================================

_IRQL_requires_max_(APC_LEVEL)
VOID
FpLogAccessAttempt(
    _In_ PFP_ENGINE Engine,
    _In_ PCUNICODE_STRING FilePath,
    _In_ FP_OPERATION_TYPE Operation,
    _In_ FP_ACCESS_RESULT Result,
    _In_ HANDLE ProcessId,
    _In_opt_ PCUNICODE_STRING RulePath
    );

/**
 * @brief Get audit log entries into caller-provided buffer.
 * @param Engine    File protection engine.
 * @param Buffer    Caller-allocated array of FP_AUDIT_ENTRY_INFO.
 * @param BufferCount  On input: max entries Buffer can hold.
 *                     On output: number of entries actually copied.
 * @return STATUS_SUCCESS, STATUS_BUFFER_TOO_SMALL, etc.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
FpGetAuditLog(
    _In_ PFP_ENGINE Engine,
    _Out_writes_to_(*BufferCount, *BufferCount) PFP_AUDIT_ENTRY_INFO Buffer,
    _Inout_ PULONG BufferCount
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
FpClearAuditLog(
    _In_ PFP_ENGINE Engine
    );

//=============================================================================
// Function Prototypes - Statistics
//=============================================================================

/**
 * @brief Get file protection statistics (atomic per-field reads).
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
FpGetStatistics(
    _In_ PFP_ENGINE Engine,
    _Out_ PFP_STATISTICS Stats
    );

/**
 * @brief Reset statistics (atomic per-field exchange).
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
FpResetStatistics(
    _In_ PFP_ENGINE Engine
    );

#ifdef __cplusplus
}
#endif