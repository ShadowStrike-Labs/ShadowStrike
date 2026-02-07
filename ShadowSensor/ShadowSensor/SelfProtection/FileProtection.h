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
    - Reparse point detection and handling
    - File rename/move tracking
    - Hardlink protection
    - Volume-relative path handling

    Security Considerations:
    - All paths are normalized before comparison
    - Case-insensitive matching for Windows compatibility
    - ADS names are stripped for comparison
    - Symbolic links resolved to prevent bypass
    - Short names resolved to prevent bypass

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

//=============================================================================
// Constants
//=============================================================================

/**
 * @brief Pool tag for file protection allocations
 */
#define FP_POOL_TAG_CONTEXT     'CFPF'
#define FP_POOL_TAG_PATH        'PFPF'
#define FP_POOL_TAG_RULE        'RFPF'

/**
 * @brief Maximum protected paths
 */
#define FP_MAX_PROTECTED_PATHS          64

/**
 * @brief Maximum path length for protected entries
 */
#define FP_MAX_PATH_LENGTH              1024

/**
 * @brief Maximum NTFS stream name length
 */
#define FP_MAX_STREAM_NAME_LENGTH       256

/**
 * @brief Maximum file extension length
 */
#define FP_MAX_EXTENSION_LENGTH         32

/**
 * @brief Maximum number of protected file extensions
 */
#define FP_MAX_PROTECTED_EXTENSIONS     32

/**
 * @brief Maximum audit log entries
 */
#define FP_MAX_AUDIT_ENTRIES            1024

//=============================================================================
// Enumerations
//=============================================================================

/**
 * @brief File protection rule type
 */
typedef enum _FP_RULE_TYPE {
    FpRuleType_Path = 0,            // Protect specific path/directory
    FpRuleType_Extension,           // Protect files by extension
    FpRuleType_FileName,            // Protect specific file name
    FpRuleType_Pattern,             // Wildcard pattern matching
    FpRuleType_Count
} FP_RULE_TYPE;

/**
 * @brief File protection flags
 */
typedef enum _FP_PROTECTION_FLAGS {
    FpProtect_None              = 0x00000000,

    //
    // Operation protection
    //
    FpProtect_BlockWrite        = 0x00000001,   // Block file writes
    FpProtect_BlockDelete       = 0x00000002,   // Block file deletion
    FpProtect_BlockRename       = 0x00000004,   // Block file rename/move
    FpProtect_BlockSetInfo      = 0x00000008,   // Block SetFileInformation
    FpProtect_BlockSetSecurity  = 0x00000010,   // Block security changes
    FpProtect_BlockHardlink     = 0x00000020,   // Block hardlink creation to file
    FpProtect_BlockStreams      = 0x00000040,   // Block ADS operations
    FpProtect_BlockExecute      = 0x00000080,   // Block execution (for quarantine)

    //
    // Protection scope
    //
    FpProtect_Recursive         = 0x00000100,   // Apply to subdirectories
    FpProtect_IncludeStreams    = 0x00000200,   // Include NTFS streams
    FpProtect_FollowLinks       = 0x00000400,   // Follow symbolic links

    //
    // Audit flags
    //
    FpProtect_AuditOnly         = 0x00001000,   // Log but don't block
    FpProtect_AlertOnAccess     = 0x00002000,   // Generate alert on any access

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

/**
 * @brief File operation type for access checks
 */
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

/**
 * @brief Access check result
 */
typedef enum _FP_ACCESS_RESULT {
    FpAccess_Allow = 0,             // Operation allowed
    FpAccess_Block,                 // Operation blocked
    FpAccess_AuditOnly,             // Logged but allowed
    FpAccess_NotProtected           // Path not in protection list
} FP_ACCESS_RESULT;

//=============================================================================
// Structures
//=============================================================================

/**
 * @brief Protected path entry
 */
typedef struct _FP_PROTECTED_PATH {
    LIST_ENTRY ListEntry;

    //
    // Path information
    //
    WCHAR NormalizedPath[FP_MAX_PATH_LENGTH];
    USHORT PathLength;
    BOOLEAN IsDirectory;

    //
    // Rule configuration
    //
    FP_RULE_TYPE RuleType;
    ULONG ProtectionFlags;

    //
    // Statistics
    //
    volatile LONG64 BlockedOperations;
    volatile LONG64 AuditedOperations;

    //
    // Timing
    //
    LARGE_INTEGER AddedTime;
    LARGE_INTEGER LastAccessTime;

    //
    // Reference counting
    //
    volatile LONG RefCount;

} FP_PROTECTED_PATH, *PFP_PROTECTED_PATH;

/**
 * @brief Protected extension entry
 */
typedef struct _FP_PROTECTED_EXTENSION {
    BOOLEAN InUse;
    WCHAR Extension[FP_MAX_EXTENSION_LENGTH];
    USHORT ExtensionLength;
    ULONG ProtectionFlags;
    volatile LONG64 BlockedCount;
} FP_PROTECTED_EXTENSION, *PFP_PROTECTED_EXTENSION;

/**
 * @brief Audit log entry
 */
typedef struct _FP_AUDIT_ENTRY {
    LIST_ENTRY ListEntry;

    LARGE_INTEGER Timestamp;
    HANDLE ProcessId;
    HANDLE ThreadId;
    FP_OPERATION_TYPE Operation;
    FP_ACCESS_RESULT Result;
    WCHAR ProcessName[260];
    WCHAR FilePath[FP_MAX_PATH_LENGTH];
    WCHAR RulePath[FP_MAX_PATH_LENGTH];

} FP_AUDIT_ENTRY, *PFP_AUDIT_ENTRY;

/**
 * @brief Path analysis result
 */
typedef struct _FP_PATH_INFO {
    //
    // Normalized path (resolved symlinks, short names)
    //
    WCHAR NormalizedPath[FP_MAX_PATH_LENGTH];
    USHORT NormalizedLength;

    //
    // Original path components
    //
    WCHAR FileName[260];
    WCHAR Extension[FP_MAX_EXTENSION_LENGTH];
    WCHAR StreamName[FP_MAX_STREAM_NAME_LENGTH];

    //
    // Path characteristics
    //
    BOOLEAN IsDirectory;
    BOOLEAN HasStream;
    BOOLEAN IsSymlink;
    BOOLEAN IsJunction;
    BOOLEAN IsReparsePoint;
    BOOLEAN IsShortName;

    //
    // Volume information
    //
    WCHAR VolumeName[64];
    ULONG VolumeSerialNumber;

} FP_PATH_INFO, *PFP_PATH_INFO;

/**
 * @brief File protection statistics
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
 * @brief File protection engine
 */
typedef struct _FP_ENGINE {
    BOOLEAN Initialized;

    //
    // Protected paths (linked list)
    //
    LIST_ENTRY ProtectedPathList;
    EX_PUSH_LOCK PathListLock;
    volatile LONG ProtectedPathCount;

    //
    // Protected extensions (static array)
    //
    FP_PROTECTED_EXTENSION ProtectedExtensions[FP_MAX_PROTECTED_EXTENSIONS];
    EX_PUSH_LOCK ExtensionLock;
    volatile LONG ProtectedExtensionCount;

    //
    // Audit log (ring buffer)
    //
    LIST_ENTRY AuditLog;
    EX_PUSH_LOCK AuditLogLock;
    volatile LONG AuditLogCount;

    //
    // Configuration
    //
    struct {
        BOOLEAN EnablePathNormalization;
        BOOLEAN EnableStreamProtection;
        BOOLEAN EnableSymlinkResolution;
        BOOLEAN EnableShortNameResolution;
        BOOLEAN EnableAuditLogging;
        ULONG MaxAuditEntries;
    } Config;

    //
    // Statistics
    //
    FP_STATISTICS Stats;

} FP_ENGINE, *PFP_ENGINE;

//=============================================================================
// Function Prototypes - Engine Management
//=============================================================================

/**
 * @brief Initialize the file protection engine.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
FpInitialize(
    _Out_ PFP_ENGINE* Engine
    );

/**
 * @brief Shutdown the file protection engine.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
FpShutdown(
    _Inout_ PFP_ENGINE Engine
    );

/**
 * @brief Configure the file protection engine.
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

/**
 * @brief Add a path to the protection list.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
FpAddProtectedPath(
    _In_ PFP_ENGINE Engine,
    _In_ PCUNICODE_STRING Path,
    _In_ ULONG ProtectionFlags,
    _In_ FP_RULE_TYPE RuleType
    );

/**
 * @brief Add a path (C string version).
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
FpAddProtectedPathW(
    _In_ PFP_ENGINE Engine,
    _In_ PCWSTR Path,
    _In_ ULONG ProtectionFlags,
    _In_ FP_RULE_TYPE RuleType
    );

/**
 * @brief Remove a path from the protection list.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
FpRemoveProtectedPath(
    _In_ PFP_ENGINE Engine,
    _In_ PCUNICODE_STRING Path
    );

/**
 * @brief Add a protected file extension.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
FpAddProtectedExtension(
    _In_ PFP_ENGINE Engine,
    _In_ PCWSTR Extension,
    _In_ ULONG ProtectionFlags
    );

/**
 * @brief Clear all protection rules.
 */
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
 */
_IRQL_requires_max_(APC_LEVEL)
FP_ACCESS_RESULT
FpCheckAccess(
    _In_ PFP_ENGINE Engine,
    _In_ PCUNICODE_STRING FilePath,
    _In_ FP_OPERATION_TYPE Operation,
    _In_ HANDLE RequestorPid,
    _In_ ACCESS_MASK DesiredAccess
    );

/**
 * @brief Check if a path is protected.
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
FpIsPathProtected(
    _In_ PFP_ENGINE Engine,
    _In_ PCUNICODE_STRING Path,
    _Out_opt_ PULONG ProtectionFlags
    );

/**
 * @brief Check file access with full context.
 */
_IRQL_requires_max_(APC_LEVEL)
FP_ACCESS_RESULT
FpCheckFileAccess(
    _In_ PFP_ENGINE Engine,
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FP_OPERATION_TYPE Operation,
    _Out_opt_ PFP_PROTECTED_PATH* MatchedRule
    );

//=============================================================================
// Function Prototypes - Path Utilities
//=============================================================================

/**
 * @brief Normalize a file path.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
FpNormalizePath(
    _In_ PCUNICODE_STRING InputPath,
    _Out_ PFP_PATH_INFO PathInfo
    );

/**
 * @brief Normalize path with filter context.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
FpNormalizePathEx(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PFP_PATH_INFO PathInfo
    );

/**
 * @brief Extract stream name from path.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
FpExtractStreamName(
    _In_ PCUNICODE_STRING FullPath,
    _Out_writes_z_(StreamNameSize) PWCHAR StreamName,
    _In_ ULONG StreamNameSize,
    _Out_ PUNICODE_STRING BasePath
    );

/**
 * @brief Strip stream name from path.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
FpStripStreamName(
    _In_ PCUNICODE_STRING FullPath,
    _Out_ PUNICODE_STRING BasePath
    );

/**
 * @brief Resolve symbolic link target.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
FpResolveSymlink(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_writes_z_(TargetPathSize) PWCHAR TargetPath,
    _In_ ULONG TargetPathSize
    );

/**
 * @brief Convert short name to long name.
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

/**
 * @brief Log an access attempt.
 */
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
 * @brief Get audit log entries.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
FpGetAuditLog(
    _In_ PFP_ENGINE Engine,
    _Out_ PFP_AUDIT_ENTRY* Entries,
    _Inout_ PULONG EntryCount
    );

/**
 * @brief Clear audit log.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
FpClearAuditLog(
    _In_ PFP_ENGINE Engine
    );

//=============================================================================
// Function Prototypes - Statistics
//=============================================================================

/**
 * @brief Get file protection statistics.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
FpGetStatistics(
    _In_ PFP_ENGINE Engine,
    _Out_ PFP_STATISTICS Stats
    );

/**
 * @brief Reset statistics.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
FpResetStatistics(
    _In_ PFP_ENGINE Engine
    );

#ifdef __cplusplus
}
#endif

