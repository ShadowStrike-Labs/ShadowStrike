/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE FILE UTILITIES
 * ============================================================================
 *
 * @file FileUtils.h
 * @brief Enterprise-grade file operations for kernel-mode EDR/XDR.
 *
 * Provides CrowdStrike Falcon-class file handling with:
 * - Safe file information retrieval with proper IRQL handling
 * - Normalized path acquisition (NT/DOS path conversion)
 * - File attribute and metadata extraction
 * - Alternate Data Stream (ADS) detection
 * - File type identification (PE, script, archive, document)
 * - Secure file reading with size limits
 * - Volume information retrieval
 * - Reparse point and symbolic link handling
 * - File signature verification support
 * - Zone identifier extraction (Mark-of-the-Web) with actual content parsing
 *
 * Security Guarantees:
 * - All functions validate input parameters
 * - Buffer sizes are always checked before operations
 * - No integer overflows in size calculations
 * - Pool allocations use ExAllocatePool2 for automatic zeroing
 * - IRQL constraints are strictly enforced
 * - Bounds checking on all stream/reparse parsing
 * - Thread-safe initialization with interlocked operations
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_FILE_UTILS_H_
#define _SHADOWSTRIKE_FILE_UTILS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <fltKernel.h>
#include <ntddk.h>
#include <ntstrsafe.h>

// ============================================================================
// POOL TAGS
// ============================================================================

#define SHADOW_FILE_TAG         'fSSx'
#define SHADOW_FILEBUF_TAG      'bSSx'
#define SHADOW_FILEPATH_TAG     'pSSx'

// ============================================================================
// CONSTANTS
// ============================================================================

#define SHADOW_MAX_PATH_BYTES           (32767 * sizeof(WCHAR))
#define SHADOW_MAX_FILENAME_CHARS       255
#define SHADOW_MAX_EXTENSION_CHARS      32
#define SHADOW_FILE_READ_CHUNK_SIZE     (64 * 1024)
#define SHADOW_MAX_FILE_READ_SIZE       (16 * 1024 * 1024)
#define SHADOW_PE_HEADER_READ_SIZE      4096
#define SHADOW_MZ_SIGNATURE             0x5A4D
#define SHADOW_PE_SIGNATURE             0x00004550
#define SHADOW_ZONE_IDENTIFIER_STREAM   L":Zone.Identifier"
#define SHADOW_MAX_STACK_BUFFER         512

// ============================================================================
// ENUMERATIONS
// ============================================================================

typedef enum _SHADOW_FILE_TYPE {
    ShadowFileTypeUnknown = 0,
    ShadowFileTypePE32,
    ShadowFileTypePE64,
    ShadowFileTypeDLL,
    ShadowFileTypeDriver,
    ShadowFileTypeScript,
    ShadowFileTypeDocument,
    ShadowFileTypePDF,
    ShadowFileTypeArchive,
    ShadowFileTypeInstaller,
    ShadowFileTypeShortcut,
    ShadowFileTypeHtmlApp,
    ShadowFileTypeJar,
    ShadowFileTypeImage,
    ShadowFileTypeMedia,
    ShadowFileTypeData,
    ShadowFileTypeMax
} SHADOW_FILE_TYPE;

typedef enum _SHADOW_VOLUME_TYPE {
    ShadowVolumeUnknown = 0,
    ShadowVolumeFixed,
    ShadowVolumeRemovable,
    ShadowVolumeNetwork,
    ShadowVolumeCDROM,
    ShadowVolumeRAM,
    ShadowVolumeVirtual
} SHADOW_VOLUME_TYPE;

typedef enum _SHADOW_FILE_DISPOSITION {
    ShadowDispositionSupersede = 0,
    ShadowDispositionOpen,
    ShadowDispositionCreate,
    ShadowDispositionOpenIf,
    ShadowDispositionOverwrite,
    ShadowDispositionOverwriteIf,
    ShadowDispositionMax
} SHADOW_FILE_DISPOSITION;

// ============================================================================
// STRUCTURES
// ============================================================================

typedef struct _SHADOW_FILE_INFO {
    ULONG64 FileId;
    ULONG VolumeSerial;
    ULONG Reserved1;
    LONGLONG FileSize;
    LONGLONG AllocationSize;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG FileAttributes;
    BOOLEAN IsDirectory;
    BOOLEAN IsReadOnly;
    BOOLEAN IsHidden;
    BOOLEAN IsSystem;
    BOOLEAN IsArchive;
    BOOLEAN IsCompressed;
    BOOLEAN IsEncrypted;
    BOOLEAN IsSparseFile;
    BOOLEAN IsReparsePoint;
    BOOLEAN IsSymLink;
    BOOLEAN IsJunction;
    BOOLEAN HasADS;
    BOOLEAN HasZoneId;
    UCHAR ZoneId;
    BOOLEAN IsExecutable;
    BOOLEAN IsSigned;
    SHADOW_FILE_TYPE FileType;
    ULONG NumberOfLinks;
    BOOLEAN IsPE;
    BOOLEAN Is64Bit;
    BOOLEAN IsDLL;
    BOOLEAN IsDriver;
    USHORT PESubsystem;
    USHORT PECharacteristics;
    ULONG PETimestamp;
    ULONG PEChecksum;
} SHADOW_FILE_INFO, *PSHADOW_FILE_INFO;

typedef struct _SHADOW_VOLUME_INFO {
    SHADOW_VOLUME_TYPE VolumeType;
    ULONG VolumeSerial;
    ULONG FileSystemFlags;
    ULONG MaxComponentLength;
    WCHAR FileSystemName[32];
    WCHAR VolumeName[64];
    BOOLEAN IsReadOnly;
    BOOLEAN SupportsStreams;
    BOOLEAN SupportsHardLinks;
    BOOLEAN SupportsReparsePoints;
    BOOLEAN SupportsSecurity;
    BOOLEAN SupportsCompression;
    BOOLEAN SupportsEncryption;
    BOOLEAN IsNetworkDrive;
} SHADOW_VOLUME_INFO, *PSHADOW_VOLUME_INFO;

typedef struct _SHADOW_FILE_READ_CONTEXT {
    PFLT_INSTANCE Instance;
    PFILE_OBJECT FileObject;
    LONGLONG FileSize;
    LONGLONG CurrentOffset;
    PVOID Buffer;
    ULONG BufferSize;
    ULONG BytesRead;
    BOOLEAN EndOfFile;
    NTSTATUS LastStatus;
    BOOLEAN UsedLookaside;
    UCHAR Reserved[3];
} SHADOW_FILE_READ_CONTEXT, *PSHADOW_FILE_READ_CONTEXT;

// ============================================================================
// INITIALIZATION / CLEANUP
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeInitializeFileUtils(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeCleanupFileUtils(
    VOID
    );

// ============================================================================
// FILE NAME OPERATIONS
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeGetFileName(
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_ PUNICODE_STRING FileName
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeGetFileNameFromFileObject(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PUNICODE_STRING FileName
    );

_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowStrikeFreeFileName(
    _Inout_ PUNICODE_STRING FileName
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeGetShortFileName(
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_ PUNICODE_STRING ShortName
    );

// ============================================================================
// FILE IDENTIFICATION
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeGetFileId(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PULONG64 FileId
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeGetFileId128(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PFILE_ID_128 FileId128
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeGetVolumeSerial(
    _In_ PFLT_INSTANCE Instance,
    _Out_ PULONG VolumeSerial
    );

// ============================================================================
// FILE SIZE AND ATTRIBUTES
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeGetFileSize(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PLONGLONG FileSize
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeGetFileAttributes(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PULONG FileAttributes
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeGetFileInfo(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PSHADOW_FILE_INFO FileInfo
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeGetFileBasicInfo(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PFILE_BASIC_INFORMATION BasicInfo
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeGetFileStandardInfo(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PFILE_STANDARD_INFORMATION StandardInfo
    );

// ============================================================================
// FILE TYPE DETECTION
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeDetectFileType(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PSHADOW_FILE_TYPE FileType
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeDetectFileTypeByExtension(
    _In_ PCUNICODE_STRING FileName,
    _Out_ PSHADOW_FILE_TYPE FileType
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeIsFilePE(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PBOOLEAN IsPE,
    _Out_opt_ PBOOLEAN Is64Bit
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsExecutableExtension(
    _In_ PCUNICODE_STRING FileName
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsScriptExtension(
    _In_ PCUNICODE_STRING FileName
    );

// ============================================================================
// ALTERNATE DATA STREAMS (ADS)
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeHasAlternateDataStreams(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PBOOLEAN HasADS
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsAlternateDataStream(
    _In_ PCUNICODE_STRING FileName
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeGetZoneIdentifier(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PBOOLEAN HasZoneId,
    _Out_ PUCHAR ZoneId
    );

// ============================================================================
// VOLUME OPERATIONS
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeGetVolumeInfo(
    _In_ PFLT_INSTANCE Instance,
    _Out_ PSHADOW_VOLUME_INFO VolumeInfo
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeGetVolumeType(
    _In_ PFLT_INSTANCE Instance,
    _Out_ PSHADOW_VOLUME_TYPE VolumeType
    );

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ShadowStrikeIsNetworkVolume(
    _In_ PFLT_INSTANCE Instance
    );

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ShadowStrikeIsRemovableVolume(
    _In_ PFLT_INSTANCE Instance
    );

// ============================================================================
// FILE READING
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeReadFileHeader(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG BytesRead
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeReadFileAtOffset(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _In_ LONGLONG Offset,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG BytesRead
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeInitFileReadContext(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _In_ ULONG ChunkSize,
    _Out_ PSHADOW_FILE_READ_CONTEXT Context
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeReadNextChunk(
    _Inout_ PSHADOW_FILE_READ_CONTEXT Context
    );

_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowStrikeCleanupFileReadContext(
    _Inout_ PSHADOW_FILE_READ_CONTEXT Context
    );

// ============================================================================
// REPARSE POINT OPERATIONS
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeIsReparsePoint(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PBOOLEAN IsReparse,
    _Out_opt_ PULONG ReparseTag
    );

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ShadowStrikeIsSymbolicLink(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeGetReparseTarget(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PUNICODE_STRING TargetPath
    );

// ============================================================================
// SECURITY OPERATIONS
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeGetFileOwner(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PSID* OwnerSid,
    _Out_ PULONG SidLength
    );

_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowStrikeFreeFileSid(
    _In_ PSID Sid
    );

// ============================================================================
// CALLBACK DATA HELPERS
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
SHADOW_FILE_DISPOSITION
ShadowStrikeGetFileDisposition(
    _In_ PFLT_CALLBACK_DATA Data
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsWriteAccess(
    _In_ PFLT_CALLBACK_DATA Data
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsExecuteAccess(
    _In_ PFLT_CALLBACK_DATA Data
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeIsDirectory(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PBOOLEAN IsDirectory
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsKernelModeOperation(
    _In_ PFLT_CALLBACK_DATA Data
    );

// ============================================================================
// INLINE HELPERS
// ============================================================================

FORCEINLINE
BOOLEAN
ShadowStrikeIsDirectoryByAttributes(
    _In_ ULONG FileAttributes
    )
{
    return BooleanFlagOn(FileAttributes, FILE_ATTRIBUTE_DIRECTORY);
}

FORCEINLINE
BOOLEAN
ShadowStrikeIsHiddenFile(
    _In_ ULONG FileAttributes
    )
{
    return BooleanFlagOn(FileAttributes, FILE_ATTRIBUTE_HIDDEN);
}

FORCEINLINE
BOOLEAN
ShadowStrikeIsSystemFile(
    _In_ ULONG FileAttributes
    )
{
    return BooleanFlagOn(FileAttributes, FILE_ATTRIBUTE_SYSTEM);
}

FORCEINLINE
BOOLEAN
ShadowStrikeIsReadOnlyFile(
    _In_ ULONG FileAttributes
    )
{
    return BooleanFlagOn(FileAttributes, FILE_ATTRIBUTE_READONLY);
}

FORCEINLINE
BOOLEAN
ShadowStrikeIsReparsePointByAttributes(
    _In_ ULONG FileAttributes
    )
{
    return BooleanFlagOn(FileAttributes, FILE_ATTRIBUTE_REPARSE_POINT);
}

#ifdef __cplusplus
}
#endif

#endif // _SHADOWSTRIKE_FILE_UTILS_H_
