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
 * - Zone identifier extraction (Mark-of-the-Web)
 *
 * Security Guarantees:
 * - All functions validate input parameters
 * - Buffer sizes are always checked before operations
 * - No integer overflows in size calculations
 * - Pool allocations use tagged pools for leak detection
 * - IRQL constraints are strictly enforced
 * - No unvalidated file operations
 *
 * Performance Optimizations:
 * - Lookaside list support for common allocations
 * - Cached volume information
 * - Minimal I/O for metadata retrieval
 * - Zero-copy operations where possible
 *
 * MITRE ATT&CK Coverage:
 * - T1036: Masquerading (file type validation)
 * - T1564.004: Hidden Files/ADS detection
 * - T1027: Obfuscated Files (extension mismatch)
 * - T1055: Process Injection (PE validation)
 * - T1553.005: Mark-of-the-Web bypass detection
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
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

/**
 * @brief Pool tag for file utility allocations: 'fSSx' = ShadowStrike File
 */
#define SHADOW_FILE_TAG 'fSSx'

/**
 * @brief Pool tag for file buffer allocations
 */
#define SHADOW_FILEBUF_TAG 'bSSx'

/**
 * @brief Pool tag for file path allocations
 */
#define SHADOW_FILEPATH_TAG 'pSSx'

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * @brief Maximum file path length in bytes
 */
#define SHADOW_MAX_PATH_BYTES (32767 * sizeof(WCHAR))

/**
 * @brief Maximum file name length in characters
 */
#define SHADOW_MAX_FILENAME_CHARS 255

/**
 * @brief Maximum extension length in characters (including dot)
 */
#define SHADOW_MAX_EXTENSION_CHARS 32

/**
 * @brief Default file read chunk size (64KB)
 */
#define SHADOW_FILE_READ_CHUNK_SIZE (64 * 1024)

/**
 * @brief Maximum file size for full read (16MB)
 */
#define SHADOW_MAX_FILE_READ_SIZE (16 * 1024 * 1024)

/**
 * @brief PE header read size
 */
#define SHADOW_PE_HEADER_READ_SIZE 4096

/**
 * @brief DOS MZ signature
 */
#define SHADOW_MZ_SIGNATURE 0x5A4D

/**
 * @brief PE signature
 */
#define SHADOW_PE_SIGNATURE 0x00004550

/**
 * @brief Zone Identifier ADS name
 */
#define SHADOW_ZONE_IDENTIFIER_STREAM L":Zone.Identifier"

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief File type classification
 */
typedef enum _SHADOW_FILE_TYPE {
    ShadowFileTypeUnknown = 0,
    ShadowFileTypePE32,             ///< 32-bit PE executable
    ShadowFileTypePE64,             ///< 64-bit PE executable
    ShadowFileTypeDLL,              ///< Dynamic Link Library
    ShadowFileTypeDriver,           ///< Kernel driver (.sys)
    ShadowFileTypeScript,           ///< Script file (.js, .vbs, .ps1, .bat)
    ShadowFileTypeDocument,         ///< Office document
    ShadowFileTypePDF,              ///< PDF document
    ShadowFileTypeArchive,          ///< Archive file (.zip, .rar, .7z)
    ShadowFileTypeInstaller,        ///< Installer (.msi, .msix)
    ShadowFileTypeShortcut,         ///< Shortcut (.lnk)
    ShadowFileTypeHtmlApp,          ///< HTML Application (.hta)
    ShadowFileTypeJar,              ///< Java archive
    ShadowFileTypeImage,            ///< Image file
    ShadowFileTypeMedia,            ///< Audio/Video file
    ShadowFileTypeData,             ///< Generic data file
    ShadowFileTypeMax
} SHADOW_FILE_TYPE;

/**
 * @brief Volume type classification
 */
typedef enum _SHADOW_VOLUME_TYPE {
    ShadowVolumeUnknown = 0,
    ShadowVolumeFixed,              ///< Fixed disk (HDD/SSD)
    ShadowVolumeRemovable,          ///< Removable media (USB)
    ShadowVolumeNetwork,            ///< Network share
    ShadowVolumeCDROM,              ///< Optical drive
    ShadowVolumeRAM,                ///< RAM disk
    ShadowVolumeVirtual             ///< Virtual disk
} SHADOW_VOLUME_TYPE;

/**
 * @brief File open disposition (from CREATE operation)
 */
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

/**
 * @brief Comprehensive file information structure
 */
typedef struct _SHADOW_FILE_INFO {
    //
    // Identity
    //
    ULONG64 FileId;                 ///< Unique file identifier (NTFS MFT index)
    ULONG VolumeSerial;             ///< Volume serial number
    ULONG Reserved1;

    //
    // Size and timestamps
    //
    LONGLONG FileSize;              ///< End of file
    LONGLONG AllocationSize;        ///< Allocated size on disk
    LARGE_INTEGER CreationTime;     ///< File creation time
    LARGE_INTEGER LastAccessTime;   ///< Last access time
    LARGE_INTEGER LastWriteTime;    ///< Last write time
    LARGE_INTEGER ChangeTime;       ///< Last change time (metadata)

    //
    // Attributes
    //
    ULONG FileAttributes;           ///< FILE_ATTRIBUTE_* flags
    BOOLEAN IsDirectory;            ///< Is a directory
    BOOLEAN IsReadOnly;             ///< Read-only file
    BOOLEAN IsHidden;               ///< Hidden file
    BOOLEAN IsSystem;               ///< System file
    BOOLEAN IsArchive;              ///< Archive flag set
    BOOLEAN IsCompressed;           ///< File is compressed
    BOOLEAN IsEncrypted;            ///< File is encrypted (EFS)
    BOOLEAN IsSparseFile;           ///< Sparse file

    //
    // Special characteristics
    //
    BOOLEAN IsReparsePoint;         ///< Has reparse point
    BOOLEAN IsSymLink;              ///< Symbolic link
    BOOLEAN IsJunction;             ///< Directory junction
    BOOLEAN HasADS;                 ///< Has alternate data streams
    BOOLEAN HasZoneId;              ///< Has Zone.Identifier (MOTW)
    UCHAR ZoneId;                   ///< Zone ID value (0-4)
    BOOLEAN IsExecutable;           ///< Has executable extension
    BOOLEAN IsSigned;               ///< PE is digitally signed (basic check)

    //
    // Type classification
    //
    SHADOW_FILE_TYPE FileType;      ///< Detected file type

    //
    // Links
    //
    ULONG NumberOfLinks;            ///< Hard link count

    //
    // PE-specific (if applicable)
    //
    BOOLEAN IsPE;                   ///< Is a PE file
    BOOLEAN Is64Bit;                ///< 64-bit PE
    BOOLEAN IsDLL;                  ///< DLL flag set
    BOOLEAN IsDriver;               ///< Subsystem indicates driver
    USHORT PESubsystem;             ///< PE subsystem value
    USHORT PECharacteristics;       ///< PE characteristics
    ULONG PETimestamp;              ///< PE timestamp (compilation time)
    ULONG PEChecksum;               ///< PE checksum

} SHADOW_FILE_INFO, *PSHADOW_FILE_INFO;

/**
 * @brief Volume information structure
 */
typedef struct _SHADOW_VOLUME_INFO {
    SHADOW_VOLUME_TYPE VolumeType;  ///< Volume classification
    ULONG VolumeSerial;             ///< Volume serial number
    ULONG FileSystemFlags;          ///< FILE_*_INFORMATION flags
    ULONG MaxComponentLength;       ///< Max filename component
    WCHAR FileSystemName[32];       ///< File system name (NTFS, FAT32, etc.)
    WCHAR VolumeName[64];           ///< Volume label
    BOOLEAN IsReadOnly;             ///< Read-only volume
    BOOLEAN SupportsStreams;        ///< Supports ADS
    BOOLEAN SupportsHardLinks;      ///< Supports hard links
    BOOLEAN SupportsReparsePoints;  ///< Supports reparse points
    BOOLEAN SupportsSecurity;       ///< Supports ACLs
    BOOLEAN SupportsCompression;    ///< Supports compression
    BOOLEAN SupportsEncryption;     ///< Supports EFS
    BOOLEAN IsNetworkDrive;         ///< Network/remote drive
} SHADOW_VOLUME_INFO, *PSHADOW_VOLUME_INFO;

/**
 * @brief File read context for chunked reading
 */
typedef struct _SHADOW_FILE_READ_CONTEXT {
    PFLT_INSTANCE Instance;         ///< Filter instance
    PFILE_OBJECT FileObject;        ///< File object
    LONGLONG FileSize;              ///< Total file size
    LONGLONG CurrentOffset;         ///< Current read position
    PVOID Buffer;                   ///< Read buffer
    ULONG BufferSize;               ///< Buffer size
    ULONG BytesRead;                ///< Bytes read in last operation
    BOOLEAN EndOfFile;              ///< Reached EOF
    NTSTATUS LastStatus;            ///< Last operation status
} SHADOW_FILE_READ_CONTEXT, *PSHADOW_FILE_READ_CONTEXT;

// ============================================================================
// INITIALIZATION / CLEANUP
// ============================================================================

/**
 * @brief Initialize file utilities subsystem.
 *
 * Initializes lookaside lists and caches.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeInitializeFileUtils(
    VOID
    );

/**
 * @brief Cleanup file utilities subsystem.
 *
 * Frees all cached resources.
 *
 * @irql PASSIVE_LEVEL
 */
VOID
ShadowStrikeCleanupFileUtils(
    VOID
    );

// ============================================================================
// FILE NAME OPERATIONS
// ============================================================================

/**
 * @brief Get normalized file name from callback data.
 *
 * Retrieves the fully qualified, normalized file path from
 * a minifilter callback. Handles name provider fallback.
 *
 * @param Data          Callback data from minifilter
 * @param FileName      Receives allocated UNICODE_STRING with path
 *                      Caller must free with ShadowStrikeFreeFileName
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeGetFileName(
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_ PUNICODE_STRING FileName
    );

/**
 * @brief Get file name from file object.
 *
 * Alternative method when callback data is not available.
 *
 * @param Instance      Filter instance
 * @param FileObject    File object
 * @param FileName      Receives allocated file name
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeGetFileNameFromFileObject(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PUNICODE_STRING FileName
    );

/**
 * @brief Free file name allocated by ShadowStrikeGetFileName.
 *
 * @param FileName      File name to free
 *
 * @irql <= DISPATCH_LEVEL
 */
VOID
ShadowStrikeFreeFileName(
    _Inout_ PUNICODE_STRING FileName
    );

/**
 * @brief Get short (8.3) file name.
 *
 * @param Data          Callback data
 * @param ShortName     Receives short name (allocates buffer)
 *
 * @return STATUS_SUCCESS or STATUS_NOT_FOUND if no short name
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeGetShortFileName(
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_ PUNICODE_STRING ShortName
    );

// ============================================================================
// FILE IDENTIFICATION
// ============================================================================

/**
 * @brief Get file ID (NTFS MFT index).
 *
 * @param Instance      Filter instance
 * @param FileObject    File object
 * @param FileId        Receives 64-bit file ID
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeGetFileId(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PULONG64 FileId
    );

/**
 * @brief Get 128-bit file ID (ReFS compatible).
 *
 * @param Instance      Filter instance
 * @param FileObject    File object
 * @param FileId128     Receives 128-bit file ID
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeGetFileId128(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PFILE_ID_128 FileId128
    );

/**
 * @brief Get volume serial number.
 *
 * @param Instance      Filter instance
 * @param VolumeSerial  Receives volume serial
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeGetVolumeSerial(
    _In_ PFLT_INSTANCE Instance,
    _Out_ PULONG VolumeSerial
    );

// ============================================================================
// FILE SIZE AND ATTRIBUTES
// ============================================================================

/**
 * @brief Get file size.
 *
 * @param Instance      Filter instance
 * @param FileObject    File object
 * @param FileSize      Receives file size in bytes
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeGetFileSize(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PLONGLONG FileSize
    );

/**
 * @brief Get file attributes.
 *
 * @param Instance          Filter instance
 * @param FileObject        File object
 * @param FileAttributes    Receives FILE_ATTRIBUTE_* flags
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeGetFileAttributes(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PULONG FileAttributes
    );

/**
 * @brief Get comprehensive file information.
 *
 * Retrieves all available file metadata in a single call.
 *
 * @param Instance      Filter instance
 * @param FileObject    File object
 * @param FileInfo      Receives file information structure
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeGetFileInfo(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PSHADOW_FILE_INFO FileInfo
    );

/**
 * @brief Get basic file information (timestamps + attributes).
 *
 * Lighter weight than full GetFileInfo.
 *
 * @param Instance      Filter instance
 * @param FileObject    File object
 * @param BasicInfo     Receives FILE_BASIC_INFORMATION
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeGetFileBasicInfo(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PFILE_BASIC_INFORMATION BasicInfo
    );

/**
 * @brief Get standard file information (size + links).
 *
 * @param Instance      Filter instance
 * @param FileObject    File object
 * @param StandardInfo  Receives FILE_STANDARD_INFORMATION
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeGetFileStandardInfo(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PFILE_STANDARD_INFORMATION StandardInfo
    );

// ============================================================================
// FILE TYPE DETECTION
// ============================================================================

/**
 * @brief Detect file type from content (magic bytes).
 *
 * Reads file header and identifies type by signature.
 *
 * @param Instance      Filter instance
 * @param FileObject    File object
 * @param FileType      Receives detected file type
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeDetectFileType(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PSHADOW_FILE_TYPE FileType
    );

/**
 * @brief Detect file type from extension.
 *
 * Quick classification based on file extension only.
 *
 * @param FileName      File name or full path
 * @param FileType      Receives file type
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql <= DISPATCH_LEVEL
 */
NTSTATUS
ShadowStrikeDetectFileTypeByExtension(
    _In_ PCUNICODE_STRING FileName,
    _Out_ PSHADOW_FILE_TYPE FileType
    );

/**
 * @brief Check if file is a PE (executable).
 *
 * @param Instance      Filter instance
 * @param FileObject    File object
 * @param IsPE          Receives TRUE if PE
 * @param Is64Bit       Optional: receives TRUE if 64-bit
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeIsFilePE(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PBOOLEAN IsPE,
    _Out_opt_ PBOOLEAN Is64Bit
    );

/**
 * @brief Check if extension indicates executable.
 *
 * @param FileName      File name with extension
 *
 * @return TRUE if executable extension
 *
 * @irql <= DISPATCH_LEVEL
 */
BOOLEAN
ShadowStrikeIsExecutableExtension(
    _In_ PCUNICODE_STRING FileName
    );

/**
 * @brief Check if extension indicates script.
 *
 * @param FileName      File name with extension
 *
 * @return TRUE if script extension
 *
 * @irql <= DISPATCH_LEVEL
 */
BOOLEAN
ShadowStrikeIsScriptExtension(
    _In_ PCUNICODE_STRING FileName
    );

// ============================================================================
// ALTERNATE DATA STREAMS (ADS)
// ============================================================================

/**
 * @brief Check if file has alternate data streams.
 *
 * @param Instance      Filter instance
 * @param FileObject    File object
 * @param HasADS        Receives TRUE if ADS present
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeHasAlternateDataStreams(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PBOOLEAN HasADS
    );

/**
 * @brief Check if path references an ADS.
 *
 * @param FileName      File path to check
 *
 * @return TRUE if path contains ':'
 *
 * @irql <= DISPATCH_LEVEL
 */
BOOLEAN
ShadowStrikeIsAlternateDataStream(
    _In_ PCUNICODE_STRING FileName
    );

/**
 * @brief Get Zone Identifier (Mark-of-the-Web).
 *
 * @param Instance      Filter instance
 * @param FileObject    File object
 * @param HasZoneId     Receives TRUE if Zone.Identifier exists
 * @param ZoneId        Receives zone ID (0-4)
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
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

/**
 * @brief Get volume information.
 *
 * @param Instance      Filter instance
 * @param VolumeInfo    Receives volume information
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeGetVolumeInfo(
    _In_ PFLT_INSTANCE Instance,
    _Out_ PSHADOW_VOLUME_INFO VolumeInfo
    );

/**
 * @brief Classify volume type.
 *
 * @param Instance      Filter instance
 * @param VolumeType    Receives volume classification
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeGetVolumeType(
    _In_ PFLT_INSTANCE Instance,
    _Out_ PSHADOW_VOLUME_TYPE VolumeType
    );

/**
 * @brief Check if volume is network/remote.
 *
 * @param Instance      Filter instance
 *
 * @return TRUE if network volume
 *
 * @irql PASSIVE_LEVEL
 */
BOOLEAN
ShadowStrikeIsNetworkVolume(
    _In_ PFLT_INSTANCE Instance
    );

/**
 * @brief Check if volume is removable.
 *
 * @param Instance      Filter instance
 *
 * @return TRUE if removable volume
 *
 * @irql PASSIVE_LEVEL
 */
BOOLEAN
ShadowStrikeIsRemovableVolume(
    _In_ PFLT_INSTANCE Instance
    );

// ============================================================================
// FILE READING
// ============================================================================

/**
 * @brief Read file header (first N bytes).
 *
 * @param Instance      Filter instance
 * @param FileObject    File object
 * @param Buffer        Buffer to receive data
 * @param BufferSize    Size of buffer
 * @param BytesRead     Receives actual bytes read
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeReadFileHeader(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG BytesRead
    );

/**
 * @brief Read file at specific offset.
 *
 * @param Instance      Filter instance
 * @param FileObject    File object
 * @param Offset        Byte offset to read from
 * @param Buffer        Buffer to receive data
 * @param BufferSize    Size of buffer
 * @param BytesRead     Receives actual bytes read
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeReadFileAtOffset(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _In_ LONGLONG Offset,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG BytesRead
    );

/**
 * @brief Initialize chunked file read context.
 *
 * For reading large files in chunks without loading entirely in memory.
 *
 * @param Instance      Filter instance
 * @param FileObject    File object
 * @param ChunkSize     Size of each read chunk
 * @param Context       Receives initialized context
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeInitFileReadContext(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _In_ ULONG ChunkSize,
    _Out_ PSHADOW_FILE_READ_CONTEXT Context
    );

/**
 * @brief Read next chunk from file.
 *
 * @param Context       Read context
 *
 * @return STATUS_SUCCESS, STATUS_END_OF_FILE, or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeReadNextChunk(
    _Inout_ PSHADOW_FILE_READ_CONTEXT Context
    );

/**
 * @brief Cleanup file read context.
 *
 * @param Context       Read context to cleanup
 *
 * @irql <= DISPATCH_LEVEL
 */
VOID
ShadowStrikeCleanupFileReadContext(
    _Inout_ PSHADOW_FILE_READ_CONTEXT Context
    );

// ============================================================================
// REPARSE POINT OPERATIONS
// ============================================================================

/**
 * @brief Check if file is a reparse point.
 *
 * @param Instance      Filter instance
 * @param FileObject    File object
 * @param IsReparse     Receives TRUE if reparse point
 * @param ReparseTag    Optional: receives reparse tag
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeIsReparsePoint(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PBOOLEAN IsReparse,
    _Out_opt_ PULONG ReparseTag
    );

/**
 * @brief Check if file is a symbolic link.
 *
 * @param Instance      Filter instance
 * @param FileObject    File object
 *
 * @return TRUE if symbolic link
 *
 * @irql PASSIVE_LEVEL
 */
BOOLEAN
ShadowStrikeIsSymbolicLink(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject
    );

/**
 * @brief Get reparse point target path.
 *
 * @param Instance      Filter instance
 * @param FileObject    File object
 * @param TargetPath    Receives target path (allocates buffer)
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeGetReparseTarget(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PUNICODE_STRING TargetPath
    );

// ============================================================================
// SECURITY OPERATIONS
// ============================================================================

/**
 * @brief Get file owner SID.
 *
 * @param Instance      Filter instance
 * @param FileObject    File object
 * @param OwnerSid      Receives owner SID (allocates buffer)
 * @param SidLength     Receives SID length
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeGetFileOwner(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PSID* OwnerSid,
    _Out_ PULONG SidLength
    );

/**
 * @brief Free SID allocated by ShadowStrikeGetFileOwner.
 *
 * @param Sid           SID to free
 *
 * @irql <= DISPATCH_LEVEL
 */
VOID
ShadowStrikeFreeFileSid(
    _In_ PSID Sid
    );

// ============================================================================
// CALLBACK DATA HELPERS
// ============================================================================

/**
 * @brief Get file disposition from CREATE operation.
 *
 * @param Data          Callback data
 *
 * @return File disposition enum
 *
 * @irql <= DISPATCH_LEVEL
 */
SHADOW_FILE_DISPOSITION
ShadowStrikeGetFileDisposition(
    _In_ PFLT_CALLBACK_DATA Data
    );

/**
 * @brief Check if CREATE is for write access.
 *
 * @param Data          Callback data
 *
 * @return TRUE if write access requested
 *
 * @irql <= DISPATCH_LEVEL
 */
BOOLEAN
ShadowStrikeIsWriteAccess(
    _In_ PFLT_CALLBACK_DATA Data
    );

/**
 * @brief Check if CREATE is for execute/map access.
 *
 * @param Data          Callback data
 *
 * @return TRUE if execute access requested
 *
 * @irql <= DISPATCH_LEVEL
 */
BOOLEAN
ShadowStrikeIsExecuteAccess(
    _In_ PFLT_CALLBACK_DATA Data
    );

/**
 * @brief Check if operation is on a directory.
 *
 * @param Data              Callback data
 * @param FltObjects        Filter objects
 * @param IsDirectory       Receives TRUE if directory
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeIsDirectory(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PBOOLEAN IsDirectory
    );

/**
 * @brief Check if operation is from kernel mode.
 *
 * @param Data          Callback data
 *
 * @return TRUE if kernel mode operation
 *
 * @irql <= DISPATCH_LEVEL
 */
BOOLEAN
ShadowStrikeIsKernelModeOperation(
    _In_ PFLT_CALLBACK_DATA Data
    );

// ============================================================================
// INLINE HELPERS
// ============================================================================

/**
 * @brief Check if file attributes indicate directory.
 */
FORCEINLINE
BOOLEAN
ShadowStrikeIsDirectoryByAttributes(
    _In_ ULONG FileAttributes
    )
{
    return BooleanFlagOn(FileAttributes, FILE_ATTRIBUTE_DIRECTORY);
}

/**
 * @brief Check if file is hidden.
 */
FORCEINLINE
BOOLEAN
ShadowStrikeIsHiddenFile(
    _In_ ULONG FileAttributes
    )
{
    return BooleanFlagOn(FileAttributes, FILE_ATTRIBUTE_HIDDEN);
}

/**
 * @brief Check if file is system file.
 */
FORCEINLINE
BOOLEAN
ShadowStrikeIsSystemFile(
    _In_ ULONG FileAttributes
    )
{
    return BooleanFlagOn(FileAttributes, FILE_ATTRIBUTE_SYSTEM);
}

/**
 * @brief Check if file is read-only.
 */
FORCEINLINE
BOOLEAN
ShadowStrikeIsReadOnlyFile(
    _In_ ULONG FileAttributes
    )
{
    return BooleanFlagOn(FileAttributes, FILE_ATTRIBUTE_READONLY);
}

/**
 * @brief Check if file has reparse point attribute.
 */
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
